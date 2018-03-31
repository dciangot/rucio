# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2015, 2017
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2018
# - Wen Guan, <wen.guan@cern.ch>, 2014-2016
# - Martin Barisits, <martin.barisits@cern.ch>, 2017
# - Eric Vaandering, <ewv@fnal.gov>, 2018
# - Diego Ciangottini, <ciangottini@pg.infn.it>, 2018

import commands
import datetime
import exceptions
import json
import logging
import os
import sys
import tempfile
import time
import traceback
import urlparse
import uuid
from datetime import timedelta
from hashlib import sha1

import requests
from dateutil import parser
from dogpile.cache import make_region
from dogpile.cache.api import NoValue
from myproxy.client import MyProxyClient, MyProxyClientGetError, MyProxyClientRetrieveError
from requests.exceptions import Timeout, RequestException, ConnectionError, SSLError, HTTPError
from requests.packages.urllib3 import disable_warnings  # pylint: disable=import-error
from socket import gaierror

from fts3.rest.client.easy import Context, delegate
from fts3.rest.client.exceptions import BadEndpoint, ClientError, ServerError
from rucio.common.config import config_get, config_get_bool
from rucio.core.monitor import record_counter, record_timer
from rucio.db.sqla.constants import FTSState

logging.getLogger("requests").setLevel(logging.CRITICAL)
disable_warnings()

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

__USERCERT = config_get('conveyor', 'usercert', False, None)
__USE_DETERMINISTIC_ID = config_get_bool('conveyor', 'use_deterministic_id', False, False)

REGION_SHORT = make_region().configure('dogpile.cache.memory',
                                       expiration_time=1800)

# TODO: move in utils + docstrings sphinx

def get_dn_from_scope(scope, cert_path=__USERCERT, certkey_path=__USERCERT, ca_path='/etc/grid-security/certificates/', sitedb_host='https://cmsweb.cern.ch/sitedb/data/prod/people'):
    """Retrieve DN for user scope

    SiteDB api response example:
    {"desc": {"columns": ["username", "email", "forename", "surname", "dn", "phone1", "phone2", "im_handle"]}, 
     "result": [["diego", "diego@cern.ch", "Diego", "da Silva Gomes", "/DC=org/DC=doegrids/OU=People/CN=Diego", "+41 XXXX", "+41 22 76 XXXX", "gtalk:geneguvo@gmail.com"]]
     }
    
    :param scope: Rucio scope
    :type scope: str
    
    :param cert_path: user/service certificate path, defaults to __USERCERT
    :param cert_path: str, optional
    :param certkey_path: user/service certificate key path, defaults to __USERCERT
    :param certkey_path: str, optional
    :param ca_path: ca path for verification, defaults to '/etc/grid-security/certificates/'
    :param ca_path: str, optional
    :param sitedb_host: sitedb endpoint url, defaults to 'https://cmsweb.cern.ch/sitedb/data/prod/people'
    :param sitedb_host: str, optional
    
    :return: user DN or None if failed
    :rtype: str
    """
    username = scope.split(".")[1]

    request_data = {'match': username}
    request_data_json = json.dumps(request_data)

    # TODO: fix it
    try:
        resp = requests.get('%s?match=%s' % (sitedb_host, username),
                            data=request_data_json,
                            headers={'Content-Type': 'application/json'},
                            verify=ca_path,
                            cert=(cert_path, certkey_path))
    except (ConnectionError, SSLError):
        logging.error("Connection error trying to contact siteDB")
        raise
    except Timeout:
        logging.error("Timedout request to SiteDB")
        raise
    except (RequestException, IOError):
        logging.error("SiteDB request exception")
        raise

    if resp.status_code == requests.codes.ok:
        resp_json = resp.json()
    else:
        logging.error("Bad SiteDB request status code")
        resp.raise_for_status()

    for key, value in zip(resp_json['desc']['columns'], resp_json['result'][0]):
        if key == "dn":
            return value

    return None


def get_user_proxy(myproxy_server, userDN, activity, cert=__USERCERT, ckey=__USERCERT, force_remote=False):
    """Retrieve user proxy for the correct activity from myproxy and save it in memcache
    
    :param myproxy_server: myproxy server hostname
    :type myproxy_server: str
    :param userDN: user DN
    :type userDN: str
    :param activity: Rucio activity
    :type activity: str

    :param cert: host certificate path, defaults to __USERCERT
    :param cert: str, optional
    :param ckey: host certificate key path, defaults to __USERCERT
    :param ckey: str, optional
    :param force_remote: force retrieving from myproxy, defaults to False
    :param force_remote: bool, optional

    :return: (user_cert, user_key)
    :rtype: tuple
    """

    key = sha1(userDN+activity).hexdigest()

    result_cache = REGION_SHORT.get(key)

    if isinstance(result_cache, NoValue) or force_remote:
        logging.info("Refresh user certificates for %s", userDN)
    else:
        logging.info("User certificates from memcache")
        # TODO: check if still valid
        return result_cache

    myproxy_client = MyProxyClient(hostname=myproxy_server)

    try:
        user_cert, user_key = myproxy_client.logon(key,
                                                   None,
                                                   sslCertFile=cert,
                                                   sslKeyFile=ckey,
                                                   lifetime=168)
    except MyProxyClientGetError:
        logging.error("MyProxy client exception during GET proxy")
        raise
    except MyProxyClientRetrieveError:
        logging.error("MyProxy client exception retrieving proxy")
        raise
    except gaierror:
        logging.error("Invalid myproxy url")
        raise
    except TypeError:
        logging.error("Invalid arguments provided for myproxy client")
        raise

    REGION_SHORT.set(key, (user_cert, user_key))

    return user_cert, user_key


def delegate_proxy(external_host, cert_path=__USERCERT, certkey_path=__USERCERT, ca_path='/etc/grid-security/certificates/', duration_hours=48, timeleft_hours=12):
    """Delegate user proxy to fts server if the lifetime is less than timeleft_hours
    
    :param external_host: FTS server endpoint
    :type external_host: str

    :param cert_path: user/service certificate path, defaults to __USERCERT
    :param cert_path: str, optional
    :param certkey_path: user/service certificate key path, defaults to __USERCERT
    :param certkey_path: str, optional
    :param ca_path: ca path for verification, defaults to '/etc/grid-security/certificates/'
    :param ca_path: str, optional
    :param duration_hours: delegation validity duration in hours, defaults to 48
    :param duration_hours: int, optional
    :param timeleft_hours: minimal delegation time left, defaults to 12
    :param timeleft_hours: int, optional

    :return: delegation ID
    :rtype: str
    """

    logging.info("Delegating proxy %s to %s", cert_path, external_host)

    try:
        context = Context(external_host,
                          ucert=cert_path,
                          ukey=certkey_path,
                          verify=True,
                          capath=ca_path)
        delegation_id = delegate(context,
                                 lifetime=timedelta(hours=duration_hours),
                                 delegate_when_lifetime_lt=timedelta(hours=timeleft_hours))
    except ServerError:
        logging.error("Server side exception during FTS proxy delegation.")
        raise
    except ClientError:
        logging.error("Config side exception during FTS proxy delegation.")
        raise
    except BadEndpoint:
        logging.error("Wrong FTS endpoint: %s", external_host)
        raise

    logging.info("Delegated proxy %s", delegation_id)

    return delegation_id


def get_transfer_baseid_voname(external_host):
    """
    Get transfer VO name from external host.

    :param external_host: FTS server as a string.

    :returns base id as a string and VO name as a string.
    """
    result = (None, None)
    try:
        key = 'voname: %s' % external_host
        result = REGION_SHORT.get(key)
        if type(result) is NoValue:
            logging.debug("Refresh transfer baseid and voname for %s" % external_host)

            r = None
            if external_host.startswith('https://'):
                try:
                    r = requests.get('%s/whoami' % external_host,
                                     verify=False,
                                     cert=(__USERCERT, __USERCERT),
                                     headers={'Content-Type': 'application/json'},
                                     timeout=5)
                except:
                    logging.warn('Could not get baseid and voname from %s - %s' % (external_host, str(traceback.format_exc())))
            else:
                try:
                    r = requests.get('%s/whoami' % external_host,
                                     headers={'Content-Type': 'application/json'},
                                     timeout=5)
                except:
                    logging.warn('Could not get baseid and voname from %s - %s' % (external_host, str(traceback.format_exc())))

            if r and r.status_code == 200:
                baseid = str(r.json()['base_id'])
                voname = str(r.json()['vos'][0])
                result = (baseid, voname)

                REGION_SHORT.set(key, result)

                logging.debug("Get baseid %s and voname %s from %s" % (baseid, voname, external_host))
            else:
                logging.warn("Failed to get baseid and voname from %s, error: %s" % (external_host, r.text if r is not None else r))
                result = (None, None)
    except:
        logging.warning("Failed to get baseid and voname from %s: %s" % (external_host, traceback.format_exc()))
        result = (None, None)
    return result


def __extract_host(transfer_host):
    # graphite does not like the dots in the FQDN
    return urlparse.urlparse(transfer_host).hostname.replace('.', '_')


def submit_transfers(transfers, job_metadata):
    """
    Submit a transfer to FTS3 via JSON.

    :param transfers: Dictionary containing 'request_id', 'src_urls', 'dest_urls', 'filesize', 'md5', 'adler32', 'overwrite', 'job_metadata', 'src_spacetoken', 'dest_spacetoken'
    :param job_metadata: Dictionary containing key/value pairs, for all transfers.
    :param transfer_host: FTS server as a string.
    :returns: List of FTS transfer identifiers
    """

    # Early sanity check
    for transfer in transfers:
        if not transfer['sources'] or transfer['sources'] == []:
            raise Exception('No sources defined')
        transfer['src_urls'] = []
        for source in transfer['sources']:
            # # convert sources from (src_rse, url, src_rse_id, rank) to url
            transfer['src_urls'].append(source[1])

    # FTS3 expects 'davs' as the scheme identifier instead of https
    new_src_urls = []
    new_dst_urls = []
    for transfer in transfers:
        for url in transfer['src_urls']:
            if url.startswith('https'):
                new_src_urls.append(':'.join(['davs'] + url.split(':')[1:]))
            else:
                new_src_urls.append(url)
        for url in transfer['dest_urls']:
            if url.startswith('https'):
                new_dst_urls.append(':'.join(['davs'] + url.split(':')[1:]))
            else:
                new_dst_urls.append(url)

    transfer['src_urls'] = new_src_urls
    transfer['dest_urls'] = new_dst_urls

    # Rewrite the checksums into FTS3 format, prefer adler32 if available
    for transfer in transfers:
        transfer['checksum'] = None
        if 'md5' in transfer.keys() and transfer['md5']:
            transfer['checksum'] = 'MD5:%s' % str(transfer['md5'])
        if 'adler32' in transfer.keys() and transfer['adler32']:
            transfer['checksum'] = 'ADLER32:%s' % str(transfer['adler32'])

    transfer_ids = {}

    job_metadata['issuer'] = 'rucio'
    job_metadata['previous_attempt_id'] = None

    # we have to loop until we get proper fts3 bulk submission
    for transfer in transfers:

        job_metadata['request_id'] = transfer['request_id']

        if 'previous_attempt_id' in transfer.keys():
            job_metadata['previous_attempt_id'] = transfer['previous_attempt_id']

        params_dict = {'files': [{'sources': transfer['src_urls'],
                                  'destinations': transfer['dest_urls'],
                                  'metadata': {'issuer': 'rucio'},
                                  'filesize': int(transfer['filesize']),
                                  'checksum': str(transfer['checksum']),
                                  'activity': str(transfer['activity']),
                                  'selection_strategy': transfer.get('selection_strategy', 'auto')}],
                       'params': {'verify_checksum': True if transfer['checksum'] else False,
                                  'copy_pin_lifetime': transfer['copy_pin_lifetime'] if transfer['copy_pin_lifetime'] else -1,
                                  'bring_online': transfer['bring_online'] if transfer['bring_online'] else None,
                                  'job_metadata': job_metadata,
                                  'overwrite': transfer['overwrite'],
                                  'priority': 3}}

        # Don't put optional & missing keys in the parameters
        if transfer['dest_spacetoken']:
            params_dict['params'].update({'spacetoken': transfer['dest_spacetoken']})
        if transfer['src_spacetoken']:
            params_dict['params'].update({'source_spacetoken': transfer['src_spacetoken']})

        r = None
        params_str = json.dumps(params_dict)

        transfer_host = transfer['external_host']
        if transfer_host.startswith('https://'):
            try:
                ts = time.time()
                r = requests.post('%s/jobs' % transfer_host,
                                  verify=False,
                                  cert=(__USERCERT, __USERCERT),
                                  data=params_str,
                                  headers={'Content-Type': 'application/json'},
                                  timeout=5)
                record_timer('transfertool.fts3.submit_transfer.%s' % __extract_host(transfer_host), (time.time() - ts) * 1000)
            except:
                logging.warn('Could not submit transfer to %s' % transfer_host)
        else:
            try:
                ts = time.time()
                r = requests.post('%s/jobs' % transfer_host,
                                  data=params_str,
                                  headers={'Content-Type': 'application/json'},
                                  timeout=5)
                record_timer('transfertool.fts3.submit_transfer.%s' % __extract_host(transfer_host), (time.time() - ts) * 1000)
            except:
                logging.warn('Could not submit transfer to %s' % transfer_host)

        if r and r.status_code == 200:
            record_counter('transfertool.fts3.%s.submission.success' % __extract_host(transfer_host))
            transfer_ids[transfer['request_id']] = {'external_id': str(r.json()['job_id']),
                                                    'dest_urls': transfer['dest_urls'],
                                                    'external_host': transfer_host}
        else:
            logging.warn("Failed to submit transfer to %s, error: %s" % (transfer_host, r.text if r is not None else r))
            record_counter('transfertool.fts3.%s.submission.failure' % __extract_host(transfer_host))

    return transfer_ids


def get_deterministic_id(external_host, sid):
    """
    Get deterministic FTS job id.

    :param external_host: FTS server as a string.
    :param sid: FTS seed id.
    :returns: FTS transfer identifier.
    """
    baseid, voname = get_transfer_baseid_voname(external_host)
    if baseid is None or voname is None:
        return None
    root = uuid.UUID(baseid)
    atlas = uuid.uuid5(root, voname)
    jobid = uuid.uuid5(atlas, sid)
    return str(jobid)


def submit_bulk_transfers(external_host, files, job_params, timeout=None, user_transfer=False):
    """
    Submit a transfer to FTS3 via JSON.

    :param external_host: FTS server as a string.
    :param files: List of dictionary which for a transfer.
    :param job_params: Dictionary containing key/value pairs, for all transfers.
    :param user_transfer: boolean for user tranfer submission
    :returns: FTS transfer identifier.
    """
    if user_transfer:

        # TODO: logging info 

        try:
            #get DN
            userDN = get_dn_from_scope(files[0]['metadata']['scope'])
        except (HTTPError, ConnectionError, SSLError, Timeout, RequestException, IOError):
            logging.error('Error while getting DN from scope name')
            return None

        try:
            #get proxy
            ucert, ukey = get_user_proxy("myproxy.cern.ch", userDN, files[0]['activity'])
        except (MyProxyClientGetError, MyProxyClientRetrieveError, gaierror, TypeError):
            logging.error('Error while getting DN from scope name')
            return None

        certfile = tempfile.NamedTemporaryFile(delete=False)
        certfile.write(ucert)
        certfile.write(ukey)
        certfile.close()

        __USERCERT = certfile.name

        # TODO: check proxy validity otherwise force download

        try:
            #delegate proxy
            delegate_proxy(external_host, cert_path=certfile.name , certkey_path=certfile.name)
        except (ServerError, ClientError, BadEndpoint):
            logging.error('Error when delegating proxy to FTS')
            os.unlink(__USERCERT)
            return None
        
    # FTS3 expects 'davs' as the scheme identifier instead of https
    for file in files:
        if not file['sources'] or file['sources'] == []:
            if user_transfer:
                os.unlink(__USERCERT)
            raise Exception('No sources defined')

        new_src_urls = []
        new_dst_urls = []
        for url in file['sources']:
            if url.startswith('https'):
                new_src_urls.append(':'.join(['davs'] + url.split(':')[1:]))
            else:
                new_src_urls.append(url)
        for url in file['destinations']:
            if url.startswith('https'):
                new_dst_urls.append(':'.join(['davs'] + url.split(':')[1:]))
            else:
                new_dst_urls.append(url)

        file['sources'] = new_src_urls
        file['destinations'] = new_dst_urls

    transfer_id = None
    expected_transfer_id = None
    if __USE_DETERMINISTIC_ID:
        job_params = job_params.copy()
        job_params["id_generator"] = "deterministic"
        job_params["sid"] = files[0]['metadata']['request_id']
        expected_transfer_id = get_deterministic_id(external_host, job_params["sid"])
        logging.debug("Submit bulk transfers in deterministic mode, sid %s, expected transfer id: %s" % (job_params["sid"], expected_transfer_id))

    # bulk submission
    params_dict = {'files': files, 'params': job_params}
    params_str = json.dumps(params_dict)

    r = None
    if external_host.startswith('https://'):
        try:
            ts = time.time()
            r = requests.post('%s/jobs' % external_host,
                              verify=False,
                              cert=(__USERCERT, __USERCERT),
                              data=params_str,
                              headers={'Content-Type': 'application/json'},
                              timeout=timeout)
            record_timer('transfertool.fts3.submit_transfer.%s' % __extract_host(external_host), (time.time() - ts) * 1000 / len(files))
        except:
            logging.warn('Could not submit transfer to %s - %s' % (external_host, str(traceback.format_exc())))
    else:
        try:
            ts = time.time()
            r = requests.post('%s/jobs' % external_host,
                              data=params_str,
                              headers={'Content-Type': 'application/json'},
                              timeout=timeout)
            record_timer('transfertool.fts3.submit_transfer.%s' % __extract_host(external_host), (time.time() - ts) * 1000 / len(files))
        except:
            logging.warn('Could not submit transfer to %s - %s' % (external_host, str(traceback.format_exc())))

    if r and r.status_code == 200:
        record_counter('transfertool.fts3.%s.submission.success' % __extract_host(external_host), len(files))
        transfer_id = str(r.json()['job_id'])
    else:
        if expected_transfer_id:
            transfer_id = expected_transfer_id
            logging.warn("Failed to submit transfer to %s, will use expected transfer id %s, error: %s" % (external_host, transfer_id, r.text if r is not None else r))
        else:
            logging.warn("Failed to submit transfer to %s, error: %s" % (external_host, r.text if r is not None else r))
        record_counter('transfertool.fts3.%s.submission.failure' % __extract_host(external_host), len(files))

    # TODO: unlink tmp file, check exception
    if user_transfer:
        os.unlink(__USERCERT)

    return transfer_id


def query(transfer_id, transfer_host):
    """
    Query the status of a transfer in FTS3 via JSON.

    :param transfer_id: FTS transfer identifier as a string.
    :param transfer_host: FTS server as a string.
    :returns: Transfer status information as a dictionary.
    """

    job = None

    if transfer_host.startswith('https://'):
        job = requests.get('%s/jobs/%s' % (transfer_host, transfer_id),
                           verify=False,
                           cert=(__USERCERT, __USERCERT),
                           headers={'Content-Type': 'application/json'},
                           timeout=5)
    else:
        job = requests.get('%s/jobs/%s' % (transfer_host, transfer_id),
                           headers={'Content-Type': 'application/json'},
                           timeout=5)
    if job and job.status_code == 200:
        record_counter('transfertool.fts3.%s.query.success' % __extract_host(transfer_host))
        return job.json()

    record_counter('transfertool.fts3.%s.query.failure' % __extract_host(transfer_host))
    raise Exception('Could not retrieve transfer information: %s', job.content)


def query_latest(transfer_host, state, last_nhours=1):
    """
    Query the latest status transfers status in FTS3 via JSON.

    :param transfer_host: FTS server as a string.
    :param state: Transfer state as a string or a dictionary.
    :returns: Transfer status information as a dictionary.
    """

    jobs = None

    if transfer_host.startswith('https://'):
        try:
            whoami = requests.get('%s/whoami' % (transfer_host),
                                  verify=False,
                                  cert=(__USERCERT, __USERCERT),
                                  headers={'Content-Type': 'application/json'})
            if whoami and whoami.status_code == 200:
                delegation_id = whoami.json()['delegation_id']
            else:
                raise Exception('Could not retrieve delegation id: %s', whoami.content)
            state_string = ','.join(state)
            jobs = requests.get('%s/jobs?dlg_id=%s&state_in=%s&time_window=%s' % (transfer_host,
                                                                                  delegation_id,
                                                                                  state_string,
                                                                                  last_nhours),
                                verify=False,
                                cert=(__USERCERT, __USERCERT),
                                headers={'Content-Type': 'application/json'})
        except Exception:
            logging.warn('Could not query latest terminal states from %s' % transfer_host)
    else:
        try:
            whoami = requests.get('%s/whoami' % (transfer_host),
                                  headers={'Content-Type': 'application/json'})
            if whoami and whoami.status_code == 200:
                delegation_id = whoami.json()['delegation_id']
            else:
                raise Exception('Could not retrieve delegation id: %s', whoami.content)
            state_string = ','.join(state)
            jobs = requests.get('%s/jobs?dlg_id=%s&state_in=%s&time_window=%s' % (transfer_host,
                                                                                  delegation_id,
                                                                                  state_string,
                                                                                  last_nhours),
                                headers={'Content-Type': 'application/json'})
        except Exception:
            logging.warn('Could not query latest terminal states from %s' % transfer_host)

    if jobs and (jobs.status_code == 200 or jobs.status_code == 207):
        record_counter('transfertool.fts3.%s.query_latest.success' % __extract_host(transfer_host))
        try:
            jobs_json = jobs.json()
            return jobs_json
        except:
            logging.error("Failed to parse the jobs status %s" % str(traceback.format_exc()))

    record_counter('transfertool.fts3.%s.query.failure' % __extract_host(transfer_host))


def query_details(transfer_id, transfer_host):
    """
    Query the detailed status of a transfer in FTS3 via JSON.

    :param transfer_id: FTS transfer identifier as a string.
    :param transfer_host: FTS server as a string.
    :returns: Detailed transfer status information as a dictionary.
    """

    files = None

    if transfer_host.startswith('https://'):
        files = requests.get('%s/jobs/%s/files' % (transfer_host, transfer_id),
                             verify=False,
                             cert=(__USERCERT, __USERCERT),
                             headers={'Content-Type': 'application/json'},
                             timeout=5)
    else:
        files = requests.get('%s/jobs/%s/files' % (transfer_host, transfer_id),
                             headers={'Content-Type': 'application/json'},
                             timeout=5)
    if files and (files.status_code == 200 or files.status_code == 207):
        record_counter('transfertool.fts3.%s.query_details.success' % __extract_host(transfer_host))
        return files.json()

    record_counter('transfertool.fts3.%s.query_details.failure' % __extract_host(transfer_host))
    return


def format_response(transfer_host, fts_job_response, fts_files_response):
    """
    Format the response format of FTS3 query.

    :param fts_job_response: FTSs job query response.
    :param fts_files_response: FTS3 files query response.
    :returns: formatted response.
    """
    last_src_file = 0
    for i in range(len(fts_files_response)):
        if fts_files_response[i]['file_state'] in [str(FTSState.FINISHED)]:
            last_src_file = i
            break
        if fts_files_response[i]['file_state'] != 'NOT_USED':
            last_src_file = i

    # for multiple sources, if not only the first source is used, we need to mark job_m_replica,
    # then conveyor.common.add_monitor_message will correct the src_rse
    job_m_replica = 'false'
    if last_src_file > 0:
        job_m_replica = 'true'

    if fts_files_response[last_src_file]['start_time'] is None or fts_files_response[last_src_file]['finish_time'] is None:
        duration = 0
    else:
        duration = (datetime.datetime.strptime(fts_files_response[last_src_file]['finish_time'], '%Y-%m-%dT%H:%M:%S') -
                    datetime.datetime.strptime(fts_files_response[last_src_file]['start_time'], '%Y-%m-%dT%H:%M:%S')).seconds

    response = {'new_state': None,
                'transfer_id': fts_job_response.get('job_id'),
                'job_state': fts_job_response.get('job_state', None),
                'file_state': fts_files_response[last_src_file].get('file_state', None),
                'src_url': fts_files_response[last_src_file].get('source_surl', None),
                'dst_url': fts_files_response[last_src_file].get('dest_surl', None),
                'started_at': datetime.datetime.strptime(fts_files_response[last_src_file]['start_time'], '%Y-%m-%dT%H:%M:%S') if fts_files_response[last_src_file]['start_time'] else None,
                'transferred_at': datetime.datetime.strptime(fts_files_response[last_src_file]['finish_time'], '%Y-%m-%dT%H:%M:%S') if fts_files_response[last_src_file]['finish_time'] else None,
                'duration': duration,
                'reason': fts_files_response[last_src_file].get('reason', None),
                'scope': fts_job_response['job_metadata'].get('scope', None),
                'name': fts_job_response['job_metadata'].get('name', None),
                'src_rse': fts_job_response['job_metadata'].get('src_rse', None),
                'dst_rse': fts_job_response['job_metadata'].get('dst_rse', None),
                'request_id': fts_job_response['job_metadata'].get('request_id', None),
                'activity': fts_job_response['job_metadata'].get('activity', None),
                'src_rse_id': fts_job_response['file_metadata'].get('src_rse_id', None),
                'dest_rse_id': fts_job_response['job_metadata'].get('dest_rse_id', None),
                'previous_attempt_id': fts_job_response['job_metadata'].get('previous_attempt_id', None),
                'adler32': fts_job_response['job_metadata'].get('adler32', None),
                'md5': fts_job_response['job_metadata'].get('md5', None),
                'filesize': fts_job_response['job_metadata'].get('filesize', None),
                'external_host': transfer_host,
                'job_m_replica': job_m_replica,
                'details': {'files': fts_job_response['job_metadata']}}
    return response


def format_new_response(transfer_host, fts_job_response, fts_files_response):
    """
    Format the response format of FTS3 query.

    :param fts_job_response: FTSs job query response.
    :param fts_files_response: FTS3 files query response.
    :returns: formatted response.
    """

    resps = {}
    if 'request_id' in fts_job_response['job_metadata']:
        # submitted by old submitter
        request_id = fts_job_response['job_metadata']['request_id']
        resps[request_id] = format_response(transfer_host, fts_job_response, fts_files_response)
    else:
        multi_sources = fts_job_response['job_metadata'].get('multi_sources', False)
        for file_resp in fts_files_response:
            # for multiple source replicas jobs, the file_metadata(request_id) will be the same.
            # The next used file will overwrite the current used one. Only the last used file will return.
            if file_resp['file_state'] == 'NOT_USED':
                continue

            # not terminated job
            if file_resp['file_state'] not in [str(FTSState.FAILED),
                                               str(FTSState.FINISHEDDIRTY),
                                               str(FTSState.CANCELED),
                                               str(FTSState.FINISHED)]:
                continue

            if file_resp['start_time'] is None or file_resp['finish_time'] is None:
                duration = 0
            else:
                duration = (datetime.datetime.strptime(file_resp['finish_time'], '%Y-%m-%dT%H:%M:%S') -
                            datetime.datetime.strptime(file_resp['start_time'], '%Y-%m-%dT%H:%M:%S')).seconds

            request_id = file_resp['file_metadata']['request_id']
            resps[request_id] = {'new_state': None,
                                 'transfer_id': fts_job_response.get('job_id'),
                                 'job_state': fts_job_response.get('job_state', None),
                                 'file_state': file_resp.get('file_state', None),
                                 'src_url': file_resp.get('source_surl', None),
                                 'dst_url': file_resp.get('dest_surl', None),
                                 'started_at': datetime.datetime.strptime(file_resp['start_time'], '%Y-%m-%dT%H:%M:%S') if file_resp['start_time'] else None,
                                 'transferred_at': datetime.datetime.strptime(file_resp['finish_time'], '%Y-%m-%dT%H:%M:%S') if file_resp['finish_time'] else None,
                                 'duration': duration,
                                 'reason': file_resp.get('reason', None),
                                 'scope': file_resp['file_metadata'].get('scope', None),
                                 'name': file_resp['file_metadata'].get('name', None),
                                 'src_type': file_resp['file_metadata'].get('src_type', None),
                                 'dst_type': file_resp['file_metadata'].get('dst_type', None),
                                 'src_rse': file_resp['file_metadata'].get('src_rse', None),
                                 'dst_rse': file_resp['file_metadata'].get('dst_rse', None),
                                 'request_id': file_resp['file_metadata'].get('request_id', None),
                                 'activity': file_resp['file_metadata'].get('activity', None),
                                 'src_rse_id': file_resp['file_metadata'].get('src_rse_id', None),
                                 'dest_rse_id': file_resp['file_metadata'].get('dest_rse_id', None),
                                 'previous_attempt_id': file_resp['file_metadata'].get('previous_attempt_id', None),
                                 'adler32': file_resp['file_metadata'].get('adler32', None),
                                 'md5': file_resp['file_metadata'].get('md5', None),
                                 'filesize': file_resp['file_metadata'].get('filesize', None),
                                 'external_host': transfer_host,
                                 'job_m_replica': multi_sources,
                                 'details': {'files': file_resp['file_metadata']}}

            # multiple source replicas jobs and we found the successful one, it's the final state.
            if multi_sources and file_resp['file_state'] in [str(FTSState.FINISHED)]:
                break
    return resps


def bulk_query_responses(jobs_response, transfer_host):
    if type(jobs_response) is not list:
        jobs_response = [jobs_response]

    responses = {}
    for job_response in jobs_response:
        transfer_id = job_response['job_id']
        if job_response['http_status'] == '200 Ok':
            files_response = job_response['files']
            multi_sources = job_response['job_metadata'].get('multi_sources', False)
            if multi_sources and job_response['job_state'] not in [str(FTSState.FAILED),
                                                                   str(FTSState.FINISHEDDIRTY),
                                                                   str(FTSState.CANCELED),
                                                                   str(FTSState.FINISHED)]:
                # multipe source replicas jobs is still running. should wait
                responses[transfer_id] = {}
                continue

            resps = format_new_response(transfer_host, job_response, files_response)
            responses[transfer_id] = resps
        elif job_response['http_status'] == '404 Not Found':
            # Lost transfer
            responses[transfer_id] = None
        else:
            responses[transfer_id] = Exception('Could not retrieve transfer information(http_status: %s, http_message: %s)' % (job_response['http_status'],
                                                                                                                               job_response['http_message'] if 'http_message' in job_response else None))
    return responses


def bulk_query(transfer_ids, transfer_host, timeout=None):
    """
    Query the status of a bulk of transfers in FTS3 via JSON.

    :param transfer_ids: FTS transfer identifiers as a list.
    :param transfer_host: FTS server as a string.
    :returns: Transfer status information as a dictionary.
    """

    jobs = None

    if type(transfer_ids) is not list:
        transfer_ids = [transfer_ids]

    responses = {}
    fts_session = requests.Session()
    xfer_ids = ','.join(transfer_ids)
    if transfer_host.startswith('https://'):
        jobs = fts_session.get('%s/jobs/%s?files=file_state,dest_surl,finish_time,start_time,reason,source_surl,file_metadata' % (transfer_host, xfer_ids),
                               verify=False,
                               cert=(__USERCERT, __USERCERT),
                               headers={'Content-Type': 'application/json'},
                               timeout=timeout)
    else:
        jobs = fts_session.get('%s/jobs/%s?files=file_state,dest_surl,finish_time,start_time,reason,source_surl,file_metadata' % (transfer_host, xfer_ids),
                               headers={'Content-Type': 'application/json'},
                               timeout=timeout)

    if jobs is None:
        record_counter('transfertool.fts3.%s.bulk_query.failure' % __extract_host(transfer_host))
        for transfer_id in transfer_ids:
            responses[transfer_id] = Exception('Transfer information returns None: %s' % jobs)
    elif jobs.status_code == 200 or jobs.status_code == 207:
        try:
            record_counter('transfertool.fts3.%s.bulk_query.success' % __extract_host(transfer_host))
            jobs_response = jobs.json()
            responses = bulk_query_responses(jobs_response, transfer_host)
        except Exception as error:
            raise Exception("Failed to parse the job response: %s, error: %s" % (str(jobs), str(error)))
    else:
        record_counter('transfertool.fts3.%s.bulk_query.failure' % __extract_host(transfer_host))
        for transfer_id in transfer_ids:
            responses[transfer_id] = Exception('Could not retrieve transfer information: %s', jobs.content)

    return responses


def get_jobs_response(transfer_host, fts_session, jobs_response):
    """
    Parse FTS bulk query response and query details for finished jobs.

    :param transfer_host: FTS server as a string.
    :fts_session: query request as a session.
    :jobs_response: FTS bulk query response as a dict.
    :returns: Transfer status information as a dictionary.
    """

    responses = {}
    for job_response in jobs_response:
        transfer_id = job_response['job_id']
        if job_response['http_status'] == "404 Not Found":
            responses[transfer_id] = None
        elif job_response['http_status'] == "200 Ok":
            if not job_response['job_state'] in (str(FTSState.FAILED),
                                                 str(FTSState.FINISHEDDIRTY),
                                                 str(FTSState.CANCELED),
                                                 str(FTSState.FINISHED)):
                responses[transfer_id] = {}
                responses[transfer_id]['job_state'] = job_response['job_state']
                responses[transfer_id]['new_state'] = None
                responses[transfer_id]['transfer_id'] = transfer_id
            else:
                if transfer_host.startswith("https"):
                    files = fts_session.get('%s/jobs/%s/files' % (transfer_host, transfer_id),
                                            verify=False,
                                            cert=(__USERCERT, __USERCERT),
                                            headers={'Content-Type': 'application/json'})
                else:
                    files = fts_session.get('%s/jobs/%s/files' % (transfer_host, transfer_id),
                                            headers={'Content-Type': 'application/json'})
                if files and (files.status_code == 200 or files.status_code == 207):
                    record_counter('transfertool.fts3.%s.jobs_response.success' % __extract_host(transfer_host))
                    responses[transfer_id] = format_response(transfer_host, job_response, files.json())
                else:
                    record_counter('transfertool.fts3.%s.jobs_response.failure' % __extract_host(transfer_host))
                    responses[transfer_id] = Exception('Could not retrieve files information: %s', files)
    return responses


def new_bulk_query(transfer_ids, transfer_host):
    """
    Query the status of a bulk of transfers in FTS3 via JSON.

    :param transfer_ids: FTS transfer identifiers as a list.
    :param transfer_host: FTS server as a string.
    :returns: Transfer status information as a dictionary.
    """

    responses = {}
    if transfer_host.startswith('https://'):
        fts_session = requests.Session()
        jobs = fts_session.get('%s/jobs/%s' % (transfer_host, ','.join(transfer_ids)),
                               verify=False,
                               cert=(__USERCERT, __USERCERT),
                               headers={'Content-Type': 'application/json'})
        if jobs and (jobs.status_code == 200 or jobs.status_code == 207):
            record_counter('transfertool.fts3.%s.new_bulk.success' % __extract_host(transfer_host))
            jobs_response = jobs.json()
            responses = get_jobs_response(transfer_host, fts_session, jobs_response)
            for transfer_id in transfer_ids:
                if transfer_id not in responses.keys():
                    responses[transfer_id] = None
        else:
            record_counter('transfertool.fts3.%s.new_bulk.failure' % __extract_host(transfer_host))
            for transfer_id in transfer_ids:
                responses[transfer_id] = Exception('Could not retrieve transfer information: %s' % jobs)
    else:
        fts_session = requests.Session()
        jobs = fts_session.get('%s/jobs/%s' % (transfer_host, transfer_id),
                               headers={'Content-Type': 'application/json'})
        if jobs and (jobs.status_code == 200 or jobs.status_code == 207):
            record_counter('transfertool.fts3.%s.new_bulk.success' % __extract_host(transfer_host))
            jobs_response = jobs.json()
            responses = get_jobs_response(transfer_host, fts_session, jobs_response)
            for transfer_id in transfer_ids:
                if transfer_id not in responses.keys():
                    responses[transfer_id] = None
        else:
            record_counter('transfertool.fts3.%s.new_bulk.failure' % __extract_host(transfer_host))
            for transfer_id in transfer_ids:
                responses[transfer_id] = Exception('Could not retrieve transfer information: %s' % jobs)

    return responses


def cancel(transfer_id, transfer_host):
    """
    Cancel a transfer that has been submitted to FTS via JSON.

    :param transfer_id: FTS transfer identifier as a string.
    :param transfer_host: FTS server as a string.
    """

    job = None

    if transfer_host.startswith('https://'):
        job = requests.delete('%s/jobs/%s' % (transfer_host, transfer_id),
                              verify=False,
                              cert=(__USERCERT, __USERCERT),
                              headers={'Content-Type': 'application/json'})
    else:
        job = requests.delete('%s/jobs/%s' % (transfer_host, transfer_id),
                              headers={'Content-Type': 'application/json'})
    if job and job.status_code == 200:
        record_counter('transfertool.fts3.%s.cancel.success' % __extract_host(transfer_host))
        return job.json()

    record_counter('transfertool.fts3.%s.cancel.failure' % __extract_host(transfer_host))
    raise Exception('Could not cancel transfer: %s', job.content)


def update_priority(transfer_id, transfer_host, priority):
    """
    Update the priority of a transfer that has been submitted to FTS via JSON.

    :param transfer_id: FTS transfer identifier as a string.
    :param transfer_host: FTS server as a string.
    :param priority: FTS job priority as an integer from 1 to 5.
    """

    job = None
    params_dict = {"params": {"priority": priority}}
    params_str = json.dumps(params_dict)

    if transfer_host.startswith('https://'):
        job = requests.post('%s/jobs/%s' % (transfer_host, transfer_id),
                            verify=False,
                            data=params_str,
                            cert=(__USERCERT, __USERCERT),
                            headers={'Content-Type': 'application/json'},
                            timeout=3)
    else:
        job = requests.post('%s/jobs/%s' % (transfer_host, transfer_id),
                            data=params_str,
                            headers={'Content-Type': 'application/json'},
                            timeout=3)
    if job and job.status_code == 200:
        record_counter('transfertool.fts3.%s.update_priority.success' % __extract_host(transfer_host))
        return job.json()

    record_counter('transfertool.fts3.%s.update_priority.failure' % __extract_host(transfer_host))
    raise Exception('Could not update priority of transfer: %s', job.content)


def whoami(transfer_host):
    """
    Returns credential information from the FTS3 server.

    :param transfer_host: FTS server as a string.

    :returns: Credentials as stored by the FTS3 server as a dictionary.
    """

    r = None

    if transfer_host.startswith('https://'):
        r = requests.get('%s/whoami' % transfer_host,
                         verify=False,
                         cert=(__USERCERT, __USERCERT),
                         headers={'Content-Type': 'application/json'})
    else:
        r = requests.get('%s/whoami' % transfer_host,
                         headers={'Content-Type': 'application/json'})

    if r and r.status_code == 200:
        record_counter('transfertool.fts3.%s.whoami.success' % __extract_host(transfer_host))
        return r.json()

    record_counter('transfertool.fts3.%s.whoami.failure' % __extract_host(transfer_host))
    raise Exception('Could not retrieve credentials: %s', r.content)


def version(transfer_host):
    """
    Returns FTS3 server information.

    :param transfer_host: FTS server as a string.

    :returns: FTS3 server information as a dictionary.
    """

    r = None

    if transfer_host.startswith('https://'):
        r = requests.get('%s/' % transfer_host,
                         verify=False,
                         cert=(__USERCERT, __USERCERT),
                         headers={'Content-Type': 'application/json'})
    else:
        r = requests.get('%s/' % transfer_host,
                         headers={'Content-Type': 'application/json'})

    if r and r.status_code == 200:
        record_counter('transfertool.fts3.%s.version.success' % __extract_host(transfer_host))
        return r.json()

    record_counter('transfertool.fts3.%s.version.failure' % __extract_host(transfer_host))
    raise Exception('Could not retrieve version: %s', r.content)
