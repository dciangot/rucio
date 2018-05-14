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

from __future__ import absolute_import
import json
import logging
import os
import sys
import time
import traceback
import requests
import subprocess
import tempfile
import urlparse

from hashlib import sha1
from socket import gaierror
from requests.packages.urllib3 import disable_warnings  # pylint: disable=import-error

from dogpile.cache import make_region
from dogpile.cache.api import NoValue

from fts3.rest.client.exceptions import BadEndpoint, ClientError, ServerError
from rucio.common.config import config_get, config_get_bool
from rucio.core.monitor import record_counter, record_timer
from myproxy.client import MyProxyClient, MyProxyClientGetError, MyProxyClientRetrieveError
from requests.exceptions import Timeout, RequestException, ConnectionError, SSLError, HTTPError

from rucio.transfertool.fts3 import FTS3Transfertool


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


class CMSUserTransfer(FTS3Transfertool):
    """CMS implementation of a Rucio FTS3 transfertool
    """

    def get_dn_from_scope(self, scope, ca_path='/etc/grid-security/certificates/', sitedb_host='https://cmsweb.cern.ch/sitedb/data/prod/people'):
        """Retrieve DN for user scope

        SiteDB api response example:
        {"desc": {"columns": ["username", "email", "forename", "surname", "dn", "phone1", "phone2", "im_handle"]},
        "result": [["diego", "diego@cern.ch", "Diego", "da Silva Gomes", "/DC=org/DC=doegrids/OU=People/CN=Diego", "+41 XXXX", "+41 22 76 XXXX", "gtalk:geneguvo@gmail.com"]]
        }

        :param scope: Rucio scope
        :type scope: str

        :param ca_path: ca path for verification, defaults to '/etc/grid-security/certificates/'
        :param ca_path: str, optional
        :param sitedb_host: sitedb endpoint url, defaults to 'https://cmsweb.cern.ch/sitedb/data/prod/people'
        :param sitedb_host: str, optional

        :return: user DN or None if failed
        :rtype: str
        """

        try:
            cert_path = self.cert[0]
            certkey_path = self.cert[1]
            username = scope.split(".")[1]

            result_cache = REGION_SHORT.get(username)
            if isinstance(result_cache, NoValue):
                logging.info("Refresh user certificates for %s", username)
            else:
                logging.info("Serving DN from the cache...")
                return result_cache

            request_data = {'match': username}

            logging.info("Cmsweb request: %s %s %s %s", sitedb_host, request_data, cert_path, certkey_path)

            resp = requests.get('%s' % sitedb_host,
                                params=request_data,
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
                REGION_SHORT.set(username, value)
                return value

        return None

    def get_user_proxy(self, myproxy_server, userDN, activity, force_remote=False):
        """Retrieve user proxy for the correct activity from myproxy and save it in memcache

        :param myproxy_server: myproxy server hostname
        :type myproxy_server: str
        :param userDN: user DN
        :type userDN: str
        :param activity: Rucio activity
        :type activity: str

        :param force_remote: force retrieving from myproxy, defaults to False
        :param force_remote: bool, optional

        :return: (user_cert, user_key)
        :rtype: tuple
        """
        cert = self.hostcert
        ckey = self.hostkey

        key = sha1(userDN + activity).hexdigest()

        result_cache = REGION_SHORT.get(key)
        validity_h = 24

        if isinstance(result_cache, NoValue) or force_remote:
            logging.info("Refresh user certificates for %s", userDN)
        else:
            logging.info("User certificates from memcache. Checking validity...")
            # TODO: configure validity
            try:
                subprocess.check_call('grid-proxy-info --cert %s --key %s -e -h %s', result_cache[0], result_cache[1], validity_h)
            except subprocess.CalledProcessError as ex:
                if ex.returncode == 1:
                    logging.warn("Credential timeleft < %sh", validity_h)
                else:
                    logging.warn("Credential validity check failed")
            else:
                return result_cache

        logging.info("myproxy_client = MyProxyClient(hostname='myproxy.cern.ch'")
        logging.info("myproxy_client.logon('%s', None, sslCertFile='%s', sslKeyFile='%s')", key, cert, ckey)
        myproxy_client = MyProxyClient(hostname=myproxy_server)

        try:
            user_cert, user_key = myproxy_client.logon(key,
                                                       None,
                                                       sslCertFile=cert,
                                                       sslKeyFile=ckey,
                                                       lifetime=168,
                                                       )
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

    def submit(self, files, job_params, timeout=None):
        """
        Submit a transfer to FTS3 via JSON.
        :param external_host: FTS server as a string.
        :param files: List of dictionary which for a transfer.
        :param job_params: Dictionary containing key/value pairs, for all transfers.
        :param user_transfer: boolean for user tranfer submission
        :returns: FTS transfer identifier.
        """

        # TODO: logging info
        try:
            logging.info("Contacting cmsweb for user DN")
            external_host = self.external_host
            # get DN
            logging.info("scope: %s", files[0]['metadata']['scope'])
            userDN = self.get_dn_from_scope('user.dciangot')
        except (HTTPError, ConnectionError, SSLError, Timeout, RequestException, IOError):
            logging.exception('Error while getting DN from scope name')
            return None
        except:
            logging.exception('Error while getting DN from scope name')
            return None

        logging.info("DN: %s", userDN)
        try:
            # get proxy
            ucert, ukey = self.get_user_proxy("px502.cern.ch", userDN, files[0]['activity'])
        except (MyProxyClientGetError, MyProxyClientRetrieveError, gaierror, TypeError):
            logging.exception('Error while getting DN from scope name')
            ucert, ukey = ('','')
            #return 


        certfile = tempfile.NamedTemporaryFile(delete=False)
        certfile.write(ucert)
        certfile.write(ukey)
        certfile.close()

        #__USERCERT = certfile.name
        __USERCERT = self.cert[0]

        try:
            # delegate proxy
            #FTS3Transfertool(external_host=external_host).delegate_proxy()
            self.delegate_proxy()
        except (ServerError, ClientError, BadEndpoint):
            logging.error('Error when delegating proxy to FTS')
            #os.unlink(__USERCERT)
            return None

        # FTS3 expects 'davs' as the scheme identifier instead of https
        for file in files:
            if not file['sources'] or file['sources'] == []:
                #os.unlink(__USERCERT)
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
        if self.deterministic: 
            job_params = job_params.copy()
            job_params["id_generator"] = "deterministic"
            job_params["sid"] = files[0]['metadata']['request_id']
            expected_transfer_id = self.__get_deterministic_id(job_params["sid"])
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
                record_timer('transfertool.fts3.submit_transfer.%s' % self.__extract_host(self.external_host), (time.time() - ts) * 1000 / len(files))
            except:
                logging.warn('Could not submit transfer to %s - %s' % (external_host, str(traceback.format_exc())))
        else:
            try:
                ts = time.time()
                r = requests.post('%s/jobs' % external_host,
                                  data=params_str,
                                  headers={'Content-Type': 'application/json'},
                                  timeout=timeout)
                record_timer('transfertool.fts3.submit_transfer.%s' % self.__extract_host(self.external_host), (time.time() - ts) * 1000 / len(files))
            except:
                logging.warn('Could not submit transfer to %s - %s' % (external_host, str(traceback.format_exc())))

        if r and r.status_code == 200:
            record_counter('transfertool.fts3.%s.submission.success' % self.__extract_host(self.external_host), len(files))
            transfer_id = str(r.json()['job_id'])
        else:
            if expected_transfer_id:
                transfer_id = expected_transfer_id
                logging.warn("Failed to submit transfer to %s, will use expected transfer id %s, error: %s" % (external_host, transfer_id, r.text if r is not None else r))
            else:
                logging.warn("Failed to submit transfer to %s, error: %s" % (external_host, r.text if r is not None else r))
            record_counter('transfertool.fts3.%s.submission.failure' % self.__extract_host(self.external_host), len(files))

        #os.unlink(__USERCERT)

        return transfer_id

    @staticmethod
    def __extract_host(external_host):
        # graphite does not like the dots in the FQDN
        return urlparse.urlparse(external_host).hostname.replace('.', '_')
