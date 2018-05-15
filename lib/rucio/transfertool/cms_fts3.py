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
import logging
import os
import sys
import requests
import subprocess
import tempfile
import urlparse

from datetime import timedelta
from hashlib import sha1
from socket import gaierror
from requests.packages.urllib3 import disable_warnings  # pylint: disable=import-error

from dogpile.cache import make_region
from dogpile.cache.api import NoValue

from fts3.rest.client.exceptions import BadEndpoint, ClientError, ServerError
import fts3.rest.client.easy as fts
from rucio.common.config import config_get, config_get_bool
from rucio.core.monitor import record_counter
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

__USE_DETERMINISTIC_ID = config_get_bool('conveyor', 'use_deterministic_id', False, False)

REGION_SHORT = make_region().configure('dogpile.cache.memory',
                                       expiration_time=1800)


class CMSUserTransfer(FTS3Transfertool):
    """CMS implementation of a Rucio FTS3 transfertool
    """

    def __init__(self, external_host):
        """
        Initializes the transfertool

        :param external_host:   The external host where the transfertool API is running
        """
        super(CMSUserTransfer, self).__init__(external_host)

        self.hostcert = config_get('conveyor', 'hostcert', False, None)
        self.hostkey = config_get('conveyor', 'hostkey', False, None)
        self.deterministic = config_get_bool('conveyor', 'use_deterministic_id', False, False)
        self.cmsweb_endpoint = config_get('conveyor', 'cmsweb_endpoint', False, 'cmsweb.cern.ch')

    # Public methods part of the common interface

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

        key = sha1(userDN + "_" + self.cmsweb_endpoint).hexdigest()

        result_cache = REGION_SHORT.get(key)
        validity_h = 2

        if isinstance(result_cache, NoValue) or force_remote:
            logging.info("Refresh user certificates for %s", userDN)
        else:
            logging.info("User certificates from memcache. Checking validity...")
            try:
                certfile = tempfile.NamedTemporaryFile(delete=True)
                for crt in result_cache:
                    certfile.write(crt)
                command = 'grid-proxy-info -f %s -e -h %s' % (certfile.name, validity_h)
                logging.debug('grid-proxy-info -f %s  -e -h %s' % (certfile.name, validity_h))
                subprocess.check_call(command, shell=True)

                certfile.close()
            except subprocess.CalledProcessError as ex:
                certfile.close()
                if ex.returncode == 1:
                    logging.warn("Credential timeleft < %sh", validity_h)
                else:
                    logging.exception("Credential validity check failed")
            else:
                return result_cache

        logging.info("myproxy_client = MyProxyClient(hostname='myproxy.cern.ch'")
        logging.info("myproxy_client.logon('%s', None, sslCertFile='%s', sslKeyFile='%s')", key, cert, ckey)

        myproxy_client = MyProxyClient(hostname=myproxy_server)
        try:
            cert = myproxy_client.logon(key,
                                        None,
                                        sslCertFile=cert,
                                        sslKeyFile=ckey
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

        REGION_SHORT.set(key, cert)

        return cert

    def prepare_credentials(self, files):
        """Retrieve and check user proxy
        
        :param files: list of files to be transferred
        :type files: list
        :return: path to the proxy
        :rtype: string
        """

        try:
            logging.info("Contacting cmsweb for user DN")
            # get DN
            logging.info("scope: %s", files[0]['metadata']['scope'])
            userDN = self.get_dn_from_scope('user.dciangot')
        except (HTTPError, ConnectionError, SSLError, Timeout, RequestException, IOError):
            logging.exception('Error while getting DN from scope name')
            return None

        logging.info("DN: %s", userDN)
        try:
            # get proxy
            cert = self.get_user_proxy("px502.cern.ch", userDN, files[0]['activity'])
        except (MyProxyClientGetError, MyProxyClientRetrieveError, gaierror, TypeError):
            logging.exception('Error while getting DN from scope name')
            return None

        certfile = tempfile.NamedTemporaryFile(delete=False)
        for crt in cert:
            certfile.write(crt)
        certfile.close()

        cmd_list = []
        cmd_list.append('X509_USER_PROXY=%s' % certfile.name)
        cmd_list.append('voms-proxy-init -noregen -voms %s -out %s -valid %s %s'
                        % ('cms', certfile.name, '192:00', '-rfc'))
        cmd = ' '.join(cmd_list)

        usercert = certfile.name
        try:
            # add voms cms attributes
            subprocess.check_call(cmd, shell=True)
        except subprocess.CalledProcessError:
            os.unlink(usercert)
            logging.exception("Voms cms attribute failed")
            return None
        
        return usercert

    def submit(self, files, job_params, timeout=None):
        """
        Submit a transfer to FTS3 via JSON.
        :param external_host: FTS server as a string.
        :param files: List of dictionary which for a transfer.
        :param job_params: Dictionary containing key/value pairs, for all transfers.
        :param user_transfer: boolean for user tranfer submission
        :returns: FTS transfer identifier.
        """
        usercert = self.prepare_credentials(files)

        if not usercert:
            logging.error('Unable to prepare credentials.')
            return None

        # FTS3 expects 'davs' as the scheme identifier instead of https
        for file in files:
            if not file['sources'] or file['sources'] == []:
                os.unlink(usercert)
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
        jobID = None
        transfers = []
        for _file in files:
            # TODO: add file metadata
            for source, destination in zip(_file["sources"], _file["destinations"]):
                print (source, destination)
                transfers.append(fts.new_transfer(source, destination,
                                                  activity=_file['activity'],
                                                  metadata=_file['metadata'],
                                                  filesize=_file['filesize'],
                                                  checksum=_file['checksum']))

        try:
            # TODO: put ca_path var
            context = fts.Context(self.external_host,
                                  ucert=usercert,
                                  ukey=usercert,
                                  verify=True,
                                  capath='/etc/grid-security/certificates/')

            job = fts.new_job(transfers,
                              overwrite=job_params['overwrite'],
                              verify_checksum=job_params['verify_checksum'],
                              metadata=job_params['job_metadata'],
                              copy_pin_lifetime=job_params['copy_pin_lifetime'],
                              bring_online=job_params['bring_online'],
                              source_spacetoken=None,
                              spacetoken=None,
                              priority=job_params['priority'])
            # TODO: s3alternate?

            # TODO: var duration_hours=48, timeleft_hours=12
            # submission for bindings checks the delegation, so the previous delegation part is useless here
            jobID = fts.submit(context, job, delegation_lifetime=timedelta(hours=48), delegate_when_lifetime_lt=timedelta(hours=12))
        except ServerError:
            logging.error("Server side exception during FTS job submission.")
            return None
        except ClientError:
            logging.error("Client side exception during FTS job submission.")
            return None

        if jobID:
            record_counter('transfertool.fts3.%s.submission.success' % self.__extract_host(self.external_host), len(files))
            transfer_id = jobID
        else:
            transfer_id = jobID
            logging.error("Unexpected failure during FTS job submission.")
            record_counter('transfertool.fts3.%s.submission.failure' % self.__extract_host(self.external_host), len(files))

        os.unlink(usercert)

        return transfer_id

    @staticmethod
    def __extract_host(external_host):
        # graphite does not like the dots in the FQDN
        return urlparse.urlparse(external_host).hostname.replace('.', '_')
