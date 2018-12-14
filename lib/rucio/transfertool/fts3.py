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
# - Martin Barisits, <martin.barisits@cern.ch>, 2017-2018
# - Eric Vaandering, <ewv@fnal.gov>, 2018
# - Diego Ciangottini <diego.ciangottini@pg.infn.it>, 2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
#
# PY3K COMPATIBLE

from __future__ import absolute_import
import datetime
import json
try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError
import logging
import sys
import time
import traceback
try:
    from urlparse import urlparse  # py2
except ImportError:
    from urllib.parse import urlparse  # py3
import uuid

import requests
from requests.adapters import ReadTimeout
from requests.packages.urllib3 import disable_warnings  # pylint: disable=import-error

from dogpile.cache import make_region
from dogpile.cache.api import NoValue

import fts3.rest.client.easy as fts  # pylint: disable=no-name-in-module,import-error
from fts3.rest.client.exceptions import BadEndpoint, ClientError, ServerError, NotFound  # pylint: disable=no-name-in-module,import-error
from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import TransferToolTimeout, TransferToolWrongAnswer
from rucio.core.monitor import record_counter, record_timer
from rucio.db.sqla.constants import FTSState
from rucio.transfertool.transfertool import Transfertool

logging.getLogger("requests").setLevel(logging.CRITICAL)
disable_warnings()

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

REGION_SHORT = make_region().configure('dogpile.cache.memory',
                                       expiration_time=1800)

# TODO: implement RUCIO exceptions: check request.py _handle_error in fts-rest
# TODO: change timeout def (in init now) on submitter/everywhere
# TODO: implement in FTS pyrest the remaining uncovered functions


class FTS3Transfertool(Transfertool):
    """
    FTS3 implementation of a Rucio transfertool
    """

    def __init__(self, external_host, ca_path='/etc/grid-security/certificates/', duration_hours=96, timeleft_hours=72, timeout=120):
        """
        Initializes the transfertool

        :param external_host:   The external host where the transfertool API is running
        :param ca_path: ca path for verification, defaults to '/etc/grid-security/certificates/'
        :param ca_path: str, optional
        :param duration_hours: delegation validity duration in hours, defaults to 96
        :param duration_hours: int, optional
        :param timeleft_hours: minimal delegation time left, defaults to 72
        :param timeleft_hours: int, optional
        """
        usercert = config_get('conveyor', 'usercert', False, None)

        self.delegation_duration_h = duration_hours
        self.delegation_timeleft_h = timeleft_hours

        self.deterministic_id = config_get_bool('conveyor', 'use_deterministic_id', False, False)
        super(FTS3Transfertool, self).__init__(external_host, ca_path='/etc/grid-security/certificates/')
        if self.external_host.startswith('https://'):
            self.cert = (usercert, usercert)
            self.verify = False
        else:
            self.cert = None
            self.verify = True  # True is the default setting of a requests.* method

        self.ca_path = ca_path

        # TODO: are we sure that self.verify policy is correct
        try:
            self.context = fts.Context(self.external_host,
                                       ucert=self.cert[0],
                                       ukey=self.cert[1],
                                       verify=self.verify,
                                       capath=self.ca_path,
                                       timeout=timeout)
        except Exception as ex:
            raise ex

    # Public methods part of the common interface

    def delegate_proxy(self, proxy, ca_path='/etc/grid-security/certificates/'):
        """Delegate user proxy to fts server if the lifetime is less than timeleft_hours

        :param proxy: proxy to be delegated
        :param proxy: str
        :param ca_path: ca path for verification, defaults to '/etc/grid-security/certificates/'
        :param ca_path: str, optional

        :return: delegation ID
        :rtype: str
        """
        logging.info("Delegating proxy %s to %s", proxy, self.external_host)
        start_time = time.time()

        try:
            context = fts.Context(self.external_host,
                                  ucert=proxy,
                                  ukey=proxy,
                                  verify=self.verify,
                                  capath=ca_path)
            delegation_id = fts.delegate(context,
                                         lifetime=datetime.timedelta(hours=self.delegation_duration_h),
                                         delegate_when_lifetime_lt=datetime.timedelta(hours=self.delegation_timeleft_h))
            record_timer('transfertool.fts3.delegate_proxy.success.%s' % proxy, (time.time() - start_time))
        except ServerError:
            logging.error("Server side exception during FTS proxy delegation.")
            record_timer('transfertool.fts3.delegate_proxy.fail.%s' % proxy, (time.time() - start_time))
            raise
        except ClientError:
            logging.error("Config side exception during FTS proxy delegation.")
            record_timer('transfertool.fts3.delegate_proxy.fail.%s' % proxy, (time.time() - start_time))
            raise
        except BadEndpoint:
            logging.error("Wrong FTS endpoint: %s", self.external_host)
            record_timer('transfertool.fts3.delegate_proxy.fail.%s' % proxy, (time.time() - start_time))
            raise

        logging.info("Delegated proxy %s", delegation_id)

        return delegation_id, self.context

    def submit(self, files, job_params, timeout=None):
        """
        Submit transfers to FTS3 via JSON.

        :param files:        List of dictionaries describing the file transfers.
        :param job_params:   Dictionary containing key/value pairs, for all transfers.
        :param timeout:      Timeout in seconds.
        :returns:            FTS transfer identifier.
        """

        transfers = []
        # FTS3 expects 'davs' as the scheme identifier instead of https
        for transfer_file in files:
            if not transfer_file['sources'] or transfer_file['sources'] == []:
                raise Exception('No sources defined')

            new_src_urls = []
            new_dst_urls = []
            for url in transfer_file['sources']:
                if url.startswith('https'):
                    new_src_urls.append(':'.join(['davs'] + url.split(':')[1:]))
                else:
                    new_src_urls.append(url)
            for url in transfer_file['destinations']:
                if url.startswith('https'):
                    new_dst_urls.append(':'.join(['davs'] + url.split(':')[1:]))
                else:
                    new_dst_urls.append(url)

            transfer_file['sources'] = new_src_urls
            transfer_file['destinations'] = new_dst_urls

            for source, destination in zip(transfer_file["sources"], transfer_file["destinations"]):
                transfers.append(fts.new_transfer(source, destination,
                                                  activity=transfer_file['activity'],
                                                  metadata=transfer_file['metadata'],
                                                  filesize=transfer_file['filesize'],
                                                  checksum=transfer_file['checksum'],
                                                  selection_strategy=transfer_file['selection_strategy'])
                                 )

        transfer_id = None
        expected_transfer_id = None
        if self.deterministic_id:
            job_params = job_params.copy()
            job_params["id_generator"] = "deterministic"
            job_params["sid"] = files[0]['metadata']['request_id']
            expected_transfer_id = self.__get_deterministic_id(job_params["sid"])
            logging.debug("Submit bulk transfers in deterministic mode, sid %s, expected transfer id: %s", job_params["sid"], expected_transfer_id)

        try:
            start_time = time.time()
            job = fts.new_job(transfers,
                              overwrite=job_params['overwrite'],
                              verify_checksum=job_params['verify_checksum'],
                              metadata=job_params['job_metadata'],
                              copy_pin_lifetime=job_params['copy_pin_lifetime'],
                              bring_online=job_params['bring_online'],
                              source_spacetoken=None,
                              spacetoken=None,
                              priority=job_params['priority'],
                              id_generator=job_params['id_generator'],
                              s3alternate=job_params['s3alternate'])

            record_timer('transfertool.fts3.submit_transfer.%s' % self.__extract_host(self.external_host), (time.time() - start_time) * 1000 / len(files))
            transfer_id = fts.submit(self.context,
                                     job,
                                     delegation_lifetime=datetime.timedelta(hours=self.delegation_duration_h),
                                     delegate_when_lifetime_lt=datetime.timedelta(hours=self.delegation_timeleft_h))
            record_counter('transfertool.fts3.%s.submission.success' % self.__extract_host(self.external_host), len(files))
        except ServerError:
            logging.error("Server side exception during FTS job submission.")
            record_counter('transfertool.fts3.%s.submission.failure' % self.__extract_host(self.external_host), len(files))
            return None
        except ClientError:
            logging.error("Client side exception during FTS job submission.")
            record_counter('transfertool.fts3.%s.submission.failure' % self.__extract_host(self.external_host), len(files))
            return None
        except BadEndpoint:
            logging.error("Wrong FTS endpoint: %s", self.external_host)
            record_counter('transfertool.fts3.%s.submission.failure' % self.__extract_host(self.external_host), len(files))
            return None
        except Exception as error:
            logging.warn('Could not submit transfer to %s - %s' % (self.external_host, str(error)))
            record_counter('transfertool.fts3.%s.submission.failure' % self.__extract_host(self.external_host), len(files))
            return None

        return transfer_id

    def cancel(self, transfer_ids, timeout=None):
        """
        Cancel transfers that have been submitted to FTS3.

        :param transfer_ids: FTS transfer identifiers as list of strings.
        :param timeout:      Timeout in seconds.
        :returns:            True if cancellation was successful.
        """

        if len(transfer_ids) > 1:
            raise NotImplementedError('Bulk cancelling not implemented')
        transfer_id = transfer_ids[0]

        job = None

        try:
            job = fts.cancel(self.context, transfer_id)
            record_counter('transfertool.fts3.%s.cancel.success' % self.__extract_host(self.external_host))
        except Exception as ex:
            record_counter('transfertool.fts3.%s.cancel.failure' % self.__extract_host(self.external_host))
            raise ex

        return job

    # TODO: to be ported in python bindings
    def update_priority(self, transfer_id, priority, timeout=None):
        """
        Update the priority of a transfer that has been submitted to FTS via JSON.

        :param transfer_id: FTS transfer identifier as a string.
        :param priority:    FTS job priority as an integer from 1 to 5.
        :param timeout:     Timeout in seconds.
        :returns:           True if update was successful.
        """

        job = None
        params_dict = {"params": {"priority": priority}}
        params_str = json.dumps(params_dict)

        job = requests.post('%s/jobs/%s' % (self.external_host, transfer_id),
                            verify=self.verify,
                            data=params_str,
                            cert=self.cert,
                            headers={'Content-Type': 'application/json'},
                            timeout=timeout)  # TODO set to 3 in conveyor

        if job and job.status_code == 200:
            record_counter('transfertool.fts3.%s.update_priority.success' % self.__extract_host(self.external_host))
            return job.json()

        record_counter('transfertool.fts3.%s.update_priority.failure' % self.__extract_host(self.external_host))
        raise Exception('Could not update priority of transfer: %s', job.content)

    def query(self, transfer_ids, details=False, timeout=None):
        """
        Query the status of a transfer in FTS3 via JSON.

        :param transfer_ids: FTS transfer identifiers as list of strings.
        :param details:      Switch if detailed information should be listed.
        :param timeout:      Timeout in seconds.
        :returns:            Transfer status information as a list of dictionaries.
        """

        if len(transfer_ids) > 1:
            raise NotImplementedError('FTS3 transfertool query not bulk ready')

        transfer_id = transfer_ids[0]
        if details:
            return self.__query_details(transfer_id=transfer_id)

        try:
            job_status = fts.get_job_status(self.context, transfer_id)
            record_counter('transfertool.fts3.%s.query.success' % self.__extract_host(self.external_host))
        except NotFound as ex:
            record_counter('transfertool.fts3.%s.query.failure' % self.__extract_host(self.external_host))
            logging.error("Transfer information not found.")
            raise ex
        except ServerError as ex:
            record_counter('transfertool.fts3.%s.query.failure' % self.__extract_host(self.external_host))
            logging.error("Server side exception during FTS job submission.")
            raise ex
        except ClientError as ex:
            logging.error("Client side exception during FTS job submission.")
            record_counter('transfertool.fts3.%s.query.failure' % self.__extract_host(self.external_host))
            raise ex
        except BadEndpoint as ex:
            logging.error("Wrong FTS endpoint: %s", self.external_host)
            record_counter('transfertool.fts3.%s.query.failure' % self.__extract_host(self.external_host))
            raise ex

        return job_status

    # Public methods, not part of the common interface specification (FTS3 specific)

    def whoami(self):
        """
        Returns credential information from the FTS3 server.

        :returns: Credentials as stored by the FTS3 server as a dictionary.
        """
        try:
            whoami = fts.whoami(self.context)
            record_counter('transfertool.fts3.%s.whoami.success' % self.__extract_host(self.external_host))
        except Exception as ex:
            record_counter('transfertool.fts3.%s.whoami.failure' % self.__extract_host(self.external_host))
            raise ex

        return whoami

    def version(self):
        """
        Returns FTS3 server information.

        :returns: FTS3 server information as a dictionary.
        """

        get_result = None

        get_result = requests.get('%s/' % self.external_host,
                                  verify=self.verify,
                                  cert=self.cert,
                                  headers={'Content-Type': 'application/json'})

        if get_result and get_result.status_code == 200:
            record_counter('transfertool.fts3.%s.version.success' % self.__extract_host(self.external_host))
            return get_result.json()

        record_counter('transfertool.fts3.%s.version.failure' % self.__extract_host(self.external_host))
        raise Exception('Could not retrieve version: %s', get_result.content)

    # TODO: to be ported in python bindings
    def query_latest(self, state, last_nhours=1):
        """
        Query the latest status transfers status in FTS3 via JSON.

        :param state: Transfer state as a string or a dictionary.
        :returns: Transfer status information as a dictionary.
        """

        jobs = None

        try:
            jobs = fts.get_recent_jobs_statutes(state, last_nhours)
            record_counter('transfertool.fts3.%s.query_latest.success' % self.__extract_host(self.external_host))
            return jobs
        except Exception as ex:
            record_counter('transfertool.fts3.%s.query.failure' % self.__extract_host(self.external_host))
            raise ex

    def bulk_query(self, transfer_ids):
        """
        Query the status of a bulk of transfers in FTS3 via JSON.

        :param transfer_ids: FTS transfer identifiers as a list.
        :returns: Transfer status information as a dictionary.
        """

        if not isinstance(transfer_ids, list):
            transfer_ids = [transfer_ids]

        try:
            jobs_response = fts.get_jobs_statuses(self.context, transfer_ids, list_files=True)
            record_counter('transfertool.fts3.%s.bulk_query.success' % self.__extract_host(self.external_host))
            responses = self.__bulk_query_responses(jobs_response)
        except NotFound as ex:
            record_counter('transfertool.fts3.%s.bulk_query.failure' % self.__extract_host(self.external_host))
            logging.error("Transfer information not found.")
            raise ex
        except ServerError as ex:
            record_counter('transfertool.fts3.%s.bulk_query.failure' % self.__extract_host(self.external_host))
            logging.error("Server side exception during FTS job query.")
            raise ex
        except ClientError as ex:
            logging.error("Client side exception during FTS job query.")
            record_counter('transfertool.fts3.%s.bulk_query.failure' % self.__extract_host(self.external_host))
            raise ex
        except BadEndpoint as ex:
            logging.error("Wrong FTS endpoint: %s", self.external_host)
            record_counter('transfertool.fts3.%s.bulk_query.failure' % self.__extract_host(self.external_host))
            raise ex

        return responses

    def list_se_status(self):
        """
        Get the list of banned Storage Elements.

        :returns: Detailed dictionnary of banned Storage Elements.
        """

        try:
            result = requests.get('%s/ban/se' % self.external_host,
                                  verify=self.verify,
                                  cert=self.cert,
                                  headers={'Content-Type': 'application/json'},
                                  timeout=None)
        except Exception as error:
            raise Exception('Could not retrieve transfer information: %s', error)
        if result and result.status_code == 200:
            return result.json()
        raise Exception('Could not retrieve transfer information: %s', result.content)

    # TODO: to be ported in python bindings
    def set_se_status(self, storage_element, message, ban=True, timeout=None):
        """
        Ban a Storage Element. Used when a site is in downtime.
        One can use a timeout in seconds. In that case the jobs will wait before being cancel.
        If no timeout is specified, the jobs are canceled immediately

        :param storage_element: The Storage Element that will be banned.
        :param message: The reason of the ban.
        :param ban: Boolean. If set to True, ban the SE, if set to False unban the SE.
        :param timeout: if None, send to FTS status 'cancel' else 'waiting' + the corresponding timeout.

        :returns: 0 in case of success, otherwise raise Exception
        """

        params_dict = {'storage': storage_element, 'message': message}
        status = 'CANCEL'
        if timeout:
            params_dict['timeout'] = timeout
            status = 'WAIT'
        params_dict['status'] = status
        params_str = json.dumps(params_dict)

        result = None
        if ban:
            try:
                result = requests.post('%s/ban/se' % self.external_host,
                                       verify=self.verify,
                                       cert=self.cert,
                                       data=params_str,
                                       headers={'Content-Type': 'application/json'},
                                       timeout=None)
            except Exception:
                logging.warn('Could not ban %s on %s - %s', storage_element, self.external_host, str(traceback.format_exc()))
            if result and result.status_code == 200:
                return 0
            raise Exception('Could not ban the storage %s , status code returned : %s', (storage_element, result.status_code if result else None))
        else:

            try:
                result = requests.delete('%s/ban/se?storage=%s' % (self.external_host, storage_element),
                                         verify=self.verify,
                                         cert=self.cert,
                                         data=params_str,
                                         headers={'Content-Type': 'application/json'},
                                         timeout=None)
            except Exception:
                logging.warn('Could not unban %s on %s - %s', storage_element, self.external_host, str(traceback.format_exc()))
            if result and result.status_code == 204:
                return 0
            raise Exception('Could not unban the storage %s , status code returned : %s', (storage_element, result.status_code if result else None))

    # Private methods unique to the FTS3 Transfertool

    @staticmethod
    def __extract_host(external_host):
        # graphite does not like the dots in the FQDN
        return urlparse(external_host).hostname.replace('.', '_')

    def __get_transfer_baseid_voname(self):
        """
        Get transfer VO name from the external host.

        :returns base id as a string and VO name as a string.
        """
        result = (None, None)
        try:
            key = 'voname: %s' % self.external_host
            result = REGION_SHORT.get(key)
            if isinstance(result, NoValue):
                logging.debug("Refresh transfer baseid and voname for %s", self.external_host)

                get_result = None
                try:
                    get_result = requests.get('%s/whoami' % self.external_host,
                                              verify=self.verify,
                                              cert=self.cert,
                                              headers={'Content-Type': 'application/json'},
                                              timeout=5)
                except ReadTimeout as error:
                    raise TransferToolTimeout(error)
                except JSONDecodeError as error:
                    raise TransferToolWrongAnswer(error)
                except Exception as error:
                    logging.warn('Could not get baseid and voname from %s - %s' % (self.external_host, str(error)))

                if get_result and get_result.status_code == 200:
                    baseid = str(get_result.json()['base_id'])
                    voname = str(get_result.json()['vos'][0])
                    result = (baseid, voname)

                    REGION_SHORT.set(key, result)

                    logging.debug("Get baseid %s and voname %s from %s", baseid, voname, self.external_host)
                else:
                    logging.warn("Failed to get baseid and voname from %s, error: %s", self.external_host, get_result.text if get_result is not None else get_result)
                    result = (None, None)
        except Exception as error:
            logging.warning("Failed to get baseid and voname from %s: %s" % (self.external_host, str(error)))
            result = (None, None)
        return result

    def __get_deterministic_id(self, sid):
        """
        Get deterministic FTS job id.

        :param sid: FTS seed id.
        :returns: FTS transfer identifier.
        """
        baseid, voname = self.__get_transfer_baseid_voname()
        if baseid is None or voname is None:
            return None
        root = uuid.UUID(baseid)
        atlas = uuid.uuid5(root, voname)
        jobid = uuid.uuid5(atlas, sid)
        return str(jobid)

    def __format_response(self, fts_job_response, fts_files_response):
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
                    'external_host': self.external_host,
                    'job_m_replica': job_m_replica,
                    'details': {'files': fts_job_response['job_metadata']}}
        return response

    def __format_new_response(self, fts_job_response, fts_files_response):
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
            resps[request_id] = self.__format_response(fts_job_response, fts_files_response)
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
                                     'external_host': self.external_host,
                                     'job_m_replica': multi_sources,
                                     'details': {'files': file_resp['file_metadata']}}

                # multiple source replicas jobs and we found the successful one, it's the final state.
                if multi_sources and file_resp['file_state'] in [str(FTSState.FINISHED)]:
                    break
        return resps

    def __bulk_query_responses(self, jobs_response):
        if not isinstance(jobs_response, list):
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

                resps = self.__format_new_response(job_response, files_response)
                responses[transfer_id] = resps
            elif job_response['http_status'] == '404 Not Found':
                # Lost transfer
                responses[transfer_id] = None
            else:
                responses[transfer_id] = Exception('Could not retrieve transfer information(http_status: %s, http_message: %s)' % (job_response['http_status'],
                                                                                                                                   job_response['http_message'] if 'http_message' in job_response else None))
        return responses

    def __query_details(self, transfer_id):
        """
        Query the detailed status of a transfer in FTS3 via JSON.

        :param transfer_id: FTS transfer identifier as a string.
        :returns: Detailed transfer status information as a dictionary.
        """

        files = None

        try:
            files = fts.get_job_status(self.context, transfer_id, list_files=True)
            record_counter('transfertool.fts3.%s.query_details.success' % self.__extract_host(self.external_host))
        except Exception:
            record_counter('transfertool.fts3.%s.query_details.failure' % self.__extract_host(self.external_host))
            return

        return files
