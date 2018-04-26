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
import datetime
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
import traceback
import urlparse
import uuid
from datetime import timedelta
from hashlib import sha1
from socket import gaierror

import requests
from dogpile.cache import make_region
from dogpile.cache.api import NoValue
from myproxy.client import MyProxyClient, MyProxyClientGetError, MyProxyClientRetrieveError
from requests.exceptions import Timeout, RequestException, ConnectionError, SSLError, HTTPError
from requests.packages.urllib3 import disable_warnings  # pylint: disable=import-error

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

    try:
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
