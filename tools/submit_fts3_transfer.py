# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

"""
This submits a transfer to FTS3 via the transfertool.
"""

from rucio.transfertool.fts3_transfertool import submit_bulk_transfers

if __name__ == "__main__":

    src_urls = ['']
    dest_urls = ['']

    files = [{'activity': 'user',
              'metadata': {'scope': 'user.dciangot'}, 
              'sources': src_urls, 
              'destinations': dest_urls}]

    job_params = {'verify_checksum': False,
                  'copy_pin_lifetime': -1,
                  'bring_online': None,
                  'job_metadata': {'issuer': 'cms_rucio_test'},
                  'overwrite': True,
                  'priority': 3}

    submit_bulk_transfers('https://fts3.cern.ch:8446', files, job_params, user_transfer=True)
