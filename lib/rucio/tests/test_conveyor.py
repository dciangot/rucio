'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Wen Guan, <wen.guan@cern.ch>, 2015
'''

import time

from rucio.daemons.mock.conveyorinjector import request_transfer
from rucio.daemons.conveyor import submitter, poller, finisher, throttler
from rucio.common.config import config_get


class TestConveyorSubmitter:
    """ TestReaper Class."""

    def test_conveyor_submitter(self):
        """ CONVEYOR (DAEMON): Test the conveyor submitter daemon."""
        src = 'ATLASSCRATCHDISK://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasscratchdisk/rucio/'
        dest = 'ATLASSCRATCHDISK://dcache-se-atlas.desy.de:8443/srm/managerv2?SFN=/pnfs/desy.de/atlas/dq2/atlasscratchdisk/rucio/'
        request_transfer(loop=10, src=src, dst=dest, upload=False, same_src=True, same_dst=True)

        throttler.run(once=True)
        submitter.run(once=True)
        submitter.run(once=True)
        time.sleep(5)
        poller.run(once=True)
        finisher.run(once=True)

    def test_cms_conveyor_submitter(self):
        """ CONVEYOR (DAEMON): Test the conveyor submitter daemon for CMS user transfer."""

        src = 'ATLASSCRATCHDISK://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasscratchdisk/rucio/'
        dest = 'ATLASSCRATCHDISK://dcache-se-atlas.desy.de:8443/srm/managerv2?SFN=/pnfs/desy.de/atlas/dq2/atlasscratchdisk/rucio/'
        request_transfer(loop=10, src=src, dst=dest, upload=False, same_src=True, same_dst=True, cms_transfer=True)


        throttler.run(once=True)
        submitter.run(once=True, activities=['user_test'])
        time.sleep(60)
        print('=' * 30)
        poller.run(once=True, activities=['user_test'])
        print('=' * 30)
        finisher.run(once=True, activities=['user_test'])


if __name__ == "__main__":
    test = TestConveyorSubmitter()
    #test.test_conveyor_submitter()

    user_transfer = config_get('conveyor', 'user_transfers', False, None)
    if str(user_transfer) in ['cms']:
        test.test_cms_conveyor_submitter()
