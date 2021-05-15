#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

import unittest
import cadencecli
import apbcli
import lldcli
import os


def is_hw_device():
    return os.getenv('SDK_DEVICE_NAME') == '/dev/uio0'


class testcase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def create_key_payload_from_line(cls, line):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        self.ldev = None

    def test_cadence_get_pma_common_status(self):
        os.environ['ASIC'] = 'GIBRALTAR_A0'
        dev_id = 0
        dev_path = os.getenv('SDK_DEVICE_NAME')
        if not dev_path:
            dev_path = '/dev/testdev'
        ldev = lldcli.ll_device_create(dev_id, dev_path)
        self.assertEqual(ldev.get_device_revision(), lldcli.la_device_revision_e_GIBRALTAR_A0)

        apb_handler_pci = apbcli.apb_create(ldev, apbcli.apb_interface_type_e_PCIE)
        self.assertNotEqual(apb_handler_pci, None)

        cadence_apb_handler = cadencecli.cadence_apb_handler(apb_handler_pci)

        cmn_rdy, mac_sus_ack, refclk_active = cadencecli.Get_CMN_Status(cadence_apb_handler)
        print('Get_CMN_Status(): cmn_rdy={}, mac_sus_ack={}, refclk_active={}'.format(cmn_rdy, mac_sus_ack, refclk_active))

        lane = 0
        sync, error = cadencecli.Get_RX_BIST_Status(cadence_apb_handler, lane)
        print('Get_RX_BIST_Status(lane={}): sync={}, error={}'.format(lane, sync, error))

        pwrstate = cadencecli.Get_Powerstate(cadence_apb_handler, lane)
        print('Get_Powerstate(lane={}): pwrstate={}'.format(lane, pwrstate))

        apb_handler_pci = None
        ldev = None


if __name__ == '__main__':
    unittest.main()
