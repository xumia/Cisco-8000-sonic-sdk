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
import apbcli
import lldcli
import os


verbose = 1


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

    def test_apb_create_and_write(self):
        os.environ['ASIC'] = 'GIBRALTAR_A0'
        dev_id = 0
        dev_path = os.getenv('SDK_DEVICE_NAME')
        if not dev_path:
            dev_path = '/dev/testdev'
        ldev = lldcli.ll_device_create(dev_id, dev_path)
        self.assertEqual(ldev.get_device_revision(), lldcli.la_device_revision_e_GIBRALTAR_A0)

        apb_handler_pci = apbcli.apb_create(ldev, apbcli.apb_interface_type_e_PCIE)
        apb_handler_serdes = apbcli.apb_create(ldev, apbcli.apb_interface_type_e_SERDES)
        apb_handler_hbm = apbcli.apb_create(ldev, apbcli.apb_interface_type_e_HBM)
        self.assertNotEqual(apb_handler_pci, None)
        self.assertNotEqual(apb_handler_serdes, None)
        self.assertNotEqual(apb_handler_hbm, None)

        # Read PCI vendor/device ID through APB/PCIe interface
        apb_select = apbcli.apb.pcie_apb_select_e_CORE
        addr = 0
        val = apb_handler_pci.read(apb_select, addr)
        if is_hw_device():
            self.assertEqual(val, 0xa0011137)
        else:
            self.assertEqual(val, 0x0)

        # Read APB
        addr = 0
        for apb_select in range(2):
            val = apb_handler_hbm.read(apb_select, addr)
            self.assertEqual(val, 0)

        # TODO: Read from slice[0]->ifg[0].serdes_pool16, serdes_pair=0
        #apb_select = 0
        #val = apb_handler_serdes.read(apb_select, addr)
        # if is_hw_device():
        #    pass # TODO - run on HW device and check
        # else:
        #    pass # TODO - should fail with timeout

        apb_handler_pci = None
        apb_handler_serdes = None
        apb_handler_hbm = None
        ldev = None

    def test_apb_non_gb(self):
        os.environ['ASIC'] = 'PACIFIC_A0'
        ldev = lldcli.ll_device_create(0, '/dev/testdev')
        self.assertNotEqual(ldev.get_device_revision(), lldcli.la_device_revision_e_GIBRALTAR_A0)

        for interface_type in [
                apbcli.apb_interface_type_e_PCIE,
                apbcli.apb_interface_type_e_SERDES,
                apbcli.apb_interface_type_e_HBM]:
            try:
                apb_handler = apbcli.apb_create(ldev, interface_type)
                self.fail('apb_create() should fail on dev revision {}'.format(ldev.get_device_revision()))
            except BaseException as status:
                pass

        ldev = None


if __name__ == '__main__':
    unittest.main()
