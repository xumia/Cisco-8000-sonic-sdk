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
import beaglecli
import decor
from beaglesdk import beaglesdkcli
import os

verbose = 1


def get_supported_slices():
    if decor.is_hw_device():
        return 8
    return 1


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_beagle(unittest.TestCase):

    def setUp(self):
        device_id = 0
        device_path = "/dev/testdev"
        os.environ['ASIC'] = 'ASIC7_A0'

        self.sim_ldev = lldcli.ll_device_create(device_id, device_path)
        self.apb = apbcli.apb_create(self.sim_ldev, apbcli.apb_interface_type_e_SERDES)

    def tearDown(self):
        self.sim_ldev = None
        self.apb = None
        self.gr_beagle_trans = None
        self.beagle_dev = None

    def init(self, slice, ifg, beagle_package):
        self.slice = slice
        self.ifg = ifg
        self.beagle_package = beagle_package

        self.gr_beagle_trans = beaglecli.create_beagle_transport_asic3(
            self.sim_ldev, self.apb, self.slice, self.ifg, self.beagle_package)
        self.beagle_dev = beaglesdkcli.beagle_device.create(beaglesdkcli.beagle_type_L1, self.gr_beagle_trans)

        self.assertEqual(self.gr_beagle_trans.is_simulated_device(), self.sim_ldev.is_simulated_device())

    def test_beagle_transport(self):
        supported_slices = get_supported_slices()
        for slice in range(supported_slices):
            for ifg in range(2):
                for beagle_package in range(2):

                    self.init(slice, ifg, beagle_package)

                    encoded_apb = beaglecli.encode_apb_select(self.sim_ldev, self.slice, self.ifg, self.beagle_package)
                    self.assertEqual(self.gr_beagle_trans.get_device_id(), encoded_apb)

                    self.gr_beagle_trans.write(0, 0x12345678)
                    if(self.gr_beagle_trans.is_simulated_device()):
                        expected = 0
                    else:
                        expected = 0x12345678
                    self.assertEqual(self.gr_beagle_trans.read(0), expected)

                    self.gr_beagle_trans.write(4, 0x23456789)
                    if(self.gr_beagle_trans.is_simulated_device()):
                        expected = 0
                    else:
                        expected = 0x23456789
                    self.assertEqual(self.gr_beagle_trans.read(4), expected)

    def test_beagle_device_read_write(self):
        supported_slices = get_supported_slices()
        for slice in range(supported_slices):
            for ifg in range(2):
                for beagle_package in range(2):

                    self.init(slice, ifg, beagle_package)

                    beagle_hld = self.beagle_dev.get_hld()

                    self.assertEqual(beagle_hld.read_memory_unprotected(0), 0)
                    self.assertEqual(beagle_hld.read_memory_unprotected(4), 0)

                    beagle_hld.write_memory_unprotected(0, 0x12345678)
                    if(self.gr_beagle_trans.is_simulated_device()):
                        expected = 0
                    else:
                        expected = 0x12345678
                    self.assertEqual(beagle_hld.read_memory_unprotected(0), expected)

                    beagle_hld.write_memory_unprotected(4, 0x23456789)
                    if(self.gr_beagle_trans.is_simulated_device()):
                        expected = 0
                    else:
                        expected = 0x12345678
                    self.assertEqual(beagle_hld.read_memory_unprotected(4), expected)


if __name__ == '__main__':
    unittest.main()
