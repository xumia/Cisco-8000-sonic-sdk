#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import sim_utils
from sdk_test_case_base import sdk_test_case_base
import topology as T
import decor


@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "WB fails for FE mode")
@unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
@unittest.skipIf(decor.is_asic3(), "FE mode is not supported on GR")
class test_fe_per_lc_min_links(sdk_test_case_base):
    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            for sid in device.get_used_slices():
                device.set_fabric_slice_clos_direction(sid, sdk.la_clos_direction_e_DOWN)

    @classmethod
    def setUpClass(cls):
        super(test_fe_per_lc_min_links, cls).setUpClass(slice_modes=sim_utils.FABRIC_ELEMENT_DEV,
                                                        device_config_func=test_fe_per_lc_min_links.device_config_func)

    def setUp(self):
        super().setUp(create_default_topology=False)

    def tearDown(self):
        self.device.set_bool_property(sdk.la_device_property_e_ENABLE_FE_PER_DEVICE_MIN_LINKS, False)
        super().tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_minimum_fabric_links_per_lc_setter_getter(self):

        with self.assertRaises(sdk.InvalException):
            self.device.set_minimum_fabric_links_per_lc(2, 1)

        self.device.set_bool_property(sdk.la_device_property_e_ENABLE_FE_PER_DEVICE_MIN_LINKS, True)
        num_links = 2
        self.device.set_minimum_fabric_links_per_lc(10, num_links)
        self.assertEqual(self.device.get_minimum_fabric_links_per_lc(10), num_links)

        num_links = 5
        self.device.set_minimum_fabric_links_per_lc(10, num_links)
        self.assertEqual(self.device.get_minimum_fabric_links_per_lc(10), num_links)


if __name__ == '__main__':
    unittest.main()
