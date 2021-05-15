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

import unittest
from leaba import sdk
import sim_utils
import decor

verbose = 0


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_hw_diagnostics(unittest.TestCase):

    def setUp(self):
        self.device_id = 0
        self.device = sim_utils.create_device(self.device_id, initialize=False)
        if verbose >= 1:
            sdk.la_set_logging_level(self.device_id, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_mbist(self):
        if self.device.get_ll_device().is_gibraltar():
            self.do_mbist_gibraltar()
        else:
            if self.device.get_ll_device().is_asic3():
                self.do_mbist_asic3()
            else:
                self.do_mbist_pacific()

    def do_mbist_asic3(self):
         # init+MBIST with repair
        self.device.set_bool_property(sdk.la_device_property_e_ENABLE_MBIST_REPAIR, True)
        self.device.initialize(sdk.la_device.init_phase_e_DEVICE)

        self.device.diagnostics_test(sdk.la_device.test_feature_e_MEM_BIST)

        for i in range(len(self.device.get_used_slices())):
            self.device.set_slice_mode(i, sdk.la_slice_mode_e_NETWORK)

        self.device.initialize(sdk.la_device.init_phase_e_TOPOLOGY)

        self.device.diagnostics_test(sdk.la_device.test_feature_e_MEM_BIST_CHIPLETS)

    def do_mbist_gibraltar(self):
        # If device frequency is different from the default 1200MHz, set the property here.
        self.device.set_int_property(sdk.la_device_property_e_DEVICE_FREQUENCY, 1200000)

        # Run MBIST with repair through an API call
        self.device.set_bool_property(sdk.la_device_property_e_ENABLE_MBIST_REPAIR, True)
        self.device.diagnostics_test(sdk.la_device.test_feature_e_MEM_BIST)

        # init+MBIST without repair
        self.device.set_bool_property(sdk.la_device_property_e_ENABLE_MBIST_REPAIR, False)
        self.device.diagnostics_test(sdk.la_device.test_feature_e_HBM)

    def do_mbist_pacific(self):
        # init+MBIST with repair
        self.device.set_bool_property(sdk.la_device_property_e_ENABLE_MBIST_REPAIR, True)
        self.device.initialize(sdk.la_device.init_phase_e_DEVICE)

        # Run MBIST again, but this time through an API call
        self.device.diagnostics_test(sdk.la_device.test_feature_e_MEM_BIST)
        self.device.diagnostics_test(sdk.la_device.test_feature_e_HBM)


if __name__ == '__main__':
    unittest.main()
