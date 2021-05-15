#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import decor
from resource_handler_base import *

import unittest
from leaba import sdk
import topology as T
import os


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class tc_profiles(resource_handler_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_tc_profiles(self):
        ASIC_PL = os.getenv('ASIC') and os.getenv('ASIC').startswith('ASIC4')
        if ASIC_PL:
            self.num_init_tc_profiles_used = 0
        else:
            self.num_init_tc_profiles_used = 1  # Device creates default tc_profile on init for MCG counter support
        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_TC_PROFILE
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, self.num_init_tc_profiles_used)

        tc_profile = T.tc_profile(self, self.device)
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, 1 + self.num_init_tc_profiles_used)

        tc_profile.destroy()
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, self.num_init_tc_profiles_used)


if __name__ == '__main__':
    unittest.main()
