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

import decor
from leaba import sdk
import unittest
import decor
import topology as T
from resource_handler_base import *


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class native_ce_ptr_table_usage(resource_handler_base):
    def setUp(self):
        super().setUp()
        self.topology = T.topology(self, self.device)
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_native_ce_ptr_table_usage(self):
        rd_def = sdk.la_resource_descriptor()
        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_NATIVE_CE_PTR_TABLE
        used_during_device_init = self.device.get_resource_usage(rd_def).used

        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        # Add 2 prefix objects, each ECMP prefix object adds one entry in the table.
        pfx_obj_1 = T.prefix_object(self, self.device, 10, nh_ecmp)
        pfx_obj_2 = T.prefix_object(self, self.device, 11, nh_ecmp)

        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, used_during_device_init + 2)


if __name__ == '__main__':
    unittest.main()
