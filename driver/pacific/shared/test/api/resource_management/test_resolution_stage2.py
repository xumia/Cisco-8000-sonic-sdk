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
from leaba import sdk
import unittest
from resource_management.resource_handler_base import *
import topology as T


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class resolution_stage2(resource_handler_base):

    def setUp(self):
        super().setUp()
        self.topology = T.topology(self, self.device)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_resolution_stage2(self):
        rd_def = sdk.la_resource_descriptor()
        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_STAGE2_LB_GROUP
        group_resource_init_status = self.device.get_resource_usage(rd_def)
        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_STAGE2_LB_MEMBER
        member_resource_init_status = self.device.get_resource_usage(rd_def)

        ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(ecmp, None)

        ecmp_attached_members = [self.topology.nh_l3_ac_reg, self.topology.nh_l3_ac_def]
        for member in ecmp_attached_members:
            ecmp.add_member(member.hld_obj)

        fec = self.device.create_l3_fec(ecmp)
        self.assertIsNotNone(fec)

        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_STAGE2_LB_GROUP
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, group_resource_init_status.used + 1)
        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_STAGE2_LB_MEMBER
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, member_resource_init_status.used + 2)


if __name__ == '__main__':
    unittest.main()
