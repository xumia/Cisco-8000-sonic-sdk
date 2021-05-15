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
import decor
import topology as T


NH_MAC = T.mac_addr('48:ca:d1:3e:f6:a3')
NH_GID = 0x400


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class resolution_stage3(resource_handler_base):

    def setUp(self):
        super().setUp()
        self.topology = T.topology(self, self.device)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_resolution_stage3(self):
        rd_def = sdk.la_resource_descriptor()
        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_STAGE3_LB_GROUP
        group_resource_init_status = self.device.get_resource_usage(rd_def)
        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_STAGE3_LB_MEMBER
        member_resource_init_status = self.device.get_resource_usage(rd_def)

        nh = T.next_hop(self, self.device, NH_GID, NH_MAC, self.topology.tx_l3_ac_reg)
        ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        ecmp.add_member(nh.hld_obj)
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x12341234
        prefix.length = 32
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, ecmp, 0, False)

        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_STAGE3_LB_GROUP
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, group_resource_init_status.used + 1)
        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_STAGE3_LB_MEMBER
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, member_resource_init_status.used + 1)


if __name__ == '__main__':
    unittest.main()
