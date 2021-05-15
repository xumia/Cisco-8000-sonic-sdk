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


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class next_hop_usage(resource_handler_base):

    def setUp(self):
        super().setUp()
        self.topology = T.topology(self, self.device)

    def test_next_hop_usage(self):

        # get next-hop resource initial usage
        rd_def = sdk.la_resource_descriptor()
        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_NEXT_HOP
        initial_nh_usage = self.device.get_resource_usage(rd_def)

        # next hop params
        gid = T.NH_L3_AC_REG_GID + 1
        mac = T.NH_L3_AC_REG_MAC
        l3_port = self.topology.rx_l3_ac
        nh_type = sdk.la_next_hop.nh_type_e_NORMAL

        # create new nh
        next_hop = self.device.create_next_hop(gid, mac.hld_obj, l3_port.hld_obj, nh_type)
        self.assertNotEqual(next_hop, None)

        # verify usage
        create_nh_usage = self.device.get_resource_usage(rd_def)
        self.assertEqual(create_nh_usage.used, initial_nh_usage.used + 1)

        # destroy nh
        self.device.destroy(next_hop)

        # verify usage
        destroy_nh_usage = self.device.get_resource_usage(rd_def)
        self.assertEqual(destroy_nh_usage.used, create_nh_usage.used - 1)


if __name__ == '__main__':
    unittest.main()
