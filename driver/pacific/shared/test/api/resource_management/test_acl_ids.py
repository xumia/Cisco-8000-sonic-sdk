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
from scapy.all import *
from packet_test_utils import *
from ipv4_egress_acl.ipv4_egress_acl_base import *
import decor
import topology as T


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class acl_ids(ipv4_egress_acl_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_acl_ids(self):
        rd_def = sdk.la_resource_descriptor()
        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_IPV4_ACL
        rd_def.m_index.slice_pair_id = int(self.topology.tx_svi_eth_port_def.sys_port.hld_obj.get_slice() / 2)
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, 0)
        rd_reg = sdk.la_resource_descriptor()
        rd_reg.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_IPV4_ACL
        rd_reg.m_index.slice_pair_id = int(self.topology.tx_svi_eth_port_reg.sys_port.hld_obj.get_slice() / 2)
        res = self.device.get_resource_usage(rd_reg)
        self.assertEqual(res.used, 0)

        acl1 = self.create_simple_sec_acl()

        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)

        self.insert_nop_ace(acl1)
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, 1)
        res = self.device.get_resource_usage(rd_reg)
        self.assertEqual(res.used, 0)

        # Apply on another slice
        self.topology.tx_l3_ac_reg.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)
        self.do_test_route_default()
        self.insert_drop_ace(acl1)
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, 1)
        res = self.device.get_resource_usage(rd_reg)
        self.assertEqual(res.used, 1)

        # Remove and reapply on slice, while still applied to other
        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, 0)
        res = self.device.get_resource_usage(rd_reg)
        self.assertEqual(res.used, 1)

        self.do_test_route_default()
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, 1)
        res = self.device.get_resource_usage(rd_reg)
        self.assertEqual(res.used, 1)

        # Remove in other order
        self.topology.tx_l3_ac_reg.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, 1)
        res = self.device.get_resource_usage(rd_reg)
        self.assertEqual(res.used, 0)

        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, 0)
        res = self.device.get_resource_usage(rd_reg)
        self.assertEqual(res.used, 0)


if __name__ == '__main__':
    unittest.main()
