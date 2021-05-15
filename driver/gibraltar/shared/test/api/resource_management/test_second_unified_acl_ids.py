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

from resource_handler_base import *

import unittest
from leaba import sdk
from scapy.all import *
from packet_test_utils import *
from erspan.erspan_base import *
import topology as T
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class second_unified_acl_ids(erspan_base):

    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv4_test_base

    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_second_unified_acl_ids(self):
        rd_def = sdk.la_resource_descriptor()
        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_INGRESS_IPV4_NARROW_DB1_INTERFACE0_ACL
        rd_def.m_index.slice_pair_id = int(self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj.get_slice() / 2)
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, 0)
        rd_reg = sdk.la_resource_descriptor()
        rd_reg.m_resource_type = sdk.la_resource_descriptor.type_e_INGRESS_IPV4_NARROW_DB1_INTERFACE0_ACL
        rd_reg.m_index.slice_pair_id = int(self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj.get_slice() / 2)
        res = self.device.get_resource_usage(rd_reg)
        self.assertEqual(res.used, 0)

        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        k = []
        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        commands.append(action1)
        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_DO_MIRROR
        action2.data.do_mirror = sdk.la_acl_mirror_src_e_DO_MIRROR_FROM_LP
        commands.append(action2)
        acl1.append(k, commands)

        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, 1)
        res = self.device.get_resource_usage(rd_reg)
        self.assertEqual(res.used, 0)

        # Apply on another slice
        self.topology.tx_l3_ac_reg.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, 1)
        res = self.device.get_resource_usage(rd_reg)
        self.assertEqual(res.used, 1)

        # Remove and reapply on slice, while still applied to other
        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, 0)
        res = self.device.get_resource_usage(rd_reg)
        self.assertEqual(res.used, 1)

        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, 1)
        res = self.device.get_resource_usage(rd_reg)
        self.assertEqual(res.used, 1)

        # Remove in other order
        self.topology.tx_l3_ac_reg.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, 1)
        res = self.device.get_resource_usage(rd_reg)
        self.assertEqual(res.used, 0)

        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, 0)
        res = self.device.get_resource_usage(rd_reg)
        self.assertEqual(res.used, 0)


if __name__ == '__main__':
    unittest.main()
