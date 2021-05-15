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
import argparse
from leaba import sdk
from scapy.all import *
from packet_test_utils import *
from erspan.erspan_base import *
import topology as T
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class tcam_ingress_usage(erspan_base):

    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv4_test_base  # NEED TO FIX  - maybe ip_impl only. cehxk deeper

    def print_tcam_group_usage(self, resource_type, resource_str):
        r_desc = sdk.la_resource_descriptor()
        r_desc.m_resource_type = resource_type
        for slice_id in self.device.get_used_slices():
            r_desc.m_index.slice_id = slice_id
            usage = self.device.get_resource_usage(r_desc)
            print('%s : slice=%d total=%d used=%d' %
                  (resource_str, r_desc.m_index.slice_id, usage.total, usage.used))

    def base_test_tcam_ingress_usage(self, is_ipv4):

        # define resource descriptors
        r_desc_def_in = sdk.la_resource_descriptor()
        r_desc_reg_in = sdk.la_resource_descriptor()
        r_desc_def_in.m_resource_type = self.resource_type
        r_desc_reg_in.m_resource_type = self.resource_type
        r_desc_def_in.m_index.slice_id = int(self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj.get_slice())
        r_desc_reg_in.m_index.slice_id = int(self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj.get_slice())

        # get initial usage
        r_desc_def_out = self.device.get_resource_usage(r_desc_def_in)
        self.assertEqual(r_desc_def_out.used, 0)
        prev_def_available = r_desc_def_out.total - r_desc_def_out.used     # initial available

        r_desc_reg_out = self.device.get_resource_usage(r_desc_reg_in)
        self.assertEqual(r_desc_reg_out.used, 0)
        prev_reg_available = r_desc_reg_out.total - r_desc_reg_out.used     # initial available

        # for Debug
        if args.verbose:
            print("initial state:")
            self.print_tcam_group_usage(self.resource_type, self.resource_str)

        # create acl
        acl1 = self.device.create_acl(self.ingress_acl_key_profile, self.topology.acl_command_profile_def)

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

        ip_acls = []
        ip_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(self.packet_format, ip_acls)
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # test usage
        acl1_ace_count = acl1.get_count()
        r_desc_def_out = self.device.get_resource_usage(r_desc_def_in)
        self.assertEqual(r_desc_def_out.used, acl1_ace_count)

        cur_def_available = r_desc_def_out.total - r_desc_def_out.used      # current available
        self.assertLessEqual(cur_def_available, prev_def_available)
        prev_def_available = cur_def_available

        # for Debug
        if args.verbose:
            print("after set acl on one slice:")
            self.print_tcam_group_usage(self.resource_type, self.resource_str)

        # Apply on another slice, and then insert a drop ACE in the same ACL
        self.topology.tx_l3_ac_reg.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # test usage
        acl1_ace_count = acl1.get_count()
        r_desc_reg_out = self.device.get_resource_usage(r_desc_reg_in)
        self.assertEqual(r_desc_reg_out.used, acl1_ace_count)

        cur_reg_available = r_desc_reg_out.total - r_desc_reg_out.used      # current available
        self.assertLessEqual(cur_reg_available, prev_reg_available)
        prev_reg_available = cur_reg_available

        # for Debug
        if args.verbose:
            print("after set acl on second slice:")
            self.print_tcam_group_usage(self.resource_type, self.resource_str)

        acl1.append(k, commands)

        # test usage
        acl1_ace_count = acl1.get_count()
        r_desc_reg_out = self.device.get_resource_usage(r_desc_reg_in)
        self.assertEqual(r_desc_reg_out.used, acl1_ace_count)

        # Due to same ACL modification, TCAM usage on both the slices should be same
        r_desc_def_out = self.device.get_resource_usage(r_desc_def_in)
        self.assertEqual(r_desc_def_out.used, r_desc_reg_out.used)

        cur_def_available = r_desc_def_out.total - r_desc_def_out.used      # current available
        self.assertLessEqual(cur_def_available, prev_def_available)
        prev_def_available = cur_def_available
        cur_reg_available = r_desc_reg_out.total - r_desc_reg_out.used      # current available
        self.assertLessEqual(cur_reg_available, prev_reg_available)
        prev_reg_available = cur_reg_available

        # for Debug
        if args.verbose:
            print("after drop insertion:")
            self.print_tcam_group_usage(self.resource_type, self.resource_str)

        # Remove ACL on one slice
        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # test usage
        r_desc_def_out = self.device.get_resource_usage(r_desc_def_in)
        self.assertEqual(r_desc_def_out.used, 0)
        acl1_ace_count = acl1.get_count()
        r_desc_reg_out = self.device.get_resource_usage(r_desc_reg_in)
        self.assertEqual(r_desc_reg_out.used, acl1_ace_count)

        cur_def_available = r_desc_def_out.total - r_desc_def_out.used      # current available
        self.assertGreaterEqual(cur_def_available, prev_def_available)
        prev_def_available = cur_def_available

        # for Debug
        if args.verbose:
            print("after remove acl on one slice:")
            self.print_tcam_group_usage(self.resource_type, self.resource_str)

        # Remove ACL from another slice
        self.topology.tx_l3_ac_reg.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # test usage
        r_desc_def_out = self.device.get_resource_usage(r_desc_def_in)
        self.assertEqual(r_desc_def_out.used, 0)
        r_desc_reg_out = self.device.get_resource_usage(r_desc_reg_in)
        self.assertEqual(r_desc_reg_out.used, 0)

        cur_reg_available = r_desc_reg_out.total - r_desc_reg_out.used      # current available
        self.assertGreaterEqual(cur_reg_available, prev_reg_available)
        prev_reg_available = cur_reg_available

        # for Debug
        if args.verbose:
            print("after remove acl on second slice:")
            self.print_tcam_group_usage(self.resource_type, self.resource_str)

    # NARROW test
    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_tcam_ingress_narrow_usage(self):
        self.resource_type = sdk.la_resource_descriptor.type_e_TCAM_INGRESS_NARROW_POOL_0
        self.ingress_acl_key_profile = self.topology.ingress_acl_key_profile_ipv4_def
        self.packet_format = sdk.la_acl_packet_format_e_IPV4
        if args.verbose:
            self.resource_str = 'TCAM_INGRESS_NARROW_POOL_0'

        self.base_test_tcam_ingress_usage(is_ipv4=1)

    # WIDE test
    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_tcam_ingress_wide_usage(self):
        self.resource_type = sdk.la_resource_descriptor.type_e_TCAM_INGRESS_WIDE
        self.ingress_acl_key_profile = self.topology.ingress_acl_key_profile_ipv6_def
        self.packet_format = sdk.la_acl_packet_format_e_IPV6
        if args.verbose:
            self.resource_str = 'TCAM_INGRESS_WIDE'

        self.base_test_tcam_ingress_usage(is_ipv4=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='tcam_ingress_usage test.')
    parser.add_argument('-v', '--verbose', required=False, action='store_true', help='verbose/debug mode')
    args = parser.parse_args()
    unittest.main()
