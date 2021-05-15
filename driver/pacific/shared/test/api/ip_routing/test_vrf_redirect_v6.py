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

import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base
import decor
from sdk_test_case_base import *
from ip_routing_base import *
from ipv6_l3_ac_routing_base import *

REDIR_VRF_GID = 0x100 if not decor.is_gibraltar() else 0xF00


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_ipv6_vrf_redirect(ipv6_l3_ac_routing_base):
    slice_modes = sim_utils.STANDALONE_DEV

    @classmethod
    def setUpClass(cls):
        super(ipv6_l3_ac_routing_base, cls).setUpClass(slice_modes=cls.slice_modes)

    @unittest.skipUnless(decor.is_gibraltar() or decor.is_asic5(), "Test supported only on GB and AR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "RTF is not yet enabled on PL")
    def test_ipv6_routing_120_bit_prefix(self):
        self.destroy_default_route()
        redir_vrf, redir_vrf_dest = self.do_setup_vrf_redirect(REDIR_VRF_GID)

        prefix = self.ip_impl.build_prefix(self.DIP, length=120)

        redir_vrf.add_ipv6_route(prefix, self.topology.nh_l3_ac_reg.hld_obj, ip_routing_base.PRIVATE_DATA, False)

        # Test to ensure double-add not possible
        with self.assertRaises(sdk.ExistException):
            redir_vrf.add_ipv6_route(prefix, self.topology.nh_l3_ac_reg.hld_obj, ip_routing_base.PRIVATE_DATA, False)

        self.topology.vrf.hld_obj.add_ipv6_route(prefix, redir_vrf_dest, ip_routing_base.PRIVATE_DATA, False)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

       # Try to delete VRF without deleting route pointing to it. Should fail
        with self.assertRaises(sdk.BusyException):
            self.device.destroy(redir_vrf)

       # Try to delete VRF destination without deleting route pointing to it. Should fail
        with self.assertRaises(sdk.BusyException):
            self.device.destroy(redir_vrf_dest)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.device.destroy(redir_vrf_dest)
        self.device.destroy(redir_vrf)

    @unittest.skipUnless(decor.is_gibraltar() or decor.is_asic5(), "Test supported only on GB and AR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "RTF is not yet enabled on PL")
    def test_mod_ipv6_routing_120_bit_prefix(self):
        self.destroy_default_route()
        redir_vrf, redir_vrf_dest = self.do_setup_vrf_redirect(REDIR_VRF_GID)

        prefix = self.ip_impl.build_prefix(self.DIP, length=120)

        redir_vrf.add_ipv6_route(prefix, self.topology.nh_l3_ac_reg.hld_obj, ip_routing_base.PRIVATE_DATA, False)

        self.topology.vrf.hld_obj.add_ipv6_route(prefix, redir_vrf_dest, ip_routing_base.PRIVATE_DATA, False)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.ip_impl.modify_route(self.topology.vrf, prefix, self.topology.nh_l3_ac_ext)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT,
                          T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

        self.topology.vrf.hld_obj.modify_ipv6_route(prefix, redir_vrf_dest, ip_routing_base.PRIVATE_DATA)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        ri = self.ip_impl.get_route(self.topology.vrf, self.DIP)
        self.assertEquals(ri.latency_sensitive, False)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.device.destroy(redir_vrf_dest)
        self.device.destroy(redir_vrf)

    @unittest.skipUnless(decor.is_gibraltar(), "Test supported only on GB")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "RTF is not yet enabled on PL")
    def test_ipv6_routing_128_bit_prefix(self):
        self.destroy_default_route()
        redir_vrf, redir_vrf_dest = self.do_setup_vrf_redirect(REDIR_VRF_GID)

        prefix = self.ip_impl.build_prefix(self.DIP, length=128)

        redir_vrf.add_ipv6_route(prefix, self.topology.nh_l3_ac_reg.hld_obj, ip_routing_base.PRIVATE_DATA, False)

        # Test to ensure double-add not possible
        with self.assertRaises(sdk.ExistException):
            redir_vrf.add_ipv6_route(prefix, self.topology.nh_l3_ac_reg.hld_obj, ip_routing_base.PRIVATE_DATA, False)

        self.topology.vrf.hld_obj.add_ipv6_route(prefix, redir_vrf_dest, ip_routing_base.PRIVATE_DATA, False)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        ri = self.ip_impl.get_route(self.topology.vrf, self.DIP)
        self.assertEquals(ri.latency_sensitive, True)

       # Try to delete VRF without deleting route pointing to it. Should fail
        with self.assertRaises(sdk.BusyException):
            self.device.destroy(redir_vrf)

       # Try to delete VRF destination without deleting route pointing to it. Should fail
        with self.assertRaises(sdk.BusyException):
            self.device.destroy(redir_vrf_dest)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.device.destroy(redir_vrf_dest)
        self.device.destroy(redir_vrf)

    @unittest.skipUnless(decor.is_gibraltar(), "Test supported only on GB")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "RTF is not yet enabled on PL")
    def test_mod_ipv6_routing_128_bit_prefix(self):
        self.destroy_default_route()
        redir_vrf, redir_vrf_dest = self.do_setup_vrf_redirect(REDIR_VRF_GID)

        prefix = self.ip_impl.build_prefix(self.DIP, length=128)

        redir_vrf.add_ipv6_route(prefix, self.topology.nh_l3_ac_reg.hld_obj, ip_routing_base.PRIVATE_DATA, False)

        self.topology.vrf.hld_obj.add_ipv6_route(prefix, redir_vrf_dest, ip_routing_base.PRIVATE_DATA, False)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.ip_impl.modify_route(self.topology.vrf, prefix, self.topology.nh_l3_ac_ext)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT,
                          T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

        self.topology.vrf.hld_obj.modify_ipv6_route(prefix, redir_vrf_dest, ip_routing_base.PRIVATE_DATA)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        ri = self.ip_impl.get_route(self.topology.vrf, self.DIP)
        self.assertEquals(ri.latency_sensitive, True)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.device.destroy(redir_vrf_dest)
        self.device.destroy(redir_vrf)

    @unittest.skipUnless(decor.is_gibraltar() or decor.is_asic5(), "Test supported only on GB and AR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "RTF is not yet enabled on PL")
    def test_ipv6_ace_routing_120_bit_prefix(self):
        self.destroy_default_route()
        redir_vrf, redir_vrf_dest = self.do_setup_vrf_redirect(REDIR_VRF_GID)
        redir_vrf1, redir_vrf_dest1 = self.do_setup_vrf_redirect(101)
        redir_vrf2, redir_vrf_dest2 = self.do_setup_vrf_redirect(102)
        prefix = self.ip_impl.build_prefix(self.DIP, length=120)

        redir_vrf2.add_ipv6_route(prefix, self.topology.nh_l3_ac_reg.hld_obj, ip_routing_base.PRIVATE_DATA, False)
        # Test to ensure double-add not possible
        with self.assertRaises(sdk.ExistException):
            redir_vrf2.add_ipv6_route(prefix, self.topology.nh_l3_ac_reg.hld_obj, ip_routing_base.PRIVATE_DATA, False)

        redir_vrf1.add_ipv6_route(prefix, redir_vrf_dest2, ip_routing_base.PRIVATE_DATA, False)
        # Test to ensure double-add not possible
        with self.assertRaises(sdk.ExistException):
            redir_vrf1.add_ipv6_route(prefix, redir_vrf_dest2, ip_routing_base.PRIVATE_DATA, False)

        redir_vrf.add_ipv6_route(prefix, redir_vrf_dest1, ip_routing_base.PRIVATE_DATA, False)

        ipv6_acl = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
        count = ipv6_acl.get_count()
        self.assertEqual(count, 0)
        ipv6_acls = []
        ipv6_acls.append(ipv6_acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        k1 = []
        commands = []
        action = sdk.la_acl_command_action()
        action.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action.data.l3_dest = redir_vrf_dest
        commands.append(action)
        self.device.reserve_acl(ipv6_acl)

        count_pre = ipv6_acl.get_count()
        ipv6_acl.insert(0, k1, commands)

        count_post = ipv6_acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

       # Try to delete VRF without deleting ACE pointing to it. Should fail
        with self.assertRaises(sdk.BusyException):
            self.device.destroy(redir_vrf)

       # Try to delete VRF destination without deleting ACE pointing to it. Should fail
        with self.assertRaises(sdk.BusyException):
            self.device.destroy(redir_vrf_dest)

        ipv6_acl.erase(count_post - 1)
        count_post = ipv6_acl.get_count()
        self.assertEqual(count_post, count_pre)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        self.device.destroy(redir_vrf_dest)
        self.device.destroy(redir_vrf)
        self.device.destroy(redir_vrf_dest1)
        self.device.destroy(redir_vrf1)
        self.device.destroy(redir_vrf_dest2)
        self.device.destroy(redir_vrf2)

    @unittest.skipUnless(decor.is_gibraltar() or decor.is_asic5(), "Test supported only on GB and AR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "RTF is not yet enabled on PL")
    def test_ipv6_ace_pbr_routing_120_bit_prefix(self):
        # self.destroy_default_route()
        redir_vrf, redir_vrf_dest = self.do_setup_vrf_redirect(REDIR_VRF_GID)
        redir_vrf1, redir_vrf_dest1 = self.do_setup_vrf_redirect(101)
        redir_vrf2, redir_vrf_dest2 = self.do_setup_vrf_redirect(102)
        prefix = self.ip_impl.build_prefix(self.DIP, length=30)

        redir_vrf2.add_ipv6_route(prefix, self.topology.nh_l3_ac_reg.hld_obj, ip_routing_base.PRIVATE_DATA, False)
        # Test to ensure double-add not possible
        with self.assertRaises(sdk.ExistException):
            redir_vrf2.add_ipv6_route(prefix, self.topology.nh_l3_ac_reg.hld_obj, ip_routing_base.PRIVATE_DATA, False)

        redir_vrf1.add_ipv6_route(prefix, redir_vrf_dest2, ip_routing_base.PRIVATE_DATA, False)
        # Test to ensure double-add not possible
        with self.assertRaises(sdk.ExistException):
            redir_vrf1.add_ipv6_route(prefix, redir_vrf_dest2, ip_routing_base.PRIVATE_DATA, False)

        redir_vrf.add_ipv6_route(prefix, redir_vrf_dest1, ip_routing_base.PRIVATE_DATA, False)

        self.l3_port_impl.rx_port.hld_obj.set_pbr_enabled(True)
        ipv6_acl = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)

        commands = []
        action = sdk.la_acl_command_action()
        action.type = sdk.la_acl_action_type_e_L3_DESTINATION
        action.data.l3_dest = redir_vrf_dest
        commands.append(action)

        k1 = []
        f = sdk.la_acl_field()
        f.type = sdk.la_acl_field_type_e_IPV6_DIP
        f.val.ipv6_dip = self.DIP.hld_obj
        f.mask.ipv6_dip = T.ipv6_addr('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00').hld_obj
        k1.append(f)

        ipv6_acls = []
        ipv6_acls.append(ipv6_acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.l3_port_impl.rx_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        count_pre = ipv6_acl.get_count()
        ipv6_acl.insert(0, k1, commands)

        count_post = ipv6_acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

       # Try to delete VRF without deleting ACE pointing to it. Should fail
        with self.assertRaises(sdk.BusyException):
            self.device.destroy(redir_vrf)

       # Try to delete VRF destination without deleting ACE pointing to it. Should fail
        with self.assertRaises(sdk.BusyException):
            self.device.destroy(redir_vrf_dest)

        ipv6_acl.erase(count_post - 1)
        count_post = ipv6_acl.get_count()
        self.assertEqual(count_post, count_pre)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        self.device.destroy(redir_vrf_dest)
        self.device.destroy(redir_vrf)
        self.device.destroy(redir_vrf_dest1)
        self.device.destroy(redir_vrf1)
        self.device.destroy(redir_vrf_dest2)
        self.device.destroy(redir_vrf2)


if __name__ == '__main__':
    unittest.main()
