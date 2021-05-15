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

import sys
import unittest
from leaba import sdk
import nplapicli
import ip_test_base
import packet_test_utils as U
import uut_provider as V
import scapy.all as S
import sim_utils
import topology as T
from sdk_test_case_base import *

PRIVATE_DATA = 0x1234567890abcdef
PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
SA = T.mac_addr('be:ef:5d:35:7a:35')
SIP = T.ipv4_addr('12.10.12.10')
DIP = T.ipv4_addr('82.81.95.250')
IPV6_SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
IPV6_DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
REMOTE_ANY_IP = T.ipv4_addr('250.12.255.10')
LOCAL_IP1 = T.ipv4_addr('192.168.95.250')
ANY_IP = T.ipv4_addr('255.255.255.255')
TUNNEL_PORT_GID1 = 0x521
TTL = 128

MIRROR_CMD_GID = 0b01010
L3_MIRROR_CMD_GID = 0b01011

MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
L3_MIRROR_CMD_INGRESS_GID = L3_MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET
L3_MIRROR_CMD_EGRESS_GID = L3_MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET

MIRROR_VLAN = 0xA12

EGRESS_VLAN = 0x24
TUNNEL_TTL = 255
TUNNEL_DSCP = 46
TRAFFIC_CLASS = 0
TUNNEL_DEST = T.ipv4_addr('192.168.1.1')
TUNNEL_SOURCE = T.ipv4_addr('192.168.2.2')
UDP_SOURCE_PORT = 0x2345
UDP_DEST_PORT = 6343
SESSION_ID = 0x3ff

NEW_DEST_MAC = T.mac_addr('00:01:02:03:04:05')
NEW_SOURCE_MAC = T.mac_addr('06:07:08:09:0a:0b')
NEW_TUNNEL_TTL = 250
NEW_TUNNEL_DSCP = 47
NEW_TUNNEL_DEST = T.ipv4_addr('192.168.3.3')
NEW_TUNNEL_SOURCE = T.ipv4_addr('192.168.4.4')
NEW_VOQ_OFFSET = 5


class erspan_base(sdk_test_case_base):

    nonerspan_v4_acl = None
    nonerspan_v6_acl = None
    erspan_v4_acl = None
    erspan_v6_acl = None

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            device.set_bool_property(sdk.la_device_property_e_DESTINATION_SYSTEM_PORT_IN_IBM_METADATA, True)

    @classmethod
    def setUpClass(cls):
        super(erspan_base, cls).setUpClass(
            device_config_func=erspan_base.device_config_func)

    def setUp(self):
        self.maxDiff = None  # Show whole strings on failures (unittest variable)

        super().setUp()

        self.create_system_setup()
        try:
            self.create_packets()
        except AttributeError:
            pass

    def tearDown(self):
        self.clear_l3_acls()
        super().tearDown()

    def set_rx_slice_and_inject_header(self, rx_slice, rx_ifg):
        self.RX_slice = rx_slice
        self.RX_ifg = rx_ifg

        self.INJECT_UP_STD_HEADER = V.INJECT_UP_STD_HEADER
        header_ifg = V.get_physical_ifg(self.device.device_family, rx_slice, rx_ifg)
        self.INJECT_UP_STD_HEADER[V.INJECT_UP_STD_LAYER_INDEX].ifg_id = header_ifg

    def clear_l3_acls(self):
        acl_group = self.l3_port_impl.rx_port.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.l3_port_impl.rx_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        if acl_group:
            self.device.destroy(acl_group)

        if erspan_base.nonerspan_v4_acl is not None:
            self.device.destroy(erspan_base.nonerspan_v4_acl)
            erspan_base.nonerspan_v4_acl = None
        if erspan_base.erspan_v4_acl is not None:
            self.device.destroy(erspan_base.erspan_v4_acl)
            erspan_base.erspan_v4_acl = None
        if erspan_base.nonerspan_v6_acl is not None:
            self.device.destroy(erspan_base.nonerspan_v6_acl)
            erspan_base.nonerspan_v6_acl = None
        if erspan_base.erspan_v6_acl is not None:
            self.device.destroy(erspan_base.erspan_v6_acl)
            erspan_base.erspan_v6_acl = None

    def add_l3_2_acls(self,
                      acl1_is_mirror=True,
                      acl1_is_drop=False,
                      acl2_is_mirror=True,
                      acl2_is_drop=False):

        erspan_base.nonerspan_v4_acl = self.device.create_acl(
            self.topology.ingress_acl_key_profile_ipv4_def,
            self.topology.acl_command_profile_def)
        erspan_base.nonerspan_v6_acl = self.device.create_acl(
            self.topology.ingress_acl_key_profile_ipv6_def,
            self.topology.acl_command_profile_def)
        erspan_base.erspan_v4_acl = self.device.create_acl(
            self.topology.ingress_acl_key_profile_ipv4_def,
            self.topology.acl_command_profile_def)
        erspan_base.erspan_v6_acl = self.device.create_acl(
            self.topology.ingress_acl_key_profile_ipv6_def,
            self.topology.acl_command_profile_def)

        k = []
        acl1_cmd = []
        acl2_cmd = []

        if acl1_is_mirror:
            acl1_do_mirror_action = sdk.la_acl_command_action()
            acl1_do_mirror_action.type = sdk.la_acl_action_type_e_DO_MIRROR
            acl1_do_mirror_action.data.do_mirror = sdk.la_acl_mirror_src_e_DO_MIRROR_FROM_LP
            acl1_cmd.append(acl1_do_mirror_action)

        acl1_drop_action = sdk.la_acl_command_action()
        acl1_drop_action.type = sdk.la_acl_action_type_e_DROP
        acl1_drop_action.data.drop = acl1_is_drop
        acl1_cmd.append(acl1_drop_action)

        if acl1_is_drop:
            acl1_counter_cmd_action = sdk.la_acl_command_action()
            acl1_counter_cmd_action.type = sdk.la_acl_action_type_e_COUNTER
            acl1_counter_cmd_action.data.counter = self.device.create_counter(1)
            acl1_cmd.append(acl1_counter_cmd_action)

        erspan_base.nonerspan_v4_acl.append(k, acl1_cmd)
        erspan_base.nonerspan_v6_acl.append(k, acl1_cmd)

        if acl2_is_mirror:
            acl2_do_mirror_action = sdk.la_acl_command_action()
            acl2_do_mirror_action.type = sdk.la_acl_action_type_e_DO_MIRROR
            acl2_do_mirror_action.data.do_mirror = sdk.la_acl_mirror_src_e_DO_MIRROR_FROM_LP
            acl2_cmd.append(acl2_do_mirror_action)

        acl2_drop_action = sdk.la_acl_command_action()
        acl2_drop_action.type = sdk.la_acl_action_type_e_DROP
        acl2_drop_action.data.drop = acl2_is_drop
        acl2_cmd.append(acl2_drop_action)

        if acl2_is_drop:
            acl2_counter_cmd_action = sdk.la_acl_command_action()
            acl2_counter_cmd_action.type = sdk.la_acl_action_type_e_COUNTER
            acl2_counter_cmd_action.data.counter = self.device.create_counter(1)
            acl2_cmd.append(acl2_counter_cmd_action)

        erspan_base.erspan_v4_acl.append(k, acl2_cmd)
        erspan_base.erspan_v6_acl.append(k, acl2_cmd)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [erspan_base.erspan_v4_acl, erspan_base.nonerspan_v4_acl])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [erspan_base.erspan_v6_acl, erspan_base.nonerspan_v6_acl])

        self.l3_port_impl.rx_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

    def add_l3_acl(self, *, is_mirror=True, is_drop=False):
        erspan_base.erspan_v4_acl = self.device.create_acl(
            self.topology.ingress_acl_key_profile_ipv4_def,
            self.topology.acl_command_profile_def)
        erspan_base.erspan_v6_acl = self.device.create_acl(
            self.topology.ingress_acl_key_profile_ipv6_def,
            self.topology.acl_command_profile_def)

        k = []
        acl_cmd = []

        if is_mirror:
            do_mirror_action = sdk.la_acl_command_action()
            do_mirror_action.type = sdk.la_acl_action_type_e_DO_MIRROR
            do_mirror_action.data.do_mirror = sdk.la_acl_mirror_src_e_DO_MIRROR_FROM_LP
            acl_cmd.append(do_mirror_action)

        drop_action = sdk.la_acl_command_action()
        drop_action.type = sdk.la_acl_action_type_e_DROP
        drop_action.data.drop = is_drop
        acl_cmd.append(drop_action)

        if is_drop:
            counter_cmd_action = sdk.la_acl_command_action()
            counter_cmd_action.type = sdk.la_acl_action_type_e_COUNTER
            counter_cmd_action.data.counter = self.device.create_counter(1)
            acl_cmd.append(counter_cmd_action)

        erspan_base.erspan_v4_acl.append(k, acl_cmd)
        erspan_base.erspan_v6_acl.append(k, acl_cmd)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [erspan_base.erspan_v4_acl])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [erspan_base.erspan_v6_acl])

        self.l3_port_impl.rx_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

    def create_ip_over_ip_tunnel_ports(self):
        self.ip_impl = ip_test_base.ipv4_test_base
        # Overlay Prefix in 'vrf'
        self.overlay_prefix = self.ip_impl.build_prefix(DIP, length=16)
        self.ip_impl.add_route(
            self.topology.vrf,
            self.overlay_prefix,
            self.l3_port_impl.def_nh,
            PRIVATE_DATA)

        # VRF, Underlay Prefix
        tunnel_dest1 = self.ip_impl.build_prefix(LOCAL_IP1, length=16)

        self.ip_over_ip_any_src_tunnel_port = T.ip_over_ip_tunnel_port(self, self.device,
                                                                       TUNNEL_PORT_GID1,
                                                                       self.topology.vrf,
                                                                       tunnel_dest1,
                                                                       ANY_IP,
                                                                       self.topology.vrf)

        self.ip_over_ip_any_src_tunnel_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

    def destroy_ip_over_ip_tunnel_ports(self):

        self.ip_impl = ip_test_base.ipv4_test_base
        self.ip_over_ip_any_src_tunnel_port.destroy()
        self.ip_impl.delete_route(self.topology.vrf, self.overlay_prefix)

    def add_2_acls(self, is_drop):
        erspan_base.erspan_v4_acl = self.device.create_acl(
            self.topology.ingress_acl_key_profile_ipv4_def,
            self.topology.acl_command_profile_def)
        erspan_base.erspan_v6_acl = self.device.create_acl(
            self.topology.ingress_acl_key_profile_ipv6_def,
            self.topology.acl_command_profile_def)
        erspan_base.nonerspan_v4_acl = self.device.create_acl(
            self.topology.ingress_acl_key_profile_ipv4_def,
            self.topology.acl_command_profile_def)

        # ACL match on the Outer Header
        k_outer = []
        f_outer = sdk.la_acl_field()
        f_outer.type = sdk.la_acl_field_type_e_IPV4_DIP
        f_outer.val.ipv4_dip.s_addr = LOCAL_IP1.to_num()
        f_outer.mask.ipv4_dip.s_addr = 0xffffffff
        k_outer.append(f_outer)

        cmd_drop = []
        drop_action = sdk.la_acl_command_action()
        drop_action.type = sdk.la_acl_action_type_e_DROP
        drop_action.data.drop = is_drop
        cmd_drop.append(drop_action)

        erspan_base.nonerspan_v4_acl.append(k_outer, cmd_drop)
        acl_group = self.device.create_acl_group()

        k_erspan = []
        acl_cmd = []

        do_mirror_action = sdk.la_acl_command_action()
        do_mirror_action.type = sdk.la_acl_action_type_e_DO_MIRROR
        do_mirror_action.data.do_mirror = sdk.la_acl_mirror_src_e_DO_MIRROR_FROM_LP
        acl_cmd.append(do_mirror_action)

        erspan_base.erspan_v4_acl.append(k_erspan, acl_cmd)
        erspan_base.erspan_v6_acl.append(k_erspan, acl_cmd)

        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [erspan_base.erspan_v4_acl, erspan_base.nonerspan_v4_acl])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [erspan_base.erspan_v6_acl])

        self.l3_port_impl.rx_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

    def create_system_setup(self):
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, PRIVATE_DATA_DEFAULT)
        self.erspan_counter = self.device.create_counter(1)
        if (self.l3_port_impl.is_svi):
            self.mirror_cmd = T.erspan_mirror_command(
                self,
                self.device, MIRROR_CMD_INGRESS_GID,
                SESSION_ID,
                T.NH_SVI_REG_MAC.addr_str,
                TUNNEL_DEST,
                TUNNEL_SOURCE,
                TUNNEL_TTL,
                TUNNEL_DSCP,
                TRAFFIC_CLASS,
                self.l3_port_impl.tx_port.hld_obj,
                self.topology.tx_l2_ac_port_reg.hld_obj,
                self.topology.tx_svi_eth_port_reg.sys_port.hld_obj)
            self.l3_mirror_cmd = T.sflow_tunnel_mirror_command(
                self,
                self.device, L3_MIRROR_CMD_INGRESS_GID,
                UDP_SOURCE_PORT,
                UDP_DEST_PORT,
                T.NH_SVI_REG_MAC.addr_str,
                TUNNEL_DEST,
                TUNNEL_SOURCE,
                TUNNEL_TTL,
                TUNNEL_DSCP,
                TRAFFIC_CLASS,
                self.l3_port_impl.tx_port.hld_obj,
                self.topology.tx_l2_ac_port_reg.hld_obj,
                self.topology.tx_svi_eth_port_reg.sys_port.hld_obj)
        else:
            self.mirror_cmd = T.erspan_mirror_command(
                self,
                self.device, MIRROR_CMD_INGRESS_GID,
                SESSION_ID,
                T.NH_L3_AC_REG_MAC.addr_str,
                TUNNEL_DEST,
                TUNNEL_SOURCE,
                TUNNEL_TTL,
                TUNNEL_DSCP,
                TRAFFIC_CLASS,
                self.l3_port_impl.tx_port.hld_obj,
                None,
                self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj)
            self.l3_mirror_cmd = T.sflow_tunnel_mirror_command(
                self,
                self.device, L3_MIRROR_CMD_INGRESS_GID,
                UDP_SOURCE_PORT,
                UDP_DEST_PORT,
                T.NH_L3_AC_REG_MAC.addr_str,
                TUNNEL_DEST,
                TUNNEL_SOURCE,
                TUNNEL_TTL,
                TUNNEL_DSCP,
                TRAFFIC_CLASS,
                self.l3_port_impl.tx_port.hld_obj,
                None,
                self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj)
        self.mirror_cmd.hld_obj.set_counter(self.erspan_counter)
        self.l3_mirror_cmd.hld_obj.set_counter(self.erspan_counter)
        self.l3_port_impl.rx_port.hld_obj.set_load_balancing_profile(sdk.la_l3_port.lb_profile_e_IP)

    def get_mc_sa_addr_str(self, ip_addr):
        octets = ip_addr.addr_str.split('.')
        assert(len(octets) == 4)
        sa_addr_str = '01:00:5e'
        sa_addr_str += ':%02x' % (0x7f & int(octets[1]))
        for o in octets[2:]:
            sa_addr_str += ':%02x' % (int(o))
        return sa_addr_str

    def _test_mirroring_with_acl(self):
        if(self.l3_port_impl.is_svi):
            self.rx_port = self.topology.rx_svi
        else:
            self.rx_port = self.topology.rx_l3_ac

        self.add_l3_acl()
        self.rx_port.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=False)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.span_packet_data])

        packet_count, byte_count = self.erspan_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.span_packet, byte_count)

        self.rx_port.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=True)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.span_packet_data])

        packet_count, byte_count = self.erspan_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.span_packet, byte_count)

        self.clear_l3_acls()
        self.add_l3_acl(is_mirror=False, is_drop=False)

        self.rx_port.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=False)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.span_packet_data])

        packet_count, byte_count = self.erspan_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.span_packet, byte_count)

        self.rx_port.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=True)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data])
        self.clear_l3_acls()

    def _test_erspan_without_acl(self):
        if(self.l3_port_impl.is_svi):
            self.rx_port = self.topology.rx_svi
        else:
            self.rx_port = self.topology.rx_l3_ac

        self.rx_port.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=False)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.span_packet_data])
        mirror_cmd, is_acl_conditioned = self.rx_port.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.mirror_cmd.hld_obj.get_gid())
        self.assertFalse(is_acl_conditioned)

        packet_count, byte_count = self.erspan_counter.read(0, True, True)
        self.mirror_cmd.hld_obj.set_counter(None)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.span_packet, byte_count)

        self.rx_port.hld_obj.set_ingress_mirror_command(None, is_acl_conditioned=False)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data])

        self.rx_port.hld_obj.set_ingress_mirror_command(None, is_acl_conditioned=True)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data])

    def _test_l3_erspan_without_acl(self):
        if(self.l3_port_impl.is_svi):
            self.rx_port = self.topology.rx_svi
        else:
            self.rx_port = self.topology.rx_l3_ac

        self.rx_port.hld_obj.set_ingress_mirror_command(self.l3_mirror_cmd.hld_obj, is_acl_conditioned=False)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.l3_span_packet_data])
        mirror_cmd, is_acl_conditioned = self.rx_port.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.l3_mirror_cmd.hld_obj.get_gid())
        self.assertFalse(is_acl_conditioned)

        packet_count, byte_count = self.erspan_counter.read(0, True, True)
        self.l3_mirror_cmd.hld_obj.set_counter(None)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.l3_span_packet, byte_count)

        self.rx_port.hld_obj.set_ingress_mirror_command(None, is_acl_conditioned=False)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data])

        self.rx_port.hld_obj.set_ingress_mirror_command(None, is_acl_conditioned=True)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data])

    def _test_2acls_1(self):
        if(self.l3_port_impl.is_svi):
            self.rx_port = self.topology.rx_svi
        else:
            self.rx_port = self.topology.rx_l3_ac

        self.add_l3_2_acls(acl1_is_mirror=False, acl1_is_drop=True, acl2_is_mirror=True, acl2_is_drop=False)

        self.rx_port.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=True)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.span_packet_data])

        packet_count, byte_count = self.erspan_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.span_packet, byte_count)

        self.clear_l3_acls()

    def _test_2acls_2(self):
        if(self.l3_port_impl.is_svi):
            self.rx_port = self.topology.rx_svi
        else:
            self.rx_port = self.topology.rx_l3_ac

        self.add_l3_2_acls(acl1_is_mirror=False, acl1_is_drop=False, acl2_is_mirror=True, acl2_is_drop=False)

        self.rx_port.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=True)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.span_packet_data])
        # U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data])

        packet_count, byte_count = self.erspan_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.span_packet, byte_count)

        self.clear_l3_acls()

    def _test_2acls_3(self):
        if(self.l3_port_impl.is_svi):
            self.rx_port = self.topology.rx_svi
        else:
            self.rx_port = self.topology.rx_l3_ac

        self.add_l3_acl(is_mirror=True, is_drop=False)

        self.rx_port.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=True)
        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.span_packet_data])

        packet_count, byte_count = self.erspan_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.span_packet, byte_count)

        self.clear_l3_acls()
