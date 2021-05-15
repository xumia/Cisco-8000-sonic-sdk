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
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
from sdk_test_case_base import *
import smart_slices_choise as ssch
import nplapicli as nplapi

L3_AC_PORT_GID = 0x32
L3_AC_PORT_MAC_ADDR = T.mac_addr('44:33:44:33:44:33')
PUNT_INJECT_PORT_MAC_ADDR = "ca:fe:ba:be:ca:fe"
HOST_MAC_ADDR = "ba:be:ca:fe:ba:be"

MIRROR_CMD_GID1 = 11
MIRROR_CMD_GID2 = 21
MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0

MIRROR_VLAN = 0xA12

MIRROR_CMD_INGRESS_GID1 = MIRROR_CMD_GID1  + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID1 = MIRROR_CMD_GID1  + MIRROR_GID_EGRESS_OFFSET

MIRROR_CMD_INGRESS_GID2 = MIRROR_CMD_GID2  + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID2 = MIRROR_CMD_GID2  + MIRROR_GID_EGRESS_OFFSET

SA = T.mac_addr('be:ef:5d:35:7a:35')
SIP = T.ipv4_addr('12.10.12.10')
DIP = T.ipv4_addr('82.81.95.250')
TTL = 128
PRIVATE_DATA_DEFAULT = 0xfedcba9876543210


class l3_ac_base(sdk_test_case_base):

    PUNT_INJECT_SLICE = T.get_device_slice(3)
    PUNT_INJECT_IFG = T.get_device_ifg(0)
    PUNT_INJECT_PIF_FIRST = T.get_device_first_serdes(8)
    PUNT_INJECT_PIF_LAST = PUNT_INJECT_PIF_FIRST + 1
    PUNT_INJECT_SP_GID = 43

    def setUp(self):
        self.maxDiff = None  # Show whole strings on failures (unittest variable)

        super().setUp()
        ssch.rechoose_punt_inject_slice(self, self.device)

        self.create_system_setup()
        self.create_packets()

    def tearDown(self):
        self.clear_l3_acl()
        self.clear_l3_egress_acl()
        super().tearDown()

    def clear_l3_acl(self):
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    def add_l3_acl(self, *, is_mirror=True, is_drop=False):
        acl = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        k = []
        #k.val.mac.sa.flat = SA.to_num()
        #k.mask.mac.sa.flat = 0xffffffffffff

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = is_drop
        commands.append(action1)
        if is_mirror:
            action2 = sdk.la_acl_command_action()
            action2.type = sdk.la_acl_action_type_e_DO_MIRROR
            action2.data.do_mirror = sdk.la_acl_mirror_src_e_DO_MIRROR_FROM_LP
            commands.append(action2)
        if (is_drop):
            counter = self.device.create_counter(8)
            action3 = sdk.la_acl_command_action()
            action3.type = sdk.la_acl_action_type_e_COUNTER
            action3.data.counter = counter
            commands.append(action3)
            self.inserted_drop_counter = counter

        acl.append(k, commands)

        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

    def clear_l3_egress_acl(self):
        self.topology.tx_l3_ac_def.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

    def add_l3_egress_acl(self, *, is_mirror=True, is_drop=False):
        acl = self.device.create_acl(self.topology.egress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_SIP
        f1.val.ipv4_sip.s_addr = SIP.to_num()
        f1.mask.ipv4_sip.s_addr = 0xffffffff
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_IPV4_DIP
        f2.val.ipv4_dip.s_addr = DIP.to_num()
        f2.mask.ipv4_dip.s_addr = 0xffffff00
        k2.append(f2)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = is_drop
        commands.append(action1)
        if is_mirror:
            action2 = sdk.la_acl_command_action()
            action2.type = sdk.la_acl_action_type_e_DO_MIRROR
            action2.data.do_mirror = sdk.la_acl_mirror_src_e_DO_MIRROR_FROM_LP
            commands.append(action2)
        if (is_drop):
            counter = self.device.create_counter(8)
            action3 = sdk.la_acl_command_action()
            action3.type = sdk.la_acl_action_type_e_COUNTER
            action3.data.counter = counter
            commands.append(action3)
            self.inserted_drop_counter = counter

        acl.append(k1, commands)
        acl.append(k2, commands)

        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.tx_l3_ac_def.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)

    def create_packets(self):
        in_packet_base = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

        out_packet_base = \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

        ingress_punt_packet_base = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_INGRESS_GID1,
                   source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_L3_AC_GID, destination_lp=T.TX_L3_AC_DEF_GID,
                   relay_id=T.VRF_GID, lpts_flow_type=0
                   ) / \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

        egress_punt_packet_base = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_OUTBOUND_MIRROR, code=MIRROR_CMD_EGRESS_GID1,
                   source_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   destination_sp=T.TX_L3_AC_SYS_PORT_DEF_GID,
                   source_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID  | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                   destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                   relay_id=0, lpts_flow_type=0
                   ) / \
            S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

        self.in_packet, self.out_packet = U.pad_input_and_output_packets(in_packet_base, out_packet_base)
        __, self.ingress_punt_packet = U.pad_input_and_output_packets(in_packet_base, ingress_punt_packet_base)
        __, self.egress_punt_packet = U.pad_input_and_output_packets(in_packet_base, egress_punt_packet_base)

        self.in_packet_data = {'data': self.in_packet, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        self.out_packet_data = {
            'data': self.out_packet,
            'slice': T.TX_SLICE_DEF,
            'ifg': T.TX_IFG_DEF,
            'pif': self.l3_port_impl.serdes_def}
        self.ingress_punt_packet_data = {
            'data': self.ingress_punt_packet,
            'slice': self.PUNT_INJECT_SLICE,
            'ifg': self.PUNT_INJECT_IFG,
            'pif': self.PUNT_INJECT_PIF_FIRST}

        self.egress_punt_packet_data = {
            'data': self.egress_punt_packet,
            'slice': self.PUNT_INJECT_SLICE,
            'ifg': self.PUNT_INJECT_IFG,
            'pif': self.PUNT_INJECT_PIF_FIRST,
            'egress_mirror_pi_port_pkt': True}

        self.ingress_mirror_packet_data = {
            'data': self.in_packet,
            'slice': T.RX_SLICE,
            'ifg': T.RX_IFG1,
            'pif': T.FIRST_SERDES1,
            'ingress_mirror': True}
        self.egress_mirror_packet_data = {
            'data': self.out_packet,
            'slice': T.RX_SLICE,
            'ifg': T.RX_IFG1,
            'pif': T.FIRST_SERDES1,
            'egress_mirror': True}

    def create_system_setup(self):
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)
        prefix = ip_test_base.ipv4_test_base.get_default_prefix()
        ip_test_base.ipv4_test_base.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, PRIVATE_DATA_DEFAULT)
        self.pi_port = T.punt_inject_port(self, self.device, self.PUNT_INJECT_SLICE, self.PUNT_INJECT_IFG, self.PUNT_INJECT_SP_GID,
                                          self.PUNT_INJECT_PIF_FIRST, PUNT_INJECT_PORT_MAC_ADDR)
        self.ingress_mirror_cmd = T.create_l2_mirror_command(
            self.device, MIRROR_CMD_INGRESS_GID1, self.pi_port, HOST_MAC_ADDR, MIRROR_VLAN)
        self.egress_mirror_cmd = T.create_l2_mirror_command(
            self.device, MIRROR_CMD_EGRESS_GID1, self.pi_port, HOST_MAC_ADDR, MIRROR_VLAN)
        self.l3_port_impl.rx_port.hld_obj.set_load_balancing_profile(sdk.la_l3_port.lb_profile_e_IP)
        self.ingress_mirror_command = self.device.create_l2_mirror_command(
            MIRROR_CMD_INGRESS_GID2, self.topology.rx_eth_port1.hld_obj, self.topology.rx_eth_port1.hld_obj.get_system_port(), 0, 1)
        self.egress_mirror_command = self.device.create_l2_mirror_command(
            MIRROR_CMD_EGRESS_GID2, self.topology.rx_eth_port1.hld_obj, self.topology.rx_eth_port1.hld_obj.get_system_port(), 0, 1)
