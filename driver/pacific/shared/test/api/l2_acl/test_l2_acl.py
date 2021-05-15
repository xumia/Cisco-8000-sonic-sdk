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

import decor
from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import nplapicli as nplapi
from sdk_test_case_base import *

SYS_PORT_GID_BASE = 23

IN_SLICE = T.get_device_slice(2)
QINQ_IN_SLICE = 0
IN_IFG = 0
IN_PIF_FIRST = T.get_device_first_serdes(4)
IN_PIF_LAST = IN_PIF_FIRST + 1
OUT_SLICE = T.get_device_slice(4)
QINQ_OUT_SLICE = T.get_device_slice(5)
OUT_IFG = T.get_device_ifg(1)
OUT_PIF_FIRST = T.get_device_out_first_serdes(8)
OUT_PIF_LAST = OUT_PIF_FIRST + 1
ACL_SLICE = T.get_device_slice(3)
ACL_IFG = T.get_device_ifg(1)
ACL_PIF_FIRST = T.get_device_next_first_serdes(8)
ACL_PIF_LAST = ACL_PIF_FIRST + 1
PUNT_INJECT_SLICE = T.get_device_slice(3)
PUNT_INJECT_IFG = 0
PUNT_INJECT_PIF_FIRST = T.get_device_punt_inject_first_serdes(8)
PUNT_INJECT_PIF_LAST = PUNT_INJECT_PIF_FIRST + 1
PUNT_INJECT_SP_GID = SYS_PORT_GID_BASE + 20
MIRROR_DEST_SLICE = T.get_device_slice(3)
MIRROR_DEST_IFG = 0
MIRROR_DEST_PIF_FIRST = T.get_device_out_next_first_serdes(4)
MIRROR_DEST_PIF_LAST = MIRROR_DEST_PIF_FIRST + 1

AC_PORT_GID_BASE = 10

SWITCH_GID = 100

DST_MAC = "ca:fe:ca:fe:ca:fe"
DST_MAC2 = "ba:fe:ba:fe:ba:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0xAB9
INNER_VLAN = 0xBB9
OUTER_VLAN = 0xBBA
SOME_VLAN = 0xF12

PUNT_INJECT_PORT_MAC_ADDR = "ca:fe:ba:be:ca:fe"
HOST_MAC_ADDR = "ba:be:ca:fe:ba:be"

PUNT_VLAN = 0xA13
MIRROR_VLAN = 0xA12

SIMPLE_QOS_COUNTER_OFFSET = 4

MIRROR_CMD_GID = 9
MIRROR_CMD_GID2 = 11

MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0

MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_INGRESS_GID2 = MIRROR_CMD_GID2 + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET
MIRROR_CMD_EGRESS_GID2 = MIRROR_CMD_GID2 + MIRROR_GID_EGRESS_OFFSET


@unittest.skipIf(decor.is_hw_device(), "Skip moved from Makefile")
@unittest.skipIf(decor.is_matilda(), "Tests are not yet enabled on Mathilda models.")
class test_l2_acl(sdk_test_case_base):

    def setUp(self):
        super().setUp(create_default_topology=False)

        self.topology.create_inject_ports()
        self.create_system_setup()
        self.create_packets()

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / TCP()

        in_packet_qinq_outer_base = Ether(dst=DST_MAC2, src=SRC_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(prio=2, id=1, vlan=OUTER_VLAN, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=SOME_VLAN) / \
            IP() / TCP()

        out_packet_qinq_outer_base = Ether(dst=DST_MAC2, src=SRC_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(prio=2, id=1, vlan=OUTER_VLAN, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=SOME_VLAN) / \
            IP() / TCP()

        in_packet_qinq_inner_base = Ether(dst=DST_MAC2, src=SRC_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(prio=2, id=1, vlan=SOME_VLAN, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=INNER_VLAN) / \
            IP() / TCP()

        out_packet_qinq_inner_base = Ether(dst=DST_MAC2, src=SRC_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(prio=2, id=1, vlan=SOME_VLAN, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=INNER_VLAN) / \
            IP() / TCP()

        mirror_packet_ingress_base = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET, next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_INGRESS_GID,
                 source_sp=SYS_PORT_GID_BASE, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                 destination_lp=AC_PORT_GID_BASE + 1,
                 relay_id=SWITCH_GID, lpts_flow_type=0) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / \
            TCP()

        mirror_packet_egress_base = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET, next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_EGRESS_GID,
                 source_sp=SYS_PORT_GID_BASE, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                 destination_lp=AC_PORT_GID_BASE + 1,
                 relay_id=SWITCH_GID, lpts_flow_type=0) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / \
            TCP()

        mirror_packet_tx_at_ac_port2_base = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET, next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_OUTBOUND_MIRROR, code=MIRROR_CMD_GID,
                 source_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID, destination_sp=SYS_PORT_GID_BASE + 1,
                 source_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                 destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                 relay_id=0, lpts_flow_type=0) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / \
            TCP()

        mirror_packet_ingress_rx_at_ac_port3_base = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET, next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_INGRESS_GID,
                 source_sp=SYS_PORT_GID_BASE + 2, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=AC_PORT_GID_BASE + 2 | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                 destination_lp=AC_PORT_GID_BASE + 1,
                 relay_id=SWITCH_GID, lpts_flow_type=0) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / \
            TCP()

        mirror_packet_egress_rx_at_ac_port3_base = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET, next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_EGRESS_GID,
                 source_sp=SYS_PORT_GID_BASE + 2, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=AC_PORT_GID_BASE + 2 | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                 destination_lp=AC_PORT_GID_BASE + 1,
                 relay_id=SWITCH_GID, lpts_flow_type=0) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / \
            TCP()

        mirror_packet_ingress_rx_at_ac_port4_base = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET, next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_INGRESS_GID,
                 source_sp=SYS_PORT_GID_BASE + 3, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=AC_PORT_GID_BASE + 3 | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                 destination_lp=AC_PORT_GID_BASE + 1,
                 relay_id=SWITCH_GID, lpts_flow_type=0) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / \
            TCP()

        mirror_packet_egress_rx_at_ac_port4_base = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET, next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR, code=MIRROR_CMD_EGRESS_GID,
                 source_sp=SYS_PORT_GID_BASE + 3, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=AC_PORT_GID_BASE + 3 | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                 destination_lp=AC_PORT_GID_BASE + 1,
                 relay_id=SWITCH_GID, lpts_flow_type=0) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / \
            TCP()

        ingress_punt_packet_base = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET, next_header_offset=len(Ether()) + len(Dot1Q()),
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                 code=nplapi.NPL_REDIRECT_CODE_L2_ACL_DROP,
                 source_sp=SYS_PORT_GID_BASE, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 #source_lp=AC_PORT_GID_BASE, destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                 source_lp=AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                 destination_lp=nplapi.NPL_REDIRECT_CODE_L2_ACL_DROP,
                 relay_id=SWITCH_GID, lpts_flow_type=0) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / \
            TCP()

        egress_punt_packet_base = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET, next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_EGRESS_ACL,
                 code=nplapi.NPL_REDIRECT_CODE_L2_ACL_DROP,
                 source_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID, destination_sp=SYS_PORT_GID_BASE + 1,
                 source_lp=AC_PORT_GID_BASE | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                 destination_lp=AC_PORT_GID_BASE + 1,
                 relay_id=SWITCH_GID, lpts_flow_type=0) / \
            Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=VLAN) / \
            IP() / \
            TCP()

        ingress_qinq_outer_vlan_punt_packet_base = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type =sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET, next_header_offset =len(Ether()) + 2 * len(Dot1Q()),
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                 code=nplapi.NPL_REDIRECT_CODE_L2_ACL_DROP,
                 source_sp=SYS_PORT_GID_BASE + 4, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 # source_lp=AC_PORT_GID_BASE + 4, destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                 source_lp=AC_PORT_GID_BASE + 4 | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                 destination_lp=nplapi.NPL_REDIRECT_CODE_L2_ACL_DROP,
                 relay_id=SWITCH_GID, lpts_flow_type=0) / \
            Ether(dst=DST_MAC2, src=SRC_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(prio=2, id=1, vlan=OUTER_VLAN, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=SOME_VLAN) / \
            IP() / TCP()

        ingress_qinq_inner_vlan_punt_packet_base = \
            Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET, next_header_offset= len(Ether()) + 2 * len(Dot1Q()),
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                 code=nplapi.NPL_REDIRECT_CODE_L2_ACL_DROP,
                 source_sp=SYS_PORT_GID_BASE + 4, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 # source_lp=AC_PORT_GID_BASE + 8, destination_lp=sdk.la_packet_types.LA_L2_LOGICAL_PORT_GID_INVALID,
                 source_lp=AC_PORT_GID_BASE + 8 | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                 destination_lp=nplapi.NPL_REDIRECT_CODE_L2_ACL_DROP,
                 relay_id=SWITCH_GID, lpts_flow_type=0) / \
            Ether(dst=DST_MAC2, src=SRC_MAC, type=Ethertype.QinQ.value) / \
            Dot1Q(prio=2, id=1, vlan=SOME_VLAN, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=2, id=1, vlan=INNER_VLAN) / \
            IP() / TCP()

        self.in_packet, base_input_packet_payload_size = enlarge_packet_to_min_length(in_packet_base)
        self.out_packet = add_payload(out_packet_base, base_input_packet_payload_size)
        self.in_packet_qinq_outer = add_payload(in_packet_qinq_outer_base, base_input_packet_payload_size)
        self.out_packet_qinq_outer = add_payload(out_packet_qinq_outer_base, base_input_packet_payload_size)
        self.in_packet_qinq_inner = add_payload(in_packet_qinq_inner_base, base_input_packet_payload_size)
        self.out_packet_qinq_inner = add_payload(out_packet_qinq_inner_base, base_input_packet_payload_size)
        self.mirror_packet_ingress = add_payload(mirror_packet_ingress_base, base_input_packet_payload_size)
        self.mirror_packet_egress = add_payload(mirror_packet_egress_base, base_input_packet_payload_size)
        self.mirror_packet_tx_at_ac_port2 = add_payload(mirror_packet_tx_at_ac_port2_base, base_input_packet_payload_size)

        self.mirror_packet_ingress_rx_at_ac_port3 = add_payload(
            mirror_packet_ingress_rx_at_ac_port3_base, base_input_packet_payload_size)
        self.mirror_packet_egress_rx_at_ac_port3 = add_payload(
            mirror_packet_egress_rx_at_ac_port3_base, base_input_packet_payload_size)

        self.mirror_packet_ingress_rx_at_ac_port4 = add_payload(
            mirror_packet_ingress_rx_at_ac_port4_base, base_input_packet_payload_size)
        self.mirror_packet_egress_rx_at_ac_port4 = add_payload(
            mirror_packet_egress_rx_at_ac_port4_base, base_input_packet_payload_size)

        self.ingress_punt_packet = add_payload(ingress_punt_packet_base, base_input_packet_payload_size)
        self.egress_punt_packet = add_payload(egress_punt_packet_base, base_input_packet_payload_size)
        self.ingress_qinq_outer_vlan_punt_packet = add_payload(
            ingress_qinq_outer_vlan_punt_packet_base, base_input_packet_payload_size)
        self.ingress_qinq_inner_vlan_punt_packet = add_payload(
            ingress_qinq_inner_vlan_punt_packet_base, base_input_packet_payload_size)

    def create_empty_acl(self):
        acl0 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl0, None)

        count = acl0.get_count()
        self.assertEqual(count, 0)

        return acl0

    def create_simple_sec_acl(self, dir):
        if dir == sdk.la_acl_direction_e_INGRESS:
            self.eth_ingress_acl_key_profile = self.device.create_acl_key_profile(
                sdk.la_acl_key_type_e_ETHERNET, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_ETHERNET, 0)
            acl1 = self.device.create_acl(self.eth_ingress_acl_key_profile, self.topology.acl_command_profile_def)
        else:
            self.eth_egress_acl_key_profile = self.device.create_acl_key_profile(
                sdk.la_acl_key_type_e_ETHERNET, sdk.la_acl_direction_e_EGRESS, sdk.LA_ACL_KEY_ETHERNET, 0)
            acl1 = self.device.create_acl(self.eth_egress_acl_key_profile, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_SA
        f1.val.sa.flat = 0xcafecafecafe
        f1.mask.sa.flat = 0xffffffffffff
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_DA
        f2.val.da.flat = 0xcafecafe0000
        f2.mask.da.flat = 0xffffffff0000
        k2.append(f2)

        k3 = []
        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_DA
        f3.val.da.flat = 0xdeaddeaddead
        f3.mask.da.flat = 0xffffffffffff
        k3.append(f3)

        cmd_nop = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        cmd_nop.append(action1)

        cmd_redirect = []
        action2 = sdk.la_acl_command_action()
        if dir == sdk.la_acl_direction_e_INGRESS:
            action2.type = sdk.la_acl_action_type_e_L2_DESTINATION
            action2.data.l2_dest = self.ac_port3.hld_obj
        else:
            action2.type = sdk.la_acl_action_type_e_DROP
            action2.data.drop = False
        cmd_redirect.append(action2)

        cmd_drop = []
        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_DROP
        action3.data.drop = True

        acl1.append(k1, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, cmd_redirect)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        acl1.append(k3, cmd_drop)
        count = acl1.get_count()
        self.assertEqual(count, 3)

        acl_entry_desc = acl1.get(0)
        self.assertEqual(acl_entry_desc.key_val[0].type, k1[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.sa.flat, k1[0].val.sa.flat)
        self.assertEqual(acl_entry_desc.key_val[0].mask.sa.flat, k1[0].mask.sa.flat)
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, cmd_nop[0].type)
        self.assertEqual(acl_entry_desc.cmd_actions[0].data.drop, cmd_nop[0].data.drop)

        acl_entry_desc = acl1.get(1)
        self.assertEqual(acl_entry_desc.key_val[0].type, k2[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.sa.flat, k2[0].val.sa.flat)
        self.assertEqual(acl_entry_desc.key_val[0].mask.sa.flat, k2[0].mask.sa.flat)
        if dir == sdk.la_acl_direction_e_INGRESS:
            self.assertEqual(acl_entry_desc.cmd_actions[0].data.l2_dest.this, cmd_redirect[0].data.l2_dest.this)
        else:
            self.assertEqual(acl_entry_desc.cmd_actions[0].type, cmd_redirect[0].type)
            self.assertEqual(acl_entry_desc.cmd_actions[0].data.drop, cmd_redirect[0].data.drop)

        return acl1

    def create_simple_sec_acl_inner_vlan(self):
        acl_key = []
        key1 = sdk.la_acl_field_def()
        key1.type = sdk.la_acl_field_type_e_DA
        acl_key.append(key1)
        key2 = sdk.la_acl_field_def()
        key2.type = sdk.la_acl_field_type_e_SA
        acl_key.append(key2)
        key3 = sdk.la_acl_field_def()
        key3.type = sdk.la_acl_field_type_e_VLAN_INNER
        acl_key.append(key3)

        self.eth_ingress_acl_key_profile_inner = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_ETHERNET, sdk.la_acl_direction_e_INGRESS, acl_key, 0)

        acl1 = self.device.create_acl(self.eth_ingress_acl_key_profile_inner, self.topology.acl_command_profile_def)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_SA
        f1.val.sa.flat = 0xbafebafebafe
        f1.mask.sa.flat = 0xffffffffffff
        k1.append(f1)

        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_VLAN_INNER
        f1.val.vlan1.tci.fields.vid = INNER_VLAN
        f1.mask.vlan1.tci.fields.vid = 0xfff
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_DA
        f2.val.da.flat = 0xbafebafe0000
        f2.mask.da.flat = 0xffffffff0000
        k2.append(f2)

        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_VLAN_INNER
        f2.val.vlan2.tci.fields.vid = INNER_VLAN
        f2.mask.vlan2.tci.fields.vid = 0xfff
        k2.append(f2)

        cmd_nop = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        cmd_nop.append(action1)

        cmd_redirect = []
        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_L2_DESTINATION
        action2.data.l2_dest = self.ac_port8.hld_obj
        cmd_redirect.append(action2)

        cmd_drop = []
        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_DROP
        action3.data.drop = True

        acl1.append(k1, cmd_nop)
        acl1.append(k2, cmd_redirect)

        acl_entry_desc = acl1.get(0)
        self.assertEqual(acl_entry_desc.key_val[0].type, k1[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.sa.flat, k1[0].val.sa.flat)
        self.assertEqual(acl_entry_desc.key_val[0].mask.sa.flat, k1[0].mask.sa.flat)
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, cmd_nop[0].type)
        self.assertEqual(acl_entry_desc.cmd_actions[0].data.drop, cmd_nop[0].data.drop)

        acl_entry_desc = acl1.get(1)
        self.assertEqual(acl_entry_desc.key_val[0].type, k2[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.sa.flat, k2[0].val.sa.flat)
        self.assertEqual(acl_entry_desc.key_val[0].mask.sa.flat, k2[0].mask.sa.flat)
        self.assertEqual(acl_entry_desc.cmd_actions[0].data.l2_dest.this, cmd_redirect[0].data.l2_dest.this)

        return acl1

    def create_simple_sec_acl_vlan(self):
        self.eth_ingress_acl_key_profile = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_ETHERNET, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_ETHERNET, 0)
        acl1 = self.device.create_acl(self.eth_ingress_acl_key_profile, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_SA
        f1.val.sa.flat = 0xbafebafebafe
        f1.mask.sa.flat = 0xffffffffffff
        k1.append(f1)

        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_VLAN_OUTER
        f1.val.vlan1.tci.fields.vid = OUTER_VLAN
        f1.mask.vlan1.tci.fields.vid = 0xfff
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_DA
        f2.val.da.flat = 0xbafebafe0000
        f2.mask.da.flat = 0xffffffff0000
        k2.append(f2)

        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_VLAN_OUTER
        f2.val.vlan2.tci.fields.vid = OUTER_VLAN
        f2.mask.vlan2.tci.fields.vid = 0xfff
        k2.append(f2)

        cmd_nop = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        cmd_nop.append(action1)

        cmd_redirect = []
        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_L2_DESTINATION
        action2.data.l2_dest = self.ac_port7.hld_obj
        cmd_redirect.append(action2)

        cmd_drop = []
        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_DROP
        action3.data.drop = True

        acl1.append(k1, cmd_nop)
        acl1.append(k2, cmd_redirect)

        acl_entry_desc = acl1.get(0)
        self.assertEqual(acl_entry_desc.key_val[0].type, k1[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.sa.flat, k1[0].val.sa.flat)
        self.assertEqual(acl_entry_desc.key_val[0].mask.sa.flat, k1[0].mask.sa.flat)
        self.assertEqual(acl_entry_desc.cmd_actions[0].type, cmd_nop[0].type)
        self.assertEqual(acl_entry_desc.cmd_actions[0].data.drop, cmd_nop[0].data.drop)

        acl_entry_desc = acl1.get(1)
        self.assertEqual(acl_entry_desc.key_val[0].type, k2[0].type)
        self.assertEqual(acl_entry_desc.key_val[0].val.sa.flat, k2[0].val.sa.flat)
        self.assertEqual(acl_entry_desc.key_val[0].mask.sa.flat, k2[0].mask.sa.flat)
        self.assertEqual(acl_entry_desc.cmd_actions[0].data.l2_dest.this, cmd_redirect[0].data.l2_dest.this)

        return acl1

    def insert_ace(self, acl, cmd_type, is_drop, mirror):
        # Insert ACE that catch all traffic and result in NOP or DROP if is_drop == True

        k1 = []

        # acl_cmd = sdk.la_acl_command()
        # acl_cmd.type = cmd_type
        # if (cmd_type == sdk.la_acl_cmd_type_e_INGRESS_UNIFIED):
        #     cmd_data = acl_cmd.data.ingress_unified.sec
        # elif (cmd_type == sdk.la_acl_cmd_type_e_EGRESS_UNIFIED):
        #     cmd_data = acl_cmd.data.egress_unified.sec
        # cmd_data.drop = is_drop

        acl_cmd = []
        action = sdk.la_acl_command_action()
        action.type = sdk.la_acl_action_type_e_DROP
        action.data.drop = is_drop
        acl_cmd.append(action)

        if (is_drop):
            counter = self.device.create_counter(1)
            action = sdk.la_acl_command_action()
            action.type = sdk.la_acl_action_type_e_COUNTER
            action.data.counter = counter
            acl_cmd.append(action)
            self.inserted_drop_counter = counter

        count_pre = acl.get_count()
        acl.insert(0, k1, acl_cmd)

        count_post = acl.get_count()
        self.assertEqual(count_post, count_pre + 1)

    def insert_drop_ace(self, acl, cmd_type):
        # Insert ACE that catch all traffic and result in drop
        self.insert_ace(acl, cmd_type, True, False)

    def insert_mirror_ace(self, acl, cmd_type, mirror_cmd):
        # Insert ACE that catch all traffic and result in mirror
        self.insert_ace(acl, cmd_type, False, True)

    def insert_nop_ace(self, acl, cmd_type):
        # Insert ACE that catch all traffic and result in NOP
        self.insert_ace(acl, cmd_type, False, False)

    def create_simple_qos_acl(self):
        self.eth_ingress_acl_key_profile = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_ETHERNET, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_ETHERNET, 0)
        acl1 = self.device.create_acl(self.eth_ingress_acl_key_profile, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_SA
        f1.val.sa.flat = 0xcafecafecafe
        f1.mask.sa.flat = 0xffffffffffff
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_DA
        f2.val.da.flat = 0xcafecafe0000
        f2.mask.da.flat = 0xffffffff0000
        k2.append(f2)

        k3 = []
        f3 = sdk.la_acl_field()
        f3.type = sdk.la_acl_field_type_e_DA
        f3.val.da.flat = 0xdeaddeaddead
        f3.mask.da.flat = 0xffffffffffff
        k3.append(f3)

        cmd_nop = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        cmd_nop.append(action1)

        cmd_phb_overwrite = []
        do_qos_action = sdk.la_acl_command_action()
        do_qos_action.type = sdk.la_acl_action_type_e_COUNTER_TYPE
        do_qos_action.data.counter_type = sdk.la_acl_counter_type_e_DO_QOS_COUNTING
        cmd_phb_overwrite.append(do_qos_action)

        qos_action = sdk.la_acl_command_action()
        qos_action.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
        qos_action.data.qos_offset = SIMPLE_QOS_COUNTER_OFFSET
        cmd_phb_overwrite.append(qos_action)

        qos_action = sdk.la_acl_command_action()
        qos_action.type = sdk.la_acl_action_type_e_TRAFFIC_CLASS
        qos_action.data.traffic_class = 7
        cmd_phb_overwrite.append(qos_action)

        color_action = sdk.la_acl_command_action()
        color_action.type = sdk.la_acl_action_type_e_COLOR
        color_action.data.color = 3
        cmd_phb_overwrite.append(color_action)

        remark_fwd_action = sdk.la_acl_command_action()
        remark_fwd_action.type = sdk.la_acl_action_type_e_REMARK_FWD
        remark_fwd_action.data.remark_fwd = 0
        cmd_phb_overwrite.append(remark_fwd_action)

        encap_exp_action = sdk.la_acl_command_action()
        encap_exp_action.type = sdk.la_acl_action_type_e_ENCAP_EXP
        encap_exp_action.data.encap_exp = 0
        cmd_phb_overwrite.append(encap_exp_action)

        remark_group_action = sdk.la_acl_command_action()
        remark_group_action.type = sdk.la_acl_action_type_e_REMARK_GROUP
        remark_group_action.data.remark_group = 0
        cmd_phb_overwrite.append(remark_group_action)

        acl1.append(k1, cmd_nop)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        acl1.append(k2, cmd_phb_overwrite)
        count = acl1.get_count()
        self.assertEqual(count, 2)

        return acl1

    def create_system_setup(self):
        self.sw1 = T.switch(self, self.device, SWITCH_GID)

        # Add 'cafecafecafe' to the MAC table, going to AC port 2
        self.dest_mac = T.mac_addr(DST_MAC)

        self.eth_port1 = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_PIF_FIRST, IN_PIF_LAST)
        self.ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port1,
            None,
            VLAN,
            0x0)

        self.eth_port4 = T.ethernet_port(self, self.device, MIRROR_DEST_SLICE, MIRROR_DEST_IFG,
                                         SYS_PORT_GID_BASE + 3, MIRROR_DEST_PIF_FIRST, MIRROR_DEST_PIF_LAST)
        self.ac_port4 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 3,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port4,
            None,
            VLAN,
            0x0)

        self.egress_mirror_command = self.device.create_l2_mirror_command(
            MIRROR_CMD_EGRESS_GID2, self.eth_port4.hld_obj, self.eth_port4.hld_obj.get_system_port(), 0, 1)

        self.ingress_mirror_command = self.device.create_l2_mirror_command(
            MIRROR_CMD_INGRESS_GID2, self.eth_port4.hld_obj, self.eth_port4.hld_obj.get_system_port(), 0, 1)

        self.eth_port2 = T.ethernet_port(self, self.device, OUT_SLICE, OUT_IFG, SYS_PORT_GID_BASE + 1, OUT_PIF_FIRST, OUT_PIF_LAST)
        self.ac_port2 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port2,
            self.dest_mac,
            VLAN,
            0x0)

        self.eth_port3 = T.ethernet_port(self, self.device, ACL_SLICE, ACL_IFG, SYS_PORT_GID_BASE + 2, ACL_PIF_FIRST, ACL_PIF_LAST)
        self.ac_port3 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE +
                                     2, self.topology.filter_group_def, self.sw1, self.eth_port3, None, VLAN, 0x0)

        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            PUNT_INJECT_SLICE,
            PUNT_INJECT_IFG,
            PUNT_INJECT_SP_GID,
            PUNT_INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)

        # self.mirror_cmd = T.create_l2_mirror_command(self.device, MIRROR_CMD_GID, self.pi_port, HOST_MAC_ADDR, MIRROR_VLAN)

        self.ingress_mirror_cmd = T.create_l2_mirror_command(
            self.device, MIRROR_CMD_INGRESS_GID, self.pi_port, HOST_MAC_ADDR, MIRROR_VLAN)
        self.egress_mirror_cmd = T.create_l2_mirror_command(
            self.device, MIRROR_CMD_EGRESS_GID, self.pi_port, HOST_MAC_ADDR, MIRROR_VLAN)

        port5_serdes_first = T.get_device_next2_first_serdes(IN_PIF_FIRST)
        port5_serdes_last = T.get_device_next2_last_serdes(IN_PIF_LAST)
        self.eth_port5 = T.ethernet_port(
            self,
            self.device,
            QINQ_IN_SLICE,
            IN_IFG,
            SYS_PORT_GID_BASE + 4,
            port5_serdes_first,
            port5_serdes_last)

        self.ac_port5 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 4,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port5,
            None,
            OUTER_VLAN,
            SOME_VLAN)
        port6_first_serdes = T.get_device_out_next_next_first_serdes(OUT_PIF_FIRST)
        port6_last_serdes = T.get_device_out_next_next_last_serdes(OUT_PIF_LAST)
        self.eth_port6 = T.ethernet_port(
            self,
            self.device,
            QINQ_OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 5,
            port6_first_serdes,
            port6_last_serdes)
        self.dest_mac = T.mac_addr(DST_MAC2)
        self.ac_port6 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 5,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port6,
            self.dest_mac,
            SOME_VLAN,
            INNER_VLAN)

        self.ac_port7 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE +
                                     6, self.topology.filter_group_def, self.sw1, self.eth_port3, None, OUTER_VLAN, SOME_VLAN)
        self.ac_port8 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE +
                                     7, self.topology.filter_group_def, self.sw1, self.eth_port3, None, SOME_VLAN, INNER_VLAN)
        self.ac_port9 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 8,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port5,
            None,
            SOME_VLAN,
            INNER_VLAN)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_acl_force_destination(self):
        acl1 = self.create_simple_sec_acl(sdk.la_acl_direction_e_INGRESS)

        # Pass packet from port 2 to port 4, through a relay without ACL hit
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1])
        self.ac_port1.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            ACL_SLICE,
            ACL_IFG,
            ACL_PIF_FIRST)

        # Detach ACL
        self.ac_port1.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Pass packet from port 2 to port 4, through a relay without ACL hit
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_acl_qos_l2(self):
        acl1 = self.create_simple_qos_acl()

        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare_inner_fields(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_PIF_FIRST, self.out_packet, OUT_SLICE,
                                     OUT_IFG, OUT_PIF_FIRST, control_expected)

        # Attach a counter
        counter = self.device.create_counter(8)
        self.ac_port1.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, counter)

        # Attach the QoS ACL
        # self.topology.ingress_qos_profile_def.hld_obj.set_acl(acl1)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1])
        self.ac_port1.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # Test the resolved PHB at the end of RXPP is 0x1f  - overwriten by the ACL
        # Pass packet with ACL applied, ensure PHB changes to non-default default (0x1F).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        run_and_compare_inner_fields(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_PIF_FIRST, self.out_packet, OUT_SLICE,
                                     OUT_IFG, OUT_PIF_FIRST, control_expected)

        # Verify counter
        packet_count, byte_count = counter.read(SIMPLE_QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)
        assertPacketLengthIngress(self, self.in_packet, IN_SLICE, byte_count)

        # Detach ACL
        self.ac_port1.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        run_and_compare_inner_fields(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_PIF_FIRST, self.out_packet, OUT_SLICE,
                                     OUT_IFG, OUT_PIF_FIRST, control_expected)

    @unittest.skipIf(decor.is_pacific(), "Test disabled pending QoS rework")
    @unittest.skipIf(decor.is_gibraltar(), "Test disabled pending QoS rework")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_acl_drop(self):
        trap_priority = 0

        acl1 = self.create_simple_sec_acl(sdk.la_acl_direction_e_EGRESS)

        # Pass packet from port 2 to port 4, through a relay without ACL hit
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, [acl1])
        self.ac_port2.hld_obj.set_acl_group(sdk.la_acl_direction_e_EGRESS, acl_group)

        # Pass packet from port 2 to port 4, through a relay without ACL hit
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

        # Add drop ACE
        self.insert_drop_ace(acl1, sdk.la_acl_cmd_type_e_EGRESS_UNIFIED)

        # Test drop
        run_and_drop(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_PIF_FIRST)

        # Check counter
        packet_count, byte_count = self.inserted_drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Change drop to punt
        self.device.set_trap_configuration(
            sdk.LA_EVENT_ETHERNET_ACL_DROP,
            trap_priority,
            None,
            self.punt_dest,
            False,
            False,
            True, 0)

        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': IN_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': self.egress_punt_packet,
                               'slice': PUNT_INJECT_SLICE,
                               'ifg': PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_PIF_FIRST}])

        # Change drop back to actually drop
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ACL_DROP, trap_priority, None, None, False, False, True, 0)
        run_and_drop(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_PIF_FIRST)

        # Detach ACL
        self.ac_port2.hld_obj.clear_acl_group(sdk.la_acl_direction_e_EGRESS)

        # Pass packet from port 2 to port 4, through a relay without ACL hit
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)
        self.device.destroy(acl_group)
        self.device.destroy(acl1)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_acl_drop(self):
        trap_priority = 0

        acl1 = self.create_simple_sec_acl(sdk.la_acl_direction_e_INGRESS)

        # Pass packet from port 2 to port 4, through a relay without ACL hit
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1])
        self.ac_port1.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            ACL_SLICE,
            ACL_IFG,
            ACL_PIF_FIRST)

        # Add drop ACE
        self.insert_drop_ace(acl1, sdk.la_acl_cmd_type_e_INGRESS_UNIFIED)
        run_and_drop(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_PIF_FIRST)

        # Check counter
        packet_count, byte_count = self.inserted_drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Change drop to punt
        self.device.set_trap_configuration(
            sdk.LA_EVENT_ETHERNET_ACL_DROP,
            trap_priority,
            None,
            self.punt_dest,
            False,
            False,
            True, 0)

        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': IN_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': self.ingress_punt_packet,
                               'slice': PUNT_INJECT_SLICE,
                               'ifg': PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_PIF_FIRST}])

        # Change drop back to actually drop
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ACL_DROP, trap_priority, None, None, False, False, True, 0)
        run_and_drop(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_PIF_FIRST)

        # Detach ACL
        self.ac_port1.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Pass packet from port 2 to port 4, through a relay without ACL hit
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_two_acls(self):
        # Create two ACLs, add NOP to the first and DROP to the second. Attach the second to the port.
        self.eth_ingress_acl_key_profile = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_ETHERNET, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_ETHERNET, 0)
        acl1 = self.device.create_acl(self.eth_ingress_acl_key_profile, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)
        acl2 = self.device.create_acl(self.eth_ingress_acl_key_profile, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl2, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)
        count = acl2.get_count()
        self.assertEqual(count, 0)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_SA
        f1.val.sa.flat = 0xcafecafecafe
        f1.mask.sa.flat = 0xffffffffffff
        k1.append(f1)

        k2 = []
        f2 = sdk.la_acl_field()
        f2.type = sdk.la_acl_field_type_e_DA
        f2.val.da.flat = 0xcafecafe0000
        f2.mask.da.flat = 0xffffffff0000
        k2.append(f2)

        cmd_nop = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_DROP
        action1.data.drop = False
        cmd_nop.append(action1)

        cmd_redirect = []
        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_L2_DESTINATION
        action2.data.l2_dest = self.ac_port7.hld_obj
        cmd_redirect.append(action2)

        acl1.append(k1, cmd_nop)
        acl1.append(k2, cmd_redirect)
        acl2.append(k1, cmd_nop)
        acl2.append(k2, cmd_redirect)

        # Pass packet from port 2 to port 4, through a relay without ACL hit
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

        # Attach the second ACL
        acl_group2 = self.device.create_acl_group()
        acl_group2.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl2])
        self.ac_port1.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group2)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            ACL_SLICE,
            ACL_IFG,
            ACL_PIF_FIRST)

        # Add NOP ACE to the first ACL - should have no affect
        self.insert_nop_ace(acl1, sdk.la_acl_cmd_type_e_INGRESS_UNIFIED)
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            ACL_SLICE,
            ACL_IFG,
            ACL_PIF_FIRST)

        # Add drop ACE to the second ACL
        self.insert_drop_ace(acl2, sdk.la_acl_cmd_type_e_INGRESS_UNIFIED)
        run_and_drop(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_PIF_FIRST)

        # Check counter
        packet_count, byte_count = self.inserted_drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Switch to use first ACL
        self.ac_port1.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        acl_group1 = self.device.create_acl_group()
        acl_group1.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1])
        self.ac_port1.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group1)

        # Test default route (NOP)
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

        # Confirm no drop count
        packet_count, byte_count = self.inserted_drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 0)

        # Delete second ACL, should have no affect
        self.device.destroy(acl_group2)
        self.device.destroy(acl2)
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

        # Detach ACL
        self.ac_port1.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Pass packet from port 2 to port 4, through a relay without ACL hit
        run_and_compare(
            self,
            self.device,
            self.in_packet,
            IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)
        self.device.destroy(acl_group1)
        self.device.destroy(acl1)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_acl_drop_inner_vlan(self):
        trap_priority = 0

        acl1 = self.create_simple_sec_acl_inner_vlan()

        # Pass packet from port x  to port y, through a relay without ACL hit
        run_and_compare(
            self,
            self.device,
            self.in_packet_qinq_inner,
            QINQ_IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet_qinq_inner,
            QINQ_OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1])
        self.ac_port9.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            self.in_packet_qinq_inner,
            QINQ_IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet_qinq_inner,
            ACL_SLICE,
            ACL_IFG,
            ACL_PIF_FIRST)

        # Add drop ACE
        self.insert_drop_ace(acl1, sdk.la_acl_cmd_type_e_INGRESS_UNIFIED)
        run_and_drop(self, self.device, self.in_packet_qinq_inner, QINQ_IN_SLICE, IN_IFG, IN_PIF_FIRST)

        # Check counter
        packet_count, byte_count = self.inserted_drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Change drop to punt
        self.device.set_trap_configuration(
            sdk.LA_EVENT_ETHERNET_ACL_DROP,
            trap_priority,
            None,
            self.punt_dest,
            False,
            False,
            True, 0)

        run_and_compare_list(self, self.device,
                             {'data': self.in_packet_qinq_inner,
                              'slice': QINQ_IN_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': self.ingress_qinq_inner_vlan_punt_packet,
                               'slice': PUNT_INJECT_SLICE,
                               'ifg': PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_PIF_FIRST}])

        # Change drop back to actually drop
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ACL_DROP, trap_priority, None, None, False, False, True, 0)
        run_and_drop(self, self.device, self.in_packet_qinq_inner, QINQ_IN_SLICE, IN_IFG, IN_PIF_FIRST)

        # Detach ACL
        self.ac_port9.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        run_and_compare(
            self,
            self.device,
            self.in_packet_qinq_inner,
            QINQ_IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet_qinq_inner,
            QINQ_OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_acl_drop_outer_vlan(self):
        trap_priority = 0

        acl1 = self.create_simple_sec_acl_vlan()

        # Pass packet from port x  to port y, through a relay without ACL hit
        run_and_compare(
            self,
            self.device,
            self.in_packet_qinq_outer,
            QINQ_IN_SLICE,
            IN_IFG,
            IN_PIF_FIRST,
            self.out_packet_qinq_outer,
            QINQ_OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1])
        self.ac_port5.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        port5_serdes_first = T.get_device_next2_first_serdes(IN_PIF_FIRST)

        # (testcase, ingress_packet, expected_egress_packet, in_slice, in_ifg, in_pif, out_slice, out_ifg, out_pif)
        run_and_compare(
            self,
            self.device,
            self.in_packet_qinq_outer,
            QINQ_IN_SLICE,
            IN_IFG,
            port5_serdes_first,
            self.out_packet_qinq_outer,
            ACL_SLICE,
            ACL_IFG,
            ACL_PIF_FIRST)

        # Add drop ACE
        self.insert_drop_ace(acl1, sdk.la_acl_cmd_type_e_INGRESS_UNIFIED)
        port5_serdes = T.get_device_next2_first_serdes(IN_PIF_FIRST)
        run_and_drop(self, self.device, self.in_packet_qinq_outer, QINQ_IN_SLICE, IN_IFG, port5_serdes)

        # Check counter
        packet_count, byte_count = self.inserted_drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Change drop to punt
        self.device.set_trap_configuration(
            sdk.LA_EVENT_ETHERNET_ACL_DROP,
            trap_priority,
            None,
            self.punt_dest,
            False,
            False,
            True, 0)

        run_and_compare_list(self, self.device,
                             {'data': self.in_packet_qinq_outer,
                              'slice': QINQ_IN_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': self.ingress_qinq_outer_vlan_punt_packet,
                               'slice': PUNT_INJECT_SLICE,
                               'ifg': PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_PIF_FIRST}])

        # Change drop back to actually drop
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ACL_DROP, trap_priority, None, None, False, False, True, 0)
        run_and_drop(self, self.device, self.in_packet_qinq_outer, QINQ_IN_SLICE, IN_IFG, IN_PIF_FIRST)

        # Detach ACL
        self.ac_port5.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        port5_serdes_first = T.get_device_next2_first_serdes(IN_PIF_FIRST)
        run_and_compare(
            self,
            self.device,
            self.in_packet_qinq_outer,
            QINQ_IN_SLICE,
            IN_IFG,
            port5_serdes_first,
            self.out_packet_qinq_outer,
            QINQ_OUT_SLICE,
            OUT_IFG,
            OUT_PIF_FIRST)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_mirroring_with_same_slice_and_ifg(self):
        # Test case:  Unconditional ingress mirroring, with both Rx and SPAN ports on same slice and IFG.
        # Source Port Details: slice:3 , IFG:0.
        # SPAN Destination Port Details: slice:3 , IFG:0.
        # Expectation: Packet ingressing from Rx Port has to go out of the Tx PI port,
        # and a copy should be sent to SPAN destination port.
        self.ac_port4.hld_obj.set_ingress_mirror_command(self.ingress_mirror_cmd, is_acl_conditioned=False)
        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': PUNT_INJECT_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': self.out_packet,
                               'slice': OUT_SLICE,
                               'ifg': OUT_IFG,
                               'pif': OUT_PIF_FIRST},
                              {'data': self.mirror_packet_ingress_rx_at_ac_port4,
                               'slice': PUNT_INJECT_SLICE,
                               'ifg': PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_PIF_FIRST}])

        mirror_cmd1, is_alc_conditioned = self.ac_port4.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd1.get_gid(), self.ingress_mirror_cmd.get_gid())
        self.assertFalse(is_alc_conditioned)

        # Test case:  Conditional ingress mirroring with out ACL, and both Rx and SPAN ports are on same slice and IFG.
        # Source Port Details: slice:3 , IFG:0.
        # SPAN Destination Port Details: slice:3 , IFG:0.
        # Expectation: Packet ingressing from Rx Port has to go out of the Tx PI port,
        # and a copy should be sent to SPAN destination port.
        self.ac_port4.hld_obj.set_ingress_mirror_command(self.ingress_mirror_cmd, is_acl_conditioned=True)
        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': PUNT_INJECT_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': self.out_packet,
                               'slice': OUT_SLICE,
                               'ifg': OUT_IFG,
                               'pif': OUT_PIF_FIRST}])

        mirror_cmd1, is_alc_conditioned = self.ac_port4.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd1.get_gid(), self.ingress_mirror_cmd.get_gid())
        self.assertTrue(is_alc_conditioned)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_mirroring_with_same_ifg(self):
        # Test case:  Unconditional ingress mirroring, with both Rx and SPAN ports on same IFG but different slice.
        # Source Port Details: slice:2 , IFG:0.
        # SPAN Destination Port Details: slice:3 , IFG:0.
        # Expectation: Packet ingressing from Rx Port has to go out of the Tx PI port,
        # and a copy should be sent to SPAN destination port.
        self.ac_port1.hld_obj.set_ingress_mirror_command(self.ingress_mirror_cmd, is_acl_conditioned=False)
        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': IN_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': self.out_packet,
                               'slice': OUT_SLICE,
                               'ifg': OUT_IFG,
                               'pif': OUT_PIF_FIRST},
                              {'data': self.mirror_packet_ingress,
                               'slice': PUNT_INJECT_SLICE,
                               'ifg': PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_PIF_FIRST}])

        mirror_cmd1, is_alc_conditioned = self.ac_port1.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd1.get_gid(), self.ingress_mirror_cmd.get_gid())
        self.assertFalse(is_alc_conditioned)

        # Test case:  Conditional Ingress Mirroring, with out ACL,
        # and both Rx and SPAN ports on same IFG but different slice.
        # Source Port Details: slice:2 , IFG:0.
        # SPAN Destination Port Details: slice:3 , IFG:0.
        # Expectation: Packet ingressing from Rx Port has to go out of the Tx PI port,
        # and a copy should be sent to SPAN destination port.
        self.ac_port1.hld_obj.set_ingress_mirror_command(self.ingress_mirror_cmd, is_acl_conditioned=True)
        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': IN_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': self.out_packet,
                               'slice': OUT_SLICE,
                               'ifg': OUT_IFG,
                               'pif': OUT_PIF_FIRST}])

        mirror_cmd1, is_alc_conditioned = self.ac_port1.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd1.get_gid(), self.ingress_mirror_cmd.get_gid())
        self.assertTrue(is_alc_conditioned)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_mirroring_with_same_slice(self):
        # Test case:  Unconditional ingress mirroring,
        # With both Rx and SPAN ports on same slice but different IFG.
        # Source Port Details: slice:3 , IFG: 1.
        # SPAN Destination Port Details: slice:3 , IFG:0.
        # Expectation: Packet ingressing from Rx Port has to go out of the Tx PI port,
        # and a copy should be sent to SPAN destination port.
        self.ac_port3.hld_obj.set_ingress_mirror_command(self.ingress_mirror_cmd, is_acl_conditioned=False)
        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': ACL_SLICE,
                              'ifg': ACL_IFG,
                              'pif': ACL_PIF_FIRST},
                             [{'data': self.out_packet,
                               'slice': OUT_SLICE,
                               'ifg': OUT_IFG,
                               'pif': OUT_PIF_FIRST},
                              {'data': self.mirror_packet_ingress_rx_at_ac_port3,
                               'slice': PUNT_INJECT_SLICE,
                               'ifg': PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_PIF_FIRST}])

        mirror_cmd1, is_alc_conditioned = self.ac_port3.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd1.get_gid(), self.ingress_mirror_cmd.get_gid())
        self.assertFalse(is_alc_conditioned)

        # Test case: Conditional ingress mirroring, without ACL,
        # and both Rx and SPAN ports are on same slice but different IFG.
        # Source Port Details: slice:3 , IFG: 1.
        # SPAN Destination Port Details: slice:3 , IFG:0.
        # Expectation: Packet ingressing from Rx Port has to go out of the Tx PI port,
        # and a copy should be sent to SPAN destination port.
        self.ac_port3.hld_obj.set_ingress_mirror_command(self.ingress_mirror_cmd, is_acl_conditioned=True)
        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': ACL_SLICE,
                              'ifg': ACL_IFG,
                              'pif': ACL_PIF_FIRST},
                             [{'data': self.out_packet,
                               'slice': OUT_SLICE,
                               'ifg': OUT_IFG,
                               'pif': OUT_PIF_FIRST}])

        mirror_cmd1, is_alc_conditioned = self.ac_port3.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd1.get_gid(), self.ingress_mirror_cmd.get_gid())
        self.assertTrue(is_alc_conditioned)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_mirroring_with_same_slice_and_ifg(self):
        # Test case: unconditional egress mirroring, with both Rx and SPAN ports on same slice and IFG.
        # Source Port Details: slice:4 , IFG:1.
        # SPAN Destination Port Details: slice:3 , IFG:0.
        # Expectation: Packet ingressing from Rx Port has to go out of the Tx PI port,
        # and a copy should be sent to SPAN destination port.
        self.ac_port2.hld_obj.set_egress_mirror_command(self.egress_mirror_cmd, is_acl_conditioned=False)
        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': PUNT_INJECT_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': self.out_packet,
                               'slice': OUT_SLICE,
                               'ifg': OUT_IFG,
                               'pif': OUT_PIF_FIRST},
                              {'data': self.mirror_packet_tx_at_ac_port2,
                               'slice': PUNT_INJECT_SLICE,
                               'ifg': PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_PIF_FIRST,
                               'egress_mirror_pi_port_pkt': True}])

        mirror_cmd1, is_alc_conditioned = self.ac_port2.hld_obj.get_egress_mirror_command()
        self.assertEqual(mirror_cmd1.get_gid(), self.egress_mirror_cmd.get_gid())
        self.assertFalse(is_alc_conditioned)

        # Test case: Conditional egress mirroring, with both Rx and SPAN ports on same slice and IFG.
        # Source Port Details: slice:4 , IFG:1.
        # SPAN Destination Port Details: slice:3 , IFG:0.
        # Expectation: Packet ingressing from Rx Port has to go out of the Tx PI port,
        # and a copy should be sent to SPAN destination port.
        self.ac_port2.hld_obj.set_egress_mirror_command(self.egress_mirror_cmd, is_acl_conditioned=True)
        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': PUNT_INJECT_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': self.out_packet,
                               'slice': OUT_SLICE,
                               'ifg': OUT_IFG,
                               'pif': OUT_PIF_FIRST}])

        mirror_cmd1, is_alc_conditioned = self.ac_port2.hld_obj.get_egress_mirror_command()
        self.assertEqual(mirror_cmd1.get_gid(), self.egress_mirror_cmd.get_gid())
        self.assertTrue(is_alc_conditioned)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_mirroring_with_networkport(self):
        # Test case:  Unconditional ingress mirroring, with both Rx and SPAN ports on same slice and IFG.
        # Source Port Details: slice:3 , IFG:0.
        # SPAN Destination Port Details: slice:3 , IFG:0.
        # Expectation: Packet ingressing from Rx Port has to go out of the Tx network port,
        # and a copy should be sent to SPAN destination port.
        self.ac_port1.hld_obj.set_ingress_mirror_command(self.ingress_mirror_command, is_acl_conditioned=True)
        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': IN_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': self.out_packet,
                               'slice': OUT_SLICE,
                               'ifg': OUT_IFG,
                               'pif': OUT_PIF_FIRST}])

        mirror_cmd1, is_alc_conditioned = self.ac_port1.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd1.get_gid(), self.ingress_mirror_command.get_gid())
        self.assertTrue(is_alc_conditioned)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_mirroring_with_networkport(self):
        # Test case:  Unconditional ingress mirroring, with both Rx and SPAN ports on same slice and IFG.
        # Source Port Details: slice:4 , IFG:1.
        # SPAN Destination Port Details: slice:3 , IFG:0.
        # Expectation: Packet ingressing from Rx Port has to go out of the Tx network port,
        # and a copy should be sent to SPAN destination port.
        self.ac_port2.hld_obj.set_egress_mirror_command(self.egress_mirror_command, is_acl_conditioned=False)
        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': IN_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': self.out_packet,
                               'slice': OUT_SLICE,
                               'ifg': OUT_IFG,
                               'pif': OUT_PIF_FIRST},
                              {'data': self.out_packet,
                               'slice': MIRROR_DEST_SLICE,
                               'ifg': MIRROR_DEST_IFG,
                               'pif': MIRROR_DEST_PIF_FIRST}])

        mirror_cmd1, is_alc_conditioned = self.ac_port2.hld_obj.get_egress_mirror_command()
        self.assertEqual(mirror_cmd1.get_gid(), self.egress_mirror_command.get_gid())
        self.assertFalse(is_alc_conditioned)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_egress_mirroring_with_networkport(self):
        # Test case:  Unconditional ingress mirroring, with both Rx and SPAN ports on same slice and IFG.
        # Source Port Details: [slice:3 , IFG:0] and [slice:4, IFG:1].
        # SPAN Destination Port Details: slice:3 , IFG:0.
        # Expectation: Packet ingressing from Rx Port has to go out of the Tx network port,
        # and a copy should be sent to SPAN destination port.
        self.ac_port1.hld_obj.set_ingress_mirror_command(self.ingress_mirror_command, is_acl_conditioned=False)
        self.ac_port2.hld_obj.set_egress_mirror_command(self.egress_mirror_command, is_acl_conditioned=False)
        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': IN_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': self.out_packet,
                               'slice': OUT_SLICE,
                               'ifg': OUT_IFG,
                               'pif': OUT_PIF_FIRST},
                              {'data': self.in_packet,
                               'slice': MIRROR_DEST_SLICE,
                               'ifg': MIRROR_DEST_IFG,
                               'pif': MIRROR_DEST_PIF_FIRST},
                              {'data': self.out_packet,
                               'slice': MIRROR_DEST_SLICE,
                               'ifg': MIRROR_DEST_IFG,
                               'pif': MIRROR_DEST_PIF_FIRST}])

        mirror_cmd1, is_alc_conditioned = self.ac_port2.hld_obj.get_egress_mirror_command()
        self.assertEqual(mirror_cmd1.get_gid(), self.egress_mirror_command.get_gid())
        self.assertFalse(is_alc_conditioned)

        mirror_cmd1, is_alc_conditioned = self.ac_port1.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd1.get_gid(), self.ingress_mirror_command.get_gid())
        self.assertFalse(is_alc_conditioned)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mirroring_with_out_mirror_command(self):
        # Test case: Deleting the mirror command on both ingress and egress.
        # Source Port Details: [slice:3 , IFG:0] and [slice:4, IFG:1].
        # SPAN Destination Port Details: slice:3 , IFG:0.
        # Expectation: Packet ingressing from Rx Port has to go out of the Tx network port,
        # and No copy should be sent to SPAN destination port.
        self.ac_port1.hld_obj.set_ingress_mirror_command(None, is_acl_conditioned=False)
        self.ac_port2.hld_obj.set_egress_mirror_command(None, is_acl_conditioned=False)
        run_and_compare_list(self, self.device,
                             {'data': self.in_packet,
                              'slice': IN_SLICE,
                              'ifg': IN_IFG,
                              'pif': IN_PIF_FIRST},
                             [{'data': self.out_packet,
                               'slice': OUT_SLICE,
                               'ifg': OUT_IFG,
                               'pif': OUT_PIF_FIRST}])

        mirror_cmd1, is_alc_conditioned = self.ac_port2.hld_obj.get_egress_mirror_command()
        self.assertEqual(mirror_cmd1, None)
        self.assertFalse(is_alc_conditioned)

        mirror_cmd1, is_alc_conditioned = self.ac_port1.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd1, None)
        self.assertFalse(is_alc_conditioned)


if __name__ == '__main__':
    unittest.main()
