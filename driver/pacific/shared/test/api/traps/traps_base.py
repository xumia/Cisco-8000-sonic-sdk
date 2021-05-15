#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import sim_utils
import topology as T
from sdk_test_case_base import sdk_test_case_base
import smart_slices_choise as ssch
import decor

PRIVATE_DATA = 0x1234567890abcdef

TTL = 128
SA = T.mac_addr('be:ef:5d:35:7a:35')
DA = T.mac_addr('02:02:02:02:02:02')

SIP = T.ipv4_addr('12.10.12.10')
DIP = T.ipv4_addr('82.81.95.250')

SIP6 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
DIP6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xA13

SYS_PORT_GID_BASE = 23
IN_SP_GID = SYS_PORT_GID_BASE
OUT_SP_GID = SYS_PORT_GID_BASE + 1

ARP_ETHER_TYPE = 0x0806
LACP_ETHER_TYPE = 0X8809
PTP_ETHER_TYPE = 0x88f7
STD_MACSEC_ETHER_TYPE = 0x888E
WAN_MACSEC_ETHER_TYPE = 0x876F

BCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DONT_CARE_MAC = '00:00:00:00:00:00'


class TrapsTest(sdk_test_case_base):
    PI_SP_GID = SYS_PORT_GID_BASE + 2
    PI_SLICE = T.get_device_slice(3)
    PI_IFG = T.get_device_ifg(1)
    PI_PIF_FIRST = T.get_device_first_serdes(8)
    PUNT_RELAY_ID = 0 if decor.is_pacific() else T.VRF_GID

    def setUp(self):

        super().setUp()
        ssch.rechoose_PI_slices(self, self.device)
        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PI_SLICE,
            self.PI_IFG,
            self.PI_SP_GID,
            self.PI_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)
        if decor.is_pacific() or decor.is_gibraltar():
            self.device.set_bool_property(sdk.la_device_property_e_STATISTICAL_METER_COUNTING, True)

        self.copc_mac = self.device.create_copc(sdk.la_control_plane_classifier.type_e_MAC)
        self.copc_ipv4 = self.device.create_copc(sdk.la_control_plane_classifier.type_e_IPV4)
        self.copc_ipv6 = self.device.create_copc(sdk.la_control_plane_classifier.type_e_IPV6)

    def install_an_entry_in_copc_mac_table(
            self,
            ether_value,
            ether_mask,
            mac_da_value,
            event,
            mac_da_mask=T.mac_addr('ff:ff:ff:ff:ff:ff'),
            npp_attribute=0x0,
            mac_lp_type_value=0x0,
            mac_lp_type_mask=0x0,
            my_mac_value = False,
            my_mac_mask = False):

        key1 = []
        f1 = sdk.field()
        f1.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERNET_PROFILE_ID
        f1.val.mac.ethernet_profile_id = npp_attribute
        f1.mask.mac.ethernet_profile_id = npp_attribute
        key1.append(f1)

        f2 = sdk.field()
        f2.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_DA
        f2.val.mac.da = mac_da_value.hld_obj
        f2.mask.mac.da = mac_da_mask.hld_obj
        key1.append(f2)

        f3 = sdk.field()
        f3.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERTYPE
        f3.val.mac.ethertype = ether_value
        f3.mask.mac.ethertype = ether_mask
        key1.append(f3)

        f4 = sdk.field()
        f4.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_LP_TYPE
        f4.val.mac.lp_type = mac_lp_type_value
        f4.mask.mac.lp_type = mac_lp_type_mask
        key1.append(f4)

        f5 = sdk.field()
        f5.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_MY_MAC
        f5.val.mac.my_mac = my_mac_value
        f5.mask.mac.my_mac = my_mac_mask
        key1.append(f5)

        result1 = sdk.result()
        result1.event = event

        self.copc_mac.append(key1, result1)

    def clear_entries_from_copc_mac_table(self):
        self.copc_mac.clear()

    def install_an_entry_in_copc_ipv4_table(
            self,
            protocol_value,
            protocol_mask,
            l4_dst_port_value,
            l4_dst_port_mask,
            ethernet_profile_id_value,
            ethernet_profile_id_mask,
            lp_type_value,
            lp_type_mask,
            is_svi_value,
            is_svi_mask,
            event,
            dest_ip_value = T.ipv4_addr('0.0.0.0'),
            dest_ip_mask = T.ipv4_addr('0.0.0.0'),
            my_mac_value = False,
            my_mac_mask = False):

        key1 = []
        f1 = sdk.field()
        f1.type.ipv4 = sdk.la_control_plane_classifier.ipv4_field_type_e_ETHERNET_PROFILE_ID
        f1.val.ipv4.ethernet_profile_id = ethernet_profile_id_value
        f1.mask.ipv4.ethernet_profile_id = ethernet_profile_id_mask
        key1.append(f1)

        f2 = sdk.field()
        f2.type.ipv4 = sdk.la_control_plane_classifier.ipv4_field_type_e_LP_TYPE
        f2.val.ipv4.lp_type = lp_type_value
        f2.mask.ipv4.lp_type = lp_type_mask
        key1.append(f2)

        f3 = sdk.field()
        f3.type.ipv4 = sdk.la_control_plane_classifier.ipv4_field_type_e_PROTOCOL
        f3.val.ipv4.protocol = protocol_value
        f3.mask.ipv4.protocol = protocol_mask
        key1.append(f3)

        f4 = sdk.field()
        f4.type.ipv4 = sdk.la_control_plane_classifier.ipv4_field_type_e_DPORT
        f4.val.ipv4.dport = l4_dst_port_value
        f4.mask.ipv4.dport = l4_dst_port_mask
        key1.append(f4)

        f5 = sdk.field()
        f5.type.ipv4 = sdk.la_control_plane_classifier.ipv4_field_type_e_IS_SVI
        f5.val.ipv4.is_svi = is_svi_value
        f5.mask.ipv4.is_svi = is_svi_mask
        key1.append(f5)

        f6 = sdk.field()
        f6.type.ipv4 = sdk.la_control_plane_classifier.ipv4_field_type_e_IPV4_DIP
        f6.val.ipv4.ipv4_dip.s_addr = dest_ip_value.to_num()
        f6.mask.ipv4.ipv4_dip.s_addr = dest_ip_mask.to_num()
        key1.append(f6)

        f7 = sdk.field()
        f7.type.ipv4 = sdk.la_control_plane_classifier.ipv4_field_type_e_MY_MAC
        f7.val.ipv4.my_mac = my_mac_value
        f7.mask.ipv4.my_mac = my_mac_mask
        key1.append(f7)

        result1 = sdk.result()
        result1.event = event

        self.copc_ipv4.append(key1, result1)

    def clear_entries_from_copc_ipv4_table(self):
        self.copc_ipv4.clear()

    def install_an_entry_in_copc_ipv6_table(
            self,
            next_header_value,
            next_header_mask,
            l4_dst_port_value,
            l4_dst_port_mask,
            ethernet_profile_id_value,
            ethernet_profile_id_mask,
            lp_type_value,
            lp_type_mask,
            is_svi_value,
            is_svi_mask,
            event,
            dest_ip_value = T.ipv6_addr('0::0'),
            dest_ip_mask = T.ipv6_addr('0::0'),
            my_mac_value = False,
            my_mac_mask = False):

        key1 = []
        f1 = sdk.field()
        f1.type.ipv6 = sdk.la_control_plane_classifier.ipv6_field_type_e_ETHERNET_PROFILE_ID
        f1.val.ipv6.ethernet_profile_id = ethernet_profile_id_value
        f1.mask.ipv6.ethernet_profile_id = ethernet_profile_id_mask
        key1.append(f1)

        f2 = sdk.field()
        f2.type.ipv6 = sdk.la_control_plane_classifier.ipv6_field_type_e_LP_TYPE
        f2.val.ipv6.lp_type = lp_type_value
        f2.mask.ipv6.lp_type = lp_type_mask
        key1.append(f2)

        f3 = sdk.field()
        f3.type.ipv6 = sdk.la_control_plane_classifier.ipv6_field_type_e_NEXT_HEADER
        f3.val.ipv6.next_header = next_header_value
        f3.mask.ipv6.next_header = next_header_mask
        key1.append(f3)

        f4 = sdk.field()
        f4.type.ipv6 = sdk.la_control_plane_classifier.ipv6_field_type_e_DPORT
        f4.val.ipv6.dport = l4_dst_port_value
        f4.mask.ipv6.dport = l4_dst_port_mask
        key1.append(f4)

        f5 = sdk.field()
        f5.type.ipv6 = sdk.la_control_plane_classifier.ipv6_field_type_e_IS_SVI
        f5.val.ipv6.is_svi = is_svi_value
        f5.mask.ipv6.is_svi = is_svi_mask
        key1.append(f5)

        f6 = sdk.field()
        f6.type.ipv6 = sdk.la_control_plane_classifier.ipv6_field_type_e_IPV6_DIP
        q0 = sdk.get_ipv6_addr_q0(dest_ip_value.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(dest_ip_value.hld_obj)
        sdk.set_ipv6_addr(f6.val.ipv6.ipv6_dip, q0, q1)
        q0 = sdk.get_ipv6_addr_q0(dest_ip_mask.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(dest_ip_mask.hld_obj)
        sdk.set_ipv6_addr(f6.mask.ipv6.ipv6_dip, q0, q1)
        key1.append(f6)

        f7 = sdk.field()
        f7.type.ipv6 = sdk.la_control_plane_classifier.ipv6_field_type_e_MY_MAC
        f7.val.ipv6.my_mac = my_mac_value
        f7.mask.ipv6.my_mac = my_mac_mask
        key1.append(f7)

        result1 = sdk.result()
        result1.event = event

        self.copc_ipv6.append(key1, result1)

    def clear_entries_from_copc_ipv6_table(self):
        self.copc_ipv6.clear()
