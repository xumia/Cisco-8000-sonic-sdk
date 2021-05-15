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

import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import nplapicli as nplapi

from traps_base import *
import decor

RX_L2_AC_PORT_GID2 = 0x213


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_tagged (TrapsTest):

    def install_arp_entry_in_copc_mac_table(
            self,
            ether_value,
            ether_mask,
            ethernet_profile_id_value,
            ethernet_profile_id_mask,
            has_vlan_tag_value,
            has_vlan_tag_mask,
            result):

        key1 = []
        f1 = sdk.field()
        f1.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERNET_PROFILE_ID
        f1.val.mac.ethernet_profile_id = ethernet_profile_id_value
        f1.mask.mac.ethernet_profile_id = ethernet_profile_id_mask
        key1.append(f1)

        f2 = sdk.field()
        f2.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERTYPE
        f2.val.mac.ethertype = ether_value
        f2.mask.mac.ethertype = ether_mask
        key1.append(f2)

        f2 = sdk.field()
        f2.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_HAS_VLAN_TAG
        f2.val.mac.has_vlan_tag = has_vlan_tag_value
        f2.mask.mac.has_vlan_tag = has_vlan_tag_mask

        key1.append(f2)
        result1 = sdk.result()
        result1.event = result

        self.copc_mac.append(key1, result1)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_tagged_qinq_packet(self):
        self.rx_l2_ac_port2 = T.l2_ac_port(self,
                                           self.device,
                                           RX_L2_AC_PORT_GID2,
                                           None,
                                           self.topology.rx_switch,
                                           self.topology.rx_eth_port,
                                           T.RX_MAC,
                                           T.RX_L2_AC_PORT_VID2 + 0x100,
                                           T.RX_L2_AC_PORT_VID2 + 0x200)

        self.topology.rx_switch.hld_obj.set_mac_entry(
            DA.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        self.install_arp_entry_in_copc_mac_table(ARP_ETHER_TYPE, 0xffff, 0x1, 0x1, False, True, sdk.LA_EVENT_ETHERNET_ARP)
        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0, None, self.punt_dest, False, False, True, 0)

        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID2 + 0x100, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID2 + 0x200) / \
            S.ARP(op='is-at')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        OUTPUT_PACKET_WITH_VLAN = INPUT_PACKET_WITH_VLAN

        # Test tagged packet being tunneled.
        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          OUTPUT_PACKET_WITH_VLAN, T.TX_SLICE_REG, T.TX_IFG_REG, T.PI_IFG)

        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x0)
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)
        self.rx_l2_ac_port2.destroy()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_tagged_dot1q_packet(self):
        self.rx_l2_ac_port2 = T.l2_ac_port(self,
                                           self.device,
                                           RX_L2_AC_PORT_GID2,
                                           None,
                                           self.topology.rx_switch,
                                           self.topology.rx_eth_port,
                                           T.RX_MAC,
                                           T.RX_L2_AC_PORT_VID2,
                                           T.RX_L2_AC_PORT_VID2)

        self.topology.rx_switch.hld_obj.set_mac_entry(
            DA.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        self.install_arp_entry_in_copc_mac_table(ARP_ETHER_TYPE, 0xffff, 0x1, 0x1, False, True, sdk.LA_EVENT_ETHERNET_ARP)
        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0, None, self.punt_dest, False, False, True, 0)

        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.ARP(op='is-at')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        OUTPUT_PACKET_WITH_VLAN = INPUT_PACKET_WITH_VLAN

        # Test tagged packet being tunneled.
        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          OUTPUT_PACKET_WITH_VLAN, T.TX_SLICE_REG, T.TX_IFG_REG, T.PI_IFG)

        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x0)
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)
        self.rx_l2_ac_port2.destroy()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_untagged_packet(self):
        self.rx_l2_ac_port2 = T.l2_ac_port(self,
                                           self.device,
                                           0x213,
                                           None,
                                           self.topology.rx_switch,
                                           self.topology.rx_eth_port,
                                           T.RX_MAC,
                                           T.RX_L2_AC_PORT_VID2,
                                           T.RX_L2_AC_PORT_VID2)

        self.topology.rx_switch.hld_obj.set_mac_entry(
            DA.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        self.install_arp_entry_in_copc_mac_table(ARP_ETHER_TYPE, 0xffff, 0x3f, 0x3f, False, True, sdk.LA_EVENT_ETHERNET_ARP)
        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x3f)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0, None, self.punt_dest, False, False, True, 0)

        INPUT_PACKET_BASE = \
            S.Ether(dst=DA.addr_str, src=SA.addr_str) / \
            S.ARP(op='is-at')
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        PUNT_PACKET = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_ARP,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=RX_L2_AC_PORT_GID2 | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                   destination_lp=sdk.LA_EVENT_ETHERNET_ARP,
                   relay_id=0,
                   lpts_flow_type=0) / INPUT_PACKET

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x0)
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)
        self.rx_l2_ac_port2.destroy()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_svi_tagged_packet(self):
        self.install_arp_entry_in_copc_mac_table(ARP_ETHER_TYPE, 0xffff, 0x3f, 0x3f, False, False, sdk.LA_EVENT_ETHERNET_ARP)
        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x3f)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0, None, self.punt_dest, False, False, True, 0)
        INPUT_PACKET_WITH_VLAN_BASE = \
            S.Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            S.ARP(op='is-at')
        INPUT_PACKET_WITH_VLAN, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_VLAN_BASE)

        PUNT_PACKET_WITH_VLAN = \
            S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                   code=sdk.LA_EVENT_ETHERNET_ARP,
                   source_sp=T.RX_SYS_PORT_GID,
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=T.RX_SVI_GID,
                   destination_lp=sdk.LA_EVENT_ETHERNET_ARP,
                   relay_id=self.PUNT_RELAY_ID,
                   lpts_flow_type=0) / INPUT_PACKET_WITH_VLAN

        U.run_and_compare(self, self.device,
                          INPUT_PACKET_WITH_VLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET_WITH_VLAN, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.topology.rx_eth_port.hld_obj.set_copc_profile(0x0)
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)


if __name__ == '__main__':
    unittest.main()
