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

from scapy.all import *

from packet_test_utils import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
from ipv4_mc import *
from ipv6_mc import *
from sdk_multi_test_case_base import *


class egress_member_punt_base(sdk_multi_test_case_base):
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    MC_GROUP_GID = 0x13
    TTL = 127
    PUNT_SLICE = T.get_device_slice(2)
    PUNT_IFG = 0
    PUNT_SERDES = T.get_device_first_serdes(8)
    PUNT_SYS_PORT_GID = T.MIN_SYSTEM_PORT_GID
    PI_PORT_MAC = T.mac_addr('ab:ab:ab:ab:ab:ab')
    HOST_MAC_ADDR = T.mac_addr('cd:cd:cd:cd:cd:cd')
    PUNT_VLAN = 19

    def setUp(self):
        # MATILDA_SAVE -- need review
        if (egress_member_punt_base.PUNT_SLICE not in self.device.get_used_slices()):
            egress_member_punt_base.PUNT_SLICE = T.choose_active_slices(self.device,
                                                                        egress_member_punt_base.PUNT_SLICE, [4, 2])

        self.device_name = '/dev/testdev'

        super().setUp()

        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        self.initialize_rx_port()

        self.mc_group = self.device.create_ip_multicast_group(
            egress_member_punt_base.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(self.l3_port_impl.tx_port.hld_obj, self.get_tx_l2_port(), self.get_tx_sys_port())
        self.mc_group.add(self.l3_port_impl.tx_port_def.hld_obj, self.get_tx_l2_port_def(), self.get_tx_sys_port_def())

        self.initialize_traps()

        self.create_packets()

    def initialize_traps(self):
        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            egress_member_punt_base.PUNT_SLICE,
            egress_member_punt_base.PUNT_IFG,
            egress_member_punt_base.PUNT_SYS_PORT_GID,
            egress_member_punt_base.PUNT_SERDES,
            egress_member_punt_base.PI_PORT_MAC.addr_str)

        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            egress_member_punt_base.HOST_MAC_ADDR.addr_str,
            egress_member_punt_base.PUNT_VLAN)

        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_IP_MC_EGRESS_PUNT)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_MC_EGRESS_PUNT, 0, None, self.punt_dest, False, False, True, 0)

    def create_packets(self):
        INPUT_PACKET_BASE = \
            Ether(dst=self.get_mc_sa_addr_str(self.MC_GROUP_ADDR),
                  src=egress_member_punt_base.SA.addr_str,
                  type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.rx_vlan) / \
            IPvX(ipvx=self.protocol,
                 src=self.SIP.addr_str,
                 dst=self.MC_GROUP_ADDR.addr_str,
                 ttl=egress_member_punt_base.TTL) / \
            TCP() / \
            Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=self.get_mc_sa_addr_str(self.MC_GROUP_ADDR),
                  src=self.TX_REG_MAC.addr_str) / \
            IPvX(ipvx=self.protocol,
                 src=self.SIP.addr_str,
                 dst=self.MC_GROUP_ADDR.addr_str,
                 ttl=egress_member_punt_base.TTL - 1) / \
            TCP() / \
            Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_DEF_BASE = \
            Ether(dst=self.get_mc_sa_addr_str(self.MC_GROUP_ADDR),
                  src=self.TX_DEF_MAC.addr_str) / \
            IPvX(ipvx=self.protocol,
                 src=self.SIP.addr_str,
                 dst=self.MC_GROUP_ADDR.addr_str,
                 ttl=egress_member_punt_base.TTL - 1) / \
            TCP() / \
            Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_PUNT_BASE = \
            Ether(dst=egress_member_punt_base.HOST_MAC_ADDR.addr_str,
                  src=egress_member_punt_base.PI_PORT_MAC.addr_str,
                  type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0,
                  id=0,
                  vlan=egress_member_punt_base.PUNT_VLAN,
                  type=Ethertype.Punt.value) / \
            Punt(next_header=self.protocol_type,
                 fwd_header_type=self.get_fwd_header_type(),
                 next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_EGRESS_TRAP,
                 code=sdk.LA_EVENT_L3_IP_MC_EGRESS_PUNT,
                 source_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 destination_sp=self.TX_SYS_PORT_GID,
                 source_lp=self.rx_port_gid,
                 destination_lp=self.l3_port_impl.tx_port.hld_obj.get_gid(),
                 relay_id=T.VRF_GID,
                 lpts_flow_type=0) / \
            IPvX(ipvx=self.protocol,
                 src=self.SIP.addr_str,
                 dst=self.MC_GROUP_ADDR.addr_str,
                 ttl=egress_member_punt_base.TTL) / \
            TCP() / \
            Raw(load=RAW_PAYLOAD)

        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
        __, self.EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)
        __, self.EXPECTED_OUTPUT_PACKET_PUNT = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_PUNT_BASE)

    def do_test_egress_member_punt(self):

        self.add_ip_multicast_route(self.ANY_IP, self.MC_GROUP_ADDR.hld_obj, self.mc_group, None, False, False, None)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets_punt = []

        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})

        expected_packets_punt.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                      'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        expected_packets_punt.append({'data': self.EXPECTED_OUTPUT_PACKET_PUNT, 'slice': egress_member_punt_base.PUNT_SLICE,
                                      'ifg': egress_member_punt_base.PUNT_IFG, 'pif': egress_member_punt_base.PUNT_SERDES})
        expected_packets_punt.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                      'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})

        self.mc_group.set_punt_enabled(self.l3_port_impl.tx_port.hld_obj, self.get_tx_l2_port(), True)

        run_and_compare_list(self, self.device, ingress_packet, expected_packets_punt)

        punt_enabled = self.mc_group.get_punt_enabled(self.l3_port_impl.tx_port.hld_obj, self.get_tx_l2_port())
        self.assertEqual(punt_enabled, True)

        self.mc_group.set_punt_enabled(self.l3_port_impl.tx_port.hld_obj, self.get_tx_l2_port(), False)

        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        punt_enabled = self.mc_group.get_punt_enabled(self.l3_port_impl.tx_port.hld_obj, self.get_tx_l2_port())
        self.assertEqual(punt_enabled, False)

        # Cleanup
        self.delete_ip_multicast_route(self.ANY_IP, self.MC_GROUP_ADDR.hld_obj)

    def do_test_egress_member_punt_member_remove(self):

        self.add_ip_multicast_route(self.ANY_IP, self.MC_GROUP_ADDR.hld_obj, self.mc_group, None, False, False, None)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets_punt = []

        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})

        expected_packets_punt.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                      'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        expected_packets_punt.append({'data': self.EXPECTED_OUTPUT_PACKET_PUNT, 'slice': egress_member_punt_base.PUNT_SLICE,
                                      'ifg': egress_member_punt_base.PUNT_IFG, 'pif': egress_member_punt_base.PUNT_SERDES})
        expected_packets_punt.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                      'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})

        self.mc_group.set_punt_enabled(self.l3_port_impl.tx_port.hld_obj, self.get_tx_l2_port(), True)

        run_and_compare_list(self, self.device, ingress_packet, expected_packets_punt)

        self.mc_group.remove(self.l3_port_impl.tx_port.hld_obj, self.get_tx_l2_port())

        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Cleanup
        self.delete_ip_multicast_route(self.ANY_IP, self.MC_GROUP_ADDR.hld_obj)

    def do_test_egress_member_punt_member_get(self):

        self.mc_group.remove(self.l3_port_impl.tx_port_def.hld_obj, self.get_tx_l2_port_def())
        self.mc_group.set_punt_enabled(self.l3_port_impl.tx_port.hld_obj, self.get_tx_l2_port(), True)
        self.mc_group.add(self.l3_port_impl.tx_port_def.hld_obj, self.get_tx_l2_port_def(), self.get_tx_sys_port_def())

        self.assertEqual(self.mc_group.get_size(), 2)

        (mem0_info) = self.mc_group.get_member(0)
        self.assertEqual(mem0_info.l3_port.this, self.l3_port_impl.tx_port.hld_obj.this)
        if (mem0_info.l2_port):
            self.assertEqual(mem0_info.l2_port.this, self.get_tx_l2_port().this)

        (mem1_info) = self.mc_group.get_member(1)
        self.assertEqual(mem1_info.l3_port.this, self.l3_port_impl.tx_port_def.hld_obj.this)
        if (mem1_info.l2_port):
            self.assertEqual(mem1_info.l2_port.this, self.get_tx_l2_port_def().this)


class egress_member_punt_ipv4_test:
    protocol = 'v4'

    SIP = ipv4_mc.SIP
    ANY_IP = sdk.LA_IPV4_ANY_IP
    protocol_type = sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4

    MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')

    def get_mc_sa_addr_str(self, addr):
        return ipv4_mc.get_mc_sa_addr_str(addr)

    def add_ip_multicast_route(self, saddr, gaddr, mcg, rpf, punt_on_rpf_fail, punt_and_forward, counter):
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(saddr, gaddr, mcg, rpf, punt_on_rpf_fail,
                                                           punt_and_forward, counter)

    def modify_ip_multicast_route(self, saddr, gaddr, mcg, rpf, punt_on_rpf_fail, punt_and_forward, counter):
        self.topology.vrf.hld_obj.modify_ipv4_multicast_route(saddr, gaddr, mcg, rpf, punt_on_rpf_fail,
                                                              punt_and_forward, counter)

    def delete_ip_multicast_route(self, saddr, gaddr):
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(saddr, gaddr)


class egress_member_punt_ipv6_test:
    protocol = 'v6'

    SIP = ipv6_mc.SIP
    ANY_IP = sdk.LA_IPV6_ANY_IP
    protocol_type = sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV6

    MC_GROUP_ADDR = T.ipv6_addr('ff01:0:0:0:0:1:ffe8:658f')

    def get_mc_sa_addr_str(self, addr):
        return ipv6_mc.get_mc_sa_addr_str(addr)

    def add_ip_multicast_route(self, saddr, gaddr, mcg, rpf, punt_on_rpf_fail, punt_and_forward, counter):
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(saddr, gaddr, mcg, rpf, punt_on_rpf_fail,
                                                           punt_and_forward, counter)

    def modify_ip_multicast_route(self, saddr, gaddr, mcg, rpf, punt_on_rpf_fail, punt_and_forward, counter):
        self.topology.vrf.hld_obj.modify_ipv6_multicast_route(saddr, gaddr, mcg, rpf, punt_on_rpf_fail,
                                                              punt_and_forward, counter)

    def delete_ip_multicast_route(self, saddr, gaddr):
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(saddr, gaddr)


class egress_member_punt_l3_ac_test:
    l3_port_impl_class = T.ip_l3_ac_base
    rx_vlan = T.RX_L3_AC_ONE_TAG_PORT_VID
    rx_port_gid = T.RX_L3_AC_ONE_TAG_GID
    TX_REG_MAC = T.TX_L3_AC_REG_MAC
    TX_SYS_PORT_GID = T.TX_L3_AC_SYS_PORT_REG_GID
    TX_DEF_MAC = T.TX_L3_AC_DEF_MAC
    output_serdes = T.FIRST_SERDES_L3

    def get_tx_l2_port(self):
        return None

    def get_tx_l2_port_def(self):
        return None

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj

    def initialize_rx_port(self):
        if self.protocol == 'v4':
            self.topology.rx_l3_ac_one_tag.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        else:
            self.topology.rx_l3_ac_one_tag.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

    def get_fwd_header_type(self):
        if self.protocol == 'v4':
            return sdk.la_packet_types.LA_HEADER_TYPE_IPV4
        else:
            return sdk.la_packet_types.LA_HEADER_TYPE_IPV6


class egress_member_punt_svi_test:
    l3_port_impl_class = T.ip_svi_base
    rx_vlan = T.RX_L2_AC_PORT_VID1
    rx_port_gid = T.RX_SVI_GID
    TX_REG_MAC = T.TX_SVI_MAC
    TX_SYS_PORT_GID = T.TX_SVI_SYS_PORT_REG_GID
    TX_DEF_MAC = TX_REG_MAC
    output_serdes = T.FIRST_SERDES_SVI

    def get_tx_l2_port(self):
        return self.topology.tx_l2_ac_port_reg.hld_obj

    def get_tx_l2_port_def(self):
        return self.topology.tx_l2_ac_port_def.hld_obj

    def get_tx_sys_port(self):
        return self.topology.tx_svi_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_svi_eth_port_def.sys_port.hld_obj

    def initialize_rx_port(self):
        if self.protocol == 'v4':
            self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        else:
            self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

    def get_fwd_header_type(self):
        if self.protocol == 'v4':
            return sdk.la_packet_types.LA_HEADER_TYPE_IPV4_COLLAPSED_MC
        else:
            return sdk.la_packet_types.LA_HEADER_TYPE_IPV6_COLLAPSED_MC
