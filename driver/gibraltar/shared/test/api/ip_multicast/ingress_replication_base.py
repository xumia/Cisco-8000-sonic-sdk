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

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *

from packet_test_utils import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
from ipv4_mc import *
from ipv6_mc import *
from sdk_multi_test_case_base import *
import mtu.mtu_test_utils as MTU
import ip_test_base
from mc_base import *
import decor


class ir_base(sdk_multi_test_case_base):
    mcg_gid = 0x13
    mpls_label_num = 0x65
    mpls_punt_label_num = 0x77
    pfx_obj_gid = 0x32
    nh_gid = 0x11
    default_ttl = 127
    pipe_mode_ttl = 255
    ttl = default_ttl
    mpls_ttl = default_ttl
    mpls_ttl_decr = 1
    mc_group_addr = T.ipv4_addr('225.1.2.3')
    dst_mc_mac_addr_str = ipv4_mc.get_mc_sa_addr_str(mc_group_addr)
    dst_mc_mac_addr = ipv4_mc.get_mc_sa_addr(mc_group_addr)
    mc_group_addr_ipv6 = T.ipv6_addr('ff01:0:0:0:0:1:ffe8:658f')
    src_mac = T.mac_addr('be:ef:5d:35:7a:35')

    def setUp(self):
        super().setUp()
        self.egress_packets, self.list1, self.list2 = ([] for i in range(3))
        self.port_data = {}
        self.create_switches()
        self.create_svi()
        self.mpls_port_data = {}

    def create_switches(self):
        self.rx_sw = self.topology.rx_switch   # T.RX_SWITCH_GID  = 0xa0a
        self.tx_sw = self.topology.rx_switch1  # T.RX_SWITCH_GID1 = 0xa0b
        self.tx2_sw = self.topology.tx_switch1  # T.TX_SWITCH_GID1 = 0xa0d

    def create_svi(self):
        # rx_svi, gid:0x711
        self.rx_svi = self.topology.rx_svi
        self.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        # tx_svi, gid: 0x712
        self.tx_svi = self.topology.rx_svi1
        self.tx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.tx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        # tx2_svi, gid: 0x731
        self.tx2_svi = self.topology.tx_svi_ext
        self.tx2_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.tx2_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

    # L3AC port template functions
    def create_l3ac_port_and_packet(self, slice, ifg, first_pif, last_pif, sysport_gid, acport_gid, mac_str):
        mac = T.mac_addr(mac_str)
        vrf = self.topology.vrf
        vid1 = T.RX_L3_AC_PORT_VID1
        vid2 = T.RX_L3_AC_PORT_VID2

        eth_port = T.ethernet_port(self, self.device, slice, ifg, sysport_gid, first_pif, last_pif)
        sys_port = eth_port.hld_obj.get_system_port()
        l3ac_port = T.l3_ac_port(self, self.device, acport_gid, eth_port, vrf, mac, vid1, vid2)
        l3ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        l3ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        packet = self.create_l3ac_egress_packet(mac_str)
        self.port_data[l3ac_port] = [packet, slice, ifg, first_pif, sys_port, mac_str]
        return l3ac_port

    def create_l3ac_egress_packet(self, mac):
        if (self.ipv4):
            out_pak = self.create_svi_ipv4_egress_packet(mac)
        else:
            out_pak = self.create_svi_ipv6_egress_packet(mac)
        return out_pak

    def create_l3ac_ipv4_egress_packet(self, mac):
        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=ipv4_mc.get_mc_sa_addr_str(self.mc_group_addr), src=mac) /\
            IP(src=ipv4_mc.SIP.addr_str, dst=self.mc_group_addr.addr_str, ttl=self.ttl - 1) /\
            TCP() / Raw(load=RAW_PAYLOAD)

        out_pak, __ = pad_input_and_output_packets(EXPECTED_OUTPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
        return out_pak

    def create_l3ac_ipv6_egress_packet(self, mac):
        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=ipv6_mc.get_mc_sa_addr_str(self.mc_group_addr), src=mac) /\
            IPv6(src=ipv6_mc.SIP.addr_str, dst=self.mc_group_addr.addr_str, hlim=self.ttl - 1, plen=40) /\
            TCP() / Raw(load=RAW_PAYLOAD)

        out_pak, __ = pad_input_and_output_packets(EXPECTED_OUTPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
        return out_pak

    def create_l3ac_ingress_packet(self):
        if decor.is_asic5():
            self.l3ac_port02 = self.create_l3ac_port_and_packet(0, 0, 36, 37, 0x77, 0x707, "30:37:38:39:31:37")
        else:
            self.l3ac_port02 = self.create_l3ac_port_and_packet(0, 0, 8, 9, 0x77, 0x707, "30:37:38:39:31:37")
        if (self.ipv4):
            self.create_l3ac_ipv4_ingress_packet()
        else:
            self.create_l3ac_ipv6_ingress_packet()

    def create_l3ac_ipv4_ingress_packet(self):
        INPUT_PACKET_BASE = \
            Ether(dst=ipv4_mc.get_mc_sa_addr_str(self.mc_group_addr), src=self.src_mac.addr_str, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=ipv4_mc.SIP.addr_str, dst=self.mc_group_addr.addr_str, ttl=self.ttl) / TCP() / Raw(load=RAW_PAYLOAD)
        self.input_packet, __ = pad_input_and_output_packets(INPUT_PACKET_BASE, INPUT_PACKET_BASE)
        self.input_ip_packet = IP(src=ipv4_mc.SIP.addr_str, dst=self.mc_group_addr.addr_str,
                                  ttl=self.ttl) / TCP() / Raw(load=RAW_PAYLOAD)
        self.ingress_packet = {'data': self.input_packet, 'slice': 0, 'ifg': 0, 'pif': 8}

    def create_l3ac_egress_mpls_punt_packet(self, mac, label_num):
        EXPECTED_OUTPUT_PACKET_PUNT = \
            Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=mc_base.PUNT_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
                 next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_EGRESS_TRAP,
                 code=sdk.LA_EVENT_MPLS_INVALID_TTL,
                 source_sp=0xffff,
                 destination_sp=0x76,
                 # source_lp=T.RX_L3_AC_GID,
                 source_lp=0x707,
                 destination_lp=0x706,
                 relay_id=T.VRF_GID,
                 lpts_flow_type=0) / self.input_ip_packet

        out_pak, __ = pad_input_and_output_packets(EXPECTED_OUTPUT_PACKET_PUNT, EXPECTED_OUTPUT_PACKET_PUNT)
        return out_pak

    def create_l3ac_egress_mpls_packet(self, mac, label_num):
        EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv4_mc.get_mc_sa_addr_str(self.mc_group_addr),
                                            src=mac,
                                            type=Ethertype.MPLS.value) / MPLS(label=label_num,
                                                                              ttl=self.mpls_ttl - self. mpls_ttl_decr) / IP(src=ipv4_mc.SIP.addr_str,
                                                                                                                            dst=self.mc_group_addr.addr_str,
                                                                                                                            ttl=self.ttl - 1) / TCP() / Raw(load=RAW_PAYLOAD)

        out_pak, __ = pad_input_and_output_packets(EXPECTED_OUTPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
        return out_pak

    def create_l3ac_ipv6_ingress_packet(self):
        INPUT_PACKET_BASE = \
            Ether(dst=ipv6_mc.get_mc_sa_addr_str(self.mc_group_addr_ipv6), src=self.src_mac.addr_str, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IPv6(src=ipv6_mc.SIP.addr_str, dst=self.mc_group_addr_ipv6.addr_str, hlim=self.ttl, plen=40) /\
            TCP() / Raw(load=RAW_PAYLOAD)
        self.input_packet, __ = pad_input_and_output_packets(INPUT_PACKET_BASE, INPUT_PACKET_BASE)
        self.ingress_packet = {'data': self.input_packet, 'slice': 0, 'ifg': 0, 'pif': 8}

    def create_all_l3ac_ports(self):
        if decor.is_asic5():
            self.l3ac_port01 = self.create_l3ac_port_and_packet(0, 0, 20, 21, 0x70, 0x700, "30:37:38:39:31:30")
            self.l3ac_port11 = self.create_l3ac_port_and_packet(0, 0, 22, 23, 0x71, 0x701, "30:37:38:39:31:31")
            self.l3ac_port21 = self.create_l3ac_port_and_packet(0, 0, 24, 25, 0x72, 0x702, "30:37:38:39:31:32")
            self.l3ac_port31 = self.create_l3ac_port_and_packet(0, 0, 26, 27, 0x73, 0x703, "30:37:38:39:31:33")
            self.l3ac_port41 = self.create_l3ac_port_and_packet(0, 0, 28, 29, 0x74, 0x704, "30:37:38:39:31:34")
            self.l3ac_port51 = self.create_l3ac_port_and_packet(0, 0, 30, 31, 0x75, 0x705, "30:37:38:39:31:35")
        else:
            self.l3ac_port01 = self.create_l3ac_port_and_packet(0, 0, 6, 7, 0x70, 0x700, "30:37:38:39:31:30")
            self.l3ac_port11 = self.create_l3ac_port_and_packet(1, 0, 6, 7, 0x71, 0x701, "30:37:38:39:31:31")
            self.l3ac_port21 = self.create_l3ac_port_and_packet(2, 0, 6, 7, 0x72, 0x702, "30:37:38:39:31:32")
            self.l3ac_port31 = self.create_l3ac_port_and_packet(3, 0, 6, 7, 0x73, 0x703, "30:37:38:39:31:33")
            self.l3ac_port41 = self.create_l3ac_port_and_packet(4, 0, 6, 7, 0x74, 0x704, "30:37:38:39:31:34")
            self.l3ac_port51 = self.create_l3ac_port_and_packet(5, 0, 6, 7, 0x75, 0x705, "30:37:38:39:31:35")

        self.l3ac_port42 = self.create_l3ac_port_and_packet(4, 0, 8, 9, 0x76, 0x706, "30:37:38:39:31:42")
        self.l3ac_port43 = self.create_l3ac_port_and_packet(4, 0, 10, 11, 0x78, 0x708, "30:37:38:39:31:43")

    def create_nh_pfx_obj(self, label_num, pfx_obj_gid, nh_gid, l3ac_port_obj):
        OUTPUT_LABEL = sdk.la_mpls_label()
        OUTPUT_LABEL.label = label_num
        lsp_labels = []
        lsp_labels.append(OUTPUT_LABEL)
        nh = self.device.create_next_hop(nh_gid, self.dst_mc_mac_addr, l3ac_port_obj, sdk.la_next_hop.nh_type_e_NORMAL)
        prefix_object = self.device.create_prefix_object(
            pfx_obj_gid,
            nh,
            sdk.la_prefix_object.prefix_type_e_NORMAL)
        prefix_object.set_nh_lsp_properties(nh, lsp_labels, None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
        return prefix_object, nh

    def add_l3ac_port_to_ipmcg(self, ip_mcg, l3ac_port, pak_list):
        ip_mcg.add(l3ac_port.hld_obj, None, self.port_data[l3ac_port][4])
        self.add_packet_to_list(pak_list, l3ac_port)

    def remove_l3ac_port_from_ipmcg(self, ip_mcg, l3ac_port, pak_list):
        ip_mcg.remove(l3ac_port.hld_obj, None)
        self.remove_packet_from_list(pak_list, l3ac_port)

    def add_l3ac_mpls_port(self, mpls_mcg, egress_packets, label_num, pfx_obj_gid, nh_gid, l3ac_port):
        mpls_packet = self.create_l3ac_egress_mpls_packet(self.port_data[l3ac_port][5], label_num)
        prefix_object, nh = self.create_nh_pfx_obj(label_num,
                                                   pfx_obj_gid,
                                                   nh_gid,
                                                   l3ac_port.hld_obj)

        mpls_mcg.add(prefix_object, self.port_data[l3ac_port][4])
        egress_packets.append({'data': mpls_packet,
                               'slice': self.port_data[l3ac_port][1],
                               'ifg': self.port_data[l3ac_port][2],
                               'pif': self.port_data[l3ac_port][3]})
        self.mpls_port_data[l3ac_port] = [mpls_packet, prefix_object, nh]

    def remove_l3ac_mpls_port(self, mpls_mcg, egress_packets, l3ac_port):
        # remove prefix
        mpls_mcg.remove(self.mpls_port_data[l3ac_port][1])
        # destroy prefix
        self.device.destroy(self.mpls_port_data[l3ac_port][1])
        # destroy nh
        self.device.destroy(self.mpls_port_data[l3ac_port][2])
        egress_packets.remove({'data': self.mpls_port_data[l3ac_port][0],
                               'slice': self.port_data[l3ac_port][1],
                               'ifg': self.port_data[l3ac_port][2],
                               'pif': self.port_data[l3ac_port][3]})

    def add_l3ac_port42_mpls_punt(self, mpls_mcg, egress_packets, label_num, pfx_obj_gid, nh_gid):
        self.l3ac_port42_mpls_pak = self.create_l3ac_egress_mpls_punt_packet("30:37:38:39:31:42", label_num)

        self.l3ac_port42_prefix_object, self.l3ac_port42_nh  = self.create_nh_pfx_obj(label_num,
                                                                                      pfx_obj_gid,
                                                                                      nh_gid,
                                                                                      self.l3ac_port42.hld_obj)

        mpls_mcg.add(self.l3ac_port42_prefix_object, self.port_data[self.l3ac_port42][4])

        egress_packets.append({'data': self.l3ac_port42_mpls_pak, 'slice': 3, 'ifg': 0, 'pif': 8})

    def remove_l3ac_port42_mpls_punt(self, mpls_mcg, egress_packets):
        mpls_mcg.remove(self.l3ac_port42_prefix_object)
        self.device.destroy(self.l3ac_port42_prefix_object)
        self.device.destroy(self.l3ac_port42_nh)
        egress_packets.remove({'data': self.l3ac_port42_mpls_pak, 'slice': 3, 'ifg': 0, 'pif': 8})

    def do_test_l3ac_ingress_rep_mpls_ttl_eq_1(self):
        self.create_all_l3ac_ports()
        self.mpls_ttl = 1
        self.mpls_ttl_decr = 1
        self.ttl = 1
        self.trap = True
        self.trap_code = sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)

        pi_port = T.punt_inject_port(self, self.device, mc_base.INJECT_SLICE, mc_base.INJECT_IFG, mc_base.INJECT_SP_GID,
                                     mc_base.INJECT_PIF_FIRST, mc_base.PUNT_INJECT_PORT_MAC_ADDR)
        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID,
                                                 pi_port, mc_base.HOST_MAC_ADDR, mc_base.PUNT_VLAN)
        mirror_cmd = T.create_l2_mirror_command(self.device, mc_base.MIRROR_CMD_GID, pi_port,
                                                mc_base.HOST_MAC_ADDR, mc_base.MIRROR_VLAN)
        mc_base.initSnoopsAndTraps(self.device, punt_dest, mirror_cmd)
        self.device.set_trap_configuration(sdk.LA_EVENT_MPLS_INVALID_TTL, 0, None, punt_dest, False, False, True, 0)

        self.main_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_INGRESS)
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.main_mcg, None, False, False, None)
        self.create_l3ac_ingress_packet()
        self.egress_packets = []
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.mpls_mcg1 = self.device.create_mpls_multicast_group(self.mcg_gid + 2, sdk.la_replication_paradigm_e_EGRESS)
        self.mpls_mcg1_out_packets = []
        self.main_mcg.add(self.mpls_mcg1)
        self.add_l3ac_port42_mpls_punt(self.mpls_mcg1,
                                       self.mpls_mcg1_out_packets,
                                       self.mpls_punt_label_num,
                                       self.pfx_obj_gid,
                                       self.nh_gid)
        self.egress_packets = self.mpls_mcg1_out_packets
        #import pdb; pdb.set_trace()
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)
        self.remove_l3ac_port42_mpls_punt(self.mpls_mcg1, self.mpls_mcg1_out_packets)
        self.egress_packets = []
        #U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)
        self.main_mcg.remove(self.mpls_mcg1)
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.device.destroy(self.mpls_mcg1)
        self.device.destroy(self.main_mcg)
        self.ttl = 127

    def do_test_l3ac_ingress_rep_mpls_ttl(self, is_uniform_mode):
        if (is_uniform_mode):
            self.mpls_ttl = self.default_ttl
            self.mpls_ttl_decr = 1
            self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        else:
            self.mpls_ttl = self.pipe_mode_ttl
            self.mpls_ttl_decr = 0
            self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self.main_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_INGRESS)
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.main_mcg, None, False, False, None)
        # self.create_l3ac_ingress_packet()
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.mpls_mcg1 = self.device.create_mpls_multicast_group(self.mcg_gid + 2, sdk.la_replication_paradigm_e_EGRESS)
        self.mpls_mcg1_out_packets = []
        self.main_mcg.add(self.mpls_mcg1)
        self.add_l3ac_mpls_port(self.mpls_mcg1,
                                self.mpls_mcg1_out_packets,
                                self.mpls_label_num,
                                self.pfx_obj_gid,
                                self.nh_gid,
                                self.l3ac_port42)
        self.add_l3ac_mpls_port(self.mpls_mcg1,
                                self.mpls_mcg1_out_packets,
                                self.mpls_label_num + 1,
                                self.pfx_obj_gid + 1,
                                self.nh_gid + 1,
                                self.l3ac_port43)
        self.egress_packets = self.mpls_mcg1_out_packets
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.l3ac_mcg = self.device.create_ip_multicast_group(self.mcg_gid + 4, sdk.la_replication_paradigm_e_EGRESS)
        self.l3ac_mcg_out_packets = []

        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port01, self.l3ac_mcg_out_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port11, self.l3ac_mcg_out_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port21, self.l3ac_mcg_out_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port31, self.l3ac_mcg_out_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port41, self.l3ac_mcg_out_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port51, self.l3ac_mcg_out_packets)

        self.main_mcg.add(self.l3ac_mcg)

        self.egress_packets = self.mpls_mcg1_out_packets + self.l3ac_mcg_out_packets
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.mpls_mcg2 = self.device.create_mpls_multicast_group(self.mcg_gid + 3, sdk.la_replication_paradigm_e_EGRESS)
        self.mpls_mcg2_out_packets = []
        self.main_mcg.add(self.mpls_mcg2)
        self.add_l3ac_mpls_port(self.mpls_mcg2,
                                self.mpls_mcg2_out_packets,
                                self.mpls_label_num + 2,
                                self.pfx_obj_gid + 2,
                                self.nh_gid + 2,
                                self.l3ac_port11)
        self.add_l3ac_mpls_port(self.mpls_mcg2,
                                self.mpls_mcg2_out_packets,
                                self.mpls_label_num + 3,
                                self.pfx_obj_gid + 3,
                                self.nh_gid + 3,
                                self.l3ac_port21)
        self.egress_packets = self.mpls_mcg1_out_packets + self.l3ac_mcg_out_packets + self.mpls_mcg2_out_packets
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.l3ac_mcg2 = self.device.create_ip_multicast_group(self.mcg_gid + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.l3ac_mcg2_out_packets = []
        self.main_mcg.add(self.l3ac_mcg2)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg2, self.l3ac_port42, self.l3ac_mcg2_out_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg2, self.l3ac_port43, self.l3ac_mcg2_out_packets)
        #self.add_l3ac_port42(self.l3ac_mcg2, self.l3ac_mcg2_out_packets)
        #self.add_l3ac_port43(self.l3ac_mcg2, self.l3ac_mcg2_out_packets)
        self.egress_packets = self.mpls_mcg1_out_packets + self.l3ac_mcg_out_packets + self.mpls_mcg2_out_packets + self.l3ac_mcg2_out_packets
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.remove_l3ac_port_from_ipmcg(self.l3ac_mcg, self.l3ac_port21, self.l3ac_mcg_out_packets)
        #self.remove_l3ac_port21(self.l3ac_mcg, self.l3ac_mcg_out_packets)

        #self.add_l3ac_port21(self.l3ac_mcg2, self.l3ac_mcg2_out_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg2, self.l3ac_port21, self.l3ac_mcg2_out_packets)

        self.egress_packets = self.mpls_mcg1_out_packets + self.l3ac_mcg_out_packets + self.mpls_mcg2_out_packets + self.l3ac_mcg2_out_packets
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.main_mcg.remove(self.l3ac_mcg)
        self.egress_packets = self.mpls_mcg1_out_packets + self.l3ac_mcg2_out_packets + self.mpls_mcg2_out_packets
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        #import pdb; pdb.set_trace()
        self.main_mcg.remove(self.l3ac_mcg2)
        self.egress_packets = self.mpls_mcg1_out_packets + self.mpls_mcg2_out_packets
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        #import pdb; pdb.set_trace()
        self.remove_l3ac_mpls_port(self.mpls_mcg1, self.mpls_mcg1_out_packets, self.l3ac_port42)
        self.remove_l3ac_mpls_port(self.mpls_mcg1, self.mpls_mcg1_out_packets, self.l3ac_port43)
        self.egress_packets = self.mpls_mcg2_out_packets
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)
        self.main_mcg.remove(self.mpls_mcg1)

        self.remove_l3ac_mpls_port(self.mpls_mcg2, self.mpls_mcg2_out_packets, self.l3ac_port11)
        self.remove_l3ac_mpls_port(self.mpls_mcg2, self.mpls_mcg2_out_packets, self.l3ac_port21)
        self.egress_packets = []
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)
        self.main_mcg.remove(self.mpls_mcg2)

        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.device.destroy(self.l3ac_mcg2)
        self.device.destroy(self.l3ac_mcg)
        self.device.destroy(self.mpls_mcg1)
        self.device.destroy(self.mpls_mcg2)
        self.device.destroy(self.main_mcg)

    def do_test_l3ac_ingress_rep_mpls(self):
        self.create_all_l3ac_ports()
        self.create_l3ac_ingress_packet()
        # self.do_test_l3ac_ingress_rep_mpls_ttl(True)
        self.do_test_l3ac_ingress_rep_mpls_ttl(False)

    # L2AC port template functions
    def create_l2ac_port_and_packet(self, slice, ifg, first_pif, last_pif, sysport_gid, acport_gid, sw, svi, feature_mode=None):
        eth_port = T.ethernet_port(self, self.device, slice, ifg, sysport_gid, first_pif, last_pif)
        sys_port = eth_port.hld_obj.get_system_port()
        l2ac_port = T.l2_ac_port(self, self.device, acport_gid, None, sw, eth_port, T.RX_MAC,
                                 egress_feature_mode = feature_mode)

        packet = self.create_svi_egress_packet(svi)
        self.port_data[l2ac_port] = [packet, slice, ifg, first_pif, sys_port]
        return l2ac_port

    def create_svi_egress_packet(self, svi):
        svi_mac = svi.hld_obj.get_mac()
        mac_str = T.mac_addr.mac_num_to_str(svi_mac.flat)
        if (self.ipv4):
            out_pak = self.create_svi_ipv4_egress_packet(mac_str)
        else:
            out_pak = self.create_svi_ipv6_egress_packet(mac_str)
        return out_pak

    def create_svi_ipv4_egress_packet(self, mac_str):
        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=ipv4_mc.get_mc_sa_addr_str(self.mc_group_addr), src=mac_str) /\
            IP(src=ipv4_mc.SIP.addr_str, dst=self.mc_group_addr.addr_str, ttl=self.ttl - 1) /\
            TCP() / Raw(load=RAW_PAYLOAD)

        out_pak, __ = pad_input_and_output_packets(EXPECTED_OUTPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
        return out_pak

    def create_svi_ipv6_egress_packet(self, mac_str):
        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=ipv6_mc.get_mc_sa_addr_str(self.mc_group_addr_ipv6), src=mac_str) /\
            IPv6(src=ipv6_mc.SIP.addr_str, dst=self.mc_group_addr_ipv6.addr_str, hlim=self.ttl - 1, plen=40) /\
            TCP() / Raw(load=RAW_PAYLOAD)

        out_pak, __ = pad_input_and_output_packets(EXPECTED_OUTPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
        return out_pak

    def create_svi_ingress_packet(self):
        if decor.is_asic5():
            self.l2ac_port42 = self.create_l2ac_port_and_packet(0, 0, 36, 37, 0x90, 0x810, self.rx_sw, self.rx_svi)
        else:
            self.l2ac_port42 = self.create_l2ac_port_and_packet(4, 1, 8, 9, 0x90, 0x810, self.rx_sw, self.rx_svi)
        if (self.ipv4):
            self.create_svi_ipv4_ingress_packet()
        else:
            self.create_svi_ipv6_ingress_packet()

    def create_svi_ipv4_ingress_packet(self):
        INPUT_PACKET_BASE = \
            Ether(dst=ipv4_mc.get_mc_sa_addr_str(self.mc_group_addr), src=self.src_mac.addr_str) / \
            IP(src=ipv4_mc.SIP.addr_str, dst=self.mc_group_addr.addr_str, ttl=self.ttl) / TCP() / Raw(load=RAW_PAYLOAD)
        self.input_packet, __ = pad_input_and_output_packets(INPUT_PACKET_BASE, INPUT_PACKET_BASE)
        self.ingress_packet = {'data': self.input_packet, 'slice': 4, 'ifg': 1, 'pif': 8}

    def create_svi_ipv6_ingress_packet(self):
        INPUT_PACKET_BASE = \
            Ether(dst=ipv6_mc.get_mc_sa_addr_str(self.mc_group_addr_ipv6), src=self.src_mac.addr_str) / \
            IPv6(src=ipv6_mc.SIP.addr_str, dst=self.mc_group_addr_ipv6.addr_str, hlim=self.ttl, plen=40) /\
            TCP() / Raw(load=RAW_PAYLOAD)
        self.input_packet, __ = pad_input_and_output_packets(INPUT_PACKET_BASE, INPUT_PACKET_BASE)
        self.ingress_packet = {'data': self.input_packet, 'slice': 4, 'ifg': 1, 'pif': 8}

    def create_all_l2ac_ports(self):
        if decor.is_asic5():
            self.l2ac_port01 = self.create_l2ac_port_and_packet(0, 0, 20, 21, 0x80, 0x800, self.tx_sw, self.tx_svi)
            self.l2ac_port11 = self.create_l2ac_port_and_packet(0, 0, 22, 23, 0x81, 0x801, self.tx_sw, self.tx_svi)
            self.l2ac_port21 = self.create_l2ac_port_and_packet(0, 0, 24, 25, 0x82, 0x802, self.tx_sw, self.tx_svi)

            self.l2ac_port31 = self.create_l2ac_port_and_packet(0, 0, 26, 27, 0x83, 0x8003, self.tx2_sw, self.tx2_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)
            self.l2ac_port32 = self.create_l2ac_port_and_packet(0, 0, 28, 29, 0x84, 0x8004, self.tx2_sw, self.tx2_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)
            self.l2ac_port33 = self.create_l2ac_port_and_packet(0, 0, 30, 31, 0x85, 0x8005, self.tx2_sw, self.tx2_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)

            self.l2ac_port41 = self.create_l2ac_port_and_packet(0, 0, 32, 33, 0x86, 0x806, self.rx_sw, self.rx_svi)
            self.l2ac_port51 = self.create_l2ac_port_and_packet(0, 0, 34, 35, 0x87, 0x8007, self.rx_sw, self.rx_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)
        else:
            self.l2ac_port01 = self.create_l2ac_port_and_packet(0, 1, 6, 7, 0x80, 0x800, self.tx_sw, self.tx_svi)
            self.l2ac_port11 = self.create_l2ac_port_and_packet(1, 1, 6, 7, 0x81, 0x801, self.tx_sw, self.tx_svi)
            self.l2ac_port21 = self.create_l2ac_port_and_packet(2, 1, 6, 7, 0x82, 0x802, self.tx_sw, self.tx_svi)

            self.l2ac_port31 = self.create_l2ac_port_and_packet(3, 1, 6, 7, 0x83, 0x8003, self.tx2_sw, self.tx2_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)
            self.l2ac_port32 = self.create_l2ac_port_and_packet(3, 1, 8, 9, 0x84, 0x8004, self.tx2_sw, self.tx2_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)
            self.l2ac_port33 = self.create_l2ac_port_and_packet(3, 1, 10, 11, 0x85, 0x8005, self.tx2_sw, self.tx2_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)

            self.l2ac_port41 = self.create_l2ac_port_and_packet(4, 1, 6, 7, 0x86, 0x806, self.rx_sw, self.rx_svi)
            self.l2ac_port51 = self.create_l2ac_port_and_packet(5, 1, 6, 7, 0x87, 0x8007, self.rx_sw, self.rx_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)

    def add_l2ac_port_to_ipmcg(self, ip_mcg, svi, l2ac_port, pak_list):
        ip_mcg.add(svi.hld_obj, l2ac_port.hld_obj, self.port_data[l2ac_port][4])
        self.add_packet_to_list(pak_list, l2ac_port, svi)

    def remove_l2ac_port_from_ipmcg(self, ip_mcg, svi, l2ac_port, pak_list):
        ip_mcg.remove(svi.hld_obj, l2ac_port.hld_obj)
        self.remove_packet_from_list(pak_list, l2ac_port, svi)

    def add_l2ac_port_to_l2mcg(self, l2_mcg, svi, l2ac_port, pak_list):
        l2_mcg.add(l2ac_port.hld_obj, self.port_data[l2ac_port][4])
        self.add_packet_to_list(pak_list, l2ac_port, svi)

    def remove_l2ac_port_from_l2mcg(self, l2_mcg, svi, l2ac_port, pak_list):
        l2_mcg.remove(l2ac_port.hld_obj)
        self.remove_packet_from_list(pak_list, l2ac_port, svi)

    def add_packet_to_list(self, pak_list, port, svi=None):
        if (svi == self.rx_svi):
            pak_list.append({'data': self.input_packet,
                             'slice': self.port_data[port][1],
                             'ifg': self.port_data[port][2],
                             'pif': self.port_data[port][3]})
        else:
            pak_list.append({'data': self.port_data[port][0],
                             'slice': self.port_data[port][1],
                             'ifg': self.port_data[port][2],
                             'pif': self.port_data[port][3]})

    def remove_packet_from_list(self, pak_list, port, svi=None):
        if (svi == self.rx_svi):
            pak_list.remove({'data': self.input_packet,
                             'slice': self.port_data[port][1],
                             'ifg': self.port_data[port][2],
                             'pif': self.port_data[port][3]})
        else:
            pak_list.remove({'data': self.port_data[port][0],
                             'slice': self.port_data[port][1],
                             'ifg': self.port_data[port][2],
                             'pif': self.port_data[port][3]})

    # testcases
    def do_test_l3ac_egress_rep(self):
        self.create_all_l3ac_ports()
        self.l3ac_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_EGRESS)

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.l3ac_mcg, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.l3ac_mcg, None, False, False, None)
        self.create_l3ac_ingress_packet()
        # test empty egress group
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port01, self.egress_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port11, self.egress_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port21, self.egress_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port31, self.egress_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port41, self.egress_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port51, self.egress_packets)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.remove_l3ac_port_from_ipmcg(self.l3ac_mcg, self.l3ac_port01, self.egress_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port01, self.egress_packets)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # let test framework remove/destroy the member/groups
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj)

    def do_test_l3ac_ingress_rep(self):
        self.create_all_l3ac_ports()

        # add ports in all slices
        self.l3ac_mcg = self.device.create_ip_multicast_group(self.mcg_gid + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port01, self.egress_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port11, self.egress_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port21, self.egress_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port31, self.egress_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port41, self.egress_packets)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port51, self.egress_packets)

        self.main_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_INGRESS)
        self.main_mcg.add(self.l3ac_mcg)

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.main_mcg, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.main_mcg, None, False, False, None)
        self.create_l3ac_ingress_packet()
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # let test framework remove all the members and groups
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj)

    def do_test_l3ac_ingress_rep_with_ports(self):
        self.create_all_l3ac_ports()

        self.main_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_INGRESS)
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.main_mcg, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.main_mcg, None, False, False, None)
        self.create_l3ac_ingress_packet()
        # test empty ingress group
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # add ports to ingress group
        self.add_l3ac_port_to_ipmcg(self.main_mcg, self.l3ac_port01, self.list1)
        self.add_l3ac_port_to_ipmcg(self.main_mcg, self.l3ac_port11, self.list1)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.list1)

        # add ipmcg to ingress group
        self.l3ac_mcg = self.device.create_ip_multicast_group(self.mcg_gid + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port21, self.list2)
        self.main_mcg.add(self.l3ac_mcg)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port31, self.list2)
        self.remove_l3ac_port_from_ipmcg(self.l3ac_mcg, self.l3ac_port31, self.list2)
        self.remove_l3ac_port_from_ipmcg(self.l3ac_mcg, self.l3ac_port21, self.list2)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.list1 + self.list2)

        # modify portlist and egressgroup list
        self.remove_l3ac_port_from_ipmcg(self.main_mcg, self.l3ac_port01, self.list1)
        self.add_l3ac_port_to_ipmcg(self.l3ac_mcg, self.l3ac_port01, self.list2)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.list1 + self.list2)

        # remove and re-add member to ingress group
        self.main_mcg.remove(self.l3ac_mcg)
        self.main_mcg.add(self.l3ac_mcg)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.list1 + self.list2)

        # destroy ingress group without removing the some members
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj)
        self.device.destroy(self.main_mcg)

    def do_test_svi_egress_rep(self):
        self.create_all_l2ac_ports()
        self.svi_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_EGRESS)

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.svi_mcg, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.svi_mcg, None, False, False, None)
        self.create_svi_ingress_packet()
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # test both routed and bridge case
        self.add_l2ac_port_to_ipmcg(self.svi_mcg, self.tx_svi, self.l2ac_port01, self.egress_packets)
        self.add_l2ac_port_to_ipmcg(self.svi_mcg, self.tx2_svi, self.l2ac_port31, self.egress_packets)
        self.add_l2ac_port_to_ipmcg(self.svi_mcg, self.tx2_svi, self.l2ac_port32, self.egress_packets)
        self.add_l2ac_port_to_ipmcg(self.svi_mcg, self.tx2_svi, self.l2ac_port33, self.egress_packets)
        self.add_l2ac_port_to_ipmcg(self.svi_mcg, self.rx_svi, self.l2ac_port41, self.egress_packets)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # mc_em_db holds 2 payloads per entry. when a non-last member is deleted, then last member
        # is moved into deleted member's place.
        self.remove_l2ac_port_from_ipmcg(self.svi_mcg, self.tx2_svi, self.l2ac_port31, self.egress_packets)
        self.add_l2ac_port_to_ipmcg(self.svi_mcg, self.tx_svi, self.l2ac_port21, self.egress_packets)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # modify port list
        self.add_l2ac_port_to_ipmcg(self.svi_mcg, self.tx2_svi, self.l2ac_port31, self.egress_packets)
        self.remove_l2ac_port_from_ipmcg(self.svi_mcg, self.tx_svi, self.l2ac_port01, self.egress_packets)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj)
        self.device.destroy(self.svi_mcg)

    def do_test_svi_ingress_rep(self):
        self.create_all_l2ac_ports()
        self.create_svi_ingress_packet()

        # add l2ac_ports in all slices (allocate in l2dlp range)
        self.tx_svi_mcg = self.device.create_l2_multicast_group(self.mcg_gid + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.add_l2ac_port_to_l2mcg(self.tx_svi_mcg, self.tx_svi, self.l2ac_port01, self.egress_packets)
        self.add_l2ac_port_to_l2mcg(self.tx_svi_mcg, self.tx_svi, self.l2ac_port11, self.egress_packets)
        self.add_l2ac_port_to_l2mcg(self.tx_svi_mcg, self.tx_svi, self.l2ac_port21, self.egress_packets)
        self.tx2_svi_mcg = self.device.create_l2_multicast_group(self.mcg_gid + 2, sdk.la_replication_paradigm_e_EGRESS)
        self.add_l2ac_port_to_l2mcg(self.tx2_svi_mcg, self.tx2_svi, self.l2ac_port31, self.egress_packets)
        self.add_l2ac_port_to_l2mcg(self.tx2_svi_mcg, self.tx2_svi, self.l2ac_port33, self.egress_packets)
        self.rx_svi_mcg = self.device.create_l2_multicast_group(self.mcg_gid + 3, sdk.la_replication_paradigm_e_EGRESS)
        self.add_l2ac_port_to_l2mcg(self.rx_svi_mcg, self.rx_svi, self.l2ac_port51, self.egress_packets)

        # test both routed copies and bridge copies (transition to cud range)
        self.main_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_INGRESS)
        self.main_mcg.add(self.tx_svi.hld_obj, self.tx_svi_mcg)
        self.main_mcg.add(self.tx2_svi.hld_obj, self.tx2_svi_mcg)
        self.main_mcg.add(self.rx_svi.hld_obj, self.rx_svi_mcg)

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.main_mcg, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.main_mcg, None, False, False, None)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # adding mcg-member to ingress group inserts 3 entries to mc-em-db. when a non-last member
        # is deleted, then last member is moved to deleted member's place (slice-wise)
        self.main_mcg.remove(self.tx2_svi.hld_obj, self.tx2_svi_mcg)
        self.main_mcg.add(self.tx2_svi.hld_obj, self.tx2_svi_mcg)
        self.add_l2ac_port_to_l2mcg(self.tx2_svi_mcg, self.tx2_svi, self.l2ac_port32, self.egress_packets)
        self.remove_l2ac_port_from_l2mcg(self.tx2_svi_mcg, self.tx2_svi, self.l2ac_port33, self.egress_packets)
        self.add_l2ac_port_to_l2mcg(self.rx_svi_mcg, self.rx_svi, self.l2ac_port41, self.egress_packets)
        self.remove_l2ac_port_from_l2mcg(self.rx_svi_mcg, self.rx_svi, self.l2ac_port51, self.egress_packets)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # remove all mcg-members and destroy the ingress group
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj)
        self.main_mcg.remove(self.tx_svi.hld_obj, self.tx_svi_mcg)
        self.main_mcg.remove(self.tx2_svi.hld_obj, self.tx2_svi_mcg)
        self.main_mcg.remove(self.rx_svi.hld_obj, self.rx_svi_mcg)
        self.device.destroy(self.main_mcg)

    def do_test_svi_ingress_rep_with_ports(self):
        self.create_all_l2ac_ports()

        self.main_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_INGRESS)
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.main_mcg, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.main_mcg, None, False, False, None)
        self.create_svi_ingress_packet()

        # add empty l2mcg to ingress group
        self.mcg1 = self.device.create_l2_multicast_group(self.mcg_gid + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.main_mcg.add(self.tx_svi.hld_obj, self.mcg1)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # add port to mcg1 (allocate in cud range)
        self.add_l2ac_port_to_l2mcg(self.mcg1, self.tx_svi, self.l2ac_port01, self.egress_packets)
        self.add_l2ac_port_to_l2mcg(self.mcg1, self.tx_svi, self.l2ac_port11, self.egress_packets)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # remove/add mcg1 to check transition of copy-id to/fro l2-dlp/cud-mapping range
        self.main_mcg.remove(self.tx_svi.hld_obj, self.mcg1)
        self.add_l2ac_port_to_l2mcg(self.mcg1, self.tx_svi, self.l2ac_port21, self.egress_packets)
        self.main_mcg.add(self.tx_svi.hld_obj, self.mcg1)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # add l2ac ports to ingress group
        self.add_l2ac_port_to_ipmcg(self.main_mcg, self.rx_svi, self.l2ac_port41, self.egress_packets)
        self.add_l2ac_port_to_ipmcg(self.main_mcg, self.tx2_svi, self.l2ac_port31, self.egress_packets)
        self.remove_l2ac_port_from_l2mcg(self.mcg1, self.tx_svi, self.l2ac_port11, self.egress_packets)
        self.add_l2ac_port_to_ipmcg(self.main_mcg, self.tx_svi, self.l2ac_port11, self.egress_packets)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # modify portlist and member-mcg portlist
        self.remove_l2ac_port_from_ipmcg(self.main_mcg, self.tx_svi, self.l2ac_port11, self.egress_packets)
        self.add_l2ac_port_to_l2mcg(self.mcg1, self.tx_svi, self.l2ac_port11, self.egress_packets)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj)

    def do_test_ingress_rep(self):
        if decor.is_asic5():
            self.l3ac_port01 = self.create_l3ac_port_and_packet(0, 0, 20, 21, 0x70, 0x700, "30:37:38:39:31:30")
            self.l3ac_port11 = self.create_l3ac_port_and_packet(0, 0, 22, 23, 0x71, 0x701, "30:37:38:39:31:31")
            self.l2ac_port21 = self.create_l2ac_port_and_packet(0, 0, 24, 25, 0x82, 0x802, self.tx_sw, self.tx_svi)
            self.l2ac_port31 = self.create_l2ac_port_and_packet(0, 0, 26, 27, 0x83, 0x8003, self.tx2_sw, self.tx2_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)
        else:
            self.l3ac_port01 = self.create_l3ac_port_and_packet(0, 0, 6, 7, 0x70, 0x700, "30:37:38:39:31:30")
            self.l3ac_port11 = self.create_l3ac_port_and_packet(1, 0, 6, 7, 0x71, 0x701, "30:37:38:39:31:31")
            self.l2ac_port21 = self.create_l2ac_port_and_packet(2, 1, 6, 7, 0x82, 0x802, self.tx_sw, self.tx_svi)
            self.l2ac_port31 = self.create_l2ac_port_and_packet(3, 1, 6, 7, 0x83, 0x8003, self.tx2_sw, self.tx2_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)

        # ingress group contain l2mcg, ipmcg, l3port and l2port
        self.mcg1 = self.device.create_l2_multicast_group(self.mcg_gid + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.mcg2 = self.device.create_ip_multicast_group(self.mcg_gid + 2, sdk.la_replication_paradigm_e_EGRESS)
        self.main_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_INGRESS)

        self.add_l2ac_port_to_l2mcg(self.mcg1, self.tx_svi, self.l2ac_port21, self.egress_packets)
        self.add_l3ac_port_to_ipmcg(self.mcg2, self.l3ac_port11, self.egress_packets)
        self.add_l3ac_port_to_ipmcg(self.main_mcg, self.l3ac_port01, self.egress_packets)
        self.add_l2ac_port_to_ipmcg(self.main_mcg, self.tx2_svi, self.l2ac_port31, self.egress_packets)

        self.main_mcg.add(self.tx_svi.hld_obj, self.mcg1)
        self.main_mcg.add(self.mcg2)

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.main_mcg, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.main_mcg, None, False, False, None)

        # incoming from l2port
        self.create_svi_ingress_packet()
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # incoming from l3port
        self.create_l3ac_ingress_packet()
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.remove_l3ac_port_from_ipmcg(self.main_mcg, self.l3ac_port01, self.egress_packets)
        self.remove_l2ac_port_from_ipmcg(self.main_mcg, self.tx2_svi, self.l2ac_port31, self.egress_packets)
        self.main_mcg.remove(self.tx_svi.hld_obj, self.mcg1)
        self.main_mcg.remove(self.mcg2)

        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj)

    def do_test_mcg_counter(self):
        self.ingress_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_INGRESS)

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.ingress_mcg, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.ingress_mcg, None, False, False, None)
        self.create_l3ac_ingress_packet()

        self.counter = self.device.create_counter(1)  # set_size=1
        self.device_id = self.device.get_id()
        self.ingress_mcg.set_egress_counter(self.device_id, self.counter)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        if decor.is_asic5():
            self.l3ac_port31 = self.create_l3ac_port_and_packet(0, 0, 20, 21, 0x73, 0x703, "30:37:38:39:31:33")
        else:
            self.l3ac_port31 = self.create_l3ac_port_and_packet(3, 0, 6, 7, 0x73, 0x703, "30:37:38:39:31:33")
        self.add_l3ac_port_to_ipmcg(self.ingress_mcg, self.l3ac_port31, self.egress_packets)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        packet_count, byte_count = self.counter.read(0,  # sub-counter index
                                                     True,  # force_update
                                                     True)  # clear_on_read
        self.assertEqual(packet_count, 2)
        #U.assertPacketLengthEgress(self, self.input_packet, byte_count)

        self.ingress_mcg.set_egress_counter(self.device_id, None)

        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj)
        self.device.destroy(self.ingress_mcg)

    def do_test_set_dsp_same_slice(self):
        self.main_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_INGRESS)
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.main_mcg, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.main_mcg, None, False, False, None)
        self.create_svi_ingress_packet()

        self.txsvi_mcg = self.device.create_l2_multicast_group(self.mcg_gid + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.main_mcg.add(self.tx_svi.hld_obj, self.txsvi_mcg)

        mac_port1 = T.mac_port(self, self.device, 2, 0, 8, 9)
        sys_port1 = T.system_port(self, self.device, 0x92, mac_port1)
        mac_port1.activate()
        mac_port2 = T.mac_port(self, self.device, 2, 0, 10, 11)
        sys_port2 = T.system_port(self, self.device, 0x93, mac_port2)
        mac_port2.activate()
        spa_port = T.spa_port(self, self.device, 0x123)
        spa_port.add(sys_port1)
        spa_port.add(sys_port2)
        eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        ac_port = T.l2_ac_port(self, self.device, 0x812, None, self.tx_sw, eth_port, None)
        self.txsvi_mcg.add(ac_port.hld_obj, sys_port1.hld_obj)

        self.egress_packets = []
        self.spa_packet = self.create_svi_egress_packet(self.tx_svi)
        self.egress_packets.append({'data': self.spa_packet, 'slice': 2, 'ifg': 0, 'pif': 8})
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.txsvi_mcg.set_destination_system_port(ac_port.hld_obj, sys_port2.hld_obj)
        self.egress_packets = []
        self.egress_packets.append({'data': self.spa_packet, 'slice': 2, 'ifg': 0, 'pif': 10})
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj)
        self.device.destroy(self.main_mcg)
        self.device.destroy(self.txsvi_mcg)

    def do_test_set_dsp_different_slice(self):
        self.main_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_INGRESS)
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.main_mcg, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.main_mcg, None, False, False, None)

        self.txsvi_mcg = self.device.create_l2_multicast_group(self.mcg_gid + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.main_mcg.add(self.tx_svi.hld_obj, self.txsvi_mcg)

        mac_port1 = T.mac_port(self, self.device, 1, 0, 8, 9)
        sys_port1 = T.system_port(self, self.device, 0x94, mac_port1)
        mac_port1.activate()
        mac_port2 = T.mac_port(self, self.device, 3, 0, 10, 11)
        sys_port2 = T.system_port(self, self.device, 0x95, mac_port2)
        mac_port2.activate()
        spa_port = T.spa_port(self, self.device, 0x124)
        spa_port.add(sys_port1)
        spa_port.add(sys_port2)
        eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        ac_port = T.l2_ac_port(self, self.device, 0x813, None, self.tx_sw, eth_port, None)
        self.txsvi_mcg.add(ac_port.hld_obj, sys_port1.hld_obj)

        self.egress_packets = []
        self.spa_packet = self.create_svi_egress_packet(self.tx_svi)
        self.egress_packets.append({'data': self.spa_packet, 'slice': 1, 'ifg': 0, 'pif': 8})
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.txsvi_mcg.set_destination_system_port(ac_port.hld_obj, sys_port2.hld_obj)
        self.egress_packets = []
        self.egress_packets.append({'data': self.spa_packet, 'slice': 3, 'ifg': 0, 'pif': 10})
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj)
        self.device.destroy(self.main_mcg)
        self.device.destroy(self.txsvi_mcg)

    def do_test_l2mcg_refcount(self):
        # test when l2mcg is added as member to multiple ipmcg
        if decor.is_asic5():
            self.l2ac_port01 = self.create_l2ac_port_and_packet(0, 0, 20, 21, 0x80, 0x800, self.tx_sw, self.tx_svi)
            self.l2ac_port11 = self.create_l2ac_port_and_packet(0, 0, 22, 23, 0x81, 0x801, self.tx_sw, self.tx_svi)
            self.l2ac_port21 = self.create_l2ac_port_and_packet(0, 0, 24, 25, 0x82, 0x802, self.tx_sw, self.tx_svi)
        else:
            self.l2ac_port01 = self.create_l2ac_port_and_packet(0, 1, 6, 7, 0x80, 0x800, self.tx_sw, self.tx_svi)
            self.l2ac_port11 = self.create_l2ac_port_and_packet(1, 1, 6, 7, 0x81, 0x801, self.tx_sw, self.tx_svi)
            self.l2ac_port21 = self.create_l2ac_port_and_packet(2, 1, 6, 7, 0x82, 0x802, self.tx_sw, self.tx_svi)
        self.create_svi_ingress_packet()

        self.l2_mcg = self.device.create_l2_multicast_group(self.mcg_gid + 3, sdk.la_replication_paradigm_e_EGRESS)
        self.add_l2ac_port_to_l2mcg(self.l2_mcg, self.tx_svi, self.l2ac_port01, self.egress_packets)
        self.add_l2ac_port_to_l2mcg(self.l2_mcg, self.tx_svi, self.l2ac_port11, self.egress_packets)
        self.add_l2ac_port_to_l2mcg(self.l2_mcg, self.tx_svi, self.l2ac_port21, self.egress_packets)

        self.ip_mcg1 = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_INGRESS)
        self.ip_mcg2 = self.device.create_ip_multicast_group(self.mcg_gid + 1, sdk.la_replication_paradigm_e_INGRESS)
        self.ip_mcg3 = self.device.create_ip_multicast_group(self.mcg_gid + 2, sdk.la_replication_paradigm_e_INGRESS)

        self.ip_mcg1.add(self.tx_svi.hld_obj, self.l2_mcg)
        self.ip_mcg2.add(self.tx_svi.hld_obj, self.l2_mcg)
        self.ip_mcg3.add(self.tx_svi.hld_obj, self.l2_mcg)

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.ip_mcg1, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.ip_mcg1, None, False, False, None)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj)
        self.ip_mcg1.remove(self.tx_svi.hld_obj, self.l2_mcg)

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.ip_mcg2, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.ip_mcg2, None, False, False, None)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj)
        self.ip_mcg2.remove(self.tx_svi.hld_obj, self.l2_mcg)

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.ip_mcg3, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.ip_mcg3, None, False, False, None)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj)
        self.ip_mcg3.remove(self.tx_svi.hld_obj, self.l2_mcg)

        self.device.destroy(self.ip_mcg1)
        self.device.destroy(self.ip_mcg2)
        self.device.destroy(self.ip_mcg3)
        self.device.destroy(self.l2_mcg)

        self.do_test_l2mcg_refcount2()

    def do_test_l2mcg_refcount2(self):
        self.sw = T.switch(self, self.device, 0xa0e)
        self.svi = T.svi_port(self, self.device, 0x1000, self.sw, self.topology.vrf, T.RX_SVI_MAC)

        self.main_mcg1 = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_INGRESS)
        self.main_mcg2 = self.device.create_ip_multicast_group(self.mcg_gid + 1, sdk.la_replication_paradigm_e_INGRESS)
        self.main_mcg3 = self.device.create_ip_multicast_group(self.mcg_gid + 2, sdk.la_replication_paradigm_e_INGRESS)
        self.svi_mcg = self.device.create_l2_multicast_group(self.mcg_gid + 3, sdk.la_replication_paradigm_e_EGRESS)

        self.main_mcg1.add(self.svi.hld_obj, self.svi_mcg)
        self.main_mcg2.add(self.svi.hld_obj, self.svi_mcg)
        self.main_mcg3.add(self.svi.hld_obj, self.svi_mcg)
        self.main_mcg1.remove(self.svi.hld_obj, self.svi_mcg)
        self.main_mcg2.remove(self.svi.hld_obj, self.svi_mcg)
        self.device.destroy(self.main_mcg3)
        self.device.destroy(self.svi.hld_obj)

        self.add_l2ac_port_to_l2mcg(self.svi_mcg, None, self.l2ac_port01, self.egress_packets)

    def do_test_flood_set(self):
        self.uc_dst_mac = T.mac_addr('be:ef:5d:35:7a:36')
        if decor.is_asic5():
            self.l2ac_port42 = self.create_l2ac_port_and_packet(0, 0, 20, 21, 0x90, 0x810, self.rx_sw, self.rx_svi)
            self.l2ac_port41 = self.create_l2ac_port_and_packet(0, 0, 22, 23, 0x86, 0x806, self.rx_sw, self.rx_svi)
            self.l2ac_port51 = self.create_l2ac_port_and_packet(0, 0, 24, 25, 0x87, 0x8007, self.rx_sw, self.rx_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)
        else:
            self.l2ac_port42 = self.create_l2ac_port_and_packet(4, 1, 8, 9, 0x90, 0x810, self.rx_sw, self.rx_svi)
            self.l2ac_port41 = self.create_l2ac_port_and_packet(4, 1, 6, 7, 0x86, 0x806, self.rx_sw, self.rx_svi)
            self.l2ac_port51 = self.create_l2ac_port_and_packet(5, 1, 6, 7, 0x87, 0x8007, self.rx_sw, self.rx_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)

        INPUT_PACKET_BASE = \
            Ether(dst=self.uc_dst_mac.addr_str, src=self.src_mac.addr_str) /\
            IP(src=ipv4_mc.SIP.addr_str, dst=self.mc_group_addr.addr_str, ttl=self.ttl) / TCP() / Raw(load=RAW_PAYLOAD)
        self.input_packet, __ = pad_input_and_output_packets(INPUT_PACKET_BASE, INPUT_PACKET_BASE)
        self.ingress_packet = {'data': self.input_packet, 'slice': 4, 'ifg': 1, 'pif': 8}

        self.rxsvi_mcg = self.device.create_l2_multicast_group(self.mcg_gid + 3, sdk.la_replication_paradigm_e_EGRESS)
        self.add_l2ac_port_to_l2mcg(self.rxsvi_mcg, self.rx_svi, self.l2ac_port41, self.list1)
        self.add_l2ac_port_to_l2mcg(self.rxsvi_mcg, self.rx_svi, self.l2ac_port51, self.list1)
        self.rx_sw.hld_obj.set_flood_destination(self.rxsvi_mcg)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.list1)

        self.ingress_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_INGRESS)
        self.ingress_mcg.add(self.rx_svi.hld_obj, self.rxsvi_mcg)
        # packets are not expected - bug, will be fixed in follow-up commit
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.ingress_mcg.remove(self.rx_svi.hld_obj, self.rxsvi_mcg)

    # L2 Multicast (IGMP/MLD Snooping) + IP Multicase testcases
    def do_test_l2mc_ir(self):
        if decor.is_asic5():
            self.l2ac_port41 = self.create_l2ac_port_and_packet(0, 0, 20, 21, 0x86, 0x806, self.rx_sw, self.rx_svi)
            self.l2ac_port51 = self.create_l2ac_port_and_packet(0, 0, 22, 23, 0x87, 0x8007, self.rx_sw, self.rx_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)
        else:
            self.l2ac_port41 = self.create_l2ac_port_and_packet(4, 1, 6, 7, 0x86, 0x806, self.rx_sw, self.rx_svi)
            self.l2ac_port51 = self.create_l2ac_port_and_packet(5, 1, 6, 7, 0x87, 0x8007, self.rx_sw, self.rx_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)

        self.main_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_INGRESS)

        self.create_svi_ingress_packet()

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.main_mcg, None, False, False, None)
        self.rx_sw.hld_obj.set_ipv4_multicast_enabled(True)

        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.main_mcg, None, False, False, None)
        self.rx_sw.hld_obj.set_ipv6_multicast_enabled(True)

        self.rxsvi_flood_mcg = self.device.create_l2_multicast_group(self.mcg_gid + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsvi_mrouter_mcg = self.device.create_l2_multicast_group(self.mcg_gid + 2, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsvi_snoop_mcg = self.device.create_l2_multicast_group(self.mcg_gid + 3, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsvi_flood_list = []
        self.rxsvi_mrouter_list = []
        self.rxsvi_snoop_list = []
        self.rx_sw.hld_obj.set_flood_destination(self.rxsvi_flood_mcg)
        self.add_l2ac_port_to_l2mcg(self.rxsvi_mrouter_mcg, self.rx_svi, self.l2ac_port41, self.rxsvi_mrouter_list)
        self.add_l2ac_port_to_l2mcg(self.rxsvi_snoop_mcg, self.rx_svi, self.l2ac_port41, self.rxsvi_snoop_list)
        self.add_l2ac_port_to_l2mcg(self.rxsvi_snoop_mcg, self.rx_svi, self.l2ac_port51, self.rxsvi_snoop_list)

        # add some ports for routing
        self.tx_svi_mcg = self.device.create_l2_multicast_group(self.mcg_gid + 4, sdk.la_replication_paradigm_e_EGRESS)
        self.tx2_svi_mcg = self.device.create_l2_multicast_group(self.mcg_gid + 5, sdk.la_replication_paradigm_e_EGRESS)
        if decor.is_asic5():
            self.l2ac_port21 = self.create_l2ac_port_and_packet(0, 0, 24, 25, 0x82, 0x802, self.tx_sw, self.tx_svi)
            self.l2ac_port31 = self.create_l2ac_port_and_packet(3, 1, 26, 27, 0x83, 0x8003, self.tx2_sw, self.tx2_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)
        else:
            self.l2ac_port21 = self.create_l2ac_port_and_packet(2, 1, 6, 7, 0x82, 0x802, self.tx_sw, self.tx_svi)
            self.l2ac_port31 = self.create_l2ac_port_and_packet(3, 1, 6, 7, 0x83, 0x8003, self.tx2_sw, self.tx2_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)

        self.add_l2ac_port_to_l2mcg(self.tx_svi_mcg, self.tx_svi, self.l2ac_port21, self.list1)
        self.add_l2ac_port_to_l2mcg(self.tx2_svi_mcg, self.tx2_svi, self.l2ac_port31, self.list1)
        self.main_mcg.add(self.tx_svi.hld_obj, self.tx_svi_mcg)
        self.main_mcg.add(self.tx2_svi.hld_obj, self.tx2_svi_mcg)
        if decor.is_asic5():
            self.l3ac_port01 = self.create_l3ac_port_and_packet(0, 0, 28, 29, 0x70, 0x700, "30:37:38:39:31:30")
        else:
            self.l3ac_port01 = self.create_l3ac_port_and_packet(0, 0, 6, 7, 0x70, 0x700, "30:37:38:39:31:30")
        self.add_l3ac_port_to_ipmcg(self.main_mcg, self.l3ac_port01, self.list1)

        # execute tests
        self.do_test_routing_enabled_snooping_enabled_with_joins()
        self.do_test_routing_enabled_snooping_enabled_no_joins()
        self.do_test_routing_disabled_snooping_enabled_with_joins()
        self.do_test_routing_disabled_snooping_enabled_no_joins()

    def do_test_routing_enabled_snooping_enabled_with_joins(self):
        self.main_mcg.add(self.rx_svi.hld_obj, self.rxsvi_snoop_mcg)
        self.egress_packets = self.rxsvi_snoop_list + self.list1
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.main_mcg.remove(self.rx_svi.hld_obj, self.rxsvi_snoop_mcg)

    def do_test_routing_enabled_snooping_enabled_no_joins(self):
        self.main_mcg.add(self.rx_svi.hld_obj, self.rxsvi_mrouter_mcg)
        self.egress_packets = self.rxsvi_mrouter_list + self.list1
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.main_mcg.remove(self.rx_svi.hld_obj, self.rxsvi_mrouter_mcg)

    def do_test_routing_disabled_snooping_enabled_with_joins(self):
        self.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, False)
        self.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, False)

        self.rx_sw.hld_obj.add_ipv4_multicast_route(self.mc_group_addr.hld_obj, self.rxsvi_snoop_mcg)
        self.rx_sw.hld_obj.add_ipv6_multicast_route(self.mc_group_addr_ipv6.hld_obj, self.rxsvi_snoop_mcg)

        self.egress_packets = self.rxsvi_snoop_list
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.rx_sw.hld_obj.delete_ipv4_multicast_route(self.mc_group_addr.hld_obj)
        self.rx_sw.hld_obj.delete_ipv6_multicast_route(self.mc_group_addr_ipv6.hld_obj)

    def do_test_routing_disabled_snooping_enabled_no_joins(self):
        self.egress_packets = self.rxsvi_mrouter_list
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

    def do_test_set_rep_paradigm(self):
        if decor.is_asic5():
            self.l3ac_port01 = self.create_l3ac_port_and_packet(0, 0, 20, 21, 0x70, 0x700, "30:37:38:39:31:30")
            self.l3ac_port11 = self.create_l3ac_port_and_packet(0, 0, 22, 23, 0x71, 0x701, "30:37:38:39:31:31")
            self.l2ac_port11 = self.create_l2ac_port_and_packet(0, 0, 24, 25, 0x81, 0x801, self.tx_sw, self.tx_svi)
            self.l2ac_port21 = self.create_l2ac_port_and_packet(0, 0, 26, 27, 0x82, 0x802, self.tx_sw, self.tx_svi)
            self.l2ac_port31 = self.create_l2ac_port_and_packet(0, 0, 28, 29, 0x83, 0x8003, self.tx2_sw, self.tx2_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)
        else:
            self.l3ac_port01 = self.create_l3ac_port_and_packet(0, 0, 6, 7, 0x70, 0x700, "30:37:38:39:31:30")
            self.l3ac_port11 = self.create_l3ac_port_and_packet(1, 0, 6, 7, 0x71, 0x701, "30:37:38:39:31:31")
            self.l2ac_port11 = self.create_l2ac_port_and_packet(1, 1, 6, 7, 0x81, 0x801, self.tx_sw, self.tx_svi)
            self.l2ac_port21 = self.create_l2ac_port_and_packet(2, 1, 6, 7, 0x82, 0x802, self.tx_sw, self.tx_svi)
            self.l2ac_port31 = self.create_l2ac_port_and_packet(3, 1, 6, 7, 0x83, 0x8003, self.tx2_sw, self.tx2_svi,
                                                                feature_mode= sdk.la_l2_service_port.egress_feature_mode_e_L3)

        # create egress group and members to egress group
        self.main_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_EGRESS)
        self.add_l2ac_port_to_ipmcg(self.main_mcg, self.tx2_svi, self.l2ac_port31, self.egress_packets)
        self.add_l3ac_port_to_ipmcg(self.main_mcg, self.l3ac_port11, self.egress_packets)

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.main_mcg, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.main_mcg, None, False, False, None)

        # incoming from l2port
        self.create_svi_ingress_packet()
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        # change to ingress paradigm
        self.main_mcg.set_replication_paradigm(sdk.la_replication_paradigm_e_INGRESS)

        self.mcg1 = self.device.create_l2_multicast_group(self.mcg_gid + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.main_mcg.add(self.tx_svi.hld_obj, self.mcg1)
        self.add_l2ac_port_to_l2mcg(self.mcg1, self.tx_svi, self.l2ac_port11, self.list1)
        self.add_l2ac_port_to_l2mcg(self.mcg1, self.tx_svi, self.l2ac_port21, self.list1)

        self.mcg2 = self.device.create_ip_multicast_group(self.mcg_gid + 2, sdk.la_replication_paradigm_e_EGRESS)
        self.add_l3ac_port_to_ipmcg(self.mcg2, self.l3ac_port01, self.list1)
        self.main_mcg.add(self.mcg2)

        # incoming from l3port
        self.create_l3ac_ingress_packet()
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets + self.list1)

        # change to egress paradigm
        with self.assertRaises(sdk.InvalException):
            self.main_mcg.set_replication_paradigm(sdk.la_replication_paradigm_e_EGRESS)

        self.main_mcg.remove(self.tx_svi.hld_obj, self.mcg1)
        self.main_mcg.remove(self.mcg2)

        self.main_mcg.set_replication_paradigm(sdk.la_replication_paradigm_e_EGRESS)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj)

    def do_test_set_rep_paradigm_empty(self):
        self.main_mcg = self.device.create_ip_multicast_group(self.mcg_gid, sdk.la_replication_paradigm_e_EGRESS)
        self.main_mcg.set_replication_paradigm(sdk.la_replication_paradigm_e_INGRESS)

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.main_mcg, None, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, self.mc_group_addr_ipv6.hld_obj, self.main_mcg, None, False, False, None)
        self.create_l3ac_ingress_packet()
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.main_mcg.set_replication_paradigm(sdk.la_replication_paradigm_e_EGRESS)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.main_mcg.set_replication_paradigm(sdk.la_replication_paradigm_e_INGRESS)
        if decor.is_asic5():
            self.l3ac_port01 = self.create_l3ac_port_and_packet(0, 0, 20, 21, 0x70, 0x700, "30:37:38:39:31:30")
        else:
            self.l3ac_port01 = self.create_l3ac_port_and_packet(0, 0, 6, 7, 0x70, 0x700, "30:37:38:39:31:30")
        self.add_l3ac_port_to_ipmcg(self.main_mcg, self.l3ac_port01, self.egress_packets)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)

        self.main_mcg.set_replication_paradigm(sdk.la_replication_paradigm_e_EGRESS)
        self.remove_l3ac_port_from_ipmcg(self.main_mcg, self.l3ac_port01, self.egress_packets)
        U.run_and_compare_list(self, self.device, self.ingress_packet, self.egress_packets)
