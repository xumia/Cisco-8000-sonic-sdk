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

from packet_test_utils import *
from lc_base import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T

MC_GROUP_ID = 0x10010
MC_GROUP_ADDR = '225.1.2.3'
MC_SIP = '51.51.51.52'
MC_TEST_THRESHOLD = 4096
MC_FABRIC_MCID = 0xffff


class ingress_scale_lc_multicast_base(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(INGRESS_DEVICE_ID, slice_modes=sim_utils.LINECARD_3N_3F_DEV)

        self.topology = T.topology(self, self.device, create_default_topology=True)

        self.mc_group_addr = T.ipv4_addr(MC_GROUP_ADDR)
        self.dst_mc_mac_addr_str = self.get_mc_sa_addr_str(self.mc_group_addr)
        self.dst_mc_mac_addr = self.get_mc_sa_addr(self.mc_group_addr)
        self.mc_sip = T.ipv4_addr(MC_SIP)

        self.mpls_label_num = 0x65
        self.pfx_obj_gid = 0x32
        self.nh_gid = 0x11
        self.mpls_ttl = TTL
        self.mpls_ttl_decr = 1
        self.non_scale_mcid = 0x13

        self.topology.create_inject_ports()
        self.device.set_is_fabric_time_master(True)

        # Init TTL mode s.t. IP TTL is copied to MPLS frame
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)

        self.create_packets()
        self.create_l3ac_ports()

    def tearDown(self):
        # Reset the multicast scale threshold to free the recycle port
        self.device.set_int_property(sdk.la_device_property_e_MULTICAST_MCID_SCALE_THRESHOLD, (1 << 16))

        self.device.tearDown()

    def init_misc(self):
        self.vrf = self.topology.global_vrf
        self.ac_profile = T.ac_profile(self, self.device)

        # Create rx fabric port
        self.out_rx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            5,
            EGRESS_RX_IFG,
            EGRESS_RX_SERDES_FIRST,
            EGRESS_RX_SERDES_LAST)

        self.out_rx_fabric_mac_port.hld_obj.set_loopback_mode(sdk.la_mac_port.loopback_mode_e_PMA_CORE_CLK)
        self.out_rx_fabric_mac_port.hld_obj.activate()
        time.sleep(2)

        self.out_rx_fabric_port = T.fabric_port(self, self.device, self.out_rx_fabric_mac_port)
        # needed for running on stingray
#        out_rx_fabric_port.hld_obj.activate(sdk.la_fabric_port.link_protocol_e_PEER_DISCOVERY)
#        out_rx_fabric_port.hld_obj.activate(sdk.la_fabric_port.link_protocol_e_LINK_KEEPALIVE)
        self.out_rx_fabric_port.hld_obj.set_reachable_lc_devices([self.device.device.get_id()])

        # Create tx network port
        self.out_tx_eth_port = T.ethernet_port(
            self,
            self.device,
            EGRESS_TX_SLICE,
            EGRESS_TX_IFG,
            EGRESS_SYS_PORT_GID,
            EGRESS_TX_SERDES_FIRST,
            EGRESS_TX_SERDES_LAST)
        self.out_tx_eth_port.set_ac_profile(self.ac_profile)

        self.out_l3_port_mac = T.mac_addr(OUT_L3_AC_PORT_MAC)
        self.out_l3_ac = T.l3_ac_port(self, self.device,
                                      GID_BASE + 1,
                                      self.out_tx_eth_port,
                                      self.vrf,
                                      self.out_l3_port_mac)
        self.out_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.out_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        self.device.set_int_property(sdk.la_device_property_e_MULTICAST_MCID_SCALE_THRESHOLD, MC_TEST_THRESHOLD)

    def get_mc_sa_addr_str(self, ip_addr):
        octets = ip_addr.addr_str.split('.')
        assert(len(octets) == 4)
        sa_addr_str = '01:00:5e'
        sa_addr_str += ':%02x' % (0x7f & int(octets[1]))
        for o in octets[2:]:
            sa_addr_str += ':%02x' % (int(o))
        return sa_addr_str

    def get_mc_sa_addr(self, ip_addr):
        octets = ip_addr.addr_str.split('.')
        assert(len(octets) == 4)
        sa_addr_upper = 0x01005e << 24
        sa_addr_middle = (0x7f & int(octets[1])) << 16
        sa_addr_lower = (int(octets[2]) << 8 | int(octets[3]))
        sa_addr = sa_addr_upper | sa_addr_middle | sa_addr_lower
        mc_dst_mac = sdk.la_mac_addr_t()
        mc_dst_mac.flat = sa_addr
        return mc_dst_mac

    def create_l3ac_port(self, slice, ifg, first_pif, last_pif, sysport_gid, acport_gid, mac_str):
        mac = T.mac_addr(mac_str)

        vrf = self.topology.vrf
        vid1 = T.RX_L3_AC_PORT_VID1
        vid2 = T.RX_L3_AC_PORT_VID2

        eth_port = T.ethernet_port(self, self.device, slice, ifg, sysport_gid, first_pif, last_pif)
        l3ac_port = T.l3_ac_port(self, self.device, acport_gid, eth_port, vrf, mac, vid1, vid2)
        l3ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        l3ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)
        return eth_port, l3ac_port

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

    def create_l3ac_egress_packet(self, mac):
        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst="1:00:5e:01:02:03", src=mac) / \
            IP(dst=MC_GROUP_ADDR, src=MC_SIP, ttl=(TTL - 1)) / TCP()
        out_pak = add_payload(EXPECTED_OUTPUT_PACKET_BASE, 8)

        return out_pak

    def create_l3ac_egress_mpls_packet(self, mac, label_num):
        EXPECTED_OUTPUT_PACKET_BASE = Ether(dst="1:00:5e:01:02:03",
                                            src=mac,
                                            type=Ethertype.MPLS.value) / MPLS(label=label_num,
                                                                              ttl=self.mpls_ttl - self.mpls_ttl_decr) / IP(src=MC_SIP,
                                                                                                                           dst=self.mc_group_addr.addr_str,
                                                                                                                           ttl=TTL - 1) / TCP()

        out_pak = add_payload(EXPECTED_OUTPUT_PACKET_BASE, 8)
        return out_pak

    def create_l3ac_ports(self):
        self.l3ac_ethport01, self.l3ac_port01 = self.create_l3ac_port(0, 0, 6, 7, 0x70, 0x700, "30:37:38:39:31:30")
        self.l3ac_ethport21, self.l3ac_port21 = self.create_l3ac_port(2, 0, 10, 11, 0x72, 0x702, "40:47:48:49:41:41")

    def add_l3ac_port01_packet(self, egress_packets):
        self.l3ac_port01_pak = self.create_l3ac_egress_packet("30:37:38:39:31:30")
        egress_packets.append({'data': self.l3ac_port01_pak, 'slice': 0, 'ifg': 0, 'pif': 6})

    def remove_l3ac_port01_packet(self, egress_packets):
        egress_packets.remove({'data': self.l3ac_port01_pak, 'slice': 0, 'ifg': 0, 'pif': 6})

    def add_l3ac_port21_mpls_packet(self, egress_packets, label_num):
        self.l3ac_port21_mpls_pak = self.create_l3ac_egress_mpls_packet("40:47:48:49:41:41", label_num)
        egress_packets.append({'data': self.l3ac_port21_mpls_pak, 'slice': 2, 'ifg': 0, 'pif': 10})

    def remove_l3ac_port21_mpls_packet(self, egress_packets):
        egress_packets.remove({'data': self.l3ac_port21_mpls_pak, 'slice': 2, 'ifg': 0, 'pif': 10})

    def add_l3ac_default_tx_packet(self):
        egress_tx_pkt_base = Ether(dst="1:00:5e:01:02:03", src="40:41:42:43:44:45") / \
            IP(dst=MC_GROUP_ADDR, src=MC_SIP, ttl=(TTL - 1)) / TCP()
        self.egress_tx_pkt = add_payload(egress_tx_pkt_base, self.base_input_packet_payload_size)
        self.egress_packets.append({'data': self.egress_tx_pkt, 'slice': EGRESS_TX_SLICE,
                                    'ifg': EGRESS_TX_IFG, 'pif': EGRESS_TX_SERDES_FIRST})

    def remove_l3ac_default_tx_packet(self, egress_packets):
        egress_packets.remove({'data': self.egress_tx_pkt, 'slice': EGRESS_TX_SLICE,
                               'ifg': EGRESS_TX_IFG, 'pif': EGRESS_TX_SERDES_FIRST})

    def create_packets(self):
        self.egress_packets = []
        ingress_rx_pkt_base = Ether(dst="1:00:5e:01:02:03", src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=VLAN) / \
            IP(dst=MC_GROUP_ADDR, src=MC_SIP, ttl=TTL) / TCP()

        ingress_tx_pkt_base = \
            TS_PLB(header_type="ONE_PKT_TS3",       # Single packet, 3 timestamps
                   fcn=0,                           # Forward congestion notification
                   link_fc=0,                       # Link FC
                   plb_context="MC",                # Multicast
                   ts3=[0, 0, 0],                    # Inject fabric time
                   src_device=INGRESS_DEVICE_ID,
                   src_slice=INGRESS_RX_SLICE,
                   reserved=0) / \
            TM(header_type="MMM",               # All Multicast (ingress/fabric/egress)
               vce=0,                           # VOQ congestion experienced flag
               tc=0,                            # Traffic class
               dp=0,                            # DP?
               multicast_id=MC_FABRIC_MCID) / \
            NPU_Header_ext(base_type="NPU_NO_IVE",          # NPU Header data is taken from the actual packet produced by LC NSIM.
                           fwd_header_type="IPV4",
                           fwd_qos_tag=0x00,                # All values below were not analized for semantic meaning,
                           lb_key=0x64e9,                   # they are just pasted from a decoded packet.
                           slp_qos_id=15,
                           encap_type=0,
                           encap=0x0,
                           punt_mc_expand_encap=MC_GROUP_ID,
                           ipv4_first_fragment=1,
                           ttl=TTL,
                           fwd_slp_info=0xa0,
                           fwd_relay_id=0) / \
            IP(dst=MC_GROUP_ADDR, src=MC_SIP) / TCP()

        self.ingress_rx_pkt, self.base_input_packet_payload_size = enlarge_packet_to_min_length(ingress_rx_pkt_base)
        self.base_input_packet_payload_size = self.base_input_packet_payload_size + 6
        self.ingress_tx_pkt = add_payload(ingress_tx_pkt_base, self.base_input_packet_payload_size)
        self.egress_rx_pkt = self.ingress_tx_pkt
        self.ingress_packet = {'data': self.egress_rx_pkt, 'slice': 5, 'ifg': EGRESS_RX_IFG, 'pif': EGRESS_RX_SERDES_FIRST}
