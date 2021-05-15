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

from sdk_test_case_base import *
from packet_test_utils import *
from scapy.all import *
import ipaddress
import unittest
from leaba import sdk
import sim_utils
import topology as T
import decor
import bit_utils

IN_SLICE = 2
IN_IFG = 0
IN_SERDES_FIRST = 4
IN_SERDES_LAST = IN_SERDES_FIRST + 1
OUT_SLICE = 1
OUT_IFG = 1
OUT_SERDES_FIRST = 8
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

SYS_PORT_GID_BASE = 0x100
AC_PORT_GID_BASE = 0x200
NH_GID_BASE = 0x300
VRF_GID = 0x400

IN_SRC_MAC = '04:72:73:74:75:76'
RX_MAC = T.mac_addr('11:12:13:14:15:16')
TX_MAC = T.mac_addr('04:f4:bc:57:d5:00')

IPV4_SIP = T.ipv4_addr('12.10.12.10')
IPV6_SIP = T.ipv6_addr('1234:1234:1234:1234:0000:0000:0000:abcd')
TTL = 50
HLIM = 128

RX_VLAN = 0x100
PRIVATE_DATA = 0


@unittest.skipIf(not decor.is_hw_device(), "Running only on HW")
@unittest.skipIf(not (decor.is_pacific() or decor.is_gibraltar()), "Currently supports only Pacific/GB")
class lpm_routing(sdk_test_case_base):

    RUN_HBM = False

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_CREATED:
            if RUN_HBM:
                device.set_bool_property(sdk.la_device_property_e_ENABLE_HBM, True)
                device.set_bool_property(sdk.la_device_property_e_ENABLE_HBM_ROUTE_EXTENSION, True)
                device.set_bool_property(sdk.la_device_property_e_ENABLE_HBM_ROUTE_EXTENSION_CACHING_MODE, False)

    @classmethod
    def setUpClass(cls):
        if cls.RUN_HBM:
            super(lpm_routing, cls).setUpClass(device_config_func=lpm_routing.device_config_func)
        else:
            super(lpm_routing, cls).setUpClass()

    def setUp(self):
        self.topology = T.topology(self, self.device, create_default_topology=False)
        self.topology.create_default_profiles()
        self.topology.create_inject_ports()
        self.create_eth_ports()
        self.vrf = self.device.create_vrf(VRF_GID)
        self.create_rx_port()

    def create_eth_ports(self):
        self.ac_profile = T.ac_profile(self, self.device)

        self.rx_eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
        self.rx_eth_port.set_ac_profile(self.ac_profile)

        self.tx_eth_port = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 1,
            OUT_SERDES_FIRST,
            OUT_SERDES_LAST)
        self.tx_eth_port.set_ac_profile(self.ac_profile)

    def create_rx_port(self):
        ac_gid = AC_PORT_GID_BASE - 1
        self.rx_ac_port = self.device.create_l3_ac_port(
            ac_gid,
            self.rx_eth_port.hld_obj,
            RX_VLAN,
            0,
            RX_MAC.hld_obj,
            self.vrf,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)
        self.rx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.rx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

    def create_routing_topology(self, dips):
        v4_prefixes_action_vec = []
        v6_prefixes_action_vec = []
        expected_packet_to_port = []

        egress_vlan_tag = sdk.la_vlan_tag_t()
        egress_vlan_tag.tpid = 0x8100

        ac_gid = AC_PORT_GID_BASE
        nh_gid = NH_GID_BASE
        tx_vlan = 0

        for dip in dips:
            # AC port
            tx_ac_port = self.device.create_l3_ac_port(
                ac_gid,
                self.tx_eth_port.hld_obj,
                tx_vlan,
                0,
                TX_MAC.hld_obj,
                self.vrf,
                self.topology.ingress_qos_profile_def.hld_obj,
                self.topology.egress_qos_profile_def.hld_obj)

            tx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
            tx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
            egress_vlan_tag.tci.fields.vid = tx_vlan
            tx_ac_port.set_egress_vlan_tag(egress_vlan_tag, sdk.LA_VLAN_TAG_UNTAGGED)
            # NH
            nh = self.device.create_next_hop(nh_gid, RX_MAC.hld_obj, tx_ac_port, sdk.la_next_hop.nh_type_e_NORMAL)

            # FEC
            fec = self.device.create_l3_fec(nh)

            prefix, prefix_length = dip
            mask = ((1 << (prefix_length)) - 1) << prefix.max_prefixlen - prefix_length
            address = int.from_bytes(prefix.packed, "big") & mask
            if (prefix.version == 6):
                route = sdk.la_ipv6_prefix_t()
                route.length = prefix_length
                dip_lsb = bit_utils.get_bits(address, 63, 0)
                dip_msb = bit_utils.get_bits(address, 127, 64)
                sdk.set_ipv6_addr(route.addr, dip_lsb, dip_msb)

                prefix_action = sdk.la_ipv6_route_entry_parameters()
                prefix_action.action = sdk.la_route_entry_action_e_ADD
                prefix_action.destination = fec
                prefix_action.user_data = PRIVATE_DATA
                prefix_action.prefix = route
                prefix_action.latency_sensitive = False
                v6_prefixes_action_vec.append(prefix_action)
            else:
                route = sdk.la_ipv4_prefix_t()
                route.length = prefix_length
                route.addr.s_addr = address

                prefix_action = sdk.la_ipv4_route_entry_parameters()
                prefix_action.action = sdk.la_route_entry_action_e_ADD
                prefix_action.destination = fec
                prefix_action.user_data = PRIVATE_DATA
                prefix_action.prefix = route
                prefix_action.latency_sensitive = False
                v4_prefixes_action_vec.append(prefix_action)

            expected_packet_to_port.append([prefix, tx_vlan])

            ac_gid += 1
            tx_vlan += 1
            nh_gid += 1

        if len(v4_prefixes_action_vec):
            self.vrf.ipv4_route_bulk_updates(v4_prefixes_action_vec)
        if len(v6_prefixes_action_vec):
            self.vrf.ipv6_route_bulk_updates(v6_prefixes_action_vec)
        return expected_packet_to_port

    def _packets_lookup(self, dips):
        expected_packet_to_port = self.create_routing_topology(dips)
        for packet in expected_packet_to_port:
            self.run_packet(packet)

    def run_packet(self, packet):
        dip, tx_vlan = packet
        in_packet_base = Ether(dst=RX_MAC.addr_str, src=IN_SRC_MAC, type=Ethertype.Dot1Q.value) / Dot1Q(vlan=RX_VLAN)
        out_packet_base = Ether(dst=RX_MAC.addr_str, src=TX_MAC.addr_str, type=Ethertype.Dot1Q.value) / Dot1Q(vlan=tx_vlan)

        if (dip.version == 6):
            in_packet = in_packet_base / IPv6(src=IPV6_SIP.addr_str, dst=dip.exploded, hlim=HLIM)
            out_packet = out_packet_base / IPv6(src=IPV6_SIP.addr_str, dst=dip.exploded, hlim=HLIM - 1)
        else:
            in_packet = in_packet_base / IP(src=IPV4_SIP.addr_str, dst=dip.exploded, ttl=TTL)
            out_packet = out_packet_base / IP(src=IPV4_SIP.addr_str, dst=dip.exploded, ttl=TTL - 1)

        in_packet, out_packet = pad_input_and_output_packets(in_packet, out_packet)

        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)
