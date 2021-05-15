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


class unmatched_mc_base(sdk_multi_test_case_base):
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    MC_GROUP_GID = 0x13
    TTL = 127
    PUNT_SLICE = T.get_device_slice(2)
    PUNT_IFG = 0
    PUNT_SERDES = T.get_device_first_serdes(8)
    PUNT_SYS_PORT_GID = T.MIN_SYSTEM_PORT_GID
    PUNT_VLAN = 19
    PI_PORT_MAC = T.mac_addr('ab:ab:ab:ab:ab:ab')
    HOST_MAC_ADDR = T.mac_addr('cd:cd:cd:cd:cd:cd')

    output_serdes = T.FIRST_SERDES_L3

    def setUp(self):
        # MATILDA_SAVE -- need review
        if (self.PUNT_SLICE not in self.device.get_used_slices()):
            self.PUNT_SLICE = T.choose_active_slices(self.device,
                                                     self.PUNT_SLICE, [4, 2])

        super().setUp()

        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        self.initialize_rx_port()

        self.mc_group = self.device.create_ip_multicast_group(self.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(self.l3_port_impl.tx_port.hld_obj, self.get_tx_l2_port(), self.get_tx_sys_port())
        self.mc_group.add(self.l3_port_impl.tx_port_def.hld_obj, self.get_tx_l2_port_def(), self.get_tx_sys_port_def())

        self.initialize_traps()

        self.create_packets()

    def initialize_traps(self):
        self.pi_port = T.punt_inject_port(self, self.device, self.PUNT_SLICE, self.PUNT_IFG, self.PUNT_SYS_PORT_GID,
                                          self.PUNT_SERDES, self.PI_PORT_MAC.addr_str)

        self.punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, self.pi_port,
                                                      self.HOST_MAC_ADDR.addr_str, self.PUNT_VLAN)

        self.miss_counter = self.device.create_counter(1)

        try:
            self.device.clear_trap_configuration(self.punt_event)
        except BaseException:
            pass
        self.device.set_trap_configuration(self.punt_event, 0, None, self.punt_dest, False, False, True, 0)
        try:
            self.device.clear_trap_configuration(self.drop_event)
        except BaseException:
            pass
        self.device.set_trap_configuration(self.drop_event, 0, self.miss_counter, None, False, False, True, 0)

    def create_packets(self):
        INPUT_PACKET_BASE = \
            Ether(dst=self.get_mc_sa_addr_str(self.MC_GROUP_ADDR),
                  src=unmatched_mc_base.SA.addr_str,
                  type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=self.rx_vlan) / \
            IPvX(ipvx=self.protocol,
                 src=self.SIP.addr_str,
                 dst=self.MC_GROUP_ADDR.addr_str,
                 ttl=unmatched_mc_base.TTL) / \
            TCP() / \
            Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_PUNT_BASE = Ether(dst=unmatched_mc_base.HOST_MAC_ADDR.addr_str,
                                                 src=unmatched_mc_base.PI_PORT_MAC.addr_str,
                                                 type=Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                                     id=0,
                                                                                     vlan=unmatched_mc_base.PUNT_VLAN,
                                                                                     type=Ethertype.Punt.value) / Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                                       fwd_header_type=self.get_fwd_header_type(),
                                                                                                                       next_header_offset=len(Ether()) + len(Dot1Q()),
                                                                                                                       source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                                                                                                                       code=self.punt_event,
                                                                                                                       source_sp=T.RX_SYS_PORT_GID,
                                                                                                                       destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                       source_lp=self.rx_port_gid,
                                                                                                                       destination_lp=self.punt_event,
                                                                                                                       relay_id=T.VRF_GID,
                                                                                                                       lpts_flow_type=0) / Ether(dst=self.get_mc_sa_addr_str(self.MC_GROUP_ADDR),
                                                                                                                                                 src=unmatched_mc_base.SA.addr_str,
                                                                                                                                                 type=Ethertype.Dot1Q.value) / Dot1Q(vlan=self.rx_vlan) / IPvX(ipvx=self.protocol,
                                                                                                                                                                                                               src=self.SIP.addr_str,
                                                                                                                                                                                                               dst=self.MC_GROUP_ADDR.addr_str,
                                                                                                                                                                                                               ttl=unmatched_mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET_PUNT = pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_PUNT_BASE)

    def do_test_invalid_params(self):

        # Fail if MC prefix is invalid
        with self.assertRaises(sdk.InvalException):
            self.set_unmatched_ip_multicast_punt_enabled(self.invalid_group_prefix, True)

        self.invalid_group_prefix.addr = self.MC_GROUP_PREFIX.addr
        self.invalid_group_prefix.length = 2

        with self.assertRaises(sdk.InvalException):
            self.set_unmatched_ip_multicast_punt_enabled(self.invalid_group_prefix, True)

        self.set_unmatched_ip_multicast_punt_enabled(self.MC_GROUP_PREFIX, True)

        self.clear_unmatched_ip_multicast_punt_enabled(self.MC_GROUP_PREFIX)

        # Fail if entry already removed
        with self.assertRaises(sdk.NotFoundException):
            self.clear_unmatched_ip_multicast_punt_enabled(self.MC_GROUP_PREFIX)

    def do_test_unmatched_mc_default(self):

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        packet_count, byte_count = self.miss_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.set_unmatched_ip_multicast_punt_enabled(self.MC_DEFAULT_GROUP_PREFIX, True)
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_PUNT, 'slice': self.PUNT_SLICE,
                                 'ifg': self.PUNT_IFG, 'pif': self.PUNT_SERDES})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.clear_unmatched_ip_multicast_punt_enabled(self.MC_DEFAULT_GROUP_PREFIX)

        with self.assertRaises(sdk.NotFoundException):
            self.clear_unmatched_ip_multicast_punt_enabled(self.MC_DEFAULT_GROUP_PREFIX)

    def do_test_unmatched_mc(self):
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets_punt = []
        expected_packets_punt.append({'data': self.EXPECTED_OUTPUT_PACKET_PUNT, 'slice': self.PUNT_SLICE,
                                      'ifg': self.PUNT_IFG, 'pif': self.PUNT_SERDES})

        self.set_unmatched_ip_multicast_punt_enabled(self.MC_MISS_GROUP_PREFIX, True)

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        packet_count, byte_count = self.miss_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.clear_unmatched_ip_multicast_punt_enabled(self.MC_MISS_GROUP_PREFIX)
        self.set_unmatched_ip_multicast_punt_enabled(self.MC_GROUP_PREFIX, True)

        run_and_compare_list(self, self.device, ingress_packet, expected_packets_punt, Ether)

        self.assertEqual(self.get_unmatched_ip_multicast_punt_enabled(self.MC_GROUP_PREFIX), True)

        self.clear_unmatched_ip_multicast_punt_enabled(self.MC_GROUP_PREFIX)

    def do_test_unmatched_mc_long_addr(self):
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_PUNT, 'slice': self.PUNT_SLICE,
                                 'ifg': self.PUNT_IFG, 'pif': self.PUNT_SERDES})

        # /32 and /128 IP routes are sent to EM - test that they are handled for unmatched MC
        self.set_unmatched_ip_multicast_punt_enabled(self.MC_LONG_ADDR_GROUP_PREFIX, True)

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.assertEqual(self.get_unmatched_ip_multicast_punt_enabled(self.MC_LONG_ADDR_GROUP_PREFIX), True)

        self.clear_unmatched_ip_multicast_punt_enabled(self.MC_LONG_ADDR_GROUP_PREFIX)


class unmatched_mc_ipv4_test:

    protocol = 'v4'

    SIP = ipv4_mc.SIP

    MC_GROUP_ADDR = T.ipv4_addr('238.1.2.3')

    MC_GROUP_PREFIX = sdk.la_ipv4_prefix_t()
    MC_GROUP_PREFIX.addr = T.ipv4_addr('238.0.0.0').hld_obj
    MC_GROUP_PREFIX.length = 8

    MC_MISS_GROUP_PREFIX = sdk.la_ipv4_prefix_t()
    MC_MISS_GROUP_PREFIX.addr = T.ipv4_addr('238.0.0.0').hld_obj
    MC_MISS_GROUP_PREFIX.length = 16

    MC_DEFAULT_GROUP_PREFIX = sdk.la_ipv4_prefix_t()
    MC_DEFAULT_GROUP_PREFIX.addr = T.ipv4_addr('224.0.0.0').hld_obj
    MC_DEFAULT_GROUP_PREFIX.length = 4

    MC_LONG_ADDR_GROUP_PREFIX = sdk.la_ipv4_prefix_t()
    MC_LONG_ADDR_GROUP_PREFIX.addr = MC_GROUP_ADDR.hld_obj
    MC_LONG_ADDR_GROUP_PREFIX.length = 32

    invalid_group_prefix = sdk.la_ipv4_prefix_t()
    invalid_group_prefix.addr = T.ipv4_addr('10.0.0.1').hld_obj
    invalid_group_prefix.length = 24

    def get_mc_sa_addr_str(self, addr):
        return ipv4_mc.get_mc_sa_addr_str(addr)

    def set_unmatched_ip_multicast_punt_enabled(self, group_prefix, punt_enabled):
        self.topology.vrf.hld_obj.set_unmatched_ipv4_multicast_punt_enabled(group_prefix, punt_enabled)

    def get_unmatched_ip_multicast_punt_enabled(self, group_prefix):
        return self.topology.vrf.hld_obj.get_unmatched_ipv4_multicast_punt_enabled(group_prefix)

    def clear_unmatched_ip_multicast_punt_enabled(self, group_prefix):
        self.topology.vrf.hld_obj.clear_unmatched_ipv4_multicast_punt_enabled(group_prefix)


class unmatched_mc_ipv6_test:

    protocol = 'v6'

    SIP = ipv6_mc.SIP

    MC_GROUP_ADDR = T.ipv6_addr('ffaa:0:0:0:0:1:ffe8:658f')

    MC_GROUP_PREFIX = sdk.la_ipv6_prefix_t()
    MC_GROUP_PREFIX.addr = T.ipv6_addr('ffaa::').hld_obj
    MC_GROUP_PREFIX.length = 16

    MC_MISS_GROUP_PREFIX = sdk.la_ipv6_prefix_t()
    MC_MISS_GROUP_PREFIX.addr = T.ipv6_addr('ff10::').hld_obj
    MC_MISS_GROUP_PREFIX.length = 16

    MC_DEFAULT_GROUP_PREFIX = sdk.la_ipv6_prefix_t()
    MC_DEFAULT_GROUP_PREFIX.addr = T.ipv6_addr('ff00::').hld_obj
    MC_DEFAULT_GROUP_PREFIX.length = 8

    MC_LONG_ADDR_GROUP_PREFIX = sdk.la_ipv6_prefix_t()
    MC_LONG_ADDR_GROUP_PREFIX.addr = MC_GROUP_ADDR.hld_obj
    MC_LONG_ADDR_GROUP_PREFIX.length = 128

    invalid_group_prefix = sdk.la_ipv6_prefix_t()
    invalid_group_prefix.addr = T.ipv6_addr('dead:beef::0').hld_obj
    invalid_group_prefix.length = 32

    def get_mc_sa_addr_str(self, addr):
        return ipv6_mc.get_mc_sa_addr_str(addr)

    def set_unmatched_ip_multicast_punt_enabled(self, group_prefix, punt_enabled):
        self.topology.vrf.hld_obj.set_unmatched_ipv6_multicast_punt_enabled(group_prefix, punt_enabled)

    def get_unmatched_ip_multicast_punt_enabled(self, group_prefix):
        return self.topology.vrf.hld_obj.get_unmatched_ipv6_multicast_punt_enabled(group_prefix)

    def clear_unmatched_ip_multicast_punt_enabled(self, group_prefix):
        self.topology.vrf.hld_obj.clear_unmatched_ipv6_multicast_punt_enabled(group_prefix)


class unmatched_mc_l3_ac_test:

    l3_port_impl_class = T.ip_l3_ac_base
    rx_vlan = T.RX_L3_AC_ONE_TAG_PORT_VID
    punt_event = sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL
    drop_event = sdk.LA_EVENT_L3_IP_MULTICAST_NOT_FOUND
    rx_port_gid = T.RX_L3_AC_ONE_TAG_GID

    def get_tx_l2_port(self):
        return None

    def get_tx_l2_port_def(self):
        return None

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj

    def initialize_rx_port(self):
        self.topology.rx_l3_ac_one_tag.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.topology.rx_l3_ac_one_tag.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

    def get_fwd_header_type(self):
        if (self.protocol is 'v4'):
            return sdk.la_packet_types.LA_HEADER_TYPE_IPV4
        else:
            return sdk.la_packet_types.LA_HEADER_TYPE_IPV6


class unmatched_mc_svi_test:

    l3_port_impl_class = T.ip_svi_base
    rx_vlan = T.RX_L2_AC_PORT_VID1
    punt_event = sdk.LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL
    drop_event = sdk.LA_EVENT_L3_IP_MC_SNOOP_LOOKUP_MISS
    rx_port_gid = T.RX_SVI_GID
    fwd_header_type_suffix = '_COLLAPSED_MC'

    def get_tx_l2_port(self):
        return self.topology.tx_l2_ac_port_reg.hld_obj

    def get_tx_l2_port_def(self):
        return self.topology.tx_l2_ac_port_def.hld_obj

    def get_tx_sys_port(self):
        return self.topology.tx_svi_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_svi_eth_port_def.sys_port.hld_obj

    def initialize_rx_port(self):
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

    def get_fwd_header_type(self):
        if (self.protocol is 'v4'):
            return sdk.la_packet_types.LA_HEADER_TYPE_IPV4_COLLAPSED_MC
        else:
            return sdk.la_packet_types.LA_HEADER_TYPE_IPV6_COLLAPSED_MC
