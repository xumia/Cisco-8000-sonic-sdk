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

import sdk_test_case_base
from leaba import sdk
from packet_test_utils import *
import sim_utils
import topology as T
import ip_test_base

CHAR_BIT = 8
BYTES_NUM_IN_ADDR = 16

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
TTL = 127
SPORT = 0x1234
DPORT = 0x2345
EXTRA_VRF_GID = 0x3ff
ECN = 0x3
DSCP = 0x5
MAX_COUNTER_OFFSET = 8

SA = T.mac_addr('be:ef:5d:35:7a:35')
# IPv4
SIP_V4 = T.ipv4_addr('192.193.194.195')
DIP_V4 = T.ipv4_addr('208.209.210.211')
IP_V4_MASK = T.ipv4_addr('255.255.255.255')
IP_V4_SUBNET_MASK = T.ipv4_addr('255.255.255.0')

# IPv6
SIP_V6 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
DIP_V6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
IP_V6_MASK = T.ipv6_addr('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
IP_V6_SUBNET_MASK = T.ipv6_addr('ffff:ffff:ffff:ffff:0000:0000:0000:0000')

NUM_OF_SHORTS = 8
BITS_IN_SHORT = 16
BITS_IN_QWORD = 64
NUM_OF_BYTES = 16


def apply_v6_prefix_mask(q0, q1, prefix_length):
    dqw_addr = q1 << 64 | q0
    mask = ~((1 << (CHAR_BIT * BYTES_NUM_IN_ADDR - prefix_length)) - 1)
    dqw_addr = dqw_addr & mask
    masked_q0 = dqw_addr & ((1 << 64) - 1)
    masked_q1 = dqw_addr >> 64
    return masked_q0, masked_q1


def build_v6_prefix(dip, length):
    prefix = sdk.la_ipv6_prefix_t()
    q0 = sdk.get_ipv6_addr_q0(dip.hld_obj)
    q1 = sdk.get_ipv6_addr_q1(dip.hld_obj)
    masked_q0, masked_q1 = apply_v6_prefix_mask(q0, q1, length)
    sdk.set_ipv6_addr(prefix.addr, masked_q0, masked_q1)
    prefix.length = length
    return prefix


class ip_inactivity_l3_base(sdk_test_case_base.sdk_test_case_base):
    # default slice mode settings. Can be changed inside each test
    slice_modes = sim_utils.STANDALONE_DEV

    PUNT_SLICE = T.get_device_slice(2)
    PUNT_IFG = 0
    PUNT_SYS_PORT_GID = T.MIN_SYSTEM_PORT_GID
    PUNT_SERDES = T.get_device_first_serdes(8)
    PI_PORT_MAC = T.mac_addr('ab:ab:ab:ab:ab:ab')
    HOST_MAC_ADDR = T.mac_addr('cd:cd:cd:cd:cd:cd')
    MIRROR_CMD_GID = 10
    MIRROR_GID_INGRESS_OFFSET = 32
    MIRROR_GID_EGRESS_OFFSET = 0
    MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
    MIRROR_VLAN = 19

    def setUp(self):
        super().setUp()

        self.l3_port_impl = T.ip_l3_ac_base(self.topology)
        self.rx_port = self.l3_port_impl.rx_port
        sampling_rate = 1.0

        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PUNT_SLICE,
            self.PUNT_IFG,
            self.PUNT_SYS_PORT_GID,
            self.PUNT_SERDES,
            self.PI_PORT_MAC.addr_str)
        self.mirror_cmd = T.create_l2_mirror_command(
            self.device,
            self.MIRROR_CMD_INGRESS_GID,
            self.pi_port,
            self.HOST_MAC_ADDR.addr_str,
            self.MIRROR_VLAN,
            sampling_rate)

        self.device.clear_trap_configuration(sdk.LA_EVENT_APP_IP_INACTIVITY)
        self.device.set_snoop_configuration(sdk.LA_EVENT_APP_IP_INACTIVITY, 0, False, False, self.mirror_cmd)

    def initialize_test_data(self):
        if self.is_ipv4:
            self.ip_impl = ip_test_base.ipv4_test_base
            self.scapy_IP = scapy.layers.inet.IP
            self.ipvx = 'v4'
            self.SIP = SIP_V4
            self.DIP = DIP_V4
            self.prefix = sdk.la_ipv4_prefix_t()
            self.prefix.addr.s_addr = self.SIP.to_num()
            self.prefix.length = 17
            self.ip_version = sdk.la_ip_version_e_IPV4
            self.prefix_1 = sdk.la_ipv4_prefix_t()
            self.prefix_1.addr.s_addr = self.DIP.to_num()
            self.prefix_1.length = 17
        else:
            self.ip_impl = ip_test_base.ipv6_test_base
            self.scapy_IP = scapy.layers.inet6.IPv6
            self.ipvx = 'v6'
            self.SIP = SIP_V6
            self.DIP = DIP_V6
            self.prefix = build_v6_prefix(self.SIP, 17)
            self.ip_version = sdk.la_ip_version_e_IPV6
            self.prefix_1 = build_v6_prefix(self.DIP, 17)

        self.in_packet, self.out_packet, self.punt_snoop_header = self.create_packets()
        self.per_field_counters = {}

    def test_ip_inactivity(self):
        self.is_ipv4 = True
        self.run_test()
        self.is_ipv4 = False
        self.run_test()

    def tearDown(self):
        super().tearDown()

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_nh, PRIVATE_DATA_DEFAULT)

    def create_packets(self):
        rx_port_mac_str = T.mac_addr.mac_num_to_str(self.l3_port_impl.rx_port.hld_obj.get_mac().flat)
        tx_port_mac_str = T.mac_addr.mac_num_to_str(self.l3_port_impl.tx_port.hld_obj.get_mac().flat)
        nh_mac_str = self.l3_port_impl.reg_nh.mac_addr.addr_str
        vid1 = T.RX_L3_AC_PORT_VID1
        vid2 = T.RX_L3_AC_PORT_VID2

        if self.is_ipv4:
            INPUT_PACKET_BASE = \
                Ether(dst=rx_port_mac_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
                Dot1Q(vlan=vid1, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=vid2) / \
                IPvX(ipvx=self.ipvx,
                     src=self.SIP.addr_str,
                     dst=self.DIP.addr_str,
                     ttl=TTL,
                     dscp=DSCP, ecn=ECN,
                     flags=0x1, frag=0) / \
                TCP(sport=SPORT, dport=DPORT, flags="SA")

            EXPECTED_OUTPUT_PACKET_BASE = \
                Ether(dst=nh_mac_str, src=tx_port_mac_str) / \
                IPvX(ipvx=self.ipvx,
                     src=self.SIP.addr_str,
                     dst=self.DIP.addr_str,
                     ttl=TTL - 1,
                     dscp=DSCP, ecn=ECN,
                     flags=0x1, frag=0) / \
                TCP(sport=SPORT, dport=DPORT, flags="SA")
            NEXT_HEADER = sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4
            FWD_HEADER_TYPE = sdk.la_packet_types.LA_HEADER_TYPE_IPV4
        else:
            INPUT_PACKET_BASE = \
                Ether(dst=rx_port_mac_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
                Dot1Q(vlan=vid1, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=vid2) / \
                IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=TTL, dscp=DSCP, ecn=ECN) / \
                IPv6ExtHdrFragment(offset=100) / \
                TCP(sport=SPORT, dport=DPORT, flags="SA")

            EXPECTED_OUTPUT_PACKET_BASE = \
                Ether(dst=nh_mac_str, src=tx_port_mac_str) / \
                IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=TTL - 1, dscp=DSCP, ecn=ECN) / \
                IPv6ExtHdrFragment(offset=100) / \
                TCP(sport=SPORT, dport=DPORT, flags="SA")
            NEXT_HEADER = sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV6
            FWD_HEADER_TYPE = sdk.la_packet_types.LA_HEADER_TYPE_IPV6

        EXPECTED_PUNT_SNOOP_HEADER = Ether(dst=self.HOST_MAC_ADDR.addr_str,
                                           src=self.PI_PORT_MAC.addr_str,
                                           type=Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                               id=0,
                                                                               vlan=self.MIRROR_VLAN,
                                                                               type=Ethertype.Punt.value) / Punt(next_header=NEXT_HEADER,
                                                                                                                 fwd_header_type=FWD_HEADER_TYPE,
                                                                                                                 next_header_offset=0,
                                                                                                                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                                                                                                                 code=self.MIRROR_CMD_INGRESS_GID,
                                                                                                                 source_sp=T.get_device_punt_inject_last_serdes(33),
                                                                                                                 destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                                 source_lp=T.RX_L3_AC_GID,
                                                                                                                 destination_lp=T.TX_L3_AC_REG_GID,
                                                                                                                 relay_id=self.topology.vrf.hld_obj.get_gid())

        INPUT_PACKET, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        INPUT_PACKET = add_payload(INPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)
        EXPECTED_OUTPUT_PACKET = add_payload(EXPECTED_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)

        return INPUT_PACKET, EXPECTED_OUTPUT_PACKET, EXPECTED_PUNT_SNOOP_HEADER

    def run_test(self):
        self.initialize_test_data()
        self.add_default_route()
        self.create_packets()
        self.check_ip_snooping()

    def check_ip_snooping(self):
        # set sda mode
        sda_mode = True
        self.device.set_sda_mode(sda_mode)
        read_sda_mode = self.device.get_sda_mode()
        self.assertEqual(sda_mode, read_sda_mode)

        # add ip snooping entry
        self.device.add_source_ip_snooping_prefix(self.topology.vrf.hld_obj, self.prefix)
        ip_snooping_entries = self.device.get_source_ip_snooping_prefixes()
        self.assertEqual(1, len(ip_snooping_entries))

        # adding same entry one more time
        self.device.add_source_ip_snooping_prefix(self.topology.vrf.hld_obj, self.prefix)

        # Table size is 1, so adding one more entry should raise exception
        with self.assertRaises(sdk.NotFoundException):
            self.device.add_source_ip_snooping_prefix(self.topology.vrf.hld_obj, self.prefix_1)

        # send packet
        snoop_enabled = True
        self.send_packets(snoop_enabled)

        # remove ip snooping entry
        self.device.remove_source_ip_snooping_prefix(self.topology.vrf.hld_obj, self.prefix)

        # send packet
        snoop_enabled = False
        self.send_packets(snoop_enabled)

    def create_match_packet(self):
        self.out_packet = self.out_packet.copy()
        self.punt_header = self.punt_snoop_header.copy()
        p = self.in_packet.copy()

        self.out_packet[self.scapy_IP] = p[self.scapy_IP].copy()
        if self.is_ipv4:
            self.out_packet[self.scapy_IP].ttl = self.out_packet[self.scapy_IP].ttl - 1
        else:
            self.out_packet[self.scapy_IP].hlim = self.out_packet[self.scapy_IP].hlim - 1

        self.punt_packet = self.punt_header / self.in_packet

        self.in_packet_data = {'data': self.in_packet, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        self.out_packet_data = {
            'data': self.out_packet,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': self.l3_port_impl.serdes_reg}
        self.punt_packet_data = {'data': self.punt_packet,
                                 'slice': self.PUNT_SLICE, 'ifg': self.PUNT_IFG, 'pif': self.PUNT_SERDES}

    def send_packets(self, snoop_enabled=True):
        self.create_match_packet()
        if snoop_enabled:
            run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.punt_packet_data])
        else:
            run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data])
