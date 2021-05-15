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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T


def device_config_func(device, state):
    if state == sdk.la_device.init_phase_e_CREATED:
        device.set_bool_property(sdk.la_device_property_e_ENABLE_HBM, True)
        device.set_bool_property(sdk.la_device_property_e_ENABLE_HBM_ROUTE_EXTENSION, True)
        device.set_bool_property(sdk.la_device_property_e_ENABLE_HBM_ROUTE_EXTENSION_CACHING_MODE, True)
        device.set_int_property(sdk.la_device_property_e_LPM_L2_MAX_SRAM_BUCKETS, 10)


def ipv4_str_to_int(s):
    return int(''.join(['%02x' % int(i) for i in s.split('.')]), 16)


def ipv4_int_to_str(n):
    s = '%x' % n
    return '.'.join(['%d' % int(s[n:n + 2], 16) for n in range(0, 8, 2)])


IN_SLICE = 3
IN_IFG = 0
IN_SERDES_FIRST = 4
IN_SERDES_LAST = IN_SERDES_FIRST + 1
OUT_SLICE = 5
OUT_IFG = 1
OUT_SERDES_FIRST = 8
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

SYS_PORT_GID_BASE = 0x100
AC_PORT_GID_BASE = 0x200
NH_GID_BASE = 0x300
VRF_GID = 0x400 if not decor.is_gibraltar() else 0xF00

RX_MAC = T.mac_addr('11:12:13:14:15:16')
TX_MAC = T.mac_addr('04:f4:bc:57:d5:00')
NH_MAC = T.mac_addr('04:f4:bc:57:d5:01')
SIP_STR = '123.1.2.3'
DIP_START_STR = '200.0.0.0'
TTL = 255

RX_VLAN = 0x100
TX_VLAN_BASE = 0x150

NUM_ROUTES = 10000
NUM_PACKETS = 10000
RANDOMIZE_PACKET_ORDER = True

unittest = unittest.TestCase()

#sdk.la_set_logging_level(288, sdk.la_logger_component_e_TABLES, sdk.la_logger_level_e_DEBUG)
#sdk.la_set_logging_level(1, sdk.la_logger_component_e_TABLES, sdk.la_logger_level_e_DEBUG)

device = sim_utils.create_device(1, device_config_func=device_config_func)

topology = T.topology(unittest, device)

ac_profile = T.ac_profile(unittest, device)

rx_eth_port = T.ethernet_port(unittest, device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
tx_eth_port = T.ethernet_port(
    unittest,
    device,
    OUT_SLICE,
    OUT_IFG,
    SYS_PORT_GID_BASE + 1,
    OUT_SERDES_FIRST,
    OUT_SERDES_LAST)

rx_eth_port.set_ac_profile(ac_profile)
tx_eth_port.set_ac_profile(ac_profile)

vrf = device.create_vrf(VRF_GID)

ac_gid = AC_PORT_GID_BASE
tx_vlan = TX_VLAN_BASE + 5
egress_vlan_tag = sdk.la_vlan_tag_t()
egress_vlan_tag.tpid = 0x8100

ipv4_prefix = sdk.la_ipv4_prefix_t()
ipv4_prefix.length = 32
tx_ac_ports = []
dips = []
nh_gid = NH_GID_BASE

rx_ac_port = device.create_l3_ac_port(
    ac_gid,
    rx_eth_port.hld_obj,
    RX_VLAN,
    0,
    RX_MAC.hld_obj,
    vrf,
    topology.ingress_qos_profile_def.hld_obj,
    topology.egress_qos_profile_def.hld_obj)

rx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
ac_gid += 1

tx_ac_port = device.create_l3_ac_port(
    ac_gid,
    tx_eth_port.hld_obj,
    TX_VLAN_BASE,
    0,
    TX_MAC.hld_obj,
    vrf,
    topology.ingress_qos_profile_def.hld_obj,
    topology.egress_qos_profile_def.hld_obj)

tx_ac_port.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
egress_vlan_tag.tci.fields.vid = tx_vlan
tx_ac_port.set_egress_vlan_tag(egress_vlan_tag, sdk.LA_VLAN_TAG_UNTAGGED)
tx_ac_ports.append(tx_ac_port)

# NH
nh = device.create_next_hop(nh_gid, NH_MAC.hld_obj, tx_ac_port, sdk.la_next_hop.nh_type_e_NORMAL)
dest = nh

dip_base = ipv4_str_to_int(DIP_START_STR)

for i in range(0, NUM_ROUTES):
    print('adding route #%d' % i)
    dip = dip_base + i

    ipv4_prefix.addr.s_addr = dip
    vrf.add_ipv4_route(ipv4_prefix, dest, 0, True)
    print('done adding route #%d' % i)

#sdk.la_set_logging_level(288, sdk.la_logger_component_e_TABLES, sdk.la_logger_level_e_DEBUG)
#sdk.la_set_logging_level(1, sdk.la_logger_component_e_TABLES, sdk.la_logger_level_e_DEBUG)

for i in range(0, NUM_PACKETS):
    if RANDOMIZE_PACKET_ORDER:
        choose_from_first_10 = random.randint(0, 100) <= 80
        iroute_first = 0 if choose_from_first_10 else 10
        iroute_last = 9 if choose_from_first_10 else NUM_ROUTES - 1
        iroute = random.randint(iroute_first, iroute_last)
    else:
        iroute = i % NUM_ROUTES
    print('injecting packet #%d (to route #%d)' % (i, iroute))
    dip = dip_base + iroute
    dip_str = ipv4_int_to_str(dip)

    in_packet_base = \
        Ether(dst=RX_MAC.addr_str, src='04:72:73:74:75:76', type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=RX_VLAN, type=Ethertype.IPv4.value) / \
        IP(src=SIP_STR, dst=dip_str, ttl=TTL)

    out_packet_base = \
        Ether(dst=NH_MAC.addr_str, src=TX_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=tx_vlan, type=Ethertype.IPv4.value) / \
        IP(src=SIP_STR, dst=dip_str, ttl=TTL - 1)

    in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

    run_and_compare(
        unittest,
        device,
        in_packet,
        IN_SLICE,
        IN_IFG,
        IN_SERDES_FIRST,
        out_packet,
        OUT_SLICE,
        OUT_IFG,
        OUT_SERDES_FIRST)
    print('done injecting packet #%d' % i)
