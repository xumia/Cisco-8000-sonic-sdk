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
from packet_test_utils import *
import sim_utils
import topology as T
from scapy.all import *
import nplapicli as nplapi
import ip_test_base
import smart_slices_choise as ssch

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
SA = T.mac_addr('be:ef:5d:35:7a:35')

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xA13

SYS_PORT_GID_BASE = 23
IN_SP_GID = SYS_PORT_GID_BASE
OUT_SP_GID = SYS_PORT_GID_BASE + 1
INJECT_SP_GID = SYS_PORT_GID_BASE + 2
INJECT_SP_GID1 = SYS_PORT_GID_BASE + 3

MIRROR_CMD_INGRESS_GID = 0x31

INJECT_SLICE = T.get_device_slice(3)
INJECT_IFG = T.get_device_ifg(1)
INJECT_PIF_FIRST = T.get_device_first_serdes(8)

SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
DIP_UC = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
DIP_MC = T.ipv6_addr('ff02:0000:0000:0000:0000:0000:0000:0005')
DIP_LL_UC = T.ipv6_addr('fe80:0000:0000:0000:0000:0000:0000:1234')
DIP_LL_MC = T.ipv6_addr('ff02:0000:0000:0000:0000:0000:0000:1234')
SIP_LL_UC = T.ipv6_addr('fe80:0000:0000:0000:0000:0000:0000:1235')
SIP_UNSPEC_UC = T.ipv6_addr('0000:0000:0000:0000:0000:0000:0000:0000')
LL_UC_ADDR = T.ipv6_addr('fe80:0000:0000:0000:0000:0000:0000:0000')
LL_MC_ADDR = T.ipv6_addr('ff02:0000:0000:0000:0000:0000:0000:0000')
DIP_UC_BINCODE = 0xBEEF
LL_UC_ADDR_BINCODE = 0XFEED
SIP_UC_BINCODE = 0xBEED

TTL = 127

INPUT_PACKET_UC_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IPv6(src=SIP.addr_str, dst=DIP_UC.addr_str, hlim=TTL, plen=40) / \
    TCP(sport=0x1234, dport=0x2345)

INPUT_PACKET_UC_HOP_BY_HOP_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IPv6(src=SIP.addr_str, dst=DIP_UC.addr_str, hlim=TTL, plen=40) / \
    IPv6ExtHdrHopByHop()

INPUT_PACKET_ND_UC_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IPv6(src=SIP.addr_str, dst=DIP_LL_UC.addr_str, hlim=TTL) / \
    ICMPv6ND_NS() / \
    ICMPv6NDOptSrcLLAddr(lladdr='01:23:45:67:89:ab')

INPUT_PACKET_ND_MC_BASE = \
    Ether(dst='33:33:00:00:12:34', src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IPv6(src=SIP.addr_str, dst=DIP_LL_MC.addr_str, hlim=TTL) / \
    ICMPv6ND_NS() / \
    ICMPv6NDOptSrcLLAddr(lladdr='01:23:45:67:89:ab')

INPUT_PACKET_ND_UC_SVI_BASE = \
    Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
    IPv6(src=SIP.addr_str, dst=DIP_LL_UC.addr_str, hlim=TTL) / \
    ICMPv6ND_NA() / \
    ICMPv6NDOptSrcLLAddr(lladdr='01:23:45:67:89:ab')

INPUT_PACKET_ND_MC_SVI_BASE = \
    Ether(dst='33:33:00:00:12:34', src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
    IPv6(src=SIP.addr_str, dst=DIP_LL_MC.addr_str, hlim=TTL) / \
    ICMPv6ND_NS() / \
    ICMPv6NDOptSrcLLAddr(lladdr='01:23:45:67:89:ab')

INPUT_PACKET_MC_BASE = \
    Ether(dst=T.RX_L3_AC_IPv6_MC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IPv6(src=SIP.addr_str, dst=DIP_MC.addr_str, hlim=1, nh=89, plen=40)

INPUT_PACKET_ND_LL_UC_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IPv6(src=SIP_LL_UC.addr_str, dst=DIP_LL_UC.addr_str, hlim=TTL) / \
    ICMPv6ND_NS() / \
    ICMPv6NDOptSrcLLAddr(lladdr='01:23:45:67:89:ab')

INPUT_PACKET_UNSPEC_UC_BASE = \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IPv6(src=SIP_UNSPEC_UC.addr_str, dst=DIP_LL_UC.addr_str, hlim=TTL) / \
    ICMPv6ND_NS() / \
    ICMPv6NDOptSrcLLAddr(lladdr='01:23:45:67:89:ab')

PUNT_PACKET_UC_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=120,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         #source_lp=T.RX_L3_AC_GID, destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID, lpts_flow_type=11) / \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IPv6(src=SIP.addr_str, dst=DIP_UC.addr_str, hlim=TTL, plen=40) / \
    TCP(sport=0x1234, dport=0x2345)

PUNT_PACKET_UC_HOP_BY_HOP_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=120,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID, lpts_flow_type=11) / \
    Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IPv6(src=SIP.addr_str, dst=DIP_UC.addr_str, hlim=TTL, plen=40) / \
    IPv6ExtHdrHopByHop()

PUNT_PACKET_ND_UC_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=120,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID, lpts_flow_type=11) / \
    INPUT_PACKET_ND_UC_BASE

PUNT_PACKET_ND_MC_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=120,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID, lpts_flow_type=11) / \
    INPUT_PACKET_ND_MC_BASE

PUNT_PACKET_ND_UC_SVI_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
         next_header_offset=len(Ether()) + 1 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=120,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_SVI_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID, lpts_flow_type=11) / \
    INPUT_PACKET_ND_UC_SVI_BASE

PUNT_PACKET_ND_MC_SVI_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
         next_header_offset=len(Ether()) + 1 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=120,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.RX_SWITCH_GID, lpts_flow_type=11) / \
    INPUT_PACKET_ND_MC_SVI_BASE

PUNT_PACKET_ND_MC_SVI_SNOOP_BASE = Ether(dst=HOST_MAC_ADDR,
                                         src=PUNT_INJECT_PORT_MAC_ADDR,
                                         type=Ethertype.Dot1Q.value) / Dot1Q(prio=0,
                                                                             id=0,
                                                                             vlan=PUNT_VLAN,
                                                                             type=Ethertype.Punt.value) / Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                                                                                                               fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6_COLLAPSED_MC,
                                                                                                               next_header_offset=len(Ether()) + 1 * len(Dot1Q()),
                                                                                                               source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
                                                                                                               code=120,
                                                                                                               source_sp=T.RX_SYS_PORT_GID,
                                                                                                               destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                                                                                               source_lp=T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
                                                                                                               destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_MC_LPTS,
                                                                                                               relay_id=T.RX_SWITCH_GID,
                                                                                                               lpts_flow_type=11) / INPUT_PACKET_ND_MC_SVI_BASE

PUNT_PACKET_MC_BASE = Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
         fwd_header_type=0,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=120,
         source_sp=T.RX_SYS_PORT_GID,
         destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID,
         # destination_lp=sdk.la_packet_types.LA_L3_LOGICAL_PORT_GID_INVALID,
         destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID,
         lpts_flow_type=11) / \
    Ether(dst=T.RX_L3_AC_IPv6_MC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
    IPv6(src=SIP.addr_str, dst=DIP_MC.addr_str, hlim=1, nh=89, plen=40)

PUNT_PACKET_ND_LL_UC_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=120,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID, lpts_flow_type=11) / \
    INPUT_PACKET_ND_LL_UC_BASE

PUNT_PACKET_UNSPEC_UC_BASE = \
    Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
         next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
         code=120,
         source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
         relay_id=T.VRF_GID, lpts_flow_type=11) / \
    INPUT_PACKET_UNSPEC_UC_BASE

INPUT_PACKET_UC, PUNT_PACKET_UC = pad_input_and_output_packets(INPUT_PACKET_UC_BASE, PUNT_PACKET_UC_BASE)
INPUT_PACKET_UC_HOP_BY_HOP, PUNT_PACKET_UC_HOP_BY_HOP = pad_input_and_output_packets(
    INPUT_PACKET_UC_HOP_BY_HOP_BASE, PUNT_PACKET_UC_HOP_BY_HOP_BASE)
INPUT_PACKET_ND_UC, PUNT_PACKET_ND_UC = pad_input_and_output_packets(INPUT_PACKET_ND_UC_BASE, PUNT_PACKET_ND_UC_BASE)
INPUT_PACKET_ND_MC, PUNT_PACKET_ND_MC = pad_input_and_output_packets(INPUT_PACKET_ND_MC_BASE, PUNT_PACKET_ND_MC_BASE)
INPUT_PACKET_ND_UC_SVI, PUNT_PACKET_ND_UC_SVI = pad_input_and_output_packets(
    INPUT_PACKET_ND_UC_SVI_BASE, PUNT_PACKET_ND_UC_SVI_BASE)
INPUT_PACKET_ND_MC_SVI, PUNT_PACKET_ND_MC_SVI = pad_input_and_output_packets(
    INPUT_PACKET_ND_MC_SVI_BASE, PUNT_PACKET_ND_MC_SVI_BASE)
INPUT_PACKET_ND_MC_SVI, PUNT_PACKET_ND_MC_SVI_SNOOP = pad_input_and_output_packets(
    INPUT_PACKET_ND_MC_SVI_BASE, PUNT_PACKET_ND_MC_SVI_SNOOP_BASE)
INPUT_PACKET_MC, PUNT_PACKET_MC = pad_input_and_output_packets(INPUT_PACKET_MC_BASE, PUNT_PACKET_MC_BASE)
INPUT_PACKET_ND_LL_UC, PUNT_PACKET_ND_LL_UC = pad_input_and_output_packets(INPUT_PACKET_ND_LL_UC_BASE, PUNT_PACKET_ND_LL_UC_BASE)
INPUT_PACKET_UNSPEC_UC, PUNT_PACKET_UNSPEC_UC = pad_input_and_output_packets(
    INPUT_PACKET_UNSPEC_UC_BASE, PUNT_PACKET_UNSPEC_UC_BASE)


class ipv6_lpts_base(unittest.TestCase):

    INJECT_SLICE = T.get_device_slice(3)
    INJECT_IFG = T.get_device_ifg(1)
    INJECT_PIF_FIRST = T.get_device_first_serdes(8)
    INJECT_SP_GID = SYS_PORT_GID_BASE + 2

    def setUp(self):
        self.maxDiff = None

        self.device = sim_utils.create_device(1)
        ssch.rechoose_odd_inject_slice(self, self.device)

        self.ip_impl = ip_test_base.ipv6_test_base()
        self.topology = T.topology(self, self.device)
        self.add_default_route()

        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)

        # enable mc traffic on l3 ac
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        self.device.set_trap_configuration(
            sdk.LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE,
            1,
            None,
            self.punt_dest,
            False,
            False,
            True, 0)

    def tearDown(self):
        self.device.tearDown()

    def add_default_route(self):
        prefix = self.ip_impl.build_prefix(DIP_UC, length=0)
        self.topology.vrf.hld_obj.add_ipv6_route(prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def setup_l2_mc_snoop(self, skip_inject_up):
        sampling_rate = 1.0
        tag_tci = sdk.la_vlan_tag_tci_t()
        tag_tci.fields.pcp = 0
        tag_tci.fields.dei = 0
        tag_tci.fields.vid = PUNT_VLAN
        mirror_cmd = self.device.create_mc_lpts_mirror_command(
            MIRROR_CMD_INGRESS_GID,
            self.pi_port.sys_port.hld_obj)

        self.device.set_mc_lpts_snoop_configuration(0, skip_inject_up, False, mirror_cmd)

        self.rx_l2_ac2 = T.l2_ac_port(self, self.device,
                                      T.RX_L2_AC_PORT_GID + 10,
                                      None,
                                      self.topology.rx_switch,
                                      self.topology.rx_eth_port,
                                      T.RX_MAC,
                                      T.RX_L2_AC_PORT_VID1 + 10,
                                      T.RX_L2_AC_PORT_VID2)
        self.topology.rx_switch.hld_obj.set_flood_destination(self.rx_l2_ac2.hld_obj)

    def create_lpts_instance(self):
        lpts = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV6)
        self.assertNotEqual(lpts, None)

        count = lpts.get_count()
        self.assertEqual(count, 0)

        k0 = sdk.la_lpts_key()
        k0.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        r0 = sdk.get_ipv6_addr_q0(SIP.hld_obj)
        r1 = sdk.get_ipv6_addr_q1(SIP.hld_obj)
        # Should not catch
        sdk.set_ipv6_addr(k0.val.ipv6.sip, r0 + 1, r1)
        sdk.set_ipv6_addr(k0.mask.ipv6.sip, 0xffffffffffffffff, 0xffffffffffffffff)

        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k1.val.ipv6.dst_og_compression_code = DIP_UC_BINCODE
        k1.mask.ipv6.dst_og_compression_code = 0xffff
        k1.val.ipv6.protocol = 255
        k1.mask.ipv6.protocol = 0

        k2 = sdk.la_lpts_key()
        k2.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k2.val.ipv6.dst_og_compression_code = DIP_UC_BINCODE
        k2.mask.ipv6.dst_og_compression_code = 0xffff
        k2.val.ipv6.protocol = 255
        k2.mask.ipv6.protocol = 0

        k3 = sdk.la_lpts_key()
        k3.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k3.val.ipv6.protocol = 89
        k3.mask.ipv6.protocol = sdk.la_l4_protocol_e_RESERVED

        k4 = sdk.la_lpts_key()
        k4.type = sdk.lpts_type_e_LPTS_TYPE_IPV6

        k5 = sdk.la_lpts_key()
        k5.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        # Will catch
        k5.val.ipv6.dst_og_compression_code = LL_UC_ADDR_BINCODE
        k5.mask.ipv6.dst_og_compression_code = 0xffff

        result = sdk.la_lpts_result()
        result.flow_type = 11
        result.punt_code = 120
        result.tc = 0
        result.dest = self.punt_dest
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)

        lpts.append(k0, result)
        count = lpts.get_count()
        self.assertEqual(count, 1)

        lpts.append(k1, result)
        count = lpts.get_count()
        self.assertEqual(count, 2)

        lpts.append(k2, result)
        count = lpts.get_count()
        self.assertEqual(count, 3)

        lpts.append(k3, result)
        count = lpts.get_count()
        self.assertEqual(count, 4)

        lpts.append(k4, result)
        count = lpts.get_count()
        self.assertEqual(count, 5)

        lpts.append(k5, result)
        count = lpts.get_count()
        self.assertEqual(count, 6)

        return lpts

    def setup_forus_dest(self):
        self.prefix_uc = self.ip_impl.build_prefix(DIP_UC, length=24)
        forus_dest = self.device.create_forus_destination(DIP_UC_BINCODE)
        self.topology.vrf.hld_obj.add_ipv6_route(self.prefix_uc, forus_dest, PRIVATE_DATA_DEFAULT, True)

        self.prefix_ll_uc = self.ip_impl.build_prefix(LL_UC_ADDR, length=10)
        forus_dest = self.device.create_forus_destination(LL_UC_ADDR_BINCODE)
        self.topology.vrf.hld_obj.add_ipv6_route(self.prefix_ll_uc, forus_dest, PRIVATE_DATA_DEFAULT, True)

    def setup_forus_src(self):
        self.prefix_uc = self.ip_impl.build_prefix(SIP, length=24)
        forus_dest = self.device.create_forus_destination(SIP_UC_BINCODE)
        self.topology.vrf.hld_obj.add_ipv6_route(self.prefix_uc, forus_dest, PRIVATE_DATA_DEFAULT, True)

    def push_lpts_entry(self, lpts, position, key, result):

        count_pre = lpts.get_count()
        lpts.push(position, key, result)

        count_post = lpts.get_count()
        self.assertEqual(count_post, count_pre + 1)

    def trim_lpts_invalid(self, lpts):
        ''' Invalid removal from an LPTS - expect failure.'''

        count = lpts.get_count()

        try:
            lpts.pop(count)
            self.assertFail()
        except sdk.BaseException:
            pass

        count_tag = lpts.get_count()
        self.assertEqual(count, count_tag)

    def trim_lpts(self, lpts):
        ''' Remove the last entry of the LPTS. '''

        count = lpts.get_count()
        lpts.pop(count - 1)
        count_tag = lpts.get_count()
        self.assertEqual(count_tag, count - 1)

    def update_lpts_entry(self, lpts, position):
        ''' Update the lpts entry. '''

        count = lpts.get_count()

        k2 = sdk.la_lpts_key()
        k2.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k2.val.ipv6.dst_og_compression_code = DIP_UC_BINCODE
        k2.mask.ipv6.dst_og_compression_code = 0xffff
        k2.val.ipv6.protocol = 255
        k2.mask.ipv6.protocol = 0

        result = sdk.la_lpts_result()
        result.flow_type = 10
        result.punt_code = 11
        result.tc = 0
        result.dest = self.punt_dest
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)

        lpts.set(position, k2, result)

        lpts_entry_desc = lpts.get(position)
        self.assertEqual(lpts_entry_desc.result.flow_type, result.flow_type)
        self.assertEqual(lpts_entry_desc.result.punt_code, result.punt_code)
        self.assertEqual(lpts_entry_desc.result.tc, result.tc)

        # No change in count
        count_tag = lpts.get_count()
        self.assertEqual(count_tag, count)

    def verify_packet_fields(self, lpts, key, pin, pout):

        count_pre = lpts.get_count()

        result = sdk.la_lpts_result()
        result.flow_type = 11
        result.punt_code = 120
        result.tc = 0
        result.dest = self.punt_dest
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)

        self.push_lpts_entry(lpts, 0, key, result)

        run_and_compare(self, self.device,
                        pin, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        pout, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        count_post = lpts.get_count()
        self.assertEqual(count_post, count_pre + 1)

        lpts.pop(0)

        count_post = lpts.get_count()
        self.assertEqual(count_post, count_pre)
