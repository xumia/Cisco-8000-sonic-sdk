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

import nplapicli
import ip_test_base
import packet_test_utils as U
import uut_provider as UUT_P
import scapy.all as S
import topology as T
from erspan_base import *


class ipv6_l3_ac_erspan_base(erspan_base):

    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv6_test_base

    def create_packets(self):
        self.in_packet, pad_len = \
            U.enlarge_packet_to_min_length(S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) /
                                           S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) /
                                           S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) /
                                           S.IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, plen=40, hlim=TTL))

        self.out_packet = \
            U.add_payload(S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) /
                          S.IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, plen=40, hlim=TTL - 1), pad_len)

        punt_egr_packets = self.device.get_bool_property(sdk.la_device_property_e_TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST)

        self.set_rx_slice_and_inject_header(T.RX_SLICE, T.RX_IFG)

        if (punt_egr_packets is False):
            span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv6.value) / \
                S.IPv6(src=TUNNEL_SOURCE.addr_str,
                       dst=TUNNEL_DEST.addr_str,
                       hlim=TUNNEL_TTL,
                       tc=TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=78) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II,
                      seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str,
                        type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, plen=40, hlim=TTL)

            l3_span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv6.value) / \
                S.IPv6(src=TUNNEL_SOURCE.addr_str,
                       dst=TUNNEL_DEST.addr_str,
                       hlim=TUNNEL_TTL,
                       tc=TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_UDP) / \
                S.UDP(sport=UDP_SOURCE_PORT, dport=UDP_DEST_PORT, chksum=0) / \
                U.sflow_tunnel_metadata(source_sp=T.RX_SYS_PORT_GID,
                                        reserved=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                        source_lp=T.RX_L3_AC_GID,
                                        destination_sp=T.TX_L3_AC_SYS_PORT_DEF_GID) / \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str,
                        type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, plen=40, hlim=TTL)

        else:
            span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv6.value) / \
                S.IPv6(src=TUNNEL_SOURCE.addr_str,
                       dst=TUNNEL_DEST.addr_str,
                       hlim=TUNNEL_TTL,
                       tc=TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=113) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II,
                      seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                self.INJECT_UP_STD_HEADER / \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str,
                        type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, plen=40, hlim=TTL)

            l3_span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv6.value) / \
                S.IPv6(src=TUNNEL_SOURCE.addr_str,
                       dst=TUNNEL_DEST.addr_str,
                       hlim=TUNNEL_TTL,
                       tc=TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_UDP) / \
                S.UDP(sport=UDP_SOURCE_PORT, dport=UDP_DEST_PORT, chksum=0) / \
                U.sflow_tunnel_metadata(source_sp=T.RX_SYS_PORT_GID,
                                        reserved=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                        source_lp=T.RX_L3_AC_GID,
                                        destination_sp=T.TX_L3_AC_SYS_PORT_DEF_GID) / \
                self.INJECT_UP_STD_HEADER / \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str,
                        type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IPv6(src=IPV6_SIP.addr_str, dst=IPV6_DIP.addr_str, plen=40, hlim=TTL)

        self.span_packet = U.add_payload(span_packet_base, pad_len)
        self.l3_span_packet = U.add_payload(l3_span_packet_base, pad_len)

        self.in_packet_data = {'data': self.in_packet, 'slice': self.RX_slice, 'ifg': self.RX_ifg, 'pif': T.FIRST_SERDES}
        self.out_packet_data = {
            'data': self.out_packet,
            'slice': T.TX_SLICE_DEF,
            'ifg': T.TX_IFG_DEF,
            'pif': self.l3_port_impl.serdes_def}
        self.span_packet_data = {
            'data': self.span_packet,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': self.l3_port_impl.serdes_reg}
        self.l3_span_packet_data = {
            'data': self.l3_span_packet,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': self.l3_port_impl.serdes_reg}
