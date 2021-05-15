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


class ipv4_l3_ac_erspan_base(erspan_base):

    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv4_test_base

    def create_packets(self):
        self.in_packet, pad_len = \
            U.enlarge_packet_to_min_length(S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) /
                                           S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) /
                                           S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) /
                                           S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL))

        self.out_packet = \
            U.add_payload(S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) /
                          S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1), pad_len)

        self.out_tunl_packet = \
            U.add_payload(S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) /
                          S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1), pad_len - len(S.IP()))

        self.in_tunl_packet, tunl_pad_len = \
            U.enlarge_packet_to_min_length(S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) /
                                           S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) /
                                           S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) /
                                           S.IP(src=REMOTE_ANY_IP.addr_str, dst=LOCAL_IP1.addr_str, ttl=TTL) /
                                           S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL))

        punt_egr_packets = self.device.get_bool_property(sdk.la_device_property_e_TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST)

        self.set_rx_slice_and_inject_header(T.RX_SLICE, T.RX_IFG)

        if (punt_egr_packets is False):
            span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv4.value) / \
                S.IP(src=TUNNEL_SOURCE.addr_str, dst=TUNNEL_DEST.addr_str, ttl=TUNNEL_TTL, tos=TUNNEL_DSCP << 2, flags="DF", id=0,
                     proto=sdk.la_l4_protocol_e_GRE) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

            l3_span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv4.value) / \
                S.IP(src=TUNNEL_SOURCE.addr_str, dst=TUNNEL_DEST.addr_str, ttl=TUNNEL_TTL, tos=TUNNEL_DSCP << 2, flags="DF", id=0,
                     proto=sdk.la_l4_protocol_e_UDP) / \
                S.UDP(sport=UDP_SOURCE_PORT, dport=UDP_DEST_PORT, chksum=0) / \
                U.sflow_tunnel_metadata(source_sp=T.RX_SYS_PORT_GID,
                                        reserved=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                        source_lp=T.RX_L3_AC_GID,
                                        destination_sp=T.TX_L3_AC_SYS_PORT_DEF_GID) / \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str,
                        src=SA.addr_str,
                        type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

            tunl_span_packet_base = S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                                            src=T.TX_L3_AC_REG_MAC.addr_str,
                                            type=U.Ethertype.IPv4.value) / \
                S.IP(src=TUNNEL_SOURCE.addr_str,
                     dst=TUNNEL_DEST.addr_str,
                     ttl=TUNNEL_TTL,
                     tos=TUNNEL_DSCP << 2,
                     flags="DF",
                     id=0,
                     proto=sdk.la_l4_protocol_e_GRE) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II,
                      seqnum_present=1,
                      seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str,
                        src=SA.addr_str,
                        type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1,
                        type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=REMOTE_ANY_IP.addr_str,
                     dst=LOCAL_IP1.addr_str,
                     ttl=TTL) / \
                S.IP(src=SIP.addr_str,
                     dst=DIP.addr_str,
                     ttl=TTL)

            new_span_packet_base = \
                S.Ether(dst=NEW_DEST_MAC.addr_str, src=NEW_SOURCE_MAC.addr_str,
                        type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=EGRESS_VLAN) / \
                S.IP(src=NEW_TUNNEL_SOURCE.addr_str, dst=NEW_TUNNEL_DEST.addr_str, ttl=NEW_TUNNEL_TTL, tos=NEW_TUNNEL_DSCP << 2,
                     flags="DF", id=0, proto=sdk.la_l4_protocol_e_GRE) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)
        else:
            span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv4.value) / \
                S.IP(src=TUNNEL_SOURCE.addr_str, dst=TUNNEL_DEST.addr_str, ttl=TUNNEL_TTL, tos=TUNNEL_DSCP << 2, flags="DF", id=0,
                     proto=sdk.la_l4_protocol_e_GRE) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                self.INJECT_UP_STD_HEADER / \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

            l3_span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv4.value) / \
                S.IP(src=TUNNEL_SOURCE.addr_str, dst=TUNNEL_DEST.addr_str, ttl=TUNNEL_TTL, tos=TUNNEL_DSCP << 2, flags="DF", id=0,
                     proto=sdk.la_l4_protocol_e_UDP) / \
                S.UDP(sport=UDP_SOURCE_PORT, dport=UDP_DEST_PORT, chksum=0) / \
                U.sflow_tunnel_metadata(source_sp=T.RX_SYS_PORT_GID,
                                        reserved=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                                        source_lp=T.RX_L3_AC_GID,
                                        destination_sp=T.TX_L3_AC_SYS_PORT_DEF_GID) / \
                self.INJECT_UP_STD_HEADER / \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str,
                        src=SA.addr_str,
                        type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

            tunl_span_packet_base = S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                                            src=T.TX_L3_AC_REG_MAC.addr_str,
                                            type=U.Ethertype.IPv4.value) / \
                S.IP(src=TUNNEL_SOURCE.addr_str,
                     dst=TUNNEL_DEST.addr_str,
                     ttl=TUNNEL_TTL,
                     tos=TUNNEL_DSCP << 2,
                     flags="DF",
                     id=0,
                     proto=sdk.la_l4_protocol_e_GRE) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II,
                      seqnum_present=1,
                      seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID,
                         en=3) / \
                self.INJECT_UP_STD_HEADER / \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str,
                        src=SA.addr_str,
                        type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1,
                        type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=REMOTE_ANY_IP.addr_str,
                     dst=LOCAL_IP1.addr_str,
                     ttl=TTL) / \
                S.IP(src=SIP.addr_str,
                     dst=DIP.addr_str,
                     ttl=TTL)

            new_span_packet_base = \
                S.Ether(dst=NEW_DEST_MAC.addr_str, src=NEW_SOURCE_MAC.addr_str,
                        type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=EGRESS_VLAN) / \
                S.IP(src=NEW_TUNNEL_SOURCE.addr_str, dst=NEW_TUNNEL_DEST.addr_str, ttl=NEW_TUNNEL_TTL,
                     tos=NEW_TUNNEL_DSCP << 2, flags="DF", id=0, proto=sdk.la_l4_protocol_e_GRE) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                self.INJECT_UP_STD_HEADER / \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

        self.span_packet = U.add_payload(span_packet_base, pad_len)
        self.l3_span_packet = U.add_payload(l3_span_packet_base, pad_len)
        self.new_span_packet = U.add_payload(new_span_packet_base, pad_len)
        self.tunl_span_packet = U.add_payload(tunl_span_packet_base, tunl_pad_len)

        self.in_packet_data = {'data': self.in_packet, 'slice': self.RX_slice, 'ifg': self.RX_ifg, 'pif': T.FIRST_SERDES}
        self.in_tunl_packet_data = {'data': self.in_tunl_packet, 'slice': self.RX_slice, 'ifg': self.RX_ifg, 'pif': T.FIRST_SERDES}
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
        self.new_span_packet_data = {
            'data': self.new_span_packet,
            'slice': T.TX_SLICE_EXT,
            'ifg': T.TX_IFG_EXT,
            'pif': self.l3_port_impl.serdes_ext}
        self.out_tunl_packet_data = {
            'data': self.out_tunl_packet,
            'slice': T.TX_SLICE_DEF,
            'ifg': T.TX_IFG_DEF,
            'pif': self.l3_port_impl.serdes_def}
        self.span_tunl_packet_data = {
            'data': self.tunl_span_packet,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': self.l3_port_impl.serdes_reg}

    def _test_ip_multicast_erspan(self):
        MC_GROUP_ADDR = T.ipv4_addr('232.1.2.3')
        MC_GROUP_GID = 0x13
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        self.mc_group = self.device.create_ip_multicast_group(MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(SIP.hld_obj,
                                                           MC_GROUP_ADDR.hld_obj,
                                                           self.mc_group,
                                                           None,
                                                           False,
                                                           True,
                                                           None)
        self.topology.rx_l2_ac_port.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=False)

        self.in_packet, pad_len = \
            U.enlarge_packet_to_min_length(Ether(dst=self.get_mc_sa_addr_str(MC_GROUP_ADDR),
                                                 src=SA.addr_str, type=U.Ethertype.Dot1Q.value) /
                                           S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) /
                                           S.IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=TTL))
        punt_egr_packets = self.device.get_bool_property(sdk.la_device_property_e_TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST)

        self.set_rx_slice_and_inject_header(T.RX_SLICE, T.RX_IFG)

        if (punt_egr_packets is False):
            span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv4.value) / \
                S.IP(src=TUNNEL_SOURCE.addr_str, dst=TUNNEL_DEST.addr_str, ttl=TUNNEL_TTL, tos=TUNNEL_DSCP << 2, flags="DF", id=0,
                     proto=sdk.la_l4_protocol_e_GRE) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                S.Ether(dst=self.get_mc_sa_addr_str(MC_GROUP_ADDR),
                        src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
                S.IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=TTL)

            new_span_packet_base = \
                S.Ether(dst=NEW_DEST_MAC.addr_str, src=NEW_SOURCE_MAC.addr_str,
                        type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=EGRESS_VLAN) / \
                S.IP(src=NEW_TUNNEL_SOURCE.addr_str, dst=NEW_TUNNEL_DEST.addr_str, ttl=NEW_TUNNEL_TTL, tos=NEW_TUNNEL_DSCP << 2,
                     flags="DF", id=0, proto=sdk.la_l4_protocol_e_GRE) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                S.Ether(dst=self.get_mc_sa_addr_str(MC_GROUP_ADDR),
                        src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
                S.IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=TTL)
        else:
            span_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str,
                        type=U.Ethertype.IPv4.value) / \
                S.IP(src=TUNNEL_SOURCE.addr_str, dst=TUNNEL_DEST.addr_str, ttl=TUNNEL_TTL, tos=TUNNEL_DSCP << 2, flags="DF", id=0,
                     proto=sdk.la_l4_protocol_e_GRE) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                self.INJECT_UP_STD_HEADER / \
                S.Ether(dst=self.get_mc_sa_addr_str(MC_GROUP_ADDR),
                        src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
                S.IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=TTL)

            new_span_packet_base = \
                S.Ether(dst=NEW_DEST_MAC.addr_str, src=NEW_SOURCE_MAC.addr_str,
                        type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=EGRESS_VLAN) / \
                S.IP(src=NEW_TUNNEL_SOURCE.addr_str, dst=NEW_TUNNEL_DEST.addr_str, ttl=NEW_TUNNEL_TTL,
                     tos=NEW_TUNNEL_DSCP << 2, flags="DF", id=0, proto=sdk.la_l4_protocol_e_GRE) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II, seqnum_present=1, seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID, en=3) / \
                self.INJECT_UP_STD_HEADER / \
                S.Ether(dst=self.get_mc_sa_addr_str(MC_GROUP_ADDR),
                        src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
                S.IP(src=SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=TTL)

        self.span_packet = U.add_payload(span_packet_base, pad_len)
        self.new_span_packet = U.add_payload(new_span_packet_base, pad_len)

        self.in_packet_data = {'data': self.in_packet, 'slice': self.RX_slice, 'ifg': self.RX_ifg, 'pif': T.FIRST_SERDES}
        self.span_packet_data = {
            'data': self.span_packet,
            'slice': T.TX_SLICE_REG,
            'ifg': T.TX_IFG_REG,
            'pif': self.l3_port_impl.serdes_reg}
        self.new_span_packet_data = {
            'data': self.new_span_packet,
            'slice': T.TX_SLICE_EXT,
            'ifg': T.TX_IFG_EXT,
            'pif': self.l3_port_impl.serdes_ext}

        U.run_and_compare_list(self, self.device, self.in_packet_data, [self.span_packet_data])
