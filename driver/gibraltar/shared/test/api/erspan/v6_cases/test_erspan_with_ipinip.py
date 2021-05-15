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

import decor
import sys
import unittest
from leaba import sdk
import ip_test_base
from packet_test_utils import *
from scapy.all import *
import sim_utils
import topology as T
from erspan_base import *
from ipv4_l3_ac_erspan_base import *
import ip_test_base
from ip_over_ip_tunnel.ip_over_ip_tunnel_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_erspan_with_ipinip(ipv4_l3_ac_erspan_base):

    TUNNEL_PORT_GID1 = 0x521

    def setUpIPinIP(self):
        self.REMOTE_IP = T.ipv4_addr('10.12.10.12')
        self.LOCAL_IP = T.ipv4_addr('192.168.95.250')
        self.TUNNEL_TTL = 255

        self.tunnel_dest = ip_test_base.ipv4_test_base.build_prefix(self.LOCAL_IP, length=16)

        self.ip_over_ip_tunnel_port = T.ip_over_ip_tunnel_port(self, self.device,
                                                               self.TUNNEL_PORT_GID1,
                                                               self.topology.vrf,
                                                               self.tunnel_dest,
                                                               self.REMOTE_IP,
                                                               self.topology.vrf)

        self.tunnel_counter = self.device.create_counter(1)
        self.ip_over_ip_tunnel_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.tunnel_counter)
        self.ip_over_ip_tunnel_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

        self.in_packet, pad_len = \
            U.enlarge_packet_to_min_length(S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) /
                                           S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) /
                                           S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) /
                                           S.IP(src=self.REMOTE_IP.addr_str, dst=self.LOCAL_IP.addr_str, ttl=self.TUNNEL_TTL) /
                                           S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL))

        self.out_packet = \
            U.add_payload(S.Ether(dst=T.NH_L3_AC_DEF_MAC.addr_str, src=T.TX_L3_AC_DEF_MAC.addr_str) /
                          S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1), pad_len)

        punt_egr_packets = self.device.get_bool_property(sdk.la_device_property_e_TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST)

        self.set_rx_slice_and_inject_header(T.RX_SLICE, T.RX_IFG)

        if (punt_egr_packets is False):
            self.span_packet_base = S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                                            src=T.TX_L3_AC_REG_MAC.addr_str,
                                            type=U.Ethertype.IPv6.value) / \
                S.IPv6(src=TUNNEL_SOURCE.addr_str,
                       dst=TUNNEL_DEST.addr_str,
                       hlim=TUNNEL_TTL,
                       tc=TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=78) / \
                S.GRE(proto=nplapicli.NPL_ETHER_TYPE_ERSPAN_II,
                      seqnum_present=1,
                      seqence_number=0) / \
                U.ERSPAN(session_id=SESSION_ID,
                         en=3) / \
                S.Ether(dst=T.RX_L3_AC_MAC.addr_str,
                        src=SA.addr_str,
                        type=U.Ethertype.QinQ.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1,
                        type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
                S.IP(src=self.REMOTE_IP.addr_str,
                     dst=self.LOCAL_IP.addr_str,
                     ttl=self.TUNNEL_TTL) / \
                S.IP(src=SIP.addr_str,
                     dst=DIP.addr_str,
                     ttl=TTL)
        else:
            self.span_packet_base = S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                                            src=T.TX_L3_AC_REG_MAC.addr_str,
                                            type=U.Ethertype.IPv6.value) / \
                S.IPv6(src=TUNNEL_SOURCE.addr_str,
                       dst=TUNNEL_DEST.addr_str,
                       hlim=TUNNEL_TTL,
                       tc=TUNNEL_DSCP << 2,
                       nh=sdk.la_l4_protocol_e_GRE, plen=113) / \
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
                S.IP(src=self.REMOTE_IP.addr_str,
                     dst=self.LOCAL_IP.addr_str,
                     ttl=self.TUNNEL_TTL) / \
                S.IP(src=SIP.addr_str,
                     dst=DIP.addr_str,
                     ttl=TTL)

        self.span_packet = U.add_payload(self.span_packet_base, pad_len)

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

    def test_erspan_with_ipinip(self):
        self.setUpIPinIP()
        self.topology.rx_l3_ac.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=False)
        mirror_cmd, is_acl_conditioned = self.topology.rx_l3_ac.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.mirror_cmd.hld_obj.get_gid())

        run_and_compare_list(self, self.device, self.in_packet_data, [self.span_packet_data, self.out_packet_data])
        packet_count, byte_count = self.tunnel_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        expected_bytes = U.get_injected_packet_len(self.device, self.in_packet, T.RX_SLICE)
        self.assertTrue(byte_count, expected_bytes)

        packet_count, byte_count = self.erspan_counter.read(0, True, True)
        self.mirror_cmd.hld_obj.set_counter(None)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.span_packet, byte_count)


if __name__ == '__main__':
    unittest.main()
