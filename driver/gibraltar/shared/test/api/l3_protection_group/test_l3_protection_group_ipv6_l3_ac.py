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


import sys
import unittest
from leaba import sdk
import sim_utils
import ip_test_base
from scapy.all import *
import topology as T
import packet_test_utils as U
from l3_protection_group_base import *
import decor

load_contrib('mpls')


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv6_l3_ac(l3_protection_group_base):
    protocol = sdk.la_l3_protocol_e_IPV6_UC
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv6_test_base
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=l3_protection_group_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL, plen=40)

    INPUT_PACKET_MPLS_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=l3_protection_group_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=l3_protection_group_base.INPUT_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_IP_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.IPv6.value) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_IP_P_NH_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=U.Ethertype.IPv6.value) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_MPLS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=l3_protection_group_base.LDP_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_MPLS_SWAP_PRIMARY_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=l3_protection_group_base.LDP_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL - 1) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_MPLS_SWAP_LFA_FRR_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=l3_protection_group_base.BACKUP_LDP_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL - 1) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_MPLS_LFA_FRR_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=l3_protection_group_base.BACKUP_LDP_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_MPLS_REMOTE_LFA_FRR_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=l3_protection_group_base.BACKUP_LDP_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        MPLS(label=l3_protection_group_base.PQ_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_MPLS_TI_LFA_FRR_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=l3_protection_group_base.BACKUP_LDP_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        MPLS(label=l3_protection_group_base.PQ_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        MPLS(label=l3_protection_group_base.DEST_SID_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_TE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=l3_protection_group_base.PRIMARY_TE_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=l3_protection_group_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_LDPoTE_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=l3_protection_group_base.PRIMARY_TE_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        MPLS(label=l3_protection_group_base.LDP_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=l3_protection_group_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_TE_BACKUP_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=l3_protection_group_base.BACKUP_TE_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        MPLS(label=l3_protection_group_base.MP_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=l3_protection_group_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_LDPoTE_BACKUP_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=l3_protection_group_base.BACKUP_TE_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        MPLS(label=l3_protection_group_base.MP_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        MPLS(label=l3_protection_group_base.LDP_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=l3_protection_group_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPL_NULL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=l3_protection_group_base.LDP_LABEL.label, ttl=l3_protection_group_base.MPLS_TTL) / \
        MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV6, ttl=l3_protection_group_base.MPLS_TTL) / \
        IPv6(src=SIP.addr_str, dst=DIP.addr_str, hlim=l3_protection_group_base.IP_TTL - 1, plen=40)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_PACKET_MPLS = U.add_payload(INPUT_PACKET_MPLS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_IP = U.add_payload(EXPECTED_OUTPUT_PACKET_IP_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_IP_P_NH = U.add_payload(EXPECTED_OUTPUT_PACKET_IP_P_NH_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS = U.add_payload(EXPECTED_OUTPUT_PACKET_MPLS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS_SWAP_PRIMARY = U.add_payload(
        EXPECTED_OUTPUT_PACKET_MPLS_SWAP_PRIMARY_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS_SWAP_LFA_FRR = U.add_payload(
        EXPECTED_OUTPUT_PACKET_MPLS_SWAP_LFA_FRR_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS_LFA_FRR = U.add_payload(EXPECTED_OUTPUT_PACKET_MPLS_LFA_FRR_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS_REMOTE_LFA_FRR = U.add_payload(
        EXPECTED_OUTPUT_PACKET_MPLS_REMOTE_LFA_FRR_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS_TI_LFA_FRR = U.add_payload(
        EXPECTED_OUTPUT_PACKET_MPLS_TI_LFA_FRR_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TE = U.add_payload(EXPECTED_OUTPUT_PACKET_TE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE = U.add_payload(EXPECTED_OUTPUT_PACKET_LDPoTE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TE_BACKUP = U.add_payload(EXPECTED_OUTPUT_PACKET_TE_BACKUP_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_BACKUP = U.add_payload(EXPECTED_OUTPUT_PACKET_LDPoTE_BACKUP_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPL_NULL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPL_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_p_nh_to_mpls(self):
        self._test_prefix_ecmp_ldp_tenh_p_nh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_p_nh_to_mpls(self):
        self._test_prefix_ecmp_p_nh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_p_nh_to_mpls(self):
        self._test_prefix_ecmp_tenh_p_nh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_tenh_p_nh_to_mpls_tunnel_over_tunnel(self):
        self._test_prefix_ecmp_tenh_p_nh_to_mpls_tunnel_over_tunnel()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_p_nh_to_ip(self):
        self._test_prefix_p_nh_to_ip()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_p_nh_to_mpls(self):
        self._test_prefix_p_nh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_p_nh_to_mpls_rlfa_backup_nh(self):
        self._test_prefix_p_nh_to_mpls_rlfa_backup_nh()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_p_nh_to_mpls_tilfa_backup_nh(self):
        self._test_prefix_p_nh_to_mpls_tilfa_backup_nh()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_tenh_p_nh_to_mpls(self):
        self._test_prefix_tenh_p_nh_to_mpls()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mpls_swap_p_nh(self):
        self._test_mpls_swap_p_nh()


if __name__ == '__main__':
    unittest.main()
