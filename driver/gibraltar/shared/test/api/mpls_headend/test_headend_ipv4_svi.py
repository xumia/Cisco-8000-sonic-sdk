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
from mpls_headend_base import *
import sim_utils
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_svi(mpls_headend_base):
    protocol = sdk.la_l3_protocol_e_IPV4_UC
    php_protocol = sdk.la_l3_protocol_e_IPV4_UC
    l3_port_impl_class = T.ip_svi_base
    ip_impl_class = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    INPUT_MPLS_PACKET_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    INPUT_MPLS_PACKET_BASE_POP_FWD = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        MPLS(label=mpls_headend_base.INPUT_POP_FWD_LABEL.label, ttl=mpls_headend_base.MPLS_TTL, s=0) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    INPUT_MPLS_PACKET_DOUBLE_LABEL_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    INPUT_MPLS_PACKET_WITH_VLAN_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_IP_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_IP_FLOOD_BASE = \
        Ether(dst=T.NH_SVI_EXT_MAC.addr_str, src=T.TX_SVI_EXT_MAC.addr_str, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_IP_WITH_VLAN_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=mpls_headend_base.OUTPUT_VID + 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_MPLS_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_IP_NULL_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.IPv4.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_IP_NULL_WITH_VLAN_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=mpls_headend_base.OUTPUT_VID + 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_MPLS_UNIFORM_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.IP_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_UPDATED_MPLS_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.NEW_LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_SR_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.SR_LABEL2.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.SR_LABEL0.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_TE_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_LDPoTE_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PACKET_SWAP_LDPoTE_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_SWAP_DOUBLE_LABEL_LDPoTE_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_SWAP_WITH_VLAN_LDPoTE_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.PRIMARY_TE_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL - 1) / \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_headend_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPL_NULL_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_VPN_BGP_LU_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.BGP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_VPN_BGP_LU_NO_LDP_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.BGP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    EXPECTED_OUTPUT_VPN_BGP_LU_NULL_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_headend_base.LDP_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        MPLS(label=mpls_headend_base.VPN_LABEL.label, ttl=mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_headend_base.IP_TTL - 1)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_MPLS_PACKET = U.add_payload(INPUT_MPLS_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_MPLS_PACKET_POP_FWD = U.add_payload(INPUT_MPLS_PACKET_BASE_POP_FWD, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_MPLS_PACKET_DOUBLE_LABEL = U.add_payload(INPUT_MPLS_PACKET_DOUBLE_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_MPLS_PACKET_WITH_VLAN = U.add_payload(INPUT_MPLS_PACKET_WITH_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_IP = U.add_payload(EXPECTED_OUTPUT_PACKET_IP_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_IP_FLOOD = U.add_payload(EXPECTED_OUTPUT_PACKET_IP_FLOOD_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_IP_WITH_VLAN = U.add_payload(EXPECTED_OUTPUT_PACKET_IP_WITH_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_IP_NULL = U.add_payload(EXPECTED_OUTPUT_PACKET_IP_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_IP_NULL_WITH_VLAN = U.add_payload(
        EXPECTED_OUTPUT_PACKET_IP_NULL_WITH_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS = U.add_payload(EXPECTED_OUTPUT_PACKET_MPLS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_MPLS_UNIFORM = U.add_payload(EXPECTED_OUTPUT_PACKET_MPLS_UNIFORM_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_UPDATED_MPLS = U.add_payload(EXPECTED_OUTPUT_PACKET_UPDATED_MPLS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SR = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TE = U.add_payload(EXPECTED_OUTPUT_PACKET_TE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE = U.add_payload(EXPECTED_OUTPUT_PACKET_LDPoTE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SWAP_LDPoTE = U.add_payload(EXPECTED_OUTPUT_PACKET_SWAP_LDPoTE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SWAP_DOUBLE_LABEL_LDPoTE = U.add_payload(
        EXPECTED_OUTPUT_PACKET_SWAP_DOUBLE_LABEL_LDPoTE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_SWAP_WITH_VLAN_LDPoTE = U.add_payload(
        EXPECTED_OUTPUT_PACKET_SWAP_WITH_VLAN_LDPoTE_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPL_NULL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_LDPoTE_TE_IMPL_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_VPN_BGP_LU_PACKET = U.add_payload(EXPECTED_OUTPUT_VPN_BGP_LU_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_VPN_BGP_LU_NO_LDP_PACKET = U.add_payload(
        EXPECTED_OUTPUT_VPN_BGP_LU_NO_LDP_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_VPN_BGP_LU_NULL_PACKET = U.add_payload(
        EXPECTED_OUTPUT_VPN_BGP_LU_NULL_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)

    def test_ecmp_prefix_nh_to_ip(self):
        # lsp counter over SVI not supported.
        self._test_ecmp_prefix_nh_to_ip_setup(add_lsp_counter=False)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.m_ecmp_rec, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_ecmp_prefix_nh_to_ip_run()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - NP2 compound")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_prefix_nh_to_ip_flood(self):
        # lsp counter over SVI not supported.
        self._test_ecmp_prefix_nh_to_ip_flood_setup(add_lsp_counter=False)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.m_ecmp_rec, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_ecmp_prefix_nh_to_ip_flood_run()

    def test_ecmp_prefix_nh_to_mpls(self):
        # lsp counter over SVI not supported.
        self._test_ecmp_prefix_nh_to_mpls_setup(add_lsp_counter=False)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.m_ecmp_rec, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_ecmp_prefix_nh_to_mpls_run()

    def test_ecmp_tenh_to_mpls(self):
        # lsp counter over SVI not supported.
        self._test_ecmp_tenh_to_mpls_setup(add_lsp_counter=False)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.te_ecmp, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_ecmp_tenh_to_mpls_run(check_lsp_counter=False)

    def test_fec_prefix_nh_to_ip(self):
        # lsp counter over SVI not supported.
        self._test_fec_prefix_nh_to_ip_setup(add_lsp_counter=False)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.fec.hld_obj, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_fec_prefix_nh_to_ip_run()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - NP2 compound")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_fec_prefix_nh_to_ip_flood(self):
        # lsp counter over SVI not supported.
        self._test_fec_prefix_nh_to_ip_flood_setup(add_lsp_counter=False)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.fec.hld_obj, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_fec_prefix_nh_to_ip_flood_run()

    def test_fec_prefix_nh_to_mpls(self):
        # lsp counter over SVI not supported.
        self._test_fec_prefix_nh_to_mpls_setup(add_lsp_counter=False)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.fec.hld_obj, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_fec_prefix_nh_to_mpls_run()

    @unittest.skipIf(True, "LDPoTE-SVI")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_ldp_tenh_to_mpls(self):
        # lsp counter over SVI not supported.
        self._test_prefix_ecmp_ldp_tenh_to_mpls(add_lsp_counter=False)

    def test_prefix_ecmp_tenh_to_ip(self):
        # lsp counter over SVI not supported.
        self._test_prefix_ecmp_tenh_to_ip(add_lsp_counter=False)

    def test_prefix_ecmp_tenh_to_mpls(self):
        # lsp counter over SVI not supported.
        self._test_prefix_ecmp_tenh_to_mpls(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_to_ip(self):
        # lsp counter over SVI not supported.
        self._test_prefix_ecmp_to_ip(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ecmp_to_mpls(self):
        # lsp counter over SVI not supported.
        self._test_prefix_ecmp_to_mpls(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_global_ecmp_to_mpls(self):
        # lsp counter over SVI not supported.
        self._test_prefix_global_ecmp_to_mpls(add_lsp_counter=False)

    def test_prefix_global_ecmp_update_destination(self):
        self._test_prefix_global_ecmp_update_destination()

    def test_prefix_global_error_handling(self):
        self._test_prefix_global_error_handling()

    @unittest.skipIf(True, "LDPoTE-SVI")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ldp_tenh_to_mpls(self):
        # lsp counter over SVI not supported.
        self._test_prefix_ldp_tenh_to_mpls(add_lsp_counter=False)

    @unittest.skipIf(True, "LDPoTE-SVI")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_ldp_tenh_to_mpls_te_impl_null(self):
        # lsp counter over SVI not supported.
        self._test_prefix_ldp_tenh_to_mpls_te_impl_null(add_lsp_counter=False)

    def test_prefix_nh_to_ip(self):
        # lsp counter over SVI not supported.
        self._test_prefix_nh_to_ip(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - NP2 compound")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_nh_to_ip_flood(self):
        # lsp counter over SVI not supported.
        self._test_prefix_nh_to_ip_flood(add_lsp_counter=False)

    def test_prefix_nh_to_ip_uniform(self):
        # lsp counter over SVI not supported.
        self._test_prefix_nh_to_ip_uniform(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - NP2 compound")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_nh_to_ip_uniform_flood(self):
        # lsp counter over SVI not supported.
        self._test_prefix_nh_to_ip_uniform_flood(add_lsp_counter=False)

    def test_prefix_nh_to_mpls(self):
        self._test_prefix_nh_to_mpls()

    def test_prefix_nh_to_mpls_uniform(self):
        self._test_prefix_nh_to_mpls_uniform()

    def test_prefix_nh_to_mpls_update_label(self):
        self._test_prefix_nh_to_mpls_update_label(add_lsp_counter=False)

    def test_prefix_tenh_to_ip(self):
        self._test_prefix_tenh_to_ip()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_tenh_to_ip_flood(self):
        self._test_prefix_tenh_to_ip_flood()

    def test_prefix_tenh_to_mpls(self):
        self._test_prefix_tenh_to_mpls()

    @unittest.skipIf(True, "LDPoTE-SVI")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_ecmp_ldp_tenh_to_mpls(self):
        # lsp counter over SVI not supported.
        self._test_swap_ecmp_ldp_tenh_to_mpls(add_lsp_counter=False)

    @unittest.skipIf(True, "LDPoTE-SVI")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_ecmp_ldp_tenh_to_mpls_double_label(self):
        # lsp counter over SVI not supported.
        self._test_swap_ecmp_ldp_tenh_to_mpls_double_label(add_lsp_counter=False)

    @unittest.skipIf(True, "LDPoTE-SVI")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_with_vlan_ecmp_ldp_tenh_to_mpls(self):
        # lsp counter over SVI not supported.
        self._test_swap_with_vlan_ecmp_ldp_tenh_to_mpls(add_lsp_counter=False)

    def test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_no_ldp(self):
        # lsp counter over SVI not supported.
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_setup(is_v4=True, enable_ldp=False, add_lsp_counter=False)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.bgp_ecmp, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_run(enable_ldp=False)

    def test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_with_ldp(self):
        # lsp counter over SVI not supported.
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_setup(is_v4=True, enable_ldp=True, add_lsp_counter=False)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.bgp_ecmp, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_run(enable_ldp=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_ip_ecmp_dpe_ecmp_implicit_null_asbr_lsp_to_mpls_with_ldp(self):
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_setup(
            is_v4=True, enable_ldp=True, add_lsp_counter=True, asbr_labels_null=True)
        self.topology.vrf.hld_obj.add_ipv4_route(self.prefix, self.bgp_ecmp, mpls_headend_base.PRIVATE_DATA_DEFAULT, False)
        self._test_bgp_lu_ip_ecmp_dpe_ecmp_asbr_lsp_to_mpls_run(enable_ldp=True, asbr_labels_null=True)

    def test_bgp_lu_dpe_vpn_properties(self):
        self._test_bgp_lu_dpe_vpn_properties()

    def test_prefix_object_vpn_properties(self):
        self._test_prefix_object_vpn_properties()


if __name__ == '__main__':
    unittest.main()
