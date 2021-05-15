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

from mpls_to_mpls_headend_base import *
import sim_utils
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_svi_test(mpls_to_mpls_headend_base):
    protocol = sdk.la_l3_protocol_e_IPV4_UC
    l3_port_impl_class = T.ip_svi_base

    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    INPUT_PACKET_WITH_EXP_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL0.label, cos=1, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    INPUT_PACKET_DOUBLE_LABEL_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL, s=0) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    INPUT_PACKET_WITH_VLAN_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_SWAP_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.OUTPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.OUTPUT_LABEL2.label, cos=1, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base.OUTPUT_LABEL1.label, cos=1, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base.OUTPUT_LABEL0.label, cos=1, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=mpls_to_mpls_headend_base.OUTPUT_VID, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.OUTPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_to_mpls_headend_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.OUTPUT_LABEL0.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1, s=0) / \
        MPLS(label=mpls_to_mpls_headend_base.INPUT_LABEL1.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1)

    EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_WITH_VLAN_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=mpls_to_mpls_headend_base.OUTPUT_VID + 1) /\
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1)

    EXPECTED_OUTPUT_BGP_LU_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.LDP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base.BGP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.BGP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_BGP_LU_PACKET_NEW_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.LDP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base.BGP_LABEL_NEW.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_BGP_LU_NO_LDP_BGP_LBL_UPDATED_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.BGP_LABEL_NEW.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_BGP_LU_NO_LDP_DEST_UPDATED_PACKET_BASE = \
        Ether(dst=T.NH_SVI_DEF_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.BGP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    EXPECTED_OUTPUT_BGP_LU_DEST_UPDATED_PACKET_BASE = \
        Ether(dst=T.NH_SVI_DEF_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_to_mpls_headend_base.LDP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_to_mpls_headend_base.BGP_LABEL.label, ttl=mpls_to_mpls_headend_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_to_mpls_headend_base.IP_TTL)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_PACKET_WITH_EXP, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_WITH_EXP_BASE)
    INPUT_PACKET_DOUBLE_LABEL = U.add_payload(INPUT_PACKET_DOUBLE_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_WITH_VLAN = U.add_payload(INPUT_PACKET_WITH_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_SWAP_PACKET = U.add_payload(EXPECTED_OUTPUT_SWAP_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET = U.add_payload(
        EXPECTED_OUTPUT_MULTIPLE_LABELS_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN = U.add_payload(
        EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL = U.add_payload(
        EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PHP_UNIFORM_PACKET = U.add_payload(EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_WITH_VLAN = U.add_payload(
        EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_WITH_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_BGP_LU_PACKET = U.add_payload(EXPECTED_OUTPUT_BGP_LU_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET = U.add_payload(
        EXPECTED_OUTPUT_BGP_LU_NO_LDP_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_BGP_LU_PACKET_NEW = U.add_payload(EXPECTED_OUTPUT_BGP_LU_PACKET_NEW_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_BGP_LU_NO_LDP_BGP_LBL_UPDATED_PACKET = U.add_payload(
        EXPECTED_OUTPUT_BGP_LU_NO_LDP_BGP_LBL_UPDATED_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_BGP_LU_NO_LDP_DEST_UPDATED_PACKET = U.add_payload(
        EXPECTED_OUTPUT_BGP_LU_NO_LDP_DEST_UPDATED_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_BGP_LU_DEST_UPDATED_PACKET = U.add_payload(
        EXPECTED_OUTPUT_BGP_LU_DEST_UPDATED_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecmp_swap(self):
        # lsp counter over SVI not supported.
        self._test_ecmp_swap(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_global_ecmp_swap(self):
        # lsp counter over SVI not supported.
        self._test_prefix_global_ecmp_swap(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_global_ecmp_multiple_labels(self):
        # lsp counter over SVI not supported.
        self._test_prefix_global_ecmp_multiple_labels(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_ecmp_uniform(self):
        # lsp counter over SVI not supported.
        self._test_php_ecmp_uniform(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_prefix_global_php_ecmp_uniform(self):
        # lsp counter over SVI not supported.
        self._test_prefix_global_php_ecmp_uniform(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform(self):
        # lsp counter over SVI not supported.
        self._test_php_uniform(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap(self):
        # lsp counter over SVI not supported.
        self._test_swap(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_double_label(self):
        # lsp counter over SVI not supported.
        self._test_swap_double_label(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_with_vlan(self):
        # lsp counter over SVI not supported.
        self._test_swap_with_vlan(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_dpe_ecmp_asbr_lsp_to_mpls_no_ldp(self):
        self._test_bgp_lu_dpe_ecmp_asbr_lsp_to_mpls(enable_ldp=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_dpe_ecmp_asbr_lsp_to_mpls_with_ldp(self):
        self._test_bgp_lu_dpe_ecmp_asbr_lsp_to_mpls(enable_ldp=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_dpe_ecmp_asbr_lsp_drop_nh(self):
        self._test_bgp_lu_dpe_ecmp_asbr_lsp_drop_nh()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_error_handling(self):
        self._test_bgp_lu_error_handling()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_update_asbr_lsp_asbr(self):
        self._test_bgp_lu_update_asbr_lsp_asbr()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_update_asbr_lsp_destination_no_ldp(self):
        self._test_bgp_lu_update_asbr_lsp_destination(False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_update_asbr_lsp_destination_with_ldp(self):
        self._test_bgp_lu_update_asbr_lsp_destination(True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_update_asbr_lsp_prot_group_destination(self):
        self._test_bgp_lu_update_asbr_lsp_prot_group_destination()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bgp_lu_update_dpe_destination(self):
        self._test_bgp_lu_update_dpe_destination()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_csc_label_check(self):
        self._test_csc_label_check()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_csc_label_check_intf_non_csc(self):
        self._test_csc_label_check_intf_non_csc()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_csc_label_check_label_drop(self):
        self._test_csc_label_check_label_drop()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_csc_label_check_vrf_drop(self):
        self._test_csc_label_check_vrf_drop()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform_csc_label_check(self):
        self._test_php_uniform_csc_label_check()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform_csc_label_check_intf_non_csc(self):
        self._test_php_uniform_csc_label_check_intf_non_csc()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform_csc_label_check_label_drop(self):
        self._test_php_uniform_csc_label_check_label_drop()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform_csc_label_check_vrf_drop(self):
        self._test_php_uniform_csc_label_check_vrf_drop()


if __name__ == '__main__':
    unittest.main()
