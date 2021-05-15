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
from scapy.all import *
import sim_utils
import topology as T
import packet_test_utils as U
from mpls_midpoint_base import *
import decor
import ip_test_base

load_contrib('mpls')


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv4_svi_test(mpls_midpoint_base):
    protocol = sdk.la_l3_protocol_e_IPV4_UC
    l3_port_impl_class = T.ip_svi_base

    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    ip_impl = ip_test_base.ipv4_test_base

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_midpoint_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    INPUT_PACKET_POP_FWD_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_midpoint_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_midpoint_base.INPUT_POP_FWD_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL, s=0) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    INPUT_PACKET_DOUBLE_LABEL_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_midpoint_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL, s=0) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL1.label, ttl=mpls_midpoint_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    INPUT_PACKET_WITH_VLAN_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_midpoint_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL) / \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_midpoint_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL - 1)

    EXPECTED_OUTPUT_SWAP_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_midpoint_base.OUTPUT_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=mpls_midpoint_base.OUTPUT_VID, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_midpoint_base.OUTPUT_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 1) / \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=mpls_midpoint_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.MPLS.value) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_midpoint_base.OUTPUT_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 1, s=0) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL1.label, ttl=mpls_midpoint_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_PHP_PIPE_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.MPLS_TTL - 1)

    EXPECTED_OUTPUT_PHP_UNIFORM_WITH_VLAN_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=mpls_midpoint_base.OUTPUT_VID + 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.MPLS_TTL - 1)

    EXPECTED_OUTPUT_PHP_UNIFORM_FLOOD_PACKET_BASE = \
        Ether(dst=T.NH_SVI_EXT_MAC.addr_str, src=T.TX_SVI_EXT_MAC.addr_str) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.MPLS_TTL - 1)

    EXPECTED_OUTPUT_POP_PIPE_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL1.label, ttl=mpls_midpoint_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_POP_PIPE_FLOOD_PACKET_BASE = \
        Ether(dst=T.NH_SVI_EXT_MAC.addr_str, src=T.TX_SVI_EXT_MAC.addr_str) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL1.label, ttl=mpls_midpoint_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_POP_UNIFORM_PACKET_BASE = \
        Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL1.label, ttl=mpls_midpoint_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_TE_BACKUP_BASE = \
        Ether(dst=T.NH_SVI_EXT_MAC.addr_str, src=T.TX_SVI_EXT_MAC.addr_str) / \
        MPLS(label=mpls_midpoint_base.BACKUP_TE_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_midpoint_base.MP_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_TE_BACKUP_BACKUP_NULL_BASE = \
        Ether(dst=T.NH_SVI_EXT_MAC.addr_str, src=T.TX_SVI_EXT_MAC.addr_str) / \
        MPLS(label=mpls_midpoint_base.MP_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_TE_BACKUP_MP_NULL_BASE = \
        Ether(dst=T.NH_SVI_EXT_MAC.addr_str, src=T.TX_SVI_EXT_MAC.addr_str) / \
        MPLS(label=mpls_midpoint_base.BACKUP_TE_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    INPUT_PACKET_POP_FWD, BASE_POP_FWD_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_POP_FWD_BASE)
    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_PACKET_DOUBLE_LABEL = U.add_payload(INPUT_PACKET_DOUBLE_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_WITH_VLAN = U.add_payload(INPUT_PACKET_WITH_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_SWAP_POP_FWD_PACKET = U.add_payload(EXPECTED_OUTPUT_SWAP_PACKET_BASE, BASE_POP_FWD_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_SWAP_PACKET = U.add_payload(EXPECTED_OUTPUT_SWAP_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN = U.add_payload(
        EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL = U.add_payload(
        EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PHP_PIPE_PACKET = U.add_payload(EXPECTED_OUTPUT_PHP_PIPE_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PHP_UNIFORM_PACKET = U.add_payload(EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PHP_UNIFORM_POP_FWD_PACKET = U.add_payload(EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_BASE, BASE_POP_FWD_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PHP_UNIFORM_WITH_VLAN_PACKET = U.add_payload(EXPECTED_OUTPUT_PHP_UNIFORM_WITH_VLAN_PACKET_BASE,
                                                                 BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PHP_UNIFORM_WITH_VLAN_POP_FWD_PACKET = U.add_payload(EXPECTED_OUTPUT_PHP_UNIFORM_WITH_VLAN_PACKET_BASE,
                                                                         BASE_POP_FWD_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PHP_UNIFORM_FLOOD_PACKET = U.add_payload(
        EXPECTED_OUTPUT_PHP_UNIFORM_FLOOD_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_POP_PIPE_PACKET = U.add_payload(
        EXPECTED_OUTPUT_POP_PIPE_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_POP_PIPE_FLOOD_PACKET = U.add_payload(
        EXPECTED_OUTPUT_POP_PIPE_FLOOD_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_POP_UNIFORM_PACKET = U.add_payload(
        EXPECTED_OUTPUT_POP_UNIFORM_PACKET_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TE_BACKUP = U.add_payload(EXPECTED_OUTPUT_PACKET_TE_BACKUP_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TE_BACKUP_BACKUP_NULL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_TE_BACKUP_BACKUP_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_TE_BACKUP_MP_NULL = U.add_payload(
        EXPECTED_OUTPUT_PACKET_TE_BACKUP_MP_NULL_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)

    def test_php_uniform(self):
        self._test_php_uniform()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform_flood(self):
        self._test_php_uniform_flood()

    def test_pop_double_label_pipe(self):
        self._test_pop_double_label_pipe()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_double_label_pipe_flood(self):
        self._test_pop_double_label_pipe_flood()

    def test_swap(self):
        self._test_swap()

    def test_swap_double_label(self):
        self._test_swap_double_label()

    def test_swap_with_vlan(self):
        self._test_swap_with_vlan()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_te_midpoint_backup(self):
        # lsp counter over SVI not supported.
        self._test_te_midpoint_backup(add_lsp_counter=False)

    def test_te_midpoint_primary(self):
        # lsp counter over SVI not supported.
        self._test_te_midpoint_primary(add_lsp_counter=False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_pop_fwd(self):
        self._test_swap_pop_fwd()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_pop_fwd_with_l3vpn_decap(self):
        self._test_swap_pop_fwd_with_l3vpn_decap()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform_pop_fwd(self):
        self._test_php_uniform_pop_fwd()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_fwd_invalid_next_hdr(self):
        self._test_pop_fwd_invalid_next_hdr()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_fwd_invalid_bos(self):
        self._test_pop_fwd_invalid_bos()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_fwd_invalid_bos_and_next_hdr(self):
        self._test_pop_fwd_invalid_bos_and_next_hdr()


if __name__ == '__main__':
    unittest.main()
