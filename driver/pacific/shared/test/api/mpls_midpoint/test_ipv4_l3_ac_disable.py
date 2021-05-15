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

load_contrib('mpls')


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv4_l3_ac_test(mpls_midpoint_base):
    protocol = sdk.la_l3_protocol_e_IPV4_UC
    l3_port_impl_class = T.ip_l3_ac_base

    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_midpoint_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    INPUT_PACKET_DOUBLE_LABEL_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_midpoint_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 2, s=0) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL1.label, ttl=mpls_midpoint_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    INPUT_PACKET_DOUBLE_LABEL_1_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_midpoint_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL + 2, s=0) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL1.label, ttl=mpls_midpoint_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    INPUT_PACKET_WITH_VLAN_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_midpoint_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL) / \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_midpoint_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_SWAP_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_midpoint_base.OUTPUT_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=mpls_midpoint_base.OUTPUT_VID, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_midpoint_base.OUTPUT_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 1) / \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=mpls_midpoint_base.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_midpoint_base.OUTPUT_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 3, s=0) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL1.label, ttl=mpls_midpoint_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_PHP_PIPE_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL - 1)

    EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.MPLS_TTL - 1)

    EXPECTED_OUTPUT_POP_PIPE_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL1.label, ttl=mpls_midpoint_base.MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_POP_UNIFORM_PACKET_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        MPLS(label=mpls_midpoint_base.INPUT_LABEL1.label, ttl=mpls_midpoint_base.MPLS_TTL - 3) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_TE_BACKUP_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_midpoint_base.BACKUP_TE_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 1) / \
        MPLS(label=mpls_midpoint_base.MP_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_TE_BACKUP_BACKUP_NULL_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_midpoint_base.MP_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    EXPECTED_OUTPUT_PACKET_TE_BACKUP_MP_NULL_BASE = \
        Ether(dst=T.NH_L3_AC_EXT_MAC.addr_str, src=T.TX_L3_AC_EXT_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=mpls_midpoint_base.BACKUP_TE_LABEL.label, ttl=mpls_midpoint_base.MPLS_TTL - 1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=mpls_midpoint_base.IP_TTL)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_PACKET_DOUBLE_LABEL = U.add_payload(INPUT_PACKET_DOUBLE_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_DOUBLE_LABEL_1 = U.add_payload(INPUT_PACKET_DOUBLE_LABEL_1_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    INPUT_PACKET_WITH_VLAN = U.add_payload(INPUT_PACKET_WITH_VLAN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_SWAP_PACKET = U.add_payload(EXPECTED_OUTPUT_SWAP_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN = U.add_payload(
        EXPECTED_OUTPUT_SWAP_PACKET_WITH_VLAN_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL = U.add_payload(
        EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL_BASE,
        BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PHP_PIPE_PACKET = U.add_payload(EXPECTED_OUTPUT_PHP_PIPE_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PHP_UNIFORM_PACKET = U.add_payload(EXPECTED_OUTPUT_PHP_UNIFORM_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
    EXPECTED_OUTPUT_POP_PIPE_PACKET = U.add_payload(
        EXPECTED_OUTPUT_POP_PIPE_PACKET_BASE,
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

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_modify_label_mapping_disable_rx(self):
        self._test_modify_label_mapping(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_modify_label_mapping_disable_tx(self):
        self._test_modify_label_mapping(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform_disable_rx(self):
        self._test_php_uniform(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_uniform_disable_tx(self):
        self._test_php_uniform(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_double_label_pipe_disable_rx(self):
        self._test_pop_double_label_pipe(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_double_label_pipe_disable_tx(self):
        self._test_pop_double_label_pipe(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_double_label_uniform_1_disable_rx(self):
        self._test_pop_double_label_uniform_1(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_double_label_uniform_1_disable_tx(self):
        self._test_pop_double_label_uniform_1(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_double_label_uniform_2_disable_rx(self):
        self._test_pop_double_label_uniform_2(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pop_double_label_uniform_2_disable_tx(self):
        self._test_pop_double_label_uniform_2(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_disable_rx(self):
        self._test_swap(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_disable_tx(self):
        self._test_swap(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_double_label_disable_rx(self):
        self._test_swap_double_label(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_double_label_disable_tx(self):
        self._test_swap_double_label(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_with_vlan_disable_rx(self):
        self._test_swap_with_vlan(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_with_vlan_disable_tx(self):
        self._test_swap_with_vlan(disable_tx=True)


if __name__ == '__main__':
    unittest.main()
