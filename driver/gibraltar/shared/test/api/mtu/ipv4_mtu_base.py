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
from ip_test_base import *
import sim_utils
import topology as T
import packet_test_utils as U
import ip_test_base
from sdk_test_case_base import *


class ipv4_mtu_base(sdk_test_case_base):
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210

    PREFIX1_GID = 0x691
    LDP_LABEL = sdk.la_mpls_label()
    LDP_LABEL.label = 0x64
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    IP_TTL = 0x88
    MPLS_TTL = 0xff
    ip_impl_class = ip_test_base.ipv4_test_base

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=IP_TTL) / \
        TCP()

    EXPECTED_OUTPUT_PACKET_MPLS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=LDP_LABEL.label, ttl=MPLS_TTL) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=IP_TTL - 1) / \
        TCP()

    INPUT_PACKET = U.add_payload(INPUT_PACKET_BASE, 100)
    EXPECTED_OUTPUT_PACKET_MPLS = U.add_payload(EXPECTED_OUTPUT_PACKET_MPLS_BASE, 100)

    def setUp(self):
        super().setUp()

        self.l3_port_impl = T.ip_l3_ac_base(self.topology)
        self.ip_impl = self.ip_impl_class()

        # Create counter
        self.counter = self.device.create_counter(1)

        priority = 0
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_TX_MTU_FAILURE, priority, self.counter, None, False, False, True, 0)

    def mtu_pad_packet(self, scapy_packet, len):
        # make packet to be atleast len length
        padding = ''
        padding = padding.ljust(len * 2, '8')
        return scapy_packet / Raw(load=unhexlify(padding.encode("ascii")))

    def create_ipv4_route(self):
        prefix = ipv4_test_base.get_default_prefix()
        ipv4_test_base.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh,
                                 ipv4_mtu_base.PRIVATE_DATA_DEFAULT)

    def create_ipv4_to_mpls(self):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        pfx_obj = T.prefix_object(self, self.device, self.PREFIX1_GID, nh_ecmp)
        self.assertNotEqual(pfx_obj.hld_obj, None)

        lsp_counter = None
        lsp_labels = []
        lsp_labels.append(self.LDP_LABEL)

        pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            lsp_counter,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_obj,
                               self.PRIVATE_DATA_DEFAULT)

    def do_run_and_drop_trap(self, in_packet):
        run_and_drop(self, self.device, in_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # test counter
        packets, bytes = self.counter.read(0,  # sub-counter index
                                           True,  # force_update
                                           True)  # clear_on_read
        self.assertEqual(packets, 1)

    def _test_ipv4_to_ipv4(self):
        self.create_ipv4_route()

        # Precise wirelength MTU check enabled.
        in_packet = self.mtu_pad_packet(self.INPUT_PACKET.copy(), 750)

        # Set MTU to be one more than the final output packet. The test removes 8 bytes of 802.1q tags.
        self.topology.tx_l3_ac_eth_port_def.hld_obj.set_mtu(len(in_packet) - 8 - 1)
        self.do_run_and_drop_trap(in_packet)

    def _test_ipv4_to_mpls(self):
        self.create_ipv4_to_mpls()

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # Precise wirelength MTU check enabled.
        in_packet = self.mtu_pad_packet(self.INPUT_PACKET.copy(), 750)
        # Set MTU to be one more than the final output packet. The test removes 8 bytes of 802.1q tags.
        self.topology.tx_l3_ac_eth_port_reg.hld_obj.set_mtu(len(in_packet) - 8 - 1 + 4)

        self.do_run_and_drop_trap(in_packet)
