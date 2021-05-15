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

from scapy.all import *
from scale_base import *
import sys
import unittest
from leaba import sdk
import ip_test_base
import sim_utils
import topology as T
import packet_test_utils as U

U.parse_ip_after_mpls()


class srte_scale_base(scale_base):

    SR_LABEL0 = sdk.la_mpls_label()
    SR_LABEL0.label = 0x160
    SR_LABEL1 = sdk.la_mpls_label()
    SR_LABEL1.label = 0x161
    SR_LABEL2 = sdk.la_mpls_label()
    SR_LABEL2.label = 0x162
    SR_LABEL3 = sdk.la_mpls_label()
    SR_LABEL3.label = 0x163
    SR_LABEL4 = sdk.la_mpls_label()
    SR_LABEL4.label = 0x164
    SR_LABEL5 = sdk.la_mpls_label()
    SR_LABEL5.label = 0x165
    SR_LABEL6 = sdk.la_mpls_label()
    SR_LABEL6.label = 0x166
    SR_LABEL7 = sdk.la_mpls_label()
    SR_LABEL7.label = 0x167

    INPUT_PACKET_BASE = \
        Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ipv4_l3_ac.SA.addr_str, type=U.Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=ipv4_l3_ac.SIP.addr_str, dst=ipv4_l3_ac.DIP.addr_str, ttl=ipv4_l3_ac.IP_TTL)

    EXPECTED_OUTPUT_PACKET_SR_8_LABELS_BASE = \
        Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.MPLS.value) / \
        MPLS(label=SR_LABEL7.label, ttl=ipv4_l3_ac.MPLS_TTL) / \
        MPLS(label=SR_LABEL6.label, ttl=ipv4_l3_ac.MPLS_TTL) / \
        MPLS(label=SR_LABEL5.label, ttl=ipv4_l3_ac.MPLS_TTL) / \
        MPLS(label=SR_LABEL4.label, ttl=ipv4_l3_ac.MPLS_TTL) / \
        MPLS(label=SR_LABEL3.label, ttl=ipv4_l3_ac.MPLS_TTL) / \
        MPLS(label=SR_LABEL2.label, ttl=ipv4_l3_ac.MPLS_TTL) / \
        MPLS(label=SR_LABEL1.label, ttl=ipv4_l3_ac.MPLS_TTL) / \
        MPLS(label=SR_LABEL0.label, ttl=ipv4_l3_ac.MPLS_TTL) / \
        IP(src=ipv4_l3_ac.SIP.addr_str, dst=ipv4_l3_ac.DIP.addr_str, ttl=ipv4_l3_ac.IP_TTL - 1)

    INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    EXPECTED_OUTPUT_PACKET_SR_8_LABELS = U.add_payload(EXPECTED_OUTPUT_PACKET_SR_8_LABELS_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    def _test_srte_scale(self):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        lsp_labels_max = []
        lsp_labels_max.append(self.SR_LABEL0)
        lsp_labels_max.append(self.SR_LABEL1)
        lsp_labels_max.append(self.SR_LABEL2)
        lsp_labels_max.append(self.SR_LABEL3)
        lsp_labels_max.append(self.SR_LABEL4)
        lsp_labels_max.append(self.SR_LABEL5)
        lsp_labels_max.append(self.SR_LABEL6)
        lsp_labels_max.append(self.SR_LABEL7)

        # Supported SRTE scale for > 3 labels is 4K. Create one with GID 0 and the
        # other with GID 64K-1 to test the min and max GIDs.
        max_srte_extended_policies = self.device.get_limit(sdk.limit_type_e_DEVICE__MAX_SR_EXTENDED_POLICIES)
        max_pfx_objs = max_srte_extended_policies
        num_tunnels = max_srte_extended_policies
        pfx_objs = []
        for i in range(max_pfx_objs):
            global_pfx_obj = T.global_prefix_object(self, self.device, i, nh_ecmp)
            try:
                global_pfx_obj.hld_obj.set_global_lsp_properties(
                    lsp_labels_max, None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)
                pfx_objs.append(global_pfx_obj)
            except sdk.ResourceException:
                num_tunnels = i
                print("SRTE scale test: Created {num_tunnels} SRTE tunnels with 8 labels...".format(num_tunnels=i))
                break

        # Add a route to verify the last lsp
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, pfx_objs[num_tunnels - 1],
                               self.PRIVATE_DATA_DEFAULT)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_SR_8_LABELS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        for i in range(num_tunnels):
            pfx_objs[i].destroy()
