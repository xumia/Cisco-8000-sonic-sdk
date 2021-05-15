#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from packet_test_utils import *
from scapy.all import *
import unittest
import sys
from leaba import sdk
import sim_utils
import topology as T
from sdk_test_case_base import *

# Network topology
IN_IFG = 0
IN_SERDES_FIRST = T.get_device_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1

OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST_1 = T.get_device_next_first_serdes(8)
OUT_SERDES_LAST_1 = OUT_SERDES_FIRST_1 + 1
OUT_SERDES_FIRST_2 = T.get_device_out_first_serdes(10)
OUT_SERDES_LAST_2 = OUT_SERDES_FIRST_2 + 1

SYS_PORT_GID_BASE = 23

# Ensure that all egress AC ports are part of same size 16 block
AC_PORT_GID_BASE = 1024

SWITCH_GID = 100

DST_MAC_1 = "ca:fe:ca:fe:ca:fe"
DST_MAC_2 = "fe:ca:fe:ca:fe:ca"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0xAB9

# QoS remarking
# Ingress QoS fields
IN_PCPDEI = sdk.la_vlan_pcpdei()
IN_PCPDEI.fields.pcp = 2
IN_PCPDEI.fields.dei = 1

# Intermediate tags
TAG_PCPDEI = sdk.la_vlan_pcpdei()
TAG_PCPDEI.fields.pcp = 6
TAG_PCPDEI.fields.dei = 1

# Egress QoS fields
OUT_PCPDEI_1 = sdk.la_vlan_pcpdei()
OUT_PCPDEI_1.fields.pcp = 3
OUT_PCPDEI_1.fields.dei = 0

OUT_PCPDEI_2 = sdk.la_vlan_pcpdei()
OUT_PCPDEI_2.fields.pcp = 6
OUT_PCPDEI_2.fields.dei = 0

# Unchanged QoS fields
IP_TOS = sdk.la_ip_tos()
IP_TOS.fields.dscp = 35
IP_TOS.fields.ecn = 2


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_l2_qos_intf_scale_base(sdk_test_case_base):
    IN_SLICE = T.get_device_slice(2)
    OUT_SLICE = T.get_device_slice(4)

    def setUp(self):
        super().setUp(create_default_topology=False)
        self.IN_SLICE = T.choose_active_slices(self.device, self.IN_SLICE, [2, 3])
        self.OUT_SLICE = T.choose_active_slices(self.device, self.OUT_SLICE, [4, 1])
        self.create_network_topology()
        self.topology.create_inject_ports()
        self._add_objects_to_keep()

    def create_network_topology(self):
        # Create qos profiles
        self.ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        self.egress_qos_profile1 = T.egress_qos_profile(self, self.device)
        self.egress_qos_profile2 = T.egress_qos_profile(self, self.device)

        # Create a switch with to L2-AC ports
        self.sw1 = T.switch(self, self.device, SWITCH_GID)
        self.ac_profile = T.ac_profile(self, self.device)

        self.dest_mac1 = T.mac_addr(DST_MAC_1)
        self.dest_mac2 = T.mac_addr(DST_MAC_2)

        self.eth_port1 = T.ethernet_port(
            self,
            self.device,
            self.IN_SLICE,
            IN_IFG,
            SYS_PORT_GID_BASE,
            IN_SERDES_FIRST,
            IN_SERDES_LAST)
        self.eth_port1.set_ac_profile(self.ac_profile)
        self.ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port1,
            None,
            VLAN,
            0x0,
            self.ingress_qos_profile,
            self.egress_qos_profile1)

        self.eth_port1 = T.ethernet_port(
            self,
            self.device,
            self.OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 1,
            OUT_SERDES_FIRST_1,
            OUT_SERDES_LAST_1)
        self.eth_port1.set_ac_profile(self.ac_profile)
        self.ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port1,
            self.dest_mac1,
            VLAN,
            0x0,
            self.ingress_qos_profile,
            self.egress_qos_profile1)

        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            self.OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 2,
            OUT_SERDES_FIRST_2,
            OUT_SERDES_LAST_2)
        self.eth_port2.set_ac_profile(self.ac_profile)
        self.ac_port2 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 2,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port2,
            self.dest_mac2,
            VLAN,
            0x0,
            self.ingress_qos_profile,
            self.egress_qos_profile2)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 0
        eve.pcpdei_rewrite_only = True

        self.ac_port1.hld_obj.set_egress_vlan_edit_command(eve)
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_l2_packet_qos_remarking(self):
        # Prepare remarking of IN_PCPDEI -> OUT_PCPDEI
        encap_qos_values = sdk.encapsulating_headers_qos_values()
        self.ingress_qos_profile.hld_obj.set_qos_tag_mapping_pcpdei(IN_PCPDEI, TAG_PCPDEI)
        self.egress_qos_profile1.hld_obj.set_qos_tag_mapping_pcpdei(TAG_PCPDEI, OUT_PCPDEI_1, encap_qos_values)
        self.egress_qos_profile2.hld_obj.set_qos_tag_mapping_pcpdei(TAG_PCPDEI, OUT_PCPDEI_2, encap_qos_values)

        # Prepare packets
        in_packet_base_1 = Ether(dst=DST_MAC_1, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=IN_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        in_packet_base_2 = Ether(dst=DST_MAC_2, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=IN_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        out_packet_base_1 = Ether(dst=DST_MAC_1, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=OUT_PCPDEI_1.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        out_packet_base_2 = Ether(dst=DST_MAC_2, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=OUT_PCPDEI_2.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        in_packet_1, out_packet_1 = pad_input_and_output_packets(in_packet_base_1, out_packet_base_1)
        in_packet_2, out_packet_2 = pad_input_and_output_packets(in_packet_base_2, out_packet_base_2)

        run_and_compare(
            self,
            self.device,
            in_packet_1,
            self.IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet_1,
            self.OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST_1)

        run_and_compare(
            self,
            self.device,
            in_packet_2,
            self.IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet_2,
            self.OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST_2)


if __name__ == '__main__':
    unittest.main()
