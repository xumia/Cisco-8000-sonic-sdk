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
from scapy.all import *
import sim_utils
import topology as T
from packet_test_utils import *
from sdk_test_case_base import *

# Network topology
IN_SLICE = T.get_device_slice(2)
IN_IFG = 0
IN_SERDES_FIRST = T.get_device_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1
OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = T.get_device_next_first_serdes(8)
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10
SWITCH_GID = 100

MAC1 = "10:11:11:11:11:11"
MAC2 = "20:22:22:22:22:22"
MAC3 = "30:33:33:33:33:33"
MAC4 = "40:44:44:44:44:44"
VLAN = 0xAB9

# Ingress QoS fields
IN_PCPDEI = sdk.la_vlan_pcpdei()
IN_PCPDEI.fields.pcp = 2
IN_PCPDEI.fields.dei = 1

# Intermediate tags
TAG_PCPDEI = sdk.la_vlan_pcpdei()
TAG_PCPDEI.fields.pcp = 6
TAG_PCPDEI.fields.dei = 1

# Egress QoS fields
OUT_PCPDEI = sdk.la_vlan_pcpdei()
OUT_PCPDEI.fields.pcp = 3
OUT_PCPDEI.fields.dei = 0

# Unchanged QoS fields
IP_TOS = sdk.la_ip_tos()
IP_TOS.fields.dscp = 35
IP_TOS.fields.ecn = 2

# Meter set size
METER_SET_SIZE = 8


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_trunk_per_ifg_meter(sdk_test_case_base):

    def setUp(self):
        super().setUp(create_default_topology=False)

        # MATILDA_SAVE -- need review
        global OUT_SLICE, IN_SLICE
        IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [2, 3])
        OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [4, 1])

        self.create_network_topology()
        self.meter = T.create_meter_set(self, self.device, is_aggregate=True, set_size=METER_SET_SIZE)

    def create_network_topology(self):
        if not any(self.topology.inject_ports):
            self.topology.create_inject_ports()

        # Create qos profiles
        self.ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        self.egress_qos_profile = T.egress_qos_profile(self, self.device)

        # Create a switch with to L2-AC ports
        self.sw1 = T.switch(self, self.device, SWITCH_GID)
        self.ac_profile = T.ac_profile(self, self.device)

        # Add 'cafecafecafe' to the MAC table, going to AC port 2
        self.mac1 = T.mac_addr(MAC1)
        self.mac2 = T.mac_addr(MAC2)
        self.mac3 = T.mac_addr(MAC3)
        self.mac4 = T.mac_addr(MAC4)

        self.eth_port1 = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
        self.eth_port1.set_ac_profile(self.ac_profile)
        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 1,
            OUT_SERDES_FIRST,
            OUT_SERDES_LAST)
        self.eth_port2.set_ac_profile(self.ac_profile)

        self.ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port1,
            self.mac1,
            VLAN,
            0x0,
            self.ingress_qos_profile,
            self.egress_qos_profile)

        self.ac_port2 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port2,
            self.mac2,
            VLAN,
            0x0,
            self.ingress_qos_profile,
            self.egress_qos_profile)

        self.ac_port3 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 2,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port1,
            self.mac3,
            VLAN + 1,
            0x0,
            self.ingress_qos_profile,
            self.egress_qos_profile)

        self.ac_port4 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 3,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port2,
            self.mac4,
            VLAN + 1,
            0x0,
            self.ingress_qos_profile,
            self.egress_qos_profile)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 0
        eve.pcpdei_rewrite_only = True

        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)
        self.ac_port4.hld_obj.set_egress_vlan_edit_command(eve)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_trunk_per_ifg_meter(self):
        in_packet_base1 = Ether(dst=MAC2, src=MAC1, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=IN_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()
        out_packet_base1 = Ether(dst=MAC2, src=MAC1, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=OUT_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()
        self.in_packet1, self.out_packet1 = pad_input_and_output_packets(in_packet_base1, out_packet_base1)

        in_packet_base2 = Ether(dst=MAC4, src=MAC3, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN + 1, pcpdei=IN_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()
        out_packet_base2 = Ether(dst=MAC4, src=MAC3, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN + 1, pcpdei=OUT_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()
        self.in_packet2, self.out_packet2 = pad_input_and_output_packets(in_packet_base2, out_packet_base2)

        # Configure QoS profiles
        encap_qos_values = sdk.encapsulating_headers_qos_values()
        self.ingress_qos_profile.hld_obj.set_qos_tag_mapping_pcpdei(IN_PCPDEI, TAG_PCPDEI)
        self.egress_qos_profile.hld_obj.set_qos_tag_mapping_pcpdei(TAG_PCPDEI, OUT_PCPDEI, encap_qos_values)

        # Enable metering
        for pcp in range(0, 8):
            pcpdei = sdk.la_vlan_pcpdei()
            pcpdei.fields.pcp = pcp
            pcpdei.fields.dei = 1
            self.ingress_qos_profile.hld_obj.set_metering_enabled_mapping(pcpdei, True)
            self.ingress_qos_profile.hld_obj.set_meter_or_counter_offset_mapping(pcpdei, pcp)

        # Attach PER_IFG_EXACT_METER on AC1 & AC3.
        self.ac_port1.hld_obj.set_meter(self.meter)
        self.ac_port3.hld_obj.set_meter(self.meter)

        # Traffic test with AC1 & AC3.
        run_and_compare(self, self.device, self.in_packet1,
                        IN_SLICE, IN_IFG, IN_SERDES_FIRST, self.out_packet1,
                        OUT_SLICE, OUT_IFG, OUT_SERDES_FIRST)

        run_and_compare(self, self.device, self.in_packet2,
                        IN_SLICE, IN_IFG, IN_SERDES_FIRST, self.out_packet2,
                        OUT_SLICE, OUT_IFG, OUT_SERDES_FIRST)

        (pkts, bytes) = self.meter.read(2, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(pkts, 2)


if __name__ == '__main__':
    unittest.main()
