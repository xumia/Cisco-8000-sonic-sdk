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

from packet_test_utils import *
from scapy.all import *
import unittest
import sys
from leaba import sdk
import sim_utils
import topology as T
from sdk_test_case_base import *
import decor

# Network topology
IN_SLICE = T.get_device_slice(2)
IN_IFG = 0
IN_SERDES_FIRST = T.get_device_first_serdes(4)
IN_SERDES_LAST = IN_SERDES_FIRST + 1
OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = T.get_device_out_first_serdes(8)
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

SWITCH_GID = 100

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"

DST_MAC2 = "de:ad:de:ad:de:ad"
SRC_MAC2 = "ca:fe:ca:fe:ca:fe"

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
OUT_PCPDEI = sdk.la_vlan_pcpdei()
OUT_PCPDEI.fields.pcp = 3
OUT_PCPDEI.fields.dei = 0

# Unchanged QoS fields
IP_TOS = sdk.la_ip_tos()
IP_TOS.fields.dscp = 35
IP_TOS.fields.ecn = 2

# C-Vlan Tag Pcpdei
C_PCPDEI = sdk.la_vlan_pcpdei()
C_PCPDEI.fields.pcp = 4
C_PCPDEI.fields.dei = 1

# Pcpdei for Pipe mode
IN_PACKET_PCPDEI = sdk.la_vlan_pcpdei()
IN_PACKET_PCPDEI.fields.pcp = 5
IN_PACKET_PCPDEI.fields.dei = 1


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_l2_qos_remark_qinq_tunnel_base(sdk_test_case_base):

    def setUp(self):
        super().setUp(True)
        # MATILDA_SAVE -- need review
        global OUT_SLICE, IN_SLICE
        IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [2, 3])
        OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [4, 1])
        self.create_network_topology()

    def tearDown(self):
        super().tearDown()

    def create_network_topology(self):
        # Create qos profiles
        self.ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        self.egress_qos_profile = T.egress_qos_profile(self, self.device)

        self.ingress_qos_profile.hld_obj.set_qos_tag_mapping_pcpdei(IN_PCPDEI, TAG_PCPDEI)

        # Prepare remarking of IN_PCPDEI -> OUT_PCPDEI
        encap_qos_values = sdk.encapsulating_headers_qos_values()
        self.egress_qos_profile.hld_obj.set_qos_tag_mapping_pcpdei(TAG_PCPDEI, OUT_PCPDEI, encap_qos_values)

        # Create a switch with to L2-AC ports
        self.sw1 = T.switch(self, self.device, SWITCH_GID)
        self.ac_profile = T.ac_profile(self, self.device)

        # Add 'cafecafecafe' to the MAC table, going to AC port 2
        self.dest_mac = T.mac_addr(DST_MAC)
        self.src_mac = T.mac_addr(SRC_MAC)

        self.eth_port1 = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
        self.eth_port1.set_ac_profile(self.ac_profile)
        self.ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port1,
            self.src_mac,
            VLAN,
            0x0,
            self.ingress_qos_profile,
            self.egress_qos_profile)

        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            OUT_SLICE,
            OUT_IFG,
            SYS_PORT_GID_BASE + 1,
            OUT_SERDES_FIRST,
            OUT_SERDES_LAST)
        self.eth_port2.set_ac_profile(self.ac_profile)
        self.ac_port2 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.sw1,
            self.eth_port2,
            self.dest_mac,
            VLAN + 1,
            0x0,
            self.ingress_qos_profile,
            self.egress_qos_profile)

        # IVE command for tunnel egress.
        self.ive = sdk.la_vlan_edit_command()
        self.ive.num_tags_to_push = 0
        self.ive.num_tags_to_pop = 1

        # EVE command for tunnel ingress.
        self.eve = sdk.la_vlan_edit_command()
        self.eve.num_tags_to_push = 1
        self.eve.num_tags_to_pop = 0
        self.eve.tag0.tpid = 0x8100
        self.eve.tag0.tci.fields.vid = VLAN + 1

        # EVE command for tunnel egress.
        self.eve_egr = sdk.la_vlan_edit_command()
        self.eve_egr.num_tags_to_push = 0
        self.eve_egr.num_tags_to_pop = 0
        self.eve_egr.pcpdei_rewrite_only = True

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_packet_qos_remarking_qinq_uniform_ingress(self):

        # Set EVE command on the Tx port.
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(self.eve)

        # Prepare packets
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=IN_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN + 1, type=Ethertype.Dot1Q.value, pcpdei=OUT_PCPDEI.flat) / \
            Dot1QPrio(vlan=VLAN, pcpdei=IN_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_packet_qos_remarking_qinq_pipe_ingress(self):

        # Set port default pcpdei on the Rx port.
        self.eth_port1.hld_obj.set_ingress_default_pcpdei(IN_PCPDEI)

        # Configure AC profile
        # PORT VLAN
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x8100
        pvf.tpid2 = 0x0000

        # Enable default port pcpdei on the Tx port.
        self.ac_profile.hld_obj.set_default_pcpdei_per_format_enabled(pvf, True)

        # Set EVE command on the Tx port.
        self.ac_port2.hld_obj.set_egress_vlan_edit_command(self.eve)

        # Prepare packets
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=IN_PACKET_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN + 1, type=Ethertype.Dot1Q.value, pcpdei=OUT_PCPDEI.flat) / \
            Dot1QPrio(vlan=VLAN, pcpdei=IN_PACKET_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_packet_qos_remarking_qinq_uniform_egress(self):

        # Set IVE command on the Rx port.
        self.ac_port2.hld_obj.set_ingress_vlan_edit_command(self.ive)

        # Set EVE command on the Tx port.
        self.ac_port1.hld_obj.set_egress_vlan_edit_command(self.eve_egr)

        # Prepare packets
        in_packet_base = Ether(dst=DST_MAC2, src=SRC_MAC2, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN + 1, type=Ethertype.Dot1Q.value, pcpdei=IN_PCPDEI.flat) / \
            Dot1QPrio(vlan=VLAN, pcpdei=C_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        out_packet_base = Ether(dst=DST_MAC2, src=SRC_MAC2, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=OUT_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST,
            out_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_packet_qos_remarking_qinq_pipe_egress(self):

        # Set port default pcpdei on the Rx port.
        self.eth_port2.hld_obj.set_ingress_default_pcpdei(IN_PCPDEI)

        # Configure AC profile
        # PORT VLAN
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x8100
        pvf.tpid2 = 0x0000

        # Enable default port pcpdei on the Tx port.
        self.ac_profile.hld_obj.set_default_pcpdei_per_format_enabled(pvf, True)

        # Set IVE command on the Rx port.
        self.ac_port2.hld_obj.set_ingress_vlan_edit_command(self.ive)

        # Set EVE command on the Tx port.
        self.eve_egr.pcpdei_rewrite_only = False
        self.ac_port1.hld_obj.set_egress_vlan_edit_command(self.eve_egr)

        # Prepare packets
        in_packet_base = Ether(dst=DST_MAC2, src=SRC_MAC2, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN + 1, type=Ethertype.Dot1Q.value, pcpdei=IN_PACKET_PCPDEI.flat) / \
            Dot1QPrio(vlan=VLAN, pcpdei=C_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        out_packet_base = Ether(dst=DST_MAC2, src=SRC_MAC2, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=C_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        run_and_compare(
            self,
            self.device,
            in_packet,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST,
            out_packet,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST)


if __name__ == '__main__':
    unittest.main()
