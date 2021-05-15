#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

ZERO_PCPDEI = sdk.la_vlan_pcpdei()
ZERO_PCPDEI.fields.pcp = 0
ZERO_PCPDEI.fields.dei = 0

# Unchanged QoS fields
IP_TOS = sdk.la_ip_tos()
IP_TOS.fields.dscp = 35
IP_TOS.fields.ecn = 2

# Markdown PCP
MARKDOWN_PCP = sdk.la_vlan_pcpdei()
MARKDOWN_PCP.fields.pcp = 1
MARKDOWN_PCP.fields.dei = 1

# Expected markdown PCP
EXPECTED_MARKDOWN_PCP = sdk.la_vlan_pcpdei()
EXPECTED_MARKDOWN_PCP.fields.pcp = 3
EXPECTED_MARKDOWN_PCP.fields.dei = 0

# QoS color list
COLOR_LST = [sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_RED]


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_l2_qos_remark_base(sdk_test_case_base):

    def setUp(self):
        super().setUp(create_default_topology=False)
        # MATILDA_SAVE -- need review
        global OUT_SLICE, IN_SLICE
        IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [2, 3])
        OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [4, 1])

        self.create_network_topology()
        self.topology.create_inject_ports()
        self._add_objects_to_keep()

    def create_network_topology(self):
        # Create qos profiles
        self.ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        self.egress_qos_profile = T.egress_qos_profile(self, self.device)

        # Create a switch with to L2-AC ports
        self.sw1 = T.switch(self, self.device, SWITCH_GID)
        self.ac_profile = T.ac_profile(self, self.device)

        # Add 'cafecafecafe' to the MAC table, going to AC port 2
        self.dest_mac = T.mac_addr(DST_MAC)

        self.eth_port1 = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
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
            VLAN,
            0x0,
            self.ingress_qos_profile,
            self.egress_qos_profile)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 0
        eve.pcpdei_rewrite_only = True

        self.ac_port2.hld_obj.set_egress_vlan_edit_command(eve)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_meter_markdown_mapping_pcpdei_ext(self):
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=IN_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()
        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=EXPECTED_MARKDOWN_PCP.flat) / \
            IP(tos=IP_TOS.flat) / TCP()
        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

        self.ingress_qos_profile_new = T.ingress_qos_profile(self, self.device)
        self.egress_qos_profile_new = T.egress_qos_profile(self, self.device)

        # Configure ingress QoS profile
        self.ac_port1.hld_obj.set_ingress_qos_profile(self.ingress_qos_profile_new.hld_obj)
        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_pcpdei(IN_PCPDEI, TAG_PCPDEI)

        # Configure egress QoS profile
        encap_qos_values = sdk.encapsulating_headers_qos_values()
        encap_qos_values.pcpdei.fields.pcp = 1
        encap_qos_values.tos.fields.dscp = 1
        encap_qos_values.tc.value = 1
        encap_qos_values.use_for_inner_labels = False
        self.egress_qos_profile_new.hld_obj.set_qos_tag_mapping_pcpdei(MARKDOWN_PCP, OUT_PCPDEI, encap_qos_values)
        self.ac_port2.hld_obj.set_egress_qos_profile(self.egress_qos_profile_new.hld_obj)

        # Configure meter markdown profile table
        meter_markdown_gid = 0
        for profile in range(0, 1):
            meter_markdown_profile = self.device.create_meter_markdown_profile(meter_markdown_gid)
            meter_markdown_gid += 1
            for color in COLOR_LST:
                self.ingress_qos_profile_new.hld_obj.set_color_mapping(IN_PCPDEI, color)
                for pcp in range(0, 8):
                    for dei in range(0, 2):
                        from_pcpdei_tag = sdk.la_vlan_pcpdei()
                        from_pcpdei_tag.fields.pcp = pcp
                        from_pcpdei_tag.fields.dei = dei
                        to_pcpdei_tag = sdk.la_vlan_pcpdei()
                        to_pcpdei_tag.fields.pcp = 7 - pcp
                        to_pcpdei_tag.fields.dei = dei
                        meter_markdown_profile.set_meter_markdown_mapping_pcpdei(
                            color, from_pcpdei_tag, to_pcpdei_tag)
                        pcpdei_tag = meter_markdown_profile.get_meter_markdown_mapping_pcpdei(
                            color, from_pcpdei_tag)
                        self.assertEqual(to_pcpdei_tag.fields.pcp, pcpdei_tag.fields.pcp)
                        self.assertEqual(to_pcpdei_tag.fields.dei, pcpdei_tag.fields.dei)

                # Program meter profile selection table
                self.ingress_qos_profile_new.hld_obj.set_meter_markdown_profile(meter_markdown_profile)
                meter_markdown_profile_new = self.ingress_qos_profile_new.hld_obj.get_meter_markdown_profile()
                self.assertEqual(meter_markdown_profile.this, meter_markdown_profile_new.this)

                # Traffic test
                out_serdes = 0 if decor.is_asic5() else OUT_SERDES_FIRST
                run_and_compare(
                    self,
                    self.device,
                    self.in_packet,
                    IN_SLICE,
                    IN_IFG,
                    IN_SERDES_FIRST,
                    self.out_packet,
                    OUT_SLICE,
                    OUT_IFG,
                    out_serdes)

            # Clean-up meter markdown profile table
            self.ingress_qos_profile_new.hld_obj.clear_meter_markdown_profile()
            self.device.destroy(meter_markdown_profile)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_packet_qos_remarking(self):
        # Prepare remarking of IN_PCPDEI -> OUT_PCPDEI
        encap_qos_values = sdk.encapsulating_headers_qos_values()
        self.ingress_qos_profile.hld_obj.set_qos_tag_mapping_pcpdei(IN_PCPDEI, TAG_PCPDEI)
        self.egress_qos_profile.hld_obj.set_qos_tag_mapping_pcpdei(TAG_PCPDEI, OUT_PCPDEI, encap_qos_values)

        # Prepare packets
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=IN_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=OUT_PCPDEI.flat) / \
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

    @unittest.skipIf(decor.is_asic5(), "Test is failing on AR: PRIO")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_get_qos_profile(self):
        # Prepare remarking of IN_PCPDEI -> ZERO_PCPDEI in the initial profiles
        encap_qos_values = sdk.encapsulating_headers_qos_values()
        self.ingress_qos_profile.hld_obj.set_qos_tag_mapping_pcpdei(IN_PCPDEI, ZERO_PCPDEI)
        self.egress_qos_profile.hld_obj.set_qos_tag_mapping_pcpdei(ZERO_PCPDEI, ZERO_PCPDEI, encap_qos_values)

        in_packet_initial_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=IN_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        out_packet_initial_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=ZERO_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        in_packet_initial, out_packet_initial = pad_input_and_output_packets(in_packet_initial_base, out_packet_initial_base)

        # Create new qos profiles
        ingress_qos_profile_new = T.ingress_qos_profile(self, self.device)
        egress_qos_profile_new = T.egress_qos_profile(self, self.device)

        # Prepare remarking of IN_PCPDEI -> OUT_PCPDEI in the new qos profiles
        encap_qos_values = sdk.encapsulating_headers_qos_values()
        ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_pcpdei(IN_PCPDEI, TAG_PCPDEI)
        egress_qos_profile_new.hld_obj.set_qos_tag_mapping_pcpdei(TAG_PCPDEI, OUT_PCPDEI, encap_qos_values)

        # Test remarking using the initial qos profiles
        out_serdes = 0 if decor.is_asic5() else OUT_SERDES_FIRST
        run_and_compare(
            self,
            self.device,
            in_packet_initial,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet_initial,
            OUT_SLICE,
            OUT_IFG,
            out_serdes)

        # Assign new profiles
        self.ac_port1.hld_obj.set_ingress_qos_profile(ingress_qos_profile_new.hld_obj)
        self.ac_port2.hld_obj.set_egress_qos_profile(egress_qos_profile_new.hld_obj)

        # Verify that the new profiles are updated
        in_packet_new_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=IN_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        out_packet_new_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=OUT_PCPDEI.flat) / \
            IP(tos=IP_TOS.flat) / TCP()

        in_packet_new, out_packet_new = pad_input_and_output_packets(in_packet_new_base, out_packet_new_base)

        run_and_compare(
            self,
            self.device,
            in_packet_new,
            IN_SLICE,
            IN_IFG,
            IN_SERDES_FIRST,
            out_packet_new,
            OUT_SLICE,
            OUT_IFG,
            OUT_SERDES_FIRST)

        # Test getting the new profiles
        retrieved_ingress_profile = self.ac_port1.hld_obj.get_ingress_qos_profile()
        self.assertEqual(retrieved_ingress_profile.this, ingress_qos_profile_new.hld_obj.this)

        retrieved_egress_profile = self.ac_port2.hld_obj.get_egress_qos_profile()
        self.assertEqual(retrieved_egress_profile.this, egress_qos_profile_new.hld_obj.this)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_meter_and_counter_profile(self):

        # Create a meter-set with set-size 1
        meter0 = self.device.create_meter(sdk.la_meter_set.type_e_EXACT, 1)

        # Create a meter-profile
        meter0_prof = self.device.create_meter_profile(
            sdk.la_meter_profile.type_e_GLOBAL,
            sdk.la_meter_profile.meter_measure_mode_e_BYTES,
            sdk.la_meter_profile.meter_rate_mode_e_SR_TCM,
            sdk.la_meter_profile.color_awareness_mode_e_AWARE)
        meter0_prof.set_cbs(1024)
        meter0_prof.set_ebs_or_pbs(1024)
        action_prof = self.device.create_meter_action_profile()

        # Set profile to meter in the meter-set
        meter0.set_committed_bucket_coupling_mode(0, sdk.la_meter_set.coupling_mode_e_TO_EXCESS_BUCKET)
        meter0.set_meter_profile(0, meter0_prof)
        meter0.set_meter_action_profile(0, action_prof)
        meter0.set_cir(0, 70000000000)

        # Attach ac_port1 to the meter set
        self.ac_port1.hld_obj.set_meter(meter0)

        # Attach ac_port1 to a counter
        counter = self.device.create_counter(8)
        self.ac_port1.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, counter)


if __name__ == '__main__':
    unittest.main()
