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
import ip_test_base
from sdk_test_case_base import *

# Network topology
IN_SLICE = T.get_device_slice(2)
IN_IFG = 0
IN_SERDES_FIRST = 4
IN_SERDES_LAST = IN_SERDES_FIRST + 1
OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = 8
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

# Forwarding headers
IN_DSCP = sdk.la_ip_dscp()
IN_DSCP.value = 48

# Intermediate tags
TAG_IP_DSCP = sdk.la_ip_dscp()
TAG_IP_DSCP.value = 60

TAG_DUMMY_IP_DSCP = sdk.la_ip_dscp()
TAG_DUMMY_IP_DSCP.value = 50

# Counter
QOS_COUNTER_SET_SIZE = 32
QOS_COUNTER_OFFSET = 17

# Egress QoS fields
# Forwarding headers
OUT_DSCP = sdk.la_ip_dscp()
OUT_DSCP.value = 63

ZERO_DSCP = sdk.la_ip_dscp()
ZERO_DSCP.value = 0

# Egress QoS fields
OUT_PCPDEI = sdk.la_vlan_pcpdei()
OUT_PCPDEI.fields.pcp = 3
OUT_PCPDEI.fields.dei = 0


class test_dscp_qos_remark_base(sdk_test_case_base):

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

        # Create new ingress/egress qos profiles
        self.ingress_qos_profile_new = T.ingress_qos_profile(self, self.device)
        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(True)
        self.egress_qos_profile_new = T.egress_qos_profile(self, self.device)

        # Prepare remarking of IN_DSCP -> OUT_DSCP
        self.encap_qos_values_new = sdk.encapsulating_headers_qos_values()
        self.encap_qos_values_new.pcpdei = OUT_PCPDEI

        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, IN_DSCP, TAG_IP_DSCP)
        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV6, IN_DSCP, TAG_IP_DSCP)
        self.egress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(TAG_IP_DSCP, OUT_DSCP, self.encap_qos_values_new)

        # Get the topology-assigned default ingress/egress qos profiles
        ingress_qos_profile_def = self.topology.ingress_qos_profile_def
        egress_qos_profile_def = self.topology.egress_qos_profile_def

        # Write to the same entries in the topology qos profiles, just to make
        # sure the values don't overwrite the entries in the new profiles.
        encap_qos_values_def = sdk.encapsulating_headers_qos_values()

        ingress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, IN_DSCP, TAG_DUMMY_IP_DSCP)
        ingress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV6, IN_DSCP, TAG_DUMMY_IP_DSCP)
        egress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(
            TAG_IP_DSCP, ZERO_DSCP, encap_qos_values_def)

        self.ingress_qos_profile_new.hld_obj.set_meter_or_counter_offset_mapping(
            sdk.la_ip_version_e_IPV4, IN_DSCP, QOS_COUNTER_OFFSET)
        self.ingress_qos_profile_new.hld_obj.set_meter_or_counter_offset_mapping(
            sdk.la_ip_version_e_IPV6, IN_DSCP, QOS_COUNTER_OFFSET)

        # Create a switch with to L2-AC ports
        self.sw1 = T.switch(self, self.device, SWITCH_GID)
        self.ac_profile = T.ac_profile(self, self.device)

        # Configure default AC profile
        ac_profile = self.device.create_ac_profile()
        self.assertIsNotNone(self.ac_profile)

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
            None,
            0x0,
            0x0,
            self.ingress_qos_profile_new,
            self.egress_qos_profile_new)

        # Prepare q_counter for ingress
        self.q_counter = self.device.create_counter(QOS_COUNTER_SET_SIZE)
        self.ac_port1.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, self.q_counter)

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
            0x0,
            0x0,
            self.ingress_qos_profile_new,
            self.egress_qos_profile_new)


class dscp_qos_remarking_untagged_packet_test(test_dscp_qos_remark_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_dscp_qos_remarking_untagged_packet(self):

        # Configure AC profile
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x0000
        pvf.tpid2 = 0x0000

        self.ac_profile.hld_obj.set_qos_mode_per_format(pvf, sdk.la_ac_profile.qos_mode_e_L3)

        qos_mode = self.ac_profile.hld_obj.get_qos_mode_per_format(pvf)
        self.assertEqual(qos_mode, sdk.la_ac_profile.qos_mode_e_L3)

        key_sel = self.ac_profile.hld_obj.get_key_selector_per_format(pvf)
        self.assertEqual(key_sel, sdk.la_ac_profile.key_selector_e_PORT)

        # Prepare an untagged packet
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC) / \
            IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str,
                 ttl=self.TTL, dscp=IN_DSCP.value) / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC) / \
            IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str,
                 ttl=self.TTL, dscp=OUT_DSCP.value) / TCP()

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

        # Check counter
        packets, bytes = self.q_counter.read(QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packets, 1)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_dscp_qos_remarking_ecn_set_CSCvx31641(self):

        # Configure AC profile
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x0000
        pvf.tpid2 = 0x0000

        self.ac_profile.hld_obj.set_qos_mode_per_format(pvf, sdk.la_ac_profile.qos_mode_e_L3)

        qos_mode = self.ac_profile.hld_obj.get_qos_mode_per_format(pvf)
        self.assertEqual(qos_mode, sdk.la_ac_profile.qos_mode_e_L3)

        key_sel = self.ac_profile.hld_obj.get_key_selector_per_format(pvf)
        self.assertEqual(key_sel, sdk.la_ac_profile.key_selector_e_PORT)

        IN_TOS = sdk.la_ip_tos()
        IN_TOS.fields.ecn = 1
        IN_TOS.fields.dscp = 48

        OUT_TOS = sdk.la_ip_tos()
        OUT_TOS.fields.ecn = 1
        OUT_TOS.fields.dscp = 63

        # Prepare an untagged packet, with ToS ECN bit set.
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC) / \
            IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str,
                 ttl=self.TTL, tos=IN_TOS.flat) / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC) / \
            IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str,
                 ttl=self.TTL, tos=OUT_TOS.flat) / TCP()

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


class ipv4_test:
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    TTL = 128
    ipvx = 'v4'


class ipv6_test:
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
    TTL = 128
    ipvx = 'v6'


if __name__ == '__main__':
    unittest.main()
