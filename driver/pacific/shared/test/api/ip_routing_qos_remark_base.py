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
import sys
import unittest
from leaba import sdk
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
from sdk_test_case_base import *


class ip_routing_qos_remark_test(sdk_test_case_base):
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    OUTPUT_VID = 0xac

    # QoS remarking
    # Ingress QoS fields
    # Terminated headers
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

    # Egress QoS fields
    # Forwarding headers
    OUT_DSCP = sdk.la_ip_dscp()
    OUT_DSCP.value = 63

    ZERO_DSCP = sdk.la_ip_dscp()
    ZERO_DSCP.value = 0

    # Encapsulating headers
    OUT_PCPDEI = sdk.la_vlan_pcpdei()
    OUT_PCPDEI.fields.pcp = 5
    OUT_PCPDEI.fields.dei = 1

    # IP ECN field
    IP_ECN = 2

    def setUp(self):
        super().setUp()
        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.add_default_route()
        self.create_packets()
        self.set_egress_tag_mode()
        self.set_l2_egress_vlan_tag()

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, self.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = self.ip_impl.get_default_prefix()
            self.ip_impl.delete_route(self.topology.vrf, prefix)
            self.has_default_route = False

    def route_single_fec(self):
        self.set_counter()
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if(self.l3_port_impl.is_svi):
            packet_count, byte_count = self.l2_ingress_qcounter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            packet_count, byte_count = self.l2_egress_qcounter.read(0, True, True)
            self.assertEqual(packet_count, 1)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_forwarding_header_qos_remarking(self):
        # Use the topology-assigned default ingress/egress qos profiles
        ingress_qos_profile_def = self.topology.ingress_qos_profile_def
        egress_qos_profile_def = self.topology.egress_qos_profile_def

        # Prepare remarking of IN_DSCP -> OUT_DSCP
        encap_qos_values = sdk.encapsulating_headers_qos_values()
        encap_qos_values.pcpdei = self.OUT_PCPDEI

        ingress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, self.IN_DSCP, self.TAG_IP_DSCP)
        ingress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV6, self.IN_DSCP, self.TAG_IP_DSCP)
        egress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(self.TAG_IP_DSCP, self.OUT_DSCP, encap_qos_values)

        # Test a packet using the QoS mapping
        self.route_single_fec()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ecn_remark_control(self):
        # By default ECN packet stamping is OFF
        self.assertEqual(self.l3_port_impl.tx_port.hld_obj.get_ecn_remark_enabled(), False)

        self.l3_port_impl.tx_port.hld_obj.set_ecn_remark_enabled(True)
        self.assertEqual(self.l3_port_impl.tx_port.hld_obj.get_ecn_remark_enabled(), True)

        self.l3_port_impl.tx_port.hld_obj.set_ecn_remark_enabled(False)
        self.assertEqual(self.l3_port_impl.tx_port.hld_obj.get_ecn_remark_enabled(), False)

    def set_egress_tag_mode(self):
        if self.egress_tagged_mode:
            tag = sdk.la_vlan_tag_t()
            tag.tpid = 0x8100
            tag.tci.fields.pcp = 0
            tag.tci.fields.dei = 0
            tag.tci.fields.vid = self.OUTPUT_VID

            self.l3_port_impl.tx_port.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

    def set_l2_egress_vlan_tag(self):
        if self.egress_tagged_mode:
            eve = sdk.la_vlan_edit_command()
            eve.num_tags_to_push = 1
            eve.num_tags_to_pop = 0
            eve.tag0.tpid = 0x8100
            eve.tag0.tci.fields.vid = self.OUTPUT_VID

            self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_vlan_edit_command(eve)

    def egress_l2_headers(self, pcpdei):
        if self.egress_tagged_mode:
            return Ether(dst=self.output_ether_0_dst, src=self.output_ether_0_src, type=U.Ethertype.Dot1Q.value) / \
                U.Dot1QPrio(vlan=self.OUTPUT_VID, pcpdei=pcpdei)
        else:
            return Ether(dst=self.output_ether_0_dst, src=self.output_ether_0_src)

    def create_packets(self):
        INPUT_PACKET_BASE = S.Ether(dst=self.input_ether_0_dst,
                                    src=self.SA.addr_str,
                                    type=U.Ethertype.Dot1Q.value) / U.Dot1QPrio(vlan=self.input_dot1q_0_vlan,
                                                                                pcpdei=self.IN_PCPDEI.flat) / U.IPvX(ipvx=self.ipvx,
                                                                                                                     src=self.SIP.addr_str,
                                                                                                                     dst=self.DIP.addr_str,
                                                                                                                     ttl=self.TTL,
                                                                                                                     dscp=self.IN_DSCP.value,
                                                                                                                     ecn=self.IP_ECN) / U.TCP()

        EXPECTED_OUTPUT_PACKET_BASE = self.egress_l2_headers(
            self.OUT_PCPDEI.flat) / U.IPvX(
            ipvx=self.ipvx,
            src=self.SIP.addr_str,
            dst=self.DIP.addr_str,
            ttl=self.TTL - 1,
            dscp=self.OUT_DSCP.value,
            ecn=self.IP_ECN) / U.TCP()

        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    def set_counter(self):
        self.l2_ingress_qcounter = self.device.create_counter(sdk.LA_NUM_L2_INGRESS_TRAFFIC_CLASSES)
        self.topology.rx_l2_ac_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, self.l2_ingress_qcounter)
        self.l2_egress_qcounter = self.device.create_counter(sdk.LA_NUM_EGRESS_TRAFFIC_CLASSES)
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_QOS, self.l2_egress_qcounter)

        self.l3_ingress_pcounter = self.device.create_counter(sdk.la_l3_protocol_counter_e_LAST)
        self.l3_port_impl.rx_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.l3_ingress_pcounter)
        self.l3_egress_pcounter = self.device.create_counter(sdk.la_l3_protocol_counter_e_LAST)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l3_egress_pcounter)


class ip_routing_with_set_get_qos_profile_test(ip_routing_qos_remark_test):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_get_qos_profile(self):
        # This test should be run once per L3 type (L3-AC, SVI). No need to duplicate per IP protocol.

        # Get the topology-assigned default ingress/egress qos profiles
        ingress_qos_profile_def = self.topology.ingress_qos_profile_def
        egress_qos_profile_def = self.topology.egress_qos_profile_def

        # Create new ingress/egress qos profiles
        ingress_qos_profile_new = T.ingress_qos_profile(self, self.device)
        ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(True)
        egress_qos_profile_new = T.egress_qos_profile(self, self.device)

        # Prepare remarking of IN_DSCP -> OUT_DSCP
        encap_qos_values_new = sdk.encapsulating_headers_qos_values()
        encap_qos_values_new.pcpdei = self.OUT_PCPDEI

        ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, self.IN_DSCP, self.TAG_IP_DSCP)
        ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV6, self.IN_DSCP, self.TAG_IP_DSCP)
        egress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(self.TAG_IP_DSCP, self.OUT_DSCP, encap_qos_values_new)

        # Write to the same entries in the topology qos profiles, just to make
        # sure the values don't overwrite the entries in the new profiles.
        encap_qos_values_def = sdk.encapsulating_headers_qos_values()

        ingress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, self.IN_DSCP, self.TAG_DUMMY_IP_DSCP)
        ingress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV6, self.IN_DSCP, self.TAG_DUMMY_IP_DSCP)

        egress_qos_profile_def.hld_obj.set_qos_tag_mapping_dscp(
            self.TAG_IP_DSCP, self.ZERO_DSCP, encap_qos_values_def)

        # Assign new profiles
        rx_port = self.l3_port_impl.rx_one_tag_port
        rx_port.hld_obj.set_ingress_qos_profile(ingress_qos_profile_new.hld_obj)
        self.topology.rx_l2_ac_port.hld_obj.set_ingress_qos_profile(ingress_qos_profile_new.hld_obj)

        tx_port = self.l3_port_impl.tx_port
        tx_port.hld_obj.set_egress_qos_profile(egress_qos_profile_new.hld_obj)
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_qos_profile(egress_qos_profile_new.hld_obj)

        # Test a packet using the QoS mapping
        self.route_single_fec()

        # Test getting the new profiles
        retrieved_ingress_profile = rx_port.hld_obj.get_ingress_qos_profile()
        self.assertEqual(retrieved_ingress_profile.this, ingress_qos_profile_new.hld_obj.this)

        retrieved_egress_profile = tx_port.hld_obj.get_egress_qos_profile()
        self.assertEqual(retrieved_egress_profile.this, egress_qos_profile_new.hld_obj.this)

        # Cleanup
        # Assign the previous profiles, in order to "un-use" the new ones.
        rx_port.hld_obj.set_ingress_qos_profile(ingress_qos_profile_def.hld_obj)
        tx_port.hld_obj.set_egress_qos_profile(egress_qos_profile_def.hld_obj)
        self.topology.rx_l2_ac_port.hld_obj.set_ingress_qos_profile(ingress_qos_profile_def.hld_obj)
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_qos_profile(egress_qos_profile_def.hld_obj)
        ingress_qos_profile_new.destroy()
        egress_qos_profile_new.destroy()


class ipv4_test:
    ip_impl_class = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    ipvx = 'v4'


class ipv6_test:
    ip_impl_class = ip_test_base.ipv6_test_base
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
    ipvx = 'v6'


class rx_svi_test:
    l3_port_impl_class = T.ip_svi_base

    input_ether_0_dst = T.RX_SVI_MAC.addr_str
    input_dot1q_0_vlan = T.RX_L2_AC_PORT_VID1
    output_ether_0_dst = T.NH_SVI_REG_MAC.addr_str
    output_ether_0_src = T.TX_SVI_MAC.addr_str


class rx_l3_ac_test:
    l3_port_impl_class = T.ip_l3_ac_base

    input_ether_0_dst = T.RX_L3_AC_ONE_TAG_MAC.addr_str
    input_dot1q_0_vlan = T.RX_L3_AC_ONE_TAG_PORT_VID
    output_ether_0_dst = T.NH_L3_AC_REG_MAC.addr_str
    output_ether_0_src = T.TX_L3_AC_REG_MAC.addr_str


class egress_tagged_test:
    egress_tagged_mode = True


class egress_untagged_test:
    egress_tagged_mode = False


if __name__ == '__main__':
    unittest.main()
