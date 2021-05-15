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
from leaba import sdk
import topology as T
from sdk_test_case_base import *
import sim_utils

IN_SLICE = T.get_device_slice(2)
IN_IFG = 0
IN_SERDES_FIRST = 4
IN_SERDES_LAST = IN_SERDES_FIRST + 1

OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = 8
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

OUT_SLICE1 = T.get_device_slice(1)
OUT_IFG1 = 0
OUT_SERDES_FIRST1 = 12
OUT_SERDES_LAST1 = OUT_SERDES_FIRST1 + 1

OUT_SLICE2 = OUT_SLICE
OUT_IFG2 = OUT_IFG
OUT_SERDES_FIRST2 = 12
OUT_SERDES_LAST2 = OUT_SERDES_FIRST2 + 1

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

SWITCH_GID = 100

DST_MAC = 'ca:fe:ca:fe:ca:fe'
SRC_MAC = 'de:ad:de:ad:de:ad'
VLAN = 0xAB9

MC_GROUP_GID = 0x13

MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')

# QoS remarking
# Ingress QoS fields
IN_PCPDEI = sdk.la_vlan_pcpdei()
IN_PCPDEI.fields.pcp = 2
IN_PCPDEI.fields.dei = 1

IN_PCPDEI_1 = sdk.la_vlan_pcpdei()
IN_PCPDEI_1.fields.pcp = 5
IN_PCPDEI_1.fields.dei = 1

# Intermediate tags
TAG_PCPDEI = sdk.la_vlan_pcpdei()
TAG_PCPDEI.fields.pcp = 6
TAG_PCPDEI.fields.dei = 1

# Egress QoS fields
OUT_PCPDEI = sdk.la_vlan_pcpdei()
OUT_PCPDEI.fields.pcp = 3
OUT_PCPDEI.fields.dei = 0

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

# Unchanged QoS fields
IP_TOS = sdk.la_ip_tos()
IP_TOS.fields.dscp = 35
IP_TOS.fields.ecn = 2


class test_l2_multicast_qos_remark(sdk_test_case_base):

    def setUp(self):
        super().setUp()

        # MATILDA_SAVE -- need review
        global OUT_SLICE, IN_SLICE, OUT_SLICE1, OUT_SLICE2
        IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [2, 3])
        OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [4, 0])
        OUT_SLICE1 = T.choose_active_slices(self.device, OUT_SLICE1, [1, 5])
        OUT_SLICE2 = OUT_SLICE

        # Create multicast group
        self.mc_group = self.device.create_l2_multicast_group(MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.mc_group)

        # Create switch
        self.sw1 = T.switch(self, self.device, 100)
        self.sw1.hld_obj.set_flood_destination(self.mc_group)

        # Get the topology-assigned default ingress/egress qos profiles
        self.ingress_qos_profile_def = self.topology.ingress_qos_profile_def
        self.egress_qos_profile_def = self.topology.egress_qos_profile_def

        # Create input AC port
        self.in_eth_port = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
        self.ac_profile = T.ac_profile(self, self.device)
        self.in_eth_port.set_ac_profile(self.ac_profile)

        self.in_ac_port = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            None,
            self.in_eth_port,
            None,
            VLAN,
            0x0,
            self.ingress_qos_profile_def,
            self.egress_qos_profile_def)

        self.eve = sdk.la_vlan_edit_command()
        self.eve.num_tags_to_push = 0
        self.eve.num_tags_to_pop = 0
        self.eve.pcpdei_rewrite_only = True

        # Create 2 output system-ports
        self.out_mac_port1 = T.mac_port(self, self.device, OUT_SLICE, OUT_IFG, OUT_SERDES_FIRST, OUT_SERDES_LAST)
        self.out_sys_port1 = T.system_port(self, self.device, SYS_PORT_GID_BASE + 1, self.out_mac_port1)

        self.out_mac_port2 = T.mac_port(self, self.device, OUT_SLICE1, OUT_IFG1, OUT_SERDES_FIRST1, OUT_SERDES_LAST1)
        self.out_sys_port2 = T.system_port(self, self.device, SYS_PORT_GID_BASE + 2, self.out_mac_port2)

        self.out_mac_port1.activate()
        self.out_mac_port2.activate()

        # Create packets
        self.create_packets()

    def create_packets(self):
        in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=IN_PCPDEI.flat) / \
            IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str,
                 dscp=IN_DSCP.value) / TCP()

        out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=OUT_PCPDEI.flat) / \
            IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str,
                 dscp=IN_DSCP.value) / TCP()

        out_packet_with_dscp_remark_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
            Dot1QPrio(vlan=VLAN, pcpdei=OUT_PCPDEI.flat) / \
            IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str,
                 dscp=OUT_DSCP.value) / TCP()

        self.in_packet, self.out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)
        __, self.out_packet_with_dscp_remark = pad_input_and_output_packets(in_packet_base, out_packet_with_dscp_remark_base)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_empty_mcg(self):
        run_and_drop(self, self.device, self.in_packet, IN_SLICE, IN_IFG, IN_SERDES_FIRST)


class dscp_qos_remarking_l2_multicast_dot1q_test(test_l2_multicast_qos_remark):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_multicast_dscp_qos_remarking(self):

        dest_mac = T.mac_addr(DST_MAC)
        self.in_ac_port.hld_obj.attach_to_switch(self.sw1.hld_obj)
        self.sw1.hld_obj.set_mac_entry(dest_mac.hld_obj, self.mc_group, sdk.LA_MAC_AGING_TIME_NEVER)

        # Create qos profiles
        ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        ingress_qos_profile.hld_obj.set_qos_tag_mapping_enabled(True)
        egress_qos_profile = T.egress_qos_profile(self, self.device)

        # Prepare remarking of IN_DSCP -> OUT_DSCP
        self.encap_qos_values_new = sdk.encapsulating_headers_qos_values()
        self.encap_qos_values_new.pcpdei = OUT_PCPDEI

        ingress_qos_profile.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV4, IN_DSCP, TAG_IP_DSCP)
        ingress_qos_profile.hld_obj.set_qos_tag_mapping_dscp(sdk.la_ip_version_e_IPV6, IN_DSCP, TAG_IP_DSCP)
        egress_qos_profile.hld_obj.set_qos_tag_mapping_dscp(TAG_IP_DSCP, OUT_DSCP, self.encap_qos_values_new)

        # Assign new profiles
        self.in_ac_port.hld_obj.set_ingress_qos_profile(ingress_qos_profile.hld_obj)

        # Configure AC profile
        # PORT VLAN
        pvf = sdk.la_packet_vlan_format_t()
        pvf.outer_vlan_is_priority = False
        pvf.tpid1 = 0x8100
        pvf.tpid2 = 0x0000

        self.ac_profile.hld_obj.set_qos_mode_per_format(pvf, sdk.la_ac_profile.qos_mode_e_L3)

        qos_mode = self.ac_profile.hld_obj.get_qos_mode_per_format(pvf)
        self.assertEqual(qos_mode, sdk.la_ac_profile.qos_mode_e_L3)

        key_sel = self.ac_profile.hld_obj.get_key_selector_per_format(pvf)
        self.assertEqual(key_sel, sdk.la_ac_profile.key_selector_e_PORT_VLAN)

        with self.assertRaises(sdk.ExistException):
            self.ac_profile.hld_obj.set_key_selector_per_format(pvf, sdk.la_ac_profile.key_selector_e_PORT_VLAN)

        # Create 2 output AC ports
        eth_port1 = T.sa_ethernet_port(self, self.device, self.out_sys_port1)
        ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.sw1,
            eth_port1,
            None,
            VLAN,
            0x0,
            self.ingress_qos_profile_def,
            egress_qos_profile)

        eth_port2 = T.sa_ethernet_port(self, self.device, self.out_sys_port2)
        ac_port2 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 2,
            self.topology.filter_group_def,
            self.sw1,
            eth_port2,
            None,
            VLAN + 1,
            0x0,
            self.ingress_qos_profile_def,
            egress_qos_profile)

        ac_port1.hld_obj.set_egress_vlan_edit_command(self.eve)
        ac_port2.hld_obj.set_egress_vlan_edit_command(self.eve)

        # Add the output AC ports to the MC group
        self.mc_group.add(ac_port1.hld_obj, self.out_sys_port1.hld_obj)
        self.mc_group.add(ac_port2.hld_obj, self.out_sys_port2.hld_obj)

        # Run the packet and check results
        ingress_packet = {'data': self.in_packet, 'slice': IN_SLICE, 'ifg': IN_IFG, 'pif': IN_SERDES_FIRST}
        expected_packets = []
        expected_packets.append({'data': self.out_packet_with_dscp_remark, 'slice': OUT_SLICE1,
                                 'ifg': OUT_IFG1, 'pif': OUT_SERDES_FIRST1})
        expected_packets.append({'data': self.out_packet_with_dscp_remark,
                                 'slice': OUT_SLICE, 'ifg': OUT_IFG, 'pif': OUT_SERDES_FIRST})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)


class ipv4_test:
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    ipvx = 'v4'


class ipv6_test:
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
    ipvx = 'v6'


if __name__ == '__main__':
    unittest.main()
