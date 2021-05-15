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

import os
import sys
import unittest
from distutils.util import strtobool
from leaba import sdk
import decor
import packet_test_utils as U
import topology as T
from packet_test_defs import *
from scapy.all import *
from scapy.layers.l2 import *
from copy import deepcopy
from binascii import hexlify, unhexlify
import svl_base
from svl_base import *

U.parse_ip_after_mpls()
load_contrib('mpls')

SvlTestPair = {
    "test_mpls_standby_label_swap": "test_mpls_active_label_swap",
    "test_mpls_standby_drop_receive_disabled": "test_mpls_active_label_swap2",
    "test_mpls_standby_te_midpoint_primary": "test_mpls_active_te_midpoint_primary",
    "test_mpls_standby_single_null_vpn": "test_mpls_active_single_null_vpn",
    "test_mpls_standby_tenh_to_mpls": "test_mpls_active_tenh_to_mpls"
}


@unittest.skipIf(not decor.is_gibraltar(), "Test is applicable only on GB")
@unittest.skipIf(decor.is_matilda('3.2'), "These tests require at least 4 slices, Matilda has 3, so skip.")
class SvlBaseActive(unittest.TestCase, svl_base.SvlBaseActiveContext):
    topology_init_done = False
    base = None
    dev = None

    @classmethod
    def tearDownClass(cls):
        if SvlBaseActive.dev is not None:
            SvlBaseActive.dev.tearDown()

    def setUp(self):
        if not SvlBaseActive.topology_init_done:
            if SvlBaseActive.dev is None:
                self.base = SvlBase(self.device_id, self.remote_device_id, self.switch_num, self.active)
                self.device = SvlBase.dev
                SvlBaseActive.dev = self.device
                SvlBaseActive.base = self.base
            else:
                self.base = SvlBaseActive.base
                self.device = SvlBaseActive.dev
            self.topology = T.topology(self, self.device, create_default_topology=False)
            ingress_qos_profile = T.ingress_qos_profile(self, self.device)
            egress_qos_profile = T.egress_qos_profile(self, self.device)
            self.base.create_topology(self, ingress_qos_profile, egress_qos_profile)
            SvlBaseActive.topology_init_done = True

            SvlBaseActive.base = self.base
            self.base.stackport.set_peer_device_id(self.remote_device_id)
        self.device = SvlBase.dev
        self.base = SvlBaseActive.base

    def test_mpls_active_label_swap_local(self):
        local_l3ac = SvlBase.l3acs[3]
        local_nh = SvlBase.lnh[2]
        INPUT_LABEL = sdk.la_mpls_label()
        INPUT_LABEL.label = 0x50
        OUTPUT_LABEL = sdk.la_mpls_label()
        OUTPUT_LABEL.label = 0x55
        PRIVATE_DATA = 0x1234567890abcdef

        local_l3ac.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)
        lsr = self.device.get_lsr()
        nhlfe = self.device.create_mpls_swap_nhlfe(local_nh, OUTPUT_LABEL)

        lsr.add_route(INPUT_LABEL, nhlfe, PRIVATE_DATA)

        IN_PCPDEI = sdk.la_vlan_pcpdei()
        IN_PCPDEI.fields.pcp = 2
        IN_PCPDEI.fields.dei = 1

        INPUT_PACKET = Ether(dst='00:BE:EF:CA:FE:07',
                             src='00:AB:CD:AB:CD:07',
                             type=0x8100) / \
            U.Dot1QPrio(vlan=BASEVID0,
                        pcpdei=IN_PCPDEI.flat) / \
            MPLS(label=INPUT_LABEL.label,
                 ttl=0x88,
                 cos=1) / \
            U.IPvX(ipvx='v4',
                   src='10.16.10.5',
                   dst='20.15.20.6',
                   ttl=0x90,
                   dscp=40,
                   ecn=3) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)
        EXPECTED_OUTPUT_SWAP_PACKET = \
            Ether(dst='00:CA:FE:BA:BE:06', src='00:BE:EF:CA:FE:06') / \
            MPLS(label=OUTPUT_LABEL.label, ttl=0x87) / \
            U.IPvX(ipvx='v4', src='10.16.10.5', dst='20.15.20.6', ttl=0x90, dscp=40, ecn=3) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[7].slice, 'ifg': ports[7].ifg, 'pif': ports[7].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[6].slice, 'ifg': ports[6].ifg,
                                 'pif': ports[6].first_serdes, 'data': EXPECTED_OUTPUT_SWAP_PACKET})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def test_mpls_active_label_swap(self):
        local_l3ac = SvlBase.l3acs[0]
        remote_nh = SvlBase.rnh[0]
        INPUT_LABEL = sdk.la_mpls_label()
        INPUT_LABEL.label = 0x64
        OUTPUT_LABEL = sdk.la_mpls_label()
        OUTPUT_LABEL.label = 0x65
        PRIVATE_DATA = 0x1234567890abcdef

        local_l3ac.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)
        lsr = self.device.get_lsr()
        nhlfe = self.device.create_mpls_swap_nhlfe(remote_nh, OUTPUT_LABEL)

        lsr.add_route(INPUT_LABEL, nhlfe, PRIVATE_DATA)

        IN_PCPDEI = sdk.la_vlan_pcpdei()
        IN_PCPDEI.fields.pcp = 2
        IN_PCPDEI.fields.dei = 1

        INPUT_PACKET = Ether(dst='00:BE:EF:CA:FE:04',
                             src='00:AB:CD:AB:CD:04',
                             type=0x8100) / \
            U.Dot1QPrio(vlan=BASEVID0,
                        pcpdei=IN_PCPDEI.flat) / \
            MPLS(label=INPUT_LABEL.label,
                 ttl=0x88,
                 cos=1) / \
            U.IPvX(ipvx='v4',
                   src='10.6.10.5',
                   dst='20.5.20.6',
                   ttl=0x90,
                   dscp=40,
                   ecn=3) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[4].slice, 'ifg': ports[4].ifg, 'pif': ports[4].first_serdes}
        expected_packets = []

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        lsr.delete_route(INPUT_LABEL)
        self.device.destroy(nhlfe)
        self.assertEqual(len(unchecked), 1)

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    def test_mpls_active_label_swap2(self):
        local_l3ac = SvlBase.l3acs[0]
        remote_nh = SvlBase.rnh[0]
        INPUT_LABEL = sdk.la_mpls_label()
        INPUT_LABEL.label = 0x64
        OUTPUT_LABEL = sdk.la_mpls_label()
        OUTPUT_LABEL.label = 0x65
        PRIVATE_DATA = 0x1234567890abcdef

        local_l3ac.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)
        lsr = self.device.get_lsr()
        nhlfe = self.device.create_mpls_swap_nhlfe(remote_nh, OUTPUT_LABEL)

        lsr.add_route(INPUT_LABEL, nhlfe, PRIVATE_DATA)

        IN_PCPDEI = sdk.la_vlan_pcpdei()
        IN_PCPDEI.fields.pcp = 2
        IN_PCPDEI.fields.dei = 1

        INPUT_PACKET = Ether(dst='00:BE:EF:CA:FE:04',
                             src='00:AB:CD:AB:CD:04',
                             type=0x8100) / \
            U.Dot1QPrio(vlan=BASEVID0,
                        pcpdei=IN_PCPDEI.flat) / \
            MPLS(label=INPUT_LABEL.label,
                 ttl=0x88,
                 cos=1) / \
            U.IPvX(ipvx='v4',
                   src='10.6.10.5',
                   dst='20.5.20.6',
                   ttl=0x90,
                   dscp=40,
                   ecn=3) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[4].slice, 'ifg': ports[4].ifg, 'pif': ports[4].first_serdes}
        expected_packets = []

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        lsr.delete_route(INPUT_LABEL)
        self.device.destroy(nhlfe)
        self.assertEqual(len(unchecked), 1)

    def test_mpls_active_single_null_vpn(self):
        VPN_LABEL = sdk.la_mpls_label()
        VPN_LABEL.label = 0x10

        local_l3ac = SvlBase.l3acs[0]
        remote_nh = SvlBase.rnh[3]

        local_l3ac.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)
        lsr = self.device.get_lsr()

        decap = lsr.add_vpn_decap(VPN_LABEL, SvlBase.vrf)
        fec = self.device.create_l3_fec(remote_nh)

        v4prefix0 = sdk.la_ipv4_prefix_t()
        v4prefix0.length = 24
        v4prefix0.addr.s_addr = 0x52515F00
        SvlBase.vrf.add_ipv4_route(v4prefix0, fec, 0, False)

        IN_PCPDEI = sdk.la_vlan_pcpdei()
        IN_PCPDEI.fields.pcp = 2
        IN_PCPDEI.fields.dei = 1

        INPUT_PACKET = Ether(dst='00:BE:EF:CA:FE:04', src='00:AB:CD:AB:CD:04', type=0x8100) / \
            U.Dot1QPrio(vlan=BASEVID0, pcpdei=IN_PCPDEI.flat) / \
            MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4, ttl=0x88, cos=1, s=0) / \
            MPLS(label=VPN_LABEL.label, ttl=0x88) / \
            U.IPvX(ipvx='v4', src='12.10.12.10', dst='82.81.95.250', ttl=0x90, dscp=40, ecn=3) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[4].slice, 'ifg': ports[4].ifg, 'pif': ports[4].first_serdes}
        expected_packets = []

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        SvlBase.vrf.delete_ipv4_route(v4prefix0)
        self.device.destroy(fec)
        self.assertEqual(len(unchecked), 1)

    def test_mpls_active_tenh_to_mpls(self):
        TE_TUNNEL_GID = 802
        local_l3ac = SvlBase.l3acs[2]
        remote_nh0 = SvlBase.rnh[0]

        local_l3ac.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)

        te_tunnel = T.te_tunnel(self, self.device, TE_TUNNEL_GID, remote_nh0)
        te_counter = None

        TE_LABEL = sdk.la_mpls_label()
        TE_LABEL.label = 0x12

        te_labels = []
        te_labels.append(TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(remote_nh0, te_labels, te_counter)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        v4prefix0 = sdk.la_ipv4_prefix_t()
        v4prefix0.length = 24
        v4prefix0.addr.s_addr = 0x52515500
        SvlBase.vrf.add_ipv4_route(v4prefix0, te_ecmp, 0, False)

        IN_PCPDEI = sdk.la_vlan_pcpdei()
        IN_PCPDEI.fields.pcp = 2
        IN_PCPDEI.fields.dei = 1

        INPUT_PACKET = Ether(dst='00:BE:EF:CA:FE:06', src='00:AB:CD:AB:CD:06', type=0x8100) / \
            U.Dot1QPrio(vlan=BASEVID0, pcpdei=IN_PCPDEI.flat) / \
            U.IPvX(ipvx='v4', src='12.10.22.10', dst='82.81.85.250', ttl=0x90, dscp=40, ecn=3) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[6].slice, 'ifg': ports[6].ifg, 'pif': ports[6].first_serdes}
        expected_packets = []

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        SvlBase.vrf.delete_ipv4_route(v4prefix0)
        self.device.destroy(te_ecmp)
        self.assertEqual(len(unchecked), 1)

    def test_mpls_active_te_midpoint_primary(self):
        TE_TUNNEL_GID = 800
        PROTECTION_GROUP_ID = 801
        PRIVATE_DATA = 0x1234567890abcdef
        local_l3ac = SvlBase.l3acs[1]
        remote_nh0 = SvlBase.rnh[1]
        remote_nh1 = SvlBase.rnh[2]

        local_l3ac.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        prot_monitor = T.protection_monitor(self, self.device)

        te_tunnel = T.te_tunnel(self, self.device, TE_TUNNEL_GID, remote_nh0)
        te_counter = None

        INPUT_LABEL = sdk.la_mpls_label()
        INPUT_LABEL.label = 0x64

        MP_LABEL = sdk.la_mpls_label()
        MP_LABEL.label = 0x66

        BACKUP_LABEL = sdk.la_mpls_label()
        BACKUP_LABEL.label = 0x67

        PRIMARY_TE_LABEL = sdk.la_mpls_label()
        PRIMARY_TE_LABEL.label = 0x65

        te_labels = []
        te_labels.append(BACKUP_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(remote_nh0, te_labels, te_counter)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            PROTECTION_GROUP_ID,
            remote_nh1,
            te_tunnel.hld_obj,
            prot_monitor.hld_obj)
        lsr = self.device.get_lsr()

        nhlfe = self.device.create_mpls_tunnel_protection_nhlfe(l3_prot_group.hld_obj, PRIMARY_TE_LABEL, MP_LABEL)

        lsr.add_route(INPUT_LABEL, nhlfe, PRIVATE_DATA)

        IN_PCPDEI = sdk.la_vlan_pcpdei()
        IN_PCPDEI.fields.pcp = 2
        IN_PCPDEI.fields.dei = 1

        INPUT_PACKET = Ether(dst='00:BE:EF:CA:FE:05',
                             src='00:AB:CD:AB:CD:05',
                             type=0x8100) / \
            U.Dot1QPrio(vlan=BASEVID0,
                        pcpdei=IN_PCPDEI.flat) / \
            MPLS(label=INPUT_LABEL.label,
                 ttl=0x88,
                 cos=1) / \
            U.IPvX(ipvx='v4',
                   src='10.6.11.5',
                   dst='20.5.21.6',
                   ttl=0x90,
                   dscp=40,
                   ecn=3) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[5].slice, 'ifg': ports[5].ifg, 'pif': ports[5].first_serdes}
        expected_packets = []

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        lsr.delete_route(INPUT_LABEL)
        self.device.destroy(nhlfe)
        self.assertEqual(len(unchecked), 1)


@unittest.skipIf(not decor.is_gibraltar(), "Test is applicable only on GB")
@unittest.skipIf(decor.is_matilda('3.2'), "These tests require at least 4 slices, Matilda has 3, so skip.")
class SvlBaseStandby(unittest.TestCase, svl_base.SvlBaseStandbyContext):
    topology_init_done = False
    base = None
    dev = None

    @classmethod
    def tearDownClass(cls):
        if SvlBaseStandby.dev is not None:
            SvlBaseStandby.dev.tearDown()

    def setUp(self):
        if not SvlBaseStandby.topology_init_done:
            if SvlBaseStandby.dev is None:
                self.base = SvlBase(self.device_id, self.remote_device_id, self.switch_num, self.active)
                self.device = SvlBase.dev
                SvlBaseStandby.dev = self.device
                SvlBaseStandby.base = self.base
            else:
                self.base = SvlBaseStandby.base
                self.device = SvlBaseStandby.dev

            self.topology = T.topology(self, self.device, create_default_topology=False)
            ingress_qos_profile = T.ingress_qos_profile(self, self.device)
            egress_qos_profile = T.egress_qos_profile(self, self.device)
            self.base.create_topology(self, ingress_qos_profile, egress_qos_profile)
            SvlBaseStandby.topology_init_done = True

            SvlBaseStandby.base = self.base
            self.base.stackport.set_peer_device_id(self.remote_device_id)
        self.device = SvlBase.dev
        self.base = SvlBaseStandby.base

    def test_mpls_standby_label_swap(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        local_l3ac = SvlBase.l3acs[0]
        local_nh = SvlBase.lnh[0]
        INPUT_LABEL = sdk.la_mpls_label()
        INPUT_LABEL.label = 0x64
        OUTPUT_LABEL = sdk.la_mpls_label()
        OUTPUT_LABEL.label = 0x65
        PRIVATE_DATA = 0x1234567890abcdef

        local_l3ac.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)
        lsr = self.device.get_lsr()
        nhlfe = self.device.create_mpls_swap_nhlfe(local_nh, OUTPUT_LABEL)

        lsr.add_route(INPUT_LABEL, nhlfe, PRIVATE_DATA)

        EXPECTED_OUTPUT_SWAP_PACKET = \
            Ether(dst='00:BE:EF:BA:BE:04', src='00:DE:AD:BE:EF:04') / \
            MPLS(label=OUTPUT_LABEL.label, ttl=0x87) / \
            U.IPvX(ipvx='v4', src='10.6.10.5', dst='20.5.20.6', ttl=0x90, dscp=40, ecn=3) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[1].slice,
            'ifg': stack_ports[1].ifg,
            'pif': stack_ports[1].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[4].slice, 'ifg': ports[4].ifg,
                                 'pif': ports[4].first_serdes, 'data': EXPECTED_OUTPUT_SWAP_PACKET})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)
        lsr.delete_route(INPUT_LABEL)
        self.device.destroy(nhlfe)

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device - inject PIF used on HW.")
    def test_mpls_standby_drop_receive_disabled(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        local_l3ac = SvlBase.l3acs[0]
        local_nh = SvlBase.lnh[0]
        INPUT_LABEL = sdk.la_mpls_label()
        INPUT_LABEL.label = 0x64
        OUTPUT_LABEL = sdk.la_mpls_label()
        OUTPUT_LABEL.label = 0x65
        PRIVATE_DATA = 0x1234567890abcdef

        local_l3ac.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)
        lsr = self.device.get_lsr()
        nhlfe = self.device.create_mpls_swap_nhlfe(local_nh, OUTPUT_LABEL)

        lsr.add_route(INPUT_LABEL, nhlfe, PRIVATE_DATA)

        EXPECTED_OUTPUT_SWAP_PACKET = \
            Ether(dst='00:BE:EF:BA:BE:04', src='00:DE:AD:BE:EF:04') / \
            MPLS(label=OUTPUT_LABEL.label, ttl=0x87) / \
            U.IPvX(ipvx='v4', src='10.6.10.5', dst='20.5.20.6', ttl=0x90, dscp=40, ecn=3) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[1].slice,
            'ifg': stack_ports[1].ifg,
            'pif': stack_ports[1].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[4].slice, 'ifg': ports[4].ifg,
                                 'pif': ports[4].first_serdes, 'data': EXPECTED_OUTPUT_SWAP_PACKET})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Disable Rx
        SvlBase.stack_spa.set_member_receive_enabled(SvlBase.ssps[1].hld_obj, False)
        is_receive_enabled = SvlBase.stack_spa.get_member_receive_enabled(SvlBase.ssps[1].hld_obj)
        self.assertEqual(is_receive_enabled, False)

        U.run_and_drop(self, self.device, INPUT_PACKET, stack_ports[1].slice, stack_ports[1].ifg, stack_ports[1].first_serdes)

        # Enable Rx
        SvlBase.stack_spa.set_member_receive_enabled(SvlBase.ssps[1].hld_obj, True)
        is_receive_enabled = SvlBase.stack_spa.get_member_receive_enabled(SvlBase.ssps[1].hld_obj)
        self.assertEqual(is_receive_enabled, True)

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)
        lsr.delete_route(INPUT_LABEL)
        self.device.destroy(nhlfe)

    def test_mpls_standby_single_null_vpn(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        VPN_LABEL = sdk.la_mpls_label()
        VPN_LABEL.label = 0x10

        local_l3ac = SvlBase.l3acs[3]
        local_nh = SvlBase.lnh[3]

        local_l3ac.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)
        lsr = self.device.get_lsr()

        decap = lsr.add_vpn_decap(VPN_LABEL, SvlBase.vrf)
        fec = self.device.create_l3_fec(local_nh)

        v4prefix0 = sdk.la_ipv4_prefix_t()
        v4prefix0.length = 24
        v4prefix0.addr.s_addr = 0x52515F00
        SvlBase.vrf.add_ipv4_route(v4prefix0, fec, 0, False)

        IN_PCPDEI = sdk.la_vlan_pcpdei()
        IN_PCPDEI.fields.pcp = 2
        IN_PCPDEI.fields.dei = 1

        EXPECTED_OUTPUT_PACKET = Ether(dst='00:BE:EF:BA:BE:07', src='00:DE:AD:BE:EF:07') / \
            U.IPvX(ipvx='v4', src='12.10.12.10', dst='82.81.95.250', ttl=0x8F, dscp=40, ecn=3) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[1].slice,
            'ifg': stack_ports[1].ifg,
            'pif': stack_ports[1].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[7].slice, 'ifg': ports[7].ifg,
                                 'pif': ports[7].first_serdes, 'data': EXPECTED_OUTPUT_PACKET})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)
        SvlBase.vrf.delete_ipv4_route(v4prefix0)
        self.device.destroy(fec)

    def test_mpls_standby_tenh_to_mpls(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        TE_TUNNEL_GID = 802
        local_l3ac = SvlBase.l3acs[0]
        local_nh0 = SvlBase.lnh[0]

        local_l3ac.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)

        te_tunnel = T.te_tunnel(self, self.device, TE_TUNNEL_GID, local_nh0)
        te_counter = None

        TE_LABEL = sdk.la_mpls_label()
        TE_LABEL.label = 0x12

        te_labels = []
        te_labels.append(TE_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(local_nh0, te_labels, te_counter)

        te_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(te_ecmp, None)
        te_ecmp.add_member(te_tunnel.hld_obj)

        v4prefix0 = sdk.la_ipv4_prefix_t()
        v4prefix0.length = 24
        v4prefix0.addr.s_addr = 0x52515500
        SvlBase.vrf.add_ipv4_route(v4prefix0, te_ecmp, 0, False)

        IN_PCPDEI = sdk.la_vlan_pcpdei()
        IN_PCPDEI.fields.pcp = 2
        IN_PCPDEI.fields.dei = 1

        EXPECTED_OUTPUT_PACKET = Ether(dst='00:BE:EF:BA:BE:04', src='00:DE:AD:BE:EF:04') / \
            MPLS(label=TE_LABEL.label, ttl=0x8F) / \
            U.IPvX(ipvx='v4', src='12.10.22.10', dst='82.81.85.250', ttl=0x8F, dscp=40, ecn=3) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[1].slice,
            'ifg': stack_ports[1].ifg,
            'pif': stack_ports[1].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[4].slice, 'ifg': ports[4].ifg,
                                 'pif': ports[4].first_serdes, 'data': EXPECTED_OUTPUT_PACKET})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)
        SvlBase.vrf.delete_ipv4_route(v4prefix0)
        self.device.destroy(te_ecmp)

    def test_mpls_standby_te_midpoint_primary(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        TE_TUNNEL_GID = 800
        PROTECTION_GROUP_ID = 801
        PRIVATE_DATA = 0x1234567890abcdef
        local_l3ac = SvlBase.l3acs[1]
        local_nh0 = SvlBase.lnh[1]
        local_nh1 = SvlBase.lnh[2]
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)
        prot_monitor = T.protection_monitor(self, self.device)

        local_l3ac.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

        te_tunnel = T.te_tunnel(self, self.device, TE_TUNNEL_GID, local_nh0)
        te_counter = None

        INPUT_LABEL = sdk.la_mpls_label()
        INPUT_LABEL.label = 0x64

        MP_LABEL = sdk.la_mpls_label()
        MP_LABEL.label = 0x66

        BACKUP_LABEL = sdk.la_mpls_label()
        BACKUP_LABEL.label = 0x67

        PRIMARY_TE_LABEL = sdk.la_mpls_label()
        PRIMARY_TE_LABEL.label = 0x65

        te_labels = []
        te_labels.append(BACKUP_LABEL)

        te_tunnel.hld_obj.set_nh_lsp_properties(local_nh0, te_labels, te_counter)

        l3_prot_group = T.l3_protection_group(
            self,
            self.device,
            PROTECTION_GROUP_ID,
            local_nh1,
            te_tunnel.hld_obj,
            prot_monitor.hld_obj)
        lsr = self.device.get_lsr()

        nhlfe = self.device.create_mpls_tunnel_protection_nhlfe(l3_prot_group.hld_obj, PRIMARY_TE_LABEL, MP_LABEL)

        lsr.add_route(INPUT_LABEL, nhlfe, PRIVATE_DATA)

        EXPECTED_OUTPUT_SWAP_PACKET = \
            Ether(dst='00:BE:EF:BA:BE:06', src='00:DE:AD:BE:EF:06') / \
            MPLS(label=PRIMARY_TE_LABEL.label, ttl=0x87) / \
            U.IPvX(ipvx='v4', src='10.6.11.5', dst='20.5.21.6', ttl=0x90, dscp=40, ecn=3) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[1].slice,
            'ifg': stack_ports[1].ifg,
            'pif': stack_ports[1].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[6].slice, 'ifg': ports[6].ifg,
                                 'pif': ports[6].first_serdes, 'data': EXPECTED_OUTPUT_SWAP_PACKET})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)
        lsr.delete_route(INPUT_LABEL)
        self.device.destroy(nhlfe)
