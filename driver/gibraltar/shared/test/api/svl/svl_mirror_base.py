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
import nplapicli as nplapi
import svl_base
from svl_base import *

SvlTestPair = {
    "test_svl_standby_l2_ingress_mirror_remote_mirror_destination": "test_svl_active_l2_ingress_mirror_remote_mirror_destination",
    "test_svl_standby_ip_ingress_mirror_remote_mirror_destination": "test_svl_active_ip_ingress_mirror_remote_mirror_destination",
    "test_svl_standby_l2_egress_mirror_remote_mirror_destination": "test_svl_active_l2_egress_mirror_remote_mirror_destination",
    "test_svl_standby_ip_egress_mirror_remote_mirror_destination": "test_svl_active_ip_egress_mirror_remote_mirror_destination",
    "test_svl_active_l2_ingress_mirror_remote_cpu_mirror_destination": "test_svl_standby_l2_ingress_mirror_remote_cpu_mirror_destination",
    "test_svl_active_l2_egress_mirror_remote_cpu_mirror_destination": "test_svl_standby_l2_egress_mirror_remote_cpu_mirror_destination"}

INGRESS_MIRROR_ID = 1
EGRESS_MIRROR_ID  = 2
INGRESS_MIRROR_TO_CPU   = 3
EGRESS_MIRROR_TO_CPU    = 4

MIRROR_HOST_MAC_ADDR = "fe:dc:ba:12:34:12"
MIRROR_HOST_VID = 0xA13


@unittest.skipIf(decor.is_hw_device(), "Skip for HW device.")
@unittest.skipIf(not decor.is_gibraltar(), "Test is applicable only on GB")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip for WB")
@unittest.skipIf(decor.is_matilda('3.2'), "These tests require at least 4 slices, Matilda has 3, so skip.")
class SvlBaseActive(unittest.TestCase, svl_base.SvlBaseActiveContext):
    topology_init_done = False
    base = None

    def setUp(self):
        if not SvlBaseActive.topology_init_done:
            self.base = SvlBase(self.device_id, self.remote_device_id, self.switch_num, self.active)
            self.device = SvlBase.dev

            self.topology = T.topology(self, self.device, create_default_topology=False)
            ingress_qos_profile = T.ingress_qos_profile(self, self.device)
            egress_qos_profile = T.egress_qos_profile(self, self.device)
            self.base.create_topology(self, ingress_qos_profile, egress_qos_profile)
            SvlBaseActive.topology_init_done = True

            SvlBaseActive.base = self.base
            self.base.stackport.set_peer_device_id(self.remote_device_id)
        self.device = SvlBase.dev
        self.base = SvlBaseActive.base

    @classmethod
    def tearDownClass(cls):
        SvlBaseActive.base.tearDownClass()
        SvlBaseActive.topology_init_done = False
        SvlBaseActive.base = None
        del cls

    def test_svl_active_l2_ingress_mirror_remote_mirror_destination(self):
        self.remote_eth_port0 = SvlBase.reps[0]
        self.l2acport0 = SvlBase.l2acs[0]
        self.mirrorcmd0 = self.device.create_l2_mirror_command(
            INGRESS_MIRROR_ID,
            self.remote_eth_port0,
            self.remote_eth_port0.get_system_port(),
            0,
            1)

        self.l2acport0.set_ingress_mirror_command(self.mirrorcmd0, False)

        DA = T.mac_addr('00:BE:EF:CA:FE:01')
        SA = T.mac_addr('00:BE:EF:CA:FE:00')
        SIP = T.ipv4_addr('192.168.10.10')
        DIP_UC = T.ipv4_addr('192.168.10.20')

        INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[0].slice, 'ifg': ports[0].ifg, 'pif': ports[0].first_serdes}
        expected_packets = []
        expected_packets.append({'data': INPUT_PACKET, 'slice': ports[1].slice, 'ifg': ports[1].ifg, 'pif': ports[1].first_serdes})

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        self.l2acport0.set_ingress_mirror_command(None, False)
        self.device.destroy(self.mirrorcmd0)
        self.assertEqual(len(unchecked), 1)

    def test_svl_active_ip_ingress_mirror_remote_mirror_destination(self):
        self.remote_eth_port0 = SvlBase.reps[4]
        self.l3acport0 = SvlBase.l3acs[0]
        self.mirrorcmd0 = self.device.create_l2_mirror_command(
            INGRESS_MIRROR_ID,
            self.remote_eth_port0,
            self.remote_eth_port0.get_system_port(),
            0,
            1)

        self.l3acport0.set_ingress_mirror_command(self.mirrorcmd0, False)

        DA = T.mac_addr('00:BE:EF:CA:FE:04')
        SA = T.mac_addr('00:AB:CD:AB:CD:01')
        SIP = T.ipv4_addr('10.10.10.10')
        DIP_UC = T.ipv4_addr('20.20.20.20')

        INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        OUT_DA = T.mac_addr('00:CA:FE:BA:BE:05')  # NH1 MAC
        OUT_SA = T.mac_addr('00:BE:EF:CA:FE:05')  # L3 AC1
        OUTPUT_PACKET_BASE = \
            Ether(dst=OUT_DA.addr_str, src=OUT_SA.addr_str) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET, __ = U.enlarge_packet_to_min_length(OUTPUT_PACKET_BASE)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[4].slice, 'ifg': ports[4].ifg, 'pif': ports[4].first_serdes}
        expected_packets = []
        expected_packets.append({'data': OUTPUT_PACKET, 'slice': ports[5].slice, 'ifg': ports[5].ifg, 'pif': ports[5].first_serdes})

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        self.l3acport0.set_ingress_mirror_command(None, False)
        self.device.destroy(self.mirrorcmd0)
        self.assertEqual(len(unchecked), 1)

    def test_svl_active_l2_egress_mirror_remote_mirror_destination(self):
        self.remote_eth_port0 = SvlBase.reps[1]
        self.l2acport0 = SvlBase.l2acs[1]
        self.mirrorcmd0 = self.device.create_l2_mirror_command(
            EGRESS_MIRROR_ID,
            self.remote_eth_port0,
            self.remote_eth_port0.get_system_port(),
            0,
            1)

        self.l2acport0.set_egress_mirror_command(self.mirrorcmd0, False)

        DA = T.mac_addr('00:BE:EF:CA:FE:01')
        SA = T.mac_addr('00:BE:EF:CA:FE:00')
        SIP = T.ipv4_addr('192.168.10.10')
        DIP_UC = T.ipv4_addr('192.168.10.20')

        INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[0].slice, 'ifg': ports[0].ifg, 'pif': ports[0].first_serdes}
        expected_packets = []
        expected_packets.append({'data': INPUT_PACKET, 'slice': ports[1].slice, 'ifg': ports[1].ifg, 'pif': ports[1].first_serdes})

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        self.l2acport0.set_egress_mirror_command(None, False)
        self.device.destroy(self.mirrorcmd0)
        self.assertEqual(len(unchecked), 1)

    def test_svl_active_ip_egress_mirror_remote_mirror_destination(self):
        self.remote_eth_port0 = SvlBase.reps[5]
        self.l3acport0 = SvlBase.l3acs[1]
        self.mirrorcmd0 = self.device.create_l2_mirror_command(
            EGRESS_MIRROR_ID,
            self.remote_eth_port0,
            self.remote_eth_port0.get_system_port(),
            0,
            1)

        self.l3acport0.set_egress_mirror_command(self.mirrorcmd0, False)

        DA = T.mac_addr('00:BE:EF:CA:FE:04')
        SA = T.mac_addr('00:AB:CD:AB:CD:01')
        SIP = T.ipv4_addr('10.10.10.10')
        DIP_UC = T.ipv4_addr('20.20.20.20')

        INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        OUT_DA = T.mac_addr('00:CA:FE:BA:BE:05')  # NH1 MAC
        OUT_SA = T.mac_addr('00:BE:EF:CA:FE:05')  # L3 AC1
        OUTPUT_PACKET_BASE = \
            Ether(dst=OUT_DA.addr_str, src=OUT_SA.addr_str) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET, __ = U.enlarge_packet_to_min_length(OUTPUT_PACKET_BASE)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[4].slice, 'ifg': ports[4].ifg, 'pif': ports[4].first_serdes}
        expected_packets = []
        expected_packets.append({'data': OUTPUT_PACKET, 'slice': ports[5].slice, 'ifg': ports[5].ifg, 'pif': ports[5].first_serdes})

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        self.l3acport0.set_egress_mirror_command(None, False)
        self.device.destroy(self.mirrorcmd0)
        self.assertEqual(len(unchecked), 1)


@unittest.skipIf(decor.is_hw_device(), "Skip for HW device.")
@unittest.skipIf(not decor.is_gibraltar(), "Test is applicable only on GB")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip for WB")
@unittest.skipIf(decor.is_matilda('3.2'), "These tests require at least 4 slices, Matilda has 3, so skip.")
class SvlBaseStandby(unittest.TestCase, svl_base.SvlBaseStandbyContext):
    topology_init_done = False
    base = None

    def setUp(self):
        if not SvlBaseStandby.topology_init_done:
            self.base = SvlBase(self.device_id, self.remote_device_id, self.switch_num, self.active)
            self.device = SvlBase.dev

            self.topology = T.topology(self, self.device, create_default_topology=False)
            ingress_qos_profile = T.ingress_qos_profile(self, self.device)
            egress_qos_profile = T.egress_qos_profile(self, self.device)
            self.base.create_topology(self, ingress_qos_profile, egress_qos_profile)
            SvlBaseStandby.topology_init_done = True

            SvlBaseStandby.base = self.base
            self.base.stackport.set_peer_device_id(self.remote_device_id)
        self.device = SvlBase.dev
        self.base = SvlBaseStandby.base

    @classmethod
    def tearDownClass(cls):
        SvlBaseStandby.base.tearDownClass()
        SvlBaseStandby.topology_init_done = False
        SvlBaseStandby.base = None
        del cls

    def test_svl_standby_l2_ingress_mirror_remote_mirror_destination(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        self.local_eth_port0 = SvlBase.eps[0]
        self.remote_l2acport0 = SvlBase.rl2acs[0]
        self.mirrorcmd0 = self.device.create_l2_mirror_command(
            INGRESS_MIRROR_ID, self.local_eth_port0, self.local_eth_port0.get_system_port(), 0, 1)

        self.remote_l2acport0.set_ingress_mirror_command(self.mirrorcmd0, False)

        DA = T.mac_addr('00:BE:EF:CA:FE:01')
        SA = T.mac_addr('00:BE:EF:CA:FE:00')
        SIP = T.ipv4_addr('192.168.10.10')
        DIP_UC = T.ipv4_addr('192.168.10.20')

        REMOTE_INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        REMOTE_INPUT_PACKET, __ = U.enlarge_packet_to_min_length(REMOTE_INPUT_PACKET_BASE)

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[0].slice,
            'ifg': stack_ports[0].ifg,
            'pif': stack_ports[0].first_serdes}
        expected_packets = []
        expected_packets.append({'data': REMOTE_INPUT_PACKET,
                                 'slice': ports[0].slice,
                                 'ifg': ports[0].ifg,
                                 'pif': ports[0].first_serdes})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)
        self.remote_l2acport0.set_ingress_mirror_command(None, False)
        self.device.destroy(self.mirrorcmd0)

    def test_svl_standby_ip_ingress_mirror_remote_mirror_destination(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        self.local_eth_port0 = SvlBase.eps[4]
        self.remote_l3acport0 = SvlBase.rl3acs[0]
        self.mirrorcmd0 = self.device.create_l2_mirror_command(
            INGRESS_MIRROR_ID, self.local_eth_port0, self.local_eth_port0.get_system_port(), 0, 1)

        self.remote_l3acport0.set_ingress_mirror_command(self.mirrorcmd0, False)

        DA = T.mac_addr('00:BE:EF:CA:FE:04')
        SA = T.mac_addr('00:AB:CD:AB:CD:01')
        SIP = T.ipv4_addr('10.10.10.10')
        DIP_UC = T.ipv4_addr('20.20.20.20')

        REMOTE_INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        REMOTE_INPUT_PACKET, __ = U.enlarge_packet_to_min_length(REMOTE_INPUT_PACKET_BASE)

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[0].slice,
            'ifg': stack_ports[0].ifg,
            'pif': stack_ports[0].first_serdes}
        expected_packets = []
        expected_packets.append({'data': REMOTE_INPUT_PACKET,
                                 'slice': ports[4].slice,
                                 'ifg': ports[4].ifg,
                                 'pif': ports[4].first_serdes})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)
        self.remote_l3acport0.set_ingress_mirror_command(None, False)
        self.device.destroy(self.mirrorcmd0)

    def test_svl_standby_l2_egress_mirror_remote_mirror_destination(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        self.local_eth_port0 = SvlBase.eps[1]
        self.remote_l2acport0 = SvlBase.rl2acs[1]
        self.mirrorcmd0 = self.device.create_l2_mirror_command(
            EGRESS_MIRROR_ID, self.local_eth_port0, self.local_eth_port0.get_system_port(), 0, 1)

        self.remote_l2acport0.set_egress_mirror_command(self.mirrorcmd0, False)

        DA = T.mac_addr('00:BE:EF:CA:FE:01')
        SA = T.mac_addr('00:BE:EF:CA:FE:00')
        SIP = T.ipv4_addr('192.168.10.10')
        DIP_UC = T.ipv4_addr('192.168.10.20')

        REMOTE_INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        REMOTE_INPUT_PACKET, __ = U.enlarge_packet_to_min_length(REMOTE_INPUT_PACKET_BASE)

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[1].slice,
            'ifg': stack_ports[1].ifg,
            'pif': stack_ports[1].first_serdes}
        expected_packets = []
        expected_packets.append({'data': REMOTE_INPUT_PACKET,
                                 'slice': ports[1].slice,
                                 'ifg': ports[1].ifg,
                                 'pif': ports[1].first_serdes})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)
        self.remote_l2acport0.set_egress_mirror_command(None, False)
        self.device.destroy(self.mirrorcmd0)

    def test_svl_standby_ip_egress_mirror_remote_mirror_destination(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        self.local_eth_port0 = SvlBase.eps[5]
        self.remote_l3acport0 = SvlBase.rl3acs[1]
        self.mirrorcmd0 = self.device.create_l2_mirror_command(
            EGRESS_MIRROR_ID, self.local_eth_port0, self.local_eth_port0.get_system_port(), 0, 1)

        self.remote_l3acport0.set_egress_mirror_command(self.mirrorcmd0, False)

        SIP = T.ipv4_addr('10.10.10.10')
        DIP_UC = T.ipv4_addr('20.20.20.20')
        OUT_DA = T.mac_addr('00:CA:FE:BA:BE:05')  # NH1 MAC
        OUT_SA = T.mac_addr('00:BE:EF:CA:FE:05')  # L3 AC1

        REMOTE_OUTPUT_PACKET_BASE = \
            Ether(dst=OUT_DA.addr_str, src=OUT_SA.addr_str) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        REMOTE_OUTPUT_PACKET, __ = U.enlarge_packet_to_min_length(REMOTE_OUTPUT_PACKET_BASE)

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[1].slice,
            'ifg': stack_ports[1].ifg,
            'pif': stack_ports[1].first_serdes}
        expected_packets = []
        expected_packets.append({'data': REMOTE_OUTPUT_PACKET,
                                 'slice': ports[5].slice,
                                 'ifg': ports[5].ifg,
                                 'pif': ports[5].first_serdes})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)
        self.remote_l3acport0.set_egress_mirror_command(None, False)
        self.device.destroy(self.mirrorcmd0)

    def test_svl_standby_l2_ingress_mirror_remote_cpu_mirror_destination(self):
        slice_id = 0
        ifg = 0
        first_serdes = self.device.get_pci_serdes()
        last_serdes = first_serdes + 1
        rp = T.remote_port(self, self.device, self.remote_device_id, slice_id, ifg, first_serdes, last_serdes)
        pci_sys_port_gid = (T.INJECT_PORT_BASE_GID + slice_id)
        pci_sys_port_gid = toggle_switch_num_in_gid(pci_sys_port_gid)
        sp = T.system_port(self, self.device, pci_sys_port_gid, rp)
        mac_address = T.mac_addr(INJECT_PORT_MAC_ADDR)
        injectport = self.device.create_punt_inject_port(sp.hld_obj, mac_address.hld_obj)

        host_mac_addr = T.mac_addr(MIRROR_HOST_MAC_ADDR)
        tag_tci = sdk.la_vlan_tag_tci_t()
        tag_tci.fields.pcp = 0
        tag_tci.fields.dei = 0
        tag_tci.fields.vid = MIRROR_HOST_VID

        voq_offset = 0
        meter = None
        probability = 1

        self.mirrorcmd0 = self.device.create_l2_mirror_command(INGRESS_MIRROR_TO_CPU, injectport,
                                                               host_mac_addr.hld_obj, tag_tci,
                                                               voq_offset, meter, probability)
        self.l2acport0 = SvlBase.l2acs[0]
        self.l2acport0.set_ingress_mirror_command(self.mirrorcmd0, False)

        DA = T.mac_addr('00:DE:AD:BE:EF:01')
        SA = T.mac_addr('00:DE:AD:BE:EF:00')
        SIP = T.ipv4_addr('192.168.10.10')
        DIP_UC = T.ipv4_addr('192.168.10.20')

        INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[0].slice, 'ifg': ports[0].ifg, 'pif': ports[0].first_serdes}
        expected_packets = []
        expected_packets.append({'data': INPUT_PACKET, 'slice': ports[1].slice, 'ifg': ports[1].ifg, 'pif': ports[1].first_serdes})

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        self.l2acport0.set_ingress_mirror_command(None, False)
        self.device.destroy(self.mirrorcmd0)
        self.assertEqual(len(unchecked), 1)

    def test_svl_standby_l2_egress_mirror_remote_cpu_mirror_destination(self):
        slice_id = 2
        ifg = 0
        first_serdes = self.device.get_pci_serdes()
        last_serdes = first_serdes + 1
        rp = T.remote_port(self, self.device, self.remote_device_id, slice_id, ifg, first_serdes, last_serdes)
        pci_sys_port_gid = (T.INJECT_PORT_BASE_GID + slice_id)
        pci_sys_port_gid = toggle_switch_num_in_gid(pci_sys_port_gid)
        sp = T.system_port(self, self.device, pci_sys_port_gid, rp)
        mac_address = T.mac_addr(INJECT_PORT_MAC_ADDR)
        injectport = self.device.create_punt_inject_port(sp.hld_obj, mac_address.hld_obj)

        host_mac_addr = T.mac_addr(MIRROR_HOST_MAC_ADDR)
        tag_tci = sdk.la_vlan_tag_tci_t()
        tag_tci.fields.pcp = 0
        tag_tci.fields.dei = 0
        tag_tci.fields.vid = MIRROR_HOST_VID

        voq_offset = 0
        meter = None
        probability = 1

        self.mirrorcmd0 = self.device.create_l2_mirror_command(EGRESS_MIRROR_TO_CPU, injectport,
                                                               host_mac_addr.hld_obj, tag_tci,
                                                               voq_offset, meter, probability)
        self.l2acport1 = SvlBase.l2acs[1]
        self.l2acport1.set_egress_mirror_command(self.mirrorcmd0, False)

        DA = T.mac_addr('00:DE:AD:BE:EF:01')
        SA = T.mac_addr('00:DE:AD:BE:EF:00')
        SIP = T.ipv4_addr('192.168.10.10')
        DIP_UC = T.ipv4_addr('192.168.10.20')

        INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[0].slice, 'ifg': ports[0].ifg, 'pif': ports[0].first_serdes}
        expected_packets = []
        expected_packets.append({'data': INPUT_PACKET, 'slice': ports[1].slice, 'ifg': ports[1].ifg, 'pif': ports[1].first_serdes})

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        self.l2acport1.set_egress_mirror_command(None, False)
        self.device.destroy(self.mirrorcmd0)
        self.assertEqual(len(unchecked), 1)


@unittest.skipIf(decor.is_hw_device(), "Skip for HW device.")
@unittest.skipIf(not decor.is_gibraltar(), "Test is applicable only on GB")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip for WB")
class SvlBaseActiveRerun(unittest.TestCase, svl_base.SvlBaseActiveContext):
    topology_init_done = False
    base = None

    def setUp(self):
        if not SvlBaseActive.topology_init_done:
            self.base = SvlBase(self.device_id, self.remote_device_id, self.switch_num, self.active)
            self.device = SvlBase.dev

            self.topology = T.topology(self, self.device, create_default_topology=False)
            ingress_qos_profile = T.ingress_qos_profile(self, self.device)
            egress_qos_profile = T.egress_qos_profile(self, self.device)
            self.base.create_topology(self, ingress_qos_profile, egress_qos_profile)
            SvlBaseActive.topology_init_done = True

            SvlBaseActive.base = self.base
            self.base.stackport.set_peer_device_id(self.remote_device_id)
        self.device = SvlBase.dev
        self.base = SvlBaseActive.base

    @classmethod
    def tearDownClass(cls):
        SvlBaseActive.base.tearDownClass()
        SvlBaseActive.topology_init_done = False
        SvlBaseActive.base = None
        del cls

    def test_svl_active_l2_ingress_mirror_remote_cpu_mirror_destination(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        injectport = SvlBase.punt_inject[0]

        host_mac_addr = T.mac_addr(MIRROR_HOST_MAC_ADDR)
        tag_tci = sdk.la_vlan_tag_tci_t()
        tag_tci.fields.pcp = 0
        tag_tci.fields.dei = 0
        tag_tci.fields.vid = MIRROR_HOST_VID

        voq_offset = 0
        meter = None
        probability = 1

        self.mirrorcmd0 = self.device.create_l2_mirror_command(INGRESS_MIRROR_TO_CPU, injectport,
                                                               host_mac_addr.hld_obj, tag_tci,
                                                               voq_offset, meter, probability)
        self.remote_l2acport0 = SvlBase.rl2acs[0]
        self.remote_l2acport0.set_ingress_mirror_command(self.mirrorcmd0, False)

        DA = T.mac_addr('00:DE:AD:BE:EF:01')
        SA = T.mac_addr('00:DE:AD:BE:EF:00')
        SIP = T.ipv4_addr('192.168.10.10')
        DIP_UC = T.ipv4_addr('192.168.10.20')

        REMOTE_INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        REMOTE_INPUT_PACKET, __ = U.enlarge_packet_to_min_length(REMOTE_INPUT_PACKET_BASE)

        PUNT_ENCAP_PACKET = \
            Ether(dst=MIRROR_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=MIRROR_HOST_VID, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                   code=INGRESS_MIRROR_TO_CPU,
                   source_sp=SvlBase.rsps[0].hld_obj.get_gid(),
                   destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   source_lp=(nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING | SvlBase.rl2acs[0].get_gid()),
                   destination_lp=SvlBase.rl2acs[1].get_gid(),
                   relay_id=BASEVID0, lpts_flow_type=0) / REMOTE_INPUT_PACKET

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[0].slice,
            'ifg': stack_ports[0].ifg,
            'pif': stack_ports[0].first_serdes}
        expected_packets = []
        expected_packets.append({'data': PUNT_ENCAP_PACKET,
                                 'slice': 0,
                                 'ifg': 0,
                                 'pif': self.device.get_pci_serdes()})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)
        self.remote_l2acport0.set_ingress_mirror_command(None, False)
        self.device.destroy(self.mirrorcmd0)

    def test_svl_active_l2_egress_mirror_remote_cpu_mirror_destination(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        injectport = SvlBase.punt_inject[1]

        host_mac_addr = T.mac_addr(MIRROR_HOST_MAC_ADDR)
        tag_tci = sdk.la_vlan_tag_tci_t()
        tag_tci.fields.pcp = 0
        tag_tci.fields.dei = 0
        tag_tci.fields.vid = MIRROR_HOST_VID

        voq_offset = 0
        meter = None
        probability = 1

        self.mirrorcmd0 = self.device.create_l2_mirror_command(EGRESS_MIRROR_TO_CPU, injectport,
                                                               host_mac_addr.hld_obj, tag_tci,
                                                               voq_offset, meter, probability)
        self.remote_l2acport1 = SvlBase.rl2acs[1]
        self.remote_l2acport1.set_egress_mirror_command(self.mirrorcmd0, False)

        DA = T.mac_addr('00:DE:AD:BE:EF:01')
        SA = T.mac_addr('00:DE:AD:BE:EF:00')
        SIP = T.ipv4_addr('192.168.10.10')
        DIP_UC = T.ipv4_addr('192.168.10.20')

        REMOTE_INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        REMOTE_INPUT_PACKET, __ = U.enlarge_packet_to_min_length(REMOTE_INPUT_PACKET_BASE)

        PUNT_ENCAP_PACKET = \
            Ether(dst=MIRROR_HOST_MAC_ADDR, src=INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=MIRROR_HOST_VID, type=U.Ethertype.Punt.value) / \
            U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                   fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                   next_header_offset=0,
                   source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_OUTBOUND_MIRROR,
                   code=EGRESS_MIRROR_TO_CPU,
                   source_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                   destination_sp=SvlBase.rsps[1].hld_obj.get_gid(),
                   source_lp=0xBFFFF,
                   destination_lp=0x3FFFF,
                   relay_id=0, lpts_flow_type=0) / REMOTE_INPUT_PACKET

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[1].slice,
            'ifg': stack_ports[1].ifg,
            'pif': stack_ports[1].first_serdes}
        expected_packets = []
        expected_packets.append({'data': PUNT_ENCAP_PACKET,
                                 'slice': 2,
                                 'ifg': 0,
                                 'pif': self.device.get_pci_serdes()})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)
        self.remote_l2acport1.set_egress_mirror_command(None, False)
        self.device.destroy(self.mirrorcmd0)
