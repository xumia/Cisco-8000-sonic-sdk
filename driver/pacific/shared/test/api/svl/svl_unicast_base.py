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

SvlTestPair = {
    "test_svl_standby_01_remote_l2_unicast": "test_svl_active_01_remote_l2_unicast",
    "test_svl_standby_02_remote_l3_unicast": "test_svl_active_03_remote_l3_unicast"
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

    #@unittest.skip("Test temporarily disabled")
    def test_svl_active_00_local_l2_unicast(self):
        LOCAL_DA = T.mac_addr('00:BE:EF:CA:FE:03')
        SA = T.mac_addr('00:BE:EF:CA:FE:00')
        SIP = T.ipv4_addr('10.10.10.10')
        DIP_UC = T.ipv4_addr('30.30.30.30')

        INPUT_PACKET_BASE = \
            Ether(dst=LOCAL_DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        U.run_and_compare(
            self,
            self.device,
            INPUT_PACKET,
            ports[0].slice,
            ports[0].ifg,
            ports[0].first_serdes,
            INPUT_PACKET,
            ports[3].slice,
            ports[3].ifg,
            ports[3].first_serdes)

    def test_svl_active_01_remote_l2_unicast(self):
        REMOTE_DA = T.mac_addr('00:DE:AD:BE:EF:03')
        SA = T.mac_addr('00:BE:EF:CA:FE:01')
        SIP = T.ipv4_addr('20.20.20.20')
        DIP_UC = T.ipv4_addr('80.80.80.80')

        INPUT_PACKET_BASE = \
            Ether(dst=REMOTE_DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[1].slice, 'ifg': ports[1].ifg, 'pif': ports[1].first_serdes}
        # only remote destination, we should not see any frame in local switch
        expected_packets = []
        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        self.assertEqual(len(unchecked), 1)

    #@unittest.skip("Test temporarily disabled")
    def test_svl_active_02_local_l3_unicast(self):
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

        U.run_and_compare(
            self,
            self.device,
            INPUT_PACKET,
            ports[4].slice,
            ports[4].ifg,
            ports[4].first_serdes,
            OUTPUT_PACKET,
            ports[5].slice,
            ports[5].ifg,
            ports[5].first_serdes)

    def test_svl_active_03_remote_l3_unicast(self):
        DA = T.mac_addr('00:BE:EF:CA:FE:05')
        SA = T.mac_addr('00:AB:CD:AB:CD:02')
        SIP = T.ipv4_addr('20.20.20.20')
        DIP_UC = T.ipv4_addr('80.80.80.80')

        INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[5].slice, 'ifg': ports[5].ifg, 'pif': ports[5].first_serdes}
        # only remote destination, we should not see any frame in local switch
        expected_packets = []
        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        self.assertEqual(len(unchecked), 1)

    def test_svl_active_04_well_known_destination_0(self):
        # Save current trap configuration
        prev_trap_config = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)

        # Configure trap to superior priority and to drop
        destination = None
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING, 0, None, destination, False, False, True, 0)

        DA = T.mac_addr('00:DE:AD:BE:EF:99')
        SA = T.mac_addr('00:DE:AD:BE:EF:88')
        SIP = T.ipv4_addr('192.168.1.1')
        DIP = T.ipv4_addr('192.168.1.10')

        NO_SERVICE_MAPPING_VID = BASEVID0 + 1
        INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str) / \
            Dot1Q(vlan=NO_SERVICE_MAPPING_VID) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        rx_drop_voq_counter = self.device.get_forwarding_drop_counter()

        enqueue_packet_count, enqueue_byte_count = rx_drop_voq_counter.read(0,    # ENQUEUE counter
                                                                            True,  # force_update
                                                                            True)  # clear_on_read
        drop_packet_count, drop_byte_count = rx_drop_voq_counter.read(1,      # DROP counter
                                                                      True,   # force_update
                                                                      True)   # clear_on_read
        # Verify the counter is empty.
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)
        self.assertEqual(drop_packet_count, 0)
        self.assertEqual(drop_byte_count, 0)

        U.run_and_drop(self, self.device, INPUT_PACKET, ports[0].slice, ports[0].ifg, ports[0].first_serdes)

        enqueue_packet_count, enqueue_byte_count = rx_drop_voq_counter.read(0, True, True)
        drop_packet_count, drop_byte_count = rx_drop_voq_counter.read(1, True, True)

        # The packets should be dropped, so verify that the ENQUEUE counter is empty
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)

        expected_packet_size = U.get_injected_packet_len(self.device, INPUT_PACKET, ports[0].slice)
        self.assertEqual(drop_packet_count, 1)
        self.assertEqual(drop_byte_count, expected_packet_size)

        # Restore trap configuration
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING, *prev_trap_config)

    def test_svl_active_05_well_known_destination_rx_drop(self):
        #sw = SvlBase.switch
        #print('Flood Destination = ', sw.get_flood_destination())
        LOCAL_UNKNOWN_DA = T.mac_addr('00:DE:AD:BE:EF:11')
        SA = T.mac_addr('00:DE:AD:BE:EF:00')
        SIP = T.ipv4_addr('192.168.10.10')
        DIP_UC = T.ipv4_addr('192.168.10.100')

        INPUT_PACKET_BASE = \
            Ether(dst=LOCAL_UNKNOWN_DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        rx_drop_voq_counter = self.device.get_forwarding_drop_counter()

        enqueue_packet_count, enqueue_byte_count = rx_drop_voq_counter.read(0,    # ENQUEUE counter
                                                                            True,  # force_update
                                                                            True)  # clear_on_read
        drop_packet_count, drop_byte_count = rx_drop_voq_counter.read(1,      # DROP counter
                                                                      True,   # force_update
                                                                      True)   # clear_on_read
        # Verify the counter is empty.
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)
        self.assertEqual(drop_packet_count, 0)
        self.assertEqual(drop_byte_count, 0)

        U.run_and_drop(self, self.device, INPUT_PACKET, ports[0].slice, ports[0].ifg, ports[0].first_serdes)

        enqueue_packet_count, enqueue_byte_count = rx_drop_voq_counter.read(0, True, True)
        drop_packet_count, drop_byte_count = rx_drop_voq_counter.read(1, True, True)

        # The packets should be dropped, so verify that the ENQUEUE counter is empty
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)

        expected_packet_size = U.get_injected_packet_len(self.device, INPUT_PACKET, ports[0].slice)
        self.assertEqual(drop_packet_count, 1)
        self.assertEqual(drop_byte_count, expected_packet_size)


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

    def test_svl_standby_00_local_l2_unicast(self):
        LOCAL_DA = T.mac_addr('00:DE:AD:BE:EF:03')
        SA = T.mac_addr('00:DE:AD:BE:EF:00')
        SIP = T.ipv4_addr('50.50.50.50')
        DIP_UC = T.ipv4_addr('80.80.80.80')

        INPUT_PACKET_BASE = \
            Ether(dst=LOCAL_DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        U.run_and_compare(
            self,
            self.device,
            INPUT_PACKET,
            ports[0].slice,
            ports[0].ifg,
            ports[0].first_serdes,
            INPUT_PACKET,
            ports[3].slice,
            ports[3].ifg,
            ports[3].first_serdes)

    def test_svl_standby_01_remote_l2_unicast(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        LOCAL_DA = T.mac_addr('00:DE:AD:BE:EF:03')
        SA = T.mac_addr('00:BE:EF:CA:FE:01')
        SIP = T.ipv4_addr('20.20.20.20')
        DIP_UC = T.ipv4_addr('80.80.80.80')

        OUTPUT_PACKET_BASE = \
            Ether(dst=LOCAL_DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET, __ = U.enlarge_packet_to_min_length(OUTPUT_PACKET_BASE)

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[1].slice,
            'ifg': stack_ports[1].ifg,
            'pif': stack_ports[1].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[3].slice, 'ifg': ports[3].ifg, 'pif': ports[3].first_serdes, 'data': OUTPUT_PACKET})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)

    def test_svl_standby_02_remote_l3_unicast(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        OUT_DA = T.mac_addr('00:BE:EF:BA:BE:07')  # NH1 MAC
        OUT_SA = T.mac_addr('00:DE:AD:BE:EF:07')  # L3 AC1
        SIP = T.ipv4_addr('20.20.20.20')
        DIP_UC = T.ipv4_addr('80.80.80.80')

        OUTPUT_PACKET_BASE = \
            Ether(dst=OUT_DA.addr_str, src=OUT_SA.addr_str) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET, __ = U.enlarge_packet_to_min_length(OUTPUT_PACKET_BASE)

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[1].slice,
            'ifg': stack_ports[1].ifg,
            'pif': stack_ports[1].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[7].slice, 'ifg': ports[7].ifg, 'pif': ports[7].first_serdes, 'data': OUTPUT_PACKET})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)

    def test_svl_standby_03_well_known_destination_0(self):
        # Save current trap configuration
        prev_trap_config = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)

        # Configure trap to superior priority and to drop
        destination = None
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING, 0, None, destination, False, False, True, 0)

        DA = T.mac_addr('00:DE:AD:BE:EF:99')
        SA = T.mac_addr('00:DE:AD:BE:EF:88')
        SIP = T.ipv4_addr('192.168.1.1')
        DIP = T.ipv4_addr('192.168.1.10')

        NO_SERVICE_MAPPING_VID = BASEVID0 + 1
        INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str) / \
            Dot1Q(vlan=NO_SERVICE_MAPPING_VID) / \
            IP(src=SIP.addr_str, dst=DIP.addr_str)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        rx_drop_voq_counter = self.device.get_forwarding_drop_counter()

        enqueue_packet_count, enqueue_byte_count = rx_drop_voq_counter.read(0,    # ENQUEUE counter
                                                                            True,  # force_update
                                                                            True)  # clear_on_read
        drop_packet_count, drop_byte_count = rx_drop_voq_counter.read(1,      # DROP counter
                                                                      True,   # force_update
                                                                      True)   # clear_on_read
        # Verify the counter is empty.
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)
        self.assertEqual(drop_packet_count, 0)
        self.assertEqual(drop_byte_count, 0)

        U.run_and_drop(self, self.device, INPUT_PACKET, ports[0].slice, ports[0].ifg, ports[0].first_serdes)

        enqueue_packet_count, enqueue_byte_count = rx_drop_voq_counter.read(0, True, True)
        drop_packet_count, drop_byte_count = rx_drop_voq_counter.read(1, True, True)

        # The packets should be dropped, so verify that the ENQUEUE counter is empty
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)

        expected_packet_size = U.get_injected_packet_len(self.device, INPUT_PACKET, ports[0].slice)
        self.assertEqual(drop_packet_count, 1)
        self.assertEqual(drop_byte_count, expected_packet_size)

        # Restore trap configuration
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING, *prev_trap_config)

    def test_svl_standby_04_well_known_destination_rx_drop(self):
        #sw = SvlBase.switch
        #print('Flood Destination = ', sw.get_flood_destination())
        LOCAL_UNKNOWN_DA = T.mac_addr('00:DE:AD:BE:EF:11')
        SA = T.mac_addr('00:DE:AD:BE:EF:00')
        SIP = T.ipv4_addr('192.168.10.10')
        DIP_UC = T.ipv4_addr('192.168.10.100')

        INPUT_PACKET_BASE = \
            Ether(dst=LOCAL_UNKNOWN_DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        rx_drop_voq_counter = self.device.get_forwarding_drop_counter()

        enqueue_packet_count, enqueue_byte_count = rx_drop_voq_counter.read(0,    # ENQUEUE counter
                                                                            True,  # force_update
                                                                            True)  # clear_on_read
        drop_packet_count, drop_byte_count = rx_drop_voq_counter.read(1,      # DROP counter
                                                                      True,   # force_update
                                                                      True)   # clear_on_read
        # Verify the counter is empty.
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)
        self.assertEqual(drop_packet_count, 0)
        self.assertEqual(drop_byte_count, 0)

        U.run_and_drop(self, self.device, INPUT_PACKET, ports[0].slice, ports[0].ifg, ports[0].first_serdes)

        enqueue_packet_count, enqueue_byte_count = rx_drop_voq_counter.read(0, True, True)
        drop_packet_count, drop_byte_count = rx_drop_voq_counter.read(1, True, True)

        # The packets should be dropped, so verify that the ENQUEUE counter is empty
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)

        expected_packet_size = U.get_injected_packet_len(self.device, INPUT_PACKET, ports[0].slice)
        self.assertEqual(drop_packet_count, 1)
        self.assertEqual(drop_byte_count, expected_packet_size)
