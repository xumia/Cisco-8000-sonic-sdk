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
    "test_svl_standby_l2_flood": "test_svl_active_l2_flood",
    "test_svl_standby_ip_multicast": "test_svl_active_ip_multicast",
    "test_svl_standby_ip_multicast_with_svi": "test_svl_active_ip_multicast_with_svi",
    "test_svl_standby_ip_multicast_with_svi_traffic_from_remote_l2": "test_svl_active_ip_multicast_with_svi_traffic_from_l2"}


@unittest.skipIf(not decor.is_gibraltar(), "Test is applicable only on GB")
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
            self.base.create_topology(self, ingress_qos_profile, egress_qos_profile, True)
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

    @staticmethod
    def get_mc_addr_str(ip_addr):
        octets = ip_addr.addr_str.split('.')
        assert(len(octets) == 4)
        mac_addr_str = '01:00:5e'
        mac_addr_str += ':%02x' % (0x7f & int(octets[1]))
        for o in octets[2:]:
            mac_addr_str += ':%02x' % (int(o))
        return mac_addr_str

    def test_svl_active_l2_flood(self):
        LOCAL_UNKNOWN_DA = T.mac_addr('00:DE:AD:BE:EF:11')
        SA = T.mac_addr('00:DE:AD:BE:EF:12')
        SIP = T.ipv4_addr('192.168.10.100')
        DIP_UC = T.ipv4_addr('192.168.10.200')

        INPUT_PACKET_BASE = \
            Ether(dst=LOCAL_UNKNOWN_DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[0].slice, 'ifg': ports[0].ifg, 'pif': ports[0].first_serdes}
        expected_packets = []
        expected_packets.append({'data': INPUT_PACKET, 'slice': ports[1].slice, 'ifg': ports[1].ifg, 'pif': ports[1].first_serdes})
        expected_packets.append({'data': INPUT_PACKET, 'slice': ports[2].slice, 'ifg': ports[2].ifg, 'pif': ports[2].first_serdes})
        expected_packets.append({'data': INPUT_PACKET, 'slice': ports[3].slice, 'ifg': ports[3].ifg, 'pif': ports[3].first_serdes})

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        self.assertEqual(len(unchecked), 1)

    def test_svl_active_local_ip_multicast(self):
        OUT_SA = T.mac_addr('00:BE:EF:CA:FE:05')
        SA = T.mac_addr('00:01:02:CA:FE:00')
        SIP = T.ipv4_addr('192.168.10.100')
        DIP_MC = T.ipv4_addr('224.0.1.3')

        RAW_PAYLOAD = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'
        INPUT_PACKET_BASE = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_0 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src=OUT_SA.addr_str) / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[4].slice, 'ifg': ports[4].ifg, 'pif': ports[4].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[5].slice, 'ifg': ports[5].ifg,
                                 'pif': ports[5].first_serdes, 'data': OUTPUT_PACKET_0})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def test_svl_active_ip_multicast(self):
        OUT_SA = T.mac_addr('00:BE:EF:CA:FE:07')
        SA = T.mac_addr('00:01:02:CA:FE:00')
        SIP = T.ipv4_addr('192.168.10.100')
        DIP_MC = T.ipv4_addr('224.0.1.4')

        RAW_PAYLOAD = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'
        INPUT_PACKET_BASE = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_0 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src=OUT_SA.addr_str) / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[6].slice, 'ifg': ports[6].ifg, 'pif': ports[6].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[7].slice, 'ifg': ports[7].ifg,
                                 'pif': ports[7].first_serdes, 'data': OUTPUT_PACKET_0})

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        self.assertEqual(len(unchecked), 1)

    def test_svl_active_ip_multicast_with_svi(self):
        SA = T.mac_addr('00:01:02:CA:FE:00')
        SIP = T.ipv4_addr('192.168.10.100')
        DIP_MC = T.ipv4_addr('224.0.1.2')

        RAW_PAYLOAD = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'
        INPUT_PACKET_BASE = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_0 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:BE:EF:CA:FE:04') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_1 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:BE:EF:CA:FE:06') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_2 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:BE:EF:CA:FE:07') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_3 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:00:C0:FF:EE:00') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[5].slice, 'ifg': ports[5].ifg, 'pif': ports[5].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[4].slice, 'ifg': ports[4].ifg,
                                 'pif': ports[4].first_serdes, 'data': OUTPUT_PACKET_0})
        expected_packets.append({'slice': ports[6].slice, 'ifg': ports[6].ifg,
                                 'pif': ports[6].first_serdes, 'data': OUTPUT_PACKET_1})
        expected_packets.append({'slice': ports[7].slice, 'ifg': ports[7].ifg,
                                 'pif': ports[7].first_serdes, 'data': OUTPUT_PACKET_2})
        expected_packets.append({'slice': ports[0].slice, 'ifg': ports[0].ifg,
                                 'pif': ports[0].first_serdes, 'data': OUTPUT_PACKET_3})
        expected_packets.append({'slice': ports[1].slice, 'ifg': ports[1].ifg,
                                 'pif': ports[1].first_serdes, 'data': OUTPUT_PACKET_3})
        expected_packets.append({'slice': ports[2].slice, 'ifg': ports[2].ifg,
                                 'pif': ports[2].first_serdes, 'data': OUTPUT_PACKET_3})
        expected_packets.append({'slice': ports[3].slice, 'ifg': ports[3].ifg,
                                 'pif': ports[3].first_serdes, 'data': OUTPUT_PACKET_3})

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        self.assertEqual(len(unchecked), 1)

    def test_svl_active_ip_multicast_with_svi_traffic_from_l2(self):
        SA = T.mac_addr('00:01:02:CA:FE:00')
        SIP = T.ipv4_addr('192.168.10.100')
        DIP_MC = T.ipv4_addr('224.0.1.2')

        RAW_PAYLOAD = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'
        INPUT_PACKET_BASE = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_0 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:BE:EF:CA:FE:04') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_1 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:BE:EF:CA:FE:05') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_2 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:BE:EF:CA:FE:06') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_3 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:BE:EF:CA:FE:07') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_4 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[1].slice, 'ifg': ports[1].ifg, 'pif': ports[1].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[4].slice, 'ifg': ports[4].ifg,
                                 'pif': ports[4].first_serdes, 'data': OUTPUT_PACKET_0})
        expected_packets.append({'slice': ports[5].slice, 'ifg': ports[5].ifg,
                                 'pif': ports[5].first_serdes, 'data': OUTPUT_PACKET_1})
        expected_packets.append({'slice': ports[6].slice, 'ifg': ports[6].ifg,
                                 'pif': ports[6].first_serdes, 'data': OUTPUT_PACKET_2})
        expected_packets.append({'slice': ports[7].slice, 'ifg': ports[7].ifg,
                                 'pif': ports[7].first_serdes, 'data': OUTPUT_PACKET_3})
        expected_packets.append({'slice': ports[0].slice, 'ifg': ports[0].ifg,
                                 'pif': ports[0].first_serdes, 'data': OUTPUT_PACKET_4})
        expected_packets.append({'slice': ports[2].slice, 'ifg': ports[2].ifg,
                                 'pif': ports[2].first_serdes, 'data': OUTPUT_PACKET_4})
        expected_packets.append({'slice': ports[3].slice, 'ifg': ports[3].ifg,
                                 'pif': ports[3].first_serdes, 'data': OUTPUT_PACKET_4})

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        self.assertEqual(len(unchecked), 1)


@unittest.skipIf(not decor.is_gibraltar(), "Test is applicable only on GB")
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
            self.base.create_topology(self, ingress_qos_profile, egress_qos_profile, True)
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

    @staticmethod
    def get_mc_addr_str(ip_addr):
        octets = ip_addr.addr_str.split('.')
        assert(len(octets) == 4)
        mac_addr_str = '01:00:5e'
        mac_addr_str += ':%02x' % (0x7f & int(octets[1]))
        for o in octets[2:]:
            mac_addr_str += ':%02x' % (int(o))
        return mac_addr_str

    def test_svl_standby_l2_flood(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        LOCAL_UNKNOWN_DA = T.mac_addr('00:DE:AD:BE:EF:11')
        SA = T.mac_addr('00:DE:AD:BE:EF:12')
        SIP = T.ipv4_addr('192.168.10.100')
        DIP_UC = T.ipv4_addr('192.168.10.200')

        REMOTE_INPUT_PACKET_BASE = \
            Ether(dst=LOCAL_UNKNOWN_DA.addr_str, src=SA.addr_str, type=0x8100) / \
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
        expected_packets.append({'data': REMOTE_INPUT_PACKET,
                                 'slice': ports[1].slice,
                                 'ifg': ports[1].ifg,
                                 'pif': ports[1].first_serdes})
        expected_packets.append({'data': REMOTE_INPUT_PACKET,
                                 'slice': ports[2].slice,
                                 'ifg': ports[2].ifg,
                                 'pif': ports[2].first_serdes})
        expected_packets.append({'data': REMOTE_INPUT_PACKET,
                                 'slice': ports[3].slice,
                                 'ifg': ports[3].ifg,
                                 'pif': ports[3].first_serdes})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)

    def test_svl_standby_local_ip_multicast(self):
        OUT_SA = T.mac_addr('00:DE:AD:BE:EF:04')
        SA = T.mac_addr('00:01:02:CA:FE:00')
        SIP = T.ipv4_addr('192.168.10.100')
        DIP_MC = T.ipv4_addr('224.0.1.3')

        RAW_PAYLOAD = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'
        INPUT_PACKET_BASE = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_0 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src=OUT_SA.addr_str) / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[5].slice, 'ifg': ports[5].ifg, 'pif': ports[5].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[4].slice, 'ifg': ports[4].ifg,
                                 'pif': ports[4].first_serdes, 'data': OUTPUT_PACKET_0})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def test_svl_standby_ip_multicast(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        SA = T.mac_addr('00:01:02:CA:FE:00')
        SIP = T.ipv4_addr('192.168.10.100')
        DIP_MC = T.ipv4_addr('224.0.1.4')

        RAW_PAYLOAD = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'

        OUTPUT_PACKET_0 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src="00:DE:AD:BE:EF:06") / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_1 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src="00:DE:AD:BE:EF:07") / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[1].slice,
            'ifg': stack_ports[1].ifg,
            'pif': stack_ports[1].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[6].slice, 'ifg': ports[6].ifg,
                                 'pif': ports[6].first_serdes, 'data': OUTPUT_PACKET_0})
        expected_packets.append({'slice': ports[7].slice, 'ifg': ports[7].ifg,
                                 'pif': ports[7].first_serdes, 'data': OUTPUT_PACKET_1})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)

    def test_svl_standby_ip_multicast_with_svi(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        SA = T.mac_addr('00:01:02:CA:FE:00')
        SIP = T.ipv4_addr('192.168.10.100')
        DIP_MC = T.ipv4_addr('224.0.1.2')

        RAW_PAYLOAD = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'

        OUTPUT_PACKET_0 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:DE:AD:BE:EF:04') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_1 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:DE:AD:BE:EF:05') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_2 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:DE:AD:BE:EF:06') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_3 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:DE:AD:BE:EF:07') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_4 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:00:C0:FF:EE:00') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[0].slice,
            'ifg': stack_ports[0].ifg,
            'pif': stack_ports[0].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[4].slice, 'ifg': ports[4].ifg,
                                 'pif': ports[4].first_serdes, 'data': OUTPUT_PACKET_0})
        expected_packets.append({'slice': ports[5].slice, 'ifg': ports[5].ifg,
                                 'pif': ports[5].first_serdes, 'data': OUTPUT_PACKET_1})
        expected_packets.append({'slice': ports[6].slice, 'ifg': ports[6].ifg,
                                 'pif': ports[6].first_serdes, 'data': OUTPUT_PACKET_2})
        expected_packets.append({'slice': ports[7].slice, 'ifg': ports[7].ifg,
                                 'pif': ports[7].first_serdes, 'data': OUTPUT_PACKET_3})
        expected_packets.append({'slice': ports[0].slice, 'ifg': ports[0].ifg,
                                 'pif': ports[0].first_serdes, 'data': OUTPUT_PACKET_4})
        expected_packets.append({'slice': ports[1].slice, 'ifg': ports[1].ifg,
                                 'pif': ports[1].first_serdes, 'data': OUTPUT_PACKET_4})
        expected_packets.append({'slice': ports[2].slice, 'ifg': ports[2].ifg,
                                 'pif': ports[2].first_serdes, 'data': OUTPUT_PACKET_4})
        expected_packets.append({'slice': ports[3].slice, 'ifg': ports[3].ifg,
                                 'pif': ports[3].first_serdes, 'data': OUTPUT_PACKET_4})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)

    def test_svl_standby_ip_multicast_with_svi_traffic_from_remote_l2(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        if INPUT_PACKET is None:
            self.assertTrue(False)

        SA = T.mac_addr('00:01:02:CA:FE:00')
        SIP = T.ipv4_addr('192.168.10.100')
        DIP_MC = T.ipv4_addr('224.0.1.2')

        RAW_PAYLOAD = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'

        OUTPUT_PACKET_0 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:DE:AD:BE:EF:04') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_1 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:DE:AD:BE:EF:05') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_2 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:DE:AD:BE:EF:06') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_3 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src='00:DE:AD:BE:EF:07') / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET_4 = \
            Ether(dst=SvlBaseActive.get_mc_addr_str(DIP_MC), src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_MC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        ingress_packet = {
            'data': INPUT_PACKET,
            'slice': stack_ports[1].slice,
            'ifg': stack_ports[1].ifg,
            'pif': stack_ports[1].first_serdes}
        expected_packets = []
        expected_packets.append({'slice': ports[4].slice, 'ifg': ports[4].ifg,
                                 'pif': ports[4].first_serdes, 'data': OUTPUT_PACKET_0})
        expected_packets.append({'slice': ports[5].slice, 'ifg': ports[5].ifg,
                                 'pif': ports[5].first_serdes, 'data': OUTPUT_PACKET_1})
        expected_packets.append({'slice': ports[6].slice, 'ifg': ports[6].ifg,
                                 'pif': ports[6].first_serdes, 'data': OUTPUT_PACKET_2})
        expected_packets.append({'slice': ports[7].slice, 'ifg': ports[7].ifg,
                                 'pif': ports[7].first_serdes, 'data': OUTPUT_PACKET_3})
        expected_packets.append({'slice': ports[0].slice, 'ifg': ports[0].ifg,
                                 'pif': ports[0].first_serdes, 'data': OUTPUT_PACKET_4})
        expected_packets.append({'slice': ports[1].slice, 'ifg': ports[1].ifg,
                                 'pif': ports[1].first_serdes, 'data': OUTPUT_PACKET_4})
        expected_packets.append({'slice': ports[2].slice, 'ifg': ports[2].ifg,
                                 'pif': ports[2].first_serdes, 'data': OUTPUT_PACKET_4})
        expected_packets.append({'slice': ports[3].slice, 'ifg': ports[3].ifg,
                                 'pif': ports[3].first_serdes, 'data': OUTPUT_PACKET_4})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)
