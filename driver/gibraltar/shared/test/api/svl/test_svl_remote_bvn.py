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

import unittest
import svl_base
import decor

from leaba import sdk
import packet_test_utils as U
import topology as T
from packet_test_defs import *
from scapy.all import *
import svl_base
from svl_base import *

SvlTestPair = {
    "test_standby_route_to_local_subif_from_remote_subif": "test_active_route_to_remote_subif_from_local_subif"
}


@unittest.skipIf(not decor.is_gibraltar(), "Test is applicable only on Gibraltar")
@unittest.skipIf(decor.is_matilda('3.2'), "These tests require at least 4 slices, Matilda has 3, so skip.")
class SvlRemoteBvnActive(unittest.TestCase, svl_base.SvlBaseActiveContext):
    topology_init_done = False
    base = None
    dev = None
    topology = None

    def setUp(self):
        if not SvlRemoteBvnActive.topology_init_done:
            if SvlRemoteBvnActive.dev is None:
                self.base = SvlBase(self.device_id, self.remote_device_id, self.switch_num, self.active)
                self.device = SvlBase.dev
                SvlRemoteBvnActive.dev = self.device
                SvlRemoteBvnActive.base = self.base
            else:
                self.base = SvlRemoteBvnActive.base
                self.device = SvlRemoteBvnActive.dev

            self.topology = T.topology(self, self.device, create_default_topology=False)
            ingress_qos_profile = T.ingress_qos_profile(self, self.device)
            egress_qos_profile = T.egress_qos_profile(self, self.device)
            self.base.create_topology(self, ingress_qos_profile, egress_qos_profile)
            SvlRemoteBvnActive.topology = self.topology
            SvlRemoteBvnActive.topology_init_done = True
            self.base.create_l3_sub_interface_topology(self, self.topology, ingress_qos_profile, egress_qos_profile)

        self.device = SvlBase.dev
        self.base = SvlRemoteBvnActive.base
        self.topology = SvlRemoteBvnActive.topology

    @classmethod
    def tearDownClass(cls):
        if SvlRemoteBvnActive.dev is not None:
            SvlRemoteBvnActive.dev.tearDown()
        del cls

    def test_route_to_sub_interface(self):
        DA = T.mac_addr('00:BE:EF:CA:FE:04')
        SA = T.mac_addr('00:AB:CD:AB:CD:01')
        SIP = T.ipv4_addr('10.10.10.10')
        DIP_UC = T.ipv4_addr('10.20.01.20')

        INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=BASEVID0) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        OUT_DA = T.mac_addr('00:DE:E0:CA:FE:01')  # NH MAC
        OUT_SA = T.mac_addr('00:BE:E0:CA:FE:01')  # L3 AC MAC
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
            ports[8].slice,
            ports[8].ifg,
            ports[8].first_serdes)

    def test_route_to_l3_interface_from_sub_interface(self):
        DA = T.mac_addr('00:BE:E0:CA:FE:01')
        SA = T.mac_addr('00:AB:CD:AB:CD:02')
        SIP = T.ipv4_addr('20.10.1.10')
        DIP_UC = T.ipv4_addr('20.20.20.20')

        INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=L3_SUBIF_VLAN_BASE) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        OUT_DA = T.mac_addr('00:CA:FE:BA:BE:05')  # NH MAC
        OUT_SA = T.mac_addr('00:BE:EF:CA:FE:05')  # L3 AC MAC
        OUTPUT_PACKET_BASE = \
            Ether(dst=OUT_DA.addr_str, src=OUT_SA.addr_str) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=124) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        OUTPUT_PACKET, __ = U.enlarge_packet_to_min_length(OUTPUT_PACKET_BASE)

        U.run_and_compare(
            self,
            self.device,
            INPUT_PACKET,
            ports[8].slice,
            ports[8].ifg,
            ports[8].first_serdes,
            OUTPUT_PACKET,
            ports[5].slice,
            ports[5].ifg,
            ports[5].first_serdes)

    def test_active_route_to_remote_subif_from_local_subif(self):
        DA = T.mac_addr('00:BE:E0:CA:FE:01')
        SA = T.mac_addr('00:AB:CD:AB:CD:02')
        SIP = T.ipv4_addr('10.20.1.10')
        DIP_UC = T.ipv4_addr('20.10.1.20')

        INPUT_PACKET_BASE = \
            Ether(dst=DA.addr_str, src=SA.addr_str, type=0x8100) / \
            Dot1Q(vlan=L3_SUBIF_VLAN_BASE) / \
            IP(src=SIP.addr_str, dst=DIP_UC.addr_str, ttl=125) / \
            TCP(sport=0x1234, dport=0x2345) / Raw(load=RAW_PAYLOAD)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        ingress_packet = {'data': INPUT_PACKET, 'slice': ports[8].slice, 'ifg': ports[8].ifg, 'pif': ports[8].first_serdes}
        expected_packets = []
        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        self.assertEqual(len(unchecked), 1)


@unittest.skipIf(not decor.is_gibraltar(), "Test is applicable only on Gibraltar")
@unittest.skipIf(decor.is_matilda('3.2'), "These tests require at least 4 slices, Matilda has 3, so skip.")
class SvlRemoteBvnStandby(unittest.TestCase, svl_base.SvlBaseStandbyContext):
    topology_init_done = False
    base = None
    dev = None
    topology = None

    def setUp(self):
        if not SvlRemoteBvnStandby.topology_init_done:
            if SvlRemoteBvnStandby.dev is None:
                self.base = SvlBase(self.device_id, self.remote_device_id, self.switch_num, self.active)
                self.device = SvlBase.dev
                SvlRemoteBvnStandby.dev = self.device
                SvlRemoteBvnStandby.base = self.base
            else:
                self.base = SvlRemoteBvnStandby.base
                self.device = SvlRemoteBvnStandby.dev

            self.topology = T.topology(self, self.device, create_default_topology=False)
            ingress_qos_profile = T.ingress_qos_profile(self, self.device)
            egress_qos_profile = T.egress_qos_profile(self, self.device)
            self.base.create_topology(self, ingress_qos_profile, egress_qos_profile)
            SvlRemoteBvnStandby.topology = self.topology
            SvlRemoteBvnStandby.topology_init_done = True
            self.base.create_l3_sub_interface_topology(self, self.topology, ingress_qos_profile, egress_qos_profile)

        self.device = SvlBase.dev
        self.base = SvlRemoteBvnStandby.base
        self.topology = SvlRemoteBvnStandby.topology

    @classmethod
    def tearDownClass(cls):
        if SvlRemoteBvnStandby.dev is not None:
            SvlRemoteBvnStandby.dev.tearDown()
        del cls

    def test_standby_route_to_local_subif_from_remote_subif(self):
        pcap_in = SvlTestPair[self._testMethodName]
        INPUT_PACKET = get_packet_from_saved_pcap(pcap_in)
        self.assertTrue((INPUT_PACKET is not None))

        OUT_DA = T.mac_addr('00:CE:E0:CA:FE:01')  # NH MAC
        OUT_SA = T.mac_addr('00:AE:E0:CA:FE:01')  # L3 AC MAC
        SIP = T.ipv4_addr('10.20.1.10')
        DIP_UC = T.ipv4_addr('20.10.1.20')
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
        expected_packets.append({'slice': ports[8].slice, 'ifg': ports[8].ifg, 'pif': ports[8].first_serdes, 'data': OUTPUT_PACKET})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)
        remove_saved_pcap(pcap_in)


if __name__ == '__main__':
    unittest.main()
