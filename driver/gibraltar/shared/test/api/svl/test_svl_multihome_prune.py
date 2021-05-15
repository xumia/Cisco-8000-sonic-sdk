#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import decor
import packet_test_utils as U
import topology as T
import svl_base

from leaba import sdk
from svl_base import *
from packet_test_defs import *


SvlTestPair = {
    "test_svl_standby_multihome_flood": "test_svl_active_multihome_flood"
}


@unittest.skipIf(not (decor.is_gibraltar()), "Test is applicable only on Gibraltar")
@unittest.skipIf(decor.is_matilda('3.2'), "These tests require at least 4 slices, Matilda has 3, so skip.")
class SvlMultiHomeActive(unittest.TestCase, svl_base.SvlBaseActiveContext):
    topology_init_done = False
    base = None

    def setUp(self):
        if not SvlMultiHomeActive.topology_init_done:
            self.base = SvlBase(self.device_id, self.remote_device_id, self.switch_num, self.active)
            self.device = SvlBase.dev

            self.topology = T.topology(self, self.device, create_default_topology=False)
            ingress_qos_profile = T.ingress_qos_profile(self, self.device)
            egress_qos_profile = T.egress_qos_profile(self, self.device)
            self.base.create_multihome_topology(self, ingress_qos_profile, egress_qos_profile)
            SvlMultiHomeActive.topology_init_done = True

            SvlMultiHomeActive.base = self.base
            self.base.stackport.set_peer_device_id(self.remote_device_id)
        self.device = SvlBase.dev
        self.base = SvlMultiHomeActive.base

    @classmethod
    def tearDownClass(cls):
        if SvlBase.dev is not None:
            SvlBase.dev.tearDown()
        del cls

    def test_svl_active_multihome_flood(self):
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
        expected_packets.append({'data': INPUT_PACKET, 'slice': ports[4].slice, 'ifg': ports[4].ifg, 'pif': ports[4].first_serdes})
        expected_packets.append({'data': INPUT_PACKET, 'slice': ports[5].slice, 'ifg': ports[5].ifg, 'pif': ports[5].first_serdes})
        expected_packets.append({'data': INPUT_PACKET, 'slice': ports[6].slice, 'ifg': ports[6].ifg, 'pif': ports[6].first_serdes})
        expected_packets.append({'data': INPUT_PACKET, 'slice': ports[7].slice, 'ifg': ports[7].ifg, 'pif': ports[7].first_serdes})

        unchecked = run_and_compare_list_then_save(self, self.device, ingress_packet, expected_packets, True, self._testMethodName)
        self.assertEqual(len(unchecked), 1)


@unittest.skipIf(not (decor.is_gibraltar()), "Test is applicable only on Gibraltar")
@unittest.skipIf(decor.is_matilda('3.2'), "These tests require at least 4 slices, Matilda has 3, so skip.")
class SvlMultiHomeStandby(unittest.TestCase, svl_base.SvlBaseStandbyContext):
    topology_init_done = False
    base = None

    def setUp(self):
        if not SvlMultiHomeStandby.topology_init_done:
            self.base = SvlBase(self.device_id, self.remote_device_id, self.switch_num, self.active)
            self.device = SvlBase.dev

            self.topology = T.topology(self, self.device, create_default_topology=False)
            ingress_qos_profile = T.ingress_qos_profile(self, self.device)
            egress_qos_profile = T.egress_qos_profile(self, self.device)
            self.base.create_multihome_topology(self, ingress_qos_profile, egress_qos_profile)
            SvlMultiHomeStandby.topology_init_done = True

            SvlMultiHomeStandby.base = self.base
            self.base.stackport.set_peer_device_id(self.remote_device_id)
        self.device = SvlBase.dev
        self.base = SvlMultiHomeStandby.base

    @classmethod
    def tearDownClass(cls):
        if SvlBase.dev is not None:
            SvlBase.dev.tearDown()
        del cls

    def test_svl_standby_multihome_flood(self):
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
                                 'slice': ports[4].slice,
                                 'ifg': ports[4].ifg,
                                 'pif': ports[4].first_serdes})
        expected_packets.append({'data': REMOTE_INPUT_PACKET,
                                 'slice': ports[5].slice,
                                 'ifg': ports[5].ifg,
                                 'pif': ports[5].first_serdes})
        expected_packets.append({'data': REMOTE_INPUT_PACKET,
                                 'slice': ports[6].slice,
                                 'ifg': ports[6].ifg,
                                 'pif': ports[6].first_serdes})
        expected_packets.append({'data': REMOTE_INPUT_PACKET,
                                 'slice': ports[7].slice,
                                 'ifg': ports[7].ifg,
                                 'pif': ports[7].first_serdes})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        remove_saved_pcap(pcap_in)


if __name__ == '__main__':
    unittest.main()
