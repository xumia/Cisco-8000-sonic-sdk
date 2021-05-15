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

import unittest
from leaba import sdk
from leaba.debug import debug_device
from packet_test_utils import *
import decor
import topology as T
from scapy.all import *
import nplapicli
from bit_utils import *

from sdk_test_case_base import *

SA = T.mac_addr('be:ef:5d:35:7a:35')
SIP = T.ipv4_addr('192.193.194.195')
DIP = T.ipv4_addr('208.209.210.211')
TTL = 127
PRIVATE_DATA_DEFAULT = 0xfedcba9876543210

RX_L3_AC_GID = 0x900
RX_L3_AC_MAC = T.mac_addr('12:34:45:67:89:01')

INPUT_PACKET_BASE = \
    Ether(dst=RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.Dot1Q.value) / \
    Dot1Q(vlan=T.RX_L3_AC_PORT_VID1) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

EXPECTED_DEFAULT_OUTPUT_PACKET_BASE = \
    Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
    IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1)

INPUT_PACKET, INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
EXPECTED_DEFAULT_OUTPUT_PACKET = add_payload(EXPECTED_DEFAULT_OUTPUT_PACKET_BASE, INPUT_PACKET_PAYLOAD_SIZE)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class flow_cache(sdk_test_case_base):

    def setUp(self):
        super().setUp()

        self.dd = debug_device(self.device)
        self.add_default_route()
        self.rx_l3_ac_port = T.l3_ac_port(
            self,
            self.device,
            RX_L3_AC_GID,
            self.topology.rx_eth_port,
            self.topology.vrf,
            RX_L3_AC_MAC,
            T.RX_L3_AC_PORT_VID1)
        self.rx_l3_ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

    def add_default_route(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.nh_l3_ac_reg.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def do_test_route_default(self):
        run_and_compare(self, self.device,
                        INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3)

    def disable_delete_mechanisms(self):
        for slice_id in self.device.get_used_slices():
            reg = self.dd.read_register(self.dd.device_tree.slice[slice_id].npu.rxpp_fwd.flc_queues.data_random_delete)
            reg.data_random_delete_th = 0xffff
            self.dd.write_register(self.dd.device_tree.slice[slice_id].npu.rxpp_fwd.flc_queues.data_random_delete, reg)
            reg = self.dd.read_register(self.dd.device_tree.slice[slice_id].npu.rxpp_fwd.flc_queues.data_aging_cycle)
            reg.data_activity_aging_cycle_value = 0
            reg.data_aging_cycle_value = 0
            self.dd.write_register(self.dd.device_tree.slice[slice_id].npu.rxpp_fwd.flc_queues.data_aging_cycle, reg)
            reg = self.dd.read_register(self.dd.device_tree.slice[slice_id].npu.rxpp_fwd.flc_queues.disable_ser_packets_removal_reg)
            reg.disable_ser_packets_removal = 1
            self.dd.write_register(self.dd.device_tree.slice[slice_id].npu.rxpp_fwd.flc_queues.disable_ser_packets_removal_reg, reg)

    def disable_changing_the_verifier_seed(self):
        for slice_id in self.device.get_used_slices():
            reg = self.dd.read_register(self.dd.device_tree.slice[slice_id].npu.rxpp_term.flc_db.verifier_update_rate_reg)
            reg.verifier_update_rate = 0
            self.dd.write_register(self.dd.device_tree.slice[slice_id].npu.rxpp_term.flc_db.verifier_update_rate_reg, reg)

    @unittest.skipUnless(decor.is_hw_gibraltar(), "Flow cache only works on GB. Test is not enabled yet for GB NSIM.")
    def test_flow_cache(self):
        # Injecting packet is "slow" process, we disable deleting mechanisms and
        # disable changing verifier seed so second packet hit cache instead of miss
        self.disable_delete_mechanisms()
        self.disable_changing_the_verifier_seed()

        self.do_test_route_default()

        flc = self.device.get_flow_cache_handler()
        self.assertNotEqual(flc, None)

        flow_cache_counters = flc.get_flow_cache_counters()
        self.assertEqual(flow_cache_counters.hit_counter, 0)
        self.assertEqual(flow_cache_counters.miss_counter, 0)

        flc.set_flow_cache_enabled(True)

        flow_cache_enabled = flc.get_flow_cache_enabled()
        self.assertEqual(flow_cache_enabled, True)

        self.do_test_route_default()

        flow_cache_counters = flc.get_flow_cache_counters()
        self.assertEqual(flow_cache_counters.hit_counter, 0)
        self.assertEqual(flow_cache_counters.miss_counter, 1)

        self.do_test_route_default()

        flow_cache_counters = flc.get_flow_cache_counters()
        self.assertEqual(flow_cache_counters.hit_counter, 1)
        self.assertEqual(flow_cache_counters.miss_counter, 0)

        flc.set_flow_cache_enabled(False)

        flow_cache_enabled = flc.get_flow_cache_enabled()
        self.assertEqual(flow_cache_enabled, False)

        self.do_test_route_default()

        flow_cache_counters = flc.get_flow_cache_counters()
        self.assertEqual(flow_cache_counters.hit_counter, 0)
        self.assertEqual(flow_cache_counters.miss_counter, 0)


if __name__ == '__main__':
    unittest.main()
