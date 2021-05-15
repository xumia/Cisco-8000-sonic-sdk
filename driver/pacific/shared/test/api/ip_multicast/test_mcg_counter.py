#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *

import decor
from packet_test_utils import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
from ipv4_mc import *
from sdk_multi_test_case_base import *
import mtu.mtu_test_utils as MTU
import ip_test_base


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class mcg_counter(sdk_multi_test_case_base):
    MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')

    INPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_L2_SVI_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=T.TX_SVI_MAC.addr_str) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_L3_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=T.TX_L3_AC_REG_MAC.addr_str) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET_L2_SVI = pad_input_and_output_packets(
        INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_L2_SVI_BASE)
    INPUT_PACKET, EXPECTED_OUTPUT_PACKET_L3 = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_L3_BASE)

    output_serdes_svi = T.FIRST_SERDES_SVI
    output_serdes_l3 = T.FIRST_SERDES_L3_REG

    def setUp(self):
        super().setUp()

        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        self.mc_group = self.device.create_ip_multicast_group(mc_base.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)

        self.counter = self.device.create_counter(1)  # set_size=1
        self.device_id = self.device.get_id()
        self.mc_group.set_egress_counter(self.device_id, self.counter)

        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

    @unittest.skipIf(decor.is_hw_pacific(), "Test causing crash on Pacific")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_l2_svi(self):

        self.mc_group.add(
            self.topology.tx_svi.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            self.topology.tx_svi_eth_port_reg.sys_port.hld_obj)

        expected_packets = []
        # receive forward copies
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_L2_SVI, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes_svi})

        self.do_test(expected_packets)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_l3(self):

        self.mc_group.add(self.topology.tx_l3_ac_reg.hld_obj, None, self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj)

        expected_packets = []
        # receive forward copies
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_L3, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes_l3})

        self.do_test(expected_packets)

    def do_test(self, expected_packets):

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.MC_GROUP_ADDR.hld_obj, self.mc_group, None, False, False, None)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}

        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        packet_count, byte_count = self.counter.read(0,  # sub-counter index
                                                     True,  # force_update
                                                     True)  # clear_on_read
        self.assertEqual(packet_count, 1)

        self.assertEqual(byte_count, len(self.INPUT_PACKET) + 4)  # Add CRC counted by Tx MCG counter

        # Remove by setting mcg counter to None and set a new mcg counter
        self.mc_group.set_egress_counter(self.device_id, None)
        cnt1 = self.device.create_counter(1)
        self.mc_group.set_egress_counter(self.device_id, cnt1)
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        packet_count, byte_count = cnt1.read(0,  # sub-counter index
                                             True,  # force_update
                                             True)  # clear_on_read
        self.assertEqual(packet_count, 1)

        # Remove previous mcg counter by setting a new mcg counter
        cnt2 = self.device.create_counter(1)
        self.mc_group.set_egress_counter(self.device_id, cnt2)
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        packet_count, byte_count = cnt2.read(0,  # sub-counter index
                                             True,  # force_update
                                             True)  # clear_on_read
        self.assertEqual(packet_count, 1)

        # Loop over all IFGs to verify counter creation on all possible IFGs to check device RR mechanism
        for ifg_id in range(T.NUM_SLICES_PER_DEVICE * T.NUM_IFGS_PER_SLICE):
            dev_id, cnt3 = self.mc_group.get_egress_counter()
            self.assertEqual(dev_id, self.device_id)
            self.assertNotEqual(cnt3, None)

            cnt4 = self.device.create_counter(1)  # set_size=1

            # Check counter removal API for every second ifg
            if (ifg_id % 2 == 0):
                self.mc_group.set_egress_counter(self.device_id, None)  # Remove the mcg counter by setting None
                dev_id, cnt5 = self.mc_group.get_egress_counter()
                self.assertEqual(cnt5, None)

            self.mc_group.set_egress_counter(self.device_id, cnt4)  # If mcg counter already exists it will be removed

            run_and_compare_list(self, self.device, ingress_packet, expected_packets)

            packet_count, byte_count = cnt4.read(0,  # sub-counter index
                                                 True,  # force_update
                                                 True)  # clear_on_read
            self.assertEqual(packet_count, 1)

        # Cleanup
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, mcg_counter.MC_GROUP_ADDR.hld_obj)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
def setUpModule():
    sdk_multi_test_case_base.initialize()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
def tearDownModule():
    sdk_multi_test_case_base.destroy()


if __name__ == '__main__':
    unittest.main()
