#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import pdb
from pfc_base import *
import unittest
import decor
from pfc_local import *


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
class ipv4_pfc(pfc_local, pfc_base, pfc_common):
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pfc(self):
        self.init_common()
        # Add an entry in the congestion table
        self.set_pfc_congestion_table(DEST_VALUE, TC_VALUE, True, self.s_rx_slice)

        #####
        # Send a packet with the wd filter set. No PFC packet will be sent.
        #####
        dest_mac_port = self.m_mac_port_p2.hld_obj
        dest_mac_port.set_pfc_queue_configured_state(TC_VALUE, sdk.la_mac_port.pfc_config_queue_state_e_DROPPING)

        ingress_packet = {
            'data': self.INPUT_TEST_PACKET,
            'slice': self.s_rx_slice,
            'ifg': self.s_rx_ifg,
            'pif': self.s_first_serdes_p1}
        expected_packets = []
        expected_packets.append({'data': self.OUTPUT_TEST_PACKET, 'slice': self.s_tx_slice,
                                 'ifg': self.s_tx_ifg, 'pif': self.s_first_serdes_p2})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether,
                             False, {'rxpp_npu_input.ifg_rx_fd.receive_time': 0x0})

        (p, b) = self.pfc_tx_meter.read(TC_VALUE, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(p, 0)

        dest_mac_port.set_pfc_queue_configured_state(TC_VALUE, sdk.la_mac_port.pfc_config_queue_state_e_ACTIVE)

        # First packet inject as a measurement packet - receive_time[0] == 0
        # Inject the packet and test outputs
        ingress_packet = {
            'data': self.INPUT_TEST_PACKET,
            'slice': self.s_rx_slice,
            'ifg': self.s_rx_ifg,
            'pif': self.s_first_serdes_p1}
        expected_packets = []
        expected_packets.append({'data': self.OUTPUT_TEST_PACKET, 'slice': self.s_tx_slice,
                                 'ifg': self.s_tx_ifg, 'pif': self.s_first_serdes_p2})
        expected_packets.append({'data': self.pfc_packet, 'slice': self.s_rx_slice,
                                 'ifg': self.s_rx_ifg, 'pif': self.s_first_serdes_p1})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether,
                             False, {'rxpp_npu_input.ifg_rx_fd.receive_time': 0x0})

        (p, b) = self.pfc_tx_meter.read(TC_VALUE, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(p, 1)

        # Second packet inject as a pilot packet - receive_time[0] == 1
        # Inject the packet and test outputs
        ingress_packet = {
            'data': self.INPUT_TEST_PACKET,
            'slice': self.s_rx_slice,
            'ifg': self.s_rx_ifg,
            'pif': self.s_first_serdes_p1}
        expected_packets = []
        expected_packets.append({'data': self.OUTPUT_TEST_PACKET, 'slice': self.s_tx_slice,
                                 'ifg': self.s_tx_ifg, 'pif': self.s_first_serdes_p2})
        expected_packets.append({'data': self.pfc_packet, 'slice': self.s_rx_slice,
                                 'ifg': self.s_rx_ifg, 'pif': self.s_first_serdes_p1})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether,
                             False, {'rxpp_npu_input.ifg_rx_fd.receive_time': 0x1})

        (p, b) = self.pfc_tx_meter.read(TC_VALUE, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(p, 1)

        # send another packet to test dropping due to low latency
        # latency is fixed in simulation to 0x1516. So set the threshold
        # to 0x1516*2^16ns = 353726us
        self.device.set_sw_fc_pause_threshold(TC_VALUE, 354000)
        expected_packets = []
        expected_packets.append({'data': self.OUTPUT_TEST_PACKET, 'slice': self.s_tx_slice,
                                 'ifg': self.s_tx_ifg, 'pif': self.s_first_serdes_p2})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # Send a packet that doesn't match mirror or pilot sample.
        # Inject the packet and test outputs
        ingress_packet = {
            'data': self.INPUT_TEST_PACKET,
            'slice': self.s_rx_slice,
            'ifg': self.s_rx_ifg,
            'pif': self.s_first_serdes_p1}
        expected_packets = []
        expected_packets.append({'data': self.OUTPUT_TEST_PACKET, 'slice': self.s_tx_slice,
                                 'ifg': self.s_tx_ifg, 'pif': self.s_first_serdes_p2})
        expected_packets.append({'data': self.NETFLOW_PKT, 'slice': INJECT_SLICE,
                                 'ifg': T.PI_IFG, 'pif': T.PI_PIF})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether,
                             False, {'rxpp_npu_input.ifg_rx_fd.receive_time': 0x2})

        self.set_pfc_congestion_table(DEST_VALUE, TC_VALUE, False, self.s_rx_slice)


if __name__ == '__main__':
    unittest.main()
