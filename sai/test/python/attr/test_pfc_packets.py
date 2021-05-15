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

import pytest
from scapy.all import *
from packet_test_utils import PFC, Ethertype
import sai_packet_utils
import sai_test_utils as st_utils
from saicli import *

PFC_MAC_ADDR = "01:80:c2:00:00:01"


def create_port_stat_vec(stat_id_list):
    port_stat_vec = portStatVec(len(stat_id_list))
    for i, port_id in enumerate(stat_id_list):
        port_stat_vec[i] = port_id
    return port_stat_vec


def create_pfc_packet(pfc_enable_bits):
    return Ether(dst=PFC_MAC_ADDR,
                 src=pytest.tb.router_mac,
                 type=Ethertype.FlowControl.value) / PFC(class_enable_vector=pfc_enable_bits)


class Test_pfc_packets():
    def verify_rx_counter_on_fc(self, tc):
        in_port_pif = pytest.top.port_cfg.in_port
        in_port_oid = pytest.tb.ports[in_port_pif]

        # Enable PFC
        pfc_enable_bits = 1 << tc
        pytest.tb.set_object_attr(in_port_oid, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, pfc_enable_bits)

        # Inject PFC packet
        pfc_pkt = create_pfc_packet(pfc_enable_bits)
        sai_packet_utils.run(self, pfc_pkt, in_port_pif)

        # Retrieve RX counters
        port_id_rx_list = [SAI_PORT_STAT_PFC_0_RX_PKTS,
                           SAI_PORT_STAT_PFC_1_RX_PKTS,
                           SAI_PORT_STAT_PFC_2_RX_PKTS,
                           SAI_PORT_STAT_PFC_3_RX_PKTS,
                           SAI_PORT_STAT_PFC_4_RX_PKTS,
                           SAI_PORT_STAT_PFC_5_RX_PKTS,
                           SAI_PORT_STAT_PFC_6_RX_PKTS,
                           SAI_PORT_STAT_PFC_7_RX_PKTS]

        rx_counters = getPortCountersExt(in_port_oid, create_port_stat_vec(port_id_rx_list), False)

        # Verify appropriate traffic class RX was incremented
        assert rx_counters[tc] == 1

        # Verify no other RX was incremented
        for i in range(len(port_id_rx_list)):
            if i != tc:
                assert rx_counters[i] == 0

        # Run a second packet and verify count has incremented
        sai_packet_utils.run(self, pfc_pkt, in_port_pif)
        rx_counters = getPortCountersExt(in_port_oid, create_port_stat_vec(port_id_rx_list), False)
        assert rx_counters[tc] == 2

        # Verify all TX counters are 0
        port_id_tx_list = [SAI_PORT_STAT_PFC_0_TX_PKTS,
                           SAI_PORT_STAT_PFC_1_TX_PKTS,
                           SAI_PORT_STAT_PFC_2_TX_PKTS,
                           SAI_PORT_STAT_PFC_3_TX_PKTS,
                           SAI_PORT_STAT_PFC_4_TX_PKTS,
                           SAI_PORT_STAT_PFC_5_TX_PKTS,
                           SAI_PORT_STAT_PFC_6_TX_PKTS,
                           SAI_PORT_STAT_PFC_7_TX_PKTS]

        tx_counters = getPortCountersExt(in_port_oid, create_port_stat_vec(port_id_tx_list), False)
        for i in range(len(port_id_tx_list)):
            assert tx_counters[i] == 0

        pytest.tb.set_object_attr(in_port_oid, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0)

    def test_pfc_rx_counter(self, basic_route_v4_topology):
        st_utils.skipIf(pytest.tb.is_hw())
        for tc in range(8):
            self.verify_rx_counter_on_fc(tc)

    def test_pfc_activation_clears_counters(self, basic_route_v4_topology):
        st_utils.skipIf(pytest.tb.is_hw())
        in_port_pif = pytest.top.port_cfg.in_port
        in_port_oid = pytest.tb.ports[in_port_pif]

        # Enable PFC
        pfc_enable_bits = 1 << 4
        pytest.tb.set_object_attr(in_port_oid, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, pfc_enable_bits)

        # Inject PFC packet
        pfc_pkt = create_pfc_packet(pfc_enable_bits)
        sai_packet_utils.run(self, pfc_pkt, in_port_pif)

        # Retrieve RX counters
        port_id_rx_list = [SAI_PORT_STAT_PFC_4_RX_PKTS]
        rx_counters = getPortCountersExt(in_port_oid, create_port_stat_vec(port_id_rx_list), False)

        # Verify increment
        assert rx_counters[0] == 1

        # Change PFC activation to include an extra TC
        pfc_enable_bits |= 1 << 5
        pytest.tb.set_object_attr(in_port_oid, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, pfc_enable_bits)

        # Retrieve RX counters
        port_id_rx_list = [SAI_PORT_STAT_PFC_4_RX_PKTS]
        rx_counters = getPortCountersExt(in_port_oid, create_port_stat_vec(port_id_rx_list), False)

        # Verify counter was reset due to PFC TC change
        assert rx_counters[0] == 0

        pytest.tb.set_object_attr(in_port_oid, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0)
