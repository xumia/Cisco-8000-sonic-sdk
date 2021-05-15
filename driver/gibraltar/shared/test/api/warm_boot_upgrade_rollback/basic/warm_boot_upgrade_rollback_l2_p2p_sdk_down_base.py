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

from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
from sdk_test_case_base import *
import warm_boot_upgrade_rollback_test_utils as wb
import decor


NUM_OF_ITERATIONS = 3


class warm_boot_upgrade_rollback_l2_p2p_sdk_down_base(sdk_test_case_base):

    SA = T.mac_addr('be:ef:5d:35:7a:35')
    DA = T.mac_addr('02:02:02:02:02:02')

    def _test_warm_boot_l2_p2p_traffic_while_sdk_down(self):
        # ports
        rx_ac_port = self.topology.rx_l2_ac_port
        tx_ac_port = self.topology.tx_l2_ac_port_reg

        # create and attach ingress counter to rx port
        ingress_counter = self.device.create_counter(1)
        rx_ac_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, ingress_counter)

        # create and attach egress counter to tx port
        egress_counter = self.device.create_counter(1)
        tx_ac_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)

        rx_ac_port.hld_obj.detach()
        rx_ac_port.hld_obj.set_destination(tx_ac_port.hld_obj)

        # create packets
        in_packet_base = S.Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=2, id=1, vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP() / S.TCP()

        out_packet_base = S.Ether(dst=self.DA.addr_str, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=2, id=1, vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP() / S.TCP()

        in_packet, out_packet = U.pad_input_and_output_packets(in_packet_base, out_packet_base)

        # get sizes of in/out packets
        in_packet_size = U.get_injected_packet_len(self.device, in_packet, T.RX_SLICE)
        out_packet_size = U.get_output_packet_len_for_counters(self.device, out_packet)

        if decor.is_asic5():
            T.FIRST_SERDES_SVI_REG = 12
        else:
            T.FIRST_SERDES_SVI_REG = 0

        for i in range(NUM_OF_ITERATIONS):
            U.run_and_compare(
                self,
                self.device,
                in_packet,
                T.RX_SLICE,
                T.RX_IFG,
                T.FIRST_SERDES,
                out_packet,
                T.TX_SLICE_REG,
                T.TX_IFG_REG,
                T.FIRST_SERDES_SVI_REG)

        num_of_packets = NUM_OF_ITERATIONS
        self.check_counter_values(ingress_counter, num_of_packets, num_of_packets * in_packet_size)
        self.check_counter_values(egress_counter, num_of_packets, num_of_packets * out_packet_size)

        wb.warm_boot_disconnect(self.device)

        for i in range(NUM_OF_ITERATIONS):
            U.run_and_compare(
                self,
                self.device,
                in_packet,
                T.RX_SLICE,
                T.RX_IFG,
                T.FIRST_SERDES,
                out_packet,
                T.TX_SLICE_REG,
                T.TX_IFG_REG,
                T.FIRST_SERDES_SVI_REG)

        wb.warm_boot_reconnect(self.device)

        num_of_packets = 2 * NUM_OF_ITERATIONS
        self.check_counter_values(ingress_counter, num_of_packets, num_of_packets * in_packet_size)
        self.check_counter_values(egress_counter, num_of_packets, num_of_packets * out_packet_size)

        for i in range(NUM_OF_ITERATIONS):
            U.run_and_compare(
                self,
                self.device,
                in_packet,
                T.RX_SLICE,
                T.RX_IFG,
                T.FIRST_SERDES,
                out_packet,
                T.TX_SLICE_REG,
                T.TX_IFG_REG,
                T.FIRST_SERDES_SVI_REG)

            num_of_packets = 2 * NUM_OF_ITERATIONS + i + 1
            self.check_counter_values(ingress_counter, num_of_packets, num_of_packets * in_packet_size)
            self.check_counter_values(egress_counter, num_of_packets, num_of_packets * out_packet_size)

    def check_counter_values(self, counter, expected_packets, expected_bytes):
        packet_count, byte_count = counter.read(0, True, False)
        self.assertEqual(packet_count, expected_packets)
        self.assertEqual(byte_count, expected_bytes)
