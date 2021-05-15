#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import unittest
from leaba import sdk
import sim_utils
import packet_test_utils as U
import scapy.all as S
import topology as T
from sdk_test_case_base import *


TTL = 128
SA = T.mac_addr('be:ef:5d:35:7a:35')
DA = T.mac_addr('02:02:02:02:02:02')

SIP = T.ipv4_addr('12.10.12.10')
DIP = T.ipv4_addr('82.81.95.250')


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class voq_counter_unit_test(sdk_test_case_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_voq_counter_enqueue(self):
        # get ports
        rx_eth_port = self.topology.rx_eth_port
        rx_ac_port = self.topology.rx_l2_ac_port
        tx_eth_port = self.topology.tx_svi_eth_port_reg
        tx_ac_port = self.topology.tx_l2_ac_port_reg

        rx_ac_port.hld_obj.detach()
        rx_ac_port.hld_obj.set_destination(tx_ac_port.hld_obj)

        # attach voq counter
        tx_eth_port_voq_set = tx_eth_port.sys_port.voq_set
        tx_eth_port_voq_set_size = tx_eth_port_voq_set.get_set_size()
        tx_eth_port_voq_counter = self.device.device.create_counter(2)
        tx_eth_port_voq_set.set_counter(sdk.la_voq_set.voq_counter_type_e_BOTH,
                                        tx_eth_port_voq_set_size,
                                        tx_eth_port_voq_counter)

        # create packets
        in_packet_base = S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=2, id=1, vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP() / S.TCP()

        out_packet_base = S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(prio=2, id=1, vlan=T.RX_L2_AC_PORT_VID1) / \
            S.IP() / S.TCP()

        in_packet, out_packet = U.pad_input_and_output_packets(in_packet_base, out_packet_base)

        enqueue_packet_count, enqueue_byte_count = tx_eth_port_voq_counter.read(0,    # ENQUEUE counter
                                                                                True,  # force_update
                                                                                True)  # clear_on_read
        drop_packet_count, drop_byte_count = tx_eth_port_voq_counter.read(1,      # DROP counter
                                                                          True,   # force_update
                                                                          True)   # clear_on_read

        # Verify the counter is empty.
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)
        self.assertEqual(drop_packet_count, 0)
        self.assertEqual(drop_byte_count, 0)

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

        enqueue_packet_count, enqueue_byte_count = tx_eth_port_voq_counter.read(0, True, True)
        drop_packet_count, drop_byte_count = tx_eth_port_voq_counter.read(1, True, True)

        expected_packet_size = U.get_injected_packet_len(self.device, in_packet, T.RX_SLICE)

        # Verify ENQUEUE counter is equal to expected packet size
        self.assertEqual(enqueue_packet_count, 1)
        self.assertEqual(enqueue_byte_count, expected_packet_size)

        # The packets should be enqueued, so verify that the DROP counter is empty
        self.assertEqual(drop_packet_count, 0)
        self.assertEqual(drop_byte_count, 0)

        # Per slice voq counters
        in_packet, out_packet = U.pad_input_and_output_packets(in_packet_base, out_packet_base)

        enqueue_packet_count, enqueue_byte_count = tx_eth_port_voq_counter.read(T.RX_SLICE,  # slice id
                                                                                0,    # ENQUEUE counter
                                                                                True,  # force_update
                                                                                True)  # clear_on_read
        drop_packet_count, drop_byte_count = tx_eth_port_voq_counter.read(T.RX_SLICE,  # slice id
                                                                          1,      # DROP counter
                                                                          True,   # force_update
                                                                          True)   # clear_on_read

        # Verify the counter is empty.
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)
        self.assertEqual(drop_packet_count, 0)
        self.assertEqual(drop_byte_count, 0)

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

        enqueue_packet_count, enqueue_byte_count = tx_eth_port_voq_counter.read(T.RX_SLICE, 0, True, True)
        drop_packet_count, drop_byte_count = tx_eth_port_voq_counter.read(T.RX_SLICE, 1, True, True)

        expected_packet_size = U.get_injected_packet_len(self.device, in_packet, T.RX_SLICE)

        # Verify ENQUEUE counter is equal to expected packet size
        self.assertEqual(enqueue_packet_count, 1)
        self.assertEqual(enqueue_byte_count, expected_packet_size)

        # The packets should be enqueued, so verify that the DROP counter is empty
        self.assertEqual(drop_packet_count, 0)
        self.assertEqual(drop_byte_count, 0)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_voq_counter_drop(self):
        '''
            Inject a packet that should hit the no-service-mapping trap, with the trap configured to drop.
            1. Validate the packet is dropped.
            2. Validate its VOQ counter works.
        '''
        # Save current trap configuration
        prev_trap_config = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)

        # Configure trap to superior priority and to drop
        destination = None
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING, 0, None, destination, False, False, True, 0)

        # create packets
        NO_SERVICE_MAPPING_VID = T.RX_L2_AC_PORT_VID1 + 1
        in_packet_base = \
            S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=NO_SERVICE_MAPPING_VID) / \
            S.IP() / S.TCP()

        in_packet, __ = U.enlarge_packet_to_min_length(in_packet_base)

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

        rx_serdes = T.get_device_rx_first_serdes(T.FIRST_SERDES)
        U.run_and_drop(
            self,
            self.device,
            in_packet,
            T.RX_SLICE,
            T.RX_IFG,
            rx_serdes)

        enqueue_packet_count, enqueue_byte_count = rx_drop_voq_counter.read(0, True, True)
        drop_packet_count, drop_byte_count = rx_drop_voq_counter.read(1, True, True)

        # The packets should be dropped, so verify that the ENQUEUE counter is empty
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)

        expected_packet_size = U.get_injected_packet_len(self.device, in_packet, T.RX_SLICE)
        self.assertEqual(drop_packet_count, 1)
        self.assertEqual(drop_byte_count, expected_packet_size)

        # Per slice voq counters.
        rx_drop_voq_counter = self.device.get_forwarding_drop_counter()

        enqueue_packet_count, enqueue_byte_count = rx_drop_voq_counter.read(T.RX_SLICE,  # slice id
                                                                            0,    # ENQUEUE counter
                                                                            True,  # force_update
                                                                            True)  # clear_on_read
        drop_packet_count, drop_byte_count = rx_drop_voq_counter.read(T.RX_SLICE,  # slice id
                                                                      1,      # DROP counter
                                                                      True,   # force_update
                                                                      True)   # clear_on_read
        # Verify the counter is empty.
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)
        self.assertEqual(drop_packet_count, 0)
        self.assertEqual(drop_byte_count, 0)

        U.run_and_drop(
            self,
            self.device,
            in_packet,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES)

        enqueue_packet_count, enqueue_byte_count = rx_drop_voq_counter.read(T.RX_SLICE, 0, True, True)
        drop_packet_count, drop_byte_count = rx_drop_voq_counter.read(T.RX_SLICE, 1, True, True)

        # The packets should be dropped, so verify that the ENQUEUE counter is empty
        self.assertEqual(enqueue_packet_count, 0)
        self.assertEqual(enqueue_byte_count, 0)

        expected_packet_size = U.get_injected_packet_len(self.device, in_packet, T.RX_SLICE)
        self.assertEqual(drop_packet_count, 1)
        self.assertEqual(drop_byte_count, expected_packet_size)

        # Restore trap configuration
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING, *prev_trap_config)


if __name__ == '__main__':
    unittest.main()
