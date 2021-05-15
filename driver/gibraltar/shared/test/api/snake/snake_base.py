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

import os
import socket
import unittest
from leaba import sdk

import snake_standalone
import mac_port_helper
import random

from sanity_constants import *

NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS = 0x26

INJECT_ENCAP_LENGTH = 35
MAC_CRC_LENGTH = 4

TEST_MAX_DELTA_PACKET = 5

ETH_P_ALL = 3

# On diag this is is /bin while on regular linux this is /sbin
IFCONFIG_CMD = ''
for fpath in {'/sbin/ifconfig', '/bin/ifconfig'}:
    if os.path.exists(fpath):
        IFCONFIG_CMD = fpath

# Due to limitation of Pacific A0 - recycle and inject ports can't be on same IFG we force to the correct IFG.


class snake_base(unittest.TestCase):
    def setUp(self):
        self.snake = snake_standalone.snake_base_topology()
        self.snake.set_default_args()
        self.traffic_enabled = False
        self.sockets = snake_standalone.NUM_SLICES_PER_DEVICE * [None]

    def tearDown(self):
        # Check for notifications
        n_lists = self.snake.mph.read_notifications(2)
        # Count non-link notifications, e.g. MEM_PROTECT, OTHER, ...
        non_link_notifications = 0
        for note_list in n_lists:
            for note_desc in note_list:
                print('Notification: {}'.format(self.snake.debug_device.notification_to_string(note_desc)))
                non_link_notifications += (note_desc.type != sdk.la_notification_type_e_LINK)

        self.snake.teardown()
        # TODO: cleanup and un-comment the following check
        # self.assertEqual(non_link_notifications, 0)

    # Copied from sim_utils which may not be available
    def is_pacific(self):
        rev = self.snake.ll_device.get_device_revision()
        asic_is_pacific = rev >= sdk.la_device_revision_e_PACIFIC_A0 and rev <= sdk.la_device_revision_e_PACIFIC_B1

        return asic_is_pacific

    def get_inject_actual_ifg(self, slice_id, ifg):
        if self.is_pacific():
            slices_with_flipped_ifgs = [0, 3, 4]
        else:  # GB
            slices_with_flipped_ifgs = [1, 2, 5]

        if (slice_id in slices_with_flipped_ifgs):
            actual_ifg = ifg ^ 1
        else:
            actual_ifg = ifg

        return actual_ifg

    def get_inject_pif(self):
        if self.is_pacific():
            return 18
        else:  # GB
            return 24

    def open_sockets(self):
        for i in range(snake_standalone.NUM_SLICES_PER_DEVICE):
            with open('%s' % (self.snake.ll_device.get_network_interface_file_name(i))) as fd:
                first_line = fd.readline()
                if first_line.find('not enabled') < 0:
                    self.open_socket(i)

    def open_socket(self, slice_id):
        if_name = self.snake.ll_device.get_network_interface_name(slice_id)

        os.system('echo 0 > /proc/sys/net/ipv6/conf/{}/router_solicitations'.format(if_name))
        os.system('{} {} up'.format(IFCONFIG_CMD, if_name))
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.bind((if_name, ETH_P_ALL))
        self.sockets[slice_id] = s

    def close_sockets(self):
        for i in range(NUM_SLICES_PER_DEVICE):
            self.close_socket(i)

    def close_socket(self, slice_id):
        s = self.sockets[slice_id]
        if s is None:
            return
        if_name = self.snake.ll_device.get_network_interface_name(slice_id)
        os.system('{} {} down'.format(IFCONFIG_CMD, if_name))
        s.close()
        self.sockets[slice_id] = None

    def inject(self, packet, packet_size, entry_slice, inject_packets_count=1):
        full_packet = packet

        # Padding
        # The full packet contains the inject encapsulation and doesn't contain the MAC CRC.
        while len(full_packet) < (packet_size + INJECT_ENCAP_LENGTH - MAC_CRC_LENGTH):
            full_packet += bytes([random.randint(0, 255)])

        s = self.sockets[entry_slice]
        for i in range(inject_packets_count):
            bytes_num = s.send(full_packet)
            if bytes_num != len(full_packet):
                print('Error: send failed len(packet)=%d bytes_num=%d' % (len(full_packet), bytes_num))

    def check_mac_stats_internal_loopback(self, total_packets, packet_size):
        expected_packets = 0
        test_max_delta_bytes = packet_size * TEST_MAX_DELTA_PACKET

        for index in range(len(self.snake.mph.network_mac_ports)):
            mac_info = self.snake.mph.get_mac_stats(index)
            print(
                'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), '
                'Rx {rx_frames} {rx_bytes}, Tx {tx_frames} {tx_bytes}, Tx CRC {tx_crc_err}, Tx Underrun {tx_underrun_err}, '
                'Uncorrectable {uncorrectable}, Correctable {correctable}'.format(
                    **mac_info))
            if index == 0:
                # First port connected to traffic generator, don't check Rx
                rx_packets = mac_info['rx_frames']
                self.assertEqual(mac_info['rx_bytes'], rx_packets * packet_size)
                expected_packets = rx_packets + total_packets
                expected_bytes = expected_packets * packet_size
                # Don't check Tx

            else:
                self.assertAlmostEqual(mac_info['rx_frames'], expected_packets, delta=TEST_MAX_DELTA_PACKET)
                self.assertAlmostEqual(mac_info['rx_bytes'], expected_bytes, delta=test_max_delta_bytes)
                self.assertAlmostEqual(mac_info['tx_frames'], expected_packets, delta=TEST_MAX_DELTA_PACKET)
                self.assertAlmostEqual(mac_info['tx_bytes'], expected_bytes, delta=test_max_delta_bytes)

    def check_mac_stats_external_loopback(self, total_packets, packet_size):
        expected_packets = 0
        test_max_delta_bytes = packet_size * TEST_MAX_DELTA_PACKET
        for index in range(len(self.snake.mph.mac_ports)):
            mac_info = self.snake.mph.get_mac_stats(index)
            print(
                'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), '
                'Rx {rx_frames} {rx_bytes}, Tx {tx_frames} {tx_bytes}, Tx CRC {tx_crc_err}, Tx Underrun {tx_underrun_err}, '
                'Uncorrectable {uncorrectable}, Correctable {correctable}'.format(
                    **mac_info))
            if index == 0:
                rx_packets = mac_info['rx_frames']
                expected_packets = rx_packets + total_packets
                expected_bytes = expected_packets * packet_size
                self.assertEqual(mac_info['rx_bytes'], rx_packets * packet_size)
                self.assertAlmostEqual(mac_info['tx_frames'], expected_packets, delta=total_packets)
                self.assertAlmostEqual(mac_info['tx_bytes'], expected_bytes, delta=total_packets * packet_size)

            elif index == 1:
                rx_packets = mac_info['rx_frames']
                self.assertAlmostEqual(mac_info['rx_frames'], expected_packets, delta=total_packets)
                expected_packets = rx_packets
                expected_bytes = expected_packets * packet_size
                self.assertAlmostEqual(mac_info['rx_bytes'], rx_packets * packet_size, delta=test_max_delta_bytes)
                self.assertAlmostEqual(mac_info['tx_frames'], expected_packets, delta=TEST_MAX_DELTA_PACKET)
                self.assertAlmostEqual(mac_info['tx_bytes'], expected_bytes, delta=test_max_delta_bytes)

            else:
                self.assertAlmostEqual(mac_info['rx_frames'], expected_packets, delta=TEST_MAX_DELTA_PACKET)
                self.assertAlmostEqual(mac_info['rx_bytes'], expected_bytes, delta=test_max_delta_bytes)
                self.assertAlmostEqual(mac_info['tx_frames'], expected_packets, delta=TEST_MAX_DELTA_PACKET)
                self.assertAlmostEqual(mac_info['tx_bytes'], expected_bytes, delta=test_max_delta_bytes)

    def check_mac_stats(self, total_packets, packet_size):
        if self.snake.args.p2p_ext is True:
            self.check_mac_stats_external_loopback(total_packets, packet_size)
        else:
            self.check_mac_stats_internal_loopback(total_packets, packet_size)

    def check_dram_hbm(self, is_used):
        dram_counters = self.snake.debug_device.get_dram_counters()

        total_write = 0
        total_read = 0
        for ifg_counter in dram_counters:
            if ifg_counter['slice'] == 6:
                print('Slice {slice}, IFG {ifg}: write packets {write_packets}, read packets {read_packets}'.format(**ifg_counter))
                if is_used:
                    self.assertNotEqual(ifg_counter['write_packets'], 0)
                    self.assertNotEqual(ifg_counter['read_packets'], 0)
                    total_write += ifg_counter['write_packets']
                    total_read += ifg_counter['read_packets']
                else:
                    self.assertEqual(ifg_counter['write_packets'], 0)
                    self.assertEqual(ifg_counter['read_packets'], 0)

        self.assertEqual(total_read, total_write)
