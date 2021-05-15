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

import sim_utils
import unittest
from leaba import sdk
import argparse
from sanity_constants import *
from snake_base import *
from snake_test_base import *
from mac_port_helper import *
import decor

PACKET_INCREMENT = 1000
APPLY_PACIFIC_B0_IFG = False
TEST_PACKET_SIZE = 348

if decor.is_gibraltar():
    number_of_ports = 128
else:
    number_of_ports = 108


@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
class max_power(snake_test_base):
    pkt_size = TEST_PACKET_SIZE
    num_injected_packets = 0
    max_rx_gbps = 0
    board_config = None

    def parse_args(self):
        parser = argparse.ArgumentParser(description='MaxPower Test.')

        parser.add_argument('--flow_caching', default=False, action='store_true',
                            help='enable flow caching')
        parser.add_argument('--hbm', default=False, action='store_true',
                            help='enable HBM,  default False')
        parser.add_argument('--packet_sizes', type=int, nargs=2, default=[220, 156],
                            metavar=('first', 'second'),
                            help='packet size for two flows, default %(default)s')
        parser.add_argument('--json_mix', default=None,
                            help='Port mix configuration using JSON file, default %(default)s')
        parser.add_argument(
            '--device_frequency_khz',
            type=int,
            default=None,
            help='Device frequency in KHz to configure. If not provided, use the device\'s default, default %(default)s')

        self.parser = parser
        self.args = self.parser.parse_args()

    def start(self, flows, start_traffic=False):
        # global settings for all the flows
        #
        self.snake.args.board_cfg_path = self.board_config
        self.snake.args.loop_mode = 'serdes'
        if self.args.json_mix is not None:
            self.snake.args.json_mix = self.args.json_mix
        else:
            self.snake.args.loop_count = number_of_ports
            self.snake.args.loop_port = [0, 0, 0]
            self.snake.args.loop_type = [2, 100]
            self.snake.args.p2p = 1

        self.snake.args.protocol = flows[0]['protocol'] if flows else 'none'
        self.snake.args.no_real_port = True
        self.snake.args.hbm = 2 if self.args.hbm else 0
        self.snake.args.device_frequency_khz = self.args.device_frequency_khz

        if not start_traffic:
            self.base_loop_test(self.pkt_size, slice=0, ifg=0, inject_packets_count=0,
                                rate_check=False, stop_after_dwell=False, flows=flows)
            self.num_injected_packets = 0
        else:
            # inject 100 packets at a time till it reaches max bandwidth of the device
            self.base_loop_test(self.pkt_size, slice=0, ifg=0, inject_packets_count=PACKET_INCREMENT,
                                rate_check=False, stop_after_dwell=False, flows=flows)
            self.num_injected_packets = PACKET_INCREMENT
            current_rx_gbps = self.snake.mph.get_device_rate()
            while current_rx_gbps > self.max_rx_gbps:
                self.max_rx_gbps = current_rx_gbps
                self.add(flows, PACKET_INCREMENT)
                current_rx_gbps = self.snake.mph.get_device_rate()
                print('number of packets circulating:', self.num_injected_packets)

    def show(self):
        self.snake.mph.print_mac_rate()
        print('number of packets circulating:', self.num_injected_packets)

    def stop(self):
        self.num_injected_packets = 0
        self.current_rx_gbps = 0
        self.max_rx_gbps = 0
        self.tearDown()

    def add(self, flows, number_of_packets=1):
        self.num_injected_packets += number_of_packets
        self.create_packets(0, 0, flows)
        if flows:
            for flow in flows:
                self.inject(flow['packet'], flow['packet_size'], flow['entry_slice'], number_of_packets)
        else:
            self.inject(self.inject_packet, self.pkt_size, 0, number_of_packets)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_traffic(self):
        if decor.is_gibraltar():
            flows = [{'entry_slice': 0,
                      'entry_ifg': 0,
                      'src_mac': 'de:ad:de:ad:de:ad',
                      'dst_mac': 'ca:fe:ca:fe:ca:fe',
                      'src_ip': '2:2:2:2:1111:1111:1111:1111',
                      'dst_ip': '1111:DB8:A0B:12F0:7777:7777:8888:8888',
                      'vlan_id': 0x100,
                      'packet_size': self.args.packet_sizes[0],
                      'protocol': 'ipv6'},
                     {'entry_slice': 2,
                      'entry_ifg': 0,
                      'src_mac': 'de:ad:de:ad:de:ad',
                      'dst_mac': '22:22:22:22:26:0a',
                      'src_ip': '2:2:2:2:1111:1111:1111:1111',
                      'dst_ip': '1122:DB8:A0B:12F0:7777:7777:8888:8888',
                      'vlan_id': 0x200,
                      'packet_size': self.args.packet_sizes[1],
                      'protocol': 'ipv6'}]
        else:
            flows = [{'entry_slice': 0,
                      'entry_ifg': 0,
                      'src_mac': 'de:ad:de:ad:de:ad',
                      'dst_mac': 'ca:fe:ca:fe:ca:fe',
                      'src_ip': '2:2:2:2:1111:1111:1111:1111',
                      'dst_ip': '1111:DB8:A0B:12F0:7777:7777:8888:8888',
                      'vlan_id': 0x100,
                      'packet_size': self.args.packet_sizes[0],
                      'protocol': 'ipv6'}]
        self.start(flows, True)
        self.show()
        self.stop()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_traffic(self):
        flows = [{'entry_slice': 0,
                  'entry_ifg': 0,
                  'src_mac': 'de:ad:de:ad:de:ad',
                  'dst_mac': 'ca:fe:ca:fe:ca:fe',
                  'src_ip': '2.2.2.2',
                  'dst_ip': '192.168.10.0',
                  'vlan_id': 0x100,
                  'packet_size': self.args.packet_sizes[0],
                  'protocol': 'ipv4'},
                 {'entry_slice': 2,
                  'entry_ifg': 0,
                  'src_mac': 'de:ad:de:ad:de:ad',
                  'dst_mac': '22:22:22:22:26:0a',
                  'src_ip': '2.2.2.2',
                  'dst_ip': '192.169.10.0',
                  'vlan_id': 0x200,
                  'packet_size': self.args.packet_sizes[1],
                  'protocol': 'ipv4'}]
        self.start(flows, True)
        self.show()
        self.stop()

    '''
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_traffic(self):
        flows = [{'entry_slice': 0,
                  'entry_ifg': 0,
                  'src_mac': 'de:ad:de:ad:de:ad',
                  'dst_mac': 'ca:fe:ca:fe:ca:fe',
                  'vlan_id': 0x100,
                  'packet_size': self.args.packet_sizes[0],
                  'protocol': 'none'},
                 {'entry_slice': 2,
                  'entry_ifg': 0,
                  'src_mac': 'de:ad:de:ad:de:ad',
                  'dst_mac': '22:22:22:22:26:0a',
                  'vlan_id': 0x200,
                  'packet_size': self.args.packet_sizes[1],
                  'protocol': 'none'}]
        self.start(flows, True)
        self.show()
        self.stop()
    '''

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_traffic(self):
        flows = [{'entry_slice': 0,
                  'entry_ifg': 0,
                  'src_mac': 'de:ad:de:ad:de:ad',
                  'dst_mac': 'ca:fe:ca:fe:ca:fe',
                  'vlan_id': 0x100,
                  'packet_size': self.args.packet_sizes[0],
                  'protocol': 'none'}]
        self.start(flows, True)
        self.show()
        self.stop()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_empty_flow(self):
        '''
        default to L2 if there is no flow
        '''
        self.start([], True)
        self.show()
        self.stop()


if __name__ == '__main__':
    mpower = max_power()
    mpower.parse_args()
    mpower.setUp()
    print('testing empty flows')
    mpower.test_empty_flow()
    print('testing ipv6 flows')
    mpower.test_ipv6_traffic()
    print('testing ipv4 flows')
    mpower.test_ipv4_traffic()
    print('testing l2 flows')
    mpower.test_l2_traffic()
