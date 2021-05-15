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

number_of_ports = 128 if decor.is_gibraltar() else 108


class max_power_base(snake_test_base):
    pkt_size = TEST_PACKET_SIZE
    num_injected_packets = 0
    max_rx_gbps = 0
    board_config = None
    params = {}

    def start(self, flows, start_traffic=False):
        '''
           start traffic if start_traffic is True. Otherwise, setup the snakes and manually injecting packets
        '''
        #self.snake.args.board_cfg_path = self.board_config
        self.snake.args.protocol = flows[0]['protocol'] if flows else 'none'
        self.snake.args.no_real_port = True
        self.snake.args.hbm = 2 if self.params['hbm'] else 0
        self.snake.args.cache = self.params['cache']
        self.snake.args.device_frequency_khz = self.params['device_frequency_khz']
        self.snake.args.loop_mode = 'serdes'
        if self.params['json_mix'] is not None:
            self.snake.args.json_mix = self.params['json_mix']
        else:
            self.snake.args.loop_count = number_of_ports
            self.snake.args.loop_port = [0, 0, 0]
            self.snake.args.loop_type = [2, 100]
            self.snake.args.p2p = 1

        if not start_traffic:
            self.base_loop_test(self.pkt_size, slice=0, ifg=0, inject_packets_count=0,
                                rate_check=False, stop_after_dwell=False, flows=flows)
            self.num_injected_packets = 0
        else:
            # inject PACKET_INCREMENT packets at a time till it reaches max bandwidth of the device
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
        self.close_sockets()

    def add(self, flows, number_of_packets=1):
        self.num_injected_packets += number_of_packets
        self.create_packets(0, 0, flows)
        if flows:
            for flow in flows:
                self.inject(flow['packet'], flow['packet_size'], flow['entry_slice'], number_of_packets)
        else:
            self.inject(self.inject_packet, self.pkt_size, 0, number_of_packets)

    '''
       for ipv4, the first 24 bits are network address and in decimal
       for ipv6, the first 64 bits are network address and in hex
    '''

    def inc_network(self, ip_str, inc, ipv4=False):
        if not ipv4:
            new_str = ip_str.split(':')
            new_str[3] = format(int(new_str[3], 16) + inc, 'x').upper()
            return ":".join(new_str)
        else:
            new_str = ip_str.split('.')
            new_str[2] = format(int(new_str[2], 10) + inc, 'd').upper()
            return ".".join(new_str)

    def new_flow(self, flow, inc, ipv4=False):
        flow_n = flow.copy()
        flow_n['dst_ip'] = self.inc_network(flow_n['dst_ip'], inc, ipv4)
        return flow_n

    def run_ipv6_traffic(self):
        flows = []
        for i in range(0, self.params['nflows']):
            flows.append(self.new_flow(
                {'entry_slice': 0,
                 'entry_ifg': 0,
                 'src_mac': 'de:ad:de:ad:de:ad',
                 'dst_mac': 'ca:fe:ca:fe:ca:fe',
                 'src_ip': '2:2:2:2:1111:1111:1111:1111',
                 'dst_ip': '1111:DB8:A0B:12F0:7777:7777:8888:8888',
                 'vlan_id': 0x100,
                 'packet_size': self.params['packet_sizes'][0],
                 'protocol': 'ipv6'
                 }, i))
        # add  packets to the second snake
        if decor.is_gibraltar():
            for i in range(0, self.params['nflows']):
                flows.append(self.new_flow(
                    {
                        'entry_slice': 2,
                        'entry_ifg': 0,
                        'src_mac': 'de:ad:de:ad:de:ad',
                        'dst_mac': '22:22:22:22:26:0a',
                        'src_ip': '2:2:2:2:1111:1111:1111:1111',
                        'dst_ip': '1122:DB8:A0B:12F0:7777:7777:8888:8888',
                        'vlan_id': 0x200,
                        'packet_size': self.params['packet_sizes'][1],
                        'protocol': 'ipv6'}, i)
                )
        self.start(flows, True)
        self.show()
        if self.snake.cache:
            cache_counter = self.snake.cache.get_flow_cache_counters()
            total = cache_counter.hit_counter + cache_counter.miss_counter + cache_counter.dont_use_cache_counter
            print("hit counter: {}, ratio: {}".format(cache_counter.hit_counter, cache_counter.hit_counter / total))
            print("miss counter: {}, ratio: {}".format(cache_counter.miss_counter, cache_counter.miss_counter / total))
            print(
                "don't use cache counter: {}, ratio: {}".format(
                    cache_counter.dont_use_cache_counter,
                    cache_counter.dont_use_cache_counter / total))
        import time
        time.sleep(30)
        import blacktip_utils as bb
        try:
            power_dict = bb.blacktip().gb_get_power(True)
            self.assertLess(300, power_dict["NP_total_power"], "need to draw at lease 300W")
        except AssertionError:
            self.stop()
            self.skipTest("This is not a blacktip")
        self.stop()

    def run_ipv4_traffic(self):
        flows = []
        for i in range(0, self.params['nflows']):
            flows.append(self.new_flow(
                {'entry_slice': 0,
                 'entry_ifg': 0,
                 'src_mac': 'de:ad:de:ad:de:ad',
                 'dst_mac': 'ca:fe:ca:fe:ca:fe',
                 'src_ip': '2.2.2.2',
                 'dst_ip': '192.168.10.0',
                 'vlan_id': 0x100,
                 'packet_size': self.params['packet_sizes'][0],
                 'protocol': 'ipv4'
                 }, i, True))
            flows.append(self.new_flow(
                {'entry_slice': 2,
                 'entry_ifg': 0,
                 'src_mac': 'de:ad:de:ad:de:ad',
                 'dst_mac': '22:22:22:22:26:0a',
                 'src_ip': '2.2.2.2',
                 'dst_ip': '192.169.10.0',
                 'vlan_id': 0x200,
                 'packet_size': self.params['packet_sizes'][1],
                 'protocol': 'ipv4'
                 }, i, True))
        self.start(flows, True)
        self.show()
        if self.snake.cache:
            cache_counter = self.snake.cache.get_flow_cache_counters()
            total = cache_counter.hit_counter + cache_counter.miss_counter + cache_counter.dont_use_cache_counter
            print("hit counter: {}, ratio: {}".format(cache_counter.hit_counter, cache_counter.hit_counter / total))
            print("miss counter: {}, ratio: {}".format(cache_counter.miss_counter, cache_counter.miss_counter / total))
            print(
                "don't use cache counter: {}, ratio: {}".format(
                    cache_counter.dont_use_cache_counter,
                    cache_counter.dont_use_cache_counter / total))
        self.stop()

    def run_l2_traffic(self):
        flows = [{'entry_slice': 0,
                  'entry_ifg': 0,
                  'src_mac': 'de:ad:de:ad:de:ad',
                  'dst_mac': 'ca:fe:ca:fe:ca:fe',
                  'vlan_id': 0x100,
                  'packet_size': self.params['packet_sizes'][0],
                  'protocol': 'none'}]
        self.start(flows, True)
        self.show()
        self.stop()

    def run_empty_flow(self):
        '''
        default to L2 if there is no flow
        '''
        self.start([], True)
        self.show()
        self.stop()
