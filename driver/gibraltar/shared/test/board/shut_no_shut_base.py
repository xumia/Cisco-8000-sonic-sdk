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

import time
import datetime

from leaba import sdk
from leaba import debug
import sim_utils
import lldcli

from enum import Enum
from snake_standalone import snake_base_topology
from ports_base import *

REST_DELAY = 10  # Time in seconds
ITERATION_DELAY = 5  # Time in seconds


class shut_no_shut_base(ports_base):

    class PORTS_TO_SHUT(Enum):
        PORTS_SHUT_ALL = 1
        PORTS_SHUT_EVEN = 2

    def shut_no_shut_base_test(self, ports_to_shut, traffic_mode, is_an_enabled, is_mlp=False):
        ports_mix = 'default_mix.json'
        if is_mlp:
            ports_mix = 'mlp_mix.json'
        if is_an_enabled:
            ports_mix = 'anlt_mix.json'
        if traffic_mode is not self.TRAFFIC_MODE.NO_TRAFFIC and not is_an_enabled:
            ports_mix = 'traffic_gen_mix.json'

        self.fill_args_from_env_vars(ports_mix)
        self.snake.run_snake()

        shutted_mac_ports = []
        for index, mac_port in enumerate(self.snake.mph.mac_ports):
            if (ports_to_shut is self.PORTS_TO_SHUT.PORTS_SHUT_ALL) or (
                    ports_to_shut is self.PORTS_TO_SHUT.PORTS_SHUT_EVEN and (index % 2) == 0):
                shutted_mac_ports.append(mac_port)

        if traffic_mode is self.TRAFFIC_MODE.TRAFFIC_IN_THE_MIDDLE or traffic_mode is self.TRAFFIC_MODE.TRAFFIC_AFTER_ACTIVATE:
            self.open_spirent()
            self.add_data_streams()

        if traffic_mode is self.TRAFFIC_MODE.TRAFFIC_IN_THE_MIDDLE:
            self.spirent.run_traffic()

        self.outfile = open("{}/fec_counters_{}.csv".format(self.reports_dir, self.id()), "w+", 1)
        self.outfile.write(
            "Iteration,Link,name,Slice,IFG,SerDes,BER,FLR,FLR_R,cw0,cw1,cw2,cw3,cw4,cw5,cw6,cw7,cw8,cw9,cw10,cw11,cw12,cw13,cw14,cw15,Uncorrectable,Symbol bursts\n")
        for shut_iter in range(self.test_iterations):
            print('Iteration {} Started'.format(shut_iter))

            self.shut_no_shut_mac_ports(shutted_mac_ports)

            time.sleep(REST_DELAY)
            self.snake.mph.clear_mac_stats()

            time.sleep(ITERATION_DELAY)

            if traffic_mode is self.TRAFFIC_MODE.TRAFFIC_AFTER_ACTIVATE:
                stats = self.spirent.run_and_get_rx_tx(5)
                self.snake.mph.print_mac_stats()
                self.assertEqual(
                    stats['tx_packets'],
                    stats['rx_packets'],
                    'Iter={}: te tx={} != rx={}'.format(shut_iter,
                                                        stats['tx_packets'],
                                                        stats['rx_packets']))

            fec_counters = self.snake.mph.get_mac_fec_counters()
            self.save_mac_fec_counters(fec_counters, shut_iter)
            self.check_mac_fec(fec_counters)
            if shut_iter == 0:
                self.max_fec_counters = fec_counters
            else:
                self.analyze_mac_fec(fec_counters)

        self.save_mac_fec_counters(self.max_fec_counters, "Max/Worst")
        self.outfile.close()

        if traffic_mode is self.TRAFFIC_MODE.TRAFFIC_IN_THE_MIDDLE:
            self.spirent.stop_traffic()
            self.snake.mph.print_mac_stats()

    def analyze_mac_fec(self, fec_counters):
        for index, fec_counter in enumerate(fec_counters):
            if (fec_counter['ber'] > self.max_fec_counters[index]['ber']):
                self.max_fec_counters[index]['ber'] = fec_counter['ber']
            if (fec_counter['flr'] > self.max_fec_counters[index]['flr']):
                self.max_fec_counters[index]['flr'] = fec_counter['flr']
            if (fec_counter['uncw'] > self.max_fec_counters[index]['uncw']):
                self.max_fec_counters[index]['uncw'] = fec_counter['uncw']
            for cw_i, cw in enumerate(fec_counter['cw']):
                if (cw > self.max_fec_counters[index]['cw'][cw_i]):
                    self.max_fec_counters[index]['cw'][cw_i] = cw

    def _test_shut_all_ports(self):

        self.shut_no_shut_base_test(self.PORTS_TO_SHUT.PORTS_SHUT_ALL, self.TRAFFIC_MODE.NO_TRAFFIC, False)

    def _test_shut_half_ports(self):

        self.shut_no_shut_base_test(self.PORTS_TO_SHUT.PORTS_SHUT_EVEN, self.TRAFFIC_MODE.NO_TRAFFIC, False)

    def _test_shut_all_ports_ANLT(self):

        self.shut_no_shut_base_test(self.PORTS_TO_SHUT.PORTS_SHUT_ALL, self.TRAFFIC_MODE.NO_TRAFFIC, True)

    def _test_shut_half_ports_ANLT(self):

        self.shut_no_shut_base_test(self.PORTS_TO_SHUT.PORTS_SHUT_EVEN, self.TRAFFIC_MODE.NO_TRAFFIC, True)

    def _test_shut_all_ports_with_traffic(self):

        self.shut_no_shut_base_test(self.PORTS_TO_SHUT.PORTS_SHUT_ALL, self.TRAFFIC_MODE.TRAFFIC_AFTER_ACTIVATE, False)

    def _test_shut_all_ports_with_constant_traffic(self):

        self.shut_no_shut_base_test(self.PORTS_TO_SHUT.PORTS_SHUT_ALL, self.TRAFFIC_MODE.TRAFFIC_IN_THE_MIDDLE, False)

    def _test_shut_all_ports_low_power(self):
        self.snake.args.serdes_low_power = True

        self.shut_no_shut_base_test(self.PORTS_TO_SHUT.PORTS_SHUT_ALL, self.TRAFFIC_MODE.NO_TRAFFIC, False)

    def _test_shut_half_ports_low_power(self):
        self.snake.args.serdes_low_power = True

        self.shut_no_shut_base_test(self.PORTS_TO_SHUT.PORTS_SHUT_EVEN, self.TRAFFIC_MODE.NO_TRAFFIC, False)

    def _test_shut_all_ports_low_power_ANLT(self):
        self.snake.args.serdes_low_power = True

        self.shut_no_shut_base_test(self.PORTS_TO_SHUT.PORTS_SHUT_ALL, self.TRAFFIC_MODE.NO_TRAFFIC, True)

    def _test_shut_half_ports_low_power_ANLT(self):
        self.snake.args.serdes_low_power = True

        self.shut_no_shut_base_test(self.PORTS_TO_SHUT.PORTS_SHUT_EVEN, self.TRAFFIC_MODE.NO_TRAFFIC, True)

    def _test_shut_mlp_all_ports_with_traffic(self):
        self.shut_no_shut_base_test(self.PORTS_TO_SHUT.PORTS_SHUT_ALL, self.TRAFFIC_MODE.TRAFFIC_AFTER_ACTIVATE, False, True)
