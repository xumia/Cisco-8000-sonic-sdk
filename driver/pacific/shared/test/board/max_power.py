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

import argparse
from max_power_base import *


class max_power(max_power_base):
    def parse_args(self):
        parser = argparse.ArgumentParser(description='MaxPower Test.')
        parser.add_argument('--cache', default=False, action='store_true',
                            help='enable cache mode')
        parser.add_argument('--nflows', type=int, default=1, choices=range(1, 65),
                            help='number of injected packets with different dest ip')
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


if __name__ == '__main__':
    mpower = max_power()
    mpower.setUp()
    mpower.parse_args()
    mpower.params['cache'] = mpower.args.cache
    mpower.params['nflows'] = mpower.args.nflows
    mpower.params['hbm'] = mpower.args.hbm
    mpower.params['packet_sizes'] = mpower.args.packet_sizes
    mpower.params['json_mix'] = mpower.args.json_mix
    mpower.params['device_frequency_khz'] = mpower.args.device_frequency_khz

    print('testing empty flows')
    mpower.run_empty_flow()
    mpower.tearDown()
    print('testing ipv6 flows')
    mpower.run_ipv6_traffic()
    mpower.tearDown()
    print('testing ipv4 flows')
    mpower.run_ipv4_traffic()
    mpower.tearDown()
    print('testing l2 flows')
    mpower.run_l2_traffic()
    mpower.tearDown()
