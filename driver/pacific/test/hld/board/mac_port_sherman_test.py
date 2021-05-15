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

import time
import unittest
from leaba import sdk
import lldcli
import aaplcli

import mac_port_board_test_base as board_base


class test_sherman_mac_port(board_base.mac_port_board_test_base):

    def setUp(self):
        self.time_setup_start = time.perf_counter()
        self.device_init(True)

    def create_port_mix_sherman(self):
        port_mix = []

        for slice in range(6):
            for ifg in range(2):
                for port in range(2):
                    port_mix.append({'slice': slice, 'ifg': ifg, 'serdes': port * 8, 'serdes_count': 8,
                                     'speed': sdk.la_mac_port.port_speed_e_E_400G,
                                     'fc': sdk.la_mac_port.fc_mode_e_NONE, 'fec': sdk.la_mac_port.fec_mode_e_RS_KP4,
                                     'p2p_loops': 8})
                port_mix.append({'slice': slice, 'ifg': ifg, 'serdes': 16, 'serdes_count': 2,
                                 'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                 'fc': sdk.la_mac_port.fc_mode_e_NONE, 'fec': sdk.la_mac_port.fec_mode_e_RS_KP4,
                                 'p2p_loops': 2})

        return port_mix

    def create_port_mix_sherman_reduced(self):
        port_mix = []

        for slice in range(5):
            for ifg in range(2):
                for port in range(2):
                    port_mix.append({'slice': slice, 'ifg': ifg, 'serdes': port * 8, 'serdes_count': 8,
                                     'speed': sdk.la_mac_port.port_speed_e_E_400G,
                                     'fc': sdk.la_mac_port.fc_mode_e_NONE, 'fec': sdk.la_mac_port.fec_mode_e_RS_KP4,
                                     'p2p_loops': 8})
                if (slice != 2):
                    port_mix.append({'slice': slice, 'ifg': ifg, 'serdes': 16, 'serdes_count': 2,
                                     'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                     'fc': sdk.la_mac_port.fc_mode_e_NONE, 'fec': sdk.la_mac_port.fec_mode_e_RS_KP4,
                                     'p2p_loops': 2})

        return port_mix

    def test_pma_loopback(self):
        mac_port_mix = self.create_port_mix_sherman()

        self.pma_loopback(mac_port_mix)

    def test_avago_ilb_loopback(self):
        mac_port_mix = self.create_port_mix_sherman()

        self.avago_loopback(mac_port_mix, True, sdk.la_mac_port.loopback_mode_e_SERDES)

    def test_parallel_avago_ilb_loopback(self):
        mac_port_mix = self.create_port_mix_sherman()

        self.avago_loopback(mac_port_mix, False, sdk.la_mac_port.loopback_mode_e_SERDES)

    def test_avago_elb_loopback(self):
        mac_port_mix = self.create_port_mix_sherman_reduced()

        self.avago_loopback(mac_port_mix, True, sdk.la_mac_port.loopback_mode_e_NONE)

    def test_parallel_avago_elb_loopback(self):
        mac_port_mix = self.create_port_mix_sherman_reduced()

        self.avago_loopback(mac_port_mix, False, sdk.la_mac_port.loopback_mode_e_NONE)


if __name__ == '__main__':
    unittest.main()
