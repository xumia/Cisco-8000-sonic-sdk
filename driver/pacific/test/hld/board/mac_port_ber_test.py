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

MAX_TUNE_RETRIES = 30


class test_hw_mac_port(board_base.mac_port_board_test_base):

    def setUp(self):
        self.time_setup_start = time.perf_counter()
        self.device_init(True)

    # Add all MAC port valid configurations
    def add_mac_port_ber_configs(self, mac_port_configs):
        mac_port_configs.append({'name': "1x10G", 'serdes_count': 1, 'speed': sdk.la_mac_port.port_speed_e_E_10G,
                                 'fec_modes': [
                                     sdk.la_mac_port.fec_mode_e_NONE,
                                     sdk.la_mac_port.fec_mode_e_KR],
                                 'fc_modes': [
                                     sdk.la_mac_port.fc_mode_e_NONE]
                                 })

        mac_port_configs.append({'name': "1x25G", 'serdes_count': 1, 'speed': sdk.la_mac_port.port_speed_e_E_25G,
                                 'fec_modes': [
                                     sdk.la_mac_port.fec_mode_e_NONE,
                                     sdk.la_mac_port.fec_mode_e_RS_KR4,
                                     sdk.la_mac_port.fec_mode_e_RS_KP4],
                                 'fc_modes': [
                                     sdk.la_mac_port.fc_mode_e_NONE]
                                 })

        mac_port_configs.append({'name': "1x50G", 'serdes_count': 1, 'speed': sdk.la_mac_port.port_speed_e_E_50G,
                                 'fec_modes': [
                                     sdk.la_mac_port.fec_mode_e_RS_KR4,
                                     sdk.la_mac_port.fec_mode_e_RS_KP4],
                                 'fc_modes': [
                                     sdk.la_mac_port.fc_mode_e_NONE]
                                 })

        # 2x25 is invalid for BER

        mac_port_configs.append({'name': "2x50G", 'serdes_count': 2, 'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                 'fec_modes': [
                                     sdk.la_mac_port.fec_mode_e_RS_KR4,
                                     sdk.la_mac_port.fec_mode_e_RS_KP4],
                                 'fc_modes': [
                                     sdk.la_mac_port.fc_mode_e_NONE]
                                 })

        # 4x25 is invalid for BER

        mac_port_configs.append({'name': "8x50G", 'serdes_count': 8, 'speed': sdk.la_mac_port.port_speed_e_E_400G,
                                 'fec_modes': [
                                     sdk.la_mac_port.fec_mode_e_RS_KP4],
                                 'fc_modes': [
                                     sdk.la_mac_port.fc_mode_e_NONE]
                                 })

    def add_mac_port_ber_elb_configs(self, mac_port_configs):
        mac_port_configs.append({'name': "1x25G", 'serdes_count': 1, 'speed': sdk.la_mac_port.port_speed_e_E_25G,
                                 'fec_modes': [
                                     sdk.la_mac_port.fec_mode_e_NONE,
                                     sdk.la_mac_port.fec_mode_e_RS_KR4,
                                     sdk.la_mac_port.fec_mode_e_RS_KP4],
                                 'fc_modes': [
                                     sdk.la_mac_port.fc_mode_e_NONE]
                                 })

        # 1x50 Moved to the end, so all will fit in one slice

        # 2x25 is invalid for BER

        mac_port_configs.append({'name': "2x50G", 'serdes_count': 2, 'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                 'fec_modes': [
                                     sdk.la_mac_port.fec_mode_e_RS_KR4,
                                     sdk.la_mac_port.fec_mode_e_RS_KP4],
                                 'fc_modes': [
                                     sdk.la_mac_port.fc_mode_e_NONE]
                                 })

        # 4x25 is invalid for BER

        mac_port_configs.append({'name': "8x50G", 'serdes_count': 8, 'speed': sdk.la_mac_port.port_speed_e_E_400G,
                                 'fec_modes': [
                                     sdk.la_mac_port.fec_mode_e_RS_KP4],
                                 'fc_modes': [
                                     sdk.la_mac_port.fc_mode_e_NONE]
                                 })

        mac_port_configs.append({'name': "1x50G", 'serdes_count': 1, 'speed': sdk.la_mac_port.port_speed_e_E_50G,
                                 'fec_modes': [
                                     sdk.la_mac_port.fec_mode_e_RS_KR4,
                                     sdk.la_mac_port.fec_mode_e_RS_KP4],
                                 'fc_modes': [
                                     sdk.la_mac_port.fc_mode_e_NONE]
                                 })

    def print_mac_pma_ber(self):
        for index in range(len(self.common_mac_ports)):
            mac_info = self.get_mac_pma_ber(index)
            mac_info['lane_ber_str'] = list(map(lambda ber_val: '{:.03e}'.format(ber_val), mac_info['lane_ber']))
            print(
                'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), BER {lane_ber_str}'.format(
                    **mac_info))

    def test_pma_loopback(self):
        mac_port_configs = []
        self.add_mac_port_ber_configs(mac_port_configs)

        mac_port_mix = self.create_mac_port_mix_from_configs(mac_port_configs)

        self.pma_loopback(mac_port_mix)

        self.print_mac_pma_ber()

    def test_avago_ilb_loopback(self):
        mac_port_configs = []
        self.add_mac_port_ber_configs(mac_port_configs)

        mac_port_mix = self.create_mac_port_mix_from_configs(mac_port_configs)

        self.avago_loopback(mac_port_mix, True, sdk.la_mac_port.loopback_mode_e_SERDES)

        self.print_mac_pma_ber()

    def test_parallel_avago_ilb_loopback(self):
        mac_port_configs = []
        self.add_mac_port_ber_configs(mac_port_configs)

        mac_port_mix = self.create_mac_port_mix_from_configs(mac_port_configs)

        self.avago_loopback(mac_port_mix, False, sdk.la_mac_port.loopback_mode_e_SERDES)

        self.print_mac_pma_ber()

    def test_avago_elb_loopback(self):
        mac_port_configs = []
        self.add_mac_port_ber_elb_configs(mac_port_configs)

        self.cur_slice = 5

        mac_port_mix = self.create_mac_port_mix_from_configs(mac_port_configs)

        self.avago_loopback(mac_port_mix, True, sdk.la_mac_port.loopback_mode_e_NONE)

        self.print_mac_pma_ber()

    def test_parallel_avago_elb_loopback(self):
        mac_port_configs = []
        self.add_mac_port_ber_elb_configs(mac_port_configs)

        self.cur_slice = 5

        mac_port_mix = self.create_mac_port_mix_from_configs(mac_port_configs)

        self.avago_loopback(mac_port_mix, False, sdk.la_mac_port.loopback_mode_e_NONE)

        self.print_mac_pma_ber()


if __name__ == '__main__':
    unittest.main()
