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

import mac_port_board_test_base as board_base


class test_xena_ports(board_base.mac_port_board_test_base):

    def setUp(self):
        self.device_init(True)

    def tearDown(self):
        sdk.la_destroy_device(self.device)

    def xena_test(self, mac_port_configs):
        self.cur_slice = 2
        self.cur_ifg = 0
        self.cur_serdes = 0

        self.create_mac_ports(mac_port_configs)

        # Activate
        for mac_port in self.mac_ports:
            try:
                mac_port.activate()
            except hldcli.BaseException:
                raise Exception('activate slice {}, IFG {}, SerDes {}'.format(
                    mac_port.get_slice(), mac_port.get_ifg(), mac_port.get_first_serdes_id()))

            try:
                mac_port.tune(True)
            except hldcli.BaseException:
                raise Exception('tune slice {}, IFG {}, SerDes {}'.format(
                    mac_port.get_slice(), mac_port.get_ifg(), mac_port.get_first_serdes_id()))

        self.check_mac_up()

    def test_xena_4_1x25(self):
        mac_port_configs = []
        mac_port_configs.append({'name': "1x25G", 'serdes_count': 1, 'speed': sdk.la_mac_port.port_speed_e_E_25G,
                                 'fec_modes': [
                                     sdk.la_mac_port.fec_mode_e_RS_KR4],
                                 'fc_modes': [
                                     sdk.la_mac_port.fc_mode_e_NONE,
                                     sdk.la_mac_port.fc_mode_e_NONE,
                                     sdk.la_mac_port.fc_mode_e_NONE,
                                     sdk.la_mac_port.fc_mode_e_NONE]
                                 })

        self.xena_test(mac_port_configs)

    def test_xena_2_2x25(self):
        mac_port_configs = []
        mac_port_configs.append({'name': "2x25G", 'serdes_count': 2, 'speed': sdk.la_mac_port.port_speed_e_E_50G,
                                 'fec_modes': [
                                     sdk.la_mac_port.fec_mode_e_RS_KR4],
                                 'fc_modes': [
                                     sdk.la_mac_port.fc_mode_e_NONE,
                                     sdk.la_mac_port.fc_mode_e_NONE]
                                 })

        self.xena_test(mac_port_configs)

    def test_xena_1_4x25(self):
        mac_port_configs = []
        mac_port_configs.append({'name': "4x25G", 'serdes_count': 4, 'speed': sdk.la_mac_port.port_speed_e_E_100G,
                                 'fec_modes': [
                                     sdk.la_mac_port.fec_mode_e_RS_KR4],
                                 'fc_modes': [
                                     sdk.la_mac_port.fc_mode_e_NONE]
                                 })

        self.xena_test(mac_port_configs)

    def test_xena_1_2x25(self):
        mac_port_configs = []
        mac_port_configs.append({'name': "2x25G", 'serdes_count': 2, 'speed': sdk.la_mac_port.port_speed_e_E_50G,
                                 'fec_modes': [
                                     sdk.la_mac_port.fec_mode_e_RS_KR4],
                                 'fc_modes': [
                                     sdk.la_mac_port.fc_mode_e_NONE]
                                 })

        self.xena_test(mac_port_configs)
        self.print_mac_up()

    def test_xena_2_2x25_repeat(self):
        mac_port_xena_4_1x25_cfg = [{'name': "1x25G", 'serdes_count': 1, 'speed': sdk.la_mac_port.port_speed_e_E_25G,
                                     'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KR4],
                                     'fc_modes': [
                                         sdk.la_mac_port.fc_mode_e_NONE,
                                         sdk.la_mac_port.fc_mode_e_NONE,
                                         sdk.la_mac_port.fc_mode_e_NONE,
                                         sdk.la_mac_port.fc_mode_e_NONE]
                                     }]

        mac_port_xena_2_2x25_cfg = [{'name': "2x25G", 'serdes_count': 2, 'speed': sdk.la_mac_port.port_speed_e_E_50G,
                                     'fec_modes': [sdk.la_mac_port.fec_mode_e_RS_KR4],
                                     'fc_modes': [
                                         sdk.la_mac_port.fc_mode_e_NONE,
                                         sdk.la_mac_port.fc_mode_e_NONE]
                                     }]

        for i in range(2):
            print('Iteration {} 4 1x25'.format(i))
            self.destroy_mac_ports()
            self.xena_test(mac_port_xena_4_1x25_cfg)

            print('Iteration {} 2 2x25'.format(i))
            self.destroy_mac_ports()
            self.xena_test(mac_port_xena_2_2x25_cfg)


if __name__ == '__main__':
    unittest.main()
