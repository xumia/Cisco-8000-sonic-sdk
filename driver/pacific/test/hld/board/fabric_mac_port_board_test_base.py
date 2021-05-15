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
import common_mac_port_board_test_base as common_mac_port_base

MAX_RETRY = 100
MAX_SERDES_ID = 17
MAX_RETUNE = 2


class fabric_mac_port_board_test_base(common_mac_port_base.common_mac_port_board_test_base):

    def configure_phase_topology(self):
        for sid in range(6):
            slice_mode = None
            if sid < 3:
                slice_mode = sdk.la_slice_mode_e_NETWORK
            else:
                slice_mode = sdk.la_slice_mode_e_CARRIER_FABRIC
            self.device.set_slice_mode(sid, slice_mode)

    def initialize_test_variables(self):
        self.cur_slice = 3
        self.cur_ifg = 0
        self.cur_serdes = 0

    def fabric_mac_port_setup(self, name, serdes_count, speed, fc_modes):
        for fc_mode in fc_modes:
            if (self.cur_serdes % serdes_count) != 0:
                self.cur_serdes = (int(self.cur_serdes / serdes_count) + 1) * serdes_count
            if (self.cur_serdes + serdes_count - 1) > MAX_SERDES_ID:
                self.cur_serdes += serdes_count
            self.fix_current_serdes()

            serdes_start = self.cur_serdes
            serdes_last = serdes_start + serdes_count - 1
            try:
                fabric_mac_port = self.device.create_fabric_mac_port(
                    self.cur_slice, self.cur_ifg, serdes_start, serdes_last, speed, fc_mode)
            except lldcli.BaseException:
                raise Exception('Failed create_fabric_mac_port {0} with FC_MODE {1} '.format(name, fc_mode))

            try:
                fabric_port = self.device.create_fabric_port(fabric_mac_port)
            except lldcli.BaseException:
                raise Exception('Failed create_fabric_port {0} with FC_MODE {1} '.format(name, fc_mode))

            self.assertIsNotNone(fabric_mac_port)
            self.common_mac_ports.append(fabric_mac_port)
            self.common_fabric_ports.append(fabric_port)

            out_speed = fabric_mac_port.get_speed()
            self.assertEqual(out_speed, speed)

            self.cur_serdes += serdes_count
            self.fix_current_serdes()

    def create_fabric_mac_ports(self, fabric_mac_port_configs):
        for fabric_mac_port_config in fabric_mac_port_configs:
            self.fabric_mac_port_setup(
                fabric_mac_port_config['name'],
                fabric_mac_port_config['serdes_count'],
                fabric_mac_port_config['speed'],
                fabric_mac_port_config['fc_modes'])
