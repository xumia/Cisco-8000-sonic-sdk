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

MAX_SERDES_ID = 17

# Timeout in seconds for ports to become UP
TIMEOUT_PORT_UP = 60


class mac_port_board_test_base(common_mac_port_base.common_mac_port_board_test_base):

    def configure_phase_topology(self):
        for sid in range(6):
            self.device.set_slice_mode(sid, sdk.la_slice_mode_e_NETWORK)

    def initialize_test_variables(self):
        self.cur_slice = 0
        self.cur_ifg = 0
        self.cur_serdes = 0

    def create_mac_port_mix_from_configs(self, mac_port_configs):
        port_mix = []

        for mac_port_config in mac_port_configs:
            serdes_count = mac_port_config['serdes_count']
            for fec_mode in mac_port_config['fec_modes']:
                for fc_mode in mac_port_config['fc_modes']:
                    if (self.cur_serdes % serdes_count) != 0:
                        self.cur_serdes = (int(self.cur_serdes / serdes_count) + 1) * serdes_count
                    if (self.cur_serdes + serdes_count - 1) > MAX_SERDES_ID:
                        self.cur_serdes += serdes_count
                    self.fix_current_serdes()

                    port_mix.append({'slice': self.cur_slice, 'ifg': self.cur_ifg, 'serdes': self.cur_serdes,
                                     'serdes_count': serdes_count, 'speed': mac_port_config['speed'],
                                     'fc': fc_mode, 'fec': fec_mode})

                    self.cur_serdes += serdes_count
                    self.fix_current_serdes()

        return port_mix

    def create_mac_ports_from_mix(self, port_mix):
        for port_cfg in port_mix:
            serdes_start = port_cfg['serdes']
            serdes_last = serdes_start + port_cfg['serdes_count'] - 1
            mac_port = self.device.create_mac_port(port_cfg['slice'], port_cfg['ifg'], serdes_start, serdes_last, port_cfg['speed'],
                                                   port_cfg['fc'], port_cfg['fec'])

            self.common_mac_ports.append(mac_port)

    def mac_port_setup(self, name, serdes_count, speed, fc_modes, fec_modes):
        for fec_mode in fec_modes:
            for fc_mode in fc_modes:
                if (self.cur_serdes % serdes_count) != 0:
                    self.cur_serdes = (int(self.cur_serdes / serdes_count) + 1) * serdes_count
                if (self.cur_serdes + serdes_count - 1) > MAX_SERDES_ID:
                    self.cur_serdes += serdes_count
                self.fix_current_serdes()

                serdes_start = self.cur_serdes
                serdes_last = serdes_start + serdes_count - 1
                try:
                    mac_port = self.device.create_mac_port(self.cur_slice, self.cur_ifg, serdes_start, serdes_last,
                                                           speed, fc_mode, fec_mode)
                except hldcli.BaseException:
                    raise Exception('Failed create_mac_port {0} with FC_MODE {1}, FEC_MODE {2} '.format(name, fc_mode, fec_mode))

                self.assertIsNotNone(mac_port)
                self.common_mac_ports.append(mac_port)

                out_speed = mac_port.get_speed()
                self.assertEqual(out_speed, speed)

                self.cur_serdes += serdes_count
                self.fix_current_serdes()

    def create_mac_ports(self, mac_port_configs):
        for mac_port_config in mac_port_configs:
            self.mac_port_setup(
                mac_port_config['name'],
                mac_port_config['serdes_count'],
                mac_port_config['speed'],
                mac_port_config['fc_modes'],
                mac_port_config['fec_modes'])

    def pma_loopback(self, mac_port_mix):
        time_start = time.perf_counter()

        # Create MAC ports
        self.create_mac_ports_from_mix(mac_port_mix)

        time_create = time.perf_counter()

        # Set loopback mode
        for mac_port in self.common_mac_ports:
            mac_port.set_loopback_mode(sdk.la_mac_port.loopback_mode_e_PMA_CORE_CLK)

        time_retune = time.perf_counter()

        # Check (link up)
        self.check_mac_up()

        time_check = time.perf_counter()

        self.print_mac_up()

        print('Total ports {}'. format(len(self.common_mac_ports)))

        total_times_info = {
            'setup': time_start - self.time_setup_start,
            'create': time_create - time_start,
            'init': 0,
            'tune_complete': 0,
            'retune': 0,
            'check': time_check - time_retune}
        print(
            'Total time: setup {setup:.2f}, create {create:.2f}, init {init:.2f}, tune complete {tune_complete:.2f}, re-tune {retune:.2f}, check {check:.2f}'.format(
                **total_times_info))

    def avago_loopback_create(self, mac_port_mix, loopback_mode):
        # Create MAC ports
        self.create_mac_ports_from_mix(mac_port_mix)

        # Set loopback mode and activate
        for mac_port in self.common_mac_ports:
            mac_port.set_loopback_mode(loopback_mode)

    def mac_ports_apply_params(self, mac_port):
        mac_info = {
            'slice': mac_port.get_slice(),
            'ifg': mac_port.get_ifg(),
            'serdes': mac_port.get_first_serdes_id()}
        serdes_count = mac_port.get_num_of_serdes()

        PRE_ICAL = sdk.la_mac_port.serdes_param_stage_e_PRE_ICAL
        PRE_PCAL = sdk.la_mac_port.serdes_param_stage_e_PRE_PCAL
        ACTIVATE = sdk.la_mac_port.serdes_param_stage_e_ACTIVATE
        FIXED = sdk.la_mac_port.serdes_param_mode_e_FIXED
        ADAPTIVE = sdk.la_mac_port.serdes_param_mode_e_ADAPTIVE
        props = [
            [PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFHF, FIXED, 4],
            [PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFLF, FIXED, 1],
            [PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_PLL_BB, FIXED, 1],
            [ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_PLL_IFLT, FIXED, 6],
            [ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_PLL_INT, FIXED, 8],
            [ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_PLL_BB, FIXED, 25],
            [ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_PLL_IFLT, FIXED, 1],
            [ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_PLL_INT, FIXED, 7],

            [PRE_PCAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFHF, ADAPTIVE, 0],
            [PRE_PCAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFLF, ADAPTIVE, 0],
        ]

        for serdes in range(serdes_count):
            for prop in props:
                (stage, param, mode, val) = prop
                mac_port.set_serdes_parameter(serdes, stage, param, mode, val)

    def avago_loopback_start(self, blocking):
        time_start = time.perf_counter()

        ports_time = []

        # Set loopback mode and activate
        for mac_port in self.common_mac_ports:
            port_time = {'start': time.perf_counter()}

            try:
                self.mac_ports_apply_params(mac_port)
                mac_port.activate()
            except hldcli.BaseException:
                raise Exception('activate slice {}, IFG {}, SerDes {}'.format(
                    mac_port.get_slice(), mac_port.get_ifg(), mac_port.get_first_serdes_id()))

            port_time['activate'] = time.perf_counter()
            ports_time.append(port_time)

        time_activate = time.perf_counter()

        start_time = time.time()
        curr_time = time.time()
        while (curr_time - start_time) < TIMEOUT_PORT_UP:
            if self.is_all_mac_up():
                break
            time_to_wait = TIMEOUT_PORT_UP + start_time - curr_time
            notifications = self.read_notifications(time_to_wait)
            curr_time = time.time()
            for notification in notifications:
                print('time diff {}'.format(curr_time - start_time))
                self.print_notification(notification)

        time_check = time.perf_counter()

        total_times_info = {
            'setup': time_start - self.time_setup_start,
            'init': time_activate - time_start,
            'check': time_check - time_activate}
        print(
            'Total time: setup {setup:.2f}, init {init:.2f}, check {check:.2f}'.format(
                **total_times_info))

        all_up = self.print_mac_up()

        return all_up

    def avago_loopback(self, mac_port_mix, blocking, loopback_mode):
        self.avago_loopback_create(mac_port_mix, loopback_mode)

        return self.avago_loopback_start(blocking)
