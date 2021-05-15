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

import os
import argparse
import json
import sim_utils
from leaba import sdk
from snake_base import *
import mac_port_helper
from diag_connector import *

DEBUG = False
BOARD_CONFIG_PATH = 'examples/sanity/churchill'
BOARD_CONFIG_FILE = '_board_config.json'
BOARD_CONNECT = 'test/ports/config/gibraltar_ports_conn_config.json'
PARAM_JSON = 'examples/sanity/churchill_serdes_settings.json'
PORTS_MODES = 'test/ports/config/mac_ports_modes.json'
TEST_ITERATIONS = 1
cable_loss = {"1m": 10.6,
              "2m": 12.6,
              "3m": 14.6}


class ports_test_base(snake_base):
    SLICE_ID_IDX = 0
    IFG_IDX = 1
    FIRST_SERDES_IDX = 2
    SER_IN_USE_IDX = 3
    EGRESS_LOSS_IDX = 4
    INGRESS_LOSS_IDX = 5
    CONN_CABLE_IDX = 2
    DWELL_UP_TIME = 120  # Time in seconds
    CREATE_LEFT_PORTS = 1
    CREATE_RIGHT_PORTS = 2
    PORT_SANITY_DEFAULT_MODES = 0
    PORT_SANITY_EXTEND_MODES = 1
    PORT_SANITY_EXTEND_MODES_ANLT_ONLY = 2
    BER_AVERAGE_THRESHOLD = 200

    def fill_args_from_env_vars(self):
        # Mac ports valid modes file is shared among ASICs
        self.ports_modes = PORTS_MODES
        self.dc = diag_connector()

        proto_type = os.getenv("board_proto").upper()
        if proto_type is None:
            proto_type = 'P1'
            self.board_select = 'churchill7'
        elif proto_type == 'P3':
            self.board_select = 'churchill4'
        elif proto_type == 'P2':
            self.board_select = 'churchill7'
        elif proto_type == 'P1':
            self.board_select = 'churchill5'
        else:
            proto_type == 'P1'
            self.board_select = 'churchill7'

        board_cfg_path = os.getenv("board_cfg_path")
        if board_cfg_path is None:
            if proto_type == 'P2':
                proto_type = 'P1'
            board_cfg_path = BOARD_CONFIG_PATH + proto_type + BOARD_CONFIG_FILE
        self.snake.args.board_cfg_path = board_cfg_path

        board_connect_path = os.getenv("board_connect_path")
        if board_connect_path is None:
            board_connect_path = BOARD_CONNECT
        self.connect_mix = board_connect_path

        self.snake.args.params_json = os.getenv("serdes_params_json")
        if self.snake.args.params_json is None:
            self.snake.args.params_json = PARAM_JSON

        self.test_iterations = os.getenv("test_iterations")
        if self.test_iterations is None:
            self.test_iterations = TEST_ITERATIONS
        else:
            self.test_iterations = int(self.test_iterations)

        self.device_rev = os.getenv("device_rev")
        if self.device_rev is None:
            self.device_rev = 'gibraltar'

        self.port_sanity_mode = os.getenv("port_sanity_mode")
        if self.port_sanity_mode is None:
            self.port_sanity_mode = self.PORT_SANITY_DEFAULT_MODES
        else:
            self.port_sanity_mode = int(self.port_sanity_mode)

        self.port_sanity_dump_pair = os.getenv("port_sanity_dump_pair")
        if self.port_sanity_dump_pair is None:
            self.port_sanity_dump_pair = False

    def speed_value_to_enum(self, speed_value):
        return {
            10: sdk.la_mac_port.port_speed_e_E_10G,
            25: sdk.la_mac_port.port_speed_e_E_25G,
            40: sdk.la_mac_port.port_speed_e_E_40G,
            50: sdk.la_mac_port.port_speed_e_E_50G,
            100: sdk.la_mac_port.port_speed_e_E_100G,
            200: sdk.la_mac_port.port_speed_e_E_200G,
            400: sdk.la_mac_port.port_speed_e_E_400G,
            800: sdk.la_mac_port.port_speed_e_E_800G,
        }[int(speed_value)]

    def fec_value_to_enum(self, fec_value):
        return {
            'NONE': sdk.la_mac_port.fec_mode_e_NONE,
            'KR': sdk.la_mac_port.fec_mode_e_KR,
            'RS_KR4': sdk.la_mac_port.fec_mode_e_RS_KR4,
            'RS_KP4': sdk.la_mac_port.fec_mode_e_RS_KP4,
        }[fec_value]

    def fc_value_to_enum(self, fc_value):
        return {
            'NONE': sdk.la_mac_port.fc_mode_e_NONE,
            'PAUSE': sdk.la_mac_port.fc_mode_e_PAUSE,
            'PFC': sdk.la_mac_port.fc_mode_e_PFC,
            'CFFC': sdk.la_mac_port.fc_mode_e_CFFC,
        }[fc_value]

    def create_port_connectivity_config(self):
        self.port_pairs = []
        self.ports = {}
        self.valid_modes = {}
        self.mp_db_loss = []

    def load_connectivity_config_from_json(self, connectivity_file, select_board):
        select_board_str = 'connectivity_' + select_board
        print(select_board_str)
        with open(connectivity_file, 'r') as fp:
            connectivity_cfg = json.load(fp)
            for conn_settings in connectivity_cfg[select_board_str]:
                self.port_pairs.append(conn_settings)
            if (DEBUG):
                print(self.port_pairs)
        fp.close()

    def load_front_port_from_json(self, board_cfg_file):
        with open(board_cfg_file, 'r') as fp:
            board_cfg = json.load(fp)
            for fp_port in board_cfg['fp_ports']:
                serdes_info = []
                serdes_info.append(fp_port['slice_id'])
                serdes_info.append(fp_port['ifg'])
                serdes_info.append(fp_port['first_pif'])
                serdes_info.append(fp_port['ser_in_use'])
                try:
                    serdes_info.append(fp_port['egress_loss'])
                    serdes_info.append(fp_port['ingress_loss'])
                except BaseException:
                    pass
                self.ports[fp_port['fp']] = serdes_info
            if (DEBUG):
                print(self.ports)
        fp.close()

    def load_valid_modes_from_json(self, ports_modes_file, device_rev):
        print(device_rev)
        with open(ports_modes_file, 'r') as fp:
            valid_modes = json.load(fp)
            self.valid_modes = valid_modes[device_rev]
        fp.close()

    def dbg_print(self, *args):
        if (DEBUG):
            print(args)

    def snake_init(self):
        self.snake.reset()
        self.snake.device_init(
            self.snake_args.id,
            self.snake_args.path,
            self.snake_args.board_cfg_path,
            self.snake_args.hbm,
            self.snake_args.line_card)
        self.device = self.snake.device

        self.mph = mac_port_helper.mac_port_helper(True)
        self.mph.init(self.device)
        self.snake.mph = self.mph

    def snake_activate_ports(self):
        self.mph.mac_ports_activate(self.snake_args.module_type, self.snake_args.params_json)
        all_up = self.mph.wait_mac_ports_up(timeout=self.link_down_timeout)
        self.mph.print_mac_up()

    def create_paired_ports(self, testing_mode, testing_pair, loopback_mode, is_an_enabled, special_mode = 0):
        serdes_per_port = self.valid_modes[testing_mode]['serdes_per_port']
        print(f"Testing pair {testing_pair}")

        port = testing_pair[0]
        num_subports = self.ports[port][self.SER_IN_USE_IDX] / serdes_per_port

        for subport in range(int(num_subports)):
            speed = self.speed_value_to_enum(self.valid_modes[testing_mode]['speed'])
            fec_mode = self.fec_value_to_enum(self.valid_modes[testing_mode]['fec_mode'])
            fc_mode = self.fc_value_to_enum(self.valid_modes[testing_mode]['fc_mode'])

            # first port
            port = testing_pair[0]
            slice_id = self.ports[port][self.SLICE_ID_IDX]
            ifg = self.ports[port][self.IFG_IDX]
            first_serdes = self.ports[port][self.FIRST_SERDES_IDX]

            first_pif = first_serdes + subport * serdes_per_port
            first_anlt = self.get_first_anlt_serdes(slice_id, ifg, first_pif, serdes_per_port)
            if (special_mode != self.CREATE_RIGHT_PORTS):
                print(f"Create mac port Serdes {slice_id}/{ifg}/{first_pif}")
                self.mph.create_mac_port(
                    slice_id,
                    ifg,
                    first_pif,
                    serdes_per_port,
                    speed,
                    fec_mode,
                    fc_mode,
                    loopback_mode,
                    is_an_enabled)
                peer = testing_pair[1]
                fp_db_loss = False
                try:
                    fp_db_loss = self.ports[port][self.EGRESS_LOSS_IDX] + \
                        self.ports[peer][self.INGRESS_LOSS_IDX] + cable_loss[testing_pair[self.CONN_CABLE_IDX]]
                except BaseException:
                    pass
                if (fp_db_loss):
                    self.mp_db_loss.append(fp_db_loss)

            if (special_mode != self.CREATE_LEFT_PORTS):
                # second port
                port = testing_pair[1]
                slice_id = self.ports[port][self.SLICE_ID_IDX]
                ifg = self.ports[port][self.IFG_IDX]
                first_serdes = self.ports[port][self.FIRST_SERDES_IDX]

                first_pif = self.find_first_anlt_tx(slice_id, ifg, first_serdes, first_anlt, serdes_per_port)
                assert first_pif >= first_serdes and first_pif < (first_serdes + self.ports[port][self.SER_IN_USE_IDX])
                print(f"Create mac port Serdes {slice_id}/{ifg}/{first_pif}")
                self.mph.create_mac_port(
                    slice_id,
                    ifg,
                    first_pif,
                    serdes_per_port,
                    speed,
                    fec_mode,
                    fc_mode,
                    loopback_mode,
                    is_an_enabled)
                peer = testing_pair[0]
                fp_db_loss = False
                try:
                    fp_db_loss = self.ports[port][self.EGRESS_LOSS_IDX] + \
                        self.ports[peer][self.INGRESS_LOSS_IDX] + cable_loss[testing_pair[self.CONN_CABLE_IDX]]
                except BaseException:
                    pass
                if (fp_db_loss):
                    self.mp_db_loss.append(fp_db_loss)

    def get_first_anlt_serdes(self, slice_id, ifg, first_pif, serdes_per_port):
        anlt_list = self.device.get_serdes_anlt_order(slice_id, ifg)
        first_anlt = anlt_list[first_pif]
        for serdes in range(serdes_per_port):
            first_anlt = min(first_anlt, anlt_list[first_pif + serdes])
        return first_anlt

    def find_first_anlt_tx(self, slice_id, ifg, first_serdes, first_anlt, serdes_per_port):
        anlt_list = self.device.get_serdes_anlt_order(slice_id, ifg)
        mac_pool = first_serdes / 8
        anlt_sub_list = anlt_list[first_serdes:int((mac_pool + 1) * 8)]
        anlt_sub_list = [x % 8 for x in anlt_sub_list]

        first_anlt_tx = anlt_sub_list.index(first_anlt % 8) + int(mac_pool * 8)
        first_tx = (int(first_anlt_tx / serdes_per_port)) * serdes_per_port
        return first_tx

    def destroy_paired_ports(self):
        self.mph.teardown()
        self.mph.init(self.device)
        self.mph.print_mac_up()
