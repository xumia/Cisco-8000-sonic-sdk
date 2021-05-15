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
from leaba import debug
import lldcli
import aaplcli

import mac_port_board_test_base as board_base

import json
import argparse


class test_sherman_mac_port(board_base.mac_port_board_test_base):

    def setUp(self):
        self.time_setup_start = time.perf_counter()
        self.device_init(True)

    def __init__(self, device_name='/dev/uio0', device_id=0, board='none', hbm=False):
        self.time_setup_start = time.perf_counter()

        sdk.set_error_mode(sdk.error_mode_e_EXCEPTION)
        lldcli.set_error_mode(lldcli.error_mode_e_EXCEPTION)

        self.device_init(device_id, device_name, board, hbm)
        self.reset()

    def reset(self):
        self.common_mac_ports = []

    def device_init(self, device_id, device_name, board, hbm):
        hard_reset = True

        self.device_id = device_id
        self.device_name = device_name
        self.device = sdk.la_create_device(self.device_name, self.device_id)

        self.ll_device = self.device.get_ll_device()
        self.pacific_tree = self.ll_device.get_pacific_tree()

        # Hard reset on - off
        if hard_reset:
            self.ll_device.write_register(self.pacific_tree.sbif.reset_reg, 0x0)
            time.sleep(0.1)

            self.ll_device.write_register(self.pacific_tree.sbif.reset_reg, 0x1)
            time.sleep(0.1)

        self.device.initialize(sdk.la_device.init_phase_e_DEVICE)

        for sid in range(6):
            self.device.set_slice_mode(sid, sdk.la_slice_mode_e_NETWORK)

        if 'sherman' in board:
            self.sherman_config(board)
        elif board == 'stingray':
            self.stingray_config()

        self.device.initialize(sdk.la_device.init_phase_e_TOPOLOGY)
        self.init_interrupts()

        #self.debug_device = debug.debug_device(self.device)

    def teardown_iteration(self):
        for mac_port in self.common_mac_ports:
            self.device.destroy(mac_port)

        if self.fd_notification is not None:
            self.device.close_notification_fd(self.fd_notification)
            self.fd_notification = None

        self.device.flush()
        sdk.la_destroy_device(self.device)
        self.device = None
        self.reset()

    #####################################################################################################
    # Board configurations
    #####################################################################################################
    def sherman_P5_setting(self):
        ifg_swap_lists = []

        serdes_polarity_inverse_rx = []
        serdes_polarity_inverse_tx = []

        # Slice 0
        ifg_swap_lists.append([2, 3, 0, 1, 6, 7, 4, 5, 9, 11, 8, 10, 15, 13, 12, 14, 16, 17])
        serdes_polarity_inverse_rx.append({4, 5, 6, 7, 8, 15})
        serdes_polarity_inverse_tx.append({})
        ifg_swap_lists.append([0, 1, 3, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 16])
        serdes_polarity_inverse_rx.append({})
        serdes_polarity_inverse_tx.append({})

        # Slice 1
        ifg_swap_lists.append([0, 3, 2, 1, 6, 7, 5, 4, 8, 11, 10, 9, 15, 13, 14, 12, 16, 17])
        serdes_polarity_inverse_rx.append({0, 1, 4, 5, 8, 9, 10, 11, 12, 13, 14})
        serdes_polarity_inverse_tx.append({1, 3, 4, 7, 9, 10, 13})
        ifg_swap_lists.append([0, 3, 2, 1, 7, 4, 5, 6, 9, 10, 8, 11, 12, 14, 15, 13, 16, 17])
        serdes_polarity_inverse_rx.append({0, 1, 2, 4, 5, 6, 8, 9, 12, 13, 14})
        serdes_polarity_inverse_tx.append({1, 4, 7})

        # Slice 2
        ifg_swap_lists.append([0, 2, 3, 1, 6, 7, 4, 5, 10, 8, 11, 9, 12, 14, 13, 15, 16, 17])
        serdes_polarity_inverse_rx.append({0, 1, 2, 3, 4, 6, 7, 14})
        serdes_polarity_inverse_tx.append({0, 3, 4, 8, 10, 13, 14})
        ifg_swap_lists.append([0, 2, 1, 3, 4, 5, 6, 7, 8, 10, 9, 11, 15, 14, 12, 13, 16, 17])
        serdes_polarity_inverse_rx.append({3, 6, 7, 10, 11, 14, 15})
        serdes_polarity_inverse_tx.append({2, 4, 6, 7, 14})

        # Slice 3
        ifg_swap_lists.append([0, 3, 1, 2, 7, 6, 4, 5, 9, 11, 8, 10, 15, 13, 14, 12, 16, 17])
        serdes_polarity_inverse_rx.append({0, 1, 2, 5, 8, 12})
        serdes_polarity_inverse_tx.append({1, 3, 5, 9, 13, 15})
        ifg_swap_lists.append([3, 0, 2, 1, 6, 7, 4, 5, 11, 8, 10, 9, 15, 12, 14, 13, 17, 16])
        serdes_polarity_inverse_rx.append({2, 6, 7, 8, 9, 12, 13, 14})
        serdes_polarity_inverse_tx.append({6, 12, 15})

        # Slice 4
        ifg_swap_lists.append([0, 1, 3, 2, 4, 6, 5, 7, 8, 9, 10, 11, 13, 12, 14, 15, 16, 17])
        serdes_polarity_inverse_rx.append({6, 7, 10, 11, 12})
        serdes_polarity_inverse_tx.append({1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15})
        ifg_swap_lists.append([2, 0, 1, 3, 5, 7, 4, 6, 8, 10, 11, 9, 13, 15, 12, 14, 16, 17])
        serdes_polarity_inverse_rx.append({1, 2, 3, 6, 7, 9, 11, 13, 14, 15})
        serdes_polarity_inverse_tx.append({0, 1, 2, 3, 5, 6, 8, 9, 10, 11, 13, 14, 15})

        # Slice 5
        ifg_swap_lists.append([0, 1, 2, 3, 4, 5, 6, 7, 10, 9, 8, 11, 12, 13, 14, 15, 16, 17])
        serdes_polarity_inverse_rx.append({1, 2, 5, 12, 15})
        serdes_polarity_inverse_tx.append({0, 1, 10, 11, 12, 13, 14, 15})
        ifg_swap_lists.append([3, 2, 1, 0, 4, 5, 6, 7, 9, 11, 8, 10, 12, 13, 14, 15, 17, 16])
        serdes_polarity_inverse_rx.append({1, 3, 4, 6, 12, 13, 14, 15})
        serdes_polarity_inverse_tx.append({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
        return ifg_swap_lists, serdes_polarity_inverse_rx, serdes_polarity_inverse_tx

    def sherman_P4_setting(self):
        ifg_swap_lists = []

        serdes_polarity_inverse_rx = []
        serdes_polarity_inverse_tx = []

        # Slice 0
        ifg_swap_lists.append([2, 3, 0, 1, 6, 7, 4, 5, 9, 11, 8, 10, 15, 13, 12, 14, 16, 17])
        serdes_polarity_inverse_rx.append({4, 5, 6, 7, 8, 15})
        serdes_polarity_inverse_tx.append({})
        ifg_swap_lists.append([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 10, 12, 13, 14, 15, 17, 16])
        serdes_polarity_inverse_rx.append({})
        serdes_polarity_inverse_tx.append({})

        # Slice 1
        ifg_swap_lists.append([0, 1, 2, 3, 6, 7, 5, 4, 10, 9, 8, 11, 15, 13, 14, 12, 16, 17])
        serdes_polarity_inverse_rx.append({5, 6, 7, 8, 9, 11, 13, 14})
        serdes_polarity_inverse_tx.append({2, 5, 6, 10})
        ifg_swap_lists.append([3, 1, 2, 0, 7, 4, 5, 6, 10, 8, 11, 9, 12, 14, 15, 13, 16, 17])
        serdes_polarity_inverse_rx.append({0, 2, 3, 4, 7, 9, 10, 11, 12, 14, 15})
        serdes_polarity_inverse_tx.append({1, 4, 5, 8, 9, 11, 12, 15})

        # Slice 2
        ifg_swap_lists.append([2, 0, 3, 1, 7, 6, 4, 5, 8, 10, 11, 9, 13, 14, 15, 12, 16, 17])
        serdes_polarity_inverse_rx.append({4, 6, 7, 11, 13, 14})
        serdes_polarity_inverse_tx.append({3, 5, 8, 10, 11, 12, 13})
        ifg_swap_lists.append([0, 3, 1, 2, 4, 5, 6, 7, 9, 8, 11, 10, 15, 14, 12, 13, 16, 17])
        serdes_polarity_inverse_rx.append({0, 3, 5, 7, 10, 12, 14})
        serdes_polarity_inverse_tx.append({4, 7, 10, 14})

        # Slice 3
        ifg_swap_lists.append([2, 3, 0, 1, 7, 6, 4, 5, 11, 9, 8, 10, 15, 13, 14, 12, 16, 17])
        serdes_polarity_inverse_rx.append({7, 8, 10, 11, 12, 14})
        serdes_polarity_inverse_tx.append({9, 10, 12})
        ifg_swap_lists.append([3, 0, 2, 1, 6, 7, 4, 5, 10, 8, 9, 11, 15, 12, 14, 13, 17, 16])
        serdes_polarity_inverse_rx.append({1, 3, 7, 10, 11, 13, 14})
        serdes_polarity_inverse_tx.append({10, 11, 13, 14, 15})

        # Slice 4
        ifg_swap_lists.append([1, 0, 2, 3, 6, 4, 7, 5, 8, 9, 11, 10, 13, 12, 14, 15, 16, 17])
        serdes_polarity_inverse_rx.append({6, 10, 11, 12})
        serdes_polarity_inverse_tx.append({3, 9, 10, 11, 12, 14})
        ifg_swap_lists.append([0, 2, 1, 3, 5, 6, 7, 4, 8, 10, 9, 11, 13, 15, 12, 14, 16, 17])
        serdes_polarity_inverse_rx.append({1, 2, 3, 6, 7, 9, 11, 13, 14, 15})
        serdes_polarity_inverse_tx.append({5, 8, 13})

        # Slice 5
        ifg_swap_lists.append([0, 1, 3, 2, 4, 5, 6, 7, 10, 9, 11, 8, 12, 13, 14, 15, 16, 17])
        serdes_polarity_inverse_rx.append({1, 2, 4, 5, 7, 12, 15})
        serdes_polarity_inverse_tx.append({0, 1, 10, 11, 14, 15})
        ifg_swap_lists.append([0, 1, 2, 3, 4, 5, 6, 7, 9, 11, 8, 10, 12, 13, 14, 15, 17, 16])
        serdes_polarity_inverse_rx.append({1, 3, 4, 6, 12, 13, 14, 15})
        serdes_polarity_inverse_tx.append({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
        return ifg_swap_lists, serdes_polarity_inverse_rx, serdes_polarity_inverse_tx

    def sherman_P2_setting(self):
        ifg_swap_lists = []

        serdes_polarity_inverse_rx = []
        serdes_polarity_inverse_tx = []

        # Slice 0
        ifg_swap_lists.append([2, 3, 0, 1, 6, 7, 4, 5, 9, 11, 8, 10, 15, 13, 12, 14, 16, 17])
        serdes_polarity_inverse_rx.append({4, 5, 6, 7, 8, 15})
        serdes_polarity_inverse_tx.append({})
        ifg_swap_lists.append([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 10, 12, 13, 14, 15, 17, 16])
        serdes_polarity_inverse_rx.append({})
        serdes_polarity_inverse_tx.append({})

        # Slice 1
        ifg_swap_lists.append([0, 1, 2, 3, 6, 7, 5, 4, 10, 9, 8, 11, 15, 13, 14, 12, 16, 17])
        serdes_polarity_inverse_rx.append({5, 6, 7, 8, 9, 11, 13, 14})
        serdes_polarity_inverse_tx.append({2, 5, 6, 10})
        ifg_swap_lists.append([3, 1, 2, 0, 7, 4, 5, 6, 10, 8, 11, 9, 12, 14, 15, 13, 16, 17])
        serdes_polarity_inverse_rx.append({0, 2, 3, 4, 7, 9, 10, 11, 12, 14, 15})
        serdes_polarity_inverse_tx.append({1, 4, 5, 8, 9, 11, 12, 15})

        # Slice 2
        ifg_swap_lists.append([2, 0, 3, 1, 7, 6, 4, 5, 8, 10, 11, 9, 13, 14, 15, 12, 16, 17])
        serdes_polarity_inverse_rx.append({4, 6, 7, 11, 13, 14})
        serdes_polarity_inverse_tx.append({3, 5, 8, 10, 11, 12, 13})
        ifg_swap_lists.append([0, 3, 1, 2, 4, 5, 6, 7, 9, 8, 11, 10, 15, 14, 12, 13, 16, 17])
        serdes_polarity_inverse_rx.append({0, 3, 5, 7, 10, 12, 14})
        serdes_polarity_inverse_tx.append({4, 7, 10, 14})

        # Slice 3
        ifg_swap_lists.append([2, 3, 0, 1, 7, 6, 4, 5, 11, 9, 8, 10, 15, 13, 14, 12, 16, 17])
        serdes_polarity_inverse_rx.append({7, 8, 10, 11, 12, 14})
        serdes_polarity_inverse_tx.append({9, 10, 12})
        ifg_swap_lists.append([3, 0, 2, 1, 6, 7, 4, 5, 10, 8, 9, 11, 15, 12, 14, 13, 17, 16])
        serdes_polarity_inverse_rx.append({1, 3, 7, 10, 11, 13, 14})
        serdes_polarity_inverse_tx.append({10, 11, 13, 14, 15})

        # Slice 4
        ifg_swap_lists.append([1, 0, 2, 3, 6, 4, 7, 5, 8, 9, 11, 10, 13, 12, 14, 15, 16, 17])
        serdes_polarity_inverse_rx.append({6, 10, 11, 12})
        serdes_polarity_inverse_tx.append({3, 9, 10, 11, 12, 14})
        ifg_swap_lists.append([0, 2, 1, 3, 5, 6, 7, 4, 8, 10, 9, 11, 13, 15, 12, 14, 16, 17])
        serdes_polarity_inverse_rx.append({1, 2, 3, 6, 7, 9, 11, 13, 14, 15})
        serdes_polarity_inverse_tx.append({5, 8, 13})

        # Slice 5
        ifg_swap_lists.append([0, 1, 3, 2, 4, 7, 5, 6, 10, 9, 11, 8, 13, 15, 14, 12, 16, 17])
        serdes_polarity_inverse_rx.append({1, 2})
        serdes_polarity_inverse_rx.append({0, 1, 10, 11, 12, 13, 14, 15})
        ifg_swap_lists.append([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17])
        serdes_polarity_inverse_tx.append({0, 2, 5, 4, 7, 12, 13, 14, 15})
        serdes_polarity_inverse_tx.append({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
        return ifg_swap_lists, serdes_polarity_inverse_rx, serdes_polarity_inverse_tx

    def sherman_config(self, board):
        if board == 'shermanP2':
            ifg_swap_lists, serdes_polarity_inverse_rx, serdes_polarity_inverse_tx = self.sherman_P2_setting()
        if board == 'shermanP4':
            ifg_swap_lists, serdes_polarity_inverse_rx, serdes_polarity_inverse_tx = self.sherman_P4_setting()
        if board == 'shermanP5':
            ifg_swap_lists, serdes_polarity_inverse_rx, serdes_polarity_inverse_tx = self.sherman_P5_setting()

        for sid in range(6):
            for ifg_id in range(2):
                ifg_num = sid * 2 + ifg_id
                serdes_src = ifg_swap_lists[ifg_num]
                self.device.set_serdes_source(sid, ifg_id, serdes_src)

                for serdes in serdes_polarity_inverse_rx[ifg_num]:
                    self.device.set_serdes_polarity_inversion(sid, ifg_id, serdes, sdk.la_serdes_direction_e_RX, True)

                for serdes in serdes_polarity_inverse_tx[ifg_num]:
                    self.device.set_serdes_polarity_inversion(sid, ifg_id, serdes, sdk.la_serdes_direction_e_TX, True)

    def stingray_config(self):
        slice_id = 2
        ifg_id = 1
        swap_list = [0, 1, 2, 3, 4, 5, 6, 7, 11, 9, 10, 8, 12, 13, 14, 15, 16, 17]

        self.device.set_serdes_source(slice_id, ifg_id, swap_list)

    def print_mac_rs_fec(self):
        for index in range(len(self.common_mac_ports)):
            mac_info = self.get_mac_rs_fec(index)
            print(
                'Link [{index}] name {name}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), RS-FEC: Correctable {correctable}, Un-correctable {uncorrectable}'.format(
                    **mac_info))

    def print_mac_rs_fec_debug(self):
        for index in range(len(self.common_mac_ports)):
            mac_info = self.get_mac_rs_fec_debug(index)
            print(
                'Link [{index}] name {name}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), RS-FEC: CW {codeword}, CW_UNC {codeword_uncorrectable}, BURST {symbol_burst}, BER {ber:.05e}'.format(
                    **mac_info))

    def get_mac_rs_fec_lane_errors(self, mac_index):
        # This is temporary till we extend the API to export those values as well
        # Supports only 400G ports
        mac_port = self.common_mac_ports[mac_index]

        mac_info = self.get_mac_info_base(mac_port)
        mac_info['index'] = mac_index

        slice = mac_info['slice']
        ifg = mac_info['ifg']
        mac_pool_idx = int(mac_info['serdes'] / 8)

        values = []
        for i in range(8):
            values.append(
                tc.ll_device.read_register(
                    tc.pacific_tree.slice[slice].ifg[ifg].mac_pool8[mac_pool_idx].rx_symb_err_lane0_reg[i]))
            values.append(
                tc.ll_device.read_register(
                    tc.pacific_tree.slice[slice].ifg[ifg].mac_pool8[mac_pool_idx].rx_symb_err_lane1_reg[i]))
            values.append(
                tc.ll_device.read_register(
                    tc.pacific_tree.slice[slice].ifg[ifg].mac_pool8[mac_pool_idx].rx_symb_err_lane2_reg[i]))
            values.append(
                tc.ll_device.read_register(
                    tc.pacific_tree.slice[slice].ifg[ifg].mac_pool8[mac_pool_idx].rx_symb_err_lane3_reg[i]))

        mac_info['values'] = values

        return mac_info

    def print_mac_rs_fec_lane_errors(self):
        for index in range(len(self.common_mac_ports)):
            mac_info = self.get_mac_rs_fec_lane_errors(index)
            print('Link [{index}] name {name}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}): '.format(**mac_info))

            values = mac_info['values']
            for i in range(8):
                print('({:5}, {:5}),'.format(values[2 * i], values[2 * i + 1]))

            print()


def create_port_mix_from_json_file(filename):
    with open(filename, 'r') as fh:
        json_db = json.load(fh)

    mac_port_mix = []
    for port_ent in json_db:
        mac_port_val = port_ent
        for field in ['speed', 'fc', 'fec']:
            mac_port_val[field] = eval(port_ent[field])

        if 'serdes_list' in mac_port_val:
            for serdes in mac_port_val['serdes_list']:
                temp_val = mac_port_val.copy()
                temp_val['serdes'] = serdes
                mac_port_mix.append(temp_val)
        else:
            mac_port_mix.append(mac_port_val)

    return mac_port_mix


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MAC port stress testing.')

    parser.add_argument('--path', default='/dev/uio0',
                        help='Device path, default %(default)s')
    parser.add_argument('--id', type=int, default=0,
                        help='Device ID, default %(default)i')
    parser.add_argument('--board', choices=['none', 'shermanP2', 'shermanP4', 'shermanP5', 'stingray'],
                        help='Add board specific configurations, default %(default)s', default='none')
    parser.add_argument('--port_json', default=None,
                        help='Port definition JSON file, default %(default)s')
    parser.add_argument('--iter', type=int, default=1,
                        help='Number of iterations, default %(default)i')
    parser.add_argument('--shut', type=int, default=1,
                        help='Number of port shutdown and no-shutdown iterations, default %(default)i')
    parser.add_argument('--ber', default=False, action='store_true', help='Measure port PMA BER')
    parser.add_argument('--rsfec', default=False, action='store_true', help='Measure port RS-FEC debug counters')
    parser.add_argument('--loopback', default=False, action='store_true', help='Create port in SerDes loopback mode')

    args = parser.parse_args()

    mac_port_mix = create_port_mix_from_json_file(args.port_json)

    loopback_mode = sdk.la_mac_port.loopback_mode_e_NONE if not args.loopback else sdk.la_mac_port.loopback_mode_e_SERDES
    for iter in range(args.iter):
        if iter > 0:
            tc.teardown_iteration()

        print('Iteration {}'.format(iter))
        tc = test_sherman_mac_port(args.path, args.id, args.board)

        tc.avago_loopback_create(mac_port_mix, loopback_mode)

        for shut_iter in range(args.shut):
            if shut_iter > 0:
                print('Iteration {}, shutdown iteration {}'.format(iter, shut_iter))
                # Shutdown all ports
                for mac_port in tc.common_mac_ports:
                    mac_port.stop()

                time.sleep(10)

            all_up = tc.avago_loopback_start(False)

            for retry in range(20):
                if all_up:
                    break

                print("Retry {}".format(retry))
                time.sleep(1)
                all_up = tc.print_mac_up()

            if not all_up:
                print('FAILED')
                exit(-1)

            if args.ber:
                max_ber = tc.print_mac_pma_ber()
                print("MAX BER {}".format(max_ber))

            if args.rsfec:
                tc.print_mac_rs_fec()
