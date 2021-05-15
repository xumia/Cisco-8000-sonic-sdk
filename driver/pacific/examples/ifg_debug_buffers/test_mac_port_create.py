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

# This is test is meant to run on emualtor for testing the creation of mac
# ports with different configuration, and sending pkts using ifgb debug
# buffers

import decor
import unittest
from leaba import sdk
import pdb
from ifg_dbg_bufs_util import *
from leaba import debug
import sim_utils
import os.path
import argparse


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_mac_port_create_helper():

    pacific_ports = {
        10: {1: ['NONE', 'KR']},
        25: {1: ['NONE', 'KR', 'RS_KP4', 'RS_KR4']},
        40: {
            2: ['NONE'],
            4: ['NONE', 'KR']
        },
        50: {
            1: ['RS_KP4', 'RS_KR4'],
            2: ['NONE', 'RS_KP4', 'RS_KR4']
        },
        100: {
            2: ['RS_KP4', 'RS_KR4', 'RS_KP4_FI'],
            4: ['NONE', 'RS_KP4', 'RS_KR4']
        },
        200: {8: ['RS_KP4']},
        400: {8: ['RS_KP4']},
        800: {16: ['RS_KP4']}
    }

    gibraltar_ports = {
        10: {1: ['NONE', 'KR']},
        25: {1: ['NONE', 'KR', 'RS_KP4', 'RS_KR4']},
        40: {
            2: ['NONE'],
            4: ['NONE', 'KR']
        },
        50: {
            1: ['RS_KP4', 'RS_KR4'],
            2: ['NONE', 'RS_KP4', 'RS_KR4']
        },
        100: {
            2: ['RS_KP4', 'RS_KR4', 'RS_KP4_FI'],
            4: ['NONE', 'RS_KP4', 'RS_KR4']
        },
        200: {
            4: ['RS_KP4'],
            8: ['RS_KP4']
        },
        400: {8: ['RS_KP4']},
        800: {16: ['RS_KP4']}
    }

    asic4_asic3_ports = {
        10: {1: ['NONE', 'KR']},
        25: {1: ['NONE', 'KR', 'RS_KP4', 'RS_KR4']},
        40: {
            2: ['NONE'],
            4: ['NONE', 'KR']
        },
        50: {
            1: ['RS_KP4', 'RS_KR4'],
            2: ['NONE', 'RS_KP4', 'RS_KR4']
        },
        100: {
            1: ['RS_KP4'],
            2: ['RS_KP4', 'RS_KR4', 'RS_KP4_FI'],
            4: ['NONE', 'RS_KP4', 'RS_KR4']
        },
        200: {
            2: ['RS_KP4'],
            4: ['RS_KP4'],
            8: ['RS_KP4']
        },
        400: {
            4: ['RS_KP4'],
            8: ['RS_KP4']
        },
        800: {16: ['RS_KP4']}
    }

    asic5_ports = {
        10: {1: ['NONE', 'KR']},
        25: {1: ['RS_KR4']},
        40: {
            2: ['RS_KR4'],
            4: ['NONE']
        },
        50: {
            1: ['RS_KP4'],
            2: ['RS_KR4']
        },
        100: {
            2: ['RS_KP4'],
            4: ['RS_KR4']
        }
    }

    speed_string = {
        10: sdk.la_mac_port.port_speed_e_E_10G,
        25: sdk.la_mac_port.port_speed_e_E_25G,
        40: sdk.la_mac_port.port_speed_e_E_40G,
        50: sdk.la_mac_port.port_speed_e_E_50G,
        100: sdk.la_mac_port.port_speed_e_E_100G,
        200: sdk.la_mac_port.port_speed_e_E_200G,
        400: sdk.la_mac_port.port_speed_e_E_400G,
        800: sdk.la_mac_port.port_speed_e_E_800G
    }

    fec_mode_string = {
        "NONE": sdk.la_mac_port.fec_mode_e_NONE,
        "KR": sdk.la_mac_port.fec_mode_e_KR,
        "RS_KR4": sdk.la_mac_port.fec_mode_e_RS_KR4,
        "RS_KP4": sdk.la_mac_port.fec_mode_e_RS_KP4,
        "RS_KP4_FI": sdk.la_mac_port.fec_mode_e_RS_KP4_FI
    }

    loopback_mode_string = {
        "INFO_MAC": sdk.la_mac_port.loopback_mode_e_INFO_MAC_CLK,
        "INFO_SRDS": sdk.la_mac_port.loopback_mode_e_INFO_SRDS_CLK,
        "MII_CORE": sdk.la_mac_port.loopback_mode_e_MII_CORE_CLK,
        "MII_SRDS": sdk.la_mac_port.loopback_mode_e_MII_SRDS_CLK,
        "NONE": sdk.la_mac_port.loopback_mode_e_NONE,
        "PMA_CORE": sdk.la_mac_port.loopback_mode_e_PMA_CORE_CLK,
        "PMA_SRDS": sdk.la_mac_port.loopback_mode_e_PMA_SRDS_CLK,
        "REMOTE_PMA": sdk.la_mac_port.loopback_mode_e_REMOTE_PMA,
        "REMOTE_SERDES": sdk.la_mac_port.loopback_mode_e_REMOTE_SERDES,
        "SERDES": sdk.la_mac_port.loopback_mode_e_SERDES,
    }

    def __init__(self, args):
        self.args = args
        if len(self.args.speed) > 1 and not self.args.destroy_ports:
            raise RuntimeError('When using more than one speed please enable destroy ports')

        if len(self.args.speed) == 0:
            self.args.destroy_ports = True

    def mac_port_create(self, device, ll_device, d_device, speed, serdes_count, fec_modes, tree):
        rc = 0
        mps = []
        num_slices_emulator = 1

        speed_s = speed
        speed = self.speed_string[speed]
        loopback_mode = self.loopback_mode_string[self.args.loopback_mode]

        for slice_id in range(num_slices_emulator):
            for ifg_id in range(self.args.num_ifgs):
                ports_per_ifg = self.args.num_ports_per_ifg if self.args.num_ports_per_ifg else int(
                    self.num_of_serdes_per_ifg / serdes_count)
                for port_id in range(ports_per_ifg):
                    fec_mode = fec_modes[(port_id + ifg_id) % len(fec_modes)]
                    print("creating port: slice {} ifg {} port {} speed {} serdes_count {} fec {}".format(
                        slice_id, ifg_id, port_id, speed_s, serdes_count, fec_mode))

                    mac_port = device.create_mac_port(
                        slice_id,
                        ifg_id,
                        serdes_count *
                        port_id,
                        serdes_count *
                        port_id +
                        serdes_count -
                        1,
                        speed,
                        sdk.la_mac_port.fc_mode_e_NONE,
                        self.fec_mode_string[fec_mode])

                    mac_port.set_loopback_mode(loopback_mode)
                    mac_port.activate()
                    mps.append(mac_port)

        if (os.getenv('LEABA_EMULATED_DEVICE')):
            time.sleep(20)

        for mac_port in mps:
            mac_port_s = mac_port.read_mac_status()
            speed = list(self.speed_string.keys())[list(self.speed_string.values()).index(mac_port.get_speed())]
            fec_mode = list(self.fec_mode_string.keys())[list(self.fec_mode_string.values()).index(mac_port.get_fec_mode())]

            if mac_port_s.link_state:
                print(
                    'Port={} slice {} ifg {} speed {} serdes_count {} fec {} Link is UP'.format(
                        mac_port.to_string(),
                        mac_port.get_slice(),
                        mac_port.get_ifg(),
                        speed,
                        mac_port.get_num_of_serdes(),
                        fec_mode))

            else:
                print(
                    'Port={} slice {} ifg {} speed {} serdes_count {} fec {} Link is DOWN\nlink_state={} \nhigh_ber={} \npcs_status={} \nblock_lock={} \nam_lock={}'.format(
                        mac_port.to_string(),
                        mac_port.get_slice(),
                        mac_port.get_ifg(),
                        speed,
                        mac_port.get_num_of_serdes(),
                        fec_mode,
                        mac_port_s.link_state,
                        mac_port_s.high_ber,
                        mac_port_s.pcs_status,
                        mac_port_s.block_lock,
                        mac_port_s.am_lock))
                rc = rc or 1

        return mps

    def test_packet_send_receive(self, device, ll_device, d_device, tree):
        rc = 0
        self.mps = []
        self.tree = tree
        self.ll_device = ll_device
        ifgb = ifg_dbg_bufs_util()

        num_of_slices = 1
        num_of_ifg_per_slice = 2

        if self.ll_device.is_pacific():
            self.num_of_serdes_per_ifg = 18
            ports_config_dict = self.pacific_ports
        elif self.ll_device.is_gibraltar():
            self.num_of_serdes_per_ifg = 24
            ports_config_dict = self.gibraltar_ports
        elif self.ll_device.is_asic5():
            self.num_of_serdes_per_ifg = 24
            ports_config_dict = self.asic5_ports
            num_of_ifg_per_slice = 1
        elif self.ll_device.is_asic4() or self.ll_device.is_asic3():
            self.num_of_serdes_per_ifg = 16
            ports_config_dict = self.asic4_asic3_ports

        speeds = self.args.speed if self.args.speed else ports_config_dict.keys()

        for speed in speeds:
            # if someone wants to trace in pdb, uncomment below
            # pdb.set_trace()

            num_of_serdes = [self.args.num_of_serdes] if self.args.num_of_serdes else ports_config_dict[speed].keys()
            if not set(num_of_serdes).issubset(set(ports_config_dict[speed].keys())):
                raise RuntimeError('Speed {} doest support serdes count {}'.format(speed, num_of_serdes))

            for serdes_count in num_of_serdes:
                fec_modes = self.args.fec_modes if self.args.fec_modes else ports_config_dict[speed][serdes_count]
                if not set(fec_modes).issubset(set(ports_config_dict[speed][serdes_count])):
                    raise RuntimeError(
                        'Speed {} with serdes count {} doest support all fec modes {}'.format(
                            speed, serdes_count, fec_modes))

                num_of_ports_needes = self.num_of_serdes_per_ifg / \
                    (serdes_count * len(fec_modes))
                if int(num_of_ports_needes):
                    self.mps = self.mac_port_create(device, ll_device, d_device, speed, serdes_count,
                                                    fec_modes, self.tree)

                else:
                    for fec_mode in fec_modes:
                        self.mps = self.mac_port_create(device, ll_device, d_device, speed, serdes_count, [fec_mode], self.tree)

                mac_ports_up = list(filter(lambda mac_port: mac_port.read_mac_status().link_state, self.mps))
                rc = rc or (len(mac_ports_up) != len(self.mps))

                for mp in mac_ports_up:
                    speed = list(self.speed_string.keys())[list(self.speed_string.values()).index(mp.get_speed())]
                    fec_mode = list(self.fec_mode_string.keys())[list(self.fec_mode_string.values()).index(mp.get_fec_mode())]
                    print("#" * 100)
                    print("creating port: slice {} ifg {} speed {} serdes_count {} fec {}".format(
                        mp.get_slice(), mp.get_ifg(), speed, mp.get_num_of_serdes(), fec_mode))

                    ifgb.init(device, mp, d_device)

                    if ifgb.start(pkt_size=64, nof_pkts=1, time_ms=1000):
                        rc = 1
                        print(
                            "Sending packet over Slice {} ifg {} port {} FAILED".format(
                                mp.get_slice(), mp.get_ifg(), mp.to_string()))

                    else:
                        print(
                            "Sending packet over Slice {} ifg {} port {} SUCCEEDED".format(
                                mp.get_slice(), mp.get_ifg(), mp.to_string()))

                if self.args.destroy_ports:
                    for mp in self.mps:
                        mp.stop()
                        device.destroy(mp)

        return rc


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
@unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
class test_mac_port_create():
    def test_mac_port_create(self, args):

        if (os.getenv('LEABA_EMULATED_DEVICE')):
            self.device = sdk.la_create_device('/dev/uio0', 0)
        else:
            # to run in nsim
            self.dev_id = 1
            self.device = sim_utils.create_device(self.dev_id)

        self.debug_device = debug.debug_device(self.device)

        self.ll_device = self.device.get_ll_device()

        if self.ll_device.is_pacific():
            self.tree = self.ll_device.get_pacific_tree()
        elif self.ll_device.is_gibraltar():
            self.tree = self.ll_device.get_gibraltar_tree()
        elif self.ll_device.is_asic4():
            self.tree = self.ll_device.get_asic4_tree()
        elif self.ll_device.is_asic3():
            self.tree = self.ll_device.get_asic3_tree()
        elif self.ll_device.is_asic5():
            self.tree = self.ll_device.get_asic5_tree()

        self.ll_device.write_register(self.tree.sbif.reset_reg, 0x0)
        self.ll_device.set_shadow_read_enabled(False)

        if (os.getenv('LEABA_EMULATED_DEVICE')):
            # below does not work on nsim
            self.device.set_bool_property(sdk.la_device_property_e_IGNORE_MBIST_ERRORS, True)
            self.device.set_bool_property(sdk.la_device_property_e_EMULATED_DEVICE, True)
            if (not self.ll_device.is_asic5()):
                self.device.set_bool_property(sdk.la_device_property_e_INIT_PORTS_ONLY, True)

            self.device.initialize(self.device.init_phase_e_DEVICE)

            if self.ll_device.is_asic5():
                self.device.set_slice_mode(0, sdk.la_slice_mode_e_NETWORK)
            else:
                for i in range(6):
                    self.device.set_slice_mode(i, sdk.la_slice_mode_e_NETWORK)

            self.device.initialize(self.device.init_phase_e_TOPOLOGY)

        if self.ll_device.is_asic5():
            # for Asic5 need to also init the counters
            for i in range(18):
                self.ll_device.write_register(
                    self.tree.slice[0].ifg[0].mac_pool2[i].cip_cntr_mem_init, 1)

        self.mac_port_create_helper = test_mac_port_create_helper(args)

        if self.mac_port_create_helper.test_packet_send_receive(self.device, self.ll_device, self.debug_device, self.tree):
            print("Test_mac_create FAILED")
            return 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--loopback_mode',
        help='loopback mode',
        default='PMA_CORE',
        choices=[
            'INFO_MAC',
            'INFO_SRDS',
            'MII_CORE',
            'MII_SRDS',
            'NONE',
            'PMA_CORE',
            'PMA_SRDS',
            'REMOTE_PMA',
            'REMOTE_SERDES',
            'SERDES'])
    parser.add_argument('--num_ports_per_ifg', help='number of ports per ifg', type=int, default=0)
    parser.add_argument('--num_ifgs', help='number of ifgs', type=int, default=1, choices=[1, 2])
    parser.add_argument('--num_of_serdes', help='number of serdes per port', type=int, default=0)
    parser.add_argument(
        '--speed',
        help='port speed',
        type=int,
        default=[],
        nargs='+',
        choices=[
            10,
            25,
            40,
            50,
            100,
            200,
            400,
            800])
    parser.add_argument(
        '--fec_modes',
        help='fec modes to run with',
        default=[],
        nargs='+',
        choices=[
            'NONE',
            'KR',
            'RS_KP4',
            'RS_KR4',
            'RS_KP4_FI'])
    parser.add_argument('--destroy_ports', help='destroy ports at the end of the test', default=False, action='store_true')

    args = parser.parse_args()

    test_mac_port = test_mac_port_create()
    test_mac_port.test_mac_port_create(args)

    debug_device = test_mac_port.debug_device
    tree = test_mac_port.mac_port_create_helper.tree
    mps = test_mac_port.mac_port_create_helper.mps
    device = test_mac_port.device
