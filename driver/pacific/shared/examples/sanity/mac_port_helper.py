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
import select
import os
import json
from leaba import sdk
from leaba import debug
import lldcli
from pma_tx_err_helper import *

SYSTEM_PORT_SPEEDUP = 1.2
KILO = 1000
MEGA = 1000 * KILO
GIGA = 1000 * MEGA
REAL_PORT_SPEED = {
    sdk.la_mac_port.port_speed_e_E_MGIG: 1 * GIGA,
    sdk.la_mac_port.port_speed_e_E_10G: 10 * GIGA,
    sdk.la_mac_port.port_speed_e_E_20G: 20 * GIGA,
    sdk.la_mac_port.port_speed_e_E_25G: 25 * GIGA,
    sdk.la_mac_port.port_speed_e_E_40G: 40 * GIGA,
    sdk.la_mac_port.port_speed_e_E_50G: 50 * GIGA,
    sdk.la_mac_port.port_speed_e_E_100G: 100 * GIGA,
    sdk.la_mac_port.port_speed_e_E_200G: 200 * GIGA,
    sdk.la_mac_port.port_speed_e_E_400G: 400 * GIGA,
    sdk.la_mac_port.port_speed_e_E_800G: 800 * GIGA
}

PORT_SPEED = {
    sdk.la_mac_port.port_speed_e_E_MGIG: 1,
    sdk.la_mac_port.port_speed_e_E_10G: 10,
    sdk.la_mac_port.port_speed_e_E_20G: 20,
    sdk.la_mac_port.port_speed_e_E_25G: 25,
    sdk.la_mac_port.port_speed_e_E_40G: 40,
    sdk.la_mac_port.port_speed_e_E_50G: 50,
    sdk.la_mac_port.port_speed_e_E_100G: 100,
    sdk.la_mac_port.port_speed_e_E_200G: 200,
    sdk.la_mac_port.port_speed_e_E_400G: 400,
    sdk.la_mac_port.port_speed_e_E_800G: 800
}

# Timeout in seconds for ports to become UP
TIMEOUT_PORT_UP = 60


class mac_port_helper:
    def __init__(self, verbose=False):
        self.mac_ports = []
        self.network_mac_ports = []
        self.fabric_mac_ports = []
        self.verbose = verbose
        self.trap_counters = []

        self.serdes_param_map = {}

    def init_interrupts(self):
        self.critical_fd, self.normal_fd = self.device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)

    def init(self, device):
        self.device = device
        self.init_interrupts()

        self.debug_device = debug.debug_device(self.device)
        self.ll_device = self.device.get_ll_device()
        self.pma_tx_err_helper = pma_tx_err_helper(self.device)

        self.used_slices = self.device.get_used_slices()
        self.used_ifgs = (0, 1)

    def connect(self, device, init_interrupts=False):
        self.device = device

        if init_interrupts:
            self.init_interrupts()

        self.debug_device = debug.debug_device(self.device)
        self.ll_device = self.device.get_ll_device()

        # empty all mac_ports
        self.mac_ports = []
        self.network_mac_ports = []
        self.fabric_mac_ports = []

        for la_obj in self.device.get_objects():
            # TODO: may be we should handle trap_counters objects as well.
            if (la_obj.type() == sdk.la_object.object_type_e_MAC_PORT):
                slice = la_obj.get_slice()
                ifg = la_obj.get_ifg()
                serdes = la_obj.get_first_serdes_id()
                print("Adding port {}/{}/{} - num serdes={}".format(slice, ifg, serdes, la_obj.get_num_of_serdes()))
                self.mac_ports.append(la_obj)

    def teardown(self):
        self.device.close_notification_fds()

        for mac_port in self.mac_ports:
            mac_port.stop()
            self.device.destroy(mac_port)

        self.mac_ports = []
        self.network_mac_ports = []
        self.fabric_mac_ports = []

    def create_mac_port(
            self,
            slice_id,
            ifg,
            first_pif,
            serdes_per_port,
            speed,
            fec_mode,
            fc_mode,
            loopback_mode,
            is_an_enabled=False):
        last_pif = first_pif + serdes_per_port - 1
        try:
            mac_port = self.device.create_mac_port(slice_id, ifg, first_pif, last_pif, speed,
                                                   fc_mode, fec_mode)
        except BaseException:
            raise Exception('Error: create_mac_port failed. slice=%d ifg=%d first_pif=%d last_pif=%d speed=%d fec_mode=%d' %
                            (slice_id, ifg, first_pif, last_pif, speed, fec_mode))

        self.mac_ports.append(mac_port)
        self.network_mac_ports.append(mac_port)

        if loopback_mode != sdk.la_mac_port.loopback_mode_e_NONE:
            mac_port.set_loopback_mode(loopback_mode)

        if is_an_enabled and loopback_mode == sdk.la_mac_port.loopback_mode_e_NONE:
            mac_port.set_an_enabled(is_an_enabled)

        # Init TM
        self.init_port_default_tm(mac_port, int(REAL_PORT_SPEED[speed] * SYSTEM_PORT_SPEEDUP))

        return mac_port

    def create_fabric_mac_port(self, slice_id, ifg, first_pif, serdes_per_port, speed, fc_mode, loopback_mode):
        last_pif = first_pif + serdes_per_port - 1
        try:
            mac_port = self.device.create_fabric_mac_port(slice_id, ifg, first_pif, last_pif, speed,
                                                          fc_mode)
        except BaseException:
            raise Exception('Error: create_mac_port failed. slice=%d ifg=%d first_pif=%d last_pif=%d speed=%d fc_mode=%d' %
                            (slice_id, ifg, first_pif, last_pif, speed, fc_mode))

        self.mac_ports.append(mac_port)
        self.fabric_mac_ports.append(mac_port)

        if loopback_mode != sdk.la_mac_port.loopback_mode_e_NONE:
            mac_port.set_loopback_mode(loopback_mode)

        return mac_port

    def destroy_mac_port(self, index):
        self.device.destroy(self.mac_ports[index])
        del self.mac_ports[index]
        del self.network_mac_ports[index]

    def pacific_mac_ports_apply_params(self, mac_port, module_type, params):
        mac_info = {
            'slice': mac_port.get_slice(),
            'ifg': mac_port.get_ifg(),
            'serdes': mac_port.get_first_serdes_id()}
        serdes_count = mac_port.get_num_of_serdes()

        ACTIVATE = sdk.la_mac_port.serdes_param_stage_e_ACTIVATE
        PRE_ICAL = sdk.la_mac_port.serdes_param_stage_e_PRE_ICAL
        PRE_PCAL = sdk.la_mac_port.serdes_param_stage_e_PRE_PCAL
        FIXED = sdk.la_mac_port.serdes_param_mode_e_FIXED
        ADAPTIVE = sdk.la_mac_port.serdes_param_mode_e_ADAPTIVE
        STATIC = sdk.la_mac_port.serdes_param_mode_e_STATIC
        props = [
            [ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_PLL_BB, FIXED, 1],
            [ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_PLL_IFLT, FIXED, 6],
            [ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_PLL_INT, FIXED, 8],
            [ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_PLL_BB, FIXED, 25],
            [ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_PLL_IFLT, FIXED, 1],
            [ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_PLL_INT, FIXED, 7],

            [PRE_PCAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFHF, ADAPTIVE, 0],
            [PRE_PCAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFLF, ADAPTIVE, 0],
        ]

        # Set low EID threshold
        props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_ELECTRICAL_IDLE_THRESHOLD, FIXED, 2])

        params_values = None
        if params is not None:
            # lookup for the port in the params DB
            # Key is: Slice,IFG,SerDes,speed,module_type
            # Module type is: optics=0; Loopback=1; copper=2 (10G only), C2C=3'

            serdes_speed = int(REAL_PORT_SPEED[mac_port.get_serdes_speed()] / GIGA)

            # Check if this is Chip2Chip if not use parameter
            entry_key_c2c = '{},{},{},{},{}'.format(
                mac_info['slice'],
                mac_info['ifg'],
                mac_info['serdes'],
                serdes_speed,
                'CHIP2CHIP')
            entry_key_optic = '{},{},{},{},{}'.format(
                mac_info['slice'],
                mac_info['ifg'],
                mac_info['serdes'],
                serdes_speed,
                module_type)

            if entry_key_c2c in self.params_map:
                params_values = self.params_map[entry_key_c2c]
            elif entry_key_optic in self.params_map:
                params_values = self.params_map[entry_key_optic]
            else:
                print('Failed to find parameters for SerDes with key {}'.format(entry_key_optic))

        if params_values is not None:
            props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_PRE1, FIXED, params_values['TX_PRE1']])
            props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_ATTN, FIXED, params_values['TX_ATTN']])
            props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_POST, FIXED, params_values['TX_POST']])
            props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_ELECTRICAL_IDLE_THRESHOLD, FIXED, params_values['EID_THRESHOLD']])

            props.append([PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_CTLE_GAINSHAPE1, FIXED, params_values['RX_GS1']])
            props.append([PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_CTLE_GAINSHAPE2, FIXED, params_values['RX_GS2']])
            props.append([PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_CTLE_LF_MIN, FIXED, params_values['RX_GAIN_LF_MIN']])
            props.append([PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_CTLE_LF_MAX, FIXED, params_values['RX_GAIN_LF_MAX']])
            props.append([PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_CTLE_HF_MIN, FIXED, params_values['RX_GAIN_HF_MIN']])
            props.append([PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_CTLE_HF_MAX, FIXED, params_values['RX_GAIN_HF_MAX']])
            props.append([PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_TERM, FIXED, params_values['RX_TERM']])
            props.append([PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFLF, FIXED, params_values['RX_FFE_BFGLF']])
            props.append([PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFHF, FIXED, params_values['RX_FFE_BFGHF']])

            props.append([PRE_PCAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFLF, ADAPTIVE, params_values['RX_FFE_BFGLF']])
            props.append([PRE_PCAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFHF, ADAPTIVE, params_values['RX_FFE_BFGHF']])
            props.append([PRE_PCAL, sdk.la_mac_port.serdes_param_e_HYSTERESIS_POST1_NEGATIVE,
                          FIXED, params_values['HYSTERESIS_POST1_NEGATIVE']])
            props.append([PRE_PCAL, sdk.la_mac_port.serdes_param_e_HYSTERESIS_POST1_POSETIVE,
                          FIXED, params_values['HYSTERESIS_POST1_POSITIVE']])

        else:
            props.append([PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFLF, FIXED, 1])
            props.append([PRE_ICAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFHF, FIXED, 4])

            props.append([PRE_PCAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFLF, ADAPTIVE, 1])
            props.append([PRE_PCAL, sdk.la_mac_port.serdes_param_e_RX_FFE_BFHF, ADAPTIVE, 4])
            props.append([PRE_PCAL, sdk.la_mac_port.serdes_param_e_RX_CTLE_LF, STATIC, 0])

        for serdes in range(serdes_count):
            for prop in props:
                (stage, param, mode, val) = prop
                mac_port.set_serdes_parameter(serdes, stage, param, mode, val)

    def gibraltar_mac_ports_apply_params(self, mac_port, module_type, params):
        mac_info = {
            'slice': mac_port.get_slice(),
            'ifg': mac_port.get_ifg(),
            'serdes': mac_port.get_first_serdes_id()}
        serdes_count = mac_port.get_num_of_serdes()

        ACTIVATE = sdk.la_mac_port.serdes_param_stage_e_ACTIVATE
        PRE_ICAL = sdk.la_mac_port.serdes_param_stage_e_PRE_ICAL
        PRE_PCAL = sdk.la_mac_port.serdes_param_stage_e_PRE_PCAL
        FIXED = sdk.la_mac_port.serdes_param_mode_e_FIXED
        ADAPTIVE = sdk.la_mac_port.serdes_param_mode_e_ADAPTIVE
        STATIC = sdk.la_mac_port.serdes_param_mode_e_STATIC
        props = []

        params_values_list = None
        if params is not None:
            # lookup for the port in the params DB
            # Key is: Slice,IFG,SerDes,speed,module_type
            # Module type is: optics=0; Loopback=1; copper=2 (10G only), C2C=3'

            serdes_speed = int(REAL_PORT_SPEED[mac_port.get_serdes_speed()] / GIGA)

            entry_key_c2c = '{},{},{},{}'.format(
                mac_info['slice'],
                mac_info['ifg'],
                serdes_speed,
                'CHIP2CHIP')
            entry_key_optic = '{},{},{},{}'.format(
                mac_info['slice'],
                mac_info['ifg'],
                serdes_speed,
                module_type)

            # Default module_type is COPPER. Get copper param map when AN is enabled.
            if mac_port.get_an_enabled():
                params_values_list = self.params_map[entry_key_optic]
            elif entry_key_c2c in self.params_map:
                params_values_list = self.params_map[entry_key_c2c]
            elif entry_key_optic in self.params_map:
                params_values_list = self.params_map[entry_key_optic]
            else:
                print('Failed to find parameters for SerDes with key {}'.format(entry_key_optic))

        if params_values_list is not None:
            for ser in range(serdes_count):
                done_with_lane = False
                cur_ser = ser + mac_info['serdes']
                if not isinstance(params_values_list, list):
                    params_values_list = [params_values_list]

                for params_values in params_values_list:
                    if 'serdes' in params_values:
                        serdes_list = params_values['serdes']
                    else:
                        serdes_list = range(24)
                    for ii in serdes_list:
                        if ii != cur_ser:
                            continue
                        done_with_lane = True
                        props = []
                        props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_PRE1, FIXED, params_values['TX_PRE1']])
                        props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_MAIN, FIXED, params_values['TX_MAIN']])
                        props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_POST, FIXED, params_values['TX_POST']])
                        props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_CTLE_CODE,
                                      FIXED, params_values['RX_CTLE_CODE']])
                        props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_DSP_MODE,
                                      FIXED, params_values['RX_DSP_MODE']])
                        props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_AFE_TRIM,
                                      FIXED, params_values['RX_AFE_TRIM']])
                        props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_AC_COUPLING_BYPASS,
                                      FIXED, params_values['RX_AC_COUPLING_BYPASS']])
                        if 'TX_INNER_EYE1' in params_values:
                            props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_INNER_EYE1,
                                          FIXED, params_values['TX_INNER_EYE1']])
                        if 'TX_INNER_EYE2' in params_values:
                            props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_INNER_EYE2,
                                          FIXED, params_values['TX_INNER_EYE2']])
                        if 'RX_VGA_TRACKING' in params_values:
                            props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_RX_VGA_TRACKING,
                                          FIXED, params_values['RX_VGA_TRACKING']])
                        if 'TX_LUT_MODE' in params_values:
                            props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_LUT_MODE,
                                          FIXED, params_values['TX_LUT_MODE']])
                        if 'DATAPATH_TX_PRECODE' in params_values:
                            props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_DATAPATH_TX_PRECODE,
                                          FIXED, params_values['DATAPATH_TX_PRECODE']])
                        if 'DATAPATH_RX_PRECODE' in params_values:
                            props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_DATAPATH_RX_PRECODE,
                                          FIXED, params_values['DATAPATH_RX_PRECODE']])
                        if 'AUTO_RX_PRECODE_THRESHOLD' in params_values:
                            props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_AUTO_RX_PRECODE_THRESHOLD,
                                          FIXED, params_values['AUTO_RX_PRECODE_THRESHOLD']])
                        if mac_port.get_an_enabled():
                            if 'TX_PRE2' in params_values:
                                props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_PRE2, FIXED, params_values['TX_PRE2']])
                            if 'TX_PRE3' in params_values:
                                props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_PRE3, FIXED, params_values['TX_PRE3']])
                            if 'TX_POST2' in params_values:
                                props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_POST2, FIXED, params_values['TX_POST2']])
                            if 'TX_POST3' in params_values:
                                props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_TX_POST3, FIXED, params_values['TX_POST3']])
                            if 'CTLE_TUNE' in params_values:
                                props.append([ACTIVATE, sdk.la_mac_port.serdes_param_e_CTLE_TUNE,
                                              FIXED, params_values['CTLE_TUNE']])
                        for prop in props:
                            (stage, param, mode, val) = prop
                            mac_port.set_serdes_parameter(ser, stage, param, mode, val)
                        break
                    if done_with_lane:
                        break
                if not done_with_lane:
                    print(
                        'Failed to find parameters for per serdes lanes! slice %d ifg %d serdes %d ' %
                        (mac_info['slice'], mac_info['ifg'], cur_ser))

    def asic3_mac_ports_apply_params(self, mac_port, module_type, params):
        mac_info = {
            'slice': mac_port.get_slice(),
            'ifg': mac_port.get_ifg(),
            'serdes': mac_port.get_first_serdes_id()}
        serdes_count = mac_port.get_num_of_serdes()

        ACTIVATE = sdk.la_mac_port.serdes_param_stage_e_ACTIVATE
        PRE_ICAL = sdk.la_mac_port.serdes_param_stage_e_PRE_ICAL
        PRE_PCAL = sdk.la_mac_port.serdes_param_stage_e_PRE_PCAL
        FIXED = sdk.la_mac_port.serdes_param_mode_e_FIXED
        ADAPTIVE = sdk.la_mac_port.serdes_param_mode_e_ADAPTIVE
        STATIC = sdk.la_mac_port.serdes_param_mode_e_STATIC
        props = []

        params_values_list = None
        if params is not None:
            # lookup for the port in the params DB
            # Key is: Slice,IFG,SerDes,speed,module_type
            # Module type is: optics=0; Loopback=1; copper=2 (10G only), C2C=3'

            serdes_speed = int(REAL_PORT_SPEED[mac_port.get_serdes_speed()] / GIGA)

            entry_key_c2c = '{},{},{},{}'.format(
                mac_info['slice'],
                mac_info['ifg'],
                serdes_speed,
                'CHIP2CHIP')
            entry_key_optic = '{},{},{},{}'.format(
                mac_info['slice'],
                mac_info['ifg'],
                serdes_speed,
                module_type)

            # Default module_type is COPPER. Get copper param map when AN is enabled.
            if mac_port.get_an_enabled():
                params_values_list = self.params_map[entry_key_optic]
            elif entry_key_c2c in self.params_map:
                params_values_list = self.params_map[entry_key_c2c]
            elif entry_key_optic in self.params_map:
                params_values_list = self.params_map[entry_key_optic]
            else:
                print('Failed to find parameters for SerDes with key {}'.format(entry_key_optic))

        if params_values_list is not None:
            for ser in range(serdes_count):
                done_with_lane = False
                cur_ser = ser + mac_info['serdes']
                if not isinstance(params_values_list, list):
                    params_values_list = [params_values_list]

                for params_values in params_values_list:
                    if 'serdes' in params_values:
                        serdes_list = params_values['serdes']
                    else:
                        serdes_list = range(self.device.get_num_of_serdes(mac_info['slice'], mac_info['ifg']))
                    for ii in serdes_list:
                        if ii != cur_ser:
                            continue
                        done_with_lane = True
                        props = []

                        self.init_serdes_params()

                        serdes_params_key_list = list(self.serdes_param_map.keys())
                        serdes_params_val_list = list(self.serdes_param_map.values())

                        for param in params_values:
                            if param in serdes_params_val_list:
                                position = serdes_params_val_list.index(param)
                                if serdes_params_key_list[position][1] == 'serdes_param_e_':
                                    props.append([ACTIVATE, serdes_params_key_list[position][0], FIXED, params_values[param]])
                            # else:
                                # Not raising an exception because of slice, ifg ...

                        for prop in props:
                            (stage, param, mode, val) = prop
                            mac_port.set_serdes_parameter(ser, stage, param, mode, val)
                        break
                    if done_with_lane:
                        break
                if not done_with_lane:
                    print(
                        'Failed to find parameters for per serdes lanes! slice %d ifg %d serdes %d ' %
                        (mac_info['slice'], mac_info['ifg'], cur_ser))
                    raise Exception()

    def mac_ports_activate(self, module_type, params):
        self.params_map = None
        if params is not None:
            with open(params, 'r') as fh:
                self.params_map = json.load(fh)

        self.mac_up_cnt = 0
        self.mac_up_bitmap = [False] * len(self.mac_ports)

        self.mac_time = []
        for i in range(len(self.mac_ports)):
            self.mac_time.append({"slice": 0,
                                  "ifg": 0,
                                  "first_serdes": 0,
                                  "time_before_activate": time.time(),
                                  "after_port_up": time.time()})

        for index, mac_port in enumerate(self.mac_ports):
            current_slice = mac_port.get_slice()
            current_ifg = mac_port.get_ifg()
            current_serdes = mac_port.get_first_serdes_id()
            mac_info = {
                'slice': current_slice,
                'ifg': current_ifg,
                'serdes': current_serdes}
            try:
                if self.ll_device.is_pacific():
                    self.pacific_mac_ports_apply_params(mac_port, module_type, params)
                elif self.ll_device.is_gibraltar():
                    self.gibraltar_mac_ports_apply_params(mac_port, module_type, params)
                elif self.ll_device.is_asic3():
                    self.asic3_mac_ports_apply_params(mac_port, module_type, params)

                # placement real values and time before activate, for current port
                self.mac_time[index]["slice"] = current_slice
                self.mac_time[index]["ifg"] = current_ifg
                self.mac_time[index]["first_serdes"] = current_serdes
                self.mac_time[index]["time_before_activate"] = time.time()
                mac_port.activate()
            except BaseException:
                raise Exception(
                    'Error: mac_port::activate failed (Slice {slice} / IFG {ifg} / SerDes {serdes}).'.format(**mac_info))

    def get_mac_port_idx(self, slice, ifg, first_serdes):
        for index, mp in enumerate(self.mac_ports):
            if (mp.get_slice() == slice and mp.get_ifg() == ifg and mp.get_first_serdes_id() == first_serdes):
                return index
        return -1

    def wait_mac_ports(self, cnt, timeout):
        start_time = time.time()
        end_time = start_time + timeout
        while True:
            # Read notification, wait up to 1 second
            crit, norm = self.read_notifications(1)
            notifications = crit + norm
            curr_time = time.time()
            if self.mac_up_cnt == cnt or curr_time > end_time:
                # All UP or time elapsed and nothing happen
                break
            if len(notifications) == 0:
                continue
            for notification in notifications:
                if notification.type == sdk.la_notification_type_e_LINK:
                    mp_idx = self.get_mac_port_idx(notification.u.link.slice_id,
                                                   notification.u.link.ifg_id,
                                                   notification.u.link.first_serdes_id)
                    if notification.u.link.type == sdk.la_link_notification_type_e_DOWN and self.mac_up_bitmap[mp_idx]:
                        self.mac_up_bitmap[mp_idx] = False
                        self.mac_up_cnt = self.mac_up_cnt - 1
                    elif notification.u.link.type == sdk.la_link_notification_type_e_UP and not self.mac_up_bitmap[mp_idx]:
                        self.mac_up_bitmap[mp_idx] = True
                        self.mac_up_cnt = self.mac_up_cnt + 1
                        self.mac_time[mp_idx]["after_port_up"] = time.time()
                if self.verbose:
                    print('time diff {:.3}; notification: {}'.format(curr_time - start_time,
                                                                     self.debug_device.notification_to_string(notification)))

        return self.mac_up_cnt == cnt

    def wait_for_mac_port_up(self, idx, timeout=TIMEOUT_PORT_UP):
        start_time = time.time()
        end_time = start_time + timeout
        up = False
        while True:
            # Read notification, wait up to 1 second
            crit, norm = self.read_notifications(1)
            notifications = crit + norm
            curr_time = time.time()
            if curr_time > end_time or up:
                break
            if len(notifications) == 0:
                continue
            for notification in notifications:
                if notification.type == sdk.la_notification_type_e_LINK:
                    mp_idx = self.get_mac_port_idx(notification.u.link.slice_id,
                                                   notification.u.link.ifg_id,
                                                   notification.u.link.first_serdes_id)
                    if notification.u.link.type == sdk.la_link_notification_type_e_UP and mp_idx == idx:
                        up = True

    def wait_mac_ports_up(self, timeout=TIMEOUT_PORT_UP):
        return self.wait_mac_ports(len(self.mac_ports), timeout)

    def wait_mac_ports_down(self, timeout=TIMEOUT_PORT_UP):
        return self.wait_mac_ports(0, timeout)

    def init_port_default_tm(self, mac_port, speed):
        ifc_sch = mac_port.get_scheduler()
        if ifc_sch is None:
            raise Exception('Error: port::get_scheduler failed')

        ifc_sch.set_credit_cir(speed)
        ifc_sch.set_transmit_cir(speed)
        ifc_sch.set_credit_eir_or_pir(speed, False)
        ifc_sch.set_transmit_eir_or_pir(speed, False)
        ifc_sch.set_cir_weight(1)
        ifc_sch.set_eir_weight(1)

    def read_notifications(self, timeout_seconds):
        # create a poll object
        po = select.poll()
        for fd in [self.critical_fd, self.normal_fd]:
            po.register(fd, select.POLLIN)
            os.set_blocking(fd, False)  # prepare for non-blocking read

        # The poll is in miliseconds
        res = po.poll(timeout_seconds * 1000)
        if len(res) == 0:
            # timed out - no notification descriptor available
            return [], []

        desc_critical = self.read_notifications_fd(self.critical_fd)
        desc_normal = self.read_notifications_fd(self.normal_fd)

        return desc_critical, desc_normal

    def read_notifications_fd(self, fd):
        sizeof = sdk.la_notification_desc.__sizeof__()
        desc_list = []
        while True:
            # A non-blocking read throws BlockingIOError when nothing is left to read
            try:
                buf = os.read(fd, sizeof)
            except BlockingIOError:
                break
            desc = sdk.la_notification_desc(bytearray(buf))
            desc_list.append(desc)

        return desc_list

    def mac_ports_up(self):
        for index in range(len(self.mac_ports)):
            mac_info = self.get_mac_info(index)
            if not mac_info['link_state']:
                return False

        return True

    #####################################################################################################
    # Helper information collection and print functions
    #####################################################################################################
    def get_mac_info(self, mac_index):
        mac_port = self.mac_ports[mac_index]
        mac_status = mac_port.read_mac_status()

        mac_info = {
            'index': mac_index,
            'slice': mac_port.get_slice(),
            'ifg': mac_port.get_ifg(),
            'serdes': mac_port.get_first_serdes_id()}
        mac_info['fc_mode'] = mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        mac_info['fec_mode'] = mac_port.get_fec_mode()
        speed = mac_port.get_speed()
        serdes_count = mac_port.get_num_of_serdes()
        mac_info['name'] = '{}x{:d}G'.format(serdes_count, int(PORT_SPEED[speed] / serdes_count))
        mac_info['serdes_speed'] = PORT_SPEED[speed] / serdes_count
        mac_info['link_state'] = mac_status.link_state
        mac_info['pcs_status'] = mac_status.pcs_status
        mac_info['am_lock'] = mac_status.am_lock
        mac_info['anlt'] = mac_port.get_an_enabled()
        mac_info['loopback'] = mac_port.get_loopback_mode()

        return mac_info

    def print_mac_up(self):
        all_pcs_lock = True
        for index in range(len(self.mac_ports)):
            mac_info = self.get_mac_info(index)
            mac_info['am_lock_str'] = ' '.join(
                list(map(lambda am_lock_val: '{}'.format('T' if am_lock_val else 'F'), mac_info['am_lock'])))
            if not mac_info['link_state']:
                all_pcs_lock = False
            if mac_info['link_state']:
                if self.verbose:
                    print(
                        'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, ANLT {anlt}, Loopback {loopback}, (slice {slice}, IFG {ifg}, SerDes {serdes}), '
                        'link {link_state}, pcs {pcs_status}'.format(
                            **mac_info))
            else:
                print(
                    'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, ANLT {anlt}, Loopback {loopback}, (slice {slice}, IFG {ifg}, SerDes {serdes}), '
                    'link {link_state}, pcs {pcs_status}, am_lock {am_lock_str}'.format(
                        **mac_info))
        return all_pcs_lock

    def print_link_up_time_ber(self):
        mac_fec_counters = self.get_mac_fec_counters()
        for index, mac_fec in enumerate(mac_fec_counters):
            mac_info = self.get_mac_info(index)
            print('Link [{index}] {name}, SerDes {slice}/{ifg}/{serdes}, BER {ber:.3e}, link up time '.format(**mac_fec), end='')
            if mac_info['link_state']:
                link_up_time = self.mac_time[index]["after_port_up"] - self.mac_time[index]["time_before_activate"]
                print('{:.2f}s'.format(link_up_time))
            else:
                print('n/a (link down)')

    def clear_mac_stats(self):
        for index, mp in enumerate(self.mac_ports):
            self.get_mac_stats(index)
        self.get_mac_fec_counters()

    def print_mac_stats(self):
        for index in range(len(self.mac_ports)):
            mac_info = self.get_mac_stats(index)
            print(
                'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), '
                'Rx {rx_frames} {rx_bytes}, Tx {tx_frames} {tx_bytes}, Tx CRC {tx_crc_err}, Tx Underrun {tx_underrun_err}, '
                'Uncorrectable {uncorrectable}, Correctable {correctable}'.format(
                    **mac_info))

    def get_mac_fec_counters(self, clear_on_read=True):
        mac_fec_counters = []
        for index, mp in enumerate(self.mac_ports):
            mac_info = self.get_mac_stats(index, clear_on_read)
            fec_mode = mp.get_fec_mode()
            try:
                rs = mp.read_rs_fec_debug_counters()
                mac_info['cw'] = rs.codeword
                mac_info['uncw'] = rs.codeword_uncorrectable
                mac_info['ber'] = rs.extrapolated_ber
                mac_info['symbol'] = rs.symbol_burst
                mac_info['flr'] = rs.extrapolated_flr
                mac_info['flr_r'] = rs.flr_r
            except sdk.InvalException:
                mac_info['cw'] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                mac_info['uncw'] = 0
                mac_info['ber'] = -1
                mac_info['symbol'] = [0, 0, 0, 0, 0, 0, 0]
                mac_info['flr'] = -1
                mac_info['flr_r'] = 0.0

            mac_fec_counters.append(mac_info)
        return mac_fec_counters

    def print_mac_ber(self):
        mac_fec_counters = self.get_mac_fec_counters()
        for mac_info in mac_fec_counters:
            print(
                'Link [{index}] name {name}, (slice {slice}, IFG {ifg}, SerDes {serdes}), BER {ber:.3e}, FLR {flr:.3e}, FLR_R {flr_r:.3} Codewords {cw}, Uncorrectable {uncw}, Symbol bursts {symbol}'.format(
                    **mac_info))

    def print_mac_pma_ber(self):
        for index in range(len(self.mac_ports)):
            mac_info = self.get_mac_pma_ber(index)
            mac_info['lane_ber_str'] = list(map(lambda ber_val: '{:.03e}'.format(ber_val), mac_info['lane_ber']))
            print(
                'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), BER {lane_ber_str}'.format(
                    **mac_info))

    def get_mac_pma_ber(self, mac_index):
        mac_port = self.mac_ports[mac_index]

        mac_info = {
            'index': mac_index,
            'slice': mac_port.get_slice(),
            'ifg': mac_port.get_ifg(),
            'serdes': mac_port.get_first_serdes_id()}
        mac_info['fc_mode'] = mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        mac_info['fec_mode'] = mac_port.get_fec_mode()
        speed = mac_port.get_speed()
        serdes_count = mac_port.get_num_of_serdes()
        mac_info['name'] = '{}x{:d}G'.format(serdes_count, int(PORT_SPEED[speed] / serdes_count))

        mac_port.set_pma_test_mode(sdk.la_mac_port.pma_test_mode_e_PRBS31)
        ber_result = mac_port.read_pma_test_ber()
        mac_port.set_pma_test_mode(sdk.la_mac_port.pma_test_mode_e_NONE)

        mac_info['lane_ber'] = list(filter(lambda ber: ber >= 0, ber_result.lane_ber))

        return mac_info

    def get_mac_stats(self, mac_index, clear_on_read=True):
        mac_port = self.mac_ports[mac_index]
        mac_mib = mac_port.read_mib_counters(clear_on_read)

        mac_info = self.get_mac_info(mac_index)
        mac_info['rx_frames'] = mac_mib.rx_frames_ok
        mac_info['tx_frames'] = mac_mib.tx_frames_ok
        mac_info['rx_bytes'] = mac_mib.rx_bytes_ok
        mac_info['tx_bytes'] = mac_mib.tx_bytes_ok
        mac_info['tx_crc_err'] = mac_mib.tx_crc_errors
        mac_info['rx_crc_err'] = mac_mib.rx_crc_errors
        mac_info['tx_underrun_err'] = mac_mib.tx_mac_underrun_err
        mac_info['rx_mac_code_err'] = mac_mib.rx_mac_code_err
        mac_info['tx_64b_frames'] = mac_mib.tx_64b_frames
        mac_info['rx_64b_frames'] = mac_mib.rx_64b_frames
        mac_info['tx_65to127b_frames'] = mac_mib.tx_65to127b_frames
        mac_info['rx_65to127b_frames'] = mac_mib.rx_65to127b_frames
        mac_info['tx_128to255b_frames'] = mac_mib.tx_128to255b_frames
        mac_info['rx_128to255b_frames'] = mac_mib.rx_128to255b_frames
        mac_info['tx_256to511b_frames'] = mac_mib.tx_256to511b_frames
        mac_info['rx_256to511b_frames'] = mac_mib.rx_256to511b_frames
        mac_info['tx_512to1023b_frames'] = mac_mib.tx_512to1023b_frames
        mac_info['rx_512to1023b_frames'] = mac_mib.rx_512to1023b_frames
        mac_info['tx_1024to1518b_frames'] = mac_mib.tx_1024to1518b_frames
        mac_info['rx_1024to1518b_frames'] = mac_mib.rx_1024to1518b_frames
        mac_info['tx_1519to2500b_frames'] = mac_mib.tx_1519to2500b_frames
        mac_info['rx_1519to2500b_frames'] = mac_mib.rx_1519to2500b_frames
        mac_info['tx_2501to9000b_frames'] = mac_mib.tx_2501to9000b_frames
        mac_info['rx_2501to9000b_frames'] = mac_mib.rx_2501to9000b_frames

        if (mac_info['fec_mode'] != sdk.la_mac_port.fec_mode_e_NONE):
            mac_info['uncorrectable'] = mac_port.read_counter(mac_port.counter_e_FEC_UNCORRECTABLE)
            mac_info['correctable'] = mac_port.read_counter(mac_port.counter_e_FEC_CORRECTABLE)
        else:
            mac_info['uncorrectable'] = -1
            mac_info['correctable'] = -1

        return mac_info

    def init_serdes_params(self):
        keys = ["serdes_param_stage_e_", "serdes_param_mode_e_", "serdes_param_e_"]
        ignore_keys = ("FIRST", "LAST")
        suffix_idx = 1
        # create map with tuple key using serdes_prefix with it's value
        for elem in dir(sdk.la_mac_port):
            if "serdes_param" in elem and not elem.endswith(ignore_keys):
                for key in keys:
                    if key in elem:
                        split_str = elem.split(key)
                        self.serdes_param_map[(key, getattr(sdk.la_mac_port, elem))] = split_str[-1]

    def string_macport(self, mp):
        return "%d/%d/%d" % (mp.get_slice(), mp.get_ifg(), mp.get_first_serdes_id())

    def string_serdes_params(self, key, key_val):
        # in case of misformatting
        if key[-1] != '_':
            key += "_"

        t = (key, key_val)
        rst = "Invalid (%s,%s)" % (key, key_val)
        if t in self.serdes_param_map:
            rst = self.serdes_param_map[t]
        return rst

    def print_histogram(self, mac_index, clear=True):
        mac_port = self.mac_ports[mac_index]
        hist = mac_port.get_state_histogram(clear)
        for elem in dir(sdk.la_mac_port):
            if 'state_e' in elem:
                if elem != 'state_e_LAST' and hist[getattr(sdk.la_mac_port, elem)] != 0:
                    print("%-30s %d" % (elem, hist[getattr(sdk.la_mac_port, elem)]))

    def dump_fec_to_csv(self, filepath, device_name='', wait=5 * 60, cycle=1, refclk=[0, 0, 0, 0]):
        f = open(filepath, "w+", 1)
        # reset counters
        self.clear_mac_stats()

        # wait for #wait seconds
        for i in range(wait):
            if (i % 10) == 0:
                print("remaining wait time: ", wait - i)
            time.sleep(1)

        fec_counters = self.get_mac_fec_counters()
        headline_str = "device name,cycle,refclk,wait_time,Link,name,Slice,IFG,SerDes,link_state,pcs_status,BER,FLR,FLR_R," + \
            "cw0,cw1,cw2,cw3,cw4,cw5,cw6,cw7,cw8,cw9,cw10,cw11,cw12,cw13,cw14,cw15,Correctable,Uncorrectable," + \
            "Symbol0,Symbol1,Symbol2,Symbol3,Symbol4,Symbol5,Symbol6,rx_mac_code_err,rx_frames,tx_frames,rx_bytes,tx_bytes"

        if self.ll_device.is_gibraltar():
            import srmcli
            headline_str += ",rx_die,rx_channel,rx_ready,tx_die,tx_channel,tx_ready,snr,afe,pga_gain,ffe_taps0"
            # Add blank lines for each ffe_tap value
            # Minus 1 because we have one header for ffe_taps already
            for i in range(len(srmcli.ffe_taps_t().data) - 1):
                headline_str += ",ffe_taps" + str(i + 1)

        headline_str += "\n"
        f.write(headline_str)

        for fec_counter in fec_counters:
            string = "{},{},{},{},{index},{name},{slice},{ifg},{serdes},{link_state},{pcs_status},{ber:.3e},{flr:.3e},{flr_r:.3},{cw},{correctable},{uncw},{symbol},{rx_mac_code_err},{rx_frames},{tx_frames},{rx_bytes},{tx_bytes}".format(
                device_name, cycle, ':'.join(map(str, refclk)), wait, **fec_counter)
            if self.ll_device.is_gibraltar():
                rx_die = self.device.get_serdes_addr(int(fec_counter['slice']), int(
                    fec_counter['ifg']), int(fec_counter['serdes']), sdk.la_serdes_direction_e_RX)
                tx_die = self.device.get_serdes_addr(int(fec_counter['slice']), int(
                    fec_counter['ifg']), int(fec_counter['serdes']), sdk.la_serdes_direction_e_TX)
                rx_ch = self.device.get_serdes_source(int(fec_counter['slice']), int(fec_counter['ifg']))[
                    int(fec_counter['serdes'])] % 2
                tx_ch = int(fec_counter['serdes']) % 2
                snr = srmcli.srm_rx_dsp_snr_read_db(rx_die, rx_ch)
                ffe_taps = srmcli.ffe_taps_t()
                srmcli.srm_rx_dsp_ffe_taps_query(rx_die, rx_ch, 0, ffe_taps)
                rdata0 = srmcli.srm_reg_read(rx_die, 0x2884 + rx_ch * 0x800)
                afe_trim0 = ((rdata0 >> 9) & 0x1f)
                pga_gain0 = ((rdata0 >> 0) & 0x1ff)
                rx_ready = srmcli.srm_is_rx_ready(rx_die, rx_ch)
                tx_ready = srmcli.srm_is_tx_ready(tx_die, tx_ch)
                string += ",{},{},{},{},{},{},{},{},{},{}".format(rx_die,
                                                                  rx_ch,
                                                                  rx_ready,
                                                                  tx_die,
                                                                  tx_ch,
                                                                  tx_ready,
                                                                  snr,
                                                                  afe_trim0,
                                                                  pga_gain0,
                                                                  ffe_taps.data)
            string += "\n"
            string = (string.replace('[', '')).replace(']', '')
            f.write(string)
        f.close()
        return fec_counters

    def print_link_down_histogram(self, mac_index, clear=True):
        mp = self.mac_ports[mac_index]
        hist = mp.get_link_down_histogram(clear)
        print("Link Down Histogram for", self.string_macport(mp))
        print(" rx_link_status_down      : ", hist.rx_link_status_down_count)
        print(" remote_fault_down        : ", hist.rx_remote_link_status_down_count)
        print(" local_fault_down         : ", hist.rx_local_link_status_down_count)
        print(" rx_pcs_link_status_down  : ", hist.rx_pcs_link_status_down_count)
        print(" rx_pcs_align_status_down : ", hist.rx_pcs_align_status_down_count)
        print(" rx_pcs_hi_ber_up         : ", hist.rx_pcs_hi_ber_up_count)
        print(" rsf_rx_high_ser          : ", hist.rsf_rx_high_ser_interrupt_register_count)
        print(" rx_pma_sig_ok_loss       : ", hist.rx_pma_sig_ok_loss_interrupt_register_count)
        print(" rx_deskew_fifo_overflow  : ", hist.rx_deskew_fifo_overflow_count)

    #####################################################################################################
    # Helper SerDes PRBS test mode functions
    #####################################################################################################

    def get_serdes_prbs_mode(self, mac_index):
        mac_port = self.mac_ports[mac_index]
        test_mode = mac_port.get_serdes_test_mode()

        # Print the test mode
        for elem in dir(sdk.la_mac_port):
            if 'serdes_test_mode_e' in elem:
                if elem != 'serdes_test_mode_e_LAST' and getattr(sdk.la_mac_port, elem) == test_mode:
                    print('{}'.format(elem))

        return test_mode

    def set_serdes_prbs_mode(self, mac_index, mode):
        mac_port = self.mac_ports[mac_index]

        if mode == sdk.la_mac_port.serdes_test_mode_e_NONE:
            mac_port.set_serdes_test_mode(sdk.la_mac_port.serdes_test_mode_e_NONE)
            mac_port.set_serdes_continuous_tuning_enabled(True)
        else:
            mac_port.set_serdes_continuous_tuning_enabled(False)
            time.sleep(3)
            mac_port.set_serdes_test_mode(mode)

    def dump_serdes_prbs_ber(self, mac_index):
        mac_port = self.mac_ports[mac_index]
        ber_data = mac_port.read_serdes_test_ber()
        for i in range(mac_port.get_num_of_serdes()):
            print('slice/ifg/serdes {}/{}/{} {} errors / {} count, {} BER '.format(mac_port.get_slice(), mac_port.get_ifg(),
                                                                                   mac_port.get_first_serdes_id() + i, ber_data.errors[i], ber_data.count[i], ber_data.lane_ber[i]))
            if ber_data.errors[i] >= 0xFFFFFFFF:
                print("BER indicates max error count.\n")

    def read_mac_rate(self):
        self.set_counter_timer(enable=True)

        device_stats = {'tx_frames': 0, 'rx_frames': 0, 'tx_bytes': 0, 'rx_bytes': 0}
        all_slice_stats = []
        mac_info = []

        for slice in self.used_slices:
            slice_stats = []
            for ifg in self.used_ifgs:
                ifg_stats = {'tx_frames': 0, 'rx_frames': 0, 'tx_bytes': 0, 'rx_bytes': 0}
                slice_stats.append(ifg_stats)
            all_slice_stats.append(slice_stats)

        # Read and calculate rates
        for index in range(len(self.mac_ports)):
            ipg_gap_len, ipg_gap_bytes = self.mac_ports[index].get_ipg()
            # Rate calc is not supporting tx_ipg_period > 0 as it requires knowing packet size
            ipg = ipg_gap_len if (ipg_gap_bytes == 0) else 0
            tx_preamble = 8  # Currently we don't enable preamble compression

            mac_info.append(self.get_mac_stats(index))

            mac_info[index]['tx_mpps'] = mac_info[index]['tx_frames'] / 1000000
            tx_bytes = mac_info[index]['tx_bytes'] + (tx_preamble + ipg) * mac_info[index]['tx_frames']
            mac_info[index]['tx_gbps'] = tx_bytes * 8 / 1000000000

            mac_info[index]['rx_mpps'] = mac_info[index]['rx_frames'] / 1000000
            rx_bytes = mac_info[index]['rx_bytes'] + (tx_preamble + ipg) * mac_info[index]['rx_frames']
            mac_info[index]['rx_gbps'] = rx_bytes * 8 / 1000000000

            device_stats['tx_frames'] += mac_info[index]['tx_frames']
            device_stats['tx_bytes'] += tx_bytes
            device_stats['rx_frames'] += mac_info[index]['rx_frames']
            device_stats['rx_bytes'] += rx_bytes

            all_slice_stats[mac_info[index]['slice']][mac_info[index]['ifg']]['tx_frames'] += mac_info[index]['tx_frames']
            all_slice_stats[mac_info[index]['slice']][mac_info[index]['ifg']]['tx_bytes'] += tx_bytes
            all_slice_stats[mac_info[index]['slice']][mac_info[index]['ifg']]['rx_frames'] += mac_info[index]['rx_frames']
            all_slice_stats[mac_info[index]['slice']][mac_info[index]['ifg']]['rx_bytes'] += rx_bytes

        self.set_counter_timer(enable=False)

        ifg_stats = all_slice_stats
        for slice in self.used_slices:
            for ifg in self.used_ifgs:
                ifg_stats[slice][ifg]['tx_mpps'] = ifg_stats[slice][ifg]['tx_frames'] / 1000000
                ifg_stats[slice][ifg]['rx_mpps'] = ifg_stats[slice][ifg]['rx_frames'] / 1000000
                ifg_stats[slice][ifg]['tx_gbps'] = ifg_stats[slice][ifg]['tx_bytes'] * 8 / 1000000000
                ifg_stats[slice][ifg]['rx_gbps'] = ifg_stats[slice][ifg]['rx_bytes'] * 8 / 1000000000
                ifg_stats[slice][ifg]['slice'] = slice
                ifg_stats[slice][ifg]['ifg'] = ifg

        device_stats['tx_mpps'] = device_stats['tx_frames'] / 1000000
        device_stats['rx_mpps'] = device_stats['rx_frames'] / 1000000
        device_stats['tx_gbps'] = device_stats['tx_bytes'] * 8 / 1000000000
        device_stats['rx_gbps'] = device_stats['rx_bytes'] * 8 / 1000000000
        return (mac_info, ifg_stats, device_stats)

    def print_mac_rate(self):
        (mac_info, ifg_stats, device_stats) = self.read_mac_rate()
        for index in range(len(mac_info)):
            print(
                'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), '
                'Rx {rx_frames} {rx_bytes} Mpps {rx_mpps:.2f} Gbps {rx_gbps:.2f}, '
                'Tx {tx_frames} {tx_bytes} Mpps {tx_mpps:.2f} Gbps {tx_gbps:.2f}'.format(
                    **mac_info[index]))
        for slice in self.used_slices:
            for ifg in self.used_ifgs:
                print(
                    'Total Slice {slice} / IFG {ifg}: '
                    'Rx {rx_frames} {rx_bytes} Mpps {rx_mpps:.2f} Gbps {rx_gbps:.2f}, '
                    'Tx {tx_frames} {tx_bytes} Mpps {tx_mpps:.2f} Gbps {tx_gbps:.2f}'.format(
                        **ifg_stats[slice][ifg]))
        print(
            'Total device '
            'Rx {rx_frames} {rx_bytes} Mpps {rx_mpps:.2f} Gbps {rx_gbps:.2f}, '
            'Tx {tx_frames} {tx_bytes} Mpps {tx_mpps:.2f} Gbps {tx_gbps:.2f}'.format(
                **device_stats))

    def get_device_rate(self):
        (mac_info, ifg_stats, device_stats) = self.read_mac_rate()
        print('device rate {:.4f} gbps'.format(device_stats['rx_gbps'] + device_stats['tx_gbps']))
        return device_stats['rx_gbps'] + device_stats['tx_gbps']

    def set_counter_timer(self, enable):

        # Device Freq in MHz
        dev_rev = self.ll_device.get_device_revision()
        if dev_rev is lldcli.la_device_revision_e_ASIC3_A0:
            device_freq = 1000000
        else:
            device_freq = self.device.get_int_property(sdk.la_device_property_e_DEVICE_FREQUENCY)

        clock_cycles_in_sec = device_freq * 1000

        # {32bits (Time) , bit (CounterTimerEn) }
        clk_and_enable = (clock_cycles_in_sec << 1) + enable

        for slice in self.used_slices:
            for ifg in self.used_ifgs:
                block = self.debug_device.device_tree.slice[slice].ifg[ifg]
                for mp8 in block.mac_pool8:
                    if (mp8.counter_timer):
                        self.ll_device.write_register(mp8.counter_timer, clk_and_enable)
                if hasattr(block, 'mac_pool2'):
                    self.ll_device.write_register(block.mac_pool2.counter_timer, clk_and_enable)
                if hasattr(block, 'ifgb'):
                    self.ll_device.write_register(block.ifgb.counter_timer, clk_and_enable)
                if hasattr(block, 'ifgbi'):
                    self.ll_device.write_register(block.ifgbi.counter_timer, clk_and_enable)
                    self.ll_device.write_register(block.ifgbe_core.counter_timer, clk_and_enable)
                    self.ll_device.write_register(block.ifgbe_mac.counter_timer, clk_and_enable)

        if (enable):
            for slice in self.used_slices:
                for ifg in self.used_ifgs:
                    block = self.debug_device.device_tree.slice[slice].ifg[ifg]
                    # trigger reg (zero & start counting)
                    for mp8 in block.mac_pool8:
                        if (mp8.counter_timer_trigger_reg):
                            self.ll_device.write_register(mp8.counter_timer_trigger_reg, 1)
                    if hasattr(block, 'mac_pool2'):
                        self.ll_device.write_register(block.mac_pool2.counter_timer_trigger_reg, 1)
                    if hasattr(block, 'ifgb'):
                        self.ll_device.write_register(block.ifgb.counter_timer_trigger_reg, 1)
                    if hasattr(block, 'ifgbi'):
                        self.ll_device.write_register(block.ifgbi.counter_timer_trigger_reg, 1)
                        self.ll_device.write_register(block.ifgbe_core.counter_timer_trigger_reg, 1)
                        self.ll_device.write_register(block.ifgbe_mac.counter_timer_trigger_reg, 1)

            time.sleep(1)

    def setup_trap_counters(self):
        last_trap = sdk.LA_EVENT_OAMP_LAST
        for trap in range(sdk.LA_EVENT_ETHERNET_FIRST, last_trap):
            counter = self.device.create_counter(1)
            self.trap_counters.append((counter, trap))
            if trap != sdk.LA_EVENT_L3_DROP_ADJ:
                self.device.set_trap_configuration(trap,
                                                   0,    # priority
                                                   counter,
                                                   None,  # destination
                                                   True,
                                                   False,
                                                   True,
                                                   0)    # tc (don't care)
            else:
                self.device.set_trap_configuration(trap,
                                                   0,    # priority
                                                   counter,
                                                   None,  # destination
                                                   False,
                                                   False,
                                                   True,
                                                   0)    # tc (don't care)

    def print_trap_counter(self):
        trap_names = {}
        tnames = [t for t in dir(sdk) if 'LA_EVENT' in t]
        for t in tnames:
            trap_names[getattr(sdk, t)] = t
        for counter in self.trap_counters:
            print(counter[0].read(0, True, True), trap_names[counter[1]])

    def dump_serdes_parameters(self, mac_index):
        # check if empty
        if not self.serdes_param_map:
            self.init_serdes_params()

        max_width = len(max(self.serdes_param_map.values(), key=len))
        mp = self.mac_ports[mac_index]
        for serdes_index in range(mp.get_num_of_serdes()):
            print("\n\nSDK Serdes Parameters for %d/%d/%d" %
                  (mp.get_slice(), mp.get_ifg(), mp.get_first_serdes_id() + serdes_index))
            print("%s | %s | %s | %s | %s" %
                  ("NUM", "STAGE".center(max_width), "MODE".center(max_width), "PARAMETER".center(max_width), "VALUE"))
            print("%s---%s---%s---%s---%s" %
                  ("".ljust(3, "-"), "".ljust(max_width, "-"), "".ljust(max_width, "-"), "".ljust(max_width, "-"), "-----"))

            params = mp.get_serdes_parameters(serdes_index)
            for entry in range(len(params)):
                p = params[entry]
                print("%3d | %s | %s | %s | %d" %
                      (entry, self.string_serdes_params("serdes_param_stage_e_", p.stage).ljust(max_width),
                       self.string_serdes_params("serdes_param_mode_e_", p.mode).ljust(max_width),
                       self.string_serdes_params("serdes_param_e_", p.parameter).ljust(max_width),
                       p.value))
