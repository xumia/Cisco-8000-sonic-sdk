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

import os
import unittest
from leaba import sdk
from leaba import debug
import test_lldcli
import tempfile
import sim_utils
import json
import packet_test_utils
import re
import time
from pma_tx_err_helper import *

EXPECTED_JSON_FILENAME = 'test_mac_port.json.gz'


class mac_port_base(unittest.TestCase):

    def setUp(self):
        self.slices_changed_from_default = False
        self.device = sim_utils.create_device(1)
        self.set_base_params()

    def set_base_params(self):
        self.expected_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'expected', 'test_mac_port')
        self.mac_ports = []
        self.activate_ports = False
        self.pma_tx_err_helper = pma_tx_err_helper(self.device)

    def tearDown(self):
        self.device.tearDown()

    def mac_port_setup(self, base_slice, base_ifg, base_serdes, serdes_count, ports_per_ifg, speed, fc_modes, fec_modes):
        self.num_ifgs_used = 0
        self.max_num_ifgs = 2 * len(self.device.get_used_slices())
        slice_idx = base_slice
        slice_id = self.device.get_used_slices()[slice_idx]
        ifg_id = base_ifg
        for fec_mode in fec_modes:
            for fc_mode in fc_modes:
                for port_idx in range(ports_per_ifg):
                    serdes_start = base_serdes + port_idx * serdes_count
                    serdes_last = serdes_start + serdes_count - 1
                    try:
                        mac_port = self.device.create_mac_port(slice_id, ifg_id, serdes_start, serdes_last,
                                                               speed, fc_mode, fec_mode)
                    except sdk.BaseException:
                        print(
                            'Failed create_mac_port {0} in slice {1}, ifg {2}, serdes_start {3}, serdes_last {4}, with SPEED {5}, FC_MODE {6}, FEC_MODE {7} '.format(
                                port_idx,
                                slice_id,
                                ifg_id,
                                serdes_start,
                                serdes_last,
                                speed,
                                fc_mode,
                                fec_mode))
                        raise

                    self.assertIsNotNone(mac_port)

                    self.mac_ports.append(mac_port)

                    if (self.activate_ports):
                        mac_port.activate()

                    out_speed = mac_port.get_speed()
                    self.assertEqual(out_speed, speed)

                    out_fc = mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
                    self.assertEqual(out_fc, fc_mode)

                    out_fec = mac_port.get_fec_mode()
                    self.assertEqual(out_fec, fec_mode)

                    out_lb_mode = mac_port.get_loopback_mode()
                    self.assertEqual(out_lb_mode, sdk.la_mac_port.loopback_mode_e_NONE)

                print('----------- fec_mode=', fec_mode, "    fc_mode=", fc_mode, "   slice_id=", slice_id, " ifg_id=", ifg_id)
                ifg_id += 1
                if ifg_id > 1:
                    ifg_id = 0
                    slice_idx += 1
                    if slice_idx >= len(self.device.get_used_slices()):
                        slice_idx = 0
                        self.slices_changed_from_default = True
                    slice_id = self.device.get_used_slices()[slice_idx]

                self.num_ifgs_used += 1
                # if the test was design for an ASIC with more slices than the number of
                # available slices - don't crush, just return.
                if self.num_ifgs_used >= self.max_num_ifgs:
                    self.slices_changed_from_default = True
                    return

    def save_mac_port_state(self, port):
        # Create a temporary file for storing mac_port state
        fhandle, fname = tempfile.mkstemp(text=True)
        port.save_state(port.port_debug_info_e_ALL, fname)
        with open(fname) as json_file:
            mac_port_state = json.load(json_file)
        # Delete the tempfile file
        os.unlink(fname)
        return mac_port_state
