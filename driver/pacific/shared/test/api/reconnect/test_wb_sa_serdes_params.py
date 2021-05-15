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

import unittest
from leaba import sdk
from snake_base import *
import decor
import warm_boot_test_utils as wb
from wb_sa_base import *


@unittest.skip("Needs adjustments after merging WB with master")
@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
@unittest.skipUnless(decor.is_gibraltar(), "WB is only suppored for gibraltar")
class test_wb_sa(test_wb_sa_base):
    def test_wb_sa_serdes_params(self):
        '''
        check serdes params persistence across warmboot, no traffic testing
        '''
        print("checking serdes params")
        self.setup_ports()
        device = self.snake.device
        ldev = device.get_ll_device()

        stage = sdk.la_mac_port.serdes_param_stage_e_ACTIVATE
        self.supported_serdes_params = [sdk.la_mac_port.serdes_param_e_DATAPATH_RX_GRAY_MAP,
                                        sdk.la_mac_port.serdes_param_e_DATAPATH_TX_GRAY_MAP,
                                        sdk.la_mac_port.serdes_param_e_DATAPATH_RX_PRECODE,
                                        sdk.la_mac_port.serdes_param_e_DATAPATH_TX_PRECODE,
                                        sdk.la_mac_port.serdes_param_e_DATAPATH_RX_SWIZZLE,
                                        sdk.la_mac_port.serdes_param_e_DATAPATH_TX_SWIZZLE,
                                        sdk.la_mac_port.serdes_param_e_TX_POST,
                                        sdk.la_mac_port.serdes_param_e_TX_POST2,
                                        sdk.la_mac_port.serdes_param_e_TX_POST3,
                                        sdk.la_mac_port.serdes_param_e_TX_PRE1,
                                        sdk.la_mac_port.serdes_param_e_TX_PRE2,
                                        sdk.la_mac_port.serdes_param_e_TX_PRE3,
                                        sdk.la_mac_port.serdes_param_e_TX_MAIN,
                                        sdk.la_mac_port.serdes_param_e_TX_INNER_EYE1,
                                        sdk.la_mac_port.serdes_param_e_TX_INNER_EYE2,
                                        sdk.la_mac_port.serdes_param_e_TX_LUT_MODE,
                                        sdk.la_mac_port.serdes_param_e_RX_AC_COUPLING_BYPASS,
                                        sdk.la_mac_port.serdes_param_e_RX_AFE_TRIM,
                                        sdk.la_mac_port.serdes_param_e_RX_CTLE_CODE,
                                        sdk.la_mac_port.serdes_param_e_RX_DSP_MODE,
                                        sdk.la_mac_port.serdes_param_e_RX_VGA_TRACKING]
        mode = sdk.la_mac_port.serdes_param_mode_e_FIXED
        all_serdes_params = []
        mac_ports = self.snake.mph.mac_ports
        for i in range(len(mac_ports)):
            val = i
            serdes_params = [None] * (sdk.la_mac_port.serdes_param_e_LAST + 1)
            for param in self.supported_serdes_params:
                try:
                    for j in range(2):
                        mac_ports[i].set_serdes_parameter(j, stage, param, mode, val)
                    serdes_params[param] = val
                except BaseException as e:
                    self.assertEqual(e.args[0], sdk.la_status_e_E_NOTIMPLEMENTED)

            all_serdes_params.append(serdes_params)

        wb.warm_boot(device)
        # Restore notification pipes manually
        self.snake.mph.critical_fd, self.snake.mph.normal_fd = device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)
        self.snake.mph.wait_mac_ports_up()
        # Retrieve the re-created mac_port objects
        mac_ports = device.get_objects(sdk.la_object.object_type_e_MAC_PORT)
        # Verify serdes params
        for i in range(len(mac_ports)):
            serdes_params = all_serdes_params[i]
            for param in self.supported_serdes_params:
                try:
                    for j in range(2):
                        mode_out, val_out = mac_ports[i].get_serdes_parameter(j, stage, param)
                        self.assertEqual(mode, mode_out)
                        self.assertEqual(serdes_params[param], val_out)
                except BaseException as e:
                    self.assertEqual(e.args[0], sdk.la_status_e_E_NOTFOUND)
                    self.assertEqual(serdes_params[param], None)


if __name__ == '__main__':
    unittest.main()
