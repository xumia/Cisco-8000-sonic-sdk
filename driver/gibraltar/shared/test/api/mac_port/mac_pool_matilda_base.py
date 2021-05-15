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
import leaba
import decor
import packet_test_utils
import re
from mac_port_base import *
import mac_pool_port_configs as mpCfg


# Tests which mac_port configurations are available.
# When the device is a Mathilda model, ports operating in serdes speed grater than 25 Gbit should be disabled.
# Test flow: 1) Sets the device HW to operate for one of the mathilda models,
# 2)tries to create mac ports in all the different configurations
# 3) makes sure all the speed above 25 Gbit fails (raises exception), and the rest succeed.
# in GB mode (i.e. not Mathilda) thests that all configuration are available.
# Model to test could be set throught the MATILDA_MODEL  property


class mac_pool_matilda_base(mac_port_base):
    verbose = 0  # most verbose ==3, least verbose ==0

    def set_property(self, la_device, init_stage):
        if (init_stage == sdk.la_device.init_phase_e_CREATED):
            la_device.set_int_property(sdk.la_device_property_e_MATILDA_MODEL_TYPE, self.mathilda_mode)

    def clear_ports(self):
        self.device.clear_device()
        self.device.close_notification_fds()

    # called by the unittest infrastracture, before the test is run
    def setUp(self):
        self.set_all_modes_dict()

    # called by the unittest infrastracture, once the tet is over
    def tearDown(self):
        self.device.tearDown()

    def do_test_single_mode(self):
        mode_str = self.m_modes_str[self.mathilda_mode]

        cfg = mpCfg.mac_pool_port_configs()
        cfg.set_all_configs_GB()

        results = []
        for config_str in cfg.all_configuration_options():

            self.set_base_params()
            cfg.config_mac_pool(config_str)
            ret_code = 0

            self.log_vebose("testing configuration", cfg.name, ":", lvl=2)
            expected_res = self.expected_test_results(cfg.serdes_speed)
            if expected_res != 0:

                # @ we expect this mac_port_setup() to rais an  "leaba.sdk.InvalException".
                # The test will crush if mac_port_setup() raises any other exception - or fail to rais an exception
                err_msg = "When trying to add port, expected an Invalid Exception in configuration " + config_str + \
                          " for MATILDA_MODEL_TYPE==" + mode_str + \
                          "but got no exception. this config shuld be disabled for mathilda\n"

                with self.assertRaises(leaba.sdk.InvalException, msg=err_msg) as context:
                    self.mac_port_setup(cfg.slice_id, cfg.ifg_id, cfg.first_serdes_id, cfg.serdes_count, cfg.ports_per_ifg,
                                        cfg.speed, cfg.fc_modes, cfg.fec_modes)

                # 22 is the bad mac_config number
                err_msg = "When trying to add port, expected an Invalid Exception in configuration " + config_str + \
                    " for MATILDA_MODEL_TYPE==" + mode_str + "but got some other exception\n"
                exeption_str = str(sdk.la_status_e_E_INVAL)
                self.assertTrue(exeption_str in str(context.exception), msg=err_msg)
                ret_code = expected_res

            else:
                self.mac_port_setup(cfg.slice_id, cfg.ifg_id, cfg.first_serdes_id, cfg.serdes_count, cfg.ports_per_ifg,
                                    cfg.speed, cfg.fc_modes, cfg.fec_modes)
                ret_code = 0

            results.append([config_str, ret_code, expected_res])
            self.clear_ports()

        self.log_vebose('\n--------------------------------------------------------------- results')
        self.log_vebose('tested Mathilda configuration: ', self.m_modes_str[self.mathilda_mode])
        for res in results:
            self.log_vebose('\t', res[0], ':  ', res[1] == res[2], '\t', 'ret code was: ', res[1])
        self.log_vebose('\n--------------------------------------------------------------- end')

    def expected_test_results(self, serdes_speed):
        if self.mathilda_mode == 0:
            return 0
        elif serdes_speed < 50:
            return 0
        else:
            return 1

    def set_all_modes_dict(self):
        self.m_modes_str = ['GB', '6.4', '3.2A', '3.2B', '8T_A', '8T_B']  # there is also an 'all' mode
        self.m_mathilda_mod_toInt = {name: i for i, name in enumerate(self.m_modes_str)}
        self.m_mathilda_mod_toInt['all'] = -1

    def log_vebose(self, *strs, lvl=1):
        if self.verbose >= lvl:
            print(*strs)


if __name__ == '__main__':
    unittest.main()
