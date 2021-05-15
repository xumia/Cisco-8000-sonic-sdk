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

import decor
import os
import unittest
from leaba import sdk
import leaba
import decor
import packet_test_utils
import topology as T
import re
from mac_port_base import *
import mac_pool_port_configs as mpCfg


# Tests all mac_port configurations.
# Makes sure that a mac_port can be created with each available config,
# Configs are taken from mac_pool_port_configs


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
@unittest.skipIf(decor.is_pacific(), "This replaces the test_mac_pool______ for ASICs that are not pacific.")
class mac_pool_all_conf_test(mac_port_base):
    verbose = 0  # most verbose ==3, least verbose ==0

    def clear_ports(self):
        self.device.clear_device()
        self.device.close_notification_fds()

    # main test function, called by the unittest infrastracture.
    def test_mac_port_all_configs(self):
        cfg = mpCfg.mac_pool_port_configs()
        if decor.is_gibraltar():
            cfg.set_all_configs_GB(self.device)
        elif decor.is_asic4():
            cfg.set_all_configs_asic4()
        elif decor.is_asic3():
            cfg.set_all_configs_asic3()
        elif decor.is_asic5():
            cfg.set_all_configs_asic5()
        else:
            self.assertTrue(False, "Unknown device type, could not get the relevant port configurations.")

        results = []
        self.log_vebose('\n--------------------------------------------------------------- start mac pool tests')
        in_db = cfg.expected_packet_test_db_entry()
        for config_str in cfg.all_configuration_options():

            self.set_base_params()
            cfg.config_mac_pool(config_str)

            self.log_vebose("testing configuration", cfg.name, ":", lvl=2)
            self.mac_port_setup(cfg.slice_id, cfg.ifg_id, cfg.first_serdes_id, cfg.serdes_count, cfg.ports_per_ifg,
                                cfg.speed, cfg.fc_modes, cfg.fec_modes)

            self.assertTrue(
                config_str in in_db,
                "all tested port configurations should appear in cfg.expected_packet_test_db_entry().")

            self.clear_ports()

    def log_vebose(self, *strs, lvl=1):
        if self.verbose >= lvl:
            print(*strs)


if __name__ == '__main__':
    unittest.main()
