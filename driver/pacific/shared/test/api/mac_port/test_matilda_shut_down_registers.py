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
import mac_pool_matilda_base as mc_base


# Tests which mac_port configurations are available.
# When the device is a Mathilda model, ports operating in serdes speed grater than 25 Gbit should be disabled.
# Test flow: 1) Sets the device HW to operate for one of the mathilda models,
# 2)tries to create mac ports in all the different configurations
# 3) makes sure all the speed above 25 Gbit fails (raises exception), and the rest succeed.
# in GB mode (i.e. not Mathilda) thests that all configuration are available.
# Model to test could be set throught the MATILDA_MODEL  property


@unittest.skipUnless(decor.is_hw_gibraltar(), "Only meaning full on GB HW devices.")
class mac_pool_matilda(mc_base.mac_pool_matilda_base):

    def __test_matilda_registeries_shutdown_32B(self):
        self.mathilda_mode = self.m_mathilda_mod_toInt['3.2B']
        self.device = sim_utils.create_device(1, device_config_func=self.set_property)
        self.do_test_on_or_filtered()

    def test_matilda_registeries_shutdown_32A(self):
        self.mathilda_mode = self.m_mathilda_mod_toInt['3.2A']
        self.device = sim_utils.create_device(1, device_config_func=self.set_property)
        self.do_test_on_or_filtered()

    def do_test_on_or_filtered(self):

        lld = self.device.get_ll_device()
        tree = lld.get_gibraltar_tree()

        for sid in range(6):
            for ifg_id in range(2):
                self.do_read_write_memory(tree, sid, ifg_id)

    def do_read_write_memory(self, tree, sid, ifg_id):
        lld = self.device.get_ll_device()
        lld.set_shadow_read_enabled(False)
        lld.set_write_to_device(True)
        pool = tree.slice[sid].ifg[ifg_id]

        # access the ifg
        lld.write_memory(pool.ifgb.tc_lut_mem[0], 1, 1)
        res = lld.read_memory(pool.ifgb.tc_lut_mem[0], 1)
        if sid in self.device.get_used_slices():
            assert(res == 1)
        else:
            assert(res == 0)

        pattern_1 = 0xb4
        pattern_2 = 0xd8
        # access the serdices
        if (self.device.get_num_of_serdes(sid, ifg_id) == 24):
            cfg = (
                pattern_1 << 40) | (
                pattern_1 << 32) | (
                pattern_1 << 24) | (
                pattern_1 << 16) | (
                pattern_1 << 8) | pattern_1

            lld.write_register(pool.serdes_pool24.serdes_tx_lane_swap_config, cfg)
            cfg = (
                pattern_2 << 40) | (
                pattern_2 << 32) | (
                pattern_2 << 24) | (
                pattern_2 << 16) | (
                pattern_2 << 8) | pattern_2
            lld.write_register(pool.serdes_pool24.serdes_rx_lane_swap_config, cfg)
        else:
            cfg = (pattern_1 << 24) | (pattern_1 << 16) | (pattern_1 << 8) | pattern_1
            lld.write_register(pool.serdes_pool16.serdes_tx_lane_swap_config, cfg)
            cfg = (pattern_2 << 24) | (pattern_2 << 16) | (pattern_2 << 8) | pattern_2
            lld.write_register(pool.serdes_pool16.serdes_rx_lane_swap_config, cfg)

    def tearDown(self):
        self.device.tearDown()


if __name__ == '__main__':
    unittest.main()
