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


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class mac_pool_matilda(mc_base.mac_pool_matilda_base):

    @unittest.skipUnless(decor.is_gibraltar(), " Test is only relevant for GB")
    def __test_GB_base_for_matilda(self):
        self.mathilda_mode = self.m_mathilda_mod_toInt['GB']
        self.device = sim_utils.create_device(1, device_config_func=self.set_property)
        self.do_test_single_mode()

    @unittest.skipUnless(decor.is_gibraltar(), " Test is only relevant for GB")
    def __test_matilda_64(self):
        self.mathilda_mode = self.m_mathilda_mod_toInt['6.4']
        self.device = sim_utils.create_device(1, device_config_func=self.set_property)
        self.do_test_single_mode()

    @unittest.skipUnless(decor.is_gibraltar(), " Test is only relevant for GB")
    def __test_matilda_32A(self):
        self.mathilda_mode = self.m_mathilda_mod_toInt['3.2A']
        self.device = sim_utils.create_device(1, device_config_func=self.set_property)
        self.do_test_single_mode()

    @unittest.skipUnless(decor.is_gibraltar(), " Test is only relevant for GB")
    def __test_matilda_32B(self):
        self.mathilda_mode = self.m_mathilda_mod_toInt['3.2B']
        self.device = sim_utils.create_device(1, device_config_func=self.set_property)
        self.do_test_single_mode()

    def tearDown(self):
        self.device.tearDown()


if __name__ == '__main__':
    unittest.main()
