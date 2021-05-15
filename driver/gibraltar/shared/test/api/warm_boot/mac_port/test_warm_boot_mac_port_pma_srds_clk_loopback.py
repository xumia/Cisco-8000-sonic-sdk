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

import decor
import mac_port_helper

from mac_port.mac_port_loopback_base import *

import warm_boot_test_utils
warm_boot_test_utils.support_warm_boot()


@unittest.skipIf(decor.is_hw_device(), "Skipped because original test without WB is skipped in HW sanity.")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Auto restoring of notification pipes after WB not supported.")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar(), "WB is currently supported by GB and PAC only")
class test_mac_port_pma_srds_clk_loopback(mac_port_loopback_base):
    def test_pma_srds_clk_loopback(self):
        self.parallel_loopback_test(sdk.la_mac_port.loopback_mode_e_PMA_SRDS_CLK, do_warm_boot=True)


if __name__ == '__main__':
    unittest.main()
