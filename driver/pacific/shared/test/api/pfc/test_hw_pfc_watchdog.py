#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import sim_utils
from hw_pfc_base import *
from pfc_watchdog import *
from pfc_common import *
import decor


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
class test_pfc_watchdog(hw_pfc_base, pfc_watchdog, pfc_common):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_hw_pfc_watchdog(self):
        self.init_common()
        self.enable_rx_counting_common(self.topology.rx_eth_port)
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR,
                                  sdk.la_mac_port.fc_mode_e_PFC)
        self.pfc_rx_counter = self.device.create_counter(8)
        self.mac_port.set_pfc_enable((1 << TC_VALUE))
        self.mac_port.set_pfc_counter(self.pfc_rx_counter)
        self.enable_rx_counting(self.topology.rx_eth_port)
        self.watchdog_test(self.mac_port)


if __name__ == '__main__':
    unittest.main()
