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
import sim_utils
import topology as T
from l2_protection_group_base import *
from packet_test_utils import *
from scapy.all import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_protection_group_switching_to_protecting_port(l2_protection_group_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_protection_group_switching_to_protecting_port(self):
        self.create_network_topology()
        self.configure_switching()
        self.m_protection_monitor.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        run_and_compare(
            self,
            self.device,
            self.s_packet,
            self.s_rx_slice,
            self.s_rx_ifg,
            self.s_first_serdes,
            self.s_packet,
            self.s_tx_spa_slice,
            self.s_tx_spa_ifg,
            self.s_first_serdes_spa)


if __name__ == '__main__':
    unittest.main()
