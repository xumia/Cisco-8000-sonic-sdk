#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from packet_test_utils import *
from scapy.all import *
import topology as T
import ip_test_base
import sim_utils
from hw_pfc_base import *
from pfc_common import *
import decor


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
class test_hw_pfc(hw_pfc_base, pfc_common):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_hw_pfc_rx(self):
        self.init_common()

        for eth_port in [self.topology.rx_eth_port, self.topology.rx_eth_port1]:
            self.init_rx_counting(eth_port, TC_VALUE)
            self.enable_rx_counting_common(eth_port)
            mac_port = eth_port.mac_port.hld_obj
            run_and_drop(
                self,
                self.device,
                self.pfc_packet,
                mac_port.get_slice(),
                mac_port.get_ifg(),
                mac_port.get_first_serdes_id())
            counter = mac_port.get_pfc_counter()
            packets, bytes = counter.read(TC_VALUE, True, True)
            self.assertEqual(packets, 1)


if __name__ == '__main__':
    unittest.main()
