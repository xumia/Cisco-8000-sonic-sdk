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
import unittest
from leaba import sdk
from packet_test_utils import *
from scapy.all import *
from ipv4_lpts_base import *
import sim_utils
import topology as T
import ip_test_base


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class lpts_meter(ipv4_lpts_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_lpts_meter(self):

        METER_SET_SIZE = 1
        PACKET_PER_SEC_LIMIT = 1000000

        meter1 = T.create_meter_set(self, self.device, is_aggregate=True, set_size=METER_SET_SIZE)
        meter2 = T.create_meter_set(self, self.device, is_aggregate=True, set_size=METER_SET_SIZE)
        meter3 = T.create_meter_set(self, self.device, is_aggregate=True, set_size=METER_SET_SIZE)

        lpts = self.create_lpts_instance(meter1, meter2, meter3)
        self.setup_forus_dest()

        ingress_counter = self.device.create_counter(1)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, ingress_counter)

        run_and_compare(self, self.device,
                        INPUT_PACKET_UC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_UC, PUNT_SLICE, PUNT_IFG, PUNT_PIF_FIRST)

        (p, b) = ingress_counter.read(0, True, True)
        self.assertEqual(p, 1)

        (p, b) = meter2.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(p, 1)

        run_and_compare(self, self.device,
                        INPUT_PACKET_MC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_MC, PUNT_SLICE, PUNT_IFG, PUNT_PIF_FIRST)

        (p, b) = meter3.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(p, 1)


if __name__ == '__main__':
    unittest.main()
