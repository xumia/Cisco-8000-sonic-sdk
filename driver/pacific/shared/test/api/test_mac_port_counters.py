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
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_mac_port_counters(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_mac_port_mib_counters(self):
        slice_id = 0
        ifg_id = 0
        first_serdes_id = 4
        last_serdes_id = 5

        mac_port = self.device.create_mac_port(slice_id, ifg_id, first_serdes_id, last_serdes_id,
                                               sdk.la_mac_port.port_speed_e_E_50G,
                                               sdk.la_mac_port.fc_mode_e_NONE,
                                               sdk.la_mac_port.fec_mode_e_NONE)

        self.assertIsNotNone(mac_port)

        clear = True
        counters = mac_port.read_mib_counters(clear)

        # Make sure all counters are 0 because currently simulator doesn't simulate the read_mib_counters
        attributes = [attr for attr in dir(counters) if not attr.startswith('__') and not attr == 'this']
        for attr in attributes:
            self.assertEqual(getattr(counters, attr), 0)


if __name__ == '__main__':
    unittest.main()
