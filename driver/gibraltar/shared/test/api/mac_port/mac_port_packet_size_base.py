#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from math import ceil


class mac_port_packet_size_base(unittest.TestCase):
    def tearDown(self):
        self.device.tearDown()

    def mac_port_max_min_size_test(self, in_test_max_size, in_test_min_size, slice_id, ifg_id, first_serdes, last_serdes):
        speed = sdk.la_mac_port.port_speed_e_E_100G
        fc_mode = sdk.la_mac_port.fc_mode_e_NONE
        fec_mode = sdk.la_mac_port.fec_mode_e_RS_KR4
        self.device.create_mac_port(slice_id, ifg_id, first_serdes, last_serdes, speed, fc_mode, fec_mode)
        port = self.device.get_mac_port(slice_id, ifg_id, first_serdes)

        # Test non-default valid value
        test_max_size = ceil((in_test_max_size + in_test_min_size) / 2)
        test_min_size = ceil((in_test_max_size + in_test_min_size) / 2)

        val = port.set_max_packet_size(test_max_size)
        val = port.set_min_packet_size(test_min_size)

        max_size = port.get_max_packet_size()
        min_size = port.get_min_packet_size()

        self.assertEqual(test_max_size, max_size)
        self.assertEqual(test_min_size, min_size)

        # Test setting correct min/max values
        val = port.set_min_packet_size(in_test_min_size)
        val = port.set_max_packet_size(in_test_max_size)

        max_size = port.get_max_packet_size()
        min_size = port.get_min_packet_size()

        self.assertEqual(in_test_max_size, max_size)
        self.assertEqual(in_test_min_size, min_size)

        # Test setting invalid minimum/maximum size throws error
        test_max_size = in_test_max_size + 1
        test_min_size = in_test_min_size - 1

        self.assertRaises(sdk.OutOfRangeException, port.set_max_packet_size, test_max_size)
        self.assertRaises(sdk.OutOfRangeException, port.set_min_packet_size, test_min_size)


if __name__ == '__main__':
    unittest.main()
