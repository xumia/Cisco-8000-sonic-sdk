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

from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import leaba
import decor


IN_SLICE = T.get_device_slice(2)
IN_IFG = 0
IN_SERDES_FIRST = 4
IN_SERDES_LAST = IN_SERDES_FIRST + 1
OUT_SLICE = T.get_device_slice(4)
OUT_IFG = T.get_device_ifg(1)
OUT_SERDES_FIRST = 8
OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

SWITCH_GID = 0x36B0  # Exceeding 12k to hit extended table (link_relay_attributes_table)

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0xAB9


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_switch_getter_test(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)

        self.topology = T.topology(self, self.device)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_l2_switch_getter(self):
        # WA Temporary protection to disallow SWTICH_GIDs >= 12k until configuring extended table is implemented
        with self.assertRaises(sdk.InvalException):
            sw = T.switch(self, self.device, SWITCH_GID)


if __name__ == '__main__':
    unittest.main()
