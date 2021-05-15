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

#!/usr/bin/env python3

import decor
import sys
import unittest
from leaba import sdk
from scapy.all import *
from rate_limiter_set_base import *
import sim_utils
import topology as T
import packet_test_utils as U


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class set_get_cir(rate_limiter_set_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_get_cir(self):

        self.create_attach_rate_limiter_set()
        for pkt_type in range(sdk.la_rate_limiters_packet_type_e_LAST):
            self.rate_limiter_set.set_cir(pkt_type, RATE)
            res_cir = self.rate_limiter_set.get_cir(pkt_type)
            self.assertAlmostEqual(res_cir / RATE, 1.0, places=1)

    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pac")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_port_counter_getter(self):
        self.create_attach_rate_limiter_set()
        for pkt_type in range(sdk.la_rate_limiters_packet_type_e_LAST):
            pass_count = self.rate_limiter_set.get_pass_count(pkt_type, False)
            self.assertIsNotNone(pass_count)
            drop_count = self.rate_limiter_set.get_drop_count(pkt_type, False)
            self.assertIsNotNone(drop_count)


if __name__ == '__main__':
    unittest.main()
