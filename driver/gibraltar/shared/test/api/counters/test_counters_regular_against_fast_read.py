#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from counters_base import *
import decor


class test_counters_regular_against_fast_read(counters_base):

    @unittest.skipIf(not decor.is_gibraltar(), "The property sdk.la_device_property_e_COUNTERS_SHADOW_AGE_OUT is only in GB")
    @unittest.skipIf(
        not decor.is_hw_device(),
        "Need to test again after NSIM enables larger read. The assumption is that it fails in NSIM because NSIM not enables wide enough read to enable the read of the whole bank")
    def test_fast_read_equals_to_regular_read(self):
        self.assign_counters()
        regular_counters_state = self.inject_packets_thorugh_countered_ports()
        self.device.set_int_property(sdk.la_device_property_e_COUNTERS_SHADOW_AGE_OUT, 5)
        self.clear_counters()
        fast_read_counters_state = self.inject_packets_thorugh_countered_ports()
        self.assertEqual(regular_counters_state, fast_read_counters_state, self.counter_ports_to_string())


if __name__ == '__main__':
    unittest.main()
