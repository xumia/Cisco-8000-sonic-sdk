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
from protection_monitor_base import*
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class protection_monitor_state_update(protection_monitor_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_protection_monitor_state_update(self):
        self.create_protection_monitor()

        state = self.m_protection_monitor.get_state()
        self.assertEqual(state, sdk.la_protection_monitor.monitor_state_e_UNTRIGGERED)

        self.m_protection_monitor.set_state(sdk.la_protection_monitor.monitor_state_e_TRIGGERED)

        state = self.m_protection_monitor.get_state()
        self.assertEqual(state, sdk.la_protection_monitor.monitor_state_e_TRIGGERED)


if __name__ == '__main__':
    unittest.main()
