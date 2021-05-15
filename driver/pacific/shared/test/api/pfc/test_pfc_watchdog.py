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

import decor
import pdb
from pfc_base import *
import unittest
import decor
from pfc_local import *
from pfc_watchdog import *
import interrupt_utils


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
class test_pfc_watchdog(pfc_local, pfc_base, pfc_common, pfc_watchdog):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_pfc(self):
        self.init_common()

        self.watchdog_test(self.m_mac_port.hld_obj)

        # Test draining a VOQ index
        voq = self.find_voq_set(self.s_sys_p2_gid)
        voq.set_state(TC_VALUE, sdk.la_voq_set.state_e_DROPPING)
        voq.flush(TC_VALUE, False)
        # Check the state of the queue
        self.assertEqual(voq.get_state(TC_VALUE), sdk.la_voq_set.state_e_DROPPING)

        # Set state of index back to active.
        voq.set_state(TC_VALUE, sdk.la_voq_set.state_e_ACTIVE)
        # Check the state of the queue
        self.assertEqual(voq.get_state(TC_VALUE), sdk.la_voq_set.state_e_ACTIVE)

        # Try setting the state of a voq index while the voq_set is dropping.
        voq.set_state(sdk.la_voq_set.state_e_DROPPING)
        with self.assertRaises(sdk.BusyException):
            voq.set_state(TC_VALUE, sdk.la_voq_set.state_e_DROPPING)

        # Set the voq_set back to active.
        voq.set_state(sdk.la_voq_set.state_e_ACTIVE)
        # Try flushing a VOQ when not set to dropping.
        with self.assertRaises(sdk.InvalException):
            voq.flush(TC_VALUE, False)


if __name__ == '__main__':
    unittest.main()
