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
import decor
from voq_cgm_profile_base import *
import topology as T


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
class voq_profile_attach(voq_cgm_profile_base):
    def setUp(self):
        voq_cgm_profile_base.setUp(self)

        VOQ_SET_SIZE = 8
        DEST_SLICE = 0
        DEST_IFG = 0

        # Create UC VOQ
        is_success, base_voq, base_vsc_vec = T.topology.allocate_voq_set(
            self.device, self.device.get_id(), DEST_SLICE, DEST_IFG, VOQ_SET_SIZE)
        self.assertTrue(is_success)
        self.uc_voq_set = self.device.create_voq_set(
            base_voq,
            VOQ_SET_SIZE,
            base_vsc_vec,
            self.device.get_id(),
            DEST_SLICE,
            DEST_IFG)

        # Get MC VOQ (assumes standalone mode)
        self.mc_voq_set = self.device.get_egress_multicast_slice_replication_voq_set(0)

    def tearDown(self):
        self.mc_voq_set.set_cgm_profile(0, None)

        self.uc_voq_set.set_state(sdk.la_voq_set.state_e_DROPPING)
        self.device.destroy(self.uc_voq_set)
        voq_cgm_profile_base.tearDown(self)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_voq_profile_attach(self):
        # Attach CGM profile to UC VOQ then fail on attach to MC VOQ
        self.uc_voq_set.set_cgm_profile(0, self.voq_cgm_profile)
        with self.assertRaises(sdk.BaseException) as cm:
            self.mc_voq_set.set_cgm_profile(0, self.voq_cgm_profile)
        STATUS = cm.exception
        self.assertEqual(STATUS.args[0], sdk.la_status_e_E_BUSY)

        # Cleanup
        self.uc_voq_set.set_cgm_profile(0, None)

        # Attach CGM profile to MC VOQ then fail on attach to UC VOQ
        self.mc_voq_set.set_cgm_profile(0, self.voq_cgm_profile)
        with self.assertRaises(sdk.BaseException) as cm:
            self.uc_voq_set.set_cgm_profile(0, self.voq_cgm_profile)
        STATUS = cm.exception
        self.assertEqual(STATUS.args[0], sdk.la_status_e_E_BUSY)

        # Cleanup
        self.mc_voq_set.set_cgm_profile(0, None)

        # Attach CGM profile to MC VOQ then fail evict to HBM
        self.mc_voq_set.set_cgm_profile(0, self.voq_cgm_profile)
        evict_to_hbm_enable = True
        with self.assertRaises(sdk.BaseException) as cm:
            self.voq_cgm_profile.set_sms_size_in_packets_behavior(0, 0, 0, 0, False, evict_to_hbm_enable)
        STATUS = cm.exception
        self.assertEqual(STATUS.args[0], sdk.la_status_e_E_INVAL)

        # Cleanup
        self.mc_voq_set.set_cgm_profile(0, None)

        # Attach configure CGM profile to evict to HBM then fail attach to MC VOQ
        self.voq_cgm_profile.set_sms_size_in_packets_behavior(0, 0, 0, 0, False, evict_to_hbm_enable)
        with self.assertRaises(sdk.BaseException) as cm:
            self.mc_voq_set.set_cgm_profile(0, self.voq_cgm_profile)
        STATUS = cm.exception
        self.assertEqual(STATUS.args[0], sdk.la_status_e_E_INVAL)


if __name__ == '__main__':
    unittest.main()
