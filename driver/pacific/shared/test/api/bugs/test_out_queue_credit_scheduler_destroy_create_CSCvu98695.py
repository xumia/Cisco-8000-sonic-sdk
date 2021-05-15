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

# Problem description: When an OQSE is destroyed and immedialtely created, stale VSC's are found attached to the OQSE.
#
# The test does the following:
#
# 1. Create an OQSE and attach VSC's to it.
#
# 2. Delete the OQSE created in the above step.
#
# 3. Create a new OQSE.
#
# 4. Verify that the old/stale VSC's are not attached to the OQSE.

import decor
import unittest
from leaba import sdk
import sim_utils
import topology as T


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class out_queue_credit_scheduler_destroy_create_CSCvu98695(unittest.TestCase):

    def setUp(self):

        self.device = sim_utils.create_device(1)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_out_queue_credit_scheduler_destroy_create_CSCvu98695(self):
        base_voq = 192
        voq_set_size = 3
        base_vsc_vec = [192, 208, 224, 240, 256, 272]
        dest_device = 0
        dest_slice = 1
        dest_ifg = 1

        device_id = self.device.get_id()

        voq_set = self.device.create_voq_set(base_voq, voq_set_size, base_vsc_vec, dest_device, dest_slice, dest_ifg)

        vsc_mappings = [sdk.la_oq_vsc_mapping_e_RR2, sdk.la_oq_vsc_mapping_e_RR1, sdk.la_oq_vsc_mapping_e_RR0]

        oqse = self.device.create_output_queue_scheduler(
            dest_slice, dest_ifg, sdk.la_output_queue_scheduler.scheduling_mode_e_DIRECT_2SP_3WFQ)

        # Attach VSC's.
        for voqset_idx in range(3):
            voq = base_voq + voqset_idx
            mode = vsc_mappings[voqset_idx]
            for slice_idx in self.device.get_used_slices():
                vsc = base_vsc_vec[slice_idx] + voqset_idx
                oqse.attach_vsc(vsc, mode, device_id, slice_idx, voq)

        # Destroy
        self.device.destroy(oqse)

        base_voq = 6456
        voq_set_size = 3
        base_vsc_vec = [680, 696, 712, 728, 744, 760]

        voq_set = self.device.create_voq_set(base_voq, voq_set_size, base_vsc_vec, dest_device, dest_slice, dest_ifg)
        oqse = self.device.create_output_queue_scheduler(
            dest_slice, dest_ifg, sdk.la_output_queue_scheduler.scheduling_mode_e_DIRECT_2SP_3WFQ)

        # Verify no stale VSC's are present.
        vsc_lst = oqse.get_attached_vscs()
        vsc_vector_len = 0
        self.assertEqual(len(vsc_lst), vsc_vector_len)

    def tearDown(self):
        self.device.tearDown()


if __name__ == '__main__':
    unittest.main()
