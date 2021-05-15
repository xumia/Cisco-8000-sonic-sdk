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

# Test covering CSCvi26250.
#
# Problem description: la_voq_set create A-create B-destroy B-create B sequence would fail on second creation, if first VOQ set is aligned to a native-VOQ-set boundary and second VOQ set follows that one immediately.
#-----------
#
# The test does the following:
#
# 1. Create VOQ set with ID 288 and size 8.
#
# 2. Create VOQ set with ID 296 and size 8.
#
# 3. Destroy last VOQ.
#
# 4. Create the last VOQ again with same params.

from packet_test_utils import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
import decor

SET_SIZE = 2
BASE_VSC = 192
VSC_SLICE_STEP = 16
NETWORK_SLICES = 6


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class voq_set_destroy_create_cscvi26250(unittest.TestCase):

    def setUp(self):

        self.device = sim_utils.create_device(1)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_voq_set_destroy_create_cscvi26250(self):
        base_vsc_vec = []
        # Create la_voq_set A:
        for slice_id in range(NETWORK_SLICES):
            base_vsc_vec.append(BASE_VSC + slice_id * VSC_SLICE_STEP)
        voq_set = self.device.create_voq_set(288, SET_SIZE, base_vsc_vec, 0, 0, 0)

        base_vsc_vec = []
        # Create la_voq_set B:
        for slice_id in range(NETWORK_SLICES):
            base_vsc_vec.append(BASE_VSC + 8 + slice_id * VSC_SLICE_STEP)
        voq_set2 = self.device.create_voq_set(296, SET_SIZE, base_vsc_vec, 0, 0, 0)

        # Destroy la_voq_set B:
        voq_set2.set_state(sdk.la_voq_set.state_e_DROPPING)
        self.device.destroy(voq_set2)

        # Recreate la_voq_set B:
        voq_set2 = self.device.create_voq_set(296, SET_SIZE, base_vsc_vec, 0, 0, 0)

    def tearDown(self):
        self.device.tearDown()


if __name__ == '__main__':
    unittest.main()
