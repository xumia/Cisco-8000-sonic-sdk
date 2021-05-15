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

# Test covering CSCvj54143.
#
# Creates a VOQ set in a distributed system (3 network slices, 3 fabric
# slices) that's just below the maximum VOQ GID for the device.

import decor
import unittest
from leaba import sdk
import sim_utils


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class high_voq_creation(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1, slice_modes=sim_utils.LINECARD_3N_3F_DEV)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_high_voq_creation(self):
        max_voqs = self.device.get_limit(sdk.limit_type_e_DEVICE__NUM_SYSTEM_VOQS)

        dest_dev = 4
        dest_slice = 0
        dest_ifg = 0
        base_voq = max_voqs - 8
        base_vsc = [4944, 4960, 4976, sdk.LA_VSC_GID_INVALID, sdk.LA_VSC_GID_INVALID, sdk.LA_VSC_GID_INVALID]

        self.device.create_voq_set(base_voq, 8, base_vsc, dest_dev, dest_slice, dest_ifg)


if __name__ == '__main__':
    unittest.main()
