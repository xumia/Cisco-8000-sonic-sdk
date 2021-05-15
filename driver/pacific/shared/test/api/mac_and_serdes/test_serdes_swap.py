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

import os
import sim_utils
import unittest
from leaba import sdk
import packet_test_utils
import re
from mac_and_serdes_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Cannot do WB if device is uninitialized.")
class serdes_swap(mac_and_serdes_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not applicable on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_serdes_swap(self):

        # Leave Slice 0, IFG 0 as default
        # On Slice 0, IFG 1 do the following: Swap the source of all SerDes's, and invert all polarity

        swap_all_list_16 = [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12]
        swap_all_list_18 = [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 17, 16]
        swap_all_list_24 = [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 17, 16, 19, 18, 20, 21, 22, 23]

        # Complete initialization
        self.device.initialize(sdk.la_device.init_phase_e_DEVICE)

        for sid in self.device.get_used_slices():
            try:
                self.device.set_slice_mode(sid, sdk.la_slice_mode_e_NETWORK)
            except sdk.BaseException:
                raise exceptions.AssertionError('Slice is {}'.format(sid))

        for slice_id in self.device.get_used_slices():
            for ifg_id in range(2):
                serdes_count = self.device.get_num_of_serdes(slice_id, ifg_id)

                # Do the settings only on IFG 0 and test for default values on IFG 1
                if ifg_id == 1:
                    continue

                # Swap SerDes source
                swap_all_list = None
                if serdes_count == 16:
                    swap_all_list = swap_all_list_16
                elif serdes_count == 18:
                    swap_all_list = swap_all_list_18
                elif serdes_count == 24:
                    swap_all_list = swap_all_list_24
                self.device.set_serdes_source(slice_id, ifg_id, swap_all_list)

                # Invert polarity
                for serdes_id in range(serdes_count):
                    self.device.set_serdes_polarity_inversion(
                        slice_id, ifg_id, serdes_id, sdk.la_serdes_direction_e_RX, True)
                    self.device.set_serdes_polarity_inversion(
                        slice_id, ifg_id, serdes_id, sdk.la_serdes_direction_e_TX, True)

        self.device.initialize(sdk.la_device.init_phase_e_TOPOLOGY)

        # Check
        for slice_id in self.device.get_used_slices():
            for ifg_id in range(2):
                serdes_count = self.device.get_num_of_serdes(slice_id, ifg_id)

                swap_list = self.device.get_serdes_source(slice_id, ifg_id)
                self.assertEqual(len(swap_list), serdes_count)

                # On IFG 1 the settings are the default
                if ifg_id == 1:
                    for serdes_id in range(serdes_count):
                        self.assertEqual(serdes_id, swap_list[serdes_id])

                    for serdes_id in range(serdes_count):
                        invert = self.device.get_serdes_polarity_inversion(
                            slice_id, ifg_id, serdes_id, sdk.la_serdes_direction_e_RX)
                        self.assertEqual(invert, False)
                        invert = self.device.get_serdes_polarity_inversion(
                            slice_id, ifg_id, serdes_id, sdk.la_serdes_direction_e_TX)
                        self.assertEqual(invert, False)
                else:
                    # Swap SerDes source
                    swap_all_list = None
                    if serdes_count == 16:
                        swap_all_list = swap_all_list_16
                    elif serdes_count == 18:
                        swap_all_list = swap_all_list_18
                    elif serdes_count == 24:
                        swap_all_list = swap_all_list_24

                    for serdes_id in range(serdes_count):
                        self.assertEqual(swap_all_list[serdes_id], swap_list[serdes_id])

                    for serdes_id in range(serdes_count):
                        invert = self.device.get_serdes_polarity_inversion(
                            slice_id, ifg_id, serdes_id, sdk.la_serdes_direction_e_RX)
                        self.assertEqual(invert, True)
                        invert = self.device.get_serdes_polarity_inversion(
                            slice_id, ifg_id, serdes_id, sdk.la_serdes_direction_e_TX)
                        self.assertEqual(invert, True)


if __name__ == '__main__':
    unittest.main()
