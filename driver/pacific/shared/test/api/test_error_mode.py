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
from leaba import sdk as sdk


@unittest.skipIf(decor.is_hw_device(), "Skip for HW device.")
class error_mode_uint_test(unittest.TestCase):

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_error_mode(self):
        # Check device creation (success and failing) in code mode
        sdk.set_error_mode(sdk.error_mode_e_CODE)

        # 1a. Attempt to create a valid device.
        #     Ensure status indicates success and device is not None.
        (status, device) = sdk.la_create_device('/dev/testdev', 17)
        self.assertEqual(status, sdk.la_status_e_SUCCESS)
        self.assertNotEqual(device, None)
        self.assertEqual(device.get_id(), 17)
        sdk.la_destroy_device(device)

        # 1b. Attempt to create a device with an out-of-range ID.
        #     Ensure status is EOUTOFRANGE and device is None.
        (status, device) = sdk.la_create_device('/dev/testdev', 1000)
        self.assertEqual(status, sdk.la_status_e_E_OUTOFRANGE)
        self.assertEqual(device, None)

        # 1c. Attempt to create a device with NULL path.
        (status, device) = sdk.la_create_device(None, 17)
        self.assertEqual(status, sdk.la_status_e_E_INVAL)
        self.assertEqual(device, None)

        # Check device creation (success and failing) in exception mode
        sdk.set_error_mode(sdk.error_mode_e_EXCEPTION)

        # 2a. Attempt to create a valid device.
        #     Ensure created device is not None.
        device = sdk.la_create_device('/dev/testdev', 17)
        self.assertNotEqual(device, None)
        self.assertEqual(device.get_id(), 17)
        sdk.la_destroy_device(device)

        # 2b. Attempt to create a device with an out-of-range ID.
        # Ensure an exception is generated correctly.
        try:
            device = sdk.la_create_device('/dev/testdev', 1000)
            self.fail()
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_OUTOFRANGE)


if __name__ == '__main__':
    unittest.main()
