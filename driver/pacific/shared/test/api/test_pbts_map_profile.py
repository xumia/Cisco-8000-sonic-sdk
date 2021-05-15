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

from scapy.all import *
import sys
import unittest
from leaba import sdk
import ip_test_base
import topology as T
import packet_test_utils as U
from sdk_test_case_base import *
import decor

U.parse_ip_after_mpls()


class pbts_map_profile_tester(sdk_test_case_base):
    def setUp(self):
        super().setUp()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_set_get(self):
        max_offset = sdk.la_pbts_destination_offset()
        max_offset.value = 7

        profile = self.device.create_pbts_map_profile(sdk.la_pbts_map_profile.level_e_LEVEL_0, max_offset)

        fcid = sdk.la_fwd_class_id()
        for id in range(7):
            fcid.value = id
            offset = profile.get_mapping(fcid)
            # All mappings default to offset 0
            self.assertEqual(offset.value, 0)

        for id in range(7):
            fcid.value = id
            offset.value = id
            # Set all mapping 1:1 with FCID
            profile.set_mapping(fcid, offset)

        for id in range(7):
            fcid.value = id
            offset = profile.get_mapping(fcid)
            self.assertEqual(offset.value, id)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_size_check(self):
        max_offset = sdk.la_pbts_destination_offset()
        max_offset.value = 3

        # create profile with max size 4(offset 3)
        profile = self.device.create_pbts_map_profile(sdk.la_pbts_map_profile.level_e_LEVEL_0, max_offset)

        fcid = sdk.la_fwd_class_id()
        fcid.value = 7

        offset = sdk.la_pbts_destination_offset()
        offset.value = 4

        # Try use offset value(4) > max(3)
        with self.assertRaises(sdk.InvalException):
            profile.set_mapping(fcid, offset)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_unsupported_levels(self):
        max_offset = sdk.la_pbts_destination_offset()
        max_offset.value = 3

        # create profile at level 1
        with self.assertRaises(sdk.InvalException):
            profile = self.device.create_pbts_map_profile(sdk.la_pbts_map_profile.level_e_LEVEL_1, max_offset)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_pacific(), "Test is not yet enabled on Pacific")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_scale(self):
        max_offset = sdk.la_pbts_destination_offset()
        max_offset.value = 3

        profiles = []
        # create 4 profiles
        for id in range(4):
            profile = self.device.create_pbts_map_profile(sdk.la_pbts_map_profile.level_e_LEVEL_0, max_offset)
            profiles.append(profile)

        # Next profile create should fail
        with self.assertRaises(sdk.ResourceException):
            profile = self.device.create_pbts_map_profile(sdk.la_pbts_map_profile.level_e_LEVEL_0, max_offset)

        # Release one profile and create again. Should pass.
        self.device.destroy(profiles.pop())
        profile = self.device.create_pbts_map_profile(sdk.la_pbts_map_profile.level_e_LEVEL_0, max_offset)
        profiles.append(profile)


if __name__ == '__main__':
    unittest.main()
