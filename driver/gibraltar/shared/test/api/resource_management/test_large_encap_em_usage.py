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

import decor
from resource_handler_base import *
import decor

import unittest
import argparse
from leaba import sdk
import topology as T


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class large_encap_em_usage(resource_handler_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipUnless(decor.is_hw_device(), "Skip for SIM until accurate scale model is enabled")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_large_encap_em_usage(self):
        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_LARGE_ENCAP_EM
        used_during_device_init = [0, 0, 0]
        for slice_pair_id in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            rd.m_index.slice_pair_id = slice_pair_id
            res = self.device.get_resource_usage(rd)
            used_during_device_init[slice_pair_id] = res.used

        num_entries = 4

        # Clear traps. All traps are set at init, so clear some and add them back to
        # check usage

        for trap in range(sdk.LA_EVENT_IPV4_FIRST, (sdk.LA_EVENT_IPV4_FIRST + num_entries)):
            self.device.clear_trap_configuration(trap)

        # Check usage
        for slice_pair_id in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            rd.m_index.slice_pair_id = slice_pair_id
            res = self.device.get_resource_usage(rd)
            self.assertEqual(res.used, (used_during_device_init[slice_pair_id] - num_entries))

        # Add traps back.
        for trap in range(sdk.LA_EVENT_IPV4_FIRST, (sdk.LA_EVENT_IPV4_FIRST + num_entries)):
            self.device.set_trap_configuration(trap, 0, None, None, False, False, True, 0)

        # Check usage
        for slice_pair_id in range(T.NUM_SLICE_PAIRS_PER_DEVICE):
            rd.m_index.slice_pair_id = slice_pair_id
            res = self.device.get_resource_usage(rd)
            self.assertEqual(res.used, used_during_device_init[slice_pair_id])


if __name__ == '__main__':
    unittest.main()
