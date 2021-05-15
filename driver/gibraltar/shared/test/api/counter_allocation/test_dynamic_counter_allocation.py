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
import test_hldcli
import unittest
from leaba import hldcli
from leaba import sdk
import sdk_test_case_base


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_pacific(), "Pacific does not allocate counters dynamically")
@unittest.skipIf(decor.is_gibraltar(), "Gibraltar does not allocate counters dynamically")
class test_dynamic_counter_allocation(sdk_test_case_base.sdk_test_case_base):

    def setUp(self):
        super().setUp()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_dynamic_allocation(self):
        INGRESS_COUNTER_USER_TYPES = [
            hldcli.COUNTER_USER_TYPE_L2_AC_PORT,
            hldcli.COUNTER_USER_TYPE_L3_AC_PORT,
            hldcli.COUNTER_USER_TYPE_TUNNEL,
            hldcli.COUNTER_USER_TYPE_SVI_OR_ADJACENCY,
            hldcli.COUNTER_USER_TYPE_MPLS_DECAP,
            hldcli.COUNTER_USER_TYPE_DROP,
            hldcli.COUNTER_USER_TYPE_TRAP,
            hldcli.COUNTER_USER_TYPE_SEC_ACE,
            hldcli.COUNTER_USER_TYPE_BFD,
            hldcli.COUNTER_USER_TYPE_VOQ,
            hldcli.COUNTER_USER_TYPE_METER,
            hldcli.COUNTER_USER_TYPE_QOS
        ]

        EGRESS_COUNTER_USER_TYPES = [
            hldcli.COUNTER_USER_TYPE_L2_AC_PORT,
            hldcli.COUNTER_USER_TYPE_L3_AC_PORT,
            hldcli.COUNTER_USER_TYPE_DROP,
            hldcli.COUNTER_USER_TYPE_TUNNEL,
            hldcli.COUNTER_USER_TYPE_SVI_OR_ADJACENCY,
            hldcli.COUNTER_USER_TYPE_MPLS_NH,
            hldcli.COUNTER_USER_TYPE_MPLS_GLOBAL,
            hldcli.COUNTER_USER_TYPE_L2_MIRROR,
            hldcli.COUNTER_USER_TYPE_QOS,
            hldcli.COUNTER_USER_TYPE_TRAP,
            hldcli.COUNTER_USER_TYPE_ERSPAN,
            hldcli.COUNTER_USER_TYPE_SEC_ACE,
            hldcli.COUNTER_USER_TYPE_SR_DM
        ]

        # Get reference to counter_manager
        counter_manager = test_hldcli.la_device_get_counter_bank_manager(self.device)

        original_size = counter_manager.size()

        # Allocate new counters (ingress)
        counters = []
        for counter_user_type in INGRESS_COUNTER_USER_TYPES:
            counter_allocation = hldcli.counter_allocation()
            counter_manager.allocate(
                is_slice_pair=True,
                direction=hldcli.COUNTER_DIRECTION_INGRESS,
                set_size=1,
                slice_id=0,
                user_type=counter_user_type,
                out_counter_allocation=counter_allocation)
            counters.append(counter_allocation)

        # Release counters
        for counter_user_type, counter in zip(INGRESS_COUNTER_USER_TYPES, counters):
            counter_manager.release(counter_user_type, counter)

        size = counter_manager.size()
        self.assertEqual(size, original_size, "Counter manager size did not return to original size")

        # Allocate new counters (egress)
        counters = []
        for counter_user_type in EGRESS_COUNTER_USER_TYPES:
            counter_allocation = hldcli.counter_allocation()
            counter_manager.allocate(
                is_slice_pair=True,
                direction=hldcli.COUNTER_DIRECTION_EGRESS,
                set_size=1,
                slice_id=0,
                user_type=counter_user_type,
                out_counter_allocation=counter_allocation)
            counters.append(counter_allocation)

        # Release counters
        for counter_user_type, counter in zip(EGRESS_COUNTER_USER_TYPES, counters):
            counter_manager.release(counter_user_type, counter)

        size = counter_manager.size()
        self.assertEqual(size, original_size, "Counter manager size did not return to original size")


if __name__ == "__main__":
    unittest.main()
