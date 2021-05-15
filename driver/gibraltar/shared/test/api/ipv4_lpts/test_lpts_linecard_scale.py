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
from packet_test_utils import *
from scapy.all import *
from ipv4_lpts_base import *
import sim_utils
import topology as T
import ip_test_base

MAX_LPTS_V4_ENTRIES = 3 * 1024 - 3


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class lpts_linecard_scale(ipv4_lpts_base):
    ipv4_lpts_base.slice_modes = sim_utils.LINECARD_3N_3F_DEV

    #@unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_lpts_linecard_scale(self):
        lpts = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV4)

        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.protocol = 6
        k1.mask.ipv4.protocol = sdk.la_l4_protocol_e_RESERVED

        result = sdk.la_lpts_result()
        result.flow_type = 11
        result.punt_code = 120
        result.dest = self.punt_dest2
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)

        for i in range(0, MAX_LPTS_V4_ENTRIES):
            self.push_lpts_entry(lpts, i, k1, result)

        count = lpts.get_count()
        self.assertEqual(count, MAX_LPTS_V4_ENTRIES)

        lpts.clear()

        count = lpts.get_count()
        self.assertEqual(count, 0)


if __name__ == '__main__':
    unittest.main()
