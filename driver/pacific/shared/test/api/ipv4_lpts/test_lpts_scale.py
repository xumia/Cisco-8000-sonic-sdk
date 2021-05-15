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


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class lpts_scale(ipv4_lpts_base):

    #@unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_lpts_scale(self):
        lpts = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV4)

        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.protocol = 6
        k1.mask.ipv4.protocol = sdk.la_l4_protocol_e_RESERVED

        result = sdk.la_lpts_result()
        result.flow_type = 11
        result.punt_code = 120
        result.tc = 0
        result.dest = self.punt_dest2
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)

        for i in range(0, 512):
            self.push_lpts_entry(lpts, i, k1, result)

        count = lpts.get_count()
        self.assertEqual(count, 512)

        k2 = sdk.la_lpts_key()
        k2.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.protocol = 17
        k1.mask.ipv4.protocol = sdk.la_l4_protocol_e_RESERVED

        result = sdk.la_lpts_result()
        result.flow_type = 10
        result.punt_code = 11
        result.tc = 0
        result.dest = self.punt_dest2
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True, set_size=1)

        for i in range(0, 512):
            count = lpts.get_count()

            lpts.set(i, k2, result)

            lpts_entry_desc = lpts.get(i)
            self.assertEqual(lpts_entry_desc.key_val.val.ipv4.sip.s_addr, k2.val.ipv4.sip.s_addr)
            self.assertEqual(lpts_entry_desc.result.flow_type, result.flow_type)
            self.assertEqual(lpts_entry_desc.result.punt_code, result.punt_code)
            self.assertEqual(lpts_entry_desc.result.tc, result.tc)

            # No change in count
            count_tag = lpts.get_count()
            self.assertEqual(count_tag, count)

        lpts.clear()

        count = lpts.get_count()
        self.assertEqual(count, 0)


if __name__ == '__main__':
    unittest.main()
