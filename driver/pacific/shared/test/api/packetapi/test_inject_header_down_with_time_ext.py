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

#!/usr/bin/env python3

import leaba.sdk as sdk
import sim_utils
import unittest
from packet_test_defs import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class inject_header_down_with_time_ext_test(unittest.TestCase):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_header(self):

        hdr = InjectDown(type=7,
                         internal=0,
                         phb_tc=1,
                         phb_dp=1,
                         encap=7,
                         dest=0x12345,
                         counter_ptr=0x6789a,
                         l3_dlp=0xbcde,
                         down_nh=0x123,
                         ts_offset=0x45,
                         ts_opcode=2,
                         lm_opcode=4,
                         lm_offset=0x66) / InjectTimeExt(cpu_time=0xabcdef12)
        hdr_bytes = list(bytes(hdr))

        la_hdr = sdk.la_packet_inject_header_down_with_time_ext()
        la_hdr.type = 7
        la_hdr.phb_tc = 1
        la_hdr.phb_dp = 1
        la_hdr.encap = 7
        la_hdr.dest = 0x12345
        la_hdr.counter_ptr = 0x6789a
        la_hdr.l3_dlp = 0xbcde
        la_hdr.down_nh = 0x123
        la_hdr.ts_offset = 0x45
        la_hdr.ts_opcode = 2
        la_hdr.lm_opcode = 4
        la_hdr.lm_offset = 0x66
        la_hdr.ext_type = sdk.la_packet_types.LA_INJECT_HEADER_EXT_TYPE_TIME
        la_hdr.cpu_time = 0xabcdef12

        la_hdr_bytes = sdk.packet_header_bswap(la_hdr.raw)

        self.assertEqual(hdr_bytes, la_hdr_bytes)


if __name__ == '__main__':
    unittest.main()
