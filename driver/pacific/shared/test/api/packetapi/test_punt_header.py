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
class punt_header_test(unittest.TestCase):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_header(self):

        hdr = Punt(next_header=0x11,
                   fwd_header_type=2,
                   next_header_offset=0xee,
                   source=3,
                   code=0xdd,
                   lpts_flow_type=0xcc,
                   source_sp=0x1234,
                   destination_sp=0x1234,
                   source_lp=0x56789,
                   destination_lp=0xabcde,
                   relay_id=0x2bbb,
                   time_stamp=0x123456789abcdef0,
                   receive_time=0xabcdef12)
        hdr_bytes = list(bytes(hdr))

        la_hdr = sdk.la_packet_punt_header()
        la_hdr.next_header = 0x11
        la_hdr.fwd_header_type = 2
        la_hdr.next_header_offset = 0xee
        la_hdr.source = 3
        la_hdr.code = 0xdd
        la_hdr.lpts_flow_type = 0xcc
        la_hdr.source_sp = 0x1234
        la_hdr.destination_sp = 0x1234
        la_hdr.source_lp = 0x56789
        la_hdr.destination_lp = 0xabcde
        la_hdr.relay_id = 0x2bbb
        la_hdr.time_stamp = 0x123456789abcdef0
        la_hdr.receive_time = 0xabcdef12

        la_hdr_bytes = sdk.packet_header_bswap(la_hdr.raw)

        self.assertEqual(hdr_bytes, la_hdr_bytes)


if __name__ == '__main__':
    unittest.main()
