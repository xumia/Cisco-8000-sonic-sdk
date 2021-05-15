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

import unittest
from packet_test_utils import *
from scapy.all import *
from og_lpts_v6_base import *
import topology as T
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class basic_lpts(og_lpts_v6_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_basic_lpts(self):
        lpts = self.create_lpts_instance()
        self.setup_forus_dest()
        run_and_compare(self, self.device,
                        INPUT_PACKET_UC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_UC, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)
        run_and_compare(self, self.device,
                        INPUT_PACKET_UC2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_UC2, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)
        # Test case needs to be reworked for SIP prefix matching
        # run_and_compare(self, self.device,
        #                 INPUT_PACKET_UC3, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
        #                 PUNT_PACKET_UC3, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)
        run_and_compare(self, self.device,
                        INPUT_PACKET_UC5, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_UC5, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)
        run_and_compare(self, self.device,
                        INPUT_PACKET_UC6, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET_UC6, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)
        lpts.clear()
        count = lpts.get_count()
        self.assertEqual(count, 0)


if __name__ == '__main__':
    unittest.main()
