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

import unittest
from leaba import sdk
from packet_test_utils import *
from scapy.all import *
from bfd_ipv6_base import *
import decor
import topology as T
import ip_test_base
import lldcli


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
class bfd_inject_ipv6_single_hop(bfd_ipv6_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bfd_inject_ipv6_single_hop(self):
        self.single_hop_session.set_transmit_interval(3300)

        trigger_npu_host_and_compare(self, self.device, self.single_hop_session.get_internal_id() * 2,
                                     OUTPUT_SH_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Session tx counter is at offset 0
        counter = self.single_hop_session.get_counter()
        packets, bytes = counter.read(0, True, True)
        self.assertEqual(packets, 1)

        # Test that set_inject_down_destination can handle a null nh.
        # 1. Get the original nh.
        # 2. Set inject down nh to null, which should not cause any issues.
        # 3. Rewrite the original nh.
        # 4. Reinject packet and verify output.
        nh = self.single_hop_session.get_inject_down_destination()
        self.single_hop_session.set_inject_down_destination(None)
        self.single_hop_session.set_inject_down_destination(nh)

        trigger_npu_host_and_compare(self, self.device, self.single_hop_session.get_internal_id() * 2,
                                     OUTPUT_SH_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Session tx counter is at offset 0
        packets, bytes = counter.read(0, True, True)
        self.assertEqual(packets, 1)


if __name__ == '__main__':
    unittest.main()
