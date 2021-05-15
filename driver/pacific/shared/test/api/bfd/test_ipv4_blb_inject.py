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
from bfd_base import *
import decor
import topology as T
import ip_test_base


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
class bfd_inject_ipv4_blb(bfd_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bfd_inject_ipv4_blb(self):
        self.bfd_ipv4_blb_session.set_transmit_interval(3300)

        out_slice, out_ifg, out_pif = self.calculate_expected_output(self.OUTPUT_IPV4_BLB_PACKET)

        trigger_npu_host_and_compare(self, self.device, self.bfd_ipv4_blb_session.get_internal_id() * 2,
                                     self.OUTPUT_IPV4_BLB_PACKET,
                                     out_slice, out_ifg, out_pif)

        # Session tx counter is at offset 0
        counter = self.bfd_ipv4_blb_session.get_counter()
        packets, bytes = counter.read(0, True, True)
        self.assertEqual(packets, 1)

        # Send again but with the packet injected with a local label.
        # Set the ttl to zero so that it gets decremented to 255. This is what gets written to the inner IP packet.
        self.bfd_ipv4_blb_session.set_mpls_encap(self.out_label, 0)

        out_slice, out_ifg, out_pif = self.calculate_expected_output(self.OUTPUT_IPV4_BLB_ENCAP_PACKET, True)

        trigger_npu_host_and_compare(self, self.device, self.bfd_ipv4_blb_session.get_internal_id() * 2,
                                     self.OUTPUT_IPV4_BLB_ENCAP_PACKET,
                                     out_slice, out_ifg, out_pif)

        # Session tx counter is at offset 0
        counter = self.bfd_ipv4_blb_session.get_counter()
        packets, bytes = counter.read(0, True, True)
        self.assertEqual(packets, 1)


if __name__ == '__main__':
    unittest.main()
