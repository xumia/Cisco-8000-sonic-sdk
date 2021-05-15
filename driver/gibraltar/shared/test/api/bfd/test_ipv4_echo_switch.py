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
class ipv4_echo_switch(bfd_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_echo_switch(self):

        run_and_compare(self, self.device,
                        self.INPUT_IPV4_ECHO_SWITCH_PACKET, self.s_rx_slice, self.s_rx_ifg, self.s_first_serdes_p3,
                        self.OUTPUT_IPV4_ECHO_SWITCH_PACKET, self.s_rx_slice, self.s_rx_ifg, self.s_first_serdes_p3)


if __name__ == '__main__':
    unittest.main()
