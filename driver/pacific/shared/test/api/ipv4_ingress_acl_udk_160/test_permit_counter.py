#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from scapy.all import *
from packet_test_utils import *
from ipv4_ingress_acl_udk_160_base import *
import sim_utils
import topology as T
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class permit_counter_tester(ipv4_ingress_acl_udk_160_base):

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_permit_counter(self):

        port_counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, port_counter)
        self.topology.rx_l3_ac.hld_obj.set_drop_counter_offset(sdk.la_stage_e_INGRESS, 1)

        self._test_permit_acl_counter()

        # Check ACE counters
        packet_count, byte_count = self.permit_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Check port counter
        packet_count, bytes = port_counter.read(0, True, True)  # Port counter should be incremented
        self.assertEqual(packet_count, 1)


if __name__ == '__main__':
    unittest.main()
