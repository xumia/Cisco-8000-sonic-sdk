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
from leaba import sdk
from scapy.all import *
from packet_test_utils import *
from ingress_acl_base import *
import sim_utils
import topology as T
import decor

MAX_V4_ENTRIES = 3 * 512 - 7
V4_ENTRIES_TO_ERASE = 512
V6_ENTRIES = 112


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class acl_dynamic_realocation(ingress_acl_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skip("Test is skipped because of slow performance with dynamic allocation")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_acl_dynamic_realocation(self):
        ipv4_acl = self.create_ipv4_empty_acl()

        count = ipv4_acl.get_count()
        self.assertEqual(count, 0)

        acl_group = []
        acl_group = self.device.create_acl_group()

        ipv4_acls = []
        ipv4_acls.append(ipv4_acl)
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        for i in range(MAX_V4_ENTRIES, count, -1):
            # Inserting in high position causes the ACL to be inserted at the highest line+1
            # This avoids the need to push all existing entries up, and makes the test run much faster
            self.insert_ipv4_ace(ipv4_acl, False, False, None, position=100000)

        count = ipv4_acl.get_count()
        self.assertEqual(count, MAX_V4_ENTRIES)

        for i in range(1, V4_ENTRIES_TO_ERASE, 1):
            ipv4_acl.erase(512)
        count = ipv4_acl.get_count()
        self.assertEqual(count, MAX_V4_ENTRIES - V4_ENTRIES_TO_ERASE + 1)

        ipv6_acl = self.create_ipv6_empty_acl()
        count = ipv6_acl.get_count()
        self.assertEqual(count, 0)

        ipv6_acls = []
        ipv6_acls.append(ipv6_acl)
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        for i in range(1, V6_ENTRIES):
            self.insert_ipv6_ace(ipv6_acl, False, False, None, position=100000)

        count = ipv4_acl.get_count()
        self.assertEqual(count, MAX_V4_ENTRIES - V4_ENTRIES_TO_ERASE + 1)
        count = ipv6_acl.get_count()
        self.assertEqual(count, V6_ENTRIES - 1)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)


if __name__ == '__main__':
    unittest.main()
