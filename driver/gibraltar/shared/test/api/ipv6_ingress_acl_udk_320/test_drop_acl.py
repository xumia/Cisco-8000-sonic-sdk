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

import decor
import unittest
from leaba import sdk
import ip_test_base
from packet_test_utils import *
from ipv6_ingress_acl_udk_320_base import *
from scapy.all import *
import sim_utils
import topology as T


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class drop_acl(ipv6_ingress_acl_udk_320_base):

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_drop_acl(self):
        acl1 = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        ipv6_acls = []
        ipv6_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        # Add drop ACE
        self.insert_drop_ace(acl1)

        port_counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, port_counter)
        self.topology.rx_l3_ac.hld_obj.set_drop_counter_offset(sdk.la_stage_e_INGRESS, 1)

        # read and clear port counter for drop test
        packet_count, bytes = port_counter.read(0, True, True)
        # Test dropped packet
        self.do_test_route_default_with_drop()

        # Check counter
        packet_count, byte_count = self.inserted_drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 0)

        packet_count, byte_count = self.inserted_drop_counter.read(1, True, True)
        self.assertEqual(packet_count, 1)

        # Port counter shouldn't be incremented if the packet was dropped
        packet_count, bytes = port_counter.read(0, True, True)
        self.assertEqual(packet_count, 0)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        self.drop_counter = None
        # Test default route
        self.do_test_route_default()


if __name__ == '__main__':
    unittest.main()
