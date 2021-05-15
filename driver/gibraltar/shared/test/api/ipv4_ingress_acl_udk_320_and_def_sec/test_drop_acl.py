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
from ipv4_ingress_acl_udk_320_and_def_sec_base import *
import sim_utils
import topology as T
import decor


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
class drop_acl(ipv4_ingress_acl_udk_320_and_def_sec_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic5(), "RTF is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_drop_acl(self):
        acl_def_sec = self.create_simple_sec_acl_for_def_sec()

        ipv4_acls1 = []
        ipv4_acls1.append(acl_def_sec)
        acl_group1 = []
        acl_group1 = self.device.create_acl_group()
        acl_group1.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls1)
        self.topology.rx_l3_ac1.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group1)

        self.insert_drop_ace_for_def_sec(acl_def_sec)

        acl_udk = self.create_simple_sec_acl_for_udk()

        # Test default route
        self.do_test_route_default_for_udk()  # udk

        ipv4_acls2 = []
        ipv4_acls2.append(acl_udk)
        acl_group2 = []
        acl_group2 = self.device.create_acl_group()
        acl_group2.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls2)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group2)

        self.do_test_route_default_with_acl_for_udk()  # udk

        # Add drop ACE
        self.insert_drop_ace_for_udk(acl_udk)

        port_counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, port_counter)
        self.topology.rx_l3_ac.hld_obj.set_drop_counter_offset(sdk.la_stage_e_INGRESS, 1)

        # Test dropped packet
        self.do_test_route_default_with_drop_for_udk()  # udk

        # test dropped packet for default acl.
        self.do_test_drop_ace_for_def_sec()

        # Check counters
        packet_count, byte_count = self.inserted_drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 0)

        packet_count, byte_count = self.inserted_drop_counter.read(1, True, True)
        self.assertEqual(packet_count, 1)

        packet_count, bytes = port_counter.read(0, True, True)  # Port counter shouldn't be incremented if the packet was dropped
        self.assertEqual(packet_count, 0)

        # Detach UDK ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default_for_udk()


if __name__ == '__main__':
    unittest.main()
