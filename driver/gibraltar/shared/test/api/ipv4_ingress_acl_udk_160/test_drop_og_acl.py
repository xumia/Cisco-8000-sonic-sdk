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
from ipv4_ingress_acl_og_160_base import *
import sim_utils
import topology as T
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class drop_og_acl(ipv4_ingress_acl_og_160_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_drop_og_acl(self):
        # Test regular port
        self._test_drop_og_acl()

        # Test svi
        self._test_drop_og_acl(True)

    def _test_drop_og_acl(self, is_svi=False):
        if (is_svi):
            self.delete_default_route()
            self.add_default_route(is_svi)
        is_udk = True
        is_first = True
        l3_port = self.topology.rx_svi if is_svi else self.topology.rx_l3_ac
        # This loop first tests OG ACLs, then on the next iteration
        # tests non-udk default ACLs.  This verifies support for
        # both in the same ucode load
        for udk_default_loops in range(2):
            acl1 = self.create_simple_sec_acl(is_udk, is_svi)

            # Test default route
            self.do_test_route_default(is_svi)
            ipv4_acls = []
            ipv4_acls.append(acl1)
            acl_group = []
            acl_group = self.device.create_acl_group()
            acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
            l3_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
            self.do_test_route_default_with_acl(is_svi)

            # Add drop ACE
            self.drop_counter = self.insert_drop_ace(acl1)

            if (is_first):
                port_counter = self.device.create_counter(8)
                l3_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, port_counter)
                l3_port.hld_obj.set_drop_counter_offset(sdk.la_stage_e_INGRESS, 1)
                if_first = False

            # Test dropped packet
            self.do_test_route_default_with_drop(is_svi)

            # Check counters
            packet_count, byte_count = self.drop_counter.read(0, True, True)
            self.assertEqual(packet_count, 0)

            packet_count, byte_count = self.drop_counter.read(1, True, True)
            self.assertEqual(packet_count, 1)

            # Port counter shouldn't be incremented if the packet was dropped
            packet_count, bytes = port_counter.read(0, True, True)
            self.assertEqual(packet_count, 0)

            # Detach ACL
            l3_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
            self.device.destroy(acl_group)
            self.device.destroy(acl1)

            # Test default route
            self.do_test_route_default(is_svi)
            is_udk = False


if __name__ == '__main__':
    unittest.main()
