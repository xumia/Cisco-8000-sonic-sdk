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

import decor
import unittest
from leaba import sdk
from scapy.all import *
from packet_test_utils import *
from ipv4_ingress_acl_base import *
import sim_utils
import topology as T

MAX_ACL_ENTRIES = 5 * 1024 - 7


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
class test_ipv4_ingress_acl_lc(ipv4_ingress_acl_base):
    ipv4_ingress_acl_base.slice_modes = sim_utils.LINECARD_3N_3F_DEV

    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_drop_acl_lc(self):
        acl1 = self.create_simple_sec_acl()

        self.do_test_route_default()

        ipv4_acls = []
        ipv4_acls.append(acl1)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        # Add drop ACE
        self.insert_drop_ace(acl1)

        port_counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, port_counter)
        self.topology.rx_l3_ac.hld_obj.set_drop_counter_offset(sdk.la_stage_e_INGRESS, 1)

        # Test dropped packet
        self.do_test_route_default_with_drop()

        # Check counters
        packet_count, byte_count = self.drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 0)

        packet_count, byte_count = self.drop_counter.read(1, True, True)
        self.assertEqual(packet_count, 1)

        packet_count, bytes = port_counter.read(0, True, True)  # Port counter shouldn't be incremented if the packet was dropped
        self.assertEqual(packet_count, 0)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()

    @unittest.skip("Test is skipped because of slow performance with dynamic allocation")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "RTF is not yet enabled on PL")
    def test_acl_linecard_scale(self):
        T.RX_SLICE = 0
        acl = self.create_simple_sec_acl()
        count = acl.get_count()

        ipv4_acls = []
        ipv4_acls.append(acl)
        acl_group = []
        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        for i in range(count, MAX_ACL_ENTRIES):
            # Inserting in high position causes the ACL to be inserted at the highest line+1
            # This avoids the need to push all existing entries up, and makes the test run much faster
            self.insert_ace(acl, False, False, None, position=1000000)

        count = acl.get_count()
        self.assertEqual(count, MAX_ACL_ENTRIES)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)


if __name__ == '__main__':
    unittest.main()
