#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import decor
import topology as T
from resource_handler_base import *

MC_GROUP_ADDR = T.ipv6_addr('ff31:0:0:0:0:1:ffe8:658f')
MC_GROUP_GID = 0x13
SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
SIP2 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:3333')


@unittest.skipIf(True, "NPL does not support for this test")
@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class vrf_compressed_counters_usage(resource_handler_base):

    def setUp(self):
        super().setUp()

        self.topology = T.topology(self, self.device)
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)
        self.counter1 = self.device.create_counter(1)  # set_size=1
        self.counter2 = self.device.create_counter(1)  # set_size=1
        self.counter3 = self.device.create_counter(2)  # set_size=2 is Invalid for route stats counter.

        self.mc_group = self.device.create_ip_multicast_group(MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)

    @unittest.skipIf(True, "NPL does not support for this test")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vrf_compressed_counters_usage(self):
        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_VRF_COMPRESSED_COUNTERS
        res = self.device.get_resource_usage(rd)
        used_during_device_init = res.used

        # Test invalid counter set size
        with self.assertRaises(sdk.InvalException):
            self.topology.vrf.hld_obj.add_ipv6_multicast_route(
                SIP.hld_obj,
                MC_GROUP_ADDR.hld_obj,
                self.mc_group,
                self.l3_port_impl.rx_port.hld_obj,
                False,
                False,
                self.counter3)

        # Add 2 (s,g) route entries with counters.
        num_entries_added = 2
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            SIP.hld_obj, MC_GROUP_ADDR.hld_obj, self.mc_group, self.l3_port_impl.rx_port.hld_obj, False, False, self.counter1)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            SIP2.hld_obj, MC_GROUP_ADDR.hld_obj, self.mc_group, self.l3_port_impl.rx_port.hld_obj, False, False, self.counter2)
        # Check usage.
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, (used_during_device_init + num_entries_added))

        # Modify one (s,g) to have no counter.
        self.topology.vrf.hld_obj.modify_ipv6_multicast_route(
            SIP2.hld_obj, MC_GROUP_ADDR.hld_obj, self.mc_group, self.l3_port_impl.rx_port.hld_obj, False, False, None)
        # Check usage.
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, (used_during_device_init + num_entries_added - 1))

        # Modify (s,g) to swap counter sets.
        self.topology.vrf.hld_obj.modify_ipv6_multicast_route(
            SIP.hld_obj, MC_GROUP_ADDR.hld_obj, self.mc_group, self.l3_port_impl.rx_port.hld_obj, False, False, self.counter2)
        # Check usage.
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, (used_during_device_init + num_entries_added - 1))

        # Delete 2 (s,g) route entries.
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(SIP.hld_obj, MC_GROUP_ADDR.hld_obj)
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(SIP2.hld_obj, MC_GROUP_ADDR.hld_obj)
        # Check usage.
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, used_during_device_init)


if __name__ == '__main__':
    unittest.main()
