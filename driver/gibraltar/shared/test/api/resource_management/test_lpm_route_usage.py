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
import decor
from ip_routing.ip_routing_base import *
from resource_handler_base import *
import topology as T


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class lpm_route_usage(ip_routing_base, resource_handler_base):
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv4_test_base
    ipv6_impl = ip_test_base.ipv6_test_base
    DIPv4 = T.ipv4_addr('82.81.95.250')
    DIPv6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_lpm_route_usage(self):

        # define V4 and v6 descriptors
        v4_desc = sdk.la_resource_descriptor()
        v4_desc.m_resource_type = sdk.la_resource_descriptor.type_e_LPM_IPV4_ROUTES

        v6_desc = sdk.la_resource_descriptor()
        v6_desc.m_resource_type = sdk.la_resource_descriptor.type_e_LPM_IPV6_ROUTES

        # save initial usage
        v4_usage = self.device.get_resource_usage(v4_desc)
        initial_v4_used = v4_usage.used
        initial_v4_total = v4_usage.total
        prev_v4_available = initial_v4_total - initial_v4_used

        v6_usage = self.device.get_resource_usage(v6_desc)
        initial_v6_used = v6_usage.used
        initial_v6_total = v6_usage.total
        prev_v6_available = initial_v6_total - initial_v6_used

        # Insert entry in ipv4 lpm table.
        nh_null = self.l3_port_impl.glean_null_nh
        ipv4_prefix = self.ip_impl.build_prefix(self.DIPv4, length=16)
        self.ip_impl.add_route(self.topology.vrf, ipv4_prefix, nh_null, ip_routing_base.PRIVATE_DATA)

        # check usage
        v4_usage = self.device.get_resource_usage(v4_desc)          # get v4 usage
        v6_usage = self.device.get_resource_usage(v6_desc)          # get v6 usage

        self.assertEqual(v4_usage.used, initial_v4_used + 1)        # check v4 used

        current_v4_available = v4_usage.total - v4_usage.used
        current_v6_available = v6_usage.total - v6_usage.used
        self.assertLessEqual(current_v4_available, prev_v4_available)      # check v4 available
        self.assertLessEqual(current_v6_available, prev_v6_available)      # check v6 available

        prev_v4_available = current_v4_available
        prev_v6_available = current_v6_available

        # Remove entry from ipv4 lpm table.
        self.ip_impl.delete_route(self.topology.vrf, ipv4_prefix)

        # check usage
        v4_usage = self.device.get_resource_usage(v4_desc)          # get v4 usage
        v6_usage = self.device.get_resource_usage(v6_desc)          # get v6 usage

        self.assertEqual(v4_usage.used, initial_v4_used)        # check v4 used

        current_v4_available = v4_usage.total - v4_usage.used
        current_v6_available = v6_usage.total - v6_usage.used
        self.assertGreaterEqual(current_v4_available, prev_v4_available)      # check v4 available
        self.assertGreaterEqual(current_v6_available, prev_v6_available)      # check v6 available

        prev_v4_available = current_v4_available
        prev_v6_available = current_v6_available

        # Insert entry in ipv6 lpm table.
        ipv6_prefix = self.ipv6_impl.build_prefix(self.DIPv6, length=48)
        self.ipv6_impl.add_route(self.topology.vrf, ipv6_prefix, nh_null, ip_routing_base.PRIVATE_DATA)

        # check usage
        v4_usage = self.device.get_resource_usage(v4_desc)          # get v4 usage
        v6_usage = self.device.get_resource_usage(v6_desc)          # get v6 usage

        self.assertEqual(v6_usage.used, initial_v6_used + 1)        # check v6 used

        current_v4_available = v4_usage.total - v4_usage.used
        current_v6_available = v6_usage.total - v6_usage.used
        self.assertLessEqual(current_v4_available, prev_v4_available)      # check v4 available
        self.assertLessEqual(current_v6_available, prev_v6_available)      # check v6 available

        prev_v4_available = current_v4_available
        prev_v6_available = current_v6_available

        # Remove entry from ipv6 lpm table.
        self.ipv6_impl.delete_route(self.topology.vrf, ipv6_prefix)

        # check usage
        v4_usage = self.device.get_resource_usage(v4_desc)          # get v4 usage
        v6_usage = self.device.get_resource_usage(v6_desc)          # get v6 usage

        self.assertEqual(v6_usage.used, initial_v6_used)        # check v6 used

        current_v4_available = v4_usage.total - v4_usage.used
        current_v6_available = v6_usage.total - v6_usage.used
        self.assertGreaterEqual(current_v4_available, prev_v4_available)      # check v4 available
        self.assertGreaterEqual(current_v6_available, prev_v6_available)      # check v6 available


if __name__ == '__main__':
    unittest.main()
