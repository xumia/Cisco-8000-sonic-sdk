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
@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
class lpm_usage(ip_routing_base, resource_handler_base):
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl = ip_test_base.ipv4_test_base

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_lpm_usage(self):
        r_desc_in = sdk.la_resource_descriptor()
        r_desc_in.m_resource_type = sdk.la_resource_descriptor.type_e_LPM
        r_desc_out = self.device.get_resource_usage(r_desc_in)

        prev_lpm_used_entries = r_desc_out.used

        r_desc_in.m_resource_type = sdk.la_resource_descriptor.type_e_LPM_IPV4_ROUTES
        r_desc_out = self.device.get_resource_usage(r_desc_in)
        prev_lpm_ipv4_used_entries = r_desc_out.used

        # Insert 1k entries in ipv4 lpm table.
        count = 1000
        nh_null = self.l3_port_impl.glean_null_nh
        for i in range(0, count):
            ipv4_prefix = sdk.la_ipv4_prefix_t()
            ipv4_prefix.addr.s_addr = (0xc0a80a00 + (i << 8))
            ipv4_prefix.length = 24
            self.ip_impl.add_route(self.topology.vrf, ipv4_prefix, nh_null, ip_routing_base.PRIVATE_DATA)

        r_desc_out = self.device.get_resource_usage(r_desc_in)
        self.assertEqual(r_desc_out.used, prev_lpm_ipv4_used_entries + count)

        r_desc_in.m_resource_type = sdk.la_resource_descriptor.type_e_LPM
        r_desc_out = self.device.get_resource_usage(r_desc_in)
        self.assertGreater(r_desc_out.used, prev_lpm_used_entries)


if __name__ == '__main__':
    unittest.main()
