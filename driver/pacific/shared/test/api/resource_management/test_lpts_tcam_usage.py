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
import argparse
from leaba import sdk
from packet_test_utils import *
from scapy.all import *
from ipv4_lpts.ipv4_lpts_base import *
from ipv6_lpts.ipv6_lpts_base import *
import decor
import topology as T
import ip_test_base

NETWORK_SLICES = 6
args = None


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class lpts_tcam_usage(ipv4_lpts_base, ipv6_lpts_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_lpts_tcam_usage(self):
        lpts_v4 = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV4)
        lpts_v6 = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV6)

        k1 = sdk.la_lpts_key()
        k1.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k1.val.ipv4.protocol = 6
        k1.mask.ipv4.protocol = sdk.la_l4_protocol_e_RESERVED

        k2 = sdk.la_lpts_key()
        k2.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        k2.val.ipv6.protocol = 255
        k2.mask.ipv6.protocol = 0

        result = sdk.la_lpts_result()
        result.flow_type = 11
        result.punt_code = 120
        result.tc = 0
        result.meter = T.create_meter_set(self, self.device, is_statistical=True, set_size=1)
        result.dest = self.punt_dest2

        add_entries = 10
        for i in range(0, add_entries):
            result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True, set_size=1)
            self.push_lpts_entry(lpts_v4, i, k1, result)

        for i in range(0, add_entries):
            result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True, set_size=1)
            self.push_lpts_entry(lpts_v6, i, k2, result)

        count = lpts_v4.get_count()
        self.assertEqual(count, add_entries)

        count = lpts_v6.get_count()
        self.assertEqual(count, add_entries)

        r_desc_in = sdk.la_resource_descriptor()
        # Verify total entries for ipv4/ipv6 lpts table in each slice via resource usage
        r_desc_in.m_resource_type = sdk.la_resource_descriptor.type_e_IPV4_LPTS
        for slice_id in self.device.get_used_slices():
            r_desc_in.m_index.slice_id = slice_id
            r_desc_out = self.device.get_resource_usage(r_desc_in)
            self.assertEqual(r_desc_out.used, add_entries)

        r_desc_in.m_resource_type = sdk.la_resource_descriptor.type_e_IPV6_LPTS
        for slice_id in self.device.get_used_slices():
            r_desc_in.m_index.slice_id = slice_id
            r_desc_out = self.device.get_resource_usage(r_desc_in)
            self.assertEqual(r_desc_out.used, add_entries)

        if args.verbose:
            # Print total size of the ipv4 lpts table in each slice
            r_desc_in.m_resource_type = sdk.la_resource_descriptor.type_e_IPV4_LPTS
            for slice_id in self.device.get_used_slices():
                r_desc_in.m_index.slice_id = slice_id
                r_desc_out = self.device.get_resource_usage(r_desc_in)
                print('IPv4 LPTS: slice=%d total=%d used=%d' %
                      (r_desc_in.m_index.slice_id, r_desc_out.total, r_desc_out.used))

            # Print total size of the ipv4 sec acl table in each slice (logically ipv4 sec acl and ipv4 lpts share table)
            r_desc_in.m_resource_type = sdk.la_resource_descriptor.type_e_TCAM_INGRESS_NARROW_POOL_0
            for slice_id in self.device.get_used_slices():
                r_desc_in.m_index.slice_id = slice_id
                r_desc_out = self.device.get_resource_usage(r_desc_in)
                print('Ingress IPv4 NARROW DB1 INTERFACE0 TCAM : slice=%d total=%d used=%d' %
                      (r_desc_in.m_index.slice_id, r_desc_out.total, r_desc_out.used))

            # Print total size of the ipv6 lpts table in each slice
            r_desc_in.m_resource_type = sdk.la_resource_descriptor.type_e_IPV6_LPTS
            for slice_id in self.device.get_used_slices():
                r_desc_in.m_index.slice_id = slice_id
                r_desc_out = self.device.get_resource_usage(r_desc_in)
                print('IPv6 LPTS: slice=%d total=%d used=%d' %
                      (r_desc_in.m_index.slice_id, r_desc_out.total, r_desc_out.used))

            # Print total size of the ipv6 sec acl table in each slice (logically ipv6 sec acl and ipv6 lpts share table)
            r_desc_in.m_resource_type = sdk.la_resource_descriptor.type_e_TCAM_INGRESS_NARROW_POOL_0
            for slice_id in self.device.get_used_slices():
                r_desc_in.m_index.slice_id = slice_id
                r_desc_out = self.device.get_resource_usage(r_desc_in)
                print('Ingress IPv6 NARROW DB1 INTERFACE0 ACL TCAM : slice=%d total=%d used=%d' %
                      (r_desc_in.m_index.slice_id, r_desc_out.total, r_desc_out.used))

        lpts_v4.clear()
        lpts_v6.clear()

        count = lpts_v4.get_count()
        self.assertEqual(count, 0)

        count = lpts_v6.get_count()
        self.assertEqual(count, 0)

        # After clear check ipv4/ipv6 lpts table in each slice via resource usage
        r_desc_in.m_resource_type = sdk.la_resource_descriptor.type_e_IPV4_LPTS
        for slice_id in self.device.get_used_slices():
            r_desc_in.m_index.slice_id = slice_id
            r_desc_out = self.device.get_resource_usage(r_desc_in)
            self.assertEqual(r_desc_out.used, 0)

        r_desc_in.m_resource_type = sdk.la_resource_descriptor.type_e_IPV6_LPTS
        for slice_id in self.device.get_used_slices():
            r_desc_in.m_index.slice_id = slice_id
            r_desc_out = self.device.get_resource_usage(r_desc_in)
            self.assertEqual(r_desc_out.used, 0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='lpts_tcam_usage test.')
    parser.add_argument('-v', '--verbose', required=False, action='store_true', help='verbose/debug mode')
    args = parser.parse_args()
    unittest.main()
