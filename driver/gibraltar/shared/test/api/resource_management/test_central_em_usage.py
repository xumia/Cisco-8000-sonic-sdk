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
import topology as T
from resource_handler_base import *
from ip_test_base import ipv6_test_base
from ip_test_base import ipv4_test_base


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class central_em_usage(resource_handler_base):
    PRIVATE_DATA = 0x1234567890abcdef
    DIPv4 = T.ipv4_addr('11.0.0.3')
    MAC = T.mac_addr('00:11:22:33:44:03')
    DIPv6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipUnless(decor.is_hw_device(), "Skip for SIM until accurate scale model is enabled")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_central_em_usage(self):
        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_CENTRAL_EM
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, 0)

        self.topology = T.topology(self, self.device)
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_CENTRAL_EM
        res = self.device.get_resource_usage(rd)
        used_after_topology_init = res.used

        # Add+modify some double width entries.
        num_double_entries_added = 1
        self.ipv6_impl = ipv6_test_base
        subnet = self.ipv6_impl.build_prefix(self.DIPv6, length=128)
        self.ipv6_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
        self.ipv6_impl.add_host(self.l3_port_impl.tx_port, self.DIPv6, self.MAC)
        self.ipv6_impl.modify_host(self.l3_port_impl.tx_port, self.DIPv6, self.MAC)

        # Check usage
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, (used_after_topology_init + (num_double_entries_added * 2)))

        # Add+modify some single width entries.
        num_single_entries_added = 1
        self.ipv4_impl = ipv4_test_base
        subnet = self.ipv4_impl.build_prefix(self.DIPv4, length=16)
        self.ipv4_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
        self.ipv4_impl.add_host(self.l3_port_impl.tx_port, self.DIPv4, self.MAC)
        self.ipv4_impl.modify_host(self.l3_port_impl.tx_port, self.DIPv4, self.MAC)

        # Check usage
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, (used_after_topology_init + num_single_entries_added + (num_double_entries_added * 2)))

        # Remove routes.
        self.ipv4_impl.delete_host(self.l3_port_impl.tx_port, self.DIPv4)
        self.ipv6_impl.delete_host(self.l3_port_impl.tx_port, self.DIPv6)

        # Check usage
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, used_after_topology_init)


if __name__ == '__main__':
    unittest.main()
