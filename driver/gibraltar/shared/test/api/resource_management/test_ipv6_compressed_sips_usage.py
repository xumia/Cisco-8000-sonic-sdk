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
import topology as T
from resource_handler_base import *

MC_GROUP_ADDR = T.ipv6_addr('ff31:0:0:0:0:1:ffe8:658f')
MC_GROUP_GID = 0x13
SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
SIP2 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:3333')


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class ipv6_compressed_sips_usage(resource_handler_base):

    def setUp(self):
        super().setUp()

        self.topology = T.topology(self, self.device)
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_compressed_sips_usage(self):
        rd = sdk.la_resource_descriptor()
        rd.m_resource_type = sdk.la_resource_descriptor.type_e_IPV6_COMPRESSED_SIPS
        res = self.device.get_resource_usage(rd)
        used_during_device_init = res.used

        # Add some (s,g) route entries.
        self.mc_group = self.device.create_ip_multicast_group(MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        num_entries_added = 2
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            SIP.hld_obj, MC_GROUP_ADDR.hld_obj, self.mc_group, self.l3_port_impl.rx_port.hld_obj, False, False, None)
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            SIP2.hld_obj, MC_GROUP_ADDR.hld_obj, self.mc_group, self.l3_port_impl.rx_port.hld_obj, False, False, None)

        # Check usage.
        res = self.device.get_resource_usage(rd)
        self.assertEqual(res.used, (used_during_device_init + num_entries_added))


if __name__ == '__main__':
    unittest.main()
