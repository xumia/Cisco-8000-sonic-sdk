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
from scapy.all import *
from packet_test_utils import *
from ipv4_ingress_acl_udk_320_base2 import *
import sim_utils
import topology as T
import ip_test_base


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class drop_acl(ipv4_ingress_acl_udk_320_base2):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")  # and RTF
    def test_drop_acl(self):
        acl1 = self.create_simple_sec_acl()

        # Test default route
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

        # Create IP-over-IP tunnel
        ip_impl = ip_test_base.ipv4_test_base
        TUNNEL_PORT_GID1 = 0x521
        self.tunnel_dest = ip_impl.build_prefix(LOCAL_IP, length=16)
        self.ip_over_ip_tunnel_port = T.ip_over_ip_tunnel_port(self, self.device,
                                                               TUNNEL_PORT_GID1,
                                                               self.topology.vrf,
                                                               self.tunnel_dest,
                                                               REMOTE_IP,
                                                               self.topology.vrf)

        # Inherit port features
        self.ip_over_ip_tunnel_port.hld_obj.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)

        # Test dropped packet
        self.do_test_route_default_with_drop()

        # Check counters
        packet_count, byte_count = self.inserted_drop_counter.read(0, True, True)
        self.assertEqual(packet_count, 0)

        packet_count, byte_count = self.inserted_drop_counter.read(1, True, True)
        self.assertEqual(packet_count, 1)

        packet_count, bytes = port_counter.read(0, True, True)
        # Incoming Port counter will be incremented and not the tunnel counter if the packet was dropped
        self.assertEqual(packet_count, 1)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()


if __name__ == '__main__':
    unittest.main()
