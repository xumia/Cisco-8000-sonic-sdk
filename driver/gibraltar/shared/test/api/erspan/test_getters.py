#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import sys
import unittest
from leaba import sdk
import ip_test_base
from packet_test_utils import *
from scapy.all import *
import sim_utils
import topology as T
from erspan_base import *
from ipv4_l3_ac_erspan_base import *
import ip_test_base


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_getters(ipv4_l3_ac_erspan_base):

    # If we don't have ACL, the packet will be mirrorred only if we set an UNconditional mirror command.
    def test_getters(self):
        self.topology.rx_l3_ac.hld_obj.set_ingress_mirror_command(self.mirror_cmd.hld_obj, is_acl_conditioned=False)

        # Update the TTL
        self.mirror_cmd.hld_obj.set_ttl(NEW_TUNNEL_TTL)
        self.assertEqual(NEW_TUNNEL_TTL, self.mirror_cmd.hld_obj.get_ttl())

        # Update the DSCP
        ip_dscp = sdk.la_ip_dscp()
        ip_dscp.value = NEW_TUNNEL_DSCP
        self.mirror_cmd.hld_obj.set_dscp(ip_dscp)
        self.assertEqual(NEW_TUNNEL_DSCP, self.mirror_cmd.hld_obj.get_dscp().value)

        # Update the Tunnel Destination
        tunnel_dst_addr_t = sdk.la_ipv4_addr_t()
        tunnel_dst_addr_t.s_addr = NEW_TUNNEL_DEST.hld_obj.s_addr
        tunnel_dst = sdk.la_ip_addr(tunnel_dst_addr_t)
        self.mirror_cmd.hld_obj.set_tunnel_destination(tunnel_dst)
        get_addr = self.mirror_cmd.hld_obj.get_tunnel_destination()
        self.assertEqual(NEW_TUNNEL_DEST.hld_obj.s_addr, get_addr.to_v4().s_addr)

        # Update the Tunnel Source
        tunnel_src_addr_t = sdk.la_ipv4_addr_t()
        tunnel_src_addr_t.s_addr = NEW_TUNNEL_SOURCE.hld_obj.s_addr
        tunnel_src = sdk.la_ip_addr(tunnel_src_addr_t)
        self.mirror_cmd.hld_obj.set_tunnel_source(tunnel_src)
        get_addr2 = self.mirror_cmd.hld_obj.get_tunnel_source()
        self.assertEqual(NEW_TUNNEL_SOURCE.hld_obj.s_addr, get_addr2.to_v4().s_addr)

        # Update the Dest MAC address
        self.mirror_cmd.hld_obj.set_mac(NEW_DEST_MAC.hld_obj)
        self.assertEqual(NEW_DEST_MAC.hld_obj.flat, self.mirror_cmd.hld_obj.get_mac().flat)

        # l3_port_obj = self.mirror_cmd.hld_obj.get_l3_port().this
        # self.assertEqual(self.l3_port_impl.tx_port_ext.hld_obj.this, l3_port_obj)
        # self.assertEqual(None, self.mirror_cmd.hld_obj.get_l2_port())
        # Update the Egress port
        self.mirror_cmd.hld_obj.set_egress_port(self.topology.tx_l3_ac_eth_port_ext.sys_port.hld_obj)
        system_port_obj = self.mirror_cmd.hld_obj.get_system_port().this
        self.assertEqual(self.topology.tx_l3_ac_eth_port_ext.sys_port.hld_obj.this, system_port_obj)

        # Set the vlan for the tx side for l3 ac
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = EGRESS_VLAN
        self.mirror_cmd.hld_obj.set_egress_vlan_tag(tag)

        # Set the mac for the tx side for l3 ac
        # self.l3_port_impl.tx_port_ext.hld_obj.set_mac(NEW_SOURCE_MAC.hld_obj)
        self.mirror_cmd.hld_obj.set_source_mac(NEW_SOURCE_MAC.hld_obj)

        run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.new_span_packet_data])
        mirror_cmd, is_acl_conditioned = self.topology.rx_l3_ac.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.mirror_cmd.hld_obj.get_gid())
        self.assertFalse(is_acl_conditioned)

        # Verify the packet and byte counts
        packet_count, byte_count = self.erspan_counter.read(0, True, True)
        self.mirror_cmd.hld_obj.set_counter(None)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.new_span_packet, byte_count)

        # Update the Traffic-class
        self.mirror_cmd.hld_obj.set_voq_offset(NEW_VOQ_OFFSET)
        self.assertEqual(NEW_VOQ_OFFSET, self.mirror_cmd.hld_obj.get_voq_offset())

        # Set the truncation mode
        self.mirror_cmd.hld_obj.set_truncate(True)
        self.assertEqual(True, self.mirror_cmd.hld_obj.get_truncate())


if __name__ == '__main__':
    unittest.main()
