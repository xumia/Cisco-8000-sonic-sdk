#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import pytest
from saicli import *
from sai_test_utils import *
from acl_table_tests import *
from acl_entry_tests import *
import sai_packet_utils as U
from scapy.all import *


@pytest.mark.usefixtures("basic_route_v4_one_port_topology")
class Test_acl_key_profile():
    aclTable = acl_table_tests()
    aclEntry = acl_entry_tests()

    def test_acl_key_profile(self):
        # This test verifies that ACL tables can be created after ACL entries are created.
        # Create 3 ACL tables, each with an ACL entry. Bind 2 tables to
        # a port. One ingress, one egress to make sure they are not merged
        # into a single ACL key profile.
        args = {}
        args[SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = [SAI_ACL_BIND_POINT_TYPE_PORT]
        args[SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_TYPE] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_CODE] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS] = True
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        table_obj1 = self.aclTable.create_table(args)

        args = {}
        args[SAI_ACL_COUNTER_ATTR_TABLE_ID] = table_obj1
        args[SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT] = True
        args[SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT] = True
        cntr_obj1 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_COUNTER, args, verify=[True, False])

        args = {}
        args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = table_obj1
        args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 1
        args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, cntr_obj1]
        args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 22, 0xffff]
        args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry_obj1 = self.aclEntry.create_entry(args)

        # Create the Egress ACL table/entry
        args = {}
        args[SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = [SAI_ACL_BIND_POINT_TYPE_PORT]
        args[SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_SRC_IP] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_DST_IP] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS] = True
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        table_obj2 = self.aclTable.create_table(args)

        args = {}
        args[SAI_ACL_COUNTER_ATTR_TABLE_ID] = table_obj2
        args[SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT] = True
        args[SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT] = True
        cntr_obj2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_COUNTER, args, verify=[True, False])

        args = {}
        args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = table_obj2
        args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 1
        args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, cntr_obj2]
        args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, "10.11.12.1", "255.255.255.255"]
        args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 22, 0xffff]
        args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry_obj2 = self.aclEntry.create_entry(args)

        # Bind the ACL table to egress port
        pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, table_obj2)
        assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == table_obj2

        # Create the Egress ACL table/entry
        args = {}
        args[SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = [SAI_ACL_BIND_POINT_TYPE_PORT]
        args[SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_SRC_IP] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_DST_IP] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS] = True
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_EGRESS
        table_obj3 = self.aclTable.create_table(args)

        args = {}
        args[SAI_ACL_COUNTER_ATTR_TABLE_ID] = table_obj3
        args[SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT] = True
        args[SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT] = True
        cntr_obj3 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_COUNTER, args, verify=[True, False])

        args = {}
        args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = table_obj3
        args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 1
        args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, cntr_obj3]
        args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, "10.11.12.2", "255.255.255.255"]
        args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 23, 0xffff]
        args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry_obj3 = self.aclEntry.create_entry(args)

        # Bind the ACL table to egress port
        pytest.tb.bind_acl_to_port(pytest.top.out_port, SAI_PORT_ATTR_EGRESS_ACL, table_obj3)
        assert pytest.tb.get_port_egress_acl(pytest.top.out_port) == table_obj3

        # Now verify that the ACLs bound to the ingress and egress interface are working.
        # Send 5 IPv4 UDP packets to the ingress interface. These should not be dropped
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1, type=0x0800) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64, tos=41) / \
            UDP(sport=22, dport=2048)
        for x in range(5):
            U.run(self, in_pkt, pytest.top.in_port)

        # Send 11 IPv4 TCP packets to ingress interface. These should match ACL and be dropped.
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1, type=0x0800) / \
            IP(src="10.11.12.1", dst=pytest.top.neighbor_ip2, ttl=64, tos=41, proto=6) / \
            TCP(sport=22, dport=2048)
        for x in range(11):
            U.run(self, in_pkt, pytest.top.in_port)

        # Send 17 IPv4 TCP packets to egress interface. These should match ACL and be dropped.
        out_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1, type=0x0800) / \
            IP(src="10.11.12.2", dst=pytest.top.neighbor_ip2, ttl=64, tos=41, proto=6) / \
            TCP(sport=23, dport=2048)
        for x in range(17):
            U.run(self, out_pkt, pytest.top.out_port)

        # Send 8 IPv4 TCP packets to egress interface. These should not be dropped.
        out_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1, type=0x0800) / \
            IP(src="10.11.12.3", dst=pytest.top.neighbor_ip2, ttl=64, tos=41, proto=6) / \
            TCP(sport=23, dport=2048)
        for x in range(8):
            U.run(self, out_pkt, pytest.top.out_port)

        # Verify that the ACLs for ingress and egress dropped matched packets, indicating
        # the ACLs were applied on interfaces and working correctly.
        assert pytest.tb.get_object_attr(cntr_obj2, SAI_ACL_COUNTER_ATTR_PACKETS) == 11
        assert pytest.tb.get_object_attr(cntr_obj3, SAI_ACL_COUNTER_ATTR_PACKETS) == 17

        # cleanup
        pytest.tb.remove_object(entry_obj1)
        pytest.tb.remove_object(cntr_obj1)
        pytest.tb.remove_object(table_obj1)
        pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)
        pytest.tb.remove_object(entry_obj2)
        pytest.tb.remove_object(cntr_obj2)
        pytest.tb.remove_object(table_obj2)
        pytest.tb.bind_acl_to_port(pytest.top.out_port, SAI_PORT_ATTR_EGRESS_ACL, 0)
        pytest.tb.remove_object(entry_obj3)
        pytest.tb.remove_object(cntr_obj3)
        pytest.tb.remove_object(table_obj3)
