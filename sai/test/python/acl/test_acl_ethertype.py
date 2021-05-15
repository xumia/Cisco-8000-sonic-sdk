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
class Test_acl_ethertype():
    aclTable = acl_table_tests()

    def test_ether_type(self):
        # Test an ACL with ETHER__TYPE attribute
        # Create an ACL table, counters and ACL entry
        args = {}
        table_obj = self.aclTable.create_table_1_field(SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE)
        assert table_obj != 0
        args = {}
        args[SAI_ACL_COUNTER_ATTR_TABLE_ID] = table_obj
        args[SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT] = True
        args[SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT] = True
        cntr_obj = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_COUNTER, args)
        assert cntr_obj != 0
        aclEntry = acl_entry_tests()
        args = {}
        args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = table_obj
        args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 1
        args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, cntr_obj]
        args[SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE] = [True, 0xffff, 0x0800]
        args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry_obj = aclEntry.create_entry(args)
        assert entry_obj != 0

        # Send IPv4 packet to make sure it works
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1, type=0x0800) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64, tos=41) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac, type=0x0800) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63, tos=41) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # Bind the ACL table to ingress port
        pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, table_obj)
        assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == table_obj

        # Send 5 IPv4 packets. These should be dropped
        for x in range(5):
            U.run(self, in_pkt, pytest.top.in_port)

        # Send 2 ARP packets. These should not be dropped
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1, type=0x0806) / \
            ARP(pdst='10.10.10.1')

        for x in range(2):
            U.run(self, in_pkt, pytest.top.in_port)

        # Verify that the ACL drop counter is 5
        assert pytest.tb.get_object_attr(cntr_obj, SAI_ACL_COUNTER_ATTR_PACKETS) == 5

        # cleanup
        pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)
        pytest.tb.remove_object(entry_obj)
        pytest.tb.remove_object(cntr_obj)
        pytest.tb.remove_object(table_obj)
