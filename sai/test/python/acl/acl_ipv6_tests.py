#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import sai_packet_utils as U
import sai_test_base as st_base
import sai_test_utils as st_utils
from scapy.all import *
import sai_topology as topology


class aclTests():

    def create_packet_counter(self, acl_table):
        counter_args = {}
        counter_args[SAI_ACL_COUNTER_ATTR_TABLE_ID] = acl_table
        counter_args[SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT] = True

        acl_counter = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_COUNTER, counter_args)

        self.check_counter_attributes(acl_counter, acl_table)

        return acl_counter

    def check_table_attributes(self, acl_table, acl_stage, entry_count, counter_count, table_size=0):
        # Checking table attribute values.
        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_SIZE) == table_size

        arg = sai_attribute_t(SAI_ACL_TABLE_ATTR_ACL_STAGE, 0)
        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_ACL_STAGE) == acl_stage

        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_FIELD_SRC_IP) == False
        # Enable when object group ACL is available.
        # assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6)

        # Checking available counter
        # assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_AVAILABLE_ACL_COUNTER) == counter_count

        # Checking number of entries using 2 different getters
        assert len(pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_ENTRY_LIST)) == entry_count

    def check_entry_attributes(self, entry1, entry2, entry3, acl_table, check_dscp_ecn=False):
        # Checking if entry is bound to right table.
        assert pytest.tb.get_object_attr(entry1, SAI_ACL_ENTRY_ATTR_TABLE_ID) == acl_table

        # Check priority.
        arg = sai_attribute_t(SAI_ACL_ENTRY_ATTR_PRIORITY, 0)
        assert pytest.tb.get_object_attr(entry2, SAI_ACL_ENTRY_ATTR_PRIORITY) == 5

        # Check admin state
        assert pytest.tb.get_object_attr(entry3, SAI_ACL_ENTRY_ATTR_ADMIN_STATE)

        # Checking match field rules
        assert pytest.tb.get_object_attr(entry2, SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT) == [True, 64, 255]

        # Enable when object group ACL is available.
        # assert pytest.tb.get_object_attr(entry2, SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6) == [
        #    True, pytest.top.neighbor_ip1, pytest.top.full_mask]
        assert pytest.tb.get_object_attr(entry2, SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6) == [
            True, pytest.top.neighbor_ip2, pytest.top.full_mask]

        if check_dscp_ecn:
            assert pytest.tb.get_object_attr(entry2, SAI_ACL_ENTRY_ATTR_FIELD_DSCP) == [True, 10, 63]
            assert pytest.tb.get_object_attr(entry2, SAI_ACL_ENTRY_ATTR_FIELD_ECN) == [True, 1, 1]

    def check_counter_attributes(self, acl_counter, acl_table):
        assert pytest.tb.get_object_attr(acl_counter, SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT)
        assert pytest.tb.get_object_attr(acl_counter, SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT) == False

        # Checking if drop is well connected to a table
        assert pytest.tb.get_object_attr(acl_counter, SAI_ACL_COUNTER_ATTR_TABLE_ID) == acl_table

    def ingress_ipv6_acl_table_test(self, args=None, v4_v6=False, switch_binding=False):
        if args is None:
            args = pytest.tb.generate_ipv6_acl_key()

        max_available = {}
        max_available['tables'] = pytest.tb.get_acl_table_available()[0][2]

        # Setting stage.
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size

        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        max_available['entries'] = pytest.tb.get_acl_table_entry_available(acl_table)

        # Creating drop counter
        drop_counter = self.create_packet_counter(acl_table)
        fwd_counter = self.create_packet_counter(acl_table)

        # Preparing entry args.
        entry1_args = {}
        entry1_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry1_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 2
        # Enable when object group ACL is available.
        # entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = [True,
        # pytest.top.neighbor_ip1, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [True, pytest.top.neighbor_ip2, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]

        entry2_args = {}
        entry2_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry2_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 5
        # Enable when object group ACL is available.
        # entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = [True,
        # pytest.top.neighbor_ip1, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [True, pytest.top.neighbor_ip2, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, drop_counter]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 10, 0x3f]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_ECN] = [True, 1, 1]

        entry3_args = {}
        entry3_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry3_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 10
        entry3_args[SAI_ACL_ENTRY_ATTR_ADMIN_STATE] = True
        # Enable when object group ACL is available.
        # entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = [
        # True, "1111:db9:a0b:12f0::3333", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [
            True, "1111:db9:a0b:12f0::5555", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]

        entry4_args = {}
        entry4_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry4_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 3
        entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 20, 0x3f]
        entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, fwd_counter]
        entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] = [True, 7]

        drop_count = 0
        fwd_count = 0

        # Creating entries.
        acl_entry1 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry1_args)
        acl_entry2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry2_args)
        pytest.tb.do_warm_boot()
        acl_entry3 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry3_args)
        acl_entry4 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry4_args)

        if not v4_v6:
            self.check_table_attributes(acl_table, SAI_ACL_STAGE_INGRESS, 4, 2, table_size)
        self.check_entry_attributes(acl_entry1, acl_entry2, acl_entry3, acl_table, True)
        self.check_counter_attributes(drop_counter, acl_table)

        # Pkt that are not subjected to any ACL
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64, tc=41) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63, tc=41) / \
            UDP(sport=64, dport=2048)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # Bind ACL
        if switch_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, acl_table)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, acl_table)
            assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == acl_table

        # These packets should be dropped (entry2 should be hit).
        U.run(self, in_pkt, pytest.top.in_port)
        drop_count += 1
        U.run(self, in_pkt, pytest.top.in_port)
        drop_count += 1

        # Pkt that hits entry4 matching DSCP
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64, tc=81) / \
            UDP(sport=64, dport=2048)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63, tc=81) / \
            UDP(sport=64, dport=2048)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)
        fwd_count += 1

        # Pkt that hit entry 1
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64) / \
            UDP(sport=63, dport=2048)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63) / \
            UDP(sport=63, dport=2048)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # Unbind ACL for other tests
        if switch_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, 0)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)
        assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == 0

        # Count ACL dropped packets
        assert pytest.tb.get_object_attr(drop_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == drop_count
        # Count ACL permitted packets
        assert pytest.tb.get_object_attr(fwd_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == fwd_count

        # cleanup
        pytest.tb.remove_object(acl_entry1)
        pytest.tb.remove_object(acl_entry2)
        pytest.tb.remove_object(acl_entry3)
        pytest.tb.remove_object(acl_entry4)
        pytest.tb.remove_object(acl_table)
        pytest.tb.remove_object(drop_counter)

    def ingress_v4_v6_acl_table_test(self, v4_v6=True, switch_binding=False, add_delete_port=False):
        args = pytest.tb.generate_combined_v4_v6_acl_key()
        self.ingress_ipv6_acl_table_test(args, v4_v6, switch_binding)

    def egress_ipv6_acl_table_test(self, args=None, v4_v6=False, switch_binding=False):
        if args is None:
            args = pytest.tb.generate_ipv6_acl_key()

        max_available = {}
        max_available['tables'] = pytest.tb.get_acl_table_available()[0][2]

        # Setting stage.
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_EGRESS

        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        max_available['entries'] = pytest.tb.get_acl_table_entry_available(acl_table)

        # Creating drop counter
        drop_counter = self.create_packet_counter(acl_table)

        # Preparing entry args.
        entry1_args = {}
        entry1_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry1_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 2
        # Enable when object group ACL is available.
        # entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = [True,
        # pytest.top.neighbor_ip1, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [True, pytest.top.neighbor_ip2, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]

        entry2_args = {}
        entry2_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry2_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 5
        # Enable when object group ACL is available.
        # entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = [True,
        # pytest.top.neighbor_ip1, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [True, pytest.top.neighbor_ip2, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, drop_counter]

        entry3_args = {}
        entry3_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry3_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 10
        entry3_args[SAI_ACL_ENTRY_ATTR_ADMIN_STATE] = True
        # Enable when object group ACL is available.
        # entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = [True,
        #                                                  "1111:db9:a0b:12f0::3333", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [True,
                                                          "1111:db9:a0b:12f0::5555", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]

        # Creating entries.
        acl_entry1 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry1_args)
        pytest.tb.do_warm_boot()
        acl_entry2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry2_args)
        acl_entry3 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry3_args)

        if not v4_v6:
            self.check_table_attributes(acl_table, SAI_ACL_STAGE_EGRESS, 3, 1)
        self.check_entry_attributes(acl_entry1, acl_entry2, acl_entry3, acl_table)
        self.check_counter_attributes(drop_counter, acl_table)

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        if switch_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, acl_table)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.out_port, SAI_PORT_ATTR_EGRESS_ACL, acl_table)
            assert pytest.tb.get_port_egress_acl(pytest.top.out_port) == acl_table

        U.run(self, in_pkt, pytest.top.in_port)
        U.run(self, in_pkt, pytest.top.in_port)

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64) / \
            UDP(sport=63, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63) / \
            UDP(sport=63, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # Unbind ACL for other tests
        if switch_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, 0)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.out_port, SAI_PORT_ATTR_EGRESS_ACL, 0)
        assert pytest.tb.get_port_egress_acl(pytest.top.out_port) == 0

        # Count of dropped packets should be 2.
        assert pytest.tb.get_object_attr(drop_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == 2

        # cleanup
        pytest.tb.remove_object(acl_entry1)
        pytest.tb.remove_object(acl_entry2)
        pytest.tb.remove_object(acl_entry3)
        pytest.tb.remove_object(acl_table)
        pytest.tb.remove_object(drop_counter)

    def egress_v4_v6_acl_table_test(self, v4_v6=True, switch_binding=False, add_delete_port=False):
        args = pytest.tb.generate_combined_v4_v6_acl_key()
        self.egress_ipv6_acl_table_test(args, v4_v6, switch_binding)

    def ingress_ipv6_acl_trap(self, args=None, v4_v6=False, switch_binding=False):
        if args is None:
            args = pytest.tb.generate_ipv6_acl_key()

        attr = sai_attribute_t(SAI_SWITCH_ATTR_CPU_PORT, 0)
        pytest.tb.apis[SAI_API_SWITCH].get_switch_attribute(pytest.tb.switch_id, 1, attr)
        cpu_queue_list = pytest.tb.get_queue_list(attr.value.oid)
        queue_obj_ids = []
        for q in cpu_queue_list.to_pylist():
            queue_obj_ids.append(q)

        # Setting stage.
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size

        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Creating trap counter
        trap_counter = self.create_packet_counter(acl_table)

        # Preparing entry args.
        entry1_args = {}
        entry1_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry1_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 2
        # Enable when object group ACL is available.
        # entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = [True,
        # pytest.top.neighbor_ip1, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [True, pytest.top.neighbor_ip2, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]

        entry2_args = {}
        entry2_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry2_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 5
        # Enable when object group ACL is available.
        # entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = [True,
        # pytest.top.neighbor_ip1, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [True, pytest.top.neighbor_ip2, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_TRAP]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] = [True, 5]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, trap_counter]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 10, 0x3f]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_ECN] = [True, 1, 1]

        # Creating entries.
        acl_entry1 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry1_args)
        pytest.tb.do_warm_boot()
        acl_entry2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry2_args)

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64, tc=41) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63, tc=41) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        if switch_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, acl_table)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, acl_table)
            assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == acl_table

        # Get cpu q stats before pkt
        q_stats_before = []
        for q in range(0, 8):
            q_stats_before.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

        U.punt_test(self, in_pkt, pytest.top.in_port, in_pkt)
        U.punt_test(self, in_pkt, pytest.top.in_port, in_pkt)

        q_stats_after = []
        for q in range(0, 8):
            q_stats_after.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_after[q][0], q_stats_after[q][1]))

        # Verify the difference of packets in queue 5 before and after is 2
        assert (q_stats_after[entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] -
                q_stats_before[entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] == 2)

        # Unbind ACL for other tests
        if switch_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, 0)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)
        assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == 0

        # Count of dropped packets should be 2.
        assert pytest.tb.get_object_attr(trap_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == 2

        # cleanup
        pytest.tb.remove_object(acl_entry1)
        pytest.tb.remove_object(acl_entry2)
        pytest.tb.remove_object(acl_table)
        pytest.tb.remove_object(trap_counter)

    def ingress_ipv6_acl_copy(self, args=None, v4_v6=False, switch_binding=False):
        if args is None:
            args = pytest.tb.generate_ipv6_acl_key()

        cpu_queue_list = pytest.tb.get_queue_list(pytest.tb.cpu_port)
        queue_obj_ids = []
        for q in cpu_queue_list.to_pylist():
            queue_obj_ids.append(q)

        # Setting stage.
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size

        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Creating trap counter
        trap_counter = self.create_packet_counter(acl_table)

        # Preparing entry args.
        entry1_args = {}
        entry1_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry1_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 2
        # Enable when object group ACL is available.
        # entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = [True,
        # pytest.top.neighbor_ip1, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [True, pytest.top.neighbor_ip2, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]

        entry2_args = {}
        entry2_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry2_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 5
        # Enable when object group ACL is available.
        # entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = [True,
        # pytest.top.neighbor_ip1, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [True, pytest.top.neighbor_ip2, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_COPY]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] = [True, 5]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, trap_counter]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 10, 0x3f]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_ECN] = [True, 1, 1]

        # Creating entries.
        acl_entry1 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry1_args)
        pytest.tb.do_warm_boot()
        acl_entry2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry2_args)

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64, tc=41) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63, tc=41) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        if switch_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, acl_table)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, acl_table)
            assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == acl_table

        # Get cpu q stats before pkt
        q_stats_before = []
        for q in range(0, 8):
            q_stats_before.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

        U.punt_snoop_test_helper(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt}, in_pkt, 1, None, True, "up")
        U.punt_snoop_test_helper(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt}, in_pkt, 1, None, True, "up")

        q_stats_after = []
        for q in range(0, 8):
            q_stats_after.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_after[q][0], q_stats_after[q][1]))

        # Verify the difference of packets in queue 5 before and after is 2
        assert (q_stats_after[entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] -
                q_stats_before[entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] == 2)

        # Unbind ACL for other tests
        if switch_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, 0)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)
        assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == 0

        # Count of dropped packets should be 2.
        assert pytest.tb.get_object_attr(trap_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == 2

        # cleanup
        pytest.tb.remove_object(acl_entry1)
        pytest.tb.remove_object(acl_entry2)
        pytest.tb.remove_object(acl_table)
        pytest.tb.remove_object(trap_counter)

    def ingress_ipv6_acl_copy_svi(self, args=None, v4_v6=False, switch_binding=False):
        dst_ip = "2620:0:1cfe:face:b00c::4"

        if args is None:
            args = pytest.tb.generate_ipv6_acl_key()

        cpu_queue_list = pytest.tb.get_queue_list(pytest.tb.cpu_port)
        queue_obj_ids = []
        for q in cpu_queue_list.to_pylist():
            queue_obj_ids.append(q)

        # Setting stage.
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size

        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Preparing entry args.
        entry_args = {}
        entry_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 5
        # entry_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = [
        #    True, pytest.top.svi_dst_neighbor_ip, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [True, dst_ip, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_COPY]

        # Creating entries.
        acl_entry = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry_args)

        in_pkt = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=dst_ip, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.svi_dst_neighbor_mac, src=pytest.top.svi_mac) / \
            IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=dst_ip, hlim=63) / \
            UDP(sport=64, dport=2048)

        if switch_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, acl_table)
        else:
            pytest.tb.bind_acl_to_rif(pytest.tb.svi_rif_id, SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL, acl_table)

        pytest.tb.set_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.default_ip,
            pytest.top.default_ip_mask,
            SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION,
            SAI_PACKET_ACTION_FORWARD)
        action = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.default_ip,
            pytest.top.default_ip_mask,
            SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION)
        assert action == SAI_PACKET_ACTION_FORWARD

        pytest.tb.set_route_attribute(pytest.tb.virtual_router_id,
                                      pytest.top.default_ip,
                                      pytest.top.default_ip_mask,
                                      SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID,
                                      pytest.tb.cpu_port)
        nh = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.default_ip,
            pytest.top.default_ip_mask,
            SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID)
        assert nh == pytest.tb.cpu_port

        pytest.tb.set_route_attribute(pytest.tb.virtual_router_id,
                                      pytest.top.default_ip,
                                      pytest.top.default_ip_mask,
                                      SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID,
                                      pytest.tb.svi_nh)
        nh = pytest.tb.get_route_attribute(
            pytest.tb.virtual_router_id,
            pytest.top.default_ip,
            pytest.top.default_ip_mask,
            SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID)
        assert nh == pytest.tb.svi_nh

        # Get cpu q stats before pkt
        q_stats_before = []
        for q in range(0, 8):
            q_stats_before.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

        # packet from svi/VLAN to CPU will be tagged
        in_pkt_tagged = Ether(dst=pytest.top.svi_mac, src=pytest.top.svi_dst_neighbor_mac) / \
            Dot1Q(prio=0, vlan=pytest.top.vlan) / \
            IPv6(src=pytest.top.svi_dst_neighbor_ip, dst=dst_ip, hlim=64) / \
            UDP(sport=64, dport=2048)

        U.punt_snoop_test_helper(
            self, in_pkt, pytest.top.out_port, {
                pytest.top.out_port: expected_out_pkt}, in_pkt_tagged, 1, None, True, "up")
        U.punt_snoop_test_helper(
            self, in_pkt, pytest.top.out_port, {
                pytest.top.out_port: expected_out_pkt}, in_pkt_tagged, 1, None, True, "up")

        # Unbind ACL for other tests
        if switch_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, 0)
        else:
            pytest.tb.bind_acl_to_rif(pytest.tb.svi_rif_id, SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL, 0)

        # cleanup
        pytest.tb.remove_object(acl_entry)
        pytest.tb.remove_object(acl_table)

    def ingress_ipv6_acl_table_test_mirror(
            self,
            mirror_oid,
            args={},
            v4_v6=False,
            switch_acl_attachment=False,
            add_delete_port=False):

        def __port_q_stats(port):
            out_queue_list = pytest.tb.get_queue_list(pytest.tb.ports[port])
            queue_obj_ids = []
            for q in out_queue_list.to_pylist():
                queue_obj_ids.append(q)
            q_stats = []
            for q in range(0, 8):
                q_stats.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
                print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats[q][0], q_stats[q][1]))
            return q_stats

        mirror_oids = [mirror_oid]

        if args is None:
            args = pytest.tb.generate_ipv6_acl_key()

        max_available = {}
        max_available['tables'] = pytest.tb.get_acl_table_available()[0][2]

        # Setting stage.
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size

        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        max_available['entries'] = pytest.tb.get_acl_table_entry_available(acl_table)

        # Creating drop counter
        drop_counter = self.create_packet_counter(acl_table)
        fwd_counter = self.create_packet_counter(acl_table)

        # Preparing entry args.
        entry1_args = {}
        entry1_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry1_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 2
        # Enable when object group ACL is available.
        # entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = [True,
        # pytest.top.neighbor_ip2, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [
            True, pytest.top.v6_neighbor_ip2, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS] = [True, mirror_oids]
        entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, fwd_counter]
        entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] = [True, 7]

        entry2_args = {}
        entry2_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry2_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 5
        # Enable when object group ACL is available.
        # entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = [True,
        # pytest.top.v6_neighbor_ip1, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, drop_counter]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 10, 0x3f]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_ECN] = [True, 1, 1]

        entry3_args = {}
        entry3_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry3_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 10
        entry3_args[SAI_ACL_ENTRY_ATTR_ADMIN_STATE] = True
        # Enable when object group ACL is available.
        # entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6] = [
        # True, "1111:db9:a0b:12f0::3333", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [
            True, "1111:db9:a0b:12f0::5555", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        # entry3_args[SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS] = [True, mirror_oids]

        entry4_args = {}
        entry4_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry4_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 3
        entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 20, 0x3f]
        entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, fwd_counter]
        entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] = [True, 7]

        drop_count = 0
        fwd_count = 0
        # entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS] = [mirror_oid]

        # Creating entries.
        entries = []
        acl_entry1 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry1_args)
        entries.append(acl_entry1)
        pytest.tb.do_warm_boot()
        acl_entry2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry2_args)
        entries.append(acl_entry2)
        acl_entry3 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry3_args)
        entries.append(acl_entry3)
        acl_entry4 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry4_args)
        entries.append(acl_entry4)

        # Add new ACL action as ingress mirror. During ACE creation, ACL action did not include mirroring.
        # To the existing list of ACL actions, also include ingress mirroring.
        pytest.tb.set_object_attr(acl_entry3, SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS, [True, mirror_oids], verify=True)

        # Modify ACL action to include mirroring. Modify with same mirror oid as it was used during ACE create
        pytest.tb.set_object_attr(acl_entry1, SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS, [True, mirror_oids], verify=True)

        # Pkt that are not subjected to any ACL
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.v6_neighbor_ip1, dst=pytest.top.v6_neighbor_ip2, hlim=64, tc=41) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.v6_neighbor_ip1, dst=pytest.top.v6_neighbor_ip2, hlim=63, tc=41) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        if switch_acl_attachment:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, acl_table)
            if add_delete_port:
                # After attaching switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1_v4_v6()
                pytest.top.configure_rif_id_1_v4_v6(pytest.top.in_port)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, acl_table)
            assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == acl_table

        # dropped packet
        U.run(self, in_pkt, pytest.top.in_port)
        drop_count += 1

        in_pkt_entry_1 = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IPv6(src=pytest.top.v6_neighbor_ip1, dst=pytest.top.v6_neighbor_ip2, hlim=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IPv6(src=pytest.top.v6_neighbor_ip1, dst=pytest.top.v6_neighbor_ip2, hlim=63) / \
            UDP(sport=64, dport=2048)
        # Destination port Q stats before packet injection
        q_stats_before = __port_q_stats(pytest.top.out_port)

        # Mirror port Q stats before mirroring
        mirror_port_q_stats_before = __port_q_stats(pytest.top.mirror_dest)

        # These packets should increment queue counters of out port and mirror port
        U.run_and_compare(self, in_pkt_entry_1, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)
        fwd_count += 1

        # Destination port Q stats after packet injection
        q_stats_after = __port_q_stats(pytest.top.out_port)

        # Mirror port Q stats after mirroring
        mirror_port_q_stats_after = __port_q_stats(pytest.top.mirror_dest)

        # Verify the difference of packets in queue 5 before and after is 1 on destination port
        assert (q_stats_after[entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] -
                q_stats_before[entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] == 1)

        # Verify the difference of packets on mirror destination port
        # queue 0 (mirror pkt uses TC zero as per mirror object attribute) is 1
        assert (mirror_port_q_stats_after[0][0] -
                mirror_port_q_stats_before[0][0] == 1)

        # Remove ACL mirror action and confirm.
        pytest.tb.set_object_attr(acl_entry1, SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS, [False, []], verify=True)

        mirror_port_q_stats_before = __port_q_stats(pytest.top.mirror_dest)

        # These packets should increment queue counters of out port and NOT mirror port
        U.run_and_compare(self, in_pkt_entry_1, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)
        fwd_count += 1

        mirror_port_q_stats_after = __port_q_stats(pytest.top.mirror_dest)

        # Should be zero
        assert (mirror_port_q_stats_after[0][0] -
                mirror_port_q_stats_before[0][0] == 0)

        assert pytest.tb.get_object_attr(drop_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == drop_count
        assert pytest.tb.get_object_attr(fwd_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == fwd_count

        # Check its not possible to delete mirror session before ACEs that use it are deleted.
        with st_utils.expect_sai_error(SAI_STATUS_OBJECT_IN_USE):
            pytest.tb.remove_object(mirror_oid)

        # cleanup
        if switch_acl_attachment:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, 0)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)
        assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == 0

        pytest.tb.remove_object(acl_entry1)
        pytest.tb.remove_object(acl_entry2)
        pytest.tb.remove_object(acl_entry3)
        pytest.tb.remove_object(acl_entry4)
        pytest.tb.remove_object(acl_table)
        pytest.tb.remove_object(drop_counter)
        pytest.tb.remove_object(fwd_counter)

    def ingress_ipv6_acl_table_mirror_test(self, mirror_oid, args=None, v4_v6=False, switch_binding=False, add_delete_port=False):
        if args is None:
            args = pytest.tb.generate_ipv6_acl_key()
        self.ingress_ipv6_acl_table_test_mirror(
            mirror_oid,
            args,
            v4_v6,
            switch_acl_attachment=switch_binding,
            add_delete_port=add_delete_port)
