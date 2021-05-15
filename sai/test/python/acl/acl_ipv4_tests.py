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
import sai_test_utils as st_utils
from scapy.all import *
import acl_udk_profiles as udk


class aclTests():
    def create_packet_counter(self, acl_table):
        counter_args = {}
        counter_args[SAI_ACL_COUNTER_ATTR_TABLE_ID] = acl_table
        counter_args[SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT] = True

        acl_counter = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_COUNTER, counter_args)

        self.check_counter_attributes(acl_counter, acl_table)

        return acl_counter

    def check_switch_attributes(self):
        assert len(pytest.tb.get_ingress_capability()) == 2
        assert pytest.tb.get_acl_table_available()[0][2] > 0

    def check_table_attributes(
            self,
            acl_table,
            acl_stage,
            max_available,
            created_table_count,
            bind_point_count,
            entry_count,
            table_size=0):
        # Checking table attribute values.
        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_SIZE) == table_size
        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_ACL_STAGE) == acl_stage
        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_FIELD_SRC_IP)
        # Enable when object group ACL is available.
        #assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6) == False
        assert (max_available['tables'] - pytest.tb.get_acl_table_available()[0][2]) == created_table_count

        # test entry_list with buffer overflow status
        entries = sai_object_list_t([])
        arg = sai_attribute_t(SAI_ACL_TABLE_ATTR_ENTRY_LIST, entries)
        arg2 = sai_attribute_t(SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST, entries)
        with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            pytest.tb.apis[SAI_API_ACL].get_acl_table_attribute(acl_table, 1, arg)
        with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            pytest.tb.apis[SAI_API_ACL].get_acl_table_attribute(acl_table, 1, arg2)

        assert arg2.value.objlist.count == bind_point_count
        assert (arg.value.objlist.count == entry_count)
        assert len(pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_ENTRY_LIST)) == entry_count
        #assert (max_available['entries'] - pytest.tb.get_acl_table_entry_available(acl_table)) == entry_count

    def check_entry_attributes(self, entry1, entry2, entry3, acl_table, check_dscp_ecn=False):
        # Checking if entry is bound to right table.
        assert pytest.tb.get_object_attr(entry1, SAI_ACL_ENTRY_ATTR_TABLE_ID) == acl_table

        # Check priority.
        assert pytest.tb.get_object_attr(entry2, SAI_ACL_ENTRY_ATTR_PRIORITY) == 5

        # Check admin state
        assert pytest.tb.get_object_attr(entry3, SAI_ACL_ENTRY_ATTR_ADMIN_STATE)

        # Checking match field rules
        assert pytest.tb.get_object_attr(entry2, SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT) == [True, 64, 255]

        assert pytest.tb.get_object_attr(entry2, SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP) == [
            True, pytest.top.neighbor_ip1, "255.255.255.255"]
        assert pytest.tb.get_object_attr(entry2, SAI_ACL_ENTRY_ATTR_FIELD_DST_IP) == [
            True, pytest.top.neighbor_ip2, "255.255.255.255"]

        if check_dscp_ecn:
            assert pytest.tb.get_object_attr(entry2, SAI_ACL_ENTRY_ATTR_FIELD_DSCP) == [True, 10, 63]
            assert pytest.tb.get_object_attr(entry2, SAI_ACL_ENTRY_ATTR_FIELD_ECN) == [True, 1, 1]

    def check_counter_attributes(self, acl_counter, acl_table):
        assert pytest.tb.get_object_attr(acl_counter, SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT)
        assert pytest.tb.get_object_attr(acl_counter, SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT) == False

        # Checking if drop is well connected to a table
        assert pytest.tb.get_object_attr(acl_counter, SAI_ACL_COUNTER_ATTR_TABLE_ID) == acl_table

    def partial_key_acl_table_test(self):
        args = {}
        args[SAI_ACL_TABLE_ATTR_FIELD_ECN] = True
        args[SAI_ACL_TABLE_ATTR_FIELD_DSCP] = True
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)
        assert acl_table != 0
        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_FIELD_ECN)
        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_FIELD_DSCP)
        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_ACL_STAGE) == args[SAI_ACL_TABLE_ATTR_ACL_STAGE]
        pytest.tb.remove_object(acl_table)

        args = {}
        args[SAI_ACL_TABLE_ATTR_FIELD_DSCP] = True
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)
        assert acl_table != 0
        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_FIELD_ECN) == False
        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_FIELD_DSCP)
        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_FIELD_ECN) != args[SAI_ACL_TABLE_ATTR_FIELD_DSCP]
        pytest.tb.remove_object(acl_table)

        args = {}
        args[SAI_ACL_TABLE_ATTR_FIELD_ECN] = True
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)
        assert acl_table != 0
        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_FIELD_ECN)
        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_FIELD_DSCP) == False
        assert pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_FIELD_DSCP) != args[SAI_ACL_TABLE_ATTR_FIELD_ECN]
        pytest.tb.remove_object(acl_table)

    def create_policer(self):
        args = {}
        args[SAI_POLICER_ATTR_METER_TYPE] = SAI_METER_TYPE_PACKETS
        args[SAI_POLICER_ATTR_MODE] = SAI_POLICER_MODE_SR_TCM
        args[SAI_POLICER_ATTR_CBS] = 200000
        args[SAI_POLICER_ATTR_CIR] = 10000
        args[SAI_POLICER_ATTR_PBS] = 200000
        args[SAI_POLICER_ATTR_PIR] = 10000
        return pytest.tb.create_policer(args)

    def ingress_ipv4_acl_table_tos_test_internal(self, args={}, switch_acl_attachment=False, add_delete_port=False):

        table_size = 10
        # Setting stage.
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        if switch_acl_attachment:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_SWITCH]
        else:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_PORT, SAI_ACL_BIND_POINT_TYPE_VLAN, SAI_ACL_BIND_POINT_TYPE_LAG]
        args[SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = bind_point_type_list

        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Creating drop counter
        drop_counter = self.create_packet_counter(acl_table)
        permit_counter = self.create_packet_counter(acl_table)
        entry1_args = {}
        entry1_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry1_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 6
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip1, "255.255.255.255"]
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.255.255"]
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, drop_counter]
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 10, 0x3f]

        entry2_args = {}
        entry2_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry2_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 7
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip1, "255.255.255.255"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.255.255"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, drop_counter]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_ECN] = [True, 1, 1]

        entry3_args = {}
        entry3_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry3_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 3
        entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip1, "255.255.255.255"]
        entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.255.255"]
        entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry3_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] = [True, 5]
        entry3_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_FORWARD]
        entry3_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, permit_counter]

        # Creating entries.
        acl_entry1 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry1_args)
        pytest.tb.do_warm_boot()
        acl_entry2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry2_args)
        acl_entry3 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry3_args)

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64, tos=41) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63, tos=41) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)
        if switch_acl_attachment:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, acl_table)
            if add_delete_port:
                # After attaching switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1()
                pytest.top.configure_rif_id_1(pytest.top.in_port)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, acl_table)
            assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == acl_table

        # Packet should be dropped.
        U.run(self, in_pkt, pytest.top.in_port)

        # change tos to only dscp matching value
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64, tos=40) / \
            UDP(sport=64, dport=2048)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63, tos=40) / \
            UDP(sport=64, dport=2048)
        # Packet should be dropped.
        U.run(self, in_pkt, pytest.top.in_port)

        # change tos to only ecn matching value
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64, tos=1) / \
            UDP(sport=64, dport=2048)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63, tos=1) / \
            UDP(sport=64, dport=2048)
        # Packet should be dropped.
        U.run(self, in_pkt, pytest.top.in_port)

        # change tos to non matching (match no ace) value
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64, tos=0) / \
            UDP(sport=64, dport=2048)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63, tos=0) / \
            UDP(sport=64, dport=2048)
        # packet should not be dropped.
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        assert pytest.tb.get_object_attr(drop_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == 3
        assert pytest.tb.get_object_attr(permit_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == 1

        if switch_acl_attachment:
            # Unbind ACL
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, 0)
            if add_delete_port:
                # After attaching switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1()
                pytest.top.configure_rif_id_1(pytest.top.in_port)
        else:
            # Unbind ACL for other tests.
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)

        pytest.tb.remove_object(acl_entry1)
        pytest.tb.remove_object(acl_entry2)
        pytest.tb.remove_object(acl_entry3)
        pytest.tb.remove_object(acl_table)
        pytest.tb.remove_object(drop_counter)
        pytest.tb.remove_object(permit_counter)

    def ingress_ipv4_acl_table_ip_type_test_internal(self, args={}, switch_acl_attachment=False, add_delete_port=False):
        table_size = 10
        # Setting stage.
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        if switch_acl_attachment:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_SWITCH]
        else:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_PORT, SAI_ACL_BIND_POINT_TYPE_VLAN, SAI_ACL_BIND_POINT_TYPE_LAG]
        args[SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = bind_point_type_list
        args[SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE] = True
        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)
        # ACE for ip-type get.
        entry_args = {}
        entry_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 0
        entry_args[SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE] = [True, 3, 3]  # IPV4ANY
        entry_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_FORWARD]
        acl_iptype_entry = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry_args)

        assert pytest.tb.get_object_attr(acl_iptype_entry, SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE) == [True, 3, 3]

        pytest.tb.remove_object(acl_iptype_entry)
        pytest.tb.remove_object(acl_table)

    def ingress_ipv4_acl_table_test_internal(self, args={}, v4_v6=False, switch_acl_attachment=False, add_delete_port=False):

        max_available = {}
        max_available['tables'] = pytest.tb.get_acl_table_available()[0][2]

        table_size = 14
        # Setting stage.
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        if switch_acl_attachment:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_SWITCH]
        else:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_PORT, SAI_ACL_BIND_POINT_TYPE_VLAN, SAI_ACL_BIND_POINT_TYPE_LAG]
        args[SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = bind_point_type_list

        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        max_available['entries'] = pytest.tb.get_acl_table_entry_available(acl_table)

        # Creating drop counter
        drop_counter = self.create_packet_counter(acl_table)
        permit_counter = self.create_packet_counter(acl_table)

        # policer
        policer_id = self.create_policer()

        # Preparing entry args.
        entry1_args = {}
        entry1_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry1_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 2
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip1, "255.255.255.0"]
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.255.0"]
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 63, 0xff]
        entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_FORWARD]

        entry2_args = {}
        entry2_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry2_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 5
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip1, "255.255.255.255"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.255.255"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, drop_counter]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 10, 0x3f]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_ECN] = [True, 1, 1]

        entry3_args = {}
        entry3_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry3_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 10
        entry3_args[SAI_ACL_ENTRY_ATTR_ADMIN_STATE] = True
        entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, "192.168.0.3", "255.255.255.255"]
        entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, "192.169.0.5", "255.255.255.255"]

        entry4_args = {}
        entry4_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry4_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 3
        entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip4, "255.255.255.255"]
        entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.255.255"]
        entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] = [True, 5]
        entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_FORWARD]
        entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, permit_counter]

        entry5_args = {}
        entry5_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry5_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 4
        entry5_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip4, "255.255.255.255"]
        entry5_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.255.255"]
        entry5_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 65, 0xff]
        entry5_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] = [True, 6]
        entry5_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_FORWARD]
        entry5_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER] = [True, policer_id]

        entry6_args = {}
        entry6_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry6_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 0
        entry6_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip1, "255.255.255.0"]
        entry6_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.255.0"]
        entry6_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]

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
        acl_entry5 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry5_args)
        entries.append(acl_entry5)
        acl_entry6 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry6_args)
        entries.append(acl_entry6)

        if not v4_v6:
            self.check_table_attributes(acl_table, SAI_ACL_STAGE_INGRESS, max_available, 1,
                                        len(bind_point_type_list), len(entries), table_size)
        self.check_entry_attributes(acl_entry1, acl_entry2, acl_entry3, acl_table, True)
        self.check_counter_attributes(drop_counter, acl_table)
        self.check_switch_attributes()

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64, tos=41) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63, tos=41) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        if switch_acl_attachment:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, acl_table)
            if add_delete_port:
                # After attaching switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1()
                pytest.top.configure_rif_id_1(pytest.top.in_port)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, acl_table)
            assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == acl_table

        # Those packets should be dropped. verify there is no packet out
        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, {}, match_all=True)
        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, {}, match_all=True)

        in_pkt_entry_4 = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip4, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt_entry_4 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip4, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        out_queue_list = pytest.tb.get_queue_list(pytest.tb.ports[pytest.top.out_port])

        queue_obj_ids = []
        for q in out_queue_list.to_pylist():
            queue_obj_ids.append(q)

        q_stats_before = []
        for q in range(0, 8):
            q_stats_before.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

        # These packets should increment queue counters of traffic class 5
        U.run(self, in_pkt_entry_4, pytest.top.in_port)
        U.run(self, in_pkt_entry_4, pytest.top.in_port)

        out_queue_list = pytest.tb.get_queue_list(pytest.tb.ports[pytest.top.out_port])

        queue_obj_ids = []
        for q in out_queue_list.to_pylist():
            queue_obj_ids.append(q)

        q_stats_after = []
        for q in range(0, 8):
            q_stats_after.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_after[q][0], q_stats_after[q][1]))

        # Verify the difference of packets in queue 5 before and after is 2
        assert (q_stats_after[entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] -
                q_stats_before[entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] == 2)

        new_set_tc_attr_value = [True, 6]

        pytest.tb.set_object_attr(acl_entry4, SAI_ACL_ENTRY_ATTR_ACTION_SET_TC, new_set_tc_attr_value)
        assert pytest.tb.get_object_attr(acl_entry4, SAI_ACL_ENTRY_ATTR_ACTION_SET_TC) == new_set_tc_attr_value

        # Re-send two more packets to see if the set tc worked

        q_stats_before = []
        for q in range(0, 8):
            q_stats_before.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

        # These packets should increment queue counters of traffic class 6
        U.run(self, in_pkt_entry_4, pytest.top.in_port)
        U.run(self, in_pkt_entry_4, pytest.top.in_port)

        out_queue_list = pytest.tb.get_queue_list(pytest.tb.ports[pytest.top.out_port])

        queue_obj_ids = []
        for q in out_queue_list.to_pylist():
            queue_obj_ids.append(q)

        q_stats_after = []
        for q in range(0, 8):
            q_stats_after.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_after[q][0], q_stats_after[q][1]))

        assert (q_stats_after[entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] -
                q_stats_before[entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] == 0)
        assert (q_stats_after[new_set_tc_attr_value[1]][0] - q_stats_before[new_set_tc_attr_value[1]][0] == 2)

        # test single forwarding action is working due to entry1
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=63, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=63, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # make sure this entry is dropped due to entry6
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=61, dport=2048)

        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, {}, match_all=True)

        in_pkt_entry_5 = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip4, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=65, dport=2048)

        p_stats_before = pytest.tb.get_policer_stats(policer_id)

        U.run(self, in_pkt_entry_5, pytest.top.in_port)

        p_stats = pytest.tb.get_policer_stats(policer_id)
        assert (p_stats[0] - p_stats_before[0]) == 1

        if switch_acl_attachment:
            # Unbind ACL
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, 0)
            if add_delete_port:
                # After attaching switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1()
                pytest.top.configure_rif_id_1(pytest.top.in_port)
        else:
            # Unbind ACL for other tests.
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)

        assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == 0
        # Count of dropped packets should be 2.
        assert pytest.tb.get_object_attr(drop_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == 2
        assert pytest.tb.get_object_attr(permit_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == 4

        # cleanup
        pytest.tb.remove_object(acl_entry1)
        pytest.tb.remove_object(acl_entry2)
        pytest.tb.remove_object(acl_entry3)
        pytest.tb.remove_object(acl_entry4)
        pytest.tb.remove_object(acl_entry5)
        pytest.tb.remove_object(acl_table)
        pytest.tb.remove_object(drop_counter)
        pytest.tb.remove_object(permit_counter)
        pytest.tb.remove_object(policer_id)

    def ingress_ipv4_acl_table_both_key_test_internal(
            self,
            args={},
            v4_v6=True,
            switch_acl_attachment=False,
            add_delete_port=False):

        out_queue_list = pytest.tb.get_queue_list(pytest.tb.ports[pytest.top.out_port])
        queue_obj_ids = []
        for q in out_queue_list.to_pylist():
            queue_obj_ids.append(q)
        drop_count = 0
        permit_count = 0

        table_size = 10
        # Setting stage.
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        if switch_acl_attachment:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_SWITCH]
        else:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_PORT, SAI_ACL_BIND_POINT_TYPE_VLAN, SAI_ACL_BIND_POINT_TYPE_LAG]
        args[SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = bind_point_type_list

        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Creating drop counter
        drop_counter = self.create_packet_counter(acl_table)

        # Preparing entry args.

        entry2_args = {}
        entry2_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry2_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 5
        if SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6 in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6]:
            entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [True, pytest.top.v6_neighbor_ip2, pytest.top.v6_full_mask]
        if SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
            entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 39, 0xff]

        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] = [True, 5]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, drop_counter]

        # Create ACE
        acl_entry2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry2_args)
        pytest.tb.do_warm_boot()

        # Get ACL action rule and verify correctness
        assert pytest.tb.get_object_attr(acl_entry2, SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION) == [True, SAI_PACKET_ACTION_DROP]
        # Get ACL action rule attribute value and verify correctness
        assert pytest.tb.get_object_attr(acl_entry2, SAI_ACL_ENTRY_ATTR_ACTION_SET_TC) == [True, 5]

        # Change ACL action attribute and check
        new_set_tc_attr_value = [True, 7]
        pytest.tb.set_object_attr(acl_entry2, SAI_ACL_ENTRY_ATTR_ACTION_SET_TC, new_set_tc_attr_value)
        assert pytest.tb.get_object_attr(acl_entry2, SAI_ACL_ENTRY_ATTR_ACTION_SET_TC) == new_set_tc_attr_value

        if (SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6 in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6]):
            in_v6_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
                IPv6(src=pytest.top.v6_neighbor_ip1, dst=pytest.top.v6_neighbor_ip2, hlim=64, tc=41) / \
                UDP(sport=39, dport=2048)
            expected_out_v6_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
                IPv6(src=pytest.top.v6_neighbor_ip1, dst=pytest.top.v6_neighbor_ip2, hlim=63, tc=41) / \
                UDP(sport=39, dport=2048)

        if (SAI_ACL_TABLE_ATTR_FIELD_DST_IP in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IP]):
            in_v4_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
                IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64, tos=41) / \
                UDP(sport=39, dport=2048)
            expected_out_v4_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
                IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63, tos=41) / \
                UDP(sport=39, dport=2048)

        # Bind ACL
        if switch_acl_attachment:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, acl_table)
            if add_delete_port:
                # After attaching switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1()
                pytest.top.configure_rif_id_1(pytest.top.in_port)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, acl_table)
            assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == acl_table

        # These packets should be dropped.
        if SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6 in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6]:
            U.run(self, in_v6_pkt, pytest.top.in_port)
            drop_count += 1

        # These packets should NOT increment drop counter.
        U.run_and_compare(self, in_v4_pkt, pytest.top.in_port, expected_out_v4_pkt, pytest.top.out_port)

        # Unbind ACL
        if switch_acl_attachment:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, 0)
            if add_delete_port:
                # After attaching switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1()
                pytest.top.configure_rif_id_1(pytest.top.in_port)
        else:
            # Unbind ACL for other tests.
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)

        assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == 0

        # Verify drop and permit counters
        assert pytest.tb.get_object_attr(drop_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == drop_count

        # cleanup
        pytest.tb.remove_object(acl_entry2)
        pytest.tb.remove_object(acl_table)
        pytest.tb.remove_object(drop_counter)

    def ingress_ipv4_acl_table_test(self, args=None, v4_v6=False, switch_binding=False, add_delete_port=False):
        if args is None:
            args = pytest.tb.generate_ipv4_acl_key()
        self.ingress_ipv4_acl_table_test_internal(
            args,
            v4_v6,
            switch_acl_attachment=switch_binding,
            add_delete_port=add_delete_port)
        self.ingress_ipv4_acl_table_tos_test_internal(args, switch_acl_attachment=switch_binding, add_delete_port=add_delete_port)
        self.ingress_ipv4_acl_table_ip_type_test_internal(
            args, switch_acl_attachment=switch_binding, add_delete_port=add_delete_port)

    def ingress_ipv4_acl_table_udk_test(self, switch_binding=False, add_delete_port=False):
        args = udk.generate_ipv4_acl_udk_key()
        self.ingress_ipv4_acl_table_test_internal(args, switch_acl_attachment=switch_binding, add_delete_port=add_delete_port)

    def ingress_ipv4_acl_table_custom_udk_test(self, switch_binding=False, add_delete_port=False):
        args = udk.generate_ipv4_acl_custom_udk_key()
        self.ingress_ipv4_acl_table_test_internal(args, switch_acl_attachment=switch_binding, add_delete_port=add_delete_port)

    def ingress_v4_v6_acl_table_test(self, v4_v6=True, switch_binding=False, add_delete_port=False):
        args = pytest.tb.generate_combined_v4_v6_acl_key()
        self.ingress_ipv4_acl_table_test(args, v4_v6, switch_binding, add_delete_port)

    def ingress_ipv4_acl_table_both_key_test(self, args=None, v4_v6=False, switch_binding=False, add_delete_port=False):
        if args is None:
            args = pytest.tb.generate_combined_v4_v6_acl_key()
        self.ingress_ipv4_acl_table_both_key_test_internal(
            args,
            True,
            switch_acl_attachment=switch_binding,
            add_delete_port=add_delete_port)

    def ingress_v4_v6_acl_table_both_key_test(self, v4_v6=True, switch_binding=False, add_delete_port=False):
        args = pytest.tb.generate_combined_v4_v6_acl_key()
        self.ingress_ipv4_acl_table_both_key_test(args, v4_v6, switch_binding, add_delete_port)

    def egress_ipv4_acl_table_test_internal(self, args={}, v4_v6=False, switch_acl_attachment=False, add_delete_port=False):

        max_available = {}
        max_available['tables'] = pytest.tb.get_acl_table_available()[0][2]

        # Setting stage.
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_EGRESS
        if switch_acl_attachment:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_SWITCH]
        else:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_PORT, SAI_ACL_BIND_POINT_TYPE_VLAN, SAI_ACL_BIND_POINT_TYPE_LAG]
        args[SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = bind_point_type_list

        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        max_available['entries'] = pytest.tb.get_acl_table_entry_available(acl_table)

        # Creating drop counter and debug counter
        drop_counter = self.create_packet_counter(acl_table)
        debug_counter = pytest.tb.create_debug_counter(SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS, SAI_IN_DROP_REASON_ACL_ANY)
        debug_counter_index = pytest.tb.get_object_attr(debug_counter, SAI_DEBUG_COUNTER_ATTR_INDEX)
        # make sure it is cleared
        pytest.tb.get_switch_stats(debug_counter_index, SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, clear=True)

        # Preparing entry args.
        entry1_args = {}
        entry1_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry1_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 2
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip1, "255.255.252.0"]
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.252.0"]
        entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_FORWARD]

        entry2_args = {}
        entry2_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry2_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 5
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip1, "255.255.255.255"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.255.255"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, drop_counter]

        entry3_args = {}
        entry3_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry3_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 10
        entry3_args[SAI_ACL_ENTRY_ATTR_ADMIN_STATE] = True
        entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, "192.168.0.3", "255.255.255.255"]
        entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, "192.169.0.5", "255.255.255.255"]

        # Creating entries.
        entries = []
        acl_entry1 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry1_args)
        entries.append(acl_entry1)
        acl_entry2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry2_args)
        entries.append(acl_entry2)
        pytest.tb.do_warm_boot()
        acl_entry3 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry3_args)
        entries.append(acl_entry3)

        if not v4_v6:
            self.check_table_attributes(acl_table, SAI_ACL_STAGE_EGRESS, max_available, 1, len(bind_point_type_list), len(entries))
        self.check_entry_attributes(acl_entry1, acl_entry2, acl_entry3, acl_table)
        self.check_counter_attributes(drop_counter, acl_table)
        self.check_switch_attributes()

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        if switch_acl_attachment:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, acl_table)
            if add_delete_port:
                # After attaching switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1()
                pytest.top.configure_rif_id_1(pytest.top.in_port)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.out_port, SAI_PORT_ATTR_EGRESS_ACL, acl_table)
            assert pytest.tb.get_port_egress_acl(pytest.top.out_port) == acl_table

        U.run(self, in_pkt, pytest.top.in_port)
        U.run(self, in_pkt, pytest.top.in_port)

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=63, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=63, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # Unbind ACL for other tests.
        if switch_acl_attachment:
            # Unbind ACL
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, 0)
            if add_delete_port:
                # After attaching switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1()
                pytest.top.configure_rif_id_1(pytest.top.in_port)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.out_port, SAI_PORT_ATTR_EGRESS_ACL, 0)

        assert pytest.tb.get_port_egress_acl(pytest.top.out_port) == 0
        # Count of dropped packets should be 2.
        debug_counter_val = pytest.tb.get_switch_stats(debug_counter_index, SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, clear=True)
        # debug counter value should have same value as ACL drop_counter
        assert debug_counter_val[0] == 2
        assert pytest.tb.get_object_attr(drop_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == 2

        # cleanup
        pytest.tb.remove_object(acl_entry1)
        pytest.tb.remove_object(acl_entry2)
        pytest.tb.remove_object(acl_entry3)
        pytest.tb.remove_object(acl_table)
        pytest.tb.remove_object(drop_counter)
        pytest.tb.remove_object(debug_counter)

    def egress_ipv4_acl_table_test(self, args=None, v4_v6=False, switch_binding=False, add_delete_port=False):
        if args is None:
            args = pytest.tb.generate_ipv4_acl_key()
        self.egress_ipv4_acl_table_test_internal(args, v4_v6, switch_acl_attachment=switch_binding, add_delete_port=add_delete_port)

    def egress_v4_v6_acl_table_test(self, v4_v6=True, switch_binding=False, add_delete_port=False):
        args = pytest.tb.generate_combined_v4_v6_acl_key()
        self.egress_ipv4_acl_table_test(args, v4_v6, switch_binding, add_delete_port)

    def ingress_ipv4_acl_user_metadata_test(
            self,
            args,
            dest_ip,
            user_meta_attr,
            user_meta_value,
            user_meta_mask,
            in_pkt,
            expected_out_pkt):
        # Collect queue objects associated with output port
        out_queue_list = pytest.tb.get_queue_list(pytest.tb.ports[pytest.top.out_port])
        queue_obj_ids = []
        for q in out_queue_list.to_pylist():
            queue_obj_ids.append(q)

        # Create ACL table.
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_PORT, SAI_ACL_BIND_POINT_TYPE_VLAN, SAI_ACL_BIND_POINT_TYPE_LAG]
        args[SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = bind_point_type_list
        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Atlest one should be true
        t1 = pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_FIELD_ROUTE_DST_USER_META)
        t2 = pytest.tb.get_object_attr(acl_table, SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_DST_USER_META)
        assert t1 or t2

        # ACE counters
        drop_counter = self.create_packet_counter(acl_table)
        permit_counter = self.create_packet_counter(acl_table)

        # ACEs.
        entry1_args = {}
        entry1_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry1_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 3
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip4, "255.255.255.255"]
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, dest_ip, "255.255.255.255"]
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] = [True, 5]
        entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_FORWARD]
        entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, permit_counter]
        acl_entry1 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry1_args)

        entry2_args = {}
        entry2_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry2_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 4
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip4, "255.255.255.255"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, dest_ip, "255.255.255.255"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry2_args[user_meta_attr] = [True, user_meta_value, user_meta_mask]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] = [True, 6]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_FORWARD]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, permit_counter]
        acl_entry2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry2_args)

        assert pytest.tb.get_object_attr(acl_entry2, user_meta_attr) == [True, user_meta_value, user_meta_mask]

        # Bind ACL
        pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, acl_table)
        assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == acl_table

        # collect stats before pkt inject
        q_stats_before = []
        for q in range(0, 8):
            q_stats_before.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

        # These packets should increment queue counters of traffic class entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC]
        U.run(self, in_pkt, pytest.top.in_port)
        U.run(self, in_pkt, pytest.top.in_port)

        # collect stats after pkt inject
        q_stats_after = []
        for q in range(0, 8):
            q_stats_after.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_after[q][0], q_stats_after[q][1]))

        # Verify the difference of packets in queue entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] before and after is 2
        assert (q_stats_after[entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] -
                q_stats_before[entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] == 0)
        assert (q_stats_after[entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] -
                q_stats_before[entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] == 2)

        # change TC and test
        new_set_tc_attr_value = [True, 7]
        pytest.tb.set_object_attr(acl_entry2, SAI_ACL_ENTRY_ATTR_ACTION_SET_TC, new_set_tc_attr_value)
        assert pytest.tb.get_object_attr(acl_entry2, SAI_ACL_ENTRY_ATTR_ACTION_SET_TC) == new_set_tc_attr_value
        q_stats_before = []
        for q in range(0, 8):
            q_stats_before.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))
        # These packets should increment queue counters of traffic class new_set_tc_attr_value
        U.run(self, in_pkt, pytest.top.in_port)
        U.run(self, in_pkt, pytest.top.in_port)
        q_stats_after = []
        for q in range(0, 8):
            q_stats_after.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_after[q][0], q_stats_after[q][1]))
        assert (q_stats_after[entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] -
                q_stats_before[entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] == 0)
        assert (q_stats_after[new_set_tc_attr_value[1]][0] - q_stats_before[new_set_tc_attr_value[1]][0] == 2)

        # Unbind ACL.
        pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)

        # Total pkt count checks
        assert pytest.tb.get_object_attr(permit_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == 4

        # cleanup
        pytest.tb.remove_object(acl_entry1)
        pytest.tb.remove_object(acl_entry2)
        pytest.tb.remove_object(acl_table)
        pytest.tb.remove_object(drop_counter)
        pytest.tb.remove_object(permit_counter)

    def ingress_ipv4_acl_em_table_user_metadata_test(self, args):
        user_meta_attr = SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_DST_USER_META
        user_meta_value = pytest.top.v4_neighbor_ip2_user_meta
        user_meta_mask = 0xf
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip4, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)
        # Host route/EM table lookup result test using DC neighbor IP and its result payload as user meta in ACL match key
        self.ingress_ipv4_acl_user_metadata_test(
            args,
            pytest.top.neighbor_ip2,
            user_meta_attr,
            user_meta_value,
            user_meta_mask,
            in_pkt,
            expected_out_pkt)

    def ingress_ipv4_acl_lpm_table_user_metadata_test(self, args):
        user_meta_attr = SAI_ACL_ENTRY_ATTR_FIELD_ROUTE_DST_USER_META
        user_meta_value = pytest.top.route_prefix3_user_meta
        user_meta_mask = 0xff
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip4, dst=pytest.top.route_ip3, ttl=64) / \
            UDP(sport=64, dport=2048)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.route_ip3, ttl=63) / \
            UDP(sport=64, dport=2048)
        # lpm route lookup result test using DIP = IP in configured subnet, and its payload user meta in ACL match key
        self.ingress_ipv4_acl_user_metadata_test(
            args,
            pytest.top.route_ip3,
            user_meta_attr,
            user_meta_value,
            user_meta_mask,
            in_pkt,
            expected_out_pkt)

    def ingress_ipv4_acl_udk_neighbor_metadata_test(self):
        args = udk.generate_ipv4_acl_udk_neighbor_metadata_key()
        self.ingress_ipv4_acl_em_table_user_metadata_test(args)

    def ingress_ipv4_acl_udk_route_metadata_test(self):
        args = udk.generate_ipv4_acl_udk_route_metadata_key()
        self.ingress_ipv4_acl_lpm_table_user_metadata_test(args)

    def ingress_ipv4_acl_udk_l3_dst_metadata_test_in_em(self):
        # When creating acl table give both ROUTE_DST_USER_META and
        # NEIGHBOR_DST_USER_META as table attribute.
        # During ACE add and testing use only one of the two attributes
        # The test uses one field at a time to create ACE and test.
        args = udk.generate_ipv4_acl_udk_l3_dest_metadata_key()
        self.ingress_ipv4_acl_em_table_user_metadata_test(args)

        # New RTF ACL infra does NOT allow create create, destroy, create sequence.
        # Hence following test scenario is execute as its own set

        # self.ingress_ipv4_acl_lpm_table_user_metadata_test(args)

    def ingress_ipv4_acl_udk_l3_dst_metadata_test_in_lpm(self):
        # For test intent, check comment in ingress_ipv4_acl_udk_l3_dst_metadata_test_in_em
        args = udk.generate_ipv4_acl_udk_l3_dest_metadata_key()
        self.ingress_ipv4_acl_lpm_table_user_metadata_test(args)

    def ingress_mac_fwding_v4_v6_udk_l2_cid_acl_test_internal(
            self, args={}, trap=False, switch_acl_attachment=False, add_delete_port=False):

        if trap:
            attr = sai_attribute_t(SAI_SWITCH_ATTR_CPU_PORT, 0)
            pytest.tb.apis[SAI_API_SWITCH].get_switch_attribute(pytest.tb.switch_id, 1, attr)
            cpu_queue_list = pytest.tb.get_queue_list(attr.value.oid)
            queue_obj_ids = []
            for q in cpu_queue_list.to_pylist():
                queue_obj_ids.append(q)
        else:
            out_queue_list = pytest.tb.get_queue_list(pytest.tb.ports[pytest.top.out_port])
            queue_obj_ids = []
            for q in out_queue_list.to_pylist():
                queue_obj_ids.append(q)
        drop_count = 0
        permit_count = 0

        acl_match_qualifier_with_ttl_only = False
        if (len(args) == 1 and SAI_ACL_TABLE_ATTR_FIELD_TTL in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_TTL]):
            acl_match_qualifier_with_ttl_only = True

        table_size = 10
        # Setting stage.
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        if switch_acl_attachment:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_SWITCH]
        else:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_PORT, SAI_ACL_BIND_POINT_TYPE_VLAN, SAI_ACL_BIND_POINT_TYPE_LAG]
        args[SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = bind_point_type_list

        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Creating drop counter
        permit_counter = self.create_packet_counter(acl_table)
        drop_counter = self.create_packet_counter(acl_table)

        # Preparing entry args.

        entry2_args = {}
        entry2_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry2_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 5
        if SAI_ACL_TABLE_ATTR_FIELD_SRC_IP in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_SRC_IP]:
            entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.v4_neighbor_ip1, "255.255.255.255"]
        if SAI_ACL_TABLE_ATTR_FIELD_DST_IP in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IP]:
            entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.v4_neighbor_ip2, "255.255.255.255"]
        if SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6 in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6]:
            entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [True, pytest.top.v6_neighbor_ip2, pytest.top.v6_full_mask]
        if SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
            entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 63, 0xff]
        if SAI_ACL_TABLE_ATTR_FIELD_DSCP in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DSCP]:
            entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 10, 0x3f]
        if SAI_ACL_TABLE_ATTR_FIELD_ECN in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_ECN]:
            entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_ECN] = [True, 1, 1]
        if SAI_ACL_TABLE_ATTR_FIELD_TTL in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_TTL]:
            entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_TTL] = [True, 64, 0xff]

        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, drop_counter]

        entry4_args = {}
        entry4_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry4_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 3
        if SAI_ACL_TABLE_ATTR_FIELD_DST_MAC in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_MAC]:
            entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC] = [True, pytest.top.neighbor_mac2, "ff:ff:ff:ff:ff:ff"]
        if SAI_ACL_TABLE_ATTR_FIELD_SRC_IP in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_SRC_IP]:
            entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.v4_neighbor_ip4, "255.255.255.255"]
        if SAI_ACL_TABLE_ATTR_FIELD_DST_IP in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IP]:
            entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.v4_neighbor_ip2, "255.255.255.255"]
        if SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6 in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6]:
            entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6] = [True, pytest.top.v6_neighbor_ip2, pytest.top.v6_full_mask]
        if SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
            entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        if SAI_ACL_TABLE_ATTR_FIELD_FDB_DST_USER_META in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_FDB_DST_USER_META]:
            entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_FDB_DST_USER_META] = [True, pytest.top.neighbor_mac2_user_meta, 0xff]
        if SAI_ACL_TABLE_ATTR_FIELD_TTL in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_TTL]:
            entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_TTL] = [True, 63, 0xff]
        entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] = [True, 5]
        if trap:
            entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_TRAP]
        else:
            entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_FORWARD]
        entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, permit_counter]

        # Create ACE
        acl_entry2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry2_args)
        pytest.tb.do_warm_boot()
        acl_entry4 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry4_args)

        if SAI_ACL_TABLE_ATTR_FIELD_DST_MAC in args.keys():
            assert pytest.tb.get_object_attr(acl_entry4, SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC) == [
                True, pytest.top.neighbor_mac2, "ff:ff:ff:ff:ff:ff"]
        if SAI_ACL_TABLE_ATTR_FIELD_FDB_DST_USER_META in args.keys():
            assert pytest.tb.get_object_attr(acl_entry4, SAI_ACL_ENTRY_ATTR_FIELD_FDB_DST_USER_META) == [
                True, pytest.top.neighbor_mac2_user_meta, 0xff]

        # Test before binding ACL
        if (SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6 in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6]) \
           or (SAI_ACL_TABLE_ATTR_FIELD_TTL in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_TTL]):
            in_v6_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.neighbor_mac1) / \
                IPv6(src=pytest.top.v6_neighbor_ip1, dst=pytest.top.v6_neighbor_ip2, hlim=64, tc=41) / \
                UDP(sport=63, dport=2048)
            expected_out_v6_pkt = in_v6_pkt
            U.run_and_compare(self, in_v6_pkt, pytest.top.in_port, expected_out_v6_pkt, pytest.top.out_port)

        if (SAI_ACL_TABLE_ATTR_FIELD_DST_IP in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IP]) \
           or (SAI_ACL_TABLE_ATTR_FIELD_TTL in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_TTL]):
            in_v4_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.neighbor_mac1) / \
                IP(src=pytest.top.v4_neighbor_ip1, dst=pytest.top.v4_neighbor_ip2, ttl=64, tos=41) / \
                UDP(sport=63, dport=2048)
            expected_out_v4_pkt = in_v4_pkt
            U.run_and_compare(self, in_v4_pkt, pytest.top.in_port, expected_out_v4_pkt, pytest.top.out_port)

        # Test after binding ACL
        if switch_acl_attachment:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, acl_table)
            if add_delete_port:
                # After attaching switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.tb.deconfigure_vlan_members()
                pytest.tb.deconfigure_bridge_ports()
                pytest.tb.configure_bridge_ports([pytest.top.in_port, pytest.top.out_port, pytest.top.mirror_dest])
                pytest.tb.configure_vlan_members([{"vlan": pytest.top.vlan, "port": pytest.top.in_port, "is_tag": False},
                                                  {"vlan": pytest.top.vlan, "port": pytest.top.out_port, "is_tag": False},
                                                  {"vlan": pytest.top.vlan, "port": pytest.top.mirror_dest, "is_tag": False}])
        else:
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, acl_table)
            if add_delete_port:
                pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)
                pytest.tb.deconfigure_vlan_members()
                pytest.tb.deconfigure_bridge_ports()
                pytest.tb.configure_bridge_ports([pytest.top.in_port, pytest.top.out_port, pytest.top.mirror_dest])
                pytest.tb.configure_vlan_members([{"vlan": pytest.top.vlan, "port": pytest.top.in_port, "is_tag": False},
                                                  {"vlan": pytest.top.vlan, "port": pytest.top.out_port, "is_tag": False},
                                                  {"vlan": pytest.top.vlan, "port": pytest.top.mirror_dest, "is_tag": False}])
                pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, acl_table)
            assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == acl_table

        # These packets should be dropped.
        if SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6 in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6]:
            U.run(self, in_v6_pkt, pytest.top.in_port)
            U.run(self, in_v6_pkt, pytest.top.in_port)
            drop_count += 2

        if SAI_ACL_TABLE_ATTR_FIELD_DST_IP in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IP]:
            U.run(self, in_v4_pkt, pytest.top.in_port)
            U.run(self, in_v4_pkt, pytest.top.in_port)
            drop_count += 2

        if (SAI_ACL_TABLE_ATTR_FIELD_TTL in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_TTL]) \
           and (SAI_ACL_TABLE_ATTR_FIELD_DST_IP not in args.keys()) \
           and (SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6 not in args.keys()):
            # ipv4 pkt with ttl = 64 should be dropped
            U.run(self, in_v4_pkt, pytest.top.in_port)
            U.run(self, in_v4_pkt, pytest.top.in_port)
            drop_count += 2
            U.run(self, in_v6_pkt, pytest.top.in_port)
            U.run(self, in_v6_pkt, pytest.top.in_port)
            drop_count += 2

        q_stats_before = []
        for q in range(0, 8):
            q_stats_before.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

        verify_q_count = 0
        if acl_match_qualifier_with_ttl_only or \
           (SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6 in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6]):
            in_v6_pkt_entry_4 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.neighbor_mac1) / \
                IPv6(src=pytest.top.v6_neighbor_ip4, dst=pytest.top.v6_neighbor_ip2, hlim=63) / \
                UDP(sport=64, dport=2048)
            # These packets should increment queue counters of traffic class 5
            U.run(self, in_v6_pkt_entry_4, pytest.top.in_port)
            U.run(self, in_v6_pkt_entry_4, pytest.top.in_port)
            verify_q_count += 2
            permit_count += 2

        if acl_match_qualifier_with_ttl_only or \
           SAI_ACL_TABLE_ATTR_FIELD_DST_IP in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IP]:
            in_v4_pkt_entry_4 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.neighbor_mac1) / \
                IP(src=pytest.top.v4_neighbor_ip4, dst=pytest.top.v4_neighbor_ip2, ttl=63) / \
                UDP(sport=64, dport=2048)
            # These packets should increment queue counters of traffic class 5
            U.run(self, in_v4_pkt_entry_4, pytest.top.in_port)
            U.run(self, in_v4_pkt_entry_4, pytest.top.in_port)
            verify_q_count += 2
            permit_count += 2

        q_stats_after = []
        for q in range(0, 8):
            q_stats_after.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_after[q][0], q_stats_after[q][1]))

        # Verify the difference of packets in queue 5 before and after
        assert (q_stats_after[entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] -
                q_stats_before[entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] == verify_q_count)

        # Set new TC
        new_set_tc_attr_value = [True, 6]
        pytest.tb.set_object_attr(acl_entry4, SAI_ACL_ENTRY_ATTR_ACTION_SET_TC, new_set_tc_attr_value)
        assert pytest.tb.get_object_attr(acl_entry4, SAI_ACL_ENTRY_ATTR_ACTION_SET_TC) == new_set_tc_attr_value

        verify_q_count = 0
        # Re-send two more packets to see if the set tc worked
        q_stats_before = []
        for q in range(0, 8):
            q_stats_before.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

        # These packets should increment queue counters of traffic class 6
        if acl_match_qualifier_with_ttl_only or \
           SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6 in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6]:
            U.run(self, in_v6_pkt_entry_4, pytest.top.in_port)
            U.run(self, in_v6_pkt_entry_4, pytest.top.in_port)
            verify_q_count += 2
            permit_count += 2

        if acl_match_qualifier_with_ttl_only or \
           SAI_ACL_TABLE_ATTR_FIELD_DST_IP in args.keys() and args[SAI_ACL_TABLE_ATTR_FIELD_DST_IP]:
            U.run(self, in_v4_pkt_entry_4, pytest.top.in_port)
            U.run(self, in_v4_pkt_entry_4, pytest.top.in_port)
            verify_q_count += 2
            permit_count += 2

        q_stats_after = []
        for q in range(0, 8):
            q_stats_after.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_after[q][0], q_stats_after[q][1]))

        assert (q_stats_after[entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] -
                q_stats_before[entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] == 0)
        assert (q_stats_after[new_set_tc_attr_value[1]][0] - q_stats_before[new_set_tc_attr_value[1]][0] == verify_q_count)

        # Unbind ACL
        if switch_acl_attachment:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, 0)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)
        assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == 0

        # Verify drop and permit counters
        assert pytest.tb.get_object_attr(drop_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == drop_count
        assert pytest.tb.get_object_attr(permit_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == permit_count

        # cleanup
        pytest.tb.remove_object(acl_entry2)
        pytest.tb.remove_object(acl_entry4)
        pytest.tb.remove_object(acl_table)
        pytest.tb.remove_object(drop_counter)
        pytest.tb.remove_object(permit_counter)

    def ingress_mac_fwding_v4_v6_acl_udk_test(self, switch_binding=False, add_delete_port=False):
        '''
            Perform ACL test using UDK fields from L2, L3, L4 packet headers.
        '''
        args = udk.generate_l2_v4_v6_udk_acl_key(pytest.request_profile)
        self.ingress_mac_fwding_v4_v6_udk_l2_cid_acl_test_internal(
            args, trap=False, switch_acl_attachment=switch_binding, add_delete_port=add_delete_port)

    def ingress_mac_fwding_v4_v6_acl_l2cid_test(self, switch_binding=False, add_delete_port=False):
        '''
            Perform ACL test using UDK fields from L2, L3, L4 packet headers and L2/FDB user meta aka class id.
        '''
        fdb_dst_user_meta_range = pytest.tb.get_object_attr(pytest.tb.switch_id, SAI_SWITCH_ATTR_FDB_DST_USER_META_DATA_RANGE)
        assert fdb_dst_user_meta_range == [1, 255]
        args = udk.generate_l2_v4_v6_l2cid_acl_key(pytest.request_profile)
        self.ingress_mac_fwding_v4_v6_udk_l2_cid_acl_test_internal(
            args, trap=False, switch_acl_attachment=switch_binding, add_delete_port=add_delete_port)

    def ingress_l2_trap_v4_v6_acl_l2cid_test(self, switch_binding=False, add_delete_port=False):
        '''
            Perform ACL test using UDK fields from L2, L3, L4 packet headers. Packets are L2 fwded and trapped.
        '''
        args = udk.generate_l2_v4_v6_l2cid_acl_key(pytest.request_profile)
        self.ingress_mac_fwding_v4_v6_udk_l2_cid_acl_test_internal(
            args, trap=True, switch_acl_attachment=switch_binding, add_delete_port=add_delete_port)

    def ingress_ipv4_acl_table_test_mirror(
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
        max_available = {}
        max_available['tables'] = pytest.tb.get_acl_table_available()[0][2]

        table_size = 10
        # Setting stage.
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        if switch_acl_attachment:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_SWITCH]
        else:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_PORT, SAI_ACL_BIND_POINT_TYPE_VLAN, SAI_ACL_BIND_POINT_TYPE_LAG]
        args[SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = bind_point_type_list

        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        max_available['entries'] = pytest.tb.get_acl_table_entry_available(acl_table)

        # Creating drop counter
        drop_counter = self.create_packet_counter(acl_table)
        permit_counter = self.create_packet_counter(acl_table)

        # Preparing entry args.
        entry1_args = {}
        entry1_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry1_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 2
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip1, "255.255.255.0"]
        entry1_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.255.0"]
        entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_FORWARD]
        entry1_args[SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS] = [True, mirror_oids]

        entry2_args = {}
        entry2_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry2_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 5
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip1, "255.255.255.255"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.255.255"]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry2_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, drop_counter]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 10, 0x3f]
        entry2_args[SAI_ACL_ENTRY_ATTR_FIELD_ECN] = [True, 1, 1]

        entry3_args = {}
        entry3_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry3_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 10
        entry3_args[SAI_ACL_ENTRY_ATTR_ADMIN_STATE] = True
        entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, "192.168.0.3", "255.255.255.255"]
        entry3_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, "192.169.0.5", "255.255.255.255"]

        entry4_args = {}
        entry4_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry4_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 3
        entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip4, "255.255.255.255"]
        entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.255.255"]
        entry4_args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, 64, 0xff]
        entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC] = [True, 5]
        entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_FORWARD]
        entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, permit_counter]
        #entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS] = [mirror_oid]

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

        if not v4_v6:
            self.check_table_attributes(acl_table, SAI_ACL_STAGE_INGRESS, max_available, 1,
                                        len(bind_point_type_list), len(entries), table_size)
        self.check_entry_attributes(acl_entry1, acl_entry2, acl_entry3, acl_table, True)
        self.check_counter_attributes(drop_counter, acl_table)
        self.check_switch_attributes()

        # Add new ACL action as ingress mirror. During ACE creation, ACL action did not include mirroring.
        # To the existing list of ACL actions, also include ingress mirroring.
        pytest.tb.set_object_attr(acl_entry4, SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS, [True, mirror_oids], verify=True)

        # Modify ACL action to include mirroring. Modify with same mirror oid as it was used during ACE create
        pytest.tb.set_object_attr(acl_entry1, SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS, [True, mirror_oids], verify=True)

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64, tos=41) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63, tos=41) / \
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

        in_pkt_entry_4 = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip4, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt_entry_4 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip4, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        # Destination port Q stats before packet injection
        q_stats_before = __port_q_stats(pytest.top.out_port)

        # Mirror port Q stats before mirroring
        mirror_port_q_stats_before = __port_q_stats(pytest.top.mirror_dest)

        # These packets should increment queue counters of traffic class 5 and mirror pkt
        U.run(self, in_pkt_entry_4, pytest.top.in_port)

        # Destination port Q stats after packet injection
        q_stats_after = __port_q_stats(pytest.top.out_port)

        # Mirror port Q stats after mirroring
        mirror_port_q_stats_after = __port_q_stats(pytest.top.mirror_dest)

        # Verify the difference of packets in queue 5 before and after is 1 on destination port
        assert (q_stats_after[entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] -
                q_stats_before[entry4_args[SAI_ACL_ENTRY_ATTR_ACTION_SET_TC][1]][0] == 1)

        # Verify the difference of packets on mirror destination port
        # queue 0 (mirror pkt uses TC zero as per mirror object attribute) is 1
        assert (mirror_port_q_stats_after[0][0] -
                mirror_port_q_stats_before[0][0] == 1)

        # Remove ACL mirror action and confirm.
        pytest.tb.set_object_attr(acl_entry4, SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS, [False, []], verify=True)

        mirror_port_q_stats_before = __port_q_stats(pytest.top.mirror_dest)

        # These packets should increment queue counters of traffic class 5 and NOT mirror pkt
        U.run(self, in_pkt_entry_4, pytest.top.in_port)

        mirror_port_q_stats_after = __port_q_stats(pytest.top.mirror_dest)

        # Should be zero
        assert (mirror_port_q_stats_after[0][0] -
                mirror_port_q_stats_before[0][0] == 0)

        assert pytest.tb.get_object_attr(drop_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == 1
        assert pytest.tb.get_object_attr(permit_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == 2

        # Verify it is not possible to delete mirror session before ACEs that use it are deleted.
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
        pytest.tb.remove_object(permit_counter)

    def ingress_ipv4_acl_table_mirror_test(self, mirror_oid, args=None, v4_v6=False, switch_binding=False, add_delete_port=False):
        if args is None:
            args = pytest.tb.generate_ipv4_acl_key()
        self.ingress_ipv4_acl_table_test_mirror(
            mirror_oid,
            args,
            v4_v6,
            switch_acl_attachment=switch_binding,
            add_delete_port=add_delete_port)
