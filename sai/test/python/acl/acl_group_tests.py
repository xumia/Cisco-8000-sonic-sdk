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
from scapy.all import *
import sai_topology as topology


class acl_group_tests():

    def ingress_acl_table_group_test(self, switch_acl_attachment=False, add_delete_port=False):
        # Creating Table Group...
        args = {}
        args[SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_GROUP_ATTR_TYPE] = SAI_ACL_TABLE_GROUP_TYPE_PARALLEL
        if switch_acl_attachment:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_SWITCH]
        else:
            bind_point_type_list = [SAI_ACL_BIND_POINT_TYPE_PORT, SAI_ACL_BIND_POINT_TYPE_VLAN, SAI_ACL_BIND_POINT_TYPE_LAG]
        args[SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST] = bind_point_type_list
        acl_table_group = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP, args)
        assert pytest.tb.get_object_attr(acl_table_group, SAI_ACL_TABLE_GROUP_ATTR_TYPE) == SAI_ACL_TABLE_GROUP_TYPE_PARALLEL
        assert pytest.tb.get_object_attr(acl_table_group, SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST) == bind_point_type_list

        if switch_acl_attachment:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, acl_table_group)
            if add_delete_port:
                # After attach switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1()
                pytest.top.configure_rif_id_1(pytest.top.in_port)
        else:
            # Binding Table Group to a port
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, acl_table_group)
            assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == acl_table_group

        # Send packet that should pass...
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=63, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=63, dport=2048)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # Creating IPv4 Table...
        args = pytest.tb.generate_ipv4_acl_key()
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Creating drop counter...
        counter_args = {}
        counter_args[SAI_ACL_COUNTER_ATTR_TABLE_ID] = acl_table
        counter_args[SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT] = True
        drop_counter = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_COUNTER, counter_args)

        # Creating Table entry...
        entry_args = {}
        entry_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 2
        entry_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip1, "255.255.255.255"]
        entry_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.255.255"]
        entry_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, drop_counter]

        acl_entry = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry_args)

        # Creating first group member...
        args = {}
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID] = acl_table_group
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID] = acl_table
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY] = 0

        acl_table_group_member = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, args)

        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        # Creating IPv6 Table...
        args = pytest.tb.generate_ipv6_acl_key()
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        acl_table2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        pytest.tb.do_warm_boot()

        # Creating second group member...
        args = {}
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID] = acl_table_group
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID] = acl_table2
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY] = 0
        acl_table_group_member2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, args)
        """

        if switch_acl_attachment:
            if add_delete_port:
                # After attach switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1()
                pytest.top.configure_rif_id_1(pytest.top.in_port)

        # Sending packet...
        U.run(self, in_pkt, pytest.top.in_port)

        # Count of dropped packets should be 1.
        assert pytest.tb.get_object_attr(drop_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == 1

        # Unbinding ACL Table Group
        if switch_acl_attachment:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, 0)
            if add_delete_port:
                # After attach switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1()
                pytest.top.configure_rif_id_1(pytest.top.in_port)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)
            assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == 0

        # cleanup
        pytest.tb.remove_object(acl_table_group_member)
        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        pytest.tb.remove_object(acl_table_group_member2)
        """
        pytest.tb.remove_object(acl_table_group)
        pytest.tb.remove_object(acl_entry)
        pytest.tb.remove_object(acl_table)
        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        pytest.tb.remove_object(acl_table2)
        """
        pytest.tb.remove_object(drop_counter)

    def egress_acl_table_group_test(self, switch_acl_attachment=False, add_delete_port=False):
        # Creating Table Group...
        args = {}
        args[SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE] = SAI_ACL_STAGE_EGRESS
        acl_table_group = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP, args)

        if switch_acl_attachment:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, acl_table_group)
            if add_delete_port:
                # After attach switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1()
                pytest.top.configure_rif_id_1(pytest.top.in_port)
        else:
            # Binding Table Group to a port
            pytest.tb.bind_acl_to_port(pytest.top.out_port, SAI_PORT_ATTR_EGRESS_ACL, acl_table_group)
            assert pytest.tb.get_port_egress_acl(pytest.top.out_port) == acl_table_group

        # Send packet that should pass...
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=63, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=63, dport=2048)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # Creating IPv4 Table...
        args = pytest.tb.generate_ipv4_acl_key()
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_EGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Creating drop counter...
        counter_args = {}
        counter_args[SAI_ACL_COUNTER_ATTR_TABLE_ID] = acl_table
        counter_args[SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT] = True
        drop_counter = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_COUNTER, counter_args)

        debug_counter = pytest.tb.create_debug_counter(SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS, SAI_IN_DROP_REASON_ACL_ANY)
        debug_counter_index = pytest.tb.get_object_attr(debug_counter, SAI_DEBUG_COUNTER_ATTR_INDEX)
        # make sure it is cleared
        pytest.tb.get_switch_stats(debug_counter_index, SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, clear=True)

        # Creating Table entry...
        entry_args = {}
        entry_args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
        entry_args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 2
        entry_args[SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP] = [True, pytest.top.neighbor_ip1, "255.255.255.255"]
        entry_args[SAI_ACL_ENTRY_ATTR_FIELD_DST_IP] = [True, pytest.top.neighbor_ip2, "255.255.255.255"]
        entry_args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        entry_args[SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, drop_counter]
        acl_entry = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, entry_args)

        # Creating first group member...
        args = {}
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID] = acl_table_group
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID] = acl_table
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY] = 0
        acl_table_group_member = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, args)

        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        # Creating IPv6 Table...
        args = pytest.tb.generate_ipv6_acl_key()
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_EGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        acl_table2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Creating second group member...
        args = {}
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID] = acl_table_group
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID] = acl_table2
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY] = 0
        acl_table_group_member2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, args)
        """

        if switch_acl_attachment:
            if add_delete_port:
                # After attach switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1()
                pytest.top.configure_rif_id_1(pytest.top.in_port)

        # Sending packet...
        U.run(self, in_pkt, pytest.top.in_port)
        assert pytest.tb.get_object_attr(drop_counter, SAI_ACL_COUNTER_ATTR_PACKETS) == 1
        debug_counter_val = pytest.tb.get_switch_stats(debug_counter_index, SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, clear=True)
        # debug counter value should have same value as ACL drop_counter
        assert debug_counter_val[0] == 1

        # Unbinding ACL Table Group
        if switch_acl_attachment:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, 0)
            if add_delete_port:
                # After attach switch acl, delete port and add back port to
                # check if switch ACL applies to the newly created port or not.
                pytest.top.deconfigure_rif_id_1()
                pytest.top.configure_rif_id_1(pytest.top.in_port)
        else:
            pytest.tb.bind_acl_to_port(pytest.top.out_port, SAI_PORT_ATTR_EGRESS_ACL, 0)
        assert pytest.tb.get_port_egress_acl(pytest.top.out_port) == 0

        # cleanup
        pytest.tb.remove_object(acl_table_group_member)
        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        pytest.tb.remove_object(acl_table_group_member2)
        """
        pytest.tb.remove_object(acl_table_group)
        pytest.tb.remove_object(acl_entry)
        pytest.tb.remove_object(acl_table)
        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        pytest.tb.remove_object(acl_table2)
        """
        pytest.tb.remove_object(drop_counter)
        pytest.tb.remove_object(debug_counter)
