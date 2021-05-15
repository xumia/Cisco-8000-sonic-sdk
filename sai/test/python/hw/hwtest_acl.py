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
import pdb

# SAI
import saicli as S
from sai_packet_test_defs import *  # import scapy with extensions*
import sai_packet_utils as spu
import sai_test_utils as stu
import sai_topology as stp


def test_acl(init_device_and_ports):

    tb = init_device_and_ports.sai_test_base

    # create basic test topology
    top = stp.sai_topology(tb, "v4")
    # packets sent to neighbor_mac2 will come back to our device (because of loopback config)
    # We don't want them to get dropped because of wrong MAC address
    top.neighbor_mac2 = tb.router_mac
    # 2x25=50G loopback ports
    top.in_port_cfg = stu.port_config(top.in_port, 2, 25, 1514, S.SAI_PORT_INTERNAL_LOOPBACK_MODE_MAC)
    top.out_port_cfg = stu.port_config(top.out_port, 2, 25, 1514, S.SAI_PORT_INTERNAL_LOOPBACK_MODE_MAC)
    top.configure_basic_route_topology()

    # create DSCP->Q QOS map on out port
    # DSCP -> TC
    map_key_value = [(10, 7), (20, 5), (5, 4), (2, 2)]
    qos_map_dscp_to_tc_obj_id = tb.create_qos_map(S.SAI_QOS_MAP_TYPE_DSCP_TO_TC, map_key_value)
    tb.set_switch_attribute(S.SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP, qos_map_dscp_to_tc_obj_id)

    # TC -> queue
    map_key_value = [(7, 7), (5, 5), (4, 4), (2, 2)]
    qos_map_tc_to_queue_obj_id = tb.create_qos_map(S.SAI_QOS_MAP_TYPE_TC_TO_QUEUE, map_key_value)
    tb.set_switch_attribute(S.SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP, qos_map_tc_to_queue_obj_id)

    # ######### create ACLs #########
    # Create egress ACL table
    acl_egress_table_args = tb.generate_ipv4_acl_key()
    acl_egress_table_args[S.SAI_ACL_TABLE_ATTR_ACL_STAGE] = S.SAI_ACL_STAGE_INGRESS
    acl_egress_table_args[S.SAI_ACL_TABLE_ATTR_SIZE] = 10
    acl_egress_table = tb.create_object(S.SAI_OBJECT_TYPE_ACL_TABLE, acl_egress_table_args)

    # Create ingress ACL on out port - action: copy packet to CPU
    acl_ingress_table_args = tb.generate_ipv4_acl_key()
    acl_ingress_table_args[S.SAI_ACL_TABLE_ATTR_ACL_STAGE] = S.SAI_ACL_STAGE_INGRESS
    acl_ingress_table_args[S.SAI_ACL_TABLE_ATTR_SIZE] = 10
    acl_ingress_table = tb.create_object(S.SAI_OBJECT_TYPE_ACL_TABLE, acl_ingress_table_args)

    # create ACL counters
    counter_args = {}
    counter_args[S.SAI_ACL_COUNTER_ATTR_TABLE_ID] = acl_ingress_table
    counter_args[S.SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT] = True
    acl_ingress_counter = tb.create_object(S.SAI_OBJECT_TYPE_ACL_COUNTER, counter_args)

    counter_args[S.SAI_ACL_COUNTER_ATTR_TABLE_ID] = acl_egress_table
    acl_egress_counter = tb.create_object(S.SAI_OBJECT_TYPE_ACL_COUNTER, counter_args)

    # create acl entries
    # Create egress ACL on out port - action: change DSCP
    entry_args = {}
    entry_args[S.SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_egress_table
    entry_args[S.SAI_ACL_ENTRY_ATTR_PRIORITY] = 1
    entry_args[S.SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 10, 0x3f]
    entry_args[S.SAI_ACL_ENTRY_ATTR_FIELD_ECN] = [True, 0, 3]
    #entry_args[S.SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, S.SAI_PACKET_ACTION_FORWARD]
    entry_args[S.SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, acl_egress_counter]
    entry_args[S.SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP] = [True, 5]
    acl_egress_entry = tb.create_object(S.SAI_OBJECT_TYPE_ACL_ENTRY, entry_args)

    entry_args = {}
    entry_args[S.SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_ingress_table
    entry_args[S.SAI_ACL_ENTRY_ATTR_PRIORITY] = 1
    entry_args[S.SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, S.SAI_PACKET_ACTION_TRAP]
    entry_args[S.SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, acl_ingress_counter]
    acl_ingress_entry = tb.create_object(S.SAI_OBJECT_TYPE_ACL_ENTRY, entry_args)

    # bind to out port
    tb.bind_acl_to_port(top.out_port, S.SAI_PORT_ATTR_INGRESS_ACL, acl_ingress_table)
    tb.bind_acl_to_port(top.in_port, S.SAI_PORT_ATTR_INGRESS_ACL, acl_egress_table)

    # print output Q stats before traffic
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Q stats before traffic !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    out_queue_list = tb.get_queue_list(tb.ports[top.out_port])
    queue_obj_ids = []
    for q in out_queue_list.to_pylist():
        queue_obj_ids.append(q)

    q_stats_before = []
    for q in range(0, 8):
        q_stats_before.append(tb.get_queue_stats(queue_obj_ids[q]))
        print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

    pad_len = 50
    in_ttl = 5
    # tos 40 -> DSCP=10
    in_pkt = Ether(dst=tb.router_mac, src=top.neighbor_mac1) / \
        IP(src=top.neighbor_ip1, dst=top.neighbor_ip2, ttl=in_ttl, tos=40) / ("\0" * pad_len)
    # tos 20 -> DSCP=5
    expected_out_pkt = Ether(dst=top.neighbor_mac2, src=tb.router_mac) / \
        IP(src=top.neighbor_ip1, dst=top.neighbor_ip2, ttl=in_ttl - 1, tos=20) / ("\0" * pad_len)
    # inject packet with SAI_HOSTIF_TX_TYPE_PIPELINE_BYPASS
    tb.inject_packet_down(in_pkt, top.in_port)

    # print output Q stats after traffic
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Q stats after traffic!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    q_stats_after = []
    for q in range(0, 8):
        q_stats_after.append(tb.get_queue_stats(queue_obj_ids[q]))
        print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_after[q][0], q_stats_after[q][1]))

    out_port_ingress_pkt_count = tb.get_object_attr(acl_ingress_counter, S.SAI_ACL_COUNTER_ATTR_PACKETS)
    print("ACL counters: ingress pkt count {}".format(out_port_ingress_pkt_count))
    out_port_egress_pkt_count = tb.get_object_attr(acl_egress_counter, S.SAI_ACL_COUNTER_ATTR_PACKETS)
    print("ACL counters: egress pkt count {}".format(out_port_egress_pkt_count))

    # receive packet on CPU
    num_pkts, out_pkt, sip, trap_id, dst_port = tb.get_punt_packet()
    spu.assertEqualPackets("ACL test", out_pkt, spu.scapy_to_hex(expected_out_pkt))

    # cleanup
    tb.remove_object(acl_ingress_entry)
    tb.remove_object(acl_egress_entry)
    tb.remove_object(acl_ingress_counter)
    tb.remove_object(acl_egress_counter)
    tb.bind_acl_to_port(top.out_port, S.SAI_PORT_ATTR_INGRESS_ACL, S.SAI_NULL_OBJECT_ID)
    tb.bind_acl_to_port(top.in_port, S.SAI_PORT_ATTR_INGRESS_ACL, S.SAI_NULL_OBJECT_ID)
    tb.remove_object(acl_ingress_table)
    tb.remove_object(acl_egress_table)
