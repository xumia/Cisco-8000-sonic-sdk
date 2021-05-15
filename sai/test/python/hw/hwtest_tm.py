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

# Python
import pytest
import pdb
# SAI
from packet_test_defs import *  # import scapy with extensions*
import saicli as S
import sai_packet_utils as packet_utils
# SAI HW
from sai_hw_topology import sai_hw_100G_to_50G_topology
from sai_hw_utils import leaba_tf_wait

# In order to enable access to validation scripts, include the below import
try:
    from leaba_val import *
except ModuleNotFoundError:
    print("validation scripts not loaded")

# Sending high rate traffic from TG --> out_port
# Packets are lost because we send from 100G port to 50G port.
# Packets coming out of out_port, going back in (because of loopback config)
# Dropping all packets coming in on out_port, using ACLs with counters
# mapping streams:
#  DSCP -> TC, TC -> out queue.
# Queues associated to schedulers according to below:
# Stream1 queue - Strict priority scheduler - no packets should be dropped
# Stream2 queue - WRR scheduler, weight 1
# Stream3 queue - WRR scheduler, weight 2


def test_tm(traffic_gen, sai_hw_100G_to_50G_topology, request):
    """SAI traffic management test"""

    tb, top = sai_hw_100G_to_50G_topology
    te = traffic_gen

    wrr1_weight = 15
    wrr2_weight = 80

    # DSCP -> TC
    map_key_value = [(10, 7), (20, 5), (5, 4), (2, 2)]
    qos_map_dscp_to_tc_obj_id = tb.create_qos_map(S.SAI_QOS_MAP_TYPE_DSCP_TO_TC, map_key_value)
    tb.set_switch_attribute(S.SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP, qos_map_dscp_to_tc_obj_id)

    # TC -> queue
    map_key_value = [(7, 7), (5, 5), (4, 4), (2, 2)]
    qos_map_tc_to_queue_obj_id = tb.create_qos_map(S.SAI_QOS_MAP_TYPE_TC_TO_QUEUE, map_key_value)
    tb.set_switch_attribute(S.SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP, qos_map_tc_to_queue_obj_id)

    # create schedulers, and apply to out_port queues
    strict_sched_obj_id = tb.create_scheduler(S.SAI_SCHEDULING_TYPE_STRICT)
    wrr1_sched_obj_id = tb.create_scheduler(S.SAI_SCHEDULING_TYPE_WRR, wrr1_weight)
    wrr2_sched_obj_id = tb.create_scheduler(S.SAI_SCHEDULING_TYPE_WRR, wrr2_weight)
    scheduler_min_pir = 1  # Default is no limit. But here we're trying to set PIR to the minimum
    wrr2_sched_low_pir_obj_id = tb.create_scheduler(S.SAI_SCHEDULING_TYPE_WRR, wrr2_weight, scheduler_min_pir)
    out_queue_list = tb.get_queue_list(tb.ports[top.out_port])

    queue_obj_ids = []
    for q in out_queue_list.to_pylist():
        queue_obj_ids.append(q)

    tb.set_queue_attr(queue_obj_ids[7], S.SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, strict_sched_obj_id)
    tb.set_queue_attr(queue_obj_ids[5], S.SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, wrr1_sched_obj_id)
    tb.set_queue_attr(queue_obj_ids[4], S.SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, wrr2_sched_obj_id)
    tb.set_queue_attr(queue_obj_ids[2], S.SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, wrr2_sched_low_pir_obj_id)

    # get the ports up
    tb.set_port_admin_state(top.in_port, True)
    tb.set_port_admin_state(top.out_port, True)

    # check if in_port is link-up
    tb.link_state_check(top.in_port, is_up=True)
    tb.link_state_check(top.out_port, is_up=True)

    # tos 40 -> DSCP=10
    in_pkt1 = Ether(dst=tb.router_mac, src=top.neighbor_mac1) / \
        IP(src=top.neighbor_ip1, dst=top.neighbor_ip2, ttl=5, tos=40)

    # tos 80 -> DSCP=20
    in_pkt2 = Ether(dst=tb.router_mac, src=top.neighbor_mac1) / \
        IP(src=top.neighbor_ip1, dst=top.neighbor_ip2, ttl=5, tos=80)

    # tos 20 -> DSCP=5
    in_pkt3 = Ether(dst=tb.router_mac, src=top.neighbor_mac1) / \
        IP(src=top.neighbor_ip1, dst=top.neighbor_ip2, ttl=5, tos=20)

    # tos 8 -> DSCP=2
    in_pkt4 = Ether(dst=tb.router_mac, src=top.neighbor_mac1) / \
        IP(src=top.neighbor_ip1, dst=top.neighbor_ip2, ttl=5, tos=8)

    punt_pkt = Ether(dst=tb.router_mac, src=top.neighbor_mac1) / \
        IP(src=top.neighbor_ip1, dst=top.local_ip1, ttl=64) / \
        UDP(sport=64, dport=2048) / ("\0" * 50)
    ip2me_trap = tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IP2ME, S.SAI_PACKET_ACTION_TRAP)

    print("Starting SAI traffic management test")

    stream_id = 0
    for key, port in te.ports.items():
        port_name = key
        te.add_stream(key, stream_id, 64, in_pkt1, 24, 0)
        te.add_stream(key, stream_id + 1, 64, in_pkt2, 25, 0)
        te.add_stream(key, stream_id + 2, 64, in_pkt3, 25, 0)
        te.add_stream(key, stream_id + 3, 64, in_pkt4, 25, 0)
        te.add_stream(key, stream_id + 4, 64, punt_pkt, 1, 0)  # stream that will be punted to CPU
        te.enable_capture(key, True)
        te.clear_port_statistics(key)

    te.set_expected_streams_per_port(5)

    # get Q stats before the run
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Q stats before!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    out_queue_list = tb.get_queue_list(tb.ports[top.out_port])
    queue_obj_ids = []
    for q in out_queue_list.to_pylist():
        queue_obj_ids.append(q)

    q_stats_before = []
    for q in range(0, 8):
        q_stats_before.append(tb.get_queue_stats(queue_obj_ids[q]))
        print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

    # create acls for counting packets coming in from out_port
    acl_table_args = tb.generate_ipv4_acl_key()
    acl_table_args[S.SAI_ACL_TABLE_ATTR_ACL_STAGE] = S.SAI_ACL_STAGE_INGRESS
    acl_table_args[S.SAI_ACL_TABLE_ATTR_SIZE] = 10
    acl_table = tb.create_object(S.SAI_OBJECT_TYPE_ACL_TABLE, acl_table_args)
    assert acl_table != 0

    # create counters
    counter_args = {}
    counter_args[S.SAI_ACL_COUNTER_ATTR_TABLE_ID] = acl_table
    counter_args[S.SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT] = True
    acl1_counter = tb.create_object(S.SAI_OBJECT_TYPE_ACL_COUNTER, counter_args)
    acl2_counter = tb.create_object(S.SAI_OBJECT_TYPE_ACL_COUNTER, counter_args)
    acl3_counter = tb.create_object(S.SAI_OBJECT_TYPE_ACL_COUNTER, counter_args)
    acl4_counter = tb.create_object(S.SAI_OBJECT_TYPE_ACL_COUNTER, counter_args)

    # create acl entries
    entry_args = {}
    entry_args[S.SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
    entry_args[S.SAI_ACL_ENTRY_ATTR_PRIORITY] = 1
    entry_args[S.SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 10, 0x3f]
    entry_args[S.SAI_ACL_ENTRY_ATTR_FIELD_ECN] = [True, 0, 3]
    entry_args[S.SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, S.SAI_PACKET_ACTION_DROP]
    entry_args[S.SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, acl1_counter]
    acl_entry1 = tb.create_object(S.SAI_OBJECT_TYPE_ACL_ENTRY, entry_args)

    entry_args[S.SAI_ACL_ENTRY_ATTR_PRIORITY] = 2
    entry_args[S.SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, acl2_counter]
    entry_args[S.SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 20, 0x3f]
    acl_entry2 = tb.create_object(S.SAI_OBJECT_TYPE_ACL_ENTRY, entry_args)

    entry_args[S.SAI_ACL_ENTRY_ATTR_PRIORITY] = 3
    entry_args[S.SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, acl3_counter]
    entry_args[S.SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 5, 0x3f]
    acl_entry3 = tb.create_object(S.SAI_OBJECT_TYPE_ACL_ENTRY, entry_args)

    entry_args[S.SAI_ACL_ENTRY_ATTR_PRIORITY] = 4
    entry_args[S.SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, acl4_counter]
    entry_args[S.SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, 2, 0x3f]
    acl_entry3 = tb.create_object(S.SAI_OBJECT_TYPE_ACL_ENTRY, entry_args)

    # bind to out port
    tb.bind_acl_to_port(top.out_port, S.SAI_PORT_ATTR_INGRESS_ACL, acl_table)

    for key, port in te.ports.items():
        te.start_traffic(key)
        # start only the first port
        break

    if request.config.getoption("--debug_mode"):
        print("Starting debugger...")
        pdb.set_trace()

    tb.do_warm_boot()

    # let the traffic run for a while
    leaba_tf_wait(2)

    # Stop traffic
    te.stop_all_traffic_and_disable_capture()

    leaba_tf_wait(8)

    stat1 = te.get_stream_statistics(port_name, stream_id)
    packet_no_drop_stream = stat1["tx_packets"]
    stat2 = te.get_stream_statistics(port_name, stream_id + 1)
    stat3 = te.get_stream_statistics(port_name, stream_id + 2)
    stat4 = te.get_stream_statistics(port_name, stream_id + 3)

    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Q stats !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    q_stats_after = []
    for q in range(0, 8):
        q_stats_after.append(tb.get_queue_stats(queue_obj_ids[q]))
        print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_after[q][0], q_stats_after[q][1]))

    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! TE stats !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("no drop stream:")
    print(stat1)
    print("stream2:")
    print(stat2)
    print("stream3:")
    print(stat3)
    print("stream4:")
    print(stat4)

    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! SAI stats !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    acl1_cnt = tb.get_object_attr(acl1_counter, S.SAI_ACL_COUNTER_ATTR_PACKETS)
    acl2_cnt = tb.get_object_attr(acl2_counter, S.SAI_ACL_COUNTER_ATTR_PACKETS)
    acl3_cnt = tb.get_object_attr(acl3_counter, S.SAI_ACL_COUNTER_ATTR_PACKETS)
    acl4_cnt = tb.get_object_attr(acl4_counter, S.SAI_ACL_COUNTER_ATTR_PACKETS)
    print("acl counters: {0} {1} {2} {3}".format(acl1_cnt, acl2_cnt, acl3_cnt, acl4_cnt))
    print("event counter!!!!!!!!!!!")
    S.dump_event_counters(tb.switch_id)
    print("in port")
    tb.get_router_interface_stats(tb.rif_id_1, dump=True)
    print("out port")
    tb.get_router_interface_stats(tb.rif_id_2, dump=True)

    if not pytest.IS_SIMULATOR:
        assert acl1_cnt == packet_no_drop_stream
        assert acl4_cnt != 0  # Make sure not all the packets were dropped
        assert (acl4_cnt * 10000 < packet_no_drop_stream)  # Very low PIR so # of packets received are several factors fewer
        # check that packet drop ratio is according to the weights. Allow 10% error
        expected_pkt_ratio = wrr2_weight / wrr1_weight
        actual_pkt_ratio = acl3_cnt / acl2_cnt
        assert expected_pkt_ratio * 0.9 < actual_pkt_ratio or expected_pkt_ratio * 1.1 > actual_pkt_ratio
        # make sure q counters reading is OK
        assert q_stats_after[7][0] - q_stats_before[7][0] == acl1_cnt
        assert q_stats_after[5][0] - q_stats_before[5][0] == acl2_cnt
        assert q_stats_after[4][0] - q_stats_before[4][0] == acl3_cnt

    # test inject
    for i in range(10):
        tb.inject_packet_up(in_pkt1 / ("\0" * 500))
    acl1_cnt_after_inject = tb.get_object_attr(acl1_counter, S.SAI_ACL_COUNTER_ATTR_PACKETS)
    if not pytest.IS_SIMULATOR:
        assert acl1_cnt_after_inject - acl1_cnt == 10

    # test punt
    pytest.tb = tb
    in_pkt = Ether(dst=tb.router_mac, src=top.neighbor_mac1) / \
        IP(src=top.neighbor_ip1, dst=top.local_ip1, ttl=64) / \
        UDP(sport=64, dport=2048) / ("\0" * 50)
    packet_utils.punt_test(test_tm, in_pkt, top.out_port)
    tb.remove_trap(ip2me_trap)

    # test SDK msg up/down notifications
    up_msg_num_before = tb.port_state_up_msg_counts(top.in_port)
    down_msg_num_before = tb.port_state_down_msg_counts(top.in_port)
    for key, port in te.ports.items():
        te.reset_port(key)
    for i in range(10):
        leaba_tf_wait(1)
        up_msg_num_after = tb.port_state_up_msg_counts(top.in_port)
        down_msg_num_after = tb.port_state_down_msg_counts(top.in_port)
        if (up_msg_num_after == up_msg_num_before + 1) and (down_msg_num_after == down_msg_num_before + 1):
            break
