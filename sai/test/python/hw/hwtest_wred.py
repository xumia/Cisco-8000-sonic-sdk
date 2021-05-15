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

# SDK
from leaba import sdk
# Python
import pdb
import pytest
# SAI
from packet_test_defs import *  # import scapy with extensions*
import saicli as S
# SAI HW
from sai_hw_topology import sai_hw_100G_to_50G_topology
from sai_hw_utils import leaba_tf_wait
# SDK
from leaba import debug  # must be at the end

# In order to enable access to validation scripts, include the below import
try:
    from leaba_val import *
except BaseException:
    print("validation scripts not loaded")


def test_wred(traffic_gen, sai_hw_100G_to_50G_topology, request):
    """SAI WRED test"""

    tb, top = sai_hw_100G_to_50G_topology
    te = traffic_gen

    #### Create QOS maps ####
    # DSCP -> TC
    map_key_value = [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6), (7, 7)]
    qos_map_dscp_to_tc_obj_id = tb.create_qos_map(S.SAI_QOS_MAP_TYPE_DSCP_TO_TC, map_key_value)
    tb.set_switch_attribute(S.SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP, qos_map_dscp_to_tc_obj_id)

    # TC -> queue
    map_key_value = [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6), (7, 7)]
    qos_map_tc_to_queue_obj_id = tb.create_qos_map(S.SAI_QOS_MAP_TYPE_TC_TO_QUEUE, map_key_value)
    tb.set_switch_attribute(S.SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP, qos_map_tc_to_queue_obj_id)

    # DSCP -> color
    map_key_value = [(0, S.SAI_PACKET_COLOR_GREEN), (1, S.SAI_PACKET_COLOR_GREEN), (2, S.SAI_PACKET_COLOR_GREEN), (6, S.SAI_PACKET_COLOR_GREEN),
                     (3, S.SAI_PACKET_COLOR_YELLOW), (4, S.SAI_PACKET_COLOR_YELLOW), (5, S.SAI_PACKET_COLOR_YELLOW),
                     (7, S.SAI_PACKET_COLOR_GREEN)]
    qos_map_dscp_to_color_obj_id = tb.create_qos_map(S.SAI_QOS_MAP_TYPE_DSCP_TO_COLOR, map_key_value)
    tb.set_switch_attribute(S.SAI_SWITCH_ATTR_QOS_DSCP_TO_COLOR_MAP, qos_map_dscp_to_color_obj_id)

    # enable WRED ECN
    tb.set_switch_attribute(S.SAI_SWITCH_ATTR_ECN_ECT_THRESHOLD_ENABLE, True)

    SMALL_Q_SIZE = 250 * 384
    # create wred
    wred_attr = {S.SAI_WRED_ATTR_GREEN_ENABLE: True,
                 S.SAI_WRED_ATTR_YELLOW_ENABLE: True,
                 S.SAI_WRED_ATTR_RED_ENABLE: True,
                 S.SAI_WRED_ATTR_GREEN_DROP_PROBABILITY: 100,
                 S.SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY: 100,
                 S.SAI_WRED_ATTR_RED_DROP_PROBABILITY: 100,
                 S.SAI_WRED_ATTR_GREEN_MIN_THRESHOLD: 0,
                 S.SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD: 0,
                 S.SAI_WRED_ATTR_GREEN_MAX_THRESHOLD: SMALL_Q_SIZE,
                 S.SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD: SMALL_Q_SIZE,
                 # ECN
                 S.SAI_WRED_ATTR_ECN_MARK_MODE: S.SAI_ECN_MARK_MODE_NONE}

    wred_drop_obj_id = tb.create_wred(wred_attr)

    # wred obj with drop and mark profiles (mark profile parameters taken from the drop parameters)
    wred_attr[S.SAI_WRED_ATTR_ECN_MARK_MODE] = S.SAI_ECN_MARK_MODE_ALL
    wred_attr[S.SAI_WRED_ATTR_GREEN_MAX_THRESHOLD] = 1024 * 1024 * 2
    wred_attr[S.SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD] = 1024 * 1024 * 2
    wred_drop_mark_obj_id = tb.create_wred(wred_attr)

    # wred obj with mark profile, drop turned off until the max threshold
    wred_attr[S.SAI_WRED_ATTR_ECN_MARK_MODE] = S.SAI_ECN_MARK_MODE_ALL
    wred_attr[S.SAI_WRED_ATTR_GREEN_DROP_PROBABILITY] = 0
    wred_attr[S.SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY] = 0
    wred_attr[S.SAI_WRED_ATTR_GREEN_MAX_THRESHOLD] = 1024 * 1024 * 10
    wred_attr[S.SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD] = 1024 * 1024 * 2
    wred_attr[S.SAI_WRED_ATTR_ECN_GREEN_MARK_PROBABILITY] = 100
    wred_attr[S.SAI_WRED_ATTR_ECN_YELLOW_MARK_PROBABILITY] = 50
    wred_mark_obj_id = tb.create_wred(wred_attr)

    out_queue_list = tb.get_queue_list(tb.ports[top.out_port])
    queue_obj_ids = []
    for q in out_queue_list.to_pylist():
        queue_obj_ids.append(q)

    """
    queues 0,1,2,7 Green packets with ECT bit
    queues 3,4,5 Yellow packets with ECT bit
    queue  6     Green packets with tos=0 (no ECT bit)

    queues 0,3      default wred
    queues 1,4      No mark. Drop 100% Max queue SMALL_Q_SIZE
    queues 2,5  Drop and mark both profiles. Green and yellow drop 100%. Green and Yellow mark 100%.
    non ECT queue should drop all packets. ECT queue should mark all packets within min and max
    queues 6, 7 No drop. Yellow mark 50%. Green mark 100%.
    """
    default_wred_obj_id = S.SAI_NULL_OBJECT_ID
    tb.set_queue_attr(queue_obj_ids[0], S.SAI_QUEUE_ATTR_WRED_PROFILE_ID, default_wred_obj_id)
    tb.set_queue_attr(queue_obj_ids[3], S.SAI_QUEUE_ATTR_WRED_PROFILE_ID, default_wred_obj_id)
    tb.set_queue_attr(queue_obj_ids[1], S.SAI_QUEUE_ATTR_WRED_PROFILE_ID, wred_drop_obj_id)
    tb.set_queue_attr(queue_obj_ids[4], S.SAI_QUEUE_ATTR_WRED_PROFILE_ID, wred_drop_obj_id)
    tb.set_queue_attr(queue_obj_ids[2], S.SAI_QUEUE_ATTR_WRED_PROFILE_ID, wred_drop_mark_obj_id)
    tb.set_queue_attr(queue_obj_ids[5], S.SAI_QUEUE_ATTR_WRED_PROFILE_ID, wred_drop_mark_obj_id)
    tb.set_queue_attr(queue_obj_ids[6], S.SAI_QUEUE_ATTR_WRED_PROFILE_ID, wred_mark_obj_id)
    tb.set_queue_attr(queue_obj_ids[7], S.SAI_QUEUE_ATTR_WRED_PROFILE_ID, wred_mark_obj_id)

    # get the ports up, and verify
    tb.set_port_admin_state(top.in_port, True)
    tb.set_port_admin_state(top.out_port, True)
    tb.link_state_check(top.in_port, is_up=True)
    tb.link_state_check(top.out_port, is_up=True)

    # attributes of packets to create (dscp, tos)
    packet_attributes = [(0, 1), (1, 1), (2, 1), (3, 1), (4, 1), (5, 1), (6, 0), (7, 1)]
    in_pkt = []
    for i in range(len(packet_attributes)):
        pkt_tos = packet_attributes[i][0] * 4  + packet_attributes[i][1]
        in_pkt.append(Ether(dst=tb.router_mac, src=top.neighbor_mac1) /
                      IP(src=top.neighbor_ip1, dst=top.neighbor_ip2, ttl=5, tos=pkt_tos))

    # create acls for counting packets coming in from out_port
    acl_table_args = tb.generate_ipv4_acl_key()
    acl_table_args[S.SAI_ACL_TABLE_ATTR_ACL_STAGE] = S.SAI_ACL_STAGE_INGRESS
    acl_table_args[S.SAI_ACL_TABLE_ATTR_SIZE] = 8 * 2
    acl_table = tb.create_object(S.SAI_OBJECT_TYPE_ACL_TABLE, acl_table_args)

    counter_args = {}
    counter_args[S.SAI_ACL_COUNTER_ATTR_TABLE_ID] = acl_table
    counter_args[S.SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT] = True

    acl_counter_ecn = []
    acl_counter_no_ecn = []
    for i in range(8):
        acl_counter_ecn.append(tb.create_object(S.SAI_OBJECT_TYPE_ACL_COUNTER, counter_args))
        acl_counter_no_ecn.append(tb.create_object(S.SAI_OBJECT_TYPE_ACL_COUNTER, counter_args))

    # create acl entries
    entry_args = {}
    entry_args[S.SAI_ACL_ENTRY_ATTR_TABLE_ID] = acl_table
    entry_args[S.SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, S.SAI_PACKET_ACTION_DROP]

    acl_entries_ecn = []
    acl_entries_no_ecn = []
    for i in range(8):
        entry_args[S.SAI_ACL_ENTRY_ATTR_FIELD_DSCP] = [True, i, 0x3f]

        entry_args[S.SAI_ACL_ENTRY_ATTR_PRIORITY] = i * 2
        entry_args[S.SAI_ACL_ENTRY_ATTR_FIELD_ECN] = [True, 3, 3]
        entry_args[S.SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, acl_counter_ecn[i]]
        acl_entries_ecn.append(tb.create_object(S.SAI_OBJECT_TYPE_ACL_ENTRY, entry_args))

        entry_args[S.SAI_ACL_ENTRY_ATTR_PRIORITY] = i * 2 + 1
        entry_args[S.SAI_ACL_ENTRY_ATTR_FIELD_ECN] = [True, packet_attributes[i][1], 3]
        entry_args[S.SAI_ACL_ENTRY_ATTR_ACTION_COUNTER] = [True, acl_counter_no_ecn[i]]
        acl_entries_no_ecn.append(tb.create_object(S.SAI_OBJECT_TYPE_ACL_ENTRY, entry_args))

    # bind to out port
    tb.bind_acl_to_port(top.out_port, S.SAI_PORT_ATTR_INGRESS_ACL, acl_table)

    print("Starting WRED test")

    # zero counters
    read_voq_drop_counters()

    for key, port in te.ports.items():
        te.reset_port(key)
        for i in range(8):
            # 1 packet stream
            te.add_stream(key, i, 64, in_pkt[i], 100 / 8, 0)
        te.enable_capture(key, True)
        te.clear_port_statistics(key)

    te.set_expected_streams_per_port(8)

    print("Q stats before sending")
    for i in range(8):
        q_stats = tb.get_queue_stats(queue_obj_ids[i])
        print("q {} max size {} water_mark {}".format(i, q_stats[4], q_stats[5]))

    for key, port in te.ports.items():
        te.start_traffic(key)
        # start only the first port
        break

    if request.config.getoption("--debug_mode"):
        print("Starting debugger...")
        pdb.set_trace()

    tb.do_warm_boot()

    max_q_size = [0] * 8
    water_mark = [0] * 8
    # let the traffic run for a while
    for i in range(1, 5):
        leaba_tf_wait(1)
        print("{0}:tx count {1}".format(i, te.get_tx_count()))
        print("{0}:rx count {1}".format(i, te.get_rx_count()))
        for i in range(8):
            q_stats = tb.get_queue_stats(queue_obj_ids[i])
            if q_stats[4] > max_q_size[i]:
                max_q_size[i] = q_stats[4]
            water_mark[i] = q_stats[5]

    # Stop traffic
    te.stop_all_traffic_and_disable_capture()

    for key, port in te.ports.items():
        stat_te_stream = te.get_stream_statistics(key, 0)
        break
    print("traffic generator counter for one stream")
    print(stat_te_stream)
    print("SDK registers WRED counters:")
    voq_drop_counters = read_voq_drop_counters()
    print(voq_drop_counters)

    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! SAI stats !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("Out port counters")

    tb.get_router_interface_stats(tb.rif_id_1, dump=True)

    print(" Queue statistics:")
    acl_counter_ecn_pkts = []
    acl_counter_no_ecn_pkts = []
    for i in range(8):
        acl_counter_no_ecn_pkts.append(tb.get_object_attr(acl_counter_no_ecn[i], S.SAI_ACL_COUNTER_ATTR_PACKETS))
        acl_counter_ecn_pkts.append(tb.get_object_attr(acl_counter_ecn[i], S.SAI_ACL_COUNTER_ATTR_PACKETS))
        print(
            "   q {} ecn: {} no ecn {} max size {} water_mark {}".format(
                i,
                acl_counter_ecn_pkts[i],
                acl_counter_no_ecn_pkts[i],
                max_q_size[i],
                water_mark[i]))

    print("Port statistics:")
    curr_counters = tb.get_port_stats(tb.ports[top.out_port], clear=False)
    print("sai_port_id({}), wred dropped packets({}), wred dropped bytes({}) , ecn marked packets({})".format(
        tb.ports[top.out_port], curr_counters[61], curr_counters[62], curr_counters[36]))
    assert curr_counters[61] > 0
    assert curr_counters[62] > 0
    assert curr_counters[36] > 0

    if not pytest.IS_SIMULATOR:
        for i in range(8):
            if i in (1, 4):
                # queue size should never pass the drop threshold
                assert water_mark[i] <= SMALL_Q_SIZE

            if i in (0, 1, 3, 4, 6):
                assert acl_counter_ecn_pkts[i] == 0
            else:
                assert acl_counter_ecn_pkts[i] != 0
            # todo: Q 7 has red packets, so would expect 0 ecn packets. In practice it behave as if packets are yellow

            # Small amount of packets received before Q reaches the mark all size
            assert acl_counter_ecn_pkts[2] / 1000 > acl_counter_no_ecn_pkts[2]
            # 50% mark. number of ecn and no ecn packets should be almost equal
            assert abs(acl_counter_ecn_pkts[7] - acl_counter_no_ecn_pkts[7]) < acl_counter_ecn_pkts[7] / 1000

    # -----------------------------
    # Pass/Fail
    # -----------------------------

    # put default wred back on queue
    for i in range(len(queue_obj_ids)):
        tb.set_queue_attr(queue_obj_ids[i],
                          S.SAI_QUEUE_ATTR_WRED_PROFILE_ID,
                          default_wred_obj_id)

    # remove should succeed now
    tb.remove_object(wred_drop_obj_id)
    tb.remove_object(wred_drop_mark_obj_id)
    tb.remove_object(wred_mark_obj_id)
    # put default qos map back and remove qos
    tb.set_switch_attribute(S.SAI_SWITCH_ATTR_QOS_DSCP_TO_COLOR_MAP, S.SAI_NULL_OBJECT_ID)
    tb.set_switch_attribute(S.SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP, S.SAI_NULL_OBJECT_ID)
    tb.set_switch_attribute(S.SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP, S.SAI_NULL_OBJECT_ID)
    tb.remove_object(qos_map_dscp_to_color_obj_id)
    tb.remove_object(qos_map_dscp_to_tc_obj_id)
    tb.remove_object(qos_map_tc_to_queue_obj_id)


def read_voq_drop_counters():
    la_device = sdk.la_get_device(0)
    ll_device = la_device.get_ll_device()
    dd = debug.debug_device(la_device)
    gb_tree = ll_device.get_gibraltar_tree()
    reg_vals = {}
    for ifg in range(24):
        all_voq_counters = dd.read_register(gb_tree.pdvoq_shared_mma.voq_counters[ifg])
        all_voq_counters_str = str(all_voq_counters).split('\n')
        for s in all_voq_counters_str:
            try:
                one_reg = re.search("(\\S+) .*?(0x.*)", s)
                key = "{}[{}]".format(one_reg.group(1), ifg)
                val = int(one_reg.group(2), 16)
                if val != 0:
                    reg_vals[key] = val
            except BaseException:
                pass

    all_voq_drop_counters = dd.read_register(gb_tree.pdvoq_shared_mma.voq_drop_counters)
    all_voq_drop_counters_str = str(all_voq_drop_counters).split('\n')
    for s in all_voq_drop_counters_str + all_voq_counters_str:
        try:
            one_reg = re.search("(\\S+) .*?(0x.*)", s)
            reg_vals[one_reg.group(1)] = int(one_reg.group(2), 16)
        except BaseException:
            pass
    return reg_vals
