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
import time
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


def test_trap_policer(traffic_gen, sai_hw_100G_to_50G_topology, request):
    """SAI TRAP POLICER test"""
    tb, top = sai_hw_100G_to_50G_topology
    te = traffic_gen
    CIR = 600

    trap_group = tb.create_trap_group(1)
    args = {}
    args[S.SAI_POLICER_ATTR_METER_TYPE] = S.SAI_METER_TYPE_PACKETS
    args[S.SAI_POLICER_ATTR_MODE] = S.SAI_POLICER_MODE_SR_TCM
    args[S.SAI_POLICER_ATTR_CBS] = 1024
    args[S.SAI_POLICER_ATTR_CIR] = CIR
    args[S.SAI_POLICER_ATTR_RED_PACKET_ACTION] = S.SAI_PACKET_ACTION_DROP
    trap_policer = tb.create_policer(args)
    tb.set_trap_group_policer(trap_group, trap_policer)
    ip2me_trap = tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_IP2ME, S.SAI_PACKET_ACTION_TRAP, 255, trap_group)

    in_pkt = Ether(dst=tb.router_mac, src=top.neighbor_mac1) / \
        IP(src=top.neighbor_ip1, dst=top.local_ip1, ttl=64) / \
        UDP(sport=64, dport=2048) / ("\0" * 50)

    in_port_obj = tb.ports[top.in_port]

    cpu_port = tb.get_object_attr(tb.switch_id, S.SAI_SWITCH_ATTR_CPU_PORT)
    out_queue_list = tb.get_queue_list(cpu_port)
    queue_obj_ids = []
    for q in out_queue_list.to_pylist():
        queue_obj_ids.append(q)

    # get the ports up, and verify
    tb.set_port_admin_state(top.in_port, True)
    tb.set_port_admin_state(top.out_port, True)
    tb.link_state_check(top.in_port, is_up=True)
    tb.link_state_check(top.out_port, is_up=True)

    stream_id = 0
    for key, port in te.ports.items():
        te.reset_port(key)
        te.add_stream(key, stream_id, 240, in_pkt, 100, 0)
        te.enable_capture(key, True)
        te.clear_port_statistics(key)

    te.set_expected_streams_per_port(0)

    counters = tb.get_port_stats(in_port_obj)
    tb.dump_port_stats(counters)

    for key, port in te.ports.items():
        te.start_traffic(key)
        # start only the first port
        break

    time.sleep(10)
    before_time = time.time()
    num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = tb.get_punt_packet()
    p_stats_before = tb.get_policer_stats(trap_policer)
    print("------------ cpu num pkts before {}, trap_id {}".format(num_pkts_before, hex(pkt_trap_id)))

    before_green = p_stats_before[0]
    before_cpu = num_pkts_before
    policer_speed_reached = False
    for i in range(0, 10):
        # tb.do_warm_boot()
        time.sleep(10)

        # Stop traffic
        after_time = time.time()

        num_pkts, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = tb.get_punt_packet()
        p_stats_after = tb.get_policer_stats(trap_policer)

        delta_green = p_stats_after[0] - before_green
        delta_pkts = num_pkts - before_cpu
        delta_seconds = int(after_time - before_time)
        average_cpu = delta_pkts / delta_seconds
        average_green = delta_green / delta_seconds

        print("------------ cpu num pkts after {}, trap_id {}".format(num_pkts, hex(pkt_trap_id)))

        print("-------------------------------------------------------------------------------------")
        print("cpu num pkts {} time delta {} CIR {} average cpu {}".format(delta_pkts, delta_seconds, CIR, average_cpu))
        print("cpu num greens {} time delta {} CIR {} average {}".format(
            delta_green, delta_seconds, CIR, average_green))
        print("-------------------------------------------------------------------------------------")
        if average_green >= CIR:
            policer_speed_reached = True
            break
        before_green = p_stats_after[0]
        before_cpu = num_pkts
        before_time = after_time

    assert policer_speed_reached
    te.stop_all_traffic_and_disable_capture(False)
