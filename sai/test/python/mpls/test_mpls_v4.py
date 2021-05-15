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

import pytest
import random
import saicli as S
from scapy.all import *
from sai_packet_test_defs import *
import sai_test_utils as st_utils
import sai_packet_utils as U


@pytest.mark.usefixtures("mpls_v4_topology")
class Test_mpls_v4():

    def test_topology_config(self):
        pytest.top.deconfigure_mpls_topology()
        pytest.top.configure_mpls_topology()
        pytest.top.deconfigure_mpls_topology()
        pytest.top.configure_mpls_topology()

    @pytest.mark.skipif(True, reason="Currently fail. Need to fix")
    def test_topology_invalid_label_size_config(self):
        pytest.top.configure_mpls_topology_unsupported_label_size()
        pytest.top.deconfigure_mpls_topology_unsupported_label_size

    # inseg_entry with next hop = next_hop_group with two entries:
    #                             next_hop MPLS, and next_hop IP
    def test_inseg_to_next_hop_group(self):

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            MPLS(label=pytest.top.mpls_in_next_hop, ttl=64) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.route3_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        in_pkt2 = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            MPLS(label=pytest.top.mpls_in_next_hop2, ttl=64) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.route3_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.route3_ip, ttl=63) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt2 = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            MPLS(label=pytest.top.mpls_out_label, ttl=63) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.route3_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        # Sending two different packets, to explore both ECMP paths
        # Found out by trial and error two labels mapped to two different paths
        U.run_and_compare_set(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt, pytest.top.in_port: expected_out_pkt2})

        U.run_and_compare_set(
            self, in_pkt2, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt, pytest.top.in_port: expected_out_pkt2})

    # route with next hop = next_hop_group with two entries:
    #                       next_hop MPLS, and next_hop IP
    def test_route_to_next_hop_group(self):
        for i in range(5):
            # random port, so we will explore both ECMP paths
            udp_port = random.randint(1000, 2000)

            in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
                IP(src=pytest.top.neighbor_ip1, dst=pytest.top.route3_ip, ttl=64) / \
                UDP(sport=64, dport=udp_port)

            expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
                IP(src=pytest.top.neighbor_ip1, dst=pytest.top.route3_ip, ttl=63) / \
                UDP(sport=64, dport=udp_port)

            expected_out_pkt2 = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
                MPLS(label=pytest.top.mpls_out_label, ttl=63) / \
                IP(src=pytest.top.neighbor_ip1, dst=pytest.top.route3_ip, ttl=63) / \
                UDP(sport=64, dport=udp_port)

            U.run_and_compare_set(
                self, in_pkt, pytest.top.in_port, {
                    pytest.top.out_port: expected_out_pkt, pytest.top.in_port: expected_out_pkt2})

    # route with next hop = next_hop type MPLS
    def test_push(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.route4_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            MPLS(label=pytest.top.mpls_out_label, ttl=63) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.route4_ip, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.in_port)

    # inseg_entry with next hop = next_hop type IP
    def test_php(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            MPLS(label=pytest.top.mpls_in_label_php, ttl=64) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

    # inseg_entry with next hop = next_hop type MPLS
    def test_swap(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            MPLS(label=pytest.top.mpls_in_label_swap, ttl=64) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)  / ("\0" * 100)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            MPLS(label=pytest.top.mpls_out_label, ttl=63) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048) / ("\0" * 100)

        rif_1_before = pytest.tb.get_router_interface_stats(pytest.tb.rif_id_1)
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.in_port)
        rif_1_after = pytest.tb.get_router_interface_stats(pytest.tb.rif_id_1, dump=True)

        # verify counter values
        rif_1_before[S.SAI_ROUTER_INTERFACE_STAT_IN_OCTETS] += len(in_pkt) + 4  # + 4 because of FCS
        rif_1_before[S.SAI_ROUTER_INTERFACE_STAT_OUT_OCTETS] += len(expected_out_pkt) + 4
        rif_1_before[S.SAI_ROUTER_INTERFACE_STAT_IN_PACKETS] += 1
        rif_1_before[S.SAI_ROUTER_INTERFACE_STAT_OUT_PACKETS] += 1
        rif_1_before[S.SAI_ROUTER_INTERFACE_STAT_MPLS_IN_OCTETS] += len(in_pkt) + 4  # + 4 because of FCS
        rif_1_before[S.SAI_ROUTER_INTERFACE_STAT_MPLS_OUT_OCTETS] += len(expected_out_pkt) + 4
        rif_1_before[S.SAI_ROUTER_INTERFACE_STAT_MPLS_IN_PACKETS] += 1
        rif_1_before[S.SAI_ROUTER_INTERFACE_STAT_MPLS_OUT_PACKETS] += 1

        assert rif_1_before == rif_1_after

    # inseg_entry with next hop = rif of type SAI_ROUTER_INTERFACE_TYPE_MPLS_ROUTER
    def test_pop(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            MPLS(label=pytest.top.mpls_in_label_pop, ttl=64) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

    def test_create_set_get_remove(self):
        label = 5
        num_pop = 1

        # create entry with no attributes
        attrs = {}
        inseg_entry = pytest.tb.create_inseg_entry(label, attrs)

        # set and verify NUM_OF_POP attribute value
        pytest.tb.set_object_attr(inseg_entry, S.SAI_INSEG_ENTRY_ATTR_NUM_OF_POP, num_pop, verify=True)

        # change and verify NEXT_HOP_ID value
        pytest.tb.set_object_attr(inseg_entry, S.SAI_INSEG_ENTRY_ATTR_NEXT_HOP_ID, pytest.tb.rif_id_mpls_in, verify=True)

        # We only support get for below attributes
        assert 0 == pytest.tb.get_object_attr(inseg_entry, S.SAI_INSEG_ENTRY_ATTR_TRAP_PRIORITY)
        assert S.SAI_PACKET_ACTION_FORWARD == pytest.tb.get_object_attr(inseg_entry, S.SAI_INSEG_ENTRY_ATTR_PACKET_ACTION)

        # remove the entry
        pytest.tb.remove_object(inseg_entry)

    @pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
    def test_mpls_qos_queue_change(self):
        # MPLS -> TC
        map_key_value = [(2, 7), (3, 5), (5, 4)]
        qos_map_mpls_to_tc_obj_id = pytest.tb.create_qos_map(
            S.SAI_QOS_MAP_TYPE_MPLS_EXP_TO_TC, map_key_value)

        qos_map_switch_map_oid = pytest.tb.get_switch_attribute(S.SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_TC_MAP)
        pytest.tb.set_switch_attribute(S.SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_TC_MAP, qos_map_mpls_to_tc_obj_id)

        # TC -> queue
        map_key_value = [(7, 7), (5, 5), (4, 4)]
        qos_map_tc_to_queue_obj_id = pytest.tb.create_qos_map(
            S.SAI_QOS_MAP_TYPE_TC_TO_QUEUE, map_key_value)

        qos_map_switch_map_oid2 = pytest.tb.get_switch_attribute(S.SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP)
        pytest.tb.set_switch_attribute(S.SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP, qos_map_switch_map_oid2)

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            MPLS(label=pytest.top.mpls_in_label_swap, cos=2, ttl=64) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            MPLS(label=pytest.top.mpls_out_label, cos=2, ttl=63) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        in_pkt2 = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            MPLS(label=pytest.top.mpls_in_label_swap, cos=3, ttl=64) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt2 = Ether(dst=pytest.top.neighbor_mac1, src=pytest.tb.router_mac) / \
            MPLS(label=pytest.top.mpls_out_label, cos=3, ttl=63) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        out_queue_list = pytest.tb.get_queue_list(pytest.tb.ports[pytest.top.in_port])

        queue_obj_ids = []
        for q in out_queue_list.to_pylist():
            queue_obj_ids.append(q)

        q_stats_before = []
        for q in range(0, 8):
            q_stats_before.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.in_port)
        U.run_and_compare(self, in_pkt2, pytest.top.in_port, expected_out_pkt2, pytest.top.in_port)
        U.run_and_compare(self, in_pkt2, pytest.top.in_port, expected_out_pkt2, pytest.top.in_port)

        out_queue_list = pytest.tb.get_queue_list(pytest.tb.ports[pytest.top.in_port])

        queue_obj_ids = []
        for q in out_queue_list.to_pylist():
            queue_obj_ids.append(q)

        q_stats_after = []
        for q in range(0, 8):
            q_stats_after.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_after[q][0], q_stats_after[q][1]))
        # verify the difference of packets
        assert (q_stats_after[5][0] - q_stats_before[5][0] == 2)
        assert (q_stats_after[7][0] - q_stats_before[7][0] == 1)

        # remove the qos map
        pytest.tb.set_switch_attribute(S.SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_TC_MAP, qos_map_switch_map_oid)
        pytest.tb.set_switch_attribute(S.SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP, qos_map_switch_map_oid2)
        pytest.tb.remove_object(qos_map_mpls_to_tc_obj_id)
        pytest.tb.remove_object(qos_map_tc_to_queue_obj_id)
