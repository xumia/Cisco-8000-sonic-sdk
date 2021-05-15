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
from sai_test_utils import *
from scapy.all import *
import sai_packet_utils as U
import sai_topology as topology
import sai_test_base as st_base
import pdb


@pytest.mark.usefixtures("basic_route_v4_one_port_topology")
class TestQOS:
    MAX_QOS_DOT1P_VAL = 15
    MAX_QOS_TC_VAL = 7
    MAX_QOS_DSCP_VAL = 63
    MAX_QOS_QUEUE_INDEX_VAL = 7
    MAX_QOS_MPLS_VAL = 7

    def add_remove_test(self, map_type, switch_map_attr, map_key_value_params, bad_key, bad_val):
        # Verify relevant get switch attribute work
        default_switch_map_oid = pytest.tb.get_switch_attribute(switch_map_attr)
        assert default_switch_map_oid == SAI_NULL_OBJECT_ID

        # get some other map OID for later use
        if switch_map_attr != SAI_SWITCH_ATTR_QOS_DOT1P_TO_COLOR_MAP:
            other_switch_map_attr = SAI_SWITCH_ATTR_QOS_DOT1P_TO_COLOR_MAP
        else:
            other_switch_map_attr = SAI_SWITCH_ATTR_QOS_DOT1P_TO_TC_MAP

        # Create new qos map, and verify qos map get type attributes work
        initial_map_key_value_params = [map_key_value_params[0]]
        qos_map_obj_id = pytest.tb.create_qos_map(map_type, initial_map_key_value_params)
        # change value list
        pytest.tb.obj_wrapper.set_attr(
            qos_map_obj_id, SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST, sai_qos_map(
                map_type, map_key_value_params), verify=True)

        pytest.tb.do_warm_boot()

        attr = pytest.tb.get_qos_map_attribute(qos_map_obj_id, SAI_QOS_MAP_ATTR_TYPE, 0)
        assert(attr.value.u32 == map_type)

        # check out of range key and val
        with expect_sai_error(SAI_STATUS_INVALID_ATTR_VALUE_MAX):
            pytest.tb.create_qos_map(map_type, [(bad_key, 1)])
            pytest.tb.create_qos_map(map_type, [(1, bad_val)])

        # test get QOS map value list
        # allocate empty qos_map, with len long enough to get our return value
        empty_qos_map = sai_qos_map(map_type, [])
        with expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            attr = pytest.tb.get_qos_map_attribute(
                qos_map_obj_id,
                SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST,
                sai_qos_map_list_t(empty_qos_map))

        empty_qos_map = sai_qos_map(map_type, [[0, 0]] * len(map_key_value_params))
        attr = pytest.tb.get_qos_map_attribute(
            qos_map_obj_id,
            SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST,
            sai_qos_map_list_t(empty_qos_map))
        res_list = sai_py_qos_map_list_t(attr.value.qosmap).list
        # verify that get return what we set
        assert(attr.value.qosmap.count == len(map_key_value_params))
        assert(str(res_list) == str(sai_qos_map(map_type, map_key_value_params)))

        # Use newly created class map
        pytest.tb.set_switch_attribute(switch_map_attr, qos_map_obj_id)
        assert pytest.tb.get_switch_attribute(switch_map_attr) == qos_map_obj_id

        # check to see that the fact that class map is used, is preserved over warm boot
        pytest.tb.do_warm_boot()

        # Should not be able to remove used QOS map
        with expect_sai_error(SAI_STATUS_OBJECT_IN_USE):
            pytest.tb.remove_object(qos_map_obj_id)

        # trying to set to QOS map with wrong type
        with expect_sai_error(SAI_STATUS_INVALID_PARAMETER):
            pytest.tb.set_switch_attribute(other_switch_map_attr, qos_map_obj_id)

        # Put back default
        pytest.tb.set_switch_attribute(switch_map_attr, SAI_NULL_OBJECT_ID)

        # Now, should be able to remove
        pytest.tb.remove_object(qos_map_obj_id)

    def test_dot1p_to_tc(self):
        map_key_value = [(1, 2), (3, 4), (5, 6)]
        self.add_remove_test(
            SAI_QOS_MAP_TYPE_DOT1P_TO_TC,
            SAI_SWITCH_ATTR_QOS_DOT1P_TO_TC_MAP,
            map_key_value,
            self.MAX_QOS_DOT1P_VAL + 1,
            self.MAX_QOS_TC_VAL + 1)

    def test_dscp_to_tc(self):
        map_key_value = [(1, 2), (3, 4), (5, 6)]
        self.add_remove_test(
            SAI_QOS_MAP_TYPE_DSCP_TO_TC,
            SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP,
            map_key_value,
            self.MAX_QOS_DSCP_VAL + 1,
            self.MAX_QOS_TC_VAL + 1)

    def test_dot1p_to_color(self):
        map_key_value = [(1, SAI_PACKET_COLOR_RED), (3, SAI_PACKET_COLOR_GREEN), (5, SAI_PACKET_COLOR_YELLOW)]
        self.add_remove_test(
            SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR,
            SAI_SWITCH_ATTR_QOS_DOT1P_TO_COLOR_MAP,
            map_key_value,
            self.MAX_QOS_DOT1P_VAL + 1,
            SAI_PACKET_COLOR_RED + 1)

    def test_dscp_to_color(self):
        map_key_value = [(1, SAI_PACKET_COLOR_RED), (3, SAI_PACKET_COLOR_GREEN), (5, SAI_PACKET_COLOR_YELLOW)]
        self.add_remove_test(
            SAI_QOS_MAP_TYPE_DSCP_TO_COLOR,
            SAI_SWITCH_ATTR_QOS_DSCP_TO_COLOR_MAP,
            map_key_value,
            self.MAX_QOS_DSCP_VAL + 1,
            SAI_PACKET_COLOR_RED + 1)

    def test_qos_to_queue(self):
        map_key_value = [(1, 2), (3, 4), (5, 6)]
        self.add_remove_test(
            SAI_QOS_MAP_TYPE_TC_TO_QUEUE,
            SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP,
            map_key_value,
            self.MAX_QOS_TC_VAL + 1,
            self.MAX_QOS_QUEUE_INDEX_VAL + 1)

    @pytest.mark.skipif(is_sai_15x(), reason="Disabled on SAI 1.5.x")
    def test_mpls_to_tc(self):
        map_key_value = [(1, 2), (3, 4), (5, 6)]
        self.add_remove_test(
            SAI_QOS_MAP_TYPE_MPLS_EXP_TO_TC,
            SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_TC_MAP,
            map_key_value,
            self.MAX_QOS_MPLS_VAL + 1,
            self.MAX_QOS_TC_VAL + 1)

    @pytest.mark.skipif(is_sai_15x(), reason="Disabled on SAI 1.5.x")
    def test_mpls_to_color(self):
        map_key_value = [(1, SAI_PACKET_COLOR_RED), (3, SAI_PACKET_COLOR_GREEN), (5, SAI_PACKET_COLOR_YELLOW)]
        self.add_remove_test(
            SAI_QOS_MAP_TYPE_MPLS_EXP_TO_COLOR,
            SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_COLOR_MAP,
            map_key_value,
            self.MAX_QOS_MPLS_VAL + 1,
            SAI_PACKET_COLOR_RED + 1)

    def test_qos_queue_change(self):
        # DSCP -> TC
        map_key_value = [(10, 7), (20, 5), (5, 4)]
        qos_map_dscp_to_tc_obj_id = pytest.tb.create_qos_map(
            SAI_QOS_MAP_TYPE_DSCP_TO_TC, map_key_value)

        qos_map_switch_map_oid = pytest.tb.get_switch_attribute(SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP)
        pytest.tb.set_switch_attribute(SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP, qos_map_dscp_to_tc_obj_id)

        # TC -> queue
        map_key_value = [(7, 7), (5, 5), (4, 4)]
        qos_map_tc_to_queue_obj_id = pytest.tb.create_qos_map(
            SAI_QOS_MAP_TYPE_TC_TO_QUEUE, map_key_value)

        qos_map_switch_map_oid2 = pytest.tb.get_switch_attribute(SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP)
        pytest.tb.set_switch_attribute(SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP, qos_map_switch_map_oid2)

        # send an inject up packet with tos 40 -> DSCP =10
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64, tos=40) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63, tos=40) / \
            UDP(sport=64, dport=2048)

        # send inject up with tos 80 -> DSCP=20
        in_pkt2 = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64, tos=80) / \
            UDP(sport=64, dport=2048)

        expected_out_pkt2 = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63, tos=80) / \
            UDP(sport=64, dport=2048)

        out_queue_list = pytest.tb.get_queue_list(pytest.tb.ports[pytest.top.out_port])

        queue_obj_ids = []
        for q in out_queue_list.to_pylist():
            queue_obj_ids.append(q)

        q_stats_before = []
        for q in range(0, 8):
            q_stats_before.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

        U.inject_up_test(self, in_pkt, expected_out_pkt)
        # inject 2 more packets with dscp 20
        U.inject_up_test(self, in_pkt2, expected_out_pkt2)
        U.inject_up_test(self, in_pkt2, expected_out_pkt2)

        out_queue_list = pytest.tb.get_queue_list(pytest.tb.ports[pytest.top.out_port])

        queue_obj_ids = []
        for q in out_queue_list.to_pylist():
            queue_obj_ids.append(q)

        q_stats_after = []
        for q in range(0, 8):
            q_stats_after.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_after[q][0], q_stats_after[q][1]))
        # verify the difference of packets (2 at queue 5 and 1 at queue 7)
        assert (q_stats_after[5][0] - q_stats_before[5][0] == 2)
        assert (q_stats_after[7][0] - q_stats_before[7][0] == 1)

        # remove the qos map
        pytest.tb.set_switch_attribute(SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP, qos_map_switch_map_oid)
        pytest.tb.set_switch_attribute(SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP, qos_map_switch_map_oid2)
        pytest.tb.remove_object(qos_map_dscp_to_tc_obj_id)
        pytest.tb.remove_object(qos_map_tc_to_queue_obj_id)

    # NOTE: this test is for port QoS attribute and therefore cannot use add_remove_test()
    def test_pfc_to_queue(self):
        map_type = SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_QUEUE
        # Note: this is not supported for now - see: MAX_QOS_PRIO_VAL 0
        # uncomment when pfc priority feature is implemented in SAI
        # map_key_value = [(1, 2), (3, 4), (5, 6)]
        # setting a key value of 0 to make the test pass, remove when
        # implemented
        map_key_value = [(0, 2)]

        # Create new qos map, and verify qos map get type attributes work
        qos_map_obj_id = pytest.tb.create_qos_map(map_type, map_key_value)
        attr = pytest.tb.get_qos_map_attribute(qos_map_obj_id, SAI_QOS_MAP_ATTR_TYPE, 0)
        assert(attr.value.u32 == map_type)

        empty_qos_map = sai_qos_map(map_type, [[0, 0]] * len(map_key_value))
        attr = pytest.tb.get_qos_map_attribute(
            qos_map_obj_id,
            SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST,
            sai_qos_map_list_t(empty_qos_map))
        res_list = sai_py_qos_map_list_t(attr.value.qosmap).list

        # verify that get return what we set
        assert(attr.value.qosmap.count == len(map_key_value))
        assert(str(res_list) == str(sai_qos_map(map_type, map_key_value)))

        # cleanup the object created earlier
        pytest.tb.remove_object(qos_map_obj_id)

        # Create new qos map, and verify qos map get type attributes work
        # -ve test: key > 0 for index is invalid as not supported for now
        with expect_sai_error(SAI_STATUS_INVALID_ATTR_VALUE_MAX):
            qos_map_obj_id = pytest.tb.create_qos_map(map_type, [(1, 2), (2, 3)])
            pytest.tb.remove_object(qos_map_obj_id)
