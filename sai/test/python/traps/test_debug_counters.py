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
import saicli as S
import sai_packet_utils as U
import sai_test_base as st_base
import sai_test_utils as st_utils
from scapy.all import *
import sai_topology as topology
from datetime import datetime


@pytest.mark.usefixtures("next_hop_group_v4_topology")
class Test_debug_counters():
    def create_error_pkts(self):
        error_pkts = {}
        # dst = route_prefix2 -> SAI_IN_DROP_REASON_DIP_LINK_LOCAL
        error_pkts[S.SAI_IN_DROP_REASON_DIP_LINK_LOCAL] = \
            [Ether(dst=pytest.top.svi_mac, src=pytest.top.neighbor_mac1) /
             IP(src=pytest.top.neighbor_ip1, dst=pytest.top.route_prefix2, ttl=64) /
             UDP(sport=64, dport=2048)]

        # Unknown dot1q tag at ingress -> SAI_IN_DROP_REASON_INGRESS_VLAN_FILTER
        error_pkts[S.SAI_IN_DROP_REASON_INGRESS_VLAN_FILTER] = \
            [Ether(dst=pytest.top.svi_mac, src=pytest.top.neighbor_mac1) /
             Dot1Q(vlan=123) /
             IP(src=pytest.top.neighbor_ip1, dst="12.12.12.12", ttl=64) /
             UDP(sport=64, dport=2048)]

        # currently we forward STP packets, so relevant counter will always be 0
        # IP(src=pytest.top.neighbor_ip1, dst="12.12.12.12", ttl=64) /
        # error_pkts[S.SAI_IN_DROP_REASON_INGRESS_STP_FILTER] = \
        #  [Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.neighbor_mac1) /
        #   LLC() / STP ()]

        # Bad checksum -> SAI_IN_DROP_REASON_IP_HEADER_ERROR)
        error_pkts[S.SAI_IN_DROP_REASON_IP_HEADER_ERROR] = \
            [Ether(dst=pytest.top.svi_mac, src=pytest.top.neighbor_mac1) /
             IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64, chksum=0x1234) /
             UDP(sport=64, dport=2048),
             # TTL = 0 -> SAI_IN_DROP_REASON_IP_HEADER_ERROR
             Ether(dst=pytest.top.svi_mac, src=pytest.top.neighbor_mac1) /
             IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=0) /
             UDP(sport=64, dport=2048),
             # LA_EVENT_IPV4_OPTIONS_EXIST -> SAI_IN_DROP_REASON_IP_HEADER_ERROR
             Ether(dst=pytest.top.svi_mac, src=pytest.top.neighbor_mac1) /
             IP(ihl=0x46, src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) /
             UDP(sport=64, dport=2048),
             ]

        # L2 - going out from same interface
        error_pkts[S.SAI_IN_DROP_REASON_L2_LOOPBACK_FILTER] = \
            [Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.neighbor_mac1) /
             IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) /
             UDP(sport=64, dport=2048)]

        # Bad L3 protocol -> SAI_IN_DROP_REASON_NO_L3_HEADER
        error_pkts[S.SAI_IN_DROP_REASON_NO_L3_HEADER] = \
            [Ether(type=0xaa, dst=pytest.top.svi_mac, src=pytest.top.neighbor_mac1, ) /
             IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) /
             UDP(sport=64, dport=2048)]

        # disabled intentionally. There is request to forward these packets
        # SMAC == DMAC -> SAI_IN_DROP_REASON_SMAC_EQUALS_DMAC
        # error_pkts[S.SAI_IN_DROP_REASON_SMAC_EQUALS_DMAC] = \
        #  [Ether(dst=pytest.tb.router_mac, src=pytest.tb.router_mac) /
        #   IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) /
        #   UDP(sport=64, dport=2048)]

        # SMAC == multicast -> SAI_IN_DROP_REASON_SMAC_MULTICAST
        error_pkts[S.SAI_IN_DROP_REASON_SMAC_MULTICAST] = \
            [Ether(dst=pytest.top.svi_mac, src="ff:ff:00:00:00:00") /
             IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) /
             UDP(sport=64, dport=2048)]

        # TTL = 1 -> SAI_IN_DROP_REASON_TTL
        error_pkts[S.SAI_IN_DROP_REASON_TTL] = \
            [Ether(dst=pytest.top.svi_mac, src=pytest.top.neighbor_mac1) /
             IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=1) /
             UDP(sport=64, dport=2048)]

        # No route to dst IP -> SAI_IN_DROP_REASON_LPM4_MISS
        error_pkts[S.SAI_IN_DROP_REASON_LPM4_MISS] = \
            [Ether(dst=pytest.top.svi_mac, src=pytest.top.neighbor_mac1) /
             IP(src=pytest.top.neighbor_ip1, dst="1.2.3.4", ttl=64) /
             UDP(sport=64, dport=2048)]
        return error_pkts

    def test_query_attributes(self):
        count, cap_list = pytest.tb.query_attribute_enum_values_capability(
            S.SAI_OBJECT_TYPE_DEBUG_COUNTER, S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST)

        # assert that result makes some sense
        assert count > 0
        error_pkts = self.create_error_pkts()
        for reason in error_pkts.keys():
            assert reason in cap_list

        count, cap_list = pytest.tb.query_attribute_enum_values_capability(
            S.SAI_OBJECT_TYPE_DEBUG_COUNTER, S.SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST)
        assert count == 0

        with st_utils.expect_sai_error(S.SAI_STATUS_INVALID_PARAMETER):
            attr_cap = pytest.tb.query_attribute_capability(S.SAI_OBJECT_TYPE_DEBUG_COUNTER, 0x1111)

        attr_cap_type = pytest.tb.query_attribute_capability(S.SAI_OBJECT_TYPE_DEBUG_COUNTER, S.SAI_DEBUG_COUNTER_ATTR_TYPE)
        attr_cap_index = pytest.tb.query_attribute_capability(S.SAI_OBJECT_TYPE_DEBUG_COUNTER, S.SAI_DEBUG_COUNTER_ATTR_INDEX)
        assert attr_cap_type["create"]
        assert attr_cap_type["set"] == False
        assert attr_cap_type["get"]
        assert attr_cap_index["create"] == False
        assert attr_cap_index["set"] == False
        assert attr_cap_index["get"]

    # test all supported drop reasons
    def test_error_pkts(self):
        # send packets causing errors
        error_pkts = self.create_error_pkts()
        counter_indexes = []
        expected_counter_vals = []
        all_reasons = []

        ttl_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_TTL_ERROR, S.SAI_PACKET_ACTION_DROP, 255)
        for reason in error_pkts.keys():
            # create counter for the reason
            counter = pytest.tb.create_debug_counter(S.SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS, reason)
            attr_val = pytest.tb.get_object_attr(counter, S.SAI_DEBUG_COUNTER_ATTR_INDEX)
            counter_indexes.append(attr_val)
            # make sure counters are clear
            actual_counter_vals = pytest.tb.get_switch_stats(attr_val, S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, clear=True)

            all_reasons.append(reason)
            expected_val = 0
            for pkt in error_pkts[reason]:
                expected_val += 1
                # send the packet
                U.run(self, pkt, pytest.top.sw_port)
            expected_counter_vals.append(expected_val)

        # verify counter values.
        actual_counter_vals = pytest.tb.get_switch_stats(counter_indexes, S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, clear=True)
        for i in range(len(expected_counter_vals)):
            try:
                assert expected_counter_vals[i] == actual_counter_vals[i]
            except BaseException:
                print(
                    "Failed for reason:{0} got {1} expected {2}".format(
                        all_reasons[i],
                        actual_counter_vals[i],
                        expected_counter_vals[i]))
                S.dump_event_counters(pytest.tb.switch_id)
                for tt in range(len(expected_counter_vals)):
                    print(
                        "Reason:{0} got {1} expected {2}".format(
                            all_reasons[tt],
                            actual_counter_vals[tt],
                            expected_counter_vals[tt]))
                raise
        pytest.tb.remove_trap(ttl_trap)

    # testing create/remove, set/get attribute, get/clear counter value
    def test_create_remove(self):
        ttl_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_TTL_ERROR, S.SAI_PACKET_ACTION_DROP, 245)

        # counter with drop reason list
        drop_reasons = [
            S.SAI_IN_DROP_REASON_IP_HEADER_ERROR,
            S.SAI_IN_DROP_REASON_L2_LOOPBACK_FILTER,
            S.SAI_IN_DROP_REASON_LPM4_MISS]

        counter1 = pytest.tb.create_debug_counter(
            S.SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS, drop_reasons)
        # counter without drop reason list. Adding drop reason list later
        counter2 = pytest.tb.create_debug_counter(S.SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS)

        # verify getters
        index1 = pytest.tb.get_object_attr(counter1, S.SAI_DEBUG_COUNTER_ATTR_INDEX)
        index2 = pytest.tb.get_object_attr(counter2, S.SAI_DEBUG_COUNTER_ATTR_INDEX)
        assert index2 == index1 + 1

        attr_val = pytest.tb.get_object_attr(counter2, S.SAI_DEBUG_COUNTER_ATTR_TYPE)
        assert attr_val == S.SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS

        attr_val = pytest.tb.get_object_attr(counter2, S.SAI_DEBUG_COUNTER_ATTR_BIND_METHOD)
        assert attr_val == S.SAI_DEBUG_COUNTER_BIND_METHOD_AUTOMATIC

        # add and verify drop reason list
        counter_list = [S.SAI_IN_DROP_REASON_TTL, S.SAI_IN_DROP_REASON_DIP_LINK_LOCAL]
        pytest.tb.set_object_attr(counter2,
                                  S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST,
                                  counter_list)
        attr_val = pytest.tb.get_object_attr(counter2, S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST)
        assert attr_val == counter_list

        # make sure counters are clear
        #counter_vals = pytest.tb.get_switch_stats([index1, index2], S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, clear=True)

        pytest.tb.do_warm_boot()

        # send packets causing errors
        error_pkts = self.create_error_pkts()

        for reason in error_pkts.keys():
            if reason in [S.SAI_IN_DROP_REASON_IP_HEADER_ERROR, S.SAI_IN_DROP_REASON_TTL, S.SAI_IN_DROP_REASON_DIP_LINK_LOCAL]:
                # send 1 packet for each reason
                U.run(self, error_pkts[reason][0], pytest.top.sw_port)

        # read first time without clear
        counter_vals = pytest.tb.get_switch_stats([index1, index2], S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST)
        # Verify counter values are according to packets we sent
        assert counter_vals[0] == 1
        assert counter_vals[1] == 2

        # clear index1 counter
        pytest.tb.clear_switch_stats([index1], S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST)

        # read second time with clear. index2 Should give same result (data was not cleared)
        counter_vals = pytest.tb.get_switch_stats([index1, index2], S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, clear=True)
        assert counter_vals[0] == 0
        assert counter_vals[1] == 2

        # After read with clear, all counter values should be 0
        counter_vals = pytest.tb.get_switch_stats([index1, index2], S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST)
        for i in range(len(counter_vals)):
            assert counter_vals[i] == 0

        pytest.tb.remove_object(counter1)
        pytest.tb.remove_object(counter2)
        pytest.tb.remove_object(ttl_trap)

    def test_mc_dmac_mismatch_counter(self):
        debug_counter = pytest.tb.create_debug_counter(
            S.SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS,
            S.SAI_IN_DROP_REASON_MC_DMAC_MISMATCH)
        attr_val = pytest.tb.get_object_attr(debug_counter, S.SAI_DEBUG_COUNTER_ATTR_INDEX)
        # make sure it is cleared
        pytest.tb.get_switch_stats(attr_val, S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, clear=True)

        # send multicast packet
        in_pkt = Ether(dst=pytest.tb.router_mac, src="00:ef:00:ef:00:ef") / \
            IP(dst="224.0.0.5", src=pytest.top.neighbor_ip1, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.run(self, in_pkt, pytest.top.in_port)

        # Count of dropped packets should be 1.
        debug_counter_val = pytest.tb.get_switch_stats(
            attr_val, S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, clear=True)
        assert debug_counter_val[0] == 1

    def test_unsupported_counter(self):
        with st_utils.expect_sai_error(S.SAI_STATUS_NOT_IMPLEMENTED):
            debug_counter = pytest.tb.create_debug_counter(S.SAI_DEBUG_COUNTER_TYPE_PORT_IN_DROP_REASONS,
                                                           S.SAI_IN_DROP_REASON_DECAP_ERROR)


@pytest.fixture(scope="class")
def rp_no_route_topology(base_v4_topology):
    pytest.tb.configure_ports([pytest.top.in_port_cfg, pytest.top.out_port_cfg])

    # configure rif 1
    pytest.top.configure_rif_id_1(pytest.top.in_port)

    # configure rif 2 with no route
    pytest.tb.rif_id_2 = pytest.tb.create_router_interface(
        pytest.tb.virtual_router_id, pytest.top.out_port, S.SAI_ROUTER_INTERFACE_TYPE_PORT)

    # default route
    pytest.tb.create_route(pytest.tb.virtual_router_id, pytest.top.default_ip, pytest.top.default_ip_mask, S.SAI_NULL_OBJECT_ID)

    pytest.tb.setup_vrf_punt_path(pytest.tb.virtual_router_id, pytest.top.local_ip1, pytest.top.full_mask)
    pytest.tb.setup_vrf_punt_path(pytest.tb.virtual_router_id, pytest.top.local_ip2, pytest.top.full_mask)

    pytest.top.configure_rif_loopback()

    yield

    pytest.top.deconfigure_rif_loopback()
    pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.local_ip1, pytest.top.full_mask)
    pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.local_ip2, pytest.top.full_mask)

    pytest.tb.remove_route(pytest.tb.virtual_router_id, pytest.top.default_ip, pytest.top.default_ip_mask)

    pytest.tb.remove_router_interface(pytest.tb.rif_id_2)
    pytest.top.deconfigure_rif_id_1()
    pytest.tb.remove_ports()


@pytest.mark.usefixtures("rp_no_route_topology")
class Test_drop_counters():

    def test_rp_no_route_counter(self):
        debug_counter = pytest.tb.create_debug_counter(
            S.SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS,
            S.SAI_IN_DROP_REASON_LPM4_MISS)
        attr_val = pytest.tb.get_object_attr(debug_counter, S.SAI_DEBUG_COUNTER_ATTR_INDEX)
        # make sure it is cleared
        pytest.tb.get_switch_stats(attr_val, S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, clear=True)

        # send packet
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.run(self, in_pkt, pytest.top.in_port)

        # Count of dropped packets should be 1.
        debug_counter_val = pytest.tb.get_switch_stats(
            attr_val, S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, clear=True)
        assert debug_counter_val[0] == 1

    def test_non_routable_mac_counter(self):
        debug_counter = pytest.tb.create_debug_counter(S.SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS, S.SAI_IN_DROP_REASON_L2_ANY)
        attr_val = pytest.tb.get_object_attr(debug_counter, S.SAI_DEBUG_COUNTER_ATTR_INDEX)
        pytest.tb.get_switch_stats(attr_val, S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, clear=True)

        in_pkt2 = Ether(dst="00:cd:ab:cd:ab:cd", src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        U.run(self, in_pkt2, pytest.top.in_port)
        print("Time before reading ", datetime.now().time())
        # Count of dropped packets should be 1.
        debug_counter_val = pytest.tb.get_switch_stats(
            attr_val, S.SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, clear=True)
        assert debug_counter_val[0] == 1
        print("Time after reading ", datetime.now().time())
