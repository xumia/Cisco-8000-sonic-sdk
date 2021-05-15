#!/usr/bin/env python3
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
from saicli import *
from acl_table_tests import *
from acl_entry_tests import *
import sai_packet_utils as U
from scapy.all import *


class acl_range_tests():

    def create_range(self, range_type, lower, upper):
        args = {}
        if range_type is not None:
            args[SAI_ACL_RANGE_ATTR_TYPE] = range_type
        if lower is not None and upper is not None:
            args[SAI_ACL_RANGE_ATTR_LIMIT] = [lower, upper]
        acl_range = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_RANGE, args, verify=[True, False])
        return acl_range

    def create_range_table(self, types, stage=SAI_ACL_STAGE_INGRESS, size=None):
        aclTable = acl_table_tests()
        return aclTable.create_table_1_field(SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE, types, stage, size)

    def create_range_drop_entry(self, table, range_objs, enabled=True, priority=0):
        aclEntry = acl_entry_tests()
        field = SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE
        return aclEntry.create_drop_entry_1_field(table, field, range_objs, 0, enabled, priority)

    def create_and_exercise_sport_range(self, lower, upper):
        self.create_and_exercise_ranges((SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE, lower, upper))

    def create_and_exercise_dport_range(self, lower, upper):
        self.create_and_exercise_ranges((SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE, lower, upper))

    def create_and_exercise_sport_dport_range(self, sport, dport):
        sport = (SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE, *sport)
        dport = (SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE, *dport)
        self.create_and_exercise_ranges(sport, dport)

    def create_and_exercise_ranges(self, *range_params):
        range_objs = [self.create_range(*p) for p in range_params]
        table_obj = self.create_range_table([p[0] for p in range_params])
        table_size = pytest.tb.get_object_attr(table_obj, SAI_ACL_TABLE_ATTR_AVAILABLE_ACL_ENTRY)
        entry_obj = self.create_range_drop_entry(table_obj, range_objs)
        assert pytest.tb.get_object_attr(table_obj, SAI_ACL_TABLE_ATTR_AVAILABLE_ACL_ENTRY) < table_size

        # Verify that pkts pass before applying the ACL
        for params in self.pkt_params(True, range_params):
            self.exercise_udp_ports(**params)

        # Bind the table to the interface
        pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, table_obj)

        # Verify that pkts inside all ranges are dropped
        for params in self.pkt_params(True, range_params):
            with pytest.raises(Exception):
                self.exercise_udp_ports(**params)

        # Verify that pkts outside 1 or more ranges are forwarded
        for params in self.pkt_params(False, range_params):
            self.exercise_udp_ports(**params)

        # Clean up
        pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)
        pytest.tb.remove_object(entry_obj)
        assert pytest.tb.get_object_attr(table_obj, SAI_ACL_TABLE_ATTR_AVAILABLE_ACL_ENTRY) == table_size
        pytest.tb.remove_object(table_obj)
        for range_obj in range_objs:
            pytest.tb.remove_object(range_obj)

    # Generate pkt params for a single range - selectively inside or outside the range
    def pkt_param(self, inside, range_type, lower, upper):
        if range_type == SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE:
            name = 'sport'
            max_val = 0xFFFF
        elif range_type == SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE:
            name = 'dport'
            max_val = 0xFFFF

        if inside:
            yield {name: upper}
            if upper != lower:
                step = max(1, (upper - lower) // 5)
                for val in range(lower, upper, step):
                    yield {name: val}
        else:
            if lower > 0:
                yield {name: 0}
                yield {name: lower - 1}
            if upper < max_val:
                yield {name: max_val}
                yield {name: upper + 1}

    # Generate combinations of pkt params - selectively inside all ranges or not
    def pkt_params(self, inside, range_params):
        if len(range_params) == 1:
            for param in self.pkt_param(inside, *range_params[0]):
                yield param
        elif inside:
            for param in self.pkt_params(True, range_params[1:]):
                for param0 in self.pkt_param(True, *range_params[0]):
                    yield {**param, **param0}
        else:
            for param in self.pkt_params(True, range_params[1:]):
                for param0 in self.pkt_param(False, *range_params[0]):
                    yield {**param, **param0}
            for param in self.pkt_params(False, range_params[1:]):
                for param0 in self.pkt_param(True, *range_params[0]):
                    yield {**param, **param0}

    def exercise_udp_ports(self, sport=0, dport=0):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=sport, dport=dport)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=sport, dport=dport)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)
