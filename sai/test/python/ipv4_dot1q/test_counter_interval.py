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
import sai_packet_utils as U
import sai_test_utils as st_utils
from scapy.all import *
from saicli import *
import time


@pytest.mark.usefixtures("dot1q_bridge_v4_topology")
class Test_counter_interval():
    def test_mibs_counter(self):

        # set refresh time to 1 sec
        pytest.tb.set_object_attr(pytest.tb.switch_id, SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL, 1)

        in_pkt = Ether(dst=pytest.top.neighbor_mac2, src="00:ef:00:ef:00:ef") / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        #U.run_and_compare(self, in_pkt, pytest.top.in_port, in_pkt, pytest.top.out_port)

        # test update mibs
        in_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.in_port])
        pytest.tb.dump_port_stats(in_stats)

        # test no update
        in_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.in_port])
        pytest.tb.dump_port_stats(in_stats)

        time.sleep(2)

        # test update shadow
        in_stats = pytest.tb.get_port_stats(pytest.tb.ports[pytest.top.in_port])
        pytest.tb.dump_port_stats(in_stats)

        # set refresh interval back 0 (always update)
        pytest.tb.set_object_attr(pytest.tb.switch_id, SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL, 0)

    @pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
    def test_queue_watermark(self):

        pytest.tb.set_object_attr(pytest.tb.switch_id, SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL, 1)

        in_pkt = Ether(dst=pytest.top.neighbor_mac2, src="00:ef:00:ef:00:ef") / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        #U.run_and_compare(self, in_pkt, pytest.top.in_port, in_pkt, pytest.top.out_port)

        queue_obj_ids = []
        out_queue_list = pytest.tb.get_queue_list(pytest.tb.ports[pytest.top.out_port])
        for q in out_queue_list.to_pylist():
            queue_obj_ids.append(q)

        q_stats_before = []
        for q in range(0, 8):
            q_stats_before.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

        out_queue_list = pytest.tb.get_queue_list(pytest.tb.ports[pytest.top.out_port])
        q_stats_before = []
        for q in range(0, 8):
            q_stats_before.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

        time.sleep(2)

        q_stats_before = []
        for q in range(0, 8):
            q_stats_before.append(pytest.tb.get_queue_stats(queue_obj_ids[q]))
            print("voq {0}: packets: {1} bytes: {2}".format(q, q_stats_before[q][0], q_stats_before[q][1]))

        pytest.tb.set_object_attr(pytest.tb.switch_id, SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL, 0)
