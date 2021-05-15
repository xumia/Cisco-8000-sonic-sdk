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
import sai_packet_utils as U
import sai_test_utils as st_utils
from scapy.all import *
import saicli as S


@pytest.mark.usefixtures("flood_local_learn_bridge_topology")
class Test_flood_and_learn():

    def test_topology_config(self):
        pytest.top.deconfigure_flood_local_learn_bridge_topology()
        pytest.top.configure_flood_local_learn_bridge_topology()
        pytest.top.deconfigure_flood_local_learn_bridge_topology()
        pytest.top.configure_flood_local_learn_bridge_topology()

    def test_first_in_packet(self):
        st_utils.skipIf(pytest.tb.is_hw_dev)
        in_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        in_pkt2 = Ether(dst=pytest.top.neighbor_mac1, src=pytest.top.neighbor_mac2) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        port_packets = {pytest.top.out_port: in_pkt, pytest.top.sw_port: in_pkt}
        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

        port_packets = {pytest.top.in_port: in_pkt2}
        # SAI will process and install MAC entry, spin and check if learn notification process had completed
        time.sleep(1)
        U.run_and_compare_set(self, in_pkt2, pytest.top.out_port, port_packets, match_all=True, with_learn=True)

        port_packets = {pytest.top.out_port: in_pkt}
        time.sleep(1)
        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

    def test_set_fdb_entry_port_id(self):
        st_utils.skipIf(pytest.tb.is_hw_dev)
        # create fdb_entry
        fdb_entry = pytest.tb.create_fdb_entry(
            pytest.tb.vlans[pytest.top.vlan], pytest.top.neighbor_mac2, pytest.tb.bridge_ports[pytest.top.out_port])
        in_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        port_packets = {pytest.top.out_port: in_pkt}
        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, port_packets, True)

        obj_count, obj_list = pytest.tb.get_object_keys(S.SAI_OBJECT_TYPE_FDB_ENTRY)

        # change fdb_entry from one port to another
        pytest.tb.set_fdb_entry_port_id(pytest.tb.vlans[pytest.top.vlan],
                                        pytest.top.neighbor_mac2, pytest.tb.bridge_ports[pytest.top.sw_port])
        attr = pytest.tb.get_fdb_entry_port_id(pytest.tb.vlans[pytest.top.vlan], pytest.top.neighbor_mac2)
        assert attr == pytest.tb.bridge_ports[pytest.top.sw_port]

        port_packets = {pytest.top.sw_port: in_pkt}
        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, port_packets, True)

        obj_count, obj_list = pytest.tb.get_object_keys(S.SAI_OBJECT_TYPE_FDB_ENTRY)
