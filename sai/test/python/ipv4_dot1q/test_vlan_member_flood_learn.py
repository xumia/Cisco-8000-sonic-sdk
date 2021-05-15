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
import packet_test_utils as P


@pytest.mark.usefixtures("flood_vlan_member_local_learn_bridge_topology")
class Test_flood_and_learn():

    def test_first_in_packet(self):
        st_utils.skipIf(pytest.tb.is_hw_dev)
        in_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.neighbor_mac1, type=P.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=203) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        in_pkt2 = Ether(dst=pytest.top.neighbor_mac1, src=pytest.top.neighbor_mac2, type=P.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=203) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        out_tagged_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.neighbor_mac1, type=P.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=101) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        out_untagged_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        out_pkt2 = Ether(dst=pytest.top.neighbor_mac1, src=pytest.top.neighbor_mac2, type=P.Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=101) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        # disable learning, should flood
        pytest.top.configure_bridge_ports_learning_mode(S.SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DISABLE)

        # before traffic there should be no entries
        orig_obj_count = 0
        orig_obj_list = []

        port_packets = {pytest.top.out_port: out_tagged_pkt, pytest.top.sw_port: out_untagged_pkt}
        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

        # enable learning, should flood
        pytest.top.configure_bridge_ports_learning_mode(S.SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW)

        port_packets = {pytest.top.out_port: out_tagged_pkt, pytest.top.sw_port: out_untagged_pkt}
        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

        port_packets = {pytest.top.in_port: out_pkt2}
        # SAI will process and install MAC entry, spin and check if learn notification process had completed
        time.sleep(1)
        U.run_and_compare_set(self, in_pkt2, pytest.top.out_port, port_packets, match_all=True, with_learn=True)

        port_packets = {pytest.top.out_port: out_tagged_pkt}
        time.sleep(1)
        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, port_packets, match_all=True, with_learn=True)

        # check FDB entries after packet sending, new FDB entries should match number of ports in the test
        time.sleep(2)
        obj_count, obj_list = pytest.tb.get_object_keys(S.SAI_OBJECT_TYPE_FDB_ENTRY)
        st_utils.dump_fdb_entries(obj_count, obj_list)

        # verify FDB entries
        # new learns are from all ports including the incoming and outgoing traffic ports
        assert (obj_count - orig_obj_count == orig_obj_count + 2)
        # verify new MAC on each one of the BV
        bv_set = {}
        for idx in range(obj_count):
            fdb_entry = obj_list[idx]
            mac_addr = st_utils.sai_py_mac_t(fdb_entry.mac_address)
            if mac_addr != pytest.top.neighbor_mac1:
                continue
            # no duplicates
            assert (fdb_entry.bv_id not in bv_set)
            bv_set.add(fdb_entry.bv_id)
