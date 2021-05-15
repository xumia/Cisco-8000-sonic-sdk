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
import time


@pytest.mark.usefixtures("basic_route_v4_topology")
class Test_traps_event():

    def create_event_traps(self):
        self.arp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST, S.SAI_PACKET_ACTION_DROP, 7)
        self.dhcp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_DHCP, S.SAI_PACKET_ACTION_DROP, 6)
        self.lacp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_LACP, S.SAI_PACKET_ACTION_DROP, 5)
        self.lldp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_LLDP, S.SAI_PACKET_ACTION_DROP, 4)
        self.ttlerr_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_TTL_ERROR, S.SAI_PACKET_ACTION_DROP, 3)
        self.mtuerr_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_L3_MTU_ERROR, S.SAI_PACKET_ACTION_DROP, 2)
        self.udld_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_UDLD, S.SAI_PACKET_ACTION_DROP, 1)

    def remove_event_traps(self):
        pytest.tb.remove_trap(self.lacp_trap)
        pytest.tb.remove_trap(self.arp_trap)
        pytest.tb.remove_trap(self.lldp_trap)
        pytest.tb.remove_trap(self.ttlerr_trap)
        pytest.tb.remove_trap(self.mtuerr_trap)
        pytest.tb.remove_trap(self.dhcp_trap)

    def lacp_packet(self, count, trap_type):
        num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
        s_i_p = st_utils.lane_to_slice_ifg_pif(pytest.top.in_port)

        if pytest.tb.is_hw():
            if self.cpu_queue_list is None:
                attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_CPU_PORT, 0)
                pytest.tb.apis[S.SAI_API_SWITCH].get_switch_attribute(pytest.tb.switch_id, 1, attr)
                self.cpu_queue_list = pytest.tb.get_queue_list(attr.value.oid)

            for q in self.cpu_queue_list.to_pylist():
                q_cnts = pytest.tb.get_queue_stats(q)
                if q_cnts[0] is not 0:
                    print("q_cnts: queue {0} packets {1} drops {2}\n" .format(hex(q), q_cnts[0], q_cnts[1]))
            num_pkts, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
            print("punt pkts: num_pkts {0} sip {1}\n" .format(num_pkts, hex(pkt_sip)))
        else:
            lacp_da = '01:80:c2:00:00:02'

            in_pkt = \
                Ether(dst=lacp_da, src=pytest.tb.router_mac, type=U.Ethertype.LACP.value) / \
                IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64)

            expected_out_pkt = in_pkt

            attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_CPU_PORT, 0)
            pytest.tb.apis[S.SAI_API_SWITCH].get_switch_attribute(pytest.tb.switch_id, 1, attr)

            group_list = S.sai_object_list_t([0])
            lst = S.sai_attribute_t(S.SAI_PORT_ATTR_INGRESS_PRIORITY_GROUP_LIST, group_list)
            with st_utils.expect_sai_error(S.SAI_STATUS_BUFFER_OVERFLOW):
                pytest.tb.apis[S.SAI_API_PORT].get_port_attribute(attr.value.oid, 1, lst)
            if (lst.value.objlist.count == 0):
                raise

            queue_lst = S.sai_attribute_t(S.SAI_PORT_ATTR_QOS_QUEUE_LIST, group_list)
            with st_utils.expect_sai_error(S.SAI_STATUS_BUFFER_OVERFLOW):
                pytest.tb.apis[S.SAI_API_PORT].get_port_attribute(attr.value.oid, 1, queue_lst)
            if (queue_lst.value.objlist.count == 0):
                raise

            U.punt_test(self, in_pkt, pytest.top.in_port, expected_out_pkt, count, trap_type)

    def lldp_packet(self, count, trap_type):
        lldp_da = '01:80:c2:00:00:0e'

        in_pkt = \
            Ether(dst=lldp_da, src=pytest.tb.router_mac, type=U.Ethertype.LLDP.value) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64)

        expected_out_pkt = in_pkt

        U.punt_test(self, in_pkt, pytest.top.in_port, expected_out_pkt, count, trap_type)

    def udld_packet(self, count, trap_type):
        in_pkt = \
            Ether(dst='01:00:0C:CC:CC:CC', src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64)

        expected_out_pkt = in_pkt

        U.punt_test(self, in_pkt, pytest.top.in_port, expected_out_pkt, count, trap_type)

    def arp_packet(self, count, trap_type):

        in_pkt = \
            Ether(dst="ff:ff:ff:ff:ff:ff", src=pytest.top.neighbor_mac1) / \
            ARP()

        expected_out_pkt = in_pkt

        U.punt_test(self, in_pkt, pytest.top.in_port, expected_out_pkt, count, trap_type)

    def dhcp_packet(self, count, trap_type):

        in_pkt = \
            Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1, type=0x800) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.local_ip1, ttl=64) / \
            UDP(sport=68, dport=67)

        expected_out_pkt = in_pkt

        U.punt_test(self, in_pkt, pytest.top.in_port, expected_out_pkt, count, trap_type)

    def ttlerr_packet(self, count, trap_type):

        in_pkt = \
            Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=1)

        in_pad_len = 0
        if len(in_pkt) < 72:
            in_pad_len = 72 - len(in_pkt)
            padded_in_packet = in_pkt / ("\0" * in_pad_len)
        else:
            padded_in_packet = in_pkt

        num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
        s_i_p = st_utils.lane_to_slice_ifg_pif(pytest.top.in_port)

        pytest.tb.inject_network_packet(padded_in_packet, s_i_p["slice"], s_i_p["ifg"], s_i_p["pif"])
        time.sleep(1)

        num_pkts, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
        assert num_pkts == num_pkts_before + count
        if count != 0:
            exp_out_ip = padded_in_packet[IP].build()
            exp_out_ip = IP(exp_out_ip)
            exp_out_ip.ttl = 0

            U.assertEqualPackets(self, out_pkt, U.scapy_to_hex(exp_out_ip))
            assert pkt_sip == pytest.tb.ports[pytest.top.in_port]
            assert pkt_trap_id == trap_type

    def mtuerr_packet(self, count, trap_type):

        in_pkt = \
            Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64)

        if len(in_pkt) < 1350:
            in_pad_len = 1350 - len(in_pkt)
            padded_in_packet = in_pkt / ("\0" * in_pad_len)
        else:
            padded_in_packet = in_pkt

        num_pkts_before, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
        s_i_p = st_utils.lane_to_slice_ifg_pif(pytest.top.in_port)

        pytest.tb.inject_network_packet(padded_in_packet, s_i_p["slice"], s_i_p["ifg"], s_i_p["pif"])
        time.sleep(1)

        num_pkts, out_pkt, pkt_sip, pkt_trap_id, pkt_dst_port, pkt_src_lag = pytest.tb.get_punt_packet()
        assert num_pkts == num_pkts_before + count
        if count != 0:
            exp_out_ip = padded_in_packet[IP].build()
            exp_out_ip = IP(exp_out_ip)
            exp_out_ip.ttl = 63

            U.assertEqualPackets(self, out_pkt, U.scapy_to_hex(exp_out_ip))
            assert pkt_dst_port == pytest.tb.ports[pytest.top.out_port]
            assert pkt_trap_id == trap_type

    def test_arp_trap(self):
        self.create_event_traps()
        # test arp drop
        self.arp_packet(0, self.arp_trap)
        # test arp trap and priority
        pytest.tb.set_trap_priority(self.arp_trap, 8)
        pytest.tb.set_trap_action(self.arp_trap, S.SAI_PACKET_ACTION_TRAP)
        self.arp_packet(1, self.arp_trap)

        self.remove_event_traps()

    def test_dhcp_trap(self):
        self.create_event_traps()
        # test dhcp trap and priority
        pytest.tb.set_trap_priority(self.dhcp_trap, 8)
        pytest.tb.set_trap_action(self.dhcp_trap, S.SAI_PACKET_ACTION_TRAP)
        self.dhcp_packet(1, self.dhcp_trap)

        self.remove_event_traps()

    def test_lacp_drop(self):
        self.create_event_traps()
        # all traps action to drop with lacp having highest priority
        pytest.tb.set_trap_priority(self.lacp_trap, 8)
        self.lacp_packet(0, self.lacp_trap)

        self.remove_event_traps()

    def test_lacp_lldp_udld_trap(self):
        self.create_event_traps()

        pytest.tb.set_trap_action(self.lacp_trap, S.SAI_PACKET_ACTION_TRAP)
        pytest.tb.set_trap_action(self.lldp_trap, S.SAI_PACKET_ACTION_TRAP)
        pytest.tb.set_trap_action(self.udld_trap, S.SAI_PACKET_ACTION_TRAP)
        pytest.tb.set_trap_priority(self.lacp_trap, 8)
        # lacp priority higher than lldp and udld
        self.lacp_packet(1, self.lacp_trap)

        # setting lldp priority higher than lacp and udld
        pytest.tb.set_trap_priority(self.lldp_trap, 8)
        pytest.tb.set_trap_priority(self.lacp_trap, 2)
        self.lldp_packet(1, self.lldp_trap)
        # setting udld priority higher than lldp and lacp
        pytest.tb.set_trap_priority(self.udld_trap, 8)
        pytest.tb.set_trap_priority(self.lldp_trap, 2)
        self.udld_packet(1, self.udld_trap)

        self.remove_event_traps()

    def test_lldp_drop(self):
        self.create_event_traps()
        pytest.tb.set_trap_priority(self.lldp_trap, 8)
        self.lldp_packet(0, self.lldp_trap)

        self.remove_event_traps()

    def test_ttlerr_drop(self):
        self.create_event_traps()
        pytest.tb.set_trap_priority(self.ttlerr_trap, 8)
        self.ttlerr_packet(0, self.ttlerr_trap)

        self.remove_event_traps()

    def test_udld_drop(self):
        self.create_event_traps()
        pytest.tb.set_trap_priority(self.udld_trap, 8)
        self.udld_packet(0, self.udld_trap)
        self.remove_event_traps()

    def test_mtuerr_drop(self):
        self.create_event_traps()
        pytest.tb.set_trap_priority(self.mtuerr_trap, 8)
        self.mtuerr_packet(0, self.mtuerr_trap)
        self.remove_event_traps()

    def test_ttlerr_mtuerr_trap(self):
        st_utils.skipIf(pytest.tb.is_gb)
        pytest.tb.set_mtu_router_interface(pytest.tb.rif_id_1, 1000)
        pytest.tb.set_mtu_router_interface(pytest.tb.rif_id_2, 1000)

        self.create_event_traps()
        pytest.tb.set_trap_action(self.mtuerr_trap, S.SAI_PACKET_ACTION_TRAP)
        pytest.tb.set_trap_action(self.ttlerr_trap, S.SAI_PACKET_ACTION_TRAP)
        # setting ttlerr priority higher than the other trap
        pytest.tb.set_trap_priority(self.ttlerr_trap, 8)
        self.ttlerr_packet(1, self.ttlerr_trap)
        # ttl and mtu traps are not created at the same tx stage so the priority is always ttl first then mtu
        pytest.tb.set_trap_priority(self.ttlerr_trap, 4)
        pytest.tb.set_trap_priority(self.mtuerr_trap, 8)
        self.mtuerr_packet(1, self.mtuerr_trap)

        self.remove_event_traps()
