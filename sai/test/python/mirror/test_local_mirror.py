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
import sai_packet_utils as U
import sai_test_utils as st_utils
from scapy.all import *

# Mirror Test cases covered
#   Ingress-Mirroring
#       1. Local mirror session create/delete
#       2. Local mirror session create, modify mirror pkt-size, sample-rate and delete
#       3. After creating logical ports (bridge port/s) on eth port, attach mirror session
#           3.1 Test out packet on both destnation bridged port and mirror monitor port
#       4. After attaching mirror session on eth port, test any new logical bridge ports created
#          on underlying port (that is mirroring) also mirror packet. Done by removing/deleting
#          logical port from the underlying port, and adding it back. Incoming packets on
#          new logical port should mirror packets.
#       5. Repeat [4] using rif as mirroring port.
#
#   Egress Mirroring
#       TBD


@pytest.mark.usefixtures("mirror_bridge_topology")
class Test_localmirror_bport():

    def test_create_delete_mirror_session(self):
        args = {}
        args[SAI_MIRROR_SESSION_ATTR_TYPE] = SAI_MIRROR_SESSION_TYPE_LOCAL
        args[SAI_MIRROR_SESSION_ATTR_TC] = 4
        args[SAI_MIRROR_SESSION_ATTR_MONITOR_PORT] = pytest.tb.bridge_ports[pytest.top.mirror_dest]
        mirror_session = pytest.tb.create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, args, verify=[True, False])
        assert mirror_session != 0
        pytest.tb.remove_object(mirror_session)

    def test_mirror_session_attrib_modify(self):
        args = {}
        args[SAI_MIRROR_SESSION_ATTR_TYPE] = SAI_MIRROR_SESSION_TYPE_LOCAL
        args[SAI_MIRROR_SESSION_ATTR_TC] = 4
        args[SAI_MIRROR_SESSION_ATTR_MONITOR_PORT] = pytest.tb.bridge_ports[pytest.top.mirror_dest]
        mirror_session = pytest.tb.create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, args, verify=[True, False])
        assert mirror_session != 0
        modifyable_attrs = {}
        modifyable_attrs[SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE] = 0
        modifyable_attrs[SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE] = 120
        for k, v in modifyable_attrs.items():
            pytest.tb.set_object_attr(mirror_session, k, v, verify=True)

        pytest.tb.remove_object(mirror_session)

    def __create_mirror_session_and_input_pkt(self):
        args = {}
        args[SAI_MIRROR_SESSION_ATTR_TYPE] = SAI_MIRROR_SESSION_TYPE_LOCAL
        args[SAI_MIRROR_SESSION_ATTR_TC] = 0
        args[SAI_MIRROR_SESSION_ATTR_MONITOR_PORT] = pytest.tb.bridge_ports[pytest.top.mirror_dest]
        mirror_session_oid = pytest.tb.create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, args, verify=[True, False])
        assert mirror_session_oid != 0

        # inject packet, check packet only on out-port
        in_pkt = Ether(dst=pytest.top.neighbor_mac2, src="00:ef:00:ef:00:ef") / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        return mirror_session_oid, in_pkt

    def __attach_mirror_session(self, port_list, mirror_session_oids):
        for port in port_list:
            for oid in mirror_session_oids:
                pytest.tb.set_object_attr(pytest.tb.ports[pytest.top.in_port],
                                          SAI_PORT_ATTR_INGRESS_MIRROR_SESSION, mirror_session_oids)

            programmed_oids = pytest.tb.get_object_attr(pytest.tb.ports[pytest.top.in_port], SAI_PORT_ATTR_INGRESS_MIRROR_SESSION)
            assert programmed_oids == mirror_session_oids

    def __detach_all_mirror_session(self, port_list):
        mirror_dest_oids = []
        for port in port_list:
            pytest.tb.set_object_attr(port, SAI_PORT_ATTR_INGRESS_MIRROR_SESSION, mirror_dest_oids)

    def __get_bport_stats(self):
        in_stats = pytest.tb.get_ingress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.in_port])
        out_stats = pytest.tb.get_egress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.out_port])
        mirror_dest_stats = pytest.tb.get_egress_bridge_port_stats(pytest.tb.bridge_ports[pytest.top.mirror_dest])
        return in_stats, out_stats, mirror_dest_stats

    def __compare_stats(self, pre_pkt_in_stats, pre_pkt_out_stats, post_pkt_in_stats, post_pkt_out_stats):
        # Bridge port stats are not available for now. Do not check. Remove return once
        # bridge port stats are available again.
        return None
        # pkt count
        assert post_pkt_in_stats[0] == pre_pkt_in_stats[0] + 1
        assert post_pkt_out_stats[0] == pre_pkt_out_stats[0] + 1
        #assert mirror_dest_stats[0] == pre_mirror_dest_stats[0] + 1
        # byte count
        assert post_pkt_in_stats[1] - pre_pkt_in_stats[1] == post_pkt_out_stats[1] - pre_pkt_out_stats[1]
        #assert in_stats[1] - pre_in_stats[1] == mirror_dest_stats[1] - pre_mirror_dest_stats[1]
        #assert out_stats[1] - pre_out_stats[1] == mirror_dest_stats[1] - pre_mirror_dest_stats[1]

    def test_local_mirror_on_bridge_port(self):
        '''
        This test case helps to test mirror on all logical ports that are already
        created on underlying port. When mirror session is attached to underlying
        port, traffic on all logical port should mirror too.
        '''
        pre_pkt_in_stats, pre_pkt_out_stats, pre_pkt_mirror_dest_stats = self.__get_bport_stats()
        mirror_session_oid, in_pkt = self.__create_mirror_session_and_input_pkt()
        U.run_and_compare(self, in_pkt, pytest.top.in_port, in_pkt, pytest.top.out_port)
        post_pkt_in_stats, post_pkt_out_stats, post_pkt_mirror_dest_stats = self.__get_bport_stats()
        self.__compare_stats(pre_pkt_in_stats, pre_pkt_out_stats, post_pkt_in_stats, post_pkt_out_stats)

        for i in range(2):
            # attach mirror-session to ingress port, check packet on both out-port and mirror-dest port
            self.__attach_mirror_session([pytest.tb.ports[pytest.top.in_port]], [mirror_session_oid])
            pre_pkt_in_stats, pre_pkt_out_stats, pre_pkt_mirror_dest_stats = self.__get_bport_stats()
            U.run_and_compare_set(
                self, in_pkt, pytest.top.in_port, {
                    pytest.top.out_port: in_pkt, pytest.top.mirror_dest: in_pkt}, True)
            post_pkt_in_stats, post_pkt_out_stats, post_pkt_mirror_dest_stats = self.__get_bport_stats()
            self.__compare_stats(pre_pkt_in_stats, pre_pkt_out_stats, post_pkt_in_stats, post_pkt_out_stats)

            # detach mirror-session from ingress port passing empty mirror oids will detach all mirror sessions on the port
            self.__detach_all_mirror_session([pytest.tb.ports[pytest.top.in_port]])
            # check packet on only out-port and not on mirror-dest port
            pre_pkt_in_stats, pre_pkt_out_stats, pre_pkt_mirror_dest_stats = self.__get_bport_stats()
            U.run_and_compare_set(self, in_pkt, pytest.top.in_port, {pytest.top.out_port: in_pkt}, True)
            post_pkt_in_stats, post_pkt_out_stats, post_pkt_mirror_dest_stats = self.__get_bport_stats()
            self.__compare_stats(pre_pkt_in_stats, pre_pkt_out_stats, post_pkt_in_stats, post_pkt_out_stats)

        pytest.tb.remove_object(mirror_session_oid)

    def test_local_mirror_on_bridge_port_with_bridgeport_add_delete(self):
        '''
        This test case helps to test when a logical port is created on underlying
        port, that has a mirror session attached, the traffic on logical port
        should mirror too
        '''
        pre_pkt_in_stats, pre_pkt_out_stats, pre_pkt_mirror_dest_stats = self.__get_bport_stats()
        mirror_session_oid, in_pkt = self.__create_mirror_session_and_input_pkt()
        U.run_and_compare(self, in_pkt, pytest.top.in_port, in_pkt, pytest.top.out_port)
        post_pkt_in_stats, post_pkt_out_stats, post_pkt_mirror_dest_stats = self.__get_bport_stats()
        self.__compare_stats(pre_pkt_in_stats, pre_pkt_out_stats, post_pkt_in_stats, post_pkt_out_stats)

        # attach mirror-session to ingress port, check packet on both out-port and mirror-dest port
        self.__attach_mirror_session([pytest.tb.ports[pytest.top.in_port]], [mirror_session_oid])
        pre_pkt_in_stats, pre_pkt_out_stats, pre_pkt_mirror_dest_stats = self.__get_bport_stats()
        U.run_and_compare_set(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: in_pkt, pytest.top.mirror_dest: in_pkt}, True)
        post_pkt_in_stats, post_pkt_out_stats, post_pkt_mirror_dest_stats = self.__get_bport_stats()
        self.__compare_stats(pre_pkt_in_stats, pre_pkt_out_stats, post_pkt_in_stats, post_pkt_out_stats)

        # Delete l2 port and add back l2 port to check if newly created l2-port continues to mirror.
        pytest.tb.deconfigure_vlan_members()
        pytest.tb.obj_wrapper.remove_object(pytest.tb.bridge_ports[pytest.top.in_port])
        # create l2 port on top of port with attached mirror session
        pytest.tb.create_bridge_port(pytest.top.in_port)
        pytest.tb.configure_vlan_members([{"vlan": pytest.top.vlan, "port": pytest.top.in_port, "is_tag": False},
                                          {"vlan": pytest.top.vlan, "port": pytest.top.out_port, "is_tag": False},
                                          {"vlan": pytest.top.vlan, "port": pytest.top.mirror_dest, "is_tag": False}])
        # check if new l2 port continues to mirror pkt
        pre_pkt_in_stats, pre_pkt_out_stats, pre_pkt_mirror_dest_stats = self.__get_bport_stats()
        U.run_and_compare_set(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: in_pkt, pytest.top.mirror_dest: in_pkt}, True)
        post_pkt_in_stats, post_pkt_out_stats, post_pkt_mirror_dest_stats = self.__get_bport_stats()
        self.__compare_stats(pre_pkt_in_stats, pre_pkt_out_stats, post_pkt_in_stats, post_pkt_out_stats)

        self.__detach_all_mirror_session([pytest.tb.ports[pytest.top.in_port]])
        pytest.tb.remove_object(mirror_session_oid)


@pytest.mark.usefixtures("mirror_rif_topology")
class Test_localmirror_rif():

    def test_create_delete_mirror_session(self):
        args = {}
        args[SAI_MIRROR_SESSION_ATTR_TYPE] = SAI_MIRROR_SESSION_TYPE_LOCAL
        args[SAI_MIRROR_SESSION_ATTR_TC] = 4
        args[SAI_MIRROR_SESSION_ATTR_MONITOR_PORT] = pytest.tb.rif_id_4
        mirror_session = pytest.tb.create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, args, verify=[True, False])
        assert mirror_session != 0
        pytest.tb.remove_object(mirror_session)

    def test_mirror_session_attrib_modify(self):
        args = {}
        args[SAI_MIRROR_SESSION_ATTR_TYPE] = SAI_MIRROR_SESSION_TYPE_LOCAL
        args[SAI_MIRROR_SESSION_ATTR_TC] = 4
        args[SAI_MIRROR_SESSION_ATTR_MONITOR_PORT] = pytest.tb.rif_id_4
        mirror_session = pytest.tb.create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, args, verify=[True, False])
        assert mirror_session != 0
        modifyable_attrs = {}
        modifyable_attrs[SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE] = 0
        modifyable_attrs[SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE] = 120
        for k, v in modifyable_attrs.items():
            pytest.tb.set_object_attr(mirror_session, k, v, verify=True)

        pytest.tb.remove_object(mirror_session)

    def __attach_mirror_session(self, port_list, mirror_session_oids):
        for port in port_list:
            for oid in mirror_session_oids:
                pytest.tb.set_object_attr(pytest.tb.ports[pytest.top.in_port],
                                          SAI_PORT_ATTR_INGRESS_MIRROR_SESSION, mirror_session_oids)

            programmed_oids = pytest.tb.get_object_attr(pytest.tb.ports[pytest.top.in_port], SAI_PORT_ATTR_INGRESS_MIRROR_SESSION)
            assert programmed_oids == mirror_session_oids

    def __detach_all_mirror_session(self, port_list):
        mirror_dest_oids = []
        for port in port_list:
            pytest.tb.set_object_attr(port, SAI_PORT_ATTR_INGRESS_MIRROR_SESSION, mirror_dest_oids)

    def __create_mirror_session_and_input_pkt_and_out_pkt(self):
        args = {}
        args[SAI_MIRROR_SESSION_ATTR_TYPE] = SAI_MIRROR_SESSION_TYPE_LOCAL
        args[SAI_MIRROR_SESSION_ATTR_TC] = 0
        args[SAI_MIRROR_SESSION_ATTR_MONITOR_PORT] = pytest.tb.rif_id_4
        mirror_session_oid = pytest.tb.create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, args, verify=[True, False])
        assert mirror_session_oid != 0

        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        return mirror_session_oid, in_pkt, expected_out_pkt

    def test_local_mirror_on_rif_port(self):
        '''
        This test case helps to test mirror on all logical ports that are already
        created on underlying port. When mirror session is attached to underlying
        port, traffic on all logical port should mirror too.
        '''
        mirror_session_oid, in_pkt, expected_out_pkt = self.__create_mirror_session_and_input_pkt_and_out_pkt()
        # inject packet, check packet only on out-port
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        for i in range(2):
            # attach mirror-session to ingress port, check packet on both out-port and mirror-dest port
            self.__attach_mirror_session([pytest.tb.ports[pytest.top.in_port]], [mirror_session_oid])
            U.run_and_compare_set(
                self, in_pkt, pytest.top.in_port, {
                    pytest.top.out_port: expected_out_pkt, pytest.top.mirror_dest: in_pkt}, True)
            # detach mirror-session from ingress port passing empty mirror oids will detach all mirror sessions on the port
            self.__detach_all_mirror_session([pytest.tb.ports[pytest.top.in_port]])
            # check packet on only out-port and not on mirror-dest port
            U.run_and_compare_set(self, in_pkt, pytest.top.in_port, {pytest.top.out_port: expected_out_pkt}, True)

        pytest.tb.remove_object(mirror_session_oid)

    def test_local_mirror_on_rif_with_rif_add_delete(self):
        '''
        This test case helps to test when a logical port is created on underlying
        port, that has a mirror session attached, the traffic on logical port
        should mirror too
        '''
        mirror_session_oid, in_pkt, expected_out_pkt = self.__create_mirror_session_and_input_pkt_and_out_pkt()
        # inject packet, check packet only on out-port
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        # attach mirror-session to ingress port, check packet on both out-port and mirror-dest port
        self.__attach_mirror_session([pytest.tb.ports[pytest.top.in_port]], [mirror_session_oid])
        U.run_and_compare_set(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt, pytest.top.mirror_dest: in_pkt}, True)

        # delete rif
        pytest.top.deconfigure_rif_id_1_v4_v6()
        # recreate rif
        pytest.top.configure_rif_id_1_v4_v6(pytest.top.in_port)
        # Check mirroring continues to happen
        U.run_and_compare_set(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt, pytest.top.mirror_dest: in_pkt}, True)
        # detach mirror-session from ingress port passing empty mirror oids will detach all mirror sessions on the port
        self.__detach_all_mirror_session([pytest.tb.ports[pytest.top.in_port]])
        # check packet on only out-port and not on mirror-dest port
        U.run_and_compare_set(self, in_pkt, pytest.top.in_port, {pytest.top.out_port: expected_out_pkt}, True)
        pytest.tb.remove_object(mirror_session_oid)
