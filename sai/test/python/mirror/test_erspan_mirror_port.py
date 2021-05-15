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
from sai_packet_test_defs import *
from mirror_utils import *

# Mirror Test cases covered
#   Ingress-Mirroring
#       1. Erspan mirror session create/delete
#       2. Erspan mirror session create, modify erspan header, delete
#       3. After creating logical ports (bridge port/s) on eth port, attach mirror session
#           3.1 Test out packet on both destination bridged port and mirror monitor port
#       4. After attaching mirror session on eth port, test any new logical bridge ports created
#          on underlying port (that is mirroring) also mirror packet. Done by removing/deleting
#          logical port from the underlying port, and adding it back. Incoming packets on
#          new logical port should mirror packets.
#       5. Repeat [4] using rif as mirroring port.
#
#   Egress Mirroring
#       TBD


@pytest.mark.usefixtures("mirror_port_bridge_rif_topology")
class Test_erspan_bport():

    def test_create_delete_mirror_session(self):
        self.utils = ErspanMirrorUtils()
        attrs = self.utils.build_mirror_session_attr(mirror_port=True)
        mirror_session = pytest.tb.create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, attrs, verify=[True, False])
        assert mirror_session != 0
        self.utils.verify_default_attribute(mirror_session)
        pytest.tb.remove_object(mirror_session)

    def test_mirror_session_attrib_modify(self):
        self.utils = ErspanMirrorUtils()
        attrs = self.utils.build_mirror_session_attr(mirror_port=True)
        mirror_session = pytest.tb.create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, attrs, verify=[True, False])
        assert mirror_session != 0
        self.utils.verify_default_attribute(mirror_session)

        modifyable_attrs = self.utils.build_modifyable_mirror_session_attr()
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

    def test_erspan_on_bridge_port(self):
        '''
        This test case helps to test mirror on all logical ports that are already
        created on underlying port. When mirror session is attached to underlying
        port, traffic on all logical port should mirror too.
        '''
        self.utils = ErspanMirrorUtils()
        mirror_session_oid, in_pkt, erspan_pkt = self.utils.create_erspan_mirror_session_and_bridge_inpkt_erspan_pkt(
            mirror_port=True)
        # inject packet, check packet only on out-port
        U.run_and_compare(self, in_pkt, pytest.top.in_port, in_pkt, pytest.top.out_port)

        for i in range(2):
            # attach mirror-session to ingress port, check packet on both out-port and mirror-dest port
            self.__attach_mirror_session([pytest.tb.ports[pytest.top.in_port]], [mirror_session_oid])
            U.run_and_compare_set(
                self, in_pkt, pytest.top.in_port, {
                    pytest.top.out_port: in_pkt, pytest.top.mirror_dest: erspan_pkt}, True)

            # detach mirror-session from ingress port passing empty mirror oids will detach all mirror sessions on the port
            self.__detach_all_mirror_session([pytest.tb.ports[pytest.top.in_port]])
            # check packet on only out-port and not on mirror-dest port
            U.run_and_compare_set(self, in_pkt, pytest.top.in_port, {pytest.top.out_port: in_pkt})

        pytest.tb.remove_object(mirror_session_oid)

    def test_erspan_on_bridge_port_with_port_add_delete(self):
        '''
        This test case helps to test when a logical port is created on underlying
        port, that has a mirror session attached, the traffic on logical port
        should mirror too
        '''
        self.utils = ErspanMirrorUtils()
        mirror_session_oid, in_pkt, erspan_pkt = self.utils.create_erspan_mirror_session_and_bridge_inpkt_erspan_pkt(
            mirror_port=True)
        # attach mirror-session to ingress port, check packet on both out-port and mirror-dest port
        self.__attach_mirror_session([pytest.tb.ports[pytest.top.in_port]], [mirror_session_oid])
        U.run_and_compare_set(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: in_pkt, pytest.top.mirror_dest: erspan_pkt}, True)

        pytest.tb.remove_fdb_entry(pytest.tb.vlans[pytest.top.vlan], pytest.top.neighbor_mac2)
        # Delete bridge port and add back to check if newly created l2-port continues to mirror.
        pytest.tb.deconfigure_vlan_members()
        pytest.tb.obj_wrapper.remove_object(pytest.tb.bridge_ports[pytest.top.in_port])
        # create bridge port on top of port with attached mirror session
        pytest.tb.create_bridge_port(pytest.top.in_port)
        pytest.tb.configure_vlan_members([{"vlan": pytest.top.vlan, "port": pytest.top.in_port, "is_tag": False},
                                          {"vlan": pytest.top.vlan, "port": pytest.top.out_port, "is_tag": False}])
        pytest.tb.create_fdb_entry(pytest.tb.vlans[pytest.top.vlan],
                                   pytest.top.neighbor_mac2,
                                   pytest.tb.bridge_ports[pytest.top.out_port])

        # check mirroring continues to work.
        U.run_and_compare_set(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: in_pkt, pytest.top.mirror_dest: erspan_pkt}, True)

        self.__detach_all_mirror_session([pytest.tb.ports[pytest.top.in_port]])
        pytest.tb.remove_object(mirror_session_oid)


@pytest.mark.usefixtures("mirror_port_rif_topology")
class Test_erspan_rif():

    def test_create_delete_mirror_session(self):
        self.utils = ErspanMirrorUtils()
        attrs = self.utils.build_mirror_session_attr(mirror_port=True)
        mirror_session = pytest.tb.create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, attrs, verify=[True, False])
        assert mirror_session != 0
        self.utils.verify_default_attribute(mirror_session)
        pytest.tb.remove_object(mirror_session)

    def test_mirror_session_attrib_modify(self):
        self.utils = ErspanMirrorUtils()
        attrs = self.utils.build_mirror_session_attr(mirror_port=True)
        mirror_session = pytest.tb.create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, attrs, verify=[True, False])
        assert mirror_session != 0
        self.utils.verify_default_attribute(mirror_session)

        modifyable_attrs = self.utils.build_modifyable_mirror_session_attr()
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

    def test_erspan_on_rif(self):
        '''
        This test case helps to test mirror on all logical ports that are already
        created on underlying port. When mirror session is attached to underlying
        port, traffic on all logical port should mirror too.
        '''
        self.utils = ErspanMirrorUtils()
        mirror_session_oid, in_pkt, erspan_pkt = self.utils.create_erspan_mirror_session_and_route_inpkt_erspan_pkt(
            mirror_port=True)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        # inject packet, check packet only on out-port
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

        for i in range(2):
            # attach mirror-session to ingress port, check packet on both out-port and mirror-dest port
            self.__attach_mirror_session([pytest.tb.ports[pytest.top.in_port]], [mirror_session_oid])

            # Removing 'sai_samplepacket' and 'sai_mirror' sessions from ports call the same underlying
            # apis. Verify we do not remove 'sai_mirror' sessions when intending to only remove
            # samplepacket sessions.
            pytest.tb.set_object_attr(pytest.tb.ports[pytest.top.in_port],
                                      SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE, SAI_NULL_OBJECT_ID)

            U.run_and_compare_set(
                self, in_pkt, pytest.top.in_port, {
                    pytest.top.out_port: expected_out_pkt, pytest.top.mirror_dest: erspan_pkt}, True)

            # detach mirror-session from ingress port passing empty mirror oids will detach all mirror sessions on the port
            self.__detach_all_mirror_session([pytest.tb.ports[pytest.top.in_port]])
            # check packet on only out-port and not on mirror-dest port
            U.run_and_compare_set(self, in_pkt, pytest.top.in_port, {pytest.top.out_port: expected_out_pkt})

        # modifyable_attrs = self.utilsbuild_modifyable_mirror_session_attr_vlan_tagged()
        # for k, v in modifyable_attrs.items():
        #     pytest.tb.set_object_attr(mirror_session, k, v, verify=True)

        pytest.tb.remove_object(mirror_session_oid)

    def test_erpsan_on_rif_with_rif_add_delete(self):
        '''
        This test case helps to test when a logical port is created on underlying
        port, that has a mirror session attached, the traffic on logical port
        should mirror too
        '''
        self.utils = ErspanMirrorUtils()
        mirror_session_oid, in_pkt, erspan_pkt = self.utils.create_erspan_mirror_session_and_route_inpkt_erspan_pkt(
            mirror_port=True)
        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=64, dport=2048)

        # inject packet, check packet only on out-port
        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)
        # attach mirror-session to ingress port, check packet on both out-port and mirror-dest port
        self.__attach_mirror_session([pytest.tb.ports[pytest.top.in_port]], [mirror_session_oid])
        U.run_and_compare_set(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt, pytest.top.mirror_dest: erspan_pkt}, True)
        # delete rif
        pytest.top.deconfigure_rif_id_1_v4_v6()
        # recreate rif
        pytest.top.configure_rif_id_1_v4_v6(pytest.top.in_port)
        U.run_and_compare_set(
            self, in_pkt, pytest.top.in_port, {
                pytest.top.out_port: expected_out_pkt, pytest.top.mirror_dest: erspan_pkt}, True)

        self.__detach_all_mirror_session([pytest.tb.ports[pytest.top.in_port]])
        pytest.tb.remove_object(mirror_session_oid)
