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
from acl_ipv6_tests import *
import sai_packet_utils as U
from scapy.all import *
from sai_packet_test_defs import *


class MirrorUtils():
    def build_mirror_session_attr(self):
        attrs = {}
        attrs[SAI_MIRROR_SESSION_ATTR_TYPE] = SAI_MIRROR_SESSION_TYPE_ENHANCED_REMOTE
        attrs[SAI_MIRROR_SESSION_ATTR_TC] = 0
        attrs[SAI_MIRROR_SESSION_ATTR_TTL] = 223
        attrs[SAI_MIRROR_SESSION_ATTR_IPHDR_VERSION] = 4
        attrs[SAI_MIRROR_SESSION_ATTR_TOS] = 0
        attrs[SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS] = "1.1.1.1"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS] = "2.2.2.2"
        attrs[SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS] = "01:02:03:09:09:09"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS] = "01:02:03:01:02:03"
        attrs[SAI_MIRROR_SESSION_ATTR_GRE_PROTOCOL_TYPE] = 0x88BE
        attrs[SAI_MIRROR_SESSION_ATTR_ERSPAN_ENCAPSULATION_TYPE] = SAI_ERSPAN_ENCAPSULATION_TYPE_MIRROR_L3_GRE_TUNNEL
        attrs[SAI_MIRROR_SESSION_ATTR_MONITOR_PORT] = pytest.tb.rif_id_4
        attrs[SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE] = 0
        attrs[SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE] = 1
        return attrs

    def verify_default_attribute(self, mirror_session):  # , set_attr_values):
        assert pytest.tb.get_object_attr(mirror_session, SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE) == 0
        assert pytest.tb.get_object_attr(mirror_session, SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE) == 1

    def build_modifyable_mirror_session_attr(self):
        attrs = {}
        attrs[SAI_MIRROR_SESSION_ATTR_TTL] = 223
        attrs[SAI_MIRROR_SESSION_ATTR_TOS] = 0
        attrs[SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS] = "11.11.11.11"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS] = "22.22.22.22"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS] = "04:02:03:01:02:03"
        attrs[SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE] = 0
        return attrs

    def create_erspan_mirror_session_and_route_inpkt_erspan_pkt(self):
        attrs = self.build_mirror_session_attr()
        mirror_session_oid = pytest.tb.create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, attrs, verify=[True, False])
        assert mirror_session_oid != 0
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)
        erspan_pkt = Ether(dst=attrs[SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS], src=pytest.tb.router_mac) / \
            IP(src=attrs[SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS],
               dst=attrs[SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS],
               ttl=attrs[SAI_MIRROR_SESSION_ATTR_TTL],
               tos=attrs[SAI_MIRROR_SESSION_ATTR_TOS],
               flags="DF",
               id=0,
               proto=47) / \
            GRE(proto=attrs[SAI_MIRROR_SESSION_ATTR_GRE_PROTOCOL_TYPE],
                seqnum_present=1,
                seqence_number=0) / \
            ERSPAN(session_id=0, en=0) / \
            Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)
        return mirror_session_oid, in_pkt, erspan_pkt


@pytest.mark.usefixtures("mirror_rif_topology")
class Test_acl_mirror():
    def test_ingress_ipv6_acl_mirror_action(self):
        self.utils = MirrorUtils()
        mirror_oid, _, _ = self.utils.create_erspan_mirror_session_and_route_inpkt_erspan_pkt()
        aclTestInstance = aclTests()
        aclTestInstance.ingress_ipv6_acl_table_mirror_test(mirror_oid)
        pytest.tb.remove_object(mirror_oid)


@pytest.mark.usefixtures("mirror_rif_topology")
class Test_acl_mirror_switch_attachment():

    def test_ingress_ipv6_acl_mirror_action(self):
        self.utils = MirrorUtils()
        mirror_oid, _, _ = self.utils.create_erspan_mirror_session_and_route_inpkt_erspan_pkt()
        aclTestInstance = aclTests()
        aclTestInstance.ingress_ipv6_acl_table_mirror_test(mirror_oid, switch_binding=True)
        pytest.tb.remove_object(mirror_oid)


@pytest.mark.usefixtures("mirror_rif_topology")
class Test_acl_mirror_switch_attachment_port_add_delete():

    def test_ingress_ipv6_acl_mirror_action(self):
        self.utils = MirrorUtils()
        mirror_oid, _, _ = self.utils.create_erspan_mirror_session_and_route_inpkt_erspan_pkt()
        aclTestInstance = aclTests()
        aclTestInstance.ingress_ipv6_acl_table_mirror_test(mirror_oid, switch_binding=True, add_delete_port=True)
        pytest.tb.remove_object(mirror_oid)
