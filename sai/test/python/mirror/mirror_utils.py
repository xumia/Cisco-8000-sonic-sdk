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
from sai_test_utils import *
from scapy.all import *
from sai_packet_test_defs import *


MIN_SYSTEM_PORT_GID = 4  # Keep this value in sync with value of MIN_SYSTEM_PORT_GID in la_device_impl.h


class SflowUtils():
    def build_sflow_session_attr(self, mirror_port=False):
        attrs = {}
        attrs[SAI_MIRROR_SESSION_ATTR_TYPE] = SAI_MIRROR_SESSION_TYPE_SFLOW
        attrs[SAI_MIRROR_SESSION_ATTR_TC] = 0
        attrs[SAI_MIRROR_SESSION_ATTR_TTL] = 223
        attrs[SAI_MIRROR_SESSION_ATTR_IPHDR_VERSION] = 4
        attrs[SAI_MIRROR_SESSION_ATTR_TOS] = 0
        attrs[SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS] = "1.1.1.1"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS] = "2.2.2.2"
        attrs[SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS] = "01:02:03:09:09:09"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS] = "01:02:03:01:02:03"
        attrs[SAI_MIRROR_SESSION_ATTR_UDP_SRC_PORT] = 9900
        attrs[SAI_MIRROR_SESSION_ATTR_UDP_DST_PORT] = 6344
        if mirror_port:
            attrs[SAI_MIRROR_SESSION_ATTR_MONITOR_PORT] = pytest.tb.ports[pytest.top.mirror_dest]
        else:
            attrs[SAI_MIRROR_SESSION_ATTR_MONITOR_PORT] = pytest.tb.rif_id_4
        attrs[SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE] = 0
        attrs[SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE] = 1
        return attrs

    def verify_default_attribute(self, sflow_session):  # , set_attr_values):
        assert pytest.tb.get_object_attr(sflow_session, SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE) == 0
        assert pytest.tb.get_object_attr(sflow_session, SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE) == 1

    def build_modifyable_sflow_session_attr(self):
        attrs = {}
        attrs[SAI_MIRROR_SESSION_ATTR_TTL] = 223
        attrs[SAI_MIRROR_SESSION_ATTR_TOS] = 0
        attrs[SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS] = "11.11.11.11"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS] = "22.22.22.22"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS] = "04:02:03:01:02:03"
        attrs[SAI_MIRROR_SESSION_ATTR_UDP_SRC_PORT] = 4777
        attrs[SAI_MIRROR_SESSION_ATTR_UDP_DST_PORT] = 4701
        attrs[SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE] = 0
        return attrs

    def create_bridge_inpkt_and_out_sflow_pkt(self, attrs, in_port_sp_gid, dstMac):
        in_pkt = Ether(dst=dstMac, src="00:ef:00:ef:00:ef") / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        sflow_pkt = Ether(dst=attrs[SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS],
                          src=pytest.tb.router_mac) / IP(src=attrs[SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS],
                                                         dst=attrs[SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS],
                                                         ttl=attrs[SAI_MIRROR_SESSION_ATTR_TTL],
                                                         tos=attrs[SAI_MIRROR_SESSION_ATTR_TOS],
                                                         flags="DF",
                                                         id=0) / UDP(sport=attrs[SAI_MIRROR_SESSION_ATTR_UDP_SRC_PORT],
                                                                     dport=attrs[SAI_MIRROR_SESSION_ATTR_UDP_DST_PORT],
                                                                     chksum=0) / U.sflow_tunnel_metadata(source_sp=MIN_SYSTEM_PORT_GID + in_port_sp_gid,
                                                                                                         destination_sp=65535,
                                                                                                         source_lp=524289) / Ether(dst=dstMac,
                                                                                                                                   src="00:ef:00:ef:00:ef") / IP(src=pytest.top.neighbor_ip1,
                                                                                                                                                                 dst=pytest.top.neighbor_ip2,
                                                                                                                                                                 ttl=64) / UDP(sport=64,
                                                                                                                                                                               dport=2048)

        return in_pkt, sflow_pkt

    def create_sflow_session_and_bridge_inpkt_sflow_pkt(self, in_port_sp_gid, mirror_port=False):
        attrs = self.build_sflow_session_attr(mirror_port)
        sflow_session_oid = self.create_sflow_session(attrs)
        assert sflow_session_oid != 0
        in_pkt, sflow_pkt = self.create_bridge_inpkt_and_out_sflow_pkt(attrs, in_port_sp_gid, pytest.top.neighbor_mac2)
        return sflow_session_oid, in_pkt, sflow_pkt

    def create_routable_inpkt_and_out_sflow_pkt(self, attrs, in_port_sp_gid, inPktSrcMac, outPktDstMac, sip, dip):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=inPktSrcMac) / \
            IP(src=sip, dst=dip, ttl=64) / \
            UDP(sport=64, dport=2048)
        sflow_pkt = Ether(dst=attrs[SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS],
                          src=attrs[SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS]) / IP(src=attrs[SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS],
                                                                                   dst=attrs[SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS],
                                                                                   ttl=attrs[SAI_MIRROR_SESSION_ATTR_TTL],
                                                                                   tos=attrs[SAI_MIRROR_SESSION_ATTR_TOS],
                                                                                   flags="DF",
                                                                                   id=0) / UDP(sport=attrs[SAI_MIRROR_SESSION_ATTR_UDP_SRC_PORT],
                                                                                               dport=attrs[SAI_MIRROR_SESSION_ATTR_UDP_DST_PORT],
                                                                                               chksum=0) / U.sflow_tunnel_metadata(source_sp=MIN_SYSTEM_PORT_GID + in_port_sp_gid,
                                                                                                                                   destination_sp=65535,
                                                                                                                                   source_lp=524289) / Ether(dst=pytest.tb.router_mac,
                                                                                                                                                             src=inPktSrcMac) / IP(src=sip,
                                                                                                                                                                                   dst=dip,
                                                                                                                                                                                   ttl=64) / UDP(sport=64,
                                                                                                                                                                                                 dport=2048)
        out_pkt = Ether(dst=outPktDstMac, src=pytest.tb.router_mac) / \
            IP(src=sip, dst=dip, ttl=63) / \
            UDP(sport=64, dport=2048)

        return in_pkt, sflow_pkt, out_pkt

    def create_sflow_session_and_route_inpkt_sflow_pkt(self, in_port_sp_gid, mirror_port=False):
        attrs = self.build_sflow_session_attr(mirror_port)
        sflow_session_oid = self.create_sflow_session(attrs)
        assert sflow_session_oid != 0

        in_pkt, sflow_pkt, _ = self.create_routable_inpkt_and_out_sflow_pkt(
            attrs, in_port_sp_gid, pytest.top.neighbor_mac1, pytest.top.neighbor_mac2, pytest.top.neighbor_ip1, pytest.top.neighbor_ip2)

        return sflow_session_oid, in_pkt, sflow_pkt

    def create_sflow_session(self, attrs):
        attrlist = []
        for key in attrs:
            if key == SAI_MIRROR_SESSION_ATTR_POLICER + 1 or key == SAI_MIRROR_SESSION_ATTR_POLICER + 2:
                attrlist.append([key, attrs[key], "skip_verify"])
            else:
                attrlist.append([key, attrs[key]])
        return pytest.tb.obj_wrapper.create_object(
            SAI_OBJECT_TYPE_MIRROR_SESSION, pytest.tb.switch_id, attrlist, [
                True, False], False)
        # return pytest.tb.create_sflow_session(SAI_OBJECT_TYPE_MIRROR_SESSION, attrs, verify=[True, False])


class ErspanMirrorUtils():
    def build_mirror_session_attr(self, mirror_port=False):
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
        if mirror_port:
            attrs[SAI_MIRROR_SESSION_ATTR_MONITOR_PORT] = pytest.tb.ports[pytest.top.mirror_dest]
        else:
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
        attrs[SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS] = "04:02:03:09:09:09"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS] = "04:02:03:01:02:03"
        attrs[SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE] = 0
        return attrs

    def build_modifyable_mirror_session_attr_vlan_tagged(self):
        attrs = {}
        attrs[SAI_MIRROR_SESSION_ATTR_TTL] = 223
        attrs[SAI_MIRROR_SESSION_ATTR_TOS] = 0
        attrs[SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS] = "11.11.11.11"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS] = "22.22.22.22"
        attrs[SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS] = "04:02:03:09:09:09"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS] = "04:02:03:01:02:03"
        attrs[SAI_MIRROR_SESSION_ATTR_DST_VLAN_HEADER_VALID] = 1
        attrs[SAI_MIRROR_SESSION_ATTR_DST_VLAN_ID] = 256
        attrs[SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE] = 0
        return attrs

    def create_bridge_inpkt_and_out_erspan_pkt(self, attrs, dstMac, erspan_session_id = 0):
        in_pkt = Ether(dst=dstMac, src="00:ef:00:ef:00:ef") / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        erspan_pkt = Ether(dst=attrs[SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS],
                           src=attrs[SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS]) / \
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
            ERSPAN(session_id=erspan_session_id, en=0) / \
            Ether(dst=dstMac, src="00:ef:00:ef:00:ef") / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        return in_pkt, erspan_pkt

    def create_erspan_mirror_session_and_bridge_inpkt_erspan_pkt(self, mirror_port=False):
        attrs = self.build_mirror_session_attr(mirror_port)
        mirror_session_oid = pytest.tb.create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, attrs, verify=[True, False])
        assert mirror_session_oid != 0
        in_pkt, erspan_pkt = self.create_bridge_inpkt_and_out_erspan_pkt(attrs, pytest.top.neighbor_mac2, mirror_session_oid)
        return mirror_session_oid, in_pkt, erspan_pkt

    def create_routable_inpkt_and_out_erspan_pkt(self, attrs, inPktSrcMac, outPktDstMac, sip, dip, erspan_session_id = 0):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=inPktSrcMac) / \
            IP(src=sip, dst=dip, ttl=64) / \
            UDP(sport=64, dport=2048)

        erspan_pkt = Ether(dst=attrs[SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS],
                           src=attrs[SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS]) / \
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
            ERSPAN(session_id=erspan_session_id, en=0) / \
            Ether(dst=pytest.tb.router_mac, src=inPktSrcMac) / \
            IP(src=sip, dst=dip, ttl=64) / \
            UDP(sport=64, dport=2048)

        out_pkt = Ether(dst=outPktDstMac, src=pytest.tb.router_mac) / \
            IP(src=sip, dst=dip, ttl=63) / \
            UDP(sport=64, dport=2048)

        return in_pkt, erspan_pkt, out_pkt

    def create_erspan_mirror_session_and_route_inpkt_erspan_pkt(self, mirror_port=False):
        attrs = self.build_mirror_session_attr(mirror_port)
        mirror_session_oid = pytest.tb.create_object(SAI_OBJECT_TYPE_MIRROR_SESSION, attrs, verify=[True, False])
        assert mirror_session_oid != 0
        in_pkt, erspan_pkt, _ = self.create_routable_inpkt_and_out_erspan_pkt(
            attrs, pytest.top.neighbor_mac1, pytest.top.neighbor_mac2, pytest.top.neighbor_ip1, pytest.top.neighbor_ip2, mirror_session_oid)
        return mirror_session_oid, in_pkt, erspan_pkt
