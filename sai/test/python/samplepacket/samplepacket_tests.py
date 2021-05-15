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


class samplepacket_tests(object):
    def __init__(self, ip_version):
        self.ip_version = ip_version

    def _create_samplepacket_session(self):
        args = {}
        args[SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE] = 1
        samplepacket = pytest.tb.create_object(SAI_OBJECT_TYPE_SAMPLEPACKET, args, verify=[True, False])

        return samplepacket

    def _create_pkts(self):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1)

        out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac)

        if self.ip_version is "v4":
            in_pkt = in_pkt / \
                IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64)

            out_pkt = out_pkt / \
                IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63)
        else:
            in_pkt = in_pkt / \
                IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=64)

            out_pkt = out_pkt / \
                IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=63)

        in_pkt = in_pkt / \
            UDP(sport=64, dport=2048)
        out_pkt = out_pkt / \
            UDP(sport=64, dport=2048)

        return in_pkt, out_pkt

    def _attach_samplepacket_session(self, port, samplepacket_oid, gress):
        pytest.tb.set_object_attr(pytest.tb.ports[port], gress, samplepacket_oid, verify=True)

    def _detach_samplepacket(self, port, gress):
        pytest.tb.set_object_attr(pytest.tb.ports[pytest.top.in_port], gress, SAI_NULL_OBJECT_ID, verify=True)

    def _test_send_packet(self, mirror_port, in_port, out_port, ingress):

        oid = self._create_samplepacket_session()
        in_pkt, out_pkt = self._create_pkts()

        if ingress:
            samplepacket_gress = SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE
            mirror_gress = SAI_PORT_ATTR_INGRESS_MIRROR_SESSION
            cpu_pkt = in_pkt
        else:
            samplepacket_gress = SAI_PORT_ATTR_EGRESS_SAMPLEPACKET_ENABLE
            mirror_gress = SAI_PORT_ATTR_EGRESS_MIRROR_SESSION
            cpu_pkt = out_pkt

        self._attach_samplepacket_session(mirror_port, oid, samplepacket_gress)
        exp_out_pkts = {out_port: out_pkt}

        # Remove Mirror Sessions (not samplepacket sessions)
        mirror_dest_oids = []
        pytest.tb.set_object_attr(pytest.tb.ports[mirror_port], mirror_gress, mirror_dest_oids, verify=True)

        U.punt_snoop_test_helper(self, in_pkt, in_port, exp_out_pkts, cpu_pkt, out_port=out_port, ingress=ingress)
        self._detach_samplepacket(in_port, samplepacket_gress)
