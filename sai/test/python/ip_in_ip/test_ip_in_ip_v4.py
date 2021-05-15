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
from scapy.all import *
import sai_topology as topology
from sai_test_utils import *
import itertools


class IPINIP_Tests():
    def _create_tunnel(self, args_user=None):
        pytest.top.overlay_lpbk = pytest.top.tb.create_router_interface(pytest.top.tb.virtual_router_id)
        pytest.top.entry = []
        args = {}
        args[S.SAI_TUNNEL_ATTR_DECAP_TTL_MODE] = S.SAI_TUNNEL_TTL_MODE_UNIFORM_MODEL
        args[S.SAI_TUNNEL_ATTR_TYPE] = S.SAI_TUNNEL_TYPE_IPINIP
        args[S.SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE] = pytest.top.tb.rif_loopback
        args[S.SAI_TUNNEL_ATTR_OVERLAY_INTERFACE] = pytest.top.overlay_lpbk
        args[S.SAI_TUNNEL_ATTR_DECAP_DSCP_MODE] = S.SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL
        args[S.SAI_TUNNEL_ATTR_DECAP_ECN_MODE] = S.SAI_TUNNEL_DECAP_ECN_MODE_COPY_FROM_OUTER
        if args_user:
            args.update(args_user)
        pytest.top.tunnel = pytest.tb.create_object(S.SAI_OBJECT_TYPE_TUNNEL, args)

    def _add_tunnel_term_entry(self, dst_ip, args_user=None):
        args = {}
        args[S.SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID] = pytest.top.tb.virtual_router_id
        args[S.SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE] = S.SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP
        args[S.SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE] = S.SAI_TUNNEL_TYPE_IPINIP
        args[S.SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID] = pytest.top.tunnel
        args[S.SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP] = dst_ip
        if args_user:
            args.update(args_user)
        pytest.top.entry.append(pytest.tb.create_object(S.SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY, args))

    def _remove_tunnel(self):
        for x in pytest.top.entry:
            pytest.tb.remove_object(x)
        pytest.tb.remove_object(pytest.top.tunnel)
        pytest.tb.remove_object(pytest.top.overlay_lpbk)

    def _run_ipinip_decap(self, in_pkt, expected_out_pkt):

        obj_count, obj_list = pytest.top.tb.get_object_keys(S.SAI_OBJECT_TYPE_ROUTE_ENTRY)
        dump_route_entries(obj_count, obj_list)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, pytest.top.out_port)

    def test_decap_src_ip(self, in_pkt, out_pkt, src_ip, dst_ip):
        args = {}
        args[S.SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE] = S.SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P
        args[S.SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_SRC_IP] = src_ip
        self._create_tunnel()
        self._add_tunnel_term_entry(dst_ip, args_user=args)
        self._run_ipinip_decap(in_pkt, out_pkt)
        self._remove_tunnel()

    def test_decap_no_src_ip(self, in_pkt, out_pkt, dst_ip):
        self._create_tunnel()
        self._add_tunnel_term_entry(dst_ip)
        self._run_ipinip_decap(in_pkt, out_pkt)
        self._remove_tunnel()

    def test_decap_ttl_pipe(self, in_pkt, out_pkt, dst_ip):
        args = {}
        args[S.SAI_TUNNEL_ATTR_DECAP_TTL_MODE] = S.SAI_TUNNEL_TTL_MODE_PIPE_MODEL
        self._create_tunnel(args)
        self._add_tunnel_term_entry(dst_ip)
        self._run_ipinip_decap(in_pkt, out_pkt)
        self._remove_tunnel()

    def test_decap_multiple_entries(self, in_pkts, out_pkts, dst_ips):
        self._create_tunnel()
        # add multiple tunnel terms
        for dst_ip in dst_ips:
            self._add_tunnel_term_entry(dst_ip)

        # validate number of term entries
        entries = sai_object_list_t([])
        arg = sai_attribute_t(SAI_TUNNEL_ATTR_TERM_TABLE_ENTRY_LIST, entries)
        with expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            pytest.tb.apis[SAI_API_TUNNEL].get_tunnel_attribute(pytest.top.tunnel, 1, arg)

        assert(arg.value.objlist.count == len(dst_ips))

        # test decap on each term
        for (in_pkt, out_pkt) in zip(in_pkts, out_pkts):
            self._run_ipinip_decap(in_pkt, out_pkt)
        self._remove_tunnel()

    # ipv6 tunnel currenlty not supported. verify we return not supported
    def test_configure_ipv6_decap_tunnel(self, src_ip):
        self._create_tunnel()
        args = {}
        args[S.SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID] = pytest.top.tb.virtual_router_id
        args[S.SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE] = S.SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP
        args[S.SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE] = S.SAI_TUNNEL_TYPE_IPINIP
        args[S.SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID] = pytest.top.tunnel
        args[S.SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP] = src_ip
        with expect_sai_error(SAI_STATUS_NOT_IMPLEMENTED):
            pytest.tb.create_object(S.SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY, args)


@pytest.mark.usefixtures("basic_route_v4_topology")
class Test_ipinip_v4():

    LOCAL_IP = "4.4.4.4"
    REMOTE_IP = "5.5.5.5"
    REMOTE_IPV6 = "1111:db9:a0b:12f0::2222"
    INNER_TTL = 64
    OUTER_TTL = 125
    DSCP_VAL = 8
    ECN_VAL = 0  # TODO Zero until ECN working
    TOS = (DSCP_VAL << 2) | ECN_VAL

    tests = IPINIP_Tests()

    def test_decap_src_ip(self):
        in_pkt = Ether(dst=pytest.top.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=self.REMOTE_IP, dst=self.LOCAL_IP, ttl=self.OUTER_TTL, tos=self.TOS) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=self.INNER_TTL) / \
            UDP(sport=64, dport=2048) / \
            ("\0" * 26)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=self.OUTER_TTL - 1, tos=self.TOS) / \
            UDP(sport=64, dport=2048) / \
            ("\0" * 26)
        self.tests.test_decap_src_ip(in_pkt, expected_out_pkt, self.REMOTE_IP, self.LOCAL_IP)

    def test_decap_no_src_ip(self):

        in_pkt = Ether(dst=pytest.top.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=self.REMOTE_IP, dst=self.LOCAL_IP, ttl=self.OUTER_TTL, tos=self.TOS) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=self.INNER_TTL) / \
            UDP(sport=64, dport=2048) / \
            ("\0" * 26)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=self.OUTER_TTL - 1, tos=self.TOS) / \
            UDP(sport=64, dport=2048) / \
            ("\0" * 26)

        self.tests.test_decap_no_src_ip(in_pkt, expected_out_pkt, self.LOCAL_IP)

    def test_decap_ttl_pipe(self):
        in_pkt = Ether(dst=pytest.top.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=self.REMOTE_IP, dst=self.LOCAL_IP, ttl=self.OUTER_TTL, tos=self.TOS) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=self.INNER_TTL) / \
            UDP(sport=64, dport=2048) / \
            ("\0" * 26)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=self.INNER_TTL - 1, tos=self.TOS) / \
            UDP(sport=64, dport=2048) / \
            ("\0" * 26)

        self.tests.test_decap_ttl_pipe(in_pkt, expected_out_pkt, self.LOCAL_IP)

    def test_decap_multiple_entries(self):
        num_entries = 10
        in_pkts = []
        out_pkts = []
        dst_ips = []
        for x in range(10):

            dst_ip = "4.4.4." + str(x)
            dst_ips.append(dst_ip)

            in_pkt = Ether(dst=pytest.top.tb.router_mac, src=pytest.top.neighbor_mac1) / \
                IP(src=self.REMOTE_IP, dst=dst_ip, ttl=self.OUTER_TTL, tos=self.TOS) / \
                IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=self.INNER_TTL) / \
                UDP(sport=64, dport=2048) / \
                ("\0" * 26)

            in_pkts.append(in_pkt)

            expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.tb.router_mac) / \
                IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=self.OUTER_TTL - 1, tos=self.TOS) / \
                UDP(sport=64, dport=2048) / \
                ("\0" * 26)

            out_pkts.append(expected_out_pkt)

        self.tests.test_decap_multiple_entries(in_pkts, out_pkts, dst_ips)

    def test_configure_ipv6_decap_tunnel(self):
        self.tests.test_configure_ipv6_decap_tunnel(self.REMOTE_IPV6)


@pytest.mark.usefixtures("basic_route_v6_topology")
class Test_ipinip_v6_in_v4():

    LOCAL_IP = "4.4.4.4"
    REMOTE_IP = "5.5.5.5"
    INNER_TTL = 64
    OUTER_TTL = 125
    DSCP_VAL = 8
    ECN_VAL = 0  # TODO Zero until ECN working
    TOS = (DSCP_VAL << 2) | ECN_VAL

    tests = IPINIP_Tests()

    def test_decap_src_ip(self):
        in_pkt = Ether(dst=pytest.top.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=self.REMOTE_IP, dst=self.LOCAL_IP, ttl=self.OUTER_TTL, tos=self.TOS) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=self.INNER_TTL) / \
            UDP(sport=64, dport=2048) / \
            ("\0" * 26)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=self.OUTER_TTL - 1, tc=self.TOS) / \
            UDP(sport=64, dport=2048) / \
            ("\0" * 26)
        self.tests.test_decap_src_ip(in_pkt, expected_out_pkt, self.REMOTE_IP, self.LOCAL_IP)

    def test_decap_no_src_ip(self):

        in_pkt = Ether(dst=pytest.top.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=self.REMOTE_IP, dst=self.LOCAL_IP, ttl=self.OUTER_TTL, tos=self.TOS) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=self.INNER_TTL) / \
            UDP(sport=64, dport=2048) / \
            ("\0" * 26)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=self.OUTER_TTL - 1, tc=self.TOS) / \
            UDP(sport=64, dport=2048) / \
            ("\0" * 26)

        self.tests.test_decap_no_src_ip(in_pkt, expected_out_pkt, self.LOCAL_IP)

    def test_decap_ttl_pipe(self):
        in_pkt = Ether(dst=pytest.top.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=self.REMOTE_IP, dst=self.LOCAL_IP, ttl=self.OUTER_TTL, tos=self.TOS) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=self.INNER_TTL) / \
            UDP(sport=64, dport=2048) / \
            ("\0" * 26)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.tb.router_mac) / \
            IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=self.INNER_TTL - 1, tc=self.TOS) / \
            UDP(sport=64, dport=2048) / \
            ("\0" * 26)

        self.tests.test_decap_ttl_pipe(in_pkt, expected_out_pkt, self.LOCAL_IP)

    def test_decap_multiple_entries(self):
        num_entries = 10
        in_pkts = []
        out_pkts = []
        dst_ips = []
        for x in range(10):

            dst_ip = "4.4.4." + str(x)
            dst_ips.append(dst_ip)

            in_pkt = Ether(dst=pytest.top.tb.router_mac, src=pytest.top.neighbor_mac1) / \
                IP(src=self.REMOTE_IP, dst=dst_ip, ttl=self.OUTER_TTL, tos=self.TOS) / \
                IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=self.INNER_TTL) / \
                UDP(sport=64, dport=2048) / \
                ("\0" * 26)

            in_pkts.append(in_pkt)

            expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.top.tb.router_mac) / \
                IPv6(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, hlim=self.OUTER_TTL - 1, tc=self.TOS) / \
                UDP(sport=64, dport=2048) / \
                ("\0" * 26)

            out_pkts.append(expected_out_pkt)

        self.tests.test_decap_multiple_entries(in_pkts, out_pkts, dst_ips)
