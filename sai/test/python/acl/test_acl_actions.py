#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from acl_entry_tests import *
from acl_table_tests import *
import sai_packet_utils as U
from scapy.all import *


@pytest.mark.usefixtures("mirror_rif_topology")
class Test_acl_actions():

    def test_action_redirect_to_nexthop(self):
        # Redirect out the mirror port
        self.redirect(pytest.tb.nh_id3, pytest.top.mirror_dest)

    def redirect(self, redirect_target, redirect_port):
        match_sport = 42

        aclTable = acl_table_tests()
        table_obj = aclTable.create_table_1_field(SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT)

        aclEntry = acl_entry_tests()
        args = {}
        args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = table_obj
        args[SAI_ACL_ENTRY_ATTR_PRIORITY] = 1
        args[SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT] = [True, match_sport, 0xFFFF]
        args[SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT] = [True, redirect_target]
        entry_obj = aclEntry.create_entry(args)

        # Verify that pkts reach the dest port & not the redirect port before applying the ACL
        self.send_udp_pkt(match_sport, pytest.top.out_port)
        with pytest.raises(Exception):
            self.send_udp_pkt(match_sport, redirect_port)

        # Bind the table to the interface
        pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, table_obj)

        # Verify that matching pkts reach the redirect port & not the dest port
        self.send_udp_pkt(match_sport, redirect_port)
        with pytest.raises(Exception):
            self.send_udp_pkt(match_sport, pytest.top.out_port)

        # Verify that non-matching pkts reach the dest port & not the redirect port
        self.send_udp_pkt(1, pytest.top.out_port)
        with pytest.raises(Exception):
            self.send_udp_pkt(1, redirect_port)

        pytest.tb.bind_acl_to_port(pytest.top.in_port, SAI_PORT_ATTR_INGRESS_ACL, 0)
        pytest.tb.remove_object(entry_obj)
        pytest.tb.remove_object(table_obj)

    def send_udp_pkt(self, sport, out_port):
        in_pkt = Ether(dst=pytest.tb.router_mac, src=pytest.top.neighbor_mac1) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64) / \
            UDP(sport=sport)

        expected_out_pkt = Ether(dst=pytest.top.neighbor_mac2, src=pytest.tb.router_mac) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=63) / \
            UDP(sport=sport)

        U.run_and_compare(self, in_pkt, pytest.top.in_port, expected_out_pkt, out_port)
