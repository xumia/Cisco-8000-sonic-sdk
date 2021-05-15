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
import sai_test_base as st_base
import sai_test_utils as st_utils
from scapy.all import *
import sai_topology as topology
import time


@pytest.fixture(scope="class")
def no_service_topology(base_v4_topology):
    pytest.tb.configure_ports([pytest.top.in_port_cfg, pytest.top.out_port_cfg, pytest.top.sw_port_cfg, pytest.top.rt_port_cfg])
    #pytest.lag_id = pytest.tb.create_lag()
    #lag_member_id = pytest.tb.create_lag_member(pytest.lag_id, pytest.top.out_port)
    #pytest.top.out_port = pytest.lag_id

    yield

    # pytest.tb.remove_object(lag_member_id)
    # pytest.tb.remove_object(pytest.lag_id)
    #delattr(pytest, 'lag_id')
    pytest.tb.remove_ports()


@pytest.mark.usefixtures("no_service_topology")
class Test_no_service():

    def lldp_packet(self, count, trap_type):
        lldp_da = '01:80:c2:00:00:0e'

        in_pkt = \
            Ether(dst=lldp_da, src=pytest.tb.router_mac, type=U.Ethertype.LLDP.value) / \
            IP(src=pytest.top.neighbor_ip1, dst=pytest.top.neighbor_ip2, ttl=64)

        expected_out_pkt = in_pkt

        U.punt_test(self, in_pkt, pytest.top.in_port, expected_out_pkt, count, trap_type)

    def test_lldp(self):
        self.lldp_trap = pytest.tb.create_trap(SAI_HOSTIF_TRAP_TYPE_LLDP, SAI_PACKET_ACTION_TRAP, 4)
        self.lldp_packet(1, self.lldp_trap)
