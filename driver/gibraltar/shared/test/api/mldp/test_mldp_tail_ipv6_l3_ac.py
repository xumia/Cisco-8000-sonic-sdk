#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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


import sys
import unittest
import decor
from leaba import sdk
import ip_test_base
from scapy.all import *
import sim_utils
import nplapicli as nplapi
import topology as T
import packet_test_utils as U
from mldp_edge_base import *

load_contrib('mpls')


@unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
class mldp_tail_node_ipv6_l3_ac_test(mldp_edge_base):
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv6_test_base
    SIP = T.ipv6_addr('1001:0:0:0:0:0:1234:0001')
    DIP = T.ipv6_addr('1002:0:0:0:0:0:1234:0001')
    PACKET_SIP = SIP
    MC_GROUP_GID = 0x13
    MC_GROUP_ADDR = T.ipv6_addr('ff31:0:0:0:0:1:ffe8:658f')
    ipvx = 'v6'
    INPUT_LABEL_TAIL = sdk.la_mpls_label()
    INPUT_LABEL_TAIL.label = 0x65
    node_type = node_type_e.MLDP_TAIL_NODE
    MPLS_RPF_ID = 10000      # must be in range 4K to 32K
    IP_RPF_ID   = 20000      # used for RPF missed test
    OUT_RANGE_RPF_ID = 1000  # out of range rpf id

    # IPv4, (s,g) hit, no rpf
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    def test_mldp_ipv6_no_rpf(self):
        self.node_type = node_type_e.MLDP_TAIL_NODE
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.MPLS_RPF_ID
        self.trap = None
        self.enable_rpf_check = False
        self.punt_on_rpf_fail = False
        self.do_test_route()

    # IPv4, (s,g) hit, rpf pass
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    def test_mldp_ipv6_rpf_pass(self):
        self.node_type = node_type_e.MLDP_TAIL_NODE
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.MPLS_RPF_ID
        self.trap = None
        self.enable_rpf_check = True
        self.punt_on_rpf_fail = False
        self.do_test_route()

    # IPv4 (s,g) hit, rpf failed
    def test_mldp_ipv6_rpf_fail(self):
        self.node_type = node_type_e.MLDP_TAIL_NODE
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.IP_RPF_ID
        self.trap = True
        self.enable_rpf_check = True
        self.punt_on_rpf_fail = True
        trap_code = sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL

        self.prepare_punt(sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
                          sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                          trap_code, self.MPLS_RPF_ID, trap_code, 0)

        self.do_test_route()


@unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
class mldp_tail_node_ipv6_g_l3_ac_test_g(mldp_edge_base):
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv6_test_base
    SIP = T.ipv6_addr('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
    DIP = T.ipv6_addr('1002:0:0:0:0:0:1234:0001')
    PACKET_SIP = T.ipv6_addr('1003:0:0:0:0:0:1234:0001')
    MC_GROUP_GID = 0x13
    ipvx = 'v6'
    MC_GROUP_ADDR = T.ipv6_addr('ff31:0:0:0:0:2:ffe8:658f')
    INPUT_LABEL_TAIL = sdk.la_mpls_label()
    INPUT_LABEL_TAIL.label = 0x65
    node_type = node_type_e.MLDP_TAIL_NODE
    MPLS_RPF_ID = 10000      # must be in range 4K to 32K
    IP_RPF_ID   = 20000      # used for RPF missed test
    OUT_RANGE_RPF_ID = 1000  # out of range rpf id

    # IPv4, (*,g) hit, no rpf
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    def test_mldp_ipv6_no_rpf_g(self):
        self.node_type = node_type_e.MLDP_TAIL_NODE
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.MPLS_RPF_ID
        self.trap = None
        self.enable_rpf_check = False
        self.punt_on_rpf_fail = False
        self.do_test_route()

    # IPv4, (*,g) hit, rpf pass
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    def test_mldp_ipv6_rpf_pass_g(self):
        self.node_type = node_type_e.MLDP_TAIL_NODE
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.MPLS_RPF_ID
        self.trap = None
        self.enable_rpf_check = True
        self.punt_on_rpf_fail = False
        self.do_test_route()

    # IPv4 (*,g) hit, rpf failed
    def test_mldp_ipv6_rpf_fail_g(self):
        self.node_type = node_type_e.MLDP_TAIL_NODE
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.IP_RPF_ID
        self.trap = True
        self.enable_rpf_check = True
        self.punt_on_rpf_fail = True
        trap_code = sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL

        self.prepare_punt(sdk.la_packet_types.LA_HEADER_TYPE_IPV6,
                          sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                          trap_code, self.MPLS_RPF_ID, trap_code, 0)

        self.do_test_route()


@unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
class mldp_tail_node_ipv6_l3_ac_test_pim_all(mldp_edge_base):
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv6_test_base
    SIP = T.ipv6_addr('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
    DIP = T.ipv6_addr('1002:0:0:0:0:0:1234:0001')
    PACKET_SIP = SIP
    ipvx = 'v6'
    MC_GROUP_ADDR = T.ipv6_addr('ff02:0:0:0:0:0:0:0d')
    MC_GROUP_GID = 0x13
    MPLS_RPF_ID = 10000      # must be in range 4K to 32K
    INPUT_LABEL_TAIL = sdk.la_mpls_label()
    INPUT_LABEL_TAIL.label = 0x65
    node_type = node_type_e.MLDP_TAIL_NODE

    def test_mldp_ipv6_pim_all(self):
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.MPLS_RPF_ID
        self.trap = True
        self.pim_all = True
        self.enable_rpf_check = True
        self.punt_on_rpf_fail = True
        trap_code = mc_base.LPTS_PUNT_CODE_V6

        self.prepare_punt(sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                          sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
                          trap_code, self.rpfid, nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
                          mc_base.LPTS_FLOW_TYPE_V6)

        self.create_lpts()
        self.do_test_route()


if __name__ == '__main__':
    unittest.main()
