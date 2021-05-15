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
@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
class mldp_tail_node_ipv4_l3_ac_test_v4(mldp_edge_base):
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    PACKET_SIP = SIP
    MC_GROUP_GID = 0x13
    MC_GROUP_ADDR = T.ipv4_addr('232.1.2.3')
    ipvx = 'v4'
    INPUT_LABEL_TAIL = sdk.la_mpls_label()
    INPUT_LABEL_TAIL.label = 0x65
    node_type = node_type_e.MLDP_TAIL_NODE
    MPLS_RPF_ID = 10000      # must be in range 4K to 32K
    IP_RPF_ID   = 20000      # used for RPF missed test
    OUT_RANGE_RPF_ID = 1000  # out of range rpf id

    # IPv4, (s,g) hit, no rpf
    def test_mldp_ipv4_fwd(self):
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.IP_RPF_ID
        self.trap = None
        self.enable_rpf_check = False
        self.punt_on_rpf_fail = False
        self.do_test_route()

    # IPv4, (s,g) hit, no rpf; modify route
    def test_mldp_ipv4_modify_rpf_fail(self):
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.IP_RPF_ID
        self.trap = None
        self.enable_rpf_check = False
        self.punt_on_rpf_fail = False
        self.do_test_route()

        self.rpfid1 = self.IP_RPF_ID
        self.trap = True
        self.enable_rpf_check = True
        self.punt_on_rpf_fail = True
        trap_code = sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL

        self.prepare_punt(sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
                          sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                          trap_code, self.MPLS_RPF_ID, trap_code, 0)

        self.modify_multicast_route()
        self.retest = True
        self.do_test_route()

    # IPv4, (s,g) hit, rpf pass
    def test_mldp_ipv4_rpf_pass(self):
        self.node_type = node_type_e.MLDP_TAIL_NODE
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.MPLS_RPF_ID
        self.trap = None
        self.enable_rpf_check = True
        self.punt_on_rpf_fail = False
        self.do_test_route()

    # IPv4 (s,g) hit, rpf failed
    def test_mldp_ipv4_rpf_fail(self):
        self.node_type = node_type_e.MLDP_TAIL_NODE
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.IP_RPF_ID
        self.trap = True
        self.enable_rpf_check = True
        self.punt_on_rpf_fail = True
        trap_code = sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL

        self.prepare_punt(sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
                          sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                          trap_code, self.MPLS_RPF_ID, trap_code, 0)

        self.do_test_route()

    def test_mldp_ipv4_update_label_termination_db_invalid_label(self):
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.IP_RPF_ID
        self.trap = None
        self.enable_rpf_check = False
        self.punt_on_rpf_fail = False
        self.do_test_route()

        # modify the termination table
        self.INPUT_LABEL_TAIL = sdk.la_mpls_label()
        self.INPUT_LABEL_TAIL.label = 0x70
        self.exception = sdk.la_status_e_E_NOTFOUND
        self.modify_termination_table()

    def test_mldp_ipv4_add_termination_db_invalid_rpfid(self):
        self.rpfid = self.OUT_RANGE_RPF_ID
        self.rpfid1 = self.IP_RPF_ID
        self.trap = None
        self.enable_rpf_check = False
        self.punt_on_rpf_fail = False
        self.exception = sdk.la_status_e_E_INVAL
        self._install_mldp_edge_node()

    def test_mldp_ipv4_update_termination_db_invalid_rpfid(self):
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.IP_RPF_ID
        self.trap = None
        self.enable_rpf_check = False
        self.punt_on_rpf_fail = False
        self.do_test_route()

        # modify the termination table
        self.exception = sdk.la_status_e_E_INVAL
        self.rpfid = self.OUT_RANGE_RPF_ID
        self.modify_termination_table()

    def test_mldp_ipv4_update_label_termination_db_rpf_fail(self):
        self.node_type = node_type_e.MLDP_TAIL_NODE
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.MPLS_RPF_ID
        self.trap = None
        self.enable_rpf_check = True
        self.punt_on_rpf_fail = True
        self.do_test_route()

        # modify the termination table to make rpfid same as in the mcast route
        self.rpfid = self.IP_RPF_ID
        self.modify_termination_table()
        self.trap = True
        trap_code = sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL
        self.retest = True
        self.prepare_punt(sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
                          sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                          trap_code, self.IP_RPF_ID, trap_code, 0)
        self.do_test_route()

    # IPv4 (s,g) hit, rpfid out of range
    def test_mldp_ipv4_rpf_out_of_range(self):
        self.node_type = node_type_e.MLDP_TAIL_NODE
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.OUT_RANGE_RPF_ID
        self.trap = None
        self.pim_all = False
        self.enable_rpf_check = True
        self.punt_on_rpf_fail = False
        try:
            self.do_test_route()
        except sdk.BaseException:
            pass


@unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
class mldp_tail_node_ipv4_l3_ac_test_pim_all(mldp_edge_base):
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    PACKET_SIP = SIP
    MC_GROUP_GID = 0x13
    MC_GROUP_ADDR = T.ipv4_addr('224.0.0.13')
    ipvx = 'v4'
    INPUT_LABEL_TAIL = sdk.la_mpls_label()
    INPUT_LABEL_TAIL.label = 0x65
    node_type = node_type_e.MLDP_TAIL_NODE
    MPLS_RPF_ID = 10000      # must be in range 4K to 32K
    IP_RPF_ID   = 20000      # used for RPF missed test
    OUT_RANGE_RPF_ID = 1000  # out of range rpf id

    def test_mldp_ipv4_pim_all(self):
        self.node_type = node_type_e.MLDP_TAIL_NODE
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.MPLS_RPF_ID
        self.trap = True
        self.pim_all = True
        self.enable_rpf_check = True
        self.punt_on_rpf_fail = True
        trap_code = mc_base.LPTS_PUNT_CODE_V4

        self.prepare_punt(sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
                          sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
                          trap_code, self.MPLS_RPF_ID, nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
                          mc_base.LPTS_FLOW_TYPE_V4)

        self.create_lpts()
        self.do_test_route()


@unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
class mldp_tail_node_ipv4_g_l3_ac_test_v4_g(mldp_edge_base):
    l3_port_impl_class = T.ip_l3_ac_base
    ip_impl_class = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('255.255.255.255')
    DIP = T.ipv4_addr('82.81.95.250')
    PACKET_SIP = T.ipv4_addr('192.168.1.10')
    MC_GROUP_GID = 0x13
    MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')
    ipvx = 'v4'
    INPUT_LABEL_TAIL = sdk.la_mpls_label()
    INPUT_LABEL_TAIL.label = 0x65
    node_type = node_type_e.MLDP_TAIL_NODE
    MPLS_RPF_ID = 10000      # must be in range 4K to 32K
    IP_RPF_ID   = 20000      # used for RPF missed test
    OUT_RANGE_RPF_ID = 1000  # out of range rpf id

    # IPv4, (*,g) hit, no rpf
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    def test_mldp_ipv4_no_rpf_g(self):
        self.node_type = node_type_e.MLDP_TAIL_NODE
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.MPLS_RPF_ID
        self.trap = None
        self.enable_rpf_check = False
        self.punt_on_rpf_fail = False
        self.do_test_route()

    # IPv4, (*,g) hit, rpf pass
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    def test_mldp_ipv4_rpf_pass_g(self):
        self.node_type = node_type_e.MLDP_TAIL_NODE
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.MPLS_RPF_ID
        self.trap = None
        self.enable_rpf_check = True
        self.punt_on_rpf_fail = False
        self.do_test_route()

    # IPv4 (*,g) hit, rpf failed
    def test_mldp_ipv4_rpf_fail_g(self):
        self.node_type = node_type_e.MLDP_TAIL_NODE
        self.rpfid = self.MPLS_RPF_ID
        self.rpfid1 = self.IP_RPF_ID
        self.trap = True
        self.enable_rpf_check = True
        self.punt_on_rpf_fail = True
        trap_code = sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL

        self.prepare_punt(sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
                          sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                          trap_code, self.MPLS_RPF_ID, trap_code, 0)

        self.do_test_route()


if __name__ == '__main__':
    unittest.main()
