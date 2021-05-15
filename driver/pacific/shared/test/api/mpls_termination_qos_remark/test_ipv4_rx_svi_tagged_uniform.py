#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from leaba import sdk
import ip_test_base
from scapy.all import *
from mpls_termination_qos_remark_base import *
import sim_utils
import topology as T
import packet_test_utils as U
import decor

U.parse_ip_after_mpls()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv4_rx_svi_tagged_uniform(mpls_termination_qos_remark_base):

    ip_impl_class = ip_test_base.ipv4_test_base
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    ipvx = 'v4'

    l3_port_impl_class = T.ip_svi_base

    input_ether_0_dst = T.RX_SVI_MAC.addr_str
    input_dot1q_0_vlan = T.RX_L2_AC_PORT_VID1
    output_ether_0_dst = T.NH_SVI_REG_MAC.addr_str
    output_ether_0_src = T.TX_SVI_MAC.addr_str

    egress_tagged_mode = True

    qos_inheritance_mode = sdk.la_mpls_qos_inheritance_mode_e_UNIFORM

    def test_single_null(self):
        self._test_single_null()

    def test_single_null_remark_disabled(self):
        self._test_single_null_remark_disabled()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_null_vpn(self):
        self._test_single_null_vpn()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_null_vpn_remark_disabled(self):
        self._test_single_null_vpn_remark_disabled()

    def test_two_nulls_outer_v4(self):
        self._test_two_nulls_outer_v4()

    def test_two_nulls_outer_v4_remark_disabled(self):
        self._test_two_nulls_outer_v4_remark_disabled()


if __name__ == '__main__':
    unittest.main()
