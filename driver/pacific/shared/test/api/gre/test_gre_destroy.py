#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import packet_test_utils as U
import scapy.all as S
import decor
import topology as T
import packet_test_defs as P
import ip_test_base
from sdk_test_case_base import *
import mtu.mtu_test_utils as MTU
from sdk_test_case_base import *
from gre_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class test_gre_destroy(sdk_test_case_base):

    GRE_PORT_GID = 0x901
    GRE_SIP = T.ipv4_addr('12.10.12.11')
    GRE_DIP = T.ipv4_addr('12.1.95.250')

    def setUp(self):
        super().setUp()

    def tearDown(self):
        self.device.destroy(self.gre_tunnel)
        super().tearDown()

    def gre_port_create_tunnel(self, mode=sdk.la_ip_tunnel_mode_e_ENCAP_DECAP):
        self.gre_tunnel = self.device.create_gre_port(
            self.GRE_PORT_GID,
            self.topology.vrf.hld_obj,
            self.GRE_SIP.hld_obj,
            self.GRE_DIP.hld_obj,
            self.topology.vrf2.hld_obj,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_destroy_tunnel(self):
        # setUp is called once before the loop and tearDown after the loop
        for i in range(17):
            if (i > 0):
                self.setUp()
            self.gre_port_create_tunnel()
            if (i < 16):
                self.tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_destroy_tunnel_encap_only(self):
        for i in range(17):
            if (i > 0):
                self.setUp()
            self.gre_port_create_tunnel(sdk.la_ip_tunnel_mode_e_ENCAP_ONLY)
            if (i < 16):
                self.tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_gre_destroy_tunnel_decap_only(self):
        for i in range(17):
            if (i > 0):
                self.setUp()
            self.gre_port_create_tunnel(sdk.la_ip_tunnel_mode_e_DECAP_ONLY)
            if (i < 16):
                self.tearDown()


if __name__ == '__main__':
    unittest.main()
