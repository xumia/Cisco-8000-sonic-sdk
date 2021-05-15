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

import decor
import sys
import unittest
from leaba import sdk
import topology as T
import decor
import ip_test_base
from sdk_test_case_base import *
from ip_over_ip_tunnel import ip_over_ip_tunnel_base
from resource_management.resource_handler_base import *


@unittest.skipIf(decor.is_hw_device(), "Skip on HW")
class test_tunnel_index_table_usage(resource_handler_base):

    def setUp(self):
        super().setUp()
        self.topology = T.topology(self, self.device)
        self.ip_impl = ip_test_base.ipv4_test_base
        self.tunnel_dest1 = self.ip_impl.build_prefix(T.ipv4_addr('192.168.95.250'), length=16)
        self.tunnel_dest2 = self.ip_impl.build_prefix(T.ipv4_addr('2.8.95.250'), length=16)
        self.tunnel_dest3 = self.ip_impl.build_prefix(T.ipv4_addr('2.2.2.250'), length=16)
        self.REMOTE_IP = T.ipv4_addr('12.10.12.10')
        self.REMOTE_IP_1 = T.ipv4_addr('12.10.22.10')
        self.REMOTE_IP_2 = T.ipv4_addr('12.10.32.10')
        self.SIP = T.ipv4_addr('1.1.1.1')
        self.DIP = T.ipv4_addr('3.3.3.2')
        self.ip_over_ip_tunnel_port = T.ip_over_ip_tunnel_port(self, self.device,
                                                               0x521,
                                                               self.topology.vrf,
                                                               self.tunnel_dest1,
                                                               self.REMOTE_IP,
                                                               self.topology.vrf)
        self.ip_over_ip_tunnel_port_2 = T.ip_over_ip_tunnel_port(self, self.device,
                                                                 0x522,
                                                                 self.topology.vrf,
                                                                 self.tunnel_dest2,
                                                                 self.REMOTE_IP_1,
                                                                 self.topology.vrf)
        self.ip_over_ip_tunnel_port_3 = T.ip_over_ip_tunnel_port(self, self.device,
                                                                 0x524,
                                                                 self.topology.vrf,
                                                                 self.tunnel_dest3,
                                                                 self.REMOTE_IP_2,
                                                                 self.topology.vrf)
        self.gre_encap_port = T.gre_port(self, self.device,
                                         0x533,
                                         sdk.la_ip_tunnel_mode_e_ENCAP_ONLY,
                                         self.topology.vrf,
                                         self.SIP,
                                         self.DIP,
                                         self.topology.vrf)

    @unittest.skipIf(decor.is_hw_device(), "Skip on HW")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    def test_tunnel_index_table_usage(self):
        # check MY_IPV4_TABLE
        rd_def_my_ipv4 = sdk.la_resource_descriptor()
        rd_def_my_ipv4.m_index.slice_id = T.RX_SLICE
        rd_def_my_ipv4.m_resource_type = sdk.la_resource_descriptor.type_e_MY_IPV4_TABLE
        rd_def_my_ipv4_out = self.device.get_resource_usage(rd_def_my_ipv4)
        assert(rd_def_my_ipv4_out.used == 3)

        # check SIP_INDEX_TABLE
        rd_def_sip = sdk.la_resource_descriptor()
        # rd_def_sip.m_index.slice_id = T.RX_SLICE
        rd_def_sip.m_resource_type = sdk.la_resource_descriptor.type_e_SIP_INDEX_TABLE
        rd_def_my_sip_out = self.device.get_resource_usage(rd_def_sip)
        assert(rd_def_my_sip_out.used == rd_def_my_ipv4_out.used + 1)


if __name__ == '__main__':
    unittest.main()
