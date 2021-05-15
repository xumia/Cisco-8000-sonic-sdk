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

import decor
from leaba import sdk
import unittest
from resource_management.resource_handler_base import *
import decor
import topology as T

AC_PORT_GID_BASE = 0x123
L2_VLAN = 0x456
L3_VLAN = 0x789

RX_L3_AC_MAC = T.mac_addr('31:32:33:34:35:37')


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class ac_ports(resource_handler_base):

    def setUp(self):
        super().setUp()
        self.topology = T.topology(self, self.device)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ac_ports(self):
        eth_port = self.topology.rx_eth_port

        # L2_AC_PORT
        rd_def = sdk.la_resource_descriptor()
        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_L2_SERVICE_PORT
        rd_def.m_index.slice_pair_id = T.RX_SLICE // 2
        l2_ac_init_status = self.device.get_resource_usage(rd_def)

        l2_ac_port = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            self.topology.rx_switch,
            eth_port,
            None,
            L2_VLAN,
            0x0)

        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_L2_SERVICE_PORT
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, l2_ac_init_status.used + 1)

        # L3_AC_PORT
        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_L3_AC_PORT
        if decor.is_asic4():
            rd_def.m_index.slice_id = T.RX_SLICE
        l3_ac_init_status = self.device.get_resource_usage(rd_def)

        l3_ac_port = T.l3_ac_port(self, self.device,
                                  AC_PORT_GID_BASE,
                                  eth_port,
                                  self.topology.vrf,
                                  RX_L3_AC_MAC,
                                  L3_VLAN,
                                  0)

        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_L3_AC_PORT
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, l3_ac_init_status.used + 1)


if __name__ == '__main__':
    unittest.main()
