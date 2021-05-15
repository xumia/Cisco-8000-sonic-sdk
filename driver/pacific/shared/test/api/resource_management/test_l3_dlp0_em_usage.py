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
L3_VLAN = 0x789
RX_L3_AC_MAC = T.mac_addr('31:32:33:34:35:37')


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class l3_dlp0_em_db_usage(resource_handler_base):

    def setUp(self):
        super().setUp()
        self.topology = T.topology(self, self.device)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipUnless(decor.is_hw_device(), "Skip for SIM until accurate scale model is enabled")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l3_dlp0_em_db_usage(self):
        eth_port = self.topology.rx_eth_port

        rd_def = sdk.la_resource_descriptor()

        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_L3_DLP0_EM
        rd_def.m_index.slice_pair_id = T.RX_SLICE // 2
        l3_ac_init_status = self.device.get_resource_usage(rd_def)

        l3_ac_port = T.l3_ac_port(self, self.device,
                                  AC_PORT_GID_BASE,
                                  eth_port,
                                  self.topology.vrf,
                                  RX_L3_AC_MAC,
                                  L3_VLAN,
                                  0)

        rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_L3_DLP0_EM
        rd_def.m_index.slice_pair_id = T.RX_SLICE // 2
        res = self.device.get_resource_usage(rd_def)
        self.assertEqual(res.used, l3_ac_init_status.used + 1)


if __name__ == '__main__':
    unittest.main()
