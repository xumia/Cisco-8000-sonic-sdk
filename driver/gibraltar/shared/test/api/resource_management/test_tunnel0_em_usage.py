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
from sdk_test_case_base import *
from ip_over_ip_tunnel.ipv4_l3_ac_ip_over_ip_tunnel_base import *
from resource_management.resource_handler_base import *


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class test_tunnel0_em_usage(ipv4_l3_ac_ip_over_ip_tunnel_base, resource_handler_base):

    def setUp(self):
        self.num_entries_at_init = [0, 0, 0, 0, 0, 0]
        rd_def = sdk.la_resource_descriptor()
        for slice_id in range(T.NUM_SLICES_PER_DEVICE):
            rd_def.m_index.slice_id = slice_id
            rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_TUNNEL_0_EM
            self.num_entries_at_init[slice_id] = self.device.get_resource_usage(rd_def)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipUnless(decor.is_hw_device(), "Skip for SIM until accurate scale model is enabled")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_tunnel0_em_usage(self):
        self.topology = T.topology(self, self.device)
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

        # Create 3 tunnel ports. this will add 3 entries into TUNNEL_0_EM db.
        self.create_ip_over_ip_tunnel_ports()
        rd_def = sdk.la_resource_descriptor()
        for slice_id in range(T.NUM_SLICES_PER_DEVICE):
            rd_def.m_index.slice_id = slice_id
            rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_TUNNEL_0_EM
            rd_out = self.device.get_resource_usage(rd_def)
            assert(rd_out.used == self.num_entries_at_init[slice_id].used + 3)


if __name__ == '__main__':
    unittest.main()
