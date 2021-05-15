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


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class small_encap_em_db_usage(resource_handler_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipUnless(decor.is_hw_device(), "Skip for SIM until accurate scale model is enabled")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_small_encap_em_db_usage(self):
        self.topology = T.topology(self, self.device)

        # L2_AC_PORT uses DATABASE_EGRESS_SMALL_EM create 3 ports replicated to all slices.
        self.eth_port1 = self.topology.rx_eth_port
        self.eth_port2 = self.topology.tx_svi_eth_port_reg
        self.eth_port3 = self.topology.tx_svi_eth_port_ext

        num_entries_at_init = [0, 0, 0, 0, 0, 0, 0]

        rd_def = sdk.la_resource_descriptor()
        for slice_id in range(T.NUM_SLICES_PER_DEVICE):
            rd_def.m_index.slice_id = slice_id
            rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_SMALL_ENCAP_EM
            num_entries_at_init[slice_id] = self.device.get_resource_usage(rd_def)

        self.l2_ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            self.topology.rx_switch,
            self.eth_port1,
            None,
            L2_VLAN,
            0x0)

        self.l2_ac_port2 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 1,
            self.topology.filter_group_def,
            self.topology.rx_switch1,
            self.eth_port2,
            None,
            L2_VLAN + 1,
            0x0)

        self.l2_ac_port3 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE + 2,
            None,
            self.topology.tx_switch1,
            self.eth_port3,
            None,
            L2_VLAN + 2,
            0x0)

        for slice_id in range(T.NUM_SLICES_PER_DEVICE):
            rd_def.m_index.slice_id = slice_id
            rd_def.m_resource_type = sdk.la_resource_descriptor.type_e_EGRESS_SMALL_ENCAP_EM
            rd_out = self.device.get_resource_usage(rd_def)
            assert(rd_out.used == (num_entries_at_init[slice_id].used + 1))


if __name__ == '__main__':
    unittest.main()
