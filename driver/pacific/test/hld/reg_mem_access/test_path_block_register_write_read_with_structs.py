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

import unittest
from reg_mem_access_base_with_structs import *


class path_block_register_write_read_with_structs(reg_mem_access_base_with_structs):

    def test_path_block_register_write_read(self):
        self.REG = self.pacific_tree.cdb.top.ecc_1b_err_interrupt_register_mask
        self.REG_VALUE = self.debug_device.create_register(self.REG)
        self.REG_VALUE.slb_pipe_psn_table0_ecc_1b_err_interrupt_mask = 1

        self.register_write_read()

    def test_path_block_register_write_read_revision(self):
        self.REG = self.pacific_tree.slice[0].ifg[0].ifgb.rx_port_cgm_cfg[0]
        self.REG_VALUE = self.debug_device.create_register(self.REG)
        self.REG_VALUE.p_tc0_drop_th = 12
        self.REG_VALUE.p_tc1_drop_th = 34

        self.register_write_read()


if __name__ == '__main__':
    unittest.main()
