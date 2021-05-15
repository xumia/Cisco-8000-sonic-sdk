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

import unittest
from leaba import sdk
import lldcli
import time
import argparse
import sys
import re
import base_interrupt

args = None


class stress_test_bits(base_interrupt.base_interrupt_base):

    def setUp(self):
        super().setUp(enable_interrupts=True)

        # Enable all SBIF masks, they are not enabled by SDK, but here we want to stress-test
        for r in self.pt.sbif.get_registers():
            if r.get_desc().type == lldcli.lld_register_type_e_INTERRUPT_MASK:
                self.ldev.write_register(r, (1 << r.get_desc().width_in_bits) - 1)

    def tearDown(self):
        sdk.la_destroy_device(self.device)

    def get_mask_register_from_test_register(self, reg_t):
        if reg_t.get_desc().type != lldcli.lld_register_type_e_INTERRUPT_TEST:
            return None

        if reg_t.get_block().get_block_id() == self.pt.sbif.get_block_id():
            return None

        addr = reg_t.get_desc().addr
        if addr == lldcli.lld_register.MEM_PROTECT_INTERRUPT:
            return None

        addr = addr - reg_t.get_desc().instances

        return reg_t.get_block().get_register(addr)

    def test_case(self):
        # Loop through all interrupt registers
        for b in self.pt.get_leaf_blocks():
            if b.get_block_id() == self.pt.sbif.get_block_id():
                continue
            for r in b.get_registers():
                if r.get_desc().addr == lldcli.lld_register.MEM_PROTECT_INTERRUPT_TEST:
                    continue
                if r.get_desc().type == lldcli.lld_register_type_e_INTERRUPT_TEST:
                    for i in range(r.get_desc().width_in_bits):
                        self.do_test(r, 1 << i)

    def do_test(self, reg_t, val):
        is_sbif = reg_t.get_block().get_block_id() == self.pt.sbif.get_block_id()

        reg_m = self.get_mask_register_from_test_register(reg_t)
        interrupt_expected = 1
        mask = 0
        if reg_m:
            mask = self.ldev.read_register(reg_m)
            if is_sbif:
                interrupt_expected = mask & val
            else:
                interrupt_expected = (~mask) & val

        if interrupt_expected == 1:
            self.ldev.write_register(reg_t, 0)
            self.ldev.write_register(reg_t, val)
            self.ldev.write_register(reg_t, 0)

            crit, norm = self.read_notifications(.1)

            # The error-decision logic is a deliberate oversimplification. Use with care!
            # LINK and MEM_PROTECT interrupts do not trigger a notification just because a test-bit was set.
            ok = "OK" if len(crit) + len(norm) == 1 else "ERROR"
            print('reg_t={}, val={}, crit={}, norm={}: {}'.format(reg_t.get_name(), hex(val), len(crit), len(norm), ok))
        else:
            print('reg_t={}, val={} masked off, mask={}: OK'.format(reg_t.get_name(), hex(val), hex(mask)))


if __name__ == '__main__':
    unittest.main()
