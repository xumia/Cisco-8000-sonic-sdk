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
import os
import select
import base_interrupt
import argparse
import sys

args = None


class test_mem_protect_interrupt(base_interrupt.base_interrupt_base):

    def setUp(self):
        super().setUp()

        if args.debug:
            sdk.la_set_logging_level(self.device_id, sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(288, sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)

        # Open file descriptors for monitoring MEM_PROTECT notifications
        self.fd_critical, self.fd_mem_protect = self.device.open_notification_fds(1 << sdk.la_notification_type_e_MEM_PROTECT)
        print('mem_protect notification fd={}'.format(self.fd_mem_protect))

    def tearDown(self):
        self.device.close_notification_fds()
        super().tearDown()

    def test_mem_protect(self):
        mem = eval('self.pt.' + args.mem)
        mem_entry_first = int(args.first_entry)
        count = int(args.count)
        bad_bits = int(args.bad_bits)
        block = eval('self.pt.' + mem.get_block().get_name())

        # Memory must be CPU-accessible
        self.assertTrue(mem.get_desc().readable and mem.get_desc().writable)

        # Deduce err counter register from memory and bad_bits
        if mem.get_desc().protection == lldcli.lld_memory_protection_e_ECC:
            if bad_bits == 1:
                err_counter_reg = block.ecc_1b_err_debug
            elif bad_bits >= 2:
                err_counter_reg = block.ecc_2b_err_debug
        elif mem.get_desc().protection == lldcli.lld_memory_protection_e_PARITY:
            err_counter_reg = block.parity_err_debug

        self.assertTrue(err_counter_reg is not None)

        regs = [
            block.interrupt_register,
            block.mem_protect_interrupt,
            block.mem_protect_err_status,
            err_counter_reg
        ]

        print('dump regs - before test')
        self.dump_registers(regs)

        # Generate 5 mem_protect errors
        for i in range(count):
            read_values = self.generate_mem_protect_error_using_bypass(block, mem, mem_entry_first + i, bad_bits)

            val_initial = read_values['initial']
            val_read_1 = read_values['read_1']
            val_read_2 = read_values['read_2']
            if mem.get_desc().protection == lldcli.lld_memory_protection_e_ECC and bad_bits == 1 and not (
                    val_initial == val_read_1 and val_initial == val_read_2):
                print('ERROR: ECC-1b should be auto-corrected,',
                      'val initial={}, read_1={}, read_2={}'.format(val_initial, val_read_1, val_read_2))
                self.assertEqual(val_initial, val_read_1)
                self.assertEqual(val_initial, val_read_2)

        # Test peek_register VS read_register
        val1 = self.ldev.peek_register(err_counter_reg)
        val2 = self.ldev.peek_register(err_counter_reg)
        val3 = self.ldev.read_register(err_counter_reg)
        val4 = self.ldev.read_register(err_counter_reg)

        self.assertTrue((val1 == val2) and (val1 == count))
        self.assertTrue(val3 == val1)
        self.assertTrue(val4 == 0)

        print('dump regs - after test')
        self.dump_registers(regs)

        # Read all notifications
        desc_list = self.read_notifications(self.fd_mem_protect, .1)
        self.assertTrue(len(desc_list) == count)

        for desc in desc_list:
            self.assertEqual(desc.type, sdk.la_notification_type_e_MEM_PROTECT)
            block_name = self.pt.get_block(desc.block_id).get_name()
            print('%d: la_notification_desc={id=%d, type=%d, block=%s, u.mem_protect={' % (i, desc.id, desc.type, block_name),
                  'error=%d,' % desc.u.mem_protect.error,
                  'instance_addr=0x%x,' % desc.u.mem_protect.instance_addr,
                  'entry=0x%x' % desc.u.mem_protect.entry,
                  '}},')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='mem_protect interrupt test.')
    parser.add_argument('--mem', default='npuh.host.ene_macro_memory', help='LBR path to memory-under-test')
    parser.add_argument('--first_entry', default=0, help='First memory entry to be tested')
    parser.add_argument('--count', default=5, help='Test at most this amount of entries starting from first_entry')
    parser.add_argument('--bad_bits', default=2, help='Inject this amount of corrupted bits info memory entry')
    parser.add_argument('--debug', default=False, action='store_true',
                        help='Inject this amount of corrupted bits info memory entry')
    parser.add_argument('unittest_args', nargs='*')
    args = parser.parse_args()

    # Now set the sys.argv to the unittest_args (leaving sys.argv[0] alone)
    sys.argv[1:] = args.unittest_args
    unittest.main()
