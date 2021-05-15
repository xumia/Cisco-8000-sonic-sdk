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
import lldcli
import time
import argparse
import sys
import re
import base_interrupt

args = None


class test_discover_interrupt_branch(base_interrupt.base_interrupt_base):

    def setUp(self):
        super().setUp(lld_only=True)

        self.setup_registers(args.reg)
        self.clear_all_interrupts(verbose=args.verbose)
        self.enable_all_interrupts()

        if args.verbose >= 1:
            print('---- after clear: all non-zero interrupt registers w/ extra info ----')
            self.dump_non_zero_interrupt_registers()

    def tearDown(self):
        super().tearDown()

    # Useful when working in interactive Python shell
    def manual_setUp(self, ldev, lbr_tree, reg_name, interrupt_registers):
        self.ldev = ldev
        self.lbr_tree = lbr_tree
        self.interrupt_registers = interrupt_registers

        self.setup_registers(reg_name)
        self.clear_all_interrupts(verbose=args.verbose)
        self.enable_all_interrupts()

    # Extract reg_i|t|m from command line args
    def setup_registers(self, reg_name):
        self.reg_i = eval('self.lbr_tree.' + reg_name)

        assert self.reg_i.is_valid(), "Bad arg: the register is invalid"
        assert self.reg_i.get_desc().type == lldcli.lld_register_type_e_INTERRUPT, "Bad arg: not an interrupt register"
        assert self.reg_i.get_desc().addr != lldcli.lld_register.MASTER_INTERRUPT, "Bad arg: cannot test MASTER interrupt, because it does not have a matching 'test' register"
        assert args.bit_i < self.reg_i.get_desc().width_in_bits, "Bad arg: bit_i is not in range"

        if reg_name.endswith(']'):
            path = re.sub('(\[\d+\]$)', r'_test\1', reg_name)
            self.reg_t = eval('self.lbr_tree.' + path)
        else:
            self.reg_t = eval('self.lbr_tree.' + reg_name + '_test')

        if self.reg_i.get_desc().addr == lldcli.lld_register.MEM_PROTECT_INTERRUPT:
            self.reg_m = None
        else:
            if reg_name.endswith(']'):
                path = re.sub('(\[\d+\]$)', r'_mask\1', reg_name)
                self.reg_m = eval('self.lbr_tree.' + path)
            else:
                self.reg_m = eval('self.lbr_tree.' + reg_name + '_mask')

    def test_discover_interrupt_branch(self):
        self.do_discover_interrupt_branch(args.mask_active_high, verbose=args.verbose)

    def do_discover_interrupt_branch(self, mask_active_high, verbose=0):
        if self.reg_m:
            print('---- reg_t={}, reg_m={}, mask_active_high={}'.format(self.reg_t.get_name(), self.reg_m.get_name(), mask_active_high))
        else:
            print('---- reg_t={}, reg_m=None'.format(self.reg_t.get_name()))

        reg_val0 = self.read_registers(self.interrupt_registers, verbose=verbose)

        bit_name = self.reg_i.get_field(args.bit_i).name
        bit_description = 'reg={}, bit={}, bit_i={}'.format(self.reg_i.get_name(), bit_name, args.bit_i)

        print('Testing leaf bit: {}'.format(bit_description))

        val = self.ldev.read_register(self.reg_i)
        if val & (1 << args.bit_i):
            self.fail('ERROR: leaf bit is pending, unable to clear: val={}, {}.'.format(bin(val), bit_description))
            return 0

        self.ldev.write_register(self.reg_t, 0)
        if self.reg_m:
            mask = 1 << args.bit_i
            if not mask_active_high:
                ones = (1 << self.reg_m.get_desc().width_in_bits) - 1
                mask = ones & (~mask)
            self.ldev.write_register(self.reg_m, mask)
        self.ldev.write_register(self.reg_t, 1)
        self.ldev.write_register(self.reg_t, 0)

        time.sleep(.1)

        val = self.ldev.read_register(self.reg_i)
        if (val & (1 << args.bit_i)) == 0:
            self.fail('ERROR: leaf bit did not trigger: val={}, {}.'.format(hex(val), bit_description))
            return 0

        reg_val1 = self.read_registers(self.interrupt_registers, verbose=verbose)

        if verbose >= 1:
            print('---- after test: all non-zero interrupt registers w/ extra info ----')
            self.dump_non_zero_interrupt_registers()

        print('---- "diff" before VS after ----')
        self.diff_registers(reg_val0, reg_val1)

        # clean up
        self.clear_all_interrupts(verbose=False)

    def dump_non_zero_interrupt_registers(self):
        reg_val = self.read_registers(self.interrupt_registers)
        for rv in reg_val:
            reg, val = rv['reg'], rv['val']
            if val == 0:
                continue
            line = 'reg={}, val={}'.format(reg.get_name(), hex(val))
            # Dig for extra info
            block = eval('self.lbr_tree.' + self.lbr_tree.get_block(reg.get_block_id()).get_name())
            if reg.get_desc().addr == lldcli.lld_register.MASTER_INTERRUPT:
                pass
            elif reg.get_desc().addr == lldcli.lld_register.MEM_PROTECT_INTERRUPT:
                mem_protect_err_status = self.ldev.read_register(block.mem_protect_err_status)
                line += ', mem_protect_err_status={}'.format(hex(mem_protect_err_status))
            elif block.get_block_id() < self.lbr_tree.sbif.get_block_id():
                # CIF interrupt registers other than MASTER and MEM_PROTECT must have a matching mask register at addr+instances
                reg_mask = block.get_register(reg.get_desc().addr + reg.get_desc().instances)
                assert reg_mask.get_desc().type == lldcli.lld_register_type_e_INTERRUPT_MASK, reg.get_name()
                mask = self.ldev.read_register(reg_mask)
                line += ', mask={}'.format(hex(mask))
            print(line)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='discover_interrupt_branch test.')
    parser.add_argument('--reg', required=True, help='LBR path to a non-MASTER interrupt register')
    parser.add_argument('--bit_i', default=0, type=int, help='Index of interrupt bit')
    parser.add_argument('--mask_active_high', action='store_true', help='Interrupt mask is active high')
    parser.add_argument('--verbose', default=0, type=int, help='Verbosity level: 0 - minimal prints, 1 - more prints, ...')
    parser.add_argument('unittest_args', nargs='*')
    args = parser.parse_args()

    # Now set the sys.argv to the unittest_args (leaving sys.argv[0] alone)
    sys.argv[1:] = args.unittest_args
    unittest.main()
