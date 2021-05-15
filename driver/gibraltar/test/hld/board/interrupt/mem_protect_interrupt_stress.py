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

ECC = lldcli.lld_memory_protection_e_ECC
EXT_ECC = lldcli.lld_memory_protection_e_EXT_ECC
PARITY = lldcli.lld_memory_protection_e_PARITY
EXT_PARITY = lldcli.lld_memory_protection_e_EXT_PARITY


def memory_index_in_ser_mask(block, mem):
    md = mem.get_desc()

    # Enumerate all ECC or PARITY protected memories in this block
    if md.protection in [ECC, EXT_ECC]:
        protected_memories = [m.get_desc().addr for m in block.get_memories() if m.get_desc().protection in [ECC, EXT_ECC]]
    elif md.protection in [PARITY, EXT_PARITY]:
        protected_memories = [m.get_desc().addr for m in block.get_memories() if m.get_desc().protection in [PARITY, EXT_PARITY]]

    # Index of this particular memory in the list corresponds to a bit in ECC or PARITY mask
    memory_index = protected_memories.index(md.addr)
    return memory_index


class test_mem_protect_interrupt(base_interrupt.base_interrupt_base):

    def setUp(self):
        super().setUp(enable_interrupts=True)
        # All interrupts that are modeled in pacific_interrupt_tree.py are enabled
        # in initialize(TOPOLOGY).

        dev_id = self.device.get_id()
        if args.verbose == 0:
            # This test deliberately generates access engine errors by injecting 2b ECC errors
            # Reduce noise by not logging errors for AE and ACCESS.
            # The errors are checked as return codes in the test itself.
            sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_AE, sdk.la_logger_level_e_CRIT)
            sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_ACCESS, sdk.la_logger_level_e_CRIT)
        if args.verbose >= 2:
            sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)

        # Reset all pending SER errors, mask off SERs that remain dirty after reset.
        # At the end, no SER interrupts should be pending.
        self.ser_reset_all()

        # Clear all interrupt registers including the not yet modeled in pacific_interrupt_tree.py
        self.clear_all_interrupts(verbose=args.verbose)

    def tearDown(self):
        super().tearDown()

    def ser_reset_all(self):
        count_total = 0
        count_dirty_before = 0
        blocks_dirty_after = []
        for b in self.pt.get_leaf_blocks():
            if b.get_block_id() != self.pt.sbif.get_block_id():
                if b.get_register(lldcli.lld_register.MEM_PROTECT_ERR_STATUS):
                    dirty_before, dirty_after = self.ser_reset(b)
                    count_total += 1
                    count_dirty_before += dirty_before
                    if dirty_after:
                        blocks_dirty_after.append(b)

        print('Total blocks with SER:', count_total)
        print('Dirty blocks with SER: before={}, after={}'.format(count_dirty_before, len(blocks_dirty_after)))

        # Disable masks for memories that we cannot clear right now.
        # As a result, all SER interrupts should be cleared.
        for b in blocks_dirty_after:
            self.ser_disable(b)
            dirty_before, dirty_after = self.ser_reset(b)
            assert dirty_after == False

    def ser_disable(self, block):
        reg_mask_ecc_1b = block.get_register(lldcli.lld_register.ECC_1B_ERR_INTERRUPT_MASK)
        reg_mask_ecc_2b = block.get_register(lldcli.lld_register.ECC_2B_ERR_INTERRUPT_MASK)
        if reg_mask_ecc_1b:
            all_ones = (1 << reg_mask_ecc_1b.get_desc().width_in_bits) - 1
            self.ldev.write_register(reg_mask_ecc_1b, all_ones)
            self.ldev.write_register(reg_mask_ecc_2b, all_ones)

        reg_mask_parity = block.get_register(lldcli.lld_register.PARITY_ERR_INTERRUPT_MASK)
        if reg_mask_parity:
            all_ones = (1 << reg_mask_parity.get_desc().width_in_bits) - 1
            self.ldev.write_register(reg_mask_parity, all_ones)

    def ser_reset(self, block):
        # Grab some SER registers
        reg_mem_protect_err_status = block.get_register(lldcli.lld_register.MEM_PROTECT_ERR_STATUS)
        reg_ser_error_debug_configuration = block.get_register(lldcli.lld_register.SER_ERROR_DEBUG_CONFIGURATION)
        reg_mask_ecc_1b = block.get_register(lldcli.lld_register.ECC_1B_ERR_INTERRUPT_MASK)
        reg_mask_ecc_2b = block.get_register(lldcli.lld_register.ECC_2B_ERR_INTERRUPT_MASK)
        reg_mask_parity = block.get_register(lldcli.lld_register.PARITY_ERR_INTERRUPT_MASK)

        val = self.ldev.read_register(reg_mem_protect_err_status)
        if val == 0:
            return False, False

        dirty_before = True

        # save and disable SER masks
        if reg_mask_ecc_1b:
            mask_ecc_1b = self.ldev.read_register(reg_mask_ecc_1b)
            mask_ecc_2b = self.ldev.read_register(reg_mask_ecc_2b)
            self.ldev.write_register(reg_mask_ecc_1b, (1 << reg_mask_ecc_1b.get_desc().width_in_bits) - 1)  # all-ones
            self.ldev.write_register(reg_mask_ecc_2b, (1 << reg_mask_ecc_2b.get_desc().width_in_bits) - 1)  # all-ones
        if reg_mask_parity:
            mask_parity = self.ldev.read_register(reg_mask_parity)
            self.ldev.write_register(reg_mask_parity, (1 << reg_mask_parity.get_desc().width_in_bits) - 1)  # all-ones

        # Reset error state by toggling 0-1-0
        reset_val = 1 << (reg_ser_error_debug_configuration.get_desc().width_in_bits - 1)   # reset bit is MSB
        self.ldev.write_register(reg_ser_error_debug_configuration, 0)
        self.ldev.write_register(reg_ser_error_debug_configuration, reset_val)
        self.ldev.write_register(reg_ser_error_debug_configuration, 0)

        # Restore SER masks
        if reg_mask_ecc_1b:
            self.ldev.write_register(reg_mask_ecc_1b, mask_ecc_1b)
            self.ldev.write_register(reg_mask_ecc_2b, mask_ecc_2b)
        if reg_mask_parity:
            self.ldev.write_register(reg_mask_parity, mask_parity)

        # Read SER status again
        val_after = self.ldev.read_register(reg_mem_protect_err_status)
        has_ser_errors = "no" if val_after == 0 else "has"
        if args.verbose >= 1:
            print('{}: {} SER errors after reset, mem_protect_err_status before={}, after={}'.format(
                block.get_name(), has_ser_errors, hex(val), hex(val_after)))

        return True, val_after != 0

    def test_mem_protect(self):
        err = 0

        if args.mem is not 'ALL':
            # Command line override - test one specific memory; compare interrupt registers before and after.
            mem = eval('self.pt.' + args.mem)

            reg_val0 = self.read_registers(self.interrupt_registers)
            err = self.do_test_mem_protect(mem)
            reg_val1 = self.read_registers(self.interrupt_registers)

            print('---- "diff" before VS after test')
            self.diff_registers(reg_val0, reg_val1)
            self.dump_registers([
                self.pt.sbif.msi_master_interrupt_reg,
                self.pt.sbif.msi_master_interrupt_reg_mask,
                self.pt.sbif.msi_blocks_interrupt_summary_reg0,
                self.pt.sbif.msi_blocks_interrupt_summary_reg0_mask,
                self.pt.sbif.msi_blocks_interrupt_summary_reg1,
                self.pt.sbif.msi_blocks_interrupt_summary_reg1_mask])
        else:
            # No command line override - iterate through all memory instances.
            blocks = [b for b in self.pt.get_leaf_blocks() if b.get_block_id() != self.pt.sbif.get_block_id()]
            for block in blocks:
                for mem in block.get_memories():
                    err += self.do_test_mem_protect(mem)
        print('--------\nDone, total errors={}'.format(err))

    def do_test_mem_protect(self, mem):
        md = mem.get_desc()

        # For now, don't test volatile memories as part of stress test.
        # Injecting errors into volatile memories may cause chaos.
        #
        # And, memory must be CPU readable and writable.
        if md.is_volatile() or not md.readable or not md.writable or md.subtype is lldcli.lld_memory_subtype_e_X_Y_TCAM:
            if args.verbose:
                print('{} is not testable, volatile={}, readable={}, writable={}'.format(
                    mem.get_name(), md.is_volatile(), md.readable, md.writable))
            return 0
        if args.protection == 'ECC' and md.protection != ECC:
            return 0
        if args.protection == 'PARITY' and md.protection != PARITY:
            return 0

        block = eval('self.pt.' + mem.get_block().get_name())
        test_name = 'template={}, instance={}, volatile={}'.format(md.name, mem.get_name(), md.is_volatile())

        mask_error = None
        if md.protection == ECC:
            test_name += ', protection=ECC'
            if int(args.bad_bits) < 1:  # default
                mask_ecc_1b = self.ldev.read_register(block.ecc_1b_err_interrupt_register_mask)
                mask_ecc_2b = self.ldev.read_register(block.ecc_2b_err_interrupt_register_mask)
                bad_bits = (1, 2)
            elif int(args.bad_bits) == 1:  # command line override
                mask_ecc_1b = self.ldev.read_register(block.ecc_1b_err_interrupt_register_mask)
                mask_ecc_2b = 0
                bad_bits = (1,)
            else:  # command line override
                mask_ecc_1b = 0
                mask_ecc_2b = self.ldev.read_register(block.ecc_1b_err_interrupt_register_mask)
                bad_bits = (2,)

            # If masks are non-zero, check if the memory under-test is masked off
            if mask_ecc_1b != 0 or mask_ecc_2b != 0:
                memory_index = memory_index_in_ser_mask(block, mem)
                if (mask_ecc_1b | mask_ecc_2b) & (1 << memory_index):
                    mask_error = 'ECC mask is disabled: ecc1b=%x, ecc2b=%x' % (mask_ecc_1b, mask_ecc_2b)
        elif md.protection == PARITY:
            test_name += ', protection=PARITY'
            bad_bits = (1,)
            mask_parity = self.ldev.read_register(block.parity_err_interrupt_register_mask)
            # If the mask is non-zero, check if the memory under-test is masked off
            if mask_parity != 0:
                memory_index = memory_index_in_ser_mask(block, mem)
                if mask_parity & (1 << memory_index):
                    mask_error = 'Parity mask is disabled: mask=%x' % mask_parity
        else:
            return 0

        print('[START]:', test_name)

        val = self.ldev.read_register(block.mem_protect_err_status)
        if val != 0:
            print('[SER-DIRTY]:', test_name, '{}={}'.format(block.mem_protect_err_status.get_name(), hex(val)))

        if mask_error:
            print('[ERROR-mask]', test_name, mask_error)
            err = 1
        else:
            # Test up to args.count memory entries
            mem_entry_first = int(args.first_entry)
            mem_entries_count = min(md.entries, int(args.count))
            err = 0
            for bits in bad_bits:
                for i in range(mem_entries_count):
                    err += self.do_test_mem_entry(test_name, block, mem, mem_entry_first + i, bits)

        if err:
            print('[ERROR]:', test_name, 'errors={}'.format(err))
        else:
            print('[OK]:', test_name)

        return err

    def do_test_mem_entry(self, test_name, block, mem, mem_entry, bad_bits):
        read_results = self.generate_mem_protect_error_using_bypass(block, mem, mem_entry, bad_bits)

        val_initial = read_results['initial']
        val_read_1 = read_results['read_1']
        val_read_2 = read_results['read_2']
        err_read_1 = (read_results['err_1'] != sdk.la_status_e_SUCCESS)
        err_read_2 = (read_results['err_2'] != sdk.la_status_e_SUCCESS)

        # Read all notifications
        desc_critical, desc_normal = self.read_notifications(.1)
        desc_list = desc_critical + desc_normal

        for i, desc in enumerate(desc_list):
            self.assertEqual(desc.type, sdk.la_notification_type_e_MEM_PROTECT)
            block_name = self.pt.get_block(desc.block_id).get_name()
            print(
                '%d: la_notification_desc={id=%d, type=%d, action=%d, block=%s, u.mem_protect={' %
                (i, desc.id, desc.type, desc.requested_action, block_name), 'error=%d,' %
                desc.u.mem_protect.error, 'instance_addr=0x%x,' %
                desc.u.mem_protect.instance_addr, 'entry=0x%x' %
                desc.u.mem_protect.entry, '}},')

        err_str = None
        err = 0

        # ECC-1b: 1st and 2nd read should return good values because HW auto-corrects (and no AE error).
        if mem.get_desc().protection == ECC and bad_bits == 1:
            if err_read_1 or err_read_2:
                err_str = '[ERROR-ae]:', test_name, 'ECC-1b should not generate AE error'
                err += 1
            elif val_initial != val_read_1 or val_initial != val_read_2:
                # If this is a CONFIG memory, one possible reason for value error is
                # that the memory was never written to and the shadow and HW are out of sync.
                err_str = '[ERROR-auto-correct]:', test_name, 'ECC-1b was not auto corrected'
                err += 1

        # ECC-2b and Parity
        #   - DYNAMIC memory
        #       1st and 2nd read fail, HW does not auto-correct (hence AE error) and SDK does not refresh.
        #   - CONFIG memory
        #       1st read fails, HW does not auto-correct (hence AE error).
        #       2nd read is ok, because SDK refreshes HW memory after 1st read
        elif mem.get_desc().protection == PARITY or (mem.get_desc().protection == ECC and bad_bits == 2):
            if mem.get_desc().is_volatile():
                if not (err_read_1 and err_read_2):
                    err_str = '[ERROR-volatile-read]: ' + test_name + ' read_1 and read_2 are expected to fail'
            else:
                if not err_read_1:
                    err_str = '[ERROR-config-read]: ' + test_name + ' read_1 is expected to fail'
                if err_read_2 or val_initial != val_read_2:
                    err_str = '[ERROR-config-read]: ' + test_name + ' read_2 is expected to succeed'
        else:
            assert 0, 'unreachable'

        if err_str:
            print(err_str, ', entry={}, val initial={}, read_1={}, read_2={}, err_1={}, err_2={}'.format(
                mem_entry, val_initial, val_read_1, val_read_2, err_read_1, err_read_2))
            err += 1

        # Notifications count
        #   - DYNAMIC memory: 2 notifications per 1 injected error (both 1st and 2nd reads generate interrupts)
        #   - CONFIG memory: 1 notification per 1 injected error (1st read generates an interrupt, 2nd read is clean because of SDK refresh)
        if mem.get_desc().is_volatile():
            if len(desc_list) != 2:
                print('[ERROR-volatile-notify]:', test_name,
                      'entry={}, err count expected=2, actual={}'.format(mem_entry, len(desc_list)))
                err += 1
        else:
            if len(desc_list) == 1:
                pass  # OK
            elif len(desc_list) == 0:
                print('[ERROR-config-no-notification]:', test_name, 'entry={}, no interrupt'.format(mem_entry))
                err += 1
            else:
                print('[ERROR-config-too-many-notifications]:', test_name,
                      'entry={}, err count expected=1, actual={}'.format(mem_entry, len(desc_list)))
                err += 1

        return err


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='mem_protect interrupt stress test.')
    parser.add_argument('--mem', default='ALL', help='LBR path to memory-under-test or \'ALL\' to test all memories')
    parser.add_argument('--first_entry', default=0, help='First memory entry to be tested')
    parser.add_argument('--count', default=1, help='Test at most this amount of entries starting from first_entry')
    parser.add_argument('--bad_bits', default=-1, help='Inject this amount of corrupted bits info memory entry')
    parser.add_argument(
        '--protection',
        default='ALL',
        help='If set to ECC or PARITY - test only, well, ECC or PARITY. Otherwise, test both.')
    parser.add_argument('--verbose', default=0, type=int, help='Verbosity level, 0 - minimal prints, 1 - more prints, ...')
    parser.add_argument('unittest_args', nargs='*')
    args = parser.parse_args()

    if args.mem is not 'ALL':
        pt = lldcli.pacific_tree(sdk.la_device_revision_e_PACIFIC_A0)
        mem = eval('pt.' + args.mem)
        assert mem.is_valid(), "Bad arg: mem is not valid"

    # Now set the sys.argv to the unittest_args (leaving sys.argv[0] alone)
    sys.argv[1:] = args.unittest_args
    unittest.main()
