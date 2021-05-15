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

mem_protect_wait_seconds_after_error_trigger = 0.01


class base_interrupt_base(unittest.TestCase):

    def setUp(self, enable_interrupts=True, lld_only=False):
        #sdk.la_set_logging_level(288, sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)
        #sdk.la_set_logging_level(0, sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)

        self.device_id = 0
        self.device_name = '/dev/uio0'
        if lld_only:
            self.device = None
            self.ldev = lldcli.ll_device_create(0, self.device_name)
            self.ldev.reset()
            self.ldev.reset_access_engines()
        else:
            self.device = sdk.la_create_device(self.device_name, self.device_id)
            self.device.initialize(sdk.la_device.init_phase_e_DEVICE)
            for sid in range(6):
                self.device.set_slice_mode(sid, sdk.la_slice_mode_e_NETWORK)
            self.device.set_bool_property(sdk.la_device_property_e_PROCESS_INTERRUPTS, enable_interrupts)
            self.device.initialize(sdk.la_device.init_phase_e_TOPOLOGY)
            self.ldev = self.device.get_ll_device()

        if self.ldev.is_gibraltar():
            self.lbr_tree = self.ldev.get_gibraltar_tree()
        elif self.ldev.is_asic3():
            self.lbr_tree = self.ldev.get_asic3_tree()
        else:
            self.lbr_tree = self.ldev.get_pacific_tree()

        # Buld a list of all interrupt registers
        self.interrupt_registers = [r for b in self.lbr_tree.get_leaf_blocks()
                                    for r in b.get_registers() if r.get_desc().type == lldcli.lld_register_type_e_INTERRUPT]

        if not lld_only and enable_interrupts:
            self.critical_fd, self.normal_fd = self.device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)

    def tearDown(self):
        if self.device:
            sdk.la_destroy_device(self.device)
        self.device = None
        self.ldev = None

    def dump_registers(self, regs):
        for reg in regs:
            val = self.ldev.read_register(reg)
            print('{}: {}'.format(reg.get_name(), hex(val)))

    def read_registers(self, regs, verbose=0):
        reg_val = []
        for r in regs:
            val = self.ldev.read_register(r)
            reg_val.append({'reg': r, 'val': val})
            if verbose >= 2:
                print('read_register:', r.get_name(), hex(val))
        return reg_val

    def enable_all_interrupts(self):
        mask_registers = [r for b in self.lbr_tree.get_leaf_blocks()
                          for r in b.get_registers() if r.get_desc().type == lldcli.lld_register_type_e_INTERRUPT_MASK]
        for reg in mask_registers:
            # On Pacific, sbif masks are active low, all other masks are active high
            # On Gibraltar and later, all masks are active high
            if 'sbif' in reg.get_name() and self.ldev.is_pacific():
                self.ldev.write_register(reg, (1 << reg.get_desc().width_in_bits) - 1)
            else:
                self.ldev.write_register(reg, 0)

    def clear_all_interrupts(self, verbose=0):
        reg_val0 = self.read_registers(self.interrupt_registers)
        nzero = sum([rv['val'] != 0 for rv in reg_val0])
        print('Before clear: non-zero interrupt registers', nzero)

        # Clear all interrupt registers - brute force, without any hierarchy. Do multiple rounds.
        for i in range(5):
            for r in self.interrupt_registers:
                if r.get_desc().addr != lldcli.lld_register.MASTER_INTERRUPT:
                    self.ldev.write_register(r, (1 << r.get_desc().width_in_bits) - 1)

        reg_val1 = self.read_registers(self.interrupt_registers)
        nzero = sum([rv['val'] != 0 for rv in reg_val1])
        print('After clear: non-zero interrupt registers', nzero)
        if verbose >= 1:
            print('"diff" before VS after clearing all interrupt registers')
            self.diff_registers(reg_val0, reg_val1)

    def diff_registers(self, reg_val0, reg_val1):
        assert len(reg_val0) == len(reg_val1)
        diff_count = 0
        for i in range(len(reg_val0)):
            reg = reg_val0[i]['reg']
            val0 = reg_val0[i]['val']
            val1 = reg_val1[i]['val']
            if val0 != val1:
                print('{}: val0={}, val1={}'.format(reg.get_name(), hex(val0), hex(val1)))
                diff_count += 1
        print('diff_count', diff_count)

    def read_notifications(self, timeout_seconds):
        po = select.poll()  # create a poll object
        for fd in [self.critical_fd, self.normal_fd]:
            po.register(fd, select.POLLIN)  # register a file descriptor for future poll() calls
            os.set_blocking(fd, False)  # prepare for non-blocking read

        # Poll timeout is in miliseconds
        res = po.poll(timeout_seconds * 1000)
        if len(res) == 0:
            print("\npoll() timed out - no notification descriptor available")
            return [], []

        desc_critical = self.read_notifications_fd(self.critical_fd)
        desc_normal = self.read_notifications_fd(self.normal_fd)

        return desc_critical, desc_normal

    def read_notifications_fd(self, fd):
        desc_list = []
        sizeof = sdk.la_notification_desc.__sizeof__()
        while True:
            # A non-blocking read throws BlockingIOError when nothing is left to read
            try:
                buf = os.read(fd, sizeof)
            except BlockingIOError:
                break
            desc = sdk.la_notification_desc(bytearray(buf))
            desc_list.append(desc)

        return desc_list

    def generate_mem_protect_error_using_bypass(self, block, mem, mem_entry, bad_bits, verbose=0):
        ldev = self.ldev
        block_id = mem.get_block_id()
        addr = mem.get_desc().addr + mem_entry
        width_total_bits = mem.get_desc().width_total_bits

        # For CONFIG memories, reads are terminated in shadow and do not reach the HW.
        # For DYNAMIC memories, reads bypass the shadow and go directly to HW.
        #
        # Since mem_protect error is generated on HW read, we use read_memory_raw() to reach the HW both
        # for CONFIG and DYNAMIC memories

        # Read the initial value with ECC/Parity
        val_initial = ldev.read_memory_raw(block_id, addr, width_total_bits)
        if verbose >= 1:
            print('generate_mem_protect_error_using_bypass: val_initial=%x' % val_initial)

        # Write a value with known good ECC/Parity and a payload with deliberately corrupted 'bad_bits' bits
        # Set/clear CifProtGenBypass bit to disable/enable HW ECC/Parity generation - ECC/Parity and payload are written by host
        ldev.write_register(block.memory_prot_bypass, 0x2)
        ldev.write_memory_raw(block_id, addr, width_total_bits, val_initial ^ ((1 << bad_bits) - 1))
        ldev.write_register(block.memory_prot_bypass, 0x0)

        if verbose >= 1:
            print('generate_mem_protect_error_using_bypass: val_corrupted=%x' % (val_initial ^ ((1 << bad_bits) - 1)))

        # The 1st read_memory_raw should generate a mem_protect error, which is expected to be fixed by SDK if the memory is CONFIG
        # The 2nd read_memory_raw should only generate a mem_protect error for non-CONFIG memory

        val_read_1 = None
        val_read_2 = None
        err_1 = sdk.la_status_e_SUCCESS
        err_2 = sdk.la_status_e_SUCCESS

        try:
            val_read_1 = ldev.read_memory_raw(block_id, addr, width_total_bits)
        except sdk.BaseException as e:
            err_1 = int(str(e))
        time.sleep(mem_protect_wait_seconds_after_error_trigger)

        try:
            val_read_2 = ldev.read_memory_raw(block_id, addr, width_total_bits)
        except sdk.BaseException as e:
            err_2 = int(str(e))

        time.sleep(mem_protect_wait_seconds_after_error_trigger)

        return {'initial': val_initial, 'err_1': err_1, 'read_1': val_read_1, 'err_2': err_2, 'read_2': val_read_2}
