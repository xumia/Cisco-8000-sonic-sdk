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
import sim_utils
import decor
import interrupt_utils
import lldcli
import time

verbose = 0


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
class testcase(unittest.TestCase):

    def setUp(self):
        device_id = 0
        self.device = sim_utils.create_device(device_id)
        self.critical_fd, self.normal_fd = self.device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)
        self.ldev = self.device.get_ll_device()
        if self.ldev.is_gibraltar():
            self.device_tree = self.ldev.get_gibraltar_tree()
        elif self.ldev.is_asic4():
            self.device_tree = self.ldev.get_asic4_tree()
        elif self.ldev.is_asic5():
            self.device_tree = self.ldev.get_asic5_tree()
        else:
            self.device_tree = self.ldev.get_pacific_tree()
        # Never auto-restore masks
        self.device.set_int_property(sdk.la_device_property_e_RESTORE_INTERRUPT_MASKS_INTERVAL_MILLISECONDS, int(1e9))

        # Drain any post-init notifications
        # Sleep long enough so that non-wired interrupts will have a chance to be polled.
        time.sleep(1.5)
        crit, norm = interrupt_utils.read_notifications(self.critical_fd, self.normal_fd, .1)
        if len(crit) + len(norm) > 0:
            print('ERROR: got unexpected interrupts after initialize(TOPOLOGY)')
            interrupt_utils.dump_notifications(self.device_tree, crit, norm)
        self.assertEqual(len(crit) + len(norm), 0)

        if verbose >= 1:
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)

    def tearDown(self):
        if verbose >= 1:
            sdk.la_set_logging_level(self.device.get_id(), sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)

        self.device.close_notification_fds()
        self.device.tearDown()

    @unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_enable_disable_bad_params(self):
        # Not an interrupt register
        reg = self.device_tree.sms_quad[3].sms2_cif_overflow_reg_test
        bit_i = 0
        self.do_test_bad_params(reg, bit_i, sdk.la_status_e_E_INVAL)

        # Bit out of range
        reg = self.device_tree.sms_quad[3].sms2_cif_overflow_reg
        bit_i = reg.get_desc().width_in_bits
        self.do_test_bad_params(reg, bit_i, sdk.la_status_e_E_OUTOFRANGE)

        # Register in invalid block
        reg = self.device_tree.slice[0].ifg[0].fabric_sch.general_interrupt_register_test
        bit_i = 0
        self.do_test_bad_params(reg, bit_i, sdk.la_status_e_E_INVAL)

    def do_test_bad_params(self, reg, bit_i, la_status_e):
        try:
            self.device.get_interrupt_enabled(reg, bit_i)
            self.assertEqual(False, True)
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], la_status_e)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_enable_disable_wired_bit(self):
        reg = self.device_tree.sms_quad[3].sms2_cif_overflow_reg
        reg_test = self.device_tree.sms_quad[3].sms2_cif_overflow_reg_test
        lldev = self.device.device.get_ll_device()
        if lldev.is_asic5():
            tree = lldev.get_asic5_tree()
            reg = tree.slice[0].tx.pdr.general_interrupt_register
            reg_test = tree.slice[0].tx.pdr.general_interrupt_register_test
        self.do_test_enable_disable_bit(reg, reg_test)

    @unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_enable_disable_non_wired_bit(self):
        reg = self.device_tree.slice[1].npu.sna.sna_interrupt_array
        reg_test = self.device_tree.slice[1].npu.sna.sna_interrupt_array_test
        # Wait long enough to let the polling thread to pick up the non-wired interrupt
        self.do_test_enable_disable_bit(reg, reg_test, wait_seconds=1.5)

    def do_test_enable_disable_bit(self, reg, reg_test, wait_seconds=0.1):
        # Initial state - check that all interrupt bits are initially enabled
        for bit_i in range(reg.get_desc().width_in_bits):
            enabled = self.device.get_interrupt_enabled(reg, bit_i)
            self.assertTrue(enabled)

        for set_enabled in [False, False, True, True, False, False, True, False]:
            # Disable interrupts processing and mask-off MSI root
            # Automatic dampening (periodic mask-off/on) is also idle, because interrupts are off.
            self.device.set_bool_property(sdk.la_device_property_e_PROCESS_INTERRUPTS, False)

            # Set all bits to enabled/disabled, check set/get
            for bit_i in range(reg.get_desc().width_in_bits):
                self.device.set_interrupt_enabled(reg, bit_i, set_enabled)
                enabled = self.device.get_interrupt_enabled(reg, bit_i)
                self.assertEqual(enabled, set_enabled)

            # Enable interrupts processing and enable MSI root
            self.device.set_bool_property(sdk.la_device_property_e_PROCESS_INTERRUPTS, True)

            # Check that we do not get any interrupts if disabled, and get all if enabled
            enabled = set_enabled
            self.do_generate_interrupt_all_bits(reg, reg_test, enabled, wait_seconds)

    def do_generate_interrupt_all_bits(self, reg, reg_test, is_interrupt_enabled, wait_seconds):
        n = reg_test.get_desc().width_in_bits

        # Toggle test register, generate 'n' interrupts at once
        self.ldev.write_register(reg_test, (1 << n) - 1)
        self.ldev.write_register(reg_test, 0)
        time.sleep(wait_seconds)

        crit, norm = interrupt_utils.read_notifications(self.critical_fd, self.normal_fd, .1)

        expected_n = n if is_interrupt_enabled else 0
        if is_interrupt_enabled:
            expected_n = n
        else:
            expected_n = 0
            # The interrupt register is masked off, we must clear here in test, because SDK does not see this interrupt
            self.ldev.write_register(reg, (1 << n) - 1)

        if verbose >= 1:
            print('reg={}, interrupt_enabled={}, expected_n={}, actual_n={}'.format(
                reg_test.get_name(), is_interrupt_enabled, expected_n, len(crit) + len(norm)))

        self.assertEqual(expected_n, len(crit) + len(norm))

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_enable_disable_memory(self):
        mem = self.device_tree.slice[0].ifg[0].sch.vsc_credit_deficit
        self.do_test_enable_disable_memory(mem)

    @unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_enable_disable_non_wired_memory(self):
        mem = self.device_tree.slice[2].npu.sna.pp_psn_table
        # Wait long enough to let the polling thread to pick up the non-wired interrupt
        self.do_test_enable_disable_memory(mem, 1.5)

    def do_test_enable_disable_memory(self, mem, wait_seconds=0.1):
        # Initial state
        enabled = self.device.get_interrupt_enabled(mem)
        self.assertEqual(enabled, True)
        self.do_test_mem_protect_error(mem, enabled, wait_seconds)

        # Set/get
        for set_enabled in [False, True]:
            self.device.set_interrupt_enabled(mem, set_enabled)
            enabled = self.device.get_interrupt_enabled(mem)
            self.assertEqual(enabled, set_enabled)

            self.do_test_mem_protect_error(mem, enabled, wait_seconds)

    def do_test_mem_protect_error(self, mem, is_interrupt_enabled, wait_seconds):
        block_id = mem.get_block_id()
        addr = mem.get_desc().addr
        width_total_bits = mem.get_desc().width_total_bits

        # read directly from HW, value comes with ECC header
        self.ldev.set_shadow_read_enabled(False)
        val_initial = self.ldev.read_memory_raw(block_id, addr, width_total_bits)

        # Write a value with known good ECC/Parity and a payload with deliberately corrupted bit
        # Set/clear CifProtGenBypass bit to disable/enable HW ECC/Parity generation - ECC/Parity and payload are written by host
        block = eval('self.device_tree.' + mem.get_block().get_name())
        self.ldev.write_register(block.memory_prot_bypass, 0x2)
        self.ldev.write_memory_raw(block_id, addr, width_total_bits, val_initial ^ 0x1)
        self.ldev.write_register(block.memory_prot_bypass, 0x0)

        # Generate a 1b error interrupt
        val_read = self.ldev.read_memory_raw(block_id, addr, width_total_bits)

        # Restore a good value (SDK restores value automatically only if interrupt for this memory is enabled)
        self.ldev.write_memory_raw(block_id, addr, width_total_bits, val_initial)

        self.ldev.set_shadow_read_enabled(True)

        self.assertEqual(val_initial, val_read)

        time.sleep(wait_seconds)
        crit, norm = interrupt_utils.read_notifications(self.critical_fd, self.normal_fd, .1)
        expected_n = int(is_interrupt_enabled)
        self.assertEqual(expected_n, len(crit) + len(norm))


if __name__ == '__main__':
    unittest.main()
