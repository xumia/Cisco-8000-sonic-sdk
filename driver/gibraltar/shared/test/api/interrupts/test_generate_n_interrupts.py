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
        if verbose >= 1:
            sdk.la_set_logging_level(device_id, sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)
        import sim_utils
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

        # Drain any post-init notifications
        # Sleep long enough so that non-wired interrupts will have a chance to be polled.
        time.sleep(1.5)
        crit, norm = interrupt_utils.read_notifications(self.critical_fd, self.normal_fd, .1)
        if len(crit) + len(norm) > 0:
            print('ERROR: got unexpected interrupts after initialize(TOPOLOGY)')
            interrupt_utils.dump_notifications(self.device_tree, crit, norm)
        self.assertEqual(len(crit) + len(norm), 0)

    def tearDown(self):
        self.device.close_notification_fds()
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_generate_mem_protect_for_a_block_without_memories(self):
        # We expect to get 0 notifications, because this block does not have protected memories
        if self.ldev.is_gibraltar():
            block = self.device_tree.slice[0].ifg[0].serdes_pool24
        elif self.ldev.is_asic5():
            block = self.device_tree.slice[0].ifg[0].serdes_pool16[0]
        else:
            block = self.device_tree.slice[0].ifg[0].serdes_pool
        expected = 0
        self.assertEqual(len(block.get_memories()), expected)

        self.do_generate_n_interrupts(block.mem_protect_interrupt_test, expected)

    @unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_generate_n_cause_interrupts(self):
        reg_mask = self.ldev.read_register(self.device_tree.csms.csms_interrupt_reg_mask)

        # We expect to get 'n - 1' notifications, because all bits in this reg are 'cause' bits minus the masked interrupts
        # and minus credit_gnt_dest_dev_unreachable interrupt which we don't produce notification for
        expected_n = self.device_tree.csms.csms_interrupt_reg_test.get_desc().width_in_bits - bin(reg_mask).count("1") - 1

        self.do_generate_n_interrupts(self.device_tree.csms.csms_interrupt_reg_test, expected_n)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_generate_n_msi_root_interrupts(self):
        # We expect to get 0 notifications, because MSI root does not contain 'cause' bits
        expected_n = 0
        self.do_generate_n_interrupts(self.device_tree.sbif.msi_master_interrupt_reg_test, expected_n)

    @unittest.skipIf(decor.is_hw_gibraltar(), "SKIP-GB-HW")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_generate_n_non_wired_interrupts(self):
        reg_test = self.device_tree.slice[1].npu.sna.sna_interrupt_array_test
        expected_n = reg_test.get_desc().width_in_bits
        # Wait long enough to let the polling thread to pick up the non-wired interrupt
        self.do_generate_n_interrupts(reg_test, expected_n, wait_seconds=1.5)

    def do_generate_n_interrupts(self, reg_test, expected_number_of_notifications, wait_seconds=0.1):
        n = reg_test.get_desc().width_in_bits

        # Toggle test register, generate 'n' interrupts at once
        self.ldev.write_register(reg_test, (1 << n) - 1)
        self.ldev.write_register(reg_test, 0)

        time.sleep(wait_seconds)

        crit, norm = interrupt_utils.read_notifications(self.critical_fd, self.normal_fd, .1)
        interrupt_utils.dump_notifications(self.device_tree, crit, norm)
        self.assertEqual(expected_number_of_notifications, len(crit) + len(norm))


if __name__ == '__main__':
    unittest.main()
