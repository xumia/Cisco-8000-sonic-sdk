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
verbose = False


class clear_out_of_band(base_interrupt.base_interrupt_base):

    def setUp(self):
        super().setUp(enable_interrupts=True)

        # Let the system settle down and clear post-init interrupts before we trigger yet another interrupt
        time.sleep(1)

        if verbose:
            sdk.la_set_logging_level(288, sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(0, sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(288, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(0, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)

        # Monitor all notifications
        self.fd_critical, self.fd_notifications = self.device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)
        print('notifications fd={}'.format(self.fd_notifications))

    def tearDown(self):
        self.device.close_notification_fds()
        super().tearDown()

    def test_case0(self):
        summary_regs = [
            self.pt.sbif.msi_master_interrupt_reg,
            self.pt.sbif.msi_blocks_interrupt_summary_reg0,
            self.pt.slice[0].ifg[0].ifgb.interrupt_register,
        ]
        mac_pool8_regs = [
            self.pt.slice[0].ifg[0].mac_pool8[0].interrupt_register,
            self.pt.slice[0].ifg[0].mac_pool8[0].mem_protect_interrupt,
        ]
        all_regs = summary_regs + mac_pool8_regs

        print('dump regs - before test')
        self.dump_registers(all_regs)

        # mask off MSI root
        self.ldev.write_register(self.pt.sbif.msi_master_interrupt_reg_mask, 0)

        # Trigger an interrupt, it will propagate up to MSI root, but will not be signalled to host CPU
        self.ldev.write_register(self.pt.slice[0].ifg[0].mac_pool8[0].mem_protect_interrupt_test, 0x3)

        # Check that the interrupt was really triggered
        print('dump regs - after MSI root is masked off and interrupt is triggered')
        self.dump_registers(all_regs)

        # Clear interrupts directly, since MSI root is masked off, the SDK does not clear the interrupts.
        # Hence, we reproduce the out-of-band clear.
        self.ldev.write_register(self.pt.slice[0].ifg[0].mac_pool8[0].mem_protect_interrupt_test, 0x0)
        self.ldev.write_register(self.pt.slice[0].ifg[0].mac_pool8[0].mem_protect_interrupt, 0x3)

        # We expect that branch of summary bits above mac_pool8 is pending but mac_pool8 contains no interrupts.
        values = [self.ldev.read_register(r) for r in summary_regs]
        self.assertTrue(all(v != 0 for v in values))

        values = [self.ldev.read_register(r) for r in mac_pool8_regs]
        self.assertTrue(all(v == 0 for v in values))

        print('dump regs - after clearing out-of-band')
        self.dump_registers(all_regs)

        # Now enable MSI root
        self.ldev.write_register(self.pt.sbif.msi_master_interrupt_reg_mask, 0x3)

        # Wait, let the SDK clear the interrupts
        time.sleep(1)

        print('dump regs - after MSI is enabled')
        self.dump_registers(all_regs)

        # Now we expect that everything is clear again, including the chopped off interrupt branch
        values = [self.ldev.read_register(r) for r in all_regs]
        self.assertTrue(all(v == 0 for v in values))

        # Chopped off branch is handled silently without raising a notification.
        # Expect to get none.
        desc_list = self.read_notifications(self.fd_notifications, .1)
        self.assertEqual(len(desc_list), 0)


if __name__ == '__main__':
    unittest.main()
