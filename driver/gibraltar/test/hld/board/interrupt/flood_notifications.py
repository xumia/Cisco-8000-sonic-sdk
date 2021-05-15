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


class flood_notifications(base_interrupt.base_interrupt_base):

    def setUp(self):
        super().setUp(enable_interrupts=True)

        # Let the system settle down and clear post-init interrupts before we trigger yet another interrupt
        time.sleep(1)

        if verbose:
            sdk.la_set_logging_level(288, sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(0, sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(288, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(0, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)

        # Open file descriptors for monitoring LINK_DOWN notifications
        self.fd_critical, self.fd_notification = self.device.open_notification_fds((1 << sdk.la_notification_type_e_LAST) - 1)
        print('notification fd={}'.format(self.fd_notification))

    def tearDown(self):
        self.device.close_notification_fds()
        super().tearDown()

    def test_flood(self):
        self.flood_once()
        self.flood_once()

    def flood_once(self):
        reg_interrupt = self.pt.dmc.frm.frm_interrupt_reg
        reg_test = self.pt.dmc.frm.frm_interrupt_reg_test
        reg_mask = self.pt.dmc.frm.frm_interrupt_reg_mask

        self.clear_interrupt(reg_interrupt, reg_test, reg_mask)

        # The default pipe capacity is 16 system pages
        # In addition, a 'write' to pipe does not cross page boundary.
        # Hence, the math below:
        max_notifications_in_sys_page = 4096 // sdk.la_notification_desc.__sizeof__()
        max_notifications_in_pipe = 16 * max_notifications_in_sys_page

        # Generate more notifications than a pipe can contain (max + 100)
        for i in range(max_notifications_in_pipe + 100):
            self.ldev.write_register(reg_test, 0x4)
            self.ldev.write_register(reg_test, 0)
            # Wait a bit, let the SDK clear the interrupt register and "write" a notification
            time.sleep(.001)

        # Read accumulated notifications, should be exactly the capacity of the pipe
        desc_list = self.read_notifications(self.fd_notification, 1)
        self.assertTrue(len(desc_list) == max_notifications_in_pipe)

        for desc in desc_list:
            self.assertEqual(desc.type, sdk.la_notification_type_e_OTHER)
            if False:
                print('SUCCESS: got la_notification_desc = {',
                      'id =', desc.id,
                      ', type =', desc.type,
                      '}',
                      '}')

        self.clear_interrupt(reg_interrupt, reg_test, reg_mask)

    def clear_interrupt(self, reg_interrupt, reg_test, reg_mask):
        ldev = self.ldev

        # Clear interrupt register
        self.ldev.write_register(reg_interrupt, (1 << reg_interrupt.get_desc().width_in_bits) - 1)
        # Clear interrupt test
        self.ldev.write_register(reg_test, 0)
        # Open mask
        self.ldev.write_register(reg_mask, 0)

        # Clear SBIF
        ldev.write_register(self.pt.sbif.msi_blocks_interrupt_summary_reg0, (1 << 31) - 1)
        ldev.write_register(self.pt.sbif.msi_blocks_interrupt_summary_reg1, (1 << 30) - 1)
        ldev.write_register(self.pt.sbif.msi_master_interrupt_reg, 0b11)


if __name__ == '__main__':
    unittest.main()
