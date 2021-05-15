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
verbose = 0


class test_device_reset_interrupt(base_interrupt.base_interrupt_base):

    def setUp(self):
        super().setUp(enable_interrupts=True)

        # Let the system settle down and clear post-init interrupts before we trigger yet more interrupts
        time.sleep(1)

        if verbose >= 2:
            sdk.la_set_logging_level(288, sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(0, sdk.la_logger_component_e_INTERRUPT, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(288, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(0, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(288, sdk.la_logger_component_e_API, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(0, sdk.la_logger_component_e_API, sdk.la_logger_level_e_DEBUG)

        # Open one file descriptor for monitoring all notifications
        self.fd_critical, self.fd_notifications = self.device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)

    def tearDown(self):
        self.device.close_notification_fds()
        super().tearDown()

    def test_device_reset(self):
        # Generate 4 SOFT_RESET notifications at once
        #
        # bit no | name                         | interrupt type   | sw action
        # -------+------------------------------+------------------+------------------
        #   0    | CreditGntDestDevUnreachable  | MISCONFIGURATION | none
        #   1    | MsgBufferEnqPreFifoOverflow0 | MISCONFIGURATION | SOFT_RESET
        #   2    | MsgBufferEnqPreFifoOverflow1 | MISCONFIGURATION | SOFT_RESET
        #   3    | MsgBufferEnqPreFifoOverflow2 | MISCONFIGURATION | SOFT_RESET
        #   4    | MsgBufferEnqPreFifoOverflow3 | MISCONFIGURATION | SOFT_RESET
        self.ldev.write_register(self.pt.csms.csms_interrupt_reg_test, 0b11110)
        self.ldev.write_register(self.pt.csms.csms_interrupt_reg_test, 0)

        # Generate 10 ECC errors (not SER/MEM_PROTECT)
        #
        # bit no | name                         | interrupt type   | sw action
        # -------+------------------------------+------------------+------------------
        #   0    | LookupAError                 | ECC_2B           | rewrite entry
        #   1    | LookupBError                 | ECC_2B           | rewrite entry
        #   2    | FeLinkBmpTableMem0OneEccErr  | ECC_1B           | none
        #   3    | FeLinkBmpTableMem1OneEccErr  | ECC_1B           | none
        #   4    | FeLinkBmpTableMem2OneEccErr  | ECC_1B           | none
        #   5    | FeLinkBmpTableMem3OneEccErr  | ECC_1B           | none
        #   6    | FeLinkBmpTableMem0TwoEccErr  | ECC_2B           | rewrite entry
        #   7    | FeLinkBmpTableMem1TwoEccErr  | ECC_2B           | rewrite entry
        #   8    | FeLinkBmpTableMem2TwoEccErr  | ECC_2B           | rewrite entry
        #   9    | FeLinkBmpTableMem3TwoEccErr  | ECC_2B           | rewrite entry
        self.ldev.write_register(self.pt.rx_pdr_mc_db.shared_db_interrupt_reg_test, (1 << 10) - 1)
        self.ldev.write_register(self.pt.rx_pdr_mc_db.shared_db_interrupt_reg_test, 0)

        # Read notifications
        desc_list = []
        desc_list_expected_length = 14  # see bits above

        for i in range(20):
            dl = self.read_notifications(self.fd_notifications, 1.0)
            if len(dl) > 0:
                desc_list += dl
                if len(desc_list) == desc_list_expected_length:
                    break

        print('got {} notifications:'.format(len(desc_list)))

        self.assertTrue(len(desc_list) == desc_list_expected_length)

        for desc in desc_list:
            print('  id={}, type={}, subtype={}, block_id={}, addr={}, bit_i={}'.
                  format(desc.id, desc.type, desc.subtype, desc.block_id, desc.addr, desc.bit_i))

        # Verify that the interrupts were cleared.
        val = self.ldev.read_register(self.pt.csms.csms_interrupt_reg)
        self.assertEqual(val & 0b11110, 0)
        val = self.ldev.read_register(self.pt.rx_pdr_mc_db.shared_db_interrupt_reg)
        self.assertEqual(val, 0)

    def test_interrupts_flood(self):
        count = 0
        n = 1000
        for i in range(n):
            # 4 interrupts
            self.ldev.write_register(self.pt.csms.csms_interrupt_reg_test, 0b11110)
            self.ldev.write_register(self.pt.csms.csms_interrupt_reg_test, 0)
            # 10 interrupts
            self.ldev.write_register(self.pt.rx_pdr_mc_db.shared_db_interrupt_reg_test, (1 << 10) - 1)
            self.ldev.write_register(self.pt.rx_pdr_mc_db.shared_db_interrupt_reg_test, 0)
            time.sleep(0.001)

            desc_list = self.read_notifications(self.fd_notifications, 1.0)
            count += len(desc_list)
            for desc in desc_list:
                self.assertNotEqual(desc.id, 0)
                self.assertTrue(desc.type in [0, 15])  # SOFT_RESET=0 or OTHER=15
                if verbose >= 1:
                    print('  id={}, type={}, subtype={}, block_id={}, addr={}, bit_i={}'.
                          format(desc.id, desc.type, desc.subtype, desc.block_id, desc.addr, desc.bit_i))

        # We expect to get ((4 + 10) * n) interrupts
        print('===== count=%d' % count)
        self.assertEqual(count, (4 + 10) * n)


if __name__ == '__main__':
    unittest.main()
