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


class test_link_down_interrupt(base_interrupt.base_interrupt_base):

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
        self.fd_critical, self.fd_link_down = self.device.open_notification_fds(1 << sdk.la_notification_type_e_LINK_DOWN)
        print('link_down notification fd={}'.format(self.fd_link_down))

    def tearDown(self):
        self.device.close_notification_fds()
        super().tearDown()

    def test_link_down(self):
        slice_id = 2
        ifg_id = 0
        num_serdes = 2
        speed = sdk.la_mac_port.port_speed_e_E_100G
        fc_mode = sdk.la_mac_port.fc_mode_e_NONE
        fec_mode = sdk.la_mac_port.fec_mode_e_RS_KR4

        # Create 4 mac ports, sharing the same mac_pool8[1]
        for first_serdes_id in range(8, 15, num_serdes):
            last_serdes_id = first_serdes_id + num_serdes - 1
            self.device.create_mac_port(slice_id, ifg_id, first_serdes_id, last_serdes_id, speed, fc_mode, fec_mode)

        ifg = self.pt.slice[slice_id].ifg[ifg_id]

        regs = [
            self.pt.sbif.msi_master_interrupt_reg,
            self.pt.sbif.msi_master_interrupt_reg_mask,
            self.pt.sbif.msi_blocks_interrupt_summary_reg0,
            self.pt.sbif.msi_blocks_interrupt_summary_reg0_mask,
            ifg.ifgb.interrupt_register,
            ifg.ifgb.ifg_interrupt_summary_mask,
            ifg.mac_pool8[0].interrupt_register,
            ifg.mac_pool8[1].interrupt_register,
            ifg.mac_pool2.interrupt_register,
            ifg.serdes_pool.interrupt_register,

            # Register under-test
            ifg.mac_pool8[1].rx_link_status_down,
            ifg.mac_pool8[1].rx_link_status_down_mask,

            # Monitor the top level register in the neighbour IFG[1]
            self.pt.slice[slice_id].ifg[1].ifgb.interrupt_register,
        ]

        self.link_down_clear(ifg.mac_pool8[1])

        print('dump regs - before test')
        self.dump_registers(regs)

        # Generate a link_down interrupt
        self.generate_link_down(ifg.mac_pool8[1])
        time.sleep(1)

        #print('dump regs - after test')
        # self.dump_registers(regs)

        # Read notifications that correspond to the LINK_DOWN interrupt
        desc_list = self.read_notifications(self.fd_link_down, .1)
        self.assertTrue(len(desc_list) >= 1)

        for desc in desc_list:
            self.assertEqual(desc.type, sdk.la_notification_type_e_LINK_DOWN)
            print('SUCCESS: got la_notification_desc = {',
                  'id =', desc.id,
                  ', type =', desc.type,
                  ', u.link_down = {',
                  '.slice_id =', desc.u.link_down.slice_id,
                  ', .ifg_id =', desc.u.link_down.ifg_id,
                  ', .first_serdes_id =', desc.u.link_down.first_serdes_id,
                  '}',
                  '}')
            reg = self.pt.get_block(desc.block_id).get_register(desc.addr)
            print('source register:', reg.get_name())

        self.link_down_clear(ifg.mac_pool8[1])

    def link_down_clear(self, mac_pool8):
        ldev = self.ldev

        # Clear interrupt register
        self.ldev.write_register(mac_pool8.rx_link_status_down, (1 << 8) - 1)
        # Clear interrupt test
        self.ldev.write_register(mac_pool8.rx_link_status_down_test, 0)
        # Open mask
        self.ldev.write_register(mac_pool8.rx_link_status_down_mask, 0)

        # Clear SBIF
        ldev.write_register(self.pt.sbif.msi_blocks_interrupt_summary_reg0, (1 << 31) - 1)
        ldev.write_register(self.pt.sbif.msi_blocks_interrupt_summary_reg1, (1 << 30) - 1)
        ldev.write_register(self.pt.sbif.msi_master_interrupt_reg, 0b11)

    def generate_link_down(self, mac_pool8):
        # Generate multiple interrupts at once
        self.ldev.write_register(mac_pool8.rx_link_status_down_test, 0b10101010)


if __name__ == '__main__':
    unittest.main()
