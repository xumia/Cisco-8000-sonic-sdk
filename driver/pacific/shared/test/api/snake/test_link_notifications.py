#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import time
import decor
import unittest

from leaba import sdk

from sanity_constants import *
from snake_test_base import *
TEST_PACKET_SIZE = 500

APPLY_PACIFIC_B0_IFG = False

if decor.is_gibraltar():
    if decor.is_hw_kontron_compact_cpu():
        BOARD_TYPE = 'examples/sanity/blacktip_compact_cpu_board_config.json'
    else:
        BOARD_TYPE = 'examples/sanity/blacktip_board_config.json'
    BOARD_MIX = 'test/api/snake/blacktip_full_mix.json'
    if decor.is_matilda():
        BOARD_MIX = 'test/api/snake/matilda_regular_mix.json'
else:
    BOARD_TYPE = 'examples/sanity/shermanP5_board_config.json'
    BOARD_MIX = 'test/api/snake/sherman_direct_mix.json'

verbose = 0


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipUnless(is_hw_device, "Requires HW device")
class test_link_notifications(snake_test_base):
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(),
                     "Currently not working on matilda devices, since they not aupport 8x50 ports.")
    def test_loop_pma(self):
        self.snake.args.pacific_b0_ifg = APPLY_PACIFIC_B0_IFG
        self.snake.args.board_cfg_path = BOARD_TYPE
        self.snake.args.loop_mode = 'pma'
        self.snake.args.json_mix = BOARD_MIX

        self.base_loop_test(TEST_PACKET_SIZE)

        # Clean all pending notifications
        crit, norm = self.snake.mph.read_notifications(1)
        note_list0 = crit + norm

        # Last notification is link down
        link_down_found = False
        unexpected_notifications = 0
        for note_entry in note_list0:
            if note_entry.type is sdk.la_notification_type_e_LINK and note_entry.u.link.type is sdk.la_link_notification_type_e_DOWN:
                if verbose >= 1:
                    print('got notification: {}'.format(self.snake.debug_device.notification_to_string(note_entry)))
                mac_port0 = self.snake.mph.mac_ports[0]
                self.assertEqual(note_entry.u.link.slice_id, mac_port0.get_slice())
                self.assertEqual(note_entry.u.link.ifg_id, mac_port0.get_ifg())
                self.assertEqual(note_entry.u.link.first_serdes_id, mac_port0.get_first_serdes_id())
                self.assertTrue(note_entry.u.link.u.link_down.rx_link_status_down)
                self.assertTrue(note_entry.u.link.u.link_down.rx_pcs_link_status_down)
                link_down_found = True
            else:
                print('got unexpected notification: {}'.format(self.snake.debug_device.notification_to_string(note_entry)))
                unexpected_notifications += 1

        self.assertTrue(link_down_found)
        self.assertEqual(unexpected_notifications, 0)

        if self.is_pacific():
            slice_2 = self.snake.pacific_tree.slice[2]
        else:
            slice_2 = self.snake.gibraltar_tree.slice[2]

        # Clean before trigger
        self.snake.ll_device.write_register(slice_2.ifg[0].ifgb.tx_tsf_ovf_interrupt_reg_test, 0)
        self.snake.ll_device.write_register(slice_2.ifg[0].mac_pool8[0].rx_crc_err_interrupt_register_test, 0)

        # Generate interrupts
        self.snake.ll_device.write_register(slice_2.ifg[0].ifgb.tx_tsf_ovf_interrupt_reg_test, 0x101)
        self.snake.ll_device.write_register(slice_2.ifg[0].mac_pool8[0].rx_crc_err_interrupt_register_test, 1)

        # Clean after trigger
        self.snake.ll_device.write_register(slice_2.ifg[0].ifgb.tx_tsf_ovf_interrupt_reg_test, 0)
        self.snake.ll_device.write_register(slice_2.ifg[0].mac_pool8[0].rx_crc_err_interrupt_register_test, 0)

        # Wait a little to process all interrupts
        time.sleep(1)

        # Read the notifications
        crit, norm = self.snake.mph.read_notifications(1)
        note_list = crit + norm

        # We trigger 2 interrupts on port 2/0/0 and 1 interrupt on port 2/0/8
        # For port 2/0/0 we will get either one notification containing both link errors, or one notification per error.
        # Plus, one notification for port 2/0/8.
        # A total of 2 or 3 notifications.
        #
        # "actual" accumulates the link errors. We expect to three entries to flip to True.
        expected = {
            '2/0/0': {'rx_crc': True, 'ptp': True},
            '2/0/8': {'rx_crc': False, 'ptp': True},
        }
        actual = {
            '2/0/0': {'rx_crc': False, 'ptp': False},
            '2/0/8': {'rx_crc': False, 'ptp': False},
        }

        # 3 link-error interrupts are raised as 2 or 3 notifications
        self.assertGreaterEqual(len(note_list), len(expected))

        for note_entry in note_list:
            if verbose >= 1:
                print('got notification: {}'.format(self.snake.debug_device.notification_to_string(note_entry)))
            self.assertEqual(note_entry.type, sdk.la_notification_type_e_LINK)
            self.assertEqual(note_entry.u.link.type, sdk.la_link_notification_type_e_ERROR)
            port_id = '{}/{}/{}'.format(note_entry.u.link.slice_id, note_entry.u.link.ifg_id, note_entry.u.link.first_serdes_id)

            if note_entry.u.link.u.link_error.rx_crc_error:
                actual[port_id]['rx_crc'] = True
            if note_entry.u.link.u.link_error.ptp_time_stamp_error:
                actual[port_id]['ptp'] = True

            self.assertFalse(note_entry.u.link.u.link_error.tx_crc_error)

        self.assertEqual(expected, actual)

        mac_port_2_0_0 = self.snake.mph.device.get_mac_port(2, 0, 0)
        mac_pool_reg_2_0_0 = slice_2.ifg[0].mac_pool8[0]

        self.do_test_all_link_error_bits(mac_pool_reg_2_0_0)
        self.do_test_all_link_down_interrupt_bits(mac_pool_reg_2_0_0)
        self.do_rx_link_fault_test(mac_pool_reg_2_0_0)

        self.do_test_remote_degraded_ser_during_init(mac_port_2_0_0, mac_pool_reg_2_0_0)
        self.do_test_remote_degraded_ser_after_init(mac_port_2_0_0, mac_pool_reg_2_0_0)

    def do_test_remote_degraded_ser_during_init(self, mac_port, mac_pool_reg):
        # Test queuing of degraded ser interrupt during init
        mac_port.stop()

        # trigger interrupt before port comes up
        self.trigger_remote_degraded_ser_interrupt(mac_pool_reg)
        mac_port.activate()

        # wait until link up
        self.wait_for_state(mac_port, sdk.la_mac_port.state_e_LINK_UP)

        # sleep to verify we can read notification
        time_to_unmask_interrupt = 10  # degraded SER interrupts take 10 seconds after PCS_STABLE to unmask
        time_to_get_notification = 1

        time.sleep(time_to_unmask_interrupt)
        time.sleep(time_to_get_notification)

        self.check_notifications_for_degraded_ser(expected_to_find=False,
                                                  err_msg="Remote Degraded SER interrupt not cleared during initialization")

    def do_test_remote_degraded_ser_after_init(self, mac_port, mac_pool_reg):
        # Test if we can still recieve Degraded SER notifications
        # verify link up
        self.wait_for_state(mac_port, sdk.la_mac_port.state_e_LINK_UP)

        self.trigger_remote_degraded_ser_interrupt(mac_pool_reg)

        time_to_get_notification = 1  # second
        time.sleep(time_to_get_notification)

        self.check_notifications_for_degraded_ser(expected_to_find=True,
                                                  err_msg="Remote Degraded SER interrupt did not create notification")

    def do_test_all_link_error_bits(self, mac_pool8):
        # List of link-error registers that are common to Pacific and GB
        link_error_regs = [
            mac_pool8.rx_code_err_interrupt_register_test,
            mac_pool8.rx_crc_err_interrupt_register_test,
            mac_pool8.rx_invert_crc_err_interrupt_register_test,
            mac_pool8.rx_oversize_err_interrupt_register_test,
            mac_pool8.rx_undersize_err_interrupt_register_test,
            mac_pool8.tx_crc_err_interrupt_register_test,
            mac_pool8.tx_underrun_err_interrupt_register_test,
            mac_pool8.tx_missing_eop_err_interrupt_register_test,
            mac_pool8.rsf_rx_degraded_ser_interrupt_register_test,
            mac_pool8.rsf_rx_rm_degraded_ser_interrupt_register_test,
            mac_pool8.device_time_override_interrupt_register_test,
        ]

        # Append link-error registers that are specific to Pacific or GB
        if self.is_pacific():
            link_error_regs.append(mac_pool8.rx_oob_invert_crc_err_interrupt_register_test)
        else:
            link_error_regs.append(mac_pool8.device_time_fif_ne_interrupt_register_test)

        # trigger each of the link errors
        for reg in link_error_regs:
            self.snake.ll_device.write_register(reg, 0)
            self.snake.ll_device.write_register(reg, 1)
            self.snake.ll_device.write_register(reg, 0)
            time.sleep(.5)

        # we expect to get 1 or more notifications. Collectively, the
        # notifications are expected to represent all link-errors triggered above.
        crit, norm = self.snake.mph.read_notifications(1)
        note_list = crit + norm
        count = 0
        for note in note_list:
            if note.type is not sdk.la_notification_type_e_LINK:
                print('got unexpected notification: {}'.format(self.snake.debug_device.notification_to_string(note)))
                self.assertEqual(note.type, sdk.la_notification_type_e_LINK)
            self.assertEqual(note.u.link.type, sdk.la_link_notification_type_e_ERROR)
            count += note.u.link.u.link_error.rx_code_error
            count += note.u.link.u.link_error.rx_crc_error
            count += note.u.link.u.link_error.rx_invert_crc_error
            count += note.u.link.u.link_error.rx_oob_invert_crc_error
            count += note.u.link.u.link_error.rx_oversize_error
            count += note.u.link.u.link_error.rx_undersize_error
            count += note.u.link.u.link_error.tx_crc_error
            count += note.u.link.u.link_error.tx_underrun_error
            count += note.u.link.u.link_error.tx_missing_eop_error
            count += note.u.link.u.link_error.rsf_rx_degraded_ser
            count += note.u.link.u.link_error.rsf_rx_remote_degraded_ser
            count += note.u.link.u.link_error.device_time_fifo_not_empty
            count += note.u.link.u.link_error.device_time_override

        self.assertEqual(count, len(link_error_regs))

    def do_test_all_link_down_interrupt_bits(self, mac_pool8):

        link_down_regs = {
            'rx_desk_fif_ovf_interrupt_register0_test': (mac_pool8.rx_desk_fif_ovf_interrupt_register0_test, 0x3FF, 4),
            'rx_desk_fif_ovf_interrupt_register1_test': (mac_pool8.rx_desk_fif_ovf_interrupt_register1_test, 0x3FF, 3),
            'rx_desk_fif_ovf_interrupt_register2_test': (mac_pool8.rx_desk_fif_ovf_interrupt_register2_test, 0x3FF, 2),
            'rx_desk_fif_ovf_interrupt_register3_test': (mac_pool8.rx_desk_fif_ovf_interrupt_register3_test, 0x3FF, 1),
            'rx_desk_fif_ovf_interrupt_register4_test': (mac_pool8.rx_desk_fif_ovf_interrupt_register4_test, 0x3FF, 5),
            'rx_desk_fif_ovf_interrupt_register5_test': (mac_pool8.rx_desk_fif_ovf_interrupt_register5_test, 0x3FF, 9),
            'rx_desk_fif_ovf_interrupt_register6_test': (mac_pool8.rx_desk_fif_ovf_interrupt_register6_test, 0x3FF, 6),
            'rx_desk_fif_ovf_interrupt_register7_test': (mac_pool8.rx_desk_fif_ovf_interrupt_register7_test, 0x3FF, 7),
            'rx_pcs_hi_ber_up_test': (mac_pool8.rx_pcs_hi_ber_up_test, 1, 2),
            'rx_pma_sig_ok_loss_interrupt_register_test': (mac_pool8.rx_pma_sig_ok_loss_interrupt_register_test, 0xFF, 4),
            'rx_pcs_align_status_down_test': (mac_pool8.rx_pcs_align_status_down_test, 1, 10),
            'rsf_rx_high_ser_interrupt_register_test': (mac_pool8.rsf_rx_high_ser_interrupt_register_test, 1, 6)
        }
        #'rx_pcs_link_status_down_test': (mac_pool8.rx_pcs_link_status_down_test, 1, 8),

        trigger_total_count = 0
        trigger_reg_name = 'rx_link_status_down_test'
        trigger_reg = mac_pool8.rx_link_status_down_test
        for reg_entry in link_down_regs:
            test_reg, write_val, counts = link_down_regs[reg_entry]
            for intr_cnt in range(0, counts):
                self.snake.ll_device.write_register(test_reg, 0)
                self.snake.ll_device.write_register(test_reg, write_val)
                self.snake.ll_device.write_register(test_reg, 0)

                # The above interrupts are set but updating histogram will need to trigger by
                # rx_link_status_down_test interrupt. Write this bit last.
                self.snake.ll_device.write_register(trigger_reg, 0)
                self.snake.ll_device.write_register(trigger_reg, 1)
                self.snake.ll_device.write_register(trigger_reg, 0)

                trigger_total_count = trigger_total_count + 1
                time.sleep(.5)

        # Clean all pending notifications
        crit, norm = self.snake.mph.read_notifications(1)
        note_list0 = crit + norm

        # Assert error if there's no notification.
        self.assertNotEqual(len(note_list0), 0, "rx_link_status_down_test did not trigger any notifications")

        note_entry = note_list0[0]
        port_id = '{}/{}/{}'.format(note_entry.u.link.slice_id, note_entry.u.link.ifg_id, note_entry.u.link.first_serdes_id)

        # Search for mac_port list that matches the slice_id, ifg_id, first_serdes_id
        mp = None
        for mac_port in (self.snake.mph.mac_ports):
            mac_port_id = '{}/{}/{}'.format(mac_port.get_slice(), mac_port.get_ifg(), mac_port.get_first_serdes_id())
            if (mac_port_id == port_id):
                mp = mac_port
                break
        self.assertIsNotNone(mp, None)

        # Get the histogram and check the count.
        hist = mp.get_link_down_histogram(True)
        self.assertEqual(hist.rx_link_status_down_count, trigger_total_count)
        total_faults = hist.rx_remote_link_status_down_count + hist.rx_local_link_status_down_count
        self.assertEqual(total_faults, trigger_total_count)
        self.assertEqual(hist.rsf_rx_high_ser_interrupt_register_count,
                         link_down_regs['rsf_rx_high_ser_interrupt_register_test'][2])
        self.assertEqual(hist.rx_pcs_align_status_down_count, link_down_regs['rx_pcs_align_status_down_test'][2])
        self.assertEqual(hist.rx_pcs_hi_ber_up_count, link_down_regs['rx_pcs_hi_ber_up_test'][2])
        #self.assertEqual(hist.rx_pcs_link_status_down_count, link_down_regs['rx_pcs_link_status_down_test'][2])

        for idx in range(0, sdk.SERDES):
            self.assertEqual(
                hist.rx_pma_sig_ok_loss_interrupt_register_count[idx],
                link_down_regs['rx_pma_sig_ok_loss_interrupt_register_test'][2])

        for idx in range(0, 16, 2):          # 400G each entry : 8 MAC lanes, 2 PCS per Mac lanes. (MAC0=0,1 MAC1=2,3 MAC3=4,5 ...)
            reg_str = "rx_desk_fif_ovf_interrupt_register{}_test".format((idx // 2) % 8)
            self.assertEqual(hist.rx_deskew_fifo_overflow_count[idx], link_down_regs[reg_str][2])
            self.assertEqual(hist.rx_deskew_fifo_overflow_count[idx + 1], link_down_regs[reg_str][2])

        # Now, check if counts are cleared.
        hist = mp.get_link_down_histogram(False)
        self.assertEqual(hist.rx_link_status_down_count, 0)
        self.assertEqual(hist.rx_remote_link_status_down_count, 0)
        self.assertEqual(hist.rx_local_link_status_down_count, 0)
        self.assertEqual(hist.rsf_rx_high_ser_interrupt_register_count, 0)
        self.assertEqual(hist.rx_pcs_align_status_down_count, 0)
        self.assertEqual(hist.rx_pcs_hi_ber_up_count, 0)
        self.assertEqual(hist.rx_pcs_link_status_down_count, 0)

        for idx in range(0, sdk.SERDES):
            self.assertEqual(hist.rx_pma_sig_ok_loss_interrupt_register_count[idx], 0)

        for idx in range(0, sdk.PCS):          # Loop all entries
            self.assertEqual(hist.rx_deskew_fifo_overflow_count[idx], 0)

    def trigger_remote_degraded_ser_interrupt(self, mac_pool_reg):
        # trigger a remote degraded ser interrupt before port comes up
        self.snake.ll_device.write_register(mac_pool_reg.rsf_rx_rm_degraded_ser_interrupt_register_test, 0x1)
        self.snake.ll_device.write_register(mac_pool_reg.rsf_rx_rm_degraded_ser_interrupt_register_test, 0x0)

    def check_notifications_for_degraded_ser(self, expected_to_find, err_msg):
        crit, norm = self.snake.mph.read_notifications(1)
        notifications = crit + norm

        # Look for Remote Degraded SER notification, if does not match expected_to_find throw error
        for notification in notifications:
            if notification.type is sdk.la_notification_type_e_LINK and notification.u.link.type is sdk.la_link_notification_type_e_ERROR:
                is_remote_degraded_ser = notification.u.link.u.link_error.rsf_rx_remote_degraded_ser
                self.assertTrue(is_remote_degraded_ser == expected_to_find, err_msg)

    def wait_for_state(self, mp, state):
        timeout = 20  # in seconds
        start_waiting_epoch = time.time()

        state_map = {
            sdk.la_mac_port.state_e_TUNED: "TUNED",
            sdk.la_mac_port.state_e_TUNING: "TUNING",
            sdk.la_mac_port.state_e_PCS_STABLE: "PCS_STABLE",
            sdk.la_mac_port.state_e_LINK_UP: "LINK_UP",
        }

        while mp.get_state() != state:
            curr_epoch = time.time()
            epoch_since_start = curr_epoch - start_waiting_epoch
            self.assertFalse(epoch_since_start > timeout, "Timeout waiting for MAC_PORT to enter %s state" % (state_map[state]))

    def do_rx_link_fault_test(self, mac_pool8):
        if self.is_pacific():
            link_down_regs = {
                'local': (mac_pool8.rx_pcs_link_status_down_test, 0, 8),
                'remote': (mac_pool8.rx_pcs_link_status_down_test, 1, 8)
            }
        else:
            link_down_regs = {
                'local': (mac_pool8.tx_mac_link_fault_override_cfg, 0xFFFFFF, 8),
                'remote': (mac_pool8.tx_mac_link_fault_override_cfg, 0xFF00FF, 8)
            }
        trigger_total_count = 0
        trigger_reg_name = 'rx_link_status_down_test'
        trigger_reg = mac_pool8.rx_link_status_down_test
        for reg_entry in link_down_regs:
            test_reg, write_val, counts = link_down_regs[reg_entry]
            for intr_cnt in range(0, counts):
                self.snake.ll_device.write_register(test_reg, 0)
                self.snake.ll_device.write_register(trigger_reg, 0)
                time.sleep(0.5)
                self.snake.ll_device.write_register(test_reg, write_val)
                self.snake.ll_device.write_register(trigger_reg, 1)
                time.sleep(0.5)
                trigger_total_count = trigger_total_count + 1
            self.snake.ll_device.write_register(test_reg, 0)
            self.snake.ll_device.write_register(trigger_reg, 0)

        # Wait a little to process all interrupts
        time.sleep(0.5)

        # Clean all pending notifications
        crit, norm = self.snake.mph.read_notifications(1)
        note_list0 = crit + norm

        rx_link_status_down_count = 0
        rx_remote_link_status_down_count = 0
        for note_entry in note_list0:
            if note_entry.type is sdk.la_notification_type_e_LINK and note_entry.u.link.type is sdk.la_link_notification_type_e_DOWN:
                if verbose >= 1:
                    print('got notification: {}'.format(self.snake.debug_device.notification_to_string(note_entry)))
                mac_port0 = self.snake.mph.mac_ports[0]
                rx_link_status_down_count += note_entry.u.link.u.link_down.rx_link_status_down
                rx_remote_link_status_down_count += note_entry.u.link.u.link_down.rx_remote_link_status_down
        self.assertEqual(rx_link_status_down_count, trigger_total_count)
        self.assertEqual(rx_remote_link_status_down_count, link_down_regs['remote'][2])

        # Assert error if there's no notification.
        self.assertNotEqual(len(note_list0), 0, "do_rx_link_fault_test did not trigger any notifications")

        note_entry = note_list0[0]
        port_id = '{}/{}/{}'.format(note_entry.u.link.slice_id, note_entry.u.link.ifg_id, note_entry.u.link.first_serdes_id)
        # Search for mac_port list that matches the slice_id, ifg_id, first_serdes_id
        mp = None
        for mac_port in (self.snake.mph.mac_ports):
            mac_port_id = '{}/{}/{}'.format(mac_port.get_slice(), mac_port.get_ifg(), mac_port.get_first_serdes_id())
            if (mac_port_id == port_id):
                mp = mac_port
                break
        self.assertIsNotNone(mp, None)
        # Get the histogram and check the count.
        hist = mp.get_link_down_histogram(True)
        self.assertEqual(hist.rx_link_status_down_count, trigger_total_count)
        self.assertEqual(hist.rx_remote_link_status_down_count + hist.rx_local_link_status_down_count, trigger_total_count)


if __name__ == '__main__':
    unittest.main()

    # For interactive debug
    '''
    tc = test_link_notifications()
    tc.setUp()
    tc.test_loop_pma()
    '''
