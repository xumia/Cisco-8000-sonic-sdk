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
import unittest
import os
import select

from leaba import sdk
import lldcli

MAX_RETRY = 100
MAX_SERDES_ID = 17
MAX_RETUNE = 2


class common_mac_port_board_test_base(unittest.TestCase):

    def device_init(self, hard_reset):
        self.device_id = 0
        self.device_name = '/dev/uio0'
        self.device = sdk.la_create_device(self.device_name, self.device_id)

        self.ll_device = self.device.get_ll_device()
        self.pacific_tree = self.ll_device.get_pacific_tree()

        # Hard reset on - off
        if hard_reset:
            self.ll_device.write_register(self.pacific_tree.sbif.reset_reg, 0x0)

            time.sleep(0.1)
            self.ll_device.write_register(self.pacific_tree.sbif.reset_reg, 0x1)

            time.sleep(0.1)

        self.device.initialize(sdk.la_device.init_phase_e_DEVICE)

        self.configure_phase_topology()

        self.device.initialize(sdk.la_device.init_phase_e_TOPOLOGY)

        self.init_interrupts()
        self.common_mac_ports = []
        self.common_fabric_ports = []
        self.initialize_test_variables()

    def setUp(self, hard_reset=False):
        self.device_init(hard_reset)

    def tearDown(self):
        self.device.close_notification_fds()
        sdk.la_destroy_device(self.device)

    def init_interrupts(self):
        notification_mask = (1 << sdk.la_notification_type_e_LINK_UP) | (1 << sdk.la_notification_type_e_LINK_DOWN)
        self.fd_critical, self.fd_notification = self.device.open_notification_fds(notification_mask)

    def read_notifications(self, timeout_seconds):
        fd = self.fd_notification
        po = select.poll()  # create a poll object
        po.register(fd, select.POLLIN)  # register a file descriptor for future poll() calls
        os.set_blocking(fd, False)  # prepare for non-blocking read

        # The poll is in miliseconds
        res = po.poll(timeout_seconds * 1000)
        if len(res) == 0:
            # timed out - no notification descriptor available
            return []

        sizeof = sdk.la_notification_desc.__sizeof__()
        desc_list = []
        while True:
            # A non-blocking read throughs BlockingIOError when nothing is left to read
            try:
                buf = os.read(fd, sizeof)
            except BlockingIOError:
                break
            desc = sdk.la_notification_desc(bytearray(buf))
            desc_list.append(desc)

        return desc_list

    def print_notification(self, notification_desc):
        if notification_desc.type == sdk.la_notification_type_e_LINK_DOWN:
            print('Got LINK_DOWN: slice {}, ifg {}, serdes {}, info {},{},{},{},{},{},{}'.format(
                notification_desc.u.link_down.slice_id,
                notification_desc.u.link_down.ifg_id,
                notification_desc.u.link_down.first_serdes_id,
                notification_desc.u.link_down.info.rx_link_status_down,
                notification_desc.u.link_down_info.rx_remote_link_status_down,
                notification_desc.u.link_down.info.rx_pcs_link_status_down,
                notification_desc.u.link_down.info.rx_pcs_align_status_down,
                notification_desc.u.link_down.info.rx_pcs_hi_ber_up,
                notification_desc.u.link_down.info.rsf_rx_high_ser_interrupt_register,
                notification_desc.u.link_down.info.rx_pma_sig_ok_loss_interrupt_register))
        elif notification_desc.type == sdk.la_notification_type_e_LINK_UP:
            print('Got LINK_UP: slice {}, ifg {}, serdes {}'.format(
                notification_desc.u.link_up.slice_id,
                notification_desc.u.link_up.ifg_id,
                notification_desc.u.link_up.first_serdes_id))
        else:
            print('Got unexpected notification type={}'.format(notification_desc.type))
            return

    def fix_current_serdes(self):
        # SerDes on Slice 0, IFG 0, SerDes 7 seems to be problematic on board 167 - skip it for now on all
        if (self.cur_slice == 0 and self.cur_ifg == 0 and self.cur_serdes == 7):
            self.cur_serdes += 1
        if self.cur_serdes > MAX_SERDES_ID:
            self.cur_serdes = 0
            self.cur_ifg += 1
            if self.cur_ifg > 1:
                self.cur_ifg = 0
                self.cur_slice += 1

                # Slice 2 has special connections on our board
                if self.cur_slice == 2:
                    self.cur_slice += 1

    def destroy_mac_ports(self):
        for mac_port in self.common_mac_ports:
            self.device.destroy(mac_port)
        self.common_mac_ports = []

    def update_mac_ports_from_device(self):
        self.common_mac_ports = self.device.get_objects(sdk.la_object.object_type_e_MAC_PORT)

    def update_fabric_ports_from_device(self):
        self.common_fabric_ports = self.device.get_objects(sdk.la_object.object_type_e_FABRIC_PORT)

    def get_mac_info_base(self, mac_port):
        mac_info = {
            'slice': mac_port.get_slice(),
            'ifg': mac_port.get_ifg(),
            'serdes': mac_port.get_first_serdes_id()}
        mac_info['fc_mode'] = mac_port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        mac_info['fec_mode'] = mac_port.get_fec_mode()
        speed = mac_port.get_speed()
        serdes_count = mac_port.get_num_of_serdes()
        speed_value = [10, 25, 40, 50, 100, 200, 400, 800]
        mac_info['name'] = '{}x{:d}G'.format(serdes_count, int(speed_value[speed] / serdes_count))

        return mac_info

    def get_mac_info(self, mac_index):
        mac_port = self.common_mac_ports[mac_index]

        mac_info = self.get_mac_info_base(mac_port)
        mac_info['index'] = mac_index

        mac_status = mac_port.read_mac_status()

        mac_info['link_state'] = mac_status.link_state
        mac_info['pcs_status'] = mac_status.pcs_status

        # prettify for more compact and readable prints, replace a list of bool with a list of int
        mac_info['am_lock'] = [int(x) for x in mac_status.am_lock]

        return mac_info

    def get_mac_pma_ber(self, mac_index):
        mac_port = self.common_mac_ports[mac_index]

        mac_info = self.get_mac_info_base(mac_port)
        mac_info['index'] = mac_index

        ber_result = mac_port.read_pma_test_ber()

        mac_info['lane_ber'] = list(filter(lambda ber: ber >= 0, ber_result.lane_ber))

        return mac_info

    def get_mac_rs_fec(self, mac_index):
        mac_port = self.common_mac_ports[mac_index]

        mac_info = self.get_mac_info_base(mac_port)
        mac_info['index'] = mac_index

        mac_info['correctable'] = mac_port.read_counter(sdk.la_mac_port.counter_e_FEC_CORRECTABLE)
        mac_info['uncorrectable'] = mac_port.read_counter(sdk.la_mac_port.counter_e_FEC_UN_CORRECTABLE)

        return mac_info

    def get_mac_rs_fec_debug(self, mac_index):
        mac_port = self.common_mac_ports[mac_index]

        mac_info = self.get_mac_info_base(mac_port)
        mac_info['index'] = mac_index

        if not mac_port.get_rs_fec_debug_enabled():
            # if not enabled -> enable, clear and wait few seconds
            mac_port.set_rs_fec_debug_enabled()

            # clear
            rs_fec_result = mac_port.read_rs_fec_debug_counters()

            # Wait 10 seconds
            time.sleep(10)

        # Read
        rs_fec_result = mac_port.read_rs_fec_debug_counters()

        mac_info['codeword'] = rs_fec_result.codeword
        mac_info['codeword_uncorrectable'] = rs_fec_result.codeword_uncorrectable
        mac_info['symbol_burst'] = rs_fec_result.symbol_burst
        total_errors = 16 * rs_fec_result.codeword_uncorrectable
        total_cw = rs_fec_result.codeword_uncorrectable
        for i in range(16):
            total_cw += rs_fec_result.codeword[i]
            total_errors += i * rs_fec_result.codeword[i]

        mac_info['ber'] = total_errors / (total_cw * 80) if total_cw > 0 else -1

        return mac_info

    def check_mac_up(self):
        for index in range(len(self.common_mac_ports)):
            mac_info = self.get_mac_info(index)
            self.assertTrue(
                mac_info['link_state'],
                'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), link {link_state}, pcs {pcs_status}, am_lock{am_lock}'.format(
                    **mac_info))

    def is_all_mac_up(self):
        for index in range(len(self.common_mac_ports)):
            mac_info = self.get_mac_info(index)
            if not mac_info['link_state']:
                return False

        return True

    # Helper for debug
    def print_mac_up_port(self, index):
        mac_up = False
        mac_info = self.get_mac_info(index)

        if mac_info['link_state']:
            mac_up = True
            print(
                'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), link {link_state}'.format(
                    **mac_info))
        elif mac_info['pcs_status']:
            print(
                'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), link {link_state}, pcs {pcs_status}'.format(
                    **mac_info))
        else:
            print(
                'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), link {link_state}, am_lock{am_lock}'.format(
                    **mac_info))

        return mac_up

    # Helper for debug
    def print_mac_up(self):
        all_up = True
        for index in range(len(self.common_mac_ports)):
            mac_up = self.print_mac_up_port(index)
            all_up = all_up and mac_up

        return all_up

    def print_mac_pma_ber(self):
        for mac_port in self.common_mac_ports:
            mac_port.set_pma_test_mode(sdk.la_mac_port.pma_test_mode_e_PRBS31)

        max_ber = 0
        for index in range(len(self.common_mac_ports)):
            mac_info = self.get_mac_pma_ber(index)
            for ber_val in mac_info['lane_ber']:
                if ber_val > max_ber:
                    max_ber = ber_val
                    print('New max ber {}'.format(max_ber))
            mac_info['lane_ber_str'] = list(map(lambda ber_val: '{:.03e}'.format(ber_val), mac_info['lane_ber']))
            print(
                'Link [{index}] name {name}, FC {fc_mode}, FEC {fec_mode}, (slice {slice}, IFG {ifg}, SerDes {serdes}), BER {lane_ber_str}'.format(
                    **mac_info))

        for mac_port in self.common_mac_ports:
            mac_port.set_pma_test_mode(sdk.la_mac_port.pma_test_mode_e_NONE)

        return max_ber

    def retune(self):
        for retry in range(MAX_RETUNE):
            time.sleep(1)
            all_pass = True
            for mac_port in self.common_mac_ports:
                mac_status = mac_port.read_mac_status()
                if (mac_status.link_state == False):
                    # Link down -> Reset MAC
                    print('reset slice {}, IFG {}, SerDes {}'.format(
                        mac_port.get_slice(), mac_port.get_ifg(), mac_port.get_first_serdes_id()))

                    # Check again
                    mac_status = mac_port.read_mac_status()
                    if (mac_status.link_state == False):
                        # Link down -> re-tune
                        all_pass = False
                        mac_info = {
                            'slice': mac_port.get_slice(),
                            'ifg': mac_port.get_ifg(),
                            'serdes': mac_port.get_first_serdes_id(),
                        }
                        try:
                            mac_port.tune(True)
                        except sdk.BaseException:
                            raise Exception(
                                'Error: mac_port::tune failed (Slice {slice} / IFG {ifg} / SerDes {serdes}).'.format(**mac_info))

            if all_pass:
                return
