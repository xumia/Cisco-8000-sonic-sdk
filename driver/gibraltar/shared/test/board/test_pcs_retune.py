#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from leaba import sdk
import unittest
import datetime
import time
import copy
import csv
import os
from ports_base import *
from bit_utils import *
import lldcli
import decor

MAC_PORT_LINKUP_TIME = 30
RX_PMA_CFG0_SIG_OVRD_EN_GB = 48
RX_PMA_CFG0_SIG_OVRD_VAL_GB = 56
RX_PMA_CFG0_SIG_OVRD_EN_PAC2 = 13
RX_PMA_CFG0_SIG_OVRD_VAL_PAC2 = 15
RX_PMA_CFG0_SIG_OVRD_EN_PAC = 60
RX_PMA_CFG0_SIG_OVRD_VAL_PAC = 68


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class pcs_retune(ports_base):
    loop_mode = 'none'
    p2p_ext = True

    # Enable SDK Logging
    def enable_sdk_logging(self, enable):
        if (enable):
            print("ENABLE_SDK_LOGGING")
            sdk.la_set_logging_level(0, sdk.la_logger_component_e_MAC_PORT, sdk.la_logger_level_e_DEBUG)
            if (self.en_sdk_timestamp):
                lldcli.logger_instance().set_timestamps_enabled(True)

    # Edit device properties
    def edit_device_properties(self):
        print("Editing Device Properties")
        self.device.set_int_property(sdk.la_device_property_e_NETWORK_MAC_PORT_TUNE_AND_PCS_LOCK_ITER, self.pcs_retune_iter)

    def set_default_testing_param(self):
        self.pcs_retune_iter = 2
        self.en_sdk_timestamp = False
        self.retune_test_iterations = 2
        self.link_up_timeout = MAC_PORT_LINKUP_TIME

    def read_rx_pma_cfg0(self, mac_port):
        is_pacific = self.snake.mph.ll_device.is_pacific()
        port_slice = mac_port.get_slice()
        port_ifg = mac_port.get_ifg()
        port_serdes = mac_port.get_first_serdes_id()
        mp_i = int(port_serdes / 8)

        if is_pacific and port_serdes > 15:
            rx_pma_cfg0_reg = self.lld.read_register(
                self.snake.debug_device.device_tree.slice[port_slice].ifg[port_ifg].mac_pool2[mp_i].rx_pma_cfg0)
        else:
            rx_pma_cfg0_reg = self.lld.read_register(
                self.snake.debug_device.device_tree.slice[port_slice].ifg[port_ifg].mac_pool8[mp_i].rx_pma_cfg0)
        return rx_pma_cfg0_reg

    def write_rx_pma_cfg0(self, mac_port, rx_pma_cfg0_wr):
        is_pacific = self.snake.mph.ll_device.is_pacific()

        port_slice = mac_port.get_slice()
        port_ifg = mac_port.get_ifg()
        port_serdes = mac_port.get_first_serdes_id()
        mp_i = int(port_serdes / 8)

        if is_pacific and port_serdes > 15:
            self.lld.write_register(
                self.snake.debug_device.device_tree.slice[port_slice].ifg[port_ifg].mac_pool2[mp_i].rx_pma_cfg0, rx_pma_cfg0_wr)
        else:
            self.lld.write_register(
                self.snake.debug_device.device_tree.slice[port_slice].ifg[port_ifg].mac_pool8[mp_i].rx_pma_cfg0, rx_pma_cfg0_wr)

    def force_port_retune(self):
        mp_list = self.mph.mac_ports[0::2]
        is_pacific = self.snake.mph.ll_device.is_pacific()
        is_gibraltar = self.snake.mph.ll_device.is_gibraltar()

        for mp in mp_list:
            port_slice = mp.get_slice()
            port_ifg = mp.get_ifg()
            port_serdes = mp.get_first_serdes_id()
            mp_i = int(port_serdes / 8)

            if is_pacific:
                if port_serdes > 15:
                    sig_ovrd_en_start = RX_PMA_CFG0_SIG_OVRD_EN_PAC2
                    sig_ovrd_val_start = RX_PMA_CFG0_SIG_OVRD_VAL_PAC2
                else:
                    sig_ovrd_en_start = RX_PMA_CFG0_SIG_OVRD_EN_PAC
                    sig_ovrd_val_start = RX_PMA_CFG0_SIG_OVRD_VAL_PAC
            if is_gibraltar:
                sig_ovrd_en_start = RX_PMA_CFG0_SIG_OVRD_EN_GB
                sig_ovrd_val_start = RX_PMA_CFG0_SIG_OVRD_VAL_GB

            rx_pma_cfg0_reg = self.read_rx_pma_cfg0(mp)

            for srd in range(mp.get_num_of_serdes()):
                rx_pma_cfg0_reg = set_bits(rx_pma_cfg0_reg, sig_ovrd_en_start + (port_serdes % 8),
                                           sig_ovrd_en_start + (port_serdes % 8), 1)
                rx_pma_cfg0_reg = set_bits(rx_pma_cfg0_reg, sig_ovrd_val_start + (port_serdes % 8),
                                           sig_ovrd_val_start + (port_serdes % 8), 0)

            self.write_rx_pma_cfg0(mp, rx_pma_cfg0_reg)
            time.sleep(1)

            for srd in range(mp.get_num_of_serdes()):
                rx_pma_cfg0_reg = set_bits(rx_pma_cfg0_reg, sig_ovrd_en_start + (port_serdes % 8),
                                           sig_ovrd_en_start + (port_serdes % 8), 0)
                rx_pma_cfg0_reg = set_bits(rx_pma_cfg0_reg, sig_ovrd_val_start + (port_serdes % 8),
                                           sig_ovrd_val_start + (port_serdes % 8), 1)

            self.write_rx_pma_cfg0(mp, rx_pma_cfg0_reg)

    @unittest.skipIf(decor.is_asic3(), "Test is not supported on GR")
    def test_pcs_retune(self):
        self.fill_args_from_env_vars('default_mix.json')
        link_status = self.snake.run_snake()
        self.assertTrue(link_status, 'one or more port links are down')
        self.mph = self.snake.mph
        self.device = self.snake.device
        self.lld = self.device.get_ll_device()
        for mp in self.mph.mac_ports:
            mp.stop()
        self.set_default_testing_param()
        self.enable_sdk_logging(True)
        self.edit_device_properties()
        for mp in self.mph.mac_ports:
            mp.activate()

        all_up = self.mph.wait_mac_ports_up(timeout=self.link_up_timeout)
        self.mph.print_mac_up()
        self.assertTrue(all_up, 'Not all port link are Up after retune')

        for current_test_iteration in range(1, self.retune_test_iterations + 1):
            print("**********************************")
            print(f"**   Iteration #: {current_test_iteration:3} of {self.test_iterations:3}    **")
            print("**********************************")

            self.force_port_retune()
            time.sleep(MAC_PORT_LINKUP_TIME)

            all_up = self.mph.wait_mac_ports_up(timeout=self.link_up_timeout)
            self.mph.print_mac_up()
            self.assertTrue(all_up, 'Not all port link are Up after retune')


if __name__ == '__main__':
    unittest.main()
