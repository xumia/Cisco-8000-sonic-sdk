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

#!/usr/bin/env python3

from leaba import sdk, debug
import decor
import unittest
from mac_port_base import *
import time
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_delay_link_error_interrupts(mac_port_base):

    @unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_delay_link_error_interrupts(self):
        slice_id = 0
        ifg_id = 0
        first_serdes_id = 0
        serdes_count = 1
        pool = int(first_serdes_id / 8)
        speed = sdk.la_mac_port.port_speed_e_E_25G
        fc_mode = sdk.la_mac_port.fc_mode_e_NONE
        fec_mode = sdk.la_mac_port.fec_mode_e_RS_KP4
        sdk.la_set_logging_level(0, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
        sdk.la_set_logging_level(0, sdk.la_logger_component_e_MAC_PORT, sdk.la_logger_level_e_DEBUG)
        dd = debug.debug_device(self.device)
        ll_d = self.device.get_ll_device()

        mac_pool_regs = None
        if self.device.ll_device.is_pacific():
            pt = ll_d.get_pacific_tree()
            mac_pool_regs = pt.slice[slice_id].ifg[ifg_id].mac_pool8[pool]
        elif self.device.ll_device.is_gibraltar():
            gt = ll_d.get_gibraltar_tree()
            mac_pool_regs = gt.slice[slice_id].ifg[ifg_id].mac_pool8[pool]
        elif self.device.ll_device.is_asic4():
            pl = ll_d.get_asic4_tree()
            mac_pool_regs = pl.slice[slice_id].ifg[ifg_id].mac_pool8[pool]
        else:
            self.fail('Unsupported device revision')

        self.mac_port_setup(slice_id, ifg_id, first_serdes_id, serdes_count, 1, speed, [fc_mode], [fec_mode])

        self.mp = self.mac_ports[0]
        self.mp.set_loopback_mode(sdk.la_mac_port.loopback_mode_e_SERDES)
        self.mp.activate()

        self.wait_for_state(sdk.la_mac_port.state_e_LINK_UP)
        link_up_epoch = time.time()

        timeout_sec = 30
        while self.get_degraded_ser_mask(dd, mac_pool_regs):
            epoch = time.time()
            mask_epoch = epoch - link_up_epoch
            self.assertFalse(mask_epoch > timeout_sec)

        delayed_interrupts_unmasked_epoch = time.time()
        total_time_to_unmask_secs = delayed_interrupts_unmasked_epoch - link_up_epoch

        self.assertTrue(total_time_to_unmask_secs > 10)

    def wait_for_state(self, state):
        timeout = 20  # in seconds
        start_waiting_epoch = time.time()

        state_map = {
            sdk.la_mac_port.state_e_TUNED: "TUNED",
            sdk.la_mac_port.state_e_TUNING: "TUNING",
            sdk.la_mac_port.state_e_PCS_STABLE: "PCS_STABLE",
            sdk.la_mac_port.state_e_LINK_UP: "LINK_UP",
        }

        while self.mp.get_state() != state:
            curr_epoch = time.time()
            epoch_since_start = curr_epoch - start_waiting_epoch
            self.assertFalse(epoch_since_start > timeout, "Timeout waiting for MAC_PORT to enter %s state" % (state_map[state]))

    def get_degraded_ser_mask(self, dd, mac_pool_regs):
        regs = [
            mac_pool_regs.rsf_rx_degraded_ser_interrupt_register_mask,
            mac_pool_regs.rsf_rx_rm_degraded_ser_interrupt_register_mask
        ]
        mask_vals = []

        for reg in regs:
            disabled = dd.read_register(reg)
            mask_vals.append(disabled)

        rx_degraded_ser_mask = mask_vals[0]
        rx_rm_degraded_ser_mask = mask_vals[1]
        return (rx_degraded_ser_mask.rx_degraded_ser0_mask and rx_degraded_ser_mask.rx_degraded_ser1_mask) \
            and (rx_rm_degraded_ser_mask.rx_rm_degraded_ser0_mask and rx_rm_degraded_ser_mask.rx_rm_degraded_ser1_mask)


if __name__ == '__main__':
    unittest.main()
