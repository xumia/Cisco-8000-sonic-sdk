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

from leaba import debug
import sim_utils
import time


class pma_tx_err_helper:
    def __init__(self, device):
        self.device = device
       # Lifted from validation scripts pma module
        self.debug_device = debug.debug_device(self.device)
        self.ll_device = self.device.get_ll_device()
        self.device_tree = sim_utils.get_device_tree(self.ll_device)

    #  Function to inject erroneous pattern on serdes
    #
    #  slice [in]           slice number
    #  ifg [in]             ifg number
    #  serdes [in]          serdes number
    #  enable [in]          option to enable (1) or disable (0) error injection
    #  pattern [in]         60 bit pattern to be generated per physical lane
    #  nof_words [in]       Length of error burst in units of 60 bits - per physical lane
    #  period [in]          Period in units of 60 bits between two bursts of errors - per physical lane.
    #  random_pattern[in]   1: Use the configured fixed pattern.
    #                       0: Use pattern from a PRBS31 generator output, after mask with bits in pattern.
    #
    def pma_tx_err_inject(self, slice, ifg, serdes, enable=1, pattern=0xffff, nof_words=1, period=5, random_pattern=0):
        if self.ll_device.is_pacific() and (serdes >= 16):
            mac_pool = self.device_tree.slice[slice].ifg[ifg].mac_pool2
        else:
            mac_pool = self.device_tree.slice[slice].ifg[ifg].mac_pool8[(serdes // 8)]

        if enable == 1:
            self.ll_device.write_register(mac_pool.tx_pma_err_gen_pattern[serdes % 8], pattern)
            # Error control
            wdata = 0
            wdata = debug.set_bits(wdata, 47, 0, int(period - 1))         # Period - distance between 2 bursts - in 60b words
            wdata = debug.set_bits(wdata, 55, 48, nof_words - 1)          # Burst length minus 1 - in 60b words
            self.ll_device.write_register(mac_pool.tx_pma_err_gen_ctrl[serdes % 8], wdata)
            wdata = debug.set_bits(wdata, 56, 56, 1)                # Enable error injection
            self.ll_device.write_register(mac_pool.tx_pma_err_gen_ctrl[serdes % 8], wdata)
            data = self.debug_device.read_register(mac_pool.tx_pma_err_gen_rand_ctrl[serdes % 8])
            data.tx_pma_err_gen_fixed_err_pattern = random_pattern
            self.debug_device.write_register(mac_pool.tx_pma_err_gen_rand_ctrl[serdes % 8], data)
        else:
            status = 0
            wdata = self.ll_device.read_register(mac_pool.tx_pma_err_gen_ctrl[serdes % 8])
            wdata = debug.set_bits(wdata, 55, 48, 0)
            self.ll_device.write_register(mac_pool.tx_pma_err_gen_ctrl[serdes % 8], wdata)
            time.sleep(1)
            self.ll_device.write_register(mac_pool.tx_pma_err_gen_ctrl[serdes % 8], 0)
            data = self.debug_device.read_register(mac_pool.tx_pma_err_gen_rand_ctrl[serdes % 8])
            data.tx_pma_err_gen_fixed_err_pattern = 0
            self.debug_device.write_register(mac_pool.tx_pma_err_gen_rand_ctrl[serdes % 8], data)
