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
from leaba import debug
import lldcli
import time


class test_lld_perf(unittest.TestCase):

    def setUp(self):
        self.device_id = 0
        self.device_name = '/dev/uio0'
        self.device = sdk.la_create_device(self.device_name, self.device_id)
        self.ll_device = self.device.get_ll_device()
        self.pacific_tree = self.ll_device.get_pacific_tree()

        self.ll_device.reset_access_engines(0xff)
        self.device_init()

    def device_init(self):
        t0 = time.perf_counter()
        self.device.initialize(sdk.la_device.init_phase_e_DEVICE)
        t1 = time.perf_counter()

        print('device.initialize(DEVICE)={} seconds'.format(t1 - t0))

        for sid in range(6):
            self.device.set_slice_mode(sid, sdk.la_slice_mode_e_NETWORK)

        t2 = time.perf_counter()
        self.device.initialize(sdk.la_device.init_phase_e_TOPOLOGY)
        t3 = time.perf_counter()

        print('device.initialize(TOPOLOGY)={} seconds'.format(t3 - t2))

        self.debug_device = debug.debug_device(self.device)

    def tearDown(self):
        sdk.la_destroy_device(self.device)

    def do_test_reg(self, reg, n):
        t0 = time.perf_counter()
        for i in range(n):
            self.ll_device.write_register(reg, 0)
        t1 = time.perf_counter()
        return (t1 - t0) / n

    def do_test_tcam(self, tcam, key, mask, n):
        t0 = time.perf_counter()
        for i in range(n):
            self.ll_device.write_tcam(tcam, 0, key, mask)
        t1 = time.perf_counter()
        return (t1 - t0) / n

    def test_lld_perf(self):
        n = 10000
        r128 = self.pacific_tree.slice.ifg.ifgb.spare_reg
        r32 = self.pacific_tree.slice.ifg.ifgb.ifg_interrupt_summary

        perf128 = self.do_test_reg(r128, n)
        perf32 = self.do_test_reg(r32, n)
        print('WRITE REG 128bit={}, 32bit={}'.format(perf128, perf32))

        key = 0x0800
        mask = 0x1800
        tcam = self.pacific_tree.npuh.fi.fi_core_tcam
        perf = self.do_test_tcam(tcam, key, mask, n)
        print('WRITE XY-TCAM {}={}'.format(tcam.get_name(), perf))

        tcam = self.pacific_tree.slice[0].npu.txpp.txpp.npe_mid_res_tcam
        perf = self.do_test_tcam(tcam, key, mask, n)
        print('WRITE REG-TCAM {}={}'.format(tcam.get_name(), perf))


if __name__ == '__main__':
    unittest.main()
