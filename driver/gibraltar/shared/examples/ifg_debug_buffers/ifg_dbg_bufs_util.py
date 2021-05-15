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

import random
from leaba import sdk
from leaba import debug
from ifg_debug_buffers import *


class ifg_dbg_bufs_util:

    def __init__(self):
        self.pkt_size = 600
        self.nof_pkts = 1

        self.dd = None
        self.mp = None
        self.la_dev = None
        self.ll_dev = None
        self.mp_regs = None
        self.npu_regs = None
        self.ifgb_regs = None
        self.device_tree = None

    def init(self, la_dev, mp, dd=None):
        self.la_dev = la_dev
        print('acquired device')

        if dd is None:
            self.dd = debug.debug_device(self.la_dev)
        else:
            self.dd = dd

        print('acquired debug_device')

        if mp is not None:
            self.mp = mp
            print('acquired mac_port')

        self.ll_dev = self.la_dev.get_ll_device()

        print('acquired ll_device')

        # get Register Tree
        if self.ll_dev.get_device_revision() in [sdk.la_device_revision_e_PACIFIC_A0,
                                                 sdk.la_device_revision_e_PACIFIC_B0,
                                                 sdk.la_device_revision_e_PACIFIC_B1]:
            self.device_tree = self.ll_dev.get_pacific_tree()
        elif self.ll_dev.get_device_revision() in [sdk.la_device_revision_e_GIBRALTAR_A0,
                                                   sdk.la_device_revision_e_GIBRALTAR_A1,
                                                   sdk.la_device_revision_e_GIBRALTAR_A2]:
            self.device_tree = self.ll_dev.get_gibraltar_tree()
        elif self.ll_dev.get_device_revision() == sdk.la_device_revision_e_ASIC4_A0:
            self.device_tree = self.ll_dev.get_asic4_tree()
        elif self.ll_dev.get_device_revision() == sdk.la_device_revision_e_ASIC3_A0:
            self.device_tree = self.ll_dev.get_asic3_tree()
        elif self.ll_dev.get_device_revision() == sdk.la_device_revision_e_ASIC5_A0:
            self.device_tree = self.ll_dev.get_asic5_tree()
        else:
            raise Exception('Error: Not supported device.')

        print('acquired device tree')

        ifg = self.device_tree.slice[self.mp.get_slice()].ifg[self.mp.get_ifg()]

        if self.ll_dev.get_device_revision() == sdk.la_device_revision_e_ASIC5_A0:
            self.ifgb_regs = ifg
            self.mp_regs = ifg.mac_pool2[self.mp.get_first_serdes_id() // 8]
        elif self.ll_dev.get_device_revision() == sdk.la_device_revision_e_ASIC4_A0 or self.ll_dev.get_device_revision(
        ) == sdk.la_device_revision_e_ASIC3_A0:
            self.ifgb_regs = ifg.ifgbi
            self.mp_regs = ifg.mac_pool8[self.mp.get_first_serdes_id() // 8]
        else:
            self.ifgb_regs = ifg.ifgb
            self.mp_regs = ifg.mac_pool8[self.mp.get_first_serdes_id() // 8]

        self.npu_regs = self.device_tree.slice[self.mp.get_slice()].npu

        self.clear_debug_buffers()

    def clear_debug_buffers(self):
        clear_debug_buffers(self.dd, self.ifgb_regs)

    def start(self, pkt_size=600, nof_pkts=1, time_ms=1000, in_packet=None):
        st = 0
        sid = self.mp.get_slice()
        ifg_id = self.mp.get_ifg()
        if self.ll_dev.is_asic5():
            # asic5 uses the serdes values because the pifs are dynamic
            first_pif_id = self.mp.get_first_serdes_id()
            num_of_pif = self.mp.get_num_of_serdes()
        else:
            first_pif_id = self.mp.get_first_pif_id()
            num_of_pif = self.mp.get_num_of_pif()

        # for random pkt_size: calc pkt size
        if pkt_size == 0:
            pkt_size = random.randint(64, 8192)

        # start sequence
        if nof_pkts == 1:
            print("starting send_and_compare_single_packet...")
            st = send_and_compare_single_packet(
                self.dd,
                self.ll_dev,
                sid,
                ifg_id,
                first_pif_id,
                num_of_pif,
                pkt_size,
                ifgb_regs=self.ifgb_regs,
                npu_regs=self.npu_regs,
                in_packet=in_packet)

        elif (nof_pkts == 0):
            print("starting send_continuous_traffic for %d[ms]..." % (time_ms))
            st = send_continuous_traffic(
                self.dd,
                self.ll_dev,
                sid,
                ifg_id,
                first_pif_id,
                num_of_pif,
                pkt_size,
                time_ms,
                ifgb_regs=self.ifgb_regs,
                npu_regs=self.npu_regs,
                in_packet=in_packet)

        else:
            print("starting send_%0d_iterations_traffic..." % (nof_pkts))
            st = send_X_iterations_traffic(
                self.dd,
                self.ll_dev,
                sid,
                ifg_id,
                first_pif_id,
                num_of_pif,
                pkt_size,
                nof_pkts,
                ifgb_regs=self.ifgb_regs,
                npu_regs=self.npu_regs,
                in_packet=in_packet)

        return st

    def stop_mp(self):
        self.mp.stop()

    def run_port_traffic(self, pkt_size=600, nof_pkts=0, time_ms=1000):
        sid = self.mp.get_slice()
        ifg_id = self.mp.ifg()

        if not self.mp_st:
            return 1  # eot check notation is 1==fail

        # clear ifg_interrupt_summary after creating new mac_port
        self.write_reg(self.ifgb_regs.ifg_interrupt_summary, 0x7)
        st = self.start(pkt_size=pkt_size, nof_pkts=1)
        if (st == 0):
            self.start(pkt_size=pkt_size, nof_pkts=nof_pkts, time_ms=time_ms)
            self.clear_dbg_buf_ovf_intr()
            st = self.start(pkt_size=600, nof_pkts=1)
        if (st == 0):
            st = ifg_debug.ifg_eot_check(self.device_tree, self.ll_dev, self.dd,
                                         sid, ifg_id, quiet=0)
        return st

    def clear_dbg_buf_ovf_intr(self):
        # ifgbi_core_rx_dbg_buf_interrupt_reg_register
        if self.ll_dev.is_asic4() or self.ll_dev.is_asic3():
            intr_reg = self.read_reg(self.ifgb_regs.rx_dbg_buf_interrupt_reg)
            intr_reg.rx_dbg_buf_fif_ovf = 1
            self.write_reg(self.ifgb_regs.rx_dbg_buf_interrupt_reg, intr_reg)
        else:
            intr_reg = self.read_reg(self.ifgb_regs.ifgb_interrupt_reg)
            intr_reg.dbg_buf_overflow = 1
            self.write_reg(self.ifgb_regs.ifgb_interrupt_reg, intr_reg)

    def run_port_traffic_iter(
            self, nof_iter=1, pkt_size=600, nof_pkts=0, time_ms=1000
    ):
        st = 0

        for i in range(nof_iter):
            st = self.run_port_traffic(pkt_size, nof_pkts, time_ms)
            if st == 1:
                print(str('\n' + '=' * 80 + '\n' + '[MM] ERROR!!!'))
                break
        return st

    def read_reg(self, reg):
        return self.dd.read_register(reg)

    def write_reg(self, reg, val):
        self.dd.write_register(reg, val)

    def clear_interrupts(self, r_list):
        for r in r_list:
            v = self.read_reg(r)
            self.write_reg(r, v)
