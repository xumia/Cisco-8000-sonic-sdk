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

import unittest
import lldcli
import decor


def bitmask_ones(ones):
    return ((1 << ones) - 1)


class basic_access_base(unittest.TestCase):
    # Invoked before each test case
    def setUp(self):
        # ll_device and lbr_tree are expected to be set by the inheritting class
        self.assertNotEqual(self.ll_device, None)
        self.ll_device.set_shadow_read_enabled(True)

        if not hasattr(self, "initialized_base_access_device"):
            self.initialized_base_access_device = True
            if self.ll_device.is_asic3():
                self.lbr_tree = self.ll_device.get_asic3_tree()
                self.initialize_base_access_asic3(self.lbr_tree)
            else:
                self.lbr_tree = self.ll_device.get_pacific_tree()
                self.initialize_base_access_pacific(self.lbr_tree)

    # Invoked after each test case
    def tearDown(self):
        pass

    # If the target reg/mem is narrower, the HW is expected to ignore the higher bits.
    # If the target reg/mem is wider, only 32bit are modified (as if read-modify-write).
    def do_reg_rw(self, reg, val_w, val_expected):
        # write - both to shadow and to HW
        self.ll_device.set_shadow_read_enabled(True)
        self.ll_device.write_register(reg, val_w)

        # read from simulator (if RTL, this will read directly from block's backdoor)
        if self.simulator:
            desc = reg.get_desc()
            val_r = self.simulator.read_register(reg.get_block_id(), desc.addr, desc.width_in_bits, 1)
            self.assertEqual(val_r, val_expected)

        # read from shadow
        val_r = self.ll_device.read_register(reg)
        self.assertEqual(val_r, val_expected)

        # read from HW
        self.ll_device.set_shadow_read_enabled(False)
        val_r = self.ll_device.read_register(reg)
        self.assertEqual(val_r, val_expected)

        self.ll_device.set_shadow_read_enabled(True)

    def do_mem_rw(self, mem, val_w, val_expected):
        # Ignore memory ECC bits
        mask_r = bitmask_ones(mem.get_desc().width_bits)

        # write - both to shadow and to HW
        self.ll_device.set_shadow_read_enabled(True)
        self.ll_device.write_memory(mem, 0, val_w)

        # read from simulator (if RTL, this will read directly from block's backdoor)
        if self.simulator:
            desc = mem.get_desc()
            val_r = self.simulator.read_memory(mem.get_block_id(), desc.addr, desc.width_total_bits, 1)
            self.assertEqual(val_r & mask_r, val_expected)

        # read from shadow
        val_r = self.ll_device.read_memory(mem, 0)
        self.assertEqual(val_r & mask_r, val_expected)

        # read from HW
        self.ll_device.set_shadow_read_enabled(False)
        val_r = self.ll_device.read_memory(mem, 0)
        self.assertEqual(val_r & mask_r, val_expected)

        self.ll_device.set_shadow_read_enabled(True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_regmem_rw_corner_cases(self):
        # reg write does NOT tollerate too-wide value
        try:
            self.ll_device.write_register(self.reg_3bit_cc, bitmask_ones(4))
            self.fail
        except lldcli.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], lldcli.la_status_e_E_SIZE)

        # mem write tollerates too-wide value
        self.ll_device.write_memory(self.mem_10bit_cc, 0, bitmask_ones(1000))

        # mem index is out of range
        try:
            self.ll_device.write_memory(self.mem_10bit_cc, 100000, 0x12345678)
            self.fail
        except lldcli.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], lldcli.la_status_e_E_OUTOFRANGE)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_regmem_sbif_rw(self):
        # Grab some SBIF reg/mem
        self.do_reg_rw(self.reg_sbif_8bit, bitmask_ones(8), bitmask_ones(8))
        self.do_mem_rw(self.mem_sbif_32bit, bitmask_ones(64), bitmask_ones(32))

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_regmem_LBR_rw(self):
        # Test them all, writes <= 32bit will translate to IMMEDIATE_WRITE
        self.do_mem_rw(self.mem_26bit_lbr_rw, bitmask_ones(26), bitmask_ones(26))
        self.do_mem_rw(self.mem_26bit_lbr_rw, bitmask_ones(64), bitmask_ones(26))
        self.do_mem_rw(self.mem_57bit_lbr_rw, bitmask_ones(128), bitmask_ones(self.mem_57bit_lbr_rw_len))
        self.do_reg_rw(self.reg_3bit_lbr_rw, 0x5, 0x5)
        self.do_reg_rw(self.reg_33bit_lbr_rw, bitmask_ones(33), bitmask_ones(33))
        self.do_reg_rw(self.reg_128bit_lbr_rw, bitmask_ones(128), bitmask_ones(128))

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_raw_access(self):
        width_bits = 42
        val = 0x12345678901234567890
        self.ll_device.write_register_raw(self.reg_33bit_ra.get_block_id(), self.reg_33bit_ra.get_desc().addr, width_bits, val)

        # TODO: test more thouroughly

        width_bits = 42
        val = 0x12345678901234567890
        self.ll_device.write_memory_raw(self.mem_26bit_ra.get_block_id(), self.mem_26bit_ra.get_desc().addr, width_bits, val)

        # TODO: test more thouroughly

    def do_test_tcam(self, tcam):
        desc = tcam.get_desc()

        tcam_line = 2
        key = 0x0800
        mask = 0x1800

        # write to ll_device (shadow + HW)
        self.ll_device.write_tcam(tcam, tcam_line, key, mask)

        # read from ll_device (shadow)
        (read_key, read_mask, read_valid) = self.ll_device.read_tcam(tcam, tcam_line)

        self.assertEqual(read_valid, True)
        self.assertEqual(read_key, key)
        self.assertEqual(read_mask, mask)

        # invalidate then read again
        self.ll_device.invalidate_tcam(tcam, tcam_line)
        (read_key, read_mask, read_valid) = self.ll_device.read_tcam(tcam, tcam_line)

        self.assertEqual(read_valid, False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_tcam(self):
        # XY TCAM
        self.do_test_tcam(self.xy_tcam)

        # REG TCAM
        self.do_test_tcam(self.reg_tcam)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_wait_for_value(self):
        # TODO:
        # Planned test flow: fire a batch of 3 commands
        #   - write to an interrupt test register
        #   - wait on interrupt status register
        #   - read status register
        # The 3rd command is executed conditionally, only if wait is successful
        #
        # Current test flow: write/flush, wait/flush.
        val = 0x2
        self.ll_device.write_register(self.reg_3bit_test_wfv, val)

        equal, mask = True, 0x3
        self.ll_device.wait_for_value(self.reg_3bit_status_wfv, equal, val, mask)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_writable_register(self):
        # Check a few known registers
        self.assertEqual(self.writable_reg.get_desc().writable, True)
        self.assertEqual(self.nonwritable_reg.get_desc().writable, False)
        self.assertEqual(self.writable_mem.get_desc().writable, False)
        self.assertEqual(self.nonwritable_mem.get_desc().writable, True)

        for reg in self.lbr_tree.cdb.top.get_registers():
            try:
                self.ll_device.write_register(reg, 0)
                rc = lldcli.la_status_e_SUCCESS
            except lldcli.BaseException as STATUS:
                rc = STATUS.args[0]

            expected_rc = lldcli.la_status_e_SUCCESS if reg.get_desc().writable else lldcli.la_status_e_E_ACCES
            self.assertEqual(rc, expected_rc)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_delay(self):
        reg_3bit_test = self.lbr_tree.slice[0].ifg[0].sch.mem_protect_interrupt_test
        val = 0x2
        self.ll_device.write_register(reg_3bit_test, val)
        self.ll_device.delay(5)
        val_r = self.ll_device.read_register(reg_3bit_test)
        self.assertEqual(val, val_r)

    def initialize_base_access_pacific(self, lbr_tree):
        self.reg_3bit_cc = lbr_tree.slice[0].ifg[0].sch.mem_protect_interrupt_test
        self.mem_10bit_cc = lbr_tree.slice[0].ifg[0].sch.vsc_token_bucket  # width 10, width_total 15

        self.reg_sbif_8bit = lbr_tree.sbif.misc_output_reg
        self.mem_sbif_32bit = lbr_tree.sbif.access_engine_data_mem[0]  # width 32bit, total_width 39bit

        self.reg_3bit_lbr_rw = lbr_tree.slice[0].ifg[0].sch.mem_protect_interrupt_test
        self.reg_33bit_lbr_rw = lbr_tree.slice[0].ifg[0].sch.ecc_1b_err_interrupt_register_mask
        self.reg_128bit_lbr_rw = lbr_tree.rx_counters.spare_reg
        self.mem_26bit_lbr_rw = lbr_tree.slice[0].filb.voq_mapping  # width 26, width_total 32
        self.mem_57bit_lbr_rw = lbr_tree.slice[0].filb.static_fabric_reachability  # width 57, width_total 64
        self.mem_57bit_lbr_rw_len = 57

        self.reg_33bit_ra = lbr_tree.slice[0].ifg[0].sch.ecc_1b_err_interrupt_register_mask
        self.mem_26bit_ra = lbr_tree.slice[0].filb.voq_mapping  # width 26, width_total 32

        self.xy_tcam = lbr_tree.npuh.fi.fi_core_tcam
        self.reg_tcam = lbr_tree.slice[0].npu.txpp.txpp.npe_mid_res_tcam

        self.reg_3bit_test_wfv = lbr_tree.slice[0].ifg[0].sch.mem_protect_interrupt_test
        self.reg_3bit_status_wfv = lbr_tree.slice[0].ifg[0].sch.mem_protect_interrupt

        self.writable_reg = lbr_tree.sbif.msi_master_interrupt_reg
        self.nonwritable_reg = lbr_tree.cdb.top.interrupt_register
        self.writable_mem = lbr_tree.cdb.top.mem_protect_err_status
        self.nonwritable_mem = lbr_tree.cdb.top.mem_protect_interrupt

        self.reg_3bit_test_delay = lbr_tree.slice[0].ifg[0].sch.mem_protect_interrupt_test

    def initialize_base_access_asic3(self, lbr_tree):
        self.reg_3bit_cc = lbr_tree.slice[0].asic7.serdes_pool.pool.apb_addr_reg
        self.mem_10bit_cc = lbr_tree.slice[0].fllb.fllb_control_code_ssp_lut

        self.reg_sbif_8bit = lbr_tree.slice[0].ifg[0].ifgbe.core.rx_cfg0
        self.mem_sbif_32bit = lbr_tree.sbif.access_engine_data_mem[0]  # width 32bit, total_width 4bit

        self.reg_3bit_lbr_rw = lbr_tree.slice[0].ifg[0].sch.mem_protect_interrupt_test
        self.reg_33bit_lbr_rw = lbr_tree.sms_quad.cpu_write_config_reg
        self.reg_128bit_lbr_rw = lbr_tree.rx_counters.spare_reg
        self.mem_26bit_lbr_rw = lbr_tree.npuh.host.ene_macro_memory  # width 26, width_total 4
        self.mem_57bit_lbr_rw = lbr_tree.npuh.npe.traps_lvr_macro_cfg  # width 59, width_total 8
        self.mem_57bit_lbr_rw_len = 59

        self.reg_33bit_ra = lbr_tree.slice[0].ifg[0].sch.ecc_1b_err_interrupt_register_mask
        self.mem_26bit_ra = lbr_tree.slice[0].filb.voq_mapping  # width 26, width_total 32

        self.xy_tcam = lbr_tree.npuh.fi.fi_core_tcam
        self.reg_tcam = lbr_tree.slice[0].npu.txpp.txpp.npe0_mid_res_tcam

        self.reg_3bit_test_wfv = lbr_tree.slice[0].ifg[0].sch.mem_protect_interrupt_test
        self.reg_3bit_status_wfv = lbr_tree.slice[0].ifg[0].sch.mem_protect_interrupt

        self.writable_reg = lbr_tree.sbif.msi_master_interrupt_reg
        self.nonwritable_reg = lbr_tree.cdb.top.interrupt_register
        self.writable_mem = lbr_tree.cdb.top.mem_protect_err_status
        self.nonwritable_mem = lbr_tree.cdb.top.mem_protect_interrupt

        self.reg_3bit_test_delay = lbr_tree.slice[0].ifg[0].sch.mem_protect_interrupt_test
