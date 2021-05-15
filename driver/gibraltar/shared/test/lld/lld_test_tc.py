#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import lldcli
import decor

# @brief Print register vector element
#
# Print out the register ID, position in the vector, address in byte addressing notation, name, current value and description


def print_register_vec(acc_ctx, reg_arr):
    reg_arr_desc = reg_arr.get_desc()
    block_id = reg_arr.get_block_id()

    for idx in range(reg_arr_desc.instances):
        reg_desc = reg_arr[idx].get_desc()
        (status, reg_val) = acc_ctx.read_register_array(reg_arr, idx, 1)
        print("Register[%d] @0x%X (%-45s %2d) = 0x%X // %s" %
              (idx, (reg_desc.addr + idx) << 2, reg_desc.name, idx, reg_val, reg_desc.desc))

# @brief Print register
#
# Print out the register ID, address in byte addressing notation, name, current value and description


def print_register(acc_ctx, reg):
    reg_desc = reg.get_desc()
    if (reg_desc.instances > 1):
        print_register_vec(acc_ctx, reg)
    else:
        (status, reg_val) = acc_ctx.read_register(reg)

        print("Register[ ] @0x%X (%-48s) = 0x%X // %s" % (reg_desc.addr << 2, reg_desc.name, reg_val, reg_desc.desc))

# @brief Print all registers of the SBIF block


def print_all_registers(acc_ctx, pacific):
    # collect the registers to be printed
    regs = []
    regs.append(pacific.sbif.reset_reg)
    regs.append(pacific.sbif.sbif_global_config_reg)
    regs.append(pacific.sbif.acc_eng_go_reg)
    regs.append(pacific.sbif.acc_eng_cmd_ptr_reg)
    regs.append(pacific.sbif.acc_eng_status_reg)
    regs.append(pacific.sbif.acc_eng_error_addr_reg)
    regs.append(pacific.sbif.arc_run_halt_reg)
    regs.append(pacific.sbif.arc_status_reg)
    regs.append(pacific.sbif.sbm_req_reg)
    regs.append(pacific.sbif.sbm_req_data_reg)
    regs.append(pacific.sbif.sbm_req_execute_reg)
    regs.append(pacific.sbif.sbm_rsp_result_reg)
    regs.append(pacific.sbif.sbm_rsp_data_reg)
    regs.append(pacific.sbif.misc_output_reg)
    for reg in regs:
        print_register(acc_ctx, reg)


def print_throughput(prefix_str, total_bytes, wr_time, rd_time):
    write_mbps = total_bytes * 8 / wr_time / (1024 * 1024)
    read_mbps = total_bytes * 8 / rd_time / (1024 * 1024)
    print("%s: Write %2.3fMbps, Read %2.3fMbps" % (prefix_str, write_mbps, read_mbps))

#######################################################
# Tests
#######################################################
# @brief Setup of device for example module tests


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
def test_lbr_setup(acc_ctx, pacific):
        # Take all the blocks out of reset
    acc_ctx.write_register(pacific.mac_pool2.soft_reset_configuration, 1)
    acc_ctx.write_register(pacific.serdes_pool4.soft_reset_configuration, 1)
    acc_ctx.write_register(pacific.mem_wrapper_top.soft_reset_configuration, 1)
    acc_ctx.write_register(pacific.mem_wrapper_bottom.soft_reset_configuration, 1)
    print_all_registers(acc_ctx, pacific)

#######################################################
# @brief Basic register read and write test
#
# @param[in] acc_ctx    Access context to use.
# @param[in] reg        Register ID of the register.
# @param[in] wr_val     Value to test write.
# @return 0 on success, non-zero on failure


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
def test_lbr_register_rw_reg_id(acc_ctx, reg, wr_val):
    func_name = test_lbr_register_rw_reg_id.__name__
    err = 0
    block_id = reg.get_block_id()

    # Retrieve decriptor of the register
    reg_desc = reg.get_desc()

    # Read Reg X and print
    (status, ret_val1) = acc_ctx.read_register(reg)
    print("%s: Block[%d] Register[0x%4X] => 0x%X" % (func_name, block_id, reg_desc.addr, ret_val1))

    # Write Reg X
    acc_ctx.write_register(reg, wr_val)
    # Read Reg X
    (status, ret_val2) = acc_ctx.read_register(reg)

    # compare and print
    if (wr_val != ret_val2):
        print("%s: Block[%d] Register[0x%4X]: wrote 0x%X, got 0x%X => FAIL!" %
              (func_name, block_id, reg_desc.addr, wr_val, ret_val2))
    else:
        print("%s: Block[%d] Register[0x%4X]: wrote 0x%X, got 0x%X => PASS" %
              (func_name, block_id, reg_desc.addr, wr_val, ret_val2))


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
def test_lbr_register_rw(acc_ctx, pacific):
    test_lbr_register_rw_reg_id(acc_ctx, pacific.mem_wrapper_top.data_reg0, 0x12345678)
    test_lbr_register_rw_reg_id(acc_ctx, pacific.mem_wrapper_top.data_reg1, 0xfedcba98)

#######################################################
# @brief Basic memory read and write test
#
# @param[in] acc_ctx    Access context to use.
# @param[in] mem        Memory ID of the memory.
# @return 0 on success, non-zero on failure


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
def test_lbr_memory_rw_mem_id(acc_ctx, mem):
    func_name = test_lbr_memory_rw_mem_id.__name__
    err = 0
    block_id = mem.get_block_id()

    # Retrieve decriptor of the register
    mem_desc = mem.get_desc()

    cmp_mask = (1 << mem_desc.width_bits) - 1

    t0 = time.clock()
    for i in range(mem_desc.entries):
        wr_val = (i << 16) | block_id
        acc_ctx.write_memory(mem, i, 1, wr_val)

    t1 = time.clock()
    for i in range(mem_desc.entries):
        wr_val = (i << 16) | block_id
        (status, rd_val) = acc_ctx.read_memory(mem, i, 1)
        if (wr_val != (rd_val & cmp_mask)):
            print("%s: Block[%d] Memory@0x%6X[%4d]: wrote 0x%X, got 0x%X => FAIL!" %
                  (func_name, block_id, mem_desc.addr, i, wr_val, (rd_val & cmp_mask)))
            return 1

    t2 = time.clock()

    print("%s: Block[%d] Memory@0x%X (%s), width in bits %d, entries %d - PASS" %
          (func_name, block_id, mem_desc.addr, mem_desc.name, mem_desc.width_bits, mem_desc.entries))

    total_bytes = mem_desc.entries * mem_desc.width_total
    print_throughput("Throughput", total_bytes, (t1 - t0), (t2 - t1))


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
def test_lbr_memory_rw(ctx, acc_ctx, pacific):
    ctx.set_write_burst(False)
    test_lbr_memory_rw_mem_id(acc_ctx, pacific.mac_pool2.tcb_pma_tx_mem)
    ctx.set_write_burst(True)
    test_lbr_memory_rw_mem_id(acc_ctx, pacific.mac_pool2.tcb_pma_tx_mem)
    ctx.set_write_burst(False)


#######################################################
# @brief Basic SBIF Memory write/read performance test
#
# Prints timing
#
# @return 0 on success, non-zero on failure
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
def test_sbif_memory_perf(acc_ctx, pacific):
    func_name = test_sbif_memory_perf.__name__
    err = 0

    access_engine_data_mem = pacific.sbif.access_engine_data_mem

    # Retrieve decriptor of the memory
    data_mem_desc = access_engine_data_mem.get_desc()
    data_entries = data_mem_desc.entries

    # Capture time t0
    t0 = time.clock()

    # Write values
    for eng in range(data_mem_desc.instances):
        # print("Writing %d ints to AccessEngine%d Data Mem" % (data_entries, eng))
        for i in range(data_entries):
            val = i | (eng << 16)
            acc_ctx.write_memory_array(access_engine_data_mem, eng, i, 1, val)
        print("Wrote %d ints" % data_entries)

    # Capture time t1
    t1 = time.clock()

    # Read values and check
    failed_check = False
    for eng in range(data_mem_desc.instances):
        print("Reading %d ints from AccessEngine%d Data Mem" % (data_entries, eng))
        for i in range(data_entries):
            val = i | (eng << 16)
            (status, got) = acc_ctx.read_memory_array(access_engine_data_mem, eng, i, 1)
            # compare got==val
            failed_check = failed_check or (got != val)

        print("Red %d ints, failed check %s" % (data_entries, failed_check))

    # Capture time t2
    t2 = time.clock()

    print("Total write/read %d integers (32b each)" % (data_mem_desc.instances * data_entries))
    print("Total Write time: %2.3fms, Read time: %2.3fms" % ((t1 - t0) * 1000, (t2 - t1) * 1000))

    total_bytes = data_mem_desc.instances * data_entries * 4
    print_throughput("Throughput", total_bytes, (t1 - t0), (t2 - t1))


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
def test_all(ctx, pacific):
    acc_ctx = ctx.create_access_context()

    print_all_registers(acc_ctx, pacific)

    test_lbr_setup(acc_ctx, pacific)
    test_lbr_register_rw(acc_ctx, pacific)
    test_lbr_memory_rw(ctx, acc_ctx, pacific)
    test_sbif_memory_perf(acc_ctx, pacific)

    print_all_registers(acc_ctx, pacific)


def ll_pacific_create(path):
    pacific = lldcli.pacific_tree()
    device_ctx = lldcli.ll_device.create(path, pacific)

    return device_ctx, pacific
