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

##################################################
# Direct (not thru driver) use of packet-DMA.
# Note - wrap around is not handled!
##################################################

import sys
import struct
import time
from math import ceil

from leaba import sdk
import lldcli
import test_lldcli

BYTES_IN_DWORD = 4
DWORDS_IN_DQWORD = 4
DWORD_MASK = 0xffffffff
BITS_IN_DWORD = 0x20
BUFFER_SIZE_BYTES = (16 * 1024)

CHAR_BIT = 8
CSS_MEM_LINE_WIDTH_BYTES = 4
PD_SIZE_BYTES = 0x10
PD_ERR_BIT_INSIDE_SIZE_WORD = (1 << 14)
PD_EOP_BIT_INSIDE_SIZE_WORD = (1 << 15)

PD_PTR_WIDTH = 17
DATA_PTR_WIDTH = 32
PUNT_FIELD_MASK_GO = (0x1 << 0)
PUNT_FIELD_MASK_FLOW_CTRL = (0x1 << 1)
PUNT_FIELD_MASK_FLOW_CTRL_PD_THR = (0x1f << 2)
PUNT_FIELD_MASK_FLOW_CTRL_DATA_THR = (0x3ff << 7)
PUNT_FIELD_MASK_REMOTE = (0x1 << 17)
PUNT_FIELD_MASK_WB = (0x1 << 18)

INJECT_FIELD_MASK_GO = (0x1 << 0)
INJECT_FIELD_MASK_REMOTE = (0x1 << 1)
INJECT_FIELD_MASK_WB = (0x1 << 2)

PUNT_CONFIG_REG_MASK_AND = PUNT_FIELD_MASK_FLOW_CTRL_PD_THR | PUNT_FIELD_MASK_FLOW_CTRL_DATA_THR
PUNT_CONFIG_REG_OR = PUNT_FIELD_MASK_GO  # | PUNT_FIELD_MASK_FLOW_CTRL

INJ_CONFIG_REG_VAL = INJECT_FIELD_MASK_GO


class packet_dma:
    def __init__(self, ll_dev, interface):
        self.ll_dev = ll_dev
        self.interface = interface
        base = 4 * BUFFER_SIZE_BYTES * interface  # 4 buffers per IFG
        self.punt_data_first_line = base // CSS_MEM_LINE_WIDTH_BYTES
        self.punt_pd_first_line = (base + BUFFER_SIZE_BYTES) // CSS_MEM_LINE_WIDTH_BYTES
        self.inject_data_first_line = (base + 2 * BUFFER_SIZE_BYTES) // CSS_MEM_LINE_WIDTH_BYTES
        self.inject_pd_first_line = (base + 3 * BUFFER_SIZE_BYTES) // CSS_MEM_LINE_WIDTH_BYTES
        self.last_ext_pd_rd_ptr = 0

    def write_css_mem(self, line, val):
        pacific = self.ll_dev.get_pacific_tree()
#        print('write_memory pacific.sbif.css_mem_even[%d] 0x%08x' % (line, val))
        addr = line * CSS_MEM_LINE_WIDTH_BYTES
        status = self.ll_dev.write_memory(pacific.sbif.css_mem_even, addr, val)
        if status != sdk.la_status_e_SUCCESS:
            raise Exception('Error: write_mem failed sbif.css_mem_even[%d] status=%d' % (line, status))

    def read_css_mem(self, line):
        pacific = self.ll_dev.get_pacific_tree()
        addr = line * CSS_MEM_LINE_WIDTH_BYTES
        (status, val) = self.ll_dev.read_memory(pacific.sbif.css_mem_even, addr)
        if status != sdk.la_status_e_SUCCESS:
            raise Exception('Error: read_mem failed sbif.css_mem_even[%d] status=%d' % (line, status))
#        print('read_memory pacific.sbif.css_mem_even[%d] 0x%08x' % (line, val))
        return val

    def write_register(self, reg, val):
        #        print('write_register %s 0x%08x' % (reg.get_name(), val))
        status = self.ll_dev.write_register(reg, val)
        if status != sdk.la_status_e_SUCCESS:
            raise Exception('Error: write_register failed %s status=%d' % (reg.get_name(), status))

    def read_register(self, reg):
        (status, val) = self.ll_dev.read_register(reg)
        if status != sdk.la_status_e_SUCCESS:
            raise Exception('Error: write_register failed %s status=%d' % (reg.get_name(), status))
#        print('read_register %s 0x%08x' % (reg.get_name(), val))
        return val

    def configure(self):
        pacific = self.ll_dev.get_pacific_tree()

#        self.init_memory()

        # Punt desc
        A1 = self.punt_pd_first_line * CSS_MEM_LINE_WIDTH_BYTES
        punt_pd_base_lsb = A1 & DWORD_MASK
        punt_pd_base_msb = (A1 >> BITS_IN_DWORD) & DWORD_MASK

        self.write_register(pacific.sbif.ext_dma_pd_base_lsb_reg[self.interface], punt_pd_base_lsb)
        self.write_register(pacific.sbif.ext_dma_pd_base_msb_reg[self.interface], punt_pd_base_msb)
        self.write_register(pacific.sbif.ext_dma_pd_length_reg[self.interface], BUFFER_SIZE_BYTES)

        # Punt data
        A2 = self.punt_data_first_line * CSS_MEM_LINE_WIDTH_BYTES
        punt_data_base_lsb = A2 & DWORD_MASK
        punt_data_base_msb = (A2 >> BITS_IN_DWORD) & DWORD_MASK

        self.write_register(pacific.sbif.ext_dma_data_base_lsb_reg[self.interface], punt_data_base_lsb)
        self.write_register(pacific.sbif.ext_dma_data_base_msb_reg[self.interface], punt_data_base_msb)
        self.write_register(pacific.sbif.ext_dma_data_length_reg[self.interface], BUFFER_SIZE_BYTES)
        self.write_register(pacific.sbif.ext_dma_pd_ptr_reg[self.interface], 0)
        self.write_register(pacific.sbif.ext_dma_rd_data_ptr_reg[self.interface], 0)

        # Punt config
        val = self.read_register(pacific.sbif.ext_dma_cfg_reg[self.interface])
        # WA - enable/disable flow-control
        newval = (val & PUNT_CONFIG_REG_MASK_AND) | PUNT_CONFIG_REG_OR | PUNT_FIELD_MASK_FLOW_CTRL
        self.write_register(pacific.sbif.ext_dma_cfg_reg[self.interface], newval)
        # Actual config
        newval = (val & PUNT_CONFIG_REG_MASK_AND) | PUNT_CONFIG_REG_OR
        self.write_register(pacific.sbif.ext_dma_cfg_reg[self.interface], newval)

        # Inject desc
        A3 = self.inject_pd_first_line * CSS_MEM_LINE_WIDTH_BYTES
        inject_pd_base_lsb = A3 & DWORD_MASK
        inject_pd_base_msb = (A3 >> BITS_IN_DWORD) & DWORD_MASK
        self.write_register(pacific.sbif.inj_dma_pd_base_lsb_reg[self.interface], inject_pd_base_lsb)
        self.write_register(pacific.sbif.inj_dma_pd_base_msb_reg[self.interface], inject_pd_base_msb)
        self.write_register(pacific.sbif.inj_dma_pd_length_reg[self.interface], BUFFER_SIZE_BYTES)

        self.write_register(pacific.sbif.inj_dma_wr_pd_ptr_reg[self.interface], 0)

        # Inject config
        self.write_register(pacific.sbif.inj_dma_cfg_reg[self.interface], INJ_CONFIG_REG_VAL)

    def init_memory(self):
        val = 0xbaadbeef
        lines_nr = int(ceil(BUFFER_SIZE_BYTES / CSS_MEM_LINE_WIDTH_BYTES))

        # Punt data
        first_line = self.punt_data_first_line
        for n in range(first_line, first_line + lines_nr):
            self.write_css_mem(n, val)

        # Punt desc
        first_line = self.punt_pd_first_line
        for n in range(first_line, first_line + lines_nr):
            self.write_css_mem(n, val)

        # Inject data
        first_line = self.inject_data_first_line
        for n in range(first_line, first_line + lines_nr):
            self.write_css_mem(n, val)

        # Inject desc
        first_line = self.inject_pd_first_line
        for n in range(first_line, first_line + lines_nr):
            self.write_css_mem(n, val)

    @staticmethod
    def incremenet_data_ptr(raw_ptr, bytes_nr):
        return packet_dma.increment_ptr(raw_ptr, bytes_nr, width=DATA_PTR_WIDTH)

    @staticmethod
    def incremenet_pd_ptr(raw_ptr, bytes_nr=PD_SIZE_BYTES):
        return packet_dma.increment_ptr(raw_ptr, bytes_nr, width=PD_PTR_WIDTH)

    @staticmethod
    def increment_ptr(raw_ptr, bytes_nr, width):
        wrap_bit = (1 << (width - 1))
        aptr = raw_ptr & ~wrap_bit
        wrap = raw_ptr & wrap_bit

        aptr += bytes_nr
        if aptr >= BUFFER_SIZE_BYTES:
            aptr -= BUFFER_SIZE_BYTES
            wrap ^= (1 << (width - 1))

        newptr = wrap | aptr
        return newptr

    @staticmethod
    def get_desc_buffer_available_space(raw_write_ptr, raw_read_ptr):
        wrap_bit = (1 << (PD_PTR_WIDTH - 1))

        if raw_write_ptr == raw_read_ptr:
            return BUFFER_SIZE_BYTES

        write_ptr = raw_write_ptr & ~wrap_bit
        read_ptr = raw_read_ptr & ~wrap_bit
        space = (write_ptr - read_ptr) if (write_ptr >= read_ptr) else (BUFFER_SIZE_BYTES - read_ptr + write_ptr)

        return space

    @staticmethod
    def complete_to_16(ba):
        m = len(ba) % 16
        if m == 0:
            return ba

        miss = 16 - m
        add = bytearray(miss * [0])
        retval = ba + add
        return retval

    def inject(self, packet):

        pacific = self.ll_dev.get_pacific_tree()

        if type(packet) == type('str'):
            pb = bytes([int(sb, 16) for sb in [packet[i * 2: (i + 1) * 2] for i in range(len(packet) // 2)]])
        else:
            pb = bytes(packet)
        pb16 = packet_dma.complete_to_16(pb)

        # Find a free slot
        raw_write_ptr = self.read_register(pacific.sbif.inj_dma_wr_pd_ptr_reg[self.interface])
        raw_rd_ptr = self.read_register(pacific.sbif.inj_dma_rd_pd_ptr_reg[self.interface])

        if packet_dma.get_desc_buffer_available_space(raw_write_ptr, raw_rd_ptr) == 0:
            return False  # No free slot

        old_raw_rd_ptr = raw_rd_ptr  # Used later for verification

        wrap_bit = (1 << (PD_PTR_WIDTH - 1))
        write_ptr = raw_write_ptr & ~wrap_bit

        # Write the packet
        data_addr = self.inject_data_first_line * CSS_MEM_LINE_WIDTH_BYTES + write_ptr
        first_line = data_addr // CSS_MEM_LINE_WIDTH_BYTES
        print('data_addr=0x%x' % data_addr)

        # Shuffling bytes inside DWORD, and DWORDS inside DQWORDS
        n = 0
        line = first_line
        while n < len(pb16):
            for i in range(DWORDS_IN_DQWORD):
                dword_index = DWORDS_IN_DQWORD - 1 - i
                s = n + dword_index * BYTES_IN_DWORD
                e = n + (dword_index + 1) * BYTES_IN_DWORD
                val = int.from_bytes(pb16[s:e], byteorder='big') & DWORD_MASK
                self.write_css_mem(line, val)
                line += 1
            n += 16

        # Write the descriptor
        data_addr_lsb = data_addr & DWORD_MASK
        data_addr_msb = (data_addr >> BITS_IN_DWORD) & DWORD_MASK

        pd_addr = self.inject_pd_first_line * CSS_MEM_LINE_WIDTH_BYTES + write_ptr
        print('pd_addr=0x%x' % pd_addr)
        first_line = pd_addr // CSS_MEM_LINE_WIDTH_BYTES

        self.write_css_mem(first_line + 0, data_addr_lsb)
        self.write_css_mem(first_line + 1, data_addr_msb)
        self.write_css_mem(first_line + 2, PD_EOP_BIT_INSIDE_SIZE_WORD | len(pb))
        self.write_css_mem(first_line + 3, 0)

        # Increment the write pointer (signal the device)
        new_ptr = packet_dma.incremenet_pd_ptr(raw_write_ptr)
        self.write_register(pacific.sbif.inj_dma_wr_pd_ptr_reg[self.interface], new_ptr)

        # Verify injection
        time.sleep(0.1)
        raw_rd_ptr = self.read_register(pacific.sbif.inj_dma_rd_pd_ptr_reg[self.interface])
        if old_raw_rd_ptr == raw_rd_ptr:
            # Not good
            interrupt = self.read_register(pacific.sbif.dma_err_interrupt_reg)
            print('Read register was not incremented. Interrupt=0x%x' % interrupt)
            return False

        return True

    def extract(self):

        pacific = self.ll_dev.get_pacific_tree()

        # Find the address of the new descriptor
        raw_wr_ptr = self.read_register(pacific.sbif.ext_dma_wr_pd_ptr_reg[self.interface])
        raw_rd_ptr = self.read_register(pacific.sbif.ext_dma_wr_pd_ptr_reg[self.interface])

        if raw_wr_ptr == self.last_ext_pd_rd_ptr:
            print('No new data', file=sys.stderr)
            return False, None

        wrap_bit = (1 << (PD_PTR_WIDTH - 1))
        rd_ptr = self.last_ext_pd_rd_ptr & ~wrap_bit

        # Read the descriptor - ONLY ONE packet
        pd_addr = self.punt_pd_first_line * CSS_MEM_LINE_WIDTH_BYTES + rd_ptr
        first_line = pd_addr // CSS_MEM_LINE_WIDTH_BYTES
        print('pd_addr=%x first_line=%d' % (pd_addr, first_line))

        line = first_line
        data_addr_lsb = self.read_css_mem(first_line + 0)
        data_addr_msb = self.read_css_mem(first_line + 1)
        data_len = self.read_css_mem(first_line + 2)

        # Check error
        out_bytes = None
        is_err = (data_len & PD_ERR_BIT_INSIDE_SIZE_WORD) != 0
        if is_err:
            print('Err bit set', file=sys.stderr)
        else:
            # Read data
            data_addr = (data_addr_msb << BITS_IN_DWORD) | data_addr_lsb
            print('data_addr=0x%x data_len=%d' % (data_addr, data_len))
            first_line = data_addr // CSS_MEM_LINE_WIDTH_BYTES

            raw = bytes()
            lines_nr = int(ceil(data_len / CSS_MEM_LINE_WIDTH_BYTES))
            print('first_line=%d lines_nr=%d' % (first_line, lines_nr))
            for n in range(lines_nr):
                val = self.read_css_mem(first_line + n)
                raw += bytes(val.to_bytes(length=BYTES_IN_DWORD, byteorder='big'))

            # Convert
            raw16 = packet_dma.complete_to_16(raw)
            n = 0
            line = 0
            out_bytes = bytes()
            while n < len(raw16):
                for i in range(DWORDS_IN_DQWORD):
                    dword_index = DWORDS_IN_DQWORD - 1 - i

                    s = n + dword_index * BYTES_IN_DWORD
                    e = n + (dword_index + 1) * BYTES_IN_DWORD
                    val = int.from_bytes(raw16[s:e], byteorder='big') & DWORD_MASK
                    out_bytes += bytes(val.to_bytes(length=BYTES_IN_DWORD, byteorder='big'))
                    line += 1
                n += 16

        # Increment the read pointer
        self.write_register(pacific.sbif.ext_dma_pd_ptr_reg[self.interface], raw_wr_ptr)
        self.last_ext_pd_rd_ptr = raw_wr_ptr

        return not is_err, out_bytes


def run_test(la_dev):

    ENTRY_PUNT_DATA_BASE_OFFSET_BYTES = 0
    ENTRY_PUNT_PD_BASE_OFFSET_BYTES = ENTRY_PUNT_DATA_BASE_OFFSET_BYTES + 2 * BUFFER_SIZE_BYTES
    ENTRY_INJECT_DATA_BASE_OFFSET_BYTES = ENTRY_PUNT_PD_BASE_OFFSET_BYTES + 2 * BUFFER_SIZE_BYTES
    ENTRY_INJECT_PD_BASE_OFFSET_BYTES = ENTRY_INJECT_DATA_BASE_OFFSET_BYTES + 2 * BUFFER_SIZE_BYTES

    EXIT_PUNT_DATA_BASE_OFFSET_BYTES = ENTRY_INJECT_PD_BASE_OFFSET_BYTES + 2 * BUFFER_SIZE_BYTES
    EXIT_PUNT_PD_BASE_OFFSET_BYTES = EXIT_PUNT_DATA_BASE_OFFSET_BYTES + 2 * BUFFER_SIZE_BYTES
    EXIT_INJECT_DATA_BASE_OFFSET_BYTES = EXIT_PUNT_PD_BASE_OFFSET_BYTES + 2 * BUFFER_SIZE_BYTES
    EXIT_INJECT_PD_BASE_OFFSET_BYTES = EXIT_INJECT_DATA_BASE_OFFSET_BYTES + 2 * BUFFER_SIZE_BYTES

    ll_dev = la_dev.get_ll_device()

    entry_dev_dma = packet_dma(ll_dev, ENTRY_PUNT_DATA_BASE, ENTRY_PUNT_PD_BASE, ENTRY_INJECT_DATA_BASE, ENTRY_INJECT_PD_BASE)
    entry_dev_dma.configure()

    exit_dev_dma = packet_dma(ll_dev, EXIT_PUNT_DATA_BASE, EXIT_PUNT_PD_BASE, EXIT_INJECT_DATA_BASE, EXIT_INJECT_PD_BASE)
    exit_dev_dma.configure()

    in_packet = 0x11111111222222223333333344444444  # 16 bytes - same as the PD, so that PD and data pointers are the same

    is_success = entry_dev_dma.inject(in_packet)
    if not is_success:
        print('Error: inject failed', file=sys.stderr)
        return False

    time.sleep(1)

    is_success, out_packet = exit_dev_dma.extract()
    if not is_success:
        print('Error: inject failed', file=sys.stderr)
        return False

    is_identical = compare_packets(in_packet, out_packet)
    if not is_identical:
        print('Error: packets differ', file=sys.stderr)
        print(out_packet)
        return False
