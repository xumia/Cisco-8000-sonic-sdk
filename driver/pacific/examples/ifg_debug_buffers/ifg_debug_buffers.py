# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import random
from leaba import sdk
from bit_utils import set_bits, get_bits, get_bit, set_bit


class ifg2rxpp_fragment(object):
    __slots__ = [
        'sop',
        'eop',
        'frag_size',
        'reassembly_context',
        'err_flag',
        'crc_err',
        'rx_time',
        'source_pif',
        'rcy_code',
        'tx_to_rx_rcy_data',
        'initial_tc',
        'frag_data0',
        'frag_data1',
        'frag_data2',
        't_cnt']


class ifg2rxpp_packet(object):
    __slots__ = [
        'data',
        'reassembly_context',
        'err_flag',
        'crc_err',
        'rx_time',
        'source_pif',
        'rcy_code',
        'tx_to_rx_rcy_data',
        'initial_tc',
        'length']


def send_continuous_traffic(debug_device, ll_dev, sid, ifg_id, port, nof_lanes, length, time_ms,
                            ifgb_regs, npu_regs=None, in_packet=None):
    # Set End Add To 0
    set_ifgb_tx_debug_buffer_end_addr(debug_device, 0, ifgb_regs)
    config_tx_debug_buffer(debug_device, sid, ifg_id, port, nof_lanes, ifgb_regs)
    time.sleep(0.01)

    # Enable Rx Dbg Buffer
    set_ifgb_rx_debug_buffer_capture_all(debug_device, ll_dev, 1, ifgb_regs)
    set_ifgb_rx_debug_buffer_capture_enable(debug_device, ll_dev, "CAPTURE_AND_BLOCK", ifgb_regs, npu_regs)

    # Write To Tx Buffer
    txpp_dbg_buf_pkt = write_packet_to_tx_debug_buffer(debug_device, port, length, ifgb_regs=ifgb_regs, in_packet=in_packet)
    set_ifgb_tx_debug_buffer_num_of_iterations(debug_device, 0, ifgb_regs)
    time.sleep(0.01)
    set_ifgb_tx_debug_buffer_start(debug_device, ifgb_regs)
    time.sleep(time_ms / 1000)
    set_ifgb_tx_debug_buffer_stop(debug_device, ifgb_regs)

    # Clear Rx Dbg Buffer

    entry_cnt = ll_dev.read_register(ifgb_regs.rx_dbg_buf_status)
    if entry_cnt == 0:
        print("ERROR: rx debug buffer count is 0")
        return 1

    while(entry_cnt != 0):
        for i in range(9):
            ll_dev.read_register(ifgb_regs.rx_dbg_buf_rdata[i])
        entry_cnt = ll_dev.read_register(ifgb_regs.rx_dbg_buf_status)


def send_X_iterations_traffic(debug_device, ll_dev, sid, ifg_id, port, nof_lanes, len, iter_cnt,
                              enable_rx_debug=1, packet=-1, padd_size=0, ifgb_regs=None,
                              npu_regs=None, in_packet=None):

    # set End Addr to 0
    set_ifgb_tx_debug_buffer_end_addr(debug_device, 0, ifgb_regs)
    config_tx_debug_buffer(debug_device, sid, ifg_id, port, nof_lanes, ifgb_regs)
    time.sleep(0.01)

    # enable RX DBG Buffer
    if (enable_rx_debug == 1):
        set_ifgb_rx_debug_buffer_capture_all(debug_device, ll_dev, 1, ifgb_regs)
        if ll_dev.get_device_revision() in [sdk.la_device_revision_e_ASIC4_A0,
                                            sdk.la_device_revision_e_ASIC3_A0]:
            set_ifgb_rx_debug_buffer_capture_enable(debug_device, ll_dev, "CAPTURE",
                                                    ifgb_regs, npu_regs)

    # write to TX Buffer
    txpp_dbg_buf_pkt = write_packet_to_tx_debug_buffer(
        debug_device, port, len, packet, padd_size, ifgb_regs=ifgb_regs, in_packet=in_packet)
    set_ifgb_tx_debug_buffer_num_of_iterations(debug_device, iter_cnt, ifgb_regs)
    time.sleep(0.01)
    set_ifgb_tx_debug_buffer_start(debug_device, ifgb_regs)  # Start PKT tramsmit
    set_ifgb_tx_debug_buffer_stop(debug_device, ifgb_regs)   # Clear TX DBG Buffer Start bit
    time.sleep(0.01)

    # clear RX DBG Buffer
    if (enable_rx_debug == 1):
        entry_cnt = debug_device.read_register(ifgb_regs.rx_dbg_buf_status)
        if entry_cnt.dbg_buf_status == 0:
            print("ERROR: Nothing received on RX DEBUG buffer")
            return 1

        prev_entry_cnt = 0
        while(entry_cnt.dbg_buf_status != 0):
            if (entry_cnt.dbg_buf_status != prev_entry_cnt):
                print("dbg_buf_status: %d" % (entry_cnt.dbg_buf_status))

            for i in range(9):
                debug_device.read_register(ifgb_regs.rx_dbg_buf_rdata[i])
            prev_entry_cnt = entry_cnt.dbg_buf_status
            entry_cnt = debug_device.read_register(ifgb_regs.rx_dbg_buf_status)

    print("send_X_iterations_traffic: Completed RC: {}".format(entry_cnt))


def send_and_compare_single_packet(debug_device, ll_dev, sid, ifg_id, port, nof_lanes, len,
                                   ifgb_regs, npu_regs=None, in_packet=None):
    # set End Addr to 0
    set_ifgb_tx_debug_buffer_end_addr(debug_device, 0, ifgb_regs)
    config_tx_debug_buffer(debug_device, sid, ifg_id, port, nof_lanes, ifgb_regs)

    # enable RX DBG Buffer
    set_ifgb_rx_debug_buffer_capture_source(debug_device, ll_dev, port, ifgb_regs)
    set_ifgb_rx_debug_buffer_capture_enable(debug_device, ll_dev, "CAPTURE_AND_BLOCK",
                                            ifgb_regs, npu_regs)

    # write pkt to TX Buffer, and transmit
    txpp_dbg_buf_pkt = write_packet_to_tx_debug_buffer(debug_device, port, len, ifgb_regs=ifgb_regs, in_packet=in_packet)
    set_ifgb_tx_debug_buffer_num_of_iterations(debug_device, 1, ifgb_regs)
    set_ifgb_tx_debug_buffer_start(debug_device, ifgb_regs)  # Start PKT tramsmit
    set_ifgb_tx_debug_buffer_stop(debug_device, ifgb_regs)  # Clear TX DBG Buffer Start bit

    # read Packet from RX DBG Buffer
    rxpp_dbg_buf_pkt = read_packet_from_rx_debug_buffer(debug_device, ll_dev, len, port,
                                                        ifgb_regs, npu_regs)
    if (rxpp_dbg_buf_pkt is None):
        print("ERROR: didn't get rxpp_dbg_buff_pkt")
        return 1

    print("TXPP_PKT:: %s" % (hex(txpp_dbg_buf_pkt)))
    print("RXPP_PKT:: %s" % (hex(get_bits(rxpp_dbg_buf_pkt.data, 8 * len - 1, 0))))

    # Compare TX to RX DBG Buffers
    for i in range(len):
        rxbyte = get_bits(rxpp_dbg_buf_pkt.data, len * 8 - 8 * i - 1, len * 8 - 8 * (i + 1))
        txbyte = get_bits(txpp_dbg_buf_pkt, len * 8 - 8 * i - 1, len * 8 - 8 * (i + 1))
        if (rxbyte != txbyte):
            print("ERROR: first byte mismatch at offset %0d: rx=%s tx=%s"
                  % (i, hex(rxbyte), hex(txbyte)))
            return 1
    else:  # no mismatch found:
        print("pkt comparison successful!")
    return 0


def config_tx_debug_buffer(debug_device, sid, ifg_id, port, lanes, ifgb_regs):
    if debug_device.ll_device.is_asic5():
        # start the tx and stop anything going to txpp
        tx_ctrl_reg = debug_device.read_register(
            ifgb_regs.mscdsc_core[port // 2].pkt_gen_tx_ctrl)
        if (port % 2):
            tx_ctrl_reg.pkt_gen_tx_chan_en = 0x0100
        else:
            tx_ctrl_reg.pkt_gen_tx_chan_en = 0x0001
        debug_device.write_register(
            ifgb_regs.mscdsc_core[port // 2].pkt_gen_tx_ctrl, tx_ctrl_reg)
        return

    # Set buffer enable
    # (TXPP isolation and all TX debug buffer logic out of reset)
    set_ifgb_tx_debug_buffer_enable(debug_device, 0, ifgb_regs)
    set_ifgb_tx_debug_buffer_enable(debug_device, 1, ifgb_regs)

    # Clear credit init, before configuration
    tx_debug_buff1_reg = debug_device.read_register(ifgb_regs.tx_debug_buff1)
    tx_debug_buff1_reg.tx_debug_buff_credit_inf_init = 0x0
    debug_device.write_register(ifgb_regs.tx_debug_buff1, tx_debug_buff1_reg)

    # Load default ports credits (set value >= 4 even for non existing ports,
    # leave at default and load)
    tx_debug_buff1_reg = debug_device.read_register(ifgb_regs.tx_debug_buff1)
    tx_debug_buff1_reg.tx_debug_buff_credit_val = 42
    debug_device.write_register(ifgb_regs.tx_debug_buff1, tx_debug_buff1_reg)

    # Load credit value
    tx_debug_buff1_reg = debug_device.read_register(ifgb_regs.tx_debug_buff1)
    if debug_device.ll_device.is_gibraltar() or debug_device.ll_device.is_pacific():
        tx_debug_buff1_reg.tx_debug_buff_credit_inf_init = 0xFFFFF
    else:
        tx_debug_buff1_reg.tx_debug_buff_credit_inf_init = 0x7FFFFFFFF
    debug_device.write_register(ifgb_regs.tx_debug_buff1, tx_debug_buff1_reg)

    # Clear credit init, after configuration
    tx_debug_buff1_reg = debug_device.read_register(ifgb_regs.tx_debug_buff1)
    tx_debug_buff1_reg.tx_debug_buff_credit_inf_init = 0x0
    debug_device.write_register(ifgb_regs.tx_debug_buff1, tx_debug_buff1_reg)

    # Load port credit (132 credits per lane)
    # 66(rows/lane) * 32(flits/row) / 16(flit/creadit) = 132 (creadit/lane)
    tx_debug_buff1_reg = debug_device.read_register(ifgb_regs.tx_debug_buff1)
    if debug_device.ll_device.is_gibraltar() or debug_device.ll_device.is_pacific():
        tx_debug_buff1_reg.tx_debug_buff_credit_val = lanes * 132
    else:
        tx_debug_buff1_reg.tx_debug_buff_credit_val = lanes * 72
    debug_device.write_register(ifgb_regs.tx_debug_buff1, tx_debug_buff1_reg)

    # Load credit value
    tx_debug_buff1_reg = debug_device.read_register(ifgb_regs.tx_debug_buff1)
    tx_debug_buff1_reg.tx_debug_buff_credit_inf_init = 1 << port
    debug_device.write_register(ifgb_regs.tx_debug_buff1, tx_debug_buff1_reg)

    # Clear credit init, after configuration
    tx_debug_buff1_reg = debug_device.read_register(ifgb_regs.tx_debug_buff1)
    tx_debug_buff1_reg.tx_debug_buff_credit_inf_init = 0x0
    debug_device.write_register(ifgb_regs.tx_debug_buff1, tx_debug_buff1_reg)


def write_packet_to_tx_debug_buffer(debug_device, dest_pif, length, packet=-1, padd_size=0, ifgb_regs=None, in_packet=None):
    if debug_device.ll_device.is_gibraltar() or debug_device.ll_device.is_pacific():
        return write_packet_to_tx_debug_buffer_pac_gb(debug_device, dest_pif, length, packet, padd_size, ifgb_regs)
    elif debug_device.ll_device.is_asic5():
        return write_packet_to_tx_debug_buffer_asic5(
            debug_device,
            dest_pif,
            length,
            packet,
            padd_size,
            ifgb_regs)
    else:
        return write_packet_to_tx_debug_buffer_gr_pl(
            debug_device,
            dest_pif,
            length,
            packet,
            padd_size,
            ifgb_regs,
            in_packet=in_packet)


def write_packet_to_tx_debug_buffer_asic5(debug_device, dest_pif, length, packet=-1, padd_size=0, ifgb_regs=None):
    txpp_packet_data = 0  # Data sent

    if (length > 8192):
        raise Exception("Error: Length is larger than 8192B")
    else:
        print("Write packet of length %s" % (length))

    if (packet == -1):
        # for Asic5, packet has to reach NPU, so it is better to look like a packet rather than random data
        packet = 0x22222222222244444444444408004500004c000100008006a15b0c0c0c0a404040fa001400500000000000000000500220006265000030313233343536373839

    bld_cfg_buf_reg = debug_device.read_register(ifgb_regs.tx_core.build_config_buffers)
    # can get the number of lines and number of banks
    # even maclanes get 0, odd maclanes get number of lines / 2
    tx_num_banks = bld_cfg_buf_reg.tx_num_banks
    tx_buf_lines = bld_cfg_buf_reg.tx_buf_lines
    # number of descriptor entries per ifg interface in multiples of 256
    tx_dscr_ent  = bld_cfg_buf_reg.tx_dscr_ent

    if (tx_num_banks != 20):
        print("Num banks = %0d make it 20 instead" % (tx_num_banks))
        tx_num_banks = 20
    if (tx_buf_lines < 14):
        # the hardware should have it as 14 ( 14 x 256 = 3584)
        # 36 maclanes x 16 (multiples of 16) x 6 buffer units = 3584
        print("Buf lines = %0d make it 14 instead" % (tx_buf_lines))
        tx_buf_lines = 14
    # save a variable by reusing tx_buf_lines
    # multiply the register value by 256
    tx_buf_lines = tx_buf_lines * 256

    if (tx_dscr_ent != 12):
        print("Descr lines = %0d make it 12 instead" % (tx_dscr_ent))
        tx_dscr_ent = 12
    # multiply the register value by 256
    tx_dscr_ent = tx_dscr_ent * 256

    # it is a 1:1  mapping of pif to maclane
    # so it is 6 buffers x 16 x maclane (or pif) should be tx pif
    # using dest_pif as transmit_pif
    tx_line_start = dest_pif * 6 * 16

    t_length = length   # in bytes
    d_length = length   # packet length used by descriptors
    tx_line = tx_line_start
    tx_bank = 0
    line_length = 16 * tx_num_banks  # fixed line length in bytes

    dbg_control_reg = debug_device.read_register(ifgb_regs.tx_core.debug_control)
    dbg_mem_acc_reg = debug_device.read_register(ifgb_regs.tx_core.debug_mem_access)
    tx_mem_data_reg = debug_device.read_register(ifgb_regs.tx_core.debug_tx_data_mem_data)

    # descriptor info
    sop = 1
    eop = 0

    # eop_size is bytes in last word subtract 1
    # default this value to 16 - 1
    eop_size = 15

    dsc_count = 0
    # descriptor word count, 16 bytes per word
    dsc_wd_count = 0
    # descriptor address, odd maclane uses the upper half
    dsc_addr = 0
    if (dest_pif % 2):
        dsc_addr = tx_dscr_ent // 2

    # read and zero out other fields
    core_dbg_control_reg = debug_device.read_register(ifgb_regs.mscdsc_core[dest_pif // 2].debug_control)
    core_dbg_control_reg.dbg_rx_dsc_rd_sel = 0
    core_dbg_control_reg.dbg_rx_dsc_rd_en = 0
    core_dbg_control_reg.dbg_tx_dsc_rd_sel = 0
    core_dbg_control_reg.dbg_tx_dsc_rd_en = 0

    # zero out the descriptor
    core_dsc_mem = debug_device.read_register(ifgb_regs.mscdsc_core[dest_pif // 2].debug_tx_dsc_mem_data)
    dsc_mem = 0

    core_dbg_mem_acc_reg = debug_device.read_register(ifgb_regs.mscdsc_core[dest_pif // 2].debug_mem_access)

    done = 0
    while t_length > 0:
        # set SOP/EOP/SIZE
        line_size = t_length if (t_length <= line_length) else line_length  # SET SIZE

        print("Asic5 sop = %0d eop = %0d line_size = %0d line_length = %0d" %
              (sop, eop, line_size, line_length))

        # SET WD & DATA
        if (packet == -1):
            print("Line size is %d" % line_size)
            line_data = [random.choice(["1", "0"]) for i in range(line_size * 8)]
            # make the line_data beginning and end have a 1
            line_data[0] = line_data[line_size * 8 - 1] = "1"
            # convert line_data into integer
            line_data = int(''.join(line_data), 2)
        else:
            if (t_length > padd_size):
                # grabbing the msb of the packet
                line_data = get_bits(packet,
                                     (length - padd_size) * 8 - 1,
                                     (length - padd_size - line_size) * 8)

        if (packet == -1):
            if sop == 1:
                # set the start 0x50
                line_data = set_bits(line_data, line_size * 8 - 1, line_size * 8 - 4, 0x5)
                line_data = set_bits(line_data, line_size * 8 - 5, line_size * 8 - 5, 0x0)

        txpp_packet_data = set_bits(txpp_packet_data, t_length * 8 - 1, t_length * 8 - line_size * 8, line_data)

        # most significant bit of the line_data
        msb = line_size * 8 - 1
        done = 0
        while (msb > 0):
            dbg_control_reg.dbg_tx_data_mem_bank = tx_bank
            dbg_control_reg.dbg_tx_data_mem_addr = tx_line

            lsb = 0
            msb_shift = 0
            if (msb >= 128):
                lsb = msb - 127
            else:
                eop_size = ((msb + 1) // 8) - 1
                msb_shift = 127 - msb
                done = 1

            # grab first 8 bytes
            tx_mem_data_reg.dbg_tx_data_mem_wr_data = get_bits(line_data, msb, lsb) << msb_shift
            if (done):
                msb = 0
            else:
                msb = msb - 128

            # write the registers
            debug_device.write_register(ifgb_regs.tx_core.debug_control,
                                        dbg_control_reg)
            debug_device.write_register(ifgb_regs.tx_core.debug_tx_data_mem_data,
                                        tx_mem_data_reg)

            # enable the write
            dbg_mem_acc_reg.dbg_tx_data_mem_wr_en = 1
            debug_device.write_register(ifgb_regs.tx_core.debug_mem_access,
                                        dbg_mem_acc_reg)
            tx_bank += 1
            if (tx_bank >= tx_num_banks):
                tx_bank = 0
                tx_line += 1

            dsc_wd_count += 1

            # check packet length
            if ((d_length > 656) and (dsc_wd_count >= 12)):
                # make a new descriptor
                core_dbg_control_reg.dbg_tx_dsc_mem_addr = dsc_addr
                dsc_mem = 0
                dsc_mem = set_bits(dsc_mem, 67, 67, sop)
                dsc_mem = set_bits(dsc_mem, 60, 55, dsc_wd_count)
                core_dsc_mem.dbg_tx_dsc_mem_wr_data = dsc_mem
                debug_device.write_register(ifgb_regs.mscdsc_core[dest_pif // 2].debug_control,
                                            core_dbg_control_reg)
                debug_device.write_register(ifgb_regs.mscdsc_core[dest_pif // 2].debug_tx_dsc_mem_data,
                                            core_dsc_mem)

                core_dbg_mem_acc_reg.dbg_tx_dsc_mem_wr_en = 1
                debug_device.write_register(ifgb_regs.mscdsc_core[dest_pif // 2].debug_mem_access,
                                            core_dbg_mem_acc_reg)
                print("Asic5 descriptor %d word count %d" % (dsc_addr, dsc_wd_count))

                sop = 0
                dsc_wd_count = 0
                dsc_count += 1
                dsc_addr += 1
                d_length -= (12 * 16)

        t_length -= line_size
        # end while t_length

    # send out the final descriptor
    core_dbg_control_reg.dbg_tx_dsc_mem_addr = dsc_addr
    dsc_mem = 0
    dsc_mem = set_bits(dsc_mem, 67, 67, sop)
    dsc_mem = set_bits(dsc_mem, 66, 66, 1)  # eop
    dsc_mem = set_bits(dsc_mem, 65, 62, eop_size)
    dsc_mem = set_bits(dsc_mem, 60, 55, dsc_wd_count)

    core_dsc_mem.dbg_tx_dsc_mem_wr_data = dsc_mem
    debug_device.write_register(ifgb_regs.mscdsc_core[dest_pif // 2].debug_control,
                                core_dbg_control_reg)
    debug_device.write_register(ifgb_regs.mscdsc_core[dest_pif // 2].debug_tx_dsc_mem_data,
                                core_dsc_mem)

    core_dbg_mem_acc_reg.dbg_tx_dsc_mem_wr_en = 1
    debug_device.write_register(ifgb_regs.mscdsc_core[dest_pif // 2].debug_mem_access,
                                core_dbg_mem_acc_reg)
    dsc_count += 1
    print("Asic5 descriptor %d word count %d" % (dsc_addr, dsc_wd_count))

    pkt_gen_tx_ctrl_reg = debug_device.read_register(
        ifgb_regs.mscdsc_mac[dest_pif // 2].pkt_gen_tx_ctrl)

    # because there are two maclanes per port need to multiply it by 2
    dsc_count = 2 * dsc_count
    pkt_gen_tx_ctrl_reg.pkt_gen_tx_dscr_size = dsc_count
    if (not ((done) and (tx_bank == 0))):
        # part of the tx_line was used, need to increment
        tx_line += 1

    tot_tx_line = tx_line - tx_line_start
    tot_tx_line = 2 * tot_tx_line
    # because there are two maclanes per port need to multiply it by 2
    # tx_line = 2 * tx_line
    pkt_gen_tx_ctrl_reg.pkt_gen_tx_data_size = tot_tx_line
    if (dest_pif % 2):
        pkt_gen_tx_ctrl_reg.pkt_gen_tx_chan_en = 0x0100
    else:
        pkt_gen_tx_ctrl_reg.pkt_gen_tx_chan_en = 0x0001
    print("Asic5 sop %0d dsc_count %0d total tx_line = %0d " % (sop, dsc_count, tot_tx_line))
    debug_device.write_register(ifgb_regs.mscdsc_mac[dest_pif // 2].pkt_gen_tx_ctrl,
                                pkt_gen_tx_ctrl_reg)

    # in asic5, the tx is continuous so need to stop it
    pkt_gen_tx_ctrl_reg.pkt_gen_tx_chan_en = 0
    debug_device.write_register(ifgb_regs.mscdsc_mac[dest_pif // 2].pkt_gen_tx_ctrl,
                                pkt_gen_tx_ctrl_reg)

    # disable in mscdsc_core as well
    tx_ctrl_reg = debug_device.read_register(
        ifgb_regs.mscdsc_core[dest_pif // 2].pkt_gen_tx_ctrl)
    tx_ctrl_reg.pkt_gen_tx_chan_en = 0
    debug_device.write_register(
        ifgb_regs.mscdsc_core[dest_pif // 2].pkt_gen_tx_ctrl, tx_ctrl_reg)

    print("Write packet of length %s - DONE" % (length))
    return txpp_packet_data


# define TXPP2IFG_TX_WORD_BITS  1535:0
# define TXPP2IFG_PACKET_DATA_WIDTH 1536
# define TXPP2IFG_WD_WIDTH 39
# DEBUG BUFFER IS (1024+39)*64 - MAX PACKET LENGTH is 192B*64


def write_packet_to_tx_debug_buffer_gr_pl(debug_device, dest_pif, length, packet=-1, padd_size=0, ifgb_regs=None, in_packet=None):
    txpp_packet_data = 0  # Data sent
    wd_bits = 0  # 18 bits
    pd_bits = 0  # 37 bits
    word_data = 0  # 1536 bits
    mem_entry = 0  # 1591 bits
    sop = 0
    eop = 0
    word_size = 0
    invert_crc = 0
    ts_op = 0
    ts_csum_update = 0
    ts_os = 0
    ts_phase = 0
    start_packing = 0
    unsch_rcy_code = 0
    tx_to_rx_rcy_data = 0
    ar_meter = 0

    if (length > 8192):
        raise Exception("Error: Length is larger than 8192B")
    else:
        print("Write packet of length %s" % (length))

    tx_debug_buff1_reg = debug_device.read_register(ifgb_regs.tx_debug_buff1)
    prev_addr = tx_debug_buff1_reg.tx_debug_buff_end_addr

    end_addr = length // 192
    if length % 192 == 0:
        end_addr -= 1
    if prev_addr != 0:
        prev_addr += 1
    set_ifgb_tx_debug_buffer_end_addr(debug_device, prev_addr + end_addr, ifgb_regs)

    t_length = length
    wr_addr = prev_addr

    while t_length > 0:
        # set SOP/EOP/SIZE
        sop = 1 if (t_length == length) else 0  # SET SOP
        eop = 1 if (t_length <= 192) else 0  # SET EOP
        word_size = t_length if (t_length <= 192) else 192  # SET SIZE
        print("[MM] sop = %0d, eop = %0d, word_size = %0d" % (sop, eop, word_size))

        # SET WD & DATA
        if in_packet is not None:
            word_data = in_packet
        else:
            if (packet == -1):
                print("Word size is %d" % word_size)
                word_data = [random.choice(["1", "0"]) for i in range(word_size * 8)]
                word_data[0] = word_data[word_size * 8 - 1] = "1"
                word_data = int(''.join(word_data), 2)

            else:
                if (t_length > padd_size):
                    word_data = get_bits(packet, (length - padd_size) * 8 - 1, (length - padd_size - 192) * 8)
            if (packet == -1):
                if sop == 1:
                    word_data = set_bits(word_data, word_size * 8 - 1, word_size * 8 - 4, 0x5)
                if sop == 1:
                    word_data = set_bits(word_data, word_size * 8 - 5, word_size * 8 - 5, 0x0)

        txpp_packet_data = set_bits(txpp_packet_data, t_length * 8 - 1, t_length * 8 - word_size * 8, word_data)

        wd_bits = set_bits(wd_bits, 0, 0, sop)
        wd_bits = set_bits(wd_bits, 1, 1, eop)
        wd_bits = set_bits(wd_bits, 10, 2, word_size)
        wd_bits = set_bits(wd_bits, 11, 11, invert_crc)
        wd_bits = set_bits(wd_bits, 17, 12, dest_pif)

        pd_bits = set_bits(pd_bits, 11, 0, ts_op)
        pd_bits = set_bits(pd_bits, 12, 12, start_packing)
        pd_bits = set_bits(pd_bits, 16, 13, unsch_rcy_code)
        pd_bits = set_bits(pd_bits, 24, 17, tx_to_rx_rcy_data)
        pd_bits = set_bits(pd_bits, 25, 25, ar_meter)

        # CREATE MEM ENTRY
        mem_entry = set_bits(mem_entry, 1553, 1536, wd_bits)  # 18 bits
        mem_entry = set_bits(mem_entry, 1590, 1554, pd_bits)  # 37 bits
        mem_entry = set_bits(mem_entry, 1536 - 1, 1536 - word_size * 8, word_data)

        print("Write to tx_debug_buffer @ %s" % (wr_addr))
        print("wd_bits %s" % (hex(wd_bits)))
        print("data %s" % (hex(word_data)))
        print("msb %s, lsb %s" % (t_length * 8 - 1, t_length * 8 - word_size * 8))
        # lb_note("")

        debug_device.write_memory(ifgb_regs.tx_debug_mem, wr_addr, mem_entry)
        print("########## TX BUFFER VALUE: %s" % debug_device.read_memory(ifgb_regs.tx_debug_mem, 0))
        wr_addr += 1
        t_length -= word_size
    # end while

    print("Write packet of length %s - DONE" % (length))
    return txpp_packet_data


# define TXPP2IFG_TX_WORD_BITS  1535:0
# define TXPP2IFG_PACKET_DATA_WIDTH 1536
# define TXPP2IFG_WD_WIDTH 39
# DEBUG BUFFER IS (1024+39)*64 - MAX PACKET LENGTH is 128B*64 = 8192B
def write_packet_to_tx_debug_buffer_pac_gb(debug_device, dest_pif, length, packet=-1, padd_size=0, ifgb_regs=None):
    txpp_packet_data = 0  # Data sent
    wd_bits = 0  # 39 bits
    word_data = 0  # 1024 bits
    mem_entry = 0  # 1063 bits
    sop = 0
    eop = 0
    word_size = 0
    invert_crc = 0
    ts_op = 0
    ts_csum_update = 0
    ts_os = 0
    ts_phase = 0
    start_packing = 0
    unsch_rcy_code = 0
    tx_to_rx_rcy_data = 0
    ar_meter = 0

    if (length > 8192):
        print("ERROR: Length is larger than 8192B")
    else:
        print("Write packet of length %s" % (length))

    tx_debug_buff1_reg = debug_device.read_register(ifgb_regs.tx_debug_buff1)
    prev_addr = tx_debug_buff1_reg.tx_debug_buff_end_addr

    end_addr = length // 128
    if length % 128 == 0:
        end_addr -= 1
    if prev_addr != 0:
        prev_addr += 1
    set_ifgb_tx_debug_buffer_end_addr(debug_device, prev_addr + end_addr, ifgb_regs)

    t_length = length
    wr_addr = prev_addr

    while t_length > 0:
        # set SOP/EOP/SIZE
        sop = 1 if (t_length == length) else 0  # SET SOP
        eop = 1 if (t_length <= 128) else 0  # SET EOP
        word_size = t_length if (t_length <= 128) else 128  # SET SIZE
        print("[MM] sop = %0d, eop = %0d, word_size = %0d" % (sop, eop, word_size))

        # SET WD & DATA
        if (packet == -1):
            # word_data = secrets.randbits(word_size*8)
            word_data = random.randint(0, 1 << (word_size * 8))
        else:
            if (t_length > padd_size):
                word_data = get_bits(packet, (length - padd_size) * 8 - 1, (length - padd_size - 128) * 8)
        if (packet == -1):
            if sop == 1:
                word_data = set_bits(word_data, word_size * 8 - 1, word_size * 8 - 4, 0x5)
            if sop == 1:
                word_data = set_bits(word_data, word_size * 8 - 5, word_size * 8 - 5, 0x0)
        txpp_packet_data = set_bits(txpp_packet_data, t_length * 8 - 1, t_length * 8 - word_size * 8, word_data)
        wd_bits = set_bits(wd_bits, 0, 0, sop)
        wd_bits = set_bits(wd_bits, 1, 1, eop)
        wd_bits = set_bits(wd_bits, 9, 2, word_size)
        wd_bits = set_bits(wd_bits, 10, 10, invert_crc)
        wd_bits = set_bits(wd_bits, 15, 11, dest_pif)
        wd_bits = set_bits(wd_bits, 17, 16, ts_op)
        wd_bits = set_bits(wd_bits, 18, 18, ts_csum_update)
        wd_bits = set_bits(wd_bits, 25, 19, ts_os)
        wd_bits = set_bits(wd_bits, 26, 26, ts_phase)
        wd_bits = set_bits(wd_bits, 27, 27, start_packing)
        wd_bits = set_bits(wd_bits, 29, 28, unsch_rcy_code)
        wd_bits = set_bits(wd_bits, 37, 30, tx_to_rx_rcy_data)
        wd_bits = set_bits(wd_bits, 38, 38, ar_meter)

        # CREATE MEM ENTRY
        mem_entry = set_bits(mem_entry, 1062, 1024, wd_bits)
        # mem_entry = set_bits(mem_entry,word_size*8-1,0,word_data)
        mem_entry = set_bits(mem_entry, 1024 - 1, 1024 - word_size * 8, word_data)

        print("Write to tx_debug_buffer @ %s" % (wr_addr))
        print("wd_bits %s" % (hex(wd_bits)))
        print("data %s" % (hex(word_data)))
        print("msb %s, lsb %s" % (t_length * 8 - 1, t_length * 8 - word_size * 8))
        # lb_note("")

        debug_device.write_memory(ifgb_regs.tx_debug_mem, wr_addr, mem_entry)
        wr_addr += 1
        t_length -= word_size
    # end while

    print("Write packet of length %s - DONE" % (length))
    return txpp_packet_data


def set_ifgb_tx_debug_buffer_enable(debug_device, value, ifgb_regs):
    if debug_device.ll_device.is_asic5():
        return
    print("Enable tx debug buffer %s" % (value))
    tx_debug_buff0_reg = debug_device.read_register(ifgb_regs.tx_debug_buff0)
    tx_debug_buff0_reg.tx_debug_buff_en = value
    # TODO remove: for now succeeded to enable with this bit set only
    tx_debug_buff0_reg.tx_debug_buff_ignore_tx_credits = 1
    debug_device.write_register(ifgb_regs.tx_debug_buff0, tx_debug_buff0_reg)


def set_ifgb_tx_debug_buffer_start(debug_device, ifgb_regs):
    if debug_device.ll_device.is_asic5():
        return
    print("start tx debug buffer")
    tx_debug_buff0_reg = debug_device.read_register(ifgb_regs.tx_debug_buff0)
    tx_debug_buff0_reg.tx_debug_buff_start = 0
    debug_device.write_register(ifgb_regs.tx_debug_buff0, tx_debug_buff0_reg)
    tx_debug_buff0_reg.tx_debug_buff_start = 1
    debug_device.write_register(ifgb_regs.tx_debug_buff0, tx_debug_buff0_reg)


def set_ifgb_tx_debug_buffer_stop(debug_device, ifgb_regs):
    if debug_device.ll_device.is_asic5():
        return
    tx_debug_buff0_reg = debug_device.read_register(ifgb_regs.tx_debug_buff0)
    tx_debug_buff0_reg.tx_debug_buff_start = 0
    debug_device.write_register(ifgb_regs.tx_debug_buff0, tx_debug_buff0_reg)


def set_ifgb_tx_debug_buffer_num_of_iterations(debug_device, value, ifgb_regs):
    if debug_device.ll_device.is_asic5():
        return
    print("Num of iterations %s" % (value))
    tx_debug_buff0_reg = debug_device.read_register(ifgb_regs.tx_debug_buff0)
    tx_debug_buff0_reg.tx_debug_buff_iter = value
    debug_device.write_register(ifgb_regs.tx_debug_buff0, tx_debug_buff0_reg)


def set_ifgb_tx_debug_buffer_end_addr(debug_device, value, ifgb_regs):
    if debug_device.ll_device.is_asic5():
        return
    print("Debug buffer end addr %s" % value)
    tx_debug_buff1_reg = debug_device.read_register(ifgb_regs.tx_debug_buff1)
    tx_debug_buff1_reg.tx_debug_buff_end_addr = value
    debug_device.write_register(ifgb_regs.tx_debug_buff1, tx_debug_buff1_reg)

############################### RX_DEBUG BUFFER ##########################################


def set_ifgb_rx_debug_buffer_capture_enable(debug_device, ll_dev, type, ifgb_regs, npu_regs=None):
    if debug_device.ll_device.is_asic5():
        # Asic5 might use npu_regs to clear out npu rx packet capture
        return
    value = 0
    if (type == "DISABLE"):
        value = 0
        print("Enable rx debug buffer capture enable DISABLE")
    else:
        if ll_dev.get_device_revision() in [sdk.la_device_revision_e_ASIC4_A0, sdk.la_device_revision_e_ASIC3_A0]:
            value = 1
            print("Enable rx debug buffer")
        else:
            if (type == "CAPTURE"):
                value = 1
                print("Enable rx debug buffer capture enable CAPTURE")
            elif (type == "CAPTURE_AND_BLOCK"):
                value = 2
                print("Enable rx debug buffer capture enable CAPTURE_AND_BLOCK")

    rx_dbg_cfg_reg = debug_device.read_register(ifgb_regs.rx_dbg_cfg)

    if ll_dev.get_device_revision() in [sdk.la_device_revision_e_ASIC4_A0, sdk.la_device_revision_e_ASIC3_A0]:
        rx_dbg_cfg_reg.rx_dbg_buf_enable = value
    else:
        rx_dbg_cfg_reg.dbg_buf_capture_en = value

    debug_device.write_register(ifgb_regs.rx_dbg_cfg, rx_dbg_cfg_reg)


def set_ifgb_rx_debug_buffer_capture_all(debug_device, ll_dev, enable, ifgb_regs):
    if debug_device.ll_device.is_asic5():
        return
    if ll_dev.get_device_revision() in [sdk.la_device_revision_e_ASIC4_A0, sdk.la_device_revision_e_ASIC3_A0]:
        return

    print("Enable rx debug buffer capture all %s" % (enable))
    rx_dbg_cfg_reg = debug_device.read_register(ifgb_regs.rx_dbg_cfg)
    rx_dbg_cfg_reg.dbg_buf_capture_all = enable
    debug_device.write_register(ifgb_regs.rx_dbg_cfg, rx_dbg_cfg_reg)


def set_ifgb_rx_debug_buffer_capture_source(debug_device, ll_dev, src, ifgb_regs):
    if debug_device.ll_device.is_asic5():
        return
    if ll_dev.get_device_revision() in [sdk.la_device_revision_e_ASIC4_A0, sdk.la_device_revision_e_ASIC3_A0]:
        return

    print("Set rx debug buffer capture source %s" % (src))
    rx_dbg_cfg_reg = debug_device.read_register(ifgb_regs.rx_dbg_cfg)
    rx_dbg_cfg_reg.dbg_buf_capture_source = src
    debug_device.write_register(ifgb_regs.rx_dbg_cfg, rx_dbg_cfg_reg)


# define IFG2RXPP_FRAGMENT_BITS  1023:0
# define IFG2RXPP_FRAGMENT_OFFSET 0
# define IFG2RXPP_REAS_CTXT_BITS  9:0
# define IFG2RXPP_REAS_CTXT_OFFSET 0
# define IFG2RXPP_SOP_BITS  10
# define IFG2RXPP_SOP_OFFSET 10
# define IFG2RXPP_EOP_BITS  11
# define IFG2RXPP_EOP_OFFSET 11
# define IFG2RXPP_FRAGMENT_SIZE_BITS  20:12
# define IFG2RXPP_FRAGMENT_SIZE_OFFSET 12
# define IFG2RXPP_EOF_BITS  21
# define IFG2RXPP_EOF_OFFSET 21
# define IFG2RXPP_ERR_FLAG_BITS  22
# define IFG2RXPP_ERR_FLAG_OFFSET 22
# define IFG2RXPP_CRC_ERR_BITS  23
# define IFG2RXPP_CRC_ERR_OFFSET 23
# define IFG2RXPP_RECEIVE_TIME_BITS  62:31
# define IFG2RXPP_RECEIVE_TIME_OFFSET 31
# define IFG2RXPP_SOURCE_PIF_BITS  28:24
# define IFG2RXPP_SOURCE_PIF_OFFSET 24
# define IFG2RXPP_RCY_CODE_BITS  30:29
# define IFG2RXPP_RCY_CODE_OFFSET 29
# define IFG2RXPP_TX_TO_RX_RCY_DATA_BITS  38:31
# define IFG2RXPP_TX_TO_RX_RCY_DATA_OFFSET 31
# define IFG2RXPP_INITIAL_TC_BITS  65:63
# define IFG2RXPP_INITIAL_TC_OFFSET 63
# define IFG2RXPP_PACKET_DATA_WIDTH 1024
# define IFG2RXPP_FD_WIDTH 66

def read_fragment_from_rx_debug_buffer(ll_device, length, ifgb_regs):
    print("read sequence single fragment")
    if ll_device.get_device_revision() in [sdk.la_device_revision_e_ASIC4_A0, sdk.la_device_revision_e_ASIC3_A0]:
        return read_fragment_from_rx_debug_buffer_read_descriptor_gr_pl(ll_device, length, ifgb_regs)
    else:
        return read_fragment_from_rx_debug_buffer_read_descriptor_pac_gb(ll_device, length, ifgb_regs)


def read_fragment_from_rx_debug_buffer_read_descriptor_gr_pl(ll_device, length, ifgb_regs):
    print("read sequence single fragment - Asic3 / Asic4")
    fragment_ongoing = 0
    rx_dbg_buf_rd_data = 0

    # Read all data, according to protocol, build the packets and send to scoreboard.
    fragment_data = 0
    fragment_desc = 0
    first_fragment_desc = []
    rx_data = []
    for i in range(8):
        rx_mem_data = '0' * 1611
        rx_mem_data = list(rx_mem_data)

        rx_mem_data[(2 - 2) * 537: 537] = list('{0:0537b}'.format(ll_device.read_memory(ifgb_regs.rx_debug_mem2, i)))
        print("rx_data for 2 rx_mem_data set {}\n".format(hex(int(''.join(rx_mem_data[(2 - 2) * 537: 537]), 2))))

        rx_mem_data[(2 - 1) * 537: (3 - 1) * 537] = list('{0:0537b}'.format(ll_device.read_memory(ifgb_regs.rx_debug_mem1, i)))
        print("rx_data for 1 rx_mem_data set {}\n".format(hex(int(''.join(rx_mem_data[(2 - 1) * 537: (3 - 1) * 537]), 2))))

        rx_mem_data[(2 - 0) * 537:(3 - 0) * 537] = list('{0:0537b}'.format(ll_device.read_memory(ifgb_regs.rx_debug_mem0, i)))
        print("rx_data for 0 rx_mem_data set {}\n".format(hex(int(''.join(rx_mem_data[(2 - 0) * 537:(3 - 0) * 537]), 2))))

        rx_mem_data = ''.join(rx_mem_data)
        first_fragment_desc.append(rx_mem_data)
        if len(first_fragment_desc) * 1615 >= (length + 76):
            first_fragment_desc = ''.join(first_fragment_desc)
            break

    fragment_desc = int(first_fragment_desc, 2)
    fragment_data = get_bits(fragment_desc, 1535, 1536 - length * 8)
    fragment_desc = get_bits(fragment_desc, 1610, 1536)
    first_fragment_desc = fragment_desc

    parse_ifg2rxpp_mem_struct_gr_pl(fragment_desc)

    fd_offset = 34
    pd_offset = 37
    const_offset = fd_offset + pd_offset

    # FD
    sop = get_bits(fragment_desc, 0, 0)
    eop = get_bits(fragment_desc, 1, 1)
    frag_size = get_bits(fragment_desc, 10, 2)
    reassembly_context = get_bits(fragment_desc, 27, 17)
    err_flag = get_bits(fragment_desc, 33, 32)
    source_pif = get_bits(fragment_desc, 16, 11)
    rcy_code = get_bits(fragment_desc, 31, 28)

    # PD
    rx_time = get_bits(fragment_desc, 31 + fd_offset, 0 + fd_offset)
    initial_tc = get_bits(fragment_desc, 34 + fd_offset, 32 + fd_offset)
    sub_port = get_bits(fragment_desc, 36 + fd_offset, 35 + fd_offset)

    valid = get_bits(fragment_desc, 0 + const_offset, 0 + const_offset)
    eof = get_bits(fragment_desc, 1 + const_offset, 2 + const_offset)
    dropped = get_bits(fragment_desc, 2 + const_offset, 3 + const_offset)
    prot_event = get_bits(fragment_desc, 3 + const_offset, 4 + const_offset)

    # A single entry is spread on 8 registers, of size 192b, plus 1 valid bit.
    num_of_words = 1 + (frag_size - 1) // 192
    print("fragment num of words %s" % (num_of_words))

    if valid != 1:
        print("ERROR: FD valid is 0")
    # Convert the entry to fragment object
    if(fragment_ongoing == 0):
        fragment = ifg2rxpp_fragment()
        fragment.frag_data0 = fragment_data
        fragment.frag_data1 = 0
        fragment.frag_data2 = 0
        fragment.sop = sop
        fragment.eop = eop
        fragment.frag_size = frag_size
        fragment.reassembly_context = reassembly_context
        fragment.err_flag = err_flag
        fragment.rx_time = rx_time
        fragment.source_pif = source_pif
        fragment.rcy_code = rcy_code
        fragment.initial_tc = initial_tc
        fragment.t_cnt = 1
        fragment_ongoing = 1
        return fragment


def read_fragment_from_rx_debug_buffer_read_descriptor_pac_gb(ll_device, length, ifgb_regs):
    print("read sequence single fragment - pacific / gb")
    fragment_ongoing = 0
    rx_dbg_buf_rd_data = 0

    # Read all data, according to protocol, build the packets and send to scoreboard.
    fragment_data = 0
    fragment_desc = 0
    first_fragment_desc = 0

    rx_dbg_buf_rd_data = ll_device.read_register(ifgb_regs.rx_dbg_buf_rdata[8])
    valid = get_bits(rx_dbg_buf_rd_data, 128, 128)
    if valid != 1:
        print("ERROR: FD valid is 0")
    # Descriptor, not all 128b are used in the status register[8].
    fragment_desc = get_bits(rx_dbg_buf_rd_data, 64, 0)
    first_fragment_desc = fragment_desc

    # Print the entire read fragment element, for debug (use a fragment object).
    parse_ifg2rxpp_fd_pac_gb(fragment_desc)
    sop = get_bits(fragment_desc, 10, 10)
    eop = get_bits(fragment_desc, 11, 11)
    frag_size = get_bits(fragment_desc, 20, 12)
    reassembly_context = get_bits(fragment_desc, 9, 0)
    err_flag = get_bits(fragment_desc, 22, 22)
    crc_err = get_bits(fragment_desc, 23, 23)
    rx_time = get_bits(fragment_desc, 62, 31)
    source_pif = get_bits(fragment_desc, 28, 24)
    rcy_code = get_bits(fragment_desc, 30, 29)
    tx_to_rx_rcy_data = get_bits(fragment_desc, 38, 31)
    initial_tc = get_bits(fragment_desc, 65, 63)
    eof = get_bits(fragment_desc, 21, 21)

    # A single entry is spread on 8 registers, of size 128b, plus 1 valid bit.
    num_of_words = 1 + (frag_size - 1) // 128
    print("fragment num of words %s" % (num_of_words))

    for word_num in range(0, num_of_words):
        if word_num > 0:
            rx_dbg_buf_rd_data = ll_device.read_register(ifgb_regs.rx_dbg_buf_rdata[8])
            valid = get_bits(rx_dbg_buf_rd_data, 128, 128)
            if valid != 1:
                print("ERROR: FD valid is 0")
            # Descriptor, not all 128b are used in the status register[8].
            fragment_desc = get_bits(rx_dbg_buf_rd_data, 64, 0)
            eof = get_bits(fragment_desc, 21, 21)
            parse_ifg2rxpp_fd(fragment_desc)
            check_ongoing_desc_is_valid(fragment_desc, first_fragment_desc)

        for j in range(7, -1, -1):
            rx_dbg_buf_rd_data = ll_device.read_register(ifgb_regs.rx_dbg_buf_rdata[j])
            valid = get_bits(rx_dbg_buf_rd_data, 128, 128)
            if (valid):
                data = get_bits(rx_dbg_buf_rd_data, 127, 0)
                print("dbg_buf[%s]: rx_dbg_buf_rd_data = %s" % (j, hex(data)))
                fragment_data = set_bits(fragment_data, (j + 1) * 128 - 1, j * 128, data)
            else:
                print("ERROR: valid is 0")

        # Convert the entry to fragment object
        if(fragment_ongoing == 0):
            print("new rxpp fragment:: size %s, data %s" % (frag_size, hex(fragment_data)))
            fragment = ifg2rxpp_fragment()
            fragment.frag_data0 = 0
            fragment.frag_data1 = 0
            fragment.frag_data2 = 0
            fragment.sop = sop
            fragment.eop = eop
            fragment.frag_size = frag_size
            fragment.reassembly_context = reassembly_context
            fragment.err_flag = err_flag
            fragment.crc_err = crc_err
            fragment.rx_time = rx_time
            fragment.source_pif = source_pif
            fragment.rcy_code = rcy_code
            fragment.tx_to_rx_rcy_data = tx_to_rx_rcy_data
            fragment.initial_tc = initial_tc
            fragment.frag_data0 = fragment_data
            fragment.t_cnt = 1
            fragment_ongoing = 1
        else:
            # Check for a specific case of missing EOF (other cases will fail due to other checks)
            if(word_num == 3):
                print("ERROR: EOF did not assert, fragment elements count is 4")
            if (word_num == 1):
                fragment.frag_data1 = fragment_data
                fragment.t_cnt = 2
            if (word_num == 2):
                fragment.frag_data2 = fragment_data
                fragment.t_cnt = 3

        # Write the fragment upon EOF
        if(eof == 1):
            # Write the fragment to relevant AP
            fragment_ongoing = 0
            if (fragment.t_cnt > 0):
                print("RX debug buffer read fragment data0 %s" % (hex(fragment.frag_data0)))
            if (fragment.t_cnt > 1):
                print("RX debug buffer read fragment data1 %s" % (hex(fragment.frag_data1)))
            if (fragment.t_cnt > 2):
                print("RX debug buffer read fragment data2 %s" % (hex(fragment.frag_data2)))
            return fragment


def get_header_size(debug_device, ll_dev, pif, ifgb_regs):
    header_reg = debug_device.read_register(ifgb_regs.header_size_reg)
    header_size_per_port = {
        0: header_reg.rx_header_size0,
        1: header_reg.rx_header_size1,
        2: header_reg.rx_header_size2,
        3: header_reg.rx_header_size3,
        4: header_reg.rx_header_size4,
        5: header_reg.rx_header_size5,
        6: header_reg.rx_header_size6,
        7: header_reg.rx_header_size7,
        8: header_reg.rx_header_size8,
        9: header_reg.rx_header_size9,
        10: header_reg.rx_header_size10,
        11: header_reg.rx_header_size11,
        12: header_reg.rx_header_size12,
        13: header_reg.rx_header_size13,
        14: header_reg.rx_header_size14,
        15: header_reg.rx_header_size15,
        16: header_reg.rx_header_size16,
        17: header_reg.rx_header_size17
    }
    if ll_dev.get_device_revision() in [
            sdk.la_device_revision_e_GIBRALTAR_A0,
            sdk.la_device_revision_e_GIBRALTAR_A1,
            sdk.la_device_revision_e_GIBRALTAR_A2,
            sdk.la_device_revision_e_ASIC4_A0,
            sdk.la_device_revision_e_ASIC3_A0]:
        header_size_per_port[18] = header_reg.rx_header_size18
        header_size_per_port[19] = header_reg.rx_header_size19
        header_size_per_port[20] = header_reg.rx_header_size20
        header_size_per_port[21] = header_reg.rx_header_size21
        header_size_per_port[22] = header_reg.rx_header_size22
        header_size_per_port[23] = header_reg.rx_header_size23
    if ll_dev.get_device_revision() in [sdk.la_device_revision_e_ASIC4_A0, sdk.la_device_revision_e_ASIC3_A0]:
        header_size_per_port[24] = header_reg.rx_header_size14
        header_size_per_port[25] = header_reg.rx_header_size15
        header_size_per_port[26] = header_reg.rx_header_size26
        header_size_per_port[27] = header_reg.rx_header_size27
        header_size_per_port[28] = header_reg.rx_header_size28
        header_size_per_port[29] = header_reg.rx_header_size29
        header_size_per_port[30] = header_reg.rx_header_size30
        header_size_per_port[31] = header_reg.rx_header_size31

    header_size = header_size_per_port[pif]
    print("Header size: 8 * %s" % (header_size))
    return header_size


def read_packet_from_rx_debug_buffer(debug_device, ll_dev, data_length, port, ifgb_regs, npu_regs=None):
    if debug_device.ll_device.is_asic5():
        # retrieve and print counters from npu
        term_ifg_debug_counters = debug_device.read_register(
            npu_regs.rxpp_term.fi_stage.term_ifg_debug_counters)
        incoming_counter = term_ifg_debug_counters.ifg0_input_sop_counter
        print("RXPP_PKT count:: %d" % (incoming_counter))

        rxpp_term_data = debug_device.get_debug_bus(
            npu_regs.rxpp_term.npe[0].debug_data_select_register,
            npu_regs.rxpp_term.npe[0].debug_data_bus_register,
            2, 64)

        # asic5 data packet capture may need truncation
        data_strhex = str(hex(rxpp_term_data).lstrip("0x"))
        # length in hex and str differ by multiple of 2
        rx_data_length = len(data_strhex) // 2
        if (rx_data_length > data_length):
            print("RXPP_PKT rx data_length %d truncated to data_length %d " % (rx_data_length, data_length))
            # length in hex and str differ by multiple of 2
            trunc_data = data_strhex[0:(2 * data_length)]
            rxpp_term_data = int(trunc_data, 16)

        rxpp_packet = ifg2rxpp_packet()
        rxpp_packet.data = rxpp_term_data
        return rxpp_packet

    # Aggregate the fragment into the packet
    # Reorder the bytes such that lowest index holds the first byte of the packet
    header_size = get_header_size(debug_device, ll_dev, port, ifgb_regs)
    length = data_length + 8 * header_size
    exp_entry_cnt = length // 128
    if length % 128:
        exp_entry_cnt += 1

    print("length %s, exp_entry_cnt %s" % (length, exp_entry_cnt))

    # WAIT FOR PACKET TO BE CAPTURED
    try_cnt = 0
    while True:
        entry_cnt = debug_device.read_register(ifgb_regs.rx_dbg_buf_status)
        try_cnt += 1
        print("RX debug buffer frag count = %s, try_cnt = %s"
              % (entry_cnt.dbg_buf_status, try_cnt))
        if (entry_cnt.dbg_buf_status == exp_entry_cnt) or (try_cnt >= 10):
            break
        time.sleep(1)

    if (entry_cnt.dbg_buf_status != exp_entry_cnt):
        print("ERROR: RX DEBUG BUFFER Entry count: %s != expected: %s"
              % (entry_cnt.dbg_buf_status, exp_entry_cnt))
        if (entry_cnt.dbg_buf_status < exp_entry_cnt):
            return

    # DISABLE CAPTURE
    set_ifgb_rx_debug_buffer_capture_enable(debug_device, ll_dev, "DISABLE", ifgb_regs, npu_regs)

    rxpp_packet = ifg2rxpp_packet()
    rxpp_packet.data = 0
    byte_count = 0
    while (byte_count < length):
        t = ifg2rxpp_fragment()
        t = read_fragment_from_rx_debug_buffer(ll_dev, length, ifgb_regs)
        if t is None:
            print("ERROR: Didn't return rxpp_fragment")
            return

        byte_count = byte_count + t.frag_size
        tfsm128 = t.frag_size % (128 if debug_device.ll_device.is_gibraltar() or debug_device.ll_device.is_pacific() else 192)
        if tfsm128 == 0:
            tfsm128 = 128 if debug_device.ll_device.is_gibraltar() or debug_device.ll_device.is_pacific() else 192

        print("length              %s" % (length))
        print("byte_count          %s" % (byte_count))
        print("t.frag_size         %s" % (t.frag_size))
        print("tfsm128             %s" % (tfsm128))
        print("t.t_cnt             %s" % (t.t_cnt))
        l_frag = 0
        if (t.t_cnt == 1):
            if debug_device.ll_device.is_asic3() or debug_device.ll_device.is_asic4():
                rxpp_packet.data = t.frag_data0
                l_frag = rxpp_packet.data

            else:
                l_frag = get_bits(t.frag_data0, 1024 - 1, 1024 - (tfsm128) * 8)
                print("t_cnt = %s, msb %s, lsb %s" %
                      (t.t_cnt, 8 * (length - byte_count) + tfsm128 * 8 - 1, 8 * (length - byte_count)))
                rxpp_packet.data = set_bits(rxpp_packet.data, 8 * (length - byte_count) +
                                            tfsm128 * 8 - 1, 8 * (length - byte_count), l_frag)
        if (t.t_cnt == 2):
            l_frag = get_bits(t.frag_data1, 1024 - 1, 1024 - (tfsm128) * 8)
            print("t_cnt = %s, msb %s, lsb %s" % (t.t_cnt, 8 * (length - byte_count) +
                                                  1024 + (tfsm128) * 8 - 1, 8 * (length - byte_count) + (tfsm128) * 8))
            print("t_cnt = %s, msb %s, lsb %s" %
                  (t.t_cnt, 8 * (length - byte_count) + (tfsm128) * 8 - 1, 8 * (length - byte_count)))
            rxpp_packet.data = set_bits(rxpp_packet.data, 8 * (length - byte_count) + 1024 + (tfsm128) *
                                        8 - 1, 8 * (length - byte_count) + (tfsm128) * 8, t.frag_data0)
            rxpp_packet.data = set_bits(rxpp_packet.data, 8 * (length - byte_count) +
                                        (tfsm128) * 8 - 1, 8 * (length - byte_count), l_frag)
        if (t.t_cnt == 3):
            l_frag = get_bits(t.frag_data2, 1024 - 1, 1024 - (tfsm128) * 8)
            print("t_cnt = %s, msb %s, lsb %s" % (t.t_cnt,
                                                  8 * (length - byte_count) + 2048 + (tfsm128) * 8 - 1,
                                                  8 * (length - byte_count) + 1024 + (tfsm128) * 8))
            print("t_cnt = %s, msb %s, lsb %s" % (t.t_cnt, 8 * (length - byte_count) +
                                                  1024 + (tfsm128) * 8 - 1, 8 * (length - byte_count) + (tfsm128) * 8))
            print("t_cnt = %s, msb %s, lsb %s" %
                  (t.t_cnt, 8 * (length - byte_count) + (tfsm128) * 8 - 1, 8 * (length - byte_count)))
            rxpp_packet.data = set_bits(rxpp_packet.data, 8 * (length - byte_count) + 2048 + (tfsm128) *
                                        8 - 1, 8 * (length - byte_count) + 1024 + (tfsm128) * 8, t.frag_data0)
            rxpp_packet.data = set_bits(rxpp_packet.data, 8 * (length - byte_count) + 1024 + (tfsm128) *
                                        8 - 1, 8 * (length - byte_count) + (tfsm128) * 8, t.frag_data1)
            rxpp_packet.data = set_bits(rxpp_packet.data, 8 * (length - byte_count) +
                                        (tfsm128) * 8 - 1, 8 * (length - byte_count), l_frag)

        print("l_frag %s" % (hex(l_frag)))
        print("RXPP PACKET TILL NOW")
        print("%s" % (hex(rxpp_packet.data)))

        # SOP
        if(t.sop == 1):
            rxpp_packet.err_flag = t.err_flag
            # rxpp_packet.crc_err = t.crc_err
            rxpp_packet.rx_time = t.rx_time
            rxpp_packet.source_pif = t.source_pif
            rxpp_packet.rcy_code = t.rcy_code
            # rxpp_packet.tx_to_rx_rcy_data = t.tx_to_rx_rcy_data
            rxpp_packet.initial_tc = t.initial_tc
        # Non SOP
        else:
            rxpp_packet.err_flag |= t.err_flag
            # rxpp_packet.crc_err |= t.crc_err

        # Write the packet on EOP
        if(t.eop == 1):
            return rxpp_packet


def parse_ifg2rxpp_fd_pac_gb(data):
    sop = get_bits(data, 10, 10)
    eop = get_bits(data, 11, 11)
    frag_size = get_bits(data, 20, 12)
    reassembly_context = get_bits(data, 9, 0)
    err_flag = get_bits(data, 22, 22)
    crc_err = get_bits(data, 23, 23)
    rx_time = get_bits(data, 62, 31)
    source_pif = get_bits(data, 28, 24)
    rcy_code = get_bits(data, 30, 29)
    tx_to_rx_rcy_data = get_bits(data, 38, 31)
    initial_tc = get_bits(data, 65, 63)
    eof = get_bits(data, 21, 21)
    print("Fragment Descriptor:")
    print("sop                 %s" % (sop))
    print("eop                 %s" % (eop))
    print("frag_size           %s" % (frag_size))
    print("reassembly_context  %s" % (reassembly_context))
    print("err_flag            %s" % (err_flag))
    print("crc_err             %s" % (crc_err))
    print("rx_time             %s" % (rx_time))
    print("source_pif          %s" % (source_pif))
    print("rcy_code            %s" % (rcy_code))
    print("tx_to_rx_rcy_data   %s" % (tx_to_rx_rcy_data))
    print("initial_tc          %s" % (initial_tc))
    print("eof                 %s" % (eof))


def parse_ifg2rxpp_mem_struct_gr_pl(data):
    fd_offset = 34
    pd_offset = 37
    const_offset = fd_offset + pd_offset

    # FD
    sop = get_bits(data, 0, 0)
    eop = get_bits(data, 1, 1)
    frag_size = get_bits(data, 10, 2)
    reassembly_context = get_bits(data, 27, 17)
    err_flag = get_bits(data, 33, 32)
    source_pif = get_bits(data, 16, 11)
    rcy_code = get_bits(data, 31, 28)

    # PD
    rx_time = get_bits(data, 31 + fd_offset, 0 + fd_offset)
    initial_tc = get_bits(data, 34 + fd_offset, 32 + fd_offset)
    sub_port = get_bits(data, 36 + fd_offset, 35 + fd_offset)

    valid = get_bit(data, 0 + const_offset)  # , 0 + const_offset)
    eof = get_bit(data, 1 + const_offset)  # , 1 + const_offset)
    dropped = get_bit(data, 2 + const_offset)  # , 2 + const_offset)
    prot_event = get_bit(data, 3 + const_offset)  # , 3 + const_offset)

    print("Fragment Descriptor:")
    print("sop                 %s" % (sop))
    print("eop                 %s" % (eop))
    print("frag_size           %s" % (frag_size))
    print("reassembly_context  %s" % (reassembly_context))
    print("err_flag            %s" % (err_flag))
    print("source_pif          %s" % (source_pif))
    print("rcy_code            %s" % (rcy_code))

    print("Packet Descriptor: ")
    print("rx_time             %s" % (rx_time))
    print("initial_tc          %s" % (initial_tc))
    print("sub_port            %s" % (sub_port))

    print("Other mem Struct Fields:")
    print("valid               %s" % (valid))
    print("eof                 %s" % (eof))
    print("dropped             %s" % (dropped))
    print("prot_event          %s" % (prot_event))


def parse_txpp2ifg_fd(data):
    sop = get_bits(data, 0, 0)
    eop = get_bits(data, 1, 1)
    word_size = get_bits(data, 9, 2)
    invert_crc = get_bits(data, 10, 10)
    dest_pif = get_bits(data, 15, 11)
    ts_op = get_bits(data, 17, 16)
    ts_csum_update = get_bits(data, 18, 18)
    ts_os = get_bits(data, 25, 19)
    ts_phase = get_bits(data, 26, 26)
    start_packing = get_bits(data, 27, 27)
    unsch_rcy_code = get_bits(data, 29, 28)
    tx_to_rx_rcy_data = get_bits(data, 37, 30)
    ar_meter = get_bits(data, 38, 38)
    print("sop               : %s" % (sop))
    print("eop               : %s" % (eop))
    print("word_size         : %s" % (word_size))
    print("invert_crc        : %s" % (invert_crc))
    print("dest_pif          : %s" % (dest_pif))
    print("ts_op             : %s" % (ts_op))
    print("ts_csum_update    : %s" % (ts_csum_update))
    print("ts_os             : %s" % (ts_os))
    print("ts_phase          : %s" % (ts_phase))
    print("start_packing     : %s" % (start_packing))
    print("unsch_rcy_code    : %s" % (unsch_rcy_code))
    print("tx_to_rx_rcy_data : %s" % (tx_to_rx_rcy_data))
    print("ar_meter          : %s" % (ar_meter))


def check_ongoing_desc_is_valid(fragment_desc, first_fragment_desc):
    fragment_desc = set_bits(fragment_desc, 21, 21, 0)
    first_fragment_desc = set_bits(first_fragment_desc, 21, 21, 0)
    if first_fragment_desc != fragment_desc:
        print("ERROR: descriptor value not const along the words:")
        parse_ifg2rxpp_fd(fragment_desc)
        parse_ifg2rxpp_fd(first_fragment_desc)


def clear_debug_buffers(debug_device, ifgb_regs):
    print("Clearing DEBUG buffers data")
    if debug_device.ll_device.is_asic5():
        return

    print("Clearing TX DEBUG buffer memory")
    rc = debug_device.write_memory(ifgb_regs.tx_debug_mem, 0, 0)

    print("Clearing RX DEBUG nuffer memories")
    if debug_device.ll_device.is_gibraltar() or debug_device.ll_device.is_pacific():
        rc = debug_device.write_register(ifgb_regs.rx_dbg_buf_rdata, 0) or rc
    else:
        for i in range(8):
            rc = debug_device.write_memory(ifgb_regs.rx_debug_mem0, i, 0) or rc
            rc = debug_device.write_memory(ifgb_regs.rx_debug_mem1, i, 0) or rc
            rc = debug_device.write_memory(ifgb_regs.rx_debug_mem2, i, 0) or rc

        dbg_buff_cfg = debug_device.read_register(ifgb_regs.rx_dbg_cfg)
        dbg_buff_cfg.rx_dbg_buf_fif_rstn = 0
        debug_device.write_register(ifgb_regs.rx_dbg_cfg, dbg_buff_cfg)
        time.sleep(2)

        dbg_buff_cfg = debug_device.read_register(ifgb_regs.rx_dbg_cfg)
        dbg_buff_cfg.rx_dbg_buf_enable = 0
        dbg_buff_cfg.rx_dbg_buf_fif_rstn = 1
        debug_device.write_register(ifgb_regs.rx_dbg_cfg, dbg_buff_cfg)

    if rc:
        raise Exception("Error: Failed to clear DEBUG buffers data")

    print("Done clearing DEBUG buffers data")
