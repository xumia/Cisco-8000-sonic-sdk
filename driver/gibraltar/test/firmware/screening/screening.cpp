// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "screening.h"

// Access Engine opcodes
typedef enum { AE_OP_WRITE = 1, AE_OP_READ = 2 } ae_cmd_op_t;

#define AE_STATE_READY 0
#define AE_STATE_BUSY 1
#define AE_STATE_FAIL 2

#ifdef SCREENING_DEBUG
static const uint16_t ae_engine_id = 7; // we work with a single access engine, index 7, just for the kicks.
#endif

static const uint32_t ae_cmd_fifo_entries = 512;
static uint32_t ae_cmd_fifo_w = 0;

struct __attribute__((packed)) reg_status {
    uint32_t active : 1;        // [0:0]
    uint32_t state : 6;         // [6:1]
    uint32_t count : 10;        // [16:7]
    uint32_t error : 1;         // [17:17]
    uint32_t err_block_id : 12; // [30:18]
    uint32_t err_inv_cmd : 1;   // [31:31]
    uint32_t err_abh_resp : 1;  // [32:32]
};

struct __attribute__((packed)) reg_cmd_ptr {
    uint32_t fifo_w : 10;   // [9:0]
    uint32_t fifo_r : 10;   // [19:10]
    uint32_t reserved : 12; // [31:20]
};

#ifndef RTL_SIM
#include <time.h>
#endif

static void
ae_wait()
{
#ifdef RTL_SIM
    // Readinf from acc_eng_status_reg steos the RTL simulation.
    uint32_t tmp;
    ops.sbif_read_dword(SBIF_ACC_ENG_STATUS_REG, &tmp);
#else
    // wait 100 nanoseconds if CLOCKS_PER_SEC value is large enough, or simply wait for 100 clocks.
    int i, clk_diff = (CLOCKS_PER_SEC > 10000 ? (CLOCKS_PER_SEC / 10000) : 100);
    clock_t clk;
    for (i = 0, clk = clock(); (clock() < clk + clk_diff) && (i < 1000); ++i)
        ;
#endif
}

static void
ae_reset()
{
    ops.sbif_write_dword(SBIF_ACC_ENG_RESET_REG, 0xff);
    ae_wait();
    ops.sbif_write_dword(SBIF_ACC_ENG_RESET_REG, 0);

    // reset the fifo pointers
    ops.sbif_write_dword(SBIF_ACC_ENG_CMD_PTR_REG, 0x0);
    ae_cmd_fifo_w = 0;

    // reset the data buffer
    uint32_t addr = SBIF_ACC_ENG_DATA_MEM;
    uint32_t addr_end = addr + (SBIF_ACC_ENG_DATA_MEM_ENTRIES << 2);
    for (; addr < addr_end; addr += 4) {
        ops.sbif_write_dword(addr, 0);
    }
}

#ifdef SCREENING_DEBUG
static const char*
ae_state_to_cstr(uint8_t ae_state)
{
    // From <leaba>/design/dmc/sbif/verilog/sbif_access_engine.v
    static const char* strs[] = {
        "IDLE",            // 6'd0
        "WR_REQ",          // 6'd1
        "WR_TX_HDR",       // 6'd2
        "WR_TX_ADDR",      // 6'd3
        "WR_TX_DATA",      // 6'd4
        "WR_WAIT_RSP",     // 6'd5
        "RD_REQ",          // 6'd6
        "RD_TX_HDR",       // 6'd7
        "RD_TX_ADDR",      // 6'd8
        "RD_WAIT_RSP",     // 6'd9
        "RD_RX_DATA",      // 6'd10
        "IMP_REQ",         // 6'd11
        "IMP_ST_BURST",    // 6'd12
        "IMP_MID_BURST",   // 6'd13
        "IMP_END_BURST",   // 6'd14
        "FETCH_REQ",       // 6'd15
        "FETCH_ST_BURST",  // 6'd16
        "FETCH_MID_BURST", // 6'd17
        "FETCH_END_BURST", // 6'd18
        "EXP_PREFETCH",    // 6'd19
        "EXP_REQ",         // 6'd20
        "EXP_ST_BURST",    // 6'd21
        "EXP_MID_BURST",   // 6'd22
        "EXP_END_BURST",   // 6'd23
        "POLL_REQ",        // 6'd24
        "POLL_TX_HDR",     // 6'd25
        "POLL_TX_ADDR",    // 6'd26
        "POLL_WAIT_RSP",   // 6'd27
        "POLL_RX_DATA",    // 6'd28
        "IMM_WR_REQ",      // 6'd29
        "IMM_WR_TX_HDR",   // 6'd30
        "IMM_WR_TX_ADDR",  // 6'd31
        "IMM_WR_TX_DATA",  // 6'd32
        "IMM_WR_WAIT_RSP", // 6'd33
        "RMW_RD_REQ",      // 6'd34
        "RMW_RD_TX_HDR",   // 6'd35
        "RMW_RD_TX_ADDR",  // 6'd36
        "RMW_RD_WAIT_RSP", // 6'd37
        "RMW_WR_TX_HDR",   // 6'd38
        "RMW_WR_TX_ADDR",  // 6'd39
        "RMW_WR_TX_DATA",  // 6'd40
        "RMW_WR_WAIT_RSP", // 6'd41
        "DELAY",           // 6'd42
        "SBUS_REG_WR",     // 6'd43
        "SBUS_REG_RD",     // 6'd44
        "SBUS_REG_WAIT",   // 6'd45
        "SBUS_REG_RETRY",  // 6'd46
        "ACQUIRE_SEM",     // 6'd47
        "RELEASE_SEM",     // 6'd48
    };

    return ae_state < sizeof(strs) / sizeof(strs[0]) ? strs[ae_state] : "UNKNOWN";
}
#endif

static int
ae_get_state()
{
    uint32_t go;
    struct reg_cmd_ptr cmd_ptr;
    struct reg_status status;

    ops.sbif_read_dword(SBIF_ACC_ENG_GO_REG, &go);
    ops.sbif_read_dword(SBIF_ACC_ENG_CMD_PTR_REG, (uint32_t*)&cmd_ptr);
    ops.sbif_read_dword(SBIF_ACC_ENG_STATUS_REG, (uint32_t*)&status);

#ifdef SCREENING_DEBUG
    char buf[200] = {0};
    snprintf(buf,
             sizeof(buf),
             "eng[%hu]: go=%X, fifo_r=0x%X, fifo_w=0x%X, status=0x%X (active=0x%X, state=0x%X(%s), count=0x%X, "
             "err=0x%X, err_block_id 0x%X, err_inv_cmd 0x%X, err_abh_resp 0x%X)",
             ae_engine_id,
             go,
             cmd_ptr.fifo_r,
             cmd_ptr.fifo_w,
             *((uint32_t*)(void*)&status),
             status.active,
             status.state,
             ae_state_to_cstr(status.state),
             status.count,
             status.error,
             status.err_block_id,
             status.err_inv_cmd,
             status.err_abh_resp);
    LOG_I("%s: %s\n", __func__, buf);
#endif
    if (!status.error) {
        if (!status.active && !status.state && (cmd_ptr.fifo_w == cmd_ptr.fifo_r) && !go) {
            // GO is deasserted, fifo read pointer reached the write pointer and state is clear ==> DONE
            return AE_STATE_READY;
        }

        return AE_STATE_BUSY;
    }

    return AE_STATE_FAIL;
}

static scr_error_t
exec_command(uint32_t cmd, uint32_t block_id, uint32_t addr, uint32_t val_dwords_n, const uint32_t* val_dwords)
{
    union {
        uint32_t dwords[3];
        struct {
            // dword 0
            uint32_t length : 10;    // [73:64]
            uint32_t buff_addr : 9;  // [82:74]
            uint32_t reserved2 : 1;  // [83:83]
            uint32_t interrupt : 1;  // [84:84]
            uint32_t rd_not_clr : 1; // [85:85]
            uint32_t reserved1 : 2;  // [87:86]
            uint32_t opcode : 5;     // [92:88]
            uint32_t reserved0 : 3;  // [95:93]

            // dword 1
            uint32_t block_id : 12; // [43:32]
            uint32_t reserved4 : 4; // [47:44]
            uint32_t count : 10;    // [57:48]
            uint32_t reserved3 : 6; // [63:58]

            // dword 2
            uint32_t addr; // [31:0]
        } fields;
    } ae_cmd;

    memset(&ae_cmd, 0, sizeof(ae_cmd));
    ae_cmd_op_t op = (cmd == CMD_WRITE_REG || cmd == CMD_WRITE_MEM) ? AE_OP_WRITE : AE_OP_READ;
    int buff_addr = 0;

    ae_cmd.fields.opcode = op;
    ae_cmd.fields.buff_addr = buff_addr;
    ae_cmd.fields.length = val_dwords_n;
    ae_cmd.fields.count = 1;
    ae_cmd.fields.block_id = block_id;
    ae_cmd.fields.addr = addr;

    LOG_I("%s: op=%d, block_id=0x%x, addr=0x%x, ae_cmd=0x%08x__%08x__%08x\n",
          __func__,
          op,
          block_id,
          addr,
          ae_cmd.dwords[0],
          ae_cmd.dwords[1],
          ae_cmd.dwords[2]);

    // store 'write' value
    if (op == AE_OP_WRITE) {
        ops.sbif_write_dwords(SBIF_ACC_ENG_DATA_MEM + buff_addr, val_dwords_n, val_dwords);
    }

    // write the command to the command fifo, the ae_cmd_fifo_w offset is only
    // meaningful in the non-default "fifo override" mode.
    ops.sbif_write_dwords(SBIF_ACC_ENG_CMD_MEM + ae_cmd_fifo_w, 3, ae_cmd.dwords);

    // keep track of fifo write pointer, it is incremented by 3 and wraps around at 512 (which is not an integer multiple of 3 -
    // nice!).
    ae_cmd_fifo_w = (ae_cmd_fifo_w + 3) % ae_cmd_fifo_entries;

#ifdef RTL_SIM
    // update fifo pointers
    uint32_t cmd_ptr = 0;
    ops.sbif_read_dword(SBIF_ACC_ENG_CMD_PTR_REG, &cmd_ptr);
    cmd_ptr = (cmd_ptr & 0xffc00) | (ae_cmd_fifo_w & 0x3ff);
    ops.sbif_write_dword(SBIF_ACC_ENG_CMD_PTR_REG, cmd_ptr);
#else
// do nothing, let the HW manage the fifo pointers.
#endif

    // GO=1
    ops.sbif_write_dword(SBIF_ACC_ENG_GO_REG, 1);

    // poll
    int ae_state = AE_STATE_BUSY;
    for (int i = 0; i < 100 && (ae_state == AE_STATE_BUSY); ++i) {
        ops.yield();
        ae_state = ae_get_state();
    }
    if (ae_state != AE_STATE_READY) {
        LOG_E("%s: engine[%hu] is not ready, AE state %d\n", __func__, ae_engine_id, ae_state);
        return ERR_ACCESS_ENGINE;
    }

    // Check command: read + compare expected vs actual
    if (op == AE_OP_READ) {
        uint32_t read_val_dwords[MAX_VAL_DWORDS];

        ops.sbif_read_dwords(SBIF_ACC_ENG_DATA_MEM + buff_addr, val_dwords_n, read_val_dwords);
        int cmp_res = memcmp(val_dwords, read_val_dwords, val_dwords_n);
        if (cmp_res) {
            LOG_E("%s: mismatch!\n", __func__);
            return ERR_RW_MISMATCH;
        }
    }

    return ERR_OK;
}

static uint32_t
endianness_swap32(uint32_t val)
{
    return (((val & 0xff) << 24) | ((val & 0xff00) << 8) | ((val & 0xff0000) >> 8) | (val >> 24));
}

scr_error_t
scr_read_from_storage_and_exec(uint32_t storage_base, int is_exec)
{
    // Read in chunks of up to 64bytes, this simulates how we work with flash
    enum { READ_CHUNK_BYTES = 64, READ_CHUNK_DWORDS = 16 };

    scr_error_t err = ERR_OK;
    ops.storage_rewind(storage_base);

    LOG_I("ae reset\n");
    ae_reset();
    LOG_I("start read & exec loop\n");
    while (err == ERR_OK) {
        union {
            cmd_header_t hdr;
            uint32_t dwords[3];
        } u;

        // header: 3 dwords
        if (ops.storage_read_dwords(3, u.dwords) < 0) {
            err = ERR_STORAGE;
            break;
        }

        if (u.dwords[0] == 0xffffffff) {
            LOG_D("end marker\n");
            break;
        }

        LOG_D("hdr: cmd=0x%x, block_id=0x%x, addr=0x%x, width_bytes=0x%x, val=",
              u.hdr.cmd,
              u.hdr.block_id,
              u.hdr.addr,
              u.hdr.width_bytes);
        // value: full dwords, read in chunks of up to 16 dwords (this is how our flash works)
        uint32_t val_dwords_n = (u.hdr.width_bytes + 3) / 4;
        uint32_t full_chunks = val_dwords_n / READ_CHUNK_DWORDS;
        uint32_t remainder_dwords_n = val_dwords_n % READ_CHUNK_DWORDS;

        if (val_dwords_n > MAX_VAL_DWORDS) {
            LOG_E("width_bytes=0x%x is too big\n", u.hdr.width_bytes);
            return ERR_STORAGE;
        }

        uint32_t val_dwords[MAX_VAL_DWORDS];
        memset(val_dwords, 0, sizeof(val_dwords));

        uint32_t i;
        uint32_t* p;
        // read full 16-dwords chunks
        for (i = 0, p = val_dwords; i < full_chunks; i += READ_CHUNK_DWORDS, p += READ_CHUNK_DWORDS) {
            ops.storage_read_dwords(READ_CHUNK_DWORDS, p);
            *p = endianness_swap32(*p);
            LOG_D("%08x ", *p);
        }
        // read the remainder
        if (remainder_dwords_n) {
            ops.storage_read_dwords(remainder_dwords_n, p);
            *p = endianness_swap32(*p);
            LOG_D("%08x ", *p);
        }
        LOG_D("\n");

        if (is_exec) {
            err = exec_command(u.hdr.cmd, u.hdr.block_id, u.hdr.addr, val_dwords_n, val_dwords);
        }
    }

    if (err != ERR_OK) {
        // turn on error indication
    }

    return err;
}
