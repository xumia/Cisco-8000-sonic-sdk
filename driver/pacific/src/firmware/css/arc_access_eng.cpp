// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "arc_command_queue.h"
#include "arc_types.h"

#include "arc_access_eng.h"
#include "arc_types.h"
#include "poll_nh_eventq.h"
#define LLD_BLOCK_ID_NPUH 704

// SBIF sizes
enum sbif_sizes_e {
    SBIF_ACC_ENG_DATA_MEM_ENTRIES = 512,
    SBIF_ACC_ENG_CMD_MEM_ENTRIES = 512,
};

asic_memory_info_t pacific_tree = {
    .npuh = {
        .eth_mp_em_access_register = {
            .block_id = LLD_BLOCK_ID_NPUH,
            .address = 0x123,
            .width = 110,
        },
        .eth_mp_em_response_register = {
            .block_id = LLD_BLOCK_ID_NPUH,
            .address = 0x124,
            .width = 110,
        },
        .evq_counters = {
            .block_id = LLD_BLOCK_ID_NPUH,
            .address = 0x10c,
            .width = 32,
        },
        .cpu_q_config_read_adress = {
            .block_id = LLD_BLOCK_ID_NPUH,
            .address = 0x114,
            .width = 11,
        },
        .cpu_q_config_write_adress = {
            .block_id = LLD_BLOCK_ID_NPUH,
            .address = 0x113,
            .width = 11,
        },
        .event_queue = {
            .block_id = LLD_BLOCK_ID_NPUH,
            .address = 0x700000,
            .width = 61,
        },
    },
};

// Access Engine opcodes
typedef enum {
    AE_OP_WRITE = 1,
    AE_OP_READ = 2,
    AE_OP_IMPORT = 3,
    AE_OP_EXPORT = 4,
    AE_OP_FETCH = 5,
    AE_OP_WAIT_FOR_VALUE = 6,
    AE_OP_IMMEDIATE_WRITE = 7,
    AE_OP_READ_MODIFY_WRITE = 8,
    AE_OP_DELAY = 9,
    AE_OP_ACQUIRE_SEMAPHORE = 12,
    AE_OP_RELEASE_SEMAPHORE = 13,
} ae_cmd_op_t;

#define AE_STATE_READY 0
#define AE_STATE_BUSY 1
#define AE_STATE_FAIL 2

struct __attribute__((packed)) reg_status {
    uint32_t active : 1;        // [0:0]
    uint32_t state : 6;         // [6:1]
    uint32_t count : 10;        // [16:7]
    uint32_t error : 1;         // [17:17]
    uint32_t err_block_id : 12; // [29:18]
    uint32_t err_inv_cmd : 1;   // [30:30]
    uint32_t err_abh_resp : 1;  // [31:31]
};

struct __attribute__((packed)) reg_cmd_ptr {
    uint32_t fifo_w : 10;   // [9:0]
    uint32_t fifo_r : 10;   // [19:10]
    uint32_t reserved : 12; // [31:20]
};

union ae_cmd {
    uint32_t dwords[3];
    struct rw {
        // dword 0
        uint32_t length : 10;    // [73:64] [9:0]
        uint32_t buff_addr : 9;  // [82:74] [18:10]
        uint32_t reserved2 : 1;  // [83:83] [19:19]
        uint32_t interrupt : 1;  // [84:84] [20:20]
        uint32_t rd_not_clr : 1; // [85:85] [21:21]
        uint32_t reserved1 : 2;  // [87:86] [23:22]
        uint32_t opcode : 5;     // [92:88] [28:24]
        uint32_t reserved0 : 3;  // [95:93] [31:29]

        // dword 1
        uint32_t block_id : 12; // [43:32] [11:0]
        uint32_t reserved4 : 4; // [47:44] [15:12]
        uint32_t count : 10;    // [57:48] [25:16]
        uint32_t reserved3 : 6; // [63:58] [31:26]

        // dword 2
        uint32_t addr; // [31:0]
    } read_write;
    struct delay {
        // dword 0
        uint32_t reserved2 : 20; // [83:64]
        uint32_t interrupt : 1;  // [84:84]
        uint32_t reserved1 : 3;  // [87:85]
        uint32_t opcode : 5;     // [92:88]
        uint32_t reserved0 : 3;  // [95:93]

        // dword 1
        uint32_t delay_count_high; // [63:32]

        // dword 2
        uint32_t delay_count_low; // [31:0]
    } delay;
};

static int
sbif_read_dword(css_ptr_t addr, uint32_t* val_dword)
{
    _vsmemcpy(val_dword, addr, 4);
    return 0;
}

static int
sbif_read_dwords(css_ptr_t addr, uint32_t dwords_n, uint32_t* dwords)
{
    for (uint32_t i = 0; i < dwords_n; ++i, addr += 4, ++dwords) {
        sbif_read_dword(addr, dwords);
    }
    return 0;
}

static int
sbif_write_dword(css_ptr_t addr, uint32_t val_dword)
{
    _vdmemcpy(addr, &val_dword, 4);

    return 0;
}

static int
sbif_write_dwords(css_ptr_t addr, uint32_t dwords_n, const uint32_t* dwords)
{
    for (uint32_t i = 0; i < dwords_n; ++i, addr += 4, ++dwords) {
        sbif_write_dword(addr, *dwords);
    }
    return 0;
}

static void
delay_nsec(int nsec)
{
    // make sure nsec is in [100:1000]
    nsec = (nsec > 1000 ? 1000 : (nsec < 100 ? 100 : nsec));
    // calibrate for estimated duration of _timer_default_read()
    nsec /= 100;
    for (int i = 0; i < nsec; ++i) {
        GET_TIMER();
    }
}

static uint32_t ae_cmd_fifo_w = 0;

void
ae_reset(arc_context_t* ctx)
{
    static const css_ptr_t SBIF_ACC_ENG_RESET_REG = (css_ptr_t)((1 << 24) | 0x0150);
    sbif_write_dword(SBIF_ACC_ENG_RESET_REG, (1 << ctx->ae.id));
    delay_nsec(100);
    sbif_write_dword(SBIF_ACC_ENG_RESET_REG, 0);

    // reset the fifo pointers
    sbif_write_dword(ctx->ae.cmd_ptr, 0x0);
    ae_cmd_fifo_w = 0;

    // reset the data buffer
    css_ptr_t addr = ctx->ae.data_mem;
    css_ptr_t addr_end = addr + (SBIF_ACC_ENG_DATA_MEM_ENTRIES << 2);
    for (; addr < addr_end; addr += 4) {
        sbif_write_dword(addr, 0);
    }
}

static int
ae_get_state(arc_context_t* ctx)
{
    uint32_t go;
    struct reg_cmd_ptr cmd_ptr;
    struct reg_status status;

    sbif_read_dword(ctx->ae.go_reg, &go);
    sbif_read_dword(ctx->ae.cmd_ptr, (uint32_t*)(void*)&cmd_ptr);
    sbif_read_dword(ctx->ae.status_ptr, (uint32_t*)(void*)&status);

    if (!status.error) {
        if (!status.active && !status.state && (cmd_ptr.fifo_w == cmd_ptr.fifo_r) && !go) {
            // GO is deasserted, fifo read pointer reached the write pointer and state is clear ==> DONE
            return AE_STATE_READY;
        }

        return AE_STATE_BUSY;
    }

    return AE_STATE_FAIL;
}

static ae_error_t
common_register_access(arc_context_t* ctx, ae_cmd_op_t op, uint32_t block_id, uint32_t addr, uint32_t dwords, uint32_t* data)
{
    union ae_cmd ae_cmd;
    memset(&ae_cmd, 0, sizeof(ae_cmd));

    ae_cmd.read_write.opcode = op;
    ae_cmd.read_write.buff_addr = 0;
    ae_cmd.read_write.length = dwords;
    ae_cmd.read_write.count = 1;
    ae_cmd.read_write.block_id = block_id;
    ae_cmd.read_write.addr = addr;

    if (op == AE_OP_WRITE) {
        // store 'write' value
        sbif_write_dwords(ctx->ae.data_mem, dwords, data);
    }

    for (int i = 0; i < 3; ++i) {
        // Use bits [8:0] for writing to command fifo
        size_t entry = ae_cmd_fifo_w & 0x1ff;
        sbif_write_dword(ctx->ae.cmd_mem + (entry << 2), ae_cmd.dwords[i]);

        // Use bits [9:0] when wrapping around
        ae_cmd_fifo_w = (ae_cmd_fifo_w + 1) & 0x3ff;
    }

    // GO=1
    sbif_write_dword(ctx->ae.go_reg, 1);

    uint64_t delay_cycles = 0;
    // poll
    int ae_state = AE_STATE_BUSY;
    uint32_t poll_max = 10000 + delay_cycles;
    for (uint32_t i = 0; i < poll_max && (ae_state == AE_STATE_BUSY); ++i) {
        ae_state = ae_get_state(ctx);
    }

    if (ae_state != AE_STATE_READY) {
        // LOG_E("%s: engine[%hu] is not ready, AE state %d\n", __func__, ae_engine_id, ae_state);
        return ERR_ACCESS_ENGINE;
    }

    return ERR_OK;
}

static ae_error_t
ae_write(arc_context_t* ctx, memory_info_t* info, uint32_t offset, uint32_t* data)
{
    uint32_t block_id = info->block_id;
    uint32_t addr;
    uint32_t dwords;
    ae_error_t status;
    ae_cmd_op_t op = AE_OP_WRITE;

    addr = info->address + offset;

    // add 8b of parity to the width and round up to the next dwords
    dwords = (info->width + 8 + 31) / 32;

    status = common_register_access(ctx, op, block_id, addr, dwords, data);

    return status;
}

static ae_error_t
ae_read(arc_context_t* ctx, memory_info_t* info, uint32_t offset, uint32_t* data)
{
    uint32_t block_id = info->block_id;
    uint32_t addr;
    uint32_t dwords;
    ae_error_t status;
    ae_cmd_op_t op = AE_OP_READ;

    addr = info->address + offset;

    // add 8b of parity to the width and round up to the next dwords
    dwords = (info->width + 8 + 31) / 32;

    status = common_register_access(ctx, op, block_id, addr, dwords, data);

    if (status != ERR_OK) {
        return status;
    }

    // Read the data from the data memory.
    sbif_read_dwords(ctx->ae.data_mem, dwords, data);

    return ERR_OK;
}

ae_error_t
ae_read_memory(arc_context_t* ctx, memory_info_t* info, uint32_t offset, uint32_t* data)
{
    return ae_read(ctx, info, offset, data);
}

ae_error_t
ae_read_register(arc_context_t* ctx, memory_info_t* info, uint32_t* data)
{
    return ae_read(ctx, info, 0, data);
}

ae_error_t
ae_write_memory(arc_context_t* ctx, memory_info_t* info, uint32_t offset, uint32_t* data)
{
    return ae_write(ctx, info, offset, data);
}

ae_error_t
ae_write_register(arc_context_t* ctx, memory_info_t* info, uint32_t* data)
{
    return ae_write(ctx, info, 0, data);
}

void
ae_init_ptrs(arc_context_t* ctx, uint32_t access_engine_id)
{
    ctx->ae.id = access_engine_id;
    ctx->ae.data_mem = (css_ptr_t)((1 << 24) | 0x700 + SBIF_ACC_ENG_DATA_MEM_ENTRIES * ctx->ae.id * 4);
    ctx->ae.cmd_mem = (css_ptr_t)((1 << 24) | 0x4700 + SBIF_ACC_ENG_CMD_MEM_ENTRIES * ctx->ae.id * 4);
    ctx->ae.go_reg = (css_ptr_t)((1 << 24) | 0x0154 + ctx->ae.id * 4);
    ctx->ae.cmd_ptr = (css_ptr_t)((1 << 24) | 0x174 + ctx->ae.id * 4);
    ctx->ae.status_ptr = (css_ptr_t)((1 << 24) | 0x0194 + ctx->ae.id * 4);
}
