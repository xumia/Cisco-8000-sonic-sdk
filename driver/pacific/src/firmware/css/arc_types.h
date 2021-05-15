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

#ifndef __ARC_TYPES_H__
#define __ARC_TYPES_H__

#include "api/system/la_css_memory_layout.h"
#include "arc/arc_reg.h"
#include "hw_tables/arc_cpu_common.h"
#include <stdint.h>

// The CLOCKS_PER_SEC defined in the ARC system headers is zero.
// Need to define it correctly here.
#define CLOCKS_PER_SEC (500 * 1000 * 1000) // 500 MHz

// Polling counter is in units of usec.
#define USEC_IN_TICKS (1)
#define SECOND_IN_TICKS (1000000 * USEC_IN_TICKS)

#define TICK_DELTA(start, end) ((end > start) ? (end - start) : (0xffffffff - start) + end)

#define SEC_DELTA(start, end) ((double)TICK_DELTA(start, end) / CLOCKS_PER_SEC)
#define MSEC_DELTA(start, end) ((double)TICK_DELTA(start, end) / (CLOCKS_PER_SEC / 1000))
#define USEC_DELTA(start, end) ((double)TICK_DELTA(start, end) / (CLOCKS_PER_SEC / 1000 / 1000))

// Debug macro for measuring time between opertaions (in ticks).
#define dbg_write_delta_time(ctx, x, start, end) ctx->css->dbg_counters[x] = TICK_DELTA(start, end);

// Debug High water mark
#define dbg_hwm(ctx, x, value)                                                                                                     \
    if (ctx->css->dbg_counters[x] < value)                                                                                         \
        ctx->css->dbg_counters[x] = value;
#define dbg_count(ctx, x) ctx->css->dbg_counters[x]++;
#define dbg_write(ctx, x, data) ctx->css->dbg_counters[x] = data;
#define dbg_inc(ctx, x, data) ctx->css->dbg_counters[x] += data;

struct arc_context_;

typedef void (*command_callback_fn)(arc_context_* ctx, void* msg, uint32_t length);

struct command_callback_ {
    uint16_t type;
    command_callback_fn callback_fn;
};
typedef command_callback_ command_callback_t;

typedef void (*poll_callback_fn)(arc_context_* ctx);

struct poll_callback_ {
    uint32_t enabled;
    uint32_t interval;
    uint64_t next_time;
    poll_callback_fn callback_fn;
};
typedef poll_callback_ poll_callback_t;

typedef volatile __attribute__((uncached)) css_arc_mem_t* css_arc_mem_ptr_t;

typedef volatile __attribute__((uncached)) uint8_t* css_ptr_t;

struct arc_access_engine_ptr_ {
    css_ptr_t data_mem;
    css_ptr_t cmd_mem;
    css_ptr_t go_reg;
    css_ptr_t cmd_ptr;
    css_ptr_t status_ptr;
    uint32_t id;
};

typedef arc_access_engine_ptr_ arc_access_engine_ptr;

// Hash table used for sw-based PFC.
struct __attribute__((packed)) pfc_hash_table_t {
    uint32_t destination : 12;
    uint32_t slice : 3;
    uint32_t cong_state : 1;
    uint32_t tc : 3;
    uint32_t valid : 1;
    uint32_t counter : 8;
    uint32_t padding : 4;
};

// Hash table of 256 entries x 4B = 1KB
#define PFC_HASH_TABLE_NUM_ENTRIES 256

struct arc_context_ {
    // Pointer to ARC core specific memory gets setup at boot time
    css_arc_mem_ptr_t css;

    //  Access engine ptrs and id.
    arc_access_engine_ptr ae;

    // Message command callbacks get setup at boot time
    command_callback_t* command_callbacks;
    uint32_t command_callbacks_count;

    // Poll event callbacks get setup at boot time
    poll_callback_t* poll_callbacks;
    uint32_t poll_callbacks_count;

    // Running counter
    uint32_t last_tick;
    uint64_t current_time;

    // Any ARC id specific data,
    union {
        struct arc0_data_t {
            // PFC hash table ptr
            pfc_hash_table_t* pfc_hash_table;
        } arc0;
        struct arc1_data_t {
        } arc1;
        struct arc2_data_t {
        } arc2;
        struct arc3_data_t {
        } arc3;
    } arc_specific;
};
typedef arc_context_ arc_context_t;

#endif // __ARC_TYPES_H__
