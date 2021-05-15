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

#include <cstddef>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

// metaware ARC includes
#include "arc/arc_reg.h"
#include "arc/arc_timer.h"

// SDK includes
#include "api/system/la_css_memory_layout.h"

// local includes
#include "arc0_events.h"
#include "arc1_events.h"
#include "arc2_events.h"
#include "arc3_events.h"
#include "arc_command_queue.h"
#include "arc_poll_events.h"
#include "arc_types.h"

// Template used to static_assert if the alignment is not met.
// The error message will show the number of bytes needed.
template <typename type, std::size_t alignment, std::size_t needed_bytes = 32 - (sizeof(type) % alignment)>
void
check_align()
{
    static_assert(needed_bytes == 32, "Alignment is off!");
}

// create a pointer to the CSS ARC memory
css_arc_mem_t volatile _Uncached* css_arc_mem = (css_arc_mem_t volatile _Uncached*)silicon_one::la_css_memory_layout_e::ARC_SCRATCH;

arc_context_t* ctx_g;
uint32_t id;

static void
init_css_memory(arc_context_t* ctx)
{
    int i;

    // To make debuging easier make sure each CSS ARC memory is 32 byte aligned.
    check_align<css_arc_mem_t, 32>();

    // zero the css_arc context
    _vmemset(ctx->css, 0, sizeof(*(ctx->css)));

    // setup the ID and magic marker in memory
    ctx->css->id = id;
    for (i = 0; i < MAGIC_SIZE; i++) {
        ctx->css->magic[i] = MAGIC_VALUE | (id << 8);
    }

    // poison the command message buffer
    for (i = 0; i < CMD_MSG_BUF_SIZE; i++) {
        ctx->css->from_cpu.msg_buffer[i] = i;
        ctx->css->to_cpu.msg_buffer[i] = 0x80 + i;
    }
}

static void
init_msec_clock(arc_context_t* ctx)
{
    ctx->current_time = 0;
    ctx->last_tick = GET_TIMER();
}

#define POLLING_TIME (250 * USEC_IN_TICKS)

static void
incr_clock(arc_context_t* ctx)
{
    uint32_t curr_tick = GET_TIMER();
    double delta = USEC_DELTA(ctx->last_tick, curr_tick);
    if (delta > POLLING_TIME) {
        if (delta >= 2 * POLLING_TIME) {
            dbg_count(ctx, ARC_DBG_LOOP_EXCEEDED);
        }
        ctx->last_tick = curr_tick;
        ctx->current_time += delta;
    }
}

int
main(void)
{
    arc_context_t* ctx;

    // turn off interrupts
    _clri();

    // setup ID global
    id = REG_IDENTITY_CORE_NUMBER;

    ctx_g = (arc_context_t*)malloc(sizeof(*ctx));
    ctx = ctx_g;
    if (ctx == NULL) {
        int i;
        for (i = 0; i < MAGIC_SIZE; i++) {
            // indicate we had a bad malloc in CSS
            ctx->css->magic[i] = 0x00dead00 | id;
        }
        _brk(); // never return
    }

    // set the pointer to the css memory for this core
    ctx->css = &css_arc_mem[id];
    init_css_memory(ctx);

    // initialize the running msec counter for polling events
    init_msec_clock(ctx);

    // set the pointer and size to the message commands for this arc
    switch (id) {
    case 0:
        set_arc0_command_callbacks(ctx);
        set_arc0_poll_callbacks(ctx);
        arc0_init(ctx);
        break;
    case 1:
        set_arc1_command_callbacks(ctx);
        set_arc1_poll_callbacks(ctx);
        break;
    case 2:
        set_arc2_command_callbacks(ctx);
        set_arc2_poll_callbacks(ctx);
        break;
    case 3:
        set_arc3_command_callbacks(ctx);
        set_arc3_poll_callbacks(ctx);
        break;
    }

    while (1) {
        dbg_count(ctx, ARC_DBG_LOOP);

        incr_clock(ctx);

        // handle any received commands
        arc_command_receive(ctx);

        // handle any polling events
        arc_do_poll_events(ctx);
    }

    // This line is unreachable.
    _brk();

    return 0;
}
