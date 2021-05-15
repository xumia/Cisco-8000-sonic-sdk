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

#include "arc1_events.h"
#include "arc_types.h"

// Applicatiion command includes
#include "cmd_keepalive.h"
#include "poll_sec_count.h"

// The callback function will be called for the given command type
command_callback_t arc1_command_callbacks[] = {
    // Example:
    // { .type = <message_command>, .callback_fn = <application_function> },
    {.type = arc_cmd_type_e::ARC_CMD_PING, .callback_fn = keepalive_callback},
};

// The callback functions to call for polling events
poll_callback_t arc1_poll_callbacks[] = {
    // Example:
    // { .enabled = <enabled_at_boot>, .interval = <interval>, .callback_fn = <application_function> }
    {.enabled = 1, .interval = SECOND_IN_TICKS, .callback_fn = second_counter}};

void
set_arc1_command_callbacks(arc_context_t* ctx)
{
    ctx->command_callbacks = arc1_command_callbacks;
    ctx->command_callbacks_count = sizeof(arc1_command_callbacks) / sizeof(command_callback_t);
}

void
set_arc1_poll_callbacks(arc_context_t* ctx)
{
    ctx->poll_callbacks = arc1_poll_callbacks;
    ctx->poll_callbacks_count = sizeof(arc1_poll_callbacks) / sizeof(poll_callback_t);

    uint32_t i;
    for (i = 0; i < ctx->poll_callbacks_count; i++) {
        ctx->poll_callbacks[i].next_time = ctx->current_time + ctx->poll_callbacks[i].interval;
    }
}
