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

#include "arc_poll_events.h"
#include "arc_types.h"

void
arc_do_poll_events(arc_context_t* ctx)
{
    uint32_t i;
    for (i = 0; i < ctx->poll_callbacks_count; i++) {
        if (ctx->poll_callbacks[i].enabled && (ctx->current_time >= ctx->poll_callbacks[i].next_time)) {

            ctx->poll_callbacks[i].next_time = ctx->current_time + ctx->poll_callbacks[i].interval;
            ctx->poll_callbacks[i].callback_fn(ctx);
        }
    }
}
