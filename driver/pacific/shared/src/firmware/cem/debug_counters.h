// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __DEBUG_COUNTERS_H__
#define __DEBUG_COUNTERS_H__

#include "arc_cpu_common.h"

/// @file
/// @brief Debug counters declarations.
/// Debug counters reside in DCCM in a separate data section (.cpu_io)
/// The section is defined as a first section in DCCM layout, thus we ensure that the absolute address of debug counters
/// remains the same between compilations.
/// All counters are defined as volatile int32 to ensure the memory is updated on each operations and can be accessed from CPU.

extern volatile arc_debug_counters debug_counters;
extern volatile uint32_t fw_em_poll_timeout_iterations;

static inline void
debug_counter_incr(uint32_t counter_idx)
{
    debug_counters.counter[counter_idx]++;
}

static inline void
debug_em_failure_incr(uint32_t em_command_idx)
{
    debug_counters.em_request_failure[em_command_idx]++;
}

static inline void
debug_counter_incr_cond(uint32_t counter_idx, bool cond)
{
    if (cond) {
        debug_counter_incr(counter_idx);
    }
}

static inline void
debug_em_failure_incr_cond(uint32_t em_command_idx, bool cond)
{
    if (cond) {
        debug_em_failure_incr(em_command_idx);
    }
}

#endif // __DEBUG_COUNTERS_H__
