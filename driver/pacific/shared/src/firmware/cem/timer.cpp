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

#include "timer.h"

#include <stdlib.h>

/// @brief Relevant register addresses
enum timer_reg_addr_e {
    TIMER_REG_ADDR_TIMER0_COUNT = 0x021,   ///< Reset timer count
    TIMER_REG_ADDR_TIMER0_CONTROL = 0x022, ///< Timer control register
    TIMER_REG_ADDR_TIMER0_LIMIT = 0x023,   ///< Timer limit on which timer resets
};

enum timer_control_flags_e {
    TIMER_CONTROL_FLAGS_ENABLE_IRQ = 0x1,      ///< Enables interrupt once timer reaches its limit.
    TIMER_CONTROL_FLAGS_RUN_NOT_HALTED = 0x2,  ///< Run counter only if not halted.
    TIMER_CONTROL_FLAGS_ENABLE_WATCHDOG = 0x4, ///< Generate watchdog reset signal once timer reaches its limit.
    TIMER_CONTROL_FLAGS_LIMIT_REACHED = 0x8,   ///< Flag is set by HW once limit was reached.
    TIMER_CONTROL_FLAGS_RUN_POWER_DOWN = 0x10, ///< Run counter even if powered down.
};

static const uint32_t ARC_TICKS_IN_MS = 600_000; ///< 600Mhz = 600M ticks / sec.
static const uint32_t TIMER_LIMIT = 100 * ARC_TICKS_IN_MS;

static const uint32_t TIMER_CONTROL_FLAGS = TIMER_CONTROL_FLAGS_RUN_NOT_HALTED | TIMER_CONTROL_FLAGS_ENABLE_IRQ;

// Global variable to keep timer value in 10
volatile uint32_t timer_count = 0xffff;

/// @brief Timer interrupt handling routine
///
/// Called when timer reaches its limit
_Fast_Interrupt void
irq_timer0()
{
    // disable interrupts
    int ints = _clri();

    timer_count++;
    _sr(TIMER_CONTROL_FLAGS, TIMER_REG_ADDR_TIMER0_CONTROL);

    // restore interrupts
    _seti(ints);
}

void
reset_timer_registers_and_vars()
{
    _sr(TIMER_LIMIT, TIMER_REG_ADDR_TIMER0_LIMIT);
    _sr(TIMER_CONTROL_FLAGS, TIMER_REG_ADDR_TIMER0_CONTROL);
    _sr(0x0, TIMER_REG_ADDR_TIMER0_COUNT);
    timer_count = 0;
}

void
timer_init()
{
#ifndef TEST_MODE
    // disable interrupts
    int ints = _clri();

    // Set interrupt handler
    _setvectfi(IRQ_TIMER0, irq_timer0);

    reset_timer_registers_and_vars();

    // restore interrupts
    _seti(ints);
#else
    timer_count = 0;
#endif // TEST_MODE
}

uint32_t
timer_read()
{
    return timer_count;
}

void
timer_reset()
{
#ifndef TEST_MODE
    // disable interrupts
    int ints = _clri();

    reset_timer_registers_and_vars();

    // restore interrupts
    _seti(ints);
#else
    timer_count = 0;
#endif // TEST_MODE
}
