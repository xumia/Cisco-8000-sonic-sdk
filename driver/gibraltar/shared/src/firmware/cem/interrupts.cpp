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

#include "common.h"
#include <stdlib.h>

/// @brief Addresses of external interrupt controlling register
enum irq_reg_addr_e {
    IRQ_REG_ADDR_AUX_IRQ_HINT = 0x201,
    IRQ_REG_ADDR_IRQ_SELECT = 0x40b,  // IRQ to manipulate
    IRQ_REG_ADDR_IRQ_ENABLE = 0x40c,  // enable for selected IRQ
    IRQ_REG_ADDR_IRQ_TRIGGER = 0x40d, // pulse or level trigger for selected IRQ
};

/// @file
/// This is a placeholder to add interrupt handling code.
/// Once interrupts are enabled, handlers must be set. Otherwise, other interrupts stop working.
/// For now, keeping empty functions.

_Interrupt void
irq_learn(void)
{
    // add interrupt handling code here
}

_Interrupt void
irq_em_response()
{
    // add interrupt handling code here
}

_Interrupt void
irq_aging()
{
    // add interrupt handling code here
}

_Interrupt void
irq_bulk_update()
{
    // add interrupt handling code here
}

_Interrupt void
irq_cpu()
{
    // add interrupt handling code here
}

void
init_external_interrupts()
{
#ifndef TEST_MODE
    // disable interrupts
    int ints = _clri();

    // Set interrupt handlers
    _setvecti(IRQ_EXT_17, irq_learn);
    _setvecti(IRQ_EXT_18, irq_em_response);
    _setvecti(IRQ_EXT_19, irq_aging);
    _setvecti(IRQ_EXT_20, irq_bulk_update);
    _setvecti(IRQ_EXT_21, irq_cpu);

    // restore interrupts
    _seti(ints);
#endif // TEST_MODE
}
