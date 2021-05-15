// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "status_reg.h"
#include "arc_cpu_common.h"
#include "common.h"
#include "uaux_regs.h"
#include "uaux_regs_mem.h"

// for memcpy/memset
#include <string.h>

//******************************
// CLASS: status_reg
//******************************
status_reg_data status_reg;

// Two implementations of read/write. Test mode reads/writes to DCCM instead of
// UAUX
#ifdef TEST_MODE
void
status_reg_read()
{
    _vsmemcpy(&status_reg.val, (uncached_ptr_t)reg_addr(UAUX_STATUS_REG), sizeof(status_reg_data));
}

void
status_reg_write()
{
    _vdmemcpy((uncached_ptr_t)reg_addr(UAUX_STATUS_REG), &status_reg.val, sizeof(status_reg_data));
}

void
read_cpu_status_reg(void* status)
{
    _vsmemcpy(status, (uncached_ptr_t)reg_addr(UAUX_CPU_REG), sizeof(uint32_t));
}

void
write_cpu_status_reg(const void* status)
{
    _vdmemcpy((uncached_ptr_t)reg_addr(UAUX_CPU_REG), status, sizeof(uint32_t));
}

void
status_reg_set_mask(uint32_t mask)
{
    // HW expects inverse mask
    mask = ~mask;
    _vdmemcpy((uncached_ptr_t)reg_addr(UAUX_STATUS_MASK_REG), &mask, sizeof(status_reg_data));
}

#else // not TEST_MODE

void
status_reg_read()
{
    status_reg.val = _lr(reg_addr(UAUX_STATUS_REG));
}

void
status_reg_write()
{
    _sr(status_reg.val, reg_addr(UAUX_STATUS_REG));
}

void
read_cpu_status_reg(void* status)
{
    *(uint32_t*)status = _lr(reg_addr(UAUX_CPU_REG));
}

void
write_cpu_status_reg(const void* status)
{
    _sr(*(uint32_t*)status, reg_addr(UAUX_CPU_REG));
}

void
status_reg_set_mask(uint32_t mask)
{
    // HW expects inverse mask
    mask = ~mask;
    _sr(mask, reg_addr(UAUX_STATUS_MASK_REG));
}

#endif // TEST_MODE
