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

// Implementation of UAUX registers utilities

#include "uaux_regs.h"
#include "arc_cpu_common.h"
#include "common.h"
#include "test_if.h"
#include "uaux_regs_commands.h"
#include "uaux_regs_mem.h"

// for memcpy/memset
#include <string.h>

extern volatile int32_t fw_reg_addr_read;
extern volatile int32_t fw_reg_addr_write;

//*********************************
// GLOBAL DATA
//*********************************

// Operation context
routine_context op_ctx;

#ifdef TEST_MODE
// in test mode, map the addresses to DCCM
uint8_t test_uaux_regs[TOTAL_REG_OFFSET * MEM_ALIGN];
#endif

// ********************************
// COMMON FUNCTIONS
// ********************************

bool
is_mac_entry(const long_entry_data* rec)
{
    const short_key_encoding* key_enc = (const short_key_encoding*)rec->key;
    return (key_enc->code == MAC_FORWARDING_TABLE_CODE);
}

// Two implementations of read/write. Test mode reads/writes to DCCM instead of
// UAUX
#ifdef TEST_MODE

void
read_reg(void* dest, uaux_reg_name_e reg)
{
    uint32_t size = MEM_ALIGN * reg_size(reg);
    uint32_t base_addr = reg_addr(reg);
    for (int i = 0; i < size; i += MEM_ALIGN) {
        uint32_t src = base_addr + i;
        uint8_t* dest_ptr = (uint8_t*)dest + i;
        _vsmemcpy((uint8_t*)dest_ptr, (uncached_ptr_t)src, MEM_ALIGN);
    }
}

void
write_reg(uaux_reg_name_e reg, const void* src)
{
    uint32_t size = MEM_ALIGN * reg_size(reg);
    uint32_t base_addr = reg_addr(reg);
    for (int i = 0; i < size; i += MEM_ALIGN) {
        const uint8_t* src_ptr = (const uint8_t*)src + i;
        uint32_t dest = base_addr + i;
        _vdmemcpy((uncached_ptr_t)dest, (const uint8_t*)src_ptr, MEM_ALIGN);
    }
}

#else // not TEST_MODE

void
read_reg(void* dest, uaux_reg_name_e reg)
{
    int len_in_words = reg_size(reg);
    uint32_t base_addr = reg_addr(reg);
    for (int i = 0; i < len_in_words; ++i) {
        ((uint32_t*)dest)[i] = _lr(base_addr + i);
    }
}

void
write_reg(uaux_reg_name_e reg, const void* src)
{
    uint32_t len_in_words = reg_size(reg);
    uint32_t base_addr = reg_addr(reg);
    for (int i = 0; i < len_in_words; ++i) {
        _sr(((uint32_t*)src)[i], base_addr + i);
    }
}

#endif // TEST_MODE
