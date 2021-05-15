// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "arc_interrupts.h"
#include "common.h"

#include "screening.h"
#include "spi_flash.h"

platform_ops ops; // external symbol, used by screening.cpp and spi_flash.cpp
static uint32_t ops_flash_addr = 0;

// Called from ae.c
int
platform_ops::sbif_write_dword(uint32_t addr, uint32_t val_dword)
{
    *(uint32_t*)addr = val_dword;
    return 0;
}

// Called from ae.c
int
platform_ops::sbif_write_dwords(uint32_t addr, uint32_t dwords_n, const uint32_t* dwords)
{
    for (uint32_t i = 0; i < dwords_n; ++i, addr += 4, ++dwords) {
        sbif_write_dword(addr, *dwords);
    }
    return 0;
}

// Called from ae.c
int
platform_ops::sbif_read_dword(uint32_t addr, uint32_t* val_dword)
{
    *val_dword = *(uint32_t*)addr;
    return 0;
}

// Called from ae.c
int
platform_ops::sbif_read_dwords(uint32_t addr, uint32_t dwords_n, uint32_t* dwords)
{
    for (uint32_t i = 0; i < dwords_n; ++i, addr += 4, ++dwords) {
        sbif_read_dword(addr, dwords);
    }
    return 0;
}

void
platform_ops::storage_rewind(uint32_t base_addr)
{
    ops_flash_addr = base_addr;
}

int
platform_ops::storage_read_dwords(uint32_t dwords_n, uint32_t* dwords)
{
    spi_read_from_flash(ops_flash_addr, dwords_n, dwords);
    ops_flash_addr += dwords_n;
    return 0;
}

void
platform_ops::yield()
{
    // do nothing
}

//***************************/
// LOADER
//***************************/

int
main()
{
    uint32_t pc = _lr(REG_ADDR_PC);

    if (pc > ICCM_ADDR) {
        // it means that the loader was launched not from system memory
        return 0;
    }

    // we're in system memory - means that this is loader

    _clri(); // Turn off interrupts

    ops_flash_addr = 0; // commands are stored starting at offset 0
    int is_exec = 1;
    scr_error_t err;

    err = scr_read_from_storage_and_exec(ops_flash_addr, is_exec);
    if (err) {
        // indicate an error
    }

    return 0;
}
