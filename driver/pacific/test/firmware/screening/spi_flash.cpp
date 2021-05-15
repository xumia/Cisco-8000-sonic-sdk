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

#include "spi_flash.h"

enum flash_buffer_size {
    FLASH_BUFFER_BYTES = 64,
    FLASH_BUFFER_DWORDS = FLASH_BUFFER_BYTES >> 2,
};

// Copied from /proj/pacific_lab/users/roie/validation/css/css_global.py
static void
spi_cmd_read_encode(uint32_t addr, int ndwords)
{
    uint32_t nbytes = ndwords << 2;
    if (nbytes > FLASH_BUFFER_BYTES) {
        // ERROR !!!
        return;
    }

    // write the address to SBIF addr control reg
    ops.sbif_write_dword(SBIF_SPI_CTRL_ADDR_REG, addr);

    // Encode SPI READ command
    uint32_t spi_instr = 0x03;
    uint32_t spi_sck_half_period = 0x30; // 0x0f;
    uint32_t spi_data_dir = 0x0;
    uint32_t spi_data_len = nbytes;
    uint32_t spi_add_len = 0x1;

    uint32_t val = (spi_instr & 0xff) | ((spi_sck_half_period & 0x3f) << 22) | ((spi_add_len & 0x3) << 8)
                   | ((spi_data_len & 0x7f) << 10) | ((spi_data_dir & 0x1) << 17);

    ops.sbif_write_dword(SBIF_SPI_CTRL_CFG_REG, val);
}

static void
spi_cmd_exec_poll()
{
    ops.sbif_write_dword(SBIF_SPI_CTRL_EXEC_REG, 1);

    // poll for completion
    uint32_t val = 1;
    while (val) {
        ops.yield();
        ops.sbif_read_dword(SBIF_SPI_CTRL_EXEC_REG, &val);
    }
}

// Copied from /proj/pacific_lab/users/roie/validation/css/css_global.py
void
spi_read_from_flash(uint32_t addr, uint32_t ndwords, uint32_t* dwords)
{
    int i;

    // Read 1 dword at a time, though we could read up to FLASH_BUFFER_DWORDS at a time
    for (i = 0; i < ndwords; ++i) {
        spi_cmd_read_encode(addr, 1 /* ndwords */);
        spi_cmd_exec_poll();
        ops.sbif_read_dword(SBIF_SPI_CTRL_DATA_REG_0, &(dwords[i]));
    }
}
