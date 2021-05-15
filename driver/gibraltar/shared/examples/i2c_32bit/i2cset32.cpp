// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "i2c_common.h"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

static void
help()
{
    fprintf(stderr,
            "Usage: i2cset32 I2CBUS CHIP-ADDRESS DATA-ADDRESS DATA-VALUE\n"
            "Example: i2cset32 10 0x2a 0x800000 0x0\n");
    exit(1);
}

int
main(int argc, const char* argv[])
{
    if (argc != 5) {
        help();
    }

    uint32_t bus_addr;
    uint8_t chip_addr;
    uint32_t data_addr;
    uint32_t data_value;

    if (parse_arg_bus_addr(argv[1], &bus_addr)) {
        help();
    }
    if (parse_arg_chip_addr(argv[2], &chip_addr)) {
        help();
    }
    if (parse_arg_data_addr(argv[3], &data_addr)) {
        help();
    }
    if (parse_arg_data_value(argv[4], &data_value)) {
        help();
    }

    int fd = open_i2c(bus_addr);
    if (fd < 0) {
        exit(1);
    }

    int rc = i2c_write_register(fd, chip_addr, data_addr, data_value);

    close(fd);

    return rc;
}
