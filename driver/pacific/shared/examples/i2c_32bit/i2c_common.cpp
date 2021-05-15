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

#include <byteswap.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

template <class T, size_t N>
constexpr size_t
array_size(const T (&)[N])
{
    return N;
}

int
i2c_write_register(int fd, uint8_t chip_addr, uint32_t data_addr, uint32_t val)
{
    uint32_t swapped_addr = bswap_32(data_addr);
    uint32_t swapped_val = bswap_32(val);
    uint32_t msg_buf[2] = {swapped_addr, swapped_val};

    struct i2c_msg msg = {
        .addr = chip_addr, .flags = 0, .len = sizeof(msg_buf), .buf = (uint8_t*)&msg_buf[0],
    };

    struct i2c_rdwr_ioctl_data ioctl_data = {
        .msgs = &msg, .nmsgs = 1,
    };

    int ret = ioctl(fd, I2C_RDWR, &ioctl_data);
    if (ret < 0) {
        fprintf(stderr, "ioctl(I2C_RDRW) failed - %d (%s)", errno, strerror(errno));
        return ret;
    }

    return 0;
}

int
i2c_read_register(int fd, uint8_t chip_addr, uint32_t data_addr, uint32_t* out_val)
{
    uint32_t swapped_addr = bswap_32(data_addr);
    uint32_t swapped_val = bswap_32(0xdeadbeaf);

    struct i2c_msg msgs[2];

    /*addr_msg*/
    msgs[0].addr = chip_addr;
    msgs[0].flags = 0;
    msgs[0].len = sizeof(data_addr);
    msgs[0].buf = (uint8_t*)&swapped_addr;

    /*data_msg*/
    msgs[1].addr = chip_addr;
    msgs[1].flags = I2C_M_RD;
    msgs[1].len = sizeof(swapped_val);
    msgs[1].buf = (uint8_t*)&swapped_val;

    struct i2c_rdwr_ioctl_data ioctl_data = {
        .msgs = msgs, .nmsgs = array_size(msgs),
    };

    int rc = ioctl(fd, I2C_RDWR, &ioctl_data);
    if (rc < 0) {
        fprintf(stderr, "ioctl(I2C_RDRW) failed - %d (%s)", errno, strerror(errno));
        return rc;
    }

    *out_val = bswap_32(swapped_val);

    return 0;
}

int
open_i2c(uint32_t bus_addr)
{
    char buf[80];
    snprintf(buf, sizeof(buf), "/dev/i2c-%d", bus_addr);

    int fd = open(buf, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s, %s\n", buf, strerror(errno));
    }

    return fd;
}

int
parse_arg_bus_addr(const char* arg, uint32_t* bus_addr)
{
    char* endptr;
    unsigned long val = strtol(arg, &endptr, 0 /* automatically choose decimal or hex base */);
    if (*endptr || val < 0 || val > 0xfffff) {
        fprintf(stderr, "bad bus_addr, must be an integer from 0 to 0xfffff\n");
        return -1;
    }

    *bus_addr = (uint32_t)val;

    return 0;
}

int
parse_arg_chip_addr(const char* arg, uint8_t* chip_addr)
{
    char* endptr;
    unsigned long val = strtol(arg, &endptr, 0 /* automatically choose decimal or hex base */);
    if (*endptr || val < 0x03 || val > 0x77) {
        fprintf(stderr, "bad chip_addr, must be an integer from 0x03 to 0x77\n");
        return -1;
    }

    *chip_addr = (uint8_t)val;

    return 0;
}

int
parse_arg_data_addr(const char* arg, uint32_t* data_addr)
{
    char* endptr;
    unsigned long val = strtol(arg, &endptr, 0 /* automatically choose decimal or hex base */);
    if (*endptr) {
        fprintf(stderr, "bad data_addr\n");
        return -1;
    }

    *data_addr = (uint32_t)val;

    return 0;
}

int
parse_arg_data_value(const char* arg, uint32_t* data_value)
{
    char* endptr;
    unsigned long val = strtol(arg, &endptr, 0 /* automatically choose decimal or hex base */);
    if (*endptr) {
        fprintf(stderr, "bad data_addr\n");
        return -1;
    }

    *data_value = (uint32_t)val;

    return 0;
}
