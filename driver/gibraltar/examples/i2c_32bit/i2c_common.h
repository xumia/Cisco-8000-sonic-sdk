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

#ifndef __I2C_COMMON_H__
#define __I2C_COMMON_H__

#include <stdint.h>
#include <stdlib.h>

int parse_arg_bus_addr(const char* arg, uint32_t* bus_addr);

int parse_arg_chip_addr(const char* arg, uint8_t* chip_addr);

int parse_arg_data_addr(const char* arg, uint32_t* data_addr);

int parse_arg_data_value(const char* arg, uint32_t* data_value);

int open_i2c(uint32_t bus_addr);

int i2c_write_register(int fd, uint8_t chip_addr, uint32_t data_addr, uint32_t val);

int i2c_read_register(int fd, uint8_t chip_addr, uint32_t data_addr, uint32_t* out_val);

#endif
