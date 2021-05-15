// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __TEST_DEVICE_COMMON_H__
#define __TEST_DEVICE_COMMON_H__

// Helper functions for low-level driver testing.

#include <time.h>

#include "lld/ll_device.h"

extern char* lld_file_path;

// Return throughput in Mbps
float throughput_mbps(uint64_t interval_time_nsec, float total_bytes);

static inline bool
is_gb()
{
    char* dev_path = getenv("SDK_DEVICE_NAME");
    if (dev_path && strncmp(dev_path, "/dev/uio0", strlen("/dev/uio0")) == 0) {
        bool rc = system("lspci -d 1137:a001 2> /dev/null | grep -q '.*'");
        return rc == 0;
    }
    char* asic = getenv("ASIC");
    return asic && strncmp(asic, "GIBRALTAR", strlen("GIBRALTAR")) == 0;
}

#endif // __TEST_DEVICE_COMMON_H__
