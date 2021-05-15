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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "gtest/gtest.h"

#include "lld/ll_device.h"

#include "test_device_common.h"

char* lld_file_path = nullptr;

//-----------------------------------------------------------------------------------------------------
void
usage(const char* prog)
{
    fprintf(stderr, "Usage: %s -d <device path>\n", prog);
    fprintf(stderr, "Parameters information:\n");
    fprintf(stderr, "-d <path> - Device path, E.g. /dev/uio0 \n");
}

//-----------------------------------------------------------------------------------------------------
int
main(int argc, char** argv)
{
    // This allows the user to override the flag on the command line.
    ::testing::InitGoogleTest(&argc, argv);

    // Parse specific options
    int opt;

    while ((opt = getopt(argc, argv, "d:")) != -1) {
        switch (opt) {
        case 'd':
            lld_file_path = strdup(optarg);
            break;
        default: /* '?' */
            usage(argv[0]);
        }
    }

    if (!lld_file_path) {
        // Use default
        // lld_file_path = strdup("/dev/uio0");
        lld_file_path = strdup("/dev/testdev");
    }

    if (is_gb()) {
        // Skip DeviceSimulatorTest test cases
        ::testing::GTEST_FLAG(filter) = "-DeviceSimulatorTest.*";
    }

    return RUN_ALL_TESTS();
}
