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

#include "common.h"
#include "counters.h"
#include "routine_counters.h"
#include "status_reg.h"

#include "test_cem_stub.h"
#include "test_if.h"
#include "uaux_regs_mem.h"

// for memcpy/memset
#include <string.h>

/// @file
/// @brief Test sizes of UAUX registers vs their shadows

void
test_check_var_size_init()
{
    test_CEM_NUM_CORES = 1;
    test_CEM_NUM_BANKS = 2;
    test_CEM_NUM_ENTRIES = 3;
    test_init_cem();
}

void
test_check_var_size_check()
{
    PRINT("-CHK- basic types\n");
    ASSERT(1 == sizeof(uint8_t));
    ASSERT(2 == sizeof(uint16_t));
    ASSERT(4 == sizeof(uint32_t));

    PRINT("-CHK- periodic counter\n");
    ASSERT(4 == sizeof(periodic_counter));

    PRINT("-CHK- UAUX_LEARN_REG\n");
    ASSERT(MEM_ALIGN * reg_size(UAUX_LEARN_REG) == sizeof(learn_data));
    PRINT("-CHK- UAUX_REFRESH_REG\n");
    ASSERT(MEM_ALIGN * reg_size(UAUX_REFRESH_REG) == sizeof(refresh_data));
    PRINT("-CHK- UAUX_AGING_REG\n");
    ASSERT(MEM_ALIGN * reg_size(UAUX_AGING_REG) == sizeof(scan_data));
    PRINT("-CHK- UAUX_COUNTERS_REQUEST_REG\n");
    ASSERT(MEM_ALIGN * reg_size(UAUX_COUNTERS_REQUEST_REG) == sizeof(counter_request_data));
    PRINT("-CHK- UAUX_COUNTERS_RESPONSE_REG\n");
    ASSERT(MEM_ALIGN * reg_size(UAUX_COUNTERS_RESPONSE_REG) == sizeof(uint32_t));
    PRINT("-CHK- UAUX_GROUP_REQUEST_REG\n");
    ASSERT(MEM_ALIGN * reg_size(UAUX_GROUP_REQUEST_REG) == sizeof(group_request_data));
    PRINT("-CHK- UAUX_GROUP_RESPONSE_REG\n");
    ASSERT(MEM_ALIGN * reg_size(UAUX_GROUP_RESPONSE_REG) == sizeof(group_response_data));
    PRINT("-CHK- UAUX_EM_REQUEST_REG\n");
    ASSERT(MEM_ALIGN * reg_size(UAUX_EM_REQUEST_REG) == sizeof(em_request_data));
    PRINT("-CHK- UAUX_EM_RESPONSE_REG\n");
    ASSERT(MEM_ALIGN * reg_size(UAUX_EM_RESPONSE_REG) == sizeof(em_response_data));
}

void
test_check_var_size_main_loop_poll()
{
    test_check_var_size_check();

    // everything is passed - exit normally
    test_exit(0);
}

// ******************************
// TEST
// ******************************
void __attribute__((used)) test_check_var_size()
{
    // setup main loop polling
    test_main_loop_poll_callback = test_check_var_size_main_loop_poll;

    test_check_var_size_init();
}
