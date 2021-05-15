// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LEABA_TEST_LPM_CORE_COMMON_H__
#define __LEABA_TEST_LPM_CORE_COMMON_H__

#include "lpm/lpm_core.h"
#include "test_lpm_read_entries.h"
#include "test_lpm_types.h"

using namespace silicon_one;

namespace test_lpm_core
{

void sanity_entries(const lpm_core* core,
                    const test_data_lpm_entries_set_t& user_entries_in_core,
                    const test_data_lpm_entries_set_t& auto_generated_entries_in_core);
void lookup_test(const lpm_core* core, const test_data_lpm_entries_set_t& entries_in_core, char error_message[] = nullptr);

void remove_all_entries(lpm_core* core, test_data_lpm_entries_set_t& entries_in_core);
}

#endif // __LEABA_TEST_LPM_CORE_COMMON_H__
