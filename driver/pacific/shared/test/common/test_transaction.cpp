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

#include "common/transaction.h"
#include "gtest/gtest.h"
#include <algorithm>

using namespace std;
using namespace silicon_one;

constexpr uint32_t num_insertions = 40;

la_status
test_func(vector<uint32_t>& vec, bool exception, bool error_code)
{
    transaction txn;

    for (uint32_t i = 0; i < num_insertions; ++i) {
        vec.push_back(i);
        txn.on_fail([=, &vec]() {
            // These should execute in reverse order on failure, so the
            // element should be at the end each time
            EXPECT_EQ(*(vec.end() - 1), i);
            vec.erase(vec.end() - 1);
        });
    }

    if (exception) {
        throw std::invalid_argument("test exception");
    }

    if (error_code) {
        txn.status = LA_STATUS_EINVAL;
        return txn.status;
    }

    return LA_STATUS_SUCCESS;
}

TEST(transaction, exception)
{
    vector<uint32_t> vec;

    try {
        (void)test_func(vec, true, false);
    } catch (std::exception& e) {
        EXPECT_EQ(e.what(), string{"test exception"});
    }

    EXPECT_EQ(vec.size(), 0U);
}

TEST(transaction, error_code)
{
    vector<uint32_t> vec;

    la_status status = test_func(vec, false, true);

    EXPECT_EQ(status, LA_STATUS_EINVAL);
    EXPECT_EQ(vec.size(), 0U);
}

TEST(transaction, success)
{
    vector<uint32_t> vec;

    la_status status = test_func(vec, false, false);

    EXPECT_EQ(status, LA_STATUS_SUCCESS);
    EXPECT_EQ(vec.size(), num_insertions);
}
