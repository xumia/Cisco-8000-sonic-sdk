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

#include "common/profile_allocator.h"
#include "gtest/gtest.h"
#include <memory>

using namespace std;
using namespace silicon_one;

// Note this tests that the allocator

TEST(profile_allocator, sharing)
{
    auto allocator = make_shared<profile_allocator<int> >(5, 16);

    auto profile1 = allocator->allocate(0xab);
    auto profile2 = allocator->allocate(0x12);
    auto profile3 = allocator->allocate(0xab);

    EXPECT_EQ(profile1->id(), 5U);
    EXPECT_EQ(profile2->id(), 6U);
    EXPECT_EQ(profile3->id(), 5U);

    EXPECT_EQ(profile1->value(), 0xab);
    EXPECT_EQ(profile2->value(), 0x12);
    EXPECT_EQ(profile3->value(), 0xab);
}

TEST(profile_allocator, deletion)
{
    auto allocator = make_shared<profile_allocator<int> >(11, 32);

    {
        auto profile = allocator->allocate(0xab);
        EXPECT_EQ(profile->id(), 11U);
        EXPECT_EQ(profile->value(), 0xab);
    }
    {
        auto profile1 = allocator->allocate(0x12);
        EXPECT_EQ(profile1->id(), 11U);
        EXPECT_EQ(profile1->value(), 0x12);

        auto profile2 = allocator->allocate(0x12);
        EXPECT_EQ(profile2->id(), 11U);
        EXPECT_EQ(profile2->value(), 0x12);

        auto profile3 = allocator->allocate(0xab);
        EXPECT_EQ(profile3->id(), 12U);
        EXPECT_EQ(profile3->value(), 0xab);
    }
    {
        auto profile = allocator->allocate(0xab);
        EXPECT_EQ(profile->id(), 11U);
        EXPECT_EQ(profile->value(), 0xab);
    }
}
