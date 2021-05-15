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

#include "common/ranged_index_generator.h"
#include "gtest/gtest.h"
#include <functional>
#include <iostream>
#include <random>
#include <vector>

using namespace std;
using namespace silicon_one;

struct result_t {
    index_handle index;
    int size;
};

TEST(ranged_index_generator, random_actions)
{
    // Fixed but arbitrary seed for reproducibility
    mt19937 rng(0xface1234);

    // 8 iterations
    for (int i = 0; i < 8; ++i) {
        // Use random even min&max
        uint32_t min = uniform_int_distribution<>(0, 500)(rng) * 2;
        uint32_t max = uniform_int_distribution<>(200, 10000)(rng) * 2 + min;

        vector<result_t> res_vec;
        res_vec.reserve(max - min);

        auto gen = std::make_shared<ranged_index_generator>(min, max, true);

        uniform_int_distribution<> zero_to_two(0, 2);

        // Loop until it is full plus a few extra iterations
        for (int full_count = 0; full_count < 100;) {
            // Perform a random allocation or removal
            switch (zero_to_two(rng)) {
            case 0: {
                // allocate a pair
                index_handle hndl(gen, true);
                if (hndl) {
                    res_vec.push_back({std::move(hndl), 2});
                }
            } break;
            case 1: {
                // allocate a single element
                index_handle hndl(gen, false);
                if (hndl) {
                    res_vec.push_back({std::move(hndl), 1});
                } else {
                    ++full_count;
                }
            } break;
            case 2:
                if (res_vec.size() > 0) {
                    // Delete a random element
                    uniform_int_distribution<> selector(0, res_vec.size() - 1);
                    std::swap(res_vec.at(selector(rng)), res_vec.back());
                    res_vec.pop_back();
                }
                break;
            }
        }

        // Shoudl be full
        EXPECT_EQ(gen->available(), 0U);

        // Sort results for analysis
        std::sort(res_vec.begin(), res_vec.end(), [](result_t& a, result_t& b) { return (a.index < b.index); });

        {
            // Elements should be spaced correctly
            auto it = std::adjacent_find(
                res_vec.begin(), res_vec.end(), [](result_t& a, result_t& b) { return ((a.index + a.size) != b.index); });
            EXPECT_EQ(it, res_vec.end());
        }

        // First and last value should be correct
        EXPECT_EQ(res_vec.front().index, min);
        EXPECT_EQ(res_vec.back().index + res_vec.back().size, max);

        {
            // There should be no pairs with odd indices
            auto it
                = std::find_if(res_vec.begin(), res_vec.end(), [](result_t& a) { return ((a.size == 2) && ((a.index % 2) != 0)); });
            EXPECT_EQ(it, res_vec.end());
        }

        uint32_t num_pairs = std::count_if(res_vec.begin(), res_vec.end(), [](result_t& a) { return a.size == 2; });
        // cout << "num_pairs: " << num_pairs << endl;
        uint32_t num_single = std::count_if(res_vec.begin(), res_vec.end(), [](result_t& a) { return a.size == 1; });
        // cout << "num_single: " << num_single << endl;
        EXPECT_EQ(num_pairs * 2 + num_single, max - min);

        res_vec.clear();
    }
}
