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

#ifndef __DELAYED_RANGED_INDEX_GENERATOR_H__
#define __DELAYED_RANGED_INDEX_GENERATOR_H__

#include "common/cereal_utils.h"
#include "common/ranged_index_generator.h"
#include "common/stopwatch.h"
#include <chrono>

/// @file
/// @brief Ranged index generator.

namespace silicon_one
{

/// @brief Delay ranged index generator.
///
/// Manages index allocation/deallocation for a given resource. Allows delaying of the release of the index
class delayed_ranged_index_generator
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    delayed_ranged_index_generator() = default;

    delayed_ranged_index_generator(uint64_t lower_bound, uint64_t upper_bound, std::chrono::microseconds delayed_release);

    /// @brief Allocate an unused index.
    ///
    /// @return Allocated index, or INVALID_INDEX on failure.
    uint64_t allocate();

    /// @brief Deallocate a used index.
    ///
    /// @param[in]  index   Index to deallocate.
    void release(uint64_t index);

private:
    uint64_t m_lower_bound = 0;
    uint64_t m_upper_bound = 0;
    void check_for_delayed_release();
    ranged_index_generator m_index_gen;
    std::chrono::microseconds m_delayed_release_threshold = std::chrono::microseconds(0);
    std::vector<stopwatch> m_delayed_array;
};

} // namespace silicon_one

#endif
