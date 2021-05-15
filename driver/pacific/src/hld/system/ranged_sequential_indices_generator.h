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

#ifndef __RANGED_SEQUENTIAL_INDICES_GENERATOR_H__
#define __RANGED_SEQUENTIAL_INDICES_GENERATOR_H__

#include <bitset>
#include <iostream>
#include <vector>

#include "common/cereal_utils.h"
#include "common/la_status.h"

namespace silicon_one
{

class ranged_sequential_indices_generator
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    ranged_sequential_indices_generator() = default;

    ranged_sequential_indices_generator(size_t lower_bound, size_t upper_bound);

    /// @brief Allocate `indices_num` unused indices.
    ///
    /// @param[in]  indices_num     Number of indices to allocate.
    /// @param[out] first_index     The first allocated index.
    ///
    /// @return true if indices allocated properly, false on failure.
    la_status allocate(size_t indices_num, size_t& out_first_index);

    /// @brief Release `indices_num` indices starting from `first_index`.
    ///
    /// @param[in] indices_num     Number of indices to release.
    /// @param[in] first_index     The first index to start releasing from.
    la_status release(size_t indices_num, size_t first_index);

private:
    size_t m_lower_bound;
    size_t m_upper_bound;

    // equal to upper_bound - lower_bound + 1
    size_t m_range_length;

    // m_indices_usage[i] is true iff index i is used.
    std::vector<bool> m_indices_usage;

}; // class ranged_sequential_indices_generator

} // namespace silicon_one

#endif // __RANGED_SEQUENTIAL_INDICES_GENERATOR_H__
