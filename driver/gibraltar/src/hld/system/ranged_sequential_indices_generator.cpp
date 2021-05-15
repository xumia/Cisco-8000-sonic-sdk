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

#include <bitset>
#include <iostream>
#include <vector>

#include "common/la_status.h"
#include "ranged_sequential_indices_generator.h"

namespace silicon_one
{

ranged_sequential_indices_generator::ranged_sequential_indices_generator(size_t lower_bound, size_t upper_bound)
    : m_lower_bound(lower_bound), m_upper_bound(upper_bound)
{
    m_range_length = upper_bound - lower_bound + 1;
    m_indices_usage.resize(m_range_length);
}

la_status
ranged_sequential_indices_generator::allocate(size_t indices_num, size_t& out_first_index)
{
    size_t first_index_candidate = 0;
    bool found = false;
    while (!found && (first_index_candidate + indices_num - 1) < m_range_length) {
        size_t i = first_index_candidate;
        size_t allocated_indices = 0;
        // Don't change the order of the conditions, if you do, you may get index out of range error in case you are allocating the
        // last index.
        while (allocated_indices < indices_num && !m_indices_usage[i]) {
            i++;
            allocated_indices++;
        }
        if (allocated_indices == indices_num) { // we found a valid allocation
            found = true;
        } else { // we didn't find valid allocation
            // find next candidate to be the first index
            while (m_indices_usage[i]) {
                i++;
            }
            first_index_candidate = i;
        }
    }
    if (!found) {
        return LA_STATUS_ERESOURCE;
    }

    out_first_index = first_index_candidate + m_lower_bound;
    // set allocated indices to used.
    for (size_t i = first_index_candidate; i < first_index_candidate + indices_num; i++) {
        m_indices_usage[i] = true;
    }
    return LA_STATUS_SUCCESS;
}

la_status
ranged_sequential_indices_generator::release(size_t indices_num, size_t first_index)
{
    if (first_index < m_lower_bound || first_index + indices_num - 1 > m_upper_bound) {
        return LA_STATUS_EOUTOFRANGE;
    }
    size_t _first_index = first_index - m_lower_bound;
    for (size_t i = _first_index; i < _first_index + indices_num; i++) {
        m_indices_usage[i] = false;
    }
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
