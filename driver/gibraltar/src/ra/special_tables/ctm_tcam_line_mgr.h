// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __CTM_TCAM_LINE_MGR_H__
#define __CTM_TCAM_LINE_MGR_H__

#include "common/allocator_wrapper.h"
#include "common/bit_vector.h"
#include "common/cereal_utils.h"
#include "common/gen_utils.h"

#include <stddef.h>

namespace silicon_one
{

/// @brief Shared TCAM management for CDB Central TCAMs.
///
/// Central TCAM memories are shared between different tables.
/// ctm_db is maintaining a list of free TCAM lines to be shared between NPL tables, mapped to the same resource.

class ctm_tcam_line_mgr
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    ctm_tcam_line_mgr();
    explicit ctm_tcam_line_mgr(size_t size);

    // Returns next free line, starting given min_line value (included)
    void allocate_line(size_t line);
    void release_line(size_t line);
    void allocate_all_lines();
    void release_all_lines();
    // size_t get_size();
    size_t get_num_alloc_lines() const;
    size_t get_num_free_lines() const;
    size_t get_size() const;

    size_t get_first_free_line_in_range(size_t start_line, size_t end_line);
    size_t get_next_free_line(const size_t current);

    bool is_occupied(const size_t line) const;

private:
    size_t m_size;
    bit_vector m_occupied_lines;
    size_t m_number_of_free_lines;
};

} // namespace silicon_one

#endif // __CTM_SHARED_DB_H__
