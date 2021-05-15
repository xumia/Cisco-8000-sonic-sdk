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

#ifndef __COMPOSITE_TCAM_H__
#define __COMPOSITE_TCAM_H__

#include "hw_tables/logical_tcam.h"
#include "hw_tables/tcam_types.h"

#include <vector>

namespace silicon_one
{

/// @brief Implements a list of logical TCAMs.
class composite_tcam : public logical_tcam
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief C'tor
    ///
    /// @param[in]  tcams               List of logical TCAMs.
    explicit composite_tcam(const std::vector<logical_tcam_sptr>& tcams);
    ~composite_tcam() = default;

    /// Logical TCAM API
    la_status write(size_t line, const bit_vector& key, const bit_vector& mask, const bit_vector& value) override;
    la_status write_bulk(size_t first_line, size_t bulk_size, const vector_alloc<tcam_entry_desc>& entries) override;
    la_status move(size_t src_line, size_t dest_line) override;
    la_status update(size_t line, const bit_vector& value) override;
    la_status invalidate(size_t line) override;
    la_status read(size_t line, bit_vector& out_key, bit_vector& out_mask, bit_vector& out_value, bool& out_valid) const override;

    la_status set_default_value(const bit_vector& key, const bit_vector& mask, const bit_vector& value) override;
    size_t size() const override;
    la_status get_max_available_space(size_t& out_max_scale) const override;
    la_status get_physical_usage(size_t& out_physical_usage) const override;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    composite_tcam() = default;

    // Forbid copy
    composite_tcam(const composite_tcam&);
    composite_tcam& operator=(const composite_tcam&);

private:
    // List of logical TCAMs
    std::vector<logical_tcam_sptr> m_tcams;
};

} // namespace silicon_one

#endif // __COMPOSITE_TCAM_H__
