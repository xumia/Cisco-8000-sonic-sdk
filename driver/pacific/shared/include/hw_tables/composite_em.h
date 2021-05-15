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

#ifndef __COMPOSITE_EM_H__
#define __COMPOSITE_EM_H__

#include "hw_tables/hw_tables_fwd.h"
#include "hw_tables/logical_em.h"

#include <vector>

namespace silicon_one
{

/// @brief Implements a list of logical exact matches.
class composite_em : public logical_em
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief C'tor
    ///
    /// @param[in]  ems                 List of logical EMs.
    explicit composite_em(const std::vector<logical_em_sptr>& ems);
    ~composite_em();

    // Logical EM API-s

    la_status insert(const bit_vector& key, const bit_vector& payload) override;
    la_status update(const bit_vector& key, const bit_vector& payload) override;
    la_status erase(const bit_vector& key) override;
    size_t max_size() const override;
    la_status get_physical_usage(size_t num_of_table_logical_entries, size_t& out_physical_usage) const override;
    la_status get_available_entries(size_t& out_available_entries) const override;
    la_status set_resource_monitor(const resource_monitor_sptr& monitor) override;
    la_status get_resource_monitor(resource_monitor_sptr& out_monitor) const override;
    size_t size() const override;
    la_status erase(const bit_vector& key, size_t payload_width) override;
    bool is_flexible_entry_supported() const override;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    composite_em() = default;

    // Forbid copy
    composite_em(const composite_em&);
    composite_em& operator=(const composite_em&);

private:
    // List of logical EMs
    std::vector<logical_em_sptr> m_ems;
};

} // namespace silicon_one

#endif // __COMPOSITE_EM_H__
