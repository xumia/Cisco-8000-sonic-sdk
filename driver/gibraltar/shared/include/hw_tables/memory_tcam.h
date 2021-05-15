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

#ifndef __MEMORY_TCAM_H__
#define __MEMORY_TCAM_H__

#include "lld/lld_fwd.h"

#include "hw_tables/logical_tcam.h"
#include "hw_tables/physical_locations.h"
#include "hw_tables/tcam_types.h"

namespace silicon_one
{

class ll_device;

/// @brief Implementation of #silicon_one::logical_tcam interface.
///
/// Aggregates one or more physical TCAM sections into a single logical TCAM view.
class memory_tcam : public logical_tcam
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief C'tor
    ///
    /// @param[in]  ldevice             Pointer to low level device.
    /// @param[in]  tcam_width          Key and key mask width in bits.
    /// @param[in]  sram_width          Value width in bits.
    /// @param[in]  sections            Collection of physical locations.
    memory_tcam(const ll_device_sptr& ldevice, size_t key_width, size_t value_width, const std::vector<tcam_section>& sections);

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    memory_tcam() = default;

    /// Logical TCAM API
    la_status write(size_t line, const bit_vector& key, const bit_vector& mask, const bit_vector& value) override;
    la_status write_bulk(size_t first_line, size_t bulk_size, const vector_alloc<tcam_entry_desc>& entries) override;
    la_status write_unsafe(size_t line, const bit_vector& key, const bit_vector& mask, const bit_vector& value, bool multiple_sram);
    la_status move(size_t src_line, size_t dest_line) override;
    la_status update(size_t line, const bit_vector& value) override;
    la_status update_unsafe(size_t line, const bit_vector& value);
    la_status invalidate(size_t line) override;
    la_status set_default_value(const bit_vector& key, const bit_vector& mask, const bit_vector& value) override;
    la_status set_default_value_unsafe(const bit_vector& key, const bit_vector& mask, const bit_vector& value);
    la_status read(size_t line, bit_vector& out_key, bit_vector& out_mask, bit_vector& out_value, bool& out_valid) const override;
    size_t size() const override;
    la_status get_max_available_space(size_t& out_max_scale) const override;
    bool is_valid(size_t line) const;
    la_status get_physical_usage(size_t& out_physical_usage) const override;

private:
    // Pointer to low level device.
    ll_device_sptr m_ll_device;

    // Key width in bits.
    size_t m_key_width;

    // Value width in bits.
    size_t m_value_width;

    /// Total number of rows in all sections.
    size_t m_size;

    /// Collection of memory addresses
    std::vector<tcam_section> m_sections;
};

} // namespace silicon_one

#endif // __MEMORY_TCAM_H__
