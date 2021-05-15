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

#ifndef __TRAP_TCAM_H__
#define __TRAP_TCAM_H__

#include "hw_tables/memory_tcam.h"
#include "lld/ll_device.h"

#include <memory>

namespace silicon_one
{

/// @brief Implementation of #silicon_one::logical_tcam interface.
///
/// Special implementation for trap/snoop TCAM.
/// trap/snoop TCAM is sharing the same resource, which is split to two sections:
/// - Upper table resides starting first line and grows straight (top to bottom).
/// - Lower table resides starting last line and grows reversed (bottom to top).
/// - configuration register is sets the size of the straight section.
class trap_tcam : public memory_tcam
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    enum {
        // NPL is setting trap table size to a larger number
        // to avoid blocking inserts on logical level. NPL size does not reflect physical dimentions.
        NUM_ENTRIES = 128,
    };

    /// @brief C'tor
    ///
    /// @param[in]  ldevice             Pointer to low level device.
    /// @param[in]  tcam_width          Key and key mask width in bits.
    /// @param[in]  sram_width          Value width in bits.
    /// @param[in]  sections            Collection of physical locations.
    /// @param[in]  config_regs         Replications of configuration register.
    trap_tcam(const ll_device_sptr& ldevice,
              size_t key_width,
              size_t value_width,
              const std::vector<tcam_section>& sections,
              const std::vector<lld_register_scptr>& config_regs);

    /// Logical TCAM API
    la_status write(size_t line, const bit_vector& key, const bit_vector& mask, const bit_vector& value) override;
    la_status move(size_t src_line, size_t dest_line) override;
    la_status update(size_t line, const bit_vector& value) override;
    la_status invalidate(size_t line) override;
    la_status read(size_t line, bit_vector& out_key, bit_vector& out_mask, bit_vector& out_value, bool& out_valid) const override;

    /// Trap tcam interfaces

    /// @brief Initialize trap tcam tables.
    la_status initialize();

    /// @brief Return the size of the resource.
    ///
    /// @param[in] reversed     if true, returns the size of the reversed section.
    ///
    /// @retval resource size.
    size_t get_resource_size(bool reversed) const;

    /// @brief Sets resource size.
    ///
    /// @param[in]  new_size        New size of trap table resource.
    /// @param[in]  reversed        if true, sets the size of the reversed section.
    ///
    /// @retval status code.
    la_status resize_resource(size_t new_size, bool reversed);

private:
    trap_tcam() = default; // For serialization purposes only.
    // Update configuration registers.
    la_status update_config_regs();

private:
    // Pointer to low level device.
    ll_device_sptr m_ll_device;

    // Total size of both straight and reversed sections.
    size_t m_size;

    // Value width in bits.
    size_t m_value_width;

    // Tracking of occupied entries.
    std::vector<bool> m_entries;

    // Replications of configuration register.
    std::vector<lld_register_scptr> m_config_regs;

    // Size of straight section.
    size_t m_upper_table_size;
};

} // namespace silicon_one

#endif // __TRAP_TCAM_H__
