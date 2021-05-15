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

#ifndef __MEMORY_SRAM_H__
#define __MEMORY_SRAM_H__

#include "hw_tables/logical_sram.h"
#include "hw_tables/physical_locations.h"
#include "lld/lld_fwd.h"

namespace silicon_one
{

class ll_device;

/// @brief Implementation of #silicon_one::logical_sram interface.
///
/// Aggregates one or more physical SRAM sections into a single logical SRAM view.
class memory_sram : public logical_sram
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief C'tor
    ///
    /// @param[in]  ldevice             Pointer to low level device.
    /// @param[in]  line_width          Logical memory line width in bits.
    /// @param[in]  sections            Collection of physical locations. Total width should match line width.
    memory_sram(const ll_device_sptr& ldevice,
                size_t line_width,
                const std::vector<sram_section>& sections,
                bool section_line_reversed = false);

    /// Logical SRAM API
    virtual la_status write(size_t line, const bit_vector& value);
    virtual size_t max_size() const;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    memory_sram() = default;

    // Pointer to low level device.
    ll_device_sptr m_ll_device;

    /// Memory line width in bits, including all memories in the row.
    size_t m_line_width;

    /// Number of rows in all sections.
    size_t m_size;

    /// Collection of physical memories composing this logical SRAM.
    std::vector<sram_section> m_sections;

    bool m_section_line_reversed;
};

} // namespace silicon_one

#endif // __MEMORY_SRAM_H__
