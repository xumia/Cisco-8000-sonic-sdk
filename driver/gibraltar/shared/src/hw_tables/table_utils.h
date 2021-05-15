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

#ifndef __TABLE_UTILS_H__
#define __TABLE_UTILS_H__

#include "lld/lld_fwd.h"

#include "hw_tables/em_common.h"
#include "hw_tables/physical_locations.h"

namespace silicon_one
{

class em_hasher;

namespace table_utils
{
/// @brief Writes data to SRAM.
///
/// Writes data to the specified line of provided physical SRAM.
///
/// param[in]   ldevice             #silicon_one::ll_device.
/// param[in]   sram                SRAM sub-region.
/// param[in]   line                Memory line within the region, relative to its beginning.
/// param[in]   offset              Offset in bits within the region, relative to its beginning.
/// param[in]   value               Data to be written.
///
/// @retval     status code.
la_status write_physical_sram(const ll_device_sptr& ldevice,
                              const physical_sram& sram,
                              size_t line,
                              size_t offset,
                              const bit_vector& value);

/// @brief Reads data from SRAM.
///
/// Reads data from a specified line of provided physical SRAM.
/// Assumes that all HW locations of the physical SRAM store the same value.
///
/// param[in]   ldevice             #silicon_one::ll_device.
/// param[in]   sram                SRAM sub-region.
/// param[in]   line                Memory line within the region, relative to its beginning.
/// param[in]   out_val             bit_vector to read to.
///
/// @retval     status code.
la_status read_physical_sram(const ll_device_sptr& ldevice, const physical_sram& sram, size_t line, bit_vector& out_val);

/// @brief Writes data to SRAM.
///
/// Writes data to a specific bit sequence.
///
/// param[in]   ldevice           #silicon_one::ll_device.
/// param[in]   sram              SRAM sub-region.
/// param[in]   reg_idx           Index of register to be modified.
/// param[in]   entry_offset      Offset in bits within the region, relative to its beginning.
/// param[in]   value             Data to be written.
///
/// @retval     status code.
la_status write_register_array_sram(const ll_device_sptr& ldevice,
                                    const register_array& sram,
                                    size_t reg_idx,
                                    size_t entry_offset,
                                    const bit_vector& value);

/// @brief Writes data to register array SRAM collection.
///
/// Writes data to a list of SRAM sub-regions, representing wide horizontal memory.
/// The data is split between the SRAMs according to the widths.
///
/// param[in]   ldevice           #silicon_one::ll_device.
/// param[in]   srams             List of register_array SRAMs.
/// param[in]   line              Memory line, relative to section beginning.
/// param[in]   value             Data to be written.
///
/// @retval     status code.
la_status write_sram_section(const ll_device_sptr& ldevice,
                             const std::vector<register_array>& srams,
                             size_t line,
                             const bit_vector& value);

/// @brief Writes data to memory SRAM collection.
///
/// Writes data to a list of SRAM sub-regions, representing wide horizontal memory.
/// The data is split between the SRAMs according to the widths.
///
/// param[in]   ldevice             #silicon_one::ll_device.
/// param[in]   section             List of SRAM sub-regions.
/// param[in]   line                Memory line, relative to section beginning.
/// param[in]   offset              Offset in bits, relative to section beginning.
/// param[in]   value               Data to be written.
///
/// @retval     status code.
la_status write_sram_section(const ll_device_sptr& ldevice,
                             const std::vector<physical_sram>& section,
                             size_t line,
                             size_t offset,
                             const bit_vector& value);

/// @brief Writes data to memory SRAM collection.
///
/// Writes data to a list of SRAM sub-regions, representing wide horizontal memory.
/// The data is split between the SRAMs according to the widths.
///
/// param[in]   ldevice             #silicon_one::ll_device.
/// param[in]   section             List of SRAM sub-regions.
/// param[in]   line                Memory line, relative to section beginning.
/// param[in]   offset              Offset in bits, relative to section beginning.
/// param[in]   value               Data to be written.
///
/// @retval     status code.
la_status write_sram_section_with_multiple_mem(const ll_device_sptr& ldevice,
                                               const std::vector<physical_sram>& section,
                                               size_t line,
                                               size_t offset,
                                               const bit_vector& value);

/// @brief Reads data from SRAM collection.
///
/// Reads data from a list of SRAM sub-regions, representing wide horizontal memory.
/// The data is aggregated according to the SRAM widths.
///
/// param[in]   ldevice             #silicon_one::ll_device.
/// param[in]   section             List of SRAM sub-regions.
/// param[in]   line                Memory line, relative to section beginning.
/// param[in]   out_val             bit_vector to read to.
///
/// @retval     status code.
la_status read_sram_section(const ll_device_sptr& ldevice,
                            const std::vector<physical_sram>& section,
                            size_t line,
                            bit_vector& out_val);

/// @brief Writes data to TCAM.
///
/// Writes data to the specified line of provided physical TCAM.
///
/// param[in]   ldevice             #silicon_one::ll_device.
/// param[in]   tcam                TCAM sub-region.
/// param[in]   line                Memory line within the region, relative to its beginning.
/// param[in]   key                 Key to be written.
/// param[in]   mask                Mask to be written.
///
/// @retval     status code.
la_status write_physical_tcam(const ll_device_sptr& ldevice,
                              const physical_tcam& tcam,
                              size_t line,
                              const bit_vector& key,
                              const bit_vector& mask);

/// @brief Reads data to TCAM.
///
/// Reads data from the specified line of provided physical TCAM.
/// Assumes that all HW locations of the physical TCAM store the same value.
///
/// param[in]   ldevice             #silicon_one::ll_device.
/// param[in]   tcam                TCAM sub-region.
/// param[in]   line                Memory line within the region, relative to its beginning.
/// param[in]   out_key             Key bit_vector to read to.
/// param[in]   out_mask            Mask bit_vector to read to.
/// param[in]   out_valid           valid_bit read to.
///
/// @retval     status code.
la_status read_physical_tcam(const ll_device_sptr& ldevice,
                             const physical_tcam& tcam,
                             size_t line,
                             bit_vector& out_key,
                             bit_vector& out_mask,
                             bool& out_valid);

/// @brief Writes data to TCAM collection.
///
/// Writes data to a list of TCAM sub-regions, representing wide horizontal memory.
/// The data is split between the TCAMs according to the widths.
///
/// param[in]   ldevice             #silicon_one::ll_device.
/// param[in]   section             List of SRAM sub-regions.
/// param[in]   line                Memory line, relatively to section beginning.
/// param[in]   key                 Key to be written.
/// param[in]   mask                Mask to be written.
///
/// @retval     status code.
la_status write_tcam_section(const ll_device_sptr& ldevice,
                             const std::vector<physical_tcam>& section,
                             size_t line,
                             const bit_vector& key,
                             const bit_vector& mask);

/// @brief Reads data from TCAM collection.
///
/// Reads data from a list of TCAM sub-regions, representing wide horizontal memory.
/// The data is aggregated according to the TCAM widths.
///
/// param[in]   ldevice             #silicon_one::ll_device.
/// param[in]   section             List of SRAM sub-regions.
/// param[in]   line                Memory line, relatively to section beginning.
/// param[in]   out_key             Key bit_vector to read to.
/// param[in]   out_mask            Mask bit_vector to read to.
/// param[in]   out_valid           valid_bit read to.
///
/// @retval     status code.
la_status read_tcam_section(const ll_device_sptr& ldevice,
                            const std::vector<physical_tcam>& section,
                            size_t line,
                            bit_vector& out_key,
                            bit_vector& out_mask,
                            bool& out_valid);

/// @brief Finds section, which contains provided line.
///
/// @param[in]  sections            List of sections.
/// @param[in] line                 Line number, relatively to the beginning.
/// @param[out] out_line_in_section     Line number, relatively to the beginning of found section.
///
/// @retval     section index.
template <class _Section>
size_t
find_section_idx_for_line(const std::vector<_Section>& sections, size_t line, size_t& out_line_in_section)
{
    size_t section_idx = 0;
    out_line_in_section = line;
    for (const _Section& section : sections) {

        if (out_line_in_section < section.size) {
            return section_idx;
        }

        out_line_in_section -= section.size;
        section_idx++;
    }

    // cannot happend
    dassert_crit(false);
    return 0;
}

} // namespace table_utils

} // namespace silicon_one

#endif // __TABLE_UTILS_H__
