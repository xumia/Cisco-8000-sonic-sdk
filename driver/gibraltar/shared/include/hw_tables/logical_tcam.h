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

#ifndef __LOGICAL_TCAM_H__
#define __LOGICAL_TCAM_H__

#include <memory>

#include "hw_tables/physical_locations.h"
#include "hw_tables/tcam_types.h"

namespace silicon_one
{

class ll_device;
class logical_tcam;

using logical_tcam_sptr = std::shared_ptr<logical_tcam>;

/// @brief Logical TCAM interface.
class logical_tcam
{
public:
    virtual ~logical_tcam()
    {
    }

    /// @brief Write ternary line.
    ///
    /// @param[in]  line                    Logical TCAM line to be updated, relatively to the beginning of logical TCAM.
    /// @param[in]  key                     Key to be written. The width should match width of the logical TCAM.
    /// @param[in]  mask                    Mask to be written. The width should match width of the logical TCAM.
    /// @param[in]  value                   Value to be written. The width should match width of the logical SRAM.
    ///
    /// @retval     LA_STATUS_SUCCESS       Succeeded to write.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    /// @retval     LA_STATUS_EINVAL        Provided value's width does not match line_width.
    /// @retval     LA_STATUS_EUNKNOWN      Unknown error occured during write operation.
    virtual la_status write(size_t line, const bit_vector& key, const bit_vector& mask, const bit_vector& value) = 0;

    /// @brief Write ternary lines.
    ///
    /// @param[in]  first_line              First logical TCAM line to be updated, relatively to the beginning of logical TCAM.
    /// @param[in]  bulk_size               Number of entries to be written.
    /// @param[in]  entries                 Keys, masks and values of entries to be written.
    ///
    /// @retval     LA_STATUS_SUCCESS       Succeeded to write.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    /// @retval     LA_STATUS_EINVAL        Provided value's width does not match line_width.
    /// @retval     LA_STATUS_EUNKNOWN      Unknown error occured during write operation.
    virtual la_status write_bulk(size_t first_line, size_t bulk_size, const vector_alloc<tcam_entry_desc>& entries) = 0;

    /// @brief Moves ternary line to a new location.
    /// The content of the line will be moved, including TCAM and SRAM content. The source line will be invalidated.
    ///
    /// @param[in]  src_line                Source logical TCAM line to move, relatively to the beginning of logical TCAM.
    ///                                     The line will be invalidated.
    /// @param[in]  dest_line               Destination logical TCAM line to be updated, relatively to the beginning of logical
    /// TCAM.
    ///
    /// @retval     LA_STATUS_SUCCESS       Succeeded to write.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    /// @retval     LA_STATUS_EINVAL        Provided value's width does not match line_width.
    /// @retval     LA_STATUS_EUNKNOWN      Unknown error occured during write operation.
    virtual la_status move(size_t src_line, size_t dest_line) = 0;

    /// @brief Update SRAM value.
    ///
    /// @param[in]  line                    Logical TCAM line to be updated, relatively to the beginning of logical TCAM.
    /// @param[in]  value                   Value to be written. The width should match total width of logical SRAM.
    ///
    /// @retval     LA_STATUS_SUCCESS       Succeeded to write.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    /// @retval     LA_STATUS_EINVAL        Provided value's width does not match line_width.
    /// @retval     LA_STATUS_EUNKNOWN      Unknown error occured during write operation.
    virtual la_status update(size_t line, const bit_vector& value) = 0;

    /// @brief Invalidates TCAM line.
    ///
    /// @param[in]  line                    Memory line, relatively to the beginning of logical TCAM.
    ///
    /// @retval     LA_STATUS_SUCCESS       Succeeded to write.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    /// @retval     LA_STATUS_EUNKNOWN      Unknown error occured during write operation.
    virtual la_status invalidate(size_t line) = 0;

    /// @brief Set default value.
    ///
    /// The value is written to the first line beyond resource valid range.
    ///
    /// @param[in]  key                     Key to be written. The width should match width of the logical TCAM.
    /// @param[in]  mask                    Mask to be written. The width should match width of the logical TCAM.
    /// @param[in]  value                   Value to be written. The width should match width of the logical SRAM.
    ///
    /// @retval     LA_STATUS_SUCCESS       Succeeded to write.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    /// @retval     LA_STATUS_EINVAL        Provided value's width does not match line_width.
    /// @retval     LA_STATUS_EUNKNOWN      Unknown error occured during write operation.
    virtual la_status set_default_value(const bit_vector& key, const bit_vector& mask, const bit_vector& value) = 0;

    /// @brief Read the TCAM/SRAM entries in a given line.
    ///
    /// Returns the key, mask and value.
    ///
    /// @param[in]  line                    Line to read its key, mask and value.
    /// @param[out] out_key                 Key as it's written in the TCAM line.
    /// @param[out] out_mask                Mask as it's written in the TCAM line.
    /// @param[out] out_value               Value as it's written in the SRAM line.
    /// @param[out] out_valid               True if the line is valid line.
    ///
    /// @retval     LA_STATUS_SUCCESS       Succeeded to read.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    /// @retval     LA_STATUS_EUNKNOWN      Unknown error occured during write operation.
    virtual la_status read(size_t line,
                           bit_vector& out_key,
                           bit_vector& out_mask,
                           bit_vector& out_value,
                           bool& out_valid) const = 0;

    /// @brief Returns number of TCAM entries.
    ///
    /// @retval     number of TCAM entries supported by the underlying resources.
    virtual size_t size() const = 0;

    /// @brief Retrieve maximum scale for table (maximum amount of entries that can be added).
    ///
    /// @param[out]  out_max_scale               Maximum scale for table
    ///
    /// @retval     LA_STATUS_SUCCESS           Success
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Function not yet implemented.
    virtual la_status get_max_available_space(size_t& out_max_scale) const = 0;

    /// @brief Retrieve current number of entries in the TCAM.
    ///
    /// @retval     number of valid TCAM entries
    virtual la_status get_physical_usage(size_t& out_physical_usage) const = 0;
};

} // namespace silicon_one

#endif // __LOGICAL_TCAM_H__
