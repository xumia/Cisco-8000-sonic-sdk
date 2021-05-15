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

#ifndef __LOGICAL_SRAM_H__
#define __LOGICAL_SRAM_H__

#include "hw_tables/physical_locations.h"

namespace silicon_one
{

/// @brief Logical SRAM iterface.
class logical_sram
{
public:
    virtual ~logical_sram()
    {
    }

    /// @brief Write a logical SRAM line.
    ///
    /// @param[in]  line                    Logical line to be written.
    /// @param[in]  value                   Value to be written.
    ///
    /// @retval     LA_STATUS_SUCCESS       Succeeded to write.
    /// @retval     LA_STATUS_EOUTOFRANGE   Line number is out of range.
    /// @retval     LA_STATUS_EINVAL        Provided value's width does not match line_width.
    /// @retval     LA_STATUS_EUNKNOWN      Unknown error occured during write operation.
    virtual la_status write(size_t line, const bit_vector& value) = 0;

    /// @brief Retrieve maximum table size.
    ///
    /// @retval Maximum number of entries supported by table.
    virtual size_t max_size() const = 0;
};

} // namespace silicon_one

#endif // __LOGICAL_SRAM_H__
