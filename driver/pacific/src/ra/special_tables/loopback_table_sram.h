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

#ifndef __LOOPBACK_TABLE_SRAM_H__
#define __LOOPBACK_TABLE_SRAM_H__

#include <array>

#include "lld/ll_device.h"

#include "api/types/la_common_types.h"
#include "hw_tables/logical_sram.h"
#include "nplapi/npl_tables_enum.h"

namespace silicon_one
{

class lld_register_array_container;

/// @brief Implementation of #silicon_one::logical_sram interface.
///
/// Logical memory region, implemented with list of registers.
class loopback_table_sram : public logical_sram
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief C'tor
    ///
    /// @param[in]  ldevice             Pointer to low level device.
    /// @param[in]  table_id            Table ID.
    /// @param[in]  slice               Slice.
    loopback_table_sram(const ll_device_sptr& ldevice, npl_tables_e table_id, la_slice_id_t slice);

    /// Logical SRAM API
    virtual la_status write(size_t line, const bit_vector& value);
    virtual size_t max_size() const;

private:
    enum {
        NUM_REGS_PER_IFG = 3,
        NUM_IFGS_PER_SLICE = 2,
        NUM_LOOPBACK_REGS = NUM_REGS_PER_IFG * NUM_IFGS_PER_SLICE,
    };

    // Pointer to low level device.
    ll_device_sptr m_lld;

    // Loopback registers.
    std::array<lld_register_array_sptr, NUM_LOOPBACK_REGS> m_registers;

    loopback_table_sram() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif // __LOOPBACK_TABLE_SRAM_H__
