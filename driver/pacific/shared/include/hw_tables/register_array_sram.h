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

#ifndef __REGISTER_ARRAY_SRAM_H__
#define __REGISTER_ARRAY_SRAM_H__

#include "lld/lld_fwd.h"

#include "hw_tables/logical_sram.h"
#include "hw_tables/physical_locations.h"

namespace silicon_one
{

class ll_device;

/// @brief Implementation of #silicon_one::logical_sram interface.
///
/// Logical memory region, implemented with list of registers.
class register_array_sram : public logical_sram
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief C'tor
    ///
    /// @param[in]  ldevice             Pointer to low level device.
    /// @param[in]  section             Physical locations section.
    register_array_sram(const ll_device_sptr& ldevice, const register_array_section& section);

    /// @brief C'tor
    ///
    /// @param[in]  ldevice             Pointer to low level device.
    /// @param[in]  regs                Physical location.
    register_array_sram(const ll_device_sptr& ldevice, const register_array& regs);

    /// Logical SRAM API
    virtual la_status write(size_t line, const bit_vector& value);
    virtual size_t max_size() const;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    register_array_sram() = default;

    // Pointer to low level device.
    ll_device_sptr m_ll_device;

    /// Physical location.
    register_array_section m_section;
};

} // namespace silicon_one

#endif // __REGISTER_ARRAY_SRAM_H__
