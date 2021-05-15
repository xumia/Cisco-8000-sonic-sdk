// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_ACL_COMMAND_PROFILE_H__
#define __LA_ACL_COMMAND_PROFILE_H__

#include "api/types/la_acl_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief Leaba ACL command profile API-s.
///
/// Defines API-s for managing a ACL command profile.

/// @addtogroup ACL
/// @{

namespace silicon_one
{
/// @brief   ACL command profile.
///
/// @details An ACL command profile represents a command that can be used to create ACLs based on it.

class la_acl_command_profile : public la_object
{
public:
    /// @brief Get the command description this profile represents.
    ///
    /// @param[out] out_command_def_vec     Command definition.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_command_definition(la_acl_command_def_vec_t& out_command_def_vec) const = 0;

    /// @brief  Get hw acl command profile
    //
    /// @param[out] out_hw_command_profile     hw command profile index
    ///
    /// @retval     LA_STATUS_SUCCESS    Command retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occurred.

    virtual la_status get_hw_command_profile(uint32_t& out_hw_command_profile) const = 0;

protected:
    ~la_acl_command_profile() override = default;
};

} // namespace silicon_one

/// @}
#endif // __LA_ACL_COMMAND_PROFILE_H__
