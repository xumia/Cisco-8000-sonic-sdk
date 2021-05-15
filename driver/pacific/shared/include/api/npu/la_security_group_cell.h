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

#ifndef __LA_SECURITY_GROUP_CELL_H__
#define __LA_SECURITY_GROUP_CELL_H__

#include "api/npu/la_acl.h"
#include "api/npu/la_counter_set.h"
#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_security_group_types.h"

/// @file
/// @brief Leaba Security Group Cell API-s.
///
/// Defines API-s for configuring Security Group Cell.

namespace silicon_one
{

/// @addtogroup SECURITY_GROUP_CELL
/// @{

/// @brief Security Group Cell API-s.
///
/// @details A matrix is maintained where each entry is a Cell(sgt, dgt).\n
///          Each cell entry defines a logical target on which ACL rules can be applied.
///          Counters (permit and deny) will be configured per cell level.

class la_security_group_cell : public la_object
{
public:
    /// @brief Set cell counter.
    ///
    /// @param[in]  counter                Counter object.
    ///
    /// @retval     LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL       Counter type is other CELL.
    /// @retval     LA_STATUS_EINVAL       Invalid set size.
    /// @retval     LA_STATUS_EEXIST       A counter of this type is already associated with this CELL.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status set_counter(la_counter_set* counter) = 0;

    /// @brief Get cells's counter.
    ///
    /// @param[out]     out_counter         Counter object to populate.
    ///
    /// @retval         LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval         LA_STATUS_EINVAL    Counter type is other than CELL.
    /// @retval         LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_counter(la_counter_set*& out_counter) const = 0;

    /// @brief Set cells's monitor flag (used for security group policy monitoring).
    ///
    /// @param[in]      allow_drop          Allow Drop Flag.
    ///
    /// @retval         LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval         LA_STATUS_EINVAL    Invalid value.
    /// @retval         LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_monitor_mode(bool allow_drop) = 0;

    /// @brief Get cells's monitor flag (used for security group policy monitoring).
    ///
    /// @param[out]     out_allow_drop      Allow Drop Flag.
    ///
    /// @retval         LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval         LA_STATUS_EINVAL    Invalid value.
    /// @retval         LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_monitor_mode(bool& out_allow_drop) const = 0;

    /// @brief Set Security Group ACL for the cell.
    ///
    /// @param[in]  sgacl               SGACL to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   SGACL set successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid SGACL.
    /// @retval     LA_STATUS_ERESOURCE No resources to attach the SGACL.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    virtual la_status set_acl(la_acl* sgacl) = 0;

    /// @brief Clear Security Group ACL from the cell at specific stage.
    ///
    /// @retval     LA_STATUS_SUCCESS   SGACL cleared successfully.
    /// @retval     LA_STATUS_ENOTFOUND No SGACL is currently set.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_acl() = 0;

    /// @brief Get Security Group ACL attached to the cell.
    ///
    /// @param[out] out_sgacl           Pointer to populate with the attached SGACL.
    ///
    /// @retval     LA_STATUS_SUCCESS   SGACL retrieved successfully.
    /// @retval     LA_STATUS_ENOTFOUND No SGACL is currently attached.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_acl(la_acl*& out_sgacl) const = 0;

    /// @brief Set Bincode value for the Security Group Cell.
    ///
    /// @param[in]  bincode             Bincode value to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Bincode set successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid Value.
    /// @retval     LA_STATUS_ENOTFOUND No SGACL is currently attached.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_bincode(la_uint32_t bincode) = 0;

    /// @brief Get Security Group Cell's Bincode value.
    ///
    /// @param[out] out_bincode         Bincode value for the cell.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_bincode(la_uint32_t& out_bincode) const = 0;

protected:
    ~la_security_group_cell() override = default;
};

} // namespace silicon_one

/// @}
#endif // __LA_SECURITY_GROUP_CELL_H__
