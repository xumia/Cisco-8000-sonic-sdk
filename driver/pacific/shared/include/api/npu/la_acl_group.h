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

#ifndef __LA_ACL_GROUP_H__
#define __LA_ACL_GROUP_H__

#include "api/types/la_acl_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief Leaba ACL group API-s.
///
/// Defines API-s for managing ACL group.

/// @addtogroup ACL
/// @{

namespace silicon_one
{
/// @brief   ACL Group.
///
/// @details An ACL Group to be attached to l3/l2 ports.

class la_acl_group : public la_object
{
public:
    /// @brief ACL packet_format
    enum class packet_format_e {
        ETHERNET, ///< packet format is enternet.
        IPV4,     ///< packet format is ipv4.
        IPV6      ///< packet format is ipv6.
    };

    /// @brief Set the acls of given packet format to acl group.
    ///
    /// @param[in] packet_format           Packet format of acls vector.
    /// @param[in] acls                    Acls vector to add to acl group.
    ///
    /// @retval     LA_STATUS_SUCCESS   Command retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.

    virtual la_status set_acls(la_acl_packet_format_e packet_format, const la_acl_vec_t& acls) = 0;

    /// @brief  Get acls vector of given packet format
    ///
    /// @param[in] packet_format           Packet format of acls vector.
    /// @param[out] out_acls               Acls vector.
    ///
    /// @retval     LA_STATUS_SUCCESS    Command retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occurred.

    virtual la_status get_acls(la_acl_packet_format_e packet_format, la_acl_vec_t& out_acls) const = 0;

protected:
    ~la_acl_group() override = default;
};

} // namespace silicon_one

/// @}
#endif // __LA_ACL_GROUP_H__
