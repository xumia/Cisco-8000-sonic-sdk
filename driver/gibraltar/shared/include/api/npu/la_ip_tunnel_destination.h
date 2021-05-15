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

#ifndef __LA_IP_TUNNEL_DESTINATION_H_
#define __LA_IP_TUNNEL_DESTINATION_H_

/// @file
/// @brief IP Tunnel Destination object API.
///
/// Defines API-s for managing an IP tunnel destination objects. Such objects
/// are used for provisioning IP tunnels.

#include "api/npu/la_l3_destination.h"

namespace silicon_one
{

class la_ip_tunnel_destination : public la_l3_destination
{
public:
    /// @addtogroup IP_TUNNEL_DEST
    /// @{

    /// @brief Get IP tunnel destination global ID.
    ///
    /// @return IP tunnel destination global ID.
    virtual la_l3_destination_gid_t get_gid() const = 0;

    /// @brief Get IP tunnel port for this IP tunnel destination.
    ///
    /// @return The associated IP tunnel port for this IP tunnel destination.
    virtual const la_l3_port* get_ip_tunnel_port() const = 0;

    /// @brief Get underlay destination for this IP tunnel destination.
    ///
    /// @return The associated underlay destination for this IP tunnel destination.
    virtual const la_l3_destination* get_underlay_destination() const = 0;

    /// @brief Update underlay destination for this IP tunnel destination.
    ///
    /// @param[in]  underlay_destination  Underlay destination of IP tunnel destination.
    ///
    /// @retval     LA_STATUS_SUCCESS     Underlay destination updated successfully.
    /// @retval     LA_STATUS_EINVAL      Destination is invalid.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_underlay_destination(const la_l3_destination* underlay_destination) = 0;

protected:
    ~la_ip_tunnel_destination() override = default;
    /// @}
};

} // namespace silicon_one

#endif // __LA_IP_TUNNEL_DESTINATION_H_
