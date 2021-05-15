// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_GUE_PORT_H__
#define __LA_GUE_PORT_H__

#include "api/npu/la_ip_tunnel_port.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"

namespace silicon_one
{

/// @file
/// @brief Leaba L3 Tunnel Port API-s.
///
/// Defines API-s for managing a GUE Tunnel port object.

class la_gue_port : public la_ip_tunnel_port
{

public:
    /// @brief Retrieve Tunnel's local IPv4 prefix.
    ///
    /// @param[out] out_prefix    Local prefix associated with the Tunnel port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Local prefix successfully returned.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_local_ip_prefix(la_ipv4_prefix_t& out_prefix) const = 0;

    /// @brief Set Tunnel's Local IPv4 address.
    ///
    /// @param[in]  prefix               Local prefix associated with the Tunnel port.
    ///
    /// @retval    LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval    LA_STATUS_EINVAL           Invalid address specified.
    /// @retval    LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_local_ip_prefix(const la_ipv4_prefix_t prefix) = 0;

protected:
    ~la_gue_port() override = default;
    /// @}
};

} // namepace leaba

#endif // __LA_GUE_PORT_H__
