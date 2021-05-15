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

#ifndef __LA_PUNT_INJECT_PORT_H__
#define __LA_PUNT_INJECT_PORT_H__

/// @file
/// @brief Leaba Punt-Inject Port API-s.
///
/// Defines API-s for managing and using Punt-Inject port.
///

#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_object.h"

/// @addtogroup PACKET
/// @{

namespace silicon_one
{

/// @brief Punt/Inject port used to configure punt/inject traffic.
///
class la_punt_inject_port : public la_object
{
public:
    /// @brief Retrieve the MAC associated with the port.
    ///
    /// @param[out] out_mac_addr        MAC to associated with port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_mac_addr contains port's MAC address.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac(la_mac_addr_t& out_mac_addr) const = 0;

    /// @brief Retrieve the system port used by this port.
    ///
    /// @return #silicon_one::la_system_port used by this port.
    virtual const la_system_port* get_system_port() const = 0;

protected:
    ~la_punt_inject_port() override = default;
};
}

/// @}

#endif // __LA_PUNT_INJECT_PORT_H__
