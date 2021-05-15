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

#ifndef __LA_REMOTE_PORT_H__
#define __LA_REMOTE_PORT_H__

/// @file
/// @brief Leaba Remote Port API-s.
///
/// Defines API-s for managing and using Remote port.

#include "api/system/la_mac_port.h"
#include "api/types/la_common_types.h"
#include "api/types/la_object.h"

/// @addtogroup PORT
/// @{

namespace silicon_one
{

/// @brief Remote port.
///
/// Remote ports represent a ports on remote devices in multi-device systems.
class la_remote_port : public la_object
{
public:
    /// @brief Get the remote device of this port.
    ///
    /// @return #silicon_one::la_remote_device* which this remote port is located on.
    virtual const la_remote_device* get_remote_device() const = 0;

    /// @brief Get slice used by this port on the remote device.
    ///
    /// @return #la_slice_id_t.
    virtual la_slice_id_t get_remote_slice() const = 0;

    /// @brief Get IFG used by this port on the remote device.
    ///
    /// @return #la_ifg_id_t.
    virtual la_ifg_id_t get_remote_ifg() const = 0;

    /// @brief Get ID of first SerDes element of this port on the remote device.
    ///
    /// @return First SerDes ID.
    virtual la_uint_t get_remote_first_serdes_id() const = 0;

    /// @brief Get number of SerDes elements of this port on the remote device.
    ///
    /// @return Number of SerDes elements.
    virtual size_t get_remote_num_of_serdes() const = 0;

    /// @brief Get ID of first PIF element of this port on the remote device.
    ///
    /// @return First PIF ID.
    virtual la_uint_t get_remote_first_pif_id() const = 0;

    /// @brief Get number of PIF elements of this port on the remote device.
    ///
    /// @return Number of PIF elements.
    virtual size_t get_remote_num_of_pif() const = 0;

    /// @brief Get port's speed.
    ///
    /// @param[out] out_speed           Port's speed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Speed retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_speed(la_mac_port::port_speed_e& out_speed) const = 0;

protected:
    ~la_remote_port() override = default;
};
}

/// @}

#endif // __LA_REMOTE_PORT_H__
