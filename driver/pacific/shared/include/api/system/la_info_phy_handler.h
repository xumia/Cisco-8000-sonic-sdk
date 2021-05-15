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

#ifndef __LA_INFO_PHY_HANDLER_H__
#define __LA_INFO_PHY_HANDLER_H__

/// @file
/// @brief Leaba INFO_PHY Handler API-s.
///
/// Defines API-s for managing and using INFO_PHY.
///

#include "api/system/la_info_phy_brick_handler.h"
#include "api/types/la_common_types.h"
#include "lld/lld_fwd.h"

/// @addtogroup SYSTEM
/// @{

namespace silicon_one
{

/// @brief An INFO_PHY handler.
///
/// @details An INFO_PHY handler used to control and manage INFO_PHY interfaces.
///
class la_info_phy_handler
{
public:
    /// @brief D'tor
    virtual ~la_info_phy_handler() = default;

#ifndef SWIG
    static la_info_phy_handler* create(ll_device* ldev);
#endif

    /// @brief Initialize InFO Phy.
    ///
    /// Creates all Bricks, init all PLL, Tx/Rx analog and digital
    ///
    /// @retval LA_STATUS_SUCCESS   Initialize completed successfully.
    /// @retval LA_STATUS_EUNKNOWN  Unknown error.
    virtual la_status initialize() = 0;

    /// @brief Activate InFO Phy.
    ///
    /// Active all the InFO bricks and perform initial calibration.
    ///
    /// @retval LA_STATUS_SUCCESS   Activate completed successfully.
    /// @retval LA_STATUS_EUNKNOWN  Unknown error.
    virtual la_status activate() = 0;

    /// @brief Calibrate InFO Phy.
    ///
    /// Calibrate all the InFO bricks lanes.
    ///
    /// @retval LA_STATUS_SUCCESS   Calibration completed successfully.
    /// @retval LA_STATUS_EUNKNOWN  Unknown error.
    virtual la_status calibrate() = 0;

    /// @brief Get InFO Phy brick handler.
    ///
    /// @param[in]  brick_id            Brick to be queried.
    /// @param[out] out_info_brick      InFO brick handler.
    ///
    /// @retval     LA_STATUS_SUCCESS   Brick retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Brick ID is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_info_brick_handler(size_t brick_id, la_info_phy_brick_handler*& out_info_brick) const = 0;

    /// @brief Starts periodic calibration of all InFo bricks in the device.
    ///
    /// @retval LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval LA_STATUS_EUNKNOWN  Unknown error.
    virtual la_status start_periodec_calibration() = 0;

    /// @brief Stops periodic calibration of all InFo bricks in the device.
    ///
    /// @retval LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval LA_STATUS_EUNKNOWN  Unknown error.
    virtual la_status stop_periodec_calibration() = 0;
};
}

/// @}

#endif // __LA_INFO_PHY_HANDLER_H__
