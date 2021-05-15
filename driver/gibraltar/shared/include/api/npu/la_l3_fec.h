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

#ifndef __LA_L3_FEC_H__
#define __LA_L3_FEC_H__

#include "api/npu/la_l3_destination.h"
#include "common/la_status.h"

/// @file
/// @brief Leaba L3 Forward Equivalence Class API-s.
///
/// Defines API-s for managing Layer 3 FEC-s.

namespace silicon_one
{

/// @addtogroup L3DEST_FEC L3 FEC API
/// @{

class la_l3_fec : public la_l3_destination
{

public:
    /// @brief Update the FEC destination.
    ///
    /// @param[in]  destination         L3 destination FEC points to.
    ///
    /// @retval     LA_STATUS_SUCCESS   FEC destination updated successfully.
    /// @retval     LA_STATUS_EINVAL    Destination is corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_destination(la_l3_destination* destination) = 0;

    /// @brief Update the FEC destination.
    ///
    /// @param[in]  destination         L2 destination FEC points to.
    ///
    /// @retval     LA_STATUS_SUCCESS   FEC destination updated successfully.
    /// @retval     LA_STATUS_EINVAL    Destination is corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_destination(la_l2_destination* destination) = 0;

    /// @brief Get the destination associated with the L3 FEC.
    ///
    /// @retval  The fec's destination.
    virtual la_l3_destination* get_destination() const = 0;

protected:
    ~la_l3_fec() override = default;
};
/// @}
}

#endif
