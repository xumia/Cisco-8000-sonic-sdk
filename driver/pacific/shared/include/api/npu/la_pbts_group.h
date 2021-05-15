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

#ifndef __LA_PBTS_GROUP_H_
#define __LA_PBTS_GROUP_H_

/// @file
/// @brief Leaba PBTS (Policy Based Tunnel Selection) Group API.
///
/// Defines API-s for creating and managing a group of PBTS destinations.
/// Each pbts_group can have upto 8 destinations with a minimum of one.

#include "api/npu/la_l3_destination.h"
#include "api/system/la_pbts_map_profile.h"
#include "api/types/la_qos_types.h"
#include <vector>

/// @addtogroup PBTS_GROUP
/// @{
namespace silicon_one
{

class la_pbts_group : public la_l3_destination
{
public:
    /// @brief Set compatible destination at given offset
    ///
    /// @param[in]  offset           offset to create/upate the destination.
    /// @param[in]  destination      L3 destination.
    ///
    /// @retval     LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval     LA_STATUS_INVALID    Index out of valid range(0-7).
    /// @retval     LA_STATUS_EOUTOFRANGE  offset used is out of range.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS  Member is not from this device.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_member(la_pbts_destination_offset offset, const la_l3_destination* destination) = 0;

    /// @brief Get prefix object at given offset.
    ///
    /// @param[in]  offset         offset to fetch prefix_object for.
    ///
    /// @param[out] out_member     Pointer to #silicon_one::la_l3_destination to populate.
    ///
    /// @retval     LA_STATUS_EOUTOFRANGE  offset used is out of range.
    /// @retval     LA_STATUS_SUCCESS    Operation completed successfully.
    virtual la_status get_member(la_pbts_destination_offset offset, const la_l3_destination*& out_member) const = 0;

    /// @brief Return #silicon_one::la_pbts_map_profile associated with this group
    ///
    /// @retval     The profile object
    virtual const la_pbts_map_profile* get_profile() const = 0;

protected:
    ~la_pbts_group() = default;
};

} // namespace silicon_one

/// @}
#endif // __LA_PBTS_GROUP_H_
