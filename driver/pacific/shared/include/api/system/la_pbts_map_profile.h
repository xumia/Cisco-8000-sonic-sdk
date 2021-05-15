// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_PBTS_MAP_PROFILE_H__
#define __LA_PBTS_MAP_PROFILE_H__

/// @file
/// @brief PBTS MAP Profile APIs to map FCID to Destination Offset
///
/// Defines API-s for managing a PBTS_MAP profile.

#include "api/npu/la_acl.h"
#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"

namespace silicon_one
{

/// @addtogroup SYSTEM
/// @{

/// @brief Offset added to l3 destinations
struct la_pbts_destination_offset {
    la_uint8_t value : 3;
};

/// @brief      PBTS MAP Profile.
///
/// @details    PBTS MAP profile defines the mapping between QoS field (FCID
///             derived from incoming packets) and the offset to be added to computed Destination.
///             A set of Destinations are reserved by #silicon_one::la_pbts_group.
///             la_pbts_map_profile associated with la_pbts_group determines offset of the
///             destination from this set for a given FCID.
class la_pbts_map_profile : public la_object
{

public:
    /// @brief PBTS MAP profile Level.
    enum class level_e {
        LEVEL_0 = 0, ///< Level 0.
        LEVEL_1 = 1, ///< Level 1.
        LEVEL_2 = 2, ///< Level 2.
        LEVEL_3 = 3, ///< Level 3.
    };

    /// @brief Set the mapping from FCID to offset to be added to destination.
    ///
    /// @param[in]  fcid             incoming FCID.
    /// @param[in]  offset           Mapped offset.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    offset is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occured.
    virtual la_status set_mapping(la_fwd_class_id fcid, la_pbts_destination_offset offset) = 0;

    /// @brief Get offset of given FCID
    ///
    /// @param[in]  fcid             incoming FCID.
    /// @param[out] out_pbts_offset       Offset the input FCID is mapped to.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_mapping(la_fwd_class_id fcid, la_pbts_destination_offset& out_pbts_offset) const = 0;

    /// @brief Get maximum offset this profile supports.
    ///
    /// @param[out] out_max_offset      Maximum offset this Profile supports.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_size(la_pbts_destination_offset& out_max_offset) const = 0;

    /// @brief Get HW Resolution Level
    ///
    /// @param[out] out_level      Resolution Level at which the Profile is installed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_level(la_pbts_map_profile::level_e& out_level) const = 0;

    /// @brief Get Map Profile ID
    ///
    /// @param[in]  out_profile_id      profile ID
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_profile_id(uint64_t& out_profile_id) const = 0;

protected:
    ~la_pbts_map_profile() override = default;
}; // class la_pbts_map_profile

/// @}

} // namespace silicon_one

#endif // __LA_PBTS_MAP_PROFILE_H__
