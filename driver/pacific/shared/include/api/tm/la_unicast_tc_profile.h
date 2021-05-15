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

#ifndef __LA_UNICAST_TC_PROFILE_H__
#define __LA_UNICAST_TC_PROFILE_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"

/// @file
/// @brief Leaba Traffic Class profile API-s.
///
/// Defines API-s for managing a TC profile.

/// @addtogroup TM_TC_PROFILE
/// @{

namespace silicon_one
{

/// @brief      TC offset profile.
///
/// @details    A TC offset profile maps a TC to an offset.\n
///             This usually used in mapping to different VOQs (together with the base VOQ).\n

class la_tc_profile : public la_object
{
public:
    /// @brief Set TC offset mapping.
    ///
    /// @param[in]  tc                  Traffic class to map.
    /// @param[in]  offset              Offset from base queue for (DSP, TC) mapping.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mapping updated successfully.
    /// @retval     LA_STATUS_EINVAL    TC or offset are out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_mapping(la_traffic_class_t tc, la_uint8_t offset) = 0;

    /// @brief Get offset mapping for a given TC.
    ///
    /// @param[in]  tc                  Traffic class to get its mapping.
    /// @param[out] out_offset          Offset to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Offset was read successfully.
    /// @retval     LA_STATUS_EINVAL    TC or offset are out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mapping(la_traffic_class_t tc, la_uint8_t& out_offset) const = 0;

protected:
    ~la_tc_profile() override = default;
};
}

/// @}

#endif
