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

#ifndef __la_og_lpts_application_H__
#define __la_og_lpts_application_H__

#include "api/npu/la_pcl.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_lpts_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief Leaba LPTS Application API-s.
///
/// Defines API-s for configuring LPTS Application.

/// @addtogroup LPTS
/// @{

namespace silicon_one
{

/// @brief LPTS Application
///
/// @details LPTS Application for Object Group LPTS.\n

class la_og_lpts_application : public la_object
{
public:
    /// @brief Get LPTS App properties.
    ///
    /// @param[out] out_properties      LPTS App properties.
    ///
    /// @retval     LA_STATUS_SUCCESS   Properties retrieved successfully.
    virtual la_status get_properties(la_lpts_app_properties& out_properties) const = 0;

    /// @brief Get LPTS App PCL.
    ///
    /// @param[out] out_src_pcl         LPTS App src PCL.
    ///
    /// @retval     LA_STATUS_SUCCESS   Properties retrieved successfully.
    virtual la_status get_src_pcl(la_pcl*& out_src_pcl) const = 0;

    /// @brief Get APP ID.
    ///
    /// @retval     la_lpts_app_gid_t   Application Id.
    virtual la_lpts_app_gid_t get_app_id() const = 0;

protected:
    ~la_og_lpts_application() override = default;
};

} // namespace silicon_one

/// @}

#endif // __la_og_lpts_application_H__
