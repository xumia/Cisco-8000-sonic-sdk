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

#ifndef __LA_ASBR_LSP_H__
#define __LA_ASBR_LSP_H__

#include "api/npu/la_l3_destination.h"
#include "api/npu/la_prefix_object.h"
#include "api/types/la_common_types.h"
#include "api/types/la_mpls_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief Leaba ASBR (Autonomous System Boundary Router) LSP (Label Switched Paths) API-s.
///
/// Defines API-s for managing ASBR LSPs.
///
/// ASBR LSPs are used to create/enable forwarding paths to send traffic to remote ASBR's.
///

/// @addtogroup ASBR_LSP
/// @{

namespace silicon_one
{

class la_asbr_lsp : public la_l3_destination
{
public:
    /// @brief Get the ASBR associated with this ASBR LSP.
    ///
    /// @retval The ASBR for this ASBR LSP.
    virtual const la_prefix_object* get_asbr() const = 0;

    /// @brief Update the ASBR for this ASBR LSP.
    ///
    /// @param[in]  asbr         ASBR for this ASBR LSP.
    ///
    /// @retval     LA_STATUS_SUCCESS   ASBR updated successfully.
    /// @retval     LA_STATUS_EINVAL    ASBR is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_asbr(const la_prefix_object* asbr) = 0;

    /// @brief Get the next destination associated with this ASBR LSP.
    ///
    /// @retval The destination for this ASBR LSP.
    virtual const la_l3_destination* get_destination() const = 0;

    /// @brief Update the destination for this ASBR LSP.
    ///
    /// @param[in]  destination         Destination for this ASBR LSP.
    ///
    /// @retval     LA_STATUS_SUCCESS   Destination updated successfully.
    /// @retval     LA_STATUS_EINVAL    Destination is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_destination(const la_l3_destination* destination) = 0;

protected:
    ~la_asbr_lsp() override = default;
};
}
/// @}
#endif
