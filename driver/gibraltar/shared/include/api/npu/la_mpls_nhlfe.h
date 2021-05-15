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

#ifndef __LA_MPLS_NHLFE_H__
#define __LA_MPLS_NHLFE_H__

/// @file
/// @brief Leaba MPLS NHLFE API-s.
///
/// Defines API-s for managing MPLS Next Hop Label Forwarding Entries.

#include "api/npu/la_l3_destination.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_mpls_types.h"
#include "api/types/la_object.h"

namespace silicon_one
{

/// @addtogroup MPLS_NHLFE
/// @{

class la_mpls_nhlfe : public la_l3_destination
{
public:
    /// @brief Get action for the Next Hop Label Forwarding Entry.
    ///
    /// @retval     NHLFE action.
    virtual la_mpls_action_e get_action() const = 0;

    /// @brief Get MPLS label for the Next Hop Label Forwarding Entry.
    ///
    /// Relevant for SWAP and Tunnel Protection objects only.
    /// Retrieve the MPLS swap label for a swap NHLFE.
    /// Retrieve the MPLS Primary TE label for a TE Tunnel-Protection NHLFE.
    ///
    /// @retval     NHLFE new label.
    virtual la_mpls_label get_label() const = 0;

    /// @brief Get TE Merge-Point label for the Next Hop Label Forwarding Entry.
    ///
    /// Relevant for Tunnel Protection objects only.
    ///
    /// @retval     NHLFE Merge-Point label.
    virtual la_mpls_label get_merge_point_label() const = 0;

    /// @brief Get destination of the Next Hop Label Forwarding Entry.
    ///
    /// @retval   NHLFE destination.
    virtual const la_l3_destination* get_destination() const = 0;

    /// @brief Get the destination system port of the Next Hop Label Forwarding Entry.
    ///
    /// Relevant for L2 Adjancency objects only.
    ///
    /// @retval   NHLFE destination system port.
    virtual const la_system_port* get_destination_system_port() const = 0;

protected:
    ~la_mpls_nhlfe() override = default;
};

/// @}

} // namespace silicon_one

#endif // __LA_MPLS_NHLFE_H__
