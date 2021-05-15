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

#ifndef __LA_MPLS_LABEL_DESTINATION_H__
#define __LA_MPLS_LABEL_DESTINATION_H__

/// @file
/// @brief Leaba MPLS label destination API.
///
/// Defines API-s for managing a MPLS label destination objects. Such objects can be used
/// for creating MPLS tunnels with an associated VPN label. E.g. - they can be used for
/// implmenting Per-CE VPN tunnels.

#include "api/npu/la_l3_destination.h"
#include "api/types/la_mpls_types.h"

namespace silicon_one
{

class la_mpls_label_destination : public la_l3_destination
{
public:
    /// @brief Return the associated tunnel object.
    ///
    /// @retval The associated tunnel object.
    virtual la_l3_destination* get_destination() const = 0;

    /// @brief Return the associated label.
    ///
    /// @retval The associated tunnel object.
    virtual la_mpls_label get_label() const = 0;

protected:
    ~la_mpls_label_destination() override = default;
};

} // namespace silicon_one

#endif // __LA_MPLS_LABEL_DESTINATION_H__
