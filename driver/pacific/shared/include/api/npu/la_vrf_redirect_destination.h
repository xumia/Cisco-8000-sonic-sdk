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

#ifndef __LA_VRF_REDIRECT_DESTINATION_H_
#define __LA_VRF_REDIRECT_DESTINATION_H_

/// @file
/// @brief VRF Redirect Destination object API.
///
/// These are abstract objects indicating a further lookup in the VRF table.

#include "api/npu/la_l3_destination.h"

namespace silicon_one
{

class la_vrf_redirect_destination : public la_l3_destination
// class la_vrf_redirect_destination
{
public:
    /// @addtogroup VRF_REDIRECT_DEST
    /// @{

    /// @brief Get VRF object for this destination.
    ///
    /// @return The associated VRF object for this destination.
    virtual const la_vrf* get_vrf() const = 0;

protected:
    /// @}
};

} // namespace silicon_one

#endif // __LA_VRF_REDIRECT_DESTINATION_H_
