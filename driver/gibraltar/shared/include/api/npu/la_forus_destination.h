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

#ifndef __LA_FORUS_DESTINATION_H__
#define __LA_FORUS_DESTINATION_H__

#include "api/npu/la_l3_destination.h"

/// @file
/// @brief Leaba For-us Destination API-s.
///
/// For us destinations are an abstract target to represent L3 traffic meant for the router.

namespace silicon_one
{

/// @addtogroup L3DEST
/// @{

/// @brief      For us destination class.
///
/// @details    A for us destination serves as a base class for L3 traffic meant for the router.\n
///             Layer 3 packets with a for us destination go through LPTS classification mechanism and eventually get
///             directed to the local CPU or to the RP.\n
class la_forus_destination : public la_l3_destination
{
    /// @brief Get object group code.
    ///
    /// @retval     la_uint_t    object group code.
    virtual la_uint_t get_bincode() const = 0;

protected:
    ~la_forus_destination() override = default;
};

/// @}
}

#endif
