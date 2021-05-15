// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_L3_DESTINATION_H__
#define __LA_L3_DESTINATION_H__

#include "api/types/la_ip_types.h"
#include "api/types/la_object.h"
/// @file
/// @brief Leaba Layer 3 Destination API-s.
///
/// Layer 3 destinations are an abstract target to forward L3 traffic to.
/// They include l3 ports (#silicon_one::la_l3_port) and IP multicast groups(#la_ip_multicast_group).

namespace silicon_one
{

/// @addtogroup L3DEST
/// @{

/// @brief      Layer 3 destination base class.
///
/// @details    A layer 3 destination serves as a base class for L3 ports (#silicon_one::la_l3_port).\n
///             Layer 3 packets are forwarded through VRF to L3 destinations.\n
class la_l3_destination : public la_object
{
protected:
    ~la_l3_destination() override = default;
};

/// @}
}

#endif
