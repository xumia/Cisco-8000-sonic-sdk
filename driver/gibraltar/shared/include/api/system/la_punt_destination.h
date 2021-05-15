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

#ifndef __LA_PUNT_DESTINATION_H__
#define __LA_PUNT_DESTINATION_H__

/// @file
/// @brief Leaba Punt destination API-s.
///
/// Punt destination is an abstract class for punt destination classes.
///

#include "api/types/la_object.h"

/// @addtogroup PACKET
/// @{

namespace silicon_one
{

/// @brief Punt destination base class.
///
/// @details Punt destination serves as a base class for punt destinations classes and used as a target to punt traffic to.
class la_punt_destination : public la_object
{
public:
protected:
    ~la_punt_destination() = default;
};
}

/// @}

#endif // __LA_PUNT_DESTINATION_H__
