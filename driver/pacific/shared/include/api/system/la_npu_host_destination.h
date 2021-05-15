// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_NPU_HOST_DESTINATION_H__
#define __LA_NPU_HOST_DESTINATION_H__

/// @file
/// @brief Leaba NPU Host Punt destination API-s.
///
/// Defines API-s for punting packets to the internal NPU host.
///

#include "api/system/la_punt_destination.h"
#include "api/types/la_common_types.h"

/// @addtogroup BFD
/// @{

namespace silicon_one
{

/// @brief Destination for traffic to internal NPU host.
///
class la_npu_host_destination : public la_punt_destination
{
public:
protected:
    ~la_npu_host_destination() override = default;
};
}

/// @}

#endif // __LA_NPU_HOST_DESTINATION_H__
