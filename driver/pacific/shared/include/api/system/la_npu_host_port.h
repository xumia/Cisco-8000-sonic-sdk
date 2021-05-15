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

#ifndef __LA_NPU_HOST_PORT_H__
#define __LA_NPU_HOST_PORT_H__

/// @file
/// @brief Leaba NPU Host Port API-s.
///
/// Defines API-s for managing and using NPU Host port.
///

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_tm_types.h"

/// @addtogroup BFD
/// @{

namespace silicon_one
{

class la_npu_host_port : public la_object
{
public:
    /// @brief Return interface scheduler for this npu host port.
    ///
    /// @return Interface scheduler object.
    virtual la_interface_scheduler* get_scheduler() const = 0;

    /// @brief Return system port for this npu host port.
    ///
    /// @return System port object.
    virtual const la_system_port* get_system_port() const = 0;

protected:
    ~la_npu_host_port() override = default;
};
}

/// @}

#endif // __LA_NPU_HOST_PORT_H__
