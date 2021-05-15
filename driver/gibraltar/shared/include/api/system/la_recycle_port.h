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

#ifndef __LA_RECYCLE_PORT_H__
#define __LA_RECYCLE_PORT_H__

/// @file
/// @brief Leaba Recycle Port API-s.
///
/// Defines API-s for managing and using Recycle port.
///

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_tm_types.h"

/// @addtogroup PORT
/// @{

namespace silicon_one
{

/// @brief A recycle port is defined for an IFG.
///
/// It is used when packet processing requires more than a single pass through the NPU.
class la_recycle_port : public la_object
{
public:
    /// @brief Get slice used by this port.
    ///
    /// @return #la_slice_id_t.
    virtual la_slice_id_t get_slice() const = 0;

    /// @brief Get IFG used by this port.
    ///
    /// @return #la_ifg_id_t.
    virtual la_ifg_id_t get_ifg() const = 0;

    /// @brief Return interface scheduler for this recycle port.
    ///
    /// @return Interface scheduler object.
    virtual la_interface_scheduler* get_scheduler() const = 0;

protected:
    ~la_recycle_port() override = default;
};
}

/// @}

#endif // __LA_RECYCLE_PORT_H__
