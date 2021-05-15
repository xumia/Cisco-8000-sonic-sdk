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

#ifndef __LA_REMOTE_DEVICE_H__
#define __LA_REMOTE_DEVICE_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"

namespace silicon_one
{

/// @brief Remote device.
///
/// Remote device represents a specific remote device in multi-device systems.

class la_remote_device : public la_object
{
public:
    /// @brief Get the remote device ID.
    ///
    /// @return #la_device_id_t.
    virtual la_device_id_t get_remote_device_id() const = 0;

    /// @brief Get the remote device revision.
    ///
    /// @return #la_device_revision_e.
    virtual la_device_revision_e get_remote_device_revision() const = 0;

protected:
    ~la_remote_device() override = default;
};

} // namespace silicon_one

#endif // __LA_REMOTE_DEVICE_H__
