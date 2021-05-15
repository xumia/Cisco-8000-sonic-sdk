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

#ifndef __LA_LOCK_GUARD_H__
#define __LA_LOCK_GUARD_H__

#include "api/types/la_common_types.h"
#include "common/device_id.h"

#include <mutex>

namespace silicon_one
{

/// @brief      Generic lock guard class.
///
/// Acquires a scoped mutex, and updates the global device ID metadata.
template <class mutex_type>
class la_lock_guard : public std::lock_guard<mutex_type>
{
public:
    la_lock_guard<mutex_type>(mutex_type& mutex, la_device_id_t device_id) : std::lock_guard<mutex_type>(mutex)
    {
        silicon_one::push_device_id(device_id);
    }

    ~la_lock_guard()
    {
        silicon_one::pop_device_id();
    }

    la_lock_guard(const la_lock_guard&) = delete;
    la_lock_guard& operator=(const la_lock_guard&) = delete;
};

} // namespace silicon_one

#endif // __LA_LOCK_GUARD_H__
