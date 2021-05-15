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

#ifndef __DEVICE_ID_H__
#define __DEVICE_ID_H__

#include "api/types/la_common_types.h"

#include "common/dassert.h"

namespace silicon_one
{

/// @brief Structure detailing the current global device ID, and the recursion depth.
struct device_id_info {
    enum { INVALID_ID = 288 };
    la_device_id_t device_id;
    size_t use_count;
};

/// @brief Per-thread device ID.
extern thread_local device_id_info __global_device_id;

/// @brief Set global device ID and increment use counter.
///
/// @param[in]  device_id   Current device being logged.
static inline void
push_device_id(la_device_id_t device_id)
{
    device_id_info& dii(__global_device_id);
    dassert_crit((dii.use_count == 0) || (dii.device_id == device_id));

    dii.device_id = device_id;
    dii.use_count++;
}

/// @brief Get current global device ID used for logging.
///
/// @return Current global device ID value.
static inline la_device_id_t
get_device_id()
{
    return __global_device_id.device_id;
}

/// @brief Unset current global device ID when returning from API calls and decrements use counter.
static inline void
pop_device_id()
{
    device_id_info& dii(__global_device_id);
    dii.use_count--;
    if (dii.use_count == 0) {
        dii.device_id = device_id_info::INVALID_ID;
    }
}

static inline size_t
get_device_id_use_count()
{
    device_id_info& dii(__global_device_id);
    return dii.use_count;
}
} // namespace silicon_one

#endif // __DEVICE_ID_H__
