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

#ifndef __API_TRACER_H__
#define __API_TRACER_H__

#include "common/device_id.h"
#include "common/la_profile.h"
#include "common/logger.h"
#include "common/weak_ptr_unsafe.h"
#include "la_strings.h"
#include "system/la_device_impl.h"
#include "system/reconnect_handler.h"

/// @file
/// @brief Leaba API functions tracer infrastructure.
///
/// Defines basic Leaba API function entrance.

namespace silicon_one
{

#define do_start_api_call(wb_assert, ...)                                                                                          \
    api_lock_guard<std::recursive_mutex> lock(const_cast<la_device_impl*>(static_cast<const la_device_impl*>(this->get_device())), \
                                              __func__);                                                                           \
    wb_assert;                                                                                                                     \
    bool is_recursive = (get_device_id_use_count() > 1);                                                                           \
    log_device_message_template(la_logger_component_e::API, la_logger_level_e::DEBUG, this, __func__, is_recursive, __VA_ARGS__);  \
    start_scoped_profiler("API call")

#define start_api_call_allow_warm_boot(...) do_start_api_call(, __VA_ARGS__)

#define start_api_call(...)                                                                                                        \
    do_start_api_call(dassert_crit(!static_cast<const la_device_impl*>(this->get_device())->m_warm_boot_disconnected), __VA_ARGS__)

#define start_api_getter_call(...)                                                                                                 \
    api_lock_guard<std::recursive_mutex> lock(                                                                                     \
        const_cast<la_device_impl*>(static_cast<const la_device_impl*>(this->get_device())), __func__, true /* read_only */);      \
    start_scoped_profiler("API getter call")

template <class mutex_type>
class api_lock_guard : public std::lock_guard<mutex_type>
{
public:
    explicit api_lock_guard<mutex_type>(la_device_impl* device, const char* func)
        : api_lock_guard<mutex_type>(device, func, false /* read_only */)
    {
    }
    explicit api_lock_guard<mutex_type>(const weak_ptr_unsafe<la_device_impl>& device, const char* func)
        : api_lock_guard<mutex_type>(device.get(), func, false /* read_only */)
    {
    }
    explicit api_lock_guard<mutex_type>(const weak_ptr_unsafe<la_device_impl>& device, const char* func, bool read_only)
        : api_lock_guard<mutex_type>(device.get(), func, read_only)
    {
    }

    /// @brief Api lock guard constructor.
    ///
    /// The following actions are performed by the API lock guard:
    /// 1. Acquiring a per-device global API lock.
    /// 2. Setting global Device ID (silicon_one::__global_device_id) to current device. Incrementing device_id use count if already
    /// set.
    /// 3. RPFO mode only: for operations that may change the device state, mark the device as 'dirty' for reload purposes. See
    /// #silicon_one::la_device::reconnect for more details.
    ///
    /// @param[in]  device    #silicon_one::la_device to acquire the lock for.
    /// @param[in]  func      API function acquiring the lock.
    /// @param[in]  read_only Flag indicating whether this API call is modifying/accessing the device in any manner.
    explicit api_lock_guard<mutex_type>(la_device_impl* device, const char* func, bool read_only)
        : std::lock_guard<mutex_type>(device->m_mutex), m_device(device), m_func(func), m_read_only(read_only)
    {
        silicon_one::push_device_id(m_device->get_id());
        if (!m_read_only && m_device->m_reconnect_handler) {
            m_device->m_reconnect_handler->start_transaction(func);
        }
    }
    /// @brief Api lock guard destructor.
    ///
    /// The following actions are performed by the API lock guard destructor:
    /// 1. Unlocking a per-device global API lock.
    /// 2. Decrementing device_id use count and setting global Device ID to invalid id when returning from the first API call.
    /// 3. For operations that may change device state, updating that an API call is completed. See
    /// #silicon_one::la_device::reconnect for more details.
    ~api_lock_guard()
    {
        if (!m_read_only && m_device->m_reconnect_handler) {
            m_device->m_reconnect_handler->end_transaction();
        }
        silicon_one::pop_device_id();
    }
    api_lock_guard(const api_lock_guard&) = delete;
    api_lock_guard& operator=(const api_lock_guard&) = delete;

private:
    la_device_impl* m_device;
    const char* m_func;
    bool m_read_only;
};

template <typename T>
size_t
log_recursive(char* msg, size_t len, T value)
{
    using std::to_string;
    using silicon_one::to_string;

    std::string value_str = get_value_type(static_cast<decltype(value)>(value)) + to_string(value);

    size_t offset = snprintf(msg, len, "%s)", value_str.c_str());
    return std::min(offset, len);
}

template <typename T, typename... Args>
size_t
log_recursive(char* msg, size_t len, T value, const Args&... args)
{
    using std::to_string;
    using silicon_one::to_string;

    std::string value_str = get_value_type(static_cast<decltype(value)>(value)) + to_string(value);

    size_t offset = snprintf(msg, len, "%s ", value_str.c_str());
    if (offset > len) {
        return len;
    }
    offset += log_recursive(msg + offset, len - offset, args...);
    return std::min(offset, len);
}

template <typename... Args>
void
log_device_message_template(la_logger_component_e component,
                            la_logger_level_e severity,
                            const la_object* object,
                            const char* function_name,
                            bool is_recursive,
                            const Args&... args)
{
    la_device_id_t device_id = silicon_one::get_device_id();
    if (device_id != LA_DEVICE_ID_INVALID) {
        logger& instance = logger::instance();
        if (instance.is_logging(device_id, component, severity)) {
            enum { API_BUFFER = 4096 };
            char msg[API_BUFFER];
            int offset = snprintf(msg,
                                  API_BUFFER,
                                  "%s%s::%s(",
                                  is_recursive ? "#Recursive API call# " : "",
                                  silicon_one::to_string(object).c_str(),
                                  function_name);
            if ((offset > 0) && (offset < API_BUFFER)) {
                (void)log_recursive(msg + offset, API_BUFFER - offset, args...);
            }
            instance.log(device_id, component, severity, "%s", msg);
        }
    }
}

} // namespace silicon_one

#endif // __API_TRACER_H__
