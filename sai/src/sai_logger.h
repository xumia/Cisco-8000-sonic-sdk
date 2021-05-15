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

#ifndef __SAI_LOGGER_H__
#define __SAI_LOGGER_H__

#include <stdarg.h>
#include <stdio.h>
#include <sstream>
#include <zlib.h>

extern "C" {
#include <sai.h>
}
#include "sai_strings.h"
#include "sai_warm_boot.h"

namespace silicon_one
{
namespace sai
{

class lsai_logger
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    void enable_stdout_msg(bool enable)
    {
        m_stdout_msg = enable;
    }
    void enable_syslog(bool enable)
    {
        m_syslog_msg = enable;
    }

    bool set_log_file(const char* filename);

    void set_logging_level(sai_api_t apid, sai_log_level_t log_level);

    void get_logging_level(sai_api_t apid, sai_log_level_t& log_level);

    static lsai_logger& instance()
    {
        static lsai_logger s_log_instance;
        return s_log_instance;
    }

    void log(sai_api_t api_id, sai_log_level_t severity, const char* format, ...);

    bool is_logging(sai_api_t apid, sai_log_level_t log_level)
    {
        return (apid <= SAI_API_MAX && log_level >= m_log_level[apid]);
    }

    bool is_logging_allobjects(sai_log_level_t log_level)
    {
        return (log_level <= m_log_level[SAI_API_MAX]);
    }

    void log_function(sai_log_level_t severity, const char* msg);

private:
    lsai_logger();
    ~lsai_logger()
    {
    }

    sai_log_level_t m_log_level[SAI_OBJECT_TYPE_MAX + 1];
    bool m_syslog_msg = true;
    bool m_stdout_msg = false;
};

template <typename T>
void
sai_log_recursive(std::ostringstream& msg, attr_to_string_fn attr_fn, T value)
{
    msg << to_string(attr_fn, value) << ")";
}

template <typename T, typename... Args>
void
sai_log_recursive(std::ostringstream& msg, attr_to_string_fn attr_fn, T value, const Args&... args)
{
    msg << to_string(attr_fn, value) << " ";
    sai_log_recursive(msg, attr_fn, args...);
}

template <typename... Args>
void
sai_log_message_template(sai_api_t apid,
                         sai_log_level_t log_level,
                         attr_to_string_fn attr_fn,
                         const char* function_name,
                         const Args&... args)
{
    lsai_logger& instance = lsai_logger::instance();
    if (instance.is_logging(apid, log_level)) {
        std::ostringstream msg;
        msg << "SAI_API::" << function_name << "(";
        sai_log_recursive(msg, attr_fn, args...);
        instance.log(apid, log_level, "%s", msg.str().c_str());
    }
}

#define sai_start_api(apid, objtype, objid, attr_fn, ...)                                                                          \
    lsai_object la_obj(objid);                                                                                                     \
    auto sdev = la_obj.get_device();                                                                                               \
    if (la_obj.type != objtype || sdev == nullptr || sdev->m_dev == nullptr) {                                                     \
        sai_log_error(apid, "Bad object id 0x%lx", objid);                                                                         \
        return SAI_STATUS_INVALID_PARAMETER;                                                                                       \
    }                                                                                                                              \
    std::lock_guard<std::recursive_mutex> lock(sdev->m_mutex);                                                                     \
    sai_log_message_template(apid, SAI_LOG_LEVEL_INFO, attr_fn, __func__, __VA_ARGS__)

#define sai_start_api_getter(sdev) std::lock_guard<std::recursive_mutex> lock(sdev->m_mutex)

#define sai_start_api_counter(sdev) std::lock_guard<std::recursive_mutex> lock(sdev->m_mutex)

#define sai_log_message(apid, log_level, format, ...)                                                                              \
    do {                                                                                                                           \
        lsai_logger& instance = lsai_logger::instance();                                                                           \
        if (instance.is_logging(apid, log_level)) {                                                                                \
            instance.log(apid, log_level, format, ##__VA_ARGS__);                                                                  \
        }                                                                                                                          \
    } while (0)

#define sai_log_debug(apid, format, ...) sai_log_message(apid, SAI_LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)
#define sai_log_info(apid, format, ...) sai_log_message(apid, SAI_LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#define sai_log_notice(apid, format, ...) sai_log_message(apid, SAI_LOG_LEVEL_NOTICE, format, ##__VA_ARGS__)
#define sai_log_warn(apid, format, ...) sai_log_message(apid, SAI_LOG_LEVEL_WARN, format, ##__VA_ARGS__)
#define sai_log_error(apid, format, ...) sai_log_message(apid, SAI_LOG_LEVEL_ERROR, format, ##__VA_ARGS__)
#define sai_log_critical(apid, format, ...) sai_log_message(apid, SAI_LOG_LEVEL_CRITICAL, format, ##__VA_ARGS__)

bool sai_set_logging_file(const char* filename);

class lsai_device;

class lsai_logger_throttled
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    static constexpr uint16_t DEFAULT_DEBUG_SUPRESSED = 1000;
    static constexpr uint16_t DEFAULT_DEBUG_WAIT_TIME = 10;

    lsai_logger_throttled();
    lsai_logger_throttled(std::shared_ptr<lsai_device> sai_dev);
    ~lsai_logger_throttled(){};

    void initialize(sai_api_t apid, uint16_t interval, uint16_t messages);
    void log(const char* format, ...);

private:
    sai_api_t m_apid;
    std::chrono::seconds m_message_time_interval;
    std::chrono::steady_clock::time_point m_last_sent;
    uint16_t m_message_count_interval;
    uint16_t m_cur_message_count;
};
}
}
#endif
