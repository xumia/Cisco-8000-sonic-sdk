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

#ifndef __LOGGER_H__
#define __LOGGER_H__

/// @file
/// @brief Leaba logging infrastructure.
///
/// Defines basic Leaba logging API.

#include "api/system/la_log.h"
#include "api/types/la_common_types.h"
#include "common/defines.h"
#include "common/device_id.h"

#include <chrono>
#include <mutex>
#include <stdio.h>

namespace silicon_one

{

class logger
{
public:
    enum {
        NUM_DEVICES = 288, ///< Max of 288 devices.
        NO_DEVICE = NUM_DEVICES,
    };

    /// @brief Set log callback function.
    ///
    /// @param[in]  log_func    Logging function to be used by the logger.
    void set_log_function(la_log_function_t log_func);

    /// @brief Set log file.
    ///
    /// @param[in]  filename    File to write logs to. File will be rewritten if it exists.
    ///                         If filename extension is .gz, log will be generated in zipped format.
    ///
    /// @return     true if file opened successfully; false otherwise.
    ///
    /// @note Log file and log function can be used in tandem, with each printing all messages.
    /// @note If old zlib versions are used, even non .gz filenames will be written in gzipped format.
    bool set_log_file(const char* filename);

    /// @brief Add timestamp to log messages.
    ///
    /// @param[in]  enabled   Add timestamps if true.
    void set_timestamps_enabled(bool enabled);

    /// @brief Get timestamp enabled state.
    ///
    /// @return true if timestamps enabled; false otherwise.
    bool get_timestamps_enabled();

    /// @brief Set log default callback function.
    ///
    void set_log_default_function();

    /// @brief Set logging severity for a specific device and component.
    ///
    /// @param[in]  device_id        Device being configured.
    /// @param[in]  component        Component being configured.
    /// @param[in]  severity         Severity level being configured.
    void set_logging_level(la_device_id_t device_id, la_logger_component_e component, la_logger_level_e severity);

    /// @brief Get logging severity for a specific device and component.
    ///
    /// @param[in]  device_id        Device being configured.
    /// @param[in]  component        Component being configured.
    /// @param[out] out_severity     Severity level to be populated.
    void get_logging_level(la_device_id_t device_id, la_logger_component_e component, la_logger_level_e& out_severity);

    /// @brief Set logging severity for a specific device and all components.
    ///
    /// @param[in]  device_id        Device being configured.
    /// @param[in]  severity         Severity level being configured.
    void set_logging_level(la_device_id_t device_id, la_logger_level_e severity);

    /// @brief Flush the log if last flush occurred farther than flush period.
    ///
    /// @return true if flush is executed, false otherwise.
    ///
    /// @see la_set_flush_period.
    bool flush_if_period_expired();

    /// @brief Flush all pending messages to log.
    ///
    /// @retval     LA_STATUS_SUCCESS      Operation completed successfully. All pending messages to log flushed.
    /// @return     LA_STATUS_EOUTOFMEMORY Insufficient memory available to compress.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    la_status flush();

    /// @brief Set log flush period.
    ///
    /// @param[in] period Requested flush frequency in ms.
    ///
    /// @note Actual flush period may be larger than requested, depending on internal implementation.
    /// Typically, accuracy should be 100ms.
    void set_flush_period(std::chrono::milliseconds period);

    /// @brief Get time beetween two logger flushes.
    ///
    /// @return period    Current settings for the period.
    std::chrono::milliseconds get_flush_period();

    static logger& instance()
    {
        static logger s_log_instance;
        return s_log_instance;
    }

    /// @brief Log a message.
    ///
    /// @param[in]  device_id   device being logged.
    /// @param[in]  component   Source component generating the message.
    /// @param[in]  severity    Message severity.
    /// @param[in]  format      printf-style format string.
    /// @param[in]  ...         printf-style variable argument list.
    void log(la_device_id_t device_id, la_logger_component_e component, la_logger_level_e severity, const char* format, ...)
#if !defined(SWIG) && (__GNUC__ != 9) && (__GNUC__ != 10) // GCC bug #96935
        __attribute__((format(printf, 5, 6)))
#endif
        ;

    /// @brief Query logging mode for (device, severity, component) tuple.
    ///
    /// @param[in]  device_id   device being queried.
    /// @param[in]  component   Component being queried.
    /// @param[in]  severity    Severity being queried.
    ///
    /// @return     true if logging enabled, false otherwise.
    bool is_logging(la_device_id_t device_id, la_logger_component_e component, la_logger_level_e severity)
    {
        return ((device_id <= logger::NUM_DEVICES) && (component <= la_logger_component_e::LAST)
                && (severity <= m_log_vec[device_id][(size_t)component]));
    }

    /// @brief Query logging mode for no-device + (component, severity) tuple.
    ///
    /// @param[in]  component   Component being queried.
    /// @param[in]  severity    Severity being queried.
    ///
    /// @return     true if logging enabled, false otherwise.
    bool is_logging_nodev(la_logger_component_e component, la_logger_level_e severity)
    {
        return (component <= la_logger_component_e::LAST) && (severity <= m_log_vec[logger::NUM_DEVICES][(size_t)component]);
    }

private:
    logger();
    ~logger();

    /// @brief Indicates if logger should add timestamps to messages.
    bool m_timestamps_enabled = false;

    /// @brief How often can we flush the logger. If flush is called before this period has elapsed since the last flush than
    /// nothing will happen.
    std::chrono::milliseconds m_flush_period{500};

    /// @brief Time point of the last executed flush of the logger.
    std::chrono::system_clock::time_point m_flush_timestamp;

    /// @brief Severity per component vector for all devices.
    /// @note last entry used for logs not attached to any device
    typedef la_logger_level_e severity_component_device_t[NUM_DEVICES + 1][(size_t)la_logger_component_e::LAST + 1];

    severity_component_device_t m_log_vec;

    /// @brief Logger log function, can be changed using "\@set_log_function", default is printf.
    la_log_function_t m_log_function;

    /// @brief Log file lock.
    std::mutex log_file_lock;

    void* m_log_file = nullptr;
};

/// @brief Log a message.
///
/// @param[in]  component   Component generating the message.
/// @param[in]  severity    Severity of the message.
/// @param[in]  format      printf-style format string.
/// @param[in]  ...         printf-style variable argument list.
#define log_message(component, severity, format, ...)                                                                              \
    do {                                                                                                                           \
        silicon_one::logger& instance = silicon_one::logger::instance();                                                           \
        la_device_id_t device_id = silicon_one::get_device_id();                                                                   \
        if (instance.is_logging(device_id, component, severity))                                                                   \
            instance.log(device_id, component, severity, format, ##__VA_ARGS__);                                                   \
    } while (0)

#define log_message_internal(component, severity, format, ...)                                                                     \
    log_message(silicon_one::la_logger_component_e::component, silicon_one::la_logger_level_e::severity, format, ##__VA_ARGS__)

/// @brief Log an emergency message.
///
/// @param[in]  component   Source component generating the error.
/// @param[in]  format      printf-style format string.
/// @param[in]  ...         printf-style variable argument list.
#define log_emerg(component, format, ...) log_message_internal(component, EMERG, format, ##__VA_ARGS__)

/// @brief Log an alert message.
///
/// @param[in]  component   Source component generating the error.
/// @param[in]  format      printf-style format string.
/// @param[in]  ...         printf-style variable argument list.
#define log_alert(component, format, ...) log_message_internal(component, ALERT, format, ##__VA_ARGS__)

/// @brief Log a critical message.
///
/// @param[in]  component   Source component generating the error.
/// @param[in]  format      printf-style format string.
/// @param[in]  ...         printf-style variable argument list.
#define log_crit(component, format, ...) log_message_internal(component, CRIT, format, ##__VA_ARGS__)

/// @brief Log an error message.
///
/// @param[in]  component   Source component generating the error.
/// @param[in]  format      printf-style format string.
/// @param[in]  ...         printf-style variable argument list.
#define log_err(component, format, ...) log_message_internal(component, ERROR, format, ##__VA_ARGS__)

/// @brief Log a warning message.
///
/// @param[in]  component       Source component generating the warning.
/// @param[in]  format          printf-style format string.
/// @param[in]  ...             printf-style variable argument list.
#define log_warning(component, format, ...) log_message_internal(component, WARNING, format, ##__VA_ARGS__)

/// @brief Log a notice message.
///
/// @param[in]  component   Source component generating the error.
/// @param[in]  format      printf-style format string.
/// @param[in]  ...         printf-style variable argument list.
#define log_notice(component, format, ...) log_message_internal(component, NOTICE, format, ##__VA_ARGS__)

/// @brief Log an info message.
///
/// @param[in]  component       Source component generating the information.
/// @param[in]  format          printf-style format string.
/// @param[in]  ...             printf-style variable argument list.
#define log_info(component, format, ...) log_message_internal(component, INFO, format, ##__VA_ARGS__)

/// @brief Log a debug message.
///
/// @param[in]  component       Source component generating the debug message.
/// @param[in]  format          printf-style format string.
/// @param[in]  ...             printf-style variable argument list.
#define log_debug(component, format, ...) log_message_internal(component, DEBUG, format, ##__VA_ARGS__)

/// @brief Log a detailed debug message.
///
/// @param[in]  component       Source component generating the detailed debug message.
/// @param[in]  format          printf-style format string.
/// @param[in]  ...             printf-style variable argument list.
#define log_xdebug(component, format, ...) log_message_internal(component, XDEBUG, format, ##__VA_ARGS__)

/// @brief Log a very detailed debug message.
///
/// @param[in]  component       Source component generating the very detailed debug message.
/// @param[in]  format          printf-style format string.
/// @param[in]  ...             printf-style variable argument list.
#define log_spam(component, format, ...) log_message_internal(component, SPAM, format, ##__VA_ARGS__)
}

#endif /* __LOGGER_H__ */
