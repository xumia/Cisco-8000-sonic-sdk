// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __NSIM_LOG_INTERFACE__
#define __NSIM_LOG_INTERFACE__

#include <string>
#include <vector>
#include <functional>
#include "utils/list_macros.h"
#include "utils/npsuite_logger.h"

namespace nsim
{

#define MAX_LOG_DISABLED 0
#define LOG_FILE_COMPRESSION_DISABLED false

// clang-format off
#define NSIM_LOG_MODULE_SHORT_ENUMS(list_macro) \
    list_macro(NONE,  0),                       \
    list_macro(TABLE, 3),                       \
    list_macro(USER,  7),                       \
    list_macro(FULL,  8)

#define NSIM_LOG_MODULE_ENUMS(list_macro) \
    list_macro(NSIM_LOG_NONE,  0),        \
    list_macro(NSIM_LOG_TABLE, 3),        \
    list_macro(NSIM_LOG_USER,  7),        \
    list_macro(NSIM_LOG_FULL,  8)


enum nsim_log_module_e { NSIM_LOG_MODULE_ENUMS(LIST_MACRO_FIXED_ENUM_VALUE) };
// clang-format on

//
// Convert nsim_log_module_e to a string. Cannot use to_string as conflicts with size_t
//
static inline const std::string
nsim_log_module_e_to_string(const nsim_log_module_e e)
{
    static std::vector<std::string> names = {NSIM_LOG_MODULE_ENUMS(LIST_MACRO_FIXED_ENUM_STRING)};
    if ((size_t)e >= names.size()) {
        return std::string("invalid nsim_log_module_e:") + std::to_string((int)e);
    }
    return names[(int)e];
}

class nsim_log_interface
{
public:
    virtual ~nsim_log_interface()
    {
    }

    /// @brief Sets log level to INFO for the specified module, and the module
    /// acsts as a threshold, meaning the ones "above" the specified one
    /// will only log errors and fatals (default) and the ones "below"
    /// will be set to log level INFO.
    ///
    /// Set NSIM_LOG_NONE to log only errors and fatals for all modules.
    /// Set NSIM_LOG_FULL to log everything for all modules.
    ///
    /// @param[in]  module     log module to be set
    virtual void set_log_level(nsim_log_module_e module) = 0;
    /// @brief Sets the log level to file for specified module.
    /// If NSIM_LOG_FULL is passed as the module, the specified level is set for all modules.
    /// If NSIM_LOG_NONE is passed as the module, nothing is done.
    ///
    /// @param[in] module   module
    ///
    /// @param[in] level    log level
    virtual void set_module_file_log_level(nsim_log_module_e module, npsuite::npsuite_log_level_e level) = 0;
    /// @brief Sets the log level to standard output for specified module.
    /// If NSIM_LOG_FULL is passed as the module, the specified level is set for all modules.
    /// If NSIM_LOG_NONE is passed as the module, nothing is done.
    ///
    /// @param[in] module   module
    ///
    /// @param[in] level    log level
    virtual void set_module_stdout_log_level(nsim_log_module_e module, npsuite::npsuite_log_level_e level) = 0;
    /// @brief Initializes the logger
    ///
    /// @param[in]  log_file_path   path to the log file
    virtual void set_log_file(const char* log_file_path) = 0;

    /// @brief Initializes the logger
    ///
    /// @param[in]  log_file_path   path to the log file
    ///
    /// @param[in]  logPrefixEnabled  enables time prefix of log
    virtual void set_log_file(const char* log_file_path, bool logPrefixEnabled) = 0;

    /// @brief Initializes the logger
    ///
    /// @param[in]  log_file_path     path to the log file
    ///
    /// @param[in]  logPrefixEnabled  enables time prefix of log
    ///
    /// @param[in]  maxLogSize        sets the maximum log file size
    ///
    /// @param[in]  maxLogFiles       sets the maximum number of log files (log will be distributed over this many files)
    ///
    /// @param[in]  compress          enable log file compression if true
    virtual void set_log_file(const char* log_file_path,
                              bool logPrefixEnabled,
                              size_t maxLogSize,
                              size_t maxLogFiles,
                              bool compress)
        = 0;

    /// @brief Print user log INFO message
    ///
    /// @param[in]  loglevel                    Message loglevel
    /// @param[in]  user_prefix_identifier      User prefix identifier, will appear before the message
    /// @param[in]  message                     String message
    virtual void nsim_log_message(npsuite::npsuite_log_level_e loglevel, std::string user_prefix_identifier, std::string message)
        = 0;
};
} // namespace nsim

#endif
