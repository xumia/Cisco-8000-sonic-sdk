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

#ifndef __NPSUITE_LOGGER__
#define __NPSUITE_LOGGER__

#include <string>
#include <vector>
#include <functional>
#include "utils/list_macros.h"

namespace npsuite
{

// clang-format off
#define NPSUITE_LOG_LEVEL_ENUMS(list_macro)  \
    list_macro(NPSUITE_LOG_LEVEL_TRACE),     \
    list_macro(NPSUITE_LOG_LEVEL_DEBUG),     \
    list_macro(NPSUITE_LOG_LEVEL_INFO),      \
    list_macro(NPSUITE_LOG_LEVEL_PROGRESS),  \
    list_macro(NPSUITE_LOG_LEVEL_WARNING),   \
    list_macro(NPSUITE_LOG_LEVEL_ESSENTIAL), \
    list_macro(NPSUITE_LOG_LEVEL_ERROR),     \
    list_macro(NPSUITE_LOG_LEVEL_FATAL)
// clang-format on

//
// NOTE to avoid SWIG using a type wrapper instead of int, use "enum npsuite::npsuite_log_level_e_" in prototypes.
// Else you have a type mismatch with SWIG passing an int to a function that expects "npsuite::npsuite_log_level_e"
//
typedef enum npsuite_log_level_e_ { NPSUITE_LOG_LEVEL_ENUMS(LIST_MACRO_VALUE), NPSUITE_LOG_LEVEL_NUM_LEVELS } npsuite_log_level_e;

//
// Convert npsuite_log_level_e to a string. Cannot use to_string as conflicts with size_t
//
static inline const std::string
npsuite_log_level_e_to_string(const npsuite_log_level_e e)
{
    static std::vector<std::string> names = {NPSUITE_LOG_LEVEL_ENUMS(LIST_MACRO_STRING)};
    if ((size_t)e >= names.size()) {
        return std::string("invalid npsuite_log_level_e:") + std::to_string((int)e);
    }
    return names[(int)e];
}

/// @brief Callback data type in case the user wants to integrate callback logging mechanism for NSIM
///
/// @param[in] level                    Log level of the message
/// @param[in] thread_prefix            Thread that generated the log
/// @param[in] file                     File that generated the log
/// @param[in] line                     Line that generated the log
/// @param[in] message                  User string message
typedef struct {
    npsuite_log_level_e level;
    std::string thread_prefix;
    std::string msg_prefix;
    std::string file;
    unsigned long int line;
    std::string msg;
} npsuite_logger_message_callback_data_t;

/// @brief Callback type in case the user wants to integrate callback logging mechanism for NSIM
using npsuite_logger_message_callback_t = std::function<void(const npsuite_logger_message_callback_data_t&)>;

typedef int register_log_message_client_handle_t;
}
#endif
