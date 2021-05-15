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

#include "common/dassert.h"
#include "common/backtrace.h"
#include "common/logger.h"
#include "common/proc_maps.h"

#include <iostream>
#include <map>
#include <sstream>
#include <stdarg.h> /* va_list, va_start, va_arg, va_end */
#include <string>

#define BT_BUF_SIZE 100

namespace silicon_one
{

dassert::dassert()
    : m_level_settings_array{[static_cast<int>(dassert::level_e::CRITICAL)]
                             = {.skip = false, .terminate = true, .backtrace = true, .proc_maps = true},
                             [static_cast<int>(dassert::level_e::NCRITICAL)]
                             = {.skip = false, .terminate = false, .backtrace = true, .proc_maps = true},
                             [static_cast<int>(dassert::level_e::SLOW)]
                             = {.skip = true, .terminate = true, .backtrace = true, .proc_maps = true}}
{ // dassert constructor
} // dassert constructor

dassert::~dassert()
{
}

void
dassert::set_settings(const dassert::level_e level, const dassert::settings& settings)
{
    m_level_settings_array[static_cast<int>(level)] = settings;
}

void
dassert::assert_fail(const dassert::level_e level,
                     const size_t line,
                     const std::string& function,
                     const std::string& file,
                     const std::string& expr_str,
                     const char* format,
                     ...)
{
    enum { MESSAGE_BUFFER = 4096 };
    char message[MESSAGE_BUFFER];
    va_list ap;
    va_start(ap, format);
    size_t offset = 0;
    vsnprintf(message + offset, MESSAGE_BUFFER - offset, format, ap);
    va_end(ap);

    std::ostringstream output_stream;
    output_stream << "Assertion failed: \"" << expr_str << "\", file: " << file << ", function: " << function
                  << ", line number: " << line << ".\n"
                  << message << "\n";
    switch (static_cast<int>(level)) {
    case static_cast<int>(dassert::level_e::CRITICAL): {
        log_crit(COMMON, "%s", output_stream.str().c_str());
    }

    break;
    case static_cast<int>(dassert::level_e::NCRITICAL): {
        log_err(COMMON, "%s", output_stream.str().c_str());
    }

    break;
    case static_cast<int>(dassert::level_e::SLOW): {
        log_crit(COMMON, "%s", output_stream.str().c_str());
    }
    }

    dassert::settings level_settings = m_level_settings_array[static_cast<int>(level)];
    if (level_settings.backtrace) {
        std::string output_string = demangled_backtrace();
        switch (static_cast<int>(level)) {
        case static_cast<int>(dassert::level_e::CRITICAL): {
            log_crit(COMMON, "%s", output_string.c_str());
        }

        break;
        case static_cast<int>(dassert::level_e::NCRITICAL): {
            log_err(COMMON, "%s", output_string.c_str());
        }

        break;
        case static_cast<int>(dassert::level_e::SLOW): {
            log_crit(COMMON, "%s", output_string.c_str());
        }
        }
    }
    if (level_settings.proc_maps) {
        std::string output_string = proc_maps();
        switch (static_cast<int>(level)) {
        case static_cast<int>(dassert::level_e::CRITICAL): {
            log_crit(COMMON, "%s", output_string.c_str());
        }

        break;
        case static_cast<int>(dassert::level_e::NCRITICAL): {
            log_err(COMMON, "%s", output_string.c_str());
        }

        break;
        case static_cast<int>(dassert::level_e::SLOW): {
            log_crit(COMMON, "%s", output_string.c_str());
        }
        }
    }

    if (level_settings.terminate == true) {
        logger::instance().flush();
        abort();
    }
}

void
dassert::assert_fail(const dassert::level_e level,
                     const size_t line,
                     const std::string& function,
                     const std::string& file,
                     const std::string& expr_str)
{
    assert_fail(level, line, function, file, expr_str, "");
}

} // namespace silicon_one
