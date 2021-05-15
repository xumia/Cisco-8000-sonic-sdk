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

#include "common/logger.h"
#include "api/types/la_common_types.h"
#include "common/defines.h"
#include "common/gen_utils.h"

#include "common/dassert.h"
#include <chrono>
#include <cstdio>
#include <stdarg.h>
#include <string>
#include <zlib.h>

// Old versions of zlib do not support transparent-write mode properly.
// This is needed to use zlib for writing both zipped and regular files.
//
// zlib 1.2.7 is verified working.
static_assert(ZLIB_VERNUM >= 0x1270, "zlib version should be >= 1.2.7");

using namespace std;

namespace silicon_one
{

void
la_set_logger_function(la_log_function_t log_func)
{
    logger::instance().set_log_function(log_func);
}

bool
la_set_logging_file(const char* filename)
{
    return logger::instance().set_log_file(filename);
}

void
logger::set_log_function(la_log_function_t log_func)
{
    m_log_function = log_func;
}

bool
logger::set_log_file(const char* filename)
{
    static_assert(sizeof(m_log_file) == sizeof(gzFile), "gzFile must fit a pointer");
    std::lock_guard<std::mutex> lock(log_file_lock);
    if (m_log_file != nullptr) {
        gzclose((gzFile)m_log_file);
        m_log_file = nullptr;
    }

    if (filename == nullptr) {
        return true;
    }

    string std_filename(filename);
    string gz_ext(".gz");
    bool is_gz = (std_filename.rfind(gz_ext) == (std_filename.size() - gz_ext.size()));
    const char* gzopen_flags = is_gz ? "w" : "wT";

    m_log_file = (gzFile)gzopen(filename, gzopen_flags);
    if (m_log_file) {
        gzprintf((gzFile)m_log_file, "ZLIB version = %s\n", zlibVersion());
    }

    return (m_log_file != nullptr);
}

static void
default_print_log_function(la_device_id_t device_id,
                           la_logger_component_e component,
                           la_logger_level_e logging_level,
                           const char* message)
{
    printf("%s\n", message);
}

void
logger::set_log_default_function()
{
    m_log_function = default_print_log_function;
}

logger::logger()
{
    for (int device_id = 0; device_id <= NUM_DEVICES; device_id++) {
        set_logging_level(device_id, la_logger_level_e::INFO);
    }
    m_log_function = default_print_log_function;

    m_flush_timestamp = std::chrono::system_clock::now();
}

logger::~logger()
{
    if (m_log_file != nullptr) {
        gzclose((gzFile)m_log_file);
        m_log_file = nullptr;
    }
}

static const char*
log_component_e2str(la_logger_component_e component)
{
    static const char* strs[] = {
            [(int)la_logger_component_e::COMMON] = "COMMON",
            [(int)la_logger_component_e::LLD] = "LLD",
            [(int)la_logger_component_e::AE] = "AE",
            [(int)la_logger_component_e::AAPL] = "AAPL",
            [(int)la_logger_component_e::TABLES] = "TABLES",
            [(int)la_logger_component_e::HLD] = "HLD",
            [(int)la_logger_component_e::MAC_PORT] = "MAC_PORT",
            [(int)la_logger_component_e::NPLAPI] = "NPLAPI",
            [(int)la_logger_component_e::API] = "API",
            [(int)la_logger_component_e::INTERRUPT] = "INTERRUPT",
            [(int)la_logger_component_e::RA] = "RA",
            [(int)la_logger_component_e::SIM] = "SIM",
            [(int)la_logger_component_e::SOFT_RESET] = "SOFT_RESET",
            [(int)la_logger_component_e::COUNTERS] = "COUNTERS",
            [(int)la_logger_component_e::RECONNECT] = "RECONNECT",
            [(int)la_logger_component_e::SBIF] = "SBIF",
            [(int)la_logger_component_e::ACCESS] = "ACCESS",
            [(int)la_logger_component_e::ALLOCATOR] = "ALLOCATOR",
            [(int)la_logger_component_e::APB] = "APB",
            [(int)la_logger_component_e::CPU2JTAG] = "CPU2JTAG",
            [(int)la_logger_component_e::PVT] = "PVT",
            [(int)la_logger_component_e::PCL] = "PCL",
            [(int)la_logger_component_e::SERDES] = "SERDES",
            [(int)la_logger_component_e::ARC] = "ARC",
            [(int)la_logger_component_e::INFO_PHY] = "INFO_PHY",
    };

    static_assert(array_size(strs) == (size_t)la_logger_component_e::LAST + 1, "bad size of strings array");

    if ((size_t)component < array_size(strs)) {
        return strs[(size_t)component];
    }

    return "UNKNOWN";
}

static char
log_level_e2code(la_logger_level_e severity)
{
    const char codes[] = {
            [(int)la_logger_level_e::EMERG] = 'F',
            [(int)la_logger_level_e::ALERT] = 'A',
            [(int)la_logger_level_e::CRIT] = 'C',
            [(int)la_logger_level_e::ERROR] = 'E',
            [(int)la_logger_level_e::WARNING] = 'W',
            [(int)la_logger_level_e::NOTICE] = 'N',
            [(int)la_logger_level_e::INFO] = 'I',
            [(int)la_logger_level_e::DEBUG] = 'D',
            [(int)la_logger_level_e::XDEBUG] = 'X',
            [(int)la_logger_level_e::SPAM] = 'S',
    };
    if (severity <= la_logger_level_e::LAST) {
        return codes[(size_t)severity];
    }

    return 'U';
}

void
la_set_timestamps_enabled(bool enabled)
{
    logger::instance().set_timestamps_enabled(enabled);
}

void
logger::set_timestamps_enabled(bool enable)
{
    m_timestamps_enabled = enable;
}

bool
la_get_timestamps_enabled()
{
    return logger::instance().get_timestamps_enabled();
}

bool
logger::get_timestamps_enabled()
{
    return m_timestamps_enabled;
}

void
logger::log(la_device_id_t device_id, la_logger_component_e component, la_logger_level_e severity, const char* format, ...)
{
    enum { LOG_BUFFER = 4096 };
    char message[LOG_BUFFER];
    size_t offset = 0;

    if (m_timestamps_enabled) {
        offset = add_timestamp(message + offset, static_cast<size_t>(LOG_BUFFER));
    }

    const char* component_str = log_component_e2str(component);
    char scode = log_level_e2code(severity);
    offset = offset + snprintf(message + offset, LOG_BUFFER - offset, "-%c-%s-%d- ", scode, component_str, device_id);

    va_list ap;
    va_start(ap, format);
    vsnprintf(message + offset, LOG_BUFFER - offset, format, ap);
    va_end(ap);

    if (m_log_file) {
        std::lock_guard<std::mutex> lock(log_file_lock);
        gzprintf((gzFile)m_log_file, "%s\n", message);
    }

    if (m_log_function) {
        m_log_function(device_id, component, severity, message);
    }

    if (offset >= LOG_BUFFER) {
        printf("log message length was truncated due to over sized length\n");
    }
}

void
la_set_logging_level(la_device_id_t device_id, la_logger_component_e component, la_logger_level_e severity)
{
    logger::instance().set_logging_level(device_id, component, severity);
}

void
logger::set_logging_level(la_device_id_t device_id, la_logger_component_e component, la_logger_level_e severity)
{
    if (device_id <= NUM_DEVICES) {
        m_log_vec[device_id][(size_t)component] = severity;
    }
}

void
logger::get_logging_level(la_device_id_t device_id, la_logger_component_e component, la_logger_level_e& out_severity)
{
    out_severity = m_log_vec[device_id][(size_t)component];
}

la_logger_level_e
la_get_logging_level(la_device_id_t device_id, la_logger_component_e component)
{
    la_logger_level_e level;
    logger::instance().get_logging_level(device_id, component, level);

    return level;
}

void
la_set_logging_level(la_device_id_t device_id, la_logger_level_e severity)
{
    logger::instance().set_logging_level(device_id, severity);
}

void
logger::set_logging_level(la_device_id_t device_id, la_logger_level_e severity)
{
    for (la_logger_component_e component = la_logger_component_e::FIRST; component <= la_logger_component_e::LAST;
         component = (la_logger_component_e)((size_t)component + 1)) {
        set_logging_level(device_id, component, severity);
    }
}

bool
logger::flush_if_period_expired()
{
    auto now = std::chrono::system_clock::now();

    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - m_flush_timestamp) > m_flush_period) {
        flush();
        return true;
    } else {
        return false;
    }
}

la_status
logger::flush()
{
    std::lock_guard<std::mutex> lock(log_file_lock);
    if (m_log_file == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    int status = gzflush(static_cast<gzFile>(m_log_file), Z_SYNC_FLUSH);

    m_flush_timestamp = std::chrono::system_clock::now();

    switch (status) {
    case Z_OK:
        return LA_STATUS_SUCCESS;
    case Z_MEM_ERROR:
        return LA_STATUS_EOUTOFMEMORY;
    default:
        return LA_STATUS_EUNKNOWN;
    }
}

void
logger::set_flush_period(std::chrono::milliseconds period)
{
    std::lock_guard<std::mutex> lock(log_file_lock);

    m_flush_period = period;
}

std::chrono::milliseconds
logger::get_flush_period()
{
    return m_flush_period;
}

void
la_flush_log()
{
    logger::instance().flush();
}

void
la_set_log_flush_period(long period)
{
    logger::instance().set_flush_period(static_cast<std::chrono::milliseconds>(period));
}

long
la_get_log_flush_period()
{
    return logger::instance().get_flush_period().count();
}

} // namesapce leaba
