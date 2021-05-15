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

#include "device_simulator/dsim_common/socket_connection.h"
#include "device_simulator/dsim_common/nsim_command.h"
#include "device_simulator/socket_command.h"
#include "utils/logger/logger.h"
#include "utils/table_util.h"
#include <string.h>
#if defined(_WIN32) || defined(_WIN64)
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WS2tcpip.h>
#include <io.h>
#include <stdint.h>
#define close closesocket
#define poll WSAPoll
#define strerror_r(errno, buf, len) strerror_s(buf, len, errno)
#else // LINUX
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <unistd.h>
#endif
#include <math.h>
#include <map>
#include <iomanip>
#include <iostream>

using namespace npsuite;
namespace dsim
{

enum { READ_N_BYTES_FALIURE = -1, READ_N_BYTES_SUCCESS = 0, READ_N_BYTES_FINISHED = 1 };

#ifdef MSG_NOSIGNAL
// Disables SIGPIPE on errors. EPIPE will be returned on send() to broken sockets.
// linux >= 2.2  has MSG_NOSIGNAL
// bsd/macos >= 10.2 has SO_NOSIGPIPE, no support for MSG_NOSIGNAL
// mingw no support for MSG_NOSIGNAL (but no SIGPIPE on windows so...)
static const int send_flags = MSG_NOSIGNAL;
#else
static const int send_flags = 0;
#endif

int socket_connection_common::m_socket_timeout_retry_in_seconds
    = socket_connection_common::m_socket_timeout_retry_in_seconds_default;
int socket_connection_common::m_socket_timeout_total_in_seconds
    = socket_connection_common::m_socket_timeout_total_in_seconds_default;

socket_connection_common::nsim_global_socket_stats_entry socket_connection_common::m_nsim_global_socket_stats;

//
// Get a std::string from errno
//
std::string
socket_connection_common::strerrno(int saved_errno)
{
    static const auto BUFFER_SIZE = 1024U;
    char error_message[BUFFER_SIZE];
    error_message[0] = '\0';

#if defined(_WIN32) || defined(_WIN64)
    if (!strerror_r(errno, error_message, sizeof(error_message))) {
        return std::string(error_message);
    }
#elif defined(__APPLE__)
    const int status = strerror_r(errno, error_message, sizeof(error_message));
    if (status == 0) {
        return std::string(error_message);
    }
#else
    const char* str = strerror_r(errno, error_message, sizeof(error_message));
    if (str) {
        return std::string(str);
    }
#endif
    return "Failed decoding errno: " + std::to_string(saved_errno) + " strerror_r errno=" + std::to_string(errno);
}

//
// Taken from FileSystemHandler mainly to avoid having to pull it into DSIM client dependencies
//
#if defined(_WIN32) || defined(_WIN64)
bool
socket_connection_common::GetEnvVar(const std::string& InputEnv, std::string& OutputValue)
{
    char* libvar = NULL;
    size_t requiredSize = 0;
    // getenv_s using a buffer to store the env. variable,
    // the regular getenv in case of windows hyper-threading, has a single pointer which value can be overriden by another getenv
    getenv_s(&requiredSize, NULL, 0, InputEnv.c_str());
    if (requiredSize == 0) {
        return false;
    }
    libvar = (char*)malloc(requiredSize);
    getenv_s(&requiredSize, libvar, requiredSize, InputEnv.c_str());
    OutputValue.assign(libvar);
    free(libvar);
    return true;
}
#else
bool
socket_connection_common::GetEnvVar(const std::string& InputEnv, std::string& OutputValue)
{
    const char* libvar = getenv(InputEnv.c_str());
    if (libvar == nullptr) {
        return false;
    } else {
        OutputValue.assign(libvar);
        return true;
    }
}
#endif

//************************************
// socket_connection
//************************************
socket_connection_common::socket_connection_common(const char* host, npsuite::Logger* logger)
    : m_fd(-1), m_host("0.0.0.0"), m_logger(logger)
{
    if (host != nullptr) {
        m_host = host;
    }
    config();
}

socket_connection_common::socket_connection_common(int fd, const char* host, npsuite::Logger* logger)
    : socket_connection_common(host, logger)
{
    m_fd = fd;
}

socket_connection_common::socket_connection_common(int fd,
                                                   const char* host,
                                                   const std::string& connection_details,
                                                   npsuite::Logger* logger)
    : socket_connection_common(fd, host, logger)
{
    m_connection_details = connection_details;
}

//
// Apply any environment settings for socket options.
//
void
socket_connection_common::config(void)
{
    m_socket_timeout_retry_in_seconds = m_socket_timeout_retry_in_seconds_default;
    m_socket_timeout_total_in_seconds = m_socket_timeout_total_in_seconds_default;

    std::string str_val;
    if (GetEnvVar("NSIM_SOCKET_TIMEOUT_TOTAL_IN_SECONDS", str_val)) {
        try {
            m_socket_timeout_total_in_seconds = std::stoi(str_val);
        } catch (const std::invalid_argument& e) {
            m_socket_timeout_total_in_seconds = 0;
            ELOG_INSTANCE(m_logger,
                          NSIM_DEBUG,
                          "NSIM_SOCKET_TIMEOUT_TOTAL_IN_SECONDS set to invalid value (disabled): " + std::string(e.what()));
        } catch (const std::out_of_range& e) {
            m_socket_timeout_total_in_seconds = 0;
            ELOG_INSTANCE(
                m_logger, NSIM_DEBUG, "NSIM_SOCKET_TIMEOUT_TOTAL_IN_SECONDS out of range (disabled): " + std::string(e.what()));
        }
    }

    if (GetEnvVar("NSIM_SOCKET_TIMEOUT_RETRY_IN_SECONDS", str_val)) {
        try {
            m_socket_timeout_retry_in_seconds = std::stoi(str_val);
        } catch (const std::invalid_argument& e) {
            m_socket_timeout_retry_in_seconds = 0;
            ELOG_INSTANCE(m_logger,
                          NSIM_DEBUG,
                          "NSIM_SOCKET_TIMEOUT_RETRY_IN_SECONDS set to invalid value (disabled): " + std::string(e.what()));
        } catch (const std::out_of_range& e) {
            m_socket_timeout_retry_in_seconds = 0;
            ELOG_INSTANCE(
                m_logger, NSIM_DEBUG, "NSIM_SOCKET_TIMEOUT_RETRY_IN_SECONDS out of range (disabled): " + std::string(e.what()));
        }
    }
}

//
// Dump per socket stats to stderr
//
void
socket_connection_common::dump_per_socket_stats(const std::string& prefix) const
{
    const std::initializer_list<std::string> i = {NSIM_PER_SOCKET_STATS_ENTRY_ENUMS(LIST_MACRO_SECOND_VALUE_AS_STRING)};
    const std::vector<std::string> column_names(i);
    std::vector<std::string> row_names = {SOCKET_COMMAND_ENUMS(LIST_MACRO_FIXED_ENUM_STRING)};
    const auto num_columns = column_names.size();
    const auto num_rows = row_names.size();
    std::vector<std::vector<uint64_t>> table_data;
    std::vector<bool> row_contains_data;
    std::vector<bool> column_contains_data;

    table_data.resize(num_rows);
    for (auto row = 0U; row < num_rows; row++) {
        table_data[row].resize(num_columns);
    }

    column_contains_data.resize(num_columns);
    row_contains_data.resize(num_rows);

    //
    // Populate the table data
    //
    for (auto row = 0U; row < num_rows; row++) {
        auto cmd = (socket_command_type_e)row;
        if (!m_nsim_per_socket_stats.count(cmd)) {
            continue;
        }

        const auto stats_entry = m_nsim_per_socket_stats.at(cmd);
        const uint64_t* statp = (const uint64_t*)&stats_entry;
        for (auto col = 0U; col < num_columns; col++) {
            if (statp[col]) {
                column_contains_data[col] = true;
                table_data[row][col] = statp[col];
            }
        }

        row_contains_data[row] = true;
    }
    table_dump(prefix + "Per socket stats",
               num_columns,
               num_rows,
               table_data,
               row_names,
               row_contains_data,
               column_names,
               column_contains_data);
}

//
// Dump global socket stats to stderr
//
void
socket_connection_common::dump_global_socket_stats(const std::string& prefix)
{
    const std::initializer_list<std::string> i = {NSIM_GLOBAL_STATS_ENTRY_ENUMS(LIST_MACRO_SECOND_VALUE_AS_STRING)};
    const std::vector<std::string> column_names(i);
    std::vector<std::string> row_names = {""};
    const auto num_columns = column_names.size();
    const auto num_rows = row_names.size();
    std::vector<std::vector<uint64_t>> table_data;
    std::vector<bool> row_contains_data;
    std::vector<bool> column_contains_data;

    table_data.resize(num_rows);
    for (auto row = 0U; row < num_rows; row++) {
        table_data[row].resize(num_columns);
    }

    column_contains_data.resize(num_columns);
    row_contains_data.resize(num_rows);

    //
    // Populate the table data
    //
    auto row = 0U;
    const auto stats_entry = socket_connection_common::m_nsim_global_socket_stats;
    const uint64_t* statp = (const uint64_t*)&stats_entry;
    for (auto col = 0U; col < num_columns; col++) {
        if (statp[col]) {
            column_contains_data[col] = true;
            table_data[row][col] = statp[col];
        }
    }

    row_contains_data[row] = true;

    const bool show_header = true;
    const bool show_dividers = true;
    const bool show_total = false;
    table_dump(prefix + "Global socket stats",
               num_columns,
               num_rows,
               table_data,
               row_names,
               row_contains_data,
               column_names,
               column_contains_data,
               show_header,
               show_dividers,
               show_total);
}

socket_connection_common::~socket_connection_common()
{
    close_socket();
}

sockaddr_in
socket_connection_common::find_server(std::string host, npsuite::Logger* logger)
{
    hostent* server = nullptr;
    sockaddr_in addr_in = sockaddr_in();
    // memset(&m_addr, 0, sizeof(m_addr));
    addr_in.sin_family = AF_UNSPEC;

#if defined(_WIN32) || defined(_WIN64)
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        ELOG_INSTANCE(logger, NSIM_DEBUG, "WSAStartup failed: " + std::to_string(iResult));
        return addr_in;
    }
#endif
    server = gethostbyname(host.c_str());
    if (server == nullptr) {
#if defined(_WIN32) || defined(_WIN64)
        DWORD dwError = WSAGetLastError();
        if (dwError != 0) {
            if (dwError == WSAHOST_NOT_FOUND) {
                ELOG_INSTANCE(logger, NSIM_DEBUG, "Host not found");
            } else if (dwError == WSANO_DATA) {
                ELOG_INSTANCE(logger, NSIM_DEBUG, "No data record found");
            } else {
                ELOG_INSTANCE(logger, NSIM_DEBUG, "Function failed with error: " + std::to_string(dwError));
            }
        }
#endif
        ELOG_INSTANCE(logger, NSIM_DEBUG, "Failed to find host address " + host);
        return addr_in;
    }

    addr_in.sin_addr.s_addr = ((in_addr*)server->h_addr_list[0])->s_addr;
    addr_in.sin_family = AF_INET;

    return addr_in;
}

bool
socket_connection_common::send_raw_data(size_t len_in_bytes, const void* outbuf, const std::string& prefix)
{
    transaction_lock lock(m_lock);

    return write_buf(outbuf, len_in_bytes, prefix);
}

bool
socket_connection_common::send(size_t len_in_bytes, const void* outbuf, const std::string& prefix)
{
    transaction_lock lock(m_lock);

    if (!write_buf(&len_in_bytes, sizeof(size_t), prefix)) {
        return false;
    }
    return write_buf(outbuf, len_in_bytes, prefix);
}

static size_t
read_n_bytes(int fd, void* buf, size_t len, npsuite::Logger* logger, const std::string& prefix)
{
    size_t off = 0;

    auto t0 = HiResClock::now();

    while (off != len) {
        int nbytes;
#if defined(_WIN32) || defined(_WIN64)
        nbytes = recv(fd, ((char*)buf) + off, int(len - off), 0);
#else
        nbytes = read(fd, ((uint8_t*)buf) + off, (len - off));
#endif
        if (nbytes <= 0) {
            auto saved_errno = errno;
            if (0 == nbytes) {
                ESLOG_INSTANCE(logger,
                               NSIM_DEBUG,
                               prefix + "read_n_bytes connection closed, fd=" + std::to_string(fd) + ": "
                                   + socket_connection_common::strerrno(saved_errno));
                return READ_N_BYTES_FINISHED;
            }
            if ((EAGAIN == errno) || (EINTR == errno)) {
                if (socket_connection_common::m_socket_timeout_total_in_seconds > 0) {
                    //
                    // EAGAIN can occur normally. However, if this keeps on happening and it looks like
                    // we are stuck, raise an error.
                    //
                    auto t1 = HiResClock::now();
                    FloatSec elapsed = std::chrono::duration_cast<FloatSec>(t1 - t0);
                    if (ceil(elapsed.count()) >= socket_connection_common::m_socket_timeout_total_in_seconds) {
                        ELOG_INSTANCE(logger,
                                      NSIM_DEBUG,
                                      prefix + "read_n_bytes (" + std::to_string(len) + " bytes), timed out after "
                                          + std::to_string(elapsed.count())
                                          + " seconds, retry time was set to "
                                          + std::to_string(socket_connection_common::m_socket_timeout_retry_in_seconds)
                                          + " seconds, total retry time was set to "
                                          + std::to_string(socket_connection_common::m_socket_timeout_total_in_seconds)
                                          + " seconds, fd="
                                          + std::to_string(fd)
                                          + ": "
                                          + socket_connection_common::strerrno(saved_errno));
                        return READ_N_BYTES_FINISHED;
                    }
                }
                continue;
            }

            if (EFAULT == errno) {
                ELOG_INSTANCE(
                    logger,
                    NSIM_DEBUG,
                    string_format("%sread_n_bytes EFAULT memory error, fd=%d, buf=%p, off=%lu", prefix.c_str(), fd, buf, off) + ": "
                        + socket_connection_common::strerrno(saved_errno));
            } else {
                ELOG_INSTANCE(logger,
                              NSIM_DEBUG,
                              prefix + "read_n_bytes connection error, fd=" + std::to_string(fd) + ": "
                                  + socket_connection_common::strerrno(saved_errno));
            }
            return READ_N_BYTES_FALIURE;
        }
        off += nbytes;
    }

    return READ_N_BYTES_SUCCESS;
}

size_t
socket_connection_common::receive(void* inbuf, size_t max_bytes, const std::string& prefix)
{
    transaction_lock lock(m_lock);

    size_t len_in_bytes;
    size_t ret = read_n_bytes(m_fd, &len_in_bytes, sizeof(size_t), m_logger, prefix);
    if (ret != READ_N_BYTES_SUCCESS) {
        ILOG_INSTANCE(m_logger, NSIM_DEBUG, "Socket connection was terminated, returning 0");
        return 0;
    }

    if (!len_in_bytes || len_in_bytes > max_bytes) {
        ELOG_INSTANCE(m_logger,
                      NSIM_DEBUG,
                      prefix + "receive got bad length=" + std::to_string(len_in_bytes) + " (max_bytes=" + std::to_string(max_bytes)
                          + ", fd="
                          + std::to_string(m_fd)
                          + ")");
        return 0;
    }

    ret = read_n_bytes(m_fd, inbuf, len_in_bytes, m_logger, prefix);
    if (ret != READ_N_BYTES_SUCCESS) {
        return 0;
    }
    return len_in_bytes;
}

size_t
socket_connection_common::receive_raw_data(void* inbuf, size_t max_bytes, const std::string& prefix)
{
    transaction_lock lock(m_lock);

    size_t ret;
    ret = read_n_bytes(m_fd, inbuf, max_bytes, m_logger, prefix);
    if (ret != READ_N_BYTES_SUCCESS) {
        return 0;
    }
    return max_bytes;
}

bool
socket_connection_common::poll_read(size_t timeout_in_seconds)
{
    pollfd pfd;
#if defined(_WIN32) || defined(_WIN64)
    pfd = {(unsigned)m_fd /*fd*/, POLLIN /*events to poll*/, 0 /*return type*/};
#else
    pfd = {m_fd /*fd*/, POLLIN /*events to poll*/, 0 /*return type*/};
#endif
    while (m_fd > 0) {
        int ret = poll(&pfd, 1 /*num of descriptors*/, static_cast<int>(timeout_in_seconds) * 1000);
        if (ret != 1) {
            if ((ret == 0) || ((ret < 0) && (EINTR == errno))) {
                continue;
            }
            std::string error_number = (ret < 0) ? std::to_string(errno) : "NONE";
            ELOG_INSTANCE(m_logger, NSIM_DEBUG, "poll_read: ret " + std::to_string(ret) + ", errno=" + error_number);
        }
        return ret == 1;
    }

    return false;
}

void
socket_connection_common::close_socket()
{
    if (m_fd == -1) {
        return;
    }

    close(m_fd);
    m_fd = -1;
}

bool
write_n_bytes(int fd, const void* buf, uint32_t len, npsuite::Logger* logger, const std::string& prefix)
{
    auto t0 = HiResClock::now();

    uint32_t bytes_left = len;
    const char* cptr = (const char*)buf;

    while (bytes_left > 0) {
        int nbytes = send(fd, cptr, bytes_left, send_flags);
        if (nbytes <= 0) {
            auto saved_errno = errno;
            //
            // Be aware we can also get EPIPE here if the remote end of the socket is closed.
            //
            if ((EINTR == errno) || (EAGAIN == errno)) {
                //
                // EAGAIN can occur normally. However, if this keeps on happening and it looks like
                // we are stuck, raise an error.
                //
                if (socket_connection_common::m_socket_timeout_total_in_seconds > 0) {
                    auto t1 = HiResClock::now();
                    FloatSec elapsed = std::chrono::duration_cast<FloatSec>(t1 - t0);
                    if (ceil(elapsed.count()) >= socket_connection_common::m_socket_timeout_total_in_seconds) {
                        ELOG_INSTANCE(logger,
                                      NSIM_DEBUG,
                                      prefix + "write_n_bytes (" + std::to_string(len) + " bytes), timed out after "
                                          + std::to_string(elapsed.count())
                                          + " seconds, retry time was set to "
                                          + std::to_string(socket_connection_common::m_socket_timeout_retry_in_seconds)
                                          + " seconds, total retry time was set to "
                                          + std::to_string(socket_connection_common::m_socket_timeout_total_in_seconds)
                                          + " seconds, fd="
                                          + std::to_string(fd)
                                          + ": "
                                          + socket_connection_common::strerrno(saved_errno));
                        return false;
                    }
                }
                continue;
            }
            ELOG(NSIM_DEBUG,
                 prefix + "write_n_bytes: bytes_left=" + std::to_string(bytes_left) + ", nbytes=" + std::to_string(nbytes) + ", fd="
                     + std::to_string(fd)
                     + ": "
                     + socket_connection_common::strerrno(saved_errno));
            return false;
        }

        bytes_left -= nbytes;
        cptr += nbytes;
    }

    return true;
}

bool
socket_connection_common::write_buf(const void* src, size_t bytes, const std::string& prefix)
{
    return write_n_bytes(m_fd, src, static_cast<uint32_t>(bytes), m_logger, prefix);
}

const std::string&
socket_connection_common::get_connection_details() const
{
    return m_connection_details;
}
} // namespace dsim
