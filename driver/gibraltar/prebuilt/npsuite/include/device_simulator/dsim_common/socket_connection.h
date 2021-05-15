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

#ifndef __SOCKET_CONNECTION_H__
#define __SOCKET_CONNECTION_H__
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <string>
#if defined(_WIN32) || defined(_WIN64)
#pragma comment(lib, "Ws2_32.lib")
#include <winsock2.h>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdlib.h>

#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif

#include <mutex>
#include <map>

#include "device_simulator/socket_command.h"
#include "utils/list_macros.h"

namespace npsuite
{
class Logger;
}
namespace dsim
{
/// @brief Base class for socket connections.
///
/// Implements socket functionality.
class socket_connection_common
{
public:
    virtual ~socket_connection_common();
    // C'tor
    socket_connection_common(const char* host, npsuite::Logger* logger);
    socket_connection_common(int fd, const char* host, npsuite::Logger* logger);
    socket_connection_common(int fd, const char* host, const std::string& connection_details, npsuite::Logger* logger);
    void config(void);

public:
    /// @brief Sends data to socket.
    ///
    /// @param[in]  len_in_bytes        Length of the buffer to send, in bytes.
    /// @param[in]  outbuf              Buffer to send.
    /// @retval     success of action.
    bool send(size_t len_in_bytes, const void* outbuf, const std::string& prefix = "");

    /// @brief Sends raw data to socket, without previously sending the data size.
    ///
    /// @param[in]  len_in_bytes        Length of the buffer to send, in bytes.
    /// @param[in]  outbuf              Buffer to send.
    /// @retval     success of action.
    bool send_raw_data(size_t len_in_bytes, const void* outbuf, const std::string& prefix = "");

    /// @brief Receives data from socket.
    ///
    /// param[in]   inbuf               Buffer to contain received data.
    /// param[in]   max_bytes           Size of the buffer. The received data is truncated if its size is larger than max_bytes.
    ///
    /// @retval     number of read bytes.
    size_t receive(void* inbuf, size_t max_bytes, const std::string& prefix = "");

    /// @brief Receives data from socket as it is.
    ///
    /// param[in]   inbuf               Buffer to contain received data.
    /// param[in]   max_bytes           Size of the buffer. The received data is truncated if its size is larger than max_bytes.
    ///
    /// @retval     number of read bytes.
    size_t receive_raw_data(void* inbuf, size_t max_bytes, const std::string& prefix = "");

    /// @brief Polls on read socket connection.
    ///
    /// The call is blocking until one of the following occurs:
    /// 1. There is data to read.
    /// 2. Connection is closed.
    /// 3. Timeout is expired.
    ///
    /// @param[in]  timeout_in_seconds  Wait timeout in seconds. If negative, the timeout is infinite
    ///
    /// @retval     true                Data arrived or connection is closed. If connection is closed, following call to receive
    /// will return 0 bytes.
    /// @retval     false               Timeout has expired.
    bool poll_read(size_t timeout_in_seconds);

    /// @brief Close socket connection.
    void close_socket();

    /// @brief Checks if the socket is open or closed.
    inline bool is_socket_closed()
    {
        return m_fd == -1;
    }

    /// @brief Gets the file descriptor
    ///
    /// @retval file escriptor
    inline int get_file_descriptor()
    {
        return m_fd;
    }

    /// @breif Aux function to find server ID by host string.
    static sockaddr_in find_server(std::string host, npsuite::Logger* logger);

    /// @brief Returns connection information - ip address and port
    const std::string& get_connection_details() const;

    //
    // To handle cases where the DSIM client might get stuck due to a protocol
    // or kernel problem, we have a timeout per socket read/write. This controls
    // our ability to retry up until the total retry time, after which we flag
    // an error and give up. The following env vars can override this behavior.
    // Set to <= 0 to disable.
    //
    // An example: wait for any read/write to complete for a maximum of 3 secs
    // and then immediately fail.
    //
    //     NSIM_SOCKET_TIMEOUT_RETRY_IN_SECONDS = 3
    //     NSIM_SOCKET_TIMEOUT_TOTAL_IN_SECONDS = 1
    //
    // An example: wait for any read/write to complete for a maximum of 3 secs
    // and then keep on retrying until the total time is exceeded. We will likely
    // wait about 12 seconds before declaring failure.
    //
    //     NSIM_SOCKET_TIMEOUT_RETRY_IN_SECONDS = 3
    //     NSIM_SOCKET_TIMEOUT_TOTAL_IN_SECONDS = 10
    //

    //
    // Can be overriden by env variable "NSIM_SOCKET_TIMEOUT_RETRY_IN_SECONDS"
    //
    static const int m_socket_timeout_retry_in_seconds_default = 20;

    //
    // Can be overriden by env variable "NSIM_SOCKET_TIMEOUT_TOTAL_IN_SECONDS"
    //
    static const int m_socket_timeout_total_in_seconds_default = 5 * m_socket_timeout_retry_in_seconds_default;

    static int m_socket_timeout_retry_in_seconds;
    static int m_socket_timeout_total_in_seconds;

    //
    // Taken from FileSystemHandler mainly to avoid having to pull it into DSIM client dependencies
    //
    // Sets OutputValue to environment string if found.  OutputValue is not modified if the environment
    // string is not found
    static bool GetEnvVar(const std::string& InputEnv, std::string& OutputValue);

    //
    // Map errno to std:string
    //
    static std::string strerrno(int saved_errno);

public:
// clang-format off
    //
    // Statistics, per socket
    //
    #define NSIM_PER_SOCKET_STATS_ENTRY_ENUMS(list_macro)                         \
        list_macro(NSIM_PER_SOCKET_STATS_TX_BYTES = 0,      "tx-bytes"),          \
        list_macro(NSIM_PER_SOCKET_STATS_TX_CMDS,           "tx-cmds"),           \
        list_macro(NSIM_PER_SOCKET_STATS_TX_ERROR,          "tx-error"),          \
        list_macro(NSIM_PER_SOCKET_STATS_TX_BYTES_NO_FLUSH, "tx-bytes-no-flush"), \
        list_macro(NSIM_PER_SOCKET_STATS_RX_BYTES,          "rx-bytes"),          \
        list_macro(NSIM_PER_SOCKET_STATS_RX_CMDS,           "rx-cmds"),           \
        list_macro(NSIM_PER_SOCKET_STATS_RX_ERROR,          "rx-error"),
    // clang-format on
    typedef enum {
        NSIM_PER_SOCKET_STATS_ENTRY_ENUMS(LIST_MACRO_FIRST_VALUE) NSIM_PER_SOCKET_STATS_MAX
    } nsim_per_socket_stats_entry_enum;
    typedef struct {
        //
        // Make sure the order of these matches the enum list above
        //
        uint64_t tx_bytes{};
        uint64_t tx_cmds{};
        uint64_t tx_error{};
        uint64_t tx_bytes_no_flush{};
        uint64_t rx_bytes{};
        uint64_t rx_cmds{};
        uint64_t rx_error{};
    } nsim_per_socket_stats_entry;

// clang-format off
    //
    // Statistics, global.
    //
    #define NSIM_GLOBAL_STATS_ENTRY_ENUMS(list_macro)             \
        list_macro(NSIM_GLOBAL_STATS_TX_BYTES = 0, "tx-bytes"),   \
        list_macro(NSIM_GLOBAL_STATS_TX_CMDS,      "tx-cmds"),    \
        list_macro(NSIM_GLOBAL_STATS_TX_ERROR,     "tx-error"),   \
        list_macro(NSIM_GLOBAL_STATS_RX_BYTES,     "rx-bytes"),   \
        list_macro(NSIM_GLOBAL_STATS_RX_CMDS,      "rx-cmds"),    \
        list_macro(NSIM_GLOBAL_STATS_RX_ERROR,     "rx-error"),
    // clang-format on
    typedef enum { NSIM_GLOBAL_STATS_ENTRY_ENUMS(LIST_MACRO_FIRST_VALUE) NSIM_GLOBAL_STATS_MAX } NSIM_GLOBAL_STATS_ENTRY_ENUM;
    typedef struct {
        //
        // Make sure the order of these matches the enum list above
        //
        uint64_t tx_bytes{};
        uint64_t tx_cmds{};
        uint64_t tx_error{};
        uint64_t rx_bytes{};
        uint64_t rx_cmds{};
        uint64_t rx_error{};
    } nsim_global_socket_stats_entry;

    //
    // Per socket statistics, indexed by command type
    //
    std::map<socket_command_type_e, nsim_per_socket_stats_entry> m_nsim_per_socket_stats;

    //
    // Global statistics
    //
    static nsim_global_socket_stats_entry m_nsim_global_socket_stats;

    //
    // Dump all stats to stderr
    //
    void dump_per_socket_stats(const std::string& prefix) const;
    static void dump_global_socket_stats(const std::string& prefix);

protected:
    // Write bytes to socket.
    bool write_buf(const void* src, size_t bytes, const std::string& prefix);

protected:
    // File descriptor to send/receive data.
    int m_fd;

    // host name.
    std::string m_host;

    // Logger
    npsuite::Logger* m_logger;
    using transaction_lock = std::lock_guard<std::recursive_mutex>;
    // Lock used to ensure protocol execution atomicity
    // Protocol specifies:
    // 1. send payload size
    // 2. send payload
    std::recursive_mutex m_lock;

    // Connection details - ip address and port
    std::string m_connection_details;
};

} // namespace dsim

#endif // __SOCKET_CONNECTION_H__
