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

#ifndef __DSIM_SOCKET_SERVER_H__
#define __DSIM_SOCKET_SERVER_H__
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include "device_simulator/dsim_common/socket_connection.h"

namespace npsuite
{
class Logger;
}
namespace dsim
{

/// @brief Dsim Socket Server.
///
/// Dsim Socket Server opens socket connection and allows clients to connect to it.
/// Before opening socket, clients will get refused on connection attempt.
class dsim_socket_server
{
public:
    /// @brief C'tor
    ///
    /// @param[in]  path                    Socket connection address.
    ///
    /// @param[in]  logger                  Pointer to npsuite logger.
    dsim_socket_server(const char* path, npsuite::Logger* logger);

    /// @brief C'tor
    ///
    /// @param[in]  path                    Socket connection address.
    ///
    /// @param[in]  logger                  Pointer to npsuite logger.
    /// @param[in]  max_number_of_connections                 Maximal number of connections.
    dsim_socket_server(const char* host, npsuite::Logger* logger, size_t max_number_of_connections);

    /// @brief D'tor
    ~dsim_socket_server();

    /// @brief Opening socket connection.
    /// Returns port number to connect to.
    /// After this operation, clients may connect to the socket.
    ///
    /// @param[in]  max_num_clients         Maximal number of clients allowed to connect the socket. If number, of clients is
    ///                                     greater than that, clients will get refused connection.
    /// @param[in]  port                    Port number to connect to. If 0, the port will be chosen automatically.
    ///
    /// @retval     0                           Connection attempt failed.
    /// @retval     local_port > 0              Connection attempt successful, local port to be used by client to connect.

    size_t init_connection(u_short port);

    /// @brief Monitor multiple file descriptors.
    /// The call is blocking until there is a new client connection
    /// or a new client command or until timeout exceeded.
    ///
    /// @param[in] timeout         The time period which will be spent for waiting on event
    ///
    /// @retval     true           Call finished successfully
    /// @retval     flase          Error occurs
    bool select_activity(timeval* timeout = nullptr);

    /// @brief Accepts client connection.
    ///
    /// The call is blocking until one of the clients is connected.
    ///
    bool accept_client();

    /// @brief Check if there is an incoming connection to accept
    inline bool is_new_connection()
    {
        return FD_ISSET(m_serv_fd, &m_readfds) > 0;
    }

    /// @brief Check if there is an IO operation incoming from the client
    ///
    /// @param[in] client socket connection
    bool has_pending_command(socket_connection_common& sc);

    /// @brief Get all connections to the server
    ///
    /// @retval Returns the list of all connections to the server
    std::vector<std::unique_ptr<socket_connection_common>>& get_connections();

    /// @brief Get the number of active client connections.
    ///
    /// @retval Returns the number of clients connected to the server.
    size_t get_num_of_connections();

    /// @brief Set the number of maximum allowed client connections
    void set_max_number_of_connections(size_t max_number_of_connections);

    /// @brief Returns connection information - ip address and port
    const std::string& get_connection_details() const;

    /// Close the socket.
    void close_socket();

private:
    // File descriptor to the socket. This descriptor is used to accept client connections. Not for reads/writes.
    int m_serv_fd;
    // Indicator that m_serv_fd has been closed
    bool m_shutdown;
    // Connection details for termination
    std::string m_connection_details;

    // List of connections to the server
    std::vector<std::unique_ptr<socket_connection_common>> m_connections;

    // Set of active fds to monitor
    fd_set m_readfds;

    // Number of maximum allowed client connections to the server
    size_t m_max_number_of_connections;

    // Host name
    std::string m_host;
    // Logger
    npsuite::Logger* m_logger;
};

} // namespace dsim

#endif // __DSIM_SOCKET_SERVER_H__
