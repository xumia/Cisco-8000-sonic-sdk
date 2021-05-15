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

#ifndef __DSIM_SOCKET_CLIENT_H__
#define __DSIM_SOCKET_CLIENT_H__
#include "device_simulator/dsim_common/socket_connection.h"

namespace dsim
{
/// @brief Socket Client.
///
/// Socket Client connect to a socket, previously opened by Socket Server.
class socket_client : public socket_connection_common
{
public:
    /// @brief C'tor
    ///
    /// @param[in]  host                    Socket connection address.
    ///
    /// @param[in]  logger                  Pointer to npsuite logger.
    socket_client(const char* host, npsuite::Logger* logger);

    /// @brief Connects to the socket.
    ///
    /// @param[in]  port                    Port number to connect to.
    ///
    /// @retval     true                    Server has accepted the connection. Send/Receive operations are allowed.
    /// @retval     false                   Server has accepted the connection. Cannot Send/Receive.
    bool init_connection(size_t port);
};
} // namespace dsim
#endif
