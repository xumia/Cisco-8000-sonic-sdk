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

#include "device_simulator/dsim_client/dsim_socket_client.h"
#include "utils/logger/logger.h"
#if defined(_WIN32) || defined(_WIN64)
#include <WS2tcpip.h>
#else // LINUX
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif
using namespace npsuite;

namespace dsim
{

//************************************
// socket_client
//************************************
socket_client::socket_client(const char* host, npsuite::Logger* logger) : socket_connection_common(host, logger)
{
}

bool
socket_client::init_connection(size_t port)
{

    sockaddr_in addr_in = find_server(m_host, m_logger);
    if (AF_INET != addr_in.sin_family) {
        return false;
    }

    m_fd = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
    if (m_fd == -1) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "Client failed to create socket INET");
        return false;
    }

    addr_in.sin_port = htons((u_short)port);

    int ret = connect(m_fd, (sockaddr*)&addr_in, sizeof(addr_in));
    if (ret == -1) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "Client failed to connect to " + m_host + ":" + std::to_string(port));
        return false;
    }

#if defined(_WIN32) || defined(_WIN64)
    // win32 docs say BOOL, but they also say DWORD, but upon a bit more research the take is that the docs are wrong and they take
    // char.
    const char opt = 1;
#else
    const int opt = 1;
#endif
    // (char*) on win32, but (void*) on linux. (char*) shoud work for both.
    if (setsockopt(m_fd, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt))) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "Count not set TCP_NODELAY");
    }

#ifdef SO_NOSIGPIPE
    // Ignore SIGPIPE if supported.
    const int set_SO_NOSIGPIPE = 1;
    if (setsockopt(m_fd, SOL_SOCKET, SO_NOSIGPIPE, &set_SO_NOSIGPIPE, sizeof(set_SO_NOSIGPIPE))) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "Count not set SO_NOSIGPIPE");
    }
#endif

//
// Just some general information on what is supported by the OS.
//
#ifdef SO_NOSIGPIPE
#ifdef MSG_NOSIGNAL
    ILOG_INSTANCE(m_logger, NSIM_DEBUG, "OS supports SO_NOSIGPIPE and MSG_NOSIGNAL");
#else
    ILOG_INSTANCE(m_logger, NSIM_DEBUG, "OS supports SO_NOSIGPIPE only");
#endif
#else
    ILOG_INSTANCE(m_logger, NSIM_DEBUG, "OS has no support for SIGPIPE");
#endif

    sockaddr_in ret_addr;
    socklen_t ret_addr_len = sizeof(sockaddr_in);
    int getsock_check = getsockname(m_fd, (sockaddr*)&ret_addr, &ret_addr_len);
    if (getsock_check == -1) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "Client failed to bind to " + m_host);
        return false;
    }
    m_connection_details
        = std::string((const char*)inet_ntoa(ret_addr.sin_addr)) + ":" + std::to_string((size_t)ntohs(ret_addr.sin_port));

    //
    // SO_RCVTIMEO is an option to set a timeout value for input operations. If a receive operation has been blocked for this
    // much time without receiving additional data, it returns with a short count or with the error EWOULDBLOCK if no data were
    // received.
    //
    if (m_socket_timeout_retry_in_seconds_default) {
#if defined(_WIN32) || defined(_WIN64)
        DWORD recv_timeout = socket_connection_common::m_socket_timeout_retry_in_seconds * 1000;
#else
        struct timeval recv_timeout;
        memset(&recv_timeout, 0, sizeof(recv_timeout));
        recv_timeout.tv_sec = socket_connection_common::m_socket_timeout_retry_in_seconds;
        recv_timeout.tv_usec = 0;
#endif

        if (setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&recv_timeout, sizeof(recv_timeout)) < 0) {
            ELOG_INSTANCE(m_logger,
                          NSIM_DEBUG,
                          "DSIM client failed to set SO_RCVTIMEO to "
                              + std::to_string(socket_connection_common::m_socket_timeout_retry_in_seconds)
                              + " seconds");
        } else {
            ILOG_INSTANCE(m_logger,
                          NSIM_DEBUG,
                          "DSIM client set SO_RCVTIMEO to "
                              + std::to_string(socket_connection_common::m_socket_timeout_retry_in_seconds)
                              + " seconds");
        }
    }

    //
    // SO_SNDTIMEO is an option to set a timeout value for output operations. If a send operation has blocked for this much
    // time, it returns with a partial count or with the error EWOULDBLOCK if no data were sent.
    //
    // NOTE: for send I'm using the total time as we have no retry on sends.
    //
    if (m_socket_timeout_total_in_seconds_default) {
#if defined(_WIN32) || defined(_WIN64)
        DWORD send_timeout = socket_connection_common::m_socket_timeout_total_in_seconds_default * 1000;
#else
        struct timeval send_timeout;
        memset(&send_timeout, 0, sizeof(send_timeout));
        send_timeout.tv_sec = socket_connection_common::m_socket_timeout_total_in_seconds_default;
        send_timeout.tv_usec = 0;
#endif

        if (setsockopt(m_fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&send_timeout, sizeof(send_timeout)) < 0) {
            ELOG_INSTANCE(m_logger,
                          NSIM_DEBUG,
                          "DSIM client failed to set SO_SNDTIMEO to "
                              + std::to_string(socket_connection_common::m_socket_timeout_total_in_seconds)
                              + " seconds");
        } else {
            ILOG_INSTANCE(m_logger,
                          NSIM_DEBUG,
                          "DSIM client set SO_SNDTIMEO to "
                              + std::to_string(socket_connection_common::m_socket_timeout_total_in_seconds)
                              + " seconds");
        }
    }

    return true;
}
};
