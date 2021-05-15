// BEGIN_LEGAL
//
// Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __SAI_NETLINK_SOCK_WRAPPER_H__
#define __SAI_NETLINK_SOCK_WRAPPER_H__

#include "sai_netlink_msg.h"
#include <iostream>
#include <memory>
#include <linux/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>
#include "sai_utils.h"

namespace silicon_one
{

namespace sai
{

class sai_netlink_sock_wrapper
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS;

public:
    static std::unique_ptr<sai_netlink_sock_wrapper> new_sock()
    {
        auto sock = std::unique_ptr<sai_netlink_sock_wrapper>(new sai_netlink_sock_wrapper());
        if (sock == nullptr or sock->sock_ptr() == nullptr) {
            return nullptr;
        }
        return sock;
    }

    int family() const
    {
        return m_family;
    }
    int group() const
    {
        return m_group;
    }

    ~sai_netlink_sock_wrapper()
    {
        close();
    }

    void close()
    {
        if (m_sock != nullptr) {
            nl_close(m_sock);
            m_sock = nullptr;
        }
    }

    sai_status_t send(sai_netlink_msg& msg_builder)
    {
        if (m_sock == nullptr) {
            return SAI_STATUS_FAILURE;
        }

        auto msg = msg_builder.message(m_family);
        if (msg == nullptr) {
            return SAI_STATUS_FAILURE;
        }

        int ret = nl_send_auto(m_sock, msg->msg_ptr());

        if (ret <= 0) {
            return SAI_STATUS_FAILURE;
        }
        return SAI_STATUS_SUCCESS;
    }

    sai_status_t recv()
    {
        int ret = nl_recvmsgs_default(m_sock);
        if (ret) {
            sai_log_error(SAI_API_SWITCH, "netlink recieve failed");
            return SAI_STATUS_FAILURE;
        }
        return SAI_STATUS_SUCCESS;
    }

    struct nl_sock* sock_ptr()
    {
        return m_sock;
    }

    sai_status_t open(std::string family, std::string group)
    {
        nl_socket_disable_seq_check(m_sock);

        if (genl_connect(m_sock) < 0) {
            sai_log_error(SAI_API_SWITCH, "genl_connect failed");
            nl_socket_free(m_sock);
            m_sock = nullptr;
            return SAI_STATUS_INVALID_PARAMETER;
        }

        if ((m_family = genl_ctrl_resolve(m_sock, family.c_str())) < 0) {
            sai_log_error(SAI_API_SWITCH, "genl_ctrl_resolve failed");
            nl_socket_free(m_sock);
            m_sock = nullptr;
            return SAI_STATUS_INVALID_PARAMETER;
        }

        m_group = genl_ctrl_resolve_grp(m_sock, family.c_str(), group.c_str());

        nl_socket_set_peer_groups(m_sock, 1 << (m_group - 1));

        return SAI_STATUS_SUCCESS;
    }

private:
    sai_netlink_sock_wrapper()
    {
        m_sock = nl_socket_alloc();
    }
    int m_family = -1;
    int m_group = -1;
    struct nl_sock* m_sock = nullptr;
};
}
}

#endif //__SAI_NETLINK_SOCK_WRAPPER_H__
