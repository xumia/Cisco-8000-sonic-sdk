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

#include "sai_netlink_test.h"
#include "sai_utils.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

namespace silicon_one
{

namespace sai
{

sai_status_t
sai_netlink_test_socket::recv(NlPsample& sample)
{

    if (nl_socket_modify_cb(m_sock->sock_ptr(), NL_CB_VALID, NL_CB_CUSTOM, recv_callback, &sample)) {
        sai_log_error(SAI_API_SWITCH, "netlink recieve failed");
        return SAI_STATUS_FAILURE;
    }

    if (nl_recvmsgs_default(m_sock->sock_ptr())) {
        sai_log_error(SAI_API_SWITCH, "netlink recieve timeout");
        return SAI_STATUS_FAILURE;
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_netlink_test_socket::open(const std::string& family, const std::string& group, int timeout_sec)
{
    m_sock = sai_netlink_sock_wrapper::new_sock();
    if (m_sock == nullptr) {
        sai_log_error(SAI_API_SWITCH, "invalid sock");
        return SAI_STATUS_FAILURE;
    }

    if (m_sock->open(family, group) != SAI_STATUS_SUCCESS) {
        sai_log_error(SAI_API_SWITCH, "failed to open family");
        return SAI_STATUS_FAILURE;
    }
    return _open(timeout_sec);
}

sai_status_t
sai_netlink_test_socket::_open(int timeout_sec)
{
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;

    if (setsockopt(
            nl_socket_get_fd(m_sock->sock_ptr()), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout))) {
        sai_log_error(SAI_API_SWITCH, "failed to set socket timeout");
        return SAI_STATUS_FAILURE;
    }

    struct sockaddr_nl src_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    bind(nl_socket_get_fd(m_sock->sock_ptr()), (struct sockaddr*)&src_addr, sizeof(src_addr));
    int resolved_group = m_sock->group();
    setsockopt(nl_socket_get_fd(m_sock->sock_ptr()), SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &resolved_group, sizeof(resolved_group));

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_netlink_test_socket::recv_callback(struct nl_msg* msg, void* arg)
{
    if (msg == nullptr) {
        sai_log_error(SAI_API_SWITCH, "nullptr netlink message");
        return SAI_STATUS_FAILURE;
    }

    if (arg == nullptr) {
        sai_log_error(SAI_API_SWITCH, "nullptr netlink arg");
        return SAI_STATUS_FAILURE;
    }

    struct nlattr* nla[PSAMPLE_ATTR_MAX];

    auto ctx = reinterpret_cast<NlPsample*>(arg);

    auto nlh = nlmsg_hdr(msg);

    if (genlmsg_parse(nlh, 0, nla, PSAMPLE_ATTR_MAX, NULL)) {
        perror("genlmsg_parse");
        return -1;
    }

    ctx->iif_idx = nla_get_u16(nla[PSAMPLE_ATTR_IIFINDEX]);
    ctx->oif_idx = nla_get_u16(nla[PSAMPLE_ATTR_OIFINDEX]);
    ctx->orig_size = nla_get_u32(nla[PSAMPLE_ATTR_ORIGSIZE]);
    ctx->group = nla_get_u32(nla[PSAMPLE_ATTR_SAMPLE_GROUP]);
    ctx->seq = nla_get_u32(nla[PSAMPLE_ATTR_GROUP_SEQ]);
    ctx->rate = nla_get_u32(nla[PSAMPLE_ATTR_SAMPLE_RATE]);
    struct nlattr* data = nla[PSAMPLE_ATTR_DATA];
    ctx->data_size = nla_len(data);
    uint8_t* d = static_cast<uint8_t*>(nla_data(data));

    std::copy(d, d + ctx->data_size, std::back_inserter(ctx->data));

    return SAI_STATUS_SUCCESS;
}

void
_receive_psample_test(sai_netlink_test_socket& sock, std::vector<NlPsample>& results, uint32_t num_samples)
{
    for (uint32_t i = 0; i < num_samples; i++) {
        NlPsample sample;
        if (sock.recv(sample) != SAI_STATUS_SUCCESS) {
            perror("sock.recv timeout");
            break;
        }
        results.push_back(sample);
    }
}

std::vector<NlPsample>
receive_psample_test(const std::string& family, const std::string& group, uint32_t num_samples, int timeout_sec)
{
    std::vector<NlPsample> results;
    sai_netlink_test_socket sock;
    if (sock.open(family, group, timeout_sec)) {
        return {};
    }
    _receive_psample_test(sock, results, num_samples);
    return results;
}
}
}
