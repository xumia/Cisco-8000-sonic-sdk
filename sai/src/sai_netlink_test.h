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

#ifndef SAI_NETLINK_TEST_H
#define SAI_NETLINK_TEST_H

#include "sai_netlink_sock_wrapper.h"
#include <unistd.h>
#include <linux/netlink.h>
#include <string.h>
#include <vector>

namespace silicon_one
{

namespace sai
{

struct NlPsample {
    uint16_t iif_idx = 0;
    uint16_t oif_idx = 0;
    uint32_t orig_size = 0;
    uint32_t group = 0;
    uint32_t seq = 0;
    uint32_t rate = 0;
    uint32_t data_size = 0;
    std::vector<uint8_t> data;
};

class sai_netlink_test_socket
{

public:
    sai_netlink_test_socket() = default;
    sai_netlink_test_socket(const sai_netlink_test_socket&) = delete;
    sai_netlink_test_socket(const sai_netlink_test_socket&&) = delete;

    int open(const std::string& family, const std::string& group, int timeout_sec);
    int recv(NlPsample& sample);

private:
    int _open(int timeout_sec);
    std::unique_ptr<sai_netlink_sock_wrapper> m_sock;
    static int recv_callback(struct nl_msg* msg, void* arg);
};

std::vector<NlPsample> receive_psample_test(const std::string& family,
                                            const std::string& group,
                                            uint32_t num_samples,
                                            int timeout_sec = 1);
}
}

#endif
