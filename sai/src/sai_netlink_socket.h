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

#ifndef __SAI_NETLINK_SOCKET__
#define __SAI_NETLINK_SOCKET__

#include <string>
#include <cstdint>
#include <atomic>
#include <memory>

#include "sai_netlink_sock_wrapper.h"
#include "sai_netlink_msg.h"
#include "saistatus.h"
#include "sai_utils.h"

namespace silicon_one
{
namespace sai
{

class sai_netlink_socket
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS;

public:
    sai_netlink_socket() : m_seqnum(0){};
    sai_status_t open(const std::string& family, const std::string& group);
    sai_status_t send_sample(uint16_t iif, uint16_t oif, uint32_t samplerate, uint32_t origsize, uint8_t* data, uint32_t size);
    sai_netlink_socket(const sai_netlink_socket&) = delete;

private:
    std::unique_ptr<sai_netlink_sock_wrapper> m_sock;
    std::atomic<uint32_t> m_seqnum;
    template <typename T, typename... Args>
    sai_status_t send(Args&&... args)
    {
        T msg(std::forward<Args>(args)...);
        return m_sock->send(msg);
    }
};
}
}
#endif //__SAI_NETLINK_SOCKET__
