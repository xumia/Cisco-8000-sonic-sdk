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

#include "sai_netlink_socket.h"
#include "sai_netlink_msg.h"

#include <linux/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>
#include <string>
#include <iostream>
#include <unistd.h>
#include <memory>

namespace silicon_one
{
namespace sai
{

sai_status_t
sai_netlink_socket::open(const std::string& family, const std::string& group)
{
    sai_status_t status;
    auto sock = sai_netlink_sock_wrapper::new_sock();
    if (sock == nullptr) {
        return SAI_STATUS_FAILURE;
    }

    status = sock->open(family, group);
    sai_return_on_error(status);

    m_sock = std::move(sock);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_netlink_socket::send_sample(uint16_t iif, uint16_t oif, uint32_t samplerate, uint32_t origsize, uint8_t* data, uint32_t size)
{
    return send<sai_psample>(iif, oif, samplerate, origsize, m_seqnum++, data, size);
}
}
}
