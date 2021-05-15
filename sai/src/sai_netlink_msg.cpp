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

#include "sai_netlink_msg.h"
#include "sai_utils.h"

namespace silicon_one
{

namespace sai
{

std::unique_ptr<sai_netlink_msg_wrapper>
sai_netlink_msg_wrapper::new_msg()
{
    auto msg = std::unique_ptr<sai_netlink_msg_wrapper>(new sai_netlink_msg_wrapper());
    if (msg == nullptr or msg->msg_ptr() == nullptr) {
        return nullptr;
    }
    return msg;
}

sai_netlink_msg_wrapper::sai_netlink_msg_wrapper()
{
    m_msg = nlmsg_alloc();
}

sai_netlink_msg_wrapper::~sai_netlink_msg_wrapper()
{
    if (m_msg != nullptr) {
        nlmsg_free(m_msg);
    }
}

nl_msg*
sai_netlink_msg_wrapper::msg_ptr()
{
    return m_msg;
}

std::unique_ptr<sai_netlink_msg_wrapper>
sai_netlink_msg::message(int family)
{
    add_attributes();

    auto msg = create_msg(family);
    if (msg == nullptr) {
        return nullptr;
    }
    for (auto& attr : m_attributes) {
        switch (attr.type) {
        case nl_attr_type::U16:
            if (nla_put_u16(msg->msg_ptr(), attr.attr, attr.u16) < 0) {
                return nullptr;
            }
            break;
        case nl_attr_type::U32:
            if (nla_put_u32(msg->msg_ptr(), attr.attr, attr.u32) < 0) {
                return nullptr;
            }
            break;
        case nl_attr_type::DATA: {
            struct nl_data* data = nl_data_alloc(attr.packet_data, attr.size);
            if (!data) {
                return nullptr;
            }
            if (nla_put_data(msg->msg_ptr(), attr.attr, data) < 0) {
                nl_data_free(data);
                return nullptr;
            }

            break;
        }
        default:
            assert(false);
        }
    }
    return msg;
}

std::unique_ptr<sai_netlink_msg_wrapper>
sai_netlink_msg::create_msg(int family)
{
    auto msg = sai_netlink_msg_wrapper::new_msg();

    if (msg == nullptr) {
        sai_log_error(SAI_API_SWITCH, "Failed to allocate netlink message");
        return nullptr;
    }

    auto hdr = genlmsg_put(msg->msg_ptr(), NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0, m_command, version());

    if (hdr == nullptr) {
        sai_log_error(SAI_API_SWITCH, "Failed to build netlink message header");
        return nullptr;
    }
    return msg;
}

void
sai_psample::add_attributes()
{
    static const uint32_t sample_group = 1;

    m_attributes.push_back(sai_netlink_msgAttribute{.attr = PSAMPLE_ATTR_IIFINDEX, .type = nl_attr_type::U16, {.u16 = m_iif}});
    m_attributes.push_back(sai_netlink_msgAttribute{.attr = PSAMPLE_ATTR_OIFINDEX, .type = nl_attr_type::U16, {.u16 = m_oif}});
    m_attributes.push_back(
        sai_netlink_msgAttribute{.attr = PSAMPLE_ATTR_SAMPLE_RATE, .type = nl_attr_type::U32, {.u32 = m_samplerate}});
    m_attributes.push_back(sai_netlink_msgAttribute{.attr = PSAMPLE_ATTR_ORIGSIZE, .type = nl_attr_type::U32, {.u32 = m_size}});
    m_attributes.push_back(
        sai_netlink_msgAttribute{.attr = PSAMPLE_ATTR_SAMPLE_GROUP, .type = nl_attr_type::U32, {.u32 = sample_group}});
    m_attributes.push_back(
        sai_netlink_msgAttribute{.attr = PSAMPLE_ATTR_GROUP_SEQ, .type = nl_attr_type::U32, {.u32 = m_groupseq}});
    m_attributes.push_back(
        sai_netlink_msgAttribute{.attr = PSAMPLE_ATTR_DATA, .type = nl_attr_type::DATA, {.packet_data = m_data}, .size = m_size});
}
}
}
