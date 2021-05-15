// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __NPU_HOST_EVENT_QUEUE_BASE_H__
#define __NPU_HOST_EVENT_QUEUE_BASE_H__

#include "common/bit_vector.h"
#include "common/la_status.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_device_impl;

class npu_host_event_queue_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    npu_host_event_queue_base(const la_device_impl_wptr& device);
    virtual ~npu_host_event_queue_base();

    // Disallow copy c'tor. Default construct is private, in order to support serialization
    npu_host_event_queue_base(const npu_host_event_queue_base&) = delete;

    virtual std::vector<bit_vector> collect_npu_host_events() = 0;
    void handle_npu_host_event(const bit_vector& event);

protected:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    npu_host_event_queue_base() = default;

    // Device this port belongs to
    la_device_impl_wptr m_device;

private:
    void handle_bfd_packet_event(const bit_vector& event);
    void handle_npu_host_packet_event(const bit_vector& event);
    void handle_npu_host_scanner_event(const bit_vector& event);
};

} // namespace silicon_one

#endif // __NPU_HOST_EVENT_QUEUE_BASE_H__
