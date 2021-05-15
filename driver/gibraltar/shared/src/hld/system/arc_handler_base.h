// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __ARC_HANDLER_BASE_H__
#define __ARC_HANDLER_BASE_H__

#include "api/system/la_css_memory_layout.h"
#include "api/system/la_device.h"
#include "common/bit_vector.h"
#include "common/la_status.h"
#include "hld_types_fwd.h"
#include "hw_tables/arc_cpu_common.h"
#include "lld/ll_device.h"
#include <stdint.h>
#include <stdlib.h>

namespace silicon_one
{

class la_device_impl;

class arc_handler_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    arc_handler_base(const la_device_impl_wptr& device);
    virtual ~arc_handler_base();

    // Disallow copy c'tor. Default construct is private, in order to support serialization
    arc_handler_base(const arc_handler_base&) = delete;

    la_status arc_send_from_cpu_msg(uint8_t arc_id, arc_cmd_type_e type, size_t length, uint8_t* msg);
    std::vector<bit_vector> collect_arc_events(uint8_t arc_id);
    la_status configure_css_arc_cpus();
    la_status reset_arc_cpus();

protected:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    arc_handler_base() = default;

    la_device_impl_wptr m_device;
    bool m_arc_enabled;

    enum arc_msg_offset_type_e {
        ARC_TO_CPU_CMD_READ_OFFSET,
        ARC_TO_CPU_CMD_WRITE_OFFSET,
        ARC_TO_CPU_MSG_READ_OFFSET,
        ARC_TO_CPU_MSG_WRITE_OFFSET,
        ARC_TO_CPU_CMD_QUEUE_START_OFFSET,
        ARC_TO_CPU_MSG_QUEUE_START_OFFSET,
        ARC_FROM_CPU_CMD_READ_OFFSET,
        ARC_FROM_CPU_CMD_WRITE_OFFSET,
        ARC_FROM_CPU_MSG_READ_OFFSET,
        ARC_FROM_CPU_MSG_WRITE_OFFSET,
        ARC_FROM_CPU_CMD_QUEUE_START_OFFSET,
        ARC_FROM_CPU_MSG_QUEUE_START_OFFSET,
    };

    size_t calc_arc_memory_index(arc_msg_offset_type_e msg_location);
    size_t calc_arc_offset(uint8_t arc_id, arc_msg_offset_type_e msg_location, size_t offset);
    la_status read_arc_data(uint8_t arc_id, arc_msg_offset_type_e msg_location, uint8_t* data, size_t size);
    la_status read_arc_data(uint8_t arc_id, arc_msg_offset_type_e msg_location, size_t offset, uint8_t* data, size_t size);
    la_status write_arc_data(uint8_t arc_id, arc_msg_offset_type_e msg_location, uint8_t* data, size_t size);
    la_status write_arc_data(uint8_t arc_id, arc_msg_offset_type_e msg_location, size_t offset, uint8_t* data, size_t size);
    la_status read_arc_msg_data(uint8_t arc_id, bit_vector& bv, size_t size);
    la_status write_arc_msg_data(uint8_t arc_id, uint8_t* data, size_t length);
    virtual lld_memory_sptr get_mem_ptr() = 0;
};
} // namespace silicon_one

#endif // __ARC_HANDLER_BASE_H__
