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

#include "la_ptp_handler_base.h"
#include "system/la_device_impl.h"

#include <sstream>

namespace silicon_one
{

la_ptp_handler_base::la_ptp_handler_base(const la_device_impl_wptr& device) : m_use_debug_device_time_load(false), m_device(device)
{
}

la_ptp_handler_base::~la_ptp_handler_base()
{
}

la_status
la_ptp_handler_base::initialize(la_object_id_t oid)
{
    m_oid = oid;
    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_base::destroy()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_base::enable_load_event_generation(bool enable)
{
    m_use_debug_device_time_load = enable;

    return LA_STATUS_SUCCESS;
}

la_status
la_ptp_handler_base::set_pad_config(ptp_pads_config config) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ptp_handler_base::get_pad_config(ptp_pads_config& out_config) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ptp_handler_base::load_new_time(ptp_time load_time) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ptp_handler_base::capture_time(ptp_time& out_load_time) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ptp_handler_base::adjust_device_time(ptp_sw_tuning_config adjustment) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ptp_handler_base::set_load_time_offset(la_uint64_t offset) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ptp_handler_base::get_load_time_offset(la_uint64_t& out_offset) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ptp_handler_base::load_new_time_unit(ptp_time_unit time_unit) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ptp_handler_base::get_time_unit(ptp_time_unit& out_time_unit) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ptp_handler_base::send_cpu_device_time_load() const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_object::object_type_e
la_ptp_handler_base::type() const
{
    return object_type_e::PTP_HANDLER;
}

const la_device*
la_ptp_handler_base::get_device() const
{
    return m_device.get();
}

la_object_id_t
la_ptp_handler_base::oid() const
{
    return m_oid;
}

std::string
la_ptp_handler_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_ptp_handler_base(oid=" << m_oid << ")";
    return log_message.str();
}

} // namespace silicon_one
