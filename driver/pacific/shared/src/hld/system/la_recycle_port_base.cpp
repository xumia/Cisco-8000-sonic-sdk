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

#include "system/la_recycle_port_base.h"
#include "system/la_device_impl.h"
#include "tm/la_interface_scheduler_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

constexpr la_mac_port::port_speed_e RECYCLE_PORT_DEFAULT_SPEED = la_mac_port::port_speed_e::E_100G;

la_recycle_port_base::la_recycle_port_base(const la_device_impl_wptr& device)
    : m_device(device), m_slice(LA_SLICE_ID_INVALID), m_ifg((la_ifg_id_t)-1), m_speed(RECYCLE_PORT_DEFAULT_SPEED)
{
}

la_recycle_port_base::~la_recycle_port_base()
{
}

la_status
la_recycle_port_base::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = m_scheduler->set_oqs_enabled(false /* enabled */);
    return_on_error(status);

    status = erase_slice_source_pif_entry();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_recycle_port_base::type() const
{
    return object_type_e::RECYCLE_PORT;
}

const la_device*
la_recycle_port_base::get_device() const
{
    return m_device.get();
}

la_object_id_t
la_recycle_port_base::oid() const
{
    return m_oid;
}

std::string
la_recycle_port_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_recycle_port_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_slice_id_t
la_recycle_port_base::get_slice() const
{
    start_api_getter_call();

    return m_slice;
}

la_ifg_id_t
la_recycle_port_base::get_ifg() const
{
    start_api_getter_call();

    return m_ifg;
}

la_interface_scheduler*
la_recycle_port_base::get_scheduler() const
{
    start_api_getter_call();

    return m_scheduler.get();
}

la_status
la_recycle_port_base::get_speed(la_mac_port::port_speed_e& out_speed) const
{
    out_speed = m_speed;

    return LA_STATUS_SUCCESS;
}

la_status
la_recycle_port_base::get_intf_id(la_uint_t& out_intf_id) const
{
    out_intf_id = RECYCLE_PIF_ID;
    return LA_STATUS_SUCCESS;
}
}
