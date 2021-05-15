// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "la_npu_host_port_base.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "system/la_device_impl.h"
#include "system/la_remote_port_impl.h"
#include "system/la_system_port_base.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/la_unicast_tc_profile_impl.h"
#include "tm/tm_utils.h"

#include <sstream>

namespace silicon_one
{

la_npu_host_port_base::la_npu_host_port_base(const la_device_impl_wptr& device)
    : m_device(device), m_system_port(nullptr), m_speed(NPU_HOST_PORT_DEFAULT_SPEED)
{
}

la_npu_host_port_base::~la_npu_host_port_base() = default;

la_status
la_npu_host_port_base::initialize_local(la_system_port_gid_t system_port_gid, la_voq_set* voq_set, const la_tc_profile* tc_profile)
{
    la_slice_ifg s_ifg = m_device->get_slice_id_manager()->get_npu_host_port_ifg();
    la_status status = initialize_resources(s_ifg.slice, s_ifg.ifg, LA_OBJECT_ID_INVALID /* oid */);
    return_on_error(status);

    la_system_port_base_sptr system_port;
    la_voq_set_wptr voq_set_wptr = m_device->get_sptr(voq_set);
    la_tc_profile_wcptr tc_profile_wptr = m_device->get_sptr(tc_profile);
    status = m_device->create_system_port(system_port_gid, m_device->get_sptr(this), voq_set_wptr, tc_profile_wptr, system_port);
    return_on_error(status);

    m_system_port = system_port;

    return LA_STATUS_SUCCESS;
}

la_status
la_npu_host_port_base::initialize_resources(la_slice_id_t slice, la_ifg_id_t ifg, la_object_id_t oid)
{
    if (oid != LA_OBJECT_ID_INVALID) { // In case of MCG counter npu_host ports m_oid wasn't initialized
        m_oid = oid;
    }

    la_status status = m_device->m_ifg_schedulers[slice][ifg]->initialize_interface(HOST_PIF_ID, 1 /* m_pif_count */);
    return_on_error(status);

    la_interface_scheduler_impl_sptr scheduler;
    status = m_device->create_interface_scheduler(slice, ifg, HOST_PIF_ID, m_speed, false /*is_fabric*/, scheduler);
    return_on_error(status);
    m_scheduler = scheduler;

    status = set_redirect_destination(slice, ifg);
    return_on_error(status);

    status = set_slice_source_pif_entry();
    return_on_error(status);

    status = scheduler->set_oqs_enabled(true /* enabled */);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_npu_host_port_base::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    if (m_scheduler) {
        la_status status = m_scheduler->set_oqs_enabled(false /* enabled */);
        return_on_error(status);
    }

    if (m_system_port) {
        m_device->remove_object_dependency(m_system_port, this);
        m_device->do_destroy(m_system_port);
    }

    if (m_remote_port) {
        m_device->remove_object_dependency(m_remote_port, this);
        m_device->do_destroy(m_remote_port);
    }

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_npu_host_port_base::type() const
{
    return object_type_e::NPU_HOST_PORT;
}

const la_device*
la_npu_host_port_base::get_device() const
{
    return m_device.get();
}

la_object_id_t
la_npu_host_port_base::oid() const
{
    return m_oid;
}

std::string
la_npu_host_port_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_npu_host_port_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_interface_scheduler*
la_npu_host_port_base::get_scheduler() const
{
    return m_scheduler.get();
}

const la_system_port*
la_npu_host_port_base::get_system_port() const
{
    return m_system_port.get();
}

la_status
la_npu_host_port_base::get_speed(la_mac_port::port_speed_e& out_speed) const
{
    out_speed = m_speed;

    return LA_STATUS_SUCCESS;
}

la_status
la_npu_host_port_base::set_redirect_destination(la_slice_id_t slice, la_ifg_id_t ifg)
{
    npl_redirect_destination_table_t::value_type v;
    npl_redirect_destination_table_t::key_type k;
    npl_redirect_destination_table_t::entry_pointer_type e = nullptr;

    k.device_packet_info_ifg = ifg;

    v.payloads.redirect_destination_reg.port_reg = NPL_REDIRECT_DESTINATION_NPU_HOST;

    return m_device->m_tables.redirect_destination_table[slice]->set(k, v, e);
}

bool
la_npu_host_port_base::is_remote() const
{
    if (m_remote_port)
        return true;

    return false;
}

} // namespace silicon_one
