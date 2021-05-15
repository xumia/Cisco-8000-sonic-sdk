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

#include "system/la_punt_inject_port_base.h"
#include "nplapi/npl_constants.h"
#include "system/la_device_impl.h"
#include "system/la_system_port_base.h"

#include "hld_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_punt_inject_port_base::la_punt_inject_port_base(const la_device_impl_wptr& device) : m_device(device), m_mac_addr()
{
}

la_punt_inject_port_base::~la_punt_inject_port_base()
{
}

la_status
la_punt_inject_port_base::initialize(la_object_id_t oid, la_system_port_base* system_port, la_mac_addr_t mac_addr)
{
    m_oid = oid;
    if (m_system_port != nullptr) {
        return LA_STATUS_EBUSY;
    }

    bool svl_mode = false;
    la_status status = m_device->get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (system_port->has_port_dependency()) {
        return LA_STATUS_EBUSY;
    }

    la_system_port_base::port_type_e sys_port_type = system_port->get_port_type();
    if ((svl_mode == false) && (sys_port_type == la_system_port_base::port_type_e::REMOTE)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    m_mac_addr.flat = mac_addr.flat;
    m_system_port = m_device->get_sptr(system_port);

    la_slice_id_t slice = system_port->get_slice();

    status = LA_STATUS_SUCCESS;
    if ((slice != LA_SLICE_ID_INVALID) && (sys_port_type != la_system_port_base::port_type_e::REMOTE)) {
        // Configure source PIF entries
        status = set_slice_source_pif_entry(slice);
        return_on_error(status);

        // Configure inject up entry
        npl_initial_pd_nw_rx_data_t init_data;
        memset(&init_data, 0, sizeof(npl_initial_pd_nw_rx_data_t)); // Empty struct. We only need slice, ifg and pif.
        status = m_system_port->set_inject_up_entry(init_data);
        return_on_error(status);
    }

    if (sys_port_type == la_system_port_base::port_type_e::PCI) {
        status = m_device->set_network_interface_mac_addr(slice, mac_addr);
        return_on_error(status);
    }

    status = handle_punt_inject_over_mac_at_init();
    return_on_error(status);

    m_device->add_object_dependency(system_port, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_punt_inject_port_base::destroy()
{

    if (m_system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_system_port_base::port_type_e sys_port_type = m_system_port->get_port_type();
    la_slice_id_t slice = m_system_port->get_slice(); // system_port slice

    auto status = handle_punt_inject_over_mac_at_destroy();
    return_on_error(status);

    // destroy m_system_port
    if ((slice != LA_SLICE_ID_INVALID) && (sys_port_type != la_system_port_base::port_type_e::REMOTE)) {
        // Remove source PIF entry
        status = erase_slice_source_pif_entry(slice);
        return_on_error(status);

        la_system_port_base::port_type_e sys_port_type = m_system_port->get_port_type();

        if (sys_port_type == la_system_port_base::port_type_e::PCI) {
            la_mac_addr_t mac_addr = {.flat = 0};
            status = m_device->set_network_interface_mac_addr(slice, mac_addr);
            return_on_error(status);
        }
    }

    // Remove object dependencies
    m_device->remove_object_dependency(m_system_port, this);
    m_system_port = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_punt_inject_port_base::get_mac(la_mac_addr_t& out_mac_addr) const
{
    out_mac_addr.flat = m_mac_addr.flat;
    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_punt_inject_port_base::type() const
{
    return object_type_e::PUNT_INJECT_PORT;
}

const la_device*
la_punt_inject_port_base::get_device() const
{
    return m_device.get();
}

std::string
la_punt_inject_port_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_punt_inject_port_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_punt_inject_port_base::oid() const
{
    return m_oid;
}

const la_system_port*
la_punt_inject_port_base::get_system_port() const
{
    return m_system_port.get();
}

la_status
la_punt_inject_port_base::erase_slice_source_pif_entry(la_slice_id_t slice)
{
    if (m_system_port != nullptr) {
        la_status status = m_system_port->erase_source_pif_table_entries();

        return status;
    }

    return LA_STATUS_EUNKNOWN;
}

} // namespace silicon_one
