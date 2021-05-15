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

#include "la_punt_inject_port_pacgb.h"
#include "la_system_port_pacgb.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_punt_inject_port_pacgb::la_punt_inject_port_pacgb(const la_device_impl_wptr& device) : la_punt_inject_port_base(device)
{
}

la_punt_inject_port_pacgb::~la_punt_inject_port_pacgb()
{
}

la_status
la_punt_inject_port_pacgb::handle_punt_inject_over_mac_at_init()
{
    la_system_port_base::port_type_e sys_port_type = m_system_port->get_port_type();

    if (sys_port_type == la_system_port_base::port_type_e::MAC) {
        m_system_recycle_port = m_device->allocate_punt_recycle_port(m_system_port);
        if (m_system_recycle_port == nullptr) {
            log_err(HLD, "Requires a recycle port. Recycle port was not found");
            return LA_STATUS_ENOTFOUND;
        }

        auto pacgb_sysport = m_system_port.weak_ptr_static_cast<la_system_port_pacgb>();
        auto status = pacgb_sysport->do_set_slice_rx_obm_code(m_system_recycle_port);
        m_device->add_object_dependency(m_system_recycle_port, this); // add obj dependency

        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_punt_inject_port_pacgb::handle_punt_inject_over_mac_at_destroy()
{
    if (m_system_recycle_port != nullptr) {
        // erase from obm_code table
        auto pacgb_sysport = m_system_port.weak_ptr_static_cast<la_system_port_pacgb>();
        auto status = pacgb_sysport->do_erase_slice_rx_obm_code(m_system_recycle_port);
        return_on_error(status);

        m_device->release_punt_recycle_port(m_system_recycle_port);

        m_device->remove_object_dependency(m_system_recycle_port, this);
        m_system_recycle_port = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

slice_ifg_vec_t
la_punt_inject_port_pacgb::get_ifgs() const
{
    slice_ifg_vec_t slice_ifg_vec;

    auto actual_dsp = get_actual_dsp(m_system_port);
    la_slice_ifg sp_slice_ifg = {.slice = actual_dsp->get_slice(), .ifg = actual_dsp->get_ifg()};
    slice_ifg_vec.push_back(sp_slice_ifg);

    if (m_system_recycle_port != nullptr) {
        // counters that use this function need both ifgs, one for rx_redirect table and the other for obm table
        la_slice_ifg rcy_slice_ifg = {.slice = m_system_recycle_port->get_slice(), .ifg = m_system_recycle_port->get_ifg()};
        if ((rcy_slice_ifg.slice != sp_slice_ifg.slice) || (rcy_slice_ifg.ifg != sp_slice_ifg.ifg)) {
            slice_ifg_vec.push_back(rcy_slice_ifg);
        }
    }

    return slice_ifg_vec;
}

destination_id
la_punt_inject_port_pacgb::get_destination_id(resolution_step_e prev_step) const
{
    if (m_system_port != nullptr) {
        la_system_port_base::port_type_e sys_port_type = m_system_port->get_port_type();
        if (sys_port_type == la_system_port_base::port_type_e::MAC) {
            return silicon_one::get_destination_id(m_system_recycle_port, prev_step);
        }
        return silicon_one::get_destination_id(m_system_port.get(), prev_step);
    } else {
        return DESTINATION_ID_INVALID;
    }
}

la_system_port_wcptr
la_punt_inject_port_pacgb::get_actual_system_port() const
{
    if (m_system_recycle_port) {
        return m_system_recycle_port;
    }

    return get_actual_dsp(m_system_port);
}

} // namespace silicon_one
