// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include <sstream>

#include "la_multicast_protection_group_base.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "system/la_spa_port_base.h"

namespace silicon_one
{

la_multicast_protection_group_base::la_multicast_protection_group_base(const la_device_impl_wptr& device) : m_device(device)
{
}

la_multicast_protection_group_base::~la_multicast_protection_group_base()
{
}

la_status
la_multicast_protection_group_base::initialize(la_object_id_t oid,
                                               const la_next_hop_wptr& primary_destination,
                                               const la_system_port_wptr& primary_system_port,
                                               const la_next_hop_wptr& backup_destination,
                                               const la_system_port_wptr& backup_system_port,
                                               const la_multicast_protection_monitor_wptr& protection_monitor)
{
    m_oid = oid;

    la_status status
        = verify_parameters(primary_destination, primary_system_port, backup_destination, backup_system_port, protection_monitor);
    return_on_error(status);

    m_primary_dest = primary_destination;
    m_primary_sys_port = primary_system_port;
    m_backup_dest = backup_destination;
    m_backup_sys_port = backup_system_port;
    m_monitor = protection_monitor;

    m_device->add_object_dependency(m_primary_dest, this);
    m_device->add_object_dependency(m_monitor, this);

    if (m_primary_sys_port != nullptr) {
        m_device->add_object_dependency(m_primary_sys_port, this);
    }

    if (m_backup_dest != nullptr && m_backup_sys_port != nullptr) {
        m_device->add_object_dependency(m_backup_dest, this);
        m_device->add_object_dependency(m_backup_sys_port, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_protection_group_base::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    m_device->remove_object_dependency(m_primary_dest, this);
    m_device->remove_object_dependency(m_monitor, this);

    if (m_primary_sys_port) {
        m_device->remove_object_dependency(m_primary_sys_port, this);
    }

    if (m_backup_dest) {
        m_device->remove_object_dependency(m_backup_dest, this);
    }

    if (m_backup_sys_port) {
        m_device->remove_object_dependency(m_backup_sys_port, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_protection_group_base::verify_parameters(const la_next_hop_wcptr& primary_dest,
                                                      const la_system_port_wcptr& primary_sys_port,
                                                      const la_next_hop_wcptr& backup_dest,
                                                      const la_system_port_wcptr& backup_sys_port,
                                                      const la_multicast_protection_monitor_wcptr& monitor) const
{
    if (monitor == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(monitor, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // We don't support primary/backup paths being part of the same SPA
    if (primary_dest == backup_dest) {
        return LA_STATUS_EINVAL;
    }

    la_status status = check_destination(primary_dest, primary_sys_port);
    return_on_error(status);

    // Backup destination can be null...
    if (backup_dest != nullptr) {
        status = check_destination(backup_dest, backup_sys_port);
        return_on_error(status);
    }

    /// ...but if it is, the associated system port should be as well
    if (backup_dest == nullptr && backup_sys_port != nullptr) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_protection_group_base::check_destination(const la_next_hop_wcptr& destination,
                                                      const la_system_port_wcptr& sys_port) const
{
    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_next_hop::nh_type_e nh_type;
    la_status status = destination->get_nh_type(nh_type);
    return_on_error(status);

    // Support non-normal NH types. They are treated as no-op in MCG.
    // Require that system port associated with DROP/GLEAN NH be null.
    if (nh_type != la_next_hop::nh_type_e::NORMAL) {
        if (sys_port != nullptr) {
            return LA_STATUS_EINVAL;
        }
        return LA_STATUS_SUCCESS;
    }

    if (sys_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(sys_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Check to see that system port belongs to NH L3-AC
    la_l3_port* port;
    status = destination->get_router_port(port);
    return_on_error(status);

    if (port == nullptr || port->type() != object_type_e::L3_AC_PORT) {
        return LA_STATUS_EINVAL;
    }

    const auto& l3_ac_port = m_device->get_sptr<la_l3_ac_port_impl>(port);
    const auto& eth_port = m_device->get_sptr<const la_ethernet_port_base>(l3_ac_port->get_ethernet_port());

    const auto& port_sys_port = m_device->get_sptr(eth_port->get_system_port());
    if (port_sys_port == nullptr) {
        const auto& spa_port = m_device->get_sptr<const la_spa_port_base>(eth_port->get_spa_port());
        if (!spa_port->is_member(sys_port)) {
            return LA_STATUS_EINVAL;
        }
    } else {
        if (port_sys_port != sys_port) {
            return LA_STATUS_EINVAL;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_multicast_protection_group_base::type() const
{
    return la_object::object_type_e::MULTICAST_PROTECTION_GROUP;
}

std::string
la_multicast_protection_group_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_multicast_protection_group_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_multicast_protection_group_base::oid() const
{
    return m_oid;
}

const la_device*
la_multicast_protection_group_base::get_device() const
{
    return m_device.get();
}

la_status
la_multicast_protection_group_base::get_monitor(const la_multicast_protection_monitor*& out_protection_monitor) const
{
    start_api_getter_call();

    out_protection_monitor = m_monitor.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_protection_group_base::get_primary_destination(const la_next_hop*& out_next_hop,
                                                            const la_system_port*& out_system_port) const
{
    start_api_getter_call();

    out_next_hop = m_primary_dest.get();
    out_system_port = m_primary_sys_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_protection_group_base::get_backup_destination(const la_next_hop*& out_next_hop,
                                                           const la_system_port*& out_system_port) const
{
    start_api_getter_call();

    out_next_hop = m_backup_dest.get();
    out_system_port = m_backup_sys_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_protection_group_base::modify_protection_group(const la_next_hop* primary_destination,
                                                            const la_system_port* primary_system_port,
                                                            const la_next_hop* backup_destination,
                                                            const la_system_port* backup_system_port,
                                                            const la_multicast_protection_monitor* protection_monitor)
{
    start_api_call("primary_destination=",
                   primary_destination,
                   "primary_system_port=",
                   primary_system_port,
                   "backup_destination=",
                   backup_destination,
                   "backup_system_port=",
                   backup_system_port,
                   "protection_monitor=",
                   protection_monitor);

    const auto& primary_destination_sptr = m_device->get_sptr(primary_destination);
    const auto& primary_system_port_sptr = m_device->get_sptr(primary_system_port);
    const auto& backup_destination_sptr = m_device->get_sptr(backup_destination);
    const auto& backup_system_port_sptr = m_device->get_sptr(backup_system_port);
    const auto& protection_monitor_sptr = m_device->get_sptr(protection_monitor);

    la_status status = verify_parameters(primary_destination_sptr,
                                         primary_system_port_sptr,
                                         backup_destination_sptr,
                                         backup_system_port_sptr,
                                         protection_monitor_sptr);
    return_on_error(status);

    attribute_management_details amd;
    amd.op = attribute_management_op::MULTICAST_PROTECTION_GROUP_CHANGED;
    amd.mcg_change.primary_dest = primary_destination_sptr.get();
    amd.mcg_change.primary_sys_port = primary_system_port_sptr.get();
    amd.mcg_change.backup_dest = backup_destination_sptr.get();
    amd.mcg_change.backup_sys_port = backup_system_port_sptr.get();
    amd.mcg_change.monitor = protection_monitor_sptr.get();
    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) { return amd; };

    status = m_device->notify_attribute_changed(this, amd, undo);
    return_on_error(status);

    if (m_primary_dest != primary_destination_sptr) {
        m_device->remove_object_dependency(m_primary_dest, this);
        m_primary_dest = primary_destination_sptr;
        m_device->add_object_dependency(m_primary_dest, this);
    }

    if (m_backup_dest != backup_destination_sptr) {
        // Null check is only needed for backup dest/sys port, as primary must be non-null
        if (m_backup_dest != nullptr) {
            m_device->remove_object_dependency(m_backup_dest, this);
        }
        m_backup_dest = backup_destination_sptr;
        if (m_backup_dest != nullptr) {
            m_device->add_object_dependency(m_backup_dest, this);
        }
    }

    if (m_primary_sys_port != primary_system_port_sptr) {
        if (m_primary_sys_port != nullptr) {
            m_device->remove_object_dependency(m_primary_sys_port, this);
        }
        m_primary_sys_port = primary_system_port_sptr;
        if (m_primary_sys_port != nullptr) {
            m_device->add_object_dependency(m_primary_sys_port, this);
        }
    }

    if (m_backup_sys_port != backup_system_port_sptr) {
        if (m_backup_sys_port != nullptr) {
            m_device->remove_object_dependency(m_backup_sys_port, this);
        }
        m_backup_sys_port = backup_system_port_sptr;
        if (m_backup_sys_port != nullptr) {
            m_device->add_object_dependency(m_backup_sys_port, this);
        }
    }

    if (m_monitor != protection_monitor_sptr) {
        m_device->remove_object_dependency(m_monitor, this);
        m_monitor = protection_monitor_sptr;
        m_device->add_object_dependency(m_monitor, this);
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
