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

#include "la_l3_protection_group_impl.h"
#include "la_te_tunnel_impl.h"
#include "nplapi/npl_constants.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_protection_monitor_impl.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_l3_protection_group_impl::la_l3_protection_group_impl(const la_device_impl_wptr& device)
    : m_device(device),
      m_gid(LA_L3_PROTECTION_GROUP_GID_INVALID),
      m_primary_destination(nullptr),
      m_backup_destination(nullptr),
      m_protection_monitor(nullptr)
{
}

la_l3_protection_group_impl::~la_l3_protection_group_impl()
{
}

la_status
la_l3_protection_group_impl::check_destination(la_l3_protection_group_gid_t group_gid,
                                               const la_l3_destination_wcptr& primary_destination,
                                               const la_l3_destination_wcptr& backup_destination,
                                               const la_protection_monitor_wcptr& protection_monitor) const
{
    if (primary_destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (backup_destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (protection_monitor == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(primary_destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!of_same_device(backup_destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!of_same_device(protection_monitor, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (primary_destination->type() != object_type_e::NEXT_HOP) {
        return LA_STATUS_EINVAL;
    }

    if (!((backup_destination->type() == object_type_e::NEXT_HOP) || (backup_destination->type() == object_type_e::TE_TUNNEL))) {
        return LA_STATUS_EINVAL;
    }

    if (backup_destination->type() == object_type_e::TE_TUNNEL) {
        std::vector<la_object*> deps = m_device->get_dependent_objects(this);
        for (auto objp : deps) {
            if (objp->type() == object_type_e::ASBR_LSP) {
                return LA_STATUS_EINVAL;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_protection_group_impl::initialize(la_object_id_t oid,
                                        la_l3_protection_group_gid_t group_gid,
                                        const la_l3_destination_wcptr& primary_destination,
                                        const la_l3_destination_wcptr& backup_destination,
                                        const la_protection_monitor_wcptr& protection_monitor)
{
    m_oid = oid;
    la_status status = check_destination(group_gid, primary_destination, backup_destination, protection_monitor);
    return_on_error(status);

    status = instantiate_resolution_object(protection_monitor, RESOLUTION_STEP_STAGE1_PROTECTION);
    return_on_error(status);

    status = instantiate_resolution_object(primary_destination, RESOLUTION_STEP_STAGE1_PROTECTION);
    return_on_error(status);

    status = instantiate_resolution_object(backup_destination, RESOLUTION_STEP_STAGE1_PROTECTION);
    return_on_error(status);

    // Store parameters
    m_gid = group_gid;
    m_primary_destination = primary_destination;
    m_backup_destination = backup_destination;
    m_protection_monitor = protection_monitor;

    status = configure_resolution_step();
    return_on_error(status);

    // Set object dependencies
    m_device->add_object_dependency(primary_destination, this);
    add_dependency(backup_destination);
    m_device->add_object_dependency(protection_monitor, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_protection_group_impl::configure_resolution_step()
{
    la_status status;
    npl_resolution_stage_assoc_data_wide_protection_record_t protection_record{};
    npl_wide_protection_entry_t& primary_entry(protection_record.primary_entry);
    npl_wide_protection_entry_t& protecting_entry(protection_record.protect_entry);

    status = get_stage1_table_protection_member_entry(m_primary_destination, primary_entry);
    return_on_error(status);

    status = get_stage1_table_protection_member_entry(m_backup_destination, protecting_entry);
    return_on_error(status);

    la_protection_monitor_impl_wcptr protection_monitor_impl
        = m_protection_monitor.weak_ptr_static_cast<const la_protection_monitor_impl>();
    protection_record.id = protection_monitor_impl->get_gid();
    protection_record.path = NPL_PROTECTION_SELECTOR_PRIMARY;

    // Write to table
    destination_id dest = get_destination_id(RESOLUTION_STEP_FORWARD_MPLS);
    status = m_device->m_resolution_configurators[1].configure_dest_map_entry(dest, protection_record, m_res_cfg_handle);

    return status;
}

la_status
la_l3_protection_group_impl::get_resolution_cfg_handle(const resolution_cfg_handle_t*& out_cfg_handle) const
{
    out_cfg_handle = &m_res_cfg_handle;
    return LA_STATUS_SUCCESS;
}

la_status
la_l3_protection_group_impl::get_stage1_table_protection_member_entry(const la_l3_destination_wcptr& protection_member_dest,
                                                                      npl_wide_protection_entry_t& entry)
{
    object_type_e type = protection_member_dest->type();

    if (type == object_type_e::NEXT_HOP) {
        la_next_hop_base_wcptr protection_member_nh = protection_member_dest.weak_ptr_static_cast<const la_next_hop_base>();
        npl_stage1_p_l3_nh_destination_with_common_data_t& p_l3_nh_dest(entry.stage1_nh_dest);

        p_l3_nh_dest.destination = protection_member_nh->get_destination_id(RESOLUTION_STEP_STAGE1_PROTECTION).val;
        p_l3_nh_dest.type = NPL_ENTRY_TYPE_STAGE1_P_L3_NH_DESTINATION_WITH_COMMON_DATA;
        return LA_STATUS_SUCCESS;
    }

    if (type == object_type_e::TE_TUNNEL) {
        la_te_tunnel_impl_wcptr te_tunnel_impl = protection_member_dest.weak_ptr_static_cast<const la_te_tunnel_impl>();
        npl_stage1_l3_nh_te_tunnel16b1_t& l3_nh_te_tunnel16b1(entry.stage1_te_tunnel);

        l3_nh_te_tunnel16b1.l3_nh = te_tunnel_impl->get_destination_id(RESOLUTION_STEP_STAGE1_PROTECTION).val;
        l3_nh_te_tunnel16b1.te_tunnel16b = te_tunnel_impl->get_gid();
        l3_nh_te_tunnel16b1.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_ILM_TUNNEL;
        l3_nh_te_tunnel16b1.type = NPL_ENTRY_TYPE_STAGE1_L3_NH_TE_TUNNEL16B1;
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l3_protection_group_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    remove_dependency(m_backup_destination);
    m_device->remove_object_dependency(m_primary_destination, this);
    m_device->remove_object_dependency(m_protection_monitor, this);

    la_status status = teardown_resolution_step();
    return_on_error(status);

    status = uninstantiate_resolution_object(m_backup_destination, RESOLUTION_STEP_STAGE1_PROTECTION);
    return_on_error(status);

    status = uninstantiate_resolution_object(m_primary_destination, RESOLUTION_STEP_STAGE1_PROTECTION);
    return_on_error(status);

    status = uninstantiate_resolution_object(m_protection_monitor, RESOLUTION_STEP_STAGE1_PROTECTION);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_protection_group_impl::teardown_resolution_step()
{
    return m_device->m_resolution_configurators[1].unconfigure_entry(m_res_cfg_handle);
}

la_l3_protection_group_gid_t
la_l3_protection_group_impl::get_gid() const
{
    return m_gid;
}

resolution_step_e
la_l3_protection_group_impl::get_next_resolution_step(resolution_step_e prev_step) const
{
    if ((prev_step == RESOLUTION_STEP_FEC) || (prev_step == RESOLUTION_STEP_STAGE0_ECMP)
        || (prev_step == RESOLUTION_STEP_STAGE0_CE_PTR)
        || (prev_step == RESOLUTION_STEP_FORWARD_MPLS)
        || (prev_step == RESOLUTION_STEP_STAGE1_ECMP)) {
        return RESOLUTION_STEP_STAGE1_PROTECTION;
    }

    return RESOLUTION_STEP_INVALID;
}

destination_id
la_l3_protection_group_impl::get_destination_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_STAGE1_PROTECTION: {
        return destination_id(NPL_DESTINATION_MASK_P_L3_NH | m_gid);
    }

    default: {
        return DESTINATION_ID_INVALID;
    }
    }
}

la_status
la_l3_protection_group_impl::get_primary_destination(const la_l3_destination*& out_l3_destination) const
{
    out_l3_destination = m_primary_destination.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_l3_protection_group_impl::get_backup_destination(const la_l3_destination*& out_l3_destination) const
{
    out_l3_destination = m_backup_destination.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_l3_protection_group_impl::modify_protection_group(const la_l3_destination* primary_destination,
                                                     const la_l3_destination* backup_destination,
                                                     const la_protection_monitor* protection_monitor)
{
    start_api_call("primary_destination=",
                   primary_destination,
                   "backup_destination=",
                   backup_destination,
                   "protection_monitor=",
                   protection_monitor);

    const auto primary_destination_sp = m_device->get_sptr(primary_destination);
    const auto backup_destination_sp = m_device->get_sptr(backup_destination);
    const auto protection_monitor_sp = m_device->get_sptr(protection_monitor);

    la_status status = check_destination(m_gid, primary_destination_sp, backup_destination_sp, protection_monitor_sp);
    return_on_error(status);

    status = instantiate_resolution_object(protection_monitor_sp, RESOLUTION_STEP_STAGE1_PROTECTION);
    return_on_error(status);

    status = instantiate_resolution_object(primary_destination_sp, RESOLUTION_STEP_STAGE1_PROTECTION);
    return_on_error(status);

    status = instantiate_resolution_object(backup_destination_sp, RESOLUTION_STEP_STAGE1_PROTECTION);
    return_on_error(status);

    auto old_primary_destination = m_primary_destination;
    auto old_backup_destination = m_backup_destination;
    auto old_protection_monitor = m_protection_monitor;
    m_primary_destination = primary_destination_sp;
    m_backup_destination = backup_destination_sp;
    m_protection_monitor = protection_monitor_sp;

    status = configure_resolution_step();
    return_on_error(status);

    attribute_management_details amd;
    amd.op = attribute_management_op::L3_PROT_GROUP_DESTINATION_CHANGED;
    amd.l3_dest = this;
    la_amd_undo_callback_funct_t undo = [&](attribute_management_details amd) {
        m_primary_destination = old_primary_destination;
        m_backup_destination = old_backup_destination;
        m_protection_monitor = old_protection_monitor;
        status = configure_resolution_step();
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "Error configuring resolution in undo rollback status: %s ", la_status2str(status).c_str());
        }
        return amd;
    };
    status = m_device->notify_attribute_changed(this, amd, undo);
    return_on_error(status);

    status = uninstantiate_resolution_object(old_backup_destination, RESOLUTION_STEP_STAGE1_PROTECTION);
    return_on_error(status);

    status = uninstantiate_resolution_object(old_primary_destination, RESOLUTION_STEP_STAGE1_PROTECTION);
    return_on_error(status);

    status = uninstantiate_resolution_object(old_protection_monitor, RESOLUTION_STEP_STAGE1_PROTECTION);
    return_on_error(status);

    remove_dependency(old_backup_destination);
    m_device->remove_object_dependency(old_primary_destination, this);
    m_device->remove_object_dependency(old_protection_monitor, this);

    m_device->add_object_dependency(protection_monitor_sp, this);
    m_device->add_object_dependency(primary_destination_sp, this);
    add_dependency(backup_destination_sp);
    return LA_STATUS_SUCCESS;
}

void
la_l3_protection_group_impl::add_dependency(const la_l3_destination_wcptr& destination)
{
    m_device->add_object_dependency(destination, this);
    register_attribute_dependency(destination);
}

void
la_l3_protection_group_impl::remove_dependency(const la_l3_destination_wcptr& destination)
{
    deregister_attribute_dependency(destination);
    m_device->remove_object_dependency(destination, this);
}

void
la_l3_protection_group_impl::register_attribute_dependency(const la_l3_destination_wcptr& destination)
{
    bit_vector registered_attributes((la_uint64_t)attribute_management_op::TE_TUNNEL_DESTINATION_CHANGED);
    if (destination->type() == object_type_e::TE_TUNNEL) {
        m_device->add_attribute_dependency(destination, this, registered_attributes);
    }
}

void
la_l3_protection_group_impl::deregister_attribute_dependency(const la_l3_destination_wcptr& destination)
{
    bit_vector registered_attributes((la_uint64_t)attribute_management_op::TE_TUNNEL_DESTINATION_CHANGED);
    if (destination->type() == object_type_e::TE_TUNNEL) {
        m_device->remove_attribute_dependency(destination, this, registered_attributes);
    }
}

la_status
la_l3_protection_group_impl::update_dependent_attributes(dependency_management_op op)
{
    switch (op.action.attribute_management.op) {
    case (attribute_management_op::TE_TUNNEL_DESTINATION_CHANGED): {
        la_status status = configure_resolution_step();
        return_on_error(status);
    } break;
    default:
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_protection_group_impl::notify_change(dependency_management_op op)
{
    switch (op.type_e) {
    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        return update_dependent_attributes(op);
    default:
        log_err(HLD, "received unsupported notification (%s)", silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
la_l3_protection_group_impl::get_monitor(const la_protection_monitor*& out_protection_monitor) const
{
    out_protection_monitor = m_protection_monitor.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l3_protection_group_impl::set_monitor(const la_protection_monitor* protection_monitor)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_object::object_type_e
la_l3_protection_group_impl::type() const
{
    return object_type_e::L3_PROTECTION_GROUP;
}

std::string
la_l3_protection_group_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_l3_protection_group_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_l3_protection_group_impl::oid() const
{
    return m_oid;
}

const la_device*
la_l3_protection_group_impl::get_device() const
{
    return m_device.get();
}

la_status
la_l3_protection_group_impl::instantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_l3_protection_group_impl::uninstantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
