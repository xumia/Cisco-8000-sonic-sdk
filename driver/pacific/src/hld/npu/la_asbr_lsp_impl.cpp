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

#include "la_asbr_lsp_impl.h"
#include "la_ecmp_group_impl.h"
#include "la_l3_protection_group_impl.h"
#include "nplapi/npl_constants.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_prefix_object_base.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "counter_utils.h"
#include "hld_utils.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_asbr_lsp_impl::la_asbr_lsp_impl(const la_device_impl_wptr& device)
    : m_device(device), m_asbr(nullptr), m_destination(nullptr), m_primary_nh(nullptr), m_backup_nh(nullptr)
{
}

la_asbr_lsp_impl::~la_asbr_lsp_impl()
{
}

const la_device*
la_asbr_lsp_impl::get_device() const
{
    return m_device.get();
}

la_object::object_type_e
la_asbr_lsp_impl::type() const
{
    return la_object::object_type_e::ASBR_LSP;
}

std::string
la_asbr_lsp_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_asbr_lsp_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_asbr_lsp_impl::oid() const
{
    return m_oid;
}

const la_prefix_object*
la_asbr_lsp_impl::get_asbr() const
{
    return m_asbr.get();
}

const la_l3_destination*
la_asbr_lsp_impl::get_destination() const
{
    return m_destination.get();
}

la_l3_destination_gid_t
la_asbr_lsp_impl::get_asbr_gid() const
{
    return m_asbr->get_gid();
}

destination_id
la_asbr_lsp_impl::get_destination_id(resolution_step_e prev_step) const
{
    return silicon_one::get_destination_id(m_destination, prev_step);
}

la_status
la_asbr_lsp_impl::check_asbr_and_destination(const la_prefix_object_wcptr& asbr, const la_l3_destination_wcptr& destination)
{
    la_object::object_type_e dest_type = destination->type();
    if (!((dest_type == object_type_e::NEXT_HOP) || (dest_type == object_type_e::L3_PROTECTION_GROUP))) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_l3_destination_gid_t asbr_gid = asbr->get_gid();
    if (asbr_gid >= la_device_impl::MAX_ASBR_GID) {
        return LA_STATUS_EINVAL;
    }

    if (dest_type == la_object::object_type_e::NEXT_HOP) {
        auto next_hop = destination.weak_ptr_static_cast<const la_next_hop_base>();
        la_next_hop_gid_t nh_gid = next_hop->get_gid();
        if (nh_gid >= la_device_impl::MAX_ASBR_LSP_DESTINATION_GID) {
            return LA_STATUS_EINVAL;
        }
    }

    if (dest_type == la_object::object_type_e::L3_PROTECTION_GROUP) {
        const auto l3_protection_group = destination.weak_ptr_static_cast<const la_l3_protection_group_impl>();
        la_l3_protection_group_gid_t p_nh_gid = l3_protection_group->get_gid();
        if (p_nh_gid >= la_device_impl::MAX_ASBR_LSP_DESTINATION_GID) {
            return LA_STATUS_EINVAL;
        }

        const la_l3_destination* l3_destination = nullptr;
        la_status status = l3_protection_group->get_backup_destination(l3_destination);
        return_on_error(status);
        la_object::object_type_e l3_dest_type = l3_destination->type();
        if (l3_dest_type != la_object::object_type_e::NEXT_HOP) {
            return LA_STATUS_ENOTIMPLEMENTED;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_asbr_lsp_impl::initialize(la_object_id_t oid, const la_prefix_object_wcptr& asbr, const la_l3_destination_wcptr& destination)
{
    m_oid = oid;
    m_asbr = asbr;
    m_destination = destination;

    la_status status = check_asbr_and_destination(m_asbr, m_destination);
    return_on_error(status);

    status = notify_asbr_about_lsp_destination(m_asbr, m_destination, true);
    return_on_error(status);

    add_dependency(m_asbr, m_destination);

    return LA_STATUS_SUCCESS;
}

la_status
la_asbr_lsp_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    remove_dependency(m_asbr, m_destination);

    la_status status = notify_asbr_about_lsp_destination(m_asbr, m_destination, false);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

void
la_asbr_lsp_impl::add_dependency(const la_prefix_object_wcptr& asbr, const la_l3_destination_wcptr& destination)
{
    m_device->add_object_dependency(asbr, this);
    m_device->add_object_dependency(destination, this);
    register_attribute_dependency(destination);
}

void
la_asbr_lsp_impl::remove_dependency(const la_prefix_object_wcptr& asbr, const la_l3_destination_wcptr& destination)
{
    deregister_attribute_dependency(destination);
    m_device->remove_object_dependency(destination, this);
    m_device->remove_object_dependency(asbr, this);
}

la_status
la_asbr_lsp_impl::set_destination(const la_l3_destination* destination)
{
    start_api_call("destination=", destination);

    la_l3_destination_wcptr destination_sp = m_device->get_sptr<const la_l3_destination>(destination);

    if (m_destination == destination_sp) {
        return LA_STATUS_SUCCESS;
    }

    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(destination_sp, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    transaction txn;

    la_l3_destination_wcptr old_destination = m_destination;

    txn.status = check_asbr_and_destination(m_asbr, destination_sp);
    return_on_error(txn.status);

    txn.status = m_device->check_asbr_lsps(m_asbr, destination_sp);
    if (txn.status == LA_STATUS_EEXIST) {
        return txn.status;
    }

    txn.status = m_device->update_asbr_lsp(m_asbr, destination_sp, m_device->get_sptr(this));
    return_on_error(txn.status);
    txn.on_fail([&]() { m_device->clear_asbr_lsp(m_asbr, destination_sp); });

    m_destination = destination_sp;

    txn.status = notify_asbr_about_lsp_destination(m_asbr, destination_sp, true);
    return_on_error(txn.status);
    txn.on_fail([&]() { notify_asbr_about_lsp_destination(m_asbr, destination_sp, false); });

    attribute_management_details amd;
    amd.op = attribute_management_op::ASBR_LSP_PROPERTY_CHANGED;
    amd.l3_dest = this;
    la_amd_undo_callback_funct_t undo = [this, old_destination](attribute_management_details amd) {
        m_destination = old_destination;
        return amd;
    };
    txn.status = m_device->notify_attribute_changed(this, amd, undo);
    return_on_error(txn.status);

    txn.status = m_device->clear_asbr_lsp(m_asbr, old_destination);
    return_on_error(txn.status);
    txn.on_fail([&]() { m_device->update_asbr_lsp(m_asbr, old_destination, m_device->get_sptr(this)); });

    txn.status = notify_asbr_about_lsp_destination(m_asbr, old_destination, false);
    return_on_error(txn.status);
    txn.on_fail([&]() { notify_asbr_about_lsp_destination(m_asbr, old_destination, true); });

    deregister_attribute_dependency(old_destination);
    m_device->remove_object_dependency(old_destination, this);
    m_device->add_object_dependency(destination_sp, this);
    register_attribute_dependency(destination_sp);

    return LA_STATUS_SUCCESS;
}

la_status
la_asbr_lsp_impl::set_asbr(const la_prefix_object* asbr)
{
    start_api_call("asbr=", asbr);

    la_prefix_object_wcptr asbr_sp = m_device->get_sptr<const la_prefix_object>(asbr);

    if (m_asbr == asbr_sp) {
        return LA_STATUS_SUCCESS;
    }

    if (asbr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(asbr_sp, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    transaction txn;
    txn.status = check_asbr_and_destination(asbr_sp, m_destination);
    return_on_error(txn.status);

    txn.status = m_device->check_asbr_lsps(asbr_sp, m_destination);
    if (txn.status == LA_STATUS_EEXIST) {
        return txn.status;
    }

    txn.status = m_device->update_asbr_lsp(asbr_sp, m_destination, m_device->get_sptr(this));
    return_on_error(txn.status);
    txn.on_fail([&]() { m_device->clear_asbr_lsp(asbr_sp, m_destination); });

    la_prefix_object_wcptr old_asbr = m_asbr;

    m_asbr = asbr_sp;

    txn.status = notify_asbr_about_lsp_destination(asbr_sp, m_destination, true);
    return_on_error(txn.status);
    txn.on_fail([&]() { notify_asbr_about_lsp_destination(asbr_sp, m_destination, false); });

    attribute_management_details amd;
    amd.op = attribute_management_op::ASBR_LSP_PROPERTY_CHANGED;
    amd.l3_dest = this;
    la_amd_undo_callback_funct_t undo = [this, old_asbr](attribute_management_details amd) {
        m_asbr = old_asbr;
        return amd;
    };

    txn.status = m_device->notify_attribute_changed(this, amd, undo);
    return_on_error(txn.status);

    txn.status = m_device->clear_asbr_lsp(old_asbr, m_destination);
    return_on_error(txn.status);
    txn.on_fail([&]() { m_device->update_asbr_lsp(old_asbr, m_destination, m_device->get_sptr(this)); });

    txn.status = notify_asbr_about_lsp_destination(old_asbr, m_destination, false);
    return_on_error(txn.status);
    txn.on_fail([&]() { notify_asbr_about_lsp_destination(old_asbr, m_destination, true); });

    m_device->remove_object_dependency(old_asbr, this);
    m_device->add_object_dependency(asbr_sp, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_asbr_lsp_impl::get_l3_protection_group_destinations(const la_l3_destination_wcptr& destination,
                                                       la_next_hop_wcptr& primary_nh,
                                                       la_next_hop_wcptr& backup_nh)
{
    la_object::object_type_e dest_type = destination->type();
    if (dest_type != object_type_e::L3_PROTECTION_GROUP) {
        primary_nh.reset();
        backup_nh.reset();
        return LA_STATUS_SUCCESS;
    }

    const auto l3_prot_group = destination.weak_ptr_static_cast<const la_l3_protection_group>();
    const la_l3_destination* l3_prot_group_destination;
    la_status status = l3_prot_group->get_primary_destination(l3_prot_group_destination);

    return_on_error(status);

    primary_nh = m_device->get_sptr<la_next_hop>(l3_prot_group_destination);
    status = l3_prot_group->get_backup_destination(l3_prot_group_destination);
    return_on_error(status);

    backup_nh = m_device->get_sptr<la_next_hop>(l3_prot_group_destination);
    return LA_STATUS_SUCCESS;
}

la_status
la_asbr_lsp_impl::notify_asbr_about_lsp_destination(const la_prefix_object_wcptr& asbr,
                                                    const la_l3_destination_wcptr& l3_dest,
                                                    bool is_add)
{
    la_object::object_type_e dest_type = l3_dest->type();

    if (dest_type == object_type_e::NEXT_HOP) {
        la_next_hop_wcptr nh = l3_dest.weak_ptr_static_cast<const la_next_hop>();
        la_status status = notify_asbr_about_lsp_next_hop(asbr, nh, is_add);
        return_on_error(status);

        return LA_STATUS_SUCCESS;
    }

    la_next_hop_wcptr primary_nh;
    la_next_hop_wcptr backup_nh;
    la_status status = get_l3_protection_group_destinations(l3_dest, primary_nh, backup_nh);
    return_on_error(status);

    status = notify_asbr_about_lsp_next_hop(asbr, primary_nh, is_add);
    return_on_error(status);

    status = notify_asbr_about_lsp_next_hop(asbr, backup_nh, is_add);
    return_on_error(status);

    if (is_add) {
        m_primary_nh = primary_nh;
        m_backup_nh = backup_nh;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_asbr_lsp_impl::notify_asbr_about_lsp_next_hop(const la_prefix_object_wcptr& asbr, const la_next_hop_wcptr& next_hop, bool is_add)
{
    const auto asbr_impl = asbr.weak_ptr_static_cast<const la_prefix_object_base>().weak_ptr_const_cast<la_prefix_object_base>();

    la_status status;
    if (is_add) {
        status = asbr_impl->register_asbr_lsp_next_hop(next_hop);
    } else {
        status = asbr_impl->deregister_asbr_lsp_next_hop(next_hop);
    }

    return status;
}

void
la_asbr_lsp_impl::register_attribute_dependency(const la_l3_destination_wcptr& destination)
{
    object_type_e type = destination->type();
    if (type == object_type_e::L3_PROTECTION_GROUP) {
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::L3_PROT_GROUP_DESTINATION_CHANGED);
        m_device->add_attribute_dependency(destination, this, registered_attributes);
    }
}

void
la_asbr_lsp_impl::deregister_attribute_dependency(const la_l3_destination_wcptr& destination)
{
    object_type_e type = destination->type();
    if (type == object_type_e::L3_PROTECTION_GROUP) {
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::L3_PROT_GROUP_DESTINATION_CHANGED);
        m_device->remove_attribute_dependency(destination, this, registered_attributes);
    }
}

la_status
la_asbr_lsp_impl::update_dependent_attributes(dependency_management_op op)
{
    switch (op.action.attribute_management.op) {
    case (attribute_management_op::L3_PROT_GROUP_DESTINATION_CHANGED): {
        la_next_hop_wcptr old_primary_nh = m_primary_nh;
        la_next_hop_wcptr old_backup_nh = m_backup_nh;
        la_status status = notify_asbr_about_lsp_destination(
            m_asbr, m_device->get_sptr<const la_l3_destination>(op.action.attribute_management.l3_dest), true);
        return_on_error(status);

        status = notify_asbr_about_lsp_next_hop(m_asbr, old_primary_nh, false);
        return_on_error(status);

        status = notify_asbr_about_lsp_next_hop(m_asbr, old_backup_nh, false);
        return_on_error(status);

    } break;
    default:
        return LA_STATUS_EUNKNOWN;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_asbr_lsp_impl::notify_change(dependency_management_op op)
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
la_asbr_lsp_impl::instantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_asbr_lsp_impl::uninstantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
