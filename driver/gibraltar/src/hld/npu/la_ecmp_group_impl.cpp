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

#include <algorithm>

#include "api/npu/la_l3_port.h"
#include "api/npu/la_mpls_nhlfe.h"
#include "api/types/la_ip_types.h"
#include "la_asbr_lsp_impl.h"
#include "la_destination_pe_impl.h"
#include "la_ip_tunnel_destination_impl.h"
#include "la_l3_fec_impl.h"
#include "la_l3_protection_group_impl.h"
#include "la_te_tunnel_impl.h"
#include "nplapi/npl_constants.h"
#include "npu/la_ecmp_group_impl.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_prefix_object_base.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"

#include "hld_types.h"
#include "hld_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

using namespace std;
namespace silicon_one
{

la_ecmp_group_impl::la_ecmp_group_impl(const la_device_impl_wptr& device)
    : m_device(device), m_is_ip_tunnel(false), m_is_drop(false)
{
}

la_ecmp_group_impl::~la_ecmp_group_impl()
{
}

la_status
la_ecmp_group_impl::initialize(la_object_id_t oid, level_e level)
{
    m_oid = oid;
    m_level = level;
    m_type = member_type_e::UNKNOWN;

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::destroy()
{
    for (const auto& l3_dest : m_l3_destinations) {
        remove_dependency(l3_dest);
    }

    return LA_STATUS_SUCCESS;
}

void
la_ecmp_group_impl::add_dependency(const la_l3_destination_wcptr& destination)
{
    m_device->add_object_dependency(destination, this);
    register_attribute_dependency(destination);
}

void
la_ecmp_group_impl::remove_dependency(const la_l3_destination_wcptr& destination)
{
    deregister_attribute_dependency(destination);
    m_device->remove_object_dependency(destination, this);
}

void
la_ecmp_group_impl::register_attribute_dependency(const la_l3_destination_wcptr& destination)
{
    object_type_e type = destination->type();
    if (type == object_type_e::TE_TUNNEL) {
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::TE_TUNNEL_DESTINATION_CHANGED);
        m_device->add_attribute_dependency(destination, this, registered_attributes);
    }
    if (type == object_type_e::ASBR_LSP) {
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::ASBR_LSP_PROPERTY_CHANGED);
        m_device->add_attribute_dependency(destination, this, registered_attributes);
    }
}

void
la_ecmp_group_impl::deregister_attribute_dependency(const la_l3_destination_wcptr& destination)
{
    object_type_e type = destination->type();
    if (type == object_type_e::TE_TUNNEL) {
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::TE_TUNNEL_DESTINATION_CHANGED);
        m_device->remove_attribute_dependency(destination, this, registered_attributes);
    }
    if (type == object_type_e::ASBR_LSP) {
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::ASBR_LSP_PROPERTY_CHANGED);
        m_device->remove_attribute_dependency(destination, this, registered_attributes);
    }
}

la_status
la_ecmp_group_impl::update_dependent_attributes(dependency_management_op op)
{
    switch (op.action.attribute_management.op) {
    case (attribute_management_op::TE_TUNNEL_DESTINATION_CHANGED):
    case (attribute_management_op::ASBR_LSP_PROPERTY_CHANGED): {
        resolution_step_e res_step_to_update = RESOLUTION_STEP_STAGE1_ECMP;

        // If ecmp is not in use in resolution step stage1 then nothing to do.
        if (m_resolution_data.users_for_step[res_step_to_update] == 0) {
            return LA_STATUS_SUCCESS;
        }

        for (size_t i = 0; i < m_l3_destinations.size(); i++) {
            const auto& l3_dest = m_l3_destinations[i];

            if (op.action.attribute_management.l3_dest == l3_dest) {
                la_status status = configure_resolution_step_lb_member_at_index(res_step_to_update, l3_dest, i);
                return_on_error(status);
            }
        }
    } break;
    default:
        return LA_STATUS_EUNKNOWN;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::notify_change(dependency_management_op op)
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
la_ecmp_group_impl::add_member(la_l3_destination* l3_destination)
{
    start_api_call("l3_destination=", l3_destination);

    if (l3_destination == nullptr) {
        log_err(HLD, "l3_destination is nullptr, returning EINVAL.");
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(l3_destination, this)) {
        log_err(HLD,
                "objects %s and %s are on different devices (%d, %d)",
                silicon_one::to_string(l3_destination).c_str(),
                silicon_one::to_string(this).c_str(),
                l3_destination->get_device()->get_id(),
                m_device->get_id());
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    object_type_e type = l3_destination->type();

    if (m_level == level_e::LEVEL_2) {
        if (!((type == object_type_e::NEXT_HOP) || (type == object_type_e::L3_PROTECTION_GROUP) || (type == object_type_e::ASBR_LSP)
              || (type == object_type_e::TE_TUNNEL))) {
            log_err(HLD, "NH's, L3 Protection groups and TE_tunnel's are the only valid destinations for a Level 2 ECMP.");
            return LA_STATUS_EINVAL;
        }
    }

    if (m_level == level_e::LEVEL_1) {
        if (!((type == object_type_e::NEXT_HOP) || (type == object_type_e::ECMP_GROUP) || (type == object_type_e::PREFIX_OBJECT)
              || (type == object_type_e::DESTINATION_PE)
              || (type == object_type_e::IP_TUNNEL_DESTINATION))) {
            return LA_STATUS_EINVAL;
        }
    }

    if (type == object_type_e::ECMP_GROUP) {
        const la_ecmp_group_impl* ecmp_group = static_cast<const la_ecmp_group_impl*>(l3_destination);
        if (ecmp_group->get_ecmp_level() != level_e::LEVEL_2) {
            log_err(HLD, "If destination is an ECMP group, it has to be a LEVEL 2 ECMP group.");
            return LA_STATUS_EINVAL;
        }
    }

    if (type == object_type_e::PREFIX_OBJECT) {
        const la_prefix_object_base* pfx_obj = static_cast<const la_prefix_object_base*>(l3_destination);
        if (!pfx_obj->is_resolution_forwarding_supported()) {
            log_err(HLD, "If destination is a global prefix object, its destination must be an ECMP group.");
            return LA_STATUS_EINVAL;
        }
    }

    if ((m_level == level_e::LEVEL_2) && (type != object_type_e::ASBR_LSP)) {
        for (const auto& l3_dest : m_l3_destinations) {
            object_type_e member_type = l3_dest->type();
            if (member_type == object_type_e::ASBR_LSP) {
                return LA_STATUS_EINVAL;
            }
        }
    }

    if ((m_level == level_e::LEVEL_2) && (type == object_type_e::ASBR_LSP)) {
        if (has_only_asbr_lsps_configured() == false) {
            return LA_STATUS_EINVAL;
        }
    }

    auto l3_destination_sptr = m_device->get_sptr(l3_destination);
    add_dependency(l3_destination_sptr);

    la_status status = add_member_in_resolution(l3_destination_sptr);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "add_member_in_resolution failed, status = %s.", la_status2str(status).c_str());
        return status;
    }
    if (m_l3_destinations.size() == 0) {
        m_is_drop = false;
    }
    // If any of the members point to drop/null, we set the group to drop
    if (type == object_type_e::NEXT_HOP) {
        auto next_hop = static_cast<const la_next_hop_base*>(l3_destination);
        la_next_hop::nh_type_e nh_type;
        la_status status = next_hop->get_nh_type(nh_type);
        return_on_error(status);
        if (nh_type == la_next_hop::nh_type_e::DROP || nh_type == la_next_hop::nh_type_e::NULL_) {
            m_is_drop = true;
            log_debug(HLD, "adding member of type drop in level %d nh_type %d", (int)m_level, (int)nh_type);
        }
    }
    m_l3_destinations.push_back(l3_destination_sptr);

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::remove_member(const la_l3_destination* l3_destination)
{
    start_api_call("l3_destination=", l3_destination);

    if (l3_destination == nullptr) {
        log_err(HLD, "l3_destination is nullptr, returning EINVAL.");
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(l3_destination, this)) {
        log_err(HLD,
                "objects %s and %s are on different devices (%d, %d)",
                silicon_one::to_string(l3_destination).c_str(),
                silicon_one::to_string(this).c_str(),
                l3_destination->get_device()->get_id(),
                m_device->get_id());
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Verify that the l3_destination is a member
    auto it = find(m_l3_destinations.begin(), m_l3_destinations.end(), l3_destination);
    if (it == m_l3_destinations.end()) {
        log_err(HLD, "Failed flow (it == m_l3_destinations.end()), returning ENOTFOUND");
        return LA_STATUS_ENOTFOUND;
    }
    size_t lbg_member_id = distance(m_l3_destinations.begin(), it);

    la_status status = LA_STATUS_SUCCESS;
    size_t ecmp_group_size = m_l3_destinations.size();
    size_t last_member_idx = ecmp_group_size - 1;

    status = remove_member_in_resolution(lbg_member_id);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "remove_member_in_resolution failed, status = %s.", la_status2str(status).c_str());
        return status;
    }

    // If the member to be removed is not the last member,
    // move the last member to the location of that to be removed
    if (lbg_member_id < last_member_idx) {
        m_l3_destinations[lbg_member_id] = m_l3_destinations.back();
    }

    m_l3_destinations.pop_back();
    if (m_l3_destinations.size() == 0) {
        m_is_drop = false;
    } else if (m_is_drop) {
        la_status status = set_drop_status();
        return_on_error(status);
    }

    auto l3_destination_sptr = m_device->get_sptr(l3_destination);
    remove_dependency(l3_destination_sptr);

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::get_member(size_t member_idx, const la_l3_destination*& out_member) const
{
    start_api_getter_call("");

    if (member_idx >= m_l3_destinations.size()) {
        log_err(HLD, "Failed flow (member_idx >= m_l3_destinations.size()), returning EOUTOFRANGE");
        return LA_STATUS_EOUTOFRANGE;
    }

    out_member = m_l3_destinations[member_idx].get();
    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::get_members(la_l3_destination_vec_t& out_members) const
{
    out_members.clear();

    for (const auto& dest_wptr : m_l3_destinations) {
        out_members.push_back(dest_wptr.get());
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::set_members(const la_l3_destination_vec_t& members)
{
    start_api_call("members=", members);

    la_status status = LA_STATUS_SUCCESS;

    if (members.size() == 0) {
        log_err(HLD, "Invalid flow (members.size() == 0)");
        return LA_STATUS_EINVAL;
    }

    for (const auto& l3_dest : members) {
        if (l3_dest == nullptr) {
            log_err(HLD, "l3_dest is nullptr, returning EINVAL.");
            return LA_STATUS_EINVAL;
        }

        if (!of_same_device(l3_dest, this)) {
            log_err(HLD,
                    "objects %s and %s are on different devices (%d, %d)",
                    silicon_one::to_string(l3_dest).c_str(),
                    silicon_one::to_string(this).c_str(),
                    l3_dest->get_device()->get_id(),
                    m_device->get_id());
            return LA_STATUS_EDIFFERENT_DEVS;
        }

        if (l3_dest->type() == la_object::object_type_e::PREFIX_OBJECT) {
            auto pfx_obj = static_cast<const la_prefix_object_base*>(l3_dest);
            if (!pfx_obj->is_resolution_forwarding_supported()) {
                log_err(HLD, "If destination is a global prefix object, its destination must be an ECMP group.");
                return LA_STATUS_EINVAL;
            }
        }
    }

    std::vector<la_l3_destination_wcptr> new_members;
    for (const auto& dest : members) {
        new_members.push_back(m_device->get_sptr(dest));
    }

    const auto old_members = m_l3_destinations;

    transaction txn;

    for (const auto& l3_dest : new_members) {
        add_dependency(l3_dest);
        txn.on_fail([=]() { remove_dependency(l3_dest); });
    }

    for (resolution_step_e res_step = RESOLUTION_STEP_FEC; res_step < RESOLUTION_STEP_LAST;
         res_step = (resolution_step_e)(res_step + 1)) {
        if (m_resolution_data.users_for_step[res_step] == 0) {
            continue;
        }

        txn.status = configure_resolution_step_new_members(res_step, old_members, new_members);
        if (txn.status != LA_STATUS_SUCCESS) {
            log_err(HLD, "configure_resolution_step failed, status = %s.", la_status2str(txn.status).c_str());
            return txn.status;
        }
        // IN oreder to cleanup failing
        //  in case any iteration of the resolution_step failed in configure_resolution_step , need to configure old members and
        //  unconfigure the new members.
        txn.on_fail([=]() { configure_resolution_step_new_members(res_step, new_members, old_members); });
    }

    m_l3_destinations = new_members;

    status = set_drop_status();
    return_on_error(status);

    for (const auto& l3_dest : old_members) {
        remove_dependency(l3_dest);
    }

    return LA_STATUS_SUCCESS;
}

bool
la_ecmp_group_impl::has_only_asbr_lsps_configured() const
{
    for (const auto& l3_dest : m_l3_destinations) {
        if (l3_dest->type() != object_type_e::ASBR_LSP) {
            return false;
        }
    }

    return true;
}

la_status
la_ecmp_group_impl::remove_member_in_resolution(size_t lbg_member_id)
{
    la_status status = LA_STATUS_SUCCESS;
    size_t ecmp_group_size = m_l3_destinations.size();
    size_t last_member_idx = ecmp_group_size - 1;

    for (resolution_step_e res_step = RESOLUTION_STEP_FEC; res_step < RESOLUTION_STEP_LAST;
         res_step = (resolution_step_e)(res_step + 1)) {
        if (m_resolution_data.users_for_step[res_step] == 0) {
            continue;
        }

        switch (res_step) {

        case RESOLUTION_STEP_STAGE0_ECMP:
        case RESOLUTION_STEP_STAGE1_ECMP: {
            // If the member to be removed is not the last member,
            // move the last member to the location of that to be removed
            // Write the last member at the location of the member to be removed
            const auto& l3_dest = m_l3_destinations.back();
            if (lbg_member_id < last_member_idx) {
                status = configure_resolution_step_lb_member_at_index(res_step, l3_dest, lbg_member_id);
                if (status != LA_STATUS_SUCCESS) {
                    log_err(HLD,
                            "configure_resolution_step_native_lb_member_at_index failed, status = %s.",
                            la_status2str(status).c_str());
                    return status;
                }
            }

            // Update the group member size
            status = configure_resolution_step_lb_group_size(res_step, ecmp_group_size - 1);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "configure_resolution_step_native_lb_group_size failed, status = %s.", la_status2str(status).c_str());
                return status;
            }

            // Erase the last member entry
            status = erase_resolution_step_lb_member_at_index(res_step, last_member_idx);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "erase_resolution_step_native_lb_member_at_index failed, status = %s.", la_status2str(status).c_str());
                return status;
            }

            status = uninstantiate_resolution_object(l3_dest, res_step);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "uninstantiate_resolution_object failed, status = %s.", la_status2str(status).c_str());
                return status;
            }
        } break;

        default: {
            log_err(HLD, "case %s is not a valid value for the switch", silicon_one::to_string(res_step).c_str());
            return LA_STATUS_EUNKNOWN;
        }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::set_lb_mode(la_lb_mode_e lb_mode)
{
    log_err(HLD, "LA_STATUS_ENOTIMPLEMENTED");
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ecmp_group_impl::set_lb_fields(la_lb_fields_t lb_fields)
{
    log_err(HLD, "LA_STATUS_ENOTIMPLEMENTED");
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ecmp_group_impl::set_lb_hash(la_lb_hash_e lb_hash)
{
    log_err(HLD, "LA_STATUS_ENOTIMPLEMENTED");
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ecmp_group_impl::set_slb_mode(bool enabled)
{
    log_err(HLD, "LA_STATUS_ENOTIMPLEMENTED");
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_object::object_type_e
la_ecmp_group_impl::type() const
{
    return object_type_e::ECMP_GROUP;
}

la_ecmp_group::level_e
la_ecmp_group_impl::get_ecmp_level() const
{
    return m_level;
}

std::string
la_ecmp_group_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_ecmp_group_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_ecmp_group_impl::oid() const
{
    return m_oid;
}

la_device*
la_ecmp_group_impl::get_device() const
{
    return m_device.get();
}

la_status
la_ecmp_group_impl::instantiate(resolution_step_e prev_step)
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (cur_step == RESOLUTION_STEP_INVALID) {
        log_err(HLD, "Invalid flow (cur_step == RESOLUTION_STEP_INVALID)");
        return LA_STATUS_EINVAL;
    }

    if (m_type != member_type_e::UNKNOWN) {
        if (prev_step != RESOLUTION_STEP_STAGE0_CE_PTR) {
            if (m_type != member_type_e::IP) {
                return LA_STATUS_EINVAL;
            }
        } else {
            if ((m_type != member_type_e::LDP) && (m_type != member_type_e::GLOBAL_LSP)) {
                return LA_STATUS_EINVAL;
            }
        }
    }

    // if this object already has appearance in this step then nothing to do.
    if (m_resolution_data.users_for_step[cur_step] > 0) {
        m_resolution_data.users_for_step[cur_step]++;
        return LA_STATUS_SUCCESS;
    }
    transaction txn;

    m_resolution_data.users_for_step[cur_step]++;

    txn.on_fail([&]() { m_resolution_data.users_for_step[cur_step]--; });

    // this is first appearance, allocate an id
    bool allocated = m_device->m_index_generators.ecmp_groups[cur_step].allocate(m_resolution_data.id_in_step[cur_step].val);
    if (!allocated) {
        log_err(HLD, "could not allocate ecmp_groups[cur_step], return status = LA_STATUS_ERESOURCE.");
        txn.status = LA_STATUS_ERESOURCE;
        return txn.status;
    }

    // If configure_resolution_step below fails
    txn.on_fail([&]() {
        m_device->m_index_generators.ecmp_groups[cur_step].release(m_resolution_data.id_in_step[cur_step].val);
        m_resolution_data.id_in_step[cur_step] = RESOLUTION_TABLE_INDEX_INVALID;
    });

    if (prev_step != RESOLUTION_STEP_STAGE0_CE_PTR) {
        m_type = member_type_e::IP;
    }

    auto& new_members = m_l3_destinations;

    // fully write self to resolution table
    std::vector<la_l3_destination_wcptr> old_configured_members; // empty vector - Currently no configured old members
    // old members are passed to "configure_resolution_step" to use the 'transaction' mechanism
    txn.status = configure_resolution_step(cur_step, old_configured_members, new_members);
    if (txn.status != LA_STATUS_SUCCESS) {
        log_err(HLD, "configure_resolution_step failed, status = %s.", la_status2str(txn.status).c_str());
        return txn.status;
    }

    lpm_destination_id lpm_dest_id = get_lpm_destination_id(prev_step);
    m_device->m_l3_destinations[lpm_dest_id.val & ~DEFAULT_ROUTE_DESTINATION_BIT_MASK] = m_device->get_sptr(this);

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::instantiate(resolution_step_e prev_step, const la_object* prev_obj)
{
    if (prev_obj == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_object::object_type_e obj_type = prev_obj->type();

    if (m_is_ip_tunnel) {
        if ((obj_type != object_type_e::IP_TUNNEL_DESTINATION) && (obj_type != object_type_e::L2_SERVICE_PORT)) {
            log_err(HLD, "This ECMP GROUP can only be used by IP TUNNEL");
            return LA_STATUS_EINVAL;
        }
        return instantiate(prev_step);
    }

    if ((obj_type == object_type_e::IP_TUNNEL_DESTINATION) || (obj_type == object_type_e::L2_SERVICE_PORT)) {
        resolution_step_e cur_step = get_next_resolution_step(prev_step);
        if (m_resolution_data.users_for_step[cur_step] == 0) {
            m_is_ip_tunnel = true;
        } else {
            log_err(HLD, "This ECMP GROUP cannot be used by IP TUNNEL");
            return LA_STATUS_EINVAL;
        }
    }

    if (obj_type != object_type_e::PREFIX_OBJECT) {
        return instantiate(prev_step);
    }

    auto prefix_object = m_device->get_sptr<const la_prefix_object_base>(prev_obj);
    return do_prefix_object_instantiate(prev_step, prefix_object);
}

la_status
la_ecmp_group_impl::uninstantiate(resolution_step_e prev_step)
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (cur_step == RESOLUTION_STEP_INVALID) {
        log_err(HLD, "Invalid flow (cur_step == RESOLUTION_STEP_INVALID)");
        return LA_STATUS_EINVAL;
    }

    if (m_resolution_data.users_for_step[cur_step] > 1) {
        m_resolution_data.users_for_step[cur_step]--;
        return LA_STATUS_SUCCESS;
    }

    la_status status = unconfigure_resolution_step(cur_step);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "unconfigure_resolution_step failed, status = %s.", la_status2str(status).c_str());
        return status;
    }

    m_type = member_type_e::UNKNOWN;
    lpm_destination_id lpm_dest_id = get_lpm_destination_id(prev_step);
    m_device->m_l3_destinations[lpm_dest_id.val & ~DEFAULT_ROUTE_DESTINATION_BIT_MASK] = nullptr;
    m_device->m_index_generators.ecmp_groups[cur_step].release(m_resolution_data.id_in_step[cur_step].val);
    m_resolution_data.id_in_step[cur_step] = RESOLUTION_TABLE_INDEX_INVALID;
    m_resolution_data.users_for_step[cur_step]--;
    m_is_ip_tunnel = false;
    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::do_prefix_object_instantiate(resolution_step_e prev_step, const la_prefix_object_base_wcptr& pfx_obj)
{
    if (prev_step != RESOLUTION_STEP_STAGE0_CE_PTR) {
        return LA_STATUS_EINVAL;
    }

    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (cur_step != RESOLUTION_STEP_STAGE1_ECMP) {
        return LA_STATUS_EINVAL;
    }

    la_prefix_object::prefix_type_e lsp_type;
    la_status status = pfx_obj->get_prefix_type(lsp_type);
    return_on_error(status);

    member_type_e type;
    if (lsp_type == la_prefix_object::prefix_type_e::GLOBAL) {
        type = member_type_e::GLOBAL_LSP;
    } else {
        type = member_type_e::LDP;
    }

    if (m_type == member_type_e::UNKNOWN) {
        m_type = type;
    } else if (m_type != type) {
        return LA_STATUS_EINVAL;
    }

    return instantiate(prev_step);
}

lpm_destination_id
la_ecmp_group_impl::get_lpm_destination_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);
    resolution_table_index res_table_index = get_id_in_step(cur_step);

    if (res_table_index == RESOLUTION_TABLE_INDEX_INVALID) {
        return LPM_DESTINATION_ID_INVALID;
    }

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_STAGE0_ECMP: {
        return lpm_destination_id(NPL_LPM_COMPRESSED_DESTINATION_ECMP_MASK | res_table_index.val);
    }
    case silicon_one::RESOLUTION_STEP_STAGE1_ECMP: {
        if (m_is_drop) {
            return lpm_destination_id(NPL_LPM_COMPRESSED_DESTINATION_STAGE2_ECMP_MASK_DEFAULT | res_table_index.val);
        } else {
            return lpm_destination_id(NPL_LPM_COMPRESSED_DESTINATION_STAGE2_ECMP_MASK | res_table_index.val);
        }
    }

    default: {
        return LPM_DESTINATION_ID_INVALID;
    }
    }
}

destination_id
la_ecmp_group_impl::get_destination_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);
    resolution_table_index res_table_index = get_id_in_step(cur_step);

    if (res_table_index == RESOLUTION_TABLE_INDEX_INVALID) {
        return DESTINATION_ID_INVALID;
    }

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_STAGE0_ECMP: {
        return destination_id(NPL_DESTINATION_MASK_ECMP | res_table_index.val);
    }
    case silicon_one::RESOLUTION_STEP_STAGE1_ECMP: {
        return destination_id(NPL_DESTINATION_MASK_LEVEL2_ECMP | res_table_index.val);
    }

    default: {
        return DESTINATION_ID_INVALID;
    }
    }
}

resolution_step_e
la_ecmp_group_impl::get_next_resolution_step(resolution_step_e prev_step) const
{
    if (prev_step == RESOLUTION_STEP_FORWARD_L3) {
        if (m_level == level_e::LEVEL_2) {
            return RESOLUTION_STEP_STAGE1_ECMP;
        }
        return RESOLUTION_STEP_STAGE0_ECMP;
    }

    if (prev_step == RESOLUTION_STEP_FORWARD_L2) {
        if (m_level == level_e::LEVEL_2) {
            return RESOLUTION_STEP_STAGE1_ECMP;
        }
        return RESOLUTION_STEP_STAGE0_ECMP;
    }

    if (prev_step == RESOLUTION_STEP_FORWARD_MPLS) {
        return RESOLUTION_STEP_STAGE0_ECMP;
    }

    if (prev_step == RESOLUTION_STEP_FEC) {
        return RESOLUTION_STEP_STAGE1_ECMP;
    }

    if (prev_step < RESOLUTION_STEP_STAGE1_ECMP) {
        return RESOLUTION_STEP_STAGE1_ECMP;
    }

    if (prev_step < RESOLUTION_STEP_STAGE2_ECMP) {
        return RESOLUTION_STEP_STAGE2_ECMP;
    }

    if (prev_step < RESOLUTION_STEP_STAGE3_ECMP) {
        return RESOLUTION_STEP_STAGE3_ECMP;
    }

    return RESOLUTION_STEP_INVALID;
}

resolution_table_index
la_ecmp_group_impl::get_id_in_step(resolution_step_e res_step) const
{
    if (m_resolution_data.users_for_step[res_step] == 0) {
        return RESOLUTION_TABLE_INDEX_INVALID;
    }

    return m_resolution_data.id_in_step[res_step];
}

la_status
la_ecmp_group_impl::configure_resolution_step_new_members(resolution_step_e res_step,
                                                          const std::vector<la_l3_destination_wcptr>& old_members,
                                                          const std::vector<la_l3_destination_wcptr>& new_members)
{
    la_status status = LA_STATUS_SUCCESS;
    status = configure_resolution_step(res_step, old_members, new_members);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "configure_resolution_step failed, status = %s.", la_status2str(status).c_str());
        return status;
    }

    size_t new_members_list_size = new_members.size();
    status = unconfigure_resolution_step_lb_members_list(res_step, old_members, new_members_list_size);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "unconfigure_resolution_step_stage_lb_members_list failed, status = %s.", la_status2str(status).c_str());
        return status;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::configure_resolution_step(resolution_step_e res_step,
                                              const std::vector<la_l3_destination_wcptr>& old_configured_members,
                                              const std::vector<la_l3_destination_wcptr>& new_members)
{
    switch (res_step) {
    case RESOLUTION_STEP_STAGE0_ECMP:
    case RESOLUTION_STEP_STAGE1_ECMP: {
        la_status status = configure_resolution_step_lb_members_list(res_step, old_configured_members, new_members);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "configure_resolution_step_stage_lb_members_list failed, status = %s.", la_status2str(status).c_str());
            return status;
        }

        status = configure_resolution_step_lb_group_size(res_step, new_members.size());
        return status;
    }

    case RESOLUTION_STEP_STAGE2_ECMP:
    case RESOLUTION_STEP_STAGE3_ECMP:
        log_err(HLD,
                "%s: flows for the case RESOLUTION_STEP_STAGE2_ECMP/RESOLUTION_STEP_STAGE3_ECMP are not implemented yet",
                __FUNCTION__);
        return LA_STATUS_ENOTIMPLEMENTED;

    default:
        log_err(HLD, "%s: case %s is not a valid value for the switch", __FUNCTION__, silicon_one::to_string(res_step).c_str());
        return LA_STATUS_EINVAL;
    }
}

la_status
la_ecmp_group_impl::configure_resolution_step_lb_members_list(resolution_step_e res_step,
                                                              const std::vector<la_l3_destination_wcptr>& old_configured_members,
                                                              const std::vector<la_l3_destination_wcptr>& new_members)
{
    transaction txn;
    for (size_t i = 0; i < new_members.size(); i++) {
        const auto& l3_dest = new_members[i];

        txn.status = instantiate_resolution_object(l3_dest, res_step);
        if (txn.status != LA_STATUS_SUCCESS) {
            log_err(HLD, "instantiate_resolution_object failed, status = %s.", la_status2str(txn.status).c_str());
            return txn.status;
        }
        txn.on_fail([=]() { uninstantiate_resolution_object(l3_dest, res_step); });

        txn.status = configure_resolution_step_lb_member_at_index(res_step, l3_dest, i);
        if (txn.status != LA_STATUS_SUCCESS) {
            log_err(
                HLD, "configure_resolution_step_stage_lb_member_at_index failed, status = %s.", la_status2str(txn.status).c_str());
            return txn.status;
        }

        // txn cleanup in case of a fail
        // if there was another member configured before - then reconfigure it.
        // else delete the configured entry
        if (i < old_configured_members.size()) {
            txn.on_fail([=]() {
                auto& prev_resolution_step_lb_member_at_index = old_configured_members[i];
                configure_resolution_step_lb_member_at_index(res_step, prev_resolution_step_lb_member_at_index, i);
            });
        } else {
            txn.on_fail([=]() { erase_resolution_step_lb_member_at_index(res_step, i); });
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::unconfigure_resolution_step_lb_members_list(resolution_step_e res_step,
                                                                const std::vector<la_l3_destination_wcptr>& old_members,
                                                                size_t new_members_list_size)
{
    la_status status = LA_STATUS_SUCCESS;
    size_t old_group_size = old_members.size();
    status = erase_resolution_step_old_members(res_step, old_group_size, new_members_list_size);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "erase_resolution_step_old_members failed, status = %s.", la_status2str(status).c_str());
        return status;
    }

    for (const auto& l3_dest : old_members) {
        status = uninstantiate_resolution_object(l3_dest, res_step);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "uninstantiate_resolution_object failed, status = %s.", la_status2str(status).c_str());
            return status;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::configure_resolution_step_lb_group_size(resolution_step_e res_step, size_t lbg_group_size)
{
    resolution_table_index id_in_step = get_id_in_step(res_step);

    if (id_in_step == RESOLUTION_TABLE_INDEX_INVALID) {
        return LA_STATUS_EUNKNOWN;
    }

    la_uint32_t group_id = id_in_step.val;
    int stage = res_step_to_stage(res_step);
    if (stage == RESOLUTION_INVALID_STAGE) {
        return LA_STATUS_EUNKNOWN;
    }

    return m_device->m_resolution_configurators[stage].set_group_size(
        group_id, lbg_group_size, NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED);
}

la_status
la_ecmp_group_impl::configure_resolution_step_lb_member_at_index(resolution_step_e res_step,
                                                                 const la_l3_destination_wcptr& l3_dest,
                                                                 size_t lbg_member_id)
{

    npl_resolution_stage_assoc_data_narrow_entry_t value{};
    object_type_e type = l3_dest->type();
    resolution_table_index id_in_step = get_id_in_step(res_step);

    if (id_in_step == RESOLUTION_TABLE_INDEX_INVALID) {
        return LA_STATUS_EUNKNOWN;
    }

    la_uint32_t group_id = id_in_step.val;
    auto& res_cfg_handles = m_resolution_data.cfg_handles[res_step];
    auto& res_cfg_handle = res_cfg_handles[lbg_member_id];

    switch (res_step) {
    case RESOLUTION_STEP_STAGE0_ECMP: {
        if (type == object_type_e::NEXT_HOP) {
            auto next_hop = l3_dest.weak_ptr_static_cast<const la_next_hop_base>();
            la_status status = populate_stage0_lb_to_nh_value(next_hop, value);
            return_on_error(status);

            status = m_device->m_resolution_configurators[0].configure_lb_entry(group_id, lbg_member_id, value, res_cfg_handle);
            return status;
        } else if (type == object_type_e::ECMP_GROUP) {
            auto ecmp_group = l3_dest.weak_ptr_static_cast<const la_ecmp_group_impl>();
            la_status status = populate_stage0_lb_to_ecmp_group_value(ecmp_group, value);
            return_on_error(status);

            status = m_device->m_resolution_configurators[0].configure_lb_entry(group_id, lbg_member_id, value, res_cfg_handle);
            return status;
        } else if ((type == object_type_e::PREFIX_OBJECT) || (type == object_type_e::IP_TUNNEL_DESTINATION)) {
            la_status status = m_device->m_resolution_configurators[0].configure_in_stage_lb_entry(
                group_id, lbg_member_id, l3_dest, res_cfg_handle);
            return status;
        } else if (type == object_type_e::DESTINATION_PE) {
            la_status status = m_device->m_resolution_configurators[0].configure_in_stage_lb_entry(
                group_id, lbg_member_id, l3_dest, res_cfg_handle);
            return status;
        } else {
            log_err(HLD, "reached unimplemented flow. return status LA_STATUS_ENOTIMPLEMENTED");
            return LA_STATUS_ENOTIMPLEMENTED;
        }
    }

    case RESOLUTION_STEP_STAGE1_ECMP: {
        if (type == object_type_e::NEXT_HOP) {
            la_status status = populate_stage1_lb_to_nh_value(l3_dest, value);
            return_on_error(status);

            status = m_device->m_resolution_configurators[1].configure_lb_entry(group_id, lbg_member_id, value, res_cfg_handle);
            return status;
        } else if (type == object_type_e::L3_PROTECTION_GROUP) {
            npl_em_common_data_t common_data{};
            la_status status = populate_stage1_lb_to_p_nh_common_data(l3_dest, common_data);
            return_on_error(status);

            status = m_device->m_resolution_configurators[1].configure_in_stage_lb_entry(
                group_id, lbg_member_id, l3_dest, res_cfg_handle, common_data);
            return status;
        } else if (type == object_type_e::TE_TUNNEL) {
            auto te_tunnel = l3_dest.weak_ptr_static_cast<const la_te_tunnel_impl>();
            auto tunnel_dest = m_device->get_sptr(te_tunnel->get_destination());
            object_type_e tunnel_dest_type = tunnel_dest->type();

            if (tunnel_dest_type == object_type_e::NEXT_HOP) {
                auto next_hop = std::static_pointer_cast<const la_next_hop_base>(tunnel_dest);
                la_status status = populate_stage1_lb_to_te_tunnel_nh_value(te_tunnel, next_hop, value);
                return_on_error(status);

                status = m_device->m_resolution_configurators[1].configure_lb_entry(group_id, lbg_member_id, value, res_cfg_handle);
                return status;
            }
            if (tunnel_dest_type == object_type_e::L3_PROTECTION_GROUP) {
                npl_em_common_data_t common_data{};
                auto l3_prot = std::static_pointer_cast<const la_l3_protection_group_impl>(tunnel_dest);
                la_status status = populate_stage1_lb_to_te_tunnel_p_nh_common_data(te_tunnel, l3_prot, common_data);
                return_on_error(status);

                status = m_device->m_resolution_configurators[1].configure_in_stage_lb_entry(
                    group_id, lbg_member_id, l3_dest, res_cfg_handle, common_data);
                return status;
            }
        } else if (type == object_type_e::ASBR_LSP) {
            auto asbr_lsp = l3_dest.weak_ptr_static_cast<const la_asbr_lsp_impl>();
            auto asbr_lsp_dest = asbr_lsp->get_destination();
            object_type_e asbr_lsp_dest_type = asbr_lsp_dest->type();

            if (asbr_lsp_dest_type == object_type_e::NEXT_HOP) {
                la_status status = populate_stage1_lb_to_nh_asbr_lsp(asbr_lsp, value);
                return_on_error(status);

                status = m_device->m_resolution_configurators[1].configure_lb_entry(group_id, lbg_member_id, value, res_cfg_handle);
                return status;
            } else if (asbr_lsp_dest_type == object_type_e::L3_PROTECTION_GROUP) {
                npl_em_common_data_t common_data{};
                la_status status = populate_stage1_lb_to_p_nh_asb_lsp_common_data(asbr_lsp, common_data);
                return_on_error(status);

                status = m_device->m_resolution_configurators[1].configure_in_stage_lb_entry(
                    group_id, lbg_member_id, l3_dest, res_cfg_handle, common_data);
                return status;
            }
        } else {
            log_err(HLD, "reached unimplemented flow. return status LA_STATUS_ENOTIMPLEMENTED");
            return LA_STATUS_ENOTIMPLEMENTED;
        }
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    case RESOLUTION_STEP_STAGE2_ECMP:
    case RESOLUTION_STEP_STAGE3_ECMP:
        return LA_STATUS_ENOTIMPLEMENTED;

    default:
        log_err(HLD, "%s: invalid res_step=%s", __FUNCTION__, silicon_one::to_string(res_step).c_str());
        return LA_STATUS_EINVAL;
    }
}

la_status
la_ecmp_group_impl::unconfigure_resolution_step(resolution_step_e res_step)
{
    switch (res_step) {
    case RESOLUTION_STEP_STAGE0_ECMP:
    case RESOLUTION_STEP_STAGE1_ECMP: {
        la_status status = LA_STATUS_SUCCESS;

        status = erase_resolution_step_lb_group_size(res_step);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "erase_resolution_step_lb_group_size failed, status = %s.", la_status2str(status).c_str());
            return status;
        }

        for (size_t lbg_member_id = 0; lbg_member_id < m_l3_destinations.size(); lbg_member_id++) {
            status = erase_resolution_step_lb_member_at_index(res_step, lbg_member_id);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "erase_resolution_step_lb_member_at_index failed, status = %s.", la_status2str(status).c_str());
                return status;
            }

            const auto& l3_dest = m_l3_destinations[lbg_member_id];

            status = uninstantiate_resolution_object(l3_dest, res_step);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "uninstantiate_resolution_object failed, status = %s.", la_status2str(status).c_str());
                return status;
            }
        }

        return status;
    }

    case RESOLUTION_STEP_STAGE2_ECMP:
    case RESOLUTION_STEP_STAGE3_ECMP:
        log_err(HLD,
                "%s: flows for the case RESOLUTION_STEP_STAGE2_ECMP/RESOLUTION_STEP_STAGE3_ECMP are not implemented yet",
                __FUNCTION__);
        return LA_STATUS_ENOTIMPLEMENTED;

    default:
        log_err(HLD, "%s: invalid res_step=%s", __FUNCTION__, silicon_one::to_string(res_step).c_str());
        return LA_STATUS_EINVAL;
    }
}

la_status
la_ecmp_group_impl::erase_resolution_step_lb_group_size(resolution_step_e res_step)
{
    resolution_table_index id_in_step = get_id_in_step(res_step);

    if (id_in_step == RESOLUTION_TABLE_INDEX_INVALID) {
        return LA_STATUS_EUNKNOWN;
    }

    la_uint32_t group_id = id_in_step.val;
    int stage = res_step_to_stage(res_step);
    if (stage == RESOLUTION_INVALID_STAGE) {
        return LA_STATUS_EUNKNOWN;
    }

    return m_device->m_resolution_configurators[stage].erase_group_size(group_id);
}

la_status
la_ecmp_group_impl::erase_resolution_step_lb_member_at_index(resolution_step_e res_step, size_t lbg_member_id)
{
    la_status status = LA_STATUS_SUCCESS;
    auto& res_cfg_handles = m_resolution_data.cfg_handles[res_step];
    dassert_slow(res_cfg_handles.count(lbg_member_id));
    auto& res_cfg_handle = res_cfg_handles[lbg_member_id];
    int stage = res_step_to_stage(res_step);

    if (stage == RESOLUTION_INVALID_STAGE) {
        return LA_STATUS_EUNKNOWN;
    }

    status = m_device->m_resolution_configurators[stage].unconfigure_entry(res_cfg_handle);
    if (status == LA_STATUS_SUCCESS) {
        res_cfg_handles.erase(lbg_member_id);
    }

    return status;
}

la_status
la_ecmp_group_impl::erase_resolution_step_old_members(resolution_step_e res_step,
                                                      size_t old_group_size,
                                                      size_t new_members_list_size)
{
    la_status status = LA_STATUS_SUCCESS;
    for (size_t lbg_member_id = new_members_list_size; lbg_member_id < old_group_size; lbg_member_id++) {
        status = erase_resolution_step_lb_member_at_index(res_step, lbg_member_id);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "erase_resolution_step_lb_member_at_index failed, status = %s.", la_status2str(status).c_str());
            return status;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::populate_stage0_lb_to_nh_value(const la_next_hop_base_wcptr& next_hop,
                                                   npl_resolution_stage_assoc_data_narrow_entry_t& value) const
{
    auto& destination(value.stage0_dest1);

    destination.type = NPL_ENTRY_TYPE_STAGE0_DESTINATION1;
    destination.destination = destination_id(NPL_DESTINATION_MASK_L3_NH | next_hop->get_gid()).val;
    destination.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH;

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::populate_stage0_lb_to_ecmp_group_value(const la_ecmp_group_impl_wcptr& ecmp_group,
                                                           npl_resolution_stage_assoc_data_narrow_entry_t& value) const
{
    auto& destination(value.stage0_ecmp_dest);

    destination.type = NPL_ENTRY_TYPE_STAGE0_ECMP_DESTINATION;
    destination.destination = silicon_one::get_destination_id(ecmp_group, RESOLUTION_STEP_STAGE0_ECMP).val;

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::populate_stage1_lb_to_nh_value(const la_l3_destination_wcptr& l3_dest,
                                                   npl_resolution_stage_assoc_data_narrow_entry_t& value) const
{
    if (m_is_ip_tunnel) {
        auto& destination(value.stage1_ecmp_dest1);
        destination.type = NPL_ENTRY_TYPE_STAGE1_LEVEL2_ECMP_DESTINATION;
        destination.destination = silicon_one::get_destination_id(l3_dest, RESOLUTION_STEP_STAGE1_ECMP).val;
    } else {
        auto& destination(value.stage1_ecmp_dest);
        destination.type = NPL_ENTRY_TYPE_STAGE1_DESTINATION1;
        destination.destination = silicon_one::get_destination_id(l3_dest, RESOLUTION_STEP_STAGE1_ECMP).val;
        if (m_type == member_type_e::LDP) {
            destination.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE;
        } else if (m_type == member_type_e::GLOBAL_LSP) {
            destination.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR;
        } else {
            destination.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::populate_stage1_lb_to_p_nh_common_data(const la_l3_destination_wcptr& l3_dest,
                                                           npl_em_common_data_t& em_common_data) const
{
    if (m_type == member_type_e::LDP) {
        em_common_data.common_data_ecmp2.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE;
    } else if (m_type == member_type_e::GLOBAL_LSP) {
        em_common_data.common_data_ecmp2.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR;
    } else {
        em_common_data.common_data_ecmp2.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::populate_stage1_lb_to_te_tunnel_nh_value(const la_te_tunnel_impl_wcptr& te_tunnel,
                                                             const la_next_hop_base_wcptr& next_hop,
                                                             npl_resolution_stage_assoc_data_narrow_entry_t& value) const
{
    la_te_tunnel::tunnel_type_e type;
    la_status status = te_tunnel->get_tunnel_type(type);
    return_on_error(status);

    if ((m_type == member_type_e::LDP) && (type == la_te_tunnel::tunnel_type_e::LDP_ENABLED)) {
        auto& destination(value.stage1_ecmp_tunnel_or_asbr_ldp_over_te);

        destination.type = NPL_ENTRY_TYPE_STAGE1_L3_NH_TE_TUNNEL14B_OR_ASBR1;
        destination.te_tunnel14b_or_asbr = te_tunnel->get_gid();
        destination.l3_nh = next_hop->get_gid();
    } else {
        auto& destination(value.stage1_ecmp_tunnel_or_asbr_he_with_tunnel_id);

        destination.type = NPL_ENTRY_TYPE_STAGE1_LEVEL2_ECMP_L3_NH_TE_TUNNEL14B_OR_ASBR;
        destination.te_tunnel14b_or_asbr = te_tunnel->get_gid();
        destination.l3_nh = next_hop->get_gid();
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::populate_stage1_lb_to_te_tunnel_p_nh_common_data(const la_te_tunnel_impl_wcptr& te_tunnel,
                                                                     const la_l3_protection_group_impl_wcptr& l3_protection_group,
                                                                     npl_em_common_data_t& em_common_data) const
{
    la_te_tunnel::tunnel_type_e type;
    la_status status = te_tunnel->get_tunnel_type(type);
    return_on_error(status);

    if ((m_type == member_type_e::LDP) && (type == la_te_tunnel::tunnel_type_e::LDP_ENABLED)) {
        em_common_data.common_data_ecmp2.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE;
    } else {
        em_common_data.common_data_ecmp2.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID;
    }
    em_common_data.common_data_ecmp2.te_tunnel14b_or_asbr = te_tunnel->get_gid();

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::populate_stage1_lb_to_nh_asbr_lsp(const la_asbr_lsp_impl_wcptr& asbr_lsp,
                                                      npl_resolution_stage_assoc_data_narrow_entry_t& value) const
{
    auto& entry(value.stage1_ecmp_lsp_asbr_nh);
    const la_next_hop_base* next_hop = static_cast<const la_next_hop_base*>(asbr_lsp->get_destination());

    entry.l3_nh = next_hop->get_gid();
    entry.te_tunnel14b_or_asbr = asbr_lsp->get_asbr_gid();
    entry.type = NPL_ENTRY_TYPE_STAGE1_L3_NH_TE_TUNNEL14B_OR_ASBR2;

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::populate_stage1_lb_to_p_nh_asb_lsp_common_data(const la_asbr_lsp_impl_wcptr& asbr_lsp,
                                                                   npl_em_common_data_t& em_common_data) const
{
    em_common_data.common_data_ecmp2.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE;
    em_common_data.common_data_ecmp2.te_tunnel14b_or_asbr = asbr_lsp->get_asbr_gid();
    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::add_member_in_resolution(const la_l3_destination_wcptr& l3_dest)
{
    size_t new_member_index = m_l3_destinations.size();
    la_status status = LA_STATUS_SUCCESS;

    for (resolution_step_e res_step = RESOLUTION_STEP_FEC; res_step < RESOLUTION_STEP_LAST;
         res_step = (resolution_step_e)(res_step + 1)) {
        if (m_resolution_data.users_for_step[res_step] == 0) {
            continue;
        }
        switch (res_step) {

        case RESOLUTION_STEP_STAGE0_ECMP:
        case RESOLUTION_STEP_STAGE1_ECMP: {
            status = instantiate_resolution_object(l3_dest, res_step);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "instantiate_resolution_object failed, status = %s.", la_status2str(status).c_str());
                return status;
            }

            status = configure_resolution_step_lb_member_at_index(res_step, l3_dest, new_member_index);
            if (status != LA_STATUS_SUCCESS) {
                log_err(
                    HLD, "configure_resolution_step_native_lb_member_at_index failed, status = %s.", la_status2str(status).c_str());
                return status;
            }

            status = configure_resolution_step_lb_group_size(res_step, new_member_index + 1);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "configure_resolution_step_native_lb_group_size failed, status = %s.", la_status2str(status).c_str());
                return status;
            }
        } break;

        case RESOLUTION_STEP_STAGE2_ECMP:
        case RESOLUTION_STEP_STAGE3_ECMP:
            return LA_STATUS_ENOTIMPLEMENTED;

        default: {
            log_err(HLD, "case %s is not a valid value for the switch", silicon_one::to_string(res_step).c_str());
            return LA_STATUS_EUNKNOWN;
        }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ecmp_group_impl::get_fec_table_value(npl_fec_table_value_t& value)
{
    npl_fec_fec_destination_t& destination(value.payloads.resolution_fec_result.fec_dest);
    destination.type = NPL_ENTRY_TYPE_FEC_FEC_DESTINATION;
    destination.destination = get_destination_id(RESOLUTION_STEP_FEC).val;

    return LA_STATUS_SUCCESS;
}

la_ecmp_group_impl::resolution_data::resolution_data()
{
    for (resolution_step_e res_step = RESOLUTION_STEP_FIRST; res_step < RESOLUTION_STEP_LAST;
         res_step = (resolution_step_e)(res_step + 1)) {
        users_for_step[res_step] = 0;
        id_in_step[res_step] = RESOLUTION_TABLE_INDEX_INVALID;
    }
}

la_status
la_ecmp_group_impl::get_lb_resolution(const la_lb_pak_fields_vec& lb_vector, size_t& member, const la_object*& out_object) const
{
    la_status status = LA_STATUS_SUCCESS;
    resolution_step_e step = RESOLUTION_STEP_FIRST;

    if (m_level == level_e::LEVEL_1) {
        step = RESOLUTION_STEP_STAGE0_ECMP;
    } else if (m_level == level_e::LEVEL_2) {
        step = RESOLUTION_STEP_STAGE1_ECMP;
    }

    if (m_resolution_data.users_for_step[step] == 0) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_uint32_t group_size = 0;
    npl_lb_consistency_mode_e consistency_mode = NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED;
    resolution_table_index id_in_step = get_id_in_step(step);

    if (id_in_step == RESOLUTION_TABLE_INDEX_INVALID) {
        return LA_STATUS_EUNKNOWN;
    }

    la_uint32_t group_id = id_in_step.val;

    if (step == RESOLUTION_STEP_STAGE0_ECMP) {
        status = m_device->m_resolution_configurators[0].get_group_size(group_id, group_size, consistency_mode);
        return_on_error(status);
    } else if (step == RESOLUTION_STEP_STAGE1_ECMP) {
        status = m_device->m_resolution_configurators[1].get_group_size(group_id, group_size, consistency_mode);
        return_on_error(status);
    } else {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    size_t member_id = 0;
    uint16_t seed;
    uint16_t shift_amount;
    m_device->get_ecmp_hash_seed(seed);
    m_device->get_lb_hash_shift_amount(shift_amount);
    status = do_lb_resolution(lb_vector, group_size, consistency_mode, step, seed, shift_amount, member_id);
    return_on_error(status);

    member = member_id;
    const la_l3_destination* out_l3_destination = nullptr;
    status = get_member(member_id, out_l3_destination);
    out_object = out_l3_destination;

    return status;
}

la_status
la_ecmp_group_impl::set_drop_status()
{
    bool is_drop = false;
    for (const auto& l3_destination : m_l3_destinations) {
        object_type_e type = l3_destination->type();
        if (type == object_type_e::NEXT_HOP) {
            auto next_hop = static_cast<const la_next_hop_base*>(l3_destination.get());
            la_next_hop::nh_type_e nh_type;
            la_status status = next_hop->get_nh_type(nh_type);
            return_on_error(status);
            if (nh_type == la_next_hop::nh_type_e::DROP || nh_type == la_next_hop::nh_type_e::NULL_) {
                is_drop = true;
                log_debug(HLD, "member of type drop in level %d nh_type %d", (int)m_level, (int)nh_type);
                break;
            }
        }
    }
    m_is_drop = is_drop;
    return LA_STATUS_SUCCESS;
}
}
