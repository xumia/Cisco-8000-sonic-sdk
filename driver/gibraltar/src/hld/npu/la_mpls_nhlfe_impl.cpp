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

#include "la_mpls_nhlfe_impl.h"
#include "api/npu/la_l3_port.h"
#include "la_l3_ac_port_impl.h"
#include "la_l3_fec_impl.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_next_hop_base.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"

#include "api_tracer.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_mpls_nhlfe_impl::la_mpls_nhlfe_impl(const la_device_impl_wptr& device)
    : m_device(device), m_action(la_mpls_action_e::INVALID), m_l3_destination(nullptr), m_dsp(nullptr), m_spa(nullptr)
{
}

la_mpls_nhlfe_impl::~la_mpls_nhlfe_impl()
{
}

la_object::object_type_e
la_mpls_nhlfe_impl::type() const
{
    return la_object::object_type_e::MPLS_NHLFE;
}

std::string
la_mpls_nhlfe_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_mpls_nhlfe_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_mpls_nhlfe_impl::oid() const
{
    return m_oid;
}

const la_device*
la_mpls_nhlfe_impl::get_device() const
{
    return m_device.get();
}

la_mpls_action_e
la_mpls_nhlfe_impl::get_action() const
{
    return m_action;
}

la_mpls_label
la_mpls_nhlfe_impl::get_label() const
{
    return m_label;
}

la_mpls_label
la_mpls_nhlfe_impl::get_merge_point_label() const
{
    return m_mp_label;
}

const la_l3_destination*
la_mpls_nhlfe_impl::get_destination() const
{
    return m_l3_destination.get();
}

const la_system_port*
la_mpls_nhlfe_impl::get_destination_system_port() const
{
    return m_dsp.get();
}

la_status
la_mpls_nhlfe_impl::initialize_swap(la_object_id_t oid, const la_l3_destination_wcptr& l3_destination, la_mpls_label label)
{
    m_oid = oid;
    if (l3_destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(l3_destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    m_device->add_object_dependency(l3_destination, this);

    m_action = la_mpls_action_e::SWAP;
    m_l3_destination = l3_destination;
    m_label = label;

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_nhlfe_impl::initialize_php(la_object_id_t oid, const la_l3_destination_wcptr& l3_destination)
{
    m_oid = oid;
    if (l3_destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(l3_destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    m_device->add_object_dependency(l3_destination, this);

    m_action = la_mpls_action_e::POP;
    m_l3_destination = l3_destination;

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_nhlfe_impl::initialize_tunnel_protection(la_object_id_t oid,
                                                 const la_l3_destination_wcptr& l3_destination,
                                                 la_mpls_label te_label,
                                                 la_mpls_label mp_label)
{
    m_oid = oid;
    if (l3_destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(l3_destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    m_device->add_object_dependency(l3_destination, this);

    m_action = la_mpls_action_e::TUNNEL_PROTECTION;
    m_label = te_label;
    m_mp_label = mp_label;
    m_l3_destination = l3_destination;

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_nhlfe_impl::initialize_l2_adjacency(la_object_id_t oid,
                                            const la_prefix_object_wcptr& prefix,
                                            const la_system_port_wcptr& dsp)
{
    m_oid = oid;
    if (prefix == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(prefix, this) || (dsp != nullptr && !of_same_device(dsp, this))) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Check two conditions:
    // 1. prefix dest must be a nh, and that nh, if normal,  must point to an L3 AC
    // 2. L3 AC must be on top of a SPA, and dsp must belong to that SPA
    const la_l3_destination* dest = prefix->get_destination();
    if (dest->type() != object_type_e::NEXT_HOP) {
        return LA_STATUS_EINVAL;
    }

    const la_next_hop_base* nh = static_cast<const la_next_hop_base*>(dest);
    la_next_hop::nh_type_e nh_type;
    la_status status = nh->get_nh_type(nh_type);
    if (nh_type == la_next_hop::nh_type_e::NORMAL) {
        if (dsp == nullptr) {
            return LA_STATUS_EINVAL;
        }

        la_l3_port* l3_port;
        status = nh->get_router_port(l3_port);
        return_on_error(status);
        if (l3_port == nullptr || l3_port->type() != object_type_e::L3_AC_PORT) {
            return LA_STATUS_EINVAL;
        }

        la_l3_ac_port_impl* l3_ac = static_cast<la_l3_ac_port_impl*>(l3_port);

        const la_ethernet_port_base* eth_port = static_cast<const la_ethernet_port_base*>(l3_ac->get_ethernet_port());
        const auto& spa_port = m_device->get_sptr<const la_spa_port_base>(eth_port->get_spa_port());

        if (spa_port == nullptr || !spa_port->is_member(dsp)) {
            return LA_STATUS_EINVAL;
        }
        m_spa = spa_port;

        bit_vector registered_attributes((la_uint64_t)attribute_management_op::SPA_MEMBERSHIP_CHANGED);
        m_device->add_attribute_dependency(m_spa, this, registered_attributes);
        m_dsp = dsp.weak_ptr_static_cast<const la_system_port_base>();
    }

    m_action = la_mpls_action_e::L2_ADJACENCY;
    m_l3_destination = prefix;
    m_device->add_object_dependency(prefix, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_nhlfe_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    m_device->remove_object_dependency(m_l3_destination, this);

    if (m_spa != nullptr) {
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::SPA_MEMBERSHIP_CHANGED);
        m_device->remove_attribute_dependency(m_spa, this, registered_attributes);
    }

    return LA_STATUS_SUCCESS;
}

resolution_step_e
la_mpls_nhlfe_impl::get_next_resolution_step(resolution_step_e prev_step) const
{
    if (prev_step == RESOLUTION_STEP_FORWARD_MPLS) {
        return RESOLUTION_STEP_FORWARD_MPLS;
    }

    if (prev_step == RESOLUTION_STEP_STAGE0_ECMP) {
        return RESOLUTION_STEP_STAGE0_ECMP;
    }

    return RESOLUTION_STEP_INVALID;
}

la_status
la_mpls_nhlfe_impl::instantiate(resolution_step_e prev_step)
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (cur_step == RESOLUTION_STEP_INVALID) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (m_resolution_data.users_for_step[cur_step] > 0) {
        m_resolution_data.users_for_step[cur_step]++;
        return LA_STATUS_SUCCESS;
    }

    m_resolution_data.users_for_step[cur_step]++;

    return instantiate_resolution_object(m_l3_destination, cur_step);
}

la_status
la_mpls_nhlfe_impl::uninstantiate(resolution_step_e prev_step)
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (cur_step == RESOLUTION_STEP_INVALID) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    m_resolution_data.users_for_step[cur_step]--;

    if (m_resolution_data.users_for_step[cur_step] > 0) {
        return LA_STATUS_SUCCESS;
    }

    return uninstantiate_resolution_object(m_l3_destination, cur_step);
}

destination_id
la_mpls_nhlfe_impl::get_destination_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (m_resolution_data.users_for_step[cur_step] == 0) {
        return DESTINATION_ID_INVALID;
    }

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_FORWARD_MPLS: {
        return silicon_one::get_destination_id(m_l3_destination, cur_step);
    }

    default: {
        return DESTINATION_ID_INVALID;
    }
    }
}

la_status
la_mpls_nhlfe_impl::notify_change(dependency_management_op op)
{
    switch (op.type_e) {

    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        if (op.action.attribute_management.op != attribute_management_op::SPA_MEMBERSHIP_CHANGED
            || op.action.attribute_management.spa.is_added) {
            return LA_STATUS_SUCCESS;
        }
        if (m_action == la_mpls_action_e::L2_ADJACENCY && op.action.attribute_management.spa.sys_port == m_dsp) {
            return LA_STATUS_EBUSY;
        }
        return LA_STATUS_SUCCESS;

    default:
        log_err(HLD,
                "la_mpls_nhlfe_impl::notify_change received unsupported notification (%s)",
                silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

la_mpls_nhlfe_impl::resolution_data::resolution_data()
{
    for (resolution_step_e res_step = RESOLUTION_STEP_FIRST; res_step < RESOLUTION_STEP_LAST;
         res_step = (resolution_step_e)(res_step + 1)) {
        users_for_step[res_step] = 0;
    }
}

} // namespace silicon_one
