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

#include "la_next_hop_pacific.h"
#include "api/npu/la_l3_port.h"
#include "nplapi/npl_constants.h"
#include "nplapi/nplapi_tables.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_l3_fec_impl.h"
#include "npu/la_next_hop_impl_common.h"
#include "npu/la_svi_port_base.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"
#include "system/la_spa_port_pacific.h"
#include "system/la_system_port_pacific.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_next_hop_pacific::la_next_hop_pacific(const la_device_impl_wptr& device) : la_next_hop_pacgb(device)
{
}

la_next_hop_pacific::~la_next_hop_pacific() = default;

la_status
la_next_hop_pacific::populate_nh_payload_l2_info(npl_nh_payload_t& out_nh_payload,
                                                 const la_l3_port_wptr& l3_port,
                                                 la_slice_pair_id_t slice_pair) const
{
    la_l2_destination_wptr l2_dest;

    la_status status = m_next_hop_common.get_nh_l2_destination(l2_dest);

    if (status == LA_STATUS_SUCCESS) {
        if (l2_dest->type() != la_object::object_type_e::L2_SERVICE_PORT) {
            return LA_STATUS_EINVAL;
        }
        const auto& l2_port = l2_dest.weak_ptr_static_cast<la_l2_service_port_base>();
        if (l2_port->get_egress_feature_mode() == la_l2_service_port::egress_feature_mode_e::L2) {
            status = l2_port->populate_nh_l2_payload(out_nh_payload, slice_pair);
            return_on_error(status);
        } else {
            status = populate_nh_payload_l3_info(out_nh_payload, l3_port);
            return_on_error(status);
        }
    } else if (status == LA_STATUS_ENOTFOUND) {
        const auto& svi_port = l3_port.weak_ptr_static_cast<const la_svi_port_base>();
        la_l2_service_port* inject_up_port = nullptr;
        status = svi_port->get_inject_up_source_port(inject_up_port);
        return_on_error(status);
        out_nh_payload.l2_port = 1;
        out_nh_payload.l2_flood = 1;
        out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.nh_ene_macro_code = NPL_NH_ENE_MACRO_ETH_VLAN_VLAN;
        out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_tpid_prof = 2;
    } else {
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacific::populate_nh_payload(npl_nh_payload_t& out_nh_payload,
                                         const la_l3_port_wptr& l3_port,
                                         la_slice_pair_id_t slice_pair) const
{
    object_type_e l3_type = l3_port->type();
    la_status status = LA_STATUS_SUCCESS;

    switch (l3_type) {
    case la_object::object_type_e::SVI_PORT: {
        switch (m_nh_type) {
        case nh_type_e::NORMAL: {
            status = populate_nh_payload_l2_info(out_nh_payload, l3_port, slice_pair);
            return_on_error(status);
            break;
        }
        default: { // type GLEAN with an l3_port
            status = populate_nh_payload_l3_info(out_nh_payload, l3_port);
            return_on_error(status);
            break;
        }
        }
        break;
    }
    case la_object::object_type_e::L3_AC_PORT: {
        status = populate_nh_payload_l3_info(out_nh_payload, l3_port);
        return_on_error(status);
        break;
    }
    default:
        return LA_STATUS_EINVAL;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacific::populate_nh_and_svi_payload(npl_nh_and_svi_payload_t& out_nh_and_svi_payload,
                                                 la_slice_pair_id_t slice_pair) const
{
    la_l3_port_wptr port;
    la_status status = m_next_hop_common.get_router_port(port);
    return_on_error(status);

    if ((m_nh_type == nh_type_e::GLEAN) || (m_nh_type == nh_type_e::DROP) || (m_nh_type == nh_type_e::NULL_)
        || (m_nh_type == nh_type_e::USER_TRAP2)) {
        if (port == nullptr) {
            return LA_STATUS_SUCCESS;
        }
    }

    out_nh_and_svi_payload.nh_da = m_mac_addr.flat;

    status = populate_nh_payload(out_nh_and_svi_payload.nh_payload, port, slice_pair);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacific::initialize(la_object_id_t oid,
                                la_next_hop_gid_t nh_gid,
                                la_mac_addr_t nh_mac_addr,
                                const la_l3_port_wptr& port,
                                nh_type_e nh_type)
{
    m_oid = oid;
    m_gid = nh_gid;
    m_mac_addr = nh_mac_addr;
    m_nh_type = nh_type;

    if ((nh_type == nh_type_e::NORMAL) && (port == nullptr)) {
        return LA_STATUS_EINVAL;
    }

    if ((nh_type == nh_type_e::NULL_) || (nh_type == nh_type_e::DROP) || (nh_type == nh_type_e::USER_TRAP1)
        || (nh_type == nh_type_e::USER_TRAP2)) {
        if (port != nullptr) {
            return LA_STATUS_EINVAL;
        }
    }

    la_status status = m_next_hop_common.initialize(m_device->get_sptr(this), nh_gid, nh_mac_addr, port);
    return_on_error(status);

    status = configure_resolution_step_stage3_lb(nh_type);
    return_on_error(status);

    status = configure_resolution_step_stage3_lb_group_size();
    return_on_error(status);

    if (port != nullptr) {
        m_device->add_object_dependency(port, this);
        m_device->add_ifg_dependency(port, this);
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::VOQ_CHANGED
                                         | (la_uint64_t)attribute_management_op::EGRESS_VLAN_TAG_CHANGED
                                         | (la_uint64_t)attribute_management_op::EGRESS_SFLOW_CHANGED);
        m_device->add_attribute_dependency(port, this, registered_attributes);
    }

    if ((nh_type == nh_type_e::NORMAL) && (port->type() == la_object::object_type_e::SVI_PORT)) {
        auto svi_port = port.weak_ptr_static_cast<la_svi_port_base>();
        status = svi_port->add_mac_move_nh(nh_mac_addr, this);
        return_on_error(status);

        auto l2_port = get_nh_l2_port(svi_port);
        status = set_nh_l2_port(l2_port);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacific::notify_change(dependency_management_op op)
{
    la_status status = LA_STATUS_SUCCESS;
    switch (op.type_e) {
    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        switch (op.action.attribute_management.op) {
        case attribute_management_op::VOQ_CHANGED:
        case attribute_management_op::EGRESS_SFLOW_CHANGED:
            status = configure_resolution_step_stage3_lb(m_nh_type);
            return_on_error(status);
            break;
        case attribute_management_op::EGRESS_VLAN_TAG_CHANGED:
            status = update_global_tx_tables();
            return_on_error(status);
            break;
        case attribute_management_op::L2_DLP_ATTRIB_CHANGED:
            status = update_global_tx_tables();
            return_on_error(status);
            break;
        default:
            return LA_STATUS_EUNKNOWN;
        }
        break;
    case dependency_management_op::management_type_e::IFG_MANAGEMENT:
        if (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) {
            return add_ifg(op.action.ifg_management.ifg);
        }

        return remove_ifg(op.action.ifg_management.ifg);
    default:
        log_err(HLD, "received unsupported notification (%s)", silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacific::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    set_nh_l2_port(nullptr); // remove exisiting dependency and reset m_l2_port

    la_status status = LA_STATUS_SUCCESS;
    la_l3_port_wptr port;
    status = m_next_hop_common.get_router_port(port);
    return_on_error(status);
    if ((m_nh_type == nh_type_e::NORMAL) && (port->type() == la_object::object_type_e::SVI_PORT)) {
        auto svi_port = std::static_pointer_cast<la_svi_port_base>(port.lock());
        status = svi_port->delete_mac_move_nh(m_mac_addr, this);
        return_on_error(status);
    }

    if (port != nullptr) {
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::VOQ_CHANGED
                                         | (la_uint64_t)attribute_management_op::EGRESS_VLAN_TAG_CHANGED
                                         | (la_uint64_t)attribute_management_op::EGRESS_SFLOW_CHANGED);
        m_device->remove_attribute_dependency(port, this, registered_attributes);
        m_device->remove_ifg_dependency(port, this);
        m_device->remove_object_dependency(port, this);
    }

    status = m_next_hop_common.destroy();
    return_on_error(status);

    status = teardown_resolution_step_stage3_lb_group_size();
    return_on_error(status);

    status = teardown_resolution_step_stage3_lb();
    return_on_error(status);

    return status;
}

la_status
la_next_hop_pacific::set_nh_type(nh_type_e nh_type)
{
    start_api_call("nh_type=", nh_type);

    if (nh_type == m_nh_type) {
        return LA_STATUS_SUCCESS;
    }

    la_l3_port* port;
    la_status status = get_router_port(port);
    return_on_error(status);

    if ((nh_type == nh_type_e::NULL_) && (port != nullptr)) {
        return LA_STATUS_EINVAL;
    }

    if ((nh_type == nh_type_e::NORMAL) && (port == nullptr)) {
        return LA_STATUS_EINVAL;
    }

    status = configure_resolution_step_stage3_lb(nh_type);
    return_on_error(status);

    if (port != nullptr && port->type() == la_object::object_type_e::SVI_PORT) {
        status = set_svi_nh_type(nh_type);
        return_on_error(status);
    }

    if ((nh_type == nh_type_e::DROP) && (port != nullptr)) {
        status = m_next_hop_common.clear_port_dependencies();
        return_on_error(status);

        bit_vector registered_attributes((la_uint64_t)attribute_management_op::VOQ_CHANGED
                                         | (la_uint64_t)attribute_management_op::EGRESS_VLAN_TAG_CHANGED
                                         | (la_uint64_t)attribute_management_op::EGRESS_SFLOW_CHANGED);
        m_device->remove_attribute_dependency(port, this, registered_attributes);
        m_device->remove_ifg_dependency(port, this);
        m_device->remove_object_dependency(port, this);
    }

    m_nh_type = nh_type;

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacific::get_fec_table_value(npl_native_fec_table_value_t& value, npl_destination_t& rpf_fec_table_dest) const
{
    la_l3_port_wptr tx_l3_port;
    la_status status = m_next_hop_common.get_router_port(tx_l3_port);
    return_on_error(status);

    la_l3_destination_gid_t l3_dlp_gid = LA_L3_DESTINATION_GID_INVALID;
    if (tx_l3_port != nullptr) {
        l3_dlp_gid = tx_l3_port->get_gid();
    }

    // For glean adjacency without port, set result to a generic value so that loose uRPF check does not fail
    if ((m_nh_type == nh_type_e::GLEAN) && (l3_dlp_gid == LA_L3_DESTINATION_GID_INVALID)) {
        rpf_fec_table_dest.val = NPL_DESTINATION_MASK_GLEAN;
    } else {
        rpf_fec_table_dest.val = NPL_DESTINATION_MASK_L3_DLP_SUBNET | get_l3_dlp_value_from_gid(l3_dlp_gid);
    }

    npl_native_fec_destination1_t& destination(value.payloads.native_fec_table_result.destination1);

    destination.type = NPL_NATIVE_FEC_ENTRY_TYPE_NATIVE_FEC_DESTINATION1;
    destination.destination = destination_id(NPL_DESTINATION_MASK_STAGE3_NH | m_gid).val;
    destination.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH;

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacific::instantiate(resolution_step_e prev_step)
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (cur_step == RESOLUTION_STEP_INVALID) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (m_resolution_data.users_for_step[cur_step] > 0) {
        m_resolution_data.users_for_step[cur_step]++;
        return LA_STATUS_SUCCESS;
    }

    la_status status = configure_resolution_step(cur_step);
    return_on_error(status);

    m_resolution_data.users_for_step[cur_step]++;

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacific::configure_resolution_step(resolution_step_e res_step)
{
    switch (res_step) {
    case RESOLUTION_STEP_NATIVE_FEC: {
        return configure_resolution_step_native_fec();
    }
    case RESOLUTION_STEP_STAGE3_LB: {
        return LA_STATUS_SUCCESS; // Next-hop configuration in the Stage3_LB table is done on initilalize
    }
    default: {
        return LA_STATUS_EUNKNOWN;
    }
    }
}

la_status
la_next_hop_pacific::configure_resolution_step_native_fec()
{
    la_l3_fec_impl_sptr fec;

    la_status status = m_device->create_l3_fec_wrapper(m_device->get_sptr(this), fec);
    return_on_error(status);

    lpm_destination_id lpm_dest_id = silicon_one::get_lpm_destination_id(fec, RESOLUTION_STEP_FORWARD_L3);
    m_device->m_l3_destinations[lpm_dest_id.val] = m_device->get_sptr(this);

    m_resolution_data.fec_impl = fec;

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacific::populate_stage3_lb_value(npl_stage3_lb_table_value_t& out_value) const
{
    la_l3_port_wptr l3_port;
    la_status status = m_next_hop_common.get_router_port(l3_port);
    return_on_error(status);

    bool is_l3_ac = (l3_port->type() == la_object::object_type_e::L3_AC_PORT);
    bool lp_queueing = false;
    bool is_aggregate = false;

    la_l3_destination_gid_t l3_dlp_gid = l3_port->get_gid();
    la_l2_port_gid_t dest_gid = LA_L2_PORT_GID_INVALID;
    npl_resolution_dlp_attributes_t res_dlp_attr;
    npl_stage3_lb_entry_type_e type;

    npl_npu_encap_header_l3_dlp_t l3_dlp_encap = get_l3_dlp_encap(l3_dlp_gid);

    memset(&res_dlp_attr, 0, sizeof(res_dlp_attr));

    if (is_l3_ac == true) {
        const auto& port = l3_port.weak_ptr_static_cast<const la_l3_ac_port_impl>();
        lp_queueing = port->is_lp_queueing_enabled();
        if (lp_queueing) {
            la_bvn_profile_t bvn_profile;
            status = port->get_bvn_profile(bvn_profile);
            return_on_error(status);
            res_dlp_attr.bvn_profile.unpack(bvn_profile);
        }
        is_aggregate = port->is_aggregate();
    }

    if (lp_queueing && !is_aggregate) {
        destination_id id = (silicon_one::get_destination_id(l3_port, RESOLUTION_STEP_STAGE3_LB));
        dest_gid = id.val;
        type = NPL_STAGE3_LB_ENTRY_TYPE_STAGE3_LB_BVN_L3_DLP_DLP_ATTR;
    } else {
        status = get_dsp_or_dspa(dest_gid, is_aggregate);
        return_on_error(status);
        type = is_aggregate ? NPL_STAGE3_LB_ENTRY_TYPE_STAGE3_LB_DSPA_L3_DLP_DLP_ATTR
                            : NPL_STAGE3_LB_ENTRY_TYPE_STAGE3_LB_DSP_L3_DLP_DLP_ATTR;
    }

    bool monitor = false;
    status = l3_port->get_egress_sflow_enabled(monitor);
    return_on_error(status);
    res_dlp_attr.monitor = monitor ? 1 : 0;
    uint64_t dlp_attr = res_dlp_attr.pack().get_value();

    switch (type) {
    case NPL_STAGE3_LB_ENTRY_TYPE_STAGE3_LB_BVN_L3_DLP_DLP_ATTR:
        out_value.payloads.stage3_lb_result.bvn_l3_dlp_dlp_attr.type = type;
        out_value.payloads.stage3_lb_result.bvn_l3_dlp_dlp_attr.bvn = dest_gid;
        out_value.payloads.stage3_lb_result.bvn_l3_dlp_dlp_attr.l3_dlp = l3_dlp_encap.pack().get_value();
        out_value.payloads.stage3_lb_result.bvn_l3_dlp_dlp_attr.dlp_attr = dlp_attr;
        break;
    case NPL_STAGE3_LB_ENTRY_TYPE_STAGE3_LB_DSP_L3_DLP_DLP_ATTR:
        out_value.payloads.stage3_lb_result.dsp_l3_dlp_dlp_attr.type = type;
        out_value.payloads.stage3_lb_result.dsp_l3_dlp_dlp_attr.dsp = dest_gid;
        out_value.payloads.stage3_lb_result.dsp_l3_dlp_dlp_attr.l3_dlp = l3_dlp_encap.pack().get_value();
        out_value.payloads.stage3_lb_result.dsp_l3_dlp_dlp_attr.dlp_attr = dlp_attr;
        break;
    case NPL_STAGE3_LB_ENTRY_TYPE_STAGE3_LB_DSPA_L3_DLP_DLP_ATTR:
        out_value.payloads.stage3_lb_result.dspa_l3_dlp_dlp_attr.type = type;
        out_value.payloads.stage3_lb_result.dspa_l3_dlp_dlp_attr.dspa = dest_gid;
        out_value.payloads.stage3_lb_result.dspa_l3_dlp_dlp_attr.l3_dlp = l3_dlp_encap.pack().get_value();
        out_value.payloads.stage3_lb_result.dspa_l3_dlp_dlp_attr.dlp_attr = dlp_attr;
        break;
    default:
        return LA_STATUS_EUNKNOWN;
    }
    return LA_STATUS_SUCCESS;
}
la_status
la_next_hop_pacific::configure_resolution_step_stage3_lb(nh_type_e nh_type)
{
    npl_stage3_lb_table_key_t key;
    npl_stage3_lb_table_value_t value;
    la_status status = LA_STATUS_SUCCESS;

    if (nh_type == nh_type_e::NORMAL) {
        status = populate_stage3_lb_value(value);
        return_on_error(status);
    } else {
        npl_nh_type_e npl_nh_type = la_2_npl_nh_type(nh_type);
        la_l2_port_gid_t dest_gid = NPL_DESTINATION_MASK_GLEAN | static_cast<la_l2_port_gid_t>(npl_nh_type);
        la_l3_destination_gid_t l3_dest_gid = LA_L3_DESTINATION_GID_INVALID;
        value.payloads.stage3_lb_result.destination_l3_dlp.type = NPL_STAGE3_LB_ENTRY_TYPE_STAGE3_LB_DESTINATION_L3_DLP;
        value.payloads.stage3_lb_result.destination_l3_dlp.l3_dlp = l3_dest_gid;
        value.payloads.stage3_lb_result.destination_l3_dlp.destination = dest_gid;
    }

    key.member_id = 0;
    key.group_id = m_gid;
    value.action = NPL_STAGE3_LB_TABLE_ACTION_WRITE;

    // Write to table
    npl_stage3_lb_table_t::entry_wptr_type existing_entry_ptr;
    status = m_device->m_tables.stage3_lb_table->set(key, value, existing_entry_ptr);

    return status;
}

la_status
la_next_hop_pacific::configure_resolution_step_stage3_lb_group_size()
{
    // Configure stage3_lb_group_size_table
    npl_stage3_lb_group_size_table_t::key_type k;
    npl_stage3_lb_group_size_table_t::value_type v;

    // Set key
    k.stage3_lb_id = m_gid;

    // Set value
    v.action = NPL_STAGE3_LB_GROUP_SIZE_TABLE_ACTION_WRITE;
    v.payloads.stage3_lb_group_size_table_result.curr_group_size = 1;
    v.payloads.stage3_lb_group_size_table_result.consistency_mode = NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED;

    // Write to table
    npl_stage3_lb_group_size_table_t::entry_wptr_type existing_entry_ptr;
    la_status status = m_device->m_tables.stage3_lb_group_size_table->insert(k, v, existing_entry_ptr);

    return status;
}

la_status
la_next_hop_pacific::teardown_resolution_step_stage3_lb_group_size()
{
    // Configure stage3_lb_group_size_table
    npl_stage3_lb_group_size_table_t::key_type k;

    // Set key
    k.stage3_lb_id = m_gid;

    la_status status = m_device->m_tables.stage3_lb_group_size_table->erase(k);

    return status;
}

la_status
la_next_hop_pacific::uninstantiate(resolution_step_e prev_step)
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (cur_step == RESOLUTION_STEP_INVALID) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    m_resolution_data.users_for_step[cur_step]--;

    if (m_resolution_data.users_for_step[cur_step] > 0) {
        return LA_STATUS_SUCCESS;
    }

    return teardown_resolution_step(cur_step);
}

la_status
la_next_hop_pacific::teardown_resolution_step(resolution_step_e res_step)
{
    switch (res_step) {
    case RESOLUTION_STEP_NATIVE_FEC: {
        return teardown_resolution_step_native_fec();
    }
    case RESOLUTION_STEP_STAGE3_LB: {
        return LA_STATUS_SUCCESS; // Next-hop teardown in the Stage3_LB table is done on initilalize
    }
    default: {
        return LA_STATUS_EUNKNOWN;
    }
    }
}

la_status
la_next_hop_pacific::teardown_resolution_step_native_fec()
{
    if (m_resolution_data.fec_impl == nullptr) {
        return LA_STATUS_EUNKNOWN;
    }

    lpm_destination_id lpm_dest_id = silicon_one::get_lpm_destination_id(m_resolution_data.fec_impl, RESOLUTION_STEP_FORWARD_L3);
    la_status status = m_device->destroy_l3_fec_wrapper(m_resolution_data.fec_impl);
    return_on_error(status);

    m_device->m_l3_destinations[lpm_dest_id.val] = nullptr;
    m_resolution_data.fec_impl = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacific::teardown_resolution_step_stage3_lb()
{
    // Configure stage3_lb_table
    npl_stage3_lb_table_t::key_type k;

    // Set key
    k.group_id = m_gid;
    k.member_id = 0;

    la_status status = m_device->m_tables.stage3_lb_table->erase(k);

    return status;
}

resolution_step_e
la_next_hop_pacific::get_next_resolution_step(resolution_step_e prev_step) const
{
    if (prev_step == RESOLUTION_STEP_FORWARD_L3) {
        return RESOLUTION_STEP_NATIVE_FEC;
    }

    if ((prev_step == RESOLUTION_STEP_NATIVE_FEC) || (prev_step == RESOLUTION_STEP_NATIVE_LB)
        || (prev_step == RESOLUTION_STEP_NATIVE_CE_PTR)
        || (prev_step == RESOLUTION_STEP_FORWARD_MPLS)
        || (prev_step == RESOLUTION_STEP_PATH_LP)
        || (prev_step == RESOLUTION_STEP_NATIVE_L2_LP)
        || (prev_step == RESOLUTION_STEP_STAGE2_LB)) {
        return RESOLUTION_STEP_STAGE3_LB;
    }

    return RESOLUTION_STEP_INVALID;
}

resolution_table_index
la_next_hop_pacific::get_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_STAGE3_LB: {
        la_next_hop_gid_t gid = get_gid();
        return resolution_table_index(gid);
    }
    default:
        return RESOLUTION_TABLE_INDEX_INVALID;
    }
}

lpm_destination_id
la_next_hop_pacific::get_lpm_destination_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (m_resolution_data.users_for_step[cur_step] == 0) {
        return LPM_DESTINATION_ID_INVALID;
    }

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_NATIVE_FEC: {
        lpm_destination_id lpm_dest_id = silicon_one::get_lpm_destination_id(m_resolution_data.fec_impl, prev_step);
        return lpm_dest_id;
    }

    default: {
        return LPM_DESTINATION_ID_INVALID;
    }
    }
}

destination_id
la_next_hop_pacific::get_destination_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (m_resolution_data.users_for_step[cur_step] == 0) {
        return DESTINATION_ID_INVALID;
    }

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_NATIVE_FEC: {
        return silicon_one::get_destination_id(m_resolution_data.fec_impl, prev_step);
    }

    case silicon_one::RESOLUTION_STEP_STAGE3_LB: {
        la_next_hop_gid_t id = get_gid();
        return destination_id(NPL_DESTINATION_MASK_STAGE3_NH | id);
    }

    default: {
        return DESTINATION_ID_INVALID;
    }
    }
}

la_next_hop_pacific::resolution_data::resolution_data()
{
    for (resolution_step_e res_step = RESOLUTION_STEP_FIRST; res_step < RESOLUTION_STEP_LAST;
         res_step = (resolution_step_e)(res_step + 1)) {
        users_for_step[res_step] = 0;
    }

    fec_impl = nullptr;
}

la_status
la_next_hop_pacific::modify_mac_move_dsp_or_dspa()
{
    la_status status;
    la_l2_service_port_base_wcptr l2_port_wcptr = m_l2_port;
    bool is_flood = is_recycle_ac(l2_port_wcptr);

    if (is_flood) {
        // if transition out of flood, configure DSP first and nh_payload next
        status = configure_resolution_step_stage3_lb(m_nh_type);
        return_on_error(status);
        status = update_global_tx_tables();
        return_on_error(status);
    } else {
        // configure nh_payload first and DSP next
        la_status status = update_global_tx_tables();
        return_on_error(status);
        status = configure_resolution_step_stage3_lb(m_nh_type);
        return_on_error(status);
    }

    status = modify_nh_l2_port();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacific::get_lb_resolution(const la_lb_pak_fields_vec& lb_vector, size_t& member, const la_object*& out_object) const
{
    la_status status = LA_STATUS_SUCCESS;
    resolution_step_e step = RESOLUTION_STEP_STAGE3_LB;

    if (m_resolution_data.users_for_step[step] == 0) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    npl_stage3_lb_group_size_table_t::key_type k;
    npl_stage3_lb_group_size_table_t::value_type v;
    npl_stage3_lb_group_size_table_t::entry_pointer_type group_existing_entry_ptr = nullptr;

    k.stage3_lb_id = m_gid;

    status = m_device->m_tables.stage3_lb_group_size_table->lookup(k, group_existing_entry_ptr);
    return_on_error(status);

    v = group_existing_entry_ptr->value();
    size_t group_size = v.payloads.stage3_lb_group_size_table_result.curr_group_size;
    npl_lb_consistency_mode_e consistency_mode = v.payloads.stage3_lb_group_size_table_result.consistency_mode;
    size_t member_id = 0;
    uint16_t seed;
    uint16_t shift_amount;
    m_device->get_ecmp_hash_seed(seed);
    m_device->get_lb_hash_shift_amount(shift_amount);

    status = do_lb_resolution(lb_vector, group_size, consistency_mode, step, seed, shift_amount, member_id);
    return_on_error(status);

    member = member_id;

    //
    // Always single member as per current implementation, so we are not decoding
    // based on the LB table.  We use it just to check entry existance.
    //

    npl_stage3_lb_table_key_t key;
    npl_stage3_lb_table_value_t value;
    npl_stage3_lb_table_t::entry_pointer_type existing_entry_ptr = nullptr;

    key.member_id = member_id;
    key.group_id = m_gid;

    status = m_device->m_tables.stage3_lb_table->lookup(key, existing_entry_ptr);
    return_on_error(status);

    if (existing_entry_ptr) {
        value = existing_entry_ptr->value();

        if (m_nh_type == nh_type_e::NORMAL) {
            if ((value.payloads.stage3_lb_result.dspa_l3_dlp_dlp_attr.type
                 == NPL_STAGE3_LB_ENTRY_TYPE_STAGE3_LB_DSPA_L3_DLP_DLP_ATTR)
                && (value.payloads.stage3_lb_result.dspa_l3_dlp_dlp_attr.dspa)) {
                out_object = m_device->m_spa_ports[value.payloads.stage3_lb_result.dspa_l3_dlp_dlp_attr.dspa].get();
            } else if ((value.payloads.stage3_lb_result.dsp_l3_dlp_dlp_attr.type
                        == NPL_STAGE3_LB_ENTRY_TYPE_STAGE3_LB_DSP_L3_DLP_DLP_ATTR)
                       && (value.payloads.stage3_lb_result.dsp_l3_dlp_dlp_attr.dsp)) {
                out_object = m_device->m_system_ports[value.payloads.stage3_lb_result.dsp_l3_dlp_dlp_attr.dsp].get();
            } else {
                return LA_STATUS_ENOTIMPLEMENTED;
            }
        } else {
            //
            // GLEAN/DROP/NULL NH destination
            //
            // Should not reach here!
            //
            return LA_STATUS_ENOTIMPLEMENTED;
        }
    }

    return status;
}

} // namespace silicon_one
