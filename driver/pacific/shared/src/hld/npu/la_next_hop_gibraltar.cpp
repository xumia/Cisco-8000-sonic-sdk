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

#include "la_next_hop_gibraltar.h"
#include "api/npu/la_l3_port.h"
#include "nplapi/npl_constants.h"
#include "nplapi/nplapi_tables.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_l3_fec_impl.h"
#include "npu/la_next_hop_impl_common.h"
#include "npu/la_svi_port_base.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_next_hop_gibraltar::la_next_hop_gibraltar(la_device_impl_wptr device) : la_next_hop_pacgb(device)
{
}

la_next_hop_gibraltar::~la_next_hop_gibraltar() = default;

la_status
la_next_hop_gibraltar::populate_nh_payload_l2_info(npl_nh_payload_t& out_nh_payload,
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
        const auto& svi_port = l3_port.weak_ptr_static_cast<la_svi_port_base>();
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
la_next_hop_gibraltar::populate_nh_payload(npl_nh_payload_t& out_nh_payload,
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
la_next_hop_gibraltar::populate_nh_and_svi_payload(npl_nh_and_svi_payload_t& out_nh_and_svi_payload,
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
la_next_hop_gibraltar::initialize(la_object_id_t oid,
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

    status = configure_resolution_step_stage2(nh_type);
    return_on_error(status);

    if (port != nullptr) {
        m_device->add_object_dependency(port, this);
        m_device->add_ifg_dependency(port, this);
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::VOQ_CHANGED
                                         | (la_uint64_t)attribute_management_op::EGRESS_VLAN_TAG_CHANGED
                                         | (la_uint64_t)attribute_management_op::EGRESS_SFLOW_CHANGED
                                         | (la_uint64_t)attribute_management_op::REMOTE_VOQ_CHANGED);
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
la_next_hop_gibraltar::notify_change(dependency_management_op op)
{
    la_status status = LA_STATUS_SUCCESS;
    switch (op.type_e) {
    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        switch (op.action.attribute_management.op) {
        case attribute_management_op::VOQ_CHANGED:
        case attribute_management_op::EGRESS_SFLOW_CHANGED:
        case attribute_management_op::REMOTE_VOQ_CHANGED:
            status = configure_resolution_step_stage2(m_nh_type);
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
la_next_hop_gibraltar::get_resolution_cfg_handle(const resolution_cfg_handle_t*& out_cfg_handle) const
{
    out_cfg_handle = &m_resolution_data.cfg_handle;
    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_gibraltar::destroy()
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
                                         | (la_uint64_t)attribute_management_op::EGRESS_SFLOW_CHANGED
                                         | (la_uint64_t)attribute_management_op::REMOTE_VOQ_CHANGED);
        m_device->remove_attribute_dependency(port, this, registered_attributes);
        m_device->remove_ifg_dependency(port, this);
        m_device->remove_object_dependency(port, this);
    }

    status = m_next_hop_common.destroy();
    return_on_error(status);

    status = teardown_resolution_step_stage2();
    return_on_error(status);

    return status;
}

la_status
la_next_hop_gibraltar::set_nh_type(nh_type_e nh_type)
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

    status = configure_resolution_step_stage2(nh_type);
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
                                         | (la_uint64_t)attribute_management_op::EGRESS_SFLOW_CHANGED
                                         | (la_uint64_t)attribute_management_op::REMOTE_VOQ_CHANGED);
        m_device->remove_attribute_dependency(port, this, registered_attributes);
        m_device->remove_ifg_dependency(port, this);
        m_device->remove_object_dependency(port, this);
    }

    m_nh_type = nh_type;

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_gibraltar::get_fec_table_value(npl_fec_table_value_t& value, npl_destination_t& rpf_fec_table_dest) const
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

    npl_fec_destination1_t& destination(value.payloads.resolution_fec_result.fec_dest1);

    destination.type = NPL_ENTRY_TYPE_FEC_DESTINATION1;
    destination.destination = destination_id(NPL_DESTINATION_MASK_L3_NH | m_gid).val;
    destination.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH;

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_gibraltar::instantiate(resolution_step_e prev_step)
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
la_next_hop_gibraltar::configure_resolution_step(resolution_step_e res_step)
{
    switch (res_step) {
    case RESOLUTION_STEP_FEC: {
        return configure_resolution_step_fec();
    }
    case RESOLUTION_STEP_STAGE2_NH: {
        return LA_STATUS_SUCCESS; // Next-hop configuration in the Stage3_LB table is done on initilalize
    }
    default: {
        return LA_STATUS_EUNKNOWN;
    }
    }
}

la_status
la_next_hop_gibraltar::configure_resolution_step_fec()
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
la_next_hop_gibraltar::configure_resolution_step_stage2(nh_type_e nh_type)
{
    npl_resolution_stage_assoc_data_wide_entry_t entry = {{0}};
    la_status status = LA_STATUS_SUCCESS;

    if (nh_type == nh_type_e::NORMAL) {
        auto l3_port = m_next_hop_common.get_l3_port();
        la_l3_destination_gid_t l3_dlp_gid = l3_port->get_gid();
        npl_npu_encap_header_l3_dlp_t l3_dlp_encap = get_l3_dlp_encap(l3_dlp_gid);
        bool is_l3_ac = (l3_port->type() == la_object::object_type_e::L3_AC_PORT);
        bool is_aggregate = false;
        la_l2_port_gid_t dest_gid = LA_L2_PORT_GID_INVALID;
        npl_resolution_dlp_attributes_t res_dlp_attr;
        memset(&res_dlp_attr, 0, sizeof(res_dlp_attr));

        if (is_l3_ac) {
            const auto& port = l3_port.weak_ptr_static_cast<const la_l3_ac_port_impl>();
            bool lp_queueing = port->is_lp_queueing_enabled();
            if (lp_queueing) {
                /* Qos Enabled on l3ac */
                destination_id id = (silicon_one::get_destination_id(port, RESOLUTION_STEP_STAGE2_NH));
                dest_gid = id.val;

                la_bvn_profile_t bvn_profile;
                status = port->get_bvn_profile(bvn_profile);
                return_on_error(status);
                res_dlp_attr.bvn_profile.unpack(bvn_profile);
            } else {
                is_aggregate = port->is_aggregate();
                status = get_dsp_or_dspa(dest_gid, is_aggregate);
                return_on_error(status);
            }
        } else {
            // SVI
            status = get_dsp_or_dspa(dest_gid, is_aggregate);
            return_on_error(status);
        }

        bool monitor = false;
        status = l3_port->get_egress_sflow_enabled(monitor);
        return_on_error(status);
        res_dlp_attr.monitor = monitor ? 1 : 0;
        uint64_t dlp_attr = res_dlp_attr.pack().get_value();

        entry.stage2_l3_nh_dlp_bvn_profile.type = NPL_ENTRY_TYPE_STAGE2_L3_NH_DESTINATION_L3_DLP_DLP_ATTR;
        entry.stage2_l3_nh_dlp_bvn_profile.destination = dest_gid;
        entry.stage2_l3_nh_dlp_bvn_profile.l3_dlp = l3_dlp_encap.pack().get_value();
        entry.stage2_l3_nh_dlp_bvn_profile.dlp_attr = dlp_attr;
    } else {
        npl_nh_type_e npl_nh_type = la_2_npl_nh_type(nh_type);
        la_l3_destination_gid_t l3_dest_gid = LA_L3_DESTINATION_GID_INVALID;

        entry.stage2_l3_nh_dlp.type = NPL_ENTRY_TYPE_STAGE2_L3_NH_DESTINATION_L3_DLP;
        entry.stage2_l3_nh_dlp.destination = NPL_DESTINATION_MASK_GLEAN | static_cast<la_l2_port_gid_t>(npl_nh_type);
        entry.stage2_l3_nh_dlp.l3_dlp = l3_dest_gid;
    }

    status = m_device->m_resolution_configurators[2].configure_dest_map_entry(
        destination_id(NPL_DESTINATION_MASK_L3_NH | get_gid()), entry, m_resolution_data.cfg_handle);
    return status;
}

la_status
la_next_hop_gibraltar::uninstantiate(resolution_step_e prev_step)
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
la_next_hop_gibraltar::teardown_resolution_step(resolution_step_e res_step)
{
    switch (res_step) {
    case RESOLUTION_STEP_FEC: {
        return teardown_resolution_step_fec();
    }
    case RESOLUTION_STEP_STAGE2_NH: {
        return LA_STATUS_SUCCESS; // Next-hop teardown is done on initilalize
    }
    default: {
        return LA_STATUS_EUNKNOWN;
    }
    }
}

la_status
la_next_hop_gibraltar::teardown_resolution_step_fec()
{
    if (m_resolution_data.fec_impl == nullptr) {
        return LA_STATUS_EUNKNOWN;
    }

    lpm_destination_id lpm_dest_id = silicon_one::get_lpm_destination_id(m_resolution_data.fec_impl, RESOLUTION_STEP_FORWARD_L3);
    la_status status = m_device->destroy_l3_fec_wrapper(m_resolution_data.fec_impl);
    return_on_error(status);

    m_device->m_l3_destinations[lpm_dest_id.val] = nullptr;
    m_resolution_data.fec_impl = nullptr; // Release the shared-ptr

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_gibraltar::teardown_resolution_step_stage2()
{
    return m_device->m_resolution_configurators[2].unconfigure_entry(m_resolution_data.cfg_handle);
}

resolution_step_e
la_next_hop_gibraltar::get_next_resolution_step(resolution_step_e prev_step) const
{
    if (prev_step == RESOLUTION_STEP_FORWARD_L3) {
        return RESOLUTION_STEP_FEC;
    }

    if ((prev_step == RESOLUTION_STEP_FEC) || (prev_step == RESOLUTION_STEP_STAGE0_ECMP)
        || (prev_step == RESOLUTION_STEP_STAGE0_L2_LP)
        || (prev_step == RESOLUTION_STEP_STAGE0_CE_PTR)
        || (prev_step == RESOLUTION_STEP_FORWARD_MPLS)
        || (prev_step == RESOLUTION_STEP_STAGE1_PROTECTION)
        || (prev_step == RESOLUTION_STEP_STAGE1_ECMP)
        || (prev_step == RESOLUTION_STEP_FORWARD_L2)) {
        return RESOLUTION_STEP_STAGE2_NH;
    }

    dassert_crit(false);
    return RESOLUTION_STEP_INVALID;
}

resolution_table_index
la_next_hop_gibraltar::get_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_STAGE2_NH: {
        la_next_hop_gid_t gid = get_gid();
        return resolution_table_index(gid);
    }
    default:
        return RESOLUTION_TABLE_INDEX_INVALID;
    }
}

lpm_destination_id
la_next_hop_gibraltar::get_lpm_destination_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (m_resolution_data.users_for_step[cur_step] == 0) {
        return LPM_DESTINATION_ID_INVALID;
    }

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_FEC: {
        lpm_destination_id lpm_dest_id = silicon_one::get_lpm_destination_id(m_resolution_data.fec_impl, prev_step);
        return lpm_dest_id;
    }

    default: {
        return LPM_DESTINATION_ID_INVALID;
    }
    }
}

destination_id
la_next_hop_gibraltar::get_destination_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (m_resolution_data.users_for_step[cur_step] == 0) {
        return DESTINATION_ID_INVALID;
    }

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_FEC: {
        return silicon_one::get_destination_id(m_resolution_data.fec_impl, prev_step);
    }

    case silicon_one::RESOLUTION_STEP_STAGE2_NH: {
        la_next_hop_gid_t id = get_gid();
        return destination_id(NPL_DESTINATION_MASK_L3_NH | id);
    }

    default: {
        return DESTINATION_ID_INVALID;
    }
    }
}

la_next_hop_gibraltar::resolution_data::resolution_data()
{
    for (resolution_step_e res_step = RESOLUTION_STEP_FIRST; res_step < RESOLUTION_STEP_LAST;
         res_step = (resolution_step_e)(res_step + 1)) {
        users_for_step[res_step] = 0;
    }

    fec_impl = nullptr;
}

la_status
la_next_hop_gibraltar::modify_mac_move_dsp_or_dspa()
{
    la_status status;
    la_l2_service_port_base_wcptr l2_port_wcptr = m_l2_port;
    bool is_flood = is_recycle_ac(l2_port_wcptr);

    if (is_flood) {
        // if transition out of flood, configure DSP first and nh_payload next
        status = configure_resolution_step_stage2(m_nh_type);
        return_on_error(status);
        status = update_global_tx_tables();
        return_on_error(status);
    } else {
        // configure nh_payload first and DSP next
        la_status status = update_global_tx_tables();
        return_on_error(status);
        status = configure_resolution_step_stage2(m_nh_type);
        return_on_error(status);
    }

    status = modify_nh_l2_port();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_gibraltar::get_lb_resolution(const la_lb_pak_fields_vec& lb_vector, size_t& member, const la_object*& out_object) const
{
    if (m_nh_type != nh_type_e::NORMAL) {
        //
        // GLEAN/DROP/NULL NH destination
        //
        // Should not reach here!
        //
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    auto l3_port = m_next_hop_common.get_l3_port();
    la_l2_destination_wcptr l2_dest;
    la_status status = get_l2_destination(l3_port, m_mac_addr, l2_dest);
    return_on_error(status);

    la_ethernet_port_wcptr ep;
    status = get_underlying_ethernet_port(l2_dest, ep);
    return_on_error(status);

    const auto& epi = ep.weak_ptr_static_cast<const la_ethernet_port_base>();
    out_object = epi->get_underlying_port();

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
