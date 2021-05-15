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

#include "la_prefix_object_pacific.h"
#include "nplapi/npl_constants.h"
#include "npu/la_ecmp_group_impl.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_te_tunnel_impl.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "npu/counter_utils.h"

#include <sstream>

namespace silicon_one
{

la_prefix_object_pacific::la_prefix_object_pacific(const la_device_impl_wptr& device) : la_prefix_object_base(device)
{
}

la_prefix_object_pacific::~la_prefix_object_pacific()
{
}

resolution_step_e
la_prefix_object_pacific::get_next_resolution_step(resolution_step_e prev_step) const
{
    if (prev_step == RESOLUTION_STEP_FORWARD_L3) {
        return RESOLUTION_STEP_NATIVE_CE_PTR;
    }

    if (prev_step == RESOLUTION_STEP_FORWARD_L2) {
        return RESOLUTION_STEP_NATIVE_CE_PTR;
    }

    if (prev_step == RESOLUTION_STEP_FORWARD_MPLS) {
        return RESOLUTION_STEP_NATIVE_CE_PTR;
    }

    if (prev_step == RESOLUTION_STEP_NATIVE_FEC) {
        return RESOLUTION_STEP_NATIVE_CE_PTR;
    }

    if (prev_step == RESOLUTION_STEP_NATIVE_LB) {
        return RESOLUTION_STEP_NATIVE_CE_PTR;
    }

    return RESOLUTION_STEP_INVALID;
}

destination_id
la_prefix_object_pacific::get_destination_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_NATIVE_CE_PTR: {
        return destination_id(NPL_DESTINATION_MASK_CE_PTR | (m_vpn_enabled << 17) | m_prefix_gid);
    }

    default: {
        return DESTINATION_ID_INVALID;
    }
    }
}

la_status
la_prefix_object_pacific::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    // Clear all entries
    auto tmp = m_mpls_em_entry_map;
    for (auto it : tmp) {
        const auto& nh = it.first;
        do_clear_nh_lsp_properties(nh);
    }

    remove_dependency(m_destination);

    la_status status = teardown_native_prefix_table();
    return_on_error(status);

    if (m_global_lsp_prefix_info.entry_present == true) {
        status = teardown_large_encap_global_lsp_prefix_table();
        return_on_error(status);
    }

    status = teardown_large_encap_mpls_he_no_ldp_table();
    return_on_error(status);

    status = teardown_per_pe_and_vrf_vpn_key_large_table();
    return_on_error(status);

    // Clear all entries
    auto te_em_map = m_te_pfx_obj_em_entry_map;
    for (auto it : te_em_map) {
        const auto& te = it.first;
        do_clear_te_tunnel_lsp_properties(te);
    }

    status = uninstantiate_resolution_object(m_destination, RESOLUTION_STEP_NATIVE_CE_PTR);
    return status;
}

la_status
la_prefix_object_pacific::get_fec_table_value(npl_native_fec_table_value_t& value)
{
    npl_native_fec_destination_t& destination(value.payloads.native_fec_table_result.destination);

    destination.type = NPL_NATIVE_FEC_ENTRY_TYPE_NATIVE_FEC_DESTINATION;
    destination.destination = get_destination_id(RESOLUTION_STEP_NATIVE_FEC).val;

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_pacific::set_destination(const la_l3_destination* destination)
{
    start_api_call("destination=", destination);

    if (m_destination == destination) {
        return LA_STATUS_SUCCESS;
    }

    const auto& destination_sptr = m_device->get_sptr(destination);
    if (m_global_lsp_prefix) {
        la_status status = validate_new_destination_for_global_lsp(destination_sptr);
        return_on_error(status);
    }

    const auto old_destination = m_destination;

    la_status status = update_destination(destination_sptr, m_global_lsp_prefix, false);
    return_on_error(status);

    status = uninstantiate_resolution_object(old_destination, RESOLUTION_STEP_NATIVE_CE_PTR);
    return_on_error(status);

    remove_dependency(old_destination);
    add_dependency(destination_sptr);

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_pacific::update_destination(const la_l3_destination_wcptr& destination, bool is_global, bool is_init)
{
    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_object::object_type_e dest_type = destination->type();
    if (!((dest_type == object_type_e::NEXT_HOP) || (dest_type == object_type_e::TE_TUNNEL)
          || (dest_type == object_type_e::ECMP_GROUP)
          || (dest_type == object_type_e::L3_PROTECTION_GROUP)
          || (dest_type == object_type_e::MULTICAST_PROTECTION_GROUP))) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (is_global && (dest_type != object_type_e::ECMP_GROUP && dest_type != object_type_e::NEXT_HOP)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (dest_type == object_type_e::ECMP_GROUP) {
        const auto& ecmp_group = destination.weak_ptr_static_cast<const la_ecmp_group_impl>();
        if (ecmp_group->get_ecmp_level() != la_ecmp_group::level_e::LEVEL_2) {
            return LA_STATUS_EINVAL;
        }
    }

    la_device_impl::resolution_lp_table_format_e format = (dest_type == object_type_e::TE_TUNNEL)
                                                              ? la_device_impl::resolution_lp_table_format_e::WIDE
                                                              : la_device_impl::resolution_lp_table_format_e::NARROW;

    la_status status = m_device->validate_destination_gid_format_match(format, m_prefix_gid, is_init);
    return_on_error(status);

    m_global_lsp_prefix = is_global;

    status = instantiate_resolution_object(destination, RESOLUTION_STEP_NATIVE_CE_PTR, m_device->get_sptr(this));
    return_on_error(status);

    if (!is_init) {
        status = m_device->clear_destination_gid_format(m_prefix_gid);
        return_on_error(status);
    }

    status = m_device->update_destination_gid_format(format, m_prefix_gid);
    return_on_error(status);

    m_destination = destination;

    status = configure_native_prefix_table();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

void
la_prefix_object_pacific::register_attribute_dependency(const la_l3_destination_wcptr& destination)
{
    bit_vector64_t registered_attributes((la_uint64_t)attribute_management_op::TE_TUNNEL_DESTINATION_CHANGED);
    if (destination->type() == object_type_e::TE_TUNNEL) {
        m_device->add_attribute_dependency(destination, m_device->get_sptr(this), registered_attributes);
    }
}

void
la_prefix_object_pacific::deregister_attribute_dependency(const la_l3_destination_wcptr& destination)
{
    bit_vector64_t registered_attributes((la_uint64_t)attribute_management_op::TE_TUNNEL_DESTINATION_CHANGED);
    if (destination->type() == object_type_e::TE_TUNNEL) {
        m_device->remove_attribute_dependency(destination, m_device->get_sptr(this), registered_attributes);
    }
}

la_status
la_prefix_object_pacific::update_dependent_attributes(dependency_management_op op)
{
    switch (op.action.attribute_management.op) {
    case (attribute_management_op::TE_TUNNEL_DESTINATION_CHANGED): {
        la_status status = configure_native_prefix_table();
        return_on_error(status);
    } break;
    default:
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_pacific::do_clear_nh_lsp_properties(const la_next_hop_wcptr& nh)
{
    transaction txn;

    if (nh == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(nh, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const auto& next_hop = nh.weak_ptr_static_cast<const la_next_hop_base>();

    auto mpls_em_map_entry_it = m_mpls_em_entry_map.find(next_hop);
    if (mpls_em_map_entry_it == m_mpls_em_entry_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    if (mpls_em_map_entry_it->second.use_count != 0) {
        return LA_STATUS_EBUSY;
    }

    for (auto pair_idx : get_slice_pairs(next_hop)) {
        txn.status = teardown_large_encap_mpls_he_no_ldp_table_entry(pair_idx, next_hop);
        return_on_error(txn.status);
        txn.on_fail([=]() {
            configure_large_encap_mpls_he_no_ldp_table(
                pair_idx, next_hop, mpls_em_map_entry_it->second.labels, mpls_em_map_entry_it->second.counter);
        });
    }

    // Remove the nh from the current counter
    txn.status = release_counter(next_hop, mpls_em_map_entry_it->second.counter);
    return_on_error(txn.status);

    m_mpls_em_entry_map.erase(mpls_em_map_entry_it);

    auto pair_it = m_prefix_nh_pairs.find(next_hop);
    dassert_crit(pair_it != m_prefix_nh_pairs.end());
    auto pair_obj = pair_it->second;
    txn.status = pair_obj->destroy();
    return_on_error(txn.status);
    m_prefix_nh_pairs.erase(pair_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_pacific::do_set_nh_lsp_properties(const la_next_hop_wcptr& nh,
                                                   const la_mpls_label_vec_t& labels,
                                                   const la_counter_set_wptr& counter,
                                                   lsp_counter_mode_e counter_mode)
{
    transaction txn;

    if (nh == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(nh, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if ((counter != nullptr) && (!of_same_device(counter, this))) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const auto& next_hop = nh.weak_ptr_static_cast<const la_next_hop_base>();
    la_counter_set_wptr curr_counter;
    lsp_counter_mode_e curr_counter_mode = lsp_counter_mode_e::LABEL;

    bool is_new_nh = false;
    auto mpls_em_map_entry_it = m_mpls_em_entry_map.find(next_hop);
    if (mpls_em_map_entry_it == m_mpls_em_entry_map.end()) {
        curr_counter = nullptr;
        is_new_nh = true;
    } else {
        auto& map_entry = mpls_em_map_entry_it->second;
        curr_counter = map_entry.counter;
        curr_counter_mode = map_entry.counter_mode;
    }

    if (curr_counter != counter) {
        // Add the new counter for the Prefix NH
        txn.status = allocate_counter(next_hop, counter, counter_mode, COUNTER_DIRECTION_EGRESS);
        return_on_error(txn.status);
        txn.on_fail([=]() { release_counter(next_hop, counter); });
    } else if (counter && (counter_mode != curr_counter_mode)) {
        return LA_STATUS_EINVAL;
    }

    // Update the tables with the new labels/counter
    for (auto pair_idx : get_slice_pairs(next_hop)) {
        txn.status = configure_large_encap_mpls_he_no_ldp_table(pair_idx, next_hop, labels, counter);
        return_on_error(txn.status);
        txn.on_fail([=]() { teardown_large_encap_mpls_he_no_ldp_table_entry(pair_idx, next_hop); });
    }

    mpls_em_info& entry_info = m_mpls_em_entry_map[next_hop];
    if (entry_info.ifgs == nullptr) {
        entry_info.ifgs = std::make_shared<ifg_use_count>(m_device->get_slice_id_manager());
    }
    if (entry_info.use_count != 0) {
        // Update the tables with the new labels/counter
        for (auto pair_idx : get_slice_pairs(next_hop)) {
            txn.status = configure_small_encap_mpls_he_asbr_table(pair_idx, next_hop, labels, counter);
            return_on_error(txn.status);
            txn.on_fail([=]() { teardown_small_encap_mpls_he_asbr_table_entry(pair_idx, next_hop); });
        }
    }

    if (curr_counter != counter) {
        // Remove the nh from the current counter
        txn.status = release_counter(next_hop, curr_counter);
        return_on_error(txn.status);
    }

    entry_info.labels = labels;
    entry_info.counter = counter;
    entry_info.counter_mode = counter_mode;

    if (is_new_nh) {
        dassert_crit(m_prefix_nh_pairs.find(next_hop) == m_prefix_nh_pairs.end());
        auto pair = std::make_shared<prefix_nh_pair>(m_device, m_device->get_sptr(this), next_hop, counter);
        auto status = pair->initialize();
        return_on_error(status);
        m_prefix_nh_pairs[next_hop] = pair;

        for (auto ifg : get_ifgs(next_hop)) {
            bool i, s, p; // dummy
            entry_info.ifgs->add_ifg_user(ifg, i, s, p);
        }
    } else {
        dassert_crit(m_prefix_nh_pairs.find(next_hop) != m_prefix_nh_pairs.end());
        m_prefix_nh_pairs[next_hop]->set_counter(counter);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_pacific::do_clear_vrf_properties(const la_vrf_wcptr& vrf, la_ip_version_e ip_version)
{
    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vrf, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const auto& vrf_impl = vrf.weak_ptr_static_cast<const la_vrf_impl>();

    auto vpn_map_entry_it = m_vpn_entry_map.find(vrf_impl);
    if (vpn_map_entry_it == m_vpn_entry_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    vpn_info& entry_info = m_vpn_entry_map[vrf_impl];

    if (ip_version == la_ip_version_e::IPV4) {
        if (entry_info.ipv4_valid == false) {
            return LA_STATUS_SUCCESS;
        }
        entry_info.ipv4_valid = false;
        entry_info.ipv4_labels.clear();
    } else {
        if (entry_info.ipv6_valid == false) {
            return LA_STATUS_SUCCESS;
        }
        entry_info.ipv6_valid = false;
        entry_info.ipv6_labels.clear();
    }

    if ((entry_info.ipv4_valid == false) && (entry_info.ipv6_valid == false)) {
        la_status status = teardown_per_pe_and_vrf_vpn_key_large_table_entry(vrf_impl);
        return_on_error(status);
        m_vpn_entry_map.erase(vpn_map_entry_it);
        m_device->remove_object_dependency(vrf, this);
    } else {
        if (ip_version == la_ip_version_e::IPV4) {
            auto labels = entry_info.ipv6_labels;
            la_status status = configure_per_pe_and_vrf_vpn_key_large_table(vrf_impl, la_ip_version_e::IPV6, entry_info, labels);
            return_on_error(status);
        } else {
            auto labels = entry_info.ipv4_labels;
            la_status status = configure_per_pe_and_vrf_vpn_key_large_table(vrf_impl, la_ip_version_e::IPV4, entry_info, labels);
            return_on_error(status);
        }
    }

    if (m_vpn_entry_map.empty()) {
        m_vpn_enabled = false;
        // Notify dependent objects to be reconfigured
        attribute_management_details amd;
        amd.op = attribute_management_op::PREFIX_OBJECT_VPN_PROPERTY_CHANGED;
        amd.l3_dest = this;
        la_amd_undo_callback_funct_t undo = [this](attribute_management_details amd) {
            m_vpn_enabled = true;
            return amd;
        };
        la_status status = m_device->notify_attribute_changed(this, amd, undo);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_pacific::do_set_vrf_properties(const la_vrf_wcptr& vrf,
                                                la_ip_version_e ip_version,
                                                const la_mpls_label_vec_t& labels)
{
    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vrf, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Check if the label stack has one VPN label.
    if (labels.size() != 1) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    const auto& vrf_impl = vrf.weak_ptr_static_cast<const la_vrf_impl>();

    auto vpn_map_entry_it = m_vpn_entry_map.find(vrf_impl);
    if (vpn_map_entry_it == m_vpn_entry_map.end()) {
        // Add vrf dependency only once
        m_device->add_object_dependency(vrf, this);
    }

    vpn_info& entry_info = m_vpn_entry_map[vrf_impl];
    if (ip_version == la_ip_version_e::IPV4) {
        entry_info.ipv4_labels = labels;
        entry_info.ipv4_valid = true;
    } else {
        entry_info.ipv6_labels = labels;
        entry_info.ipv6_valid = true;
    }

    // Update the tables with the new label
    la_status status = configure_per_pe_and_vrf_vpn_key_large_table(vrf_impl, ip_version, entry_info, labels);
    return_on_error(status);

    if (m_vpn_enabled == false) {
        m_vpn_enabled = true;
        // Notify dependent objects to be reconfigured
        attribute_management_details amd;
        amd.op = attribute_management_op::PREFIX_OBJECT_VPN_PROPERTY_CHANGED;
        amd.l3_dest = this;
        la_amd_undo_callback_funct_t undo = [this](attribute_management_details amd) {
            m_vpn_enabled = false;
            return amd;
        };
        status = m_device->notify_attribute_changed(this, amd, undo);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_pacific::configure_native_prefix_table()
{
    object_type_e type = m_destination->type();

    if ((type == object_type_e::NEXT_HOP) || (type == object_type_e::L3_PROTECTION_GROUP)) {
        la_status status = configure_native_ce_ptr_to_nh_or_protected_nh_value();
        return status;
    }
    if (type == object_type_e::ECMP_GROUP) {
        la_status status = configure_native_ce_ptr_to_ecmp_group_value();
        return status;
    }
    if (type == object_type_e::TE_TUNNEL) {
        la_status status = configure_native_ce_ptr_to_tenh_value();
        return status;
    }
    if (type == object_type_e::MULTICAST_PROTECTION_GROUP) {
        // Prefix object is used only for egress processing in the case of multicast protection
        return LA_STATUS_SUCCESS;
    }
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_prefix_object_pacific::configure_native_ce_ptr_to_nh_or_protected_nh_value()
{
    const auto& table(m_device->m_tables.native_ce_ptr_table);
    npl_native_ce_ptr_table_key_t key;
    npl_native_ce_ptr_table_value_t value_pfx;
    npl_native_ce_ptr_table_entry_t* entry = nullptr;
    destination_id prefix_destination_id = silicon_one::get_destination_id(m_destination, RESOLUTION_STEP_NATIVE_CE_PTR);

    key.ce_ptr = m_prefix_gid;

    value_pfx.action = NPL_NATIVE_CE_PTR_TABLE_ACTION_NARROW_ENTRY;
    value_pfx.payloads.narrow_entry.entry.destination2.destination = prefix_destination_id.val;
    value_pfx.payloads.narrow_entry.entry.destination2.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_DESTINATION2;

    la_status status = table->set(key, value_pfx, entry);

    return status;
}

la_status
la_prefix_object_pacific::configure_native_ce_ptr_to_tenh_value()
{
    const auto& table(m_device->m_tables.native_ce_ptr_table);
    npl_native_ce_ptr_table_key_t key;
    npl_native_ce_ptr_table_value_t value;
    npl_native_ce_ptr_table_entry_t* entry = nullptr;
    destination_id prefix_destination_id = silicon_one::get_destination_id(m_destination, RESOLUTION_STEP_NATIVE_CE_PTR);

    key.ce_ptr = m_prefix_gid;

    value.action = NPL_NATIVE_CE_PTR_TABLE_ACTION_WIDE_ENTRY;
    value.payloads.wide_entry.entry.destination_te_tunnel16b.destination = prefix_destination_id.val;
    const auto& te_tunnel_impl = m_destination.weak_ptr_static_cast<const la_te_tunnel_impl>();
    la_te_tunnel::tunnel_type_e type;
    la_status status = te_tunnel_impl->get_tunnel_type(type);
    return_on_error(status);
    if (type == la_te_tunnel::tunnel_type_e::LDP_ENABLED) {
        value.payloads.wide_entry.entry.destination_te_tunnel16b.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE;
    } else {
        value.payloads.wide_entry.entry.destination_te_tunnel16b.enc_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID;
    }
    value.payloads.wide_entry.entry.destination_te_tunnel16b.te_tunnel16b = te_tunnel_impl->get_gid();
    value.payloads.wide_entry.entry.destination_te_tunnel16b.type
        = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_DESTINATION_TE_TUNNEL16B;

    status = table->set(key, value, entry);

    return status;
}

la_status
la_prefix_object_pacific::configure_native_ce_ptr_to_ecmp_group_value()
{
    const auto& table(m_device->m_tables.native_ce_ptr_table);
    npl_native_ce_ptr_table_key_t key;
    npl_native_ce_ptr_table_value_t value_pfx;
    npl_native_ce_ptr_table_entry_t* entry = nullptr;
    destination_id prefix_destination_id = silicon_one::get_destination_id(m_destination, RESOLUTION_STEP_NATIVE_CE_PTR);

    key.ce_ptr = m_prefix_gid;

    value_pfx.action = NPL_NATIVE_CE_PTR_TABLE_ACTION_NARROW_ENTRY;
    value_pfx.payloads.narrow_entry.entry.destination1.destination = prefix_destination_id.val;
    value_pfx.payloads.narrow_entry.entry.destination1.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_DESTINATION1;

    la_status status = table->set(key, value_pfx, entry);

    return status;
}

la_status
la_prefix_object_pacific::teardown_native_prefix_table()
{
    if (m_destination->type() == object_type_e::MULTICAST_PROTECTION_GROUP) {
        // No native prefix is used for multicast protection
        return LA_STATUS_SUCCESS;
    }
    const auto& table(m_device->m_tables.native_ce_ptr_table);
    npl_native_ce_ptr_table_key_t key;

    key.ce_ptr = m_prefix_gid;

    la_status status = table->erase(key);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_pacific::configure_small_encap_mpls_he_asbr_table(la_slice_pair_id_t pair_idx,
                                                                   const la_next_hop_base_wcptr& nh,
                                                                   const la_mpls_label_vec_t& labels,
                                                                   const la_counter_set_wcptr& counter)
{
    const auto& table(m_device->m_tables.small_encap_mpls_he_asbr_table[pair_idx]);
    npl_small_encap_mpls_he_asbr_table_key_t key;
    npl_small_encap_mpls_he_asbr_table_value_t value;
    npl_small_encap_mpls_he_asbr_table_entry_t* out_entry = nullptr;
    auto nh_gid = nh->get_gid();

    lsp_configuration_params lsp_config = get_lsp_configuration_params(labels, counter);

    if (lsp_config.program_additional_labels_table) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (nh_gid >= la_device_impl::MAX_ASBR_LSP_DESTINATION_GID) {
        return LA_STATUS_EINVAL;
    }

    key.asbr = m_prefix_gid;
    key.nh_ptr = nh_gid;
    value.action = NPL_SMALL_ENCAP_MPLS_HE_ASBR_TABLE_ACTION_WRITE;

    prepare_lsp_table_payload(value.payloads.lsp_encap_mapping_data_payload_asbr, labels, pair_idx, counter, lsp_config, false, 0);

    la_status status = table->set(key, value, out_entry);
    return status;
}

} // namespace silicon_one
