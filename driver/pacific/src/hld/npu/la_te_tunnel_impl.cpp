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

#include "la_te_tunnel_impl.h"
#include "la_l3_ac_port_impl.h"
#include "la_l3_protection_group_impl.h"
#include "nplapi/npl_constants.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_svi_port_base.h"
#include "qos/la_egress_qos_profile_impl.h"
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

la_te_tunnel_impl::tunnel_nh_pair::tunnel_nh_pair(const la_device_impl_wptr& device,
                                                  const la_te_tunnel_impl_wptr& tunnel,
                                                  const la_next_hop_base_wcptr& nh,
                                                  const la_counter_set_wptr& counter)
    : m_device(device), m_tunnel(tunnel), m_nh(nh)
{
    m_counter = counter.weak_ptr_static_cast<la_counter_set_impl>();
}

la_te_tunnel_impl::tunnel_nh_pair::~tunnel_nh_pair()
{
}

la_status
la_te_tunnel_impl::tunnel_nh_pair::destroy()
{
    m_device->remove_ifg_dependency(m_nh, shared_from_this());
    m_device->remove_object_dependency(m_nh, m_tunnel);
    if (m_counter != nullptr) {
        m_device->remove_object_dependency(m_counter, m_tunnel);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::tunnel_nh_pair::initialize()
{
    m_device->add_ifg_dependency(m_nh, shared_from_this());
    m_device->add_object_dependency(m_nh, m_tunnel);
    if (m_counter != nullptr) {
        m_device->add_object_dependency(m_counter, m_tunnel);
    }
    return LA_STATUS_SUCCESS;
}

const la_device_impl_wptr&
la_te_tunnel_impl::tunnel_nh_pair::get_device() const
{
    return m_device;
}

void
la_te_tunnel_impl::tunnel_nh_pair::set_counter(const la_counter_set_wptr& counter)
{
    if (m_counter != nullptr) {
        m_device->remove_object_dependency(m_counter, m_tunnel);
    }

    if (counter != nullptr) {
        m_device->add_object_dependency(counter, m_tunnel);
    }

    m_counter = counter.weak_ptr_static_cast<la_counter_set_impl>();
}

la_status
la_te_tunnel_impl::tunnel_nh_pair::notify_change(dependency_management_op op)
{
    if (op.type_e != dependency_management_op::management_type_e::IFG_MANAGEMENT) {
        log_err(HLD,
                "la_te_tunnel_impl::tunnel_nh_pair::notify_change: received unsupported notification (%s)",
                silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }

    dassert_crit(op.dependee == m_nh);

    la_status status;
    if (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) {
        // Notify tunnel after counter
        if (m_counter != nullptr) {
            status = m_counter->notify_change(op);
            return_on_error(status);
        }

        return m_tunnel->notify_change(op);
    }

    // IFG_REMOVE - reverse order
    status = m_tunnel->notify_change(op);
    return_on_error(status);

    if (m_counter != nullptr) {
        return m_counter->notify_change(op);
    }

    return LA_STATUS_SUCCESS;
}

la_te_tunnel_impl::la_te_tunnel_impl(const la_device_impl_wptr& device)
    : m_device(device),
      m_te_tunnel_gid(LA_L3_DESTINATION_GID_INVALID),
      m_destination(nullptr),
      m_tunnel_type(la_te_tunnel::tunnel_type_e::NORMAL),
      m_ipv6_explicit_null_enabled(false)
{
}

la_te_tunnel_impl::~la_te_tunnel_impl()
{
}

const la_device*
la_te_tunnel_impl::get_device() const
{
    return m_device.get();
}

std::vector<la_slice_pair_id_t>
la_te_tunnel_impl::get_slice_pairs(const la_next_hop_base_wcptr& next_hop) const
{
    return next_hop->get_slice_pairs();
}

la_object::object_type_e
la_te_tunnel_impl::type() const
{
    return la_object::object_type_e::TE_TUNNEL;
}

std::string
la_te_tunnel_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_te_tunnel_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_te_tunnel_impl::oid() const
{
    return m_oid;
}

const la_l3_destination*
la_te_tunnel_impl::get_destination() const
{
    return m_destination.get();
}

la_te_tunnel_gid_t
la_te_tunnel_impl::get_gid() const
{
    return m_te_tunnel_gid;
}

destination_id
la_te_tunnel_impl::get_destination_id(resolution_step_e prev_step) const
{
    la_object::object_type_e dest_type = m_destination->type();

    if (dest_type == la_object::object_type_e::NEXT_HOP) {
        la_next_hop_base_wcptr next_hop = m_destination.weak_ptr_static_cast<const la_next_hop_base>();
        return next_hop->get_destination_id(prev_step);
    }

    if (dest_type == la_object::object_type_e::L3_PROTECTION_GROUP) {
        la_l3_protection_group_impl_wcptr l3_protection_group
            = m_destination.weak_ptr_static_cast<const la_l3_protection_group_impl>();
        return l3_protection_group->get_destination_id(prev_step);
    }

    return DESTINATION_ID_INVALID;
}

la_status
la_te_tunnel_impl::initialize(la_object_id_t oid,
                              la_te_tunnel_gid_t te_tunnel_gid,
                              const la_l3_destination_wcptr& destination,
                              la_te_tunnel::tunnel_type_e type)
{
    m_ifgs = make_unique<ifg_use_count>(m_device->get_slice_id_manager());

    m_oid = oid;
    la_object::object_type_e dest_type = destination->type();
    if (!((dest_type == la_object::object_type_e::NEXT_HOP) || (dest_type == la_object::object_type_e::L3_PROTECTION_GROUP)
          || (dest_type == la_object::object_type_e::ECMP_GROUP))) {
        return LA_STATUS_EINVAL;
    }

    m_te_tunnel_gid = te_tunnel_gid;
    m_destination = destination;
    m_tunnel_type = type;

    add_dependency(destination);

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    // Clear all entries
    auto tmp = m_te_em_entry_map;
    for (auto it : tmp) {
        const auto& nh = it.first;
        clear_nh_lsp_properties(nh.get());
    }

    m_device->remove_object_dependency(m_destination, this);

    la_status status = teardown_encap_te_he_all_nh();
    return_on_error(status);
    status = teardown_ldp_over_te_table();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::set_destination(const la_l3_destination* destination)
{
    start_api_call("destination=", destination);

    la_l3_destination_wcptr destination_sp = m_device->get_sptr(destination);

    if (destination_sp == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(destination_sp, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_destination == destination_sp) {
        return LA_STATUS_SUCCESS;
    }

    la_l3_destination_wcptr old_destination = m_destination;

    la_status status = instantiate_new_destination(destination_sp);
    return_on_error(status);

    m_destination = destination_sp;

    attribute_management_details amd;
    amd.op = attribute_management_op::TE_TUNNEL_DESTINATION_CHANGED;
    amd.l3_dest = this;
    la_amd_undo_callback_funct_t undo = [this, old_destination](attribute_management_details amd) {
        m_destination = old_destination;
        return amd;
    };
    status = m_device->notify_attribute_changed(this, amd, undo);
    return_on_error(status);

    status = uninstantiate_old_destination(old_destination);
    return_on_error(status);

    add_dependency(m_destination);
    remove_dependency(old_destination);

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::instantiate_new_destination(const la_l3_destination_wcptr& destination)
{
    for (resolution_step_e res_step = RESOLUTION_STEP_NATIVE_FEC; res_step < RESOLUTION_STEP_LAST;
         res_step = (resolution_step_e)(res_step + 1)) {
        if (m_resolution_data.users_for_step[res_step] == 0) {
            continue;
        }
        switch (res_step) {
        case RESOLUTION_STEP_NATIVE_CE_PTR:
        case RESOLUTION_STEP_STAGE2_LB:
        case RESOLUTION_STEP_PATH_LP: {
            // Instantiate the new destination
            la_status status = instantiate_resolution_object(destination, res_step);
            return_on_error(status);
        } break;
        default: {
            return LA_STATUS_EUNKNOWN;
        }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::uninstantiate_old_destination(const la_l3_destination_wcptr& destination)
{
    for (resolution_step_e res_step = RESOLUTION_STEP_NATIVE_FEC; res_step < RESOLUTION_STEP_LAST;
         res_step = (resolution_step_e)(res_step + 1)) {
        if (m_resolution_data.users_for_step[res_step] == 0) {
            continue;
        }
        switch (res_step) {
        case RESOLUTION_STEP_NATIVE_CE_PTR:
        case RESOLUTION_STEP_STAGE2_LB:
        case RESOLUTION_STEP_STAGE3_LB:
        case RESOLUTION_STEP_PATH_LP: {
            // Instantiate the new destination
            la_status status = uninstantiate_resolution_object(destination, res_step);
            return_on_error(status);
        } break;
        default: {
            return LA_STATUS_EUNKNOWN;
        }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::clear_nh_lsp_properties(const la_next_hop* nh)
{
    start_api_call("nh=", nh);

    la_next_hop_wcptr nh_sp = m_device->get_sptr(nh);

    if (nh_sp == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(nh_sp, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_next_hop_base_wcptr next_hop = nh_sp.weak_ptr_static_cast<const la_next_hop_base>();

    auto te_em_map_entry_it = m_te_em_entry_map.find(next_hop);
    if (te_em_map_entry_it == m_te_em_entry_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    // Always clear the Large-EM/Small-EM table programmed with the Tunnel labels
    la_status status = teardown_encap_te_he_nh_slice_pairs(
        next_hop, te_em_map_entry_it->second.more_labels_index_valid, te_em_map_entry_it->second.more_labels_index);
    return_on_error(status);

    // If LDP is enabled, the entry should also be removed in the DLP0-EM table
    if (m_tunnel_type == la_te_tunnel::tunnel_type_e::LDP_ENABLED) {
        auto ldp_over_te_em_map_entry_it = m_ldp_over_te_em_entry_map.find(next_hop);
        if (ldp_over_te_em_map_entry_it == m_ldp_over_te_em_entry_map.end()) {
            return LA_STATUS_ENOTFOUND;
        }
        deregister_attribute_dependency(next_hop);
        for (auto pair_idx : get_slice_pairs(next_hop)) {
            la_status status = teardown_ldp_over_te_table_entry(pair_idx, next_hop);
            return_on_error(status);
        }
        m_ldp_over_te_em_entry_map.erase(ldp_over_te_em_map_entry_it);
    }

    // Remove the nh from the current counter
    status = release_counter(next_hop, te_em_map_entry_it->second.counter);
    return_on_error(status);
    m_te_em_entry_map.erase(te_em_map_entry_it);

    auto pair_it = m_tunnel_nh_pairs.find(next_hop);
    dassert_crit(pair_it != m_tunnel_nh_pairs.end());
    auto& pair_obj = pair_it->second;
    status = pair_obj->destroy();
    return_on_error(status);
    m_tunnel_nh_pairs.erase(pair_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::do_get_nh_lsp_properties(const la_next_hop_wcptr& nh,
                                            la_mpls_label_vec_t& out_labels,
                                            const la_counter_set*& out_counter) const
{
    if (nh == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(nh, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_next_hop_base_wcptr next_hop = nh.weak_ptr_static_cast<const la_next_hop_base>();

    auto te_em_map_entry_it = m_te_em_entry_map.find(next_hop);
    if (te_em_map_entry_it == m_te_em_entry_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto& entry = te_em_map_entry_it->second;

    out_labels = entry.labels;
    out_counter = entry.counter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::get_nh_lsp_properties(const la_next_hop* nh,
                                         la_mpls_label_vec_t& out_labels,
                                         const la_counter_set*& out_counter) const
{
    start_api_getter_call();
    return do_get_nh_lsp_properties(m_device->get_sptr(nh), out_labels, out_counter);
}

la_status
la_te_tunnel_impl::set_nh_lsp_properties(const la_next_hop* nh, const la_mpls_label_vec_t& labels, la_counter_set* counter)
{
    start_api_call("nh=", nh, "labels=", labels, "counter=", counter);

    la_next_hop_wcptr nh_sp = m_device->get_sptr(nh);
    la_counter_set_wptr counter_sp = m_device->get_sptr(counter);

    if (nh_sp == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(nh_sp, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if ((counter_sp != nullptr) && (!of_same_device(counter_sp, this))) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status;

    // Always program the Large-EM table with the Tunnel labels
    la_next_hop_base_wcptr next_hop = nh_sp.weak_ptr_static_cast<const la_next_hop_base>();
    status = set_nh_lsp_properties_mpls_he(next_hop, labels, counter_sp);
    return_on_error(status);

    if (m_tunnel_type == la_te_tunnel::tunnel_type_e::LDP_ENABLED) {
        // If LDP is enabled, the Tunnel labels should also be programmed
        // in the DLP0-EM table
        status = set_nh_lsp_properties_ldp_over_te(next_hop, labels, counter_sp);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::set_nh_lsp_properties_mpls_he(const la_next_hop_base_wcptr& next_hop,
                                                 const la_mpls_label_vec_t& labels,
                                                 const la_counter_set_wptr& counter)
{
    la_counter_set_wptr curr_counter;
    bool more_labels_index_valid = false;
    uint64_t more_labels_index = 0;
    bool curr_more_labels_index_valid = false;
    uint64_t curr_more_labels_index = 0;
    transaction txn;

    bool is_new_nh = false;
    auto te_em_map_entry_it = m_te_em_entry_map.find(next_hop);
    if (te_em_map_entry_it == m_te_em_entry_map.end()) {
        is_new_nh = true;
    } else {
        auto& map_entry = te_em_map_entry_it->second;
        curr_counter = map_entry.counter;
        curr_more_labels_index = map_entry.more_labels_index;
        curr_more_labels_index_valid = map_entry.more_labels_index_valid;
    }

    more_labels_index = curr_more_labels_index;
    more_labels_index_valid = curr_more_labels_index_valid;

    if (curr_counter != counter) {
        // Add the new counter for the NH
        txn.status = allocate_counter(next_hop, counter, la_counter_set::type_e::PORT, COUNTER_DIRECTION_EGRESS);
        return_on_error(txn.status);

        txn.on_fail([&]() { release_counter(next_hop, counter); });
    }

    // Update the tables with the new labels/counter
    for (auto pair_idx : get_slice_pairs(next_hop)) {
        txn.status = configure_encap_te_he_nh_slice_pair_entry(
            pair_idx, next_hop, labels, counter, more_labels_index_valid, more_labels_index);
        return_on_error(txn.status);
        txn.on_fail(
            [&]() { teardown_encap_te_he_nh_slice_pair_entry(pair_idx, next_hop, more_labels_index_valid, more_labels_index); });
    }

    if (curr_counter != counter) {
        // Remove the nh from the current counter
        la_status status = release_counter(next_hop, curr_counter);
        return_on_error(status);
    }

    te_em_info& entry_info = m_te_em_entry_map[next_hop];
    if (entry_info.ifgs == nullptr) {
        entry_info.ifgs = std::make_shared<ifg_use_count>(m_device->get_slice_id_manager());
    }

    entry_info.labels = labels;
    entry_info.counter = counter;

    // Release old additional labels encap.
    if (!more_labels_index_valid && curr_more_labels_index_valid) {
        for (auto pair_idx : get_slice_pairs(next_hop)) {
            la_status status = teardown_additional_labels_table_entry(pair_idx, curr_more_labels_index);
            return_on_error(status);
        }
        m_device->m_index_generators.sr_extended_policies.release(curr_more_labels_index);
    }

    entry_info.more_labels_index = more_labels_index;
    entry_info.more_labels_index_valid = more_labels_index_valid;

    if (is_new_nh) {
        dassert_crit(m_tunnel_nh_pairs.find(next_hop) == m_tunnel_nh_pairs.end());

        auto pair = std::make_shared<tunnel_nh_pair>(m_device, m_device->get_sptr(this), next_hop, counter);
        auto status = pair->initialize();
        return_on_error(status);
        m_tunnel_nh_pairs[next_hop] = pair;
        for (auto ifg : get_ifgs(next_hop)) {
            bool i, s, p; // dummy
            entry_info.ifgs->add_ifg_user(ifg, i, s, p);
        }
    } else {
        dassert_crit(m_tunnel_nh_pairs.find(next_hop) != m_tunnel_nh_pairs.end());
        m_tunnel_nh_pairs[next_hop]->set_counter(counter);
    }

    return LA_STATUS_SUCCESS;
}

la_te_tunnel_impl::lsp_configuration_params
la_te_tunnel_impl::get_lsp_configuration_params(const la_mpls_label_vec_t& labels, const la_counter_set_wcptr& counter) const
{
    lsp_configuration_params lsp_config{0};
    lsp_config.multi_counter_enabled = false;

    auto num_labels = labels.size();
    // Flag set for v6ExpNull, Per Protocol Counter and Entropy Label
    bool flags_set = m_ipv6_explicit_null_enabled; // TODO Need to check for Entropy Label as well

    if (counter != nullptr) {
        const auto& counter_impl = counter.weak_ptr_static_cast<const la_counter_set_impl>();
        lsp_config.multi_counter_enabled = (counter_impl->get_type() == la_counter_set::type_e::MPLS_PER_PROTOCOL);
        flags_set = flags_set || (counter_impl->get_set_size() > 1);
    }
    lsp_config.program_additional_labels_table = ((num_labels > 3) || ((num_labels > 2) && (flags_set == true)));

    // max of 3 labels can fit in the lsp payload
    // if the multi_counter or ipv6 explicit null or entropy label flags are set or dm_counter is enabled, then the max is only 2
    lsp_config.lsp_payload_with_3_labels = (num_labels == 3) && (flags_set == false);

    return lsp_config;
}

void
la_te_tunnel_impl::prepare_encap_te_he_nh_table(la_slice_pair_id_t pair_idx,
                                                const la_next_hop_base_wcptr& nh,
                                                const la_mpls_label_vec_t& labels,
                                                const la_counter_set_wcptr& counter,
                                                const uint64_t more_labels_index,
                                                const lsp_configuration_params& lsp_config,
                                                npl_lsp_encap_mapping_data_payload_t& payload)
{
    la_counter_set_impl_wcptr counter_impl = counter.weak_ptr_static_cast<const la_counter_set_impl>();
    auto num_labels = labels.size();

    payload.counter_and_flag.lsp_counter = populate_counter_ptr_slice_pair(counter_impl, pair_idx, COUNTER_DIRECTION_EGRESS);
    // NPL uses counter read bit to indicate whther the 20 msb of the payload are the third label or used as flags.
    payload.counter_and_flag.lsp_counter.update_or_read = lsp_config.lsp_payload_with_3_labels ? 1 : 0;

    if (labels.size() > 0) {
        payload.label_stack.opt1.labels_0_1.label_0 = labels[0].label;
    }

    if (labels.size() > 1) {
        payload.label_stack.opt1.labels_0_1.label_1 = labels[1].label;
    }

    // label_3_or_more is npl union but modeled as a c++ struct. Only write to
    // one of the fields depending on conditions.
    if (lsp_config.lsp_payload_with_3_labels) {
        // Everything fits exactly into the lsp payload, no need for an additional label table entry
        // update_or_read is the num_labels_is_3 flag
        payload.label_stack.opt1.label_2_or_more.label = labels[2].label;
    } else {
        payload.label_stack.opt1.label_2_or_more.more.multi_counter_enable = lsp_config.multi_counter_enabled;
        payload.label_stack.opt1.label_2_or_more.more.enable_sr_dm_accounting = 0;
        payload.label_stack.opt1.label_2_or_more.more.service_flags.push_entropy_label = 0;
        payload.label_stack.opt1.label_2_or_more.more.service_flags.add_ipv6_explicit_null = m_ipv6_explicit_null_enabled ? 1 : 0;
        payload.label_stack.opt1.label_2_or_more.more.total_num_labels = num_labels;

        if (lsp_config.program_additional_labels_table) {
            payload.label_stack.opt1.label_2_or_more.more.more_labels.more_labels_index = more_labels_index;
        }
    }
}

la_status
la_te_tunnel_impl::configure_additional_labels_table_entry(la_slice_pair_id_t pair_idx,
                                                           const la_mpls_label_vec_t& labels,
                                                           const uint64_t more_labels_index)
{
    const auto& additional_labels_table(m_device->m_tables.additional_labels_table[pair_idx]);
    npl_additional_labels_table_key_t additional_labels_table_key;
    npl_additional_labels_table_value_t additional_labels_table_value;
    npl_additional_labels_table_entry_t* out_additional_labels_table_entry = nullptr;
    auto num_labels = labels.size();

    // key to additional tables holds two narrow entries or a single wide entry
    // Currently only wide entries are supported. When narrow entries will be supported,
    // insert would need to do read modify write, and set to the high order 60b in case od odd index and low order 60b
    // in case of even entries
    additional_labels_table_key.labels_index = more_labels_index;

    additional_labels_table_value.payloads.additional_labels.label_3 = labels[2].label;
    if (num_labels > 3) {
        additional_labels_table_value.payloads.additional_labels.label_4 = labels[3].label;
    }
    if (num_labels > 4) {
        additional_labels_table_value.payloads.additional_labels.label_5 = labels[4].label;
    }
    if (num_labels > 5) {
        additional_labels_table_value.payloads.additional_labels.label_6 = labels[5].label;
    }
    if (num_labels > 6) {
        additional_labels_table_value.payloads.additional_labels.label_7 = labels[6].label;
    }
    if (num_labels > 7) {
        additional_labels_table_value.payloads.additional_labels.label_8_or_num_labels.label = labels[7].label;
    } else {
        additional_labels_table_value.payloads.additional_labels.label_8_or_num_labels.num_labels.total_num_labels = num_labels;
    }

    return additional_labels_table->set(
        additional_labels_table_key, additional_labels_table_value, out_additional_labels_table_entry);
}

la_status
la_te_tunnel_impl::teardown_additional_labels_table_entry(la_slice_pair_id_t pair_idx, const uint64_t more_labels_index)
{
    const auto& additional_labels_table(m_device->m_tables.additional_labels_table[pair_idx]);
    npl_additional_labels_table_key_t additional_labels_table_key;

    additional_labels_table_key.labels_index = more_labels_index;
    return additional_labels_table->erase(additional_labels_table_key);
}

la_status
la_te_tunnel_impl::configure_small_encap_mpls_he_te_table_entry(la_slice_pair_id_t pair_idx,
                                                                const la_next_hop_base_wcptr& nh,
                                                                const la_mpls_label_vec_t& labels,
                                                                const la_counter_set_wcptr& counter,
                                                                const uint64_t more_labels_index,
                                                                const lsp_configuration_params& lsp_config)
{
    const auto& table(m_device->m_tables.small_encap_mpls_he_te_table[pair_idx]);
    npl_small_encap_mpls_he_te_table_key_t key;
    npl_small_encap_mpls_he_te_table_value_t value;
    npl_small_encap_mpls_he_te_table_entry_t* out_entry = nullptr;
    auto nh_gid = nh->get_gid();

    key.te_tunnel = m_te_tunnel_gid;
    key.nh_ptr = nh_gid;
    value.action = NPL_SMALL_ENCAP_MPLS_HE_TE_TABLE_ACTION_WRITE;

    prepare_encap_te_he_nh_table(
        pair_idx, nh, labels, counter, more_labels_index, lsp_config, value.payloads.lsp_encap_mapping_data_payload_asbr);

    return table->set(key, value, out_entry);
}

la_status
la_te_tunnel_impl::teardown_small_encap_mpls_he_te_table_entry(la_slice_pair_id_t pair_idx, const la_next_hop_base_wcptr& nh)
{
    const auto& table(m_device->m_tables.small_encap_mpls_he_te_table[pair_idx]);
    npl_small_encap_mpls_he_te_table_key_t key;

    key.te_tunnel = m_te_tunnel_gid;
    key.nh_ptr = nh->get_gid();

    return table->erase(key);
}

la_status
la_te_tunnel_impl::configure_large_encap_te_he_tunnel_id_table_entry(la_slice_pair_id_t pair_idx,
                                                                     const la_next_hop_base_wcptr& nh,
                                                                     const la_mpls_label_vec_t& labels,
                                                                     const la_counter_set_wcptr& counter,
                                                                     const uint64_t more_labels_index,
                                                                     const lsp_configuration_params& lsp_config)
{
    const auto& table(m_device->m_tables.large_encap_te_he_tunnel_id_table[pair_idx]);
    npl_large_encap_te_he_tunnel_id_table_key_t key;
    npl_large_encap_te_he_tunnel_id_table_value_t value;
    npl_large_encap_te_he_tunnel_id_table_entry_t* out_entry = nullptr;
    la_counter_set_impl_wcptr counter_impl = counter.weak_ptr_static_cast<const la_counter_set_impl>();

    key.te_tunnel = m_te_tunnel_gid;
    key.nh_ptr = nh->get_gid();
    value.action = NPL_LARGE_ENCAP_TE_HE_TUNNEL_ID_TABLE_ACTION_WRITE;
    prepare_encap_te_he_nh_table(
        pair_idx, nh, labels, counter, more_labels_index, lsp_config, value.payloads.lsp_encap_mapping_data_payload);

    return table->set(key, value, out_entry);
}

la_status
la_te_tunnel_impl::teardown_large_encap_te_he_tunnel_id_table_entry(la_slice_pair_id_t pair_idx,
                                                                    const la_next_hop_base_wcptr& next_hop)
{
    const auto& table(m_device->m_tables.large_encap_te_he_tunnel_id_table[pair_idx]);
    npl_large_encap_te_he_tunnel_id_table_key_t key;

    key.te_tunnel = m_te_tunnel_gid;
    key.nh_ptr = next_hop->get_gid();

    return table->erase(key);
}

la_status
la_te_tunnel_impl::configure_encap_te_he_nh_slice_pair_entry(la_slice_pair_id_t pair_idx,
                                                             const la_next_hop_base_wcptr& next_hop,
                                                             const la_mpls_label_vec_t& labels,
                                                             const la_counter_set_wcptr& counter,
                                                             bool& more_labels_index_valid,
                                                             uint64_t& more_labels_index)
{
    la_status status;
    transaction txn;

    lsp_configuration_params lsp_config = get_lsp_configuration_params(labels, counter);

    // Allocate a new index for additional_labels_table the first time if the
    // LSP configuration parameters require additional table lookup
    if (lsp_config.program_additional_labels_table && !more_labels_index_valid) {
        m_device->m_index_generators.sr_extended_policies.allocate(more_labels_index);
    }

    more_labels_index_valid = lsp_config.program_additional_labels_table;

    if (more_labels_index_valid) {
        status = configure_additional_labels_table_entry(pair_idx, labels, more_labels_index);
        return_on_error(status);
        txn.on_fail([&]() { teardown_additional_labels_table_entry(pair_idx, more_labels_index); });
    }

    status = configure_large_encap_te_he_tunnel_id_table_entry(pair_idx, next_hop, labels, counter, more_labels_index, lsp_config);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::teardown_encap_te_he_nh_slice_pair_entry(la_slice_pair_id_t pair_idx,
                                                            const la_next_hop_base_wcptr& next_hop,
                                                            const bool more_labels_index_valid,
                                                            const uint64_t more_labels_index)
{
    la_status status;

    if (more_labels_index_valid) {
        status = teardown_additional_labels_table_entry(pair_idx, more_labels_index);
        return_on_error(status);
    }

    status = teardown_large_encap_te_he_tunnel_id_table_entry(pair_idx, next_hop);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::teardown_encap_te_he_nh_slice_pairs(const la_next_hop_base_wcptr& next_hop,
                                                       bool& more_labels_index_valid,
                                                       uint64_t& more_labels_index)
{
    // Update the tables with the new labels/counter
    for (auto pair_idx : get_slice_pairs(next_hop)) {
        la_status status = teardown_encap_te_he_nh_slice_pair_entry(pair_idx, next_hop, more_labels_index_valid, more_labels_index);
        return_on_error(status);
    }

    // Release additional label index.
    if (more_labels_index_valid) {
        m_device->m_index_generators.sr_extended_policies.release(more_labels_index);
    }

    more_labels_index = 0;
    more_labels_index_valid = false;
    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::teardown_encap_te_he_all_nh()
{
    vector_alloc<te_em_entry_map_t::iterator> entries_to_remove;

    for (auto it = m_te_em_entry_map.begin(); it != m_te_em_entry_map.end(); it++) {
        entries_to_remove.push_back(it);
    }

    for (auto te_em_map_entry_it : entries_to_remove) {
        auto next_hop = te_em_map_entry_it->first;

        la_status status = teardown_encap_te_he_nh_slice_pairs(
            next_hop, te_em_map_entry_it->second.more_labels_index_valid, te_em_map_entry_it->second.more_labels_index);
        return_on_error(status);
        m_te_em_entry_map.erase(te_em_map_entry_it);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::configure_small_encap_mpls_he_te_table()
{
    vector_alloc<te_em_entry_map_t::iterator> entries_to_add;

    for (auto te_em_map_entry_it = m_te_em_entry_map.begin(); te_em_map_entry_it != m_te_em_entry_map.end(); te_em_map_entry_it++) {
        auto next_hop = te_em_map_entry_it->first;

        lsp_configuration_params lsp_config
            = get_lsp_configuration_params(te_em_map_entry_it->second.labels, te_em_map_entry_it->second.counter);

        for (auto pair_idx : get_slice_pairs(next_hop)) {
            la_status status = configure_small_encap_mpls_he_te_table_entry(pair_idx,
                                                                            next_hop,
                                                                            te_em_map_entry_it->second.labels,
                                                                            te_em_map_entry_it->second.counter,
                                                                            te_em_map_entry_it->second.more_labels_index,
                                                                            lsp_config);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::teardown_small_encap_mpls_he_te_table()
{
    for (auto te_em_map_entry_it = m_te_em_entry_map.begin(); te_em_map_entry_it != m_te_em_entry_map.end(); te_em_map_entry_it++) {
        auto next_hop = te_em_map_entry_it->first;
        for (auto pair_idx : get_slice_pairs(next_hop)) {
            la_status status = teardown_small_encap_mpls_he_te_table_entry(pair_idx, next_hop);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::set_nh_lsp_properties_ldp_over_te(const la_next_hop_base_wcptr& next_hop,
                                                     const la_mpls_label_vec_t& labels,
                                                     const la_counter_set_wptr& counter)
{
    auto it = m_te_em_entry_map.find(next_hop);
    if (it == m_te_em_entry_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    // Update the tables with the new labels/counter
    for (auto pair_idx : get_slice_pairs(next_hop)) {
        la_status status = configure_ldp_over_te_table(pair_idx, next_hop, labels, counter, it->second.more_labels_index);
        return_on_error(status);
    }

    auto te_em_map_entry_it = m_ldp_over_te_em_entry_map.find(next_hop);
    if (te_em_map_entry_it == m_ldp_over_te_em_entry_map.end()) {
        register_attribute_dependency(next_hop);
    }

    ldp_over_te_em_info& entry_info = m_ldp_over_te_em_entry_map[next_hop];
    entry_info.labels = labels;
    entry_info.counter = counter;

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::configure_ldp_over_te_table(la_slice_pair_id_t pair_idx,
                                               const la_next_hop_base_wcptr& nh,
                                               const la_mpls_label_vec_t& labels,
                                               const la_counter_set_wcptr& counter,
                                               const uint64_t more_labels_index)
{
    lsp_configuration_params lsp_config = get_lsp_configuration_params(labels, counter);

    return configure_small_encap_mpls_he_te_table_entry(pair_idx, nh, labels, counter, more_labels_index, lsp_config);
}

la_status
la_te_tunnel_impl::teardown_ldp_over_te_table()
{
    vector_alloc<ldp_over_te_em_entry_map_t::iterator> entries_to_remove;

    for (auto it = m_ldp_over_te_em_entry_map.begin(); it != m_ldp_over_te_em_entry_map.end(); it++) {
        entries_to_remove.push_back(it);
    }

    for (auto ldp_over_te_em_map_entry_it : entries_to_remove) {
        auto next_hop = ldp_over_te_em_map_entry_it->first;
        deregister_attribute_dependency(next_hop);
        for (auto pair_idx : get_slice_pairs(next_hop)) {
            la_status status = teardown_ldp_over_te_table_entry(pair_idx, next_hop);
            return_on_error(status);
        }

        m_ldp_over_te_em_entry_map.erase(ldp_over_te_em_map_entry_it);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::teardown_ldp_over_te_table_entry(la_slice_pair_id_t pair_idx, const la_next_hop_base_wcptr& next_hop)
{
    return teardown_small_encap_mpls_he_te_table_entry(pair_idx, next_hop);
}

resolution_step_e
la_te_tunnel_impl::get_next_resolution_step(resolution_step_e prev_step) const
{
    if (prev_step < RESOLUTION_STEP_NATIVE_L2_LP) {
        return RESOLUTION_STEP_NATIVE_CE_PTR;
    }

    if (prev_step < RESOLUTION_STEP_PATH_LP) {
        return RESOLUTION_STEP_STAGE2_LB;
    }

    if (prev_step == RESOLUTION_STEP_PATH_LP) {
        return RESOLUTION_STEP_PATH_LP;
    }

    return RESOLUTION_STEP_INVALID;
}

la_te_tunnel_impl::resolution_data::resolution_data()
{
    for (resolution_step_e res_step = RESOLUTION_STEP_FIRST; res_step < RESOLUTION_STEP_LAST;
         res_step = (resolution_step_e)(res_step + 1)) {
        users_for_step[res_step] = 0;
    }
}

la_status
la_te_tunnel_impl::instantiate(resolution_step_e prev_step)
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

    la_status status = instantiate_resolution_object(m_destination, cur_step);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::uninstantiate(resolution_step_e prev_step)
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (cur_step == RESOLUTION_STEP_INVALID) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (m_resolution_data.users_for_step[cur_step] > 1) {
        m_resolution_data.users_for_step[cur_step]--;
        return LA_STATUS_SUCCESS;
    }

    la_status status = uninstantiate_resolution_object(m_destination, cur_step);
    return_on_error(status);

    m_resolution_data.users_for_step[cur_step]--;
    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::get_tunnel_type(la_te_tunnel::tunnel_type_e& out_type) const
{
    out_type = m_tunnel_type;
    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::set_tunnel_type(la_te_tunnel::tunnel_type_e type)
{
    start_api_call("type=", type);

    if (m_tunnel_type == type) {
        return LA_STATUS_SUCCESS;
    }

    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    if (type == la_te_tunnel::tunnel_type_e::NORMAL) {
        if (!m_ldp_over_te_em_entry_map.empty()) {
            // User cannot change the type to a NORMAL, when there are entries in the DLP0-EM table (probably created for
            // use by a LDP_ENABLED tunnel).
            return LA_STATUS_EBUSY;
        }
    }

    if (type == la_te_tunnel::tunnel_type_e::LDP_ENABLED) {
        // User cannot change the type to a LDP_ENABLED, when there are entries in the Large-EM table (probably created
        // for use by a NORMAL tunnel).
        if (!m_te_em_entry_map.empty()) {
            return LA_STATUS_EBUSY;
        }
    }

    m_tunnel_type = type;

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::get_ipv6_explicit_null_enabled(bool& out_enabled) const
{
    out_enabled = m_ipv6_explicit_null_enabled;
    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::set_ipv6_explicit_null_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    if (m_ipv6_explicit_null_enabled == enabled) {
        return LA_STATUS_SUCCESS;
    }

    m_ipv6_explicit_null_enabled = enabled;

    for (auto te_em_map_entry_it : m_te_em_entry_map) {
        auto next_hop = te_em_map_entry_it.first;
        auto& entry = te_em_map_entry_it.second;
        for (auto pair_idx : get_slice_pairs(next_hop)) {
            la_status status = configure_encap_te_he_nh_slice_pair_entry(
                pair_idx, next_hop, entry.labels, entry.counter, entry.more_labels_index_valid, entry.more_labels_index);
            return_on_error(status);
            if (m_tunnel_type == la_te_tunnel::tunnel_type_e::LDP_ENABLED) {
                la_status status
                    = configure_ldp_over_te_table(pair_idx, next_hop, entry.labels, entry.counter, entry.more_labels_index);
                return_on_error(status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

bool
la_te_tunnel_impl::is_counter_set_size_valid(const la_counter_set_impl_wcptr& counter, la_counter_set::type_e counter_type)
{
    if (counter == nullptr) {
        return true;
    }

    if (counter_type != la_counter_set::type_e::PORT) {
        return false;
    }

    size_t counter_set_size = counter->get_set_size();

    return (counter_set_size == 1);
}

la_status
la_te_tunnel_impl::allocate_counter(const la_next_hop_base_wcptr& next_hop,
                                    const la_counter_set_wptr& new_counter,
                                    la_counter_set::type_e counter_type,
                                    counter_direction_e direction)
{
    // Check the counter's set size

    la_counter_set_impl_wptr new_counter_impl = new_counter.weak_ptr_static_cast<la_counter_set_impl>();
    if (!is_counter_set_size_valid(new_counter_impl, counter_type)) {
        return LA_STATUS_EINVAL;
    }

    if (new_counter_impl == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    // Add the nh's slices to the new counter

    la_status status = new_counter_impl->add_pq_counter_user(next_hop, counter_type, direction, is_aggregate_nh(next_hop));
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::add_ifg(const la_next_hop_base_wcptr& nh, la_slice_ifg ifg)
{
    log_debug(HLD, "la_te_tunnel_impl::%s nh=%s slice=%d ifg=%d", __func__, nh->to_string().c_str(), ifg.slice, ifg.ifg);

    auto te_em_map_entry_it = m_te_em_entry_map.find(nh);
    if (te_em_map_entry_it == m_te_em_entry_map.end()) {
        log_err(HLD, "la_te_tunnel_impl::%s: got notification from unknown next-hop", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    transaction txn;

    auto& entry = te_em_map_entry_it->second;
    bool ifg_added, slice_added, slice_pair_added;
    entry.ifgs->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([&]() {
        bool dummy;
        entry.ifgs->remove_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (slice_pair_added) {
        la_slice_pair_id_t pair_idx = ifg.slice / 2;

        txn.status = configure_encap_te_he_nh_slice_pair_entry(
            pair_idx, nh, entry.labels, entry.counter, entry.more_labels_index_valid, entry.more_labels_index);
        return_on_error(txn.status);
        txn.on_fail([&]() {
            teardown_encap_te_he_nh_slice_pair_entry(pair_idx, nh, entry.more_labels_index_valid, entry.more_labels_index);
        });

        if (m_tunnel_type == la_te_tunnel::tunnel_type_e::LDP_ENABLED) {
            txn.status = configure_ldp_over_te_table(pair_idx, nh, entry.labels, entry.counter, entry.more_labels_index);
            return_on_error(txn.status);
            txn.on_fail([&]() { teardown_ldp_over_te_table_entry(pair_idx, nh); });
        }
    }

    m_ifgs->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([&]() {
        bool dummy;
        m_ifgs->remove_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (ifg_added) {
        txn.status = m_device->notify_ifg_added(this, ifg);
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::remove_ifg(const la_next_hop_base_wcptr& nh, la_slice_ifg ifg)
{
    log_debug(HLD, "la_te_tunnel_impl::%s nh=%s slice=%d ifg=%d", __func__, nh->to_string().c_str(), ifg.slice, ifg.ifg);

    transaction txn;

    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifgs->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);
    txn.on_fail([&]() {
        bool dummy;
        m_ifgs->add_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (ifg_removed) {
        txn.status = m_device->notify_ifg_removed(this, ifg);
        return_on_error(txn.status);
        txn.on_fail([&]() { m_device->notify_ifg_added(this, ifg); });
    }

    auto te_em_map_entry_it = m_te_em_entry_map.find(nh);
    if (te_em_map_entry_it == m_te_em_entry_map.end()) {
        log_err(HLD, "la_te_tunnel_impl::%s: got notification from unknown next-hop", __func__);
        txn.status = LA_STATUS_EUNKNOWN;
        return txn.status;
    }

    auto& entry = te_em_map_entry_it->second;
    entry.ifgs->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);
    txn.on_fail([&]() {
        bool dummy;
        entry.ifgs->add_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (slice_pair_removed) {
        la_slice_pair_id_t pair_idx = ifg.slice / 2;
        txn.status = teardown_encap_te_he_nh_slice_pair_entry(pair_idx, nh, entry.more_labels_index_valid, entry.more_labels_index);
        return_on_error(txn.status);
        txn.on_fail([&]() {
            configure_encap_te_he_nh_slice_pair_entry(
                pair_idx, nh, entry.labels, entry.counter, entry.more_labels_index_valid, entry.more_labels_index);
        });
        if (m_tunnel_type == la_te_tunnel::tunnel_type_e::LDP_ENABLED) {
            txn.status = teardown_ldp_over_te_table_entry(pair_idx, nh);
            return_on_error(txn.status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::release_counter(const la_next_hop_base_wcptr& next_hop, const la_counter_set_wptr& curr_counter)
{
    la_counter_set_impl_wptr curr_counter_impl = curr_counter.weak_ptr_static_cast<la_counter_set_impl>();

    if (curr_counter_impl == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    // Remove the nh's slices from the current counter

    la_status status = curr_counter_impl->remove_pq_counter_user(next_hop);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

void
la_te_tunnel_impl::register_attribute_dependency(const la_next_hop_base_wcptr& next_hop)
{
    if (m_tunnel_type == la_te_tunnel::tunnel_type_e::LDP_ENABLED) {
        la_l3_port* l3_port = nullptr;

        la_status status = next_hop->get_router_port(l3_port);
        if (status != LA_STATUS_SUCCESS) {
            return;
        }

        bit_vector registered_attributes((la_uint64_t)attribute_management_op::L3_PORT_ATTR_CHANGED);
        m_device->add_attribute_dependency(l3_port, this, registered_attributes);
    }
}

void
la_te_tunnel_impl::deregister_attribute_dependency(const la_next_hop_base_wcptr& next_hop)
{
    if (m_tunnel_type == la_te_tunnel::tunnel_type_e::LDP_ENABLED) {
        la_l3_port* l3_port = nullptr;

        la_status status = next_hop->get_router_port(l3_port);
        if (status != LA_STATUS_SUCCESS) {
            return;
        }

        bit_vector registered_attributes((la_uint64_t)attribute_management_op::L3_PORT_ATTR_CHANGED);
        m_device->remove_attribute_dependency(l3_port, this, registered_attributes);
    }
}

void
la_te_tunnel_impl::add_dependency(const la_l3_destination_wcptr& destination)
{
    m_device->add_object_dependency(destination, this);
}

void
la_te_tunnel_impl::remove_dependency(const la_l3_destination_wcptr& destination)
{
    m_device->remove_object_dependency(destination, this);
}

la_status
la_te_tunnel_impl::update_dependent_attributes(dependency_management_op op)
{
    switch (op.action.attribute_management.op) {
    case (attribute_management_op::L3_PORT_ATTR_CHANGED): {
        for (auto it = m_ldp_over_te_em_entry_map.begin(); it != m_ldp_over_te_em_entry_map.end(); it++) {
            auto next_hop = it->first;
            la_l3_port* l3_port = nullptr;

            la_status status = next_hop->get_router_port(l3_port);
            return_on_error(status);

            if (op.action.attribute_management.l3_port == l3_port) {
                auto it_nh = m_te_em_entry_map.find(next_hop);
                if (it_nh == m_te_em_entry_map.end()) {
                    return LA_STATUS_ENOTFOUND;
                }
                for (auto pair_idx : get_slice_pairs(next_hop)) {
                    la_status status = configure_ldp_over_te_table(
                        pair_idx, next_hop, it->second.labels, it->second.counter, it_nh->second.more_labels_index);
                    return_on_error(status);
                }
            }
        }

    } break;
    default:
        return LA_STATUS_EUNKNOWN;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_te_tunnel_impl::notify_change(dependency_management_op op)
{
    switch (op.type_e) {
    case dependency_management_op::management_type_e::IFG_MANAGEMENT: {
        dassert_crit(op.dependee->type() == object_type_e::NEXT_HOP);
        la_next_hop_base_scptr nh = m_device->get_sptr<const la_next_hop_base>(op.dependee);
        return (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) ? add_ifg(nh, op.action.ifg_management.ifg)
                                                                               : remove_ifg(nh, op.action.ifg_management.ifg);
    }
    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        return update_dependent_attributes(op);
    default:
        log_err(HLD, "received unsupported notification (%s)", silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
la_te_tunnel_impl::get_lb_resolution(const la_lb_pak_fields_vec& lb_vector, size_t& member, const la_object*& out_object) const
{
    la_status status = LA_STATUS_SUCCESS;
    resolution_step_e step = RESOLUTION_STEP_STAGE2_LB;

    if (m_resolution_data.users_for_step[step] == 0) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // usually next hop object, let the caller resolve the next hop load balancing resolution
    member = 0;
    out_object = m_destination.get();

    return status;
}
} // namespace silicon_one
