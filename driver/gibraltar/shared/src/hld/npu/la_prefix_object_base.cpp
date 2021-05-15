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

#include "la_prefix_object_base.h"
#include "api/system/la_spa_port.h"
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
#include "common/transaction.h"
#include "hld_types.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "npu/counter_utils.h"

#include <sstream>

namespace silicon_one

{
la_prefix_object_base::prefix_nh_pair::prefix_nh_pair(const la_device_impl_wptr& device,
                                                      const la_prefix_object_base_wptr& prefix,
                                                      const la_next_hop_base_wcptr& nh,
                                                      const la_counter_set_wptr& counter)
    : m_device(device), m_prefix(prefix), m_nh(nh), m_counter(counter.weak_ptr_static_cast<la_counter_set_impl>())
{
}

la_prefix_object_base::prefix_nh_pair::~prefix_nh_pair()
{
}

la_status
la_prefix_object_base::prefix_nh_pair::destroy()
{
    m_device->remove_ifg_dependency(m_nh, shared_from_this());
    m_device->remove_object_dependency(m_nh, m_prefix);
    if (m_counter != nullptr) {
        m_device->remove_object_dependency(m_counter, m_prefix);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::prefix_nh_pair::initialize()
{
    m_device->add_ifg_dependency(m_nh, shared_from_this());
    m_device->add_object_dependency(m_nh, m_prefix);
    if (m_counter != nullptr) {
        m_device->add_object_dependency(m_counter, m_prefix);
    }
    return LA_STATUS_SUCCESS;
}

const la_device_impl_wptr&
la_prefix_object_base::prefix_nh_pair::get_device() const
{
    return m_device;
}

void
la_prefix_object_base::prefix_nh_pair::set_counter(const la_counter_set_wptr& counter)
{
    if (m_counter != nullptr) {
        m_device->remove_object_dependency(m_counter, m_prefix);
    }

    if (counter != nullptr) {
        m_device->add_object_dependency(counter, m_prefix);
    }

    m_counter = counter.weak_ptr_static_cast<la_counter_set_impl>();
}

la_status
la_prefix_object_base::prefix_nh_pair::notify_change(dependency_management_op op)
{
    if (op.type_e != dependency_management_op::management_type_e::IFG_MANAGEMENT) {
        log_err(HLD,
                "la_prefix_object_base::prefix_nh_pair::notify_change: received unsupported notification (%s)",
                silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }

    dassert_crit(op.dependee == m_nh);

    la_status status;
    if (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) {
        // Notify prefix after counter
        if (m_counter != nullptr) {
            status = m_counter->notify_change(op);
            return_on_error(status);
        }

        return m_prefix->notify_change(op);
    }

    // IFG_REMOVE - reverse order
    status = m_prefix->notify_change(op);
    return_on_error(status);

    if (m_counter != nullptr) {
        return m_counter->notify_change(op);
    }

    return LA_STATUS_SUCCESS;
}

la_prefix_object_base::la_prefix_object_base(const la_device_impl_wptr& device)
    : m_device(device),
      m_prefix_gid(LA_L3_DESTINATION_GID_INVALID),
      m_destination(nullptr),
      m_vpn_enabled(false),
      m_global_lsp_prefix(false),
      m_ipv6_explicit_null_enabled(false)
{
}

la_prefix_object_base::~la_prefix_object_base()
{
}

const la_device*
la_prefix_object_base::get_device() const
{
    return m_device.get();
}

la_object::object_type_e
la_prefix_object_base::type() const
{
    return la_object::object_type_e::PREFIX_OBJECT;
}

std::string
la_prefix_object_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_prefix_object_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_prefix_object_base::oid() const
{
    return m_oid;
}

const la_l3_destination*
la_prefix_object_base::get_destination() const
{
    start_api_getter_call();
    return m_destination.get();
}

la_status
la_prefix_object_base::set_destination(const la_l3_destination* destination)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_l3_destination_gid_t
la_prefix_object_base::get_gid() const
{
    return m_prefix_gid;
}

std::vector<la_slice_pair_id_t>
la_prefix_object_base::get_slice_pairs(const la_next_hop_base_wcptr& next_hop) const
{
    return next_hop->get_slice_pairs();
}

lpm_destination_id
la_prefix_object_base::get_lpm_destination_id(resolution_step_e prev_step) const
{
    return lpm_destination_id(NPL_LPM_COMPRESSED_DESTINATION_CE_PTR_MASK | m_prefix_gid);
}

la_status
la_prefix_object_base::initialize(la_object_id_t oid,
                                  la_l3_destination_gid_t prefix_gid,
                                  const la_l3_destination_wcptr& destination,
                                  la_prefix_object::prefix_type_e type)
{
    m_ifgs = make_unique<ifg_use_count>(m_device->get_slice_id_manager());

    m_global_lsp_prefix_info.em_info.ifgs = make_unique<ifg_use_count>(m_device->get_slice_id_manager());

    m_oid = oid;
    m_prefix_gid = prefix_gid;

    bool is_global;
    if (type == la_prefix_object::prefix_type_e::GLOBAL) {
        is_global = true;
    } else {
        is_global = false;
    }

    la_status status = update_destination(destination, is_global, true);
    return_on_error(status);

    add_dependency(destination);

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::validate_new_destination_for_global_lsp(const la_l3_destination_wcptr& destination)
{
    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_object::object_type_e dest_type = destination->type();

    if (dest_type != object_type_e::ECMP_GROUP && dest_type != object_type_e::NEXT_HOP) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // If L2 adjacency case, ensure that if normal NH, L3 port is on a SPA port.
    if (dest_type == object_type_e::NEXT_HOP) {
        const auto& nh = destination.weak_ptr_static_cast<const la_next_hop_base>();
        la_next_hop::nh_type_e nh_type;
        la_status status = nh->get_nh_type(nh_type);
        return_on_error(status);
        if (nh_type != la_next_hop::nh_type_e::NORMAL) {
            return LA_STATUS_SUCCESS;
        }

        la_l3_port* l3_port;
        status = nh->get_router_port(l3_port);
        return_on_error(status);
        if (l3_port == nullptr || l3_port->type() != object_type_e::L3_AC_PORT) {
            return LA_STATUS_EINVAL;
        }

        const auto& l3_ac = m_device->get_sptr<la_l3_ac_port_impl>(l3_port);
        const auto& eth_port = m_device->get_sptr<const la_ethernet_port_base>(l3_ac->get_ethernet_port());
        const auto& spa_port = m_device->get_sptr(eth_port->get_spa_port());
        if (spa_port == nullptr) {
            return LA_STATUS_EINVAL;
        }
    }

    return LA_STATUS_SUCCESS;
}

void
la_prefix_object_base::add_dependency(const la_l3_destination_wcptr& destination)
{
    m_device->add_object_dependency(destination, m_device->get_sptr(this));
    register_attribute_dependency(destination);
}

void
la_prefix_object_base::remove_dependency(const la_l3_destination_wcptr& destination)
{
    deregister_attribute_dependency(destination);
    m_device->remove_object_dependency(destination, m_device->get_sptr(this));
}

la_status
la_prefix_object_base::notify_change(dependency_management_op op)
{
    switch (op.type_e) {
    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        return update_dependent_attributes(op);
    case dependency_management_op::management_type_e::IFG_MANAGEMENT: {
        const auto& nh = m_device->get_sptr<const la_next_hop_base>(op.dependee);
        return (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) ? add_ifg(nh, op.action.ifg_management.ifg)
                                                                               : remove_ifg(nh, op.action.ifg_management.ifg);
    }
    default:
        log_err(HLD, "received unsupported notification (%s)", silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
la_prefix_object_base::clear_global_lsp_properties()
{
    start_api_call("");

    transaction txn;

    if (m_global_lsp_prefix == false) {
        return LA_STATUS_EINVAL;
    }

    if (m_global_lsp_prefix_info.entry_present == true) {
        la_mpls_label_vec_t old_labels = m_global_lsp_prefix_info.em_info.labels;
        auto old_counter = m_global_lsp_prefix_info.em_info.counter;

        txn.status = teardown_large_encap_global_lsp_prefix_table();
        return_on_error(txn.status);
        txn.on_fail([&]() {
            for (auto pair_idx : m_device->get_used_slice_pairs()) {
                configure_large_encap_global_lsp_prefix_table(pair_idx, old_labels, old_counter);
            }
            m_global_lsp_prefix_info.entry_present = true;
        });
    }

    txn.status = release_counter(nullptr /*next_hop*/, m_global_lsp_prefix_info.em_info.counter);
    return_on_error(txn.status);

    if (m_global_lsp_prefix_info.em_info.more_labels_index_valid) {
        m_device->m_index_generators.sr_extended_policies.release(m_global_lsp_prefix_info.em_info.more_labels_index);
        m_global_lsp_prefix_info.em_info.more_labels_index_valid = false;
    }
    m_global_lsp_prefix_info.em_info.labels.clear();
    m_global_lsp_prefix_info.em_info.counter = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::get_global_lsp_properties(la_mpls_label_vec_t& out_labels,
                                                 const la_counter_set*& out_counter,
                                                 lsp_counter_mode_e& out_counter_mode) const
{
    start_api_getter_call();

    if (m_global_lsp_prefix == false) {
        return LA_STATUS_EINVAL;
    }

    if (m_global_lsp_prefix_info.entry_present == false) {
        return LA_STATUS_ENOTFOUND;
    }

    out_labels = m_global_lsp_prefix_info.em_info.labels;
    out_counter = m_global_lsp_prefix_info.em_info.counter.get();
    out_counter_mode = m_global_lsp_prefix_info.em_info.counter_mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::set_global_lsp_properties(const la_mpls_label_vec_t& labels,
                                                 la_counter_set* counter,
                                                 lsp_counter_mode_e counter_mode)
{
    start_api_call("labels=", labels, "counter=", counter, "counter_mode=", counter_mode);

    transaction txn;

    if (m_global_lsp_prefix == false) {
        return LA_STATUS_EINVAL;
    }

    const la_counter_set_wptr& counter_wptr = m_device->get_sptr(counter);

    if ((counter != nullptr) && (!of_same_device(counter_wptr, this))) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const la_counter_set_wptr& curr_counter = m_global_lsp_prefix_info.em_info.counter;

    if (curr_counter != counter) {
        // Add the new counter for the Global Prefix
        txn.status = allocate_counter(nullptr /*next_hop*/, counter_wptr, counter_mode, COUNTER_DIRECTION_EGRESS);
        return_on_error(txn.status);
        txn.on_fail([=]() { release_counter(nullptr /* next_hop */, counter_wptr); });
    } else if (counter && (counter_mode != m_global_lsp_prefix_info.em_info.counter_mode)) {
        return LA_STATUS_EINVAL;
    }

    lsp_configuration_params lsp_config = get_lsp_configuration_params(labels, counter_wptr);

    // Allocate a new index for additional_labels_table the first time if the
    // LSP configuration parameters require additional table lookup
    if ((m_global_lsp_prefix_info.em_info.more_labels_index_valid == false) && lsp_config.program_additional_labels_table) {
        bool allocated
            = m_device->m_index_generators.sr_extended_policies.allocate(m_global_lsp_prefix_info.em_info.more_labels_index);
        if (!allocated) {
            txn.status = LA_STATUS_ERESOURCE;
            return txn.status;
        }
        m_global_lsp_prefix_info.em_info.more_labels_index_valid = true;

        txn.on_fail([&]() {
            m_device->m_index_generators.sr_extended_policies.release(m_global_lsp_prefix_info.em_info.more_labels_index);
            m_global_lsp_prefix_info.em_info.more_labels_index_valid = false;
        });
    }

    // Update the tables with the new labels/counter
    for (auto pair_idx : silicon_one::get_slice_pairs(m_device, la_slice_mode_e::NETWORK)) {
        txn.status = configure_large_encap_global_lsp_prefix_table(pair_idx, labels, counter_wptr);
        return_on_error(txn.status);
        txn.on_fail([=]() { teardown_large_encap_global_lsp_prefix_table_entry(pair_idx); });
    }

    if (curr_counter != counter_wptr) {
        txn.status = release_counter(nullptr /*next_hop*/, curr_counter);
        return_on_error(txn.status);
        txn.on_fail([=]() { allocate_counter(nullptr /*next_hop*/, curr_counter, counter_mode, COUNTER_DIRECTION_EGRESS); });
    }

    // Release the index (if necessary) when updating to <= 3 labels
    if ((m_global_lsp_prefix_info.em_info.more_labels_index_valid == true) && (!lsp_config.program_additional_labels_table)) {
        for (auto pair_idx : m_device->get_used_slice_pairs()) {
            txn.status = teardown_encap_additional_labels_table_entry(pair_idx);
            return_on_error(txn.status);
        }

        m_device->m_index_generators.sr_extended_policies.release(m_global_lsp_prefix_info.em_info.more_labels_index);
        m_global_lsp_prefix_info.em_info.more_labels_index_valid = false;
    }

    m_global_lsp_prefix_info.em_info.labels = labels;
    m_global_lsp_prefix_info.em_info.counter = counter_wptr;
    m_global_lsp_prefix_info.em_info.counter_mode = counter_mode;
    m_global_lsp_prefix_info.entry_present = true;

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::get_prefix_type(prefix_type_e& out_type) const
{
    if (m_global_lsp_prefix) {
        out_type = prefix_type_e::GLOBAL;
    } else {
        out_type = prefix_type_e::NORMAL;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::do_get_nh_lsp_properties(const la_next_hop_wcptr& nh,
                                                la_mpls_label_vec_t& out_labels,
                                                la_counter_set_wcptr& out_counter,
                                                lsp_counter_mode_e& out_counter_mode) const
{
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

    auto& map_entry = mpls_em_map_entry_it->second;

    out_labels = map_entry.labels;
    out_counter = map_entry.counter;
    out_counter_mode = map_entry.counter_mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::get_nh_lsp_properties(const la_next_hop* nh,
                                             la_mpls_label_vec_t& out_labels,
                                             const la_counter_set*& out_counter,
                                             lsp_counter_mode_e& out_counter_mode) const
{
    start_api_getter_call();
    la_counter_set_wcptr counter_wcptr;
    la_status status = do_get_nh_lsp_properties(m_device->get_sptr(nh), out_labels, counter_wcptr, out_counter_mode);
    return_on_error(status);

    out_counter = counter_wcptr.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::set_nh_lsp_properties(const la_next_hop* nh,
                                             const la_mpls_label_vec_t& labels,
                                             la_counter_set* counter,
                                             lsp_counter_mode_e counter_mode)
{
    start_api_call("nh=", nh, "labels=", labels, "counter=", counter, "counter_mode=", counter_mode);
    const auto& nh_sptr = m_device->get_sptr(nh);
    const auto& counter_sptr = m_device->get_sptr(counter);
    return do_set_nh_lsp_properties(nh_sptr, labels, counter_sptr, counter_mode);
}

la_status
la_prefix_object_base::clear_nh_lsp_properties(const la_next_hop* nh)
{
    start_api_call("nh=", nh);
    const auto& nh_sptr = m_device->get_sptr(nh);
    return do_clear_nh_lsp_properties(nh_sptr);
}

la_status
la_prefix_object_base::set_vrf_properties(const la_vrf* vrf, la_ip_version_e ip_version, const la_mpls_label_vec_t& labels)
{
    start_api_call("vrf=", vrf, "ip_version=", ip_version, "labels=", labels);
    const auto& vrf_sptr = m_device->get_sptr(vrf);
    return do_set_vrf_properties(vrf_sptr, ip_version, labels);
}

la_status
la_prefix_object_base::get_vrf_properties(const la_vrf* vrf, la_ip_version_e ip_version, la_mpls_label_vec_t& out_labels) const
{
    start_api_getter_call();

    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vrf, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const auto& vrf_impl = m_device->get_sptr<const la_vrf_impl>(vrf);

    auto vpn_map_entry_it = m_vpn_entry_map.find(vrf_impl);
    if (vpn_map_entry_it == m_vpn_entry_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto map_entry = vpn_map_entry_it->second;

    if (ip_version == la_ip_version_e::IPV4) {
        out_labels = map_entry.ipv4_labels;
    } else {
        out_labels = map_entry.ipv6_labels;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::clear_vrf_properties(const la_vrf* vrf, la_ip_version_e ip_version)
{
    start_api_call("vrf=", vrf, "ip_version=", ip_version);

    const auto& vrf_sptr = m_device->get_sptr(vrf);
    return do_clear_vrf_properties(vrf_sptr, ip_version);
}

la_status
la_prefix_object_base::clear_te_tunnel_lsp_properties(const la_te_tunnel* te_tunnel)
{
    start_api_call("te_tunnel=", te_tunnel);

    const auto& te_tunner_sptr = m_device->get_sptr(te_tunnel);
    return do_clear_te_tunnel_lsp_properties(te_tunner_sptr);
}

la_status
la_prefix_object_base::do_clear_te_tunnel_lsp_properties(const la_te_tunnel_wcptr& te_tunnel)
{
    if (te_tunnel == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(te_tunnel, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status;
    const auto& te_tunnel_impl = te_tunnel.weak_ptr_static_cast<const la_te_tunnel_impl>();

    la_te_tunnel::tunnel_type_e type;
    status = te_tunnel_impl->get_tunnel_type(type);
    return_on_error(status);
    if (type == la_te_tunnel::tunnel_type_e::NORMAL) {
        return LA_STATUS_EINVAL;
    }

    auto te_pfx_obj_em_map_entry_it = m_te_pfx_obj_em_entry_map.find(te_tunnel_impl);
    if (te_pfx_obj_em_map_entry_it == m_te_pfx_obj_em_entry_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    status = teardown_large_encap_mpls_ldp_over_te_table_entry(te_tunnel_impl);
    return_on_error(status);

    status = release_counter(nullptr, te_pfx_obj_em_map_entry_it->second.counter);
    return_on_error(status);

    m_te_pfx_obj_em_entry_map.erase(te_pfx_obj_em_map_entry_it);
    m_device->remove_object_dependency(te_tunnel_impl, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::get_te_tunnel_lsp_properties(const la_te_tunnel* te_tunnel,
                                                    la_mpls_label_vec_t& out_labels,
                                                    const la_counter_set*& out_counter) const
{
    if (te_tunnel == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(te_tunnel, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const auto& te_tunnel_impl = m_device->get_sptr<const la_te_tunnel_impl>(te_tunnel);

    la_te_tunnel::tunnel_type_e type;
    la_status status = te_tunnel_impl->get_tunnel_type(type);
    return_on_error(status);
    if (type == la_te_tunnel::tunnel_type_e::NORMAL) {
        return LA_STATUS_EINVAL;
    }

    auto te_pfx_obj_em_map_entry_it = m_te_pfx_obj_em_entry_map.find(te_tunnel_impl);
    if (te_pfx_obj_em_map_entry_it == m_te_pfx_obj_em_entry_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }
    auto entry = te_pfx_obj_em_map_entry_it->second;
    out_labels = entry.labels;
    out_counter = entry.counter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::set_te_tunnel_lsp_properties(const la_te_tunnel* te_tunnel,
                                                    const la_mpls_label_vec_t& labels,
                                                    la_counter_set* counter)
{
    transaction txn;

    start_api_call("te_tunnel=", te_tunnel, "labels=", labels, "counter=", counter);

    if (te_tunnel == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(te_tunnel, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const la_counter_set_wptr& counter_wptr = m_device->get_sptr(counter);
    if ((counter != nullptr) && (!of_same_device(counter_wptr, this))) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const auto& te_tunnel_impl = m_device->get_sptr<const la_te_tunnel_impl>(te_tunnel);

    la_counter_set_wptr curr_counter = nullptr;

    auto te_em_map_entry_it = m_te_pfx_obj_em_entry_map.find(te_tunnel_impl);
    if (te_em_map_entry_it != m_te_pfx_obj_em_entry_map.end()) {
        curr_counter = te_em_map_entry_it->second.counter;
    }

    if (curr_counter != counter_wptr) {
        // Add the new counter.
        txn.status = allocate_counter(nullptr /*next_hop*/, counter_wptr, lsp_counter_mode_e::LABEL, COUNTER_DIRECTION_EGRESS);
        return_on_error(txn.status);
        txn.on_fail([=]() { release_counter(nullptr /* next_hop */, counter_wptr); });
    }

    la_te_tunnel::tunnel_type_e type;
    la_status status = te_tunnel_impl->get_tunnel_type(type);
    return_on_error(status);
    if (type == la_te_tunnel::tunnel_type_e::NORMAL) {
        return LA_STATUS_EINVAL;
    }

    status = configure_large_encap_mpls_ldp_over_te_table(te_tunnel_impl, labels, counter_wptr);
    return_on_error(status);

    if (te_em_map_entry_it == m_te_pfx_obj_em_entry_map.end()) {
        m_device->add_object_dependency(te_tunnel_impl, m_device->get_sptr(this));
    }

    te_pfx_obj_em_info& entry_info = m_te_pfx_obj_em_entry_map[te_tunnel_impl];
    entry_info.labels = labels;
    entry_info.counter = counter_wptr;

    if (curr_counter) {
        // Remove the nh from the current counter
        txn.status = release_counter(nullptr /* next_hop */, curr_counter);
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

void
la_prefix_object_base::prepare_tunnel_lsp_table_payload(npl_large_em_label_encap_data_and_counter_ptr_t& payload,
                                                        const la_mpls_label_vec_t& labels,
                                                        la_slice_pair_id_t pair_idx,
                                                        const la_counter_set_wcptr& counter,
                                                        const lsp_configuration_params& lsp_config,
                                                        bool ipv6_explicit_null_enabled,
                                                        uint64_t more_labels_index) const
{
    const auto& counter_impl = counter.weak_ptr_static_cast<const la_counter_set_impl>();

    payload.num_labels = labels.size();
    payload.counter_ptr = populate_counter_ptr_slice_pair(counter_impl, pair_idx, COUNTER_DIRECTION_EGRESS);
    payload.counter_ptr.update_or_read = counter ? 1 : 0;
    if (labels.size()) {
        payload.label_encap.label = labels[0].label;
    }
}

la_status
la_prefix_object_base::configure_large_encap_mpls_ldp_over_te_table(const la_te_tunnel_impl_wcptr& te_tunnel_impl,
                                                                    const la_mpls_label_vec_t& labels,
                                                                    const la_counter_set_wcptr& counter)
{
    const auto& table(m_device->m_tables.large_encap_mpls_ldp_over_te_table);
    npl_large_encap_mpls_ldp_over_te_table_key_t key;
    npl_large_encap_mpls_ldp_over_te_table_value_t value;
    npl_large_encap_mpls_ldp_over_te_table_entry_t* out_entry = nullptr;
    auto num_labels = labels.size();

    if (num_labels > 1) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    lsp_configuration_params lsp_config = get_lsp_configuration_params(labels, counter);

    key.te_tunnel = te_tunnel_impl->get_gid();
    key.lsp_dest_prefix = m_prefix_gid;
    value.action = NPL_LARGE_ENCAP_MPLS_LDP_OVER_TE_TABLE_ACTION_WRITE;

    // TODO: method signature is missing slice pair expecting counter to be always null
    prepare_tunnel_lsp_table_payload(value.payloads.large_em_label_encap_data_and_counter_ptr,
                                     labels,
                                     0,
                                     counter,
                                     lsp_config,
                                     true /*ipv6_explicit_null_enabled */,
                                     0 /* more_labels_index */);

    la_status status = table->set(key, value, out_entry);
    return status;
}

la_status
la_prefix_object_base::teardown_large_encap_mpls_ldp_over_te_table()
{
    vector_alloc<te_pfx_obj_em_entry_map_t::iterator> entries_to_remove;

    for (auto it = m_te_pfx_obj_em_entry_map.begin(); it != m_te_pfx_obj_em_entry_map.end(); it++) {
        entries_to_remove.push_back(it);
    }

    for (auto te_pfx_obj_em_map_entry_it : entries_to_remove) {
        auto key = te_pfx_obj_em_map_entry_it->first;
        la_status status = teardown_large_encap_mpls_ldp_over_te_table_entry(key);
        return_on_error(status);

        m_te_pfx_obj_em_entry_map.erase(te_pfx_obj_em_map_entry_it);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::teardown_large_encap_mpls_ldp_over_te_table_entry(const la_te_tunnel_impl_wcptr& te_tunnel_impl)
{
    const auto& table(m_device->m_tables.large_encap_mpls_ldp_over_te_table);
    npl_large_encap_mpls_ldp_over_te_table_key_t key;

    key.te_tunnel = te_tunnel_impl->get_gid();
    key.lsp_dest_prefix = m_prefix_gid;
    la_status status = table->erase(key);

    return status;
}

la_prefix_object_base::lsp_configuration_params
la_prefix_object_base::get_lsp_configuration_params(const la_mpls_label_vec_t& labels, const la_counter_set_wcptr& counter) const
{
    lsp_configuration_params lsp_config;
    lsp_config.multi_counter_enabled = false;
    lsp_config.sr_dm_accounting_enabled = false;

    auto num_labels = labels.size();
    // Flag set for v6ExpNull, SR DM Counter , Per Protocol Counter and Entropy Label
    bool flags_set = m_ipv6_explicit_null_enabled; // TODO Need to check for Entropy Label as well

    if (counter != nullptr) {
        const auto& counter_impl = counter.weak_ptr_static_cast<const la_counter_set_impl>();
        lsp_config.multi_counter_enabled = (counter_impl->get_type() == la_counter_set::type_e::MPLS_PER_PROTOCOL);
        lsp_config.sr_dm_accounting_enabled = (counter_impl->get_type() == la_counter_set::type_e::MPLS_TRAFFIC_MATRIX);
        flags_set = flags_set || (counter_impl->get_set_size() > 1);
    }
    lsp_config.program_additional_labels_table = ((num_labels > 3) || ((num_labels > 2) && (flags_set == true)));

    // max of 3 labels can fit in the lsp payload
    // if the multi_counter or ipv6 explicit null or entropy label flags are set or dm_counter is enabled, then the max is only 2
    lsp_config.lsp_payload_with_3_labels = (num_labels == 3) && (flags_set == false);

    return lsp_config;
}

void
la_prefix_object_base::prepare_lsp_table_payload(npl_lsp_encap_mapping_data_payload_t& payload,
                                                 const la_mpls_label_vec_t& labels,
                                                 la_slice_pair_id_t pair_idx,
                                                 const la_counter_set_wcptr& counter,
                                                 const lsp_configuration_params& lsp_config,
                                                 bool ipv6_explicit_null_enabled,
                                                 uint64_t more_labels_index) const
{
    auto num_labels = labels.size();
    const auto& counter_impl = counter.weak_ptr_static_cast<const la_counter_set_impl>();

    payload.counter_and_flag.lsp_counter = populate_counter_ptr_slice_pair(counter_impl, pair_idx, COUNTER_DIRECTION_EGRESS);
    // NPL uses counter read bit to indicate whther the 20 msb of the payload are the third label or used as flags.
    payload.counter_and_flag.lsp_counter.update_or_read = lsp_config.lsp_payload_with_3_labels ? 1 : 0;

    if (num_labels > 0) {
        payload.label_stack.opt1.labels_0_1.label_0 = labels[0].label;
    }

    if (num_labels > 1) {
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
        payload.label_stack.opt1.label_2_or_more.more.enable_sr_dm_accounting = lsp_config.sr_dm_accounting_enabled;
        payload.label_stack.opt1.label_2_or_more.more.service_flags.push_entropy_label = 0;
        payload.label_stack.opt1.label_2_or_more.more.service_flags.add_ipv6_explicit_null = ipv6_explicit_null_enabled ? 1 : 0;
        payload.label_stack.opt1.label_2_or_more.more.total_num_labels = num_labels;

        if (lsp_config.program_additional_labels_table) {
            payload.label_stack.opt1.label_2_or_more.more.more_labels.more_labels_index = more_labels_index;
        }
    }
}

la_status
la_prefix_object_base::configure_large_encap_global_lsp_prefix_table(la_slice_pair_id_t pair_idx,
                                                                     const la_mpls_label_vec_t& labels,
                                                                     const la_counter_set_wcptr& counter)
{
    transaction txn;

    auto num_labels = labels.size();
    // More labels index allocator allocates wide double entries so actual index is in multiples of 2
    // Removes this when allocator is enhanced to allocate narrow entries as well
    auto more_labels_index = m_global_lsp_prefix_info.em_info.more_labels_index;

    if (num_labels > 8) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    lsp_configuration_params lsp_config = get_lsp_configuration_params(labels, counter);

    // For runtime consistency we program the additional labels then we program the lsp table
    if (lsp_config.program_additional_labels_table) {
        const auto& additional_labels_table(m_device->m_tables.additional_labels_table[pair_idx]);
        npl_additional_labels_table_key_t additional_labels_table_key;
        npl_additional_labels_table_value_t additional_labels_table_value;
        npl_additional_labels_table_entry_t* out_additional_labels_table_entry = nullptr;

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

        bool clear_entry = false;
        npl_additional_labels_table_entry_t* old_entry = nullptr;
        npl_additional_labels_table_value_t old_value;
        txn.status = additional_labels_table->lookup(additional_labels_table_key, old_entry);
        if (txn.status == LA_STATUS_ENOTFOUND) {
            clear_entry = true;
        } else if (txn.status == LA_STATUS_SUCCESS) {
            old_value = old_entry->value();
        } else {
            return txn.status;
        }

        txn.status = additional_labels_table->set(
            additional_labels_table_key, additional_labels_table_value, out_additional_labels_table_entry);
        return_on_error(txn.status);
        txn.on_fail([&]() {
            if (clear_entry) {
                additional_labels_table->erase(additional_labels_table_key);
            } else {
                additional_labels_table->set(additional_labels_table_key, old_value, out_additional_labels_table_entry);
            }
        });
    }

    const auto& table(m_device->m_tables.large_encap_global_lsp_prefix_table[pair_idx]);
    npl_large_encap_global_lsp_prefix_table_key_t key;
    npl_large_encap_global_lsp_prefix_table_value_t value;
    npl_large_encap_global_lsp_prefix_table_entry_t* out_entry = nullptr;

    key.lsp_dest_prefix = m_prefix_gid;
    value.action = NPL_LARGE_ENCAP_GLOBAL_LSP_PREFIX_TABLE_ACTION_WRITE;

    prepare_lsp_table_payload(value.payloads.lsp_encap_mapping_data_payload,
                              labels,
                              pair_idx,
                              counter,
                              lsp_config,
                              m_ipv6_explicit_null_enabled,
                              more_labels_index);

    txn.status = table->set(key, value, out_entry);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::teardown_large_encap_global_lsp_prefix_table()
{
    for (auto pair_idx : silicon_one::get_slice_pairs(m_device, la_slice_mode_e::NETWORK)) {
        la_status status = teardown_large_encap_global_lsp_prefix_table_entry(pair_idx);
        return_on_error(status);
    }

    m_global_lsp_prefix_info.entry_present = false;

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::teardown_large_encap_global_lsp_prefix_table_entry(la_slice_pair_id_t pair_idx)
{
    const auto& table(m_device->m_tables.large_encap_global_lsp_prefix_table[pair_idx]);
    npl_large_encap_global_lsp_prefix_table_key_t key;

    if (m_global_lsp_prefix_info.em_info.more_labels_index_valid) {
        la_status status = teardown_encap_additional_labels_table_entry(pair_idx);
        return_on_error(status);
    }

    key.lsp_dest_prefix = m_prefix_gid;

    la_status status = table->erase(key);

    return status;
}

la_status
la_prefix_object_base::teardown_encap_additional_labels_table_entry(la_slice_pair_id_t pair_idx)
{
    const auto& additional_labels_table(m_device->m_tables.additional_labels_table[pair_idx]);
    npl_additional_labels_table_key_t additional_labels_table_key;

    additional_labels_table_key.labels_index = m_global_lsp_prefix_info.em_info.more_labels_index;

    la_status status = additional_labels_table->erase(additional_labels_table_key);

    return status;
}

la_status
la_prefix_object_base::configure_large_encap_mpls_he_no_ldp_table(la_slice_pair_id_t pair_idx,
                                                                  const la_next_hop_base_wcptr& nh,
                                                                  const la_mpls_label_vec_t& labels,
                                                                  const la_counter_set_wcptr& counter)
{
    const auto& table(m_device->m_tables.large_encap_mpls_he_no_ldp_table[pair_idx]);
    npl_large_encap_mpls_he_no_ldp_table_key_t key;
    npl_large_encap_mpls_he_no_ldp_table_value_t value;
    npl_large_encap_mpls_he_no_ldp_table_entry_t* out_entry = nullptr;

    lsp_configuration_params lsp_config = get_lsp_configuration_params(labels, counter);

    if (lsp_config.program_additional_labels_table) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    key.lsp_dest_prefix = m_prefix_gid;
    key.nh_ptr = nh->get_gid();
    value.action = NPL_LARGE_ENCAP_MPLS_HE_NO_LDP_TABLE_ACTION_WRITE;

    prepare_lsp_table_payload(value.payloads.lsp_encap_mapping_data_payload,
                              labels,
                              pair_idx,
                              counter,
                              lsp_config,
                              false /*ipv6_explicit_null_enabled */,
                              0 /* more_labels_index */);

    la_status status = table->set(key, value, out_entry);
    return status;
}

la_status
la_prefix_object_base::teardown_large_encap_mpls_he_no_ldp_table()
{
    vector_alloc<mpls_em_entry_map_t::iterator> entries_to_remove;

    for (auto it = m_mpls_em_entry_map.begin(); it != m_mpls_em_entry_map.end(); it++) {
        entries_to_remove.push_back(it);
    }

    for (auto mpls_em_map_entry_it : entries_to_remove) {
        auto next_hop = mpls_em_map_entry_it->first;
        for (auto pair_idx : get_slice_pairs(next_hop)) {
            la_status status = teardown_large_encap_mpls_he_no_ldp_table_entry(pair_idx, next_hop);
            return_on_error(status);
        }

        m_mpls_em_entry_map.erase(mpls_em_map_entry_it);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::teardown_large_encap_mpls_he_no_ldp_table_entry(la_slice_pair_id_t pair_idx,
                                                                       const la_next_hop_base_wcptr& next_hop)
{
    const auto& table(m_device->m_tables.large_encap_mpls_he_no_ldp_table[pair_idx]);
    npl_large_encap_mpls_he_no_ldp_table_key_t key;

    key.lsp_dest_prefix = m_prefix_gid;
    key.nh_ptr = next_hop->get_gid();

    la_status status = table->erase(key);

    return status;
}

la_status
la_prefix_object_base::register_asbr_lsp_next_hop(const la_next_hop_wcptr& nh)
{
    transaction txn;

    const auto& next_hop_base = nh.weak_ptr_static_cast<const la_next_hop_base>();

    // An entry should always be found for LDP. The outgoing label can be
    // Implicit NULL or a valid label.
    auto mpls_em_map_entry_it = m_mpls_em_entry_map.find(next_hop_base);
    if (mpls_em_map_entry_it == m_mpls_em_entry_map.end()) {
        return LA_STATUS_EINVAL;
    }

    mpls_em_info& entry_info = m_mpls_em_entry_map[next_hop_base];
    if (entry_info.ifgs == nullptr) {
        entry_info.ifgs = std::make_shared<ifg_use_count>(m_device->get_slice_id_manager());
    }

    entry_info.use_count++;

    if (entry_info.use_count != 1) {
        return LA_STATUS_SUCCESS;
    }

    // Update the tables with the new labels/counter
    for (auto pair_idx : get_slice_pairs(next_hop_base)) {
        txn.status = configure_small_encap_mpls_he_asbr_table(pair_idx, next_hop_base, entry_info.labels, entry_info.counter);
        return_on_error(txn.status);
        txn.on_fail([=]() { teardown_small_encap_mpls_he_asbr_table_entry(pair_idx, next_hop_base); });
    }

    return txn.status;
}

la_status
la_prefix_object_base::deregister_asbr_lsp_next_hop(const la_next_hop_wcptr& nh)
{
    transaction txn;

    const auto& next_hop_base = nh.weak_ptr_static_cast<const la_next_hop_base>();

    auto mpls_em_map_entry_it = m_mpls_em_entry_map.find(next_hop_base);
    if (mpls_em_map_entry_it == m_mpls_em_entry_map.end()) {
        return LA_STATUS_EINVAL;
    }

    mpls_em_info& entry_info = m_mpls_em_entry_map[next_hop_base];
    if (entry_info.ifgs == nullptr) {
        entry_info.ifgs = std::make_shared<ifg_use_count>(m_device->get_slice_id_manager());
    }

    if (entry_info.use_count == 0) {
        return LA_STATUS_SUCCESS;
    }

    entry_info.use_count--;

    if (entry_info.use_count > 0) {
        return LA_STATUS_SUCCESS;
    }

    // Update the tables with the new labels/counter
    for (auto pair_idx : get_slice_pairs(next_hop_base)) {
        la_mpls_label_vec_t old_labels = entry_info.labels;
        auto old_counter = entry_info.counter;

        txn.status = teardown_small_encap_mpls_he_asbr_table_entry(pair_idx, next_hop_base);
        return_on_error(txn.status);
        txn.on_fail([=]() { configure_small_encap_mpls_he_asbr_table(pair_idx, next_hop_base, old_labels, old_counter); });
    }

    return txn.status;
}

la_status
la_prefix_object_base::teardown_small_encap_mpls_he_asbr_table_entry(la_slice_pair_id_t pair_idx,
                                                                     const la_next_hop_base_wcptr& next_hop)
{
    const auto& table(m_device->m_tables.small_encap_mpls_he_asbr_table[pair_idx]);
    npl_small_encap_mpls_he_asbr_table_key_t key;

    key.asbr = m_prefix_gid;
    key.nh_ptr = next_hop->get_gid();

    la_status status = table->erase(key);

    return status;
}

la_status
la_prefix_object_base::configure_per_pe_and_vrf_vpn_key_large_table(const la_vrf_impl_wcptr& vrf_impl,
                                                                    la_ip_version_e ip_version,
                                                                    vpn_info& map_entry,
                                                                    const la_mpls_label_vec_t& labels)
{
    const auto& table(m_device->m_tables.per_pe_and_vrf_vpn_key_large_table);
    npl_per_pe_and_vrf_vpn_key_large_table_key_t key;
    npl_per_pe_and_vrf_vpn_key_large_table_value_t value;
    npl_per_pe_and_vrf_vpn_key_large_table_entry_t* out_entry = nullptr;

    key.lsp_destination = m_prefix_gid;
    key.l3_relay_id.id = vrf_impl->get_gid();
    value.action = NPL_PER_PE_AND_VRF_VPN_KEY_LARGE_TABLE_ACTION_WRITE;

    if (ip_version == la_ip_version_e::IPV4) {
        value.payloads.vpn_encap_data.single_label_encap_data.udat.label_and_valid.label_encap.label = labels[0].label;
        value.payloads.vpn_encap_data.single_label_encap_data.udat.label_and_valid.v4_label_vld = 1;
        if (map_entry.ipv6_valid) {
            value.payloads.vpn_encap_data.single_label_encap_data.v6_label_encap.label = map_entry.ipv6_labels[0].label;
        }
        value.payloads.vpn_encap_data.single_label_encap_data.udat.label_and_valid.v6_label_vld = map_entry.ipv6_valid;
    } else {
        if (map_entry.ipv4_valid) {
            value.payloads.vpn_encap_data.single_label_encap_data.udat.label_and_valid.label_encap.label
                = map_entry.ipv4_labels[0].label;
        }
        value.payloads.vpn_encap_data.single_label_encap_data.udat.label_and_valid.v4_label_vld = map_entry.ipv4_valid;
        value.payloads.vpn_encap_data.single_label_encap_data.v6_label_encap.label = labels[0].label;
        value.payloads.vpn_encap_data.single_label_encap_data.udat.label_and_valid.v6_label_vld = 1;
    }

    la_status status = table->set(key, value, out_entry);
    return status;
}

la_status
la_prefix_object_base::teardown_per_pe_and_vrf_vpn_key_large_table()
{
    vector_alloc<vpn_entry_map_t::iterator> entries_to_remove;

    for (auto it = m_vpn_entry_map.begin(); it != m_vpn_entry_map.end(); it++) {
        entries_to_remove.push_back(it);
    }

    for (auto vpn_map_entry_it : entries_to_remove) {
        auto vrf = vpn_map_entry_it->first;
        la_status status = teardown_per_pe_and_vrf_vpn_key_large_table_entry(vrf);
        return_on_error(status);

        m_vpn_entry_map.erase(vpn_map_entry_it);
        m_device->remove_object_dependency(vrf, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::teardown_per_pe_and_vrf_vpn_key_large_table_entry(const la_vrf_impl_wcptr& vrf_impl)
{
    const auto& table(m_device->m_tables.per_pe_and_vrf_vpn_key_large_table);
    npl_per_pe_and_vrf_vpn_key_large_table_key_t key;

    key.lsp_destination = m_prefix_gid;
    key.l3_relay_id.id = vrf_impl->get_gid();

    la_status status = table->erase(key);

    return status;
}

la_status
la_prefix_object_base::instantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::uninstantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

bool
la_prefix_object_base::is_counter_set_size_valid(const la_counter_set_impl_wcptr& counter,
                                                 lsp_counter_mode_e counter_mode,
                                                 const la_next_hop_base_wcptr& next_hop)
{
    bool is_global = (next_hop == nullptr);
    size_t counter_set_size = counter->get_set_size();

    switch (counter_mode) {
    case lsp_counter_mode_e::LABEL:
        if (counter_set_size != 1) {
            return false;
        }
        break;

    case lsp_counter_mode_e::TRAFFIC_MATRIX:
        if (counter_set_size != 2) {
            return false;
        }
        break;

    case lsp_counter_mode_e::PER_PROTOCOL:
        // Only Global SR Prefixes support per-protocol counter
        if (!is_global || (counter_set_size != 2)) {
            return false;
        }
        break;

    default:
        return false;
    }

    return true;
}

la_counter_set::type_e
la_prefix_object_base::lsp_counter_mode_get_counter_type(lsp_counter_mode_e counter_mode)
{
    switch (counter_mode) {
    case lsp_counter_mode_e::LABEL:
        return (la_counter_set::type_e::MPLS_LABEL);

    case lsp_counter_mode_e::TRAFFIC_MATRIX:
        return (la_counter_set::type_e::MPLS_TRAFFIC_MATRIX);

    case lsp_counter_mode_e::PER_PROTOCOL:
        return (la_counter_set::type_e::MPLS_PER_PROTOCOL);
    }

    return (la_counter_set::type_e::INVALID);
}

la_status
la_prefix_object_base::allocate_counter(const la_next_hop_base_wcptr& next_hop,
                                        const la_counter_set_wptr& new_counter,
                                        lsp_counter_mode_e counter_mode,
                                        counter_direction_e direction)
{
    // Check the counter's set size
    // Only Global SR Prefixes support per-protocol counter

    const auto& new_counter_impl = new_counter.weak_ptr_static_cast<la_counter_set_impl>();
    if (new_counter_impl == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    if (!is_counter_set_size_valid(new_counter_impl, counter_mode, next_hop)) {
        return LA_STATUS_EINVAL;
    }

    la_counter_set::type_e type = lsp_counter_mode_get_counter_type(counter_mode);

    if (next_hop != nullptr) {
        // Add the nh's slices to the new counter
        la_status status = new_counter_impl->add_pq_counter_user(next_hop, type, direction, silicon_one::is_aggregate_nh(next_hop));
        return_on_error(status);
    } else {
        la_status status = new_counter_impl->add_global_lsp_prefix_counter(type);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::add_ifg(const la_next_hop_base_wcptr& nh, la_slice_ifg ifg)
{
    log_debug(HLD, "la_prefix_object_base::%s nh=%s slice=%d ifg=%d", __func__, nh->to_string().c_str(), ifg.slice, ifg.ifg);

    transaction txn;

    auto mpls_em_map_entry_it = m_mpls_em_entry_map.find(nh);
    if (mpls_em_map_entry_it == m_mpls_em_entry_map.end()) {
        log_err(HLD, "la_prefix_object_base::%s: got notification from unknown next-hop", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    auto& map_entry = mpls_em_map_entry_it->second;
    bool ifg_added, slice_added, slice_pair_added;
    map_entry.ifgs->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([&]() {
        bool dummy;
        map_entry.ifgs->remove_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (slice_pair_added) {
        la_slice_pair_id_t pair_idx = ifg.slice / 2;
        la_mpls_label_vec_t labels;
        la_counter_set_wcptr counter;
        lsp_counter_mode_e counter_mode;

        txn.status = do_get_nh_lsp_properties(nh, labels, counter, counter_mode);
        return_on_error(txn.status);

        txn.status = configure_large_encap_mpls_he_no_ldp_table(pair_idx, nh, labels, counter);
        return_on_error(txn.status);
        txn.on_fail([=]() { teardown_large_encap_mpls_he_no_ldp_table_entry(pair_idx, nh); });

        mpls_em_info& entry_info = m_mpls_em_entry_map[nh];
        if (entry_info.ifgs == nullptr) {
            entry_info.ifgs = std::make_shared<ifg_use_count>(m_device->get_slice_id_manager());
        }

        if (entry_info.use_count != 0) {
            txn.status = configure_small_encap_mpls_he_asbr_table(pair_idx, nh, labels, counter);
            return_on_error(txn.status);
            txn.on_fail([=]() { teardown_small_encap_mpls_he_asbr_table_entry(pair_idx, nh); });
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

    return txn.status;
}

la_status
la_prefix_object_base::remove_ifg(const la_next_hop_base_wcptr& nh, la_slice_ifg ifg)
{
    log_debug(HLD, "la_prefix_object_base::%s nh=%s slice=%d ifg=%d", __func__, nh->to_string().c_str(), ifg.slice, ifg.ifg);

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
        txn.on_fail([=]() { m_device->notify_ifg_added(this, ifg); });
    }

    auto mpls_em_map_entry_it = m_mpls_em_entry_map.find(nh);
    if (mpls_em_map_entry_it == m_mpls_em_entry_map.end()) {
        log_err(HLD, "la_prefix_object_base::%s: got notification from unknown next-hop", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    auto& map_entry = mpls_em_map_entry_it->second;
    la_mpls_label_vec_t labels = map_entry.labels;
    auto counter = map_entry.counter;
    map_entry.ifgs->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);
    txn.on_fail([&]() {
        bool dummy;
        map_entry.ifgs->add_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (!slice_pair_removed) {
        return LA_STATUS_SUCCESS;
    }

    la_slice_pair_id_t pair_idx = ifg.slice / 2;
    txn.status = teardown_large_encap_mpls_he_no_ldp_table_entry(pair_idx, nh);
    return_on_error(txn.status);
    txn.on_fail([=]() { configure_large_encap_mpls_he_no_ldp_table(pair_idx, nh, labels, counter); });

    mpls_em_info& entry_info = m_mpls_em_entry_map[nh];
    if (entry_info.ifgs == nullptr) {
        entry_info.ifgs = std::make_shared<ifg_use_count>(m_device->get_slice_id_manager());
    }

    if (entry_info.use_count != 0) {
        txn.status = teardown_small_encap_mpls_he_asbr_table_entry(pair_idx, nh);
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::release_counter(const la_next_hop_base_wcptr& next_hop, const la_counter_set_wptr& curr_counter)
{
    const auto& curr_counter_impl = curr_counter.weak_ptr_static_cast<la_counter_set_impl>();

    if (curr_counter_impl == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    if (next_hop != nullptr) {
        // Remove the nh's slices from the current counter
        la_status status = curr_counter_impl->remove_pq_counter_user(next_hop);
        return_on_error(status);
    } else {
        la_status status = curr_counter_impl->remove_global_lsp_prefix_counter();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::get_ipv6_explicit_null_enabled(bool& out_enabled) const
{
    out_enabled = m_ipv6_explicit_null_enabled;
    return LA_STATUS_SUCCESS;
}

la_status
la_prefix_object_base::set_ipv6_explicit_null_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    if (m_global_lsp_prefix == false) {
        return LA_STATUS_EINVAL;
    }

    if (m_ipv6_explicit_null_enabled == enabled) {
        return LA_STATUS_SUCCESS;
    }

    m_ipv6_explicit_null_enabled = enabled;

    lsp_configuration_params lsp_config
        = get_lsp_configuration_params(m_global_lsp_prefix_info.em_info.labels, m_global_lsp_prefix_info.em_info.counter);

    // Allocate a new index for additional_labels_table the first time if the
    // LSP configuration parameters require additional table lookup
    if ((m_global_lsp_prefix_info.em_info.more_labels_index_valid == false) && lsp_config.program_additional_labels_table) {
        bool allocated
            = m_device->m_index_generators.sr_extended_policies.allocate(m_global_lsp_prefix_info.em_info.more_labels_index);
        if (!allocated) {
            return LA_STATUS_ERESOURCE;
        }
        m_global_lsp_prefix_info.em_info.more_labels_index_valid = true;
    } else if ((m_global_lsp_prefix_info.em_info.more_labels_index_valid == true)
               && (!lsp_config.program_additional_labels_table)) {
        m_device->m_index_generators.sr_extended_policies.release(m_global_lsp_prefix_info.em_info.more_labels_index);
        m_global_lsp_prefix_info.em_info.more_labels_index_valid = false;
    }

    if (m_global_lsp_prefix_info.entry_present) {
        auto labels = m_global_lsp_prefix_info.em_info.labels;
        auto counter = m_global_lsp_prefix_info.em_info.counter;

        for (auto pair_idx : silicon_one::get_slice_pairs(m_device, la_slice_mode_e::NETWORK)) {
            la_status status = configure_large_encap_global_lsp_prefix_table(pair_idx, labels, counter);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

bool
la_prefix_object_base::is_pbts_eligible() const
{
    return (m_prefix_gid >= m_device->get_pbts_start_id());
}

bool
la_prefix_object_base::is_resolution_forwarding_supported() const
{
    if ((m_global_lsp_prefix) && (m_destination->type() != object_type_e::ECMP_GROUP)) {
        return false;
    }

    return true;
}

} // namespace silicon_one
