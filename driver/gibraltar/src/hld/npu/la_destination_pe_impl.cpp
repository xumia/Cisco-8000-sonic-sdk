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

#include "npu/la_destination_pe_impl.h"
#include "hld_utils.h"
#include "la_ecmp_group_impl.h"
#include "npu/la_prefix_object_base.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_destination_pe_impl::la_destination_pe_impl(const la_device_impl_wptr& device)
    : m_device(device), m_gid(LA_L3_DESTINATION_GID_INVALID), m_destination(nullptr), m_vpn_enabled(false)
{
}

la_destination_pe_impl::~la_destination_pe_impl()
{
}

la_status
la_destination_pe_impl::initialize(la_object_id_t oid,
                                   la_l3_destination_gid_t destination_pe_gid,
                                   const la_l3_destination_wcptr& destination)
{
    m_oid = oid;
    m_gid = destination_pe_gid;

    la_status status = update_destination(destination, true);
    return_on_error(status);

    add_dependency(destination);

    return LA_STATUS_SUCCESS;
}

la_status
la_destination_pe_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    remove_dependency(m_destination);

    la_status status = teardown_stage0_prefix_table();
    return_on_error(status);

    status = teardown_per_pe_and_vrf_vpn_key_large_table();
    return_on_error(status);

    status = teardown_per_asbr_and_dpe_table();
    return_on_error(status);

    status = uninstantiate_resolution_object(m_destination, RESOLUTION_STEP_STAGE0_CE_PTR);
    return status;
}

la_l3_destination_gid_t
la_destination_pe_impl::get_gid() const
{
    return m_gid;
}

la_object::object_type_e
la_destination_pe_impl::type() const
{
    return object_type_e::DESTINATION_PE;
}

std::string
la_destination_pe_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_destination_pe_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_destination_pe_impl::oid() const
{
    return m_oid;
}

const la_device*
la_destination_pe_impl::get_device() const
{
    return m_device.get();
}

void
la_destination_pe_impl::add_dependency(const la_l3_destination_wcptr& destination)
{
    m_device->add_object_dependency(destination, this);
}

void
la_destination_pe_impl::remove_dependency(const la_l3_destination_wcptr& destination)
{
    m_device->remove_object_dependency(destination, this);
}

const la_l3_destination*
la_destination_pe_impl::get_destination() const
{
    return m_destination.get();
}

la_status
la_destination_pe_impl::set_destination(const la_l3_destination* destination)
{
    start_api_call("destination=", destination);

    const auto& destination_sp = m_device->get_sptr<la_l3_destination>(destination);

    if (m_destination.get() == destination_sp.get()) {
        return LA_STATUS_SUCCESS;
    }

    la_l3_destination_wcptr old_destination = m_destination;

    la_status status = update_destination(destination_sp, false);
    return_on_error(status);

    status = uninstantiate_resolution_object(old_destination, RESOLUTION_STEP_STAGE0_CE_PTR);
    return_on_error(status);

    remove_dependency(old_destination);
    add_dependency(destination_sp);

    return LA_STATUS_SUCCESS;
}

la_status
la_destination_pe_impl::update_destination(const la_l3_destination_wcptr& destination, bool is_init)
{
    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_object::object_type_e dest_type = destination->type();
    if (dest_type != object_type_e::ECMP_GROUP) {
        return LA_STATUS_EINVAL;
    }

    if (dest_type == object_type_e::ECMP_GROUP) {
        la_ecmp_group_impl_wcptr ecmp_group = destination.weak_ptr_static_cast<const la_ecmp_group_impl>();
        if (ecmp_group->get_ecmp_level() != la_ecmp_group::level_e::LEVEL_2) {
            return LA_STATUS_EINVAL;
        }

        if (ecmp_group->has_only_asbr_lsps_configured() == false) {
            return LA_STATUS_EINVAL;
        }
    }

    la_status status
        = m_device->validate_destination_gid_format_match(la_device_impl::resolution_lp_table_format_e::NARROW, m_gid, is_init);
    return_on_error(status);

    status = instantiate_resolution_object(destination, RESOLUTION_STEP_STAGE0_CE_PTR, this);
    return_on_error(status);

    if (!is_init) {
        status = m_device->clear_destination_gid_format(m_gid);
        return_on_error(status);
    }

    status = m_device->update_destination_gid_format(la_device_impl::resolution_lp_table_format_e::NARROW, m_gid);
    return_on_error(status);

    m_destination = destination;

    status = configure_stage0_prefix_table();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_destination_pe_impl::configure_stage0_prefix_table()
{
    la_status status = configure_stage0_ce_ptr_to_ecmp_group_value();

    return status;
}

la_status
la_destination_pe_impl::configure_stage0_ce_ptr_to_ecmp_group_value()
{
    npl_resolution_stage_assoc_data_wide_entry_t entry_pfx{{0}};
    auto& entry(entry_pfx.stage0_ce_ptr_ecmp2);
    destination_id key = get_destination_id(RESOLUTION_STEP_FORWARD_MPLS);
    destination_id dest_id = silicon_one::get_destination_id(m_destination, RESOLUTION_STEP_STAGE0_CE_PTR);

    entry.destination = dest_id.val;
    entry.vpn_inter_as = (m_vpn_enabled << CE_PTR_VPN_OFFSET) | (1 << CR_PTR_INTER_AS_OFFSET);
    entry.ce_ptr = m_gid;
    entry.type = NPL_ENTRY_TYPE_STAGE0_CE_PTR_DESTINATION_VPN_INTER_AS_CE_PTR;

    la_status status = m_device->m_resolution_configurators[0].configure_dest_map_entry(key, entry_pfx, m_res_cfg_handle);
    return status;
}

la_status
la_destination_pe_impl::teardown_stage0_prefix_table()
{
    la_status status = m_device->m_resolution_configurators[0].unconfigure_entry(m_res_cfg_handle);
    return status;
}

la_status
la_destination_pe_impl::clear_vrf_properties(const la_vrf* vrf, la_ip_version_e protocol)
{
    start_api_call("vrf=", vrf, "protocol=", protocol);
    la_vrf_impl_wcptr vrf_impl = m_device->get_sptr<const la_vrf_impl>(vrf);

    if (vrf_impl == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vrf_impl, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto vpn_map_entry_it = m_vpn_entry_map.find(vrf_impl);
    if (vpn_map_entry_it == m_vpn_entry_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    vpn_info& entry_info = m_vpn_entry_map[vrf_impl];

    if (protocol == la_ip_version_e::IPV4) {
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
        m_device->remove_object_dependency(vrf_impl, this);
    } else {
        if (protocol == la_ip_version_e::IPV4) {
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
        la_status status = configure_stage0_prefix_table();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_destination_pe_impl::get_vrf_properties(const la_vrf* vrf, la_ip_version_e protocol, la_mpls_label_vec_t& out_labels) const
{
    la_vrf_impl_wcptr vrf_impl = m_device->get_sptr<const la_vrf_impl>(vrf);

    if (vrf_impl == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vrf_impl, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto vpn_map_entry_it = m_vpn_entry_map.find(vrf_impl);
    if (vpn_map_entry_it == m_vpn_entry_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto& map_entry = vpn_map_entry_it->second;

    if (protocol == la_ip_version_e::IPV4) {
        out_labels = map_entry.ipv4_labels;
    } else {
        out_labels = map_entry.ipv6_labels;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_destination_pe_impl::set_vrf_properties(const la_vrf* vrf, la_ip_version_e protocol, const la_mpls_label_vec_t& labels)
{
    start_api_call("vrf=", vrf, "protocol=", protocol, "labels=", labels);

    la_vrf_impl_wcptr vrf_impl = m_device->get_sptr<const la_vrf_impl>(vrf);

    if (vrf_impl == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vrf_impl, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Check if the label stack has one VPN label.
    if (labels.size() != 1) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    auto vpn_map_entry_it = m_vpn_entry_map.find(vrf_impl);
    if (vpn_map_entry_it == m_vpn_entry_map.end()) {
        // Add vrf dependency only once
        m_device->add_object_dependency(vrf, this);
    }

    vpn_info& entry_info = m_vpn_entry_map[vrf_impl];
    if (protocol == la_ip_version_e::IPV4) {
        entry_info.ipv4_labels = labels;
        entry_info.ipv4_valid = true;
    } else {
        entry_info.ipv6_labels = labels;
        entry_info.ipv6_valid = true;
    }

    // Update the tables with the new label
    la_status status = configure_per_pe_and_vrf_vpn_key_large_table(vrf_impl, protocol, entry_info, labels);
    return_on_error(status);

    if (m_vpn_enabled == false) {
        m_vpn_enabled = true;
        la_status status = configure_stage0_prefix_table();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_destination_pe_impl::configure_per_pe_and_vrf_vpn_key_large_table(const la_vrf_impl_wcptr& vrf_impl,
                                                                     la_ip_version_e protocol,
                                                                     vpn_info& map_entry,
                                                                     const la_mpls_label_vec_t& labels)
{
    const auto& table(m_device->m_tables.per_pe_and_vrf_vpn_key_large_table);
    npl_per_pe_and_vrf_vpn_key_large_table_key_t key;
    npl_per_pe_and_vrf_vpn_key_large_table_value_t value;
    npl_per_pe_and_vrf_vpn_key_large_table_entry_t* out_entry = nullptr;

    key.lsp_destination = m_gid;
    key.l3_relay_id.id = vrf_impl->get_gid();
    value.action = NPL_PER_PE_AND_VRF_VPN_KEY_LARGE_TABLE_ACTION_WRITE;

    if (protocol == la_ip_version_e::IPV4) {
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

    value.payloads.vpn_encap_data.single_label_encap_data.udat.label_and_valid.v6_label_vld = 1;

    la_status status = table->set(key, value, out_entry);
    return status;
}

la_status
la_destination_pe_impl::teardown_per_pe_and_vrf_vpn_key_large_table()
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
la_destination_pe_impl::teardown_per_pe_and_vrf_vpn_key_large_table_entry(const la_vrf_impl_wcptr& vrf_impl)
{
    const auto& table(m_device->m_tables.per_pe_and_vrf_vpn_key_large_table);
    npl_per_pe_and_vrf_vpn_key_large_table_key_t key;

    key.lsp_destination = m_gid;
    key.l3_relay_id.id = vrf_impl->get_gid();

    la_status status = table->erase(key);

    return status;
}

la_status
la_destination_pe_impl::clear_asbr_properties(const la_prefix_object* asbr)
{
    start_api_call("asbr=", asbr);
    la_prefix_object_base_wcptr asbr_base = m_device->get_sptr<const la_prefix_object_base>(asbr);

    if (asbr_base == nullptr) {
        return LA_STATUS_EINVAL;
    }

    auto asbr_map_entry_it = m_asbr_entry_map.find(asbr_base);
    if (asbr_map_entry_it == m_asbr_entry_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    la_status status = teardown_per_asbr_and_dpe_table_entry(asbr_base);
    return_on_error(status);

    m_asbr_entry_map.erase(asbr_map_entry_it);
    m_device->remove_object_dependency(asbr_base, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_destination_pe_impl::get_asbr_properties(const la_prefix_object* asbr, la_mpls_label_vec_t& out_labels) const
{
    start_api_call("asbr=", asbr);
    la_prefix_object_base_wcptr asbr_base = m_device->get_sptr<const la_prefix_object_base>(asbr);

    if (asbr_base == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(asbr_base, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto asbr_map_entry_it = m_asbr_entry_map.find(asbr_base);
    if (asbr_map_entry_it == m_asbr_entry_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto map_entry = asbr_map_entry_it->second;

    out_labels = map_entry.labels;

    return LA_STATUS_SUCCESS;
}

la_status
la_destination_pe_impl::set_asbr_properties(const la_prefix_object* asbr, const la_mpls_label_vec_t& labels)
{
    start_api_call("asbr=", asbr, "labels=", labels);
    la_prefix_object_base_wcptr asbr_base = m_device->get_sptr<const la_prefix_object_base>(asbr);

    if (asbr_base == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(asbr_base, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Check if the label stack has more than one label.
    if (labels.size() > 1) {
        return LA_STATUS_EINVAL;
    }

    // Update the tables with the new label
    la_status status = configure_per_asbr_and_dpe_table(asbr_base, labels);
    return_on_error(status);

    if (m_asbr_entry_map.empty()) {
        // Add asbr dependency only once
        m_device->add_object_dependency(asbr_base, this);
    }

    asbr_info& entry_info = m_asbr_entry_map[asbr_base];
    entry_info.labels = labels;

    return LA_STATUS_SUCCESS;
}

la_status
la_destination_pe_impl::configure_per_asbr_and_dpe_table(const la_prefix_object_base_wcptr& asbr_impl,
                                                         const la_mpls_label_vec_t& labels)
{
    const auto& table(m_device->m_tables.per_asbr_and_dpe_table);
    npl_per_asbr_and_dpe_table_key_t key;
    npl_per_asbr_and_dpe_table_value_t value;
    npl_per_asbr_and_dpe_table_entry_t* out_entry = nullptr;

    key.asbr = asbr_impl->get_gid();
    key.dpe = m_gid;
    value.action = NPL_PER_ASBR_AND_DPE_TABLE_ACTION_WRITE;
    if (labels.size()) {
        value.payloads.large_em_label_encap_data_and_counter_ptr.label_encap.label = labels[0].label;
    }
    value.payloads.large_em_label_encap_data_and_counter_ptr.num_labels = labels.size();
    value.payloads.large_em_label_encap_data_and_counter_ptr.counter_ptr.update_or_read = 0; // Disable counter till SDK implemented

    la_status status = table->set(key, value, out_entry);
    return status;
}

la_status
la_destination_pe_impl::teardown_per_asbr_and_dpe_table()
{
    vector_alloc<asbr_entry_map_t::iterator> entries_to_remove;

    for (auto it = m_asbr_entry_map.begin(); it != m_asbr_entry_map.end(); it++) {
        entries_to_remove.push_back(it);
    }

    for (auto asbr_map_entry_it : entries_to_remove) {
        auto asbr_impl = asbr_map_entry_it->first;
        la_status status = teardown_per_asbr_and_dpe_table_entry(asbr_impl);
        return_on_error(status);

        m_asbr_entry_map.erase(asbr_map_entry_it);
        m_device->remove_object_dependency(asbr_impl, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_destination_pe_impl::teardown_per_asbr_and_dpe_table_entry(const la_prefix_object_base_wcptr& asbr_impl)
{
    const auto& table(m_device->m_tables.per_asbr_and_dpe_table);
    npl_per_asbr_and_dpe_table_key_t key;

    key.asbr = asbr_impl->get_gid();
    key.dpe = m_gid;

    la_status status = table->erase(key);

    return status;
}

resolution_step_e
la_destination_pe_impl::get_next_resolution_step(resolution_step_e prev_step) const
{
    if (prev_step == RESOLUTION_STEP_FORWARD_L3) {
        return RESOLUTION_STEP_STAGE0_CE_PTR;
    }

    if (prev_step == RESOLUTION_STEP_FORWARD_L2) {
        return RESOLUTION_STEP_STAGE0_CE_PTR;
    }

    if (prev_step == RESOLUTION_STEP_FORWARD_MPLS) {
        return RESOLUTION_STEP_STAGE0_CE_PTR;
    }

    if (prev_step == RESOLUTION_STEP_STAGE0_ECMP) {
        return RESOLUTION_STEP_STAGE0_CE_PTR;
    }

    return RESOLUTION_STEP_INVALID;
}

lpm_destination_id
la_destination_pe_impl::get_lpm_destination_id(resolution_step_e prev_step) const
{
    return lpm_destination_id(NPL_LPM_COMPRESSED_DESTINATION_CE_PTR_MASK | m_gid);
}

destination_id
la_destination_pe_impl::get_destination_id(resolution_step_e prev_step) const
{
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    switch (cur_step) {
    case silicon_one::RESOLUTION_STEP_STAGE0_CE_PTR: {
        return destination_id(NPL_DESTINATION_MASK_CE_PTR | m_gid);
    }

    default: {
        return DESTINATION_ID_INVALID;
    }
    }
}

la_status
la_destination_pe_impl::get_resolution_cfg_handle(const resolution_cfg_handle_t*& out_cfg_handle) const
{
    out_cfg_handle = &m_res_cfg_handle;
    return LA_STATUS_SUCCESS;
}

la_status
la_destination_pe_impl::instantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_destination_pe_impl::uninstantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
