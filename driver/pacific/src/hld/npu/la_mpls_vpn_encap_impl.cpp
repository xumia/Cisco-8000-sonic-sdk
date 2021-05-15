// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "la_mpls_vpn_encap_impl.h"
#include "hld_utils.h"
#include "la_ecmp_group_impl.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_mpls_vpn_encap_impl::la_mpls_vpn_encap_impl(const la_device_impl_wptr& device) : m_device(device), m_destination(nullptr)
{
}

la_mpls_vpn_encap_impl::~la_mpls_vpn_encap_impl()
{
}

la_object::object_type_e
la_mpls_vpn_encap_impl::type() const
{
    return la_object::object_type_e::MPLS_VPN_ENCAP;
}

std::string
la_mpls_vpn_encap_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_mpls_vpn_encap_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_mpls_vpn_encap_impl::oid() const
{
    return m_oid;
}

const la_device*
la_mpls_vpn_encap_impl::get_device() const
{
    return m_device.get();
}

la_status
la_mpls_vpn_encap_impl::initialize(la_object_id_t oid, la_mpls_vpn_encap_gid_t gid)
{
    m_oid = oid;
    m_gid = gid;

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_vpn_encap_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        log_err(HLD, "VPN ENCAP object is busy");
        return LA_STATUS_EBUSY;
    }

    // Clear all entries
    std::vector<la_l3_destination_wcptr> entries_to_clear;
    for (auto it : m_nh_label_map) {
        entries_to_clear.push_back(it.first);
    }
    for (auto entry : entries_to_clear) {
        la_status status = teardown_per_pe_and_prefix_table_entry(entry.get());
        return_on_error(status);
    }

    clear_destination();

    return LA_STATUS_SUCCESS;
}

la_mpls_vpn_encap_gid_t
la_mpls_vpn_encap_impl::get_gid() const
{
    return m_gid;
}

const la_l3_destination*
la_mpls_vpn_encap_impl::get_destination() const
{
    return m_destination.get();
}

la_status
la_mpls_vpn_encap_impl::set_destination(const la_l3_destination* destination)
{
    start_api_call("destination=", destination);

    const auto& destination_sp = m_device->get_sptr(destination);

    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_object::object_type_e type = destination_sp->type();
    switch (type) {
    case la_object::object_type_e::PREFIX_OBJECT:
    case la_object::object_type_e::PBTS_GROUP:
        break;
    case la_object::object_type_e::DESTINATION_PE:
        break;
    case la_object::object_type_e::ECMP_GROUP: {
        const auto& ecmp_group = std::static_pointer_cast<const la_ecmp_group_impl>(destination_sp);
        if (ecmp_group->get_ecmp_level() != la_ecmp_group::level_e::LEVEL_1) {
            log_err(HLD, "ECMP Group level should be 1");
            return LA_STATUS_EINVAL;
        }
    } break;
    default:
        log_err(HLD, "Invalid destination object type");
        return LA_STATUS_EINVAL;
    }

    la_status status = instantiate_resolution_object(destination_sp, RESOLUTION_STEP_FORWARD_L3);
    return_on_error(status, HLD, ERROR, "failed to instantiate resolution object");

    destination_id dest_id = silicon_one::get_destination_id(destination_sp, RESOLUTION_STEP_FORWARD_L3);
    if (dest_id == DESTINATION_ID_INVALID) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    const auto& table(m_device->m_tables.ip_prefix_destination_table);
    npl_ip_prefix_destination_table_key_t key;
    npl_ip_prefix_destination_table_value_t value;
    npl_ip_prefix_destination_table_entry_t* entry = nullptr;

    key.ip_prefix_ptr = m_gid;
    value.payloads.prefix_destination.val = dest_id.val;

    status = table->set(key, value, entry);
    return_on_error(status);

    if (m_destination != nullptr) {
        status = uninstantiate_resolution_object(m_destination, RESOLUTION_STEP_FORWARD_L3);
        return_on_error(status);

        m_device->remove_object_dependency(m_destination, this);
    }

    m_destination = destination_sp;
    m_device->add_object_dependency(m_destination, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_vpn_encap_impl::clear_destination()
{
    if (m_destination == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = uninstantiate_resolution_object(m_destination, RESOLUTION_STEP_FORWARD_L3);
    return_on_error(status, HLD, ERROR, "failed to uninstantiate resolution object");

    const auto& table(m_device->m_tables.ip_prefix_destination_table);
    npl_ip_prefix_destination_table_key_t key;

    key.ip_prefix_ptr = m_gid;

    status = table->erase(key);
    return_on_error(status);

    m_device->remove_object_dependency(m_destination, this);

    m_destination = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_vpn_encap_impl::configure_per_pe_and_prefix_vpn_table_entry(const la_l3_destination* nh, const nh_info& entry)
{
    npl_per_pe_and_prefix_vpn_key_large_table_key_t key;
    npl_per_pe_and_prefix_vpn_key_large_table_value_t value;
    npl_per_pe_and_prefix_vpn_key_large_table_entry_t* out_entry = nullptr;

    la_l3_destination_gid_t nh_id;

    la_object::object_type_e nh_type = nh->type();
    switch (nh_type) {
    case la_object::object_type_e::PREFIX_OBJECT: {
        const auto& nh_impl = m_device->get_sptr<const la_prefix_object_base>(nh);
        nh_id = nh_impl->get_gid();
        break;
    }

    case la_object::object_type_e::DESTINATION_PE: {
        const auto& nh_impl = m_device->get_sptr<const la_destination_pe_impl>(nh);
        nh_id = nh_impl->get_gid();
        break;
    }

    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    key.ip_prefix_id = m_gid;
    key.lsp_destination = nh_id;

    if (entry.v4_valid) {
        value.payloads.vpn_encap_data.single_label_encap_data.udat.label_and_valid.label_encap.label = entry.v4_label[0].label;
    }
    value.payloads.vpn_encap_data.single_label_encap_data.udat.label_and_valid.label_encap.label_exp_bos.bos = 1;
    value.payloads.vpn_encap_data.single_label_encap_data.udat.label_and_valid.label_encap.label_exp_bos.exp = 0;
    value.payloads.vpn_encap_data.single_label_encap_data.udat.label_and_valid.v4_label_vld = entry.v4_valid;

    if (entry.v6_valid) {
        value.payloads.vpn_encap_data.single_label_encap_data.v6_label_encap.label = entry.v6_label[0].label;
    }
    value.payloads.vpn_encap_data.single_label_encap_data.v6_label_encap.label_exp_bos.bos = 1;
    value.payloads.vpn_encap_data.single_label_encap_data.v6_label_encap.label_exp_bos.exp = 0;
    value.payloads.vpn_encap_data.single_label_encap_data.udat.label_and_valid.v6_label_vld = entry.v6_valid;

    const auto& table(m_device->m_tables.per_pe_and_prefix_vpn_key_large_table);
    auto status = table->set(key, value, out_entry);
    return_on_error(status, HLD, ERROR, "large vpn label table insertion failed");

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_vpn_encap_impl::set_nh_vpn_properties(const la_l3_destination* nh,
                                              la_ip_version_e ip_version,
                                              const la_mpls_label_vec_t& labels)
{
    start_api_call("nh=", nh, "ip_version=", ip_version, "labels=", labels);

    transaction txn;

    if (nh == nullptr) {
        return LA_STATUS_EINVAL;
    }

    // Only support 1 VPN label for now
    if (labels.size() != 1) {
        log_err(HLD, "number of VPN label is not 1");
        return LA_STATUS_EINVAL;
    }

    const auto& nh_sptr = m_device->get_sptr<const la_l3_destination>(nh);
    auto& entry = m_nh_label_map[nh_sptr];

    if (ip_version == la_ip_version_e::IPV4) {
        bool old_valid = entry.v4_valid;
        la_mpls_label_vec_t old_labels = entry.v4_label;

        entry.v4_valid = true;
        entry.v4_label = labels;
        txn.on_fail([&]() {
            entry.v4_valid = old_valid;
            entry.v4_label = old_labels;
        });
    } else {
        bool old_valid = entry.v6_valid;
        la_mpls_label_vec_t old_labels = entry.v6_label;

        entry.v6_valid = true;
        entry.v6_label = labels;
        txn.on_fail([&]() {
            entry.v6_valid = old_valid;
            entry.v6_label = old_labels;
        });
    }

    txn.status = configure_per_pe_and_prefix_vpn_table_entry(nh, entry);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_vpn_encap_impl::get_nh_vpn_properties(const la_l3_destination* nh,
                                              la_ip_version_e ip_version,
                                              la_mpls_label_vec_t& out_labels) const
{
    start_api_getter_call();

    if (nh == nullptr) {
        return LA_STATUS_EINVAL;
    }

    const auto& nh_impl = m_device->get_sptr<const la_l3_destination>(nh);

    auto nh_label_map_it = m_nh_label_map.find(nh_impl);

    if (nh_label_map_it == m_nh_label_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto entry = nh_label_map_it->second;

    if (ip_version == la_ip_version_e::IPV4) {
        if (entry.v4_valid == false) {
            return LA_STATUS_ENOTFOUND;
        }

        out_labels = entry.v4_label;
    } else {
        if (entry.v6_valid == false) {
            return LA_STATUS_ENOTFOUND;
        }

        out_labels = entry.v6_label;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_vpn_encap_impl::get_all_nh_vpn_properties(la_mpls_vpn_properties_vec_t& out_nh_vpn_properties) const
{
    start_api_getter_call();

    la_mpls_vpn_properties_t v4_properties;
    la_mpls_vpn_properties_t v6_properties;

    for (auto nh_entry = m_nh_label_map.begin(); nh_entry != m_nh_label_map.end(); nh_entry++) {
        if (nh_entry->second.v4_valid) {
            v4_properties.bgp_nh = nh_entry->first.get();
            v4_properties.label = nh_entry->second.v4_label;
            out_nh_vpn_properties.push_back(v4_properties);
        }
        if (nh_entry->second.v6_valid) {
            v6_properties.bgp_nh = nh_entry->first.get();
            v6_properties.label = nh_entry->second.v6_label;
            out_nh_vpn_properties.push_back(v6_properties);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_vpn_encap_impl::teardown_per_pe_and_prefix_table_entry(const la_l3_destination* nh)
{
    npl_per_pe_and_prefix_vpn_key_large_table_key_t key;

    la_l3_destination_gid_t nh_id;

    la_object::object_type_e nh_type = nh->type();
    switch (nh_type) {
    case la_object::object_type_e::PREFIX_OBJECT: {
        const auto& nh_impl = m_device->get_sptr<const la_prefix_object_base>(nh);
        nh_id = nh_impl->get_gid();
        break;
    }

    case la_object::object_type_e::DESTINATION_PE: {
        const auto& nh_impl = m_device->get_sptr<const la_destination_pe_impl>(nh);
        nh_id = nh_impl->get_gid();
        break;
    }

    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    key.ip_prefix_id = m_gid;
    key.lsp_destination = nh_id;

    const auto& table(m_device->m_tables.per_pe_and_prefix_vpn_key_large_table);
    auto status = table->erase(key);
    return_on_error(status, HLD, ERROR, "large vpn label table erase failed");

    const auto nh_impl = m_device->get_sptr<const la_l3_destination>(nh);
    m_nh_label_map.erase(nh_impl);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_vpn_encap_impl::clear_nh_vpn_properties(const la_l3_destination* nh, la_ip_version_e ip_version)
{
    start_api_call("nh=", nh, "ip_version=", ip_version);

    const auto& nh_impl = m_device->get_sptr<const la_l3_destination>(nh);

    auto nh_label_map_it = m_nh_label_map.find(nh_impl);

    if (nh_label_map_it == m_nh_label_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto& entry = nh_label_map_it->second;

    if (ip_version == la_ip_version_e::IPV4) {
        if (entry.v4_valid == false) {
            return LA_STATUS_ENOTFOUND;
        }
        entry.v4_valid = false;
        entry.v4_label.clear();
    } else {
        if (entry.v6_valid == false) {
            return LA_STATUS_ENOTFOUND;
        }
        entry.v6_valid = false;
        entry.v4_label.clear();
    }

    if ((entry.v4_valid == false) && (entry.v6_valid == false)) {
        la_status status = teardown_per_pe_and_prefix_table_entry(nh);
        return_on_error(status);
    } else {
        la_status status = configure_per_pe_and_prefix_vpn_table_entry(nh, entry);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

lpm_destination_id
la_mpls_vpn_encap_impl::get_lpm_destination_id(resolution_step_e prev_step) const
{
    if (prev_step != RESOLUTION_STEP_FORWARD_L3) {
        return LPM_DESTINATION_ID_INVALID;
    }

    return lpm_destination_id(NPL_DESTINATION_MASK_IP_PREFIX_ID | m_gid);
}

destination_id
la_mpls_vpn_encap_impl::get_destination_id(resolution_step_e prev_step) const
{
    if (prev_step != RESOLUTION_STEP_FORWARD_L3) {
        return DESTINATION_ID_INVALID;
    }

    return destination_id(NPL_DESTINATION_MASK_IP_PREFIX_ID | m_gid);
}

} // namespace silicon_one
