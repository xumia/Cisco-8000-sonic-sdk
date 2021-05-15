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

#include <array>
#include <climits>

#include "api/npu/la_vrf.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "nplapi/npl_constants.h"
#include "npu/counter_utils.h"
#include "npu/la_acl_delegate.h"
#include "npu/la_acl_group_base.h"
#include "npu/la_counter_set_impl.h"
#include "npu/la_gre_port_impl.h"
#include "npu/la_gue_port_impl.h"
#include "npu/la_ip_over_ip_tunnel_port_impl.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_svi_port_base.h"
#include "npu/la_switch_impl.h"
#include "npu/la_vrf_impl.h"
#include "npu/la_vrf_port_common_base.h"
#include "npu/resolution_utils.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "qos/la_meter_set_impl.h"
#include "system/la_device_impl.h"
#include "system/la_erspan_mirror_command_base.h"
#include "system/la_l2_mirror_command_base.h"

namespace silicon_one
{

la_vrf_port_common_base::la_vrf_port_common_base(const la_device_impl_wptr& device, la_l3_port_wptr parent)
    : m_device(device),
      m_parent(parent),
      m_gid(0),
      m_tag1(LA_VLAN_TAG_UNTAGGED),
      m_tag2(LA_VLAN_TAG_UNTAGGED),
      m_is_active(true),
      m_l3_lp_attributes{},
      m_l3_lp_additional_attributes{},
      m_enable_ecn_remark(false),
      m_enable_ecn_counting(false),
      m_delegate_acls(),
      m_egress_acl_drop_offset(0),
      m_pbr_enabled(false),
      m_egress_sflow_enabled(false),
      m_ingress_acl_group(nullptr),
      m_egress_acl_group(nullptr),
      m_is_recycle_ac(false),
      m_egress_dhcp_snooping(false)
{
}

la_vrf_port_common_base::~la_vrf_port_common_base()
{
}

template <class _TableType, class _AddrType>
la_status
la_vrf_port_common_base::delete_ip_hosts(const std::shared_ptr<_TableType>& table, la_port_host<_AddrType>& port_hosts)
{
    typename _TableType::key_type key;

    for (auto& subnet : port_hosts.m_subnet_ip_map) {
        for (auto& host : subnet.second) {
            populate_em_table_key(host.first, key);
            la_status status = table->erase(key);
            return_on_error(status);
        }
    }

    port_hosts.pending_hosts_map.clear();

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::clear_routes_and_hosts()
{
    la_status status = delete_ip_hosts(m_device->m_tables.ipv4_vrf_dip_em_table, m_subnet_ipv4);
    return_on_error(status);

    status = delete_ip_hosts(m_device->m_tables.ipv6_vrf_dip_em_table, m_subnet_ipv6);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::destroy()
{
    la_object::object_type_e type = m_parent->type();

    if (type != la_object::object_type_e::GRE_PORT) {
        la_status status = m_device->m_mac_addr_manager->remove(m_mac_addr, NPL_MAC_DA_TYPE_UC);
        return_on_error(status);
    }

    if (m_is_recycle_ac) {
        la_mac_addr_t recycle_ac_smac;
        recycle_ac_smac.flat = RECYCLE_AC_SMAC;
        la_status status = m_device->m_mac_addr_manager->remove(recycle_ac_smac, NPL_MAC_DA_TYPE_UC);
        return_on_error(status);
    }

    la_status status = clear_routes_and_hosts();
    return_on_error(status);

    std::vector<la_counter_set_impl_wptr> counters = {m_p_counter[COUNTER_DIRECTION_EGRESS],
                                                      m_p_counter[COUNTER_DIRECTION_INGRESS],
                                                      m_q_counter[COUNTER_DIRECTION_EGRESS],
                                                      m_q_counter[COUNTER_DIRECTION_INGRESS]};

    for (auto counter : counters) {
        if (counter != nullptr) {
            m_device->remove_ifg_dependency(m_parent, counter);
            m_device->remove_object_dependency(counter, m_parent);
            counter->remove_pq_counter_user(m_parent);
        }
    }

    if (m_meter != nullptr) {
        status = m_meter->detach_user(m_parent);
        return_on_error(status);
    }

    m_device->remove_ifg_dependency(m_parent, m_ingress_qos_profile);
    m_device->remove_object_dependency(m_ingress_qos_profile, m_parent);
    m_device->remove_ifg_dependency(m_parent, m_egress_qos_profile);
    m_device->remove_object_dependency(m_egress_qos_profile, m_parent);

    if (m_ingress_acl_group != nullptr) {
        m_device->remove_object_dependency(m_ingress_acl_group, m_parent);
    }

    if (m_egress_acl_group != nullptr) {
        m_device->remove_object_dependency(m_egress_acl_group, m_parent);
    }

    status = clear_slp_based_forwarding_destination();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::notify_change(dependency_management_op op)
{
    switch (op.type_e) {
    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT: {
        la_status status = update_dependent_attributes(op);
        return_on_error(status);
        return LA_STATUS_SUCCESS;
    }
    default: {
        log_err(HLD, "%s: received unsupported notification (%s)", __PRETTY_FUNCTION__, silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::update_dependent_attributes(dependency_management_op op)
{
    switch (op.action.attribute_management.op) {
    case (attribute_management_op::ACL_GROUP_CHANGED): {
        la_status status = handle_acl_group_change(op.dependee, op.action.attribute_management.packet_format);
        return status;
    }

    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
la_vrf_port_common_base::handle_acl_group_change(const la_object* changed_acl_group, la_acl_packet_format_e packet_format)
{
    if (changed_acl_group == m_ingress_acl_group) {
        const auto acl_group_base
            = m_ingress_acl_group.weak_ptr_static_cast<const la_acl_group_base>().weak_ptr_const_cast<la_acl_group_base>();
        auto status = set_acl_group_by_packet_format(la_acl_direction_e::INGRESS, packet_format, m_ingress_acl_group);
        return_on_error(status);

        auto slices = m_ifg_use_count->get_slices();
        status = acl_group_base->allocate_rtf_conf_set_id_and_config_mapping(slices);
        return_on_error(status);

        acl_group_rtf_conf_set_id_t rtf_conf_set_id;
        status = acl_group_base->get_rtf_conf_set_id(rtf_conf_set_id);
        return_on_error(status);

        for (la_slice_id_t slice : slices) {
            la_status status = update_l3_attrib_rtf_conf_set_and_stages_per_slice(slice, rtf_conf_set_id, acl_group_base);
            return_on_error(status);
        }
    }
    if (changed_acl_group == m_egress_acl_group) {
        auto status = set_acl_group_by_packet_format(la_acl_direction_e::EGRESS, packet_format, m_egress_acl_group);
        return_on_error(status);

        const auto& acl_group_base
            = m_egress_acl_group.weak_ptr_static_cast<const la_acl_group_base>().weak_ptr_const_cast<la_acl_group_base>();
        auto slices = m_ifg_use_count->get_slices();
        status = acl_group_base->allocate_rtf_conf_set_id_and_config_mapping(slices);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

bool
la_vrf_port_common_base::has_subnets()
{
    return (!m_subnet_ipv4.m_subnet_ip_map.empty() || !m_subnet_ipv6.m_subnet_ip_map.empty());
}

la_status
la_vrf_port_common_base::get_active(bool& out_active) const
{
    out_active = m_is_active;
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_protocol_enabled(la_l3_protocol_e protocol, bool& out_enabled) const
{

    la_status status = do_get_protocol_enabled(protocol, out_enabled);
    return status;
}

la_status
la_vrf_port_common_base::do_set_protocol_enabled(la_l3_protocol_e protocol, bool enabled)
{
    npl_base_l3_lp_attributes_t attribs = m_l3_lp_attributes;

    la_status status = set_l3_lp_attributes_to_param(attribs, protocol, enabled);
    return_on_error(status);

    status = update_l3_lp_attributes(attribs);
    return_on_error(status);

    status = set_l3_lp_attributes(attribs, protocol);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::set_protocol_enabled(la_l3_protocol_e protocol, bool enabled)
{
    bool is_enabled;
    la_status status = get_protocol_enabled(protocol, is_enabled);
    return_on_error(status);

    if (is_enabled == enabled) {
        return LA_STATUS_SUCCESS;
    }

    status = do_set_protocol_enabled(protocol, enabled);
    if (status != LA_STATUS_SUCCESS) {
        // Try to rollback
        la_status rollback_status = do_set_protocol_enabled(protocol, !enabled);
        if (rollback_status != LA_STATUS_SUCCESS) {
            return LA_STATUS_EDOUBLE_FAULT;
        }
    }

    status = update_protocol_enabled(protocol, enabled);
    return_on_error(status);

    return status;
}

la_status
la_vrf_port_common_base::update_l3_lp_attributes(npl_base_l3_lp_attributes_t& attribs)
{
    return update_l3_lp_attributes(attribs, m_l3_lp_additional_attributes);
}

la_status
la_vrf_port_common_base::update_l3_lp_attributes(npl_base_l3_lp_attributes_t& attribs,
                                                 npl_l3_lp_additional_attributes_t& additional_attribs)
{
    auto slices = m_ifg_use_count->get_slices();

    for (la_slice_id_t slice : slices) {
        la_status status = update_l3_lp_attributes_per_slice(slice, attribs, additional_attribs);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_event_enabled(la_event_e event, bool& out_enabled) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_port_common_base::set_event_enabled(la_event_e event, bool enabled)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_port_common_base::set_ingress_qos_profile(la_ingress_qos_profile* ingress_qos_profile)
{
    if (ingress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ingress_qos_profile, m_device)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // If nothing to update
    if (m_ingress_qos_profile.get() == ingress_qos_profile) {
        return LA_STATUS_SUCCESS;
    }

    la_ingress_qos_profile_impl_wptr ingress_qos_profile_impl
        = m_device->get_sptr<la_ingress_qos_profile_impl>(ingress_qos_profile);
    auto old_profile = m_ingress_qos_profile;

    la_status status = add_current_ifgs(this, ingress_qos_profile_impl);
    return_on_error(status);

    m_device->add_ifg_dependency(m_parent, ingress_qos_profile_impl);
    m_device->add_object_dependency(ingress_qos_profile, m_parent);

    m_ingress_qos_profile = ingress_qos_profile_impl;

    // Trigger the L3 attribute updates
    for (auto slice : m_ifg_use_count->get_slices()) {
        update_l3_lp_attributes_per_slice(slice, m_l3_lp_attributes);
    }

    m_device->remove_ifg_dependency(m_parent, old_profile);
    m_device->remove_object_dependency(old_profile, m_parent);

    status = remove_current_ifgs(this, old_profile);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) const
{
    out_ingress_qos_profile = m_ingress_qos_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_egress_qos_profile(la_egress_qos_profile*& out_egress_qos_profile) const
{
    out_egress_qos_profile = m_egress_qos_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_mac(la_mac_addr_t& out_mac_addr) const
{
    out_mac_addr = m_mac_addr;
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::do_set_egress_vlan_tag(la_vlan_tag_t tag1, la_vlan_tag_t tag2, npl_l3_dlp_table_entry_wptr_t& entry)
{
    npl_l3_dlp_table_value_t value(entry->value());
    npl_l3_dlp_attributes_t& attrib(value.payloads.l3_dlp_attributes);

    if (is_vlan_tag_eq(tag1, LA_VLAN_TAG_UNTAGGED)) {
        // untag case
        attrib.nh_ene_macro_code = NPL_NH_ENE_MACRO_ETH;
        attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vlan_and_sa_lsb_encap.tpid_sa_lsb.tpid = 0x8100;
    } else {
        // one or more tags
        attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vlan_and_sa_lsb_encap.vlan_id = tag1.tci.fields.vid;
        attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vlan_and_sa_lsb_encap.tpid_sa_lsb.tpid = tag1.tpid;
        if (is_vlan_tag_eq(tag2, LA_VLAN_TAG_UNTAGGED)) {
            // single tag
            attrib.nh_ene_macro_code = NPL_NH_ENE_MACRO_ETH_VLAN;
        } else {
            // double tag: inner tpid is assumed to be 0x8100
            // tag2 reuses flood_rcy_sm_vlans.vid2, which used for SVI NH flood, so for regular L3 DLP it wont be used
            attrib.nh_ene_macro_code = NPL_NH_ENE_MACRO_ETH_VLAN_VLAN;
            attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vid2_or_flood_rcy_sm_vlans.flood_rcy_sm_vlans.vid2 = tag2.tci.fields.vid;
        }
    }

    la_status status = entry->update(value);

    return status;
}

la_status
la_vrf_port_common_base::get_l3_lp_qos_and_attributes(la_slice_pair_id_t pair_idx, npl_l3_dlp_qos_and_attributes_t& dlp_attr) const
{
    dlp_attr.l3_dlp_info.l3_ecn_ctrl.count_cong_pkt = m_enable_ecn_counting;
    dlp_attr.l3_dlp_info.l3_ecn_ctrl.disable_ecn = !m_enable_ecn_remark;
    dlp_attr.l3_dlp_info.dlp_attributes.port_mirror_type = m_egress_port_mirror_type;

    dlp_attr.l3_dlp_info.dlp_attributes.acl_drop_offset.cntr_offset.offset.base_cntr_offset = m_egress_acl_drop_offset;
    dlp_attr.l3_dlp_info.dlp_attributes.lp_profile = 0;
    dlp_attr.qos_attributes.qos_id = m_egress_qos_profile->get_id(pair_idx);

    la_egress_qos_marking_source_e marking_source{};
    la_status status = m_egress_qos_profile->get_marking_source(marking_source);
    return_on_error(status);
    dlp_attr.qos_attributes.is_group_qos = (marking_source == la_egress_qos_marking_source_e::QOS_GROUP);

    bool demux_count
        = (m_p_counter[COUNTER_DIRECTION_EGRESS] != nullptr) ? m_p_counter[COUNTER_DIRECTION_EGRESS]->get_set_size() > 1 : false;
    dlp_attr.qos_attributes.demux_count = demux_count ? 1 : 0;
    dlp_attr.qos_attributes.q_counter
        = populate_counter_ptr_slice_pair(m_q_counter[COUNTER_DIRECTION_EGRESS], pair_idx, COUNTER_DIRECTION_EGRESS);
    dlp_attr.qos_attributes.p_counter
        = populate_counter_ptr_slice_pair(m_p_counter[COUNTER_DIRECTION_EGRESS], pair_idx, COUNTER_DIRECTION_EGRESS);

    return LA_STATUS_SUCCESS;
}

slice_ifg_vec_t
la_vrf_port_common_base::get_ifgs() const
{
    return m_ifg_use_count->get_ifgs();
}

template <>
void
la_vrf_port_common_base::populate_em_table_key(la_ipv4_addr_t ip_addr, npl_ipv4_vrf_dip_em_table_key_t& out_em_key) const
{
    out_em_key.l3_relay_id.id = m_vrf->get_gid();
    populate_em_table_key_ipv4_address(ip_addr, out_em_key);
    // out_em_key.ipv4_ip_address_address = ip_addr.s_addr;
}

template <>
void
la_vrf_port_common_base::populate_em_table_key(la_ipv6_addr_t ip_addr, npl_ipv6_vrf_dip_em_table_key_t& out_em_key) const
{
    out_em_key.l3_relay_id.id = m_vrf->get_gid();
    out_em_key.ipv6_ip_address_address[0] = ip_addr.q_addr[0];
    out_em_key.ipv6_ip_address_address[1] = ip_addr.q_addr[1];
}

template <>
la_status
la_vrf_port_common_base::populate_em_table_value(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                                 const la_ipv4_addr_t& ip_addr,
                                                 typename npl_ipv4_vrf_dip_em_table_t::value_type& out_value) const
{
    typename npl_ipv4_vrf_dip_em_table_t::key_type key;
    typename npl_ipv4_vrf_dip_em_table_t::entry_pointer_type entry{};

    populate_em_table_key(ip_addr, key);
    la_status status = table->lookup(key, entry);

    return_on_error(status);

    out_value = entry->value();
    return LA_STATUS_SUCCESS;
}

template <>
la_status
la_vrf_port_common_base::populate_em_table_value(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                                 const la_ipv6_addr_t& ip_addr,
                                                 typename npl_ipv6_vrf_dip_em_table_t::value_type& out_value) const
{
    typename npl_ipv6_vrf_dip_em_table_t::key_type key;
    typename npl_ipv6_vrf_dip_em_table_t::entry_pointer_type entry{};

    populate_em_table_key(ip_addr, key);
    la_status status = table->lookup(key, entry);

    return_on_error(status);

    out_value = entry->value();
    return LA_STATUS_SUCCESS;
}

template <>
la_status
la_vrf_port_common_base::add_subnet_to_vrf(la_ipv4_prefix_t subnet)
{
    auto vrf = m_vrf.weak_ptr_const_cast<la_vrf_impl>();
    return vrf->add_ipv4_subnet(subnet, m_parent);
}

template <>
la_status
la_vrf_port_common_base::add_subnet_to_vrf(la_ipv6_prefix_t subnet)
{
    auto vrf = m_vrf.weak_ptr_const_cast<la_vrf_impl>();
    return vrf->add_ipv6_subnet(subnet, m_parent);
}

template <class _TableType, class _PrefixType, class _AddrType>
la_status
la_vrf_port_common_base::add_ip_subnet(const std::shared_ptr<_TableType>& table,
                                       la_port_host<_AddrType>& port_hosts,
                                       _PrefixType subnet)
{
    subnet_count_map_key_t key = get_subnet_count_map_key(subnet);

    typename subnet_ip_map_t<_AddrType>::iterator count_it = port_hosts.m_subnet_ip_map.find(key);
    if (count_it != port_hosts.m_subnet_ip_map.end()) {
        return LA_STATUS_EEXIST;
    }

    la_status status = add_subnet_to_vrf(subnet);
    return_on_error(status);

    port_hosts.m_subnet_ip_map[key] = ip_host_map<_AddrType>();

    typename ip_host_map<_AddrType>::iterator it;

    for (it = port_hosts.pending_hosts_map.begin(); it != port_hosts.pending_hosts_map.end();) {
        bool found = is_addr_in_subnet(it->first, key);
        if (found) {
            if (it->second.get_is_set_class_id()) {
                status = add_ip_host(table, port_hosts, it->first, it->second.get_mac_addr(), it->second.get_class_id());
            } else {
                status = add_ip_host(table, it->first, it->second.get_mac_addr(), port_hosts);
            }

            return_on_error(status);

            port_hosts.pending_hosts_map.erase(it++);
        } else {
            ++it;
        }
    }

    return LA_STATUS_SUCCESS;
}
template <class _PrefixType, class _AddrType>
la_status
la_vrf_port_common_base::add_ip_subnet(subnet_ip_map_t<_AddrType>& subnet_map, _PrefixType subnet)
{
    subnet_count_map_key_t key = get_subnet_count_map_key(subnet);

    typename subnet_ip_map_t<_AddrType>::iterator count_it = subnet_map.find(key);
    if (count_it != subnet_map.end()) {
        return LA_STATUS_EEXIST;
    }

    la_status status = add_subnet_to_vrf(subnet);
    return_on_error(status);

    subnet_map[key] = ip_host_map<_AddrType>();

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::add_ipv4_subnet(la_ipv4_prefix_t subnet)
{
    const auto& table(m_device->m_tables.ipv4_vrf_dip_em_table);
    return add_ip_subnet(table, m_subnet_ipv4, subnet);
}

la_status
la_vrf_port_common_base::add_ipv6_subnet(la_ipv6_prefix_t subnet)
{
    const auto& table(m_device->m_tables.ipv6_vrf_dip_em_table);
    return add_ip_subnet(table, m_subnet_ipv6, subnet);
}

template <class _PrefixType>
la_vrf_port_common_base::subnet_count_map_key_t
la_vrf_port_common_base::get_subnet_count_map_key(_PrefixType prefix) const
{
    subnet_count_map_key_t key;

    key.bytes_in_address = sizeof(prefix.addr);
    key.prefix_length = prefix.length;
    memset(key.u.addr, 0, sizeof(key.u.addr));
    apply_prefix_mask(prefix.addr, prefix.length);
    memcpy(key.u.addr, prefix.addr.b_addr, sizeof(prefix.addr));

    return key;
}

template <class _PrefixType>
void
la_vrf_port_common_base::populate_subnet_prefix_from_count_map_key(const subnet_count_map_key_t& subnet_count_map_key,
                                                                   _PrefixType& out_subnet) const
{
    out_subnet.length = subnet_count_map_key.prefix_length;
    memcpy(out_subnet.addr.b_addr, subnet_count_map_key.u.addr, sizeof(out_subnet.addr));
}

template <>
la_status
la_vrf_port_common_base::remove_subnet_from_vrf(la_ipv4_prefix_t subnet)
{
    auto vrf = m_vrf.weak_ptr_const_cast<la_vrf_impl>();
    return vrf->delete_ipv4_subnet(subnet);
}

template <>
la_status
la_vrf_port_common_base::remove_subnet_from_vrf(la_ipv6_prefix_t subnet)
{
    auto vrf = m_vrf.weak_ptr_const_cast<la_vrf_impl>();
    return vrf->delete_ipv6_subnet(subnet);
}

template <class _TableType, class _AddrType, class _PrefixType>
la_status
la_vrf_port_common_base::delete_ip_subnet(const std::shared_ptr<_TableType>& table,
                                          la_port_host<_AddrType>& port_hosts,
                                          _PrefixType subnet)
{
    subnet_count_map_key_t key = get_subnet_count_map_key(subnet);

    typename subnet_ip_map_t<_AddrType>::iterator count_it = port_hosts.m_subnet_ip_map.find(key);
    if (count_it == port_hosts.m_subnet_ip_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    size_t subnet_use_count = count_it->second.size();
    ip_host_map<_AddrType> map_hosts;

    if (subnet_use_count > 0) {
        typename ip_host_map<_AddrType>::iterator host_it = count_it->second.begin();

        ip_host_map<_AddrType> tmpmap = count_it->second;

        host_it = tmpmap.begin();
        for (; host_it != tmpmap.end(); ++host_it) {
            la_status status = delete_ip_host(table, host_it->first, port_hosts);

            if (status != LA_STATUS_SUCCESS) {

                typename ip_host_map<_AddrType>::iterator host_it1 = map_hosts.begin();
                for (; host_it1 != map_hosts.end(); ++host_it1) {
                    la_status status1;
                    status1 = add_ip_host(table, host_it1->first, host_it1->second.get_mac_addr(), port_hosts);

                    log_err(HLD, "error during readding host");
                    return_on_error(LA_STATUS_EDOUBLE_FAULT);
                }

                return status;
            } else {
                map_hosts[host_it->first] = host_it->second;
            }
        }

        typename ip_host_map<_AddrType>::iterator host_it1 = map_hosts.begin();
        for (; host_it1 != map_hosts.end(); ++host_it1) {
            if (host_it1->second.get_is_set_class_id()) {
                port_hosts.add_to_pending_list(host_it1->first, host_it1->second.get_mac_addr(), host_it1->second.get_class_id());
            } else {
                port_hosts.add_to_pending_list(host_it1->first, host_it1->second.get_mac_addr());
            }
        }
    }

    la_status status = remove_subnet_from_vrf(subnet);
    return_on_error(status);

    port_hosts.m_subnet_ip_map.erase(count_it);

    return LA_STATUS_SUCCESS;
}

template <class _AddrType, class _PrefixType>
la_status
la_vrf_port_common_base::delete_ip_subnet(subnet_ip_map_t<_AddrType>& subnet_map, _PrefixType subnet)
{
    subnet_count_map_key_t key = get_subnet_count_map_key(subnet);

    typename subnet_ip_map_t<_AddrType>::iterator count_it = subnet_map.find(key);
    if (count_it == subnet_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    size_t subnet_use_count = count_it->second.size();
    if (subnet_use_count > 0) {
        return LA_STATUS_EBUSY;
    }

    la_status status = remove_subnet_from_vrf(subnet);
    return_on_error(status);

    subnet_map.erase(count_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::delete_ipv4_subnet(la_ipv4_prefix_t subnet)
{
    const auto& table(m_device->m_tables.ipv4_vrf_dip_em_table);
    return delete_ip_subnet(table, m_subnet_ipv4, subnet);
}

la_status
la_vrf_port_common_base::delete_ipv6_subnet(la_ipv6_prefix_t subnet)
{
    const auto& table(m_device->m_tables.ipv6_vrf_dip_em_table);
    return delete_ip_subnet(table, m_subnet_ipv6, subnet);
}

template <class _AddrType, class _PrefixType>
la_status
la_vrf_port_common_base::get_ip_subnets(const subnet_ip_map_t<_AddrType>& subnet_map, std::vector<_PrefixType>& out_subnets) const
{
    out_subnets.clear();
    for (typename subnet_ip_map_t<_AddrType>::const_iterator it = subnet_map.begin(); it != subnet_map.end(); it++) {
        const subnet_count_map_key_t key = it->first;
        _PrefixType prefix;
        populate_subnet_prefix_from_count_map_key(key, prefix);
        out_subnets.push_back(prefix);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_ipv4_subnets(la_ipv4_prefix_vec_t& out_subnets) const
{
    la_status status = get_ip_subnets(m_subnet_ipv4.m_subnet_ip_map, out_subnets);

    return status;
}

la_status
la_vrf_port_common_base::get_ipv6_subnets(la_ipv6_prefix_vec_t& out_subnets) const
{
    la_status status = get_ip_subnets(m_subnet_ipv6.m_subnet_ip_map, out_subnets);

    return status;
}

template <>
bool
la_vrf_port_common_base::is_addr_in_subnet(const la_ipv4_addr_t& ip_addr, const subnet_count_map_key_t& key) const
{
    la_ipv4_addr_t addr = ip_addr;
    apply_prefix_mask(addr, key.prefix_length);

    for (size_t i = 0; i < sizeof(addr); i++) {
        if (key.u.addr[i] != addr.b_addr[i]) {
            return false;
        }
    }

    return true;
}

template <>
bool
la_vrf_port_common_base::is_addr_in_subnet(const la_ipv6_addr_t& ip_addr, const subnet_count_map_key_t& key) const
{
    la_ipv6_addr_t addr = ip_addr;
    apply_prefix_mask(addr, key.prefix_length);

    for (size_t i = 0; i < sizeof(addr); i++) {
        if (key.u.addr[i] != addr.b_addr[i]) {
            return false;
        }
    }

    return true;
}

template <>
la_status
la_vrf_port_common_base::get_addr_subnet(subnet_ip_map_t<la_ipv4_addr_t>& subnet_map,
                                         la_ipv4_addr_t ip_addr,
                                         typename subnet_ip_map_t<la_ipv4_addr_t>::iterator& out_it)
{
    bool found = false;
    typename subnet_ip_map_t<la_ipv4_addr_t>::iterator it;

    for (it = subnet_map.begin(); it != subnet_map.end(); it++) {
        found = is_addr_in_subnet(ip_addr, it->first);
        if (found) {
            break;
        }
    }

    if (!found) {
        return LA_STATUS_ENOTFOUND;
    }

    out_it = it;

    return LA_STATUS_SUCCESS;
}

template <>
la_status
la_vrf_port_common_base::get_addr_subnet(subnet_ip_map_t<la_ipv6_addr_t>& subnet_map,
                                         la_ipv6_addr_t ip_addr,
                                         typename subnet_ip_map_t<la_ipv6_addr_t>::iterator& out_it)
{
    bool found = false;
    typename subnet_ip_map_t<la_ipv6_addr_t>::iterator it;

    for (it = subnet_map.begin(); it != subnet_map.end(); it++) {
        found = is_addr_in_subnet(ip_addr, it->first);
        if (found) {
            break;
        }
    }

    if (!found) {
        return LA_STATUS_ENOTFOUND;
    }

    out_it = it;

    return LA_STATUS_SUCCESS;
}

template <class _TableType, class _AddrType>
la_status
la_vrf_port_common_base::add_ip_host(const std::shared_ptr<_TableType>& table,
                                     _AddrType ip_addr,
                                     la_mac_addr_t mac_addr,
                                     la_port_host<_AddrType>& port_hosts)
{
    typename subnet_ip_map_t<_AddrType>::iterator it;
    la_status status = get_addr_subnet(port_hosts.m_subnet_ip_map, ip_addr, it);

    if (status == LA_STATUS_ENOTFOUND) {
        port_hosts.add_to_pending_list(ip_addr, mac_addr);
    } else {
        status = insert_to_em(table, ip_addr, mac_addr, false /* override_entry */);
        return_on_error(status);

        ip_host_data data;
        data.set_mac_addr(mac_addr);
        it->second[ip_addr] = data;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr)
{
    const auto& table(m_device->m_tables.ipv4_vrf_dip_em_table);

    return add_ip_host(table, ip_addr, mac_addr, m_subnet_ipv4);
}

la_status
la_vrf_port_common_base::add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr)
{
    const auto& table(m_device->m_tables.ipv6_vrf_dip_em_table);

    return add_ip_host(table, ip_addr, mac_addr, m_subnet_ipv6);
}
template <class _TableType, class _AddrType>
la_status
la_vrf_port_common_base::delete_ip_host(const std::shared_ptr<_TableType>& table,
                                        _AddrType ip_addr,
                                        la_port_host<_AddrType>& port_hosts)
{
    typename subnet_ip_map_t<_AddrType>::iterator it;
    la_status status = get_addr_subnet(port_hosts.m_subnet_ip_map, ip_addr, it);

    if (status == LA_STATUS_ENOTFOUND) {
        if (port_hosts.pending_list_has_host(ip_addr)) {
            port_hosts.remove_host_from_pending_list(ip_addr);
        } else {
            return_on_error(status);
        }
    } else {
        // Remove the EM table entry
        typename _TableType::key_type key;

        populate_em_table_key(ip_addr, key);

        status = table->erase(key);
        return_on_error(status);

        if (it->second.size() == 0) {
            return LA_STATUS_EUNKNOWN;
        }

        port_hosts.m_subnet_ip_map[it->first].erase(ip_addr);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::delete_ipv4_host(la_ipv4_addr_t ip_addr)
{
    const auto& table(m_device->m_tables.ipv4_vrf_dip_em_table);

    return delete_ip_host(table, ip_addr, m_subnet_ipv4);
}

la_status
la_vrf_port_common_base::delete_ipv6_host(la_ipv6_addr_t ip_addr)
{
    const auto& table(m_device->m_tables.ipv6_vrf_dip_em_table);

    return delete_ip_host(table, ip_addr, m_subnet_ipv6);
}

la_status
la_vrf_port_common_base::get_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t& out_mac_addr) const
{
    const auto& table(m_device->m_tables.ipv4_vrf_dip_em_table);

    return get_ip_host(table, m_subnet_ipv4, ip_addr, out_mac_addr);
}

la_status
la_vrf_port_common_base::get_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t& out_mac_addr, la_class_id_t& out_class_id) const
{
    const auto& table(m_device->m_tables.ipv4_vrf_dip_em_table);

    return get_ip_host(table, m_subnet_ipv4, ip_addr, out_mac_addr, out_class_id);
}

la_status
la_vrf_port_common_base::get_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t& out_mac_addr) const
{
    const auto& table(m_device->m_tables.ipv6_vrf_dip_em_table);

    return get_ip_host(table, m_subnet_ipv6, ip_addr, out_mac_addr);
}

la_status
la_vrf_port_common_base::get_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t& out_mac_addr, la_class_id_t& out_class_id) const
{
    const auto& table(m_device->m_tables.ipv6_vrf_dip_em_table);

    return get_ip_host(table, m_subnet_ipv6, ip_addr, out_mac_addr, out_class_id);
}

la_status
la_vrf_port_common_base::get_ipv4_hosts(la_mac_addr_vec& out_mac_addresses) const
{
    const auto& table(m_device->m_tables.ipv4_vrf_dip_em_table);

    return get_ip_hosts(table, m_subnet_ipv4, out_mac_addresses);
}

la_status
la_vrf_port_common_base::get_ipv4_hosts(la_ipv4_addr_vec_t& out_ip_addrs) const
{
    out_ip_addrs.clear();
    for (auto& subnet : m_subnet_ipv4.m_subnet_ip_map) {
        for (auto& host : subnet.second) {
            out_ip_addrs.push_back(host.first);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_ipv6_hosts(la_mac_addr_vec& out_mac_addresses) const
{
    const auto& table(m_device->m_tables.ipv6_vrf_dip_em_table);

    return get_ip_hosts(table, m_subnet_ipv6, out_mac_addresses);
}

la_status
la_vrf_port_common_base::get_ipv6_hosts(la_ipv6_addr_vec_t& out_ip_addrs) const
{
    out_ip_addrs.clear();
    for (auto& subnet : m_subnet_ipv6.m_subnet_ip_map) {
        for (auto& host : subnet.second) {
            out_ip_addrs.push_back(host.first);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::update_l3_attrib_rtf_conf_set_and_stages_per_slice(la_slice_id_t slice,
                                                                            acl_group_rtf_conf_set_id_t rtf_conf_set_id,
                                                                            const la_acl_group_base_wcptr& acl_group_base)
{
    la_acl_wptr_vec_t ipv4_acls;
    la_acl_wptr_vec_t ipv6_acls;
    npl_init_rtf_stage_and_type_e npl_init_rtf_stage;

    la_status status = acl_group_base->get_real_acls(la_acl_packet_format_e::IPV4, ipv4_acls);
    return_on_error(status);

    status = acl_group_base->get_real_acls(la_acl_packet_format_e::IPV6, ipv6_acls);
    return_on_error(status);

    m_l3_lp_attributes.rtf_conf_set_and_stages_or_post_fwd_stage.rtf_conf_set_and_stages.rtf_conf_set.val = rtf_conf_set_id;
    m_l3_lp_attributes.rtf_conf_set_and_stages_or_post_fwd_stage.rtf_conf_set_and_stages.ipv4_ipv6_init_rtf_stage
        .ipv4_init_rtf_stage
        = NPL_INIT_RTF_NONE;
    m_l3_lp_attributes.rtf_conf_set_and_stages_or_post_fwd_stage.rtf_conf_set_and_stages.ipv4_ipv6_init_rtf_stage
        .ipv6_init_rtf_stage
        = NPL_INIT_RTF_NONE;

    if (rtf_conf_set_id != RTF_CONF_SET_ID_INVALID) {
        if (ipv4_acls.size() > 0) {
            npl_init_rtf_stage = acl_group_base->get_init_ip_rtf_stage(la_acl_packet_format_e::IPV4, ipv4_acls);
            m_l3_lp_attributes.rtf_conf_set_and_stages_or_post_fwd_stage.rtf_conf_set_and_stages.ipv4_ipv6_init_rtf_stage
                .ipv4_init_rtf_stage
                = npl_init_rtf_stage;
        }
        if (ipv6_acls.size() > 0) {
            npl_init_rtf_stage = acl_group_base->get_init_ip_rtf_stage(la_acl_packet_format_e::IPV6, ipv6_acls);
            m_l3_lp_attributes.rtf_conf_set_and_stages_or_post_fwd_stage.rtf_conf_set_and_stages.ipv4_ipv6_init_rtf_stage
                .ipv6_init_rtf_stage
                = npl_init_rtf_stage;
        }
    }
    update_l3_lp_attributes_per_slice(slice, m_l3_lp_attributes);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::set_acl_group_by_packet_format(la_acl_direction_e dir,
                                                        la_acl_packet_format_e packet_format,
                                                        const la_acl_group_wcptr& acl_group)
{
    la_status status;

    const auto& acl_group_base = acl_group.weak_ptr_static_cast<const la_acl_group_base>();

    la_acl_wptr_vec_t acls = {};
    status = acl_group_base->get_real_acls(packet_format, acls);
    return_on_error(status);

    std::vector<la_acl_delegate_wptr> old_acls = m_delegate_acls[(int)packet_format][(int)dir];
    m_delegate_acls[(int)packet_format][(int)dir].clear();

    for (auto& acl : acls) {
        if (acl == nullptr) {
            continue;
        }
        if (!of_same_device(acl, m_device)) {
            return LA_STATUS_EDIFFERENT_DEVS;
        }

        const la_acl_key_profile* acl_key_profile;
        const la_acl_command_profile* acl_command_profile;
        la_acl_key_type_e key_type;

        auto acl_delegate = get_delegate(acl);

        if (acl_delegate == nullptr) {
            return LA_STATUS_EUNKNOWN;
        }

        status = acl->get_acl_key_profile(acl_key_profile);
        return_on_error(status);

        status = acl->get_acl_command_profile(acl_command_profile);
        return_on_error(status);

        status = acl_key_profile->get_key_type(key_type);
        return_on_error(status);

        la_acl_direction_e acl_key_dir = acl_key_profile->get_direction();

        status = validate_direction(dir, acl_key_dir);
        return_on_error(status);

        // Make-before-break. Add IFGs to new acl, swap, then remove from old acl
        status = add_current_ifgs(this, acl_delegate);
        return_on_error(status);

        m_device->add_ifg_dependency(m_parent, acl_delegate);
        m_device->add_object_dependency(acl, m_parent);

        m_delegate_acls[(int)packet_format][(int)dir].push_back(acl_delegate);
    }

    for (auto& old_acl : old_acls) {
        m_device->remove_ifg_dependency(m_parent, old_acl);
        m_device->remove_object_dependency(old_acl->get_acl_parent(), m_parent);

        status = remove_current_ifgs(this, old_acl.get());
        return_on_error(status);
    }

    if (dir == la_acl_direction_e::EGRESS) {
        for (la_slice_pair_id_t pair_idx : m_device->get_used_slice_pairs()) {
            la_status status = configure_txpp_dlp_profile_table(pair_idx);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::set_acl_group(la_acl_direction_e dir, la_acl_group* acl_group_ptr)
{
    la_status status;
    const la_acl_group_wptr& acl_group = m_device->get_sptr<la_acl_group>(acl_group_ptr);

    // Add const to input acl_group to verify it is not changed.
    const la_acl_group_wcptr& acl_group_const = m_device->get_sptr<const la_acl_group>(acl_group_ptr);

    if (dir == la_acl_direction_e::INGRESS && m_ingress_acl_group != nullptr) {
        if (m_ingress_acl_group == acl_group_const) {
            return LA_STATUS_SUCCESS;
        }
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::ACL_GROUP_CHANGED);
        m_device->remove_attribute_dependency(m_ingress_acl_group, shared_from_this(), registered_attributes);
        m_device->remove_object_dependency(m_ingress_acl_group, m_parent);
        m_ingress_acl_group = nullptr;
    }

    if (dir == la_acl_direction_e::EGRESS && m_egress_acl_group != nullptr) {
        if (m_egress_acl_group == acl_group_const) {
            return LA_STATUS_SUCCESS;
        }
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::ACL_GROUP_CHANGED);
        m_device->remove_attribute_dependency(m_egress_acl_group, shared_from_this(), registered_attributes);
        m_device->remove_object_dependency(m_egress_acl_group, m_parent);
        m_egress_acl_group = nullptr;
    }

    status = validate_set_acl_group(dir, acl_group_const);
    return_on_error(status);

    if (dir == la_acl_direction_e::INGRESS) {
        m_ingress_acl_group = acl_group;
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::ACL_GROUP_CHANGED);
        m_device->add_attribute_dependency(m_ingress_acl_group, shared_from_this(), registered_attributes);
    }

    if (dir == la_acl_direction_e::EGRESS) {
        m_egress_acl_group = acl_group;
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::ACL_GROUP_CHANGED);
        m_device->add_attribute_dependency(m_egress_acl_group, shared_from_this(), registered_attributes);
    }

    status = set_acl_group_by_packet_format(dir, la_acl_packet_format_e::IPV4, acl_group_const);
    return_on_error(status);
    status = set_acl_group_by_packet_format(dir, la_acl_packet_format_e::IPV6, acl_group_const);
    return_on_error(status);

    const auto& acl_group_base = acl_group.weak_ptr_static_cast<la_acl_group_base>();
    acl_group_rtf_conf_set_id_t rtf_conf_set_id;

    auto slices = m_ifg_use_count->get_slices();
    status = acl_group_base->allocate_rtf_conf_set_id_and_config_mapping(slices);
    return_on_error(status);

    if (dir == la_acl_direction_e::INGRESS) {
        status = acl_group_base->get_rtf_conf_set_id(rtf_conf_set_id);
        return_on_error(status);

        for (la_slice_id_t slice : slices) {
            la_status status = update_l3_attrib_rtf_conf_set_and_stages_per_slice(slice, rtf_conf_set_id, acl_group_base);
            return_on_error(status);
        }

        m_device->add_object_dependency(m_ingress_acl_group, m_parent);
    } else {
        m_device->add_object_dependency(m_egress_acl_group, m_parent);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::validate_set_acl_group(la_acl_direction_e dir, const la_acl_group_wcptr& acl_group) const
{
    la_status status;
    const auto& acl_group_base = acl_group.weak_ptr_static_cast<const la_acl_group_base>();
    la_acl_wptr_vec_t ethernet_acls;

    status = acl_group_base->get_real_acls(la_acl_packet_format_e::ETHERNET, ethernet_acls);
    return_on_error(status);

    if (ethernet_acls.size() > 0) {
        log_err(HLD, "la_vrf_port_common_base::%s ethernet acls list can't be attached to l3 port", __func__);
        return LA_STATUS_EINVAL;
    }

    if (dir == la_acl_direction_e::EGRESS) {
        la_acl_wptr_vec_t ipv4_acls;
        la_acl_wptr_vec_t ipv6_acls;

        status = acl_group_base->get_real_acls(la_acl_packet_format_e::IPV4, ipv4_acls);
        status = acl_group_base->get_real_acls(la_acl_packet_format_e::IPV6, ipv6_acls);

        if (ipv4_acls.size() > 1) {
            log_err(HLD, "Cannot attach more than 1 IPv4 ACL to the port at egress, (%ld given)", ipv4_acls.size());
            return LA_STATUS_EINVAL;
        }

        if (ipv6_acls.size() > 1) {
            log_err(HLD, "Cannot attach more than 1 IPv6 ACL to the port at egress, (%ld given)", ipv6_acls.size());
            return LA_STATUS_EINVAL;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::validate_direction(la_acl_direction_e dir, la_acl_direction_e acl_key_dir) const
{
    if (dir == la_acl_direction_e::INGRESS && acl_key_dir != la_acl_direction_e::INGRESS) {
        log_err(HLD, "la_vrf_port_common_base::%s Acl attached to ingress port can not have key profile of EGRESS type", __func__);
        return LA_STATUS_EINVAL;
    }

    if (dir == la_acl_direction_e::EGRESS && acl_key_dir != la_acl_direction_e::EGRESS) {
        log_err(HLD, "la_vrf_port_common_base::%s Acl attached to egress port can not have key profile of INGRESS type", __func__);
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_acl_group(la_acl_direction_e dir, la_acl_group*& out_acl_group) const
{
    if (dir == la_acl_direction_e::INGRESS) {
        out_acl_group = m_ingress_acl_group.get();
    }

    if (dir == la_acl_direction_e::EGRESS) {
        out_acl_group = m_egress_acl_group.get();
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::clear_acl_group(la_acl_direction_e dir)
{
    la_status status;

    if (dir == la_acl_direction_e::INGRESS) {
        if (m_ingress_acl_group == nullptr) {
            return LA_STATUS_SUCCESS;
        }
        for (auto slice : m_ifg_use_count->get_slices()) {
            status = update_l3_attrib_rtf_conf_set_and_stages_per_slice(
                slice, RTF_CONF_SET_ID_INVALID, m_ingress_acl_group.weak_ptr_static_cast<const silicon_one::la_acl_group_base>());
            return_on_error(status);
        }
    }

    if (dir == la_acl_direction_e::EGRESS) {
        if (m_egress_acl_group == nullptr) {
            return LA_STATUS_SUCCESS;
        }
        for (auto pair_idx : m_ifg_use_count->get_slice_pairs()) {
            status = configure_txpp_dlp_profile_table(pair_idx);
            return_on_error(status);
        }
    }

    for (auto packet_format : {la_acl_packet_format_e::ETHERNET, la_acl_packet_format_e::IPV4, la_acl_packet_format_e::IPV6}) {
        std::vector<la_acl_delegate_wptr> acls = m_delegate_acls[(int)packet_format][(int)dir];
        m_delegate_acls[(int)packet_format][(int)dir].clear();

        for (auto& old_acl : acls) {
            m_device->remove_ifg_dependency(m_parent, old_acl);
            m_device->remove_object_dependency(old_acl->get_acl_parent(), m_parent);

            status = remove_current_ifgs(this, old_acl.get());
            return_on_error(status);
        }
    }

    if (dir == la_acl_direction_e::INGRESS) {
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::ACL_GROUP_CHANGED);
        // m_device->remove_attribute_dependency(m_ingress_acl_group, this, registered_attributes);
        m_device->remove_object_dependency(m_ingress_acl_group, m_parent);
        m_ingress_acl_group = nullptr;
    }
    if (dir == la_acl_direction_e::EGRESS) {
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::ACL_GROUP_CHANGED);
        // m_device->remove_attribute_dependency(m_egress_acl_group, this, registered_attributes);
        m_device->remove_object_dependency(m_egress_acl_group, m_parent);
        m_egress_acl_group = nullptr;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::set_pbr_enabled(bool enabled)
{
    if (m_pbr_enabled == enabled) {
        return LA_STATUS_SUCCESS;
    }

    transaction txn;
    bool old_pbr_enabled = m_pbr_enabled;
    m_pbr_enabled = enabled;

    // Trigger the L3 attribute updates
    for (auto slice : m_ifg_use_count->get_slices()) {
        txn.status = update_l3_lp_attributes_per_slice(slice, m_l3_lp_attributes);
        return_on_error(txn.status);

        txn.on_fail([&, slice]() {
            m_pbr_enabled = old_pbr_enabled;
            update_l3_lp_attributes_per_slice(slice, m_l3_lp_attributes);
        });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_pbr_enabled(bool& out_enabled) const
{
    out_enabled = m_pbr_enabled;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::set_drop_counter_offset(la_stage_e stage, size_t offset)
{
    if (offset > la_device_impl::MAX_COUNTER_OFFSET) {
        return LA_STATUS_EOUTOFRANGE;
    }

    switch (stage) {
    case la_stage_e::INGRESS:
        return configure_ingress_drop_counter_offset(offset);
    case la_stage_e::EGRESS:
        return configure_egress_drop_counter_offset(offset);
    }

    return LA_STATUS_EUNKNOWN;
}

la_status
la_vrf_port_common_base::configure_ingress_drop_counter_offset(size_t offset)
{
    m_l3_lp_attributes.acl_drop_offset.cntr_offset.offset.base_cntr_offset = offset;

    return update_l3_lp_attributes(m_l3_lp_attributes);
}

la_status
la_vrf_port_common_base::get_drop_counter_offset(la_stage_e stage, size_t& out_offset) const
{
    switch (stage) {
    case la_stage_e::INGRESS:
        out_offset = m_l3_lp_attributes.acl_drop_offset.cntr_offset.offset.base_cntr_offset;
        return LA_STATUS_SUCCESS;
    case la_stage_e::EGRESS:
        out_offset = m_egress_acl_drop_offset;
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_EUNKNOWN;
}

la_status
la_vrf_port_common_base::get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const
{
    out_mirror_cmd = m_egress_mirror_cmd.get();
    out_is_acl_conditioned = (m_egress_port_mirror_type == NPL_PORT_MIRROR_TYPE_CONDITIONED);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::update_l3_lp_attributes_per_slice(la_slice_id_t slice, npl_base_l3_lp_attributes_t& attribs)
{
    return update_l3_lp_attributes_per_slice(slice, attribs, m_l3_lp_additional_attributes);
}

la_status
la_vrf_port_common_base::update_fallback_vrf()
{
    npl_base_l3_lp_attributes_t attribs = m_l3_lp_attributes;

    const la_vrf* fallback_vrf;
    la_status status = m_vrf->get_fallback_vrf(fallback_vrf);
    return_on_error(status);

    // if (!fallback_vrf) {
    //    attribs.enable_global_vrf = 0;
    //} else {
    //    attribs.enable_global_vrf = 1;
    //}

    status = update_l3_lp_attributes(attribs);
    return_on_error(status);

    // m_l3_lp_attributes.enable_global_vrf = attribs.enable_global_vrf;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::set_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e mode)
{
    npl_base_l3_lp_attributes_t attribs = m_l3_lp_attributes;
    attribs.minimal_l3_lp_attributes.ttl_mode = la_2_npl_mpls_ttl_inheritance_mode(mode);

    la_status status = update_l3_lp_attributes(attribs);
    return_on_error(status);

    m_l3_lp_attributes.minimal_l3_lp_attributes.ttl_mode = attribs.minimal_l3_lp_attributes.ttl_mode;

    return LA_STATUS_SUCCESS;
}

la_mpls_ttl_inheritance_mode_e
la_vrf_port_common_base::get_ttl_inheritance_mode() const
{
    la_mpls_ttl_inheritance_mode_e curr_mode
        = npl_2_la_mpls_ttl_inheritance_mode(m_l3_lp_attributes.minimal_l3_lp_attributes.ttl_mode);

    return curr_mode;
}

la_status
la_vrf_port_common_base::set_qos_inheritance_mode(la_mpls_qos_inheritance_mode_e mode)
{
    // NPL always assumes Uniform mode. Instead of removing the existing SDK
    // APIs, just check and return here. In the event that there is a future
    // request to add PIPE mode, only the implementation needs to change here.
    if (mode == la_mpls_qos_inheritance_mode_e::PIPE) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    return LA_STATUS_SUCCESS;
}

la_mpls_qos_inheritance_mode_e
la_vrf_port_common_base::get_qos_inheritance_mode() const
{
    return la_mpls_qos_inheritance_mode_e::UNIFORM;
}

bool
la_vrf_port_common_base::is_counter_set_size_valid(const la_counter_set_impl_wptr& counter,
                                                   la_counter_set::type_e counter_type) const
{
    if (counter == nullptr) {
        return true;
    }

    size_t counter_set_size = counter->get_set_size();
    if (counter_type == la_counter_set::type_e::QOS) {
        return ((counter_set_size >= 1) && (counter_set_size <= LA_NUM_L3_INGRESS_TRAFFIC_CLASSES));
    }
    return ((counter_set_size >= 1) && (counter_set_size <= 8));
}

la_counter_set_impl_wptr
la_vrf_port_common_base::get_curr_counter(la_counter_set::type_e counter_type, counter_direction_e direction) const
{
    auto& curr_counter((counter_type == la_counter_set::type_e::QOS) ? m_q_counter[direction] : m_p_counter[direction]);
    return curr_counter;
}

la_status
la_vrf_port_common_base::verify_set_counter_parameters(const la_counter_set_impl_wptr& new_counter,
                                                       la_counter_set::type_e counter_type) const
{
    if ((new_counter != nullptr) && (!of_same_device(new_counter, m_device))) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if ((counter_type != la_counter_set::type_e::QOS) && (counter_type != la_counter_set::type_e::PORT)) {
        return LA_STATUS_EINVAL;
    }

    if (!is_counter_set_size_valid(new_counter, counter_type)) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::do_set_counter(const la_counter_set_impl_wptr& new_counter,
                                        la_counter_set::type_e counter_type,
                                        counter_direction_e direction)
{
    la_status status = verify_set_counter_parameters(new_counter, counter_type);
    return_on_error(status);

    auto& curr_counter((counter_type == la_counter_set::type_e::QOS) ? m_q_counter[direction] : m_p_counter[direction]);
    if (curr_counter.get() == new_counter.get()) {
        return LA_STATUS_SUCCESS;
    }

    // Add the port's slices to the new counter
    if (new_counter != nullptr) {
        bool is_aggregate = is_aggregate_port(m_parent);
        status = new_counter->add_pq_counter_user(m_parent, counter_type, direction, is_aggregate);
        return_on_error(status);

        m_device->add_ifg_dependency(m_parent, new_counter);
        m_device->add_object_dependency(new_counter, m_parent);
    }

    // Update the tables with the new counter
    auto prev_counter = curr_counter;
    curr_counter = new_counter;
    if (direction == COUNTER_DIRECTION_EGRESS) {
        status = configure_ingress_counter();
    } else {
        status = configure_egress_counter(curr_counter, counter_type);
    }

    return_on_error(status);

    // Remove the port's slices from the current counter
    if (prev_counter != nullptr) {
        m_device->remove_ifg_dependency(m_parent, prev_counter);
        m_device->remove_object_dependency(prev_counter, m_parent);
        status = prev_counter->remove_pq_counter_user(m_parent);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::set_ingress_counter(la_counter_set::type_e counter_type, la_counter_set* counter)
{
    auto counter_impl = m_device->get_sptr<la_counter_set_impl>(counter);
    return do_set_counter(counter_impl, counter_type, COUNTER_DIRECTION_INGRESS);
}

la_status
la_vrf_port_common_base::get_ingress_counter(la_counter_set::type_e counter_type, la_counter_set*& out_counter) const
{
    if ((counter_type != la_counter_set::type_e::QOS) && (counter_type != la_counter_set::type_e::PORT)) {
        return LA_STATUS_EINVAL;
    }

    auto curr_counter(get_curr_counter(counter_type, COUNTER_DIRECTION_INGRESS));

    out_counter = curr_counter.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::set_egress_counter(la_counter_set::type_e counter_type, la_counter_set* counter)
{
    auto counter_impl = m_device->get_sptr<la_counter_set_impl>(counter);
    return do_set_counter(counter_impl, counter_type, COUNTER_DIRECTION_EGRESS);
}

la_status
la_vrf_port_common_base::get_egress_counter(la_counter_set::type_e counter_type, la_counter_set*& out_counter) const
{
    if ((counter_type != la_counter_set::type_e::QOS) && (counter_type != la_counter_set::type_e::PORT)) {
        return LA_STATUS_EINVAL;
    }

    auto curr_counter(get_curr_counter(counter_type, COUNTER_DIRECTION_EGRESS));

    out_counter = curr_counter.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_ecn_remark_enabled(bool& out_enabled) const
{
    out_enabled = m_enable_ecn_remark;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_ecn_counting_enabled(bool& out_enabled) const
{
    out_enabled = m_enable_ecn_counting;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_egress_vlan_tag(la_vlan_tag_t& out_tag1, la_vlan_tag_t& out_tag2) const
{
    out_tag1 = m_tag1;
    out_tag2 = m_tag2;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::set_load_balancing_profile(la_l3_port::lb_profile_e lb_profile)
{
    npl_l3_lp_additional_attributes_t additional_attributes(m_l3_lp_additional_attributes);

    additional_attributes.load_balance_profile = la_2_npl_lb_profile(lb_profile);

    la_status status = update_l3_lp_attributes(m_l3_lp_attributes, additional_attributes);
    return_on_error(status);

    m_l3_lp_additional_attributes.load_balance_profile = additional_attributes.load_balance_profile;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_load_balancing_profile(la_l3_port::lb_profile_e& out_lb_profile) const
{
    out_lb_profile = npl_2_la_lb_profile(m_l3_lp_additional_attributes.load_balance_profile);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::set_slp_based_forwarding_enabled(bool enabled)
{
    npl_l3_lp_additional_attributes_t additional_attributes(m_l3_lp_additional_attributes);

    additional_attributes.slp_based_fwd_and_per_vrf_mpls_fwd.slp_based_forwarding = enabled ? 1 : 0;

    la_status status = update_l3_lp_attributes(m_l3_lp_attributes, additional_attributes);
    return_on_error(status);

    m_l3_lp_additional_attributes.slp_based_fwd_and_per_vrf_mpls_fwd.slp_based_forwarding
        = additional_attributes.slp_based_fwd_and_per_vrf_mpls_fwd.slp_based_forwarding;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::set_meter(la_meter_set* meter)
{
    if ((meter != nullptr) && (!of_same_device(meter, m_device))) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (meter == m_meter.get()) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;
    auto meter_set_impl = static_cast<la_meter_set_impl*>(meter);

    // Attach to the new meter
    if (meter != nullptr) {
        bool is_aggregate = is_aggregate_port(m_parent);
        status = meter_set_impl->attach_user(m_parent, is_aggregate);
        return_on_error(status);
    }

    // Update the tables with the new meter
    auto prev_meter = m_meter;
    m_meter = m_device->get_sptr(meter_set_impl); // update_l3_lp_attributes_payload needs m_meter to be set with the new meter
    status = update_l3_lp_attributes(m_l3_lp_attributes);
    if (status != LA_STATUS_SUCCESS) {
        m_meter = nullptr;

        return status;
    }

    // Detach from the current meter
    if (prev_meter != nullptr) {
        status = prev_meter->detach_user(m_parent);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_meter(const la_meter_set*& out_meter) const
{
    out_meter = m_meter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::set_ingress_sflow_enabled(bool enabled)
{
    npl_l3_lp_additional_attributes_t additional_attributes(m_l3_lp_additional_attributes);

    additional_attributes.enable_monitor = enabled ? 1 : 0;

    la_status status = update_l3_lp_attributes(m_l3_lp_attributes, additional_attributes);
    return_on_error(status);

    m_l3_lp_additional_attributes.enable_monitor = additional_attributes.enable_monitor;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_ingress_sflow_enabled(bool& out_enabled) const
{
    out_enabled = m_l3_lp_additional_attributes.enable_monitor;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::set_csc_enabled(bool enabled)
{
    npl_l3_lp_additional_attributes_t additional_attributes(m_l3_lp_additional_attributes);

    additional_attributes.slp_based_fwd_and_per_vrf_mpls_fwd.per_vrf_mpls_fwd = enabled ? 1 : 0;

    la_status status = update_l3_lp_attributes(m_l3_lp_attributes, additional_attributes);
    return_on_error(status);

    m_l3_lp_additional_attributes.slp_based_fwd_and_per_vrf_mpls_fwd.per_vrf_mpls_fwd
        = additional_attributes.slp_based_fwd_and_per_vrf_mpls_fwd.per_vrf_mpls_fwd;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_csc_enabled(bool& out_enabled) const
{
    out_enabled = m_l3_lp_additional_attributes.slp_based_fwd_and_per_vrf_mpls_fwd.per_vrf_mpls_fwd;

    return LA_STATUS_SUCCESS;
}

template <>
la_status
la_vrf_port_common_base::update_subnet(la_ipv4_prefix_t subnet)
{
    auto vrf = m_vrf.weak_ptr_const_cast<la_vrf_impl>();
    la_status status = vrf->update_ipv4_subnet(subnet, m_parent);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

template <>
la_status
la_vrf_port_common_base::update_subnet(la_ipv6_prefix_t subnet)
{
    auto vrf = m_vrf.weak_ptr_const_cast<la_vrf_impl>();
    la_status status = vrf->update_ipv6_subnet(subnet, m_parent);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

template <class _AddrType, class _PrefixType>
la_status
la_vrf_port_common_base::set_egress_sflow_enabled_host(const subnet_ip_map_t<_AddrType>& subnet_map)
{
    for (typename subnet_ip_map_t<_AddrType>::const_iterator it = subnet_map.begin(); it != subnet_map.end(); it++) {
        const subnet_count_map_key_t key = it->first;
        _PrefixType prefix;
        populate_subnet_prefix_from_count_map_key(key, prefix);
        la_status status = update_subnet(prefix);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::set_egress_sflow_enabled(bool enabled)
{
    // Routing - flag is written to resolution table by next-hop object.
    // Change local attribute and notify all next-hop objects
    // that are using this port. The next-hop objects will query this port
    // for the attribute value.
    m_egress_sflow_enabled = enabled;

    attribute_management_details amd;
    amd.op = attribute_management_op::EGRESS_SFLOW_CHANGED;
    la_amd_undo_callback_funct_t undo = [this](attribute_management_details amd) { return amd; };
    la_status status = m_device->notify_attribute_changed(m_parent.get(), amd, undo);
    return_on_error(status);

    // Directly connected host - flag is written to the LPM entry of the subnet.
    status = set_egress_sflow_enabled_host<la_ipv4_addr_t, la_ipv4_prefix_t>(m_subnet_ipv4.m_subnet_ip_map);
    return_on_error(status);
    status = set_egress_sflow_enabled_host<la_ipv6_addr_t, la_ipv6_prefix_t>(m_subnet_ipv6.m_subnet_ip_map);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::get_egress_sflow_enabled(bool& out_enabled) const
{
    out_enabled = m_egress_sflow_enabled;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_base::verify_matching_mirror_types(const la_mirror_command* mirror_cmd, mirror_type_e type)
{
    switch (mirror_cmd->type()) {
    case silicon_one::la_object::object_type_e::L2_MIRROR_COMMAND: {
        const auto* l2_mirror_cmd = static_cast<const la_l2_mirror_command_base*>(mirror_cmd);
        auto actual_type = l2_mirror_cmd->get_mirror_type();

        if (type == actual_type) {
            return LA_STATUS_SUCCESS;
        }

        break;
    }
    case silicon_one::la_object::object_type_e::ERSPAN_MIRROR_COMMAND: {
        const auto* erspan_mirror_cmd = static_cast<const la_erspan_mirror_command_base*>(mirror_cmd);
        auto actual_type = erspan_mirror_cmd->get_mirror_type();

        if (type == actual_type) {
            return LA_STATUS_SUCCESS;
        }

        break;
    }
    default:
        // not supposed to happen
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_EINVAL;
}

la_status
la_vrf_port_common_base::get_egress_dhcp_snooping_enabled(bool& out_enabled) const
{
    out_enabled = m_egress_dhcp_snooping;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
