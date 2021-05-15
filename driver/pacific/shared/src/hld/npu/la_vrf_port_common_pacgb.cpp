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
#include "npu/la_counter_set_impl.h"
#include "npu/la_gre_port_impl.h"
#include "npu/la_gue_port_impl.h"
#include "npu/la_ip_over_ip_tunnel_port_impl.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_svi_port_base.h"
#include "npu/la_switch_impl.h"
#include "npu/la_vrf_impl.h"
#include "npu/la_vrf_port_common_pacgb.h"
#include "npu/resolution_utils.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "qos/la_meter_set_impl.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_vrf_port_common_pacgb::la_vrf_port_common_pacgb(const la_device_impl_wptr& device, la_l3_port_wptr parent)
    : la_vrf_port_common_base(device, parent), m_slice_pair_data(NUM_SLICE_PAIRS_PER_DEVICE, slice_pair_data())
{
}

la_vrf_port_common_pacgb::~la_vrf_port_common_pacgb()
{
}

la_status
la_vrf_port_common_pacgb::set_mac(const la_mac_addr_t& mac_addr)
{
    // Not allow change mac address on recycle L3 AC port.
    if (m_is_recycle_ac) {
        return LA_STATUS_EINVAL;
    }

    la_status status = m_device->m_mac_addr_manager->remove(m_mac_addr, NPL_MAC_DA_TYPE_UC);
    return_on_error(status);

    status = m_device->m_mac_addr_manager->add(mac_addr, NPL_MAC_DA_TYPE_UC);
    return_on_error(status);

    uint64_t index;
    status = m_device->m_mac_addr_manager->get_index(mac_addr, index);
    return_on_error(status);

    for (auto& pair_data : m_slice_pair_data) {
        if (pair_data.l3_dlp_table_entry != nullptr) {
            auto value = pair_data.l3_dlp_table_entry->value();

            npl_l3_dlp_attributes_t& attrib(value.payloads.l3_dlp_attributes);

            attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vlan_and_sa_lsb_encap.tpid_sa_lsb.sa_lsb
                = mac_address_manager::get_lsbits(mac_addr);
            attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.sa_prefix_index = index;

            status = pair_data.l3_dlp_table_entry->update(value);
            return_on_error(status);
        }
    }

    m_mac_addr = mac_addr;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::add_ifg(la_slice_ifg ifg)
{
    bool ifg_added, slice_added, slice_pair_added;
    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);

    if (!slice_added) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = la_vrf_port_common_base::update_l3_lp_attributes_per_slice(ifg.slice, m_l3_lp_attributes);
    return_on_error(status);

    if (slice_pair_added) {
        la_slice_pair_id_t pair_idx = ifg.slice / 2;

        status = configure_l3_dlp_table(pair_idx);
        return_on_error(status);

        status = configure_txpp_dlp_profile_table(pair_idx);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::remove_ifg(la_slice_ifg ifg)
{
    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);

    if ((slice_removed) && (m_parent->type() == la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT)) {
        auto parent = m_parent.weak_ptr_static_cast<la_ip_over_ip_tunnel_port_impl>();
        la_status status = parent->teardown_tunnel_termination_table_per_slice(ifg.slice);
        return_on_error(status);
    }
    if ((slice_removed) && (m_parent->type() == la_object::object_type_e::GUE_PORT)) {
        auto parent = m_parent.weak_ptr_static_cast<la_gue_port_impl>();
        la_status status = parent->teardown_tunnel_termination_table_per_slice(ifg.slice);
        return_on_error(status);
    }

    if (slice_pair_removed) {
        la_slice_pair_id_t pair_idx = ifg.slice / 2;
        la_status status = teardown_l3_dlp_table(pair_idx);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::set_active(bool active)
{
    if (active == m_is_active) {
        return LA_STATUS_SUCCESS;
    }

    npl_base_l3_lp_attributes_t attribs = m_l3_lp_attributes;

    la_status status = do_set_active(active, attribs);
    return_on_error(status);

    status = update_l3_lp_attributes(attribs);
    return_on_error(status);

    set_l3_lp_attributes(attribs);

    // disable egress mode
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();

    for (la_slice_pair_id_t pair_idx : slice_pairs) {
        slice_pair_data& pair_data(m_slice_pair_data[pair_idx]);
        npl_l3_dlp_table_value_t value(pair_data.l3_dlp_table_entry->value());
        npl_l3_dlp_attributes_t& attrib(value.payloads.l3_dlp_attributes);

        attrib.disabled = !active;
        status = pair_data.l3_dlp_table_entry->update(value);
        return_on_error(status);
    }

    m_is_active = active;
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::set_port_egress_mode(bool active)
{

    la_status status;
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();

    for (la_slice_pair_id_t pair_idx : slice_pairs) {
        slice_pair_data& pair_data(m_slice_pair_data[pair_idx]);
        npl_l3_dlp_table_value_t value(pair_data.l3_dlp_table_entry->value());
        npl_l3_dlp_attributes_t& attrib(value.payloads.l3_dlp_attributes);

        attrib.disabled = !active;
        status = pair_data.l3_dlp_table_entry->update(value);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile)
{
    if (egress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(egress_qos_profile, m_device)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // If nothing to update
    if (m_egress_qos_profile.get() == egress_qos_profile) {
        return LA_STATUS_SUCCESS;
    }

    auto egress_qos_profile_impl = static_cast<la_egress_qos_profile_impl*>(egress_qos_profile);
    auto old_profile = m_egress_qos_profile;

    // Tell the policy about all our IFGs (triggers TCAM programming)
    la_status status = add_current_ifgs(this, egress_qos_profile_impl);
    return_on_error(status);

    m_device->add_ifg_dependency(m_parent, egress_qos_profile_impl);
    m_device->add_object_dependency(egress_qos_profile, m_parent);

    m_egress_qos_profile = m_device->get_sptr(egress_qos_profile_impl);

    // Update device
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();

    for (auto slice_pair : slice_pairs) {
        status = configure_l3_dlp_table(slice_pair);
        return_on_error(status);
    }

    m_device->remove_ifg_dependency(m_parent, old_profile);
    m_device->remove_object_dependency(old_profile, m_parent);

    status = remove_current_ifgs(this, old_profile.get());
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::set_egress_vlan_tag(la_vlan_tag_t tag1, la_vlan_tag_t tag2)
{
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();

    for (la_slice_pair_id_t pair_idx : slice_pairs) {
        slice_pair_data& pair_data(m_slice_pair_data[pair_idx]);
        la_status status = do_set_egress_vlan_tag(tag1, tag2, pair_data.l3_dlp_table_entry);
        return_on_error(status);
    }

    m_tag1 = tag1;
    m_tag2 = tag2;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::configure_l3_dlp_attributes(la_slice_pair_id_t pair_idx)
{
    la_status status;
    la_object::object_type_e type = m_parent->type();

    // Port specific code
    switch (type) {
    case la_object::object_type_e::L3_AC_PORT: {
        status = configure_l3_dlp_table(pair_idx);
    } break;
    case la_object::object_type_e::SVI_PORT: {
        status = configure_l3_dlp_table(pair_idx);
    } break;
    case la_object::object_type_e::GRE_PORT: {
        auto gre_port = m_parent.weak_ptr_static_cast<la_gre_port_impl>();
        status = gre_port->configure_ip_tunnel_dlp_table(pair_idx);
    } break;
    default:
        status = LA_STATUS_EUNKNOWN;
    }

    return status;
}

la_status
la_vrf_port_common_pacgb::configure_l3_dlp_table(la_slice_pair_id_t pair_idx)
{
    if ((m_parent->type() == la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT)
        || (m_parent->type() == la_object::object_type_e::GUE_PORT)) {
        return LA_STATUS_SUCCESS;
    }

    if (m_parent->type() == la_object::object_type_e::GRE_PORT) {
        auto gre_port = m_parent.weak_ptr_static_cast<la_gre_port_impl>();
        return (gre_port->configure_ip_tunnel_dlp_table(pair_idx));
    }
    uint64_t index;

    const auto& table(m_device->m_tables.l3_dlp_table[pair_idx]);
    npl_l3_dlp_table_key_t key = get_l3_dlp_table_key();
    npl_l3_dlp_table_value_t value;
    npl_l3_dlp_attributes_t& attrib(value.payloads.l3_dlp_attributes);

    attrib.disabled = 0;
    attrib.svi_dhcp_snooping = m_egress_dhcp_snooping;
    la_status status = get_l3_lp_qos_and_attributes(pair_idx, attrib.l3_dlp_qos_and_attributes);
    return_on_error(status);

    bool is_recycle_ac = false;
    if (m_parent->type() == la_object::object_type_e::L3_AC_PORT) {
        const la_l3_ac_port_impl_wcptr parent = m_parent.weak_ptr_static_cast<la_l3_ac_port_impl>();
        is_recycle_ac = silicon_one::is_recycle_ac(parent);
    }

    status = silicon_one::populate_rcy_data(m_device, m_egress_mirror_cmd, is_recycle_ac, attrib.tx_to_rx_rcy_data);
    return_on_error(status);

    if (m_filter_group) {
        attrib.l3_dlp_qos_and_attributes.l3_dlp_info.dlp_attributes.lp_profile = m_filter_group->get_id();
    } else {
        attrib.l3_dlp_qos_and_attributes.l3_dlp_info.dlp_attributes.lp_profile = 0;
    }

    // The encap data is a union - clear all the union fields and then
    // initialize only the svi fields
    memset(&attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap, 0, sizeof(attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap));
    attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vlan_and_sa_lsb_encap.vlan_id = m_tag1.tci.fields.vid;
    attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vlan_and_sa_lsb_encap.tpid_sa_lsb.tpid
        = (is_vlan_tag_eq(m_tag1, LA_VLAN_TAG_UNTAGGED)) ? 0x8100 : m_tag1.tpid;

    la_mac_addr_t smac;
    if (m_is_recycle_ac) {
        la_mac_addr_t recycle_ac_smac;
        recycle_ac_smac.flat = RECYCLE_AC_SMAC;
        smac = recycle_ac_smac;
    } else {
        smac = m_mac_addr;
    }

    status = m_device->m_mac_addr_manager->get_index(smac, index);
    return_on_error(status);

    attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vlan_and_sa_lsb_encap.tpid_sa_lsb.sa_lsb = mac_address_manager::get_lsbits(smac);
    attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.sa_prefix_index = index;

    attrib.nh_ene_macro_code
        = (is_vlan_tag_eq(m_tag1, LA_VLAN_TAG_UNTAGGED))
              ? NPL_NH_ENE_MACRO_ETH
              : (is_vlan_tag_eq(m_tag2, LA_VLAN_TAG_UNTAGGED) ? NPL_NH_ENE_MACRO_ETH_VLAN : NPL_NH_ENE_MACRO_ETH_VLAN_VLAN);
    attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vid2_or_flood_rcy_sm_vlans.flood_rcy_sm_vlans.vid1 = 0;
    attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vid2_or_flood_rcy_sm_vlans.flood_rcy_sm_vlans.vid2 = m_tag2.tci.fields.vid;

    if (m_parent->type() == la_object::object_type_e::SVI_PORT) {
        la_vlan_id_t out_vid1 = LA_VLAN_ID_INVALID, out_vid2 = LA_VLAN_ID_INVALID;
        status = get_rcy_sm_vlans(out_vid1, out_vid2);

        attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vid2_or_flood_rcy_sm_vlans.flood_rcy_sm_vlans.vid1 = out_vid1;
        attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vid2_or_flood_rcy_sm_vlans.flood_rcy_sm_vlans.vid2 = out_vid2;
    }

    if (m_slice_pair_data[pair_idx].l3_dlp_table_entry != nullptr) {
        status = m_slice_pair_data[pair_idx].l3_dlp_table_entry->update(value);
    } else {
        status = table->insert(key, value, m_slice_pair_data[pair_idx].l3_dlp_table_entry);
    }

    return_on_error(status);

    attribute_management_details amd;
    amd.op = attribute_management_op::L3_PORT_ATTR_CHANGED;
    amd.l3_port = m_parent.get();
    la_amd_undo_callback_funct_t undo = [this](attribute_management_details amd) { return amd; };
    status = m_device->notify_attribute_changed(m_parent.get(), amd, undo);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::teardown_l3_dlp_table(la_slice_pair_id_t pair_idx)
{
    if ((m_parent->type() == la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT)
        || (m_parent->type() == la_object::object_type_e::GUE_PORT)) {
        return LA_STATUS_SUCCESS;
    }

    const auto& table(m_device->m_tables.l3_dlp_table[pair_idx]);
    npl_l3_dlp_table_key_t key = m_slice_pair_data[pair_idx].l3_dlp_table_entry->key();

    la_status status = table->erase(key);
    return_on_error(status);

    m_slice_pair_data[pair_idx].l3_dlp_table_entry = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::configure_egress_drop_counter_offset(size_t offset)
{
    m_egress_acl_drop_offset = offset;

    // Update device
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();
    for (auto slice_pair : slice_pairs) {
        la_status status = configure_l3_dlp_table(slice_pair);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    if (mirror_cmd != nullptr && !of_same_device(mirror_cmd, m_device)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (mirror_cmd != nullptr) {
        la_status status = verify_matching_mirror_types(mirror_cmd, mirror_type_e::MIRROR_EGRESS);
        return_on_error(status);
    }

    m_egress_mirror_cmd = m_device->get_sptr(mirror_cmd);
    m_egress_port_mirror_type = is_acl_conditioned ? NPL_PORT_MIRROR_TYPE_CONDITIONED : NPL_PORT_MIRROR_TYPE_UN_CONDITIONED;

    auto slices = m_ifg_use_count->get_slices();
    for (auto slice : slices) {
        la_slice_pair_id_t pair_idx = slice / 2;
        la_status status = configure_l3_dlp_table(pair_idx);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::configure_ingress_counter()
{
    for (auto pair_idx : m_ifg_use_count->get_slice_pairs()) {
        la_status status = configure_l3_dlp_table(pair_idx);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::set_ecn_remark_enabled(bool enabled)
{
    if (m_enable_ecn_remark == enabled) {
        return LA_STATUS_SUCCESS;
    }

    m_enable_ecn_remark = enabled;

    // Update device
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();
    for (auto slice_pair : slice_pairs) {
        la_status status = configure_l3_dlp_table(slice_pair);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::set_ecn_counting_enabled(bool enabled)
{
    if (m_enable_ecn_counting == enabled) {
        return LA_STATUS_SUCCESS;
    }

    m_enable_ecn_counting = enabled;

    // Update device
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();
    for (auto slice_pair : slice_pairs) {
        la_status status = configure_l3_dlp_table(slice_pair);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::get_mac_termination_table_key(la_switch_gid_t sw_id, npl_mac_termination_em_table_key_t& out_key) const
{
    uint64_t prefix;
    la_status status = m_device->m_mac_addr_manager->get_prefix(m_mac_addr, prefix);
    return_on_error(status);

    out_key.relay_id.id = sw_id;
    out_key.ethernet_header_da_18_0_ = m_mac_addr.flat & ((1ULL << 19) - 1);
    out_key.da_prefix = prefix;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_pacgb::set_egress_dhcp_snooping_enabled(bool enabled)
{
    if (m_egress_dhcp_snooping == enabled) {
        return LA_STATUS_SUCCESS;
    }

    m_egress_dhcp_snooping = enabled;

    // Update device
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();
    for (auto slice_pair : slice_pairs) {
        la_status status = configure_l3_dlp_table(slice_pair);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
