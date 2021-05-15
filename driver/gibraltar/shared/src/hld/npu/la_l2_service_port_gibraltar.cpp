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

#include "api/npu/la_switch.h"

#include "common/defines.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "npu/counter_utils.h"
#include "npu/la_ac_profile_impl.h"
#include "npu/la_acl_delegate.h"

#include "api/npu/la_vrf.h"
#include "nplapi/npl_constants.h"
#include "npu/la_acl_impl.h"
#include "npu/la_ecmp_group_impl.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_filter_group_impl.h"
#include "npu/la_l2_service_port_gibraltar.h"
#include "npu/la_l3_protection_group_impl.h"
#include "npu/la_prefix_object_base.h"
#include "npu/la_switch_impl.h"
#include "npu/resolution_utils.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "qos/la_meter_set_impl.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"
#include "system/la_system_port_base.h"

#include "api_tracer.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>
#include <tuple>

namespace silicon_one
{

la_l2_service_port_gibraltar::la_l2_service_port_gibraltar(const la_device_impl_wptr& device)
    : la_l2_service_port_pacgb(device),
      m_slice_data(ASIC_MAX_SLICES_PER_DEVICE_NUM, slice_data()),
      m_slice_pair_data(NUM_SLICE_PAIRS_PER_DEVICE, slice_pair_data()),
      m_ac_profile_for_pwe(nullptr)
{
}

la_status
la_l2_service_port_gibraltar::configure_common_tables()
{
    return configure_resolution_step();
}

la_status
la_l2_service_port_gibraltar::teardown_tables()
{
    return teardown_resolution_step();
}

la_status
la_l2_service_port_gibraltar::set_l3_destination(const la_l3_destination* l3_destination)
{
    start_api_call("l3_destination=", l3_destination);
    if (m_port_type == port_type_e::VXLAN) {
        if (m_l3_destination == l3_destination) {
            return LA_STATUS_SUCCESS;
        }

        la_status status;

        if (l3_destination == nullptr) {
            status = teardown_resolution_step();
            return_on_error(status);
            m_device->remove_object_dependency(m_l3_destination, this);
            m_l3_destination = nullptr;
        } else {
            auto prev_l3_destination = m_l3_destination;
            m_l3_destination = m_device->get_sptr<la_l3_destination>(l3_destination);

            object_type_e type = m_l3_destination->type();

            switch (type) {
            case object_type_e::NEXT_HOP:
                status = instantiate_resolution_object(
                    m_l3_destination, RESOLUTION_STEP_FORWARD_L2, m_device->get_sptr<const la_system_port>(this));
                return_on_error(status);
                break;

            case object_type_e::ECMP_GROUP:
                status = instantiate_resolution_object(
                    m_l3_destination, RESOLUTION_STEP_FORWARD_L2, m_device->get_sptr<const la_system_port>(this));
                return_on_error(status);
                break;

            default:
                log_err(HLD, "invalid object type: %d", static_cast<int>(type));
                return LA_STATUS_EINVAL;
            }

            status = configure_resolution_step_vxlan(m_cur_ovl_nh_id);
            return_on_error(status);

            if (prev_l3_destination != nullptr) {
                status = uninstantiate_resolution_object(prev_l3_destination, RESOLUTION_STEP_FORWARD_L2);
                return_on_error(status);
                m_device->remove_object_dependency(prev_l3_destination, this);
            }
            m_device->add_object_dependency(m_l3_destination, this);
        }
    } else if (m_port_type == port_type_e::PWE) {
        return update_l3_destination_pwe(m_device->get_sptr(l3_destination));
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::instantiate_pwe_l3_destination(const la_l3_destination_wcptr& l3_destination)
{
    la_object::object_type_e dest_type = l3_destination->type();

    if ((dest_type != la_object::object_type_e::PREFIX_OBJECT) && (dest_type != la_object::object_type_e::DESTINATION_PE)
        && (dest_type != la_object::object_type_e::FEC)
        && (dest_type != la_object::object_type_e::ECMP_GROUP)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (dest_type == object_type_e::PREFIX_OBJECT) {
        auto pfx_obj = l3_destination.weak_ptr_static_cast<const la_prefix_object_base>();
        if (!pfx_obj->is_resolution_forwarding_supported()) {
            return LA_STATUS_EINVAL;
        }
    }

    return instantiate_resolution_object(l3_destination, RESOLUTION_STEP_FORWARD_L2);
}

la_status
la_l2_service_port_gibraltar::uninstantiate_pwe_l3_destination(const la_l3_destination_wcptr& l3_destination)
{
    return uninstantiate_resolution_object(l3_destination, RESOLUTION_STEP_FORWARD_L2);
}

la_status
la_l2_service_port_gibraltar::update_l3_destination_pwe(const la_l3_destination_wcptr& l3_destination)
{
    transaction txn;

    if (l3_destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (l3_destination == m_l3_destination) {
        return LA_STATUS_SUCCESS;
    }

    txn.status = instantiate_pwe_l3_destination(l3_destination);
    return_on_error(txn.status);
    txn.on_fail([&]() { uninstantiate_pwe_l3_destination(l3_destination); });

    // VPLS PWE specific check
    if (m_attached_switch) {
        // Check if this PWE destination is not used by any other PWEs
        la_status status = pwe_sw_dest_in_use(l3_destination);
        if (status != LA_STATUS_ENOTFOUND) {
            if (status == LA_STATUS_SUCCESS) {
                log_err(HLD, "PWE destination in this switch %d is already in use", m_attached_switch->get_gid());
                return LA_STATUS_EEXIST;
            } else {
                log_err(HLD, "Invalid Lookup Key");
                return LA_STATUS_EINVAL;
            }
        }
        txn.status = teardown_pwe_vpls_label_table();
        return_on_error(txn.status);
        txn.on_fail([&]() { configure_pwe_vpls_label_table(); });
    }

    auto old_l3_destination = m_l3_destination;
    m_l3_destination = l3_destination;
    txn.on_fail([&]() { m_l3_destination = old_l3_destination; });

    attribute_management_details amd;
    amd.op = attribute_management_op::PWE_L3_DESTINATION_ATTRIB_CHANGED;
    la_amd_undo_callback_funct_t undo = [this](attribute_management_details amd) { return amd; };

    txn.status = m_device->notify_attribute_changed(this, amd, undo);
    return_on_error(txn.status);

    txn.status = uninstantiate_pwe_l3_destination(old_l3_destination);
    return_on_error(txn.status);
    txn.on_fail([&]() { instantiate_pwe_l3_destination(old_l3_destination); });

    // Check for VPLS PWE
    if (m_attached_switch) {
        // Program pwe_vpls_label_table
        txn.status = configure_pwe_vpls_label_table();
        return_on_error(txn.status);
        txn.on_fail([&]() { teardown_pwe_vpls_label_table(); });
        // Program pwe_to_l3_dest table
        txn.status = configure_pwe_to_l3_dest_table();
        return_on_error(txn.status);
        txn.on_fail([&]() { teardown_pwe_to_l3_dest_table(); });
    }

    m_device->add_object_dependency(m_l3_destination, this);

    m_device->remove_object_dependency(old_l3_destination, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::update_l3_destination_for_l3vxlan(bool shared_overlay_nh)
{
    if (shared_overlay_nh) {
        m_cur_ovl_nh_id = VXLAN_SHARED_OVERLAY_NH_ID;
    } else {
        m_cur_ovl_nh_id = m_compressed_vxlan_dlp_id;
    }

    return configure_resolution_step_vxlan(m_cur_ovl_nh_id);
}

la_status
la_l2_service_port_gibraltar::do_update_relay_id_in_pwe_tables(uint64_t relay_id)
{
    // Update the MPLS termination table
    if (m_port_type == port_type_e::PWE) {
        for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
            const auto& mpls_termination_entry = m_slice_pair_data[slice_pair].mpls_termination_entry;
            npl_mpls_termination_em1_table_value_t value = mpls_termination_entry->value();

            value.payloads.mpls_termination_result.result.pwe_vpn_mldp_info.pwe_info.l2_relay_id.id = relay_id;
            la_status status = mpls_termination_entry->update(value);
            return_on_error(status);
        }
    } else if (m_port_type == port_type_e::PWE_TAGGED) {
        for (la_slice_id_t slice = 0; slice < m_slice_data.size(); slice++) {
            npl_service_mapping_tcam_pwe_tag_table_value_t value = m_slice_data_b[slice].pwe_port_tag_entry->value();

            value.payloads.sm.relay_id = relay_id;
            la_status status = m_slice_data_b[slice].pwe_port_tag_entry->update(value);
            return_on_error(status);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::do_set_pwe_vpls_filter_group(la_slice_pair_id_t pair_idx, uint64_t group_id)
{
    auto& pwe_vpls_entry = m_slice_pair_data[pair_idx].pwe_vpls_label_entry;
    auto pwe_vpls_entry_v(pwe_vpls_entry->value());
    pwe_vpls_entry_v.payloads.vpn_encap_data.l2vpn_label_encap_data.lp_profile = group_id;
    return pwe_vpls_entry->update(pwe_vpls_entry_v);
}

la_status
la_l2_service_port_gibraltar::add_ifg(la_slice_ifg ifg)
{
    bool ifg_added, slice_added, slice_pair_added;
    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);

    // Notify users before configuring the tables so that the counters get updated
    la_status status = m_device->notify_ifg_added(this, ifg);
    return_on_error(status);

    // Update AC attributes
    if (m_port_type == port_type_e::AC) {
        la_status status = m_ac_port_common.add_ifg(ifg);
        return_on_error(status);
    } else if (m_port_type == port_type_e::VXLAN) {
        if (slice_pair_added) {
            bool allocated = m_device->m_index_generators.slice_pair[ifg.slice / 2].service_port_slps.allocate(
                m_slice_pair_data[ifg.slice / 2].local_slp_id);

            if (!allocated) {
                return LA_STATUS_ERESOURCE;
            }
        }
    }
    if (slice_pair_added) {
        la_slice_pair_id_t pair_idx = ifg.slice / 2;

        if (m_port_type != port_type_e::PWE_TAGGED) {
            status = configure_service_lp_attributes_table(ifg.slice, m_slice_pair_data[pair_idx].lp_attributes_entry);
            return_on_error(status);
        }

        la_status status = configure_l2_dlp_table(pair_idx);
        return_on_error(status);

        status = configure_txpp_dlp_profile_table(pair_idx);
        return_on_error(status);

        status = notify_l2_dlp_attrib_change();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::remove_ifg(la_slice_ifg ifg)
{
    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);

    la_status status = m_device->notify_ifg_removed(this, ifg);
    return_on_error(status);

    // Remove per-slice-pair tables
    if (slice_pair_removed) {
        la_slice_pair_id_t pair_idx = ifg.slice / 2;

        if (m_port_type != port_type_e::PWE_TAGGED) {
            status = teardown_service_lp_attributes_table(ifg.slice, m_slice_pair_data[pair_idx].lp_attributes_entry);
            return_on_error(status);
        }

        status = teardown_l2_dlp_table(pair_idx);
        return_on_error(status);
    }

    if (m_port_type == port_type_e::AC) {
        status = m_ac_port_common.remove_ifg(ifg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_l2_service_port_gibraltar::~la_l2_service_port_gibraltar()
{
}

la_status
la_l2_service_port_gibraltar::configure_resolution_step()
{
    if (m_port_type == port_type_e::AC) {
        npl_resolution_stage_assoc_data_narrow_entry_t entry{{0}};
        entry.stage0_l2_dlp_dest.destination
            = silicon_one::get_destination_id(m_ac_ethernet_port, RESOLUTION_STEP_STAGE0_L2_LP).val;
        entry.stage0_l2_dlp_dest.enc_type = NPL_NPU_ENCAP_L2_HEADER_TYPE_AC;
        entry.stage0_l2_dlp_dest.type = NPL_ENTRY_TYPE_STAGE0_L2_DLP_DESTINATION;

        destination_id dest = silicon_one::get_destination_id(m_device->get_sptr(this), RESOLUTION_STEP_FORWARD_L2);
        return m_device->m_resolution_configurators[0].configure_dest_map_entry(dest, entry, m_stage_cfg_handle);
    } else if (m_port_type == port_type_e::VXLAN) {
        return configure_resolution_step_vxlan(m_cur_ovl_nh_id);
    } else if (m_port_type == port_type_e::PWE) {
        return LA_STATUS_SUCCESS;
    }
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l2_service_port_gibraltar::configure_resolution_step_vxlan(uint64_t ovl_nh_id)
{

    if (m_l3_destination == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    npl_resolution_stage_assoc_data_narrow_entry_t entry{{0}};
    entry.stage0_destination_overlay_nh.destination
        = silicon_one::get_destination_id(m_l3_destination, RESOLUTION_STEP_STAGE0_L2_LP).val;
    entry.stage0_destination_overlay_nh.overlay_nh = ovl_nh_id;
    entry.stage0_destination_overlay_nh.type = NPL_ENTRY_TYPE_STAGE0_L2_DLP_DESTINATION_OVERLAY_NH;

    destination_id dest = silicon_one::get_destination_id(this, RESOLUTION_STEP_FORWARD_L2);
    return m_device->m_resolution_configurators[0].configure_dest_map_entry(dest, entry, m_stage_cfg_handle);
}

la_status
la_l2_service_port_gibraltar::teardown_resolution_step()
{
    if (m_port_type == port_type_e::AC) {
        return m_device->m_resolution_configurators[0].unconfigure_entry(m_stage_cfg_handle);
    } else if (m_port_type == port_type_e::VXLAN && m_l3_destination != nullptr) {
        la_status status = uninstantiate_resolution_object(m_l3_destination, RESOLUTION_STEP_FORWARD_L2);
        return_on_error(status, HLD, ERROR, "uninstantiate_resolution_object failed");
    } else if (m_port_type == port_type_e::PWE) {
        return LA_STATUS_SUCCESS;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::configure_pwe_service_lp_attributes_table()
{
    la_status status;

    for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
        status = configure_service_lp_attributes_table(slice_pair * 2, m_slice_pair_data[slice_pair].lp_attributes_entry);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::teardown_pwe_service_lp_attributes_table()
{
    la_status status;
    for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
        status = teardown_service_lp_attributes_table(slice_pair * 2, m_slice_pair_data[slice_pair].lp_attributes_entry);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::configure_mpls_termination_table()
{
    for (la_slice_pair_id_t slice_pair : get_slice_pairs(m_device, la_slice_mode_e::NETWORK)) {
        const auto& table(m_device->m_tables.mpls_termination_em1_table[slice_pair]);
        npl_mpls_termination_em1_table_value_t value;
        npl_mpls_termination_em1_table_key_t key;

        key.termination_label = m_local_label.label;

        npl_mpls_termination_result_t& result(value.payloads.mpls_termination_result.result);
        result.service = NPL_MPLS_SERVICE_PWE;
        result.pwe_vpn_mldp_info.pwe_info.is_pwe_raw = 1;
        result.pwe_vpn_mldp_info.pwe_info.fat_exists = m_flow_label_enable;
        result.pwe_vpn_mldp_info.pwe_info.cw_exists = m_control_word_enable;
        result.pwe_vpn_mldp_info.pwe_info.mac_lp_attr.vlan_profile_and_lp_type.vlan_profile
            = (m_ac_profile_for_pwe) ? m_ac_profile_for_pwe.get()->get_id() : 0;
        result.pwe_vpn_mldp_info.pwe_info.mac_lp_attr.vlan_profile_and_lp_type.l2_lp_type = NPL_L2_LP_TYPE_PWE;
        result.pwe_vpn_mldp_info.pwe_info.l2_relay_id.id = (m_attached_switch) ? m_attached_switch->get_gid() : 0;
        result.pwe_vpn_mldp_info.pwe_info.mac_lp_attr.local_slp_id.id = get_local_slp_id(2 * slice_pair);

        la_status status = table->set(key, value, m_slice_pair_data[slice_pair].mpls_termination_entry);

        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::teardown_mpls_termination_table()
{
    for (la_slice_pair_id_t slice_pair : get_slice_pairs(m_device, la_slice_mode_e::NETWORK)) {
        if (!m_slice_pair_data[slice_pair].mpls_termination_entry) {
            continue;
        }
        const auto& table(m_device->m_tables.mpls_termination_em1_table[slice_pair]);
        npl_mpls_termination_em1_table_key_t key;

        key.termination_label = m_local_label.label;

        la_status status = table->erase(key);
        return_on_error(status);

        m_slice_pair_data[slice_pair].mpls_termination_entry = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::configure_pwe_encap_table()
{
    for (la_slice_pair_id_t slice_pair : get_slice_pairs(m_device, la_slice_mode_e::NETWORK)) {
        const auto& table(m_device->m_tables.pwe_label_table[slice_pair]);
        npl_pwe_label_table_value_t value;
        npl_pwe_label_table_key_t key;

        key.pwe_id = m_pwe_gid;

        // Same interface check is triggered in npl. Set to 0xFFFFF for p2p flows so check will fail for p2p.
        value.payloads.vpn_encap_data.l2vpn_label_encap_data.pwe_l2_dlp_id = 0xFFFFF;
        value.payloads.vpn_encap_data.l2vpn_label_encap_data.label = m_remote_label.label;

        value.payloads.vpn_encap_data.l2vpn_label_encap_data.l2vpn_control_bits.no_fat = m_flow_label_enable ? 0 : 1;
        npl_l2vpn_cw_fat_exists_e& cw_fat_exists(
            value.payloads.vpn_encap_data.l2vpn_label_encap_data.l2vpn_control_bits.cw_fat_exists);
        npl_ene_macro_ids_e& first_ene_macro(value.payloads.vpn_encap_data.l2vpn_label_encap_data.first_ene_macro.id);

        switch ((m_flow_label_enable ? 1 : 0) | ((m_control_word_enable ? 1 : 0) << 1)) {
        case 0:
            cw_fat_exists = NPL_L2VPN_NO_CW_NO_FAT;
            first_ene_macro = NPL_VPN_OR_6PE_LABEL_ENE_MACRO;
            break;
        case 1:
            cw_fat_exists = NPL_L2VPN_NO_CW_WITH_FAT;
            first_ene_macro = NPL_PWE_NO_CW_WITH_FAT_ENE_MACRO;
            break;
        case 2:
            cw_fat_exists = NPL_L2VPN_WITH_CW_NO_FAT;
            first_ene_macro = NPL_PWE_WITH_CW_NO_FAT_ENE_MACRO;
            break;
        case 3:
        default:
            cw_fat_exists = NPL_L2VPN_WITH_CW_WITH_FAT;
            first_ene_macro = NPL_PWE_WITH_CW_WITH_FAT_ENE_MACRO;
            break;
        }

        la_status status = table->set(key, value, m_slice_pair_data[slice_pair].pwe_encap_entry);

        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::teardown_pwe_encap_table()
{
    for (la_slice_pair_id_t slice_pair : get_slice_pairs(m_device, la_slice_mode_e::NETWORK)) {
        if (!m_slice_pair_data[slice_pair].pwe_encap_entry) {
            continue;
        }
        const auto& table(m_device->m_tables.pwe_label_table[slice_pair]);

        npl_pwe_label_table_key_t key = m_slice_pair_data[slice_pair].pwe_encap_entry->key();
        la_status status = table->erase(key);
        return_on_error(status);

        m_slice_pair_data[slice_pair].pwe_encap_entry = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::configure_pwe_vpls_label_table()
{
    for (la_slice_pair_id_t slice_pair : get_slice_pairs(m_device, la_slice_mode_e::NETWORK)) {
        const auto& table(m_device->m_tables.pwe_vpls_label_table[slice_pair]);
        npl_pwe_vpls_label_table_value_t value;
        npl_pwe_vpls_label_table_key_t key;

        destination_id dest_id = silicon_one::get_destination_id(m_l3_destination, RESOLUTION_STEP_FORWARD_L2);
        if (dest_id == DESTINATION_ID_INVALID) {
            return LA_STATUS_EUNKNOWN;
        }

        key.l2_relay_id.id = m_attached_switch->get_gid();
        key.lsp_destination = dest_id.val;

        value.payloads.vpn_encap_data.l2vpn_label_encap_data.label = m_remote_label.label;
        if (m_filter_group != nullptr) {
            value.payloads.vpn_encap_data.l2vpn_label_encap_data.lp_profile = m_filter_group->get_id();
        }
        value.payloads.vpn_encap_data.l2vpn_label_encap_data.pwe_l2_dlp_id = (NPL_DESTINATION_MASK_L2_PWE_DLP | m_pwe_gid);

        value.payloads.vpn_encap_data.l2vpn_label_encap_data.l2vpn_control_bits.no_fat = m_flow_label_enable ? 0 : 1;
        npl_l2vpn_cw_fat_exists_e& cw_fat_exists(
            value.payloads.vpn_encap_data.l2vpn_label_encap_data.l2vpn_control_bits.cw_fat_exists);

        npl_ene_macro_ids_e& first_ene_macro(value.payloads.vpn_encap_data.l2vpn_label_encap_data.first_ene_macro.id);
        switch ((m_flow_label_enable ? 1 : 0) | ((m_control_word_enable ? 1 : 0) << 1)) {
        case NPL_L2VPN_NO_CW_NO_FAT:
            cw_fat_exists = NPL_L2VPN_NO_CW_NO_FAT;
            first_ene_macro = NPL_VPN_OR_6PE_LABEL_ENE_MACRO;
            break;
        case NPL_L2VPN_NO_CW_WITH_FAT:
            cw_fat_exists = NPL_L2VPN_NO_CW_WITH_FAT;
            first_ene_macro = NPL_PWE_NO_CW_WITH_FAT_ENE_MACRO;
            break;
        case NPL_L2VPN_WITH_CW_NO_FAT:
            cw_fat_exists = NPL_L2VPN_WITH_CW_NO_FAT;
            first_ene_macro = NPL_PWE_WITH_CW_NO_FAT_ENE_MACRO;
            break;
        case NPL_L2VPN_WITH_CW_WITH_FAT:
        default:
            cw_fat_exists = NPL_L2VPN_WITH_CW_WITH_FAT;
            first_ene_macro = NPL_PWE_WITH_CW_WITH_FAT_ENE_MACRO;
            break;
        }

        la_status status = table->set(key, value, m_slice_pair_data[slice_pair].pwe_vpls_label_entry);

        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::teardown_pwe_vpls_label_table()
{
    for (la_slice_pair_id_t slice_pair : get_slice_pairs(m_device, la_slice_mode_e::NETWORK)) {
        const auto& table(m_device->m_tables.pwe_vpls_label_table[slice_pair]);

        npl_pwe_vpls_label_table_key_t key = m_slice_pair_data[slice_pair].pwe_vpls_label_entry->key();
        la_status status = table->erase(key);
        return_on_error(status);

        m_slice_pair_data[slice_pair].pwe_vpls_label_entry = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::do_update_cw_fat_pwe_vpls(bool flow_label_enable, bool control_word_enable)
{
    for (la_slice_pair_id_t slice_pair : get_slice_pairs(m_device, la_slice_mode_e::NETWORK)) {
        const auto& pwe_vpls_label_entry = m_slice_pair_data[slice_pair].pwe_vpls_label_entry;
        npl_pwe_vpls_label_table_value_t value = pwe_vpls_label_entry->value();

        value.payloads.vpn_encap_data.l2vpn_label_encap_data.l2vpn_control_bits.no_fat = flow_label_enable ? 0 : 1;
        npl_l2vpn_cw_fat_exists_e& cw_fat_exists(
            value.payloads.vpn_encap_data.l2vpn_label_encap_data.l2vpn_control_bits.cw_fat_exists);
        npl_ene_macro_ids_e& first_ene_macro(value.payloads.vpn_encap_data.l2vpn_label_encap_data.first_ene_macro.id);

        switch ((flow_label_enable ? 1 : 0) | ((control_word_enable ? 1 : 0) << 1)) {
        case NPL_L2VPN_NO_CW_NO_FAT:
            cw_fat_exists = NPL_L2VPN_NO_CW_NO_FAT;
            first_ene_macro = NPL_VPN_OR_6PE_LABEL_ENE_MACRO;
            break;
        case NPL_L2VPN_NO_CW_WITH_FAT:
            cw_fat_exists = NPL_L2VPN_NO_CW_WITH_FAT;
            first_ene_macro = NPL_PWE_NO_CW_WITH_FAT_ENE_MACRO;
            break;
        case NPL_L2VPN_WITH_CW_NO_FAT:
            cw_fat_exists = NPL_L2VPN_WITH_CW_NO_FAT;
            first_ene_macro = NPL_PWE_WITH_CW_NO_FAT_ENE_MACRO;
            break;
        case NPL_L2VPN_WITH_CW_WITH_FAT:
        default:
            cw_fat_exists = NPL_L2VPN_WITH_CW_WITH_FAT;
            first_ene_macro = NPL_PWE_WITH_CW_WITH_FAT_ENE_MACRO;
            break;
        }

        la_status status = pwe_vpls_label_entry->update(value);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::configure_pwe_to_l3_dest_table()
{
    const auto& table(m_device->m_tables.pwe_to_l3_dest_table);
    npl_pwe_to_l3_dest_table_value_t value;
    npl_pwe_to_l3_dest_table_key_t key;

    key.pwe_l2_dlp = (m_pwe_gid | NPL_DESTINATION_MASK_L2_PWE_DLP);

    value.payloads.l3_destination.destination = silicon_one::get_destination_id(m_l3_destination, RESOLUTION_STEP_FORWARD_L2).val;

    la_status status = table->set(key, value, m_pwe_l3_dest_entry);

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::teardown_pwe_to_l3_dest_table()
{
    const auto& table(m_device->m_tables.pwe_to_l3_dest_table);

    npl_pwe_to_l3_dest_table_key_t key = m_pwe_l3_dest_entry->key();
    la_status status = table->erase(key);
    return_on_error(status);

    m_pwe_l3_dest_entry = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::get_attached_destination_id(const la_l2_destination_wcptr& destination, uint64_t& attached_dest_id)
{
    if (!destination) {
        attached_dest_id = 0;
        return LA_STATUS_SUCCESS;
    }

    auto destination_ac = destination.weak_ptr_dynamic_cast<const la_l2_service_port_gibraltar>();

    if (destination_ac && destination_ac->m_port_type == port_type_e::PWE) {
        const la_l3_destination* l3_destination;
        destination_ac->get_l3_destination(l3_destination);
        destination_id dest_id = silicon_one::get_destination_id(l3_destination, RESOLUTION_STEP_FORWARD_L2);
        if (dest_id == DESTINATION_ID_INVALID) {
            return LA_STATUS_EUNKNOWN;
        }
        attached_dest_id = dest_id.val;
    } else {
        attached_dest_id = m_device->get_l2_destination_gid(destination);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::service_mapping_set_destination_p2p_pwe(const la_l2_destination_wcptr& destination)
{
    la_status status;
    la_pwe_gid_t pwe_gid;

    if (m_port_type != port_type_e::AC) {
        return LA_STATUS_SUCCESS;
    }

    auto destination_ac = destination.weak_ptr_dynamic_cast<const la_l2_service_port_gibraltar>();
    if (destination_ac) {
        if (destination_ac->m_port_type == port_type_e::PWE) {
            status = destination_ac->get_pwe_gid(pwe_gid);
            return_on_error(status);
            status = m_ac_port_common.set_destination_p2p_pwe(pwe_gid, true /* is_attached */);
            return_on_error(status);
        }
    } else {
        status = m_ac_port_common.set_destination_p2p_pwe(0, false /* is_attached */);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_slice_pair_id_vec_t
la_l2_service_port_gibraltar::pwe_get_slice_pairs() const
{
    la_slice_pair_id_vec_t slice_pairs;

    for (la_slice_pair_id_t pair_idx : get_slice_pairs(m_device, la_slice_mode_e::NETWORK)) {
        slice_pairs.push_back(pair_idx);
    }

    return slice_pairs;
}

la_status
la_l2_service_port_gibraltar::pwe_sw_dest_in_use(const la_l3_destination_wcptr& l3_destination)
{
    la_status status = LA_STATUS_ENOTFOUND;
    npl_pwe_vpls_label_table_entry_wptr_t pwe_vpls_entry;

    if (m_attached_switch == nullptr) {
        return status;
    }

    for (la_slice_pair_id_t slice_pair : get_slice_pairs(m_device, la_slice_mode_e::NETWORK)) {
        const auto& table(m_device->m_tables.pwe_vpls_label_table[slice_pair]);
        npl_pwe_vpls_label_table_key_t key;

        destination_id dest_id = silicon_one::get_destination_id(l3_destination, RESOLUTION_STEP_FORWARD_L2);
        if (dest_id == DESTINATION_ID_INVALID) {
            return LA_STATUS_EUNKNOWN;
        }

        key.l2_relay_id.id = m_attached_switch->get_gid();
        key.lsp_destination = dest_id.val;
        status = table->lookup(key, pwe_vpls_entry);
        if (status == LA_STATUS_SUCCESS) {
            break;
        }
    }

    return status;
}

void
la_l2_service_port_gibraltar::populate_payload_counters(npl_mac_lp_attributes_payload_t& payload, la_slice_id_t slice)
{
    la_slice_pair_id_t pair_idx = slice / 2;
    // TODO Wassim: Need to makre sure the following line is good enough
    // Once the {IFG, SLICE}->METER-BANK mapping is done (fix for the meters hw bug in pacific)
    payload.layer.two.shared.m_counter = populate_counter_ptr_slice_pair(m_meter, pair_idx, COUNTER_DIRECTION_INGRESS);

    payload.layer.two.shared.q_counter
        = populate_counter_ptr_slice_pair(m_q_counter[COUNTER_DIRECTION_INGRESS], pair_idx, COUNTER_DIRECTION_INGRESS);

    bool is_exist_ingress_qcounter_or_meter = (m_q_counter[COUNTER_DIRECTION_INGRESS] != nullptr) || (m_meter != nullptr);
    if (!m_p_counter[COUNTER_DIRECTION_INGRESS] && is_exist_ingress_qcounter_or_meter) {
        payload.layer.two.shared.sec_acl_attributes.p_counter = NPU_COUNTER_NOP;
    } else {
        payload.layer.two.shared.sec_acl_attributes.p_counter
            = populate_counter_ptr_slice_pair(m_p_counter[COUNTER_DIRECTION_INGRESS], pair_idx, COUNTER_DIRECTION_INGRESS);
    }
}

la_status
la_l2_service_port_gibraltar::update_lp_attributes_payload_lp(npl_mac_lp_attributes_payload_t& payload)
{
    la_slice_pair_id_vec_t slice_pairs;

    if (m_port_type == port_type_e::PWE) {
        slice_pairs = pwe_get_slice_pairs();
    } else {
        slice_pairs = m_ifg_use_count->get_slice_pairs();
    }

    for (auto pair_idx : slice_pairs) {
        // Get the per-slice counters
        populate_payload_counters(payload, pair_idx * 2);

        if (m_ingress_qos_profile) {
            payload.layer.two.shared.qos_id = m_ingress_qos_profile->get_id(pair_idx);
        }

        npl_service_lp_attributes_table_value_t value = m_slice_pair_data[pair_idx].lp_attributes_entry->value();
        value.payloads.write.mac_lp_attributes_payload.lp_attr = payload;

        la_status status = m_slice_pair_data[pair_idx].lp_attributes_entry->update(value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::update_lp_attributes_payload_pwe_tagged(npl_mac_lp_attributes_payload_t& payload)
{
    for (la_slice_id_t slice = 0; slice < m_slice_data_b.size(); slice++) {
        // Get the per-slice counters
        payload.layer.two.shared.q_counter
            = populate_q_counter_ptr(m_q_counter[COUNTER_DIRECTION_INGRESS], slice, COUNTER_DIRECTION_INGRESS);

        if (!m_p_counter[COUNTER_DIRECTION_INGRESS] && m_q_counter[COUNTER_DIRECTION_INGRESS]) {
            payload.layer.two.shared.sec_acl_attributes.p_counter = NPU_COUNTER_NOP;
        } else {
            payload.layer.two.shared.sec_acl_attributes.p_counter
                = populate_counter_ptr_slice_pair(m_p_counter[COUNTER_DIRECTION_INGRESS], slice, COUNTER_DIRECTION_INGRESS);
        }

        payload.layer.two.shared.m_counter = populate_counter_ptr_slice(m_meter, slice, COUNTER_DIRECTION_INGRESS);

        npl_service_mapping_tcam_pwe_tag_table_value_t value = m_slice_data_b[slice].pwe_port_tag_entry->value();
        value.payloads.sm.lp_attr.lp_attr = payload;

        la_status status = m_slice_data_b[slice].pwe_port_tag_entry->update(value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::allocate_pwe_slp_ids()
{
    bool p_success;

    // TODO: The allocation in all slices is not needed, a better allocation is only on NETWORK slices.
    // This should be done in all places that deal with PWE.
    for (la_slice_pair_id_t pair_idx : m_device->get_used_slice_pairs()) {
        p_success
            = m_device->m_index_generators.slice_pair[pair_idx].service_port_pwe.allocate(m_slice_pair_data[pair_idx].local_slp_id);
        if (!p_success) {
            return LA_STATUS_ERESOURCE;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::deallocate_pwe_slp_ids()
{
    for (la_slice_pair_id_t pair_idx : m_device->get_used_slice_pairs()) {
        if (m_slice_pair_data[pair_idx].local_slp_id != la_ac_port_common::LOCAL_SLP_ID_INVALID) {
            m_device->m_index_generators.slice_pair[pair_idx].service_port_pwe.release(m_slice_pair_data[pair_idx].local_slp_id);
            m_slice_pair_data[pair_idx].local_slp_id = la_ac_port_common::LOCAL_SLP_ID_INVALID;
        }
    }

    return LA_STATUS_SUCCESS;
}

uint64_t
la_l2_service_port_gibraltar::get_local_slp_id(la_slice_id_t slice_id) const
{
    la_slice_pair_id_t pair_idx = slice_id / 2;
    if (m_port_type == port_type_e::AC) {
        return m_ac_port_common.get_local_slp_id(pair_idx);
    }

    return m_slice_pair_data[pair_idx].local_slp_id;
}

la_status
la_l2_service_port_gibraltar::map_vxlan_slp()
{
    npl_overlay_ipv4_sip_table_key_t k;
    npl_overlay_ipv4_sip_table_value_t v;
    npl_overlay_ipv4_sip_table_entry_wptr_t e;

    k.sip = m_remote_ip_addr.s_addr;
    k.vxlan_tunnel_loopback = m_sip_index->id();
    for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
        v.payloads.slp_id.id = get_local_slp_id(slice_pair * 2);
        la_status status = m_device->m_tables.overlay_ipv4_sip_table[slice_pair]->insert(k, v, e);
        return_on_error(status, HLD, ERROR, "overlay_ipv4_sip_table insertion failed");
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::unmap_vxlan_slp()
{
    npl_overlay_ipv4_sip_table_key_t k;

    k.sip = m_remote_ip_addr.s_addr;
    k.vxlan_tunnel_loopback = m_sip_index->id();
    for (la_slice_id_t slice_pair : m_device->get_used_slice_pairs()) {
        la_status status = m_device->m_tables.overlay_ipv4_sip_table[slice_pair]->erase(k);
        return_on_error(status, HLD, ERROR, "overlay_ipv4_sip_table deletion failed");
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::map_mcast_vxlan_slp()
{
    if ((m_local_ip_prefix.addr.s_addr & 0xF0000000) != LA_IPV4_MC_PREFIX.addr.s_addr) {
        return LA_STATUS_EINVAL;
    }

    for (la_slice_id_t slice : m_device->get_used_slices()) {
        const auto& table(m_device->m_tables.my_ipv4_table[slice]);
        npl_my_ipv4_table_t::key_type key;
        npl_my_ipv4_table_t::key_type mask;
        npl_my_ipv4_table_t::value_type value;

        key.l3_relay_id.id = 0;
        key.dip = 0xe0000000;
        key.l4_protocol_type_3_2 = ((NPL_PROTOCOL_TYPE_UDP) >> 2) & 0x3UL;
        mask.l3_relay_id.id = 0;
        mask.dip = 0xf0000000;
        mask.l4_protocol_type_3_2 = 0x3UL;

        value.action = NPL_MY_IPV4_TABLE_ACTION_WRITE;
        value.payloads.ip_tunnel_termination_attr.ip_termination_type = NPL_TERMINATION_DIP_INDEX_LDB;
        value.payloads.ip_tunnel_termination_attr.ip_tunnel_termination_attr_or_slp.tunnel_slp_id.id = get_local_slp_id(slice);

        size_t entry_loc = -1; // without the initialization, Werror yell for no apparent reason
        la_status status = table->locate_first_free_entry(entry_loc);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "failed to find free entry in my_ipv4_table (%s)", la_status2str(status).c_str());
            return status;
        }

        // insert to the free location
        npl_my_ipv4_table_t::entry_type* entry;
        status = table->insert(entry_loc, key, mask, value, entry);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "insert mcast entry in my ipv4 table failed");
            return status;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::unmap_mcast_vxlan_slp()
{
    if ((m_local_ip_prefix.addr.s_addr & 0xF0000000) != LA_IPV4_MC_PREFIX.addr.s_addr) {
        return LA_STATUS_EINVAL;
    }

    for (la_slice_id_t slice : m_device->get_used_slices()) {
        const auto& table(m_device->m_tables.my_ipv4_table[slice]);
        npl_my_ipv4_table_t::key_type key;
        npl_my_ipv4_table_t::key_type mask;

        key.l3_relay_id.id = 0;
        key.dip = 0xe0000000;
        key.l4_protocol_type_3_2 = ((NPL_PROTOCOL_TYPE_UDP) >> 2) & 0x3UL;
        mask.l3_relay_id.id = 0;
        mask.dip = 0xf0000000;
        mask.l4_protocol_type_3_2 = 0x3UL;

        size_t entry_loc;
        npl_my_ipv4_table_t::entry_type* entry;

        la_status status = table->find(key, mask, entry, entry_loc);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "failed to find mcast entry in my_ipv4_table (%s)", la_status2str(status).c_str());
            return status;
        }

        // Remove entry
        status = table->erase(entry_loc);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "my_ipv4_table deletion failed (%s), for mcast ip", la_status2str(status).c_str());
            return status;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::get_fec_table_value(npl_fec_table_value_t& value) const
{
    npl_fec_fec_destination_t& destination(value.payloads.resolution_fec_result.fec_dest);

    destination.type = NPL_ENTRY_TYPE_FEC_FEC_DESTINATION;
    destination.destination = destination_id(NPL_DESTINATION_MASK_L2_DLP | m_port_gid).val;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::configure_txpp_dlp_profile_table(la_slice_pair_id_t slice_pair)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::teardown_txpp_dlp_profile_table(la_slice_pair_id_t slice_pair)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::set_ac_profile_for_pwe(la_ac_profile* ac_profile)
{
    start_api_call("ac_profile=", ac_profile);

    // Check parameters
    if (m_port_type != port_type_e::PWE) {
        return LA_STATUS_EINVAL;
    }

    if (ac_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (ac_profile->get_device() != get_device()) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (ac_profile == m_ac_profile_for_pwe.get()) {
        return LA_STATUS_SUCCESS;
    }

    transaction txn;

    auto old_ac_profile = m_ac_profile_for_pwe;
    m_ac_profile_for_pwe = m_device->get_sptr(static_cast<la_ac_profile_impl*>(ac_profile));
    txn.on_fail([&]() { m_ac_profile_for_pwe = old_ac_profile; });

    txn.status = configure_mpls_termination_table();
    return_on_error(txn.status);

    if (old_ac_profile != nullptr) {
        m_device->remove_object_dependency(old_ac_profile, this);
    }

    m_device->add_object_dependency(m_ac_profile_for_pwe, this);

    return LA_STATUS_SUCCESS;
}

void
la_l2_service_port_gibraltar::clear_ac_profile_for_pwe()
{
    if (m_ac_profile_for_pwe != nullptr) {
        m_device->remove_object_dependency(m_ac_profile_for_pwe, this);
    }

    m_ac_profile_for_pwe = nullptr;
}

la_status
la_l2_service_port_gibraltar::get_ac_profile_for_pwe(la_ac_profile*& out_ac_profile) const
{
    start_api_getter_call();

    if (m_port_type != port_type_e::PWE) {
        return LA_STATUS_EINVAL;
    }

    out_ac_profile = m_ac_profile_for_pwe.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::configure_pwe_port_tag_table()
{
    for (la_slice_id_t slice = 0; slice < m_slice_data_b.size(); slice++) {
        slice_data_base& data(m_slice_data_b[slice]);
        const auto& table(m_device->m_tables.service_mapping_tcam_pwe_tag_table[slice]);
        npl_service_mapping_tcam_pwe_tag_table_key_t key;
        npl_service_mapping_tcam_pwe_tag_table_key_t mask;
        npl_service_mapping_tcam_pwe_tag_table_value_t value;

        memset(&mask, 0xff, sizeof(mask)); // Full key - no masking

        la_vlan_id_t vid1, vid2;
        la_status status = get_service_mapping_vids(vid1, vid2);
        return_on_error(status);

        key.local_slp_id.id = get_local_slp_id(slice);
        key.vid1.id = vid1;

        populate_lp_attributes_payload(value.payloads.sm.lp_attr.lp_attr);
        value.payloads.sm.lp_id.id = m_port_gid;
        value.payloads.sm.relay_id = 0; // Changes when attaching to a switch

        size_t location{};
        status = table->locate_first_free_entry(location);
        return_on_error(status);

        status = table->insert(location, key, mask, value, data.pwe_port_tag_entry);
        return_on_error(status);

        data.pwe_port_tag_entry_location = location;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::populate_nh_l2_payload(npl_nh_payload_t& out_nh_payload, la_slice_pair_id_t pair_idx) const
{
    if (m_port_type != port_type_e::AC) {
        return LA_STATUS_EINVAL;
    }

    if (!m_ifg_use_count->is_slice_pair_in_use(pair_idx)) {
        // this l2_ac port does not have sys port on this pair_idx.
        // no configuration required for this pair_idx, return
        return LA_STATUS_SUCCESS;
    }

    // update qos_attributes
    bool demux_count
        = (m_p_counter[COUNTER_DIRECTION_EGRESS] != nullptr) ? m_p_counter[COUNTER_DIRECTION_EGRESS]->get_set_size() > 1 : false;
    out_nh_payload.l2_port = 1;
    out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_dlp_qos_and_attr.demux_count = demux_count ? 1 : 0;
    out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_dlp_qos_and_attr.p_counter
        = populate_counter_ptr_slice_pair(m_p_counter[COUNTER_DIRECTION_EGRESS], pair_idx, COUNTER_DIRECTION_EGRESS);
    out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_dlp_qos_and_attr.q_counter
        = populate_counter_ptr_slice_pair(m_q_counter[COUNTER_DIRECTION_EGRESS], pair_idx, COUNTER_DIRECTION_EGRESS);
    // out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_dlp_qos_and_attr.acl_drop_offset.cntr_offset.offset.base_cntr_offset
    //    = m_drop_counter_offset;
    out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_dlp_qos_and_attr.qos_id = m_egress_qos_profile->get_id(pair_idx);

    la_egress_qos_marking_source_e marking_source{};
    la_status status = m_egress_qos_profile->get_marking_source(marking_source);
    return_on_error(status);
    out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_dlp_qos_and_attr.is_group_qos
        = (marking_source == la_egress_qos_marking_source_e::QOS_GROUP);

    // update eve data
    la_vlan_edit_command eve;
    status = get_egress_vlan_edit_command(eve);
    return_on_error(status);

    // NP2 except asic3: nh supports two vlan definition
    if (eve.num_tags_to_push == 0) {
        out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.nh_ene_macro_code = NPL_NH_ENE_MACRO_ETH;
        out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_tpid_prof = 0;
    } else {
        // one or more tags
        out_nh_payload.eve_vid1 = eve.tag0.tci.fields.vid;
        if (eve.tag0.tpid == 0x8100) {
            out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_tpid_prof = 0;
        } else if (eve.tag0.tpid == 0x88a8) {
            out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_tpid_prof = 1;
        } else if (eve.tag0.tpid == 0x9100) {
            out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_tpid_prof = 2;
        } else {
            return LA_STATUS_ENOTIMPLEMENTED;
        }

        if (eve.num_tags_to_push == 1) {
            out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.nh_ene_macro_code = NPL_NH_ENE_MACRO_ETH_VLAN;
        } else if (eve.num_tags_to_push == 2) {
            out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.nh_ene_macro_code = NPL_NH_ENE_MACRO_ETH_VLAN_VLAN;
            out_nh_payload.eve_vid2 = eve.tag1.tci.fields.vid;
        } else {
            return LA_STATUS_ENOTIMPLEMENTED;
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::update_vxlan_group_policy_encap(la_slice_pair_id_t pair_idx)
{
    npl_vxlan_l2_dlp_table_entry_wptr_t& l2_dlp_entry = la_l2_service_port_base::m_slice_pair_data_b[pair_idx].vxlan_l2_dlp_entry;

    if (l2_dlp_entry == nullptr) {
        log_err(HLD, "l2_dlp_table[%d] update group policy encap failed", pair_idx);
        return LA_STATUS_SUCCESS;
    }

    typename npl_vxlan_l2_dlp_table_t::value_type value = l2_dlp_entry->value();
    value.payloads.vxlan_tunnel_attributes.group_policy_encap = m_group_policy_encap;

    la_status status = l2_dlp_entry->update(value);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::set_group_policy_encap(bool enabled)
{
    start_api_call("enabled=", enabled);

    if (m_port_type != port_type_e::VXLAN) {
        return LA_STATUS_EINVAL;
    }

    if (m_group_policy_encap == enabled) {
        return LA_STATUS_SUCCESS;
    }

    m_group_policy_encap = enabled;
    for (auto pair_idx : m_ifg_use_count->get_slice_pairs()) {
        la_status status = update_vxlan_group_policy_encap(pair_idx);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::get_group_policy_encap(bool& out_enabled) const
{
    start_api_getter_call("");

    if (m_port_type != port_type_e::VXLAN) {
        return LA_STATUS_EINVAL;
    }

    out_enabled = m_group_policy_encap;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_gibraltar::update_vxlan_group_policy_encap(npl_vxlan_l2_dlp_table_value_t& value)
{
    value.payloads.vxlan_tunnel_attributes.group_policy_encap = m_group_policy_encap;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
