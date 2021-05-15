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

#include "la_multicast_group_common_akpg.h"
#include "common/defines.h"
#include "common/math_utils.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "la_multicast_group_common_akpg.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_mpls_nhlfe_impl.h"
#include "npu/la_multicast_protection_group_base.h"
#include "npu/mc_copy_id_manager.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"
#include "tm/la_unicast_tc_profile_impl.h"

namespace silicon_one
{

la_multicast_group_common_akpg::la_multicast_group_common_akpg(const la_device_impl_wptr& device)
    : la_multicast_group_common_base(device)
{
}

la_multicast_group_common_akpg::~la_multicast_group_common_akpg()
{
}

la_status
la_multicast_group_common_akpg::initialize(la_multicast_group_gid_t multicast_gid,
                                           la_multicast_group_gid_t local_mcid,
                                           la_replication_paradigm_e rep_paradigm,
                                           bool is_scale_mode_smcid)
{
    m_gid = multicast_gid;
    m_local_mcid = local_mcid;
    m_rep_paradigm = rep_paradigm;
    m_is_scale_mode_smcid = is_scale_mode_smcid;

    // Insert a line to each one of the MCID tables
    const auto& tables(m_device->m_tables.mc_slice_bitmap_table);

    // Local MCID is always programmed because in non-scale mode it will
    // be the same as the global MCID.
    m_mc_slice_bitmap_table_key.fwd_destination = local_mcid;
    m_mc_fabric_slice_bitmap_table_value.action = NPL_MC_SLICE_BITMAP_TABLE_ACTION_WRITE;
    m_mc_network_slice_bitmap_table_value.action = NPL_MC_SLICE_BITMAP_TABLE_ACTION_WRITE;

    if (m_rep_paradigm == la_replication_paradigm_e::EGRESS) {
        m_mc_fabric_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap.bitmap_indicator
            |= 0xFF; // setting all bits to 1 no matter the field width

        m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap.bitmap_indicator
            |= 0xFF; // setting all bits to 1 no matter the field width
    } else {
        m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.group_size
            = NULL_GROUP_SIZE;
    }

    // In fabric MC, the LC should send the packet to the FE even if this group has no members, then FE will throw the packet out.
    if (m_device->m_device_mode == device_mode_e::LINECARD) {
        uint32_t network_slice_bitmap;

        // To send to fabric, we need to set the 6th bit to 1 as a hardware convention.
        // In non-scale mode, the slice bitmap is used in the ingress linecard
        // to send the packets to the fabric slice.
        network_slice_bitmap = FABRIC_BITMAP;

        // In Ingress LC there is no replecation, so we count MC traffic as UC (#1159)
        m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.counterA_inc_enable = 1;

        if (m_is_scale_mode_smcid
            || (m_device->is_reserved_smcid(m_gid) && (m_gid != la_device_impl::MULTICAST_RESERVED_SMCID_TO_FABRIC_SLICE))) {
            // In scale mode, the local MCID bitmap is initialized to zero
            // and will be updated once members are added to the group. This
            // local MCID bitmap will be used on the egress linecard second
            // pass processing to find the member slices. The reserved
            // multicast groups are not used in scale mode.
            network_slice_bitmap = 0;

            // scaled mode MCIDs count traffic as multicast
            m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.counterA_inc_enable = 0;
        }

        if (m_rep_paradigm == la_replication_paradigm_e::EGRESS) {
            m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap.bitmap
                = network_slice_bitmap;
        } else {
            m_mc_network_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.group_size
                = NULL_GROUP_SIZE_FOR_FABRIC;
        }

        // For reserved multicast scale MCIDs, set the fabric bitmap accordingly
        if (m_device->is_reserved_smcid(multicast_gid)) {
            uint32_t bitmap;
            la_status status = m_device->multicast_reserved_smcid_fabric_slice_bitmap(multicast_gid, bitmap);
            return_on_error(status);

            m_mc_fabric_slice_bitmap_table_value.payloads.mc_slice_bitmap_table_result.group_size_or_bitmap.mc_bitmap.bitmap
                = bitmap;
        }
    }

    // Scale mode MCIDs will get programmed when the first member is added and
    // a local MCID is allocated. For scale mode MCIDs the ingress side will
    // send with 0xffff and only the egress side needs a local MCID when a
    // member is added.
    if (!m_is_scale_mode_smcid) {
        la_status status = per_slice_tables_insert(m_device->m_slice_mode,
                                                   tables,
                                                   {la_slice_mode_e::CARRIER_FABRIC},
                                                   m_mc_slice_bitmap_table_key,
                                                   m_mc_fabric_slice_bitmap_table_value);
        return_on_error(status);

        status = per_slice_tables_insert(m_device->m_slice_mode,
                                         tables,
                                         {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC},
                                         m_mc_slice_bitmap_table_key,
                                         m_mc_network_slice_bitmap_table_value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_group_common_akpg::destroy()
{
    const auto& tables(m_device->m_tables.mc_slice_bitmap_table);

    // Scale mode MCIDs might not have set the mc_slice_bitmap_table because
    // they haven't assigned a local MCID yet.
    if (!(m_is_scale_mode_smcid && (m_local_mcid == NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE))) {
        la_status status = per_slice_tables_erase(m_device->m_slice_mode,
                                                  tables,
                                                  {la_slice_mode_e::CARRIER_FABRIC, la_slice_mode_e::NETWORK},
                                                  m_mc_slice_bitmap_table_key);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_group_common_akpg::configure_egress_rep_common(const group_member_desc& member,
                                                            const la_system_port_wcptr& dsp_in,
                                                            uint64_t mc_copy_id)
{
    transaction txn;
    auto dsp = la_system_port_base::upcast_from_api(m_device, dsp_in);
    if ((dsp != nullptr) && (is_dsp_remote(dsp))) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    // Configure MC EM DB
    txn.status = add_mc_em_db_entry_egress_rep(dsp, member, mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([=]() { remove_mc_em_db_entry_egress_rep(dsp, member); });

    // Configure per-slice TXPDR MC group size table
    la_slice_id_t slice = dsp->get_slice();
    txn.status = configure_mc_list_size_table_per_slice(slice, 0 /*adjustment*/);
    return_on_error(txn.status);
    txn.on_fail([=]() { configure_mc_list_size_table_per_slice(slice, -1 /*adjustment*/); });

    // Get the destination's slices
    bool new_slice_added = add_slice_user(m_slice_data, slice);
    txn.on_fail([=]() { remove_slice_user(m_slice_data, slice); });

    if (new_slice_added) {
        // Configure egress bitmap tables
        txn.status = configure_mc_slice_bitmap();
        return_on_error(txn.status);
    }

    return txn.status;
}

la_status
la_multicast_group_common_akpg::do_add_mc_em_db_entry_egress_rep(const la_system_port_wcptr& dsp,
                                                                 uint64_t member_index,
                                                                 uint64_t mc_copy_id,
                                                                 npl_mc_em_db_entry_wptr_t& out_entry)
{
    if (is_dsp_remote(dsp)) {
        return LA_STATUS_EINVAL;
    }

    const auto& dspi = dsp.weak_ptr_static_cast<const la_system_port_base>();
    const la_tc_profile_impl* tc_profile = static_cast<const la_tc_profile_impl*>(dspi->get_tc_profile());
    uint64_t tc_map_profile = tc_profile->get_id();
    uint64_t oq_group = calculate_oqg_index(dsp);
    la_slice_id_t slice = dspi->get_slice();

    la_status status = insert_entry_to_mc_em_db_tx_format_0(member_index, slice, tc_map_profile, oq_group, mc_copy_id, out_entry);

    return status;
}

la_status
la_multicast_group_common_akpg::add_mc_em_db_entry_egress_rep(const la_system_port_wcptr& dsp_in,
                                                              const group_member_desc& member,
                                                              uint64_t mc_copy_id)
{
    auto dsp = la_system_port_base::upcast_from_api(m_device, dsp_in);
    npl_mc_em_db_entry_wptr_t entry;
    la_slice_id_t slice = dsp->get_slice();
    slice_data& data(m_slice_data[slice]);
    uint64_t member_index = data.mc_em_entries.size(); // Size before adding the new port

    la_status status = do_add_mc_em_db_entry_egress_rep(dsp, member_index, mc_copy_id, entry);
    return_on_error(status);

    dassert_crit(data.mc_em_entries_map.find(member) == data.mc_em_entries_map.end());
    data.mc_em_entries_map[member] = entry;

    data.mc_em_entries.push_back(member);

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_group_common_akpg::set_member_dsp(const group_member_desc& member,
                                               const la_system_port_wcptr& curr_dsp_in,
                                               const la_system_port_wcptr& new_dsp_in,
                                               uint64_t old_mc_copy_id,
                                               uint64_t new_mc_copy_id)
{
    transaction txn;

    if ((curr_dsp_in == nullptr) || (new_dsp_in == nullptr)) {
        log_err(HLD, "%s: invalid DSP", __func__);
        return LA_STATUS_EUNKNOWN;
    }
    auto curr_dsp = la_system_port_base::upcast_from_api(m_device, curr_dsp_in);
    auto new_dsp = la_system_port_base::upcast_from_api(m_device, new_dsp_in);
    if (is_dsp_remote(new_dsp)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (curr_dsp->get_slice() == new_dsp->get_slice()) {
        // If the current and the new DSPs reside on the same slice then
        // just update the entry and return

        la_slice_id_t curr_slice = curr_dsp->get_slice();
        slice_data& curr_data(m_slice_data[curr_slice]);

        // Get the member's entry-index in the slice of the current DSP
        auto vec_it = std::find(curr_data.mc_em_entries.begin(), curr_data.mc_em_entries.end(), member);
        if (vec_it == curr_data.mc_em_entries.end()) {
            log_err(HLD, "%s: cannot find <%s> in list", __func__, member.to_string().c_str());
            return LA_STATUS_EUNKNOWN;
        }

        size_t member_index = vec_it - curr_data.mc_em_entries.begin();

        npl_mc_em_db_entry_wptr_t entry;
        txn.status = do_add_mc_em_db_entry_egress_rep(new_dsp, member_index, new_mc_copy_id, entry);
        return_on_error(txn.status);

        curr_data.mc_em_entries_map[member] = entry;

        return LA_STATUS_SUCCESS;
    }

    // The DSPs are not on the same slice. Add a new entry at the new slice, and then remove
    // the current entry. There's a gap in which packets can be dropped.
    txn.status = teardown_egress_rep_common(member, curr_dsp);
    return_on_error(txn.status);
    txn.on_fail([&]() { configure_egress_rep_common(member, curr_dsp, old_mc_copy_id); });

    txn.status = configure_egress_rep_common(member, new_dsp, new_mc_copy_id);
    return txn.status;
}

la_status
la_multicast_group_common_akpg::remove_mc_em_db_entry_egress_rep(const la_system_port_wcptr& dsp_in,
                                                                 const group_member_desc& tbr_member)
{
    auto dsp = la_system_port_base::upcast_from_api(m_device, dsp_in);
    la_slice_id_t slice = dsp->get_slice();
    slice_data& data(m_slice_data[slice]);
    auto vec_it = std::find(data.mc_em_entries.begin(), data.mc_em_entries.end(), tbr_member);
    if (vec_it == data.mc_em_entries.end()) {
        log_err(HLD, "%s: cannot find <%s> in list", __func__, tbr_member.to_string().c_str());
        return LA_STATUS_EUNKNOWN;
    }

    size_t member_index = vec_it - data.mc_em_entries.begin();
    size_t last_member_index = data.mc_em_entries.size() - 1;
    bool is_last_member = (member_index == last_member_index);

    // Get the MC-EM-DB table entry of the TBR member
    auto map_it = data.mc_em_entries_map.find(tbr_member);
    dassert_crit(map_it != data.mc_em_entries_map.end());
    npl_mc_em_db_entry_wptr_t entry = map_it->second;

    // Remove the member from the object's slice data
    data.mc_em_entries_map.erase(tbr_member);

    // If this is the last member then remove it return
    if (is_last_member) {
        data.mc_em_entries.pop_back();
        la_status status = remove_entry_from_mc_em_db_tx_format_0(member_index, entry->key());

        return status;
    }

    // Get the last member
    group_member_desc last_member = data.mc_em_entries[last_member_index];
    auto last_entry_it = data.mc_em_entries_map.find(last_member);
    dassert_crit(last_entry_it != data.mc_em_entries_map.end());
    npl_mc_em_db_entry_wptr_t last_entry = last_entry_it->second;

    npl_mc_em_db_key_t last_entry_key = last_entry->key();
    npl_mc_em_db_value_t last_entry_value = last_entry->value();

    // Change the value of the entry that was used for holding the removed member
    // so that it holds the details of the last member
    la_status status = update_entry_in_mc_em_db_tx_format_0(entry, member_index, last_entry_value, last_member_index);
    return_on_error(status);

    data.mc_em_entries_map[last_member] = entry;
    data.mc_em_entries[member_index] = last_member;

    // Erase the last member from MC-EM-DB
    status = remove_entry_from_mc_em_db_tx_format_0(last_member_index, last_entry_key);
    return_on_error(status);

    // Remove the last member from the object's slice data structures
    data.mc_em_entries.pop_back();

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_group_common_akpg::teardown_egress_rep_common(const group_member_desc& member, const la_system_port_wcptr& dsp_in)
{
    auto dsp = la_system_port_base::upcast_from_api(m_device, dsp_in);
    transaction txn;
    la_slice_id_t slice = dsp->get_slice();
    bool slice_removed = remove_slice_user(m_slice_data, slice);
    txn.on_fail([=]() { add_slice_user(m_slice_data, slice); });

    if (slice_removed) {
        // Configure egress bitmap tables
        txn.status = configure_mc_slice_bitmap();
        return_on_error(txn.status);
        txn.on_fail([=]() { configure_mc_slice_bitmap(); });
    }

    // Configure per-slice TXPDR MC group size table
    txn.status = configure_mc_list_size_table_per_slice(slice, -1 /*adjustment*/);
    return_on_error(txn.status);
    txn.on_fail([=]() { configure_mc_list_size_table_per_slice(slice, 0 /*adjustment*/); });

    // If the removed entry is not the last one - there is a gap in which
    // packets to the last entry might be dropped. This is expected and
    // acceptable.

    // Configure MC EM DB
    txn.status = remove_mc_em_db_entry_egress_rep(dsp, member);
    return_on_error(txn.status);

    return txn.status;
}

la_status
la_multicast_group_common_akpg::verify_dsp(const la_ethernet_port_wcptr& eth, const la_system_port_wcptr& dsp) const
{
    if (dsp == nullptr) {
        log_err(HLD, "%s: NULL DSP", __func__);
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(dsp, m_device)) {
        log_err(HLD,
                "%s: objects %s and this are on different devices (%d, %d)",
                __func__,
                silicon_one::to_string(dsp).c_str(),
                dsp->get_device()->get_id(),
                m_device->get_id());
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (eth == nullptr) {
        log_err(HLD, "%s: NULL ethernet port", __func__);
        return LA_STATUS_EINVAL;
    }

    const la_system_port* sp = eth->get_system_port();
    if (sp != nullptr) {
        if (sp != dsp) {
            log_err(HLD, "%s: DSP is not attached to ethernet port", __func__);
            return LA_STATUS_EINVAL;
        }

    } else {

        const la_spa_port* spa = eth->get_spa_port();
        if (spa == nullptr) {
            log_err(HLD, "%s: ethernet port without SP or SPA", __func__);
            return LA_STATUS_EINVAL;
        }

        system_port_vec_t spa_members;
        la_status status = spa->get_members(spa_members);
        return_on_error(status);

        auto it = std::find(spa_members.begin(), spa_members.end(), dsp.get());
        if (it == spa_members.end()) {
            log_err(HLD, "%s: DSP is not a member of the SPA", __func__);
            return LA_STATUS_EINVAL;
        }
    }

    const auto& dspi = dsp.weak_ptr_static_cast<const la_system_port_base>();
    la_system_port_base::port_type_e dsp_type = dspi->get_port_type();
    if ((dsp_type != la_system_port_base::port_type_e::MAC) && (dsp_type != la_system_port_base::port_type_e::PCI)
        && (dsp_type != la_system_port_base::port_type_e::RECYCLE)) {
        log_err(HLD, "%s: DSP type %s is not supported", __func__, silicon_one::to_string(dsp_type).c_str());
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_group_common_akpg::update_member_slice_data(const group_member_desc& old_member,
                                                         const group_member_desc& new_member,
                                                         la_slice_id_t slice)
{
    // Update member data in mc_em_entries_map and mc_em_entries
    // Don't worry about members being on different slices - any slice movements are done before this function is called
    if (m_slice_data[slice].mc_em_entries_map.find(old_member) == m_slice_data[slice].mc_em_entries_map.end()) {
        return LA_STATUS_SUCCESS;
    }
    auto entry = m_slice_data[slice].mc_em_entries_map[old_member];
    m_slice_data[slice].mc_em_entries_map.erase(old_member);
    m_slice_data[slice].mc_em_entries_map[new_member] = entry;

    std::replace(m_slice_data[slice].mc_em_entries.begin(), m_slice_data[slice].mc_em_entries.end(), old_member, new_member);

    return LA_STATUS_SUCCESS;
}

bool
la_multicast_group_common_akpg::is_dsp_remote(const la_system_port_wcptr& dsp) const
{
    const auto& dspi = dsp.weak_ptr_static_cast<const la_system_port_base>();
    la_system_port_base::port_type_e dsp_type = dspi->get_port_type();
    return (dsp_type == la_system_port_base::port_type_e::REMOTE);
}

void
la_multicast_group_common_akpg::set_local_mcid(la_multicast_group_gid_t local_mcid)
{
    m_local_mcid = local_mcid;
    m_mc_slice_bitmap_table_key.fwd_destination = local_mcid;
}

la_status
la_multicast_group_common_akpg::configure_ingress_rep_common(const group_member_desc& member, la_slice_id_t slice)
{

    transaction txn;
    la_multicast_group_gid_t member_mcid = get_local_mcid(member);
    if (member_mcid == ((la_multicast_group_gid_t)-1)) {
        return LA_STATUS_EINVAL;
    }

    txn.status = add_mc_em_db_entry_ingress_rep(member, slice, member_mcid);
    return_on_error(txn.status);
    txn.on_fail([=]() { remove_mc_em_db_entry_ingress_rep(member, slice); });

    txn.status = configure_mc_slice_bitmap();
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_group_common_akpg::add_mc_em_db_entry_ingress_rep(const group_member_desc& member,
                                                               la_slice_id_t slice,
                                                               uint64_t member_mcid)
{
    npl_mc_em_db_entry_wptr_t entry;
    ir_data& data(m_ir_data);
    ir_member ir_mem(member_mcid, slice, member);
    uint64_t member_index = data.mc_em_entries.size();

    la_status status = do_add_mc_em_db_entry_ingress_rep(member_index, slice, member_mcid, entry);
    return_on_error(status);

    dassert_crit(data.mc_em_entries_map.find(ir_mem) == data.mc_em_entries_map.end());
    data.mc_em_entries_map[ir_mem] = entry;
    data.mc_em_entries.push_back(ir_mem);

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_group_common_akpg::do_add_mc_em_db_entry_ingress_rep(uint64_t member_index,
                                                                  uint64_t slice,
                                                                  uint64_t member_mcid,
                                                                  npl_mc_em_db_entry_wptr_t& out_entry)
{
    uint64_t tc_map_profile;
    uint64_t base_voq_nr;

    la_status status = m_device->get_mc_bitmap_base_lookup_table_values(slice, tc_map_profile, base_voq_nr);
    return_on_error(status);

    status = insert_entry_to_mc_em_db_rx_result(member_index, slice, tc_map_profile, base_voq_nr, member_mcid, out_entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_group_common_akpg::teardown_ingress_rep_common(const group_member_desc& member, la_slice_id_t slice)
{
    transaction txn;
    la_multicast_group_gid_t mcid = get_local_mcid(member);
    if (mcid == ((la_multicast_group_gid_t)-1)) {
        return LA_STATUS_EINVAL;
    }

    txn.status = remove_mc_em_db_entry_ingress_rep(member, slice);
    return_on_error(txn.status);
    txn.on_fail([=]() { add_mc_em_db_entry_ingress_rep(member, slice, mcid); });

    txn.status = configure_mc_slice_bitmap();
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_group_common_akpg::remove_mc_em_db_entry_ingress_rep(const group_member_desc& member, la_slice_id_t slice)
{
    la_multicast_group_gid_t mcid = get_local_mcid(member);
    if (mcid == ((la_multicast_group_gid_t)-1)) {
        return LA_STATUS_EINVAL;
    }

    ir_data& data(m_ir_data);
    ir_member ir_mem(mcid, slice, member);
    auto vec_it = std::find(data.mc_em_entries.begin(), data.mc_em_entries.end(), ir_mem);
    if (vec_it == data.mc_em_entries.end()) {
        log_err(HLD,
                "%s:%d: GID: 0x%x: cannot find <%s> in list for slice %d",
                __func__,
                __LINE__,
                m_gid,
                member.to_string().c_str(),
                slice);
        return LA_STATUS_EUNKNOWN;
    }

    size_t member_index = vec_it - data.mc_em_entries.begin();
    size_t last_member_index = data.mc_em_entries.size() - 1;
    bool is_last_member = (member_index == last_member_index);

    // Get the MC-EM-DB table entry of the TBR member
    auto map_it = data.mc_em_entries_map.find(ir_mem);
    dassert_crit(map_it != data.mc_em_entries_map.end());
    npl_mc_em_db_entry_wptr_t entry = map_it->second;

    if (is_last_member) {
        la_status status = remove_entry_from_mc_em_db_rx_result(slice, member_index, entry);
        return_on_error(status);

        data.mc_em_entries_map.erase(ir_mem);
        data.mc_em_entries.erase(vec_it);
        return LA_STATUS_SUCCESS;
    }

    ir_member last_member = data.mc_em_entries[last_member_index];
    auto last_entry_it = data.mc_em_entries_map.find(last_member);
    dassert_crit(last_entry_it != data.mc_em_entries_map.end());
    npl_mc_em_db_entry_wptr_t last_entry = last_entry_it->second;

    la_status status = update_entry_in_mc_em_db_rx_result(slice, member_index, entry, last_member_index, last_entry);
    return_on_error(status);

    status = remove_entry_from_mc_em_db_rx_result(slice, last_member_index, last_entry);
    return_on_error(status);

    data.mc_em_entries_map[last_member] = entry;
    data.mc_em_entries[member_index] = last_member;
    data.mc_em_entries_map.erase(ir_mem);
    data.mc_em_entries.erase(data.mc_em_entries.begin() + last_member_index);

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_group_common_akpg::configure_cud_mapping(const group_member_desc& member,
                                                      la_slice_id_t dest_slice,
                                                      uint64_t mc_copy_id)
{
    const auto& table(m_device->m_tables.mc_cud_table[dest_slice]);
    npl_mc_cud_table_key_t key;
    npl_mc_cud_table_value_t value;
    npl_mc_cud_table_entry_wptr_t entry;

    const auto& l2_ac = member.l2_dest.weak_ptr_static_cast<const la_l2_service_port_base>();
    uint64_t l2_port_gid = (l2_ac != nullptr) ? l2_ac->get_gid() : 0;

    key.cud_mapping_local_vars_exp_mc_copy_id_14_1_ = mc_copy_id_manager::get_mc_cud_table_key(mc_copy_id);
    value.action = NPL_MC_CUD_TABLE_ACTION_UPDATE;

    if ((member.l3_port == nullptr) && (l2_ac) && (l2_ac->get_port_type() == la_l2_service_port_base::port_type_e::VXLAN)) {
        la_l3_port* l3_port;
        la_status status = member.next_hop->get_router_port(l3_port);
        if (status != LA_STATUS_SUCCESS) {
            return status;
        }
        if (member.vxlan_type == la_multicast_group_common_base::vxlan_type_e::L3_VXLAN) {
            npl_npu_l3_encap_header_t& payload(value.payloads.update.mapped_cud.app_mc_cud.npu_encap_data.l3);
            payload.l3_common_encap.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_VXLAN_HOST;
            payload.l3_common_encap.l3_dlp_nh_encap.npu_l3_common_dlp_nh_encap.l3_dlp = get_l3_dlp_encap(l3_port->get_gid());
            payload.l3_common_encap.l3_dlp_nh_encap.npu_l3_common_dlp_nh_encap.l3_dlp.properties.monitor_or_l3_dlp_ip_type
                .l3_dlp_ip_type
                = NPL_IPV4_L3_DLP;
            payload.l3_common_encap.l3_dlp_nh_encap.npu_l3_common_dlp_nh_encap.nh = member.next_hop->get_gid();
            payload.encap_ext.vxlan.tunnel_dlp.l2_dlp.id = l2_port_gid;
            payload.encap_ext.vxlan.overlay_nh = 0;
        } else {
            npl_npu_l2_encap_header_t& payload(value.payloads.update.mapped_cud.app_mc_cud.npu_encap_data.l2);
            payload.l2_encapsulation_type = NPL_NPU_ENCAP_L2_HEADER_TYPE_VXLAN;
            payload.l2_dlp_type.vxlan.l3_dlp = get_l3_dlp_encap(l3_port->get_gid());
            payload.l2_dlp_type.vxlan.l3_dlp.properties.monitor_or_l3_dlp_ip_type.l3_dlp_ip_type = NPL_IPV4_L3_DLP;
            payload.l2_dlp_type.vxlan.nh = member.next_hop->get_gid();
            payload.l2_dlp_type.vxlan.tunnel_dlp.l2_dlp.id = l2_port_gid;
            payload.l2_dlp_type.vxlan.overlay_nh = 0;
        }
        return table->set(key, value, entry);

    } else {
        npl_npu_ip_collapsed_mc_encap_header_t payload;
        uint64_t l3_port_gid = (member.l3_port != nullptr) ? member.l3_port->get_gid() : 0;

        payload.collapsed_mc_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_COLLAPSED_MC;
        payload.l3_dlp = get_l3_dlp_encap(l3_port_gid);
        payload.punt.val = (member.is_punt) ? NPL_TRUE_VALUE : NPL_FALSE_VALUE;
        payload.resolve_local_mcid.val = m_device->is_reserved_smcid(m_gid) ? NPL_TRUE_VALUE : NPL_FALSE_VALUE;
        payload.l2_dlp.id = l2_port_gid;

        // A single row in the table holds 2 mc-copy-id's
        la_status status = table->lookup(key, entry);
        if ((status != LA_STATUS_SUCCESS) && (status != LA_STATUS_ENOTFOUND)) {
            // Unexpected failure
            return status;
        }

        if (status == LA_STATUS_SUCCESS) {
            value = entry->value();
        }

        value.payloads.update.mapped_cud_is_narrow = 1;

        npl_npu_ip_collapsed_mc_encap_header_t& target_encap_header
            = ((mc_copy_id & 1) == 0)
                  ? value.payloads.update.mapped_cud.app_mc_cud_narrow_odd_and_even.even.overload_union_ip_collapsed_mc_app_defined
                        .ip_collapsed_mc
                  : value.payloads.update.mapped_cud.app_mc_cud_narrow_odd_and_even.odd.overload_union_ip_collapsed_mc_app_defined
                        .ip_collapsed_mc;
        target_encap_header = payload;

        return table->set(key, value, entry);
    }
}

la_status
la_multicast_group_common_akpg::teardown_cud_mapping(const group_member_desc& member, la_slice_id_t dest_slice, uint64_t mc_copy_id)
{

    if ((member.l3_port != nullptr) && (member.l3_port->type() == la_object::object_type_e::L3_AC_PORT)
        && (member.is_punt == false)) {
        // No CUD mapping is needed for L3-AC if no egress punt
        return LA_STATUS_SUCCESS;
    }

    la_status status;

    const auto& table(m_device->m_tables.mc_cud_table[dest_slice]);
    npl_mc_cud_table_key_t key;
    npl_mc_cud_table_entry_wptr_t entry;

    key.cud_mapping_local_vars_exp_mc_copy_id_14_1_ = mc_copy_id_manager::get_mc_cud_table_key(mc_copy_id);

    status = table->lookup(key, entry);
    if (status == LA_STATUS_ENOTFOUND) {
        dassert_crit(false); // Error in this class' logic. Should never happen
        return LA_STATUS_EUNKNOWN;
    }

    return_on_error(status);

    // Check if this is a single entry by checking the encap-type of the neighboring mc-copy-id
    auto value = entry->value();
    auto& odd_and_even = value.payloads.update.mapped_cud.app_mc_cud_narrow_odd_and_even;
    auto odd_encap_type = odd_and_even.odd.overload_union_ip_collapsed_mc_app_defined.ip_collapsed_mc.collapsed_mc_encap_type;
    auto even_encap_type = odd_and_even.even.overload_union_ip_collapsed_mc_app_defined.ip_collapsed_mc.collapsed_mc_encap_type;
    bool is_single = !((odd_encap_type == NPL_NPU_ENCAP_L3_HEADER_TYPE_COLLAPSED_MC)
                       && (even_encap_type == NPL_NPU_ENCAP_L3_HEADER_TYPE_COLLAPSED_MC));

    if (is_single) {
        // This is the only mc-copy-id in the row. Row can be erased
        return table->erase(key);
    }

    // Another mc-copy-id is sharing this row. Row cannot be erased
    // Clear the encap header of the deleted mc-copy-id
    npl_npu_ip_collapsed_mc_encap_header_t& tbr_encap_header
        = ((mc_copy_id & 1) == 0)
              ? value.payloads.update.mapped_cud.app_mc_cud_narrow_odd_and_even.even.overload_union_ip_collapsed_mc_app_defined
                    .ip_collapsed_mc
              : value.payloads.update.mapped_cud.app_mc_cud_narrow_odd_and_even.odd.overload_union_ip_collapsed_mc_app_defined
                    .ip_collapsed_mc;
    static_assert((NPL_NPU_ENCAP_L3_HEADER_TYPE_COLLAPSED_MC != 0), "Encap type not expected to be 0");
    tbr_encap_header.collapsed_mc_encap_type = (npl_npu_encap_l3_header_type_e)0;

    return entry->update(value);
}

la_status
la_multicast_group_common_akpg::reconfigure_mcemdb_entry(group_member_desc member,
                                                         const la_system_port_base_wcptr dsp,
                                                         uint64_t mc_copy_id)
{
    la_slice_id_t mem_slice = dsp->get_slice();
    slice_data& sd(m_slice_data[mem_slice]);

    // find the member in slice_data
    auto vec_it = std::find(sd.mc_em_entries.begin(), sd.mc_em_entries.end(), member);
    if (vec_it == sd.mc_em_entries.end()) {
        log_err(HLD, "%s:%d: GID: 0x%x: cannot find <%s> in list", __func__, __LINE__, m_gid, member.to_string().c_str());
        return LA_STATUS_EUNKNOWN;
    }
    size_t member_index = vec_it - sd.mc_em_entries.begin();
    bool is_0 = ((member_index % 2) == 0);

    // Get the MC-EM-DB table entry of the L2 member
    auto map_it = sd.mc_em_entries_map.find(member);
    dassert_crit(map_it != sd.mc_em_entries_map.end());

    npl_mc_em_db_entry_wptr_t mem_entry = map_it->second;
    npl_mc_em_db_value_t value(mem_entry->value());
    auto& f0(value.payloads.mc_em_db_result.tx.format_0_or_1.format_0);
    auto& mc(is_0 ? f0.mc_copy_id_0 : f0.mc_copy_id_1);
    mc.value = mc_copy_id;
    la_status status = mem_entry->update(value);
    return_on_error(status);

    status = m_device->flush_mcid_cache(mem_slice);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
