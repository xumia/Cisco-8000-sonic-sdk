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

#include "la_multicast_group_common_plgr.h"
#include "common/defines.h"
#include "common/math_utils.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "la_multicast_group_common_plgr.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_mpls_nhlfe_impl.h"
#include "npu/la_multicast_protection_group_base.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"
#include "tm/la_unicast_tc_profile_impl.h"

namespace silicon_one
{

la_multicast_group_common_plgr::la_multicast_group_common_plgr(la_device_impl_wptr device) : la_multicast_group_common_akpg(device)
{
}

la_multicast_group_common_plgr::~la_multicast_group_common_plgr()
{
}

void
la_multicast_group_common_plgr::populate_mc_em_db_tx_format_0_value(bool is_0,
                                                                    uint64_t tc_map_profile,
                                                                    uint64_t oq_group,
                                                                    uint64_t mc_copy_id,
                                                                    npl_mc_em_db_value_t& out_value)
{
    out_value.payloads.mc_em_db_result.tx.format = 0;

    auto& f0(out_value.payloads.mc_em_db_result.tx.format_0_or_1.format_0);
    auto& map(is_0 ? f0.tc_map_profile_0 : f0.tc_map_profile_1);
    auto& oq(is_0 ? f0.oq_group_0 : f0.oq_group_1);
    auto& mc(is_0 ? f0.mc_copy_id_0 : f0.mc_copy_id_1);

    map.val = tc_map_profile;
    oq.val = oq_group;
    mc.value = mc_copy_id;
}

la_status
la_multicast_group_common_plgr::remove_entry_from_mc_em_db_tx_format_0(size_t member_index, npl_mc_em_db_key_t key)
{
    const auto& table(m_device->m_tables.mc_em_db);
    npl_mc_em_db_entry_wptr_t entry;
    bool is_0 = ((member_index % 2) == 0);

    la_status status = table->lookup(key, entry);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "%s: table lookup failed :%s", __func__, la_status2str(status).c_str());
        return status;
    }

    npl_mc_em_db_value_t value(entry->value());
    if (is_0) {
        value.payloads.mc_em_db_result.tx.format_0_or_1.format_0.mc_copy_id_0.value = NPL_INVALID_MC_COPY_ID;
    } else {
        value.payloads.mc_em_db_result.tx.format_0_or_1.format_0.mc_copy_id_1.value = NPL_INVALID_MC_COPY_ID;
    }

    if ((value.payloads.mc_em_db_result.tx.format_0_or_1.format_0.mc_copy_id_0.value == NPL_INVALID_MC_COPY_ID)
        && (value.payloads.mc_em_db_result.tx.format_0_or_1.format_0.mc_copy_id_1.value == NPL_INVALID_MC_COPY_ID)) {
        status = table->erase(entry->key());
    } else {
        status = entry->update(value);
    }

    la_slice_id_t dest_slice = key.mc_em_db_key.slice_or_is_fabric;
    status = m_device->flush_mcid_cache(dest_slice);
    return_on_error(status);

    return status;
}

la_status
la_multicast_group_common_plgr::update_entry_in_mc_em_db_tx_format_0(npl_mc_em_db_entry_wptr_t dst_entry,
                                                                     size_t member_index_in_dst,
                                                                     const npl_mc_em_db_value_t& src_value,
                                                                     size_t member_index_in_src)
{
    //
    // dst[member_index_in_dst] <-- src[member_index_in_src]
    //
    bool is_0_in_dst = ((member_index_in_dst % 2) == 0);
    npl_mc_em_db_value_t dst_value(dst_entry->value());
    auto& dst_format_0(dst_value.payloads.mc_em_db_result.tx.format_0_or_1.format_0);
    auto& dst_map(is_0_in_dst ? dst_format_0.tc_map_profile_0 : dst_format_0.tc_map_profile_1);
    auto& dst_oq(is_0_in_dst ? dst_format_0.oq_group_0 : dst_format_0.oq_group_1);
    auto& dst_mc(is_0_in_dst ? dst_format_0.mc_copy_id_0 : dst_format_0.mc_copy_id_1);

    bool is_0_in_src = ((member_index_in_src % 2) == 0);
    const auto& src_format_0(src_value.payloads.mc_em_db_result.tx.format_0_or_1.format_0);
    const auto& src_map(is_0_in_src ? src_format_0.tc_map_profile_0 : src_format_0.tc_map_profile_1);
    const auto& src_oq(is_0_in_src ? src_format_0.oq_group_0 : src_format_0.oq_group_1);
    const auto& src_mc(is_0_in_src ? src_format_0.mc_copy_id_0 : src_format_0.mc_copy_id_1);

    dst_map.val = src_map.val;
    dst_oq.val = src_oq.val;
    dst_mc.value = src_mc.value;

    la_status status = dst_entry->update(dst_value);
    return_on_error(status);

    la_slice_id_t dest_slice = dst_entry->key().mc_em_db_key.slice_or_is_fabric;
    status = m_device->flush_mcid_cache(dest_slice);

    return status;
}

la_status
la_multicast_group_common_plgr::insert_entry_to_mc_em_db_rx_result(uint64_t member_index,
                                                                   uint64_t slice,
                                                                   uint64_t tc_map_profile,
                                                                   uint64_t base_voq_nr,
                                                                   uint64_t member_mcid,
                                                                   npl_mc_em_db_entry_wptr_t& out_entry)
{
    const auto& table(m_device->m_tables.mc_em_db);
    npl_mc_em_db_value_t value;
    npl_mc_em_db_entry_wptr_t entry;
    bool is_0 = ((member_index % 2) == 0);
    npl_mc_em_db_key_t key;

    key.mc_em_db_key.is_tx = 0;
    key.mc_em_db_key.slice_or_is_fabric = 0;
    key.mc_em_db_key.is_rcy = 0;
    key.mc_em_db_key.mcid = m_local_mcid;
    key.mc_em_db_key.entry_index = member_index / 2;
    value.action = NPL_MC_EM_DB_ACTION_WRITE;

    la_status status = table->lookup(key, entry);
    if (status == LA_STATUS_SUCCESS) {
        value = entry->value();
        populate_mc_em_db_rx_result_value(is_0, tc_map_profile, base_voq_nr, member_mcid, value);
    } else if (status == LA_STATUS_ENOTFOUND) {
        value.payloads.mc_em_db_result.rx.result_0.mc_copy_id.value = NPL_INVALID_MC_COPY_ID;
        value.payloads.mc_em_db_result.rx.result_1.mc_copy_id.value = NPL_INVALID_MC_COPY_ID;
        populate_mc_em_db_rx_result_value(is_0, tc_map_profile, base_voq_nr, member_mcid, value);
    } else {
        log_err(HLD,
                "%s:%d: GID:0x%x: table lookup failed for slice %lu :%s",
                __func__,
                __LINE__,
                m_gid,
                slice,
                la_status2str(status).c_str());
        return status;
    }

    status = table->set(key, value, entry);
    return_on_error(status);
    status = m_device->flush_mcid_cache(slice);
    return_on_error(status);
    out_entry = entry;
    return LA_STATUS_SUCCESS;
}

void
la_multicast_group_common_plgr::populate_mc_em_db_rx_result_value(bool is_0,
                                                                  uint64_t tc_map_profile,
                                                                  uint64_t base_voq_nr,
                                                                  uint64_t member_mcid,
                                                                  npl_mc_em_db_value_t& out_value)
{
    auto& res0(out_value.payloads.mc_em_db_result.rx.result_0);
    auto& res1(out_value.payloads.mc_em_db_result.rx.result_1);
    auto& map(is_0 ? res0.tc_map_profile : res1.tc_map_profile);
    auto& voq(is_0 ? res0.base_voq_nr : res1.base_voq_nr);
    auto& mc(is_0 ? res0.mc_copy_id : res1.mc_copy_id);

    map.val = tc_map_profile;
    voq.val = base_voq_nr;
    mc.value = member_mcid;
}

la_status
la_multicast_group_common_plgr::update_entry_in_mc_em_db_rx_result(la_slice_id_t slice,
                                                                   size_t dst_index,
                                                                   npl_mc_em_db_entry_wptr_t& dst_entry,
                                                                   size_t src_index,
                                                                   npl_mc_em_db_entry_wptr_t& src_entry)
{
    bool is_0_in_dst = ((dst_index % 2) == 0);
    bool is_0_in_src = ((src_index % 2) == 0);

    npl_mc_em_db_value_t dst_value(dst_entry->value());
    auto& dst_res0(dst_value.payloads.mc_em_db_result.rx.result_0);
    auto& dst_res1(dst_value.payloads.mc_em_db_result.rx.result_1);
    auto& dst_map(is_0_in_dst ? dst_res0.tc_map_profile : dst_res1.tc_map_profile);
    auto& dst_voq(is_0_in_dst ? dst_res0.base_voq_nr : dst_res1.base_voq_nr);
    auto& dst_mc(is_0_in_dst ? dst_res0.mc_copy_id : dst_res1.mc_copy_id);

    npl_mc_em_db_value_t src_value(src_entry->value());
    auto& src_res0(src_value.payloads.mc_em_db_result.rx.result_0);
    auto& src_res1(src_value.payloads.mc_em_db_result.rx.result_1);
    auto& src_map(is_0_in_src ? src_res0.tc_map_profile : src_res1.tc_map_profile);
    auto& src_voq(is_0_in_src ? src_res0.base_voq_nr : src_res1.base_voq_nr);
    auto& src_mc(is_0_in_src ? src_res0.mc_copy_id : src_res1.mc_copy_id);

    dst_map.val = src_map.val;
    dst_voq.val = src_voq.val;
    dst_mc.value = src_mc.value;

    la_status status = dst_entry->update(dst_value);
    return_on_error(status);

    status = m_device->flush_mcid_cache(slice);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_group_common_plgr::remove_entry_from_mc_em_db_rx_result(la_slice_id_t slice,
                                                                     size_t member_index,
                                                                     npl_mc_em_db_entry_wptr_t& entry)
{
    const auto& table(m_device->m_tables.mc_em_db);
    bool is_0 = ((member_index % 2) == 0);
    npl_mc_em_db_key_t key = entry->key();

    la_status status = table->lookup(key, entry);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD,
                "%s:%d: GID:0x%x: table lookup failed for slice:%d :%s",
                __func__,
                __LINE__,
                m_gid,
                slice,
                la_status2str(status).c_str());
        return status;
    }

    npl_mc_em_db_value_t value(entry->value());
    if (is_0) {
        value.payloads.mc_em_db_result.rx.result_0.mc_copy_id.value = NPL_INVALID_MC_COPY_ID;
    } else {
        value.payloads.mc_em_db_result.rx.result_1.mc_copy_id.value = NPL_INVALID_MC_COPY_ID;
    }

    if ((value.payloads.mc_em_db_result.rx.result_0.mc_copy_id.value == NPL_INVALID_MC_COPY_ID)
        && (value.payloads.mc_em_db_result.rx.result_1.mc_copy_id.value == NPL_INVALID_MC_COPY_ID)) {
        status = table->erase(entry->key());
        return_on_error(status);
    } else {
        status = entry->update(value);
        return_on_error(status);
    }
    status = m_device->flush_mcid_cache(slice);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
