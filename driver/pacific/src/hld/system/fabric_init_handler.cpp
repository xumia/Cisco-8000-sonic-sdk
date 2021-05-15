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

#include <array>

#include "api/tm/la_output_queue_scheduler.h"
#include "api/types/la_tm_types.h"
#include "cgm/la_voq_cgm_profile_impl.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/math_utils.h"
#include "fabric_init_handler.h"
#include "hld_utils.h"
#include "lld/ll_device.h"
#include "lld/lld_utils.h"
#include "lld/pacific_mem_structs.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"
#include "nplapi/npl_constants.h"
#include "nplapi/npl_enums.h"
#include "system/la_device_impl.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/tm_utils.h"

namespace silicon_one
{

constexpr uint64_t fabric_init_handler::MS_VOQ_CGM_PROFILES[];

fabric_init_handler::fabric_init_handler(const la_device_impl_wptr& device) : m_device(device), m_mc_voq_set(nullptr)
{
}

fabric_init_handler::~fabric_init_handler()
{
}

la_status
fabric_init_handler::configure_phase_topology_pre_soft_reset()
{
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;

    status = configure_ms_voqs();
    return_on_error(status);

    status = configure_csms();
    return_on_error(status);

    status = configure_mc_voqs();
    return_on_error(status);

    status = configure_pre_soft_reset_pdvoq();
    return_on_error(status);

    status = configure_pdoq();
    return_on_error(status);

    status = configure_rx_cgm();
    return_on_error(status);

    status = configure_pre_soft_reorder_block();
    return_on_error(status);

    status = configure_filb();
    return_on_error(status);

    status = configure_sch();
    return_on_error(status);

    status = configure_tx_cgm();
    return_on_error(status);

    status = configure_tx_pdr();
    return_on_error(status);

    status = configure_mc_bitmap_base_voq_lookup_table();
    return_on_error(status);

    status = configure_scmid_to_mcid_table_default();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_phase_topology_dynamic_memories()
{
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;

    status = configure_dynamic_memories_reorder_block();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_phase_topology_post_soft_reset()
{
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;

    status = configure_ics();
    return_on_error(status);

    status = configure_post_soft_reset_pdvoq();
    return_on_error(status);

    status = configure_post_soft_dmc_frm();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_ms_voqs()
{
    la_status status;
    // Configure all VOQ CGM profiles on fabric slices to drop.
    // The specific drop configuration is such that aligns with the HW init config
    status = configure_drop_voq_cgm_profiles();
    return_on_error(status);

    // Configure VOQ CGM profiles for MS-VOQs
    status = configure_ms_voq_cgm_profiles();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_drop_voq_cgm_profiles()
{
    la_status status;
    // Iterate over all VOQ CGM profiles
    for (size_t vog_cgm_profile_id = 0; vog_cgm_profile_id < la_device_impl::NUM_VOQ_CGM_PROFILES_PER_DEVICE;
         vog_cgm_profile_id++) {
        status = configure_drop_voq_cgm_profile_buffers_consumption_lut_for_enq(vog_cgm_profile_id);
        return_on_error(status);

        status = configure_drop_voq_cgm_profile_buff_region_thresholds(vog_cgm_profile_id);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_drop_voq_cgm_profile_buffers_consumption_lut_for_enq(size_t vog_cgm_profile_id)
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_buffers_consumption_lut_for_enq_table);

    // Prepare arguments
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::key_type k;
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::value_type v;

    v.action = NPL_VOQ_CGM_SLICE_BUFFERS_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE;

    uint64_t drop_all_bits
        = BITS_SIZEOF(v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_g.drop_green.drop_color[0], value);
    uint64_t drop_all = bit_utils::ones(drop_all_bits);

    // width of v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_X.drop_XXX.drop_color
    constexpr size_t values_per_line
        = array_size(v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_g.drop_green.drop_color);
    static_assert(values_per_line
                      == array_size(v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_y.drop_yellow.drop_color),
                  "Number of age regions mismatch between drop_green and drop_yellow fields.");
    static_assert(values_per_line == array_size(v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.evict_to_dram),
                  "Number of age regions mismatch between drop_green and evict_to_dram fields.");
    static_assert(values_per_line == array_size(v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.congestion_mark),
                  "Number of age regions mismatch between drop_green and congestion_mark fields.");

    for (size_t sms_age_region = 0; sms_age_region < values_per_line; sms_age_region++) {
        v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_g.drop_green.drop_color[sms_age_region].value
            = drop_all;
        v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_y.drop_yellow.drop_color[sms_age_region].value
            = drop_all;
        v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.evict_to_dram[sms_age_region].value = 0;   // Don't evict
        v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.congestion_mark[sms_age_region].value = 0; // Don't mark
    }

    size_t pool_size_bits = BITS_SIZEOF(k, buffer_pool_available_level);
    size_t voq_size_bits = BITS_SIZEOF(k, buffer_voq_size_level);
    size_t free_dram_cntx_bits = BITS_SIZEOF(k, free_dram_cntx);

    // Iterate over all possible LUT-table keys
    k.profile_id.value = vog_cgm_profile_id;
    for (uint64_t voq_size_level = 0; voq_size_level < 1u << voq_size_bits; voq_size_level++) {
        for (uint64_t pool_size_level = 0; pool_size_level < 1u << pool_size_bits; pool_size_level++) {
            for (uint64_t free_dram_cntx = 0; free_dram_cntx < 1u << free_dram_cntx_bits; free_dram_cntx++) {
                k.buffer_voq_size_level = voq_size_level;
                k.buffer_pool_available_level = pool_size_level;
                k.free_dram_cntx = free_dram_cntx;
                la_status write_status
                    = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
                return_on_error(write_status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_scmid_to_mcid_table_default()
{
    if (m_device->m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        return LA_STATUS_SUCCESS;
    }

    for (size_t mcid = 0; mcid < la_device_impl::MAX_MC_GROUP_GID; mcid += NPL_MULTICAST_NUM_MCIDS_PER_ENTRY) {
        for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
            const auto& table(m_device->m_tables.fe_smcid_to_mcid_table[slice_pair]);
            npl_fe_smcid_to_mcid_table_t::key_type key;
            npl_fe_smcid_to_mcid_table_t::value_type value;
            npl_fe_smcid_to_mcid_table_t::entry_pointer_type entry_ptr = nullptr;

            key.system_mcid_17_3 = bit_utils::get_bits(mcid, 17 /*msb*/, 3 /*lsb*/);
            for (int i = 0; i < NPL_MULTICAST_NUM_MCIDS_PER_ENTRY; i++) {
                value.payloads.mcid_array.mcid[i].id = NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE;
            }

            la_status status = table->insert(key, value, entry_ptr);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_drop_voq_cgm_profile_buff_region_thresholds(size_t vog_cgm_profile_id)
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_buff_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_t::value_type v;

    // The value is assumed to be initialized to zero
    v.action = NPL_VOQ_CGM_SLICE_PROFILE_BUFF_REGION_THRESHOLDS_TABLE_ACTION_WRITE;

    // Write
    k.profile_id.value = vog_cgm_profile_id;
    la_status write_status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
    return_on_error(write_status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_ms_voq_cgm_profiles()
{
    la_status status;

    status = configure_ms_voq_cgm_profile_buff_region_thresholds();
    return_on_error(status);

    status = configure_ms_voq_cgm_profile_pkt_enq_time_region_thresholds();
    return_on_error(status);

    status = configure_ms_voq_cgm_profile_pkt_region_thresholds();
    return_on_error(status);

    status = configure_ms_voq_cgm_profile_buffers_consumption_lut_for_enq();
    return_on_error(status);

    status = configure_ms_voq_cgm_profile_pd_consumption_lut_for_enq();
    return_on_error(status);

    status = configure_ms_voq_cgm_profile_dram_cgm_profile();
    return_on_error(status);

    status = configure_ms_voq_cgm_profile_slice_cgm_profile();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_ms_voq_cgm_profile_buff_region_thresholds()
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_buff_region_thresholds_table);

    la_status write_status;

    // Prepare arguments
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_t::value_type v;

    auto& q_size_buff_region(v.payloads.voq_cgm_slice_profile_buff_region_thresholds_results.q_size_buff_region);

    static constexpr uint64_t NUM_Q_SIZE_BUFF_REGIONS
        = array_size(v.payloads.voq_cgm_slice_profile_buff_region_thresholds_results.q_size_buff_region);
    std::array<size_t, NUM_Q_SIZE_BUFF_REGIONS> uch_buff_region_thresholds;
    std::array<size_t, NUM_Q_SIZE_BUFF_REGIONS> ucl_buff_region_thresholds;
    std::array<size_t, NUM_Q_SIZE_BUFF_REGIONS> mc_buff_region_thresholds;

    if (m_device->m_pfc_tuning_enabled) {
        if (m_device->m_device_mode == device_mode_e::LINECARD) {
            uch_buff_region_thresholds = {{1, 2, 3, 4, 5, 6, 16000}};
            ucl_buff_region_thresholds = {{1, 2, 3, 4, 5, 6, 16000}};
            mc_buff_region_thresholds = {{1, 2, 3, 4, 5, 6, 200}};
        } else {
            // FE
            uch_buff_region_thresholds = {{1, 2, 3, 4, 5, 6, 16000}};
            ucl_buff_region_thresholds = {{1, 2, 3, 4, 5, 6, 16000}};
            mc_buff_region_thresholds = {{1, 2, 3, 4, 5, 6, 400}};
        }
    } else {
        if (m_device->m_device_mode == device_mode_e::LINECARD) {
            uch_buff_region_thresholds = {{1, 2, 3, 4, 5, 6, 1000}};
            ucl_buff_region_thresholds = {{1, 2, 3, 4, 5, 6, 1000}};
            mc_buff_region_thresholds = {{1, 2, 3, 4, 5, 6, 200}};
        } else {
            // FE
            uch_buff_region_thresholds = {{1, 2, 3, 4, 5, 6, 1000}};
            ucl_buff_region_thresholds = {{1, 2, 3, 4, 5, 6, 1000}};
            mc_buff_region_thresholds = {{1, 2, 3, 4, 5, 6, 400}};
        }
    }

    v.action = NPL_VOQ_CGM_SLICE_PROFILE_BUFF_REGION_THRESHOLDS_TABLE_ACTION_WRITE;

    // Write UCH
    k.profile_id.value = MS_VOQ_UCH_CGM_PROFILE_INDEX;

    for (size_t i = 0; i < array_size(q_size_buff_region); i++) {
        q_size_buff_region[i].value = uch_buff_region_thresholds[i];
    };

    write_status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
    return_on_error(write_status);

    // Write UCL
    k.profile_id.value = MS_VOQ_UCL_CGM_PROFILE_INDEX;

    for (size_t i = 0; i < array_size(q_size_buff_region); i++) {
        q_size_buff_region[i].value = ucl_buff_region_thresholds[i];
    };

    write_status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
    return_on_error(write_status);

    // Write MC
    k.profile_id.value = MS_VOQ_MC_CGM_PROFILE_INDEX;

    for (size_t i = 0; i < array_size(q_size_buff_region); i++) {
        q_size_buff_region[i].value = mc_buff_region_thresholds[i];
    };

    write_status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
    return_on_error(write_status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_ms_voq_cgm_profile_pkt_enq_time_region_thresholds()
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_t::value_type v;

    auto& pkt_enq_time_region(v.payloads.voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results.pkt_enq_time_region);
    for (size_t i = 0; i < array_size(pkt_enq_time_region); i++) {
        pkt_enq_time_region[i].value = bit_utils::get_lsb_mask(la_voq_cgm_profile_impl::TIME_REGION_WIDTH);
    };

    v.action = NPL_VOQ_CGM_SLICE_PROFILE_PKT_ENQ_TIME_REGION_THRESHOLDS_TABLE_ACTION_WRITE;

    // Write
    for (auto voq_cgm_profile_id : MS_VOQ_CGM_PROFILES) {
        k.profile_id.value = voq_cgm_profile_id;
        la_status write_status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
        return_on_error(write_status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_ms_voq_cgm_profile_pkt_region_thresholds()
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_pkt_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_t::value_type v;

    auto& q_size_pkt_region(v.payloads.voq_cgm_slice_profile_pkt_region_thresholds_results.q_size_pkt_region);
    q_size_pkt_region[0].value = 10600;
    q_size_pkt_region[1].value = 11600;
    q_size_pkt_region[2].value = 12600;
    q_size_pkt_region[3].value = 13600;
    q_size_pkt_region[4].value = 14000;
    q_size_pkt_region[5].value = 15000;
    q_size_pkt_region[6].value = 15600;

    v.action = NPL_VOQ_CGM_SLICE_PROFILE_PKT_REGION_THRESHOLDS_TABLE_ACTION_WRITE;

    // Write
    for (auto voq_cgm_profile_id : MS_VOQ_CGM_PROFILES) {
        k.profile_id.value = voq_cgm_profile_id;
        la_status write_status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
        return_on_error(write_status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_ms_voq_cgm_profile_buffers_consumption_lut_for_enq()
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_buffers_consumption_lut_for_enq_table);

    // Prepare arguments
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::key_type k;
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::value_type v;

    // The value is assumed to be initialized to zero
    v.action = NPL_VOQ_CGM_SLICE_BUFFERS_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE;

    size_t pool_size_bits = BITS_SIZEOF(k, buffer_pool_available_level);
    size_t voq_size_bits = BITS_SIZEOF(k, buffer_voq_size_level);
    size_t free_dram_cntx_bits = BITS_SIZEOF(k, free_dram_cntx);

    uint64_t drop_all_bits
        = BITS_SIZEOF(v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_g.drop_green.drop_color[0], value);
    uint64_t drop_all = bit_utils::ones(drop_all_bits);

    // Iterate over all possible LUT-table keys
    for (uint64_t voq_size_level = 0; voq_size_level < 1u << voq_size_bits; voq_size_level++) {
        for (uint64_t pool_size_level = 0; pool_size_level < 1u << pool_size_bits; pool_size_level++) {
            for (uint64_t free_dram_cntx = 0; free_dram_cntx < 1u << free_dram_cntx_bits; free_dram_cntx++) {
                k.buffer_voq_size_level = voq_size_level;
                k.buffer_pool_available_level = pool_size_level;
                k.free_dram_cntx = free_dram_cntx;
                // In the last threshold fill level set to drop traffic
                uint64_t drop;
                if (k.buffer_voq_size_level == (1u << voq_size_bits) - 1) {
                    drop = drop_all;
                } else {
                    drop = 0;
                }

                for (size_t sms_age_region = 0;
                     sms_age_region
                     < array_size(v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_g.drop_green.drop_color);
                     sms_age_region++) {
                    v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_g.drop_green.drop_color[sms_age_region]
                        .value
                        = drop;
                }

                for (size_t sms_age_region = 0;
                     sms_age_region
                     < array_size(v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_y.drop_yellow.drop_color);
                     sms_age_region++) {
                    v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_y.drop_yellow.drop_color[sms_age_region]
                        .value
                        = drop;
                }

                for (auto voq_cgm_profile_id : MS_VOQ_CGM_PROFILES) {
                    k.profile_id.value = voq_cgm_profile_id;
                    la_status write_status
                        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
                    return_on_error(write_status);
                }
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_ms_voq_cgm_profile_pd_consumption_lut_for_enq()
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_pd_consumption_lut_for_enq_table);

    // Prepare arguments
    npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_t::key_type k;
    npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_t::value_type v;

    size_t NUM_OF_KEYS = 1 << 5;

    v.action = NPL_VOQ_CGM_SLICE_PD_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE;

    // Iterate over all possible LUT-table keys
    for (size_t i = 0; i < NUM_OF_KEYS; i++) {
        k.pd_pool_available_level = bit_utils::get_bits(i, 1 /*msb*/, 0 /*lsb*/);
        k.pd_voq_fill_level = bit_utils::get_bits(i, 4 /*msb*/, 2 /*lsb*/);

        // In the last threshold fill level set to drop traffic
        uint64_t drop;
        if (k.pd_voq_fill_level == bit_utils::get_lsb_mask(3)) { // 3 = width in bits of PD_VOQ_FILL_LEVEL.
            drop = 1;
        } else {
            drop = 0;
        }

        for (size_t sms_age_region = 0;
             sms_age_region < array_size(v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.drop_g.drop_green.drop_color);
             sms_age_region++) {
            v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.drop_g.drop_green.drop_color[sms_age_region].value = drop;
        }

        for (size_t sms_age_region = 0;
             sms_age_region < array_size(v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.drop_y.drop_yellow.drop_color);
             sms_age_region++) {
            v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.drop_y.drop_yellow.drop_color[sms_age_region].value = drop;
        }

        for (auto voq_cgm_profile_id : MS_VOQ_CGM_PROFILES) {
            k.profile_id.value = voq_cgm_profile_id;
            la_status write_status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
            return_on_error(write_status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_ms_voq_cgm_profile_dram_cgm_profile()
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_dram_cgm_profile_table);

    // Prepare arguments
    npl_voq_cgm_slice_dram_cgm_profile_table_t::key_type k;
    npl_voq_cgm_slice_dram_cgm_profile_table_t::value_type v;

    v.action = NPL_VOQ_CGM_SLICE_DRAM_CGM_PROFILE_TABLE_ACTION_WRITE;
    // The value is assumed to be initialized to zero

    for (auto voq_cgm_profile_id : MS_VOQ_CGM_PROFILES) {
        k.profile_id.value = voq_cgm_profile_id;
        la_status write_status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
        return_on_error(write_status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_ms_voq_cgm_profile_slice_cgm_profile()
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_slice_cgm_profile_table);
    la_status write_status;

    // Prepare arguments
    npl_voq_cgm_slice_slice_cgm_profile_table_t::key_type k;
    npl_voq_cgm_slice_slice_cgm_profile_table_t::value_type v;

    v.action = NPL_VOQ_CGM_SLICE_SLICE_CGM_PROFILE_TABLE_ACTION_WRITE;

    k.profile_id.value = MS_VOQ_UCH_CGM_PROFILE_INDEX;
    v.payloads.voq_cgm_slice_slice_cgm_profile_result.counter_id = NPL_VOQ_CGM_PD_COUNTER_MS_UC;
    write_status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
    return_on_error(write_status);

    k.profile_id.value = MS_VOQ_UCL_CGM_PROFILE_INDEX;
    v.payloads.voq_cgm_slice_slice_cgm_profile_result.counter_id = NPL_VOQ_CGM_PD_COUNTER_MS_UC;
    write_status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
    return_on_error(write_status);

    k.profile_id.value = MS_VOQ_MC_CGM_PROFILE_INDEX;
    v.payloads.voq_cgm_slice_slice_cgm_profile_result.counter_id = NPL_VOQ_CGM_PD_COUNTER_MS_MC;
    write_status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
    return_on_error(write_status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_mc_voqs()
{
    if (m_device->m_device_mode != device_mode_e::LINECARD) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;
    status = attach_mc_voqs_to_fabric_schedulers();
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::create_fabric_mc_voq_set(la_voq_set_wptr& voq_set)
{
    if (m_device->m_device_mode != device_mode_e::LINECARD) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;
    m_base_mc_vsc_vec = la_vsc_gid_vec_t(ASIC_MAX_SLICES_PER_DEVICE_NUM, LA_VSC_GID_INVALID);
    for (la_slice_id_t slice : m_device->get_used_slices()) {
        if (m_device->m_slice_mode[slice] == la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }
        // configure VSC range for sending to all network slices
        m_base_mc_vsc_vec[slice] = LC_NETWORK_VSC_RANGE_START + (slice * NATIVE_VOQ_SET_SIZE);
    }

    // create VOQs for the network slices
    for (la_slice_id_t slice : m_device->get_used_slices()) {
        if (!m_device->is_network_slice(slice)) {
            continue;
        }
        la_voq_set_wptr voq;

        la_voq_gid_t base_voq_id = la_device_impl::BASE_LC_NETWORK_MC_VOQ + NATIVE_VOQ_SET_SIZE * slice;
        status = m_device->do_create_voq_set(base_voq_id,
                                             la_device_impl::NUM_LC_NETWORK_MC_VOQS,
                                             m_base_mc_vsc_vec,
                                             m_device->get_id(),
                                             slice,
                                             0 /* dest_ifg */,
                                             voq);
        return_on_error(status);

        m_device->configure_network_static_mc_voq(slice, voq);
        return_on_error(status);

        m_device->m_is_builtin_objects[voq->oid()] = true;
    }

    // In fabric MC, the credit request is received by CSMC which load-balances the request by sending them to random fabric
    // scheduler. Design team required to set the destination to ifg 4/0.
    status = m_device->do_create_voq_set(la_device_impl::BASE_LC_FABRIC_MC_VOQ,
                                         la_device_impl::NUM_LC_FABRIC_MC_VOQS,
                                         m_base_mc_vsc_vec,
                                         m_device->get_id(),
                                         4,
                                         0,
                                         voq_set);
    return_on_error(status);

    m_mc_voq_set = voq_set;
    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::attach_mc_voqs_to_fabric_schedulers()
{
    if (m_mc_voq_set == nullptr) {
        return LA_STATUS_EUNKNOWN;
    }

    la_status status;

    for (size_t rx_nw_slice : m_device->get_used_slices()) {
        if (!m_device->is_network_slice(rx_nw_slice)) {
            continue;
        }

        for (size_t tx_fab_slice : m_device->get_used_slices()) {
            la_voq_gid_t base_voq_id;
            // select the base VOQ based on the slice
            if (m_device->is_network_slice(tx_fab_slice)) {
                base_voq_id = la_device_impl::BASE_LC_NETWORK_MC_VOQ + NATIVE_VOQ_SET_SIZE * tx_fab_slice;
            } else {
                base_voq_id = la_device_impl::BASE_LC_FABRIC_MC_VOQ;
            }
            for (size_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
                la_ifg_scheduler* ifg_sch = nullptr;
                la_output_queue_scheduler* txpdr_lp_oqcs = nullptr;
                la_output_queue_scheduler* txpdr_hp_oqcs = nullptr;
                la_vsc_gid_t base_vsc = m_base_mc_vsc_vec[rx_nw_slice];

                status = m_device->get_ifg_scheduler(tx_fab_slice, ifg, ifg_sch);
                return_on_error(status);

                status = ifg_sch->get_txpdr_hp_oqcs(txpdr_hp_oqcs);
                return_on_error(status);

                status = ifg_sch->get_txpdr_lp_oqcs(txpdr_lp_oqcs);
                return_on_error(status);

                la_output_queue_scheduler_impl* txpdr_hp_oqcs_impl = static_cast<la_output_queue_scheduler_impl*>(txpdr_hp_oqcs);
                la_output_queue_scheduler_impl* txpdr_lp_oqcs_impl = static_cast<la_output_queue_scheduler_impl*>(txpdr_lp_oqcs);

                la_output_queue_scheduler_impl* oq_sch_impl;
                for (la_voq_gid_t voq_offset = 0; voq_offset <= la_device_impl::NUM_LC_FABRIC_MC_VOQS; voq_offset++) {
                    if (voq_offset < la_device_impl::FIRST_HIGH_PRIORITY_MC_VOQ_OFFSET) {
                        oq_sch_impl = txpdr_lp_oqcs_impl;
                    } else {
                        oq_sch_impl = txpdr_hp_oqcs_impl;
                    }
                    status = oq_sch_impl->do_attach_vsc(base_vsc + voq_offset,
                                                        la_oq_vsc_mapping_e::RR1_RR3,
                                                        m_device->get_id(),
                                                        rx_nw_slice,
                                                        base_voq_id + voq_offset);
                    return_on_error(status);
                }
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_csms()
{
    lld_register_value_list_t reg_val_list;
    la_status status;

    // Set the VSC range for the fabric VOQs
    csms_fmc_req_dup_reg_register fmc_req_dup_reg;
    fmc_req_dup_reg.fields.fmc_min_vsc_range = FABRIC_MC_VSC_RANGE_START;
    fmc_req_dup_reg.fields.fmc_max_vsc_range = FABRIC_MC_VSC_RANGE_END;

    // this is a bitmap to fabric slices' IFGs - 6 bits.
    size_t fmc_dup_bitmap = 0;
    for (la_slice_id_t sid : get_slices(m_device, la_slice_mode_e::CARRIER_FABRIC)) {
        size_t offset = (sid - FIRST_POSSIBLE_FABRIC_SLICE_IN_LC) * NUM_IFGS_PER_SLICE;
        // Set 1's in the bits that belong to IFGs of slice sid.
        for (size_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            bit_utils::set_bit(&fmc_dup_bitmap, offset + ifg, 1);
        }
    }

    fmc_req_dup_reg.fields.fmc_dup_bitmap = fmc_dup_bitmap;
    reg_val_list.push_back({m_device->m_pacific_tree->csms->fmc_req_dup_reg, fmc_req_dup_reg});

    // Override the SA MC VSC range, set to the linecard VSC range
    csms_txrq_req_dup_reg_register reg;
    reg.fields.txrq_min_vsc_range = LC_NETWORK_VSC_RANGE_START;
    reg.fields.txrq_max_vsc_range = LC_NETWORK_VSC_RANGE_END;
    for (size_t i = 0; i < m_device->m_pacific_tree->csms->txrq_req_dup_reg->size(); i++) {
        reg_val_list.push_back({(*m_device->m_pacific_tree->csms->txrq_req_dup_reg)[i], reg});
    }

    // packing_control_reg
    csms_packing_control_reg_register packing_control_reg;
    status = m_device->m_ll_device->read_register(*m_device->m_pacific_tree->csms->packing_control_reg, packing_control_reg);
    return_on_error(status);

    packing_control_reg.fields.packing_watchdog_timer_thr = 1;
    reg_val_list.push_back({m_device->m_pacific_tree->csms->packing_control_reg, packing_control_reg});

    status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return status;
}

la_status
fabric_init_handler::configure_ics()
{
    la_status status;

    // Configure the MS VOQs
    status = configure_ics_ms_voq();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_ics_ms_voq()
{
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    lld_memory_line_value_list_t mem_line_val_list;

    // Iterate over RX slices
    for (size_t i = 0; i < array_size(m_device->m_pacific_tree->slice); i++) {
        if (m_device->m_slice_mode[i] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }

        auto& tree_slice(m_device->m_pacific_tree->slice[i]);

        // Create a one-2-one mapping of SMS-VOQ context to MS-VOQs
        for (size_t msvoq_num = 0; msvoq_num < MAX_NUM_OF_MSVOQS_PER_SLICE; msvoq_num++) {
            mem_line_val_list.push_back({{tree_slice->ics->context2voq, msvoq_num}, msvoq_num});
        }

        // For each VOQ-SMS contexts of MS-VOQs, set the fabric context and the VOQ CGM profile
        for (npl_cs_fabric_context_e cs_fabric_context = (npl_cs_fabric_context_e)0;
             cs_fabric_context <= NPL_CS_FABRIC_CONTEXT_PLB_MC;
             cs_fabric_context = (npl_cs_fabric_context_e)(cs_fabric_context + 1)) {
            for (size_t msvoq_num_in_fab_context = 0; msvoq_num_in_fab_context < MAX_NUM_OF_MSVOQS_PER_FABRIC_CONTEXT_PER_SLICE;
                 msvoq_num_in_fab_context++) {

                size_t msvoq_num
                    = msvoq_num_in_fab_context + to_utype(cs_fabric_context) * MAX_NUM_OF_MSVOQS_PER_FABRIC_CONTEXT_PER_SLICE;

                // Set the fabric context for a SMS-VOQ contexts of MS-VOQs.
                // - 0..114     => UC_H
                // - 114..227   => UC_L
                // - 228..341   => MC
                mem_line_val_list.push_back({{tree_slice->ics->queue_list, msvoq_num}, cs_fabric_context});

                // Assign a VOQ CGM to a SMS-VOQ contexts of MS-VOQ. This is a dynamic memory - for regular VOQs this is a cache
                // populated by the HW when assigning a context to a VOQ.
                // For MS-VOQs the SMS-VOQ context is hard-assigned, so need to prepare the cache as well.
                // - 0..114   (UC_H) => MS_VOQ_UC_CGM_PROFILE_INDEX
                // - 114..227 (UC_L) => MS_VOQ_UC_CGM_PROFILE_INDEX
                // - 228..341 (MC)   => MS_VOQ_MC_CGM_PROFILE_INDEX
                size_t voq_cgm_profile_index = get_voq_cgm_index_for_cs_fabric_context(cs_fabric_context);

                mem_line_val_list.push_back({{tree_slice->ics->queue_profile, msvoq_num}, voq_cgm_profile_index});
            }
        }
    }

    la_status status = lld_write_memory_line_list(m_device->m_ll_device, mem_line_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_pre_soft_reset_pdvoq()
{
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    // Pacific tree writes
    lld_memory_line_value_list_t mem_line_val_list;
    la_status status;

    // Iterate over RX slices
    for (size_t i = 0; i < array_size(m_device->m_pacific_tree->slice); i++) {
        if (m_device->m_slice_mode[i] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }

        auto& tree_slice(m_device->m_pacific_tree->slice[i]);

        lld_memory_scptr static_mapping = nullptr;

        if (i < LAST_NETWORK_TYPE_SLICE) {
            static_mapping = tree_slice->pdvoq->static_mapping;
        } else {
            static_mapping = tree_slice->fabric_pdvoq->static_mapping;
        }

        status = prepare_pdvoq_static_mapping(mem_line_val_list, static_mapping);
        return_on_error(status);
    }

    status = lld_write_memory_line_list(m_device->m_ll_device, mem_line_val_list);
    return_on_error(status);

    // NPL table writes
    status = configure_pdvoq_voq_properties();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pdvoq_static_mapping(lld_memory_line_value_list_t& mem_line_val_list, lld_memory_scptr static_mapping)
{
    // Indicate that the SMS-VOQ contexts for MS-VOQs are static.
    // Setting a '1' at the index corresponding to the the MS-VOQ SMS context number, at the static_mapping table, indicates a
    // static SMS-VOQ context.
    // Each line in static_mapping is 64 bits wide, so bit[0] of line[1] is indicates SMS-VOQ context 65.
    // The following code assumes that SMS-VOQ contexes 0 .. MAX_NUM_OF_MSVOQS_PER_SLICE-1 should be static
    size_t static_mapping_line_width = static_mapping->get_desc()->width_bits;

    size_t num_of_lines_to_write = div_round_up(MAX_NUM_OF_MSVOQS_PER_SLICE, static_mapping_line_width);
    size_t num_of_bits_to_set = MAX_NUM_OF_MSVOQS_PER_SLICE;

    for (size_t mem_line = 0; mem_line < num_of_lines_to_write; mem_line++) {
        size_t num_of_bits_to_set_in_line = std::min(num_of_bits_to_set, static_mapping_line_width);
        // Create a vector with num_of_bits_to_set_in_line LSB bits set, and the rest reset.
        bit_vector line_data
            = bit_vector::ones_range(num_of_bits_to_set_in_line - 1 /*msb*/, 0 /*lsb*/, static_mapping_line_width /*width*/);

        mem_line_val_list.push_back({{(static_mapping), mem_line}, line_data});
        num_of_bits_to_set -= static_mapping_line_width;
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_pdvoq_voq_properties()
{
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;
    status = configure_pdvoq_mc_voq_properties();
    return_on_error(status);

    status = configure_pdvoq_ms_voq_properties();
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_pdvoq_mc_voq_properties()
{
    if (m_device->m_device_mode != device_mode_e::LINECARD) {
        return LA_STATUS_SUCCESS;
    }

    const auto& tables(m_device->m_tables.pdvoq_slice_voq_properties_table);
    npl_pdvoq_slice_voq_properties_table_t::key_type k;
    npl_pdvoq_slice_voq_properties_table_t::value_type v;
    v.action = NPL_PDVOQ_SLICE_VOQ_PROPERTIES_TABLE_ACTION_WRITE;

    la_status status;
    for (size_t voq = 0; voq < la_device_impl::NUM_LC_FABRIC_MC_VOQS; voq++) {
        size_t voq_num = la_device_impl::BASE_LC_FABRIC_MC_VOQ + voq;
        k.voq_num = voq_num;
        v.payloads.pdvoq_slice_voq_properties_result.profile.value = la_device_impl::VOQ_CGM_DROP_PROFILE;
        v.payloads.pdvoq_slice_voq_properties_result.type = NPL_PDVOQ_VOQ_SCHEDULING_TYPE_PLB_MC;
        status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_pdvoq_ms_voq_properties()
{
    // For each MS-VOQs, set the VOQ CGM profile and PDVOQ scheduling type
    const auto& tables(m_device->m_tables.pdvoq_slice_voq_properties_table);
    npl_pdvoq_slice_voq_properties_table_t::key_type k;
    npl_pdvoq_slice_voq_properties_table_t::value_type v;

    v.action = NPL_PDVOQ_SLICE_VOQ_PROPERTIES_TABLE_ACTION_WRITE;

    for (npl_cs_fabric_context_e cs_fabric_context = (npl_cs_fabric_context_e)0; cs_fabric_context <= NPL_CS_FABRIC_CONTEXT_PLB_MC;
         cs_fabric_context = (npl_cs_fabric_context_e)(cs_fabric_context + 1)) {
        for (size_t msvoq_num_in_fab_context = 0; msvoq_num_in_fab_context < MAX_NUM_OF_MSVOQS_PER_FABRIC_CONTEXT_PER_SLICE;
             msvoq_num_in_fab_context++) {

            size_t msvoq_num = msvoq_num_in_fab_context + cs_fabric_context * MAX_NUM_OF_MSVOQS_PER_FABRIC_CONTEXT_PER_SLICE;

            k.voq_num = msvoq_num;
            v.payloads.pdvoq_slice_voq_properties_result.profile.value = get_voq_cgm_index_for_cs_fabric_context(cs_fabric_context);

            uint64_t msvoq_scheduling_type;
            switch (cs_fabric_context) {
            case NPL_CS_FABRIC_CONTEXT_PLB_UC_H:
                msvoq_scheduling_type = NPL_PDVOQ_VOQ_SCHEDULING_TYPE_MS_UC_H;
                break;

            case NPL_CS_FABRIC_CONTEXT_PLB_UC_L:
                msvoq_scheduling_type = NPL_PDVOQ_VOQ_SCHEDULING_TYPE_MS_UC_L;
                break;

            case NPL_CS_FABRIC_CONTEXT_PLB_MC:
                msvoq_scheduling_type = NPL_PDVOQ_VOQ_SCHEDULING_TYPE_MS_MC;
                break;

            default:
                return LA_STATUS_EUNKNOWN;
            }

            v.payloads.pdvoq_slice_voq_properties_result.type = msvoq_scheduling_type;

            la_status write_status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);
            return_on_error(write_status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_pdoq()
{
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    lld_memory_line_value_list_t mem_line_val_list;
    lld_register_value_list_t reg_val_list;
    la_status status;

    // Iterate over TX slices
    for (size_t i = 0; i < array_size(m_device->m_pacific_tree->slice); i++) {
        if (m_device->m_slice_mode[i] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }

        status = prepare_pdoq_oqg_to_link_map(mem_line_val_list, i);
        return_on_error(status);

        status = prepare_pdoq_ifse_general_configuration(reg_val_list, i);
        return_on_error(status);

        status = prepare_pdoq_tpse_oqpg_mapping_configuration(reg_val_list, i);
        return_on_error(status);

        status = prepare_pdoq_oqpg_cir_token_bucket_cfg(mem_line_val_list, i);
        return_on_error(status);

        status = prepare_pdoq_oq_pir_token_bucket_cfg(mem_line_val_list, i);
        return_on_error(status);

        status = prepare_pdoq_tpse_wfq_cfg(mem_line_val_list, i);
        return_on_error(status);
    }

    status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_line_list(m_device->m_ll_device, mem_line_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pdoq_oqg_to_link_map(lld_memory_line_value_list_t& mem_line_val_list, la_slice_id_t sid)
{
    // Maps OQ group (a set of 8 OQ) in a slice, to a fabric link number.
    // This table is used only for fabric purposes, so can configure the setting needed for LC_56_FABRIC_PORT_MODE, even when its
    // not the mode.
    // IFG0:
    //  OQG 0 => link 0
    //  ...
    //  OQG 8 => link 8
    //
    // IFG1:
    //  OQG 20 => link 9
    //  ...
    //  OQG 28 => link 17
    //
    // In LC_56_FABRIC_PORT_MODE,
    //  Slice3/IFG0:
    //      OQG 9 => link 18
    //  Slice5/IFG1:
    //      OQG 29 => link 18
    // TODO - ask AlexK why are the OQG not consecutive, and revise the constants used.
    lld_memory_scptr oqg_to_link_map = m_device->m_pacific_tree->slice[sid]->pdoq->top->oqg_to_link_map;

    size_t fabric_link_index = 0;
    for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
        size_t oqg_base = (NUM_SERDES_PER_IFG + NUM_ENHANCED_FABRIC_IFG_SERDES) * ifg;

        for (size_t oqg_offset = 0; oqg_offset < NUM_FABRIC_PORTS_IN_NORMAL_IFG; oqg_offset++) {
            size_t oqg = oqg_base + oqg_offset;
            mem_line_val_list.push_back({{(oqg_to_link_map), oqg}, fabric_link_index});
            fabric_link_index++;
        }
    }

    if (m_device->m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        return LA_STATUS_SUCCESS;
    }

    // Configure the setting needed for LC_56_FABRIC_PORT_MODE
    if ((sid == 3) || (sid == 5)) {
        la_ifg_id_t ifg = (sid == 3) ? 0 : 1;

        size_t oqg_base = (NUM_SERDES_PER_IFG + NUM_ENHANCED_FABRIC_IFG_SERDES) * ifg;
        size_t oqg = oqg_base + IFG_BORROWED_FABRIC_PORT_NUM;
        mem_line_val_list.push_back({{(oqg_to_link_map), oqg}, fabric_link_index});
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pdoq_ifse_general_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t sid)
{
    // Create a mapping of TPSE to IFC (i.e., port num within IFG - first serdes ID of the port).
    // Can configure the setting needed for LC_56_FABRIC_PORT_MODE, even when its not the mode.
    //
    // Each fabric port uses two serdeses, so this should map
    // - 0 => 0,
    // - 1 => 2,
    // ...
    // - 8 => 16,
    // and the rest to invalid (-1)
    //
    // In LC_56_FABRIC_PORT_MODE,
    //  Slice3/IFG0:
    //      9 => 19
    //  Slice5/IFG1:
    //      9 => 19

    pdoq_ifse_general_configuration_register ifgs_reg[NUM_IFGS_PER_SLICE];
    la_status status;

    for (la_ifg_id_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ifg_id++) {
        auto& ifg_reg(ifgs_reg[ifg_id]);

        status = m_device->m_ll_device->read_register(
            *(*m_device->m_pacific_tree->slice[sid]->pdoq->top->ifse_general_configuration)[ifg_id], ifg_reg);
        return_on_error(status);

        for (size_t tpse = 0; tpse < NUM_FABRIC_PORTS_IN_NORMAL_IFG; tpse++) {
            ifg_reg.fields.set_tpse2ifc_map(tpse, tpse * NUM_SERDES_PER_FABRIC_PORT);
        }

        const size_t INVALID_IFC = bit_utils::get_lsb_mask(ifg_reg.fields.TPSE2IFC_MAP_WIDTH);
        for (size_t tpse = NUM_FABRIC_PORTS_IN_NORMAL_IFG; tpse < ifg_reg.fields.get_tpse2ifc_map_array_size(); tpse++) {
            ifg_reg.fields.set_tpse2ifc_map(tpse, INVALID_IFC);
        }

        if (m_device->is_borrower_ifg(sid, ifg_id)) {
            ifg_reg.fields.set_tpse2ifc_map(IFG_BORROWED_FABRIC_PORT_NUM, IFG_BORROWED_SERDES_ID);
        }

        reg_val_list.push_back({(*m_device->m_pacific_tree->slice[sid]->pdoq->top->ifse_general_configuration)[ifg_id], ifg_reg});
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pdoq_tpse_oqpg_mapping_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t sid)
{
    // Hardcode the OQ to OQPG mapping in TPSE scheduling node (in the MAS: fabric link output queueing and scheduling).
    tpse_oqpg_map_tm_port_u tpse_oqpg_map_tm_port = {.flat = 0};
    tpse_oqpg_map_tm_port.fields.oq0 = 0; // map OQ 0: 0 = OQPG 0, 4-7 = OQPG 4-7
    tpse_oqpg_map_tm_port.fields.oq1 = 4; // map OQ 1: 1 = OQPG 1, 4-7 = OQPG 4-7
    tpse_oqpg_map_tm_port.fields.oq2 = 4; // map OQ 2: 2 = OQPG 2, 4-7 = OQPG 4-7
    tpse_oqpg_map_tm_port.fields.oq3 = 5; // map OQ 3: 3 = OQPG 3, 4-7 = OQPG 4-7
    tpse_oqpg_map_tm_port.fields.oq4 = 1; // map OQ 4: 0 = OQPG 4, 1 = OQPG 5,2 = OQPG 6, 3 = OQPG 7
    tpse_oqpg_map_tm_port.fields.oq5 = 2; // map OQ 5: 1 = OQPG 5, 2 = OQPG 6,3 = OQPG 7
    tpse_oqpg_map_tm_port.fields.oq6 = 1; // map OQ 6: 0 = OQGP 6, 1 = OQPG 7
                                          // OQ 7 is always mapped to OQPG 7

    pdoq_tpse_oqpg_mapping_configuration_register normal_ifg_reg = {.u8 = {0}};
    pdoq_tpse_oqpg_mapping_configuration_register enhanced_ifg_reg; // For LC_56_FABRIC_PORT_MODE

    for (size_t tm_port = 0; tm_port < NUM_FABRIC_PORTS_IN_NORMAL_IFG; tm_port++) {
        normal_ifg_reg.fields.set_tpse_oqpg_map(tm_port, tpse_oqpg_map_tm_port.flat);
    }

    if (m_device->m_device_mode == device_mode_e::LINECARD) {
        if (sid == 3) {
            enhanced_ifg_reg = normal_ifg_reg;
            enhanced_ifg_reg.fields.set_tpse_oqpg_map(9, tpse_oqpg_map_tm_port.flat);

            reg_val_list.push_back(
                {(*m_device->m_pacific_tree->slice[sid]->pdoq->top->tpse_oqpg_mapping_configuration)[0], enhanced_ifg_reg});
            reg_val_list.push_back(
                {(*m_device->m_pacific_tree->slice[sid]->pdoq->top->tpse_oqpg_mapping_configuration)[1], normal_ifg_reg});

            return LA_STATUS_SUCCESS;
        }

        if (sid == 5) {
            enhanced_ifg_reg = normal_ifg_reg;
            enhanced_ifg_reg.fields.set_tpse_oqpg_map(9, tpse_oqpg_map_tm_port.flat);

            reg_val_list.push_back(
                {(*m_device->m_pacific_tree->slice[sid]->pdoq->top->tpse_oqpg_mapping_configuration)[0], normal_ifg_reg});
            reg_val_list.push_back(
                {(*m_device->m_pacific_tree->slice[sid]->pdoq->top->tpse_oqpg_mapping_configuration)[1], enhanced_ifg_reg});

            return LA_STATUS_SUCCESS;
        }
    }

    reg_val_list.push_back(
        {(*m_device->m_pacific_tree->slice[sid]->pdoq->top->tpse_oqpg_mapping_configuration)[0], normal_ifg_reg});
    reg_val_list.push_back(
        {(*m_device->m_pacific_tree->slice[sid]->pdoq->top->tpse_oqpg_mapping_configuration)[1], normal_ifg_reg});

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pdoq_oqpg_cir_token_bucket_cfg(lld_memory_line_value_list_t& mem_line_val_list, la_slice_id_t sid)
{
    // Disable CIR shaper
    // TODO - ask AlexK whether this should be configure for all 8oq or  only the used OQPGS: 0, 4, 5, 6,    and then what to put in
    // the rest?
    // The config be can prepared also for LC_56_FABRIC_PORT_MODE, regardless of whether its on.

    for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
        // The value is stored as a relative to IFG CIR, although effectively the minimal rate indication is constant

        // Calculate exponent and mantissa
        pdoq_oqpg_cir_token_bucket_cfg_memory token_bucket_cfg;

        // Configure minimal rate. Since this value is not going to change during runtime, there's no need to use
        // tm_utils::calc_rate_ratio.
        token_bucket_cfg.fields.oqpg_cir_rate_mantissa = 1;
        token_bucket_cfg.fields.oqpg_cir_rate_exponent = 1;
        token_bucket_cfg.fields.oqpg_cir_max_bucket_value = 0;

        size_t num_fabric_ports = m_device->num_fabric_ports_in_borrower_ifg(sid, ifg);

        for (size_t fabric_port_num = 0; fabric_port_num < num_fabric_ports; fabric_port_num++) {
            for (size_t pg = 0; pg < NUM_OF_PGS; pg++) {
                size_t mem_line = fabric_port_num * NUM_OF_PGS + pg;

                mem_line_val_list.push_back(
                    {{(*m_device->m_pacific_tree->slice[sid]->pdoq->top->oqpg_cir_token_bucket_cfg)[ifg], mem_line},
                     token_bucket_cfg}); // TODO - value differs from dump 0x641
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pdoq_oq_pir_token_bucket_cfg(lld_memory_line_value_list_t& mem_line_val_list, la_slice_id_t sid)
{
    // Set to "110%" of the port rate
    // TODO - ask AlexK whether this should be configure for all 8oq or  only the used OQPGS: 0, 4, 5, 6,    and then what to put in
    // the rest?
    // The config be can prepared also for LC_56_FABRIC_PORT_MODE, regardless of whether its on.

    const la_rate_t rate = 110ULL * UNITS_IN_GIGA;

    for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
        // The value is stored as a relative to IFG PIR. Its assumed that the IFG is PIR mode (i.e. ifse_eir_shaper_mode ==0) and
        // has CIR==PIR.
        la_rate_t ifg_rate = 0;
        la_status stat = m_device->m_ifg_schedulers[sid][ifg]->get_transmit_cir(ifg_rate);
        return_on_error(stat);

        // Calculate exponenta and mantissa
        pdoq_oq_pir_token_bucket_cfg_memory token_bucket_cfg;
        tm_utils::token_bucket_ratio_cfg_t ratio_cfg = tm_utils::calc_rate_ratio(ifg_rate, rate);
        token_bucket_cfg.fields.oq_pir_rate_mantissa = ratio_cfg.fields.mantissa;
        token_bucket_cfg.fields.oq_pir_rate_exponent = ratio_cfg.fields.exponent;
        token_bucket_cfg.fields.oq_pir_max_bucket_value = tm_utils::DEFAULT_TRANSMIT_BUCKET_SIZE;

        size_t num_fabric_ports = m_device->num_fabric_ports_in_borrower_ifg(sid, ifg);

        for (size_t fabric_port_num = 0; fabric_port_num < num_fabric_ports; fabric_port_num++) {
            for (size_t pg = 0; pg < NUM_OF_PGS; pg++) {
                size_t mem_line = fabric_port_num * NUM_OF_PGS + pg;

                mem_line_val_list.push_back(
                    {{(*m_device->m_pacific_tree->slice[sid]->pdoq->top->oq_pir_token_bucket_cfg)[ifg], mem_line},
                     token_bucket_cfg}); // TODO - value differs from dump 0x1056
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pdoq_tpse_wfq_cfg(lld_memory_line_value_list_t& mem_line_val_list, la_slice_id_t sid)
{
    // Preset the weights of the fabric traffic contexes. The fabric keepalive time-stamps are using UCH context, so at least it
    // needs a weight.
    // The config be can prepared also for LC_56_FABRIC_PORT_MODE, regardless of whether its on.
    pdoq_tpse_wfq_cfg_memory tpse_wfq_cfg;
    la_status status;

    // Read existing weights. Assume the existing values for all entries in all IFGs, so take from IFG = 1, port = 0
    constexpr la_ifg_id_t c_ifg = 1;
    constexpr size_t c_fabric_port_num = 0;
    status = m_device->m_ll_device->read_memory(
        *(*m_device->m_pacific_tree->slice[sid]->pdoq->top->tpse_wfq_cfg)[c_ifg], c_fabric_port_num, tpse_wfq_cfg);
    return_on_error(status);

    tpse_wfq_cfg.fields.tpse_wfq_weight0 = 25; // MC
    tpse_wfq_cfg.fields.tpse_wfq_weight6 = 5;  // UCL
    tpse_wfq_cfg.fields.tpse_wfq_weight7 = 5;  // UCH

    for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
        size_t num_fabric_ports = m_device->num_fabric_ports_in_borrower_ifg(sid, ifg);

        for (size_t fabric_port_num = 0; fabric_port_num < num_fabric_ports; fabric_port_num++) {
            mem_line_val_list.push_back(
                {{(*m_device->m_pacific_tree->slice[sid]->pdoq->top->tpse_wfq_cfg)[ifg], fabric_port_num}, tpse_wfq_cfg});
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_rx_cgm()
{
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;

    for (size_t rx_slice : m_device->get_used_slices()) {
        if (m_device->m_slice_mode[rx_slice] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }

        // Disable RX CGM for fabric slices
        rx_cgm_global_configuration_register global_configuration_reg;

        status = m_device->m_ll_device->read_register(*(*m_device->m_pacific_tree->rx_cgm->global_configuration)[rx_slice],
                                                      global_configuration_reg);
        return_on_error(status);

        global_configuration_reg.fields.slice_disable_rx_cgm = 1;

        status = m_device->m_ll_device->write_register(*(*m_device->m_pacific_tree->rx_cgm->global_configuration)[rx_slice],
                                                       global_configuration_reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_pre_soft_reorder_block()
{
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    lld_register_value_list_t reg_val_list;
    la_status status;

    for (la_slice_id_t sid : m_device->get_used_slices()) {
        if (m_device->m_slice_mode[sid] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }

        if (sid < 3) {
            status = prepare_pp_reorder_em_fbm_config_reg(reg_val_list, sid);
            return_on_error(status);
        } else {
            status = prepare_nw_reorder_block_em_fbm_config_reg(reg_val_list, sid);
            return_on_error(status);
        }
    }

    status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pp_reorder_em_fbm_config_reg(lld_register_value_list_t& reg_val_list, la_slice_id_t sid)
{
    pp_reorder_slice_em_fbm_config_reg_register reg;

    reg.fields.em_fbm_working_mode = 1;
    reg.fields.em_fbm_total_free_buffers = 256;
    reg.fields.em_fbm_not_empty_entry = bit_utils::get_lsb_mask(NUM_FBM_FABRIC_SLICE_VALID_BUFFERS); // 0xf
    reg.fields.em_fbm_init = 0;
    reg.fields.em_fbm_almost_empty_thr = 8;
    reg.fields.em_fbm_drain_mode_thr = 20;
    reg.fields.em_fbm_rate_limit_thr = 30;

    lld_register_array_container& em_fbm_config_reg(*m_device->m_pacific_tree->slice[sid]->pp_reorder->em_fbm_config_reg);

    // This reg-array has 4 elements
    for (size_t i = 0; i < em_fbm_config_reg.get_desc()->instances; i++) {
        reg_val_list.push_back({em_fbm_config_reg[i], reg});
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_nw_reorder_block_em_fbm_config_reg(lld_register_value_list_t& reg_val_list, la_slice_id_t sid)
{
    nw_reorder_block_em_fbm_config_reg_register reg;

    reg.fields.em_fbm_working_mode = 1;
    reg.fields.em_fbm_total_free_buffers = 256;
    reg.fields.em_fbm_not_empty_entry = bit_utils::get_lsb_mask(NUM_FBM_FABRIC_SLICE_VALID_BUFFERS); // 0xf
    reg.fields.em_fbm_init = 0;
    reg.fields.em_fbm_almost_empty_thr = 8;
    reg.fields.em_fbm_drain_mode_thr = 20;
    reg.fields.em_fbm_rate_limit_thr = 30;

    for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
        const lld_register_array_container& em_fbm_config_reg(
            *m_device->m_pacific_tree->slice[sid]->nw_reorder_block[ifg]->em_fbm_config_reg);

        // This reg-array has 2 elements
        for (size_t i = 0; i < em_fbm_config_reg.get_desc()->instances; i++) {
            reg_val_list.push_back({em_fbm_config_reg[i], reg});
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_filb()
{
    // Relevant only in LC mode
    if (m_device->m_device_mode != device_mode_e::LINECARD) {
        return LA_STATUS_SUCCESS;
    }

    lld_register_value_list_t reg_val_list;
    lld_memory_value_list_t mem_val_list;
    la_status status;

    for (la_slice_id_t rx_slice : m_device->get_used_slices()) {
        status = prepare_filb_static_fabric_reachability(mem_val_list, rx_slice);
        return_on_error(status);

        status = prepare_filb_lfsr_cfg_reg(reg_val_list, rx_slice);
        return_on_error(status);
    }

    status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_list(m_device->m_ll_device, mem_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_filb_static_fabric_reachability(lld_memory_value_list_t& mem_val_list, la_slice_id_t rx_slice)
{
    // Relevant only for RX network slices
    if (!m_device->is_network_slice(rx_slice)) {
        return LA_STATUS_SUCCESS;
    }

    // The HW uses static_fabric_reachability as an AND mask to filter allowed ports for TX data traffic.
    filb_slice_static_fabric_reachability_memory static_fabric_reachability_entry = {.u8 = {0}};
    bit_vector staticlinks_bit_map(0, static_fabric_reachability_entry.fields.STATICLINKS_BIT_MAP_WIDTH);

    for (auto tx_slice : m_device->get_slice_id_manager()->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_FABRIC)) {
        size_t num_fabric_ports_in_slice;
        bool is_borrower_slice_en = m_device->is_borrower_slice(tx_slice);
        if (is_borrower_slice_en) {
            num_fabric_ports_in_slice = NUM_FABRIC_PORTS_IN_NORMAL_IFG + NUM_FABRIC_PORTS_IN_ENHANCED_IFG;
        } else {
            num_fabric_ports_in_slice = NUM_FABRIC_PORTS_IN_NORMAL_IFG + NUM_FABRIC_PORTS_IN_NORMAL_IFG;
        }

        la_uint64_t link_bitmask = bit_utils::ones(num_fabric_ports_in_slice);

        size_t fabric_slice_index = (tx_slice - FIRST_POSSIBLE_FABRIC_SLICE_IN_LC);
        size_t lsb = fabric_slice_index * MAX_FABRIC_PORTS_IN_SLICE;
        size_t msb = lsb + MAX_FABRIC_PORTS_IN_SLICE - 1;
        staticlinks_bit_map.set_bits(msb, lsb, link_bitmask);
    }

    static_fabric_reachability_entry.fields.staticlinks_bit_map = staticlinks_bit_map.get_value();

    const auto& static_fabric_reachability(m_device->m_pacific_tree->slice[rx_slice]->filb->static_fabric_reachability);

    // The static_fabric_reachability table has 512 entries. Actually only first MAX_DEVICES entries should be written.
    mem_val_list.push_back({static_fabric_reachability, static_fabric_reachability_entry});

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_filb_lfsr_cfg_reg(lld_register_value_list_t& reg_val_list, la_slice_id_t rx_slice)
{
    // Relevant only for RX network slices
    if (!m_device->is_network_slice(rx_slice)) {
        return LA_STATUS_SUCCESS;
    }

    filb_slice_lfsr_cfg_reg_register lfsr_cfg_reg;

    lfsr_cfg_reg.fields.base_lfsr_idx = 0; // default
    lfsr_cfg_reg.fields.num_select_replace_lfsr = 0;
    lfsr_cfg_reg.fields.randomize_link_on_local = 0; // default

    reg_val_list.push_back({m_device->m_pacific_tree->slice[rx_slice]->filb->lfsr_cfg_reg, lfsr_cfg_reg});

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_sch()
{
    // Relevant only in LC mode
    if (m_device->m_device_mode != device_mode_e::LINECARD) {
        return LA_STATUS_SUCCESS;
    }

    lld_register_value_list_t reg_val_list;
    la_status status;

    for (la_slice_id_t sid : m_device->get_used_slices()) {
        if (m_device->m_slice_mode[sid] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }

        status = prepare_sch_ifse_general_configuration(reg_val_list, sid);
        return_on_error(status);

        status = prepare_sch_tpse_general_configuration(reg_val_list, sid);
        return_on_error(status);
    }

    status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_sch_ifse_general_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t sid)
{
    static_assert((size_t)sch_ifse_general_configuration_register::SIZE_IN_BITS
                      == (size_t)sch_fab_ifse_general_configuration_register::SIZE_IN_BITS,
                  "sch_ifse_general_configuration_register SIZE_IN_BITS does not match");

    la_status status;

    lld_register_scptr ifse_general_configuration = nullptr;

    for (la_ifg_id_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ifg_id++) {
        sch_ifse_general_configuration_register ifg_reg;

        if (sid < FIRST_HW_FABRIC_SLICE) {
            ifse_general_configuration = m_device->m_pacific_tree->slice[sid]->ifg[ifg_id]->sch->ifse_general_configuration;
        } else {
            ifse_general_configuration = m_device->m_pacific_tree->slice[sid]->ifg[ifg_id]->fabric_sch->ifse_general_configuration;
        }

        status = m_device->m_ll_device->read_register(*ifse_general_configuration, ifg_reg);
        return_on_error(status);

        // Create a mapping of TPSE to IFC (i.e., port num within IFG - first serdes ID of the port).
        // Can configure the setting needed for LC_56_FABRIC_PORT_MODE, even when its not the mode.
        //
        // Each fabric port uses two serdeses, so this should map
        // - 0 => 0,
        // - 1 => 2,
        // ...
        // - 8 => 16,
        // and the rest to invalid (-1)
        //
        // In LC_56_FABRIC_PORT_MODE,
        //  Slice3/IFG0:
        //      9 => 19
        //  Slice5/IFG1:
        //      9 => 19

        for (size_t tpse = 0; tpse < NUM_FABRIC_PORTS_IN_NORMAL_IFG; tpse++) {
            ifg_reg.fields.set_tpse2ifc_map(tpse, tpse * NUM_SERDES_PER_FABRIC_PORT);
        }

        const size_t INVALID_IFC = bit_utils::ones(ifg_reg.fields.TPSE2IFC_MAP_WIDTH);
        for (size_t tpse = NUM_FABRIC_PORTS_IN_NORMAL_IFG; tpse < ifg_reg.fields.get_tpse2ifc_map_array_size(); tpse++) {
            ifg_reg.fields.set_tpse2ifc_map(tpse, INVALID_IFC);
        }

        if (m_device->is_borrower_ifg(sid, ifg_id)) {
            ifg_reg.fields.set_tpse2ifc_map(IFG_BORROWED_FABRIC_PORT_NUM, IFG_BORROWED_SERDES_ID);
        }

        if (m_device->is_network_slice(sid)) {
            // Fixes: CSCvx43722
            ifg_reg.fields.ifg_credit_generator_max_bucket = 3;
        }

        reg_val_list.push_back({ifse_general_configuration, ifg_reg});
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_sch_tpse_general_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t sid)
{
    static_assert((size_t)sch_tpse_general_configuration_register::SIZE_IN_BITS
                      == (size_t)sch_fab_tpse_general_configuration_register::SIZE_IN_BITS,
                  "sch_tpse_general_configuration_register SIZE_IN_BITS does not match");

    sch_tpse_general_configuration_register reg = {.u8 = {0}};
    reg.fields.fabric_mode = 1;

    // TODO - differs from dump .tpse_priority_propagation field is nonzero
    for (la_ifg_id_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ifg_id++) {
        if (sid < FIRST_HW_FABRIC_SLICE) {
            reg_val_list.push_back({m_device->m_pacific_tree->slice[sid]->ifg[ifg_id]->sch->tpse_general_configuration, reg});
        } else {
            reg_val_list.push_back(
                {m_device->m_pacific_tree->slice[sid]->ifg[ifg_id]->fabric_sch->tpse_general_configuration, reg});
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_tx_cgm()
{
    if (m_device->m_device_mode != device_mode_e::LINECARD) {
        return LA_STATUS_SUCCESS;
    }

    lld_register_value_list_t reg_val_list;
    la_status status;

    // Iterate over TX slices
    for (size_t sid : m_device->get_used_slices()) {
        status = prepare_tx_cgm_cgm_reject_mask(reg_val_list, sid);
        return_on_error(status);

        status = prepare_tx_cgm_fabric_link_uch_th_configuration(reg_val_list, sid);
        return_on_error(status);

        status = prepare_tx_cgm_fabric_link_ucl_th_configuration(reg_val_list, sid);
        return_on_error(status);

        status = prepare_tx_cgm_fabric_link_mc_th_configuration(reg_val_list, sid);
        return_on_error(status);
    }

    status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_tx_cgm_cgm_reject_mask(lld_register_value_list_t& reg_val_list, la_slice_id_t sid)
{
    // LC fabric slice dont look at global UC/MC indications - they are used by nwk slices only
    if (m_device->m_slice_mode[sid] != la_slice_mode_e::CARRIER_FABRIC) {
        return LA_STATUS_SUCCESS;
    }

    txcgm_cgm_reject_mask_register reg = {.u8 = {0}};

    reg.fields.global_uc_reject_mask = 1;
    reg.fields.global_mc_reject_mask = 1;

    reg_val_list.push_back({m_device->m_pacific_tree->slice[sid]->tx->cgm->cgm_reject_mask, reg});

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_tx_cgm_fabric_link_uch_th_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t sid)
{
    if (m_device->m_slice_mode[sid] != la_slice_mode_e::CARRIER_FABRIC) {
        return LA_STATUS_SUCCESS;
    }

    txcgm_fabric_link_uch_th_configuration_register uch_th_cfg;

    // System fixes: Change TX-CGM UCH fabric link FC config
    uch_th_cfg.fields.fabric_link_uch_th0 = 10 * (1024 / 256);
    uch_th_cfg.fields.fabric_link_uch_th1 = 20 * (1024 / 256);
    uch_th_cfg.fields.fabric_link_uch_th2 = 50 * (1024 / 256);
    uch_th_cfg.fields.fabric_link_uch_th_fc = 60 * (1024 / 256);

    // TODO - document the values above, and why configure only register [0] and not [1].
    reg_val_list.push_back({(*m_device->m_pacific_tree->slice[sid]->tx->cgm->fabric_link_uch_th_configuration)[0], uch_th_cfg});

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_tx_cgm_fabric_link_ucl_th_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t sid)
{
    if (m_device->m_slice_mode[sid] != la_slice_mode_e::CARRIER_FABRIC) {
        return LA_STATUS_SUCCESS;
    }

    txcgm_fabric_link_ucl_th_configuration_register ucl_th_cfg;

    ucl_th_cfg.fields.fabric_link_ucl_th0 = 10 * (1024 / 256);
    ucl_th_cfg.fields.fabric_link_ucl_th1 = 20 * (1024 / 256);
    ucl_th_cfg.fields.fabric_link_ucl_th2 = 50 * (1024 / 256);
    ucl_th_cfg.fields.fabric_link_ucl_th_fc = 60 * (1024 / 256);

    // TODO - document the values above, and why configure only register [0] and not [1].
    reg_val_list.push_back({(*m_device->m_pacific_tree->slice[sid]->tx->cgm->fabric_link_ucl_th_configuration)[0], ucl_th_cfg});

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_tx_cgm_fabric_link_mc_th_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t sid)
{
    if (m_device->m_slice_mode[sid] != la_slice_mode_e::CARRIER_FABRIC) {
        return LA_STATUS_SUCCESS;
    }

    txcgm_fabric_link_mc_th_configuration_register mc_th_cfg;

    mc_th_cfg.fields.fabric_link_mc_th0 = 10 * (1024 / 256);
    mc_th_cfg.fields.fabric_link_mc_th1 = 20 * (1024 / 256);
    mc_th_cfg.fields.fabric_link_mc_th2 = 50 * (1024 / 256);
    mc_th_cfg.fields.fabric_link_mc_th_fc = 60 * (1024 / 256);
    mc_th_cfg.fields.fabric_link_mc_th_fc_for_sch = 0x3ffff;

    reg_val_list.push_back({(*m_device->m_pacific_tree->slice[sid]->tx->cgm->fabric_link_mc_th_configuration)[0], mc_th_cfg});
    reg_val_list.push_back({(*m_device->m_pacific_tree->slice[sid]->tx->cgm->fabric_link_mc_th_configuration)[1], mc_th_cfg});

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_tx_pdr()
{
    if (m_device->m_device_mode != device_mode_e::LINECARD) {
        return LA_STATUS_SUCCESS;
    }

    lld_memory_line_value_list_t mem_line_val_list;
    la_status status;

    // Iterate over TX slices
    for (size_t sid : m_device->get_used_slices()) {
        status = prepare_tx_pdr_fabric_link_map(mem_line_val_list, sid);
        return_on_error(status);
    }

    status = lld_write_memory_line_list(m_device->m_ll_device, mem_line_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_tx_pdr_fabric_link_map(lld_memory_line_value_list_t& mem_line_val_list, la_slice_id_t sid)
{
    // TODO - for design rebustness, in NETWORK slices configure OQG = -1 in all entries.
    if (m_device->m_slice_mode[sid] != la_slice_mode_e::CARRIER_FABRIC) {
        return LA_STATUS_SUCCESS;
    }

    // Maps PD.RlbTxFabricLink to OQG that represent this link. When TSMS sends keepalives to link N, this maps what is the physical
    // OQG.
    // This table is used only for fabric purposes, so can configure the setting needed for LC_56_FABRIC_PORT_MODE, even when its
    // not the mode.
    // IFG0 ports:
    // - 0  => 0,
    // - 1  => 1,
    // ...
    // - 8  => 8,
    //
    // IFG1 ports:
    // - 9  => 20,
    // - 10 => 21,
    // ...
    // - 17 => 28,
    //
    // In LC_56_FABRIC_PORT_MODE,
    //  Slice3/IFG0:
    //      18 => 9
    //  Slice5/IFG1:
    //      18 => 29

    lld_memory_scptr fabric_link_map = m_device->m_pacific_tree->slice[sid]->tx->pdr->fabric_link_map;

    size_t fabric_link_index = 0;
    for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
        size_t oqg_base = (NUM_SERDES_PER_IFG + NUM_ENHANCED_FABRIC_IFG_SERDES) * ifg;

        for (size_t oqg_offset = 0; oqg_offset < NUM_FABRIC_PORTS_IN_NORMAL_IFG; oqg_offset++) {
            size_t oqg = oqg_base + oqg_offset;
            mem_line_val_list.push_back({{(fabric_link_map), fabric_link_index}, oqg});
            fabric_link_index++;
        }
    }

    // Configure the setting needed for LC_56_FABRIC_PORT_MODE
    if ((sid == 3) || (sid == 5)) {
        la_ifg_id_t ifg = (sid == 3) ? 0 : 1;

        size_t oqg_base = (NUM_SERDES_PER_IFG + NUM_ENHANCED_FABRIC_IFG_SERDES) * ifg;
        size_t oqg = oqg_base + IFG_BORROWED_FABRIC_PORT_NUM;
        mem_line_val_list.push_back({{(fabric_link_map), fabric_link_index}, oqg});
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_post_soft_reset_pdvoq()
{
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    lld_memory_line_value_list_t mem_line_val_list;
    lld_register_value_list_t reg_val_list;
    la_status status;

    // Iterate over RX slices
    for (size_t i = 0; i < array_size(m_device->m_pacific_tree->slice); i++) {
        if (m_device->m_slice_mode[i] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }

        auto& tree_slice(m_device->m_pacific_tree->slice[i]);

        lld_memory_scptr voq2context = nullptr;
        lld_memory_scptr voqcgm_profile = nullptr;
        lld_memory_scptr contextfbm_bmp = nullptr;
        lld_memory_scptr context_allocate_grant_set = nullptr;
        lld_memory_scptr context_allocate_set_master = nullptr;
        lld_memory_scptr context_allocate_set_slave = nullptr;
        lld_register_scptr cmap_th_reg = nullptr;

        if (i < LAST_NETWORK_TYPE_SLICE) {
            voq2context = tree_slice->pdvoq->voq2context;
            voqcgm_profile = tree_slice->pdvoq->voqcgm_profile;
            contextfbm_bmp = tree_slice->pdvoq->contextfbm_bmp;
            context_allocate_grant_set = tree_slice->pdvoq->context_allocate_grant_set;
            context_allocate_set_master = tree_slice->pdvoq->context_allocate_set_master;
            context_allocate_set_slave = tree_slice->pdvoq->context_allocate_set_slave;
            cmap_th_reg = tree_slice->pdvoq->cmap_th_reg;
            prepare_pdvoq_cmap_th_reg_network(reg_val_list, cmap_th_reg);
        } else {
            voq2context = tree_slice->fabric_pdvoq->voq2context;
            voqcgm_profile = tree_slice->fabric_pdvoq->voqcgm_profile;
            contextfbm_bmp = tree_slice->fabric_pdvoq->contextfbm_bmp;
            context_allocate_grant_set = tree_slice->fabric_pdvoq->context_allocate_grant_set;
            context_allocate_set_master = tree_slice->fabric_pdvoq->context_allocate_set_master;
            context_allocate_set_slave = tree_slice->fabric_pdvoq->context_allocate_set_slave;
            cmap_th_reg = tree_slice->fabric_pdvoq->cmap_th_reg;
            prepare_pdvoq_cmap_th_reg_fabric(reg_val_list, cmap_th_reg);
        }

        status = prepare_pdvoq_voq2context(mem_line_val_list, voq2context);
        return_on_error(status);

        status = prepare_pdvoq_voqcgm_profile(mem_line_val_list, voqcgm_profile);
        return_on_error(status);

        status = prepare_pdvoq_contextfbm_bmp(mem_line_val_list, contextfbm_bmp);
        return_on_error(status);

        status = prepare_pdvoq_context_allocate(
            mem_line_val_list, context_allocate_grant_set, context_allocate_set_master, context_allocate_set_slave);
        return_on_error(status);
    }

    status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_line_list(m_device->m_ll_device, mem_line_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pdvoq_voq2context(lld_memory_line_value_list_t& mem_line_val_list, lld_memory_scptr voq2context)
{
    // Create a one-2-one mapping of MS-VOQs to SMS-VOQ context
    for (size_t msvoq_num = 0; msvoq_num < MAX_NUM_OF_MSVOQS_PER_SLICE; msvoq_num++) {
        mem_line_val_list.push_back({{(voq2context), msvoq_num}, msvoq_num});
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pdvoq_voqcgm_profile(lld_memory_line_value_list_t& mem_line_val_list, lld_memory_scptr voqcgm_profile)
{
    // Create a mapping from SMS-VOQ context of MS-VOQs to VOQ-CGM profile
    for (npl_cs_fabric_context_e cs_fabric_context = (npl_cs_fabric_context_e)0; cs_fabric_context <= NPL_CS_FABRIC_CONTEXT_PLB_MC;
         cs_fabric_context = (npl_cs_fabric_context_e)(cs_fabric_context + 1)) {
        for (size_t msvoq_num_in_fab_context = 0; msvoq_num_in_fab_context < MAX_NUM_OF_MSVOQS_PER_FABRIC_CONTEXT_PER_SLICE;
             msvoq_num_in_fab_context++) {

            size_t msvoq_num = msvoq_num_in_fab_context + cs_fabric_context * MAX_NUM_OF_MSVOQS_PER_FABRIC_CONTEXT_PER_SLICE;
            size_t cgm_profile = get_voq_cgm_index_for_cs_fabric_context(cs_fabric_context);

            mem_line_val_list.push_back({{(voqcgm_profile), msvoq_num}, cgm_profile});
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pdvoq_contextfbm_bmp(lld_memory_line_value_list_t& mem_line_val_list, lld_memory_scptr contextfbm_bmp)
{
    // Indicate that the SMS-VOQ contexts used for for MS-VOQs can't be used for any other. By default, a SMS-VOQ context can be
    // used freely.
    // Setting a '0' indicates that the SMS-VOQ context is not free to be used, so set '0' for the ones used for MS-VOQs.
    // Each line in contextfbm_bmp is 64 bits wide, so bit[0] of line[1] indicates SMS-VOQ context 65.
    // The following code assumes that SMS-VOQ contexes 0 .. MAX_NUM_OF_MSVOQS_PER_SLICE-1 are statically assinged to MS-VOQs, and
    // that all lines of contextfbm_bmp were pre-configured to "free to be used" (1).
    size_t contextfbm_bmp_line_width = contextfbm_bmp->get_desc()->width_bits;

    size_t num_of_lines_to_write = div_round_up(MAX_NUM_OF_MSVOQS_PER_SLICE, contextfbm_bmp_line_width);
    size_t num_of_bits_to_reset = MAX_NUM_OF_MSVOQS_PER_SLICE;

    for (size_t mem_line = 0; mem_line < num_of_lines_to_write; mem_line++) {
        // Create a vector with num_of_bits_to_reset LSB bits reset, and the rest set.
        size_t num_of_lsb_bits_to_reset_in_line = std::min(num_of_bits_to_reset, contextfbm_bmp_line_width);
        bit_vector line_data = bit_vector::ones_range(
            contextfbm_bmp_line_width - 1 /*msb*/, num_of_lsb_bits_to_reset_in_line /*lsb*/, contextfbm_bmp_line_width /*width*/);

        mem_line_val_list.push_back({{(contextfbm_bmp), mem_line}, line_data});
        num_of_bits_to_reset -= contextfbm_bmp_line_width;
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pdvoq_context_allocate(lld_memory_line_value_list_t& mem_line_val_list,
                                                    lld_memory_scptr context_allocate_grant_set,
                                                    lld_memory_scptr context_allocate_set_master,
                                                    lld_memory_scptr context_allocate_set_slave)
{
    // Indicate that the MS-VOQs dont need credits. They can send a packet as soon as they get it.
    // This assumes that the line width and data of context_allocate_grant_set, context_allocate_set_master,
    // context_allocate_set_slave are the same.

    size_t grant_set_line_width = context_allocate_grant_set->get_desc()->width_bits;
    dassert_crit(grant_set_line_width == context_allocate_set_master->get_desc()->width_bits);
    dassert_crit(grant_set_line_width == context_allocate_set_slave->get_desc()->width_bits);

    size_t line_width = grant_set_line_width;

    size_t num_of_lines_to_write = div_round_up(MAX_NUM_OF_MSVOQS_PER_SLICE, line_width);
    size_t num_of_bits_to_set = MAX_NUM_OF_MSVOQS_PER_SLICE;

    for (size_t mem_line = 0; mem_line < num_of_lines_to_write; mem_line++) {
        // Create a vector with num_of_bits_to_set_in_line LSB bits set, and the rest reset.
        size_t num_of_bits_to_set_in_line = std::min(num_of_bits_to_set, line_width);
        bit_vector line_data = bit_vector::ones_range(num_of_bits_to_set_in_line - 1 /*msb*/, 0 /*lsb*/, line_width /*width*/);

        mem_line_val_list.push_back({{(context_allocate_grant_set), mem_line}, line_data});
        mem_line_val_list.push_back({{(context_allocate_set_master), mem_line}, line_data});
        mem_line_val_list.push_back({{(context_allocate_set_slave), mem_line}, line_data});
        num_of_bits_to_set -= line_width;
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pdvoq_cmap_th_reg_network(lld_register_value_list_t& reg_val_list, lld_register_scptr cmap_th_reg)
{
    pdvoq_slice_cmap_th_reg_register reg;

    reg.fields.context_pool_low_th = 1000;
    reg.fields.context_pool_ret_th = 1000;
    reg.fields.release_fifo_high_th = 1000;
    reg.fields.total_free_buf = 3753;

    // Indicate the MS-VOQs cannot be dynamically allocated. A group of 64 MS-VOQs is indicated by one bit.
    // Generally, if the group has some VOQs that can be allocated and some can't, then the whole group is indicated as "can".
    // The bitmap memory contextfbm_bmp cancels entries within a line.
    // 0 - cannot be allocated
    // 1 - can be allocated
    size_t not_empty_entry_width = reg.fields.NOT_EMPTY_ENTRY_WIDTH;
    size_t num_of_not_empty_groups
        = MAX_NUM_OF_MSVOQS_PER_SLICE
          / pdvoq_slice_contextfbm_bmp_memory::fields::CONTEXTFBM_BMPDATA_WIDTH; // The round-down division is on purpose.
    bit_vector not_empty_entry = bit_vector::ones_range(
        not_empty_entry_width - 1 /*msb*/, num_of_not_empty_groups /*lsb*/, not_empty_entry_width /*mask_width*/);
    reg.fields.not_empty_entry = not_empty_entry.get_value();

    reg_val_list.push_back({(cmap_th_reg), reg});

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pdvoq_cmap_th_reg_fabric(lld_register_value_list_t& reg_val_list, lld_register_scptr cmap_th_reg)
{
    pdvoq_slice5_cmap_th_reg_register reg;

    reg.fields.context_pool_low_th = 1000;
    reg.fields.context_pool_ret_th = 1000;
    reg.fields.release_fifo_high_th = 2000;
    reg.fields.total_free_buf = 2729;

    // Indicate the MS-VOQs cannot be dynamically allocated. A group of 64 MS-VOQs is indicated by one bit.
    // Generally, if the group has some VOQs that can be allocated and some can't, then the whole group is indicated as "can".
    // The bitmap memory contextfbm_bmp cancels entries within a line.
    // 0 - cannot be allocated
    // 1 - can be allocated
    size_t not_empty_entry_width = reg.fields.NOT_EMPTY_ENTRY_WIDTH;
    size_t num_of_not_empty_groups
        = MAX_NUM_OF_MSVOQS_PER_SLICE
          / pdvoq_slice5_contextfbm_bmp_memory::fields::CONTEXTFBM_BMPDATA_WIDTH; // The 64 == width of pdvoq->contextfbm_bmp. The
                                                                                  // round-down division is on purpose.
    bit_vector not_empty_entry = bit_vector::ones_range(
        not_empty_entry_width - 1 /*msb*/, num_of_not_empty_groups /*lsb*/, not_empty_entry_width /*mask_width*/);
    reg.fields.not_empty_entry = not_empty_entry.get_value();

    reg_val_list.push_back({(cmap_th_reg), reg});

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_dynamic_memories_reorder_block()
{
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    lld_memory_value_list_t mem_val_list;
    lld_memory_line_value_list_t mem_line_val_list;
    la_status status;

    for (la_slice_id_t sid : m_device->get_used_slices()) {
        if (m_device->m_slice_mode[sid] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }

        if (sid < 3) {
            status = prepare_pp_reorder_pp_exact_match_fbm(mem_val_list, mem_line_val_list, sid);
            return_on_error(status);
        } else {
            status = prepare_nw_reorder_block_nw_exact_match_fbm(mem_val_list, mem_line_val_list, sid);
            return_on_error(status);
        }
    }

    status = lld_write_memory_list(m_device->m_ll_device, mem_val_list);
    return_on_error(status);

    status = lld_write_memory_line_list(m_device->m_ll_device, mem_line_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_pp_reorder_pp_exact_match_fbm(lld_memory_value_list_t& mem_val_list,
                                                           lld_memory_line_value_list_t& mem_line_val_list,
                                                           la_slice_id_t sid)
{
    la_status status;
    const lld_memory_array_container& pp_exact_match_fbm(*m_device->m_pacific_tree->slice[sid]->pp_reorder->pp_exact_match_fbm);
    status = prepare_reorder_block_exact_match_fbm_entries(mem_val_list, mem_line_val_list, pp_exact_match_fbm);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_nw_reorder_block_nw_exact_match_fbm(lld_memory_value_list_t& mem_val_list,
                                                                 lld_memory_line_value_list_t& mem_line_val_list,
                                                                 la_slice_id_t sid)
{
    la_status status;
    for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
        const lld_memory_array_container& nw_exact_match_fbm(
            *m_device->m_pacific_tree->slice[sid]->nw_reorder_block[ifg]->nw_exact_match_fbm);

        status = prepare_reorder_block_exact_match_fbm_entries(mem_val_list, mem_line_val_list, nw_exact_match_fbm);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::prepare_reorder_block_exact_match_fbm_entries(lld_memory_value_list_t& mem_val_list,
                                                                   lld_memory_line_value_list_t& mem_line_val_list,
                                                                   const lld_memory_array_container& exact_match_fbm)
{
    for (size_t i = 0; i < exact_match_fbm.get_desc()->instances; i++) {
        // Set first 4 entries to all ones, and the rest to zero.
        mem_val_list.push_back({exact_match_fbm[i], 0});

        size_t exact_match_fbm_line_width = exact_match_fbm[i]->get_desc()->width_bits;
        bit_vector exact_match_fbm_entry_all_ones
            = bit_vector::ones_range(exact_match_fbm_line_width - 1 /*msb*/, 0 /*lsb*/, exact_match_fbm_line_width /*width*/);

        for (size_t mem_line = 0; mem_line < NUM_FBM_FABRIC_SLICE_VALID_BUFFERS; mem_line++) {
            mem_line_val_list.push_back({{exact_match_fbm[i], mem_line}, exact_match_fbm_entry_all_ones});
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_post_soft_dmc_frm()
{
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    lld_register_value_list_t reg_val_list;

    // This is cleared by soft-reset, so configre post soft reset.
    reg_val_list.push_back(
        {m_device->m_pacific_tree->dmc->frm->fabric_link_down_transition_reg, bit_vector::ones(NUM_FABRIC_PORTS_IN_DEVICE)});

    la_status status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
fabric_init_handler::configure_mc_bitmap_base_voq_lookup_table()
{
    // Update the VOQ lookup table
    const auto& table(m_device->m_tables.mc_bitmap_base_voq_lookup_table);
    npl_mc_bitmap_base_voq_lookup_table_key_t key;
    npl_mc_bitmap_base_voq_lookup_table_value_t value;
    npl_mc_bitmap_base_voq_lookup_table_entry_t* entry = nullptr;

    // In fabric MC, we have only one voq_set, and it is attached with FILB. So, to configure VOQ base, we need to update
    // the table only for slice 6 (5 if zero-based), similar to mc_slice_bitmap_table.
    key.rxpdr_local_vars_current_slice = 5 /*dest_slice*/;
    value.payloads.mc_bitmap_base_voq_lookup_table_result.base_voq = la_device_impl::BASE_LC_FABRIC_MC_VOQ;
    value.payloads.mc_bitmap_base_voq_lookup_table_result.tc_map_profile = la_device_impl::MC_SLICE_REPLICATION_TC_PROFILE;

    la_status status = table->set(key, value, entry);
    return_on_error(status);

    return status;
}

la_status
fabric_init_handler::set_pfc()
{
    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = configure_ms_voq_cgm_profile_buff_region_thresholds();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

size_t
fabric_init_handler::get_voq_cgm_index_for_cs_fabric_context(npl_cs_fabric_context_e cs_fabric_context)
{
    if (cs_fabric_context == NPL_CS_FABRIC_CONTEXT_PLB_UC_H) {
        return MS_VOQ_UCL_CGM_PROFILE_INDEX; // Low priority is the only relevant profile
    }

    if (cs_fabric_context == NPL_CS_FABRIC_CONTEXT_PLB_UC_L) {
        return MS_VOQ_UCL_CGM_PROFILE_INDEX;
    }

    if (cs_fabric_context == NPL_CS_FABRIC_CONTEXT_PLB_MC) {
        return MS_VOQ_MC_CGM_PROFILE_INDEX;
    }

    dassert_crit(!"Unknown credit scheduler fabric context type");
    return (0);
}
}
// namespace silicon_one
