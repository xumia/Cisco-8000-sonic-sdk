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

#include "voq_cgm_handler.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/math_utils.h"
#include "hld_utils.h"
#include "lld/gibraltar_mem_structs.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "system/la_device_impl.h"
#include <cmath>

namespace silicon_one
{

voq_cgm_handler::voq_cgm_handler(const la_device_impl_wptr& device) : m_device(device), m_sms_voqs_age_time_ns(0)
{
    // Initialize the size of m_evicted_buffers_default_behavior.
    la_uint64_t num_evicted_buffers_regions;
    m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_REGIONS, num_evicted_buffers_regions);

    la_uint64_t num_sms_total_bytes_regions;
    m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_total_bytes_regions);

    la_uint64_t num_sms_voq_bytes_regions;
    m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);

    m_evicted_buffers_default_behavior.resize(num_evicted_buffers_regions);
    for (la_quantization_region_t evicted_buffers_region = 0; evicted_buffers_region < num_evicted_buffers_regions;
         evicted_buffers_region++) {
        m_evicted_buffers_default_behavior[evicted_buffers_region].resize(num_sms_total_bytes_regions);
        for (la_quantization_region_t sms_total_bytes_region = 0; sms_total_bytes_region < num_sms_total_bytes_regions;
             sms_total_bytes_region++) {
            m_evicted_buffers_default_behavior[evicted_buffers_region][sms_total_bytes_region].resize(num_sms_voq_bytes_regions);
        }
    }

    cgm_ecn_num_levels = CGM_NUM_ECN_LEVELS;
    cgm_ecn_num_probability = CGM_NUM_ECN_PROBABILITY;
}

voq_cgm_handler::~voq_cgm_handler()
{
}

la_status
voq_cgm_handler::set_cgm_sms_voqs_age_time_granularity(la_cgm_sms_voqs_age_time_units_t sms_voqs_age_time_units)
{
    // Verify data correctness
    la_uint_t time_in_us = user_age_time_units_to_device_units(sms_voqs_age_time_units);
    if (time_in_us == 0) {
        return LA_STATUS_EINVAL;
    }

    // Save local state
    m_sms_voqs_age_time_ns = sms_voqs_age_time_units;

    // Read
    gibraltar::pdvoq_shared_mma_global_conf_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_gb_tree->pdvoq_shared_mma->global_conf, reg);
    return_on_error(read_status);

    // Modify struct
    reg.fields.enq_time_units = time_in_us - 1;

    // Write
    la_status write_status = m_device->m_ll_device->write_register(m_device->m_gb_tree->pdvoq_shared_mma->global_conf, reg);
    return write_status;

    // TODO: update VOQ profiles
}

la_status
voq_cgm_handler::get_cgm_sms_voqs_age_time_granularity(la_cgm_sms_voqs_age_time_units_t& out_sms_voqs_age_time_units) const
{
    if (m_sms_voqs_age_time_ns == 0) {
        return LA_STATUS_ENOTINITIALIZED;
    }
    out_sms_voqs_age_time_units = m_sms_voqs_age_time_ns;

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::set_cgm_sms_voqs_bytes_quantization(const la_cgm_sms_bytes_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::set_cgm_sms_voqs_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    // Verify data correctness
    la_status status = validate_quantization_thresholds(m_device,
                                                        thresholds.thresholds,
                                                        limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS,
                                                        limit_type_e::DEVICE__MAX_SMS_BYTES_QUANTIZATION_THRESHOLD);
    return_on_error(status);

    // Read
    gibraltar::rx_pdr_counters_thresholds_reg1_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_gb_tree->rx_pdr->counters_thresholds_reg1, reg);
    return_on_error(read_status);

    // Modify struct
    reg.fields.voq_cgm_counter_a_thr0 = div_round_nearest(thresholds.thresholds[0], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);
    reg.fields.voq_cgm_counter_a_thr1 = div_round_nearest(thresholds.thresholds[1], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);
    reg.fields.voq_cgm_counter_a_thr2 = div_round_nearest(thresholds.thresholds[2], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);

    // Write
    la_status write_status = m_device->m_ll_device->write_register(m_device->m_gb_tree->rx_pdr->counters_thresholds_reg1, reg);

    return write_status;
}

la_status
voq_cgm_handler::get_cgm_sms_voqs_bytes_quantization(la_cgm_sms_bytes_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::get_cgm_sms_voqs_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    // Read struct
    gibraltar::rx_pdr_counters_thresholds_reg1_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_gb_tree->rx_pdr->counters_thresholds_reg1, reg);

    return_on_error(read_status);

    la_uint64_t num_thresholds;
    la_status limit_status
        = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS, num_thresholds);
    return_on_error(limit_status);

    out_thresholds.thresholds.resize(num_thresholds);

    // Update output
    out_thresholds.thresholds[0] = reg.fields.voq_cgm_counter_a_thr0 * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;
    out_thresholds.thresholds[1] = reg.fields.voq_cgm_counter_a_thr1 * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;
    out_thresholds.thresholds[2] = reg.fields.voq_cgm_counter_a_thr2 * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::set_cgm_sms_evicted_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    // Verify data correctness
    la_status status
        = validate_quantization_thresholds(m_device,
                                           thresholds.thresholds,
                                           limit_type_e::DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_CONFIGURABLE_THRESHOLDS,
                                           limit_type_e::DEVICE__MAX_SMS_NUM_EVICTED_BUFF_QUANTIZATION_THRESHOLD);
    return_on_error(status);

    // Read
    gibraltar::ics_top_dram_global_buffer_size_cfg_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_gb_tree->ics_top->dram_global_buffer_size_cfg, reg);
    return_on_error(read_status);

    // Modify struct
    for (uint32_t index = 0; index < thresholds.thresholds.size(); index++) {
        uint64_t threshold_in_buffers = div_round_nearest(thresholds.thresholds[index], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);
        reg.fields.set_dram_global_buffer_size_th(index, threshold_in_buffers);
    }

    // Write
    la_status write_status = m_device->m_ll_device->write_register(m_device->m_gb_tree->ics_top->dram_global_buffer_size_cfg, reg);
    return write_status;
}

la_status
voq_cgm_handler::get_cgm_sms_evicted_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    // Read
    gibraltar::ics_top_dram_global_buffer_size_cfg_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_gb_tree->ics_top->dram_global_buffer_size_cfg, reg);
    return_on_error(read_status);

    la_uint64_t num_thresholds;
    la_status limit_status
        = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_CONFIGURABLE_THRESHOLDS, num_thresholds);
    return_on_error(limit_status);

    out_thresholds.thresholds.resize(num_thresholds);

    for (uint32_t index = 0; index < out_thresholds.thresholds.size(); index++) {
        uint64_t threshold_in_buffers = reg.fields.get_dram_global_buffer_size_th(index);
        out_thresholds.thresholds[index] = threshold_in_buffers * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;
    }

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::set_cgm_sms_voqs_packets_quantization(const la_cgm_sms_packets_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::set_cgm_sms_voqs_packets_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    // Verify data correctness
    la_status status = validate_quantization_thresholds(m_device,
                                                        thresholds.thresholds,
                                                        limit_type_e::DEVICE__SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS,
                                                        limit_type_e::DEVICE__MAX_SMS_PACKETS_QUANTIZATION_THRESHOLD);
    return_on_error(status);

    // Set struct
    gibraltar::pdvoq_shared_mma_cgm_pool_available_region_register reg;
    reg.fields.uc_region0 = thresholds.thresholds[0];
    reg.fields.uc_region1 = thresholds.thresholds[1];
    reg.fields.uc_region2 = thresholds.thresholds[2];

    // Write
    la_status write_status
        = m_device->m_ll_device->write_register(m_device->m_gb_tree->pdvoq_shared_mma->cgm_pool_available_region, reg);

    return write_status;
}

la_status
voq_cgm_handler::get_cgm_sms_voqs_packets_quantization(la_cgm_sms_packets_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::get_cgm_sms_voqs_packets_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    // Read
    gibraltar::pdvoq_shared_mma_cgm_pool_available_region_register reg;
    la_status read_status
        = m_device->m_ll_device->read_register(m_device->m_gb_tree->pdvoq_shared_mma->cgm_pool_available_region, reg);
    return_on_error(read_status);

    la_uint64_t num_thresholds;
    la_status limit_status
        = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS, num_thresholds);
    return_on_error(limit_status);

    out_thresholds.thresholds.resize(num_thresholds);

    // Set struct
    out_thresholds.thresholds[0] = reg.fields.uc_region0;
    out_thresholds.thresholds[1] = reg.fields.uc_region1;
    out_thresholds.thresholds[2] = reg.fields.uc_region2;

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::set_cgm_hbm_number_of_voqs_quantization(const la_cgm_hbm_number_of_voqs_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::set_cgm_hbm_number_of_voqs_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    // Verify data correctness
    la_status status = validate_quantization_thresholds(m_device,
                                                        thresholds.thresholds,
                                                        limit_type_e::DEVICE__HBM_NUM_OF_VOQS_QUANTIZATION_CONFIGURABLE_THRESHOLDS,
                                                        limit_type_e::DEVICE__MAX_HBM_NUM_OF_VOQS_QUANTIZATION_THRESHOLD);
    return_on_error(status);

    // Set struct
    // In Gibraltar, threshold is for number of free contexts in the HBM. Therefore, the complement is written to the HW.
    gibraltar::ics_top_dram_context_pool_alm_empty_register reg;
    reg.fields.dram_context_pool_alm_empty_th = HBM_CONTEXT_POOL_SIZE - thresholds.thresholds[0];

    // Write
    la_status write_status = m_device->m_ll_device->write_register(m_device->m_gb_tree->ics_top->dram_context_pool_alm_empty, reg);
    return write_status;
}

la_status
voq_cgm_handler::get_cgm_hbm_number_of_voqs_quantization(la_cgm_hbm_number_of_voqs_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::get_cgm_hbm_number_of_voqs_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    gibraltar::ics_top_dram_context_pool_alm_empty_register reg;

    // Read
    la_status status = m_device->m_ll_device->read_register(m_device->m_gb_tree->ics_top->dram_context_pool_alm_empty, reg);
    return_on_error(status);

    la_uint64_t num_thresholds;
    la_status limit_status
        = m_device->get_limit(limit_type_e::DEVICE__HBM_NUM_OF_VOQS_QUANTIZATION_CONFIGURABLE_THRESHOLDS, num_thresholds);
    return_on_error(limit_status);

    out_thresholds.thresholds.resize(num_thresholds);

    // Set struct and convert value from the complement (see set function for the explanation)
    out_thresholds.thresholds[0] = HBM_CONTEXT_POOL_SIZE - reg.fields.dram_context_pool_alm_empty_th;

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::set_hbm_pool_max_capacity(la_cgm_hbm_pool_id_t hbm_pool_id, float threshold)
{
    // Verify data correctness
    if (0 > threshold || threshold > 1) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // Verify data correctness
    la_uint64_t max_hbm_pool_id;
    la_status limit_status = m_device->get_limit(limit_type_e::DEVICE__NUM_CGM_HBM_POOLS, max_hbm_pool_id);
    return_on_error(limit_status);

    if (hbm_pool_id >= max_hbm_pool_id) {
        return LA_STATUS_EOUTOFRANGE;
    }

    gibraltar::dram_cgm_initial_config_values_register total_size;
    la_status status = m_device->m_ll_device->read_register(m_device->m_gb_tree->dram_cgm->initial_config_values, total_size);
    return_on_error(status);

    gibraltar::dram_cgm_initial_config_pool_values_register pool_size;
    pool_size.fields.shared_pool_max_size = total_size.fields.total_buffers_max_size * threshold;

    status = m_device->m_ll_device->write_register((*m_device->m_gb_tree->dram_cgm->initial_config_pool_values)[hbm_pool_id],
                                                   pool_size);
    return status;
}

la_status
voq_cgm_handler::get_hbm_pool_max_capacity(la_cgm_hbm_pool_id_t hbm_pool_id, float& out_threshold) const
{
    // Verify data correctness
    la_uint64_t max_hbm_pool_id;
    la_status limit_status = m_device->get_limit(limit_type_e::DEVICE__NUM_CGM_HBM_POOLS, max_hbm_pool_id);
    return_on_error(limit_status);

    if (hbm_pool_id >= max_hbm_pool_id) {
        return LA_STATUS_EOUTOFRANGE;
    }

    gibraltar::dram_cgm_initial_config_values_register toatl_size;
    la_status status = m_device->m_ll_device->read_register(m_device->m_gb_tree->dram_cgm->initial_config_values, toatl_size);
    return_on_error(status);

    gibraltar::dram_cgm_initial_config_pool_values_register pool_size;
    status = m_device->m_ll_device->read_register((*m_device->m_gb_tree->dram_cgm->initial_config_pool_values)[hbm_pool_id],
                                                  pool_size);
    return_on_error(status);

    out_threshold = (float)pool_size.fields.shared_pool_max_size / toatl_size.fields.total_buffers_max_size;
    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::set_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                           const la_cgm_hbm_pool_free_blocks_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::set_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                           const la_voq_cgm_quantization_thresholds& thresholds)
{
    // Verify data correctness
    la_status status
        = validate_quantization_thresholds(m_device,
                                           thresholds.thresholds,
                                           limit_type_e::DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS,
                                           limit_type_e::DEVICE__MAX_HBM_POOL_BYTES_QUANTIZATION_THRESHOLD);
    return_on_error(status);

    la_uint64_t max_hbm_pool_id;
    la_status limit_status = m_device->get_limit(limit_type_e::DEVICE__NUM_CGM_HBM_POOLS, max_hbm_pool_id);
    return_on_error(limit_status);

    if (hbm_pool_id >= max_hbm_pool_id) {
        return LA_STATUS_EINVAL;
    }

    // Read
    gibraltar::dram_cgm_quant_thresholds_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_gb_tree->dram_cgm->quant_thresholds, reg);
    return_on_error(read_status);

    // Modify struct
    for (uint32_t index = 0; index < thresholds.thresholds.size(); index++) {
        uint64_t item_value = thresholds.thresholds[index] / HBM_BLOCKS_GROUP_SIZE;
        if (hbm_pool_id == 0) {
            reg.fields.set_shared_pool0_th(index, item_value);
        } else {
            reg.fields.set_shared_pool1_th(index, item_value);
        }
    }

    // Write
    la_status write_status = m_device->m_ll_device->write_register(m_device->m_gb_tree->dram_cgm->quant_thresholds, reg);
    return write_status;
}

la_status
voq_cgm_handler::get_cgm_hbm_pool_free_blocks_quantization(
    la_cgm_hbm_pool_id_t hbm_pool_id,
    la_cgm_hbm_pool_free_blocks_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::get_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                           la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    // Verify data correctness
    la_uint64_t max_pool_id;
    la_status limit_status = m_device->get_limit(limit_type_e::DEVICE__NUM_CGM_HBM_POOLS, max_pool_id);
    return_on_error(limit_status);

    if (hbm_pool_id >= max_pool_id) {
        return LA_STATUS_EINVAL;
    }

    // Read
    gibraltar::dram_cgm_quant_thresholds_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_gb_tree->dram_cgm->quant_thresholds, reg);
    return_on_error(read_status);

    la_uint64_t num_thresholds;
    limit_status
        = m_device->get_limit(limit_type_e::DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS, num_thresholds);
    return_on_error(limit_status);

    out_thresholds.thresholds.resize(num_thresholds);

    for (uint32_t index = 0; index < out_thresholds.thresholds.size(); index++) {
        uint64_t item_value = (hbm_pool_id == 0) ? reg.fields.get_shared_pool0_th(index) : reg.fields.get_shared_pool1_th(index);
        out_thresholds.thresholds[index] = item_value * HBM_BLOCKS_GROUP_SIZE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::set_cgm_wred_probabilities(uint64_t prob_profile_id, double probability)
{

    auto& tables(m_device->m_tables.voq_cgm_wred_probability_table);

    npl_voq_cgm_wred_probability_table_t::key_type k;
    npl_voq_cgm_wred_probability_table_t::value_type v;

    if (prob_profile_id >= (1ul << BITS_SIZEOF(k, region_id))) {
        return LA_STATUS_EINVAL;
    }

    static la_uint64_t max_pr = (1ul << BITS_SIZEOF(v.payloads.voq_cgm_wred_probability_results.probability, value)) - 1;

    k.region_id = prob_profile_id;
    v.payloads.voq_cgm_wred_probability_results.probability.value = probability * max_pr;
    v.action = NPL_VOQ_CGM_WRED_PROBABILITY_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return_on_error(write_status);
    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::get_cgm_wred_probabilities(uint64_t prob_profile_id, double& out_probability) const
{
    auto& tables(m_device->m_tables.voq_cgm_wred_probability_table);

    npl_voq_cgm_wred_probability_table_t::key_type k;
    npl_voq_cgm_wred_probability_table_t::value_type v;
    npl_voq_cgm_wred_probability_table_t::entry_pointer_type entry_ptr = nullptr;

    if (prob_profile_id >= (1ul << BITS_SIZEOF(k, region_id))) {
        return LA_STATUS_EINVAL;
    }

    static la_uint64_t max_pr = (1ul << BITS_SIZEOF(v.payloads.voq_cgm_wred_probability_results.probability, value)) - 1;

    k.region_id = prob_profile_id;
    size_t first_inst = m_device->first_active_slice_id();
    la_status read_status = tables[first_inst]->lookup(k, entry_ptr);
    return_on_error(read_status);
    out_probability = entry_ptr->value().payloads.voq_cgm_wred_probability_results.probability.value / max_pr;

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::set_cgm_hbm_voq_age_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    // Verify data correctness
    la_status status = validate_quantization_thresholds(m_device,
                                                        thresholds.thresholds,
                                                        limit_type_e::DEVICE__HBM_NUM_VOQ_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS,
                                                        limit_type_e::DEVICE__MAX_HBM_VOQ_AGE_QUANTIZATION_THRESHOLD);
    return_on_error(status);

    // Read
    gibraltar::dram_cgm_quant_thresholds_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_gb_tree->dram_cgm->quant_thresholds, reg);
    return_on_error(read_status);

    // Read granularity.
    gibraltar::dram_cgm_time_control_cfg_register cfg_reg;
    read_status = m_device->m_ll_device->read_register(m_device->m_gb_tree->dram_cgm->time_control_cfg, cfg_reg);
    uint64_t granularity = cfg_reg.fields.cycle_count;

    // Modify struct
    for (uint32_t index = 0; index < thresholds.thresholds.size(); index++) {
        // Convert user threshold in ms to cycles.
        uint64_t register_value
            = div_round_nearest((thresholds.thresholds[index] * m_device->m_device_frequency_int_khz), granularity);
        reg.fields.set_queue_age_th(index, register_value);
    }

    // Write
    la_status write_status = m_device->m_ll_device->write_register(m_device->m_gb_tree->dram_cgm->quant_thresholds, reg);
    return write_status;
}

la_status
voq_cgm_handler::get_cgm_hbm_voq_age_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    // Read
    gibraltar::dram_cgm_quant_thresholds_register reg;
    la_status status = m_device->m_ll_device->read_register(m_device->m_gb_tree->dram_cgm->quant_thresholds, reg);
    return_on_error(status);

    // Read granularity.
    gibraltar::dram_cgm_time_control_cfg_register cfg_reg;
    status = m_device->m_ll_device->read_register(m_device->m_gb_tree->dram_cgm->time_control_cfg, cfg_reg);
    uint64_t granularity = cfg_reg.fields.cycle_count;

    la_uint64_t num_thresholds;
    la_status limit_status
        = m_device->get_limit(limit_type_e::DEVICE__HBM_NUM_VOQ_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS, num_thresholds);
    return_on_error(limit_status);

    out_thresholds.thresholds.resize(num_thresholds);

    for (uint32_t index = 0; index < out_thresholds.thresholds.size(); index++) {
        uint64_t register_value = reg.fields.get_queue_age_th(index);
        // Convert cycles to user threshold in ms.
        out_thresholds.thresholds[index] = div_round_nearest((register_value * granularity), m_device->m_device_frequency_int_khz);
    }

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::set_cgm_hbm_blocks_by_voq_quantization(const la_cgm_hbm_blocks_by_voq_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::set_cgm_hbm_blocks_by_voq_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    // Verify data correctness.
    la_status status
        = validate_quantization_thresholds(m_device,
                                           thresholds.thresholds,
                                           limit_type_e::DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_CONFIGURABLE_THRESHOLDS,
                                           limit_type_e::DEVICE__MAX_HBM_BLOCKS_BY_VOQ_QUANTIZATION_THRESHOLD);
    return_on_error(status);

    // Read
    gibraltar::dram_cgm_quant_thresholds_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_gb_tree->dram_cgm->quant_thresholds, reg);
    return_on_error(read_status);

    // Modify struct
    for (uint32_t index = 0; index < thresholds.thresholds.size(); index++) {
        reg.fields.set_queue_size_th(index, thresholds.thresholds[index] / HBM_BLOCKS_GROUP_SIZE);
    }

    // Write
    la_status write_status = m_device->m_ll_device->write_register(m_device->m_gb_tree->dram_cgm->quant_thresholds, reg);
    return write_status;
}

la_status
voq_cgm_handler::get_cgm_hbm_blocks_by_voq_quantization(la_cgm_hbm_blocks_by_voq_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::get_cgm_hbm_blocks_by_voq_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    // Read
    gibraltar::dram_cgm_quant_thresholds_register reg;
    la_status status = m_device->m_ll_device->read_register(m_device->m_gb_tree->dram_cgm->quant_thresholds, reg);
    return_on_error(status);

    la_uint64_t num_thresholds;
    la_status limit_status
        = m_device->get_limit(limit_type_e::DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_CONFIGURABLE_THRESHOLDS, num_thresholds);
    return_on_error(limit_status);

    out_thresholds.thresholds.resize(num_thresholds);

    // update struct
    for (uint32_t index = 0; index < out_thresholds.thresholds.size(); index++) {
        out_thresholds.thresholds[index] = reg.fields.get_queue_size_th(index) * HBM_BLOCKS_GROUP_SIZE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::get_voq_cgm_evicted_buffers_default_behavior(la_quantization_region_t evicted_buffers_region,
                                                              la_quantization_region_t sms_total_bytes_region,
                                                              la_quantization_region_t sms_voq_bytes_region,
                                                              la_qos_color_e& out_drop_color_level) const
{
    out_drop_color_level = m_evicted_buffers_default_behavior[evicted_buffers_region][sms_total_bytes_region][sms_voq_bytes_region];

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::save_voq_cgm_evicted_buffers_defaults()
{
    la_uint64_t num_evicted_buffers_regions;
    la_status status
        = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_REGIONS, num_evicted_buffers_regions);
    return_on_error(status);

    la_uint64_t num_sms_total_bytes_regions;
    status = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_total_bytes_regions);
    return_on_error(status);

    la_uint64_t num_sms_voq_bytes_regions;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);
    return_on_error(status);

    for (la_quantization_region_t evicted_buffers_region = 0; evicted_buffers_region < num_evicted_buffers_regions;
         evicted_buffers_region++) {
        for (la_quantization_region_t sms_total_bytes_region = 0; sms_total_bytes_region < num_sms_total_bytes_regions;
             sms_total_bytes_region++) {
            for (la_quantization_region_t sms_voq_bytes_region = 0; sms_voq_bytes_region < num_sms_voq_bytes_regions;
                 sms_voq_bytes_region++) {

                // Init configuration is the same for all evicted profile IDs, so only save for evicted profile ID of
                // la_device_impl::VOQ_CGM_DEFAULT_EVICTED_PROFILE and it is used as default configuration for all evicted profile
                // IDs.
                uint64_t mem_line
                    = ((evicted_buffers_region * la_device_impl::NUM_VOQ_CGM_EVICTED_PROFILES_PER_DEVICE
                        * num_sms_total_bytes_regions
                        * num_sms_voq_bytes_regions)
                       + (la_device_impl::VOQ_CGM_DEFAULT_EVICTED_PROFILE * num_sms_total_bytes_regions * num_sms_voq_bytes_regions)
                       + (sms_total_bytes_region * num_sms_voq_bytes_regions)
                       + sms_voq_bytes_region);

                gibraltar::pdvoq_slice_evicted_buffers_consumption_lut_memory mem_struct;
                la_status read_status = m_device->m_ll_device->read_memory(
                    m_device->m_gb_tree->slice[m_device->first_active_slice_id()]->pdvoq->evicted_buffers_consumption_lut,
                    mem_line,
                    mem_struct);
                return_on_error(read_status);

                la_qos_color_e drop_color_level = la_qos_color_e::NONE;
                if (mem_struct.fields.drop_green) {
                    drop_color_level = la_qos_color_e::GREEN;
                } else if (mem_struct.fields.drop_yellow) {
                    drop_color_level = la_qos_color_e::YELLOW;
                }
                m_evicted_buffers_default_behavior[evicted_buffers_region][sms_total_bytes_region][sms_voq_bytes_region]
                    = drop_color_level;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::save_voq_cgm_defaults()
{
    la_status status = save_voq_cgm_evicted_buffers_defaults();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::set_cgm_ecn_probability(la_uint_t level, float probability)
{
    if (level >= cgm_ecn_num_levels || probability < 0 || probability > 1) {
        return LA_STATUS_EINVAL;
    }

    if (probability == 0) {
        la_status status = clear_cgm_ecn_probability(level);
        return_on_error(status);
    } else {
        la_uint_t num = cgm_ecn_probility_to_int(probability);

        la_status status = program_cgm_ecn_probability(level, num, true);
        return_on_error(status);

        ecn_level_prob_map[level] = num;
    }

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::get_cgm_ecn_probability(la_uint_t level, float& probability)
{
    if (level >= cgm_ecn_num_levels) {
        return LA_STATUS_EINVAL;
    }

    la_uint_t prob = ecn_level_prob_map[level];

    if (prob > cgm_ecn_num_probability) {
        probability = 0;
    } else {
        probability = (prob + 1) / float(cgm_ecn_num_probability);
    }

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::initialize()
{
    for (la_uint_t level = 0; level < cgm_ecn_num_levels; level++) {
        la_status status;

        // Set probability as 1 for highest mark
        if (level == (cgm_ecn_num_levels - 1)) {
            status = set_cgm_ecn_probability(level, 1);
        } else {
            status = clear_cgm_ecn_probability(level);
        }

        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_uint_t
voq_cgm_handler::cgm_ecn_probility_to_int(float probability)
{
    la_uint_t prob;

    prob = ceil(probability * cgm_ecn_num_probability) - 1;

    return prob;
}

la_status
voq_cgm_handler::clear_cgm_ecn_probability(la_uint_t level)
{
    if (level >= cgm_ecn_num_levels) {
        return LA_STATUS_EINVAL;
    }

    la_uint_t prob = cgm_ecn_num_probability + 1;

    la_status status = program_cgm_ecn_probability(level, cgm_ecn_num_probability + 1, false);
    return_on_error(status);

    ecn_level_prob_map[level] = prob;

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::program_cgm_ecn_probability(la_uint_t level, la_uint_t int_prob, bool enable)
{
    npl_cong_level_ecn_remap_map_table_key_t key;
    npl_cong_level_ecn_remap_map_table_value_t val;
    npl_cong_level_ecn_remap_map_table_t::entry_pointer_type table_entry = nullptr;

    key.cong_level = level;
    val.action = NPL_CONG_LEVEL_ECN_REMAP_MAP_TABLE_ACTION_WRITE;

    for (la_uint_t j = 0; j < cgm_ecn_num_probability; j++) {
        if (j <= int_prob) {
            val.payloads.stat_cong_level_on.val = enable ? NPL_TRUE_VALUE : NPL_FALSE_VALUE;
        } else {
            val.payloads.stat_cong_level_on.val = NPL_FALSE_VALUE;
        }

        key.rand = j;

        for (size_t sid : m_device->get_used_slices()) {
            la_status status;
            status = m_device->m_tables.cong_level_ecn_remap_map_table[sid]->set(key, val, table_entry);

            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
