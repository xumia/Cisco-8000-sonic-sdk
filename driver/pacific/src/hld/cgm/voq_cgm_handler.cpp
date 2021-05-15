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
#include "lld/ll_device.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

voq_cgm_handler::voq_cgm_handler(const la_device_impl_wptr& device) : m_device(device), m_sms_voqs_age_time_ns(0)
{
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
    pdvoq_shared_mma_global_conf_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_pacific_tree->pdvoq_shared_mma->global_conf, reg);
    return_on_error(read_status);

    // Modify struct
    reg.fields.enq_time_units = time_in_us - 1;

    // Write
    la_status write_status = m_device->m_ll_device->write_register(m_device->m_pacific_tree->pdvoq_shared_mma->global_conf, reg);
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
voq_cgm_handler::set_cgm_sms_voqs_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::set_cgm_sms_voqs_bytes_quantization(const la_cgm_sms_bytes_quantization_thresholds& thresholds)
{
    // Verify data correctness
    for (uint32_t index = 0; index < array_size(thresholds.thresholds) - 1; index++) {
        if (thresholds.thresholds[index] > thresholds.thresholds[index + 1]) {
            return LA_STATUS_EINVAL;
        }
    }
    la_uint64_t max_threshold;
    m_device->get_limit(limit_type_e::DEVICE__MAX_SMS_BYTES_QUANTIZATION_THRESHOLD, max_threshold);
    if (thresholds.thresholds[array_size(thresholds.thresholds) - 1] > max_threshold) {
        return LA_STATUS_EINVAL;
    }

    // Read
    rx_pdr_counters_thresholds_reg1_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_pacific_tree->rx_pdr->counters_thresholds_reg1, reg);
    return_on_error(read_status);

    // Modify struct
    reg.fields.voq_cgm_counter_a_thr0 = div_round_nearest(thresholds.thresholds[0], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);
    reg.fields.voq_cgm_counter_a_thr1 = div_round_nearest(thresholds.thresholds[1], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);
    reg.fields.voq_cgm_counter_a_thr2 = div_round_nearest(thresholds.thresholds[2], la_device_impl::SMS_BLOCK_SIZE_IN_BYTES);

    // Write
    la_status write_status = m_device->m_ll_device->write_register(m_device->m_pacific_tree->rx_pdr->counters_thresholds_reg1, reg);

    return write_status;
}

la_status
voq_cgm_handler::get_cgm_sms_voqs_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::get_cgm_sms_voqs_bytes_quantization(la_cgm_sms_bytes_quantization_thresholds& out_thresholds) const
{
    // Read struct
    rx_pdr_counters_thresholds_reg1_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_pacific_tree->rx_pdr->counters_thresholds_reg1, reg);

    return_on_error(read_status);

    // Update output
    out_thresholds.thresholds[0] = reg.fields.voq_cgm_counter_a_thr0 * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;
    out_thresholds.thresholds[1] = reg.fields.voq_cgm_counter_a_thr1 * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;
    out_thresholds.thresholds[2] = reg.fields.voq_cgm_counter_a_thr2 * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::set_cgm_sms_evicted_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::get_cgm_sms_evicted_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::set_cgm_sms_voqs_packets_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::set_cgm_sms_voqs_packets_quantization(const la_cgm_sms_packets_quantization_thresholds& thresholds)
{
    // Verify data correctness
    for (uint32_t index = 0; index < array_size(thresholds.thresholds) - 1; index++) {
        if (thresholds.thresholds[index] > thresholds.thresholds[index + 1]) {
            return LA_STATUS_EINVAL;
        }
    }

    la_uint64_t max_threshold;
    m_device->get_limit(limit_type_e::DEVICE__MAX_SMS_PACKETS_QUANTIZATION_THRESHOLD, max_threshold);
    if (thresholds.thresholds[array_size(thresholds.thresholds) - 1] > max_threshold) {
        return LA_STATUS_EINVAL;
    }

    // Set struct
    pdvoq_shared_mma_cgm_pool_available_region_register reg;
    reg.fields.uc_region0 = thresholds.thresholds[0];
    reg.fields.uc_region1 = thresholds.thresholds[1];
    reg.fields.uc_region2 = thresholds.thresholds[2];

    // Write
    la_status write_status
        = m_device->m_ll_device->write_register(m_device->m_pacific_tree->pdvoq_shared_mma->cgm_pool_available_region, reg);

    return write_status;
}

la_status
voq_cgm_handler::get_cgm_sms_voqs_packets_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::get_cgm_sms_voqs_packets_quantization(la_cgm_sms_packets_quantization_thresholds& out_thresholds) const
{
    // Read
    pdvoq_shared_mma_cgm_pool_available_region_register reg;
    la_status read_status
        = m_device->m_ll_device->read_register(m_device->m_pacific_tree->pdvoq_shared_mma->cgm_pool_available_region, reg);

    return_on_error(read_status);

    // Set struct
    out_thresholds.thresholds[0] = reg.fields.uc_region0;
    out_thresholds.thresholds[1] = reg.fields.uc_region1;
    out_thresholds.thresholds[2] = reg.fields.uc_region2;

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::set_cgm_hbm_number_of_voqs_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::set_cgm_hbm_number_of_voqs_quantization(const la_cgm_hbm_number_of_voqs_quantization_thresholds& thresholds)
{
    // Verify data correctness
    for (uint32_t index = 0; index < array_size(thresholds.thresholds) - 1; index++) {
        if (thresholds.thresholds[index] > thresholds.thresholds[index + 1]) {
            return LA_STATUS_EINVAL;
        }
    }
    la_uint64_t max_threshold;
    m_device->get_limit(limit_type_e::DEVICE__MAX_HBM_NUM_OF_VOQS_QUANTIZATION_THRESHOLD, max_threshold);
    if (thresholds.thresholds[array_size(thresholds.thresholds) - 1] > max_threshold) {
        return LA_STATUS_EINVAL;
    }

    // Set struct
    // In pacific, threshold is for number of free contexts in the HBM. Therefore, the complement is written to the HW.
    ics_top_dram_context_pool_alm_empty_register reg;
    reg.fields.dram_context_pool_alm_empty_th = HBM_CONTEXT_POOL_SIZE - thresholds.thresholds[0];

    // Write
    la_status write_status
        = m_device->m_ll_device->write_register(m_device->m_pacific_tree->ics_top->dram_context_pool_alm_empty, reg);
    return write_status;
}

la_status
voq_cgm_handler::get_cgm_hbm_number_of_voqs_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::get_cgm_hbm_number_of_voqs_quantization(la_cgm_hbm_number_of_voqs_quantization_thresholds& out_thresholds) const
{
    ics_top_dram_context_pool_alm_empty_register reg;

    // Read
    la_status status = m_device->m_ll_device->read_register(m_device->m_pacific_tree->ics_top->dram_context_pool_alm_empty, reg);
    return_on_error(status);

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
    m_device->get_limit(limit_type_e::DEVICE__NUM_CGM_HBM_POOLS, max_hbm_pool_id);
    if (hbm_pool_id >= max_hbm_pool_id) {
        return LA_STATUS_EOUTOFRANGE;
    }

    hmc_cgm_initial_config_values_register total_size;
    la_status status = m_device->m_ll_device->read_register(m_device->m_pacific_tree->hmc_cgm->initial_config_values, total_size);
    return_on_error(status);

    hmc_cgm_initial_config_pool_values_register pool_size;
    pool_size.fields.shared_pool_max_size = total_size.fields.total_buffers_max_size * threshold;

    status = m_device->m_ll_device->write_register((*m_device->m_pacific_tree->hmc_cgm->initial_config_pool_values)[hbm_pool_id],
                                                   pool_size);
    return status;
}

la_status
voq_cgm_handler::get_hbm_pool_max_capacity(la_cgm_hbm_pool_id_t hbm_pool_id, float& out_threshold) const
{
    // Verify data correctness
    la_uint64_t max_hbm_pool_id;
    m_device->get_limit(limit_type_e::DEVICE__NUM_CGM_HBM_POOLS, max_hbm_pool_id);
    if (hbm_pool_id >= max_hbm_pool_id) {
        return LA_STATUS_EOUTOFRANGE;
    }

    hmc_cgm_initial_config_values_register toatl_size;
    la_status status = m_device->m_ll_device->read_register(m_device->m_pacific_tree->hmc_cgm->initial_config_values, toatl_size);
    return_on_error(status);

    hmc_cgm_initial_config_pool_values_register pool_size;
    status = m_device->m_ll_device->read_register((*m_device->m_pacific_tree->hmc_cgm->initial_config_pool_values)[hbm_pool_id],
                                                  pool_size);
    return_on_error(status);

    out_threshold = (float)pool_size.fields.shared_pool_max_size / toatl_size.fields.total_buffers_max_size;
    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::set_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                           const la_voq_cgm_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::set_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                           const la_cgm_hbm_pool_free_blocks_quantization_thresholds& thresholds)
{
    // Verify data correctness
    for (uint32_t index = 0; index < array_size(thresholds.thresholds) - 1; index++) {
        if (thresholds.thresholds[index] > thresholds.thresholds[index + 1]) {
            return LA_STATUS_EINVAL;
        }
    }

    la_uint64_t max_threshold;
    m_device->get_limit(limit_type_e::DEVICE__MAX_HBM_POOL_BYTES_QUANTIZATION_THRESHOLD, max_threshold);
    if (thresholds.thresholds[array_size(thresholds.thresholds) - 1] > max_threshold) {
        return LA_STATUS_EINVAL;
    }

    la_status limit_status = m_device->get_limit(limit_type_e::DEVICE__NUM_CGM_HBM_POOLS, max_threshold);
    return_on_error(limit_status);

    if (hbm_pool_id >= max_threshold) {
        return LA_STATUS_EINVAL;
    }

    // Read
    hmc_cgm_quant_thresholds_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_pacific_tree->hmc_cgm->quant_thresholds, reg);
    return_on_error(read_status);

    // Modify struct
    for (uint32_t index = 0; index < array_size(thresholds.thresholds); index++) {
        la_uint_t register_value = thresholds.thresholds[index] / HBM_BLOCKS_GROUP_SIZE;
        if (hbm_pool_id == 0) {
            reg.fields.set_shared_pool0_th(index, register_value);
        } else {
            reg.fields.set_shared_pool1_th(index, register_value);
        }
    }

    // Write
    la_status write_status = m_device->m_ll_device->write_register(m_device->m_pacific_tree->hmc_cgm->quant_thresholds, reg);
    return write_status;
}

la_status
voq_cgm_handler::get_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                           la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::get_cgm_hbm_pool_free_blocks_quantization(
    la_cgm_hbm_pool_id_t hbm_pool_id,
    la_cgm_hbm_pool_free_blocks_quantization_thresholds& out_thresholds) const
{
    // Verify data correctness
    la_uint64_t max_pool_id;
    la_status limit_status = m_device->get_limit(limit_type_e::DEVICE__NUM_CGM_HBM_POOLS, max_pool_id);
    return_on_error(limit_status);

    if (hbm_pool_id >= max_pool_id) {
        return LA_STATUS_EINVAL;
    }

    // Read
    hmc_cgm_quant_thresholds_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_pacific_tree->hmc_cgm->quant_thresholds, reg);
    return_on_error(read_status);

    // Modify struct
    for (uint32_t index = 0; index < array_size(out_thresholds.thresholds); index++) {
        if (hbm_pool_id == 0) {
            out_thresholds.thresholds[index] = reg.fields.get_shared_pool0_th(index) * HBM_BLOCKS_GROUP_SIZE;
        } else {
            out_thresholds.thresholds[index] = reg.fields.get_shared_pool1_th(index) * HBM_BLOCKS_GROUP_SIZE;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
voq_cgm_handler::set_cgm_hbm_voq_age_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::get_cgm_hbm_voq_age_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::set_cgm_hbm_blocks_by_voq_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::set_cgm_hbm_blocks_by_voq_quantization(const la_cgm_hbm_blocks_by_voq_quantization_thresholds& thresholds)
{
    // Verify data correctness
    for (uint32_t index = 0; index < array_size(thresholds.thresholds) - 1; index++) {
        if (thresholds.thresholds[index] > thresholds.thresholds[index + 1]) {
            return LA_STATUS_EINVAL;
        }
    }

    la_uint64_t max_threshold;
    m_device->get_limit(limit_type_e::DEVICE__MAX_HBM_BLOCKS_BY_VOQ_QUANTIZATION_THRESHOLD, max_threshold);
    if (thresholds.thresholds[array_size(thresholds.thresholds) - 1] > max_threshold) {
        return LA_STATUS_EINVAL;
    }

    // Read
    hmc_cgm_quant_thresholds_register reg;
    la_status read_status = m_device->m_ll_device->read_register(m_device->m_pacific_tree->hmc_cgm->quant_thresholds, reg);
    return_on_error(read_status);

    // Modify struct
    for (uint32_t index = 0; index < array_size(thresholds.thresholds); index++) {
        reg.fields.set_queue_size_th(index, thresholds.thresholds[index] / HBM_BLOCKS_GROUP_SIZE);
    }

    // Write
    la_status write_status = m_device->m_ll_device->write_register(m_device->m_pacific_tree->hmc_cgm->quant_thresholds, reg);
    return write_status;
}

la_status
voq_cgm_handler::get_cgm_hbm_blocks_by_voq_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
voq_cgm_handler::get_cgm_hbm_blocks_by_voq_quantization(la_cgm_hbm_blocks_by_voq_quantization_thresholds& out_thresholds) const
{
    // Read
    hmc_cgm_quant_thresholds_register reg;
    la_status status = m_device->m_ll_device->read_register(m_device->m_pacific_tree->hmc_cgm->quant_thresholds, reg);
    return_on_error(status);

    // update struct
    for (uint32_t index = 0; index < array_size(out_thresholds.thresholds); index++) {
        out_thresholds.thresholds[index] = reg.fields.get_queue_size_th(index) * HBM_BLOCKS_GROUP_SIZE;
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
