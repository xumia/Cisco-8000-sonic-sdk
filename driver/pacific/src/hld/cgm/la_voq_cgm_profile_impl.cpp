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

#include "la_voq_cgm_profile_impl.h"
#include "common/gen_utils.h"
#include "hld_utils.h"

#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"
#include "nplapi/nplapi_tables.h"
#include "system/la_device_impl.h"
#include "voq_cgm_handler.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <cmath>

namespace silicon_one
{

static constexpr la_voq_cgm_profile::sms_bytes_quantization_thresholds default_bytes_quantization_thresholds
    = {.thresholds = {576000, 579840, 583680, 589050, 591360, 595200, 4718592}};

la_voq_cgm_profile_impl::la_voq_cgm_profile_impl(const la_device_impl_wptr& device)
    : m_device(device), m_voq_cgm_pd_counter(VOQ_CGM_PD_COUNTER_INVALID), m_use_count(0)
{
}

la_voq_cgm_profile_impl::~la_voq_cgm_profile_impl()
{
}

la_status
la_voq_cgm_profile_impl::initialize(la_object_id_t oid, uint64_t voq_cgm_profile_index)
{
    m_oid = oid;
    m_index = voq_cgm_profile_index;

    // Init VOQ CGM profile to drop all packet in last PD/buff threshold
    auto status = set_defaults();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_defaults()
{
    la_status status = do_set_sms_bytes_quantization(default_bytes_quantization_thresholds);
    return_on_error(status);

    for (la_quantization_region_t sms_voqs_total_bytes_region = 0;
         sms_voqs_total_bytes_region < LA_CGM_NUM_SMS_BYTES_QUANTIZATION_REGIONS;
         sms_voqs_total_bytes_region++) {
        for (la_quantization_region_t sms_age_region = 0; sms_age_region < SMS_NUM_AGE_QUANTIZATION_REGIONS; sms_age_region++) {
            for (la_quantization_region_t hbm_total_number_of_voqs_region = 0;
                 hbm_total_number_of_voqs_region < LA_CGM_NUM_HBM_NUMBER_OF_VOQS_QUANTIZATION_REGIONS;
                 hbm_total_number_of_voqs_region++) {
                status = do_set_sms_size_in_bytes_behavior(sms_voqs_total_bytes_region,
                                                           SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS,
                                                           sms_age_region,
                                                           hbm_total_number_of_voqs_region,
                                                           la_qos_color_e::GREEN,
                                                           false /* mark_ecn */,
                                                           false /* evict_to_hbm */);
                return_on_error(status);
            }
        }
    }

    for (la_quantization_region_t hbm_pool_free_blocks_region = 0;
         hbm_pool_free_blocks_region < LA_CGM_NUM_HBM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS;
         hbm_pool_free_blocks_region++) {
        status = do_set_hbm_size_in_blocks_behavior(LA_CGM_NUM_HBM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS - 1,
                                                    hbm_pool_free_blocks_region,
                                                    la_qos_color_e::GREEN,
                                                    false /* mark_ecn */);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::destroy()
{
    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_voq_cgm_profile_impl::type() const
{
    return object_type_e::VOQ_CGM_PROFILE;
}

std::string
la_voq_cgm_profile_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_voq_cgm_profile_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_voq_cgm_profile_impl::oid() const
{
    return m_oid;
}

const la_device*
la_voq_cgm_profile_impl::get_device() const
{
    return m_device.get();
}

uint64_t
la_voq_cgm_profile_impl::get_id() const
{
    return m_index;
}

la_status
la_voq_cgm_profile_impl::set_sms_bytes_quantization(const sms_bytes_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);

    // Verify data correctness
    for (uint32_t index = 0; index < array_size(thresholds.thresholds) - 1; index++) {
        if (thresholds.thresholds[index] > thresholds.thresholds[index + 1]) {
            return LA_STATUS_EINVAL;
        }
    }
    la_uint64_t max_threshold;
    m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_SMS_BYTES, max_threshold);
    if (thresholds.thresholds[array_size(thresholds.thresholds) - 1] > max_threshold) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status status = do_set_sms_bytes_quantization(thresholds);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::do_set_sms_bytes_quantization(const sms_bytes_quantization_thresholds& thresholds)
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_buff_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_t::value_type v;

    k.profile_id.value = m_index;
    la_uint64_t num_of_bytes_in_buf = la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;
    for (uint32_t index = 0; index < array_size(thresholds.thresholds); index++) {
        v.payloads.voq_cgm_slice_profile_buff_region_thresholds_results.q_size_buff_region[index].value
            = div_round_nearest(thresholds.thresholds[index], num_of_bytes_in_buf);
    }

    v.action = NPL_VOQ_CGM_SLICE_PROFILE_BUFF_REGION_THRESHOLDS_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);

    return write_status;
}

la_status
la_voq_cgm_profile_impl::get_sms_bytes_quantization(sms_bytes_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_buff_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;

    // Read current value
    la_status status = tables[0]->lookup(k, entry_ptr);
    return_on_error(status);
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_t::value_type v = entry_ptr->value();

    // Write to out_thresholds
    la_uint64_t num_of_bytes_in_buf = la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;
    for (uint32_t index = 0; index < array_size(out_thresholds.thresholds); index++) {
        out_thresholds.thresholds[index]
            = v.payloads.voq_cgm_slice_profile_buff_region_thresholds_results.q_size_buff_region[index].value * num_of_bytes_in_buf;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_sms_packets_quantization(const sms_packets_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);

    // Verify data correctness
    for (uint32_t index = 0; index < array_size(thresholds.thresholds) - 1; index++) {
        if (thresholds.thresholds[index] > thresholds.thresholds[index + 1]) {
            return LA_STATUS_EINVAL;
        }
    }
    la_uint64_t max_threshold;
    m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_SMS_PACKETS, max_threshold);
    if (thresholds.thresholds[array_size(thresholds.thresholds) - 1] > max_threshold) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_pkt_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_t::value_type v;

    k.profile_id.value = m_index;
    for (uint32_t index = 0; index < array_size(thresholds.thresholds); index++) {
        v.payloads.voq_cgm_slice_profile_pkt_region_thresholds_results.q_size_pkt_region[index].value
            = thresholds.thresholds[index];
    }
    v.action = NPL_VOQ_CGM_SLICE_PROFILE_PKT_REGION_THRESHOLDS_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return_on_error(write_status);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_sms_packets_quantization(sms_packets_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_pkt_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;

    // Read current value
    la_status status = tables[0]->lookup(k, entry_ptr);
    return_on_error(status);
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_t::value_type v = entry_ptr->value();

    // Write to out_thresholds
    for (uint32_t index = 0; index < array_size(out_thresholds.thresholds); index++) {
        out_thresholds.thresholds[index]
            = v.payloads.voq_cgm_slice_profile_pkt_region_thresholds_results.q_size_pkt_region[index].value;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_sms_age_quantization(const sms_age_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);

    // Verify data correctness
    for (uint32_t index = 0; index < array_size(thresholds.thresholds) - 1; index++) {
        if (thresholds.thresholds[index] > thresholds.thresholds[index + 1]) {
            return LA_STATUS_EINVAL;
        }
    }
    la_uint64_t max_threshold;
    la_status get_limit_status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_SMS_AGE, max_threshold);
    return_on_error(get_limit_status);
    if (thresholds.thresholds[array_size(thresholds.thresholds) - 1] > max_threshold) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_t::value_type v;

    k.profile_id.value = m_index;
    la_cgm_sms_voqs_age_time_units_t granularity;
    la_status granularity_status = m_device->m_voq_cgm_handler->get_cgm_sms_voqs_age_time_granularity(granularity);
    return_on_error(granularity_status);
    for (uint32_t index = 0; index < array_size(thresholds.thresholds); index++) {
        v.payloads.voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results.pkt_enq_time_region[index].value
            = thresholds.thresholds[index] / granularity;
    }
    v.action = NPL_VOQ_CGM_SLICE_PROFILE_PKT_ENQ_TIME_REGION_THRESHOLDS_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return_on_error(write_status);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_sms_age_quantization(sms_age_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;

    // Read current value
    la_status status = tables[0]->lookup(k, entry_ptr);
    return_on_error(status);
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_t::value_type v = entry_ptr->value();

    // Write to out_thresholds
    la_cgm_sms_voqs_age_time_units_t granularity;
    la_status granularity_status = m_device->m_voq_cgm_handler->get_cgm_sms_voqs_age_time_granularity(granularity);
    return_on_error(granularity_status);
    for (uint32_t index = 0; index < array_size(out_thresholds.thresholds); index++) {
        out_thresholds.thresholds[index]
            = v.payloads.voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results.pkt_enq_time_region[index].value
              * granularity;
    }
    return LA_STATUS_SUCCESS;
}
la_status
la_voq_cgm_profile_impl::set_sms_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}
la_status
la_voq_cgm_profile_impl::get_sms_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}
la_status
la_voq_cgm_profile_impl::set_sms_packets_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}
la_status
la_voq_cgm_profile_impl::get_sms_packets_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}
la_status
la_voq_cgm_profile_impl::set_sms_age_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}
la_status
la_voq_cgm_profile_impl::get_sms_age_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                        la_quantization_region_t sms_bytes_region,
                                                        la_quantization_region_t sms_age_region,
                                                        la_quantization_region_t hbm_total_number_of_voqs_region,
                                                        la_qos_color_e drop_color_level,
                                                        bool mark_ecn,
                                                        bool evict_to_hbm)

{
    start_api_call("sms_voqs_total_bytes_region=",
                   sms_voqs_total_bytes_region,
                   "sms_bytes_region=",
                   sms_bytes_region,
                   "sms_age_region=",
                   sms_age_region,
                   "hbm_total_nsmber_of_voqs_region=",
                   hbm_total_number_of_voqs_region,
                   "drop_color_level=",
                   drop_color_level,
                   "mark_ecn=",
                   mark_ecn,
                   "evict_to_hbm=",
                   evict_to_hbm);

    // Verify data correctness
    if (sms_voqs_total_bytes_region >= LA_CGM_NUM_SMS_BYTES_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // Last region is always drop
    if (sms_bytes_region >= SMS_NUM_BYTES_QUANTIZATION_REGIONS - 1) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (sms_age_region >= SMS_NUM_AGE_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (hbm_total_number_of_voqs_region >= LA_CGM_NUM_HBM_NUMBER_OF_VOQS_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if ((m_voq_cgm_pd_counter == NPL_VOQ_CGM_PD_COUNTER_MC) && (evict_to_hbm == true)) {
        log_err(HLD, "VOQ CGM profile is attached to a MC VOQ. A MC VOQ cannot be evicted to the HBM.");
        return LA_STATUS_EINVAL;
    }

    la_status status = do_set_sms_size_in_bytes_behavior(sms_voqs_total_bytes_region,
                                                         sms_bytes_region,
                                                         sms_age_region,
                                                         hbm_total_number_of_voqs_region,
                                                         drop_color_level,
                                                         mark_ecn,
                                                         evict_to_hbm);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::do_set_sms_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                           la_quantization_region_t sms_bytes_region,
                                                           la_quantization_region_t sms_age_region,
                                                           la_quantization_region_t hbm_total_number_of_voqs_region,
                                                           la_qos_color_e drop_color_level,
                                                           bool mark_ecn,
                                                           bool evict_to_hbm)
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_buffers_consumption_lut_for_enq_table);

    // Prepare arguments
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::key_type k;
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::value_type v;
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.buffer_pool_available_level = sms_voqs_total_bytes_region;
    k.buffer_voq_size_level = sms_bytes_region;
    k.free_dram_cntx = hbm_total_number_of_voqs_region;

    // Read current value
    la_status status = tables[0]->lookup(k, entry_ptr);
    if (status != LA_STATUS_ENOTFOUND && status != LA_STATUS_SUCCESS) {
        return status;
    }
    if (status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    // Modify
    v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_g.drop_green.drop_color[sms_age_region].value
        = (drop_color_level <= la_qos_color_e::GREEN);
    v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_y.drop_yellow.drop_color[sms_age_region].value
        = (drop_color_level <= la_qos_color_e::YELLOW);
    v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.congestion_mark[sms_age_region].value = mark_ecn;
    v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.evict_to_dram[sms_age_region].value = evict_to_hbm;
    v.action = NPL_VOQ_CGM_SLICE_BUFFERS_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE;

    // Write
    status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);

    return status;
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                        la_quantization_region_t sms_bytes_region,
                                                        la_quantization_region_t sms_age_region,
                                                        la_quantization_region_t hbm_total_number_of_voqs_region,
                                                        la_qos_color_e& out_drop_color_level,
                                                        bool& out_mark_ecn,
                                                        bool& out_evict_to_hbm) const
{
    start_api_getter_call();

    // Verify data correctness
    if (sms_voqs_total_bytes_region >= LA_CGM_NUM_SMS_BYTES_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (sms_bytes_region >= SMS_NUM_BYTES_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (sms_age_region >= SMS_NUM_AGE_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (hbm_total_number_of_voqs_region >= LA_CGM_NUM_HBM_NUMBER_OF_VOQS_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return do_get_sms_size_in_bytes_behavior(sms_voqs_total_bytes_region,
                                             sms_bytes_region,
                                             sms_age_region,
                                             hbm_total_number_of_voqs_region,
                                             out_drop_color_level,
                                             out_mark_ecn,
                                             out_evict_to_hbm);
}

la_status
la_voq_cgm_profile_impl::do_get_sms_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                           la_quantization_region_t sms_bytes_region,
                                                           la_quantization_region_t sms_age_region,
                                                           la_quantization_region_t hbm_total_number_of_voqs_region,
                                                           la_qos_color_e& out_drop_color_level,
                                                           bool& out_mark_ecn,
                                                           bool& out_evict_to_hbm) const
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_buffers_consumption_lut_for_enq_table);

    // Prepare arguments
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::key_type k;
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.buffer_pool_available_level = sms_voqs_total_bytes_region;
    k.buffer_voq_size_level = sms_bytes_region;
    k.free_dram_cntx = hbm_total_number_of_voqs_region;

    // Read current value
    la_status read_status = tables[0]->lookup(k, entry_ptr);
    return_on_error(read_status);

    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::value_type v;
    v = entry_ptr->value();

    // Fill the result
    if (v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_g.drop_green.drop_color[sms_age_region].value) {
        out_drop_color_level = la_qos_color_e::GREEN;
    } else {
        if (v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_y.drop_yellow.drop_color[sms_age_region].value) {
            out_drop_color_level = la_qos_color_e::YELLOW;
        } else {
            out_drop_color_level = la_qos_color_e::NONE;
        }
    }

    out_mark_ecn = v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.congestion_mark[sms_age_region].value;
    out_evict_to_hbm = v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.evict_to_dram[sms_age_region].value;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                          la_quantization_region_t sms_packets_region,
                                                          la_quantization_region_t sms_age_region,
                                                          la_qos_color_e drop_color_level,
                                                          bool mark_ecn,
                                                          bool evict_to_hbm)
{
    start_api_call("sms_voqs_total_packets_region=",
                   sms_voqs_total_packets_region,
                   "sms_packets_region=",
                   sms_packets_region,
                   "sms_age_region=",
                   sms_age_region,
                   "drop_color_level=",
                   drop_color_level,
                   "mark_ecn=",
                   mark_ecn,
                   "evict_to_hbm=",
                   evict_to_hbm);

    // Verify data correctness
    if (sms_packets_region >= SMS_NUM_PACKETS_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (sms_age_region >= SMS_NUM_AGE_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (sms_voqs_total_packets_region >= LA_CGM_NUM_SMS_PACKETS_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if ((m_voq_cgm_pd_counter == NPL_VOQ_CGM_PD_COUNTER_MC) && (evict_to_hbm == true)) {
        log_err(HLD, "VOQ CGM profile is attached to a MC VOQ. A MC VOQ cannot be evicted to the HBM.");
        return LA_STATUS_EINVAL;
    }

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_pd_consumption_lut_for_enq_table);

    // Prepare arguments
    npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_t::key_type k;
    npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_t::value_type v;
    npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.pd_pool_available_level = sms_voqs_total_packets_region;
    k.pd_voq_fill_level = sms_packets_region;

    // Read current value
    la_status read_status = tables[0]->lookup(k, entry_ptr);
    if (read_status != LA_STATUS_ENOTFOUND && read_status != LA_STATUS_SUCCESS) {
        return read_status;
    }
    if (read_status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    // Modify
    v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.drop_g.drop_green.drop_color[sms_age_region].value
        = (drop_color_level <= la_qos_color_e::GREEN);
    v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.drop_y.drop_yellow.drop_color[sms_age_region].value
        = (drop_color_level <= la_qos_color_e::YELLOW);
    v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.congestion_mark[sms_age_region].value = mark_ecn;
    v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.evict_to_dram[sms_age_region].value = evict_to_hbm;
    v.action = NPL_VOQ_CGM_SLICE_PD_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return_on_error(write_status);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                          la_quantization_region_t sms_packets_region,
                                                          la_quantization_region_t sms_age_region,
                                                          la_qos_color_e& out_drop_color_level,
                                                          bool& out_mark_ecn,
                                                          bool& out_evict_to_hbm) const
{
    start_api_getter_call();

    // Verify data correctness
    if (sms_voqs_total_packets_region >= LA_CGM_NUM_SMS_PACKETS_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (sms_packets_region >= SMS_NUM_PACKETS_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (sms_age_region >= SMS_NUM_AGE_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return do_get_sms_size_in_packets_behavior(
        sms_voqs_total_packets_region, sms_packets_region, sms_age_region, out_drop_color_level, out_mark_ecn, out_evict_to_hbm);
}

la_status
la_voq_cgm_profile_impl::do_get_sms_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                             la_quantization_region_t sms_packets_region,
                                                             la_quantization_region_t sms_age_region,
                                                             la_qos_color_e& out_drop_color_level,
                                                             bool& out_mark_ecn,
                                                             bool& out_evict_to_hbm) const
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_pd_consumption_lut_for_enq_table);

    // Prepare arguments
    npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_t::key_type k;
    npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.pd_pool_available_level = sms_voqs_total_packets_region;
    k.pd_voq_fill_level = sms_packets_region;

    // Read current value
    la_status read_status = tables[0]->lookup(k, entry_ptr);
    return_on_error(read_status);

    npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_t::value_type v;
    v = entry_ptr->value();

    // Fill the result
    if (v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.drop_g.drop_green.drop_color[sms_age_region].value) {
        out_drop_color_level = la_qos_color_e::GREEN;
    } else {
        if (v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.drop_y.drop_yellow.drop_color[sms_age_region].value) {
            out_drop_color_level = la_qos_color_e::YELLOW;
        } else {
            out_drop_color_level = la_qos_color_e::NONE;
        }
    }

    out_mark_ecn = v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.congestion_mark[sms_age_region].value;
    out_evict_to_hbm = v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.evict_to_dram[sms_age_region].value;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_bytes_drop_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                             const la_voq_sms_size_in_bytes_drop_val& val)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_bytes_drop_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                             la_voq_sms_size_in_bytes_drop_val& out_val) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_bytes_mark_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                             const la_voq_sms_size_in_bytes_mark_val& val)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_bytes_mark_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                             la_voq_sms_size_in_bytes_mark_val& out_val) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_dequeue_size_in_bytes_congestion_level(const la_voq_sms_dequeue_size_in_bytes_key& key,
                                                                        const la_voq_sms_dequeue_size_in_bytes_congestion_val& val)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_dequeue_size_in_bytes_congestion_level(
    const la_voq_sms_dequeue_size_in_bytes_key& key,
    la_voq_sms_dequeue_size_in_bytes_congestion_val& out_val) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_bytes_evict_behavior(const la_voq_sms_size_in_bytes_evict_key& key,
                                                              const la_voq_sms_size_in_bytes_evict_val& val)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_bytes_evict_behavior(const la_voq_sms_size_in_bytes_evict_key& key,
                                                              la_voq_sms_size_in_bytes_evict_val& out_val) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_packets_drop_behavior(const la_voq_sms_size_in_packets_key& key,
                                                               const la_voq_sms_size_in_packets_drop_val& val)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_packets_mark_behavior(const la_voq_sms_size_in_packets_key& key,
                                                               const la_voq_sms_size_in_packets_mark_val& val)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_packets_evict_behavior(const la_voq_sms_size_in_packets_key& key,
                                                                const la_voq_sms_size_in_packets_evict_val& val)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_dequeue_size_in_packets_congestion_level(
    const la_voq_sms_dequeue_size_in_packets_key& key,
    const la_voq_sms_dequeue_size_in_packets_congestion_val& val)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_dequeue_size_in_packets_congestion_level(
    const la_voq_sms_dequeue_size_in_packets_key& key,
    la_voq_sms_dequeue_size_in_packets_congestion_val& out_val) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_packets_drop_behavior(const la_voq_sms_size_in_packets_key& key,
                                                               la_voq_sms_size_in_packets_drop_val& out_val) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_packets_mark_behavior(const la_voq_sms_size_in_packets_key& key,
                                                               la_voq_sms_size_in_packets_mark_val& out_val) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_packets_evict_behavior(const la_voq_sms_size_in_packets_key& key,
                                                                la_voq_sms_size_in_packets_evict_val& out_val) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_dequeue_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                                la_quantization_region_t sms_bytes_region,
                                                                bool mark_ecn)
{
    start_api_call(
        "sms_voqs_total_bytes_region=", sms_voqs_total_bytes_region, "sms_bytes_region=", sms_bytes_region, "mark_ecn=", mark_ecn);

    // Verify data correctness
    if (sms_voqs_total_bytes_region >= LA_CGM_NUM_SMS_BYTES_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (sms_bytes_region >= SMS_NUM_BYTES_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    const size_t total_bytes_region_size_in_bits = 2;
    la_uint_t entry = (m_index << total_bytes_region_size_in_bits) | sms_voqs_total_bytes_region;

    auto nw_slices = get_slices(m_device, la_slice_mode_e::NETWORK);
    for (la_slice_id_t slice : nw_slices) {
        lld_register_sptr buffers_consumption_lut_for_deq_reg;
        if (slice < FIRST_HW_FABRIC_SLICE) {
            buffers_consumption_lut_for_deq_reg
                = (*m_device->m_pacific_tree->slice[slice]->pdvoq->buffers_consumption_lut_for_deq)[entry];
        } else {
            buffers_consumption_lut_for_deq_reg
                = (*m_device->m_pacific_tree->slice[slice]->fabric_pdvoq->buffers_consumption_lut_for_deq)[entry];
        }

        bit_vector bv;

        la_status status = m_device->m_ll_device->read_register(buffers_consumption_lut_for_deq_reg, bv);
        return_on_error(status);

        bv.set_bit(sms_bytes_region, mark_ecn);

        status = m_device->m_ll_device->write_register(buffers_consumption_lut_for_deq_reg, bv);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_sms_dequeue_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                                la_quantization_region_t sms_bytes_region,
                                                                bool& out_mark_ecn) const
{
    start_api_getter_call();
    la_slice_id_t rep_sid = m_device->first_active_slice_id();
    // Verify data correctness
    if (sms_voqs_total_bytes_region >= LA_CGM_NUM_SMS_BYTES_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (sms_bytes_region >= SMS_NUM_BYTES_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    const size_t total_bytes_region_size_in_bits = 2;
    la_uint_t entry = (m_index << total_bytes_region_size_in_bits) | sms_voqs_total_bytes_region;

    auto buffers_consumption_lut_for_deq_reg
        = (*m_device->m_pacific_tree->slice[rep_sid]->pdvoq->buffers_consumption_lut_for_deq)[entry];
    bit_vector bv;

    la_status status = m_device->m_ll_device->read_register(buffers_consumption_lut_for_deq_reg, bv);
    return_on_error(status);

    out_mark_ecn = bv.bit(sms_bytes_region);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_sms_dequeue_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                                  bool mark_ecn)
{
    start_api_call("sms_voqs_total_bytes_region=", sms_voqs_total_packets_region, "mark_ecn=", mark_ecn);

    // Verify data correctness
    if (sms_voqs_total_packets_region >= LA_CGM_NUM_SMS_PACKETS_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    const size_t total_packets_region_size_in_bits = 2;
    la_uint_t entry = (m_index << total_packets_region_size_in_bits) | sms_voqs_total_packets_region;

    auto nw_slices = get_slices(m_device, la_slice_mode_e::NETWORK);
    for (la_slice_id_t slice : nw_slices) {
        lld_register_sptr pd_consumption_lut_for_deq_reg;
        if (slice < FIRST_HW_FABRIC_SLICE) {
            pd_consumption_lut_for_deq_reg = m_device->m_pacific_tree->slice[slice]->pdvoq->pd_consumption_lut_for_deq;
        } else {
            pd_consumption_lut_for_deq_reg = m_device->m_pacific_tree->slice[slice]->fabric_pdvoq->pd_consumption_lut_for_deq;
        }

        bit_vector bv;

        la_status status = m_device->m_ll_device->read_register(pd_consumption_lut_for_deq_reg, bv);
        return_on_error(status);

        bv.set_bit(entry, mark_ecn);

        status = m_device->m_ll_device->write_register(pd_consumption_lut_for_deq_reg, bv);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_sms_dequeue_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                                  bool& out_mark_ecn) const
{
    start_api_getter_call();

    // Verify data correctness
    if (sms_voqs_total_packets_region >= LA_CGM_NUM_SMS_PACKETS_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    const size_t total_packets_region_size_in_bits = 2;
    la_uint_t entry = (m_index << total_packets_region_size_in_bits) | sms_voqs_total_packets_region;

    auto pd_consumption_lut_for_deq_reg = m_device->m_pacific_tree->slice[0]->pdvoq->pd_consumption_lut_for_deq;
    bit_vector bv;

    la_status status = m_device->m_ll_device->read_register(pd_consumption_lut_for_deq_reg, bv);
    return_on_error(status);

    out_mark_ecn = bv.bit(entry);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_hbm_size_in_blocks_behavior(la_quantization_region_t hbm_blocks_by_voq_region,
                                                         la_quantization_region_t hbm_pool_free_blocks_region,
                                                         la_qos_color_e drop_color_level,
                                                         bool mark_ecn)
{
    start_api_call("hbm_blocks_by_voq_region=",
                   hbm_blocks_by_voq_region,
                   "hbm_pool_free_blocks_region=",
                   hbm_pool_free_blocks_region,
                   "drop_color_level=",
                   drop_color_level,
                   "mark_ecn=",
                   mark_ecn);

    // Verify data correctness

    // Last region is always drop
    if (hbm_blocks_by_voq_region >= LA_CGM_NUM_HBM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS - 1) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (hbm_pool_free_blocks_region >= LA_CGM_NUM_HBM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status status
        = do_set_hbm_size_in_blocks_behavior(hbm_blocks_by_voq_region, hbm_pool_free_blocks_region, drop_color_level, mark_ecn);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::do_set_hbm_size_in_blocks_behavior(la_quantization_region_t hbm_blocks_by_voq_region,
                                                            la_quantization_region_t hbm_pool_free_blocks_region,
                                                            la_qos_color_e drop_color_level,
                                                            bool mark_ecn)
{
    // Choose table
    const auto& table(m_device->m_tables.hmc_cgm_cgm_lut_table);

    // Prepare arguments
    npl_hmc_cgm_cgm_lut_table_t::key_type k;
    npl_hmc_cgm_cgm_lut_table_t::value_type v;
    npl_hmc_cgm_cgm_lut_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.queue_size_level = hbm_blocks_by_voq_region;
    k.shared_pool_th_level = hbm_pool_free_blocks_region;

    // Modify
    v.payloads.hmc_cgm_cgm_lut_results.dp0 = (drop_color_level <= la_qos_color_e::GREEN);
    v.payloads.hmc_cgm_cgm_lut_results.dp1 = (drop_color_level <= la_qos_color_e::YELLOW);
    v.payloads.hmc_cgm_cgm_lut_results.mark = mark_ecn;
    v.action = NPL_HMC_CGM_CGM_LUT_TABLE_ACTION_WRITE;

    // Write
    la_status write_status = table->set(k, v, entry_ptr);
    return write_status;
}

la_status
la_voq_cgm_profile_impl::get_hbm_size_in_blocks_behavior(la_quantization_region_t hbm_blocks_by_voq_region,
                                                         la_quantization_region_t hbm_pool_free_blocks_region,
                                                         la_qos_color_e& out_drop_color_level,
                                                         bool& out_mark_ecn) const
{
    start_api_getter_call();

    // Verify data correctness
    if (hbm_blocks_by_voq_region >= LA_CGM_NUM_HBM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (hbm_pool_free_blocks_region >= LA_CGM_NUM_HBM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // Choose table
    const auto& table(m_device->m_tables.hmc_cgm_cgm_lut_table);

    // Prepare arguments
    npl_hmc_cgm_cgm_lut_table_t::key_type k;
    npl_hmc_cgm_cgm_lut_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.queue_size_level = hbm_blocks_by_voq_region;
    k.shared_pool_th_level = hbm_pool_free_blocks_region;

    // Read current value
    la_status status = table->lookup(k, entry_ptr);
    return_on_error(status);

    npl_hmc_cgm_cgm_lut_table_t::value_type v = entry_ptr->value();
    if (v.payloads.hmc_cgm_cgm_lut_results.dp0) {
        out_drop_color_level = la_qos_color_e::GREEN;
    } else {
        if (v.payloads.hmc_cgm_cgm_lut_results.dp1) {
            out_drop_color_level = la_qos_color_e::YELLOW;
        } else {
            out_drop_color_level = la_qos_color_e::NONE;
        }
    }

    out_mark_ecn = v.payloads.hmc_cgm_cgm_lut_results.mark;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_associated_hbm_pool(la_cgm_hbm_pool_id_t hbm_pool_id)
{
    start_api_call("hbm_pool_id=", hbm_pool_id);

    // Verify data correctness
    la_uint64_t max_hbm_pool_id;
    m_device->get_limit(limit_type_e::DEVICE__NUM_CGM_HBM_POOLS, max_hbm_pool_id);
    if (hbm_pool_id >= max_hbm_pool_id) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // Choose table
    const auto& table(m_device->m_tables.hmc_cgm_profile_global_table);

    // Prepare arguments
    npl_hmc_cgm_profile_global_table_t::key_type k;
    npl_hmc_cgm_profile_global_table_t::value_type v;
    npl_hmc_cgm_profile_global_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;

    // Read current value
    la_status read_status = table->lookup(k, entry_ptr);
    if (read_status != LA_STATUS_ENOTFOUND && read_status != LA_STATUS_SUCCESS) {
        return read_status;
    }
    if (read_status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    // Modify
    v.payloads.hmc_cgm_profile_global_results.shared_pool_id = hbm_pool_id;
    v.action = NPL_HMC_CGM_PROFILE_GLOBAL_TABLE_ACTION_WRITE;

    // Write
    la_status write_status;
    if (read_status == LA_STATUS_SUCCESS) {
        write_status = entry_ptr->update(v);
        return write_status;
    }
    write_status = table->insert(k, v, entry_ptr);
    return_on_error(write_status);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_associated_hbm_pool(la_cgm_hbm_pool_id_t& out_hbm_pool_id) const
{
    start_api_getter_call();

    // Choose table
    const auto& table(m_device->m_tables.hmc_cgm_profile_global_table);

    // Prepare arguments
    npl_hmc_cgm_profile_global_table_t::key_type k;
    npl_hmc_cgm_profile_global_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;

    // Read current value
    la_status status = table->lookup(k, entry_ptr);
    return_on_error(status);

    npl_hmc_cgm_profile_global_table_t::value_type v = entry_ptr->value();
    out_hbm_pool_id = v.payloads.hmc_cgm_profile_global_results.shared_pool_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_averaging_configuration(double ema_coefficient, const wred_blocks_quantization_thresholds& thresholds)
{
    start_api_call("ema_coefficient=", ema_coefficient, "thresholds=", thresholds);

    // Verify data correctness
    for (uint32_t index = 0; index < array_size(thresholds.thresholds) - 1; index++) {
        if (thresholds.thresholds[index] > thresholds.thresholds[index + 1]) {
            return LA_STATUS_EINVAL;
        }
    }

    la_uint64_t max_threshold;
    m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_HBM_SIZE, max_threshold);
    if (thresholds.thresholds[array_size(thresholds.thresholds) - 1] > max_threshold) {
        return LA_STATUS_EINVAL;
    }

    if (0 > ema_coefficient || ema_coefficient > 1) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t weight;
    la_uint64_t max_weight = (1 << WRED_EMA_WEIGHT_WIDTH) - 1;
    if (0 == ema_coefficient) {
        weight = max_weight;
    } else {
        weight = (-1 * std::log2(ema_coefficient));
        if (weight > max_weight) {
            weight = max_weight;
        }
    }

    // Choose table
    const auto& table(m_device->m_tables.hmc_cgm_profile_global_table);

    // Prepare arguments
    npl_hmc_cgm_profile_global_table_t::key_type k;
    npl_hmc_cgm_profile_global_table_t::value_type v;
    npl_hmc_cgm_profile_global_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;

    // Read current value
    la_status read_status = table->lookup(k, entry_ptr);
    if (read_status != LA_STATUS_ENOTFOUND && read_status != LA_STATUS_SUCCESS) {
        return read_status;
    }

    if (read_status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    // Modify
    v.payloads.hmc_cgm_profile_global_results.wred_ema_weight = weight;
    for (uint32_t index = 0; index < array_size(thresholds.thresholds); index++) {
        v.payloads.hmc_cgm_profile_global_results.wred_region_borders[index].value = thresholds.thresholds[index];
    }

    v.action = NPL_HMC_CGM_PROFILE_GLOBAL_TABLE_ACTION_WRITE;

    // Write
    la_status write_status;
    if (read_status == LA_STATUS_SUCCESS) {
        write_status = entry_ptr->update(v);
        return write_status;
    }

    write_status = table->insert(k, v, entry_ptr);
    return_on_error(write_status);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_averaging_configuration(double& out_ema_coefficient,
                                                     wred_blocks_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();

    // Choose table
    const auto& table(m_device->m_tables.hmc_cgm_profile_global_table);

    // Prepare arguments
    npl_hmc_cgm_profile_global_table_t::key_type k;
    npl_hmc_cgm_profile_global_table_t::value_type v;
    npl_hmc_cgm_profile_global_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;

    // Read value
    la_status read_status = table->lookup(k, entry_ptr);
    return_on_error(read_status);

    v = entry_ptr->value();

    // Modify output
    out_ema_coefficient = std::exp2(-v.payloads.hmc_cgm_profile_global_results.wred_ema_weight);
    for (uint32_t index = 0; index < array_size(out_thresholds.thresholds); index++) {
        out_thresholds.thresholds[index] = v.payloads.hmc_cgm_profile_global_results.wred_region_borders[index].value;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_averaging_configuration(double ema_coefficient, const la_voq_cgm_quantization_thresholds& thresholds)
{
    start_api_call("ema_coefficient=", ema_coefficient, "thresholds=", thresholds);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_averaging_configuration(double& out_ema_coefficient,
                                                     la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_wred_configuration(wred_action_e action, const wred_regions_probabilties& action_probabilities)
{

    start_api_call("action=", action, "action_probabilities=", action_probabilities);

    // Verify data correctness
    for (uint32_t index = 0; index < array_size(action_probabilities.probabilities); index++) {
        // All probabilities should be 0 <= pr <= 1
        if (action_probabilities.probabilities[index] < 0 || action_probabilities.probabilities[index] > 1) {
            return LA_STATUS_EINVAL;
        }
    }

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_dram_cgm_profile_table);

    // Prepare arguments
    npl_voq_cgm_slice_dram_cgm_profile_table_t::key_type k;
    npl_voq_cgm_slice_dram_cgm_profile_table_t::value_type v;

    k.profile_id.value = m_index;
    v.payloads.voq_cgm_slice_dram_cgm_profile_result.wred_action = la_2_npl_wred_action(action);
    la_uint64_t max_pr = (1 << WRED_PROBABILITY_REGION_WIDTH) - 1;
    for (uint32_t index = 0; index < array_size(action_probabilities.probabilities); index++) {
        v.payloads.voq_cgm_slice_dram_cgm_profile_result.wred_probability_region[index].value
            = action_probabilities.probabilities[index] * max_pr;
    }
    v.action = NPL_VOQ_CGM_SLICE_DRAM_CGM_PROFILE_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return_on_error(write_status);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_wred_configuration(wred_action_e& out_action,
                                                wred_regions_probabilties& out_action_probabilities) const
{
    start_api_getter_call();

    // Choose table
    const auto& table(m_device->m_tables.voq_cgm_slice_dram_cgm_profile_table[0]);

    // Prepare arguments
    npl_voq_cgm_slice_dram_cgm_profile_table_t::key_type k;
    npl_voq_cgm_slice_dram_cgm_profile_table_t::value_type v;
    npl_voq_cgm_slice_dram_cgm_profile_table_t::entry_pointer_type entry_ptr{};

    k.profile_id.value = m_index;

    // Read value
    la_status read_status = table->lookup(k, entry_ptr);
    return_on_error(read_status);

    v = entry_ptr->value();

    // Modify output
    double max_pr = ((1 << WRED_PROBABILITY_REGION_WIDTH) - 1);
    out_action = npl_2_la_wred_action(v.payloads.voq_cgm_slice_dram_cgm_profile_result.wred_action);
    for (uint32_t index = 0; index < array_size(out_action_probabilities.probabilities); index++) {
        out_action_probabilities.probabilities[index]
            = v.payloads.voq_cgm_slice_dram_cgm_profile_result.wred_probability_region[index].value / max_pr;
    }

    return LA_STATUS_SUCCESS;
}
la_status
la_voq_cgm_profile_impl::set_hbm_wred_drop_configuration(const la_cgm_wred_key& key, const la_cgm_wred_drop_val& val)
{
    start_api_call("key=", key, "val=", val);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_hbm_wred_drop_configuration(const la_cgm_wred_key& key, la_cgm_wred_drop_val& out_val) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_hbm_wred_mark_ecn_configuration(const la_cgm_wred_key& key, const la_cgm_wred_mark_ecn_val& val)
{
    start_api_call("key=", key, "val=", val);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_hbm_wred_mark_ecn_configuration(const la_cgm_wred_key& key, la_cgm_wred_mark_ecn_val& out_val) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_cgm_evicted_profile_mapping(la_voq_cgm_evicted_profile* evicted_profile)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_cgm_evicted_profile_mapping(la_voq_cgm_evicted_profile*& out_evicted_profile) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::clear_cgm_evicted_profile_mapping()
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_evict_behavior(const la_voq_sms_evict_key& key, const la_voq_sms_evict_val& val)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_evict_behavior(const la_voq_sms_evict_key& key, la_voq_sms_evict_val& out_val) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_wred_drop_probability(const la_voq_sms_wred_drop_probability_selector_key& key,
                                                       const la_voq_sms_wred_drop_probability_selector_drop_val& val)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_wred_drop_probability(const la_voq_sms_wred_drop_probability_selector_key& key,
                                                       la_voq_sms_wred_drop_probability_selector_drop_val& out_val) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_wred_mark_probability(const la_voq_sms_wred_mark_probability_selector_key& key,
                                                       const la_voq_sms_wred_mark_probability_selector_mark_val& val)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_wred_mark_probability(const la_voq_sms_wred_mark_probability_selector_key& key,
                                                       la_voq_sms_wred_mark_probability_selector_mark_val& out_val) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_hbm_size_in_blocks_drop_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                              const la_cgm_hbm_size_in_blocks_drop_val& val)
{
    start_api_call("key=", key, "val=", val);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_hbm_size_in_blocks_drop_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                              la_cgm_hbm_size_in_blocks_drop_val& out_val) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_hbm_size_in_blocks_mark_ecn_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                                  const la_cgm_hbm_size_in_blocks_mark_ecn_val& val)
{
    start_api_call("key=", key, "val=", val);

    return LA_STATUS_ENOTIMPLEMENTED;
}
la_status
la_voq_cgm_profile_impl::get_hbm_size_in_blocks_mark_ecn_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                                  la_cgm_hbm_size_in_blocks_mark_ecn_val& out_val) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_hbm_dequeue_size_in_blocks_congestion_level(
    const la_cgm_hbm_dequeue_size_in_blocks_key& key,
    const la_cgm_hbm_dequeue_size_in_blocks_congestion_val& val)
{
    start_api_call("key=", key, "val=", val);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_hbm_dequeue_size_in_blocks_congestion_level(
    const la_cgm_hbm_dequeue_size_in_blocks_key& key,
    la_cgm_hbm_dequeue_size_in_blocks_congestion_val& out_val) const
{
    start_api_getter_call("key=", key);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_fcn_configuration(bool enabled, const wred_regions_probabilties& action_probabilities)
{

    start_api_call("enabled=", enabled, "action_probabilities=", action_probabilities);

    // Verify data correctness
    for (uint32_t index = 0; index < array_size(action_probabilities.probabilities); index++) {
        // All probabilities should be 0 <= pr <= 1
        if (action_probabilities.probabilities[index] < 0 || action_probabilities.probabilities[index] > 1) {
            return LA_STATUS_EINVAL;
        }
    }

    // Choose table
    const auto& table(m_device->m_tables.hmc_cgm_profile_global_table);

    // Prepare arguments
    npl_hmc_cgm_profile_global_table_t::key_type k;
    npl_hmc_cgm_profile_global_table_t::value_type v;
    npl_hmc_cgm_profile_global_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;

    // Read current value
    la_status status = table->lookup(k, entry_ptr);
    if (status != LA_STATUS_ENOTFOUND && status != LA_STATUS_SUCCESS) {
        return status;
    }

    if (status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    // Modify
    la_uint64_t max_pr = (1 << WRED_PROBABILITY_REGION_WIDTH) - 1;

    v.payloads.hmc_cgm_profile_global_results.wred_fcn_enable = enabled;
    for (uint32_t index = 0; index < array_size(action_probabilities.probabilities); index++) {
        v.payloads.hmc_cgm_profile_global_results.wred_fcn_probability_region[index].value
            = action_probabilities.probabilities[index] * max_pr;
    }
    v.action = NPL_HMC_CGM_PROFILE_GLOBAL_TABLE_ACTION_WRITE;

    // Write
    la_status write_status = table->set(k, v, entry_ptr);
    return_on_error(write_status);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_fcn_configuration(bool& out_enabled, wred_regions_probabilties& out_action_probabilities) const
{
    start_api_getter_call();

    // Choose table
    const auto& table(m_device->m_tables.hmc_cgm_profile_global_table);

    // Prepare arguments
    npl_hmc_cgm_profile_global_table_t::key_type k;
    npl_hmc_cgm_profile_global_table_t::value_type v;
    npl_hmc_cgm_profile_global_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;

    // Read value
    la_status status = table->lookup(k, entry_ptr);
    return_on_error(status);

    v = entry_ptr->value();

    // Modify output
    double max_pr = ((1 << WRED_PROBABILITY_REGION_WIDTH) - 1);
    out_enabled = v.payloads.hmc_cgm_profile_global_results.wred_fcn_enable;
    for (uint32_t index = 0; index < array_size(out_action_probabilities.probabilities); index++) {
        out_action_probabilities.probabilities[index]
            = v.payloads.hmc_cgm_profile_global_results.wred_fcn_probability_region[index].value / max_pr;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_fcn_configuration(bool enabled, const std::vector<double>& action_probabilities)
{
    start_api_call("enabled=", enabled, "action_probabilities=", action_probabilities);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_fcn_configuration(bool& out_enabled, std::vector<double>& out_action_probabilities) const
{
    start_api_getter_call();
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::configure_input_blocking_threshold(bool is_mc)
{
    // Drop profile config is done in la_device_impl::configure_voq_cgm_drop_profile() and must not change
    dassert_crit(m_index != la_device_impl::VOQ_CGM_DROP_PROFILE);

    ics_slice_set_queue_blocking_th_reg_register reg;
    reg.fields.set_queue_blocking_th = is_mc ? INPUT_BLOCKING_THRESHOLD_MC : INPUT_BLOCKING_THRESHOLD_UC;

    for (size_t i = 0; i < array_size(m_device->m_pacific_tree->slice); i++) {
        la_status status = m_device->m_ll_device->write_register(
            (*m_device->m_pacific_tree->slice[i]->ics->set_queue_blocking_th_reg)[m_index], reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::attach_voq(bool is_mc)
{
    // Validate that there are users iff the pd counter is set to either UC/MC
    dassert_crit((m_use_count == 0) == (m_voq_cgm_pd_counter == VOQ_CGM_PD_COUNTER_INVALID));

    npl_voq_cgm_pd_counter_e requested_counter = is_mc ? NPL_VOQ_CGM_PD_COUNTER_MC : NPL_VOQ_CGM_PD_COUNTER_UC;

    // Sanity

    // If CGM profile is already set to either UC/MC and the new counter type differs
    if ((m_voq_cgm_pd_counter != VOQ_CGM_PD_COUNTER_INVALID) && (m_voq_cgm_pd_counter != requested_counter)) {
        log_err(HLD, "VOQ CGM profile cannot be shared between both UC and MC VOQs.");
        return LA_STATUS_EBUSY;
    }

    if (is_mc == true) {
        bool valid_for_mc_voq = is_valid_for_mc_voq();

        if (valid_for_mc_voq == false) {
            log_err(HLD, "A MC VOQ cannot be evicted to the HBM. The VOQ CGM profile is configured to evict to HBM.");
            return LA_STATUS_EINVAL;
        }
    }

    la_status status = configure_input_blocking_threshold(is_mc);
    return_on_error(status);

    // If the voq_cgm_pd_counter type was already set, just increase use count
    if (m_voq_cgm_pd_counter != VOQ_CGM_PD_COUNTER_INVALID) {
        m_use_count++;

        return LA_STATUS_SUCCESS;
    }

    m_voq_cgm_pd_counter = requested_counter;
    m_use_count++;

    status = configure_voq_cgm_slice_slice_cgm_profile();

    return status;
}

la_status
la_voq_cgm_profile_impl::detach_voq()
{
    dassert_crit(m_use_count > 0);

    m_use_count--;

    if (m_use_count > 0) {
        return LA_STATUS_SUCCESS;
    }

    m_voq_cgm_pd_counter = VOQ_CGM_PD_COUNTER_INVALID;

    la_status status = teardown_voq_cgm_slice_slice_cgm_profile();

    return status;
}

bool
la_voq_cgm_profile_impl::is_valid_for_mc_voq() const
{
    la_status status;
    la_qos_color_e drop_color_level;
    bool mark_ecn;
    bool evict_to_hbm;

    // Eviction to HBM is not a valid config for a MC voq. Verify all configuration that might evict to HBM.

    for (la_quantization_region_t sms_voqs_total_bytes_region = 0;
         sms_voqs_total_bytes_region < LA_CGM_NUM_SMS_BYTES_QUANTIZATION_REGIONS;
         sms_voqs_total_bytes_region++) {
        for (la_quantization_region_t sms_bytes_region = 0; sms_bytes_region < SMS_NUM_BYTES_QUANTIZATION_REGIONS;
             sms_bytes_region++) {
            for (la_quantization_region_t sms_age_region = 0; sms_age_region < SMS_NUM_AGE_QUANTIZATION_REGIONS; sms_age_region++) {
                for (la_quantization_region_t hbm_total_number_of_voqs_region = 0;
                     hbm_total_number_of_voqs_region < LA_CGM_NUM_HBM_NUMBER_OF_VOQS_QUANTIZATION_REGIONS;
                     hbm_total_number_of_voqs_region++) {

                    status = do_get_sms_size_in_bytes_behavior(sms_voqs_total_bytes_region,
                                                               sms_bytes_region,
                                                               sms_age_region,
                                                               hbm_total_number_of_voqs_region,
                                                               drop_color_level,
                                                               mark_ecn,
                                                               evict_to_hbm);
                    if (status == LA_STATUS_ENOTFOUND) {
                        // If the user didn't config anything, assume that evict_to_hbm is false.
                        continue;
                    }

                    // This should never fail
                    dassert_crit(status == LA_STATUS_SUCCESS);

                    if (evict_to_hbm == true) {
                        return false;
                    }
                }
            }
        }
    }

    for (la_quantization_region_t sms_voqs_total_packets_region = 0;
         sms_voqs_total_packets_region < LA_CGM_NUM_SMS_PACKETS_QUANTIZATION_REGIONS;
         sms_voqs_total_packets_region++) {
        for (la_quantization_region_t sms_packets_region = 0; sms_packets_region < SMS_NUM_PACKETS_QUANTIZATION_REGIONS;
             sms_packets_region++) {
            for (la_quantization_region_t sms_age_region = 0; sms_age_region < SMS_NUM_AGE_QUANTIZATION_REGIONS; sms_age_region++) {

                status = do_get_sms_size_in_packets_behavior(
                    sms_voqs_total_packets_region, sms_packets_region, sms_age_region, drop_color_level, mark_ecn, evict_to_hbm);

                if (status == LA_STATUS_ENOTFOUND) {
                    // If the user didn't config anything, assume that evict_to_hbm is false.
                    continue;
                }

                // This should never fail
                dassert_crit(status == LA_STATUS_SUCCESS);

                if (evict_to_hbm == true) {
                    return false;
                }
            }
        }
    }

    // Didn't find HBM eviction - valid for MC VOQs
    return true;
}

la_status
la_voq_cgm_profile_impl::configure_voq_cgm_slice_slice_cgm_profile()
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_slice_cgm_profile_table);

    // Prepare arguments
    npl_voq_cgm_slice_slice_cgm_profile_table_t::key_type k;
    npl_voq_cgm_slice_slice_cgm_profile_table_t::value_type v;

    k.profile_id.value = m_index;
    v.action = NPL_VOQ_CGM_SLICE_SLICE_CGM_PROFILE_TABLE_ACTION_WRITE;
    v.payloads.voq_cgm_slice_slice_cgm_profile_result.counter_id = m_voq_cgm_pd_counter;

    la_status status
        = per_slice_tables_insert(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);

    return status;
}

la_status
la_voq_cgm_profile_impl::teardown_voq_cgm_slice_slice_cgm_profile()
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_slice_cgm_profile_table);

    // Prepare arguments
    npl_voq_cgm_slice_slice_cgm_profile_table_t::key_type k;

    k.profile_id.value = m_index;

    la_status status = per_slice_tables_erase(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k);

    return status;
}

} // namespace silicon_one
