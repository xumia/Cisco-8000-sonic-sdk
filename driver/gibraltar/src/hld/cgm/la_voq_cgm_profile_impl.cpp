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
#include "la_voq_cgm_evicted_profile_impl.h"

#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
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

la_voq_cgm_profile_impl::la_voq_cgm_profile_impl(const la_device_impl_wptr& device)
    : m_device(device), m_voq_cgm_pd_counter(VOQ_CGM_PD_COUNTER_INVALID), m_use_count(0)
{
    m_table_first_instance = 99999; // invalid - anything over 7
}

la_voq_cgm_profile_impl::~la_voq_cgm_profile_impl()
{
}

la_status
la_voq_cgm_profile_impl::initialize_probability_profiles()
{
    la_uint64_t num_packet_size_regions;
    la_status status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS, num_packet_size_regions);
    return_on_error(status);

    la_uint64_t num_drop_probability_levels;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_DROP_PROBABILITY_LEVELS, num_drop_probability_levels);
    return_on_error(status);

    // drop_probability_levels silicon_one::LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_ADMIT and
    // silicon_one::LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP
    // implicitly define probabilites to 0.0 and 1.0 respectively and are not inserted in probability profile.
    la_uint64_t num_drop_prob_profiles = num_drop_probability_levels - 2;

    la_uint64_t num_mark_probability_levels;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_MARK_PROBABILITY_LEVELS, num_mark_probability_levels);
    return_on_error(status);

    // mark_ecn_probability_level silicon_one::LA_CGM_SMS_BYTES_MARK_PROBABILITY_LEVEL_DONT_MARK impicitly defines
    // probability 0.0 and is not inserted in probability profile.
    la_uint64_t num_mark_prob_profiles = num_mark_probability_levels - 1;

    m_drop_prob_select_profile.resize(num_packet_size_regions);
    for (size_t packet_size_region = 0; packet_size_region < m_drop_prob_select_profile.size(); packet_size_region++) {
        m_drop_prob_select_profile[packet_size_region].resize(num_drop_prob_profiles);
        for (size_t drop_prob_select_region = 0; drop_prob_select_region < num_drop_prob_profiles; drop_prob_select_region++) {
            m_drop_prob_select_profile[packet_size_region][drop_prob_select_region].resize(NUM_DROP_MARK_COLORS);
        }
    }

    m_mark_prob_select_profile.resize(num_packet_size_regions);
    for (size_t packet_size_region = 0; packet_size_region < m_mark_prob_select_profile.size(); packet_size_region++) {
        m_mark_prob_select_profile[packet_size_region].resize(num_mark_prob_profiles);
        for (size_t mark_prob_select_region = 0; mark_prob_select_region < num_mark_prob_profiles; mark_prob_select_region++) {
            m_mark_prob_select_profile[packet_size_region][mark_prob_select_region].resize(NUM_DROP_MARK_COLORS);
        }
    }

    la_uint64_t num_hbm_blocks_by_voq_regions;
    status
        = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_REGIONS, num_hbm_blocks_by_voq_regions);
    return_on_error(status);

    m_drop_dram_wred_lut.resize(num_hbm_blocks_by_voq_regions);
    for (size_t blocks_by_voq_region = 0; blocks_by_voq_region < m_drop_dram_wred_lut.size(); blocks_by_voq_region++) {
        m_drop_dram_wred_lut[blocks_by_voq_region].resize(num_packet_size_regions);
        for (size_t packet_size_region = 0; packet_size_region < m_drop_dram_wred_lut[blocks_by_voq_region].size();
             packet_size_region++) {
            m_drop_dram_wred_lut[blocks_by_voq_region][packet_size_region].resize(NUM_DROP_MARK_COLORS);
        }
    }

    m_mark_dram_wred_lut.resize(num_hbm_blocks_by_voq_regions);
    for (size_t blocks_by_voq_region = 0; blocks_by_voq_region < m_mark_dram_wred_lut.size(); blocks_by_voq_region++) {
        m_mark_dram_wred_lut[blocks_by_voq_region].resize(num_packet_size_regions);
        for (size_t packet_size_region = 0; packet_size_region < m_mark_dram_wred_lut[blocks_by_voq_region].size();
             packet_size_region++) {
            m_mark_dram_wred_lut[blocks_by_voq_region][packet_size_region].resize(NUM_DROP_MARK_COLORS);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::initialize(la_object_id_t oid, uint64_t voq_cgm_profile_index)
{
    m_oid = oid;
    m_index = voq_cgm_profile_index;
    m_table_first_instance = m_device->first_active_slice_id();

    la_status status = initialize_probability_profiles();
    return_on_error(status);

    // Init VOQ CGM profile to drop all packet in last PD/buff threshold
    status = set_defaults();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

double
la_voq_cgm_profile_impl::round_up_probability_to_precision(double probability) const
{
    double precision;

    m_device->get_precision(la_precision_type_e::VOQ_CGM_PROBABILITY_PRECISION, precision);

    double rounded_prob = (double)((uint64_t)ceil(probability / precision)) * precision;

    return rounded_prob;
}

la_status
la_voq_cgm_profile_impl::set_defaults()
{
    la_status status;

    la_uint64_t num_sms_total_bytes_regions;
    status = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_total_bytes_regions);
    return_on_error(status);

    la_uint64_t num_sms_age_regions;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);
    return_on_error(status);

    la_uint64_t num_sms_voq_bytes_regions;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);
    return_on_error(status);

    for (la_quantization_region_t sms_voqs_total_bytes_region = 0; sms_voqs_total_bytes_region < num_sms_total_bytes_regions;
         sms_voqs_total_bytes_region++) {
        for (la_quantization_region_t sms_age_region = 0; sms_age_region < num_sms_age_regions; sms_age_region++) {
            status = do_set_sms_size_in_bytes_color_behavior(
                sms_voqs_total_bytes_region,
                num_sms_voq_bytes_regions - 1,
                sms_age_region,
                la_qos_color_e::GREEN,
                LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP /* Always drop */ /* drop_probability_level */,
                LA_CGM_SMS_BYTES_MARK_PROBABILITY_LEVEL_DONT_MARK /* Don't mark */ /* mark_ecn_probability_level */);
            return_on_error(status);
            status = do_set_sms_size_in_bytes_color_behavior(
                sms_voqs_total_bytes_region,
                num_sms_voq_bytes_regions - 1,
                sms_age_region,
                la_qos_color_e::YELLOW,
                LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP /* Always drop */ /* drop_probability_level */,
                LA_CGM_SMS_BYTES_MARK_PROBABILITY_LEVEL_DONT_MARK /* Don't mark */ /* mark_ecn_probability_level */);
            return_on_error(status);

            status = do_set_sms_size_in_bytes_evict_behavior(
                sms_voqs_total_bytes_region, num_sms_voq_bytes_regions - 1, sms_age_region, false /* evict_to_hbm */);
            return_on_error(status);
        }
    }

    la_uint64_t num_hbm_pool_free_blocks_regions;
    status = m_device->get_limit(limit_type_e::DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS,
                                 num_hbm_pool_free_blocks_regions);
    return_on_error(status);

    la_uint64_t num_hbm_blocks_by_voq_regions;
    status = m_device->get_limit(limit_type_e::DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS, num_hbm_blocks_by_voq_regions);
    return_on_error(status);

    la_uint64_t num_hbm_queue_delay_regions;
    status = m_device->get_limit(limit_type_e::DEVICE__HBM_NUM_VOQ_AGE_QUANTIZATION_REGIONS, num_hbm_queue_delay_regions);
    return_on_error(status);

    for (la_quantization_region_t hbm_pool_free_blocks_region = 0; hbm_pool_free_blocks_region < num_hbm_pool_free_blocks_regions;
         hbm_pool_free_blocks_region++) {
        la_cgm_hbm_size_in_blocks_key key{
            num_hbm_blocks_by_voq_regions - 1, num_hbm_queue_delay_regions - 1, hbm_pool_free_blocks_region};

        status = do_set_hbm_size_in_blocks_behavior(key, true /* is_drop_action */ /* sets drop behavior */, la_qos_color_e::GREEN);
        return_on_error(status);
        status = do_set_hbm_size_in_blocks_behavior(
            key, false /* is_drop_action */ /* sets mark ECN behavior */, la_qos_color_e::NONE);
        return_on_error(status);
    }

    // Set Evicted profile mapping to default.
    const auto& default_evicted_profile = m_device->m_voq_cgm_evicted_profiles[la_device_impl::VOQ_CGM_DEFAULT_EVICTED_PROFILE];
    status = do_set_cgm_evicted_profile_mapping(default_evicted_profile);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::do_reset_wred_probability_profile(voq_prob_profile_t& prob_profile)
{
    if (prob_profile == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    size_t use_count = prob_profile.use_count();
    uint64_t old_id = prob_profile->id();

    prob_profile.reset();

    // Clear ProbLUT index if this was the last probability profile using it.
    if (use_count == 1) {
        la_status status = m_device->m_voq_cgm_handler->set_cgm_wred_probabilities(old_id, 0.0 /* probability */);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::destroy()
{
    // Release probability profiles.
    for (size_t packet_size_region = 0; packet_size_region < m_drop_prob_select_profile.size(); packet_size_region++) {
        for (size_t drop_prob_select_region = 0; drop_prob_select_region < m_drop_prob_select_profile[packet_size_region].size();
             drop_prob_select_region++) {
            for (size_t color = 0; color < m_drop_prob_select_profile[packet_size_region][drop_prob_select_region].size();
                 color++) {
                do_reset_wred_probability_profile(m_drop_prob_select_profile[packet_size_region][drop_prob_select_region][color]);
            }
        }
    }

    for (size_t packet_size_region = 0; packet_size_region < m_mark_prob_select_profile.size(); packet_size_region++) {
        for (size_t mark_prob_select_region = 0; mark_prob_select_region < m_mark_prob_select_profile[packet_size_region].size();
             mark_prob_select_region++) {
            for (size_t color = 0; color < m_mark_prob_select_profile[packet_size_region][mark_prob_select_region].size();
                 color++) {
                do_reset_wred_probability_profile(m_mark_prob_select_profile[packet_size_region][mark_prob_select_region][color]);
            }
        }
    }

    for (size_t blocks_by_voq_region = 0; blocks_by_voq_region < m_drop_dram_wred_lut.size(); blocks_by_voq_region++) {
        for (size_t packet_size_region = 0; packet_size_region < m_drop_dram_wred_lut[blocks_by_voq_region].size();
             packet_size_region++) {
            for (size_t color = 0; color < m_drop_dram_wred_lut[blocks_by_voq_region][packet_size_region].size(); color++) {
                do_reset_wred_probability_profile(m_drop_dram_wred_lut[blocks_by_voq_region][packet_size_region][color]);
            }
        }
    }

    for (size_t blocks_by_voq_region = 0; blocks_by_voq_region < m_mark_dram_wred_lut.size(); blocks_by_voq_region++) {
        for (size_t packet_size_region = 0; packet_size_region < m_mark_dram_wred_lut[blocks_by_voq_region].size();
             packet_size_region++) {
            for (size_t color = 0; color < m_mark_dram_wred_lut[blocks_by_voq_region][packet_size_region].size(); color++) {
                do_reset_wred_probability_profile(m_mark_dram_wred_lut[blocks_by_voq_region][packet_size_region][color]);
            }
        }
    }

    // Remove object dependencies.
    if (m_evicted_profile) {
        m_device->remove_object_dependency(m_evicted_profile, this);
    }

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
la_voq_cgm_profile_impl::set_sms_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);

    // Verify data correctness
    la_status status;
    status = validate_quantization_thresholds(m_device,
                                              thresholds.thresholds,
                                              limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS,
                                              limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_SMS_BYTES);
    return_on_error(status);

    return do_set_sms_bytes_quantization(thresholds);
}

la_status
la_voq_cgm_profile_impl::set_sms_bytes_quantization(const sms_bytes_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::do_set_sms_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_buff_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_t::value_type v;

    k.profile_id.value = m_index;
    la_uint64_t num_of_bytes_in_buf = la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;
    for (uint32_t index = 0; index < thresholds.thresholds.size(); index++) {
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
la_voq_cgm_profile_impl::get_sms_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_buff_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;

    // Read current value
    la_status status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    return_on_error(status);
    npl_voq_cgm_slice_profile_buff_region_thresholds_table_t::value_type v = entry_ptr->value();

    la_uint64_t num_thresholds;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS, num_thresholds);
    return_on_error(status);

    out_thresholds.thresholds.resize(num_thresholds);

    // Write to out_thresholds
    la_uint64_t num_of_bytes_in_buf = la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;
    for (uint32_t index = 0; index < out_thresholds.thresholds.size(); index++) {
        out_thresholds.thresholds[index]
            = v.payloads.voq_cgm_slice_profile_buff_region_thresholds_results.q_size_buff_region[index].value * num_of_bytes_in_buf;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_sms_bytes_quantization(sms_bytes_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_packets_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);

    // Verify data correctness
    la_status status;
    status = validate_quantization_thresholds(m_device,
                                              thresholds.thresholds,
                                              limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS,
                                              limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_SMS_PACKETS);
    return_on_error(status);

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_pkt_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_t::value_type v;

    k.profile_id.value = m_index;
    for (uint32_t index = 0; index < thresholds.thresholds.size(); index++) {
        v.payloads.voq_cgm_slice_profile_pkt_region_thresholds_results.q_size_pkt_region[index].value
            = thresholds.thresholds[index];
    }
    v.action = NPL_VOQ_CGM_SLICE_PROFILE_PKT_REGION_THRESHOLDS_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return write_status;
}

la_status
la_voq_cgm_profile_impl::set_sms_packets_quantization(const sms_packets_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_packets_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_pkt_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;

    // Read current value
    la_status status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    return_on_error(status);
    npl_voq_cgm_slice_profile_pkt_region_thresholds_table_t::value_type v = entry_ptr->value();

    la_uint64_t num_thresholds;
    status
        = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS, num_thresholds);
    return_on_error(status);

    out_thresholds.thresholds.resize(num_thresholds);

    // Write to out_thresholds
    for (uint32_t index = 0; index < out_thresholds.thresholds.size(); index++) {
        out_thresholds.thresholds[index]
            = v.payloads.voq_cgm_slice_profile_pkt_region_thresholds_results.q_size_pkt_region[index].value;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_sms_packets_quantization(sms_packets_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_age_quantization(const la_voq_cgm_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);

    // Verify data correctness
    la_status status;
    status = validate_quantization_thresholds(m_device,
                                              thresholds.thresholds,
                                              limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS,
                                              limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_SMS_AGE);
    return_on_error(status);

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_t::value_type v;

    k.profile_id.value = m_index;
    la_cgm_sms_voqs_age_time_units_t granularity;
    la_status granularity_status = m_device->m_voq_cgm_handler->get_cgm_sms_voqs_age_time_granularity(granularity);
    return_on_error(granularity_status);
    for (uint32_t index = 0; index < thresholds.thresholds.size(); index++) {
        v.payloads.voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results.pkt_enq_time_region[index].value
            = thresholds.thresholds[index] / granularity;
    }
    v.action = NPL_VOQ_CGM_SLICE_PROFILE_PKT_ENQ_TIME_REGION_THRESHOLDS_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return write_status;
}

la_status
la_voq_cgm_profile_impl::set_sms_age_quantization(const sms_age_quantization_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_age_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table);

    // Prepare arguments
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_t::key_type k;
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;

    // Read current value
    la_status status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    return_on_error(status);
    npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_t::value_type v = entry_ptr->value();

    la_uint64_t num_thresholds;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS, num_thresholds);
    return_on_error(status);

    out_thresholds.thresholds.resize(num_thresholds);

    // Write to out_thresholds
    la_cgm_sms_voqs_age_time_units_t granularity;
    la_status granularity_status = m_device->m_voq_cgm_handler->get_cgm_sms_voqs_age_time_granularity(granularity);
    return_on_error(granularity_status);
    for (uint32_t index = 0; index < out_thresholds.thresholds.size(); index++) {
        out_thresholds.thresholds[index]
            = v.payloads.voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results.pkt_enq_time_region[index].value
              * granularity;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_sms_age_quantization(sms_age_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::do_set_cgm_evicted_profile_mapping(const la_voq_cgm_evicted_profile_wptr& evicted_profile)
{
    gibraltar::pdvoq_slice_cgm_profile2_evicted_profile_register reg;

    // Read all slices have the same value programmed.
    la_slice_id_t sid = m_device->first_active_slice_id();
    la_status read_status
        = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[sid]->pdvoq->cgm_profile2_evicted_profile, reg);
    return_on_error(read_status);

    // Set struct.
    const auto& voq_cgm_evicted_profile = evicted_profile.weak_ptr_static_cast<la_voq_cgm_evicted_profile_impl>();
    uint64_t evicted_profile_id = voq_cgm_evicted_profile->get_id();
    reg.fields.set_evicted_profile(m_index, evicted_profile_id);

    // Write to all Network and UDC slices.
    auto nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (auto slice : nw_slices) {
        la_status write_status
            = m_device->m_ll_device->write_register(m_device->m_gb_tree->slice[slice]->pdvoq->cgm_profile2_evicted_profile, reg);
        return_on_error(write_status);
    }

    // Add/Remove object dependency.
    if (m_evicted_profile) {
        m_device->remove_object_dependency(m_evicted_profile, this);
    }
    m_device->add_object_dependency(evicted_profile, this);

    m_evicted_profile = evicted_profile;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_cgm_evicted_profile_mapping(la_voq_cgm_evicted_profile* evicted_profile)
{
    start_api_call("evicted_profile=", evicted_profile);

    if (evicted_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(evicted_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_evicted_profile == evicted_profile) {
        return LA_STATUS_SUCCESS;
    }

    const auto& evicted_profile_sptr = m_device->get_sptr(evicted_profile);
    la_status status = do_set_cgm_evicted_profile_mapping(evicted_profile_sptr);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_cgm_evicted_profile_mapping(la_voq_cgm_evicted_profile*& out_evicted_profile) const
{
    start_api_getter_call();

    out_evicted_profile = m_evicted_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::clear_cgm_evicted_profile_mapping()
{
    start_api_call("");

    const auto& default_evicted_profile = m_device->m_voq_cgm_evicted_profiles[la_device_impl::VOQ_CGM_DEFAULT_EVICTED_PROFILE];

    if (m_evicted_profile == default_evicted_profile) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = do_set_cgm_evicted_profile_mapping(default_evicted_profile);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::ensure_sms_evict_key_valid(const la_voq_sms_evict_key& key) const
{
    la_uint64_t num_evicted_buffers_regions;
    la_status status
        = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_REGIONS, num_evicted_buffers_regions);
    return_on_error(status);
    if (key.evicted_buffers_region >= num_evicted_buffers_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_free_dram_cntxt_regions;
    status = m_device->get_limit(limit_type_e::DEVICE__HBM_NUM_OF_VOQS_QUANTIZATION_REGIONS, num_free_dram_cntxt_regions);
    return_on_error(status);
    if (key.free_dram_cntxt_region >= num_free_dram_cntxt_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_sms_evict_behavior(const la_voq_sms_evict_key& key, const la_voq_sms_evict_val& val)
{
    start_api_call("key=", key, "val=", val);

    // Validate key.
    la_status status = ensure_sms_evict_key_valid(key);
    return_on_error(status);

    // Choose table.
    const auto& tables(m_device->m_tables.voq_cgm_slice_eviction_ok_lut_for_enq_table);

    // Prepare arguments.
    npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_t::key_type k;
    npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_t::value_type v;

    k.profile_id.value = m_index;
    k.all_evicted_voq_buff_consump_level = key.evicted_buffers_region;
    k.free_dram_cntx = key.free_dram_cntxt_region;

    v.payloads.voq_cgm_slice_eviction_ok_lut_for_enq_table_results.eviction_ok = val.permit_eviction;
    v.payloads.voq_cgm_slice_eviction_ok_lut_for_enq_table_results.drop_on_eviction = val.drop_on_eviction;

    v.action = NPL_VOQ_CGM_SLICE_EVICTION_OK_LUT_FOR_ENQ_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return write_status;
}

la_status
la_voq_cgm_profile_impl::get_sms_evict_behavior(const la_voq_sms_evict_key& key, la_voq_sms_evict_val& out_val) const
{
    start_api_getter_call();

    // Validate key.
    la_status status = ensure_sms_evict_key_valid(key);
    return_on_error(status);

    // Choose table.
    const auto& tables(m_device->m_tables.voq_cgm_slice_eviction_ok_lut_for_enq_table);

    // Prepare arguments.
    npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_t::key_type k;
    npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_t::value_type v;
    npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.all_evicted_voq_buff_consump_level = key.evicted_buffers_region;
    k.free_dram_cntx = key.free_dram_cntxt_region;

    // Read current value
    status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    return_on_error(status);

    v = entry_ptr->value();
    out_val.permit_eviction = v.payloads.voq_cgm_slice_eviction_ok_lut_for_enq_table_results.eviction_ok;
    out_val.drop_on_eviction = v.payloads.voq_cgm_slice_eviction_ok_lut_for_enq_table_results.drop_on_eviction;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::do_set_wred_probability_profile(voq_prob_profile_t& prob_profile, double probability)
{
    double rounded_prob = round_up_probability_to_precision(probability);
    la_status status = m_device->m_profile_allocators.voq_probability_profile->reallocate(prob_profile, rounded_prob);
    return_on_error(status, HLD, ERROR, "Out of probability profiles");

    // Write probability into ProbLUT.
    if (prob_profile.use_count() == 1) {
        status = m_device->m_voq_cgm_handler->set_cgm_wred_probabilities(prob_profile->id(), rounded_prob);
        // Release the profile on error.
        if (status != LA_STATUS_SUCCESS) {
            prob_profile.reset();
        }
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::ensure_sms_wred_drop_probability_selector_key_valid(
    const la_voq_sms_wred_drop_probability_selector_key& key) const
{
    la_uint64_t num_packet_size_regions;
    la_status status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS, num_packet_size_regions);
    return_on_error(status);
    if (key.packet_size_region >= num_packet_size_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_drop_probability_levels;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_DROP_PROBABILITY_LEVELS, num_drop_probability_levels);
    return_on_error(status);
    if (key.drop_probability_level >= num_drop_probability_levels) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (key.color == la_qos_color_e::NONE || key.color == la_qos_color_e::RED) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::do_set_sms_wred_drop_green_probability(la_quantization_region_t packet_size_region,
                                                                la_cgm_sms_bytes_probability_level_t drop_probability_level,
                                                                double probability)
{
    const auto& tables(m_device->m_tables.voq_cgm_slice_drop_green_probability_selector_table);

    // Prepare arguments.
    npl_voq_cgm_slice_drop_green_probability_selector_table_t::key_type k;
    npl_voq_cgm_slice_drop_green_probability_selector_table_t::value_type v;
    npl_voq_cgm_slice_drop_green_probability_selector_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.packet_size_range = packet_size_region;

    decltype(&v.payloads.voq_cgm_slice_drop_color_probability_selector_results.drop_prob[0]) drop_prob;
    drop_prob = &v.payloads.voq_cgm_slice_drop_color_probability_selector_results.drop_prob[drop_probability_level];

    // Read current value
    // All the slices get the same values, thus it's safe to use slice 0 for read in read-modify-write
    la_status status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }
    if (status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    voq_prob_profile_t& drop_prob_profile
        = m_drop_prob_select_profile[packet_size_region][drop_probability_level][(int)la_qos_color_e::GREEN];

    status = do_set_wred_probability_profile(drop_prob_profile, probability);
    return_on_error(status);

    drop_prob->value = drop_prob_profile->id();

    v.action = NPL_VOQ_CGM_SLICE_DROP_GREEN_PROBABILITY_SELECTOR_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return_on_error(write_status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::do_set_sms_wred_drop_yellow_probability(la_quantization_region_t packet_size_region,
                                                                 la_cgm_sms_bytes_probability_level_t drop_probability_level,
                                                                 double probability)
{
    const auto& tables(m_device->m_tables.voq_cgm_slice_drop_yellow_probability_selector_table);

    // Prepare arguments.
    npl_voq_cgm_slice_drop_yellow_probability_selector_table_t::key_type k;
    npl_voq_cgm_slice_drop_yellow_probability_selector_table_t::value_type v;
    npl_voq_cgm_slice_drop_yellow_probability_selector_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.packet_size_range = packet_size_region;

    decltype(&v.payloads.voq_cgm_slice_drop_color_probability_selector_results.drop_prob[0]) drop_prob;
    drop_prob = &v.payloads.voq_cgm_slice_drop_color_probability_selector_results.drop_prob[drop_probability_level];

    // Read current value
    // All the slices get the same values, thus it's safe to use slice 0 for read in read-modify-write
    la_status status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }
    if (status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    voq_prob_profile_t& drop_prob_profile
        = m_drop_prob_select_profile[packet_size_region][drop_probability_level][(int)la_qos_color_e::YELLOW];

    status = do_set_wred_probability_profile(drop_prob_profile, probability);
    return_on_error(status);

    drop_prob->value = drop_prob_profile->id();

    v.action = NPL_VOQ_CGM_SLICE_DROP_YELLOW_PROBABILITY_SELECTOR_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return_on_error(write_status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_sms_wred_drop_probability(const la_voq_sms_wred_drop_probability_selector_key& key,
                                                       const la_voq_sms_wred_drop_probability_selector_drop_val& val)
{
    start_api_call("key=", key, "val=", val);

    // Validate key.
    la_status status = ensure_sms_wred_drop_probability_selector_key_valid(key);
    return_on_error(status);

    // drop_probability_levels silicon_one::LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_ADMIT and
    // silicon_one::LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP
    // implicitly define probabilites to 0.0 and 1.0 respectively and are not inserted in probability_selector tables.
    if (key.drop_probability_level == LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_ADMIT) {
        if (val.drop_probability != 0.0) {
            return LA_STATUS_EINVAL;
        }
        return LA_STATUS_SUCCESS;
    }
    if (key.drop_probability_level == LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP) {
        if (val.drop_probability != 1.0) {
            return LA_STATUS_EINVAL;
        }
        return LA_STATUS_SUCCESS;
    }
    // Adjust drop_probability_level for hw programming.
    la_cgm_sms_bytes_probability_level_t hw_drop_probability_level = key.drop_probability_level - 1;

    if (val.drop_probability < 0.0 || val.drop_probability > 1.0) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (key.color == la_qos_color_e::GREEN) {
        status = do_set_sms_wred_drop_green_probability(key.packet_size_region, hw_drop_probability_level, val.drop_probability);
    } else {
        status = do_set_sms_wred_drop_yellow_probability(key.packet_size_region, hw_drop_probability_level, val.drop_probability);
    }
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_sms_wred_drop_probability(const la_voq_sms_wred_drop_probability_selector_key& key,
                                                       la_voq_sms_wred_drop_probability_selector_drop_val& out_val) const
{
    start_api_getter_call();

    // Validate key.
    la_status status = ensure_sms_wred_drop_probability_selector_key_valid(key);
    return_on_error(status);

    // drop_probability_levels silicon_one::LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_ADMIT and
    // silicon_one::LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP
    // implicitly define probabilites to 0.0 and 1.0 respectively and are not inserted in probability_selector tables.
    if (key.drop_probability_level == LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_ADMIT) {
        out_val.drop_probability = 0.0;
        return LA_STATUS_SUCCESS;
    }
    if (key.drop_probability_level == LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP) {
        out_val.drop_probability = 1.0;
        return LA_STATUS_SUCCESS;
    }
    // Adjust drop_probability_level for hw programming.
    la_cgm_sms_bytes_probability_level_t hw_drop_probability_level = key.drop_probability_level - 1;

    const voq_prob_profile_t& drop_prob_profile
        = m_drop_prob_select_profile[key.packet_size_region][hw_drop_probability_level][to_utype(key.color)];
    if (drop_prob_profile == nullptr) {
        out_val.drop_probability = 0.0;
    } else {
        out_val.drop_probability = drop_prob_profile->value();
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::ensure_sms_wred_mark_probability_selector_key_valid(
    const la_voq_sms_wred_mark_probability_selector_key& key) const
{
    la_uint64_t num_packet_size_regions;
    la_status status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS, num_packet_size_regions);
    return_on_error(status);
    if (key.packet_size_region >= num_packet_size_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_mark_probability_levels;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_MARK_PROBABILITY_LEVELS, num_mark_probability_levels);
    return_on_error(status);
    if (key.mark_ecn_probability_level >= num_mark_probability_levels) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (key.color == la_qos_color_e::NONE || key.color == la_qos_color_e::RED) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_sms_wred_mark_probability(const la_voq_sms_wred_mark_probability_selector_key& key,
                                                       const la_voq_sms_wred_mark_probability_selector_mark_val& val)
{
    start_api_call("key=", key, "val=", val);

    // Validate key.
    la_status status = ensure_sms_wred_mark_probability_selector_key_valid(key);
    return_on_error(status);

    // mark_ecn_probability_level silicon_one::LA_CGM_SMS_BYTES_MARK_PROBABILITY_LEVEL_DONT_MARK impicitly defines
    // probability 0.0 and is not inserted in probability_selector_table.
    if (key.mark_ecn_probability_level == LA_CGM_SMS_BYTES_MARK_PROBABILITY_LEVEL_DONT_MARK) {
        if (val.mark_ecn_probability != 0.0) {
            return LA_STATUS_EINVAL;
        }
        return LA_STATUS_SUCCESS;
    }
    // Adjust mark_ecn_probability_level for hw programming.
    la_cgm_sms_bytes_probability_level_t hw_mark_ecn_probability_level = key.mark_ecn_probability_level - 1;

    if (val.mark_ecn_probability < 0.0 || val.mark_ecn_probability > 1.0) {
        return LA_STATUS_EOUTOFRANGE;
    }

    const auto& tables(m_device->m_tables.voq_cgm_slice_mark_probability_selector_table);

    // Prepare arguments.
    npl_voq_cgm_slice_mark_probability_selector_table_t::key_type k;
    npl_voq_cgm_slice_mark_probability_selector_table_t::value_type v;
    npl_voq_cgm_slice_mark_probability_selector_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.packet_size_range = key.packet_size_region;

    decltype(&v.payloads.voq_cgm_slice_mark_color_probability_selector_results.mark_yellow_prob[0]) mark_prob;
    if (key.color == la_qos_color_e::GREEN) {
        mark_prob
            = &v.payloads.voq_cgm_slice_mark_color_probability_selector_results.mark_green_prob[hw_mark_ecn_probability_level];
    } else if (key.color == la_qos_color_e::YELLOW) {
        mark_prob
            = &v.payloads.voq_cgm_slice_mark_color_probability_selector_results.mark_yellow_prob[hw_mark_ecn_probability_level];
    } else {
        return LA_STATUS_EUNKNOWN;
    }

    // Read current value
    // All the slices get the same values, thus it's safe to use slice 0 for read in read-modify-write
    status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }
    if (status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    voq_prob_profile_t& mark_prob_profile
        = m_mark_prob_select_profile[key.packet_size_region][hw_mark_ecn_probability_level][to_utype(key.color)];

    status = do_set_wred_probability_profile(mark_prob_profile, val.mark_ecn_probability);
    return_on_error(status);

    mark_prob->value = mark_prob_profile->id();

    v.action = NPL_VOQ_CGM_SLICE_MARK_PROBABILITY_SELECTOR_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return_on_error(write_status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_sms_wred_mark_probability(const la_voq_sms_wred_mark_probability_selector_key& key,
                                                       la_voq_sms_wred_mark_probability_selector_mark_val& out_val) const
{
    start_api_getter_call();

    // Validate key.
    la_status status = ensure_sms_wred_mark_probability_selector_key_valid(key);
    return_on_error(status);

    // mark_ecn_probability_level silicon_one::LA_CGM_SMS_BYTES_MARK_PROBABILITY_LEVEL_DONT_MARK impicitly defines
    // probability 0.0 and is not inserted in probability_selector_table.
    if (key.mark_ecn_probability_level == LA_CGM_SMS_BYTES_MARK_PROBABILITY_LEVEL_DONT_MARK) {
        out_val.mark_ecn_probability = 0.0;
        return LA_STATUS_SUCCESS;
    }
    // Adjust mark_ecn_probability_level for hw programming.
    la_cgm_sms_bytes_probability_level_t hw_mark_ecn_probability_level = key.mark_ecn_probability_level - 1;

    const voq_prob_profile_t& mark_prob_profile
        = m_mark_prob_select_profile[key.packet_size_region][hw_mark_ecn_probability_level][to_utype(key.color)];
    if (mark_prob_profile == nullptr) {
        out_val.mark_ecn_probability = 0.0;
    } else {
        out_val.mark_ecn_probability = mark_prob_profile->value();
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::do_set_sms_size_in_bytes_evict_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                                 la_quantization_region_t sms_bytes_region,
                                                                 la_quantization_region_t sms_age_region,
                                                                 bool evict_to_hbm)
{
    const auto& tables(m_device->m_tables.voq_cgm_slice_buffers_consumption_lut_for_enq_table);

    // Prepare arguments
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::key_type k;
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::value_type v;
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.buffer_pool_available_level = sms_voqs_total_bytes_region;
    k.buffer_voq_size_level = sms_bytes_region;

    // Read current value
    la_status status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }
    if (status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    if (v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.evict_to_dram[sms_age_region].value == evict_to_hbm) {
        return LA_STATUS_SUCCESS;
    }

    v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.evict_to_dram[sms_age_region].value = evict_to_hbm;
    v.action = NPL_VOQ_CGM_SLICE_BUFFERS_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE;

    // Write
    status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);

    return status;
}

la_status
la_voq_cgm_profile_impl::do_get_sms_size_in_bytes_evict_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                                 la_quantization_region_t sms_bytes_region,
                                                                 la_quantization_region_t sms_age_region,
                                                                 bool& out_evict_to_hbm) const
{
    const auto& tables(m_device->m_tables.voq_cgm_slice_buffers_consumption_lut_for_enq_table);

    // Prepare arguments
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::key_type k;
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::value_type v;
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.buffer_pool_available_level = sms_voqs_total_bytes_region;
    k.buffer_voq_size_level = sms_bytes_region;

    // Read current value
    la_status status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    return_on_error(status);

    v = entry_ptr->value();

    out_evict_to_hbm = v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.evict_to_dram[sms_age_region].value;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::do_set_sms_size_in_bytes_color_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                                 la_quantization_region_t sms_bytes_region,
                                                                 la_quantization_region_t sms_age_region,
                                                                 la_qos_color_e color,
                                                                 la_cgm_sms_bytes_probability_level_t drop_probability_level,
                                                                 la_cgm_sms_bytes_probability_level_t mark_ecn_probability_level)
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

    // Read current value

    la_status status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }
    if (status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    decltype(&v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_g.drop_green.drop_color[sms_age_region])
        drop_color;
    decltype(&v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.mark_g.mark_green.mark_color[sms_age_region])
        mark_color;
    // Modify
    if (color == la_qos_color_e::GREEN) {
        drop_color = &v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_g.drop_green.drop_color[sms_age_region];
        mark_color = &v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.mark_g.mark_green.mark_color[sms_age_region];
    } else if (color == la_qos_color_e::YELLOW) {
        drop_color = &v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_y.drop_yellow.drop_color[sms_age_region];
        mark_color = &v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.mark_y.mark_yellow.mark_color[sms_age_region];
    } else { // Should never reach here.
        return LA_STATUS_EUNKNOWN;
    }

    drop_color->value = drop_probability_level;
    mark_color->value = mark_ecn_probability_level;

    v.action = NPL_VOQ_CGM_SLICE_BUFFERS_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE;

    // Write
    status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);

    return status;
}

la_status
la_voq_cgm_profile_impl::do_get_sms_size_in_bytes_color_behavior(
    la_quantization_region_t sms_voqs_total_bytes_region,
    la_quantization_region_t sms_bytes_region,
    la_quantization_region_t sms_age_region,
    la_qos_color_e color,
    la_cgm_sms_bytes_probability_level_t& out_drop_probability_level,
    la_cgm_sms_bytes_probability_level_t& out_mark_ecn_probability_level) const
{
    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_buffers_consumption_lut_for_enq_table);

    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::key_type k;
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::value_type v;
    npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.buffer_pool_available_level = sms_voqs_total_bytes_region;
    k.buffer_voq_size_level = sms_bytes_region;

    // Read current value
    la_status status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    return_on_error(status);

    v = entry_ptr->value();

    if (color == la_qos_color_e::GREEN) {
        out_drop_probability_level
            = v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_g.drop_green.drop_color[sms_age_region].value;
        out_mark_ecn_probability_level
            = v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.mark_g.mark_green.mark_color[sms_age_region].value;
    } else if (color == la_qos_color_e::YELLOW) {
        out_drop_probability_level
            = v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.drop_y.drop_yellow.drop_color[sms_age_region].value;
        out_mark_ecn_probability_level
            = v.payloads.voq_cgm_slice_buffers_consumption_lut_for_enq_result.mark_y.mark_yellow.mark_color[sms_age_region].value;
    } else { // Should never reach here.
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::ensure_sms_size_in_bytes_evict_key_valid(const la_voq_sms_size_in_bytes_evict_key& key) const
{
    la_uint64_t num_sms_total_bytes_regions;
    la_status status = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_total_bytes_regions);
    return_on_error(status);
    if (key.sms_voqs_total_bytes_region >= num_sms_total_bytes_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_sms_age_regions;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);
    return_on_error(status);
    if (key.sms_age_region >= num_sms_age_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_sms_voq_bytes_regions;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);
    return_on_error(status);
    if (key.sms_bytes_region >= num_sms_voq_bytes_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_bytes_evict_behavior(const la_voq_sms_size_in_bytes_evict_key& key,
                                                              const la_voq_sms_size_in_bytes_evict_val& val)
{
    start_api_call("key=", key, "val=", val);

    // Verify data correctness
    la_status status = ensure_sms_size_in_bytes_evict_key_valid(key);
    return_on_error(status);

    return do_set_sms_size_in_bytes_evict_behavior(
        key.sms_voqs_total_bytes_region, key.sms_bytes_region, key.sms_age_region, val.evict_to_hbm);
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_bytes_evict_behavior(const la_voq_sms_size_in_bytes_evict_key& key,
                                                              la_voq_sms_size_in_bytes_evict_val& out_val) const
{
    start_api_getter_call();

    // Verify data correctness
    la_status status = ensure_sms_size_in_bytes_evict_key_valid(key);
    return_on_error(status);

    return do_get_sms_size_in_bytes_evict_behavior(
        key.sms_voqs_total_bytes_region, key.sms_bytes_region, key.sms_age_region, out_val.evict_to_hbm);
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
    start_api_getter_call();
    return LA_STATUS_ENOTIMPLEMENTED;
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
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::ensure_sms_size_in_bytes_color_key_valid(const la_voq_sms_size_in_bytes_color_key& key) const
{
    la_uint64_t num_sms_total_bytes_regions;
    la_status status = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_total_bytes_regions);
    return_on_error(status);
    if (key.sms_voqs_total_bytes_region >= num_sms_total_bytes_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_sms_age_regions;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);
    return_on_error(status);
    if (key.sms_age_region >= num_sms_age_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_sms_voq_bytes_regions;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);
    return_on_error(status);
    if (key.sms_bytes_region >= num_sms_voq_bytes_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (key.color == la_qos_color_e::NONE || key.color == la_qos_color_e::RED) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_bytes_drop_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                             const la_voq_sms_size_in_bytes_drop_val& val)
{
    start_api_call("key=", key, "val=", val);

    la_status status = ensure_sms_size_in_bytes_color_key_valid(key);
    return_on_error(status);

    la_uint64_t num_drop_probability_levels;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_DROP_PROBABILITY_LEVELS, num_drop_probability_levels);
    return_on_error(status);

    if (val.drop_probability_level > num_drop_probability_levels - 1) {
        return LA_STATUS_EOUTOFRANGE;
    }

    size_t drop_probability_level;
    size_t mark_ecn_probability_level;
    status = do_get_sms_size_in_bytes_color_behavior(key.sms_voqs_total_bytes_region,
                                                     key.sms_bytes_region,
                                                     key.sms_age_region,
                                                     key.color,
                                                     drop_probability_level,
                                                     mark_ecn_probability_level);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }

    if (status == LA_STATUS_SUCCESS) {
        if (drop_probability_level == val.drop_probability_level) {
            return LA_STATUS_SUCCESS;
        }
    }

    drop_probability_level = val.drop_probability_level;
    return do_set_sms_size_in_bytes_color_behavior(key.sms_voqs_total_bytes_region,
                                                   key.sms_bytes_region,
                                                   key.sms_age_region,
                                                   key.color,
                                                   drop_probability_level,
                                                   mark_ecn_probability_level);
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_bytes_mark_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                             const la_voq_sms_size_in_bytes_mark_val& val)
{
    start_api_call("key=", key, "val=", val);

    la_status status = ensure_sms_size_in_bytes_color_key_valid(key);
    return_on_error(status);

    la_uint64_t num_mark_probability_levels;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_MARK_PROBABILITY_LEVELS, num_mark_probability_levels);
    return_on_error(status);

    if (val.mark_ecn_probability_level > num_mark_probability_levels - 1) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_cgm_sms_bytes_probability_level_t drop_probability_level;
    la_cgm_sms_bytes_probability_level_t mark_ecn_probability_level;
    status = do_get_sms_size_in_bytes_color_behavior(key.sms_voqs_total_bytes_region,
                                                     key.sms_bytes_region,
                                                     key.sms_age_region,
                                                     key.color,
                                                     drop_probability_level,
                                                     mark_ecn_probability_level);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }

    if (status == LA_STATUS_SUCCESS) {
        if (mark_ecn_probability_level == val.mark_ecn_probability_level) {
            return LA_STATUS_SUCCESS;
        }
    }

    mark_ecn_probability_level = val.mark_ecn_probability_level;
    return do_set_sms_size_in_bytes_color_behavior(key.sms_voqs_total_bytes_region,
                                                   key.sms_bytes_region,
                                                   key.sms_age_region,
                                                   key.color,
                                                   drop_probability_level,
                                                   mark_ecn_probability_level);
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_bytes_drop_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                             la_voq_sms_size_in_bytes_drop_val& out_val) const
{
    start_api_getter_call();

    la_status status = ensure_sms_size_in_bytes_color_key_valid(key);
    return_on_error(status);

    size_t dummy_mark_ecn_probability_level;

    return do_get_sms_size_in_bytes_color_behavior(key.sms_voqs_total_bytes_region,
                                                   key.sms_bytes_region,
                                                   key.sms_age_region,
                                                   key.color,
                                                   out_val.drop_probability_level,
                                                   dummy_mark_ecn_probability_level);
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_bytes_mark_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                             la_voq_sms_size_in_bytes_mark_val& out_val) const
{
    start_api_getter_call();

    la_status status = ensure_sms_size_in_bytes_color_key_valid(key);
    return_on_error(status);

    la_cgm_sms_bytes_probability_level_t dummy_drop_probability_level;

    return do_get_sms_size_in_bytes_color_behavior(key.sms_voqs_total_bytes_region,
                                                   key.sms_bytes_region,
                                                   key.sms_age_region,
                                                   key.color,
                                                   dummy_drop_probability_level,
                                                   out_val.mark_ecn_probability_level);
}

la_status
la_voq_cgm_profile_impl::ensure_sms_dequeue_size_in_bytes_key_valid(const la_voq_sms_dequeue_size_in_bytes_key& key) const
{
    la_uint64_t num_sms_total_bytes_regions;
    la_status status = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_total_bytes_regions);
    return_on_error(status);
    if (key.sms_voqs_total_bytes_region >= num_sms_total_bytes_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_sms_age_regions;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);
    return_on_error(status);
    if (key.sms_age_region >= num_sms_age_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_sms_voq_bytes_regions;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);
    return_on_error(status);
    if (key.sms_bytes_region >= num_sms_voq_bytes_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_sms_dequeue_size_in_bytes_congestion_level(const la_voq_sms_dequeue_size_in_bytes_key& key,
                                                                        const la_voq_sms_dequeue_size_in_bytes_congestion_val& val)
{
    start_api_call("key=", key, "val=", val);

    // Validate key.
    la_status status = ensure_sms_dequeue_size_in_bytes_key_valid(key);
    return_on_error(status);

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_buffers_consumption_lut_for_deq_table);

    // Prepare arguments
    npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_t::key_type k;
    npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_t::value_type v;
    npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.buffer_pool_available_level = key.sms_voqs_total_bytes_region;
    k.buffer_voq_size_level = key.sms_bytes_region;

    // Read current value
    status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }
    if (status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    v.payloads.voq_cgm_slice_buffers_consumption_lut_for_deq_result.congestion_level[key.sms_age_region].value
        = val.congestion_level;

    v.action = NPL_VOQ_CGM_SLICE_BUFFERS_CONSUMPTION_LUT_FOR_DEQ_TABLE_ACTION_WRITE;

    // Write
    status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);

    return status;
}

la_status
la_voq_cgm_profile_impl::get_sms_dequeue_size_in_bytes_congestion_level(
    const la_voq_sms_dequeue_size_in_bytes_key& key,
    la_voq_sms_dequeue_size_in_bytes_congestion_val& out_val) const
{
    start_api_getter_call("key=", key);

    // Validate key.
    la_status status = ensure_sms_dequeue_size_in_bytes_key_valid(key);
    return_on_error(status);

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_buffers_consumption_lut_for_deq_table);

    // Prepare arguments
    npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_t::key_type k;
    npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_t::value_type v;
    npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.buffer_pool_available_level = key.sms_voqs_total_bytes_region;
    k.buffer_voq_size_level = key.sms_bytes_region;

    // Read current value
    status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    return_on_error(status);

    v = entry_ptr->value();
    out_val.congestion_level
        = v.payloads.voq_cgm_slice_buffers_consumption_lut_for_deq_result.congestion_level[key.sms_age_region].value;

    return LA_STATUS_SUCCESS;
}

// SMS helpers - packets

la_status
la_voq_cgm_profile_impl::do_get_sms_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                             la_quantization_region_t sms_packets_region,
                                                             la_quantization_region_t sms_age_region,
                                                             la_qos_color_e& out_drop_color_level,
                                                             la_qos_color_e& out_mark_ecn_color_level,
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
    la_status read_status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    return_on_error(read_status);

    npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_t::value_type v;
    v = entry_ptr->value();

    // Fill the result
    if (v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.drop_green[sms_age_region].value) {
        out_drop_color_level = la_qos_color_e::GREEN;
    } else {
        if (v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.drop_yellow[sms_age_region].value) {
            out_drop_color_level = la_qos_color_e::YELLOW;
        } else {
            out_drop_color_level = la_qos_color_e::NONE;
        }
    }

    if (v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.mark_green[sms_age_region].value) {
        out_mark_ecn_color_level = la_qos_color_e::GREEN;
    } else {
        if (v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.mark_yellow[sms_age_region].value) {
            out_mark_ecn_color_level = la_qos_color_e::YELLOW;
        } else {
            out_mark_ecn_color_level = la_qos_color_e::NONE;
        }
    }

    out_evict_to_hbm = v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.evict_to_dram[sms_age_region].value;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::do_set_sms_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                             la_quantization_region_t sms_packets_region,
                                                             la_quantization_region_t sms_age_region,
                                                             la_qos_color_e drop_color_level,
                                                             la_qos_color_e mark_ecn_color_level,
                                                             bool evict_to_hbm)
{
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
    la_status read_status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    if (read_status != LA_STATUS_ENOTFOUND && read_status != LA_STATUS_SUCCESS) {
        return read_status;
    }
    if (read_status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    // Modify
    v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.drop_green[sms_age_region].value
        = (drop_color_level <= la_qos_color_e::GREEN);
    v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.drop_yellow[sms_age_region].value
        = (drop_color_level <= la_qos_color_e::YELLOW);
    v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.mark_green[sms_age_region].value
        = (mark_ecn_color_level <= la_qos_color_e::GREEN);
    v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.mark_yellow[sms_age_region].value
        = (mark_ecn_color_level <= la_qos_color_e::YELLOW);
    v.payloads.voq_cgm_slice_pd_consumption_lut_for_enq_result.evict_to_dram[sms_age_region].value = evict_to_hbm;
    v.action = NPL_VOQ_CGM_SLICE_PD_CONSUMPTION_LUT_FOR_ENQ_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return write_status;
}

la_status
la_voq_cgm_profile_impl::ensure_sms_packets_key_valid(const la_voq_sms_size_in_packets_key& key) const
{
    la_uint64_t num_sms_packet_regions;
    la_status status
        = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS, num_sms_packet_regions);
    return_on_error(status);
    if (key.sms_packets_region >= num_sms_packet_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_sms_age_regions;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);
    return_on_error(status);
    if (key.sms_age_region >= num_sms_age_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_sms_voqs_total_packets_regions;
    status = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS, num_sms_voqs_total_packets_regions);
    return_on_error(status);
    if (key.sms_voqs_total_packets_region >= num_sms_voqs_total_packets_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_packets_drop_behavior(const la_voq_sms_size_in_packets_key& key,
                                                               const la_voq_sms_size_in_packets_drop_val& val)
{
    start_api_call("key=", key, "val=", val);

    la_status status = ensure_sms_packets_key_valid(key);
    return_on_error(status);

    la_qos_color_e drop_color_level;
    la_qos_color_e mark_ecn_color_level;
    bool evict_to_hbm;

    status = do_get_sms_size_in_packets_behavior(key.sms_voqs_total_packets_region,
                                                 key.sms_packets_region,
                                                 key.sms_age_region,
                                                 drop_color_level,
                                                 mark_ecn_color_level,
                                                 evict_to_hbm);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }

    if (status == LA_STATUS_SUCCESS) {
        if (drop_color_level == val.drop_color_level) {
            return LA_STATUS_SUCCESS;
        }
    }

    drop_color_level = val.drop_color_level;
    return do_set_sms_size_in_packets_behavior(key.sms_voqs_total_packets_region,
                                               key.sms_packets_region,
                                               key.sms_age_region,
                                               drop_color_level,
                                               mark_ecn_color_level,
                                               evict_to_hbm);
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_packets_mark_behavior(const la_voq_sms_size_in_packets_key& key,
                                                               const la_voq_sms_size_in_packets_mark_val& val)
{
    start_api_call("key=", key, "val=", val);

    la_status status = ensure_sms_packets_key_valid(key);
    return_on_error(status);

    la_qos_color_e drop_color_level;
    la_qos_color_e mark_ecn_color_level;
    bool evict_to_hbm;

    status = do_get_sms_size_in_packets_behavior(key.sms_voqs_total_packets_region,
                                                 key.sms_packets_region,
                                                 key.sms_age_region,
                                                 drop_color_level,
                                                 mark_ecn_color_level,
                                                 evict_to_hbm);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }

    if (status == LA_STATUS_SUCCESS) {
        if (mark_ecn_color_level == val.mark_ecn_color_level) {
            return LA_STATUS_SUCCESS;
        }
    }

    mark_ecn_color_level = val.mark_ecn_color_level;
    return do_set_sms_size_in_packets_behavior(key.sms_voqs_total_packets_region,
                                               key.sms_packets_region,
                                               key.sms_age_region,
                                               drop_color_level,
                                               mark_ecn_color_level,
                                               evict_to_hbm);
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_packets_evict_behavior(const la_voq_sms_size_in_packets_key& key,
                                                                const la_voq_sms_size_in_packets_evict_val& val)
{
    start_api_call("key=", key, "val=", val);

    la_status status = ensure_sms_packets_key_valid(key);
    return_on_error(status);

    if ((m_voq_cgm_pd_counter == NPL_VOQ_CGM_PD_COUNTER_MC) && (val.evict_to_hbm == true)) {
        log_err(HLD, "VOQ CGM profile is attached to a MC VOQ. A MC VOQ cannot be evicted to the HBM.");
        return LA_STATUS_EINVAL;
    }
    la_qos_color_e drop_color_level;
    la_qos_color_e mark_ecn_color_level;
    bool evict_to_hbm;

    status = do_get_sms_size_in_packets_behavior(key.sms_voqs_total_packets_region,
                                                 key.sms_packets_region,
                                                 key.sms_age_region,
                                                 drop_color_level,
                                                 mark_ecn_color_level,
                                                 evict_to_hbm);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }

    if (status == LA_STATUS_SUCCESS) {
        if (evict_to_hbm == val.evict_to_hbm) {
            return LA_STATUS_SUCCESS;
        }
    }

    evict_to_hbm = val.evict_to_hbm;
    return do_set_sms_size_in_packets_behavior(key.sms_voqs_total_packets_region,
                                               key.sms_packets_region,
                                               key.sms_age_region,
                                               drop_color_level,
                                               mark_ecn_color_level,
                                               evict_to_hbm);
}

la_status
la_voq_cgm_profile_impl::set_sms_size_in_packets_behavior(la_quantization_region_t,
                                                          la_quantization_region_t,
                                                          la_quantization_region_t,
                                                          la_qos_color_e,
                                                          bool,
                                                          bool)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::ensure_sms_dequeue_size_in_packets_key_valid(const la_voq_sms_dequeue_size_in_packets_key& key) const
{
    la_uint64_t num_sms_packet_regions;
    la_status status
        = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS, num_sms_packet_regions);
    return_on_error(status);
    if (key.sms_packets_region >= num_sms_packet_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_sms_age_regions;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);
    return_on_error(status);
    if (key.sms_age_region >= num_sms_age_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_sms_voqs_total_packets_regions;
    status = m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS, num_sms_voqs_total_packets_regions);
    return_on_error(status);
    if (key.sms_voqs_total_packets_region >= num_sms_voqs_total_packets_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_sms_dequeue_size_in_packets_congestion_level(
    const la_voq_sms_dequeue_size_in_packets_key& key,
    const la_voq_sms_dequeue_size_in_packets_congestion_val& val)
{
    start_api_call("key=", key, "val=", val);

    la_status status = ensure_sms_dequeue_size_in_packets_key_valid(key);
    return_on_error(status);

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_pd_consumption_lut_for_deq_table);

    // Prepare arguments
    npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_t::key_type k;
    npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_t::value_type v;
    npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.pd_pool_available_level = key.sms_voqs_total_packets_region;
    k.pd_voq_fill_level = key.sms_packets_region;

    // Read current value
    la_status read_status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    if (read_status != LA_STATUS_ENOTFOUND && read_status != LA_STATUS_SUCCESS) {
        return read_status;
    }
    if (read_status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    // Modify
    v.payloads.voq_cgm_slice_pd_consumption_lut_for_deq_result.congestion_level[key.sms_age_region].value = val.congestion_level;

    v.action = NPL_VOQ_CGM_SLICE_PD_CONSUMPTION_LUT_FOR_DEQ_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return write_status;
}

la_status
la_voq_cgm_profile_impl::get_sms_dequeue_size_in_packets_congestion_level(
    const la_voq_sms_dequeue_size_in_packets_key& key,
    la_voq_sms_dequeue_size_in_packets_congestion_val& out_val) const
{
    start_api_getter_call("key=", key);

    la_status status = ensure_sms_dequeue_size_in_packets_key_valid(key);
    return_on_error(status);

    // Choose table
    const auto& tables(m_device->m_tables.voq_cgm_slice_pd_consumption_lut_for_deq_table);

    // Prepare arguments
    npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_t::key_type k;
    npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_t::value_type v;
    npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.pd_pool_available_level = key.sms_voqs_total_packets_region;
    k.pd_voq_fill_level = key.sms_packets_region;

    // Read current value
    status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    return_on_error(status);

    v = entry_ptr->value();
    out_val.congestion_level
        = v.payloads.voq_cgm_slice_pd_consumption_lut_for_deq_result.congestion_level[key.sms_age_region].value;

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_packets_drop_behavior(const la_voq_sms_size_in_packets_key& key,
                                                               la_voq_sms_size_in_packets_drop_val& out_val) const
{
    start_api_getter_call();

    la_status status = ensure_sms_packets_key_valid(key);
    return_on_error(status);

    la_qos_color_e dummy_mark_ecn_color_level;
    bool dummy_evict_to_hbm;

    return do_get_sms_size_in_packets_behavior(key.sms_voqs_total_packets_region,
                                               key.sms_packets_region,
                                               key.sms_age_region,
                                               out_val.drop_color_level,
                                               dummy_mark_ecn_color_level,
                                               dummy_evict_to_hbm);
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_packets_mark_behavior(const la_voq_sms_size_in_packets_key& key,
                                                               la_voq_sms_size_in_packets_mark_val& out_val) const
{
    start_api_getter_call();

    la_status status = ensure_sms_packets_key_valid(key);
    return_on_error(status);

    la_qos_color_e dummy_drop_color_level;
    bool dummy_evict_to_hbm;

    return do_get_sms_size_in_packets_behavior(key.sms_voqs_total_packets_region,
                                               key.sms_packets_region,
                                               key.sms_age_region,
                                               dummy_drop_color_level,
                                               out_val.mark_ecn_color_level,
                                               dummy_evict_to_hbm);
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_packets_evict_behavior(const la_voq_sms_size_in_packets_key& key,
                                                                la_voq_sms_size_in_packets_evict_val& out_val) const
{
    start_api_getter_call();

    la_status status = ensure_sms_packets_key_valid(key);
    return_on_error(status);

    la_qos_color_e dummy_drop_color_level;
    la_qos_color_e dummy_mark_ecn_color_level;

    return do_get_sms_size_in_packets_behavior(key.sms_voqs_total_packets_region,
                                               key.sms_packets_region,
                                               key.sms_age_region,
                                               dummy_drop_color_level,
                                               dummy_mark_ecn_color_level,
                                               out_val.evict_to_hbm);
}

la_status
la_voq_cgm_profile_impl::get_sms_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                          la_quantization_region_t sms_packets_region,
                                                          la_quantization_region_t sms_age_region,
                                                          la_qos_color_e& out_drop_color_level,
                                                          bool& out_mark_ecn,
                                                          bool& out_evict_to_hbm) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::ensure_hbm_size_in_blocks_key_valid(const la_cgm_hbm_size_in_blocks_key& key) const
{
    la_uint64_t num_hbm_blocks_by_voq_quantization_regions;
    la_status status = m_device->get_limit(limit_type_e::DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS,
                                           num_hbm_blocks_by_voq_quantization_regions);
    return_on_error(status);
    if (key.hbm_blocks_by_voq_region >= num_hbm_blocks_by_voq_quantization_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_hbm_queue_delay_quantization_regions;
    status
        = m_device->get_limit(limit_type_e::DEVICE__HBM_NUM_VOQ_AGE_QUANTIZATION_REGIONS, num_hbm_queue_delay_quantization_regions);
    return_on_error(status);
    if (key.hbm_queue_delay_region >= num_hbm_queue_delay_quantization_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_hbm_pool_free_blocks_quantization_regions;
    status = m_device->get_limit(limit_type_e::DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS,
                                 num_hbm_pool_free_blocks_quantization_regions);
    return_on_error(status);

    if (key.hbm_pool_free_blocks_region >= num_hbm_pool_free_blocks_quantization_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::do_set_hbm_size_in_blocks_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                            bool is_drop_action,
                                                            la_qos_color_e color)
{
    const auto& table(m_device->m_tables.dram_cgm_cgm_lut_table);
    npl_dram_cgm_cgm_lut_table_t::key_type k;
    npl_dram_cgm_cgm_lut_table_t::value_type v;
    npl_dram_cgm_cgm_lut_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.queue_size_level = key.hbm_blocks_by_voq_region;
    k.dram_q_delay_level = key.hbm_queue_delay_region;
    k.shared_pool_th_level = key.hbm_pool_free_blocks_region;

    // Read current value
    la_status status = table->lookup(k, entry_ptr);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }

    if (status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    // Modify
    if (is_drop_action) {
        v.payloads.dram_cgm_cgm_lut_results.dp0 = (color <= la_qos_color_e::GREEN);
        v.payloads.dram_cgm_cgm_lut_results.dp1 = (color <= la_qos_color_e::YELLOW);
    } else {
        // In hw mark1,mark0 result is encoded as follows;
        //
        // mark1,mark0 -    Result encoding
        // 0,0 -            voq_is_evicted=0 and No marking.
        // 0,1 -            voq_is_evicted=1 and No marking.
        // 1,0 -            voq_is_evicted=1 and MarkGreen.
        // 1,1 -            voq_is_evicted=1 and MarkGreen and MarkYellow.
        //
        // Note: voq_is_evicted is set only when queue is evicted, which is determined by k.queue_size_level > 0.
        if (k.queue_size_level == 0) { // VOQ not evicted.
            // HW only supports marking for evicted VOQs.
            if (color != la_qos_color_e::NONE) {
                return LA_STATUS_EINVAL;
            }
            v.payloads.dram_cgm_cgm_lut_results.mark1 = 0;
            v.payloads.dram_cgm_cgm_lut_results.mark0 = 0;
        } else {
            // VOQ is evicted.
            if (color == la_qos_color_e::NONE) {
                v.payloads.dram_cgm_cgm_lut_results.mark1 = 0;
                v.payloads.dram_cgm_cgm_lut_results.mark0 = 1;
            } else {
                v.payloads.dram_cgm_cgm_lut_results.mark1 = 1;
                v.payloads.dram_cgm_cgm_lut_results.mark0 = (color == la_qos_color_e::YELLOW);
            }
        }
    }

    v.action = NPL_DRAM_CGM_CGM_LUT_TABLE_ACTION_WRITE;

    // Write
    la_status write_status = table->set(k, v, entry_ptr);
    return write_status;
}

la_status
la_voq_cgm_profile_impl::do_get_hbm_size_in_blocks_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                            bool is_drop_action,
                                                            la_qos_color_e& out_color) const
{
    const auto& table(m_device->m_tables.dram_cgm_cgm_lut_table);
    npl_dram_cgm_cgm_lut_table_t::key_type k;
    npl_dram_cgm_cgm_lut_table_t::value_type v;
    npl_dram_cgm_cgm_lut_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.queue_size_level = key.hbm_blocks_by_voq_region;
    k.dram_q_delay_level = key.hbm_queue_delay_region;
    k.shared_pool_th_level = key.hbm_pool_free_blocks_region;

    // Read current value
    la_status status = table->lookup(k, entry_ptr);
    return_on_error(status);

    v = entry_ptr->value();

    if (is_drop_action) {

        if (v.payloads.dram_cgm_cgm_lut_results.dp0) {
            out_color = la_qos_color_e::GREEN;
        } else {
            out_color = (v.payloads.dram_cgm_cgm_lut_results.dp1) ? la_qos_color_e::YELLOW : la_qos_color_e::NONE;
        }
    } else {
        if (v.payloads.dram_cgm_cgm_lut_results.mark1) {
            out_color = (v.payloads.dram_cgm_cgm_lut_results.mark0) ? la_qos_color_e::YELLOW : la_qos_color_e::GREEN;
        } else {
            out_color = la_qos_color_e::NONE;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_hbm_size_in_blocks_drop_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                              const la_cgm_hbm_size_in_blocks_drop_val& val)
{
    start_api_call("key=", key, "val=", val);

    la_status status = ensure_hbm_size_in_blocks_key_valid(key);
    return_on_error(status);

    status = do_set_hbm_size_in_blocks_behavior(key, true /* is_drop_action */, val.drop_color_level);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_hbm_size_in_blocks_drop_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                              la_cgm_hbm_size_in_blocks_drop_val& out_val) const
{
    start_api_getter_call();

    la_status status = ensure_hbm_size_in_blocks_key_valid(key);
    return_on_error(status);

    status = do_get_hbm_size_in_blocks_behavior(key, true /* is_drop_action */, out_val.drop_color_level);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_hbm_size_in_blocks_mark_ecn_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                                  const la_cgm_hbm_size_in_blocks_mark_ecn_val& val)
{
    start_api_call("key=", key, "val=", val);

    la_status status = ensure_hbm_size_in_blocks_key_valid(key);
    return_on_error(status);

    status = do_set_hbm_size_in_blocks_behavior(key, false /* is_drop_action */, val.mark_ecn_color_level);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_hbm_size_in_blocks_mark_ecn_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                                  la_cgm_hbm_size_in_blocks_mark_ecn_val& out_val) const
{
    start_api_getter_call();

    la_status status = do_get_hbm_size_in_blocks_behavior(key, false /* is_drop_action */, out_val.mark_ecn_color_level);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_sms_dequeue_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                                la_quantization_region_t sms_bytes_region,
                                                                bool mark_ecn)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_dequeue_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                                la_quantization_region_t sms_bytes_region,
                                                                bool& out_mark_ecn) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_sms_dequeue_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                                  bool mark_ecn)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_sms_dequeue_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                                  bool& out_mark_ecn) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::ensure_hbm_dequeue_size_in_blocks_key_valid(const la_cgm_hbm_dequeue_size_in_blocks_key& key) const
{
    la_uint64_t num_hbm_blocks_by_voq_quantization_regions;
    la_status status = m_device->get_limit(limit_type_e::DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS,
                                           num_hbm_blocks_by_voq_quantization_regions);
    return_on_error(status);
    if (key.hbm_blocks_by_voq_region >= num_hbm_blocks_by_voq_quantization_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_hbm_pool_free_blocks_quantization_regions;
    status = m_device->get_limit(limit_type_e::DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS,
                                 num_hbm_pool_free_blocks_quantization_regions);
    return_on_error(status);
    if (key.hbm_pool_free_blocks_region >= num_hbm_pool_free_blocks_quantization_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_hbm_dequeue_size_in_blocks_congestion_level(
    const la_cgm_hbm_dequeue_size_in_blocks_key& key,
    const la_cgm_hbm_dequeue_size_in_blocks_congestion_val& val)
{
    start_api_call("key=", key, "val=", val);

    la_status status = ensure_hbm_dequeue_size_in_blocks_key_valid(key);
    return_on_error(status);

    // Choose table.
    const auto& table(m_device->m_tables.dram_cgm_cgm_deq_lut_table);
    npl_dram_cgm_cgm_deq_lut_table_t::key_type k;
    npl_dram_cgm_cgm_deq_lut_table_t::value_type v;
    npl_dram_cgm_cgm_deq_lut_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.queue_size_level = key.hbm_blocks_by_voq_region;

    // Read current value
    status = table->lookup(k, entry_ptr);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }

    if (status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    // Modify
    v.payloads.dram_cgm_cgm_deq_lut_results.congestion_level[key.hbm_pool_free_blocks_region].value = val.congestion_level;

    v.action = NPL_DRAM_CGM_CGM_DEQ_LUT_TABLE_ACTION_WRITE;

    // Write
    la_status write_status = table->set(k, v, entry_ptr);

    return write_status;
}

la_status
la_voq_cgm_profile_impl::get_hbm_dequeue_size_in_blocks_congestion_level(
    const la_cgm_hbm_dequeue_size_in_blocks_key& key,
    la_cgm_hbm_dequeue_size_in_blocks_congestion_val& out_val) const
{
    start_api_getter_call("key=", key);

    la_status status = ensure_hbm_dequeue_size_in_blocks_key_valid(key);
    return_on_error(status);

    // Choose table.
    const auto& table(m_device->m_tables.dram_cgm_cgm_deq_lut_table);
    npl_dram_cgm_cgm_deq_lut_table_t::key_type k;
    npl_dram_cgm_cgm_deq_lut_table_t::value_type v;
    npl_dram_cgm_cgm_deq_lut_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.queue_size_level = key.hbm_blocks_by_voq_region;

    // Read current value
    status = table->lookup(k, entry_ptr);
    return_on_error(status);

    v = entry_ptr->value();
    out_val.congestion_level = v.payloads.dram_cgm_cgm_deq_lut_results.congestion_level[key.hbm_pool_free_blocks_region].value;

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

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_hbm_size_in_blocks_behavior(la_quantization_region_t hbm_blocks_by_voq_region,
                                                         la_quantization_region_t hbm_pool_free_blocks_region,
                                                         la_qos_color_e& out_drop_color_level,
                                                         bool& out_mark_ecn) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_associated_hbm_pool(la_cgm_hbm_pool_id_t hbm_pool_id)
{
    start_api_call("hbm_pool_id=", hbm_pool_id);

    // Verify data correctness
    la_uint64_t max_hbm_pool_id;
    la_status status = m_device->get_limit(limit_type_e::DEVICE__NUM_CGM_HBM_POOLS, max_hbm_pool_id);
    return_on_error(status);
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
    if (read_status != LA_STATUS_ENOTFOUND) {
        return_on_error(read_status);
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
    return write_status;
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

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_averaging_configuration(double ema_coefficient, const la_voq_cgm_quantization_thresholds& thresholds)
{
    start_api_call("ema_coefficient=", ema_coefficient, "thresholds=", thresholds);

    // Verify data correctness
    la_status status
        = validate_quantization_thresholds(m_device,
                                           thresholds.thresholds,
                                           limit_type_e::VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS,
                                           limit_type_e::VOQ_CGM_PROFILE__MAX_VOQ_HBM_SIZE);
    return_on_error(status);

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
    if (read_status != LA_STATUS_ENOTFOUND) {
        return_on_error(read_status);
    }

    if (read_status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    // Modify
    v.payloads.hmc_cgm_profile_global_results.wred_ema_weight = weight;
    for (uint32_t index = 0; index < thresholds.thresholds.size(); index++) {
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
    return write_status;
}

la_status
la_voq_cgm_profile_impl::get_averaging_configuration(double& out_ema_coefficient,
                                                     wred_blocks_quantization_thresholds& out_thresholds) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_averaging_configuration(double& out_ema_coefficient,
                                                     la_voq_cgm_quantization_thresholds& out_thresholds) const
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
    la_uint64_t num_thresholds;
    la_status status
        = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS, num_thresholds);
    return_on_error(status);

    out_thresholds.thresholds.resize(num_thresholds);
    out_ema_coefficient = std::exp2(-v.payloads.hmc_cgm_profile_global_results.wred_ema_weight);
    for (uint32_t index = 0; index < out_thresholds.thresholds.size(); index++) {
        out_thresholds.thresholds[index] = v.payloads.hmc_cgm_profile_global_results.wred_region_borders[index].value;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_wred_configuration(wred_action_e action, const wred_regions_probabilties& action_probabilities)
{

    start_api_call("action=", action, "action_probabilities=", action_probabilities);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_wred_configuration(wred_action_e& out_action,
                                                wred_regions_probabilties& out_action_probabilities) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::ensure_cgm_wred_key_valid(const la_cgm_wred_key& key) const
{
    // Only Green and Yellow need to be configured.
    if (key.color == la_qos_color_e::NONE || key.color == la_qos_color_e::RED) {
        return LA_STATUS_EINVAL;
    }

    la_uint64_t num_hbm_blocks_by_voq_regions;
    la_status status
        = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_REGIONS, num_hbm_blocks_by_voq_regions);
    return_on_error(status);
    if (key.hbm_blocks_by_voq_region >= num_hbm_blocks_by_voq_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint64_t num_packet_size_regions;
    status = m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS, num_packet_size_regions);
    return_on_error(status);
    if (key.hbm_packet_size_region >= num_packet_size_regions) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_hbm_wred_drop_configuration(const la_cgm_wred_key& key, const la_cgm_wred_drop_val& val)
{
    start_api_call("key=", key, "val=", val);

    // Verify data correctnes
    la_status status = ensure_cgm_wred_key_valid(key);
    return_on_error(status);

    if (val.drop_probability < 0.0 || val.drop_probability > 1.0) {
        return LA_STATUS_EINVAL;
    }

    // Choose table
    const auto& tables(m_device->m_tables.pdvoq_slice_dram_wred_lut_table);
    // Prepare arguments. All the slices get the same values, thus it's safe to use slice 0 for read in read-modify-write
    npl_pdvoq_slice_dram_wred_lut_table_t::key_type k;
    npl_pdvoq_slice_dram_wred_lut_table_t::value_type v;
    npl_pdvoq_slice_dram_wred_lut_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.queue_size_level = key.hbm_blocks_by_voq_region;
    k.packet_size_range = key.hbm_packet_size_region;

    decltype(&v.payloads.pdvoq_slice_dram_wred_lut_result.drop_g) drop_color;
    if (key.color == la_qos_color_e::GREEN) {
        drop_color = &v.payloads.pdvoq_slice_dram_wred_lut_result.drop_g;
    } else if (key.color == la_qos_color_e::YELLOW) {
        drop_color = &v.payloads.pdvoq_slice_dram_wred_lut_result.drop_y;
    } else {
        return LA_STATUS_EUNKNOWN;
    }

    // Read current value
    status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }
    if (status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    voq_prob_profile_t& drop_prob_profile
        = m_drop_dram_wred_lut[key.hbm_blocks_by_voq_region][key.hbm_packet_size_region][to_utype(key.color)];

    status = do_set_wred_probability_profile(drop_prob_profile, val.drop_probability);
    return_on_error(status);

    drop_color->region_id = drop_prob_profile->id();

    v.action = NPL_PDVOQ_SLICE_DRAM_WRED_LUT_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return_on_error(write_status);

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_hbm_wred_drop_configuration(const la_cgm_wred_key& key, la_cgm_wred_drop_val& out_val) const
{
    start_api_getter_call();

    // Verify data correctness
    la_status status = ensure_cgm_wred_key_valid(key);
    return_on_error(status);

    // TBD ALOK confirm marking of RED behavior.
    // For Red, this return drop-all, which is drop probability of 1.0 For NONE, drop probability is 0.0
    if (key.color == la_qos_color_e::NONE || key.color == la_qos_color_e::RED) {
        if (key.color == la_qos_color_e::NONE) {
            out_val = la_cgm_wred_drop_val(0.0);
        } else {
            out_val = la_cgm_wred_drop_val(1.0);
        }
        return LA_STATUS_SUCCESS;
    }

    const voq_prob_profile_t& drop_prob_profile
        = m_drop_dram_wred_lut[key.hbm_blocks_by_voq_region][key.hbm_packet_size_region][to_utype(key.color)];
    if (drop_prob_profile == nullptr) {
        out_val = la_cgm_wred_drop_val(0.0);
    } else {
        out_val = la_cgm_wred_drop_val(drop_prob_profile->value());
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_hbm_wred_mark_ecn_configuration(const la_cgm_wred_key& key, const la_cgm_wred_mark_ecn_val& val)
{
    start_api_call("key=", key, "val=", val);

    // Verify data correctness
    la_status status = ensure_cgm_wred_key_valid(key);
    return_on_error(status);

    if (val.mark_ecn_probability < 0.0 || val.mark_ecn_probability > 1.0) {
        return LA_STATUS_EINVAL;
    }

    // Choose table
    const auto& tables(m_device->m_tables.pdvoq_slice_dram_wred_lut_table);
    // Prepare arguments.
    npl_pdvoq_slice_dram_wred_lut_table_t::key_type k;
    npl_pdvoq_slice_dram_wred_lut_table_t::value_type v;
    npl_pdvoq_slice_dram_wred_lut_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;
    k.queue_size_level = key.hbm_blocks_by_voq_region;
    k.packet_size_range = key.hbm_packet_size_region;

    decltype(&v.payloads.pdvoq_slice_dram_wred_lut_result.mark_g) mark_ecn_color;
    if (key.color == la_qos_color_e::GREEN) {
        mark_ecn_color = &v.payloads.pdvoq_slice_dram_wred_lut_result.mark_g;
    } else if (key.color == la_qos_color_e::YELLOW) {
        mark_ecn_color = &v.payloads.pdvoq_slice_dram_wred_lut_result.mark_y;
    } else {
        return LA_STATUS_EUNKNOWN;
    }

    // Read current value
    // All the slices get the same values, thus it's safe to use slice 0 for read in read-modify-write
    status = tables[m_table_first_instance]->lookup(k, entry_ptr);
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status);
    }
    if (status == LA_STATUS_SUCCESS) {
        v = entry_ptr->value();
    }

    voq_prob_profile_t& mark_ecn_prob_profile
        = m_mark_dram_wred_lut[key.hbm_blocks_by_voq_region][key.hbm_packet_size_region][to_utype(key.color)];

    status = do_set_wred_probability_profile(mark_ecn_prob_profile, val.mark_ecn_probability);
    return_on_error(status);

    mark_ecn_color->region_id = mark_ecn_prob_profile->id();

    v.action = NPL_PDVOQ_SLICE_DRAM_WRED_LUT_TABLE_ACTION_WRITE;

    // Write
    la_status write_status
        = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);
    return_on_error(write_status);
    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::get_hbm_wred_mark_ecn_configuration(const la_cgm_wred_key& key, la_cgm_wred_mark_ecn_val& out_val) const
{
    start_api_getter_call();

    // Verify data correctness
    la_status status = ensure_cgm_wred_key_valid(key);
    return_on_error(status);

    // TBD ALOK confirm marking of RED behavior.
    // For Red, this return mark-all, which is mark probability of 1.0 For NONE, mark probability is 0.0
    if (key.color == la_qos_color_e::NONE || key.color == la_qos_color_e::RED) {
        if (key.color == la_qos_color_e::NONE) {
            out_val.mark_ecn_probability = 0.0;
        } else {
            out_val.mark_ecn_probability = 1.0;
        }
        return LA_STATUS_SUCCESS;
    }

    const voq_prob_profile_t& mark_ecn_prob_profile
        = m_mark_dram_wred_lut[key.hbm_blocks_by_voq_region][key.hbm_packet_size_region][to_utype(key.color)];
    if (mark_ecn_prob_profile == nullptr) {
        out_val.mark_ecn_probability = 0.0;
    } else {
        out_val.mark_ecn_probability = mark_ecn_prob_profile->value();
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::set_fcn_configuration(bool enabled, const wred_regions_probabilties& action_probabilities)
{
    start_api_call("enabled=", enabled, "action_probabilities=", action_probabilities.probabilities);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::set_fcn_configuration(bool enabled, const std::vector<double>& action_probabilities)
{

    start_api_call("enabled=", enabled, "action_probabilities=", action_probabilities);

    // Verify data correctness
    for (uint32_t index = 0; index < action_probabilities.size(); index++) {
        // All probabilities should be 0 <= pr <= 1
        if (action_probabilities[index] < 0 || action_probabilities[index] > 1) {
            return LA_STATUS_EINVAL;
        }
    }

    // Choose table
    const auto& table(m_device->m_tables.hmc_cgm_profile_global_table);

    // Prepare arguments
    npl_hmc_cgm_profile_global_table_t::key_type k;
    npl_hmc_cgm_profile_global_table_t::value_type v;
    npl_hmc_cgm_profile_global_table_t::entry_pointer_type entry_ptr = nullptr;

    if (array_size(v.payloads.hmc_cgm_profile_global_results.wred_fcn_probability_region) != action_probabilities.size()) {
        return LA_STATUS_EINVAL;
    }

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
    la_uint64_t max_pr = (1 << BITS_SIZEOF(v.payloads.hmc_cgm_profile_global_results.wred_fcn_probability_region[0], value)) - 1;

    v.payloads.hmc_cgm_profile_global_results.wred_fcn_enable = enabled;
    for (uint32_t index = 0; index < action_probabilities.size(); index++) {
        v.payloads.hmc_cgm_profile_global_results.wred_fcn_probability_region[index].value = action_probabilities[index] * max_pr;
    }
    v.action = NPL_HMC_CGM_PROFILE_GLOBAL_TABLE_ACTION_WRITE;

    // Write
    la_status write_status = table->set(k, v, entry_ptr);
    return write_status;
}

la_status
la_voq_cgm_profile_impl::get_fcn_configuration(bool& out_enabled, wred_regions_probabilties& out_action_probabilities) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_voq_cgm_profile_impl::get_fcn_configuration(bool& out_enabled, std::vector<double>& out_action_probabilities) const
{
    start_api_getter_call();

    // Choose table
    const auto& table(m_device->m_tables.hmc_cgm_profile_global_table);

    // Prepare arguments
    npl_hmc_cgm_profile_global_table_t::key_type k;
    npl_hmc_cgm_profile_global_table_t::value_type v;
    npl_hmc_cgm_profile_global_table_t::entry_pointer_type entry_ptr = nullptr;

    k.profile_id.value = m_index;

    out_action_probabilities.resize(array_size(v.payloads.hmc_cgm_profile_global_results.wred_fcn_probability_region));
    out_action_probabilities.clear();

    // Read value
    la_status status = table->lookup(k, entry_ptr);
    return_on_error(status);

    v = entry_ptr->value();

    // Modify output
    la_uint64_t max_pr = (1 << BITS_SIZEOF(v.payloads.hmc_cgm_profile_global_results.wred_fcn_probability_region[0], value)) - 1;

    out_enabled = v.payloads.hmc_cgm_profile_global_results.wred_fcn_enable;
    for (uint32_t index = 0; index < out_action_probabilities.size(); index++) {
        out_action_probabilities[index]
            = double(v.payloads.hmc_cgm_profile_global_results.wred_fcn_probability_region[index].value) / max_pr;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_voq_cgm_profile_impl::attach_voq(bool is_mc)
{
    // Validate that there are users if the pd counter is set to either UC/MC
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

    // If the voq_cgm_pd_counter type was already set, just increase use count
    if (m_voq_cgm_pd_counter != VOQ_CGM_PD_COUNTER_INVALID) {
        m_use_count++;

        return LA_STATUS_SUCCESS;
    }

    m_voq_cgm_pd_counter = requested_counter;
    m_use_count++;

    la_status status = configure_voq_cgm_slice_slice_cgm_profile();

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
    bool evict_to_hbm;

    // Eviction to HBM is not a valid config for a MC voq. Verify all configuration that might evict to HBM.

    la_uint64_t num_sms_total_bytes_regions;
    m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_total_bytes_regions);
    la_uint64_t num_sms_voq_bytes_regions;
    m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);
    la_uint64_t num_sms_age_regions;
    m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);

    for (la_quantization_region_t sms_voqs_total_bytes_region = 0; sms_voqs_total_bytes_region < num_sms_total_bytes_regions;
         sms_voqs_total_bytes_region++) {
        for (la_quantization_region_t sms_bytes_region = 0; sms_bytes_region < num_sms_voq_bytes_regions; sms_bytes_region++) {
            for (la_quantization_region_t sms_age_region = 0; sms_age_region < num_sms_age_regions; sms_age_region++) {
                status = do_get_sms_size_in_bytes_evict_behavior(
                    sms_voqs_total_bytes_region, sms_bytes_region, sms_age_region, evict_to_hbm);

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

    la_qos_color_e drop_color_level;
    la_qos_color_e mark_ecn_color_level;

    la_uint64_t num_sms_total_packets_regions;
    m_device->get_limit(limit_type_e::DEVICE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS, num_sms_total_packets_regions);
    la_uint64_t num_sms_voq_packets_regions;
    m_device->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS, num_sms_voq_packets_regions);

    for (la_quantization_region_t sms_voqs_total_packets_region = 0; sms_voqs_total_packets_region < num_sms_total_packets_regions;
         sms_voqs_total_packets_region++) {
        for (la_quantization_region_t sms_packets_region = 0; sms_packets_region < num_sms_voq_packets_regions;
             sms_packets_region++) {
            for (la_quantization_region_t sms_age_region = 0; sms_age_region < num_sms_age_regions; sms_age_region++) {

                status = do_get_sms_size_in_packets_behavior(sms_voqs_total_packets_region,
                                                             sms_packets_region,
                                                             sms_age_region,
                                                             drop_color_level,
                                                             mark_ecn_color_level,
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
