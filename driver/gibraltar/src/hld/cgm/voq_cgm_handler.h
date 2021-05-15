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

#ifndef __VOQ_CGM_HANDLER_H__
#define __VOQ_CGM_HANDLER_H__

#include "api/types/la_cgm_types.h"
#include "api/types/la_common_types.h"
#include "common/profile_allocator.h"
#include "hld_types_fwd.h"
#include <map>
#include <vector>

/// @file @brief La_device_impl's handler for VOQ CGM configuration.
///
/// Handle la_device's API-s for managing a VOQ CGM device configurations.

namespace silicon_one
{

enum {
    NUM_HBM_CONTEXT = 4096,                   ///< Total number of contexts in HBM
    HBM_CONTEXT_PREFETCHED_FIFOS_COUNT = 134, ///< Total number of contexts that are prefetched in HW
    HBM_CONTEXT_POOL_SIZE
    = NUM_HBM_CONTEXT - 1 - HBM_CONTEXT_PREFETCHED_FIFOS_COUNT, ///< Max number of allocated contexts in the HBM.
    CGM_NUM_ECN_LEVELS = 16,                                    ///< Number of ecn mark levels
    CGM_NUM_ECN_PROBABILITY = 32,                               ///< Number of ecn mark probability
};

class la_device_impl;

class voq_cgm_handler
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    enum {
        HBM_BLOCKS_GROUP_SIZE = 16, // In pacific, all HBM quiantizations use 16 HBM blocks granularity.
    };

    explicit voq_cgm_handler(const la_device_impl_wptr& device);
    ~voq_cgm_handler();

    la_status set_cgm_wred_probabilities(uint64_t prob_profile_id, double prob_threshold);
    la_status get_cgm_wred_probabilities(uint64_t prob_profile_id, double& out_prob_threshold) const;

    la_status set_cgm_sms_voqs_age_time_granularity(la_cgm_sms_voqs_age_time_units_t sms_voqs_age_time_units);
    la_status get_cgm_sms_voqs_age_time_granularity(la_cgm_sms_voqs_age_time_units_t& out_sms_voqs_age_time_unit) const;
    la_status set_cgm_sms_voqs_bytes_quantization(const la_cgm_sms_bytes_quantization_thresholds& thresholds);
    la_status get_cgm_sms_voqs_bytes_quantization(la_cgm_sms_bytes_quantization_thresholds& out_thresholds) const;
    la_status set_cgm_sms_voqs_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds);
    la_status get_cgm_sms_voqs_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const;
    la_status set_cgm_sms_evicted_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds);
    la_status get_cgm_sms_evicted_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const;
    la_status set_cgm_sms_voqs_packets_quantization(const la_cgm_sms_packets_quantization_thresholds& thresholds);
    la_status get_cgm_sms_voqs_packets_quantization(la_cgm_sms_packets_quantization_thresholds& out_thresholds) const;
    la_status set_cgm_sms_voqs_packets_quantization(const la_voq_cgm_quantization_thresholds& thresholds);
    la_status get_cgm_sms_voqs_packets_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const;
    la_status set_cgm_hbm_number_of_voqs_quantization(const la_cgm_hbm_number_of_voqs_quantization_thresholds& thresholds);
    la_status get_cgm_hbm_number_of_voqs_quantization(la_cgm_hbm_number_of_voqs_quantization_thresholds& out_thresholds) const;
    la_status set_cgm_hbm_number_of_voqs_quantization(const la_voq_cgm_quantization_thresholds& thresholds);
    la_status get_cgm_hbm_number_of_voqs_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const;
    la_status set_hbm_pool_max_capacity(la_cgm_hbm_pool_id_t hbm_pool_id, float threshold);
    la_status get_hbm_pool_max_capacity(la_cgm_hbm_pool_id_t hbm_pool_id, float& out_threshold) const;
    la_status set_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                        const la_cgm_hbm_pool_free_blocks_quantization_thresholds& thresholds);
    la_status get_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                        la_cgm_hbm_pool_free_blocks_quantization_thresholds& out_thresholds) const;
    la_status set_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                        const la_voq_cgm_quantization_thresholds& thresholds);
    la_status get_cgm_hbm_pool_free_blocks_quantization(la_cgm_hbm_pool_id_t hbm_pool_id,
                                                        la_voq_cgm_quantization_thresholds& out_thresholds) const;
    la_status set_cgm_hbm_blocks_by_voq_quantization(const la_cgm_hbm_blocks_by_voq_quantization_thresholds& thresholds);
    la_status get_cgm_hbm_blocks_by_voq_quantization(la_cgm_hbm_blocks_by_voq_quantization_thresholds& out_thresholds) const;
    la_status set_cgm_hbm_blocks_by_voq_quantization(const la_voq_cgm_quantization_thresholds& thresholds);
    la_status get_cgm_hbm_blocks_by_voq_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const;
    la_status set_cgm_hbm_voq_age_quantization(const la_voq_cgm_quantization_thresholds& out_thresholds);
    la_status get_cgm_hbm_voq_age_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const;
    la_status save_voq_cgm_defaults();
    la_status get_voq_cgm_evicted_buffers_default_behavior(la_quantization_region_t evicted_buffers_region,
                                                           la_quantization_region_t sms_total_bytes_region,
                                                           la_quantization_region_t sms_voq_bytes_region,
                                                           la_qos_color_e& out_drop_color_level) const;
    la_status initialize();
    la_status set_cgm_ecn_probability(la_uint_t level, float probability);
    la_status get_cgm_ecn_probability(la_uint_t level, float& probability);
    la_status clear_cgm_ecn_probability(la_uint_t level);

private:
    la_status save_voq_cgm_evicted_buffers_defaults();

    std::vector /*evicted_buffers_region*/
        <std::vector /*sms_total_bytes_region*/<std::vector /*sms_voq_bytes_region*/<la_qos_color_e> > >
            m_evicted_buffers_default_behavior;

    // Device this handler belongs to
    la_device_impl_wptr m_device;

    // SMS time measure granularity
    la_cgm_sms_voqs_age_time_units_t m_sms_voqs_age_time_ns;

    // Map to set ecn levels and probabilities
    std::map<la_uint_t, la_uint_t> ecn_level_prob_map;

    // ecn number of levels
    la_uint_t cgm_ecn_num_levels;

    // ecn number of levels
    la_uint_t cgm_ecn_num_probability;

    // method to program ecn probability table
    la_status program_cgm_ecn_probability(la_uint_t level, la_uint_t int_prob, bool enable);

    // unset ecn/probability bit
    la_status clear_cgm_ecn_probability(la_uint_t level, la_uint_t prob);

    // convert probaility to integer
    la_uint_t cgm_ecn_probility_to_int(float probability);

    voq_cgm_handler() = default; // For serialization purposes only.

}; // class voq_cgm_handler

} // namespace silicon_one

#endif // __VOQ_CGM_HANDLER_H__
