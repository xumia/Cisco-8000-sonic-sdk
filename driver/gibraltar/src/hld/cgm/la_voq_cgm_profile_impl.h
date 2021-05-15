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

#ifndef __LA_VOQ_CGM_PROFILE_IMPL_H__
#define __LA_VOQ_CGM_PROFILE_IMPL_H__

#include "api/cgm/la_voq_cgm_profile.h"
#include "common/math_utils.h"
#include "common/profile_allocator.h"
#include "hld_types.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_device_impl;
class la_voq_cgm_evicted_profile;
enum class limit_type_e;

class la_voq_cgm_profile_impl : public la_voq_cgm_profile
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // HW memories width
    enum {
        BUFF_REGION_WIDTH = 14,    // Num of bits to store bytes quantization.
        PKT_REGION_WIDTH = 14,     // Num of bits to store packets quantization.
        TIME_REGION_WIDTH = 8,     // Num of bits to store age quantization.
        WRED_REGION_WIDTH = 19,    // Num of bits to store the VOQ-in-HBM quantization.
        WRED_EMA_WEIGHT_WIDTH = 4, // Num of bits to store the ema_coefficient.
        // WRED_PROBABILITY_REGION_WIDTH = 17, // Num of bits to store the wred probabilities.
        SMS_NUM_BYTES_QUANTIZATION_REGIONS = 16,   // Num of bytes quantization regions
        SMS_NUM_PACKETS_QUANTIZATION_REGIONS = 8,  // Num of packets quantization regions
        SMS_NUM_AGE_QUANTIZATION_REGIONS = 16,     // Num of age quantization regions
        WRED_NUM_BLOCKS_QUANTIZATION_REGIONS = 16, // Num of age WRED blocks quantization regions
        // The four following enums define the number of configurable regions for each parameter
        SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS = SMS_NUM_BYTES_QUANTIZATION_REGIONS - 1,
        SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS = SMS_NUM_PACKETS_QUANTIZATION_REGIONS - 1,
        SMS_NUM_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS = SMS_NUM_AGE_QUANTIZATION_REGIONS - 1,
        WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS = WRED_NUM_BLOCKS_QUANTIZATION_REGIONS - 1, // All are configurable
    };

    enum {
        // Input blocking thresholds - received from design team
        INPUT_BLOCKING_THRESHOLD_DROP = 0xd800,
        INPUT_BLOCKING_THRESHOLD_UC = 15 * UNITS_IN_MEGA,
        INPUT_BLOCKING_THRESHOLD_MC = 15 * UNITS_IN_MEGA,
    };

    enum {
        NUM_DROP_MARK_COLORS = 2, // Green, Yellow
    };

    // TBD Alok how did we get this precision.
    constexpr static double probability_precision = 0.00001;

    explicit la_voq_cgm_profile_impl(const la_device_impl_wptr& device);
    virtual ~la_voq_cgm_profile_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, uint64_t voq_cgm_profile_index);
    la_status destroy();

    // Inherited API-s
    /* Returns LA_STATUS_ENOTSUP */
    la_status set_sms_bytes_quantization(const sms_bytes_quantization_thresholds& thresholds) override;
    /* Returns LA_STATUS_ENOTSUP */
    la_status get_sms_bytes_quantization(sms_bytes_quantization_thresholds& out_thresholds) const override;
    /* Returns LA_STATUS_ENOTSUP */
    la_status set_sms_packets_quantization(const sms_packets_quantization_thresholds& thresholds) override;
    /* Returns LA_STATUS_ENOTSUP */
    la_status get_sms_packets_quantization(sms_packets_quantization_thresholds& out_thresholds) const override;
    /* Returns LA_STATUS_ENOTSUP */
    la_status set_sms_age_quantization(const sms_age_quantization_thresholds& thresholds) override;
    /* Returns LA_STATUS_ENOTSUP */
    la_status get_sms_age_quantization(sms_age_quantization_thresholds& out_thresholds) const override;

    la_status set_sms_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds) override;
    la_status get_sms_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const override;
    la_status set_sms_packets_quantization(const la_voq_cgm_quantization_thresholds& thresholds) override;
    la_status get_sms_packets_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const override;
    la_status set_sms_age_quantization(const la_voq_cgm_quantization_thresholds& thresholds) override;
    la_status get_sms_age_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const override;

    /* Returns LA_STATUS_ENOTSUP */
    la_status set_sms_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                             la_quantization_region_t sms_bytes_region,
                                             la_quantization_region_t sms_age_region,
                                             la_quantization_region_t hbm_total_number_of_voqs_region,
                                             la_qos_color_e drop_color_level,
                                             bool mark_ecn,
                                             bool evict_to_hbm) override;
    /* Returns LA_STATUS_ENOTSUP */
    la_status get_sms_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                             la_quantization_region_t sms_bytes_region,
                                             la_quantization_region_t sms_age_region,
                                             la_quantization_region_t hbm_total_number_of_voqs_region,
                                             la_qos_color_e& out_drop_color_level,
                                             bool& out_mark_ecn,
                                             bool& out_evict_to_hbm) const override;

    la_status set_cgm_evicted_profile_mapping(la_voq_cgm_evicted_profile* evicted_profile) override;
    la_status get_cgm_evicted_profile_mapping(la_voq_cgm_evicted_profile*& out_evicted_profile) const override;
    la_status clear_cgm_evicted_profile_mapping() override;
    la_status set_sms_evict_behavior(const la_voq_sms_evict_key& key, const la_voq_sms_evict_val& val) override;
    la_status get_sms_evict_behavior(const la_voq_sms_evict_key& key, la_voq_sms_evict_val& out_val) const override;
    la_status set_sms_wred_drop_probability(const la_voq_sms_wred_drop_probability_selector_key& key,
                                            const la_voq_sms_wred_drop_probability_selector_drop_val& val) override;
    la_status get_sms_wred_drop_probability(const la_voq_sms_wred_drop_probability_selector_key& key,
                                            la_voq_sms_wred_drop_probability_selector_drop_val& out_val) const override;
    la_status set_sms_wred_mark_probability(const la_voq_sms_wred_mark_probability_selector_key& key,
                                            const la_voq_sms_wred_mark_probability_selector_mark_val& val) override;
    la_status get_sms_wred_mark_probability(const la_voq_sms_wred_mark_probability_selector_key& key,
                                            la_voq_sms_wred_mark_probability_selector_mark_val& out_val) const override;
    la_status set_sms_size_in_bytes_drop_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                  const la_voq_sms_size_in_bytes_drop_val& val) override;
    la_status get_sms_size_in_bytes_drop_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                  la_voq_sms_size_in_bytes_drop_val& out_val) const override;
    la_status set_sms_size_in_bytes_mark_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                  const la_voq_sms_size_in_bytes_mark_val& val) override;
    la_status get_sms_size_in_bytes_mark_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                  la_voq_sms_size_in_bytes_mark_val& out_val) const override;
    la_status set_sms_size_in_bytes_evict_behavior(const la_voq_sms_size_in_bytes_evict_key& key,
                                                   const la_voq_sms_size_in_bytes_evict_val& val) override;
    la_status get_sms_size_in_bytes_evict_behavior(const la_voq_sms_size_in_bytes_evict_key& key,
                                                   la_voq_sms_size_in_bytes_evict_val& out_val) const override;
    la_status set_sms_dequeue_size_in_bytes_congestion_level(const la_voq_sms_dequeue_size_in_bytes_key& key,
                                                             const la_voq_sms_dequeue_size_in_bytes_congestion_val& val) override;
    la_status get_sms_dequeue_size_in_bytes_congestion_level(
        const la_voq_sms_dequeue_size_in_bytes_key& key,
        la_voq_sms_dequeue_size_in_bytes_congestion_val& out_val) const override;

    /// Legacy method, returning LA_STATUS_ENOTIMPLEMENTED on GB
    la_status set_sms_size_in_packets_behavior(la_quantization_region_t,
                                               la_quantization_region_t,
                                               la_quantization_region_t,
                                               la_qos_color_e,
                                               bool,
                                               bool) override;

    /// Legacy method, returning LA_STATUS_ENOTIMPLEMENTED on GB
    la_status get_sms_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                               la_quantization_region_t sms_packets_region,
                                               la_quantization_region_t sms_age_region,
                                               la_qos_color_e& out_drop_color_level,
                                               bool& out_mark_ecn,
                                               bool& out_evict_to_hbm) const override;

    la_status set_sms_dequeue_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                     la_quantization_region_t sms_bytes_region,
                                                     bool mark_ecn) override;
    la_status get_sms_dequeue_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                     la_quantization_region_t sms_bytes_region,
                                                     bool& out_mark_ecn) const override;
    la_status set_sms_dequeue_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                       bool mark_ecn) override;
    la_status get_sms_dequeue_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                       bool& out_mark_ecn) const override;

    la_status set_sms_size_in_packets_drop_behavior(const la_voq_sms_size_in_packets_key& key,
                                                    const la_voq_sms_size_in_packets_drop_val& val) override;
    la_status set_sms_size_in_packets_mark_behavior(const la_voq_sms_size_in_packets_key& key,
                                                    const la_voq_sms_size_in_packets_mark_val& val) override;
    la_status set_sms_size_in_packets_evict_behavior(const la_voq_sms_size_in_packets_key& key,
                                                     const la_voq_sms_size_in_packets_evict_val& val) override;
    la_status set_sms_dequeue_size_in_packets_congestion_level(
        const la_voq_sms_dequeue_size_in_packets_key& key,
        const la_voq_sms_dequeue_size_in_packets_congestion_val& val) override;
    la_status get_sms_dequeue_size_in_packets_congestion_level(
        const la_voq_sms_dequeue_size_in_packets_key& key,
        la_voq_sms_dequeue_size_in_packets_congestion_val& val) const override;
    la_status get_sms_size_in_packets_drop_behavior(const la_voq_sms_size_in_packets_key& key,
                                                    la_voq_sms_size_in_packets_drop_val& out_val) const override;
    la_status get_sms_size_in_packets_mark_behavior(const la_voq_sms_size_in_packets_key& key,
                                                    la_voq_sms_size_in_packets_mark_val& out_val) const override;
    la_status get_sms_size_in_packets_evict_behavior(const la_voq_sms_size_in_packets_key& key,
                                                     la_voq_sms_size_in_packets_evict_val& out_val) const override;

    // Legacy, returns ENOTSUP
    la_status set_hbm_size_in_blocks_behavior(la_quantization_region_t hbm_blocks_by_voq_region,
                                              la_quantization_region_t hbm_pool_free_blocks_region,
                                              la_qos_color_e drop_color_level,
                                              bool mark_ecn) override;
    // Legacy, returns ENOTSUP
    la_status get_hbm_size_in_blocks_behavior(la_quantization_region_t hbm_blocks_by_voq_region,
                                              la_quantization_region_t hbm_pool_free_blocks_region,
                                              la_qos_color_e& out_drop_color_level,
                                              bool& out_mark_ecn) const override;

    la_status set_hbm_size_in_blocks_drop_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                   const la_cgm_hbm_size_in_blocks_drop_val& val) override;
    la_status get_hbm_size_in_blocks_drop_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                   la_cgm_hbm_size_in_blocks_drop_val& out_val) const override;
    la_status set_hbm_size_in_blocks_mark_ecn_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                       const la_cgm_hbm_size_in_blocks_mark_ecn_val& val) override;
    la_status get_hbm_size_in_blocks_mark_ecn_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                       la_cgm_hbm_size_in_blocks_mark_ecn_val& out_val) const override;
    la_status set_hbm_dequeue_size_in_blocks_congestion_level(const la_cgm_hbm_dequeue_size_in_blocks_key& key,
                                                              const la_cgm_hbm_dequeue_size_in_blocks_congestion_val& val) override;
    la_status get_hbm_dequeue_size_in_blocks_congestion_level(
        const la_cgm_hbm_dequeue_size_in_blocks_key& key,
        la_cgm_hbm_dequeue_size_in_blocks_congestion_val& out_val) const override;

    la_status set_associated_hbm_pool(la_cgm_hbm_pool_id_t hbm_pool_id) override;
    la_status get_associated_hbm_pool(la_cgm_hbm_pool_id_t& out_hbm_pool_id) const override;

    // Legacy, returns ENOTSUP
    la_status set_averaging_configuration(double ema_coefficient, const wred_blocks_quantization_thresholds& thresholds) override;
    la_status get_averaging_configuration(double& out_ema_coefficient,
                                          wred_blocks_quantization_thresholds& out_thresholds) const override;

    la_status set_averaging_configuration(double ema_coefficient, const la_voq_cgm_quantization_thresholds& thresholds) override;
    la_status get_averaging_configuration(double& out_ema_coefficient,
                                          la_voq_cgm_quantization_thresholds& out_thresholds) const override;

    // Legacy, returns ENOTSUP
    la_status set_wred_configuration(wred_action_e action, const wred_regions_probabilties& action_probabilities) override;
    la_status get_wred_configuration(wred_action_e& out_action, wred_regions_probabilties& out_action_probabilities) const override;

    la_status set_hbm_wred_drop_configuration(const la_cgm_wred_key& key, const la_cgm_wred_drop_val& val) override;
    la_status get_hbm_wred_drop_configuration(const la_cgm_wred_key& key, la_cgm_wred_drop_val& out_val) const override;
    la_status set_hbm_wred_mark_ecn_configuration(const la_cgm_wred_key& key, const la_cgm_wred_mark_ecn_val& val) override;
    la_status get_hbm_wred_mark_ecn_configuration(const la_cgm_wred_key& key, la_cgm_wred_mark_ecn_val& out_val) const override;

    // Legacy, returns ENOTSUP
    la_status set_fcn_configuration(bool enabled, const wred_regions_probabilties& action_probabilities) override;
    la_status get_fcn_configuration(bool& out_enabled, wred_regions_probabilties& out_action_probabilities) const override;

    la_status set_fcn_configuration(bool enabled, const std::vector<double>& action_probabilities) override;
    la_status get_fcn_configuration(bool& out_enabled, std::vector<double>& out_action_probabilities) const override;

    // la_object API-s
    virtual object_type_e type() const override;
    virtual const la_device* get_device() const override;
    virtual la_object_id_t oid() const override;
    virtual std::string to_string() const override;

    /// @brief Get profile ID.
    ///
    /// @return Profile ID in hardware.
    uint64_t get_id() const;

    la_status attach_voq(bool is_mc);
    la_status detach_voq();

private:
    using voq_prob_profile_t = profile_allocator<double>::profile_ptr;

    // Helper functions for validating ranges of parameters
    la_status ensure_sms_evict_key_valid(const la_voq_sms_evict_key& key) const;
    double round_up_probability_to_precision(double probability) const;

    // Helper functions for initializing profile configuration
    la_status initialize_probability_profiles();
    la_status set_defaults();
    la_status do_set_sms_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds);

    // SMS helpers - bytes
    la_status ensure_sms_wred_drop_probability_selector_key_valid(const la_voq_sms_wred_drop_probability_selector_key& key) const;
    la_status ensure_sms_wred_mark_probability_selector_key_valid(const la_voq_sms_wred_mark_probability_selector_key& key) const;
    la_status ensure_sms_size_in_bytes_evict_key_valid(const la_voq_sms_size_in_bytes_evict_key& key) const;
    la_status do_set_cgm_evicted_profile_mapping(const la_voq_cgm_evicted_profile_wptr& evicted_profile);
    la_status do_set_wred_probability_profile(voq_prob_profile_t& prob_profile, double probability);
    la_status do_reset_wred_probability_profile(voq_prob_profile_t& prob_profile);
    la_status do_set_sms_wred_drop_green_probability(la_quantization_region_t packet_size_region,
                                                     la_cgm_sms_bytes_probability_level_t drop_probability_level,
                                                     double probability);
    la_status do_set_sms_wred_drop_yellow_probability(la_quantization_region_t packet_size_region,
                                                      la_cgm_sms_bytes_probability_level_t drop_probability_level,
                                                      double probability);

    la_status do_set_sms_size_in_bytes_evict_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                      la_quantization_region_t sms_bytes_region,
                                                      la_quantization_region_t sms_age_region,
                                                      bool evict_to_hbm);
    la_status do_get_sms_size_in_bytes_evict_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                      la_quantization_region_t sms_bytes_region,
                                                      la_quantization_region_t sms_age_region,
                                                      bool& out_evict_to_hbm) const;

    la_status ensure_sms_size_in_bytes_color_key_valid(const la_voq_sms_size_in_bytes_color_key& key) const;
    la_status do_set_sms_size_in_bytes_color_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                      la_quantization_region_t sms_bytes_region,
                                                      la_quantization_region_t sms_age_region,
                                                      la_qos_color_e color,
                                                      la_cgm_sms_bytes_probability_level_t drop_probability,
                                                      la_cgm_sms_bytes_probability_level_t mark_ecn_probability);
    la_status do_get_sms_size_in_bytes_color_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                      la_quantization_region_t sms_bytes_region,
                                                      la_quantization_region_t sms_age_region,
                                                      la_qos_color_e color,
                                                      la_cgm_sms_bytes_probability_level_t& out_drop_probability_level,
                                                      la_cgm_sms_bytes_probability_level_t& out_mark_ecn_probability_level) const;
    la_status ensure_sms_dequeue_size_in_bytes_key_valid(const la_voq_sms_dequeue_size_in_bytes_key& key) const;

    // SMS helpers - packets
    la_status ensure_sms_packets_key_valid(const la_voq_sms_size_in_packets_key& key) const;

    la_status do_get_sms_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                  la_quantization_region_t sms_packets_region,
                                                  la_quantization_region_t sms_age_region,
                                                  la_qos_color_e& out_drop_color_level,
                                                  la_qos_color_e& out_mark_ecn_color_level,
                                                  bool& out_evict_to_hbm) const;

    la_status do_set_sms_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                  la_quantization_region_t sms_packets_region,
                                                  la_quantization_region_t sms_age_region,
                                                  la_qos_color_e drop_color_level,
                                                  la_qos_color_e mark_ecn_color_level,
                                                  bool evict_to_hbm);
    la_status ensure_sms_dequeue_size_in_packets_key_valid(const la_voq_sms_dequeue_size_in_packets_key& key) const;

    // HBM helpers
    la_status ensure_hbm_size_in_blocks_key_valid(const la_cgm_hbm_size_in_blocks_key& key) const;
    la_status do_set_hbm_size_in_blocks_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                 bool is_drop_action,
                                                 la_qos_color_e color);
    la_status do_get_hbm_size_in_blocks_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                 bool is_drop_action,
                                                 la_qos_color_e& out_color) const;
    la_status ensure_hbm_dequeue_size_in_blocks_key_valid(const la_cgm_hbm_dequeue_size_in_blocks_key& key) const;
    bool is_valid_for_mc_voq() const;
    la_status ensure_cgm_wred_key_valid(const la_cgm_wred_key& key) const;

private:
    static constexpr npl_voq_cgm_pd_counter_e VOQ_CGM_PD_COUNTER_INVALID = (npl_voq_cgm_pd_counter_e)-1;

    la_status configure_voq_cgm_slice_slice_cgm_profile();
    la_status teardown_voq_cgm_slice_slice_cgm_profile();

    // Device this VOQ profile belongs to
    la_device_impl_wptr m_device;

    // Object index
    uint64_t m_index;

    // Object ID
    la_object_id_t m_oid;

    // PD counter type
    npl_voq_cgm_pd_counter_e m_voq_cgm_pd_counter;

    // Use-count
    size_t m_use_count;

    // Mapped evicted profile
    la_voq_cgm_evicted_profile_wptr m_evicted_profile;

    std::vector      /* pkt_size_region */
        <std::vector /* drop_prob_select_region */
         <std::vector</*color*/ voq_prob_profile_t> > >
            m_drop_prob_select_profile;

    std::vector      /* pkt_size_region */
        <std::vector /* drop_prob_select_region */
         <std::vector</*color*/ voq_prob_profile_t> > >
            m_mark_prob_select_profile;

    std::vector      /* hbm_blocks_by_voq_region */
        <std::vector /* packet_size_region */
         <std::vector</*color*/ voq_prob_profile_t> > >
            m_drop_dram_wred_lut;

    std::vector      /* hbm_blocks_by_voq_region */
        <std::vector /* packet_size_region */
         <std::vector</*color*/ voq_prob_profile_t> > >
            m_mark_dram_wred_lut;

    la_voq_cgm_profile_impl() = default; // For serialization purposes only.

    size_t m_table_first_instance;
};
}

#endif
