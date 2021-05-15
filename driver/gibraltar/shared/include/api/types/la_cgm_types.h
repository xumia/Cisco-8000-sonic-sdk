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

#ifndef __LA_CGM_TYPES_H__
#define __LA_CGM_TYPES_H__

#include <stddef.h>
#include <stdint.h>
#include <vector>

#include "api/types/la_common_types.h"

/// @file
/// @brief Leaba Congestion Management definitions.
///
/// Defines CGM related types and enumerations used by the Leaba API.

namespace silicon_one
{

/// @addtogroup CGM_TYPES
/// @{

class la_voq_cgm_evicted_profile;
class la_voq_cgm_profile;

/// @brief Quantization region number.
typedef size_t la_quantization_region_t;

/// @brief HBM pool ID.
typedef la_uint_t la_cgm_hbm_pool_id_t;

/// @brief Congestion Level.
typedef la_uint8_t la_cgm_congestion_level_t;

/// @brief SMS drop and mark probability levels.
/// Drop probability of any level value between #silicon_one::LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_ADMIT and
/// #silicon_one::LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP is configurable using
/// #silicon_one::la_voq_cgm_profile::set_sms_wred_drop_probability.
/// Mark Probability of any level value higher than #silicon_one::LA_CGM_SMS_BYTES_MARK_PROBABILITY_LEVEL_DONT_MARK is
/// configurable using #silicon_one::la_voq_cgm_profile::set_sms_wred_mark_probability.
typedef size_t la_cgm_sms_bytes_probability_level_t;
constexpr la_cgm_sms_bytes_probability_level_t LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_ADMIT = 0;
constexpr la_cgm_sms_bytes_probability_level_t LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP = 7;
constexpr la_cgm_sms_bytes_probability_level_t LA_CGM_SMS_BYTES_MARK_PROBABILITY_LEVEL_DONT_MARK = 0;

/// @brief Defines the number of quantization regions and configurable thresholds of measurable quantities in SMS and HBM.
enum {
    /// Number of regions. DEPRECATED.
    LA_CGM_NUM_SMS_BYTES_QUANTIZATION_REGIONS = 4,
    LA_CGM_NUM_SMS_PACKETS_QUANTIZATION_REGIONS = 4,

    LA_CGM_NUM_HBM_NUMBER_OF_VOQS_QUANTIZATION_REGIONS = 2,
    LA_CGM_NUM_HBM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS = 8,
    LA_CGM_NUM_HBM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS = 16,
    LA_CGM_NUM_HBM_VOQ_AGE_QUANTIZATION_REGIONS = 16,
    LA_RX_CGM_NUM_SQG_QUANTIZATION_REGIONS = 4,
    LA_RX_CGM_NUM_SQ_PROFILE_QUANTIZATION_REGIONS = 4,
    LA_RX_PDR_SMS_BYTES_DROP_REGIONS = 3,

    /// Number of thresholds. DEPRECATED.
    LA_CGM_NUM_SMS_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS = LA_CGM_NUM_SMS_BYTES_QUANTIZATION_REGIONS - 1,
    LA_CGM_NUM_SMS_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS = LA_CGM_NUM_SMS_PACKETS_QUANTIZATION_REGIONS - 1,
    LA_CGM_NUM_HBM_NUMBER_OF_VOQS_QUANTIZATION_CONFIGURABLE_THRESHOLDS = LA_CGM_NUM_HBM_NUMBER_OF_VOQS_QUANTIZATION_REGIONS - 1,
    LA_CGM_NUM_HBM_POOL_FREE_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS = LA_CGM_NUM_HBM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS - 1,
    LA_CGM_NUM_HBM_BLOCKS_BY_VOQ_QUANTIZATION_CONFIGURABLE_THRESHOLDS = LA_CGM_NUM_HBM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS - 1,
    LA_CGM_NUM_HBM_VOQ_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS = LA_CGM_NUM_HBM_VOQ_AGE_QUANTIZATION_REGIONS - 1,
    LA_RX_CGM_NUM_SQG_CONFIGURABLE_THRESHOLDS = LA_RX_CGM_NUM_SQG_QUANTIZATION_REGIONS - 1,
    LA_RX_CGM_NUM_SQ_PROFILE_CONFIGURABLE_THRESHOLDS = LA_RX_CGM_NUM_SQ_PROFILE_QUANTIZATION_REGIONS - 1,
    LA_RX_PDR_SMS_BYTES_DROP_CONFIGURABLE_THRESHOLDS = LA_RX_PDR_SMS_BYTES_DROP_REGIONS - 1,
};

enum {
    // Number of status used in RXCGM policy decision.
    LA_RX_CGM_NUM_SQ_PROFILE_STATUS = 3,
};

/// @brief HR management mode for RXCGM flow control.
enum class la_rx_cgm_headroom_mode_e {
    TIMER = 0,
    THRESHOLD = 1,
};

/// @brief VOQ-in-SMS age time units
typedef la_uint_t la_cgm_sms_voqs_age_time_units_t;

/// @brief Quantization thresholds for quantized parameters of congestion manager.
///
/// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is
/// infinity. N may be obtained by using la_device::get_limit API for each quantization parameter.
/// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
/// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
struct la_voq_cgm_quantization_thresholds {
    std::vector<la_uint_t> thresholds;
};

/// @brief WRED probabilities of congestion manager.
///
/// Probabilities are provided for N regions. Each probability must be between 0.0 and 1.0.
/// N may be obtained by using la_device::get_limit API.
/// The probabilities must be monotonically increasing ordered.
struct la_voq_cgm_probability_regions {
    std::vector<double> probabilities;
};

/// @name Global quantization of total buffer quantities
/// @{

/// @brief Quantization thresholds for the size in bytes of the SMS.
///
/// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is infinity.
/// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
/// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
struct la_cgm_sms_bytes_quantization_thresholds {
    la_uint_t thresholds[LA_CGM_NUM_SMS_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS];
};

/// @brief Quantization thresholds for the size in packets of the SMS.
///
/// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is infinity.
/// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
/// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
struct la_cgm_sms_packets_quantization_thresholds {
    la_uint_t thresholds[LA_CGM_NUM_SMS_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS];
};

/// @brief Quantization thresholds for the number of VOQ's evicted to the HBM.
///
/// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is infinity.
/// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
/// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
struct la_cgm_hbm_number_of_voqs_quantization_thresholds {
    la_uint_t thresholds[LA_CGM_NUM_HBM_NUMBER_OF_VOQS_QUANTIZATION_CONFIGURABLE_THRESHOLDS];
};

/// @brief Quantization thresholds for the number of free blocks in an HBM pool.
///
/// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is infinity.
/// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
/// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
struct la_cgm_hbm_pool_free_blocks_quantization_thresholds {
    la_uint_t thresholds[LA_CGM_NUM_HBM_POOL_FREE_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS];
};

/// @brief Quantization thresholds for SQ-s size in bytes for RXCGM flow control/congestion.
///
/// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is infinity.
/// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
/// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
struct la_rx_cgm_sms_bytes_quantization_thresholds {
    la_uint64_t thresholds[LA_CGM_NUM_SMS_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS];
};

/// @brief Quantization thresholds for SQ Groups for RXCGM flow control/congestion.
///
/// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is infinity.
/// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
/// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
struct la_rx_cgm_sqg_thresholds {
    la_uint64_t thresholds[LA_RX_CGM_NUM_SQG_CONFIGURABLE_THRESHOLDS];
};

/// @brief Quantization thresholds for SQ Profiles for RXCGM flow control/congestion.
///
/// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is infinity.
/// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
/// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
struct la_rx_cgm_sq_profile_thresholds {
    la_uint64_t thresholds[LA_RX_CGM_NUM_SQ_PROFILE_CONFIGURABLE_THRESHOLDS];
};

/// @brief Status for RXCGM SQ profile policies.
///
/// RXCGM flow control/drop decisions/policies are made based on combination of 3 statuses, which can
/// take any value from 0-3. These statuses represent the regions given by the configured thresholds.
struct la_rx_cgm_policy_status {
    la_uint_t counter_a_region;
    la_uint_t sq_group_region;
    la_uint_t sq_profile_region;
};

/// @brief Quantization thresholds for SQ Profiles for RXPDR drop.
///
/// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is infinity.
/// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
/// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
struct la_rx_pdr_sms_bytes_drop_thresholds {
    la_uint_t thresholds[LA_RX_PDR_SMS_BYTES_DROP_CONFIGURABLE_THRESHOLDS];
};

/// @brief Thresholds for OQ Profiles for flow control and drop.
///
/// Thresholds are provided in bytes, buffers, and packet descripters. Each are independent of the other - if any threshold
/// is exceeded, flow control/drop is asserted.
struct la_tx_cgm_oq_profile_thresholds {
    la_uint_t fc_bytes_threshold;
    la_uint_t fc_buffers_threshold;
    la_uint_t fc_pds_threshold;
    la_uint_t drop_bytes_threshold;
    la_uint_t drop_buffers_threshold;
    la_uint_t drop_pds_threshold;
};

/// @}

/// @name Global quantization of per-VOQ buffer quantities
/// @{

/// @brief Quantization thresholds for the size in blocks of a VOQ in the HBM.
///
/// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is infinity.
/// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
/// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
struct la_cgm_hbm_blocks_by_voq_quantization_thresholds {
    la_uint_t thresholds[LA_CGM_NUM_HBM_BLOCKS_BY_VOQ_QUANTIZATION_CONFIGURABLE_THRESHOLDS];
};
/// @}

enum class la_qos_color_e;

struct la_voq_sms_evicted_buffers_key {
    la_voq_sms_evicted_buffers_key() = default;
    la_voq_sms_evicted_buffers_key(la_quantization_region_t evicted_buffers_region,
                                   la_quantization_region_t sms_voqs_total_bytes_region,
                                   la_quantization_region_t sms_bytes_region)
        : evicted_buffers_region(evicted_buffers_region),
          sms_voqs_total_bytes_region(sms_voqs_total_bytes_region),
          sms_bytes_region(sms_bytes_region)
    {
    }

    la_quantization_region_t evicted_buffers_region;      ///< Quantized size of total evicted SMS buffers.
    la_quantization_region_t sms_voqs_total_bytes_region; ///< Quantized size of SMS used bytes by all VOQs.  Configured by
                                                          /// silicon_one::la_device::set_cgm_sms_voqs_bytes_quantization.
    la_quantization_region_t sms_bytes_region;            ///< Quantized size of VOQ-in-SMS used bytes. Configured by
                                                          /// silicon_one::la_voq_cgm_profile::set_sms_bytes_quantization.
};

struct la_voq_sms_evicted_buffers_drop_val {
    la_voq_sms_evicted_buffers_drop_val() = default;
    explicit la_voq_sms_evicted_buffers_drop_val(la_qos_color_e drop_color_level) : drop_color_level(drop_color_level)
    {
    }
    la_qos_color_e drop_color_level; ///< Packets color above (including) which to drop packet.
};

struct la_voq_sms_evict_key {
    la_voq_sms_evict_key() = default;
    la_voq_sms_evict_key(la_quantization_region_t evicted_buffers_region, la_quantization_region_t free_dram_cntxt_region)
        : evicted_buffers_region(evicted_buffers_region), free_dram_cntxt_region(free_dram_cntxt_region)
    {
    }
    la_quantization_region_t evicted_buffers_region; ///< Quantized size of total evicted SMS buffers.
    la_quantization_region_t free_dram_cntxt_region; ///< Available DRAM context level.
};

struct la_voq_sms_evict_val {
    la_voq_sms_evict_val() = default;
    la_voq_sms_evict_val(bool permit_eviction, bool drop_on_eviction)
        : permit_eviction(permit_eviction), drop_on_eviction(drop_on_eviction)
    {
    }
    bool permit_eviction;  ///< OK to evict.
    bool drop_on_eviction; ///< Drop PD on eviction decision.
};

struct la_voq_sms_wred_drop_probability_selector_key {
    la_voq_sms_wred_drop_probability_selector_key() = default;
    la_voq_sms_wred_drop_probability_selector_key(la_quantization_region_t packet_size_region,
                                                  la_cgm_sms_bytes_probability_level_t drop_probability_level,
                                                  la_qos_color_e color)
        : packet_size_region(packet_size_region), drop_probability_level(drop_probability_level), color(color)
    {
    }
    la_quantization_region_t packet_size_region;                 ///< Quantized size of packet. Valid values are [0-5].
                                                                 ///< 0:0-127B, 1:128-255B, 2:256-511B, 3:512B-1023B,
                                                                 ///< 4:1024B-2047B, 5:2048B and up, 6-7: Unused.
    la_cgm_sms_bytes_probability_level_t drop_probability_level; ///< Index of probability configured by
                                                                 ///#silicon_one::la_voq_cgm_profile::set_sms_wred_drop_probability.
    la_qos_color_e color;
};

struct la_voq_sms_wred_drop_probability_selector_drop_val {
    la_voq_sms_wred_drop_probability_selector_drop_val() = default;
    explicit la_voq_sms_wred_drop_probability_selector_drop_val(double drop_probability) : drop_probability(drop_probability)
    {
    }
    double drop_probability; ///< Drop probability.
};

struct la_voq_sms_wred_mark_probability_selector_key {
    la_voq_sms_wred_mark_probability_selector_key() = default;
    la_voq_sms_wred_mark_probability_selector_key(la_quantization_region_t packet_size_region,
                                                  la_cgm_sms_bytes_probability_level_t mark_ecn_probability_level,
                                                  la_qos_color_e color)
        : packet_size_region(packet_size_region), mark_ecn_probability_level(mark_ecn_probability_level), color(color)
    {
    }

    la_quantization_region_t packet_size_region;                     ///< Quantized size of packet. Valid values are [0-5].
                                                                     ///< 0:0-127B, 1:128-255B, 2:256-511B, 3:512B-1023B,
                                                                     ///< 4:1024B-2047B, 5:2048B and up, 6-7: Unused.
    la_cgm_sms_bytes_probability_level_t mark_ecn_probability_level; ///< Index to probability configured by
    ///#silicon_one::la_voq_cgm_profile::set_sms_wred_mark_probability.
    la_qos_color_e color; ///< Packets color.
};

struct la_voq_sms_wred_mark_probability_selector_mark_val {
    la_voq_sms_wred_mark_probability_selector_mark_val() = default;
    explicit la_voq_sms_wred_mark_probability_selector_mark_val(double mark_ecn_probability)
        : mark_ecn_probability(mark_ecn_probability)
    {
    }
    double mark_ecn_probability; ///< Mark ECN probability.
};

struct la_voq_sms_size_in_bytes_color_key {
    la_voq_sms_size_in_bytes_color_key() = default;
    la_voq_sms_size_in_bytes_color_key(la_quantization_region_t sms_voqs_total_bytes_region,
                                       la_quantization_region_t sms_bytes_region,
                                       la_quantization_region_t sms_age_region,
                                       la_qos_color_e color)
        : sms_voqs_total_bytes_region(sms_voqs_total_bytes_region),
          sms_bytes_region(sms_bytes_region),
          sms_age_region(sms_age_region),
          color(color)
    {
    }

    la_quantization_region_t sms_voqs_total_bytes_region; ///< Quantized size of SMS used bytes by all VOQs.  Configured by
                                                          /// silicon_one::la_device::set_cgm_sms_voqs_bytes_quantization.
    la_quantization_region_t sms_bytes_region;            ///< Quantized size of VOQ-in-SMS used bytes. Configured by
                                                          /// silicon_one::la_voq_cgm_profile::set_sms_bytes_quantizatio.
    la_quantization_region_t sms_age_region;              ///< Quantized size of VOQ-in-SMS age. Configured by
                                                          ///#silicon_one::la_voq_cgm_profile::sms_age_quantization_thresholds.
    la_qos_color_e color;                                 ///< Packets color.
};

struct la_voq_sms_size_in_bytes_drop_val {
    la_voq_sms_size_in_bytes_drop_val() = default;
    explicit la_voq_sms_size_in_bytes_drop_val(la_cgm_sms_bytes_probability_level_t drop_probability_level)
        : drop_probability_level(drop_probability_level)
    {
    }
    la_cgm_sms_bytes_probability_level_t drop_probability_level; ///< Index of probability configured by
                                                                 ///#silicon_one::la_voq_cgm_profile::set_sms_wred_drop_probability.
};

struct la_voq_sms_size_in_bytes_mark_val {
    la_voq_sms_size_in_bytes_mark_val() = default;
    explicit la_voq_sms_size_in_bytes_mark_val(la_cgm_sms_bytes_probability_level_t mark_ecn_probability_level)
        : mark_ecn_probability_level(mark_ecn_probability_level)
    {
    }
    la_cgm_sms_bytes_probability_level_t mark_ecn_probability_level; ///< Index to probability configured by
    ///#silicon_one::la_voq_cgm_profile::set_sms_wred_mark_probability.
};

struct la_voq_sms_size_in_bytes_evict_key {
    la_voq_sms_size_in_bytes_evict_key() = default;
    la_voq_sms_size_in_bytes_evict_key(la_quantization_region_t sms_voqs_total_bytes_region,
                                       la_quantization_region_t sms_bytes_region,
                                       la_quantization_region_t sms_age_region)
        : sms_voqs_total_bytes_region(sms_voqs_total_bytes_region),
          sms_bytes_region(sms_bytes_region),
          sms_age_region(sms_age_region)
    {
    }
    la_quantization_region_t sms_voqs_total_bytes_region; ///< Quantized size of SMS used bytes by all VOQs.  Configured by
                                                          /// silicon_one::la_device::set_cgm_sms_voqs_bytes_quantization.
    la_quantization_region_t sms_bytes_region;            ///< Quantized size of VOQ-in-SMS used bytes. Configured by
                                                          /// silicon_one::la_voq_cgm_profile::set_sms_bytes_quantizatio.
    la_quantization_region_t sms_age_region;              ///< Quantized size of VOQ-in-SMS age. Configured by
                                                          ///#silicon_one::la_voq_cgm_profile::sms_age_quantization_thresholds.
};

struct la_voq_sms_size_in_bytes_evict_val {
    la_voq_sms_size_in_bytes_evict_val() = default;
    explicit la_voq_sms_size_in_bytes_evict_val(bool evict_to_hbm) : evict_to_hbm(evict_to_hbm)
    {
    }
    bool evict_to_hbm; ///< Evict eligibility for the VOQ from SMS to HBM. Final eviction decision will be
    ///< based on this eligibilty and if eviction is permited by #silicon_one::la_voq_cgm_profile::set_sms_evict_behavior.
};

struct la_voq_sms_dequeue_size_in_bytes_key {
    la_voq_sms_dequeue_size_in_bytes_key() = default;
    la_voq_sms_dequeue_size_in_bytes_key(la_quantization_region_t sms_voqs_total_bytes_region,
                                         la_quantization_region_t sms_bytes_region,
                                         la_quantization_region_t sms_age_region)
        : sms_voqs_total_bytes_region(sms_voqs_total_bytes_region),
          sms_bytes_region(sms_bytes_region),
          sms_age_region(sms_age_region)
    {
    }
    la_quantization_region_t sms_voqs_total_bytes_region; ///< Quantized size of SMS used bytes by all VOQs.  Configured by
                                                          /// #silicon_one::la_device::set_cgm_sms_voqs_bytes_quantization.
    la_quantization_region_t sms_bytes_region;            ///< Quantized size of VOQ-in-SMS used bytes. Configured by
                                                          /// #silicon_one::la_voq_cgm_profile::set_sms_bytes_quantization.
    la_quantization_region_t sms_age_region;              ///< Quantized size of VOQ-in-SMS age. Configured by
                                                          ///#silicon_one::la_voq_cgm_profile::sms_age_quantization_thresholds.
};

struct la_voq_sms_dequeue_size_in_bytes_congestion_val {
    la_cgm_congestion_level_t congestion_level; ///< Congestion level.
};

struct la_voq_sms_size_in_packets_key {
    la_voq_sms_size_in_packets_key() = default;
    la_voq_sms_size_in_packets_key(la_quantization_region_t sms_voqs_total_packets_region,
                                   la_quantization_region_t sms_packets_region,
                                   la_quantization_region_t sms_age_region)
        : sms_voqs_total_packets_region(sms_voqs_total_packets_region),
          sms_packets_region(sms_packets_region),
          sms_age_region(sms_age_region)
    {
    }
    la_quantization_region_t sms_voqs_total_packets_region; ///< Quantized size of SMS used packets by all VOQs. Configured by
                                                            /// silicon_one::la_device::set_cgm_sms_voqs_packets_quantization.
    la_quantization_region_t sms_packets_region;            ///< Quantized size of VOQ-in-SMS used packets. Configured by
                                                            /// silicon_one::la_voq_cgm_profile::set_sms_packets_quantization.
    la_quantization_region_t sms_age_region;                ///< Quantized size of VOQ-in-SMS age. Configured by
                                                            ///#silicon_one::la_voq_cgm_profile::sms_age_quantization_thresholds.
};

struct la_voq_sms_size_in_packets_drop_val {
    la_voq_sms_size_in_packets_drop_val() = default;
    explicit la_voq_sms_size_in_packets_drop_val(la_qos_color_e drop_color_level) : drop_color_level(drop_color_level)
    {
    }
    la_qos_color_e drop_color_level; ///< Packets color above (including) which to drop packet.
};

struct la_voq_sms_size_in_packets_mark_val {
    la_voq_sms_size_in_packets_mark_val() = default;
    explicit la_voq_sms_size_in_packets_mark_val(la_qos_color_e mark_ecn_color_level) : mark_ecn_color_level(mark_ecn_color_level)
    {
    }
    la_qos_color_e mark_ecn_color_level; ///< Packets color above (including) which to mark ECN in packet.
};

struct la_voq_sms_size_in_packets_evict_val {
    la_voq_sms_size_in_packets_evict_val() = default;
    explicit la_voq_sms_size_in_packets_evict_val(bool evict_to_hbm) : evict_to_hbm(evict_to_hbm)
    {
    }
    bool evict_to_hbm; ///< Evict eligibility for the VOQ from SMS to HBM. Final eviction decision will be
    ///< based on this eligibilty and if eviction is permited by #silicon_one::la_voq_cgm_profile::set_sms_evict_behavior.
};

struct la_voq_sms_dequeue_size_in_packets_key {
    la_voq_sms_dequeue_size_in_packets_key() = default;
    la_voq_sms_dequeue_size_in_packets_key(la_quantization_region_t sms_voqs_total_packets_region,
                                           la_quantization_region_t sms_packets_region,
                                           la_quantization_region_t sms_age_region)
        : sms_voqs_total_packets_region(sms_voqs_total_packets_region),
          sms_packets_region(sms_packets_region),
          sms_age_region(sms_age_region)
    {
    }
    la_quantization_region_t sms_voqs_total_packets_region; ///< Quantized size of SMS used packets by all VOQs. Configured by
                                                            /// #silicon_one::la_device::set_cgm_sms_voqs_packets_quantization.
    la_quantization_region_t sms_packets_region;            ///< Quantized size of VOQ-in-SMS used packets. Configured by
                                                            /// #silicon_one::la_voq_cgm_profile::set_sms_packets_quantization.
    la_quantization_region_t sms_age_region;                ///< Quantized size of VOQ-in-SMS age. Configured by
                                                            ///#silicon_one::la_voq_cgm_profile::sms_age_quantization_thresholds.
};

struct la_voq_sms_dequeue_size_in_packets_congestion_val {
    la_cgm_congestion_level_t congestion_level; ///< Congestion level.
};

struct la_cgm_hbm_size_in_blocks_key {
    la_cgm_hbm_size_in_blocks_key() = default;
    la_cgm_hbm_size_in_blocks_key(la_quantization_region_t hbm_blocks_by_voq_region,
                                  la_quantization_region_t hbm_queue_delay_region,
                                  la_quantization_region_t hbm_pool_free_blocks_region)
        : hbm_blocks_by_voq_region(hbm_blocks_by_voq_region),
          hbm_queue_delay_region(hbm_queue_delay_region),
          hbm_pool_free_blocks_region(hbm_pool_free_blocks_region)
    {
    }
    la_quantization_region_t hbm_blocks_by_voq_region;    ///< Quantized size of HBM used blocks. Configured by
                                                          ///#silicon_one::la_device:set_cgm_hbm_blocks_by_voq_quantization.
    la_quantization_region_t hbm_queue_delay_region;      ///< Quantized delay level of VOQ-in-HBM. Configured by
                                                          ///#silicon_one::la_device::set_cgm_hbm_voq_age_quantization.
    la_quantization_region_t hbm_pool_free_blocks_region; ///< Quantized size of HBM free blocks in associated HBM pool. Configured
                                                          /// by #silicon_one::la_device::set_cgm_hbm_pool_free_blocks_quantization.
};

struct la_cgm_hbm_size_in_blocks_drop_val {
    la_cgm_hbm_size_in_blocks_drop_val() = default;
    explicit la_cgm_hbm_size_in_blocks_drop_val(la_qos_color_e drop_color_level) : drop_color_level(drop_color_level)
    {
    }
    la_qos_color_e drop_color_level; ///< Packets color above (including) which to drop packet.
};

struct la_cgm_hbm_size_in_blocks_mark_ecn_val {
    la_cgm_hbm_size_in_blocks_mark_ecn_val() = default;
    explicit la_cgm_hbm_size_in_blocks_mark_ecn_val(la_qos_color_e mark_ecn_color_level)
        : mark_ecn_color_level(mark_ecn_color_level)
    {
    }
    la_qos_color_e mark_ecn_color_level; ///< Packets color above (including) which to mark ECN in packet.
};

struct la_cgm_hbm_dequeue_size_in_blocks_key {
    la_cgm_hbm_dequeue_size_in_blocks_key() = default;
    la_cgm_hbm_dequeue_size_in_blocks_key(la_quantization_region_t hbm_blocks_by_voq_region,
                                          la_quantization_region_t hbm_pool_free_blocks_region)
        : hbm_blocks_by_voq_region(hbm_blocks_by_voq_region), hbm_pool_free_blocks_region(hbm_pool_free_blocks_region)
    {
    }
    la_quantization_region_t hbm_blocks_by_voq_region;    ///< Quantized size of HBM used blocks. Configured by
                                                          ///#silicon_one::la_device:set_cgm_hbm_blocks_by_voq_quantization.
    la_quantization_region_t hbm_pool_free_blocks_region; ///< Quantized size of HBM free blocks in associated HBM pool. Configured
                                                          /// by #silicon_one::la_device::set_cgm_hbm_pool_free_blocks_quantization.
};

struct la_cgm_hbm_dequeue_size_in_blocks_congestion_val {
    la_cgm_congestion_level_t congestion_level; ///< Congestion level.
};

struct la_cgm_wred_key {
    la_cgm_wred_key() = default;
    la_cgm_wred_key(la_quantization_region_t hbm_blocks_by_voq_region,
                    la_quantization_region_t hbm_packet_size_region,
                    la_qos_color_e color)
        : hbm_blocks_by_voq_region(hbm_blocks_by_voq_region), hbm_packet_size_region(hbm_packet_size_region), color(color)
    {
    }
    la_quantization_region_t hbm_blocks_by_voq_region; ///< Quantized size of HBM used blocks. Configured by
                                                       ///#silicon_one::la_device:set_cgm_hbm_blocks_by_voq_quantization.
    la_quantization_region_t hbm_packet_size_region;   ///< Quantized size of packet. Valid values are [0-5].
                                                       ///< 0:0-127B, 1:128-255B, 2:256-511B, 3:512B-1023B,
                                                       ///< 4:1024B-2047B, 5:2048B and up, 6-7: Unused.
    la_qos_color_e color;                              ///< Packets color.
};

struct la_cgm_wred_drop_val {
    la_cgm_wred_drop_val() = default;
    explicit la_cgm_wred_drop_val(double drop_probability) : drop_probability(drop_probability)
    {
    }
    double drop_probability; ///< Drop probobability.
};

struct la_cgm_wred_mark_ecn_val {
    la_cgm_wred_mark_ecn_val() = default;
    explicit la_cgm_wred_mark_ecn_val(double mark_ecn_probability) : mark_ecn_probability(mark_ecn_probability)
    {
    }
    double mark_ecn_probability; ///< Mark ECN probability.
};

/// @}
}

#endif ///< __LA_CGM_TYPES_H__
