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

#ifndef __LA_VOQ_CGM_PROFILE_H__
#define __LA_VOQ_CGM_PROFILE_H__

#include "api/types/la_cgm_types.h"
#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"
#include <vector>

/// @file
/// @brief Leaba Virtual Output Queue Congestion Management profile API-s.
///
/// Defines API-s for managing a VOQ CGM profile.

namespace silicon_one
{

/// @addtogroup CGM_VOQ_PROFILE
/// @{

/// @brief      Virtual Output Queue Congestion Management profile.
///
/// @details    A VOQ CGM profile defines the packet buffering, retention and congestion management behavior of a VOQ.
///             The behavior of a VOQ buffer for an incoming packet can be one of the following:
///                1. Store the packet
///                2. Store the packet and mark ECN
///                3. Drop the packet
///
///             based on the packets QoS info and VOQ buffer state. ECN marking and dropping can be probabilistic (WRED) and
///             deterministic.

class la_voq_cgm_profile : public la_object
{
public:
    /// @brief Defines the number of quantization regions and configurable thresholds of measurable quantities of the VOQ in the
    /// SMS.
    /// DEPRECATED: the enum will be removed in future. The ranges may be obtained using la_device::get_limit().
    /// Current values of the enum are Pacific-specific.
    enum {
        // Number of regions
        SMS_NUM_BYTES_QUANTIZATION_REGIONS = 8,
        SMS_NUM_PACKETS_QUANTIZATION_REGIONS = 8,
        SMS_NUM_AGE_QUANTIZATION_REGIONS = 16,

        // Number of thresholds
        SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS = SMS_NUM_BYTES_QUANTIZATION_REGIONS - 1,
        SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS = SMS_NUM_PACKETS_QUANTIZATION_REGIONS - 1,
        SMS_NUM_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS = SMS_NUM_AGE_QUANTIZATION_REGIONS - 1,
    };

    /// @brief Quantization thresholds for the size in bytes of the VOQ in the SMS. DEPRECATED.
    ///
    /// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is
    /// infinity.
    /// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
    /// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
    /// DEPRECATED: the struct will be removed in future. The ranges may be obtained using la_device::get_limit().
    ///             The struct is replaced by la_voq_cgm_quantization_thresholds.
    struct sms_bytes_quantization_thresholds {
        la_uint_t thresholds[SMS_NUM_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS];
    };

    /// @brief Quantization thresholds for the size in packets of the VOQ in the SMS. DEPRECATED.
    ///
    /// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is
    /// infinity.
    /// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
    /// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
    /// DEPRECATED: the struct will be removed in future. The ranges may be obtained using la_device::get_limit().
    ///             The struct is replaced by la_voq_cgm_quantization_thresholds.
    struct sms_packets_quantization_thresholds {
        la_uint_t thresholds[SMS_NUM_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS];
    };

    /// @brief Quantization thresholds for the age of the VOQ in the SMS. DEPRECATED.
    ///
    /// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is
    /// infinity.
    /// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
    /// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
    /// DEPRECATED: the struct will be removed in future. The ranges may be obtained using la_device::get_limit().
    ///             The struct is replaced by la_voq_cgm_quantization_thresholds.
    struct sms_age_quantization_thresholds {
        la_uint_t thresholds[SMS_NUM_AGE_QUANTIZATION_CONFIGURABLE_THRESHOLDS];
    };

    /// @name Quantization configuration
    /// @{

    /// @brief Set the VOQ-in-SMS size in bytes quantization thresholds. DEPRECATED.
    ///
    /// Sets the quantization that translates the instantaneous size in bytes of the VOQ in the SMS to regions.
    /// Internally, the size is aligned up to the nearest SMS block size. For Pacific, the SMS block size is 384 bytes.
    ///
    /// @param[in]  thresholds              Bytes quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS       Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL        Quantization thresholds are not increasing monotonically.
    /// @retval     LA_STATUS_EOUTOFRANGE   Quantization thresholds are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status set_sms_bytes_quantization(const sms_bytes_quantization_thresholds& thresholds) = 0;

    /// @brief Set the VOQ-in-SMS size in bytes quantization thresholds.
    ///
    /// Sets the quantization that translates the instantaneous size in bytes of the VOQ in the SMS to regions.
    /// Internally, the size is aligned up to the nearest SMS block size. For Pacific, the SMS block size is 384 bytes.
    ///
    /// @param[in]  thresholds              Bytes quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS       Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL        Quantization thresholds are not increasing monotonically.
    /// @retval     LA_STATUS_EOUTOFRANGE   Quantization thresholds are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not yet implemented.
    virtual la_status set_sms_bytes_quantization(const la_voq_cgm_quantization_thresholds& thresholds) = 0;

    /// @brief Get the VOQ-in-SMS size in bytes quantization thresholds. DEPRECATED.
    ///
    /// @param[out] out_thresholds          Bytes quantization thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Quantization thresholds were read successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status get_sms_bytes_quantization(sms_bytes_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Get the VOQ-in-SMS size in bytes quantization thresholds.
    ///
    /// @param[out] out_thresholds          Bytes quantization thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Quantization thresholds were read successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not yet implemented.
    virtual la_status get_sms_bytes_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set the VOQ-in-SMS size in packets quantization thresholds. DEPRECATED.
    ///
    /// @param[in]  thresholds              Packets quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS       Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL        Quantization thresholds are not increasing monotonically.
    /// @retval     LA_STATUS_EOUTOFRANGE   Quantization thresholds are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status set_sms_packets_quantization(const sms_packets_quantization_thresholds& thresholds) = 0;

    /// @brief Set the VOQ-in-SMS size in packets quantization thresholds.
    ///
    /// @param[in]  thresholds              Packets quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS       Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL        Quantization thresholds are not increasing monotonically.
    /// @retval     LA_STATUS_EOUTOFRANGE   Quantization thresholds are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not yet implemented.
    virtual la_status set_sms_packets_quantization(const la_voq_cgm_quantization_thresholds& thresholds) = 0;

    /// @brief Get the VOQ-in-SMS size in packets quantization thresholds. DEPRECATED.
    ///
    /// @param[out] out_thresholds      Packets quantization thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization thresholds were read successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status get_sms_packets_quantization(sms_packets_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Get the VOQ-in-SMS size in packets quantization thresholds.
    ///
    /// @param[out] out_thresholds      Packets quantization thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization thresholds were read successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not yet implemented.
    virtual la_status get_sms_packets_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set the VOQ-in-SMS age quantization thresholds. DEPRECATED.
    ///
    /// Sets the quantization that translates the instantaneous age of the VOQ in the SMS to regions. The thresholds are in
    /// nanosecond. In the Pacific, the age is implemented in time-units resolution set by
    /// #silicon_one::la_device::set_cgm_sms_voqs_age_time_granularity round-down to nearest integer.
    ///
    /// @param[in]  thresholds              Age quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS       Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL        Quantization thresholds are not increasing monotonically.
    /// @retval     LA_STATUS_EOUTOFRANGE   Quantization thresholds are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status set_sms_age_quantization(const sms_age_quantization_thresholds& thresholds) = 0;

    /// @brief Set the VOQ-in-SMS age quantization thresholds.
    ///
    /// Sets the quantization that translates the instantaneous age of the VOQ in the SMS to regions. The thresholds are in
    /// nanosecond. In the Pacific, the age is implemented in time-units resolution set by
    /// #silicon_one::la_device::set_cgm_sms_voqs_age_time_granularity round-down to nearest integer.
    ///
    /// @param[in]  thresholds              Age quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS       Quantization updated successfully.
    /// @retval     LA_etTATUS_EINVAL        Quantization thresholds are not increasing monotonically.
    /// @retval     LA_STATUS_EOUTOFRANGE   Quantization thresholds are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not yet implemented.
    virtual la_status set_sms_age_quantization(const la_voq_cgm_quantization_thresholds& thresholds) = 0;

    /// @brief Get the VOQ-in-SMS age quantization thresholds. DEPRECATED.
    ///
    /// @param[out] out_thresholds      Age quantization thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization thresholds were read successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status get_sms_age_quantization(sms_age_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Get the VOQ-in-SMS age quantization thresholds.
    ///
    /// @param[out] out_thresholds      Age quantization thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization thresholds were read successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not yet implemented.
    virtual la_status get_sms_age_quantization(la_voq_cgm_quantization_thresholds& out_thresholds) const = 0;

    /// @}

    /// @name Ingress packet behavior
    /// @{

    /// @brief Set the VOQ CGM profile to evicted profile mapping.
    ///
    /// Sets VOQ CGM profile to evicted profile mapping.
    ///
    /// @param[in]  evicted_profile Evicted profile handle #silicon_one::la_voq_cgm_evicted_profile
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL                    NULL evicted_profile passed.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS           Evicted profile is on different device.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not implemented.
    virtual la_status set_cgm_evicted_profile_mapping(la_voq_cgm_evicted_profile* evicted_profile) = 0;

    /// @brief Get the VOQ CGM profile to evicted profile mapping.
    ///
    /// Gets VOQ cgm profile to evicted buffers profile mapping.
    ///
    /// @param[out]  out_evicted_profile Evicted profile handle #silicon_one::la_voq_cgm_evicted_profile
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not implemented.
    virtual la_status get_cgm_evicted_profile_mapping(la_voq_cgm_evicted_profile*& out_evicted_profile) const = 0;

    /// @brief Clear the VOQ CGM profile to evicted profile mapping.
    ///
    /// Sets the VOQ cgm profile to map to default evicted profile. The default evicted profile can be
    /// retrieved via #silicon_one::la_device::get_voq_cgm_default_evicted_profile.
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not implemented.
    virtual la_status clear_cgm_evicted_profile_mapping() = 0;

    /// @brief Set the VOQ eviction from the SMS to HBM behavior.
    ///
    /// Sets the VOQ eviction behavior for an incoming packet based on the DRAM states.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: #silicon_one::la_voq_sms_evict_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: #silicon_one::la_voq_sms_evict_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status set_sms_evict_behavior(const la_voq_sms_evict_key& key, const la_voq_sms_evict_val& val) = 0;

    /// @brief Get the VOQ eviction from the SMS to HBM behavior.
    ///
    /// Gets the VOQ eviction behavior for an incoming packet based on the DRAM states.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: #silicon_one::la_voq_sms_evict_key
    ///
    /// @param[in]  out_val     The val is architecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: #silicon_one::la_voq_sms_evict_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status get_sms_evict_behavior(const la_voq_sms_evict_key& key, la_voq_sms_evict_val& out_val) const = 0;

    /// @brief Set the VOQ SMS drop probabilities.
    ///
    /// Sets configuration of SMS WRED probability for dropping a packet based on drop level and packet size.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: #silicon_one::la_voq_sms_wred_drop_probability_selector_key
    ///
    /// @param[in]  val         The val is achitecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: #silicon_one::la_voq_sms_wred_drop_probability_selector_drop_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Probability is out of range.
    /// @retval     LA_STATUS_ERESOURCE                 Probability table is out of resource.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status set_sms_wred_drop_probability(const la_voq_sms_wred_drop_probability_selector_key& key,
                                                    const la_voq_sms_wred_drop_probability_selector_drop_val& val)
        = 0;

    /// @brief Get the VOQ SMS drop probabilities.
    ///
    /// Gets configuration of SMS WRED probability for dropping a packet based on drop level and packet size.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: #silicon_one::la_voq_sms_wred_drop_probability_selector_key
    ///
    /// @param[in]  out_val     The val is achitecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: #silicon_one::la_voq_sms_wred_drop_probability_selector_drop_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Probability is out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status get_sms_wred_drop_probability(const la_voq_sms_wred_drop_probability_selector_key& key,
                                                    la_voq_sms_wred_drop_probability_selector_drop_val& out_val) const = 0;

    /// @brief Set the VOQ SMS mark probabilities.
    ///
    /// Sets configuration SMS WRED probability for marking a packet based on mark level and packet size.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: #silicon_one::la_voq_sms_wred_mark_probability_selector_key
    ///
    /// @param[in]  val         The val is achitecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: #silicon_one::la_voq_sms_wred_mark_probability_selector_mark_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Probability is out of range.
    /// @retval     LA_STATUS_ERESOURCE                 Probability table is out of resource.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status set_sms_wred_mark_probability(const la_voq_sms_wred_mark_probability_selector_key& key,
                                                    const la_voq_sms_wred_mark_probability_selector_mark_val& val)
        = 0;

    /// @brief Get the VOQ SMS mark probabilities.
    ///
    /// Gets configuration SMS WRED probability for marking a packet based on mark level and packet size.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: key is #silicon_one::la_voq_sms_wred_mark_probability_selector_key
    ///
    /// @param[in]  out_val     The val is achitecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: val is #silicon_one::la_voq_sms_wred_mark_probability_selector_mark_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Probability is out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status get_sms_wred_mark_probability(const la_voq_sms_wred_mark_probability_selector_key& key,
                                                    la_voq_sms_wred_mark_probability_selector_mark_val& out_val) const = 0;

    /// @brief Set the VOQ packet storage behavior.
    ///
    /// Sets the VOQ behavior for an incoming packet based on the packet's color and the VOQ and SMS states.
    /// A packet can be set to be dropped based its color, or passed for further processing.
    /// A packet is dropped if its drop probability for its color is greater-or-equal to a random value.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_bytes_color_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_bytes_drop_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status set_sms_size_in_bytes_drop_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                          const la_voq_sms_size_in_bytes_drop_val& val)
        = 0;

    /// @brief Get the VOQ packet storage behavior.
    ///
    /// Gets the VOQ behavior for an incoming packet based on the packet's color and the VOQ and SMS state.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_bytes_color_key
    ///
    /// @param[out] out_val     The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_bytes_drop_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status get_sms_size_in_bytes_drop_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                          la_voq_sms_size_in_bytes_drop_val& out_val) const = 0;

    /// @brief Set the VOQ packet mark ECN behavior.
    ///
    /// Sets the VOQ behavior for an incoming packet based on the packet's color and the VOQ and SMS states.
    /// A packet can be set to be marked by ECN mark based its color.
    /// Mark ECN is set if mark ECN probability for its color is greater-or-equal to a random value.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_bytes_color_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_bytes_mark_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status set_sms_size_in_bytes_mark_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                          const la_voq_sms_size_in_bytes_mark_val& val)
        = 0;

    /// @brief Get the VOQ packet mark ECN behavior.
    ///
    /// Sets the VOQ behavior for an incoming packet based on the packet's color and the VOQ and SMS states.
    /// A packet can be set to be marked by ECN mark based its color.
    /// Mark ECN is set if mark ECN probability for its color is greater-or-equal to a random value.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_bytes_color_key
    ///
    /// @param[out] out_val     The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_bytes_mark_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status get_sms_size_in_bytes_mark_behavior(const la_voq_sms_size_in_bytes_color_key& key,
                                                          la_voq_sms_size_in_bytes_mark_val& out_val) const = 0;

    /// @brief Set the VOQ eviction from the SMS to HBM behavior.
    ///
    /// Sets the VOQ behavior for an incoming packet based on the VOQ and SMS states.
    /// Configure eviction of the VOQ from the SMS to the HBM.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_bytes_evict_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_bytes_evict_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status set_sms_size_in_bytes_evict_behavior(const la_voq_sms_size_in_bytes_evict_key& key,
                                                           const la_voq_sms_size_in_bytes_evict_val& val)
        = 0;

    /// @brief Get the VOQ eviction from the SMS to HBM behavior.
    ///
    /// Gets the VOQ behavior for an incoming packet based on the VOQ and SMS states.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_bytes_evict_key
    ///
    /// @param[out] out_val     The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_bytes_evict_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status get_sms_size_in_bytes_evict_behavior(const la_voq_sms_size_in_bytes_evict_key& key,
                                                           la_voq_sms_size_in_bytes_evict_val& out_val) const = 0;

    /// @brief Set SMS dequeue congestion level.
    ///
    /// Sets the VOQs congestion level reported based on VOQ and SMS state.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: Not supported.
    ///                         GB: #silicon_one::la_voq_sms_dequeue_size_in_bytes_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: Not supported.
    ///                         GB: #silicon_one::la_voq_sms_dequeue_size_in_bytes_congestion_val
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status set_sms_dequeue_size_in_bytes_congestion_level(const la_voq_sms_dequeue_size_in_bytes_key& key,
                                                                     const la_voq_sms_dequeue_size_in_bytes_congestion_val& val)
        = 0;

    /// @brief Get SMS dequeue congestion level.
    ///
    /// Gets the VOQs congestion level reported based on VOQ and SMS state.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: Not supported.
    ///                         GB: #silicon_one::la_voq_sms_dequeue_size_in_bytes_key
    ///
    /// @param[out]  out_val    The val is architecture-dependent.
    ///                         Pacific: Not supported.
    ///                         GB: #silicon_one::la_voq_sms_dequeue_size_in_bytes_congestion_val
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status get_sms_dequeue_size_in_bytes_congestion_level(
        const la_voq_sms_dequeue_size_in_bytes_key& key,
        la_voq_sms_dequeue_size_in_bytes_congestion_val& out_val) const = 0;

    /// @brief Set the VOQ packet storage behavior based on packet descriptors.
    ///
    /// Sets the VOQ behavior for an incoming packet based on the packet's color and the VOQ and SMS state. A packet can be
    /// set to be dropped based its color, or passed for further processing. A packet is dropped if its color is greater-or-equal to
    /// the drop color level, where color order is GREEN <= YELLOW <= RED <= NONE.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_packets_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_packets_drop_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status set_sms_size_in_packets_drop_behavior(const la_voq_sms_size_in_packets_key& key,
                                                            const la_voq_sms_size_in_packets_drop_val& val)
        = 0;

    /// @brief Set the VOQ packet storage behavior based on packet descriptors.
    ///
    /// Sets the VOQ behavior for an incoming packet based on the packet's color and the VOQ and SMS state.
    /// If passed for processing then it can be marked with ECN.
    /// A packet is marked ECN if its color is greater-or-equal to
    /// the mark ECN color level, where color order is GREEN <= YELLOW <= RED <= NONE.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_packets_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_packets_mark_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status set_sms_size_in_packets_mark_behavior(const la_voq_sms_size_in_packets_key& key,
                                                            const la_voq_sms_size_in_packets_mark_val& val)
        = 0;

    /// @brief Set the VOQ packet storage behavior based on packet descriptors.
    ///
    /// Sets the VOQ behavior for an incoming packet based on the VOQ and SMS states.
    /// Configure eviction of the VOQ from the SMS to the HBM.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_packets_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_packets_evict_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status set_sms_size_in_packets_evict_behavior(const la_voq_sms_size_in_packets_key& key,
                                                             const la_voq_sms_size_in_packets_evict_val& val)
        = 0;

    /// @brief Get the VOQ packet storage behavior based on packet descriptors.
    ///
    /// Gets the VOQ behavior for an incoming packet based on the packet's color and the VOQ and SMS state. A packet can be
    /// set to be dropped based its color, or passed for further processing. A packet is dropped if its color is greater-or-equal to
    /// the drop color level, where color order is GREEN <= YELLOW <= RED <= NONE.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_packets_key
    ///
    /// @param[out] out_val     The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_packets_drop_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status get_sms_size_in_packets_drop_behavior(const la_voq_sms_size_in_packets_key& key,
                                                            la_voq_sms_size_in_packets_drop_val& out_val) const = 0;

    /// @brief Get the VOQ packet storage behavior based on packet descriptors.
    ///
    /// Gets the VOQ behavior for an incoming packet based on the packet's color and the VOQ and SMS state.
    /// A packet is marked ECN if its color is greater-or-equal to the mark ECN color level,
    /// where color order is GREEN <= YELLOW <= RED <= NONE.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_packets_key
    ///
    /// @param[out] out_val     The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_packets_mark_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status get_sms_size_in_packets_mark_behavior(const la_voq_sms_size_in_packets_key& key,
                                                            la_voq_sms_size_in_packets_mark_val& out_val) const = 0;

    /// @brief Get the VOQ packet storage behavior based on packet descriptors.
    ///
    /// Gets the VOQ behavior for an incoming packet based on the VOQ and SMS states.
    /// Configuration of eviction of the VOQ from the SMS to the HBM.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_packets_key
    ///
    /// @param[out] out_val     The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_voq_sms_size_in_packets_evict_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not yet implemented.
    virtual la_status get_sms_size_in_packets_evict_behavior(const la_voq_sms_size_in_packets_key& key,
                                                             la_voq_sms_size_in_packets_evict_val& out_val) const = 0;

    /// @brief Set SMS dequeue congestion level.
    ///
    /// Sets the VOQs congestion level reported based on VOQ and SMS state.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: Not supported.
    ///                         GB: #silicon_one::la_voq_sms_dequeue_size_in_packets_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: Not supported.
    ///                         GB: #silicon_one::la_voq_sms_dequeue_size_in_packets_congestion_val
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status set_sms_dequeue_size_in_packets_congestion_level(const la_voq_sms_dequeue_size_in_packets_key& key,
                                                                       const la_voq_sms_dequeue_size_in_packets_congestion_val& val)
        = 0;

    /// @brief Get SMS dequeue congestion level.
    ///
    /// Gets the VOQs congestion level reported based on VOQ and SMS state.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: Not supported.
    ///                         GB: #silicon_one::la_voq_sms_dequeue_size_in_packets_key
    ///
    /// @param[out]  out_val    The val is architecture-dependent.
    ///                         Pacific: Not supported.
    ///                         GB: #silicon_one::la_voq_sms_dequeue_size_in_packets_congestion_val
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status get_sms_dequeue_size_in_packets_congestion_level(
        const la_voq_sms_dequeue_size_in_packets_key& key,
        la_voq_sms_dequeue_size_in_packets_congestion_val& out_val) const = 0;

    /// @brief Set the VOQ packet storage and ECN-marking behavior. DEPRECATED.
    ///
    /// Sets the VOQ behavior for an incoming packet based on the packet's color and the VOQ, SMS and HBM states. A packet can be
    /// set to be dropped based its color, or passed for further proccessing. If passed for proccessing then it can be marked with
    /// ECN, and/or cause the VOQ to be evicted from the SMS to the HBM. A packet is dropped if its color is greater-or-equal to
    /// the drop color level, where color order is GREEN <= YELLOW <= RED <= NONE.
    ///
    /// @param[in]  sms_voqs_total_bytes_region         SMS used bytes by all VOQs quantization region. Region ID is the index of
    /// #silicon_one::la_cgm_sms_bytes_quantization_thresholds.
    ///
    /// @param[in]  sms_bytes_region                    VOQ-in-SMS used bytes quantization region. Region ID is the index of
    /// #silicon_one::la_voq_cgm_profile::sms_bytes_quantization_thresholds.
    ///
    /// @param[in]  sms_age_region                      VOQ-in-SMS age quantization region. Region ID is the index of
    /// #silicon_one::la_voq_cgm_profile::sms_age_quantization_thresholds.
    ///
    /// @param[in]  hbm_total_number_of_voqs_region     Total number of VOQ's evicted to the HBM quantization region. Region ID is
    /// the index of #silicon_one::la_cgm_hbm_number_of_voqs_quantization_thresholds.
    ///
    /// @param[in]  drop_color_level                    Color level above (including) which to drop.
    /// @param[in]  mark_ecn                            Set ECN in the packet.
    /// @param[in]  evict_to_hbm                        Evict the VOQ from the SMS to the HBM.
    ///
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EINVAL                    The profile is attached to a MC VOQ that doesn't support eviction to HBM.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not implemented.
    virtual la_status set_sms_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                     la_quantization_region_t sms_bytes_region,
                                                     la_quantization_region_t sms_age_region,
                                                     la_quantization_region_t hbm_total_number_of_voqs_region,
                                                     la_qos_color_e drop_color_level,
                                                     bool mark_ecn,
                                                     bool evict_to_hbm)
        = 0;

    /// @brief Get the VOQ behaviour for specific regions. DEPRECATED.
    ///
    /// @param[in]  sms_voqs_total_bytes_region         SMS used bytes by all VOQs quantization region. Region ID is the index of
    /// #silicon_one::la_cgm_sms_bytes_quantization_thresholds.
    ///
    /// @param[in]  sms_bytes_region                    VOQ-in-SMS used bytes quantization region. Region ID is the index of
    /// #silicon_one::la_voq_cgm_profile::sms_bytes_quantization_thresholds.
    ///
    /// @param[in]  sms_age_region                      VOQ-in-SMS age quantization region. Region ID is the index of
    /// #silicon_one::la_voq_cgm_profile::sms_age_quantization_thresholds.
    ///
    /// @param[in]  hbm_total_number_of_voqs_region     Total number of VOQ's evicted to the HBM quantization region. Region ID is
    /// the index of #silicon_one::la_cgm_hbm_number_of_voqs_quantization_thresholds.
    ///
    /// @param[out] out_drop_color_level                Color level above which to drop (including).
    /// @param[out] out_mark_ecn                        True if VOQ profile should mark packet for the quantization regions.
    /// @param[out] out_evict_to_hbm                    Evict the VOQ from the SMS to the HBM.
    ///
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not implemented.
    virtual la_status get_sms_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                     la_quantization_region_t sms_bytes_region,
                                                     la_quantization_region_t sms_age_region,
                                                     la_quantization_region_t hbm_total_number_of_voqs_region,
                                                     la_qos_color_e& out_drop_color_level,
                                                     bool& out_mark_ecn,
                                                     bool& out_evict_to_hbm) const = 0;

    /// @brief Set the VOQ packet storage and ECN-marking behavior. DEPRECATED.
    ///
    /// Sets the VOQ behavior for an incoming packet based on the packet's color and the VOQ, SMS and HBM states. A packet can be
    /// set to be dropped based its color, or passed for further proccessing. If passed for proccessing then it can be marked with
    /// ECN, and/or cause the VOQ to be evicted from the SMS to the HBM. A packet is dropped if its color is greater-or-equal to
    /// the drop color level, where color order is GREEN <= YELLOW <= RED <= NONE.
    ///
    /// @param[in]  sms_voqs_total_packets_region       SMS size in packets by all VOQs quantization region. Region ID is the
    /// index of #silicon_one::la_cgm_sms_packets_quantization_thresholds.
    ///
    /// @param[in]  sms_packets_region                  VOQ-in-SMS size in packets quantization region. Region ID is the index of
    /// #silicon_one::la_voq_cgm_profile::sms_packets_quantization_thresholds.
    ///
    /// @param[in]  sms_age_region                      VOQ-in-SMS age quantization region. Region ID is the index of
    /// #silicon_one::la_voq_cgm_profile::sms_age_quantization_thresholds.
    ///
    /// @param[in]  drop_color_level                    Color level above (including) which to drop.
    /// @param[in]  mark_ecn                            Set ECN in the packet.
    /// @param[in]  evict_to_hbm                        Evict the VOQ from the SMS to the HBM.
    ///
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EINVAL                    The profile is attached to a MC VOQ that doesn't support eviction to HBM.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not implemented.
    virtual la_status set_sms_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                       la_quantization_region_t sms_packets_region,
                                                       la_quantization_region_t sms_age_region,
                                                       la_qos_color_e drop_color_level,
                                                       bool mark_ecn,
                                                       bool evict_to_hbm)
        = 0;

    /// @brief Get the VOQ packet storage and ECN-marking behavior. DEPRECATED.
    ///
    /// @param[in]  sms_voqs_total_packets_region       SMS size in packets by all VOQs quantization region. Region ID is the
    /// index of #silicon_one::la_cgm_sms_packets_quantization_thresholds.
    ///
    /// @param[in]  sms_packets_region                  VOQ-in-SMS size in packets quantization region. Region ID is the index of
    /// #silicon_one::la_voq_cgm_profile::sms_packets_quantization_thresholds.
    ///
    /// @param[in]  sms_age_region                      VOQ-in-SMS age quantization region. Region ID is the index of
    /// #silicon_one::la_voq_cgm_profile::sms_age_quantization_thresholds.
    ///
    /// @param[out]  out_drop_color_level               Color level above (including) which to drop.
    /// @param[out]  out_mark_ecn                       True if VOQ profile should mark packet for the quantization regions.
    /// @param[out]  out_evict_to_hbm                   Evict the VOQ from the SMS to the HBM.
    ///
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not implemented.
    virtual la_status get_sms_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                       la_quantization_region_t sms_packets_region,
                                                       la_quantization_region_t sms_age_region,
                                                       la_qos_color_e& out_drop_color_level,
                                                       bool& out_mark_ecn,
                                                       bool& out_evict_to_hbm) const = 0;

    /// @brief Set the ECN-marking behavior on VOQ dequeue.
    ///
    /// Sets whether to mark packet with ECN based on the  SMS bytes state. This action is done on VOQ dequeue,
    /// as opposed to VOQ enqueue.
    ///
    /// @param[in]  sms_voqs_total_bytes_region         SMS used bytes by all VOQs quantization region.
    /// Region ID is the index of #silicon_one::la_cgm_sms_bytes_quantization_thresholds.
    /// @param[in]  sms_bytes_region                    VOQ-in-SMS used bytes quantization region. Region ID is
    /// the index of #silicon_one::la_voq_cgm_profile::sms_bytes_quantization_thresholds.
    ///
    /// @param[in]  mark_ecn                            Set ECN in the packet.
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    virtual la_status set_sms_dequeue_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                             la_quantization_region_t sms_bytes_region,
                                                             bool mark_ecn)
        = 0;

    /// @brief Get the VOQ dequeue ECN marking for certain regions.
    ///
    /// @param[in]  sms_voqs_total_bytes_region         SMS used bytes by all VOQs quantization region.
    /// Region ID is the index of #silicon_one::la_cgm_sms_bytes_quantization_thresholds.
    ///
    /// @param[in]  sms_bytes_region                    VOQ-in-SMS used bytes quantization region. Region ID is
    /// the index of #silicon_one::la_voq_cgm_profile::sms_bytes_quantization_thresholds.
    ///
    /// @param[out] out_mark_ecn                        True if VOQ profile should mark packet for the
    /// quantization regions.
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    virtual la_status get_sms_dequeue_size_in_bytes_behavior(la_quantization_region_t sms_voqs_total_bytes_region,
                                                             la_quantization_region_t sms_bytes_region,
                                                             bool& out_mark_ecn) const = 0;

    /// @brief Set the ECN-marking behavior on VOQ dequeue.
    ///
    /// Sets whether to mark packet with ECN based on the SMS packets state. This action is done on VOQ dequeue,
    /// as opposed to VOQ enqueue.
    ///
    /// @param[in]  sms_voqs_total_packets_region         SMS used packets by all VOQs quantization region.
    /// Region ID is the index of #silicon_one::la_cgm_sms_bytes_quantization_thresholds.
    ///
    /// @param[in]  mark_ecn                            Set ECN in the packet.
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    virtual la_status set_sms_dequeue_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                               bool mark_ecn)
        = 0;

    /// @brief Get the VOQ dequeue ECN marking for certain regions.
    ///
    /// @param[in]  sms_voqs_total_packets_region         SMS used packets by all VOQs quantization region.
    /// Region ID is the index of #silicon_one::la_cgm_sms_bytes_quantization_thresholds.
    ///
    /// @param[out] out_mark_ecn                        True if VOQ profile should mark packet for the
    /// quantization regions.
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE        Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN             An unknown error occurred.
    virtual la_status get_sms_dequeue_size_in_packets_behavior(la_quantization_region_t sms_voqs_total_packets_region,
                                                               bool& out_mark_ecn) const = 0;

    /// @brief Set the VOQ packet storage and ECN-marking behavior. DEPRECATED.
    ///
    /// Sets the VOQ behavior when it is evicted to the HBM for an incoming packet based on the packet's color and the and HBM
    /// state. A packet can be set to be dropped based its color, or passed for further proccessing. If passed for proccessing
    /// then it can be marked with ECN. A packet is dropped if its color is greater-or-equal to
    /// the drop color level, where color order is GREEN <= YELLOW <= RED <= NONE.
    ///
    /// @param[in]  hbm_blocks_by_voq_region        VOQ-in-HBM size in blocks quantization region. Region ID is the index of
    /// #silicon_one::la_cgm_hbm_blocks_by_voq_quantization_thresholds.
    ///
    /// @param[in]  hbm_pool_free_blocks_region     The free size in blocks of the associated HBM pool quantization region. Region
    /// ID is the index of #silicon_one::la_cgm_hbm_pool_free_blocks_quantization_thresholds.
    ///
    /// @param[in]  drop_color_level                Color level above (including) which to drop.
    /// @param[in]  mark_ecn                        Set ECN in the packet.
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE           Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED       The functionality is not implemented.
    virtual la_status set_hbm_size_in_blocks_behavior(la_quantization_region_t hbm_blocks_by_voq_region,
                                                      la_quantization_region_t hbm_pool_free_blocks_region,
                                                      la_qos_color_e drop_color_level,
                                                      bool mark_ecn)
        = 0;

    /// @brief Get the VOQ packet storage and ECN-marking behavior. DEPRECATED.
    ///
    /// @param[in]  hbm_blocks_by_voq_region        VOQ-in-HBM size in blocks quantization region. Region ID is the index of
    /// #silicon_one::la_cgm_hbm_blocks_by_voq_quantization_thresholds.
    ///
    /// @param[in]  hbm_pool_free_blocks_region     The free size in blocks of the associated HBM pool quantization region. Region
    /// ID is the index of #silicon_one::la_cgm_hbm_pool_free_blocks_quantization_thresholds.
    ///
    /// @param[out]  out_drop_color_level           Color level above (including) which to drop.
    /// @param[out]  out_mark_ecn                   True if VOQ profile should mark packet for the quantization regions.
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE           Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED       The functionality is not implemented.
    virtual la_status get_hbm_size_in_blocks_behavior(la_quantization_region_t hbm_blocks_by_voq_region,
                                                      la_quantization_region_t hbm_pool_free_blocks_region,
                                                      la_qos_color_e& out_drop_color_level,
                                                      bool& out_mark_ecn) const = 0;

    /// @brief Set the VOQ packet storage behavior.
    ///
    /// Sets the VOQ behavior when it is evicted to the HBM for an incoming packet based on the packet's color and the HBM
    /// state. A packet can be set to be dropped based its color. A packet is dropped if its color is greater-or-equal to
    /// the drop color level, where color order is GREEN <= YELLOW <= RED <= NONE.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_hbm_size_in_blocks_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_hbm_size_in_blocks_drop_val
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE           Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED       The functionality is not yet implemented.
    virtual la_status set_hbm_size_in_blocks_drop_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                           const la_cgm_hbm_size_in_blocks_drop_val& val)
        = 0;

    /// @brief Get the VOQ packet storage and ECN-marking behavior.
    ///
    /// Gets the VOQ behavior when it is evicted to the HBM for an incoming packet based on the packet's color and the and HBM
    /// state. A packet can be set to be dropped based its color. A packet is dropped if its color is greater-or-equal to
    /// the drop color level, where color order is GREEN <= YELLOW <= RED <= NONE.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_hbm_size_in_blocks_key
    ///
    /// @param[out] out_val     The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_hbm_size_in_blocks_drop_val
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE           Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED       The functionality is not yet implemented.
    virtual la_status get_hbm_size_in_blocks_drop_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                           la_cgm_hbm_size_in_blocks_drop_val& out_val) const = 0;

    /// @brief Set the VOQ packet mark ECN behavior.
    ///
    /// Sets the VOQ behavior when it is evicted to the HBM for an incoming packet based on the packet's color and the and HBM
    /// state. A packet can be set to be marked ECN based its color. A packet is marked ECN if its color is greater-or-equal to
    /// the drop color level, where color order is GREEN <= YELLOW <= RED <= NONE.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_hbm_size_in_blocks_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_hbm_size_in_blocks_mark_ecn_val
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE           Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED       The functionality is not yet implemented.
    virtual la_status set_hbm_size_in_blocks_mark_ecn_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                               const la_cgm_hbm_size_in_blocks_mark_ecn_val& val)
        = 0;

    /// @brief Get the VOQ packet mark ECN behavior.
    ///
    /// Gets the VOQ behavior when it is evicted to the HBM for an incoming packet based on the packet's color and the and HBM
    /// state. A packet can be set to be marked ECN based its color. A packet is marked ECN if its color is greater-or-equal to
    /// the drop color level, where color order is GREEN <= YELLOW <= RED <= NONE.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_hbm_size_in_blocks_key
    ///
    /// @param[out] out_val     The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_hbm_size_in_blocks_mark_ecn_val
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE           Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED       The functionality is not yet implemented.
    virtual la_status get_hbm_size_in_blocks_mark_ecn_behavior(const la_cgm_hbm_size_in_blocks_key& key,
                                                               la_cgm_hbm_size_in_blocks_mark_ecn_val& out_val) const = 0;

    /// @brief Set HBM dequeue congestion level.
    ///
    /// Sets the congestion level based on HBM state.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: Not supported.
    ///                         GB: #silicon_one::la_cgm_hbm_dequeue_size_in_blocks_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: Not supported.
    ///                         GB: #silicon_one::la_cgm_hbm_dequeue_size_in_blocks_congestion_val
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status set_hbm_dequeue_size_in_blocks_congestion_level(const la_cgm_hbm_dequeue_size_in_blocks_key& key,
                                                                      const la_cgm_hbm_dequeue_size_in_blocks_congestion_val& val)
        = 0;

    /// @brief Get HBM dequeue congestion level.
    ///
    /// Sets the congestion level based on HBM state.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: Not supported.
    ///                         GB: #silicon_one::la_cgm_hbm_dequeue_size_in_blocks_key
    ///
    /// @param[out]  out_val    The val is architecture-dependent.
    ///                         Pacific: Not supported.
    ///                         GB: #silicon_one::la_cgm_hbm_dequeue_size_in_blocks_congestion_val
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status get_hbm_dequeue_size_in_blocks_congestion_level(
        const la_cgm_hbm_dequeue_size_in_blocks_key& key,
        la_cgm_hbm_dequeue_size_in_blocks_congestion_val& out_val) const = 0;

    /// @brief Set the HBM pool ID the VOQ will be stored in if evicted to the HBM.
    ///
    /// @param[in]  hbm_pool_id             HBM pool ID.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   HBM pool is out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_associated_hbm_pool(la_cgm_hbm_pool_id_t hbm_pool_id) = 0;

    /// @brief Get the HBM pool ID the VOQ will be stored in if evicted to the HBM.
    ///
    /// @param[out] out_hbm_pool_id         HBM pool ID associated with this VOQ profile.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_associated_hbm_pool(la_cgm_hbm_pool_id_t& out_hbm_pool_id) const = 0;

    /// @}

    /// @name WRED
    /// @{

    /// @brief Defines the number of quantization regions and configurable thresholds of measurable quantities of the VOQ in the
    /// HBM. DEPRECATED.
    enum {
        // Number of regions
        WRED_NUM_BLOCKS_QUANTIZATION_REGIONS = 8,

        // Number of thresholds
        WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS = WRED_NUM_BLOCKS_QUANTIZATION_REGIONS - 1,
    };

    /// @brief Enumerator of the WRED actions. DEPRECATED.
    enum class wred_action_e {
        PASS = 0, ///< Always Pass packets. Disable WRED mechanism.
        DROP,     ///< Drop the packet if WRED action should take place.
        MARK_ECN, ///< Mark ECN on the packet if WRED action should take place.
    };

    /// @brief Quantization thresholds for the size in blocks of the VOQ in the HBM. DEPRECATED.
    ///
    /// Thresholds are provided for all N-1 regions. The first region's lower-limit is 0 and the last region's upper-limit is
    /// infinity.
    /// For 'x' the data value and 'i' the selected region; if threshold[i] == x == threshold[i+n], region i+1 will be selected,
    /// otherwise if threshold[i-1] <= x < threshold[i], region i will be selected.
    struct wred_blocks_quantization_thresholds {
        la_uint_t thresholds[WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS];
    };

    /// @brief Probabilities for congestion notification per quantization region. DEPRECATED.
    struct wred_regions_probabilties {
        double probabilities[WRED_NUM_BLOCKS_QUANTIZATION_REGIONS];
    };

    /// @brief Set the queue-size averaging configuration. DEPRECATED.
    ///
    /// Set the queue-size averaging and quantization thresholds configuration. The Exponential Moving Average coefficient,
    /// 'ema_coefficient', is implemented as 'ema_coefficient' = pow(2, -weight), where weight is an integer.
    ///
    /// @param[in]  ema_coefficient         Exponential moving average coefficient. Rounded to the lower discrete point.
    /// @param[in]  thresholds              Blocks quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Invalid EMA coefficient or quantization thresholds.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status set_averaging_configuration(double ema_coefficient, const wred_blocks_quantization_thresholds& thresholds)
        = 0;

    /// @brief Set the queue-size averaging configuration.
    ///
    /// Set the queue-size averaging and quantization thresholds configuration. The Exponential Moving Average coefficient,
    /// 'ema_coefficient', is implemented as 'ema_coefficient' = pow(2, -weight), where weight is an integer.
    ///
    /// @param[in]  ema_coefficient         Exponential moving average coefficient. Rounded to the lower discrete point.
    /// @param[in]  thresholds              Blocks quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Invalid EMA coefficient or quantization thresholds.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED       The functionality is not yet implemented.
    virtual la_status set_averaging_configuration(double ema_coefficient, const la_voq_cgm_quantization_thresholds& thresholds) = 0;

    /// @brief Get queue-size averaging configuration. DEPRECATED.
    ///
    /// @param[out] out_ema_coefficient     Exponential moving average coefficient to populate.
    /// @param[out] out_thresholds          Blocks quantization thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status get_averaging_configuration(double& out_ema_coefficient,
                                                  wred_blocks_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Get queue-size averaging configuration.
    ///
    /// @param[out] out_ema_coefficient     Exponential moving average coefficient to populate.
    /// @param[out] out_thresholds          Blocks quantization thresholds to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status get_averaging_configuration(double& out_ema_coefficient,
                                                  la_voq_cgm_quantization_thresholds& out_thresholds) const = 0;

    /// @brief Set the WRED configuration. DEPRECATED.
    ///
    /// Sets the WRED action and the WRED action probabilities.
    /// A probability, 'pr', is implemented as 'pr' = mantissa * pow(2, -7), where mantissa is an integer.
    ///
    /// @param[in]  action                  WRED action.
    /// @param[in]  action_probabilities    Probabilities to perform the WRED action. Rounded to the lower discrete point.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Action probabilities are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status set_wred_configuration(wred_action_e action, const wred_regions_probabilties& action_probabilities) = 0;

    /// @brief Get WRED configuration. DEPRECATED.
    ///
    /// @param[out] out_action                  WRED action to populate.
    /// @param[in]  out_action_probabilities    Action probabilities to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   The functionality is not implemented.
    virtual la_status get_wred_configuration(wred_action_e& out_action,
                                             wred_regions_probabilties& out_action_probabilities) const = 0;

    /// @brief Set the HBM WRED configuration.
    ///
    /// Sets configuration HBM WRED probability for dropping a packet based on HBM VOQ state.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_wred_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_wred_drop_val
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Action probabilities are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ERESOURCE     Out of unique probability values.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status set_hbm_wred_drop_configuration(const la_cgm_wred_key& key, const la_cgm_wred_drop_val& val) = 0;

    /// @brief Get the HBM WRED configuration.
    ///
    /// Gets configuration HBM WRED probability for dropping a packet based on HBM VOQ state.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_wred_key
    ///
    /// @param[out] out_val     The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_wred_drop_val
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Action probabilities are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status get_hbm_wred_drop_configuration(const la_cgm_wred_key& key, la_cgm_wred_drop_val& out_val) const = 0;

    /// @brief Set the HBM WRED configuration.
    ///
    /// Sets configuration HBM WRED probability for marking ECN a packet based on HBM VOQ state.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_wred_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_wred_mark_ecn_val
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Action probabilities are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ERESOURCE     Out of unique probability values.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status set_hbm_wred_mark_ecn_configuration(const la_cgm_wred_key& key, const la_cgm_wred_mark_ecn_val& val) = 0;

    /// @brief Get the HBM WRED configuration.
    ///
    /// Gets configuration HBM WRED probability for marking ECN a packet based on HBM VOQ state.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_wred_key
    ///
    /// @param[out] out_val     The val is architecture-dependent.
    ///                         Pacific: TBD (currently not implemented)
    ///                         GB: #silicon_one::la_cgm_wred_mark_ecn_val
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Action probabilities are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status get_hbm_wred_mark_ecn_configuration(const la_cgm_wred_key& key, la_cgm_wred_mark_ecn_val& out_val) const = 0;

    /// Enables/disables FCN logic and configure WRED FCN marking probabilities. A probability, 'pr', is implemented as 'pr' =
    /// mantissa * pow (2, -7), where mantissa is an integer.
    ///
    /// @param[in]  enabled                 Enables/disables FCN logic.
    /// @param[in]  action_probabilities    Probabilities to perform the WRED FCN marking. Rounded to the lower discrete point.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Action probabilities are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status set_fcn_configuration(bool enabled, const wred_regions_probabilties& action_probabilities) = 0;

    /// @brief Enable/Disable and configure quantization regions FCN marking.
    ///
    /// Enables/disables FCN logic and configure WRED FCN marking probabilities. A probability, 'pr', is implemented as 'pr' =
    /// mantissa * pow (2, -13), where mantissa is an integer.
    ///
    /// @param[in]  enabled                 Enables/disables FCN logic.
    /// @param[in]  action_probabilities    Probabilities to perform the WRED FCN marking. Rounded to the lower discrete point.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Action probabilities are out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The functionality is not implemented.
    virtual la_status set_fcn_configuration(bool enabled, const std::vector<double>& action_probabilities) = 0;

    /// @brief Get FCN configuration. DEPRECATED.
    ///
    /// @param[out] out_enabled                 True if FCM is enabled.
    /// @param[out] out_action_probabilities    FCN probabilities to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   The functionality is not implemented.
    virtual la_status get_fcn_configuration(bool& out_enabled, wred_regions_probabilties& out_action_probabilities) const = 0;

    /// @brief Get FCN configuration.
    ///
    /// @param[out] out_enabled                 True if FCM is enabled.
    /// @param[out] out_action_probabilities    FCN probabilities to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   The functionality is not implemented.
    virtual la_status get_fcn_configuration(bool& out_enabled, std::vector<double>& out_action_probabilities) const = 0;

    /// @}
protected:
    ~la_voq_cgm_profile() override = default;
}; // class la_voq_cgm_profile

/// @}

} // namespace silicon_one

#endif // __LA_VOQ_CGM_PROFILE_H__
