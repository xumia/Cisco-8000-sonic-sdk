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

#ifndef __LA_METER_SET_H__
#define __LA_METER_SET_H__

#include "api/types/la_common_types.h"
#include "api/types/la_counter_or_meter_set.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_system_types.h"
#include "api/types/la_tm_types.h"

/// @file
/// @brief Leaba Meter-Set API-s.
///
/// Defines API-s for managing a set of meters. A meter is used to limit traffic rate.

namespace silicon_one
{

/// @addtogroup METER
/// @{

/// @brief      A Meter-Set.
///
/// @details    A meter-set represents a set of meters.
///             A meter measures traffic rate (in bits or packets) and drops, color-remarks or ECN-marks packets exceeding
///             thresholds.
///             A packet, arriving from a logical port (or tunnel) which has been assigned with a meter-set, will account a
///             specific meter within a meter-set. The index of that meter can be a function of various properties, e.g., the DSCP
///             field of an IP header, etc. See #silicon_one::la_ingress_qos_profile for more info.
///

class la_meter_set : public la_counter_or_meter_set
{
public:
    /// @brief Meter type.
    ///
    /// @details    There are three types of meters:
    ///                - A #silicon_one::la_meter_set::type_e::EXACT meter accounts for every packet. It can be assigned only to a
    ///                  single logical port that doesn't aggregate traffic from several physical port. It has an associated
    ///                  counter that counts all traffic sent to the meter.
    ///                - A #silicon_one::la_meter_set::type_e::STATISTICAL meter accounts for packets statistically, based on their
    ///                  size. It can be assigned to more than one logical port (or tunnel), and those can aggregate traffic from
    ///                  several physical ports, e.g., a #silicon_one::la_l2_service_port or a #silicon_one::la_l3_ac_port over an
    ///                  #silicon_one::la_spa_port.
    ///                - A #silicon_one::la_meter_set::type_e::PER_IFG_EXACT group-meter represents a group of individual
    ///                  #silicon_one::la_meter_set::type_e::EXACT meters, where each exact meter serves a single IFG and performs
    ///                  its
    ///                  own accounting. A per-IFG group-meter accounts every packet aginst a single exact meter, based on the
    ///                  ingress IFG of the packet. A per-IFG group-meter can be assigned only to a single logical port. That
    ///                  logical port can aggregate traffic from several physical port. A per-IFG group-meter has an associated
    ///                  counter that counts all traffic sent to all the meters in the group.
    ///                  All setting functions without a IFG parameter configure the same value for all meter in
    ///                  meter-group.
    /// @deprecated A #silicon_one::la_meter_set::type_e::PER_IFG_EXACT type is supported only in Pacific.
    enum class type_e {
        EXACT = 0,     ///< Exact meter.
        STATISTICAL,   ///< Statistical meter.
        PER_IFG_EXACT, ///< Group of exact meters, one per IFG.
    };

    /// @brief Meter coupling mode.
    ///
    /// @details Meter coupling mode allows a higher rank bucket to share it's surplus tokens with a lower rank bucket.
    enum class coupling_mode_e {
        NOT_COUPLED = 0,  ///< Surplus tokens are not shared.
        TO_EXCESS_BUCKET, ///< Surplus tokens are shared with the Excess bucket.
    };

    /// @brief Color and admission aware logical counter sizes
    enum {
        NUM_COLOR_AWARE_GAUGES = (size_t)la_qos_color_e::RED + 1 ///< Number of gauges in a color-aware logical counter.
    };

    /// @brief Returns the meter-set size.
    ///
    /// @retval The meter-set size.
    virtual size_t get_set_size() const = 0;

    /// @brief Returns the meter-set type.
    ///
    /// @retval The meter-set type.
    virtual type_e get_type() const = 0;

    /// @brief Set a meter profile for a specified meter within the set.
    ///
    /// Set a meter profile for a specified meter within the set. A #silicon_one::la_meter_set::type_e::EXACT and
    /// #silicon_one::la_meter_set::type_e::STATISTICAL meters support only a #silicon_one::la_meter_profile::type_e::GLOBAL meter
    /// profile. A
    /// #silicon_one::la_meter_set::type_e::PER_IFG_EXACT meter supports only #silicon_one::la_meter_profile::type_e::PER_IFG meter
    /// profile.
    ///
    /// @param[in]  meter_index                 Index of the meter within the set.
    /// @param[in]  meter_profile               Meter profile.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Meter profile type is unsupported for this meter-set type.
    /// @retval     LA_STATUS_EOUTOFRANGE       Index is out-of-range.
    /// @retval     LA_STATUS_EINVAL            Meter profile is nullptr.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_meter_profile(size_t meter_index, const la_meter_profile* meter_profile) = 0;

    /// @brief Get a meter profile for a specified meter within the set.
    ///
    /// @param[in]  meter_index                 Index of the meter within the set.
    /// @param[out] out_meter_profile           Meter profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE       Index is out-of-range.
    /// @retval     LA_STATUS_ENOTFOUND         No meter profile is set.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_meter_profile(size_t meter_index, const la_meter_profile*& out_meter_profile) const = 0;

    /// @brief Set a meter-action profile for a specified meter within the set.
    ///
    /// @param[in]  meter_index             Index of the meter within the set.
    /// @param[in]  meter_action_profile    Meter action profile.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Index is out-of-range.
    /// @retval     LA_STATUS_EINVAL        Meter action profile is nullptr.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_meter_action_profile(size_t meter_index, const la_meter_action_profile* meter_action_profile) = 0;

    /// @brief Get a meter-action profile for a specified meter within the set.
    ///
    /// @param[in]  meter_index                 Index of the meter within the set.
    /// @param[out] out_meter_action_profile    Meter action profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE       Index is out-of-range.
    /// @retval     LA_STATUS_ENOTFOUND         No meter-action profile is set.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_meter_action_profile(size_t meter_index,
                                               const la_meter_action_profile*& out_meter_action_profile) const = 0;

    /// @brief Set the committed-bucket coupling mode for a specified meter within the set.
    ///
    /// @param[in]  meter_index             Index of the meter within the set.
    /// @param[in]  coupling_mode           Coupling mode.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Index is out-of-range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_committed_bucket_coupling_mode(size_t meter_index, coupling_mode_e coupling_mode) = 0;

    /// @brief Get the committed-bucket coupling mode for a specified meter within the set.
    ///
    /// @param[in]  meter_index             Index of the meter within the set.
    /// @param[out] out_coupling_mode       Coupling mode to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Index is out-of-range.
    /// @retval     LA_STATUS_ENOTFOUND     No coupling mode is set.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_committed_bucket_coupling_mode(size_t meter_index, coupling_mode_e& out_coupling_mode) const = 0;

    /// @brief Set the committed information rate for a specified meter within the set.
    ///
    /// The committed information rate defines the rate at which tokens fill the committed bucket, in bps or pps depending on the
    /// #silicon_one::la_meter_profile::meter_measure_mode_e of the attached meter profile.
    /// In the Pacific, the rate is implemented with variable precision.
    ///
    /// @param[in]  meter_index                     Index of the meter within the set.
    /// @param[in]  cir                             Committed information rate.
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE           Index is out-of-range.
    /// @retval     LA_STATUS_EINVAL                Invalid committed information rate.
    /// @retval     LA_STATUS_ENOTINITIALIZED       A meter profile is not set.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    virtual la_status set_cir(size_t meter_index, la_rate_t cir) = 0;

    /// @brief Get the committed information rate for a specified meter within the set.
    ///
    /// @param[in]  meter_index                     Index of the meter within the set.
    /// @param[out] out_cir                         Committed information rate to populate, in bps or pps.
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE           Index is out-of-range.
    /// @retval     LA_STATUS_ENOTFOUND             No committed information rate is set.
    /// @retval     LA_STATUS_ENOTINITIALIZED       A meter profile is not set.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    virtual la_status get_cir(size_t meter_index, la_rate_t& out_cir) const = 0;

    /// @brief Set the excess information rate for a specified meter within the set.
    ///
    /// The excess information rate defines the rate at which tokens fill the excess bucket, in bps or pps depending on the
    /// #silicon_one::la_meter_profile::meter_measure_mode_e of the attached meter profile. In the Pacific, the rate is implemented
    /// with
    /// variable precision.
    ///
    /// @param[in]  meter_index                     Index of the meter within the set.
    /// @param[in]  eir                             Excess information rate.
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE           Index is out-of-range.
    /// @retval     LA_STATUS_EINVAL                Invalid excess information rate.
    /// @retval     LA_STATUS_ENOTINITIALIZED       A meter profile is not set.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    virtual la_status set_eir(size_t meter_index, la_rate_t eir) = 0;

    /// @brief Get the excess information rate for a specified meter within the set.
    ///
    /// @param[in]  meter_index                     Index of the meter within the set.
    /// @param[out] out_eir                         Excess information rate to populate, in bps or pps.
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE           Index is out-of-range.
    /// @retval     LA_STATUS_ENOTFOUND             No excess information rate is set.
    /// @retval     LA_STATUS_ENOTINITIALIZED       A meter profile is not set.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    virtual la_status get_eir(size_t meter_index, la_rate_t& out_eir) const = 0;

    /// @brief Get the associated counter.
    ///
    /// Retrieves the associated counter of a #silicon_one::la_meter_set::type_e::EXACT or a
    /// #silicon_one::la_meter_set::type_e::PER_IFG_EXACT
    /// of the set.
    ///
    /// @param[out] out_counter                 Reference to #silicon_one::la_counter_set* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Meter-set type doesn't have an associated counter.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_counter(la_counter_set*& out_counter) const = 0;

    /// @brief Set the committed information rate for a specified meter within the set, on the specified IFG.
    ///
    /// The committed information rate defines the rate at which tokens fill the committed bucket, in bps or pps depending on the
    /// #silicon_one::la_meter_profile::meter_measure_mode_e of the attached meter profile. In the Pacific, the rate is implemented
    /// with
    /// variable precision. A per-IFG configuration is supported only for #silicon_one::la_meter_set::type_e::PER_IFG_EXACT meter
    /// type.
    ///
    /// @deprecated A per-IFG configuration is supported only in Pacific.
    ///
    /// @param[in]  meter_index                     Index of the meter within the set.
    /// @param[in]  ifg                             IFG to be configured.
    /// @param[in]  cir                             Committed information rate.
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED       Meter-set type doesn't support per-IFG configuration.
    /// @retval     LA_STATUS_EOUTOFRANGE           Meter index or IFG ID is out-of-range.
    /// @retval     LA_STATUS_EINVAL                Invalid committed information rate.
    /// @retval     LA_STATUS_ENOTINITIALIZED       A meter profile is not set.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    virtual la_status set_cir(size_t meter_index, la_slice_ifg ifg, la_rate_t cir) = 0;

    /// @brief Get the committed information rate for a specified meter within the set, on the specified IFG.
    ///
    /// @deprecated A per-IFG configuration is supported only in Pacific.
    ///
    /// @param[in]  meter_index                     Index of the meter within the set.
    /// @param[in]  ifg                             IFG to query.
    /// @param[out] out_cir                         Committed information rate to populate, in bps or pps.
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED       Meter-set type doesn't support per-IFG configuration.
    /// @retval     LA_STATUS_EOUTOFRANGE           Meter index or IFG ID is out-of-range.
    /// @retval     LA_STATUS_ENOTFOUND             No committed information rate is set.
    /// @retval     LA_STATUS_ENOTINITIALIZED       A meter profile is not set.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    virtual la_status get_cir(size_t meter_index, la_slice_ifg ifg, la_rate_t& out_cir) const = 0;

    /// @brief Set the excess information rate for a specified meter within the set, on the specified IFG.
    ///
    /// The excess information rate defines the rate at which tokens fill the excess bucket, in bps or pps depending on the
    /// #silicon_one::la_meter_profile::meter_measure_mode_e of the attached meter profile. In the Pacific, the rate is implemented
    /// with
    /// variable precision. A per-IFG configuration is supported only for #silicon_one::la_meter_set::type_e::PER_IFG_EXACT meter
    /// type.
    ///
    /// @deprecated A per-IFG configuration is supported only in Pacific.
    ///
    /// @param[in]  meter_index                     Index of the meter within the set.
    /// @param[in]  ifg                             IFG to be configured.
    /// @param[in]  eir                             Excess information rate.
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED       Meter-set type doesn't support per-IFG configuration.
    /// @retval     LA_STATUS_EOUTOFRANGE           Meter index or IFG ID is out-of-range.
    /// @retval     LA_STATUS_EINVAL                Invalid excess information rate.
    /// @retval     LA_STATUS_ENOTINITIALIZED       A meter profile is not set.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    virtual la_status set_eir(size_t meter_index, la_slice_ifg ifg, la_rate_t eir) = 0;

    /// @brief Get the excess information rate for a specified meter within the set, on the specified IFG.
    ///
    /// @deprecated A per-IFG configuration is supported only in Pacific.
    ///
    /// @param[in]  meter_index                     Index of the meter within the set.
    /// @param[in]  ifg                             IFG to query.
    /// @param[out] out_eir                         Excess information rate to populate, in bps or pps.
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED       Meter-set type doesn't support per-IFG configuration.
    /// @retval     LA_STATUS_EOUTOFRANGE           Meter index or IFG ID is out-of-range.
    /// @retval     LA_STATUS_ENOTFOUND             No excess information rate is set.
    /// @retval     LA_STATUS_ENOTINITIALIZED       A meter profile is not set.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    virtual la_status get_eir(size_t meter_index, la_slice_ifg ifg, la_rate_t& out_eir) const = 0;

    /// @brief Retrieve a color-aware logical counter values.
    ///
    /// Color-aware logical counter values are periodically fetched from the device and updated in the counter set's storage.
    /// Reading a fresh counter value from the device has a performance penalty associated with it.
    ///
    /// @param[in]   counter_index          Index of the counter to read.
    /// @param[in]   force_update           Force update from HW counters.
    /// @param[in]   clear_on_read          Reset the counters after reading.
    /// @param[in]   color                  Color for which the counter is requested.
    /// @param[out]  out_packets            Reference to size_t to be populated with the packet count.
    /// @param[out]  out_bytes              Reference to size_t to be populated with the bytes count.
    /// each color.
    ///
    /// @retval    LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval    LA_STATUS_EOUTOFRANGE  Index is out-of-range.
    /// @retval    LA_STATUS_EUNKNOWN     Internal error.
    virtual la_status read(size_t counter_index,
                           bool force_update,
                           bool clear_on_read,
                           la_qos_color_e color,
                           size_t& out_packets,
                           size_t& out_bytes)
        = 0;

    /// @brief Retrieve a counter from from a specific Slice/IFG.
    ///
    /// This is a debug-only API.
    /// This read operation updates from HW and doesn't clear the counters.
    ///
    /// @param[in]   ifg                  IFG to read from.
    /// @param[in]   counter_index        Index of the counter to read.
    /// @param[in]   color                Color for which the counter is requested.
    /// @param[out]  out_packets          Reference to size_t to be populated with the packet count.
    /// @param[out]  out_bytes            Reference to size_t to be populated with the bytes count.
    ///
    /// @retval    LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval    LA_STATUS_EOUTOFRANGE  Illegal IFG.
    /// @retval    LA_STATUS_EOUTOFRANGE  Index is out-of-range.
    /// @retval    LA_STATUS_EUNKNOWN     Internal error.
    virtual la_status read(la_slice_ifg ifg, size_t counter_index, la_qos_color_e color, size_t& out_packets, size_t& out_bytes)
        = 0;

protected:
    ~la_meter_set() override = default;
}; // class la_meter_set

/// @}

} // namespace silicon_one

#endif // __LA_METER_SET_H__
