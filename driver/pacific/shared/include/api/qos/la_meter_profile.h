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

#ifndef __LA_METER_PROFILE_H__
#define __LA_METER_PROFILE_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief Meter profile API-s.
///
/// Defines API-s for managing a meter profile.

namespace silicon_one
{

/// @addtogroup METER
/// @{

/// @brief      Meter profile.
///
/// @details    A Meter profile defines general meter parameters such as committed and excess bucket sizes, whether the
///             committed an excess bucker are filled in a single-rate or two-rate mode, etc.
///             The meter profile is created with both CBS and EBS (or PBS for
///             #silicon_one::la_meter_profile::meter_rate_mode_e::TR_TCM)
///             set to 0.

class la_meter_profile : public la_object
{
public:
    /// @brief Meter profile type.
    ///
    /// @details    There are two types of meter profiles:
    ///                - A #silicon_one::la_meter_profile::type_e::GLOBAL meter profile has a global configuration identical for all
    ///                  IFGs.
    ///                - A #silicon_one::la_meter_profile::type_e::PER_IFG meter profile has a per-IFG configuration. All setting
    ///                  functions without an IFG parameter configure the same value for all IFGs.
    ///
    /// @deprecated A #silicon_one::la_meter_profile::type_e::PER_IFG type is supported only in Pacific.
    enum class type_e {
        GLOBAL,  ///< A global configuration meter profile.
        PER_IFG, ///< A per-IFG configuration meter profile.
    };

    /// @brief Meter measure mode.
    enum class meter_measure_mode_e {
        BYTES,   ///< Meter measures in bytes.
        PACKETS, ///< Meter measures in packets.
    };

    /// @brief Meter rate mode.
    enum class meter_rate_mode_e {
        SR_TCM, ///< Single-rate three-color meter. Packet will account the committed and excess buckets.
        TR_TCM, ///< Two-rate three-color meter. Packet will account the committed and peak buckets.
    };

    /// @brief Packet color awareness mode.
    enum class color_awareness_mode_e {
        BLIND = 0, ///< Color-blind. Meter assumes all packets are #la_qos_color_e::GREEN.
        AWARE      ///< Color-aware. Meter uses the incoming color.
    };

    /// @brief Meter cascading mode.
    ///
    /// @details For a packet that should account several meters, cascading defines whether a meter should be accounted in
    /// paraller or after the other meters.
    /// Relevant only for statistical meters.
    enum class cascade_mode_e {
        NOT_CASCADED = 0, ///< Meter is accounted in parallel to other meters.
        CASCADED,         ///< Meter is accounted in cascade after other meters.
    };

    /// @brief Returns the meter profile type.
    ///
    /// @retval The meter-profile type.
    virtual type_e get_type() const = 0;

    /// @brief Set the meter measure mode.
    ///
    /// @param[in]  meter_measure_mode  Meter measure mode.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EBUSY         Profile is already in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_meter_measure_mode(meter_measure_mode_e meter_measure_mode) = 0;

    /// @brief Get the meter measure mode.
    ///
    /// @param[out] out_meter_measure_mode  Meter measure mode to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND     No meter measure mode is set.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_meter_measure_mode(meter_measure_mode_e& out_meter_measure_mode) const = 0;

    /// @brief Set the meter rate mode.
    ///
    /// @param[in]  meter_rate_mode  Meter rate mode.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EBUSY         Profile is already in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_meter_rate_mode(meter_rate_mode_e meter_rate_mode) = 0;

    /// @brief Get the meter rate mode.
    ///
    /// @param[out] out_meter_rate_mode     Meter rate mode to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND     No meter rate mode is set.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_meter_rate_mode(meter_rate_mode_e& out_meter_rate_mode) const = 0;

    /// @brief Set the color awareness mode.
    ///
    /// @param[in]  color_awareness_mode    Color awareness mode.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EBUSY         Profile is already in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_color_awareness_mode(color_awareness_mode_e color_awareness_mode) = 0;

    /// @brief Get the color awareness mode.
    ///
    /// @param[out] out_color_awareness_mode    Color awareness mode to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         No color awareness mode is set.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_color_awareness_mode(color_awareness_mode_e& out_color_awareness_mode) const = 0;

    /// @brief Set the cascade mode.
    ///
    /// @param[in]  cascade_mode    Cascade mode.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EBUSY         Profile is already in use.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_cascade_mode(cascade_mode_e cascade_mode) = 0;

    /// @brief Get the cascade mode.
    ///
    /// @param[out] out_cascade_mode    Cascade mode to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         No cascade mode is set.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_cascade_mode(cascade_mode_e& out_cascade_mode) const = 0;

    /// @brief Set the committed burst size.
    ///
    /// Set the committed bucket size in bytes.
    /// The size is implemented in resolution of bytes according to #silicon_one::la_device::get_precision .Use
    /// #silicon_one::la_precision_type_e::METER_PROFILE__CBS_RESOLUTION as input.
    /// Actual size is round-down to nearest mark.
    /// Note that burst size which is less than the resolution results with burst size 0, which might not be valid.
    ///
    /// @param[in]  cbs                         Committed burst size.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            Invalid burst size.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Meter profile type doesn't support global configuration.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_cbs(la_uint64_t cbs) = 0;

    /// @brief Get the committed burst size.
    ///
    /// @param[out] out_cbs                     Committed burst size to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         No committed burst size is set.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Meter profile type doesn't support global configuration.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_cbs(la_uint64_t& out_cbs) const = 0;

    /// @brief Set the excess or peak burst size.
    ///
    /// Set the excess or peak burst size in bytes, depending on #silicon_one::la_meter_profile::meter_rate_mode_e.
    /// The size is implemented in resolution of bytes according to #silicon_one::la_device::get_precision . Use
    /// #silicon_one::la_precision_type_e::METER_PROFILE__EBS_RESOLUTION as input.
    /// Actual size is round-down to nearest mark.
    /// Note that burst size which is less than the resolution results with burst size 0, which might not be valid.
    ///
    /// @param[in]  ebs_or_pbs                  Excess or peak burst size.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            Invalid burst size.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Meter profile type doesn't support global configuration.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_ebs_or_pbs(la_uint64_t ebs_or_pbs) = 0;

    /// @brief Get the excess or peak burst size.
    ///
    /// @param[out] out_ebs_or_pbs              Excess or peak burst size to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         No excess burst size is set.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Meter profile type doesn't support global configuration.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_ebs_or_pbs(la_uint64_t& out_ebs_or_pbs) const = 0;

    /// @brief Set the committed burst size on the specified IFG.
    ///
    /// Set the committed bucket size in bytes on the specified IFG.
    /// The size is implemented in resolution of bytes according to #silicon_one::la_device::get_precision .Use
    /// #silicon_one::la_precision_type_e::METER_PROFILE__CBS_RESOLUTION as input.
    /// Actual size is round-down to nearest mark.
    /// Note that burst size which is less than the resolution results with burst size 0, which might not be valid.
    ///
    /// @deprecated A per-IFG configuration is supported only in Pacific.
    ///
    /// @param[in]  ifg                         IFG to be configured.
    /// @param[in]  cbs                         Committed burst size.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Meter profile type doesn't support per-IFG configuration.
    /// @retval     LA_STATUS_EOUTOFRANGE       IFG ID is out-of-range.
    /// @retval     LA_STATUS_EINVAL            Invalid burst size.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_cbs(la_slice_ifg ifg, la_uint64_t cbs) = 0;

    /// @brief Get the committed burst size on the specified IFG.
    ///
    /// @deprecated A per-IFG configuration is supported only in Pacific.
    ///
    /// @param[in]  ifg                         IFG to query.
    /// @param[out] out_cbs                     Committed burst size to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Meter profile type doesn't support per-IFG configuration.
    /// @retval     LA_STATUS_EOUTOFRANGE       IFG ID is out-of-range.
    /// @retval     LA_STATUS_ENOTFOUND         No committed burst size is set.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_cbs(la_slice_ifg ifg, la_uint64_t& out_cbs) const = 0;

    /// @brief Set the excess burst size.
    ///
    /// Set the excess bucket size in bytes.
    /// The size is implemented in resolution of bytes according to #silicon_one::la_device::get_precision .Use
    /// silicon_one::la_precision_type_e::METER_PROFILE__EBS_RESOLUTION as input.
    /// Actual size is round-down to nearest mark.
    /// Note that burst size which is less than the resolution results with burst size 0, which might not be valid.
    ///
    /// @deprecated A per-IFG configuration is supported only in Pacific.
    ///
    /// @param[in]  ifg                         IFG to be configured.
    /// @param[in]  ebs_or_pbs                  Excess or peak burst size.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Meter profile type doesn't support per-IFG configuration.
    /// @retval     LA_STATUS_EOUTOFRANGE       IFG ID is out-of-range.
    /// @retval     LA_STATUS_EINVAL            Invalid burst size.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_ebs_or_pbs(la_slice_ifg ifg, la_uint64_t ebs_or_pbs) = 0;

    /// @brief Get the excess burst size.
    ///
    /// @deprecated A per-IFG configuration is supported only in Pacific.
    ///
    /// @param[in]  ifg                         IFG to query.
    /// @param[out] out_ebs_or_pbs              Excess or peak burst size to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Meter profile type doesn't support per-IFG configuration.
    /// @retval     LA_STATUS_EOUTOFRANGE       IFG ID is out-of-range.
    /// @retval     LA_STATUS_ENOTFOUND         No excess burst size is set.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_ebs_or_pbs(la_slice_ifg ifg, la_uint64_t& out_ebs_or_pbs) const = 0;

protected:
    ~la_meter_profile() override = default;
}; // class la_meter_profile

/// @}

} // namespace silicon_one

#endif // __LA_METER_PROFILE_H__
