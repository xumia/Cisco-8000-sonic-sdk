// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_AC_PROFILE_H__
#define __LA_AC_PROFILE_H__

#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_object.h"
#include "la_ethernet_port.h"

/// @file
/// @brief Leaba Attachment Circuit profile API-s.
///
/// Defines API-s for managing Attachment Circuit profiles.

/// @addtogroup L2PORT_AC
/// @{

namespace silicon_one
{

/// @brief      An Attachment-Circuit profile.
///
/// @details    An AC profile defines a port's VLAN selection method per header format.
///             Either one or two VLAN ID-s are selected from a packet, depending on the packet's format (defined by the packet's
///             TPID fields).
class la_ac_profile : public la_object
{
public:
    /// @brief Enumerator defining how to map (Port, VLAN tags) to AC service port
    enum class key_selector_e {
        PORT,                         ///< Map based on Port only, ignore VLAN tags
        PORT_PVLAN,                   ///< Map based on Port and Port's VID
        PORT_VLAN,                    ///< Map based on Port and outer VLAN tag
        PORT_VLAN_VLAN,               ///< Map based on Port and first two VLAN tags
        PORT_VLAN_VLAN_WITH_FALLBACK, ///< Map based on Port and first two VLAN tags; if no mapping found, map based on
                                      /// Port and outer VLAN tag
    };

    /// @brief   Enumerator defining the QoS mode, whether based on layer2 or layer3.
    enum class qos_mode_e {
        L2, ///<QoS tag mapping and remarking based on pcpdei.
        L3, ///<QoS tag mapping and remarking based on dscp.
    };

    /// @brief Get an AC key selector, per packet VLAN format.
    ///
    /// @param[in]  tag_format          Packet VLAN format.
    /// @param[out] out_key_selector    #silicon_one::la_ac_profile::key_selector_e object to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_key_selector contains the key selector.
    /// @retval     LA_STATUS_ENOTFOUND Tag format not mapped for this AC profile.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_key_selector_per_format(la_packet_vlan_format_t tag_format, key_selector_e& out_key_selector) = 0;

    /// @brief Set the AC key selector per AC profile and packet format.
    ///
    /// @param[in]  tag_format      Packet VLAN format to apply permutation for.
    /// @param[in]  key_selector    Key selector object to be applied on incoming packets matching the given tag format.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_key_selector_per_format(la_packet_vlan_format_t tag_format, key_selector_e key_selector) = 0;

    /// @brief Enable/disable default vid control per AC profile and packet format.
    ///
    /// @param[in]  tag_format      Packet VLAN format.
    /// @param[in]  enabled         True if enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Tag format not mapped for this AC profile.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_default_vid_per_format_enabled(la_packet_vlan_format_t tag_format, bool enabled) = 0;

    /// @brief Get an AC qos mode, per packet VLAN format. Default mode is L2.
    ///
    /// @param[in]  tag_format      Packet VLAN format.
    /// @param[out] out_qos_mode    #silicon_one::la_ac_profile::qos_mode_e object to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_qos_mode contains the qos mode.
    /// @retval     LA_STATUS_ENOTFOUND Tag format not mapped for this AC profile.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_qos_mode_per_format(la_packet_vlan_format_t tag_format, qos_mode_e& out_qos_mode) = 0;

    /// @brief Set the AC qos mode per AC profile and packet format. Should be set after applying key selector
    ///        permutation to a Packet VLAN format. Default mode is L2.
    ///
    /// @param[in]  tag_format    Packet VLAN format to apply permutation for.
    /// @param[in]  qos_mode      Qos mode to be applied on incoming packets matching the given tag format.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Tag format not mapped for this AC profile.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_qos_mode_per_format(la_packet_vlan_format_t tag_format, qos_mode_e qos_mode) = 0;

    /// @brief Get the default pcpdei control flag per ac profile and packet.
    ///
    /// @param[in]  tag_format      Packet VLAN format.
    /// @param[out] out_enabled     Contains the control flag status (enable/disable).
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Tag format not mapped for this AC profile.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_default_pcpdei_per_format_enabled(la_packet_vlan_format_t tag_format, bool& out_enabled) = 0;

    /// @brief Enable/disable default pcpdei per AC profile and packet format.
    ///        Default pcpdei control will not be set when the new ac_profile is created.
    ///
    /// @param[in]  tag_format      Packet VLAN format.
    /// @param[in]  enabled         True if enabled, false otherwise.
    /// otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Tag format not mapped for this AC profile.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_default_pcpdei_per_format_enabled(la_packet_vlan_format_t tag_format, bool enabled) = 0;

protected:
    ~la_ac_profile() override = default;
};
}

/// @}

#endif
