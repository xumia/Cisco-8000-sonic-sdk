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

#ifndef __LA_ETHERNET_PORT_H__
#define __LA_ETHERNET_PORT_H__

#include "api/npu/la_copc.h"
#include "api/npu/la_l2_port.h"
#include "api/types/la_acl_types.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_event_types.h"
#include "api/types/la_security_group_types.h"

/// @file
/// @brief Leaba Ethernet Port API-s.
///
/// Defines API-s for managing an Ethernet port #silicon_one::la_ethernet_port object.

namespace silicon_one
{

/// @addtogroup L2PORT_ETH
/// @{

/// @brief      An L2 Ethernet port.
///
/// @details    An L2 Ethernet port defines Ethernet-related parameters such as allowed VLAN-s, trap behavior, filtering, etc.\n
///             It is built on top of a #silicon_one::la_system_port or #silicon_one::la_spa_port object.
class la_ethernet_port : public la_l2_port
{
public:
    enum class port_type_e {
        SIMPLE = 0, ///< MAC relay selected based on (port group, VLAN ID).\n In case of MAC termination, attempts to
                    /// terminate additional tunnel layers.
        AC,         ///< MAC relay selected based on (port, VLAN*), where VLAN includes ID, PCP, DEI, as well as IP fields (i.e.
                    /// TOS).\n In case of MAC termination, forwarding is performed. Additional tunnel layers are not terminated.
        PNP,        ///< MAC relay selected based on BVID.\n In case of MAC termination, forwarding will be based on next
                    /// customer Ethernet header.
        CBP,        ///< MAC relay selected based on BVID.\n No MAC termination will not happen.
    };

    enum class event_e {
        ARP_REPLY, ///< ARP reply packet passing through port
        DHCPV4,    ///< DHCPV4 packet passing through port
        DHCPV6,    ///< DHCPV6 packet passing through port
    };

    enum class svi_egress_tag_mode_e {
        KEEP, /// Keep the VLAN tag imposed by SVI port
        STRIP /// Strip the VLAN tag imposed by SVI port
    };

    enum class service_mapping_type_e {
        LARGE, /// Use EM for service mapping
        SMALL  /// Use TCAM for service mapping
    };

    /// @brief Traffic Matrix interface type.
    enum class traffic_matrix_type_e {
        INTERNAL = 0,
        EXTERNAL = 1,
    };

    /// @brief Get the port type.
    ///
    /// @param[out] out_type            #port_type_e to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_type contains the port type.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_port_type(port_type_e& out_type) const = 0;

    /// @brief Get allowed VLAN-s.
    ///
    /// @param[out] out_allowed_vlans   Pointer to #la_vlan_set_t to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_allowed_vlans contains the port allowed VLAN-s.
    /// @retval     LA_STATUS_EINVAL    out_allowed_vlans is NULL.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_allowed_vlans(la_vlan_set_t* out_allowed_vlans) = 0;

    /// @brief Set allowed VLAN-s.
    ///
    /// @param[in]  allowed_vlans       Set of allowed VLAN-s. Packets tagged with other VLAN-s are dropped.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    allows vlans are corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_allowed_vlans(const la_vlan_set_t allowed_vlans) = 0;

    /// @brief Get security mode.
    ///
    /// @param[out] out_security_mode   Pointer to #la_port_security_mode_e to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_security_mode contains the port's security mode.
    /// @retval     LA_STATUS_EINVAL    out_security_mode is NULL.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_security_mode(la_port_security_mode_e* out_security_mode) = 0;

    /// @brief Set security mode.
    ///
    /// @param[in]  security_mode       Security mode to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Security mode is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_security_mode(la_port_security_mode_e security_mode) = 0;

    /// @brief Get AC profile.
    ///
    /// @param[out] out_ac_profile      Pointer to #silicon_one::la_ac_profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_ac_profile contains port's AC profile.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ac_profile(la_ac_profile*& out_ac_profile) const = 0;

    /// @brief Set AC profile.
    ///
    /// AC profile defines how AC mapping keys will be selected during, per packet format, for incoming packets.
    /// Read #silicon_one::la_ac_profile and #silicon_one::la_device::create_ac_l2_service_port for more information.
    ///
    /// @param[in]  ac_profile          AC profile for the port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    AC profile is NULL.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ac_profile(la_ac_profile* ac_profile) = 0;

    /// @brief Get #silicon_one::la_l2_service_port/#silicon_one::la_l3_ac_port associated with this port and the provided VLAN IDs.
    ///
    /// @param[in] vid1              VLAN ID 1.
    /// @param[in] vid2              VLAN ID 2.
    ///
    /// @param[out] out_object      Pointer to #silicon_one::la_object to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ac_port(la_vlan_id_t vid1, la_vlan_id_t vid2, const la_object*& out_object) const = 0;

    /// @brief Get transparent PTP setting for this port.
    ///
    /// @param[out] out_enabled      bool to be populated with port's transparent PTP setting.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_transparent_ptp_enabled(bool& out_enabled) const = 0;

    /// @brief Set MTU for this port. MTU value does not include CRC bytes.
    ///
    /// @param[in]  mtu                 MTU value in bytes.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE MTU value is out of range.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_mtu(la_mtu_t mtu) = 0;

    /// @brief Get MTU value for this port.
    ///
    /// @return  MTU value in bytes.
    virtual la_mtu_t get_mtu() const = 0;

    /// @brief Enable/Disable PTP transparent clock mode.
    ///
    /// @param[in]  enabled             true if transparent clock mode should be enabled for this port; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_transparent_ptp_enabled(bool enabled) = 0;

    /// @brief Get system port associated with this ethernet port.
    ///
    /// @return la_system_port* for this ethernet port.\n
    ///         nullptr if port uses a #silicon_one::la_spa_port.
    virtual const la_system_port* get_system_port() const = 0;

    /// @brief Get SPA port associated with this ethernet port.
    ///
    /// @return la_spa_port* for this ethernet port.\n
    ///         nullptr if port uses a #silicon_one::la_system_port.
    virtual const la_spa_port* get_spa_port() const = 0;

    /// @brief Get SVI egress tag mode
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_svi_egress_tag_mode(svi_egress_tag_mode_e& out_mode) const = 0;

    /// @brief Set SVI egress tag mode
    ///
    /// If the mode is set to STRIP, on egress, a VLAN tag imposed by an SVI is
    /// stripped. The packet is sent out without the VLAN tag.
    /// If the mode is set to KEEP, on egress, a VLAN tag imposed by an SVI is
    /// kept as is. The packet is sent out with the VLAN tag.
    ///
    /// @param[in]  mode                Mode of the port, KEEP or STRIP.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_svi_egress_tag_mode(svi_egress_tag_mode_e mode) = 0;

    /// @brief Set service mapping type for this port.
    ///
    /// @param[in]  type                  service mapping type
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL      The service type is invalide
    virtual la_status set_service_mapping_type(service_mapping_type_e type) = 0;

    /// @brief Get service mapping type for this port.
    ///
    /// @param[out] out_type              service_mapping_type_e to populate.
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status get_service_mapping_type(service_mapping_type_e& out_type) const = 0;

    /// @brief Set default (PCP, DEI) value for the port.
    ///        Default PCPDEI value of zero will be set when ethernet port is created.
    ///
    /// @param[in]  pcpdei                (PCP, DEI) value.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_ingress_default_pcpdei(la_vlan_pcpdei pcpdei) = 0;

    /// @brief Get port default (PCP, DEI) value.
    ///        This will return default value of zero when called without set API usage.
    ///
    /// @return  (PCP, DEI) value.
    virtual la_vlan_pcpdei get_ingress_default_pcpdei() const = 0;

    /// @brief Set vlan id for the port.
    ///        Default vlan id of zero will be set when ethernet port is created.
    ///
    /// @param[in]  port_vid                vlan id
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_port_vid(la_vlan_id_t port_vid) = 0;

    /// @brief Get port vlan id.
    ///        This will return default value of zero when called without set API usage.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status get_port_vid(la_vlan_id_t& out_vid) const = 0;

    /// @brief Configure whether the TTL is decremented for packets egress from this port.
    /// @brief Configure whether the TTL is decremented for packets egress from this port.
    ///
    /// @param[in]  decrement_ttl         true if the port should decrement TTL, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_decrement_ttl(bool decrement_ttl) = 0;

    /// @brief Determine if the TTL is decremented for packets egress from this port.
    ///
    /// @return     True if the port decrements the TTL, false otherwise.
    virtual bool get_decrement_ttl() const = 0;

    /// @brief Configure whether the multicast copy should be pruned for this port.
    ///
    /// @param[in]  prune_enable          true if the mc copy should be pruned, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_stack_mc_prune(bool prune_enable) = 0;

    /// @brief Determine if the multicast copy prune is enabled on this port.
    ///
    /// @return     True if the port is enabled with mc copy prune, false otherwise.
    virtual la_status get_stack_mc_prune(bool& prune_enabled) const = 0;

    /// @brief Set COPC profile on the port.
    ///
    /// @param[in]  ethernet_profile_id COPC profile. Default value is 0.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid profile.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_copc_profile(la_control_plane_classifier::ethernet_profile_id_t ethernet_profile_id) = 0;

    /// @brief Get COPC profile of the port.
    ///
    /// @param[out] out_ethernet_profile_id COPC profile.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_copc_profile(la_control_plane_classifier::ethernet_profile_id_t& out_ethernet_profile_id) const = 0;

    /// @brief Enable Traffic Matrix Accounting for all L3 packets ingress on this L3 Port
    /// Stats collected in egress on all paths with Traffic Matrix counter
    ///
    /// @param[in] type       INTERNAL - accounting is disabled. EXTERNAL - accounting is enabled.
    /// Default is INTERNAL
    ///
    /// @retval     LA_STATUS_SUCCESS   Set was successful
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_traffic_matrix_interface_type(traffic_matrix_type_e type) = 0;

    /// @brief Get L3AC eligbiility for Prefix Object aggregate accounting
    ///
    /// @param[out] out_traffic_matrix_type     Traffic Matrix accounting interface type
    ///
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_traffic_matrix_interface_type(traffic_matrix_type_e& out_traffic_matrix_type) const = 0;

    /// @brief Set port Security Group Tag (SGT=Range(0-65535)).
    ///
    /// @param[in]  sgt                        Port SGT to be written.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    virtual la_status set_security_group_tag(la_sgt_t sgt) = 0;

    /// @brief Get port Security Group Tag (SGT).
    ///
    /// @param[out] out_sgt                    Get configured port SGT.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    virtual la_status get_security_group_tag(la_sgt_t& out_sgt) const = 0;

    /// @brief Set port Security Group Policy enforcement.
    ///
    /// @param[in]  enforcement                Security Group policy enable/disable enforcement.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    virtual la_status set_security_group_policy_enforcement(bool enforcement) = 0;

    /// @brief Get configured Security Group policy enforcement from port.
    ///
    /// @param[out] out_enforcement            Get configured SG policy enforcement.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    virtual la_status get_security_group_policy_enforcement(bool& out_enforcement) const = 0;

protected:
    ~la_ethernet_port() override = default;
};
}
/// @}

#endif
