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

#ifndef __LA_L2_SERVICE_PORT_H__
#define __LA_L2_SERVICE_PORT_H__

#include "api/npu/la_ac_profile.h"
#include "api/npu/la_counter_set.h"
#include "api/npu/la_l2_port.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_event_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_mpls_types.h"

/// @file
/// @brief Leaba Layer 2 Service Port API-s.
///
/// Layer 2 service ports can be connected to a single switch or to another service port.

namespace silicon_one
{

/// @addtogroup L2PORT_SRV
/// @{
class la_l2_service_port : public la_l2_port
{
public:
    enum class port_type_e {
        INVALID,
        AC,
        PWE,
        PWE_TAGGED,
        VXLAN,
    };

    enum class egress_feature_mode_e {
        L3, ///<L3 logical port attributes will be applied to outgoing routed packets
        L2, ///<L2 logical port attributes will be applied to outgoing routed packets
    };

    /// @brief Get port's STP state.
    ///
    /// @param[out] out_state           Pointer to STP state object to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_stp_state(la_port_stp_state_e& out_state) const = 0;

    /// @brief Set port's STP state.
    ///
    /// @param[in]  state               STP state.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    State is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_stp_state(la_port_stp_state_e state) = 0;

    /// @brief Get Service_port's MAC learning mode.
    ///
    /// @param[out] out_learning_mode   learning_mode to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. Result is placed in out_learning_mode.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac_learning_mode(la_lp_mac_learning_mode_e& out_learning_mode) = 0;

    /// @brief Set Service_port's MAC learning mode.
    ///
    /// @param[in]  learning_mode       Learning mode for the given Service_port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Learning mode is corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_mac_learning_mode(la_lp_mac_learning_mode_e learning_mode) = 0;

    /// @brief Get port's filter group.
    ///
    /// @param[out] out_filter_group    Reference to #silicon_one::la_filter_group* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_group contains port's filter group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_filter_group(const la_filter_group*& out_filter_group) const = 0;

    /// @brief Set port's filter group.
    ///
    /// @param[in]  filter_group        Filter group for the port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Filter group is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_filter_group(la_filter_group* filter_group) = 0;

    /// @brief Set port's egress VLAN editor.
    ///
    /// The editor is applied to both P2P and switch-based traffic.
    ///
    /// @param[in]  edit_command        VLAN edit command.
    ///
    /// @retval     LA_STATUS_SUCCESS   Edit command set successfully.
    /// @retval     LA_STATUS_EINVAL    Editor object is corrupt, or TPID-s are unsupported.
    /// @retval     LA_STATUS_ERESOURCE Cannot create requested VLAN editing profile.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_egress_vlan_edit_command(const la_vlan_edit_command& edit_command) = 0;

    /// @brief Get egress VLAN edit command.
    ///
    /// @param[out] out_edit_command    Egress VLAN edit command to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_egress_vlan_edit_command(la_vlan_edit_command& out_edit_command) const = 0;

    /// @brief Query trapping/snooping of service port events.
    ///
    /// @param[in]  event               Event to be queried.
    /// @param[out] out_enabled         bool to be populated with TRUE if event enabled; FALSE otherwise.
    ///
    /// @return status.
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Event is not applicable to port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_event_enabled(la_event_e event, bool& out_enabled) const = 0;

    /// @brief Enable/Disable trapping/snooping of Point-to-point port events.
    ///
    /// @param[in]  event               Event to be enabled/disabled.
    /// @param[in]  enabled             true if event should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    event is not applicable to port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_event_enabled(la_event_e event, bool enabled) = 0;

    /// @brief Set ingress VLAN editor.
    ///
    /// The editor is applied to both P2P and switch-based traffic.
    ///
    /// @param[in]  edit_command        VLAN editor for ingress packets.
    ///
    /// @retval     LA_STATUS_SUCCESS   Edit command configuration set successfully.
    /// @retval     LA_STATUS_EINVAL    Edit command object is corrupt/invalid.
    /// @retval     LA_STATUS_ERESOURCE Cannot create requested VLAN editing profile.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ingress_vlan_edit_command(const la_vlan_edit_command& edit_command) = 0;

    /// @brief Get ingress VLAN editor.
    ///
    /// @param[out] out_edit_command    VLAN editor for ingress packets to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_edit_command contains VLAN editor for ingress packets.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ingress_vlan_edit_command(la_vlan_edit_command& out_edit_command) const = 0;

    /// @brief Attach port to switch.
    ///
    /// Ingress traffic will go from the port to the switch.
    /// Egress traffic through the port for address learned by the switch will go to the port.
    /// Broadcast, Unknown and Multicast traffic will go to the port only after it is added to the Switch's broadcast/unknown flood
    /// groups.
    ///
    /// @param[in]  sw                  Switch to attach AC port to.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port successfully attached to switch.
    /// @retval     LA_STATUS_EINVAL    Switch is corrupt/invalid.
    /// @retval     LA_STATUS_EBUSY     Port already attached to an L2 destination.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status attach_to_switch(const la_switch* sw) = 0;

    /// @brief Get port's outgoing destination.
    ///
    /// @param[out] out_destination     L2 destination to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_destination contains the L2 destination.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_destination(const la_l2_destination*& out_destination) const = 0;

    /// @brief Get switch associated with this service port.
    ///
    /// @param[out]     out_switch          Switch associated with this service port.
    ///
    /// @retval         LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval         LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_attached_switch(const la_switch*& out_switch) const = 0;

    /// @brief Set port's outgoing L2 destination.
    ///
    /// A destination can be either another service port, or a LAG/protection group.
    ///
    /// @param[in]  destination         L2 destination.
    ///
    /// @retval     LA_STATUS_SUCCESS   Ports successfully attached.
    /// @retval     LA_STATUS_EINVAL    destination is corrupt/invalid.
    /// @retval     LA_STATUS_EBUSY     Port is attached to a switch.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_destination(const la_l2_destination* destination) = 0;

    /// @brief Detach port from destination.
    ///
    /// Port will be detached from connected switch/destination.
    /// If the port is detached from a switch, it needs to be removed from the switch's broadcast and unknown flood groups
    /// as well for traffic to stop flowing to it.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port detached successfully.
    /// @retval     LA_STATUS_ENOTFOUND Port not connected to a switch/destination.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status detach() = 0;

    /// @brief Get vxlan port's remote ip address.
    ///
    /// Only apply to vxlan tunnel port
    ///
    /// @param[out] out_ipv4_addr       remote ip address to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. dip contains the destination ip address.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_remote_ip_addr(la_ipv4_addr_t& out_ipv4_addr) const = 0;

    /// @brief Get vxlan port's local ip address.
    ///
    /// Only apply to vxlan tunnel port
    ///
    /// @param[out] out_ipv4_addr       local ip address to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. sip contains the source ip address.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_local_ip_addr(la_ipv4_addr_t& out_ipv4_addr) const = 0;

    /// @brief Get vxlan port's vrf.
    ///
    /// Only apply to vxlan tunnel port
    ///
    /// @param[out] out_vrf             vrf to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. vrf contains the vrf.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_vrf(const la_vrf*& out_vrf) const = 0;

    /// @brief Get pwe or vxlan port's l3 destination.
    ///
    /// Only apply to pwe or vxlan tunnel port
    ///
    /// @param[out] out_l3_destination  L3 destination to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_l3_destination contains the L3 destination.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_l3_destination(const la_l3_destination*& out_l3_destination) const = 0;

    /// @brief Set pwe or vxlan port's outgoing L3 destination.
    ///
    /// Only apply to pwe or vxlan tunnel port
    ///
    /// @param[in]  l3_destination      L3 destination.
    ///
    /// @retval     LA_STATUS_SUCCESS   L3 destination set successfully.
    /// @retval     LA_STATUS_EINVAL    destination is corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_l3_destination(const la_l3_destination* l3_destination) = 0;

    /// @brief Set switch to VNI mapping on VXLAN port.
    ///
    /// Only apply to vxlan tunnel port.
    ///
    /// @param[in]  sw                      The switch that VNI associated with.
    /// @param[in]  vni                     VNI that the switch maps to.
    ///
    /// @retval     LA_STATUS_SUCCESS       VNI mapping set successfully.
    /// @retval     LA_STATUS_EINVAL        switch is corrupt/invalid.
    /// @retval     LA_STATUS_EOUTOFRANGE   VNI out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_encap_vni(const la_switch* sw, la_vni_t vni) = 0;

    /// @brief Clear switch to VNI mapping on VXLAN port.
    ///
    /// Only apply to vxlan tunnel port.
    ///
    /// @param[in]  sw                  The switch that VNI associated with.
    ///
    /// @retval     LA_STATUS_SUCCESS   VNI mapping removed successfully.
    /// @retval     LA_STATUS_EINVAL    switch is corrupt/invalid.
    /// @retval     LA_STATUS_ENOTFOUND The switch to VNI mapping is not found.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_encap_vni(const la_switch* sw) = 0;

    /// @brief Get VNI that la_switch maps to.
    ///
    /// Only applicable to vxlan tunnel port.
    ///
    /// @param[in]  sw                  la_switch.
    /// @param[out] out_vni             VNI that la_switch maps to.
    ///
    /// @retval     LA_STATUS_SUCCESS   VNI get successfully.
    /// @retval     LA_STATUS_EINVAL    switch is corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_encap_vni(const la_switch* sw, la_vni_t& out_vni) const = 0;

    /// @brief Get pwe gid associated with pwe port.
    ///
    /// Only applicable to pwe port.
    ///
    /// @param[out] out_pwe_gid         PWE gid that pwe port is mapped to.
    ///
    /// @retval     LA_STATUS_SUCCESS   PWE gid get successfully.
    /// @retval     LA_STATUS_EINVAL    Port is not a PWE port.
    virtual la_status get_pwe_gid(la_pwe_gid_t& out_pwe_gid) const = 0;

    /// @brief Get port's global ID.
    ///
    /// @return L2 service port's global ID.
    virtual la_l2_port_gid_t get_gid() const = 0;

    /// @brief Get port's type.
    ///
    /// @return L2 service port's type.
    virtual port_type_e get_port_type() const = 0;

    /// @brief Set the service mapping VIDs associated with the port.
    ///
    /// The VLAN model of the port cannot be changed with this function; only existing VLANs can be changed.
    /// E.g. 'vid2' must be LA_VLAN_ID_INVALID for a port with a single VLAN.
    ///
    /// @param[in] vid1            First VLAN ID.
    /// @param[in] vid2            Second VLAN ID.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Given VLAN model is different than the current one.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_service_mapping_vids(la_vlan_id_t vid1, la_vlan_id_t vid2) = 0;

    /// @brief Retrieve the service mapping VIDs associated with the port.
    ///
    /// @param[out] out_vid1            VLAN ID to populate.
    /// @param[out] out_vid2            VLAN ID to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_service_mapping_vids(la_vlan_id_t& out_vid1, la_vlan_id_t& out_vid2) const = 0;

    /// @brief Get ethernet port associated with this service port.
    ///
    /// @param[out]     out_ethernet_port   Ethernet port associated with this service port.
    ///
    /// @retval         LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval         LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ethernet_port(const la_ethernet_port*& out_ethernet_port) const = 0;

    /// @brief Set ACL drop counter offset.
    ///
    /// @param[in]  stage                   Indicates whether the offset is for the ingress/egress ACL.
    /// @param[in]  offset                  Offset within the counter set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   The given offset is out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_drop_counter_offset(la_stage_e stage, size_t offset) = 0;

    /// @brief Get ACL drop counter offset.
    ///
    /// @param[in]   stage                  Indicates whether the offset is for the ingress/egress ACL.
    /// @param[out]  out_offset             Offset within the counter set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_drop_counter_offset(la_stage_e stage, size_t& out_offset) const = 0;

    /// @brief Adds an entry in the service mapping table associsated with the port.
    ///
    /// A catch all entry is added if vid is LA_VLAN_ID_INVALID.
    ///
    /// @param[out] vid                 VLAN ID.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Given VLAN model is different than the current one.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_service_mapping_vid(la_vlan_id_t vid) = 0;

    /// @brief Removes an entry form the service mapping table associsated with the port.
    ///
    /// A catch all entry is removed if vid is LA_VLAN_ID_INVALID.
    ///
    /// @param[out] vid                 VLAN ID.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Given VLAN model is different than the current one.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove_service_mapping_vid(la_vlan_id_t vid) = 0;

    /// @brief Gets the list of mapped vid entries form the service mapping table associsated with the port.
    ///
    /// @param[out] out_mapped_vids            The list of mapped VLAN Id's.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_service_mapping_vid_list(la_vid_vec_t& out_mapped_vids) const = 0;

    /// @brief Enable/Disable sFlow at ingress.
    ///
    /// @param[in] enabled      True if sFlow should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ingress_sflow_enabled(bool enabled) = 0;

    /// @brief Return sFlow status at ingress.
    ///
    /// @param[out] out_enabled      True if sFlow is enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ingress_sflow_enabled(bool& out_enabled) const = 0;

    /// @brief Enable/Disable sFlow at egress.
    ///
    /// @param[in] enabled      True if sFlow should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_egress_sflow_enabled(bool enabled) = 0;

    /// @brief Return sFlow status at egress.
    ///
    /// @param[out] out_enabled      True if sFlow is enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_egress_sflow_enabled(bool& out_enabled) const = 0;

    /// @brief Enable/Disable control word for PWE.
    ///
    /// @param[in] enabled      True if control word should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Port is not a PWE port.
    virtual la_status set_control_word_enabled(bool enabled) = 0;

    /// @brief Return control word status for PWE.
    ///
    /// @param[out] out_enabled      True if control word is enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Port is not a PWE port.
    virtual la_status get_control_word_enabled(bool& out_enabled) const = 0;

    /// @brief Enable/Disable flow label for PWE.
    ///
    /// @param[in] enabled      True if flow label should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Port is not a PWE port.
    virtual la_status set_flow_label_enabled(bool enabled) = 0;

    /// @brief Return flow label status for PWE.
    ///
    /// @param[out] out_enabled      True if flow label is enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Port is not a PWE port.
    virtual la_status get_flow_label_enabled(bool& out_enabled) const = 0;

    /// @brief Set AC profile for PWE.
    ///
    /// AC profile defines how AC mapping keys will be selected during, per packet format, for incoming packets for pwe port.
    /// Read #silicon_one::la_ac_profile for more information.
    ///
    /// @param[in]  ac_profile          AC profile for the pwe port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    AC profile is NULL.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ac_profile_for_pwe(la_ac_profile* ac_profile) = 0;

    /// @brief Get AC profile for PWE.
    ///
    /// @param[out] out_ac_profile      Pointer to #silicon_one::la_ac_profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_ac_profile contains port's AC profile.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ac_profile_for_pwe(la_ac_profile*& out_ac_profile) const = 0;

    /// @brief Set properties for PWE to support bum packets to PWE.
    ///
    /// @param[in] recycle_label        label used to send pwe bum pkts from 1st pass through recycle port to 2nd pass
    /// @param[in] recycle_destination  pointer to #silicon_one::la_next_hop, for sending bum pks thruough recycle port
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_ac_profile contains port's AC profile.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pwe_multicast_recycle_lsp_properties(la_mpls_label recycle_label, la_next_hop* recycle_destination) = 0;

    /// @brief Get TTL inheritance mode of the port.
    ///
    /// @param[out]  out_ttl_mode         TTL inheritance mode.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL      An unknown error occurred.
    virtual la_status get_ttl_inheritance_mode(la_ttl_inheritance_mode_e& out_ttl_mode) const = 0;

    /// @brief Set the TTL inheritance mode of the port.
    ///
    /// @param[in]  ttl_mode              TTL inheritance mode.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL      An unknown error occurred.
    virtual la_status set_ttl_inheritance_mode(la_ttl_inheritance_mode_e ttl_mode) = 0;

    /// @brief Get TTL value of the port.
    ///
    /// @param[out]  out_ttl              TTL of the port.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL      An unknown error occurred.
    virtual la_status get_ttl(la_uint8_t& out_ttl) const = 0;

    /// @brief Set TTL for the port.
    ///
    /// The TTL value is set to the outer IP header of the tunnel. The Default value is 255.
    /// Only applicable when the TTL inheritance mode is la_ttl_inheritance_mode_e::PIPE.
    ///
    /// @param[in]  ttl                   TTL value of the port.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_ttl(la_uint8_t ttl) = 0;

    /// @brief Get egress feature mode for this AC port. Default mode is L3.
    ///
    /// @param[out] out_mode  Pointer to #egress_feature_mode_e to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_egress_feature_mode(egress_feature_mode_e& out_mode) const = 0;

    /// @brief Set egress feature mode for this AC port. Default mode is L3.
    ///
    /// @param[in]  mode  egress_feature_mode_e for AC Port.
    ///
    /// @retval     LA_STATUS_SUCCESS         Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE     GID of the L2_AC is not within expected range.
    virtual la_status set_egress_feature_mode(egress_feature_mode_e mode) = 0;

    /// @brief Enable CFM mep on this service port.
    ///
    /// @param[in]   mep_dir                Indicates if MEP direction is UP/DOWN.
    /// @param[in]   mep_lvl                Indicates the level of MEP.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Invalid MEP level.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_cfm_enabled(la_mep_direction_e mep_dir, la_uint8_t mep_lvl) = 0;

    /// @brief Clear CFM mep on this service port.
    ///
    /// @param[in]   mep_dir              Indicates if MEP direction is UP/DOWN.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status clear_cfm(la_mep_direction_e mep_dir) = 0;

    /// @brief Get Mep details for a given Mep direction for this service port.
    ///
    /// @param[in]   mep_dir                Indicates if MEP direction is UP/DOWN.
    /// @param[out]  out_mep_lvl            MEP level set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND     Mep does not exist on this port.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_cfm_mep(la_mep_direction_e mep_dir, la_uint8_t& out_mep_lvl) const = 0;

    /// @brief Enable/Disable Security Group Policy Enacp on VXLAN.
    ///
    /// @param[in] enabled      True if Group Policy Encap needs to be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Port is not a VXLAN port.
    virtual la_status set_group_policy_encap(bool enabled) = 0;

    /// @brief Return Group Policy Encap status for VXLAN.
    ///
    /// @param[out] out_enabled      True if Group Policy Encap is enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Port is not a VXLAN port.
    virtual la_status get_group_policy_encap(bool& out_enabled) const = 0;

    /// @brief Remove service mapping entry for the underlying AC port and clear
    /// ethernet (Port,VLAN, VLAN) mapping.
    ///
    /// The object becomes invalid if the call is successful, and should not be used from that point on.
    ///
    /// @retval     LA_STATUS_SUCCESS   Object has been destroyed successfully.
    /// @retval     LA_STATUS_EINVAL    Object is corrupt or invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status disable() = 0;

    /// @brief Set COPC profile on L2 service port.
    ///
    /// @param[in]  l2_service_port_profile_id   COPC profile. Default value is 0.
    ///
    /// @retval     LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE  l2_service_port_profile_id is out of range.
    /// @retval     LA_STATUS_EINVAL       Object is corrupt or invalid.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status set_copc_profile(la_control_plane_classifier::l2_service_port_profile_id_t l2_service_port_profile_id) = 0;

    /// @brief Get COPC profile from L2 service port.
    ///
    /// @param[out] out_l2_service_port_profile_id COPC profile.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_copc_profile(
        la_control_plane_classifier::l2_service_port_profile_id_t& out_l2_service_port_profile_id) const = 0;

protected:
    ~la_l2_service_port() override = default;
};

/// @}
}

#endif
