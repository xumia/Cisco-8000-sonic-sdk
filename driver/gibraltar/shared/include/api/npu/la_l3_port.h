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

#ifndef __LA_L3_PORT_H__
#define __LA_L3_PORT_H__

#include "api/npu/la_acl.h"
#include "api/npu/la_acl_group.h"
#include "api/npu/la_counter_set.h"
#include "api/system/la_mirror_command.h"
#include "api/types/la_acl_types.h"
#include "api/types/la_event_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_mpls_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_tunnel_types.h"

namespace silicon_one
{

/// @file
/// @brief Leaba Layer 3 Port API-s.
///
/// Layer 3 port acts as the superclass of all Layer 3 ports.
///

class la_l3_port : public la_object
{

public:
    /// @addtogroup L3PORT
    /// @{

    /// Defines Router's port uRPF (unicast Revert Path Forwarding) mode
    enum class urpf_mode_e {
        NONE,   ///< No uRPF check for the port
        STRICT, ///< Strict uRPF check for the port (reverse path port is the ingress port)
        LOOSE,  ///< Loose uRPF check for the port (reverse path exists)
    };

    /// Defines Port's load balancing profile.
    enum class lb_profile_e {
        MPLS,   ///< Load balance based on the MPLS labels
        IP,     ///< Load balance based on the IP packet
        EL_ELI, ///< Load balance based on the Entropy label
    };

    /// @name General
    /// @{

    /// @brief   Get the port's global ID.
    ///
    /// @retval  Port's global ID.
    virtual la_l3_port_gid_t get_gid() const = 0;

    /// @brief Sets port activity state.
    ///
    /// Traffic is routed only through active ports.
    ///
    /// @param[in]  active      true is active, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port activity state changed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_active(bool active) = 0;

    /// @brief Gets port activity state.
    ///
    /// @param[out] out_active          True if port is active.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_active(bool& out_active) const = 0;

    /// @}
    /// @name Port type
    /// @{

    /// @brief Query protocol support for the port.
    ///
    /// @param[in]  protocol            Protocol to be queried.
    /// @param[out] out_enabled         Pointer to bool to be populated with true if protocol enabled; false otherwise.
    ///
    /// @return status.
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_protocol_enabled(la_l3_protocol_e protocol, bool& out_enabled) const = 0;

    /// @brief Enable/Disable specific protocol for the port.
    ///
    /// Default is enabled.
    ///
    /// @param[in]  protocol            Protocol to be enabled/disabled.
    /// @param[in]  enabled             true if protocol should be enabled; false otherwise.
    ///
    /// @return status.
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_protocol_enabled(la_l3_protocol_e protocol, bool enabled) = 0;

    /// @}
    /// @name Trap and snoop
    /// @{

    /// @brief Query trapping/snooping of port events.
    ///
    /// @param[in]  event               Event to be queried.
    /// @param[out] out_enabled         Pointer to bool to be populated with true if event enabled; false otherwise.
    ///
    /// @return status.
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_event_enabled(la_event_e event, bool& out_enabled) const = 0;

    /// @brief Enable/Disable trapping/snooping of port events.
    ///
    /// @param[in]  event               Event to be enabled/disabled.
    /// @param[in]  enabled             true if event should be enabled; false otherwise.
    ///
    /// @return status.
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_event_enabled(la_event_e event, bool enabled) = 0;

    /// @}
    /// @name uRPF (unicast Reverse Path Forwarding)
    /// @{

    /// @brief Get uRPF mode of the port.
    ///
    /// @param[out] out_urpf_mode       Pointer to #urpf_mode_e to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_urpf_mode contains port's uRPF mode.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_urpf_mode(urpf_mode_e& out_urpf_mode) const = 0;

    /// @brief Set uRPF mode of the L3 port.
    ///
    /// @param[in]  urpf_mode           uRPF mode for the port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port uRPF mode changed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_urpf_mode(urpf_mode_e urpf_mode) = 0;

    /// @}
    /// @name QoS
    /// @{

    /// @brief Set port's ingress QoS profile.
    ///
    /// @param[in]  ingress_qos_profile     Ingress QoS profile to set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Ingress QoS profile is NULL.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_ingress_qos_profile(la_ingress_qos_profile* ingress_qos_profile) = 0;

    /// @brief Get port's ingress QoS profile.
    ///
    /// @param[out] out_ingress_qos_profile     Ingress QoS profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully. out_ingress_qos_profile contains the ingress QoS
    /// profile.
    /// @retval     LA_STATUS_ENOTFOUND         No ingress QoS profile is set.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) const = 0;

    /// @brief Set port's egress QoS profile.
    ///
    /// @param[in]  egress_qos_profile      Egress QoS profile to set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Egress QoS profile is NULL.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile) = 0;

    /// @brief Get port's egress QoS profile.
    ///
    /// @param[out] out_egress_qos_profile  Egress QoS profile to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully. out_egress_qos_profile contains the egress QoS
    /// profile.
    /// @retval     LA_STATUS_ENOTFOUND     No egress QoS profile is set.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_egress_qos_profile(la_egress_qos_profile*& out_egress_qos_profile) const = 0;

    /// @brief Enable/disable ECN marking on the port.
    ///
    /// @param[in]  enabled                    true if enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_ecn_remark_enabled(bool enabled) = 0;

    /// @brief Get the ECN marking setting on the port.
    ///
    /// @param[out] out_enabled                true if enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_ecn_remark_enabled(bool& out_enabled) const = 0;

    /// @brief Set the ECN counting enabled for this port.
    ///
    /// ECN packet counting uses silicon_one::la_counter_set::type_e::QOS type counter
    /// attached via the silicon_one::la_l3_port::set_egress_counter API.
    ///
    /// @param[in]  enabled                    true if enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_ecn_counting_enabled(bool enabled) = 0;

    /// @brief Get the ECN counting enabled for this port.
    ///
    /// ECN packet counting uses #silicon_one::la_counter_set::type_e::QOS type counter
    /// attached via the #silicon_one::la_l3_port::set_egress_counter API.
    ///
    /// @param[out] out_enabled                true if enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_ecn_counting_enabled(bool& out_enabled) const = 0;

    /// @}
    /// @name ACL
    /// @{

    /// @brief Set ACL group for the port.
    ///
    /// @param[in]  dir                 Direction (ingress or egress)
    /// @param[in]  acl_group           ACL group to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   ACLs set successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid ACLs.
    /// @retval     LA_STATUS_ERESOURCE No resources to attach the ACL.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_acl_group(la_acl_direction_e dir, la_acl_group* acl_group) = 0;

    /// @brief Get the ACL group for the port.
    ///
    /// @param[in]  dir                 Direction (ingress or egress)
    ///
    /// @param[out] out_acl_group       ACL group.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_acl_group(la_acl_direction_e dir, la_acl_group*& out_acl_group) const = 0;

    /// @brief Clear ACL group for the port.
    ///
    /// @param[in]  dir                 Direction (ingress or egress)
    ///
    /// @retval     LA_STATUS_SUCCESS   ACLs set successfully.
    /// @retval     LA_STATUS_ENOTFOUND No ACL is currently set.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_acl_group(la_acl_direction_e dir) = 0;

    /// @brief Enable/Disable PBR (Policy Based Routing) on the port.
    ///
    /// @param[in]  enabled             true if PBR should be enabled for this port, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   PBR enabled/disabled successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pbr_enabled(bool enabled) = 0;

    /// @brief Retrieve PBR (Policy Based Routing) state on the port.
    ///
    /// @param[out]  out_enabled        true if PBR is enabled for this port, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   PBR enabled retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pbr_enabled(bool& out_enabled) const = 0;

    /// @brief Set MPLS QOS inheritance mode for the port.
    ///
    /// @param[in]    mode   The QOS mode
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_qos_inheritance_mode(la_mpls_qos_inheritance_mode_e mode) = 0;

    /// @brief Get QOS inheritance mode.
    ///
    /// @retval     The port's QOS inheritance mode.
    virtual la_mpls_qos_inheritance_mode_e get_qos_inheritance_mode() const = 0;

    /// @name Counting and Metering
    /// @{

    /// @brief Set port's QoS/Port ingress counter.
    ///
    /// For port counters, supported set sizes are 1 (aggregate all traffic in a single counter), or 5 (count traffic per L3
    /// protocol value defined in #la_l3_protocol_e).\n
    /// For QoS counters, supported set sizes are 1-8. An ACL rule is needed to determine counter offset; it is the user's
    /// responsibility to ensure the ACL rule's offsets are in-range for the counter set.
    /// Passing NULL counter removes an existing counter if there's one, and has no effect if there's none.
    /// If there's a counter already associated with this port then it is replaced by this function.
    ///
    /// @param[in]  counter             Counter object.
    /// @param[in]  type                Counter type.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid set size.
    /// @retval     LA_STATUS_EINVAL    Counter type is other than QOS or PORT.
    /// @retval     LA_STATUS_EEXIST    A counter of this type is already associated with this port/direction.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ingress_counter(la_counter_set::type_e type, la_counter_set* counter) = 0;

    /// @brief Get port's QoS/Port ingress counter.
    ///
    /// @param[in]      type                Counter type.
    /// @param[out]     out_counter         Counter object to populate.
    ///
    /// @retval         LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval         LA_STATUS_EINVAL    Counter type is other than QOS or PORT.
    /// @retval         LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ingress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const = 0;

    /// @brief Set port's QoS/Port egress counter.
    ///
    /// For port counters, supported set sizes are 1 (aggregate all traffic in a single counter), or 5 (count traffic per L3
    /// protocol value defined in #la_l3_protocol_e).\n
    /// For QoS counters, supported set sizes are 1-8. An ACL rule is needed to determine counter offset; it is the user's
    /// responsibility to ensure the ACL rule's offsets are in-range for the counter set.
    /// Passing NULL counter removes an existing counter if there's one, and has no effect if there's none.
    /// If there's a counter already associated with this port then it is replaced by this function.
    ///
    /// @param[in]  counter               Counter object.
    /// @param[in]  type                  Counter type.
    ///
    /// @retval     LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL       Counter type is other than QOS or PORT.
    /// @retval     LA_STATUS_EINVAL       Invalid set size.
    /// @retval     LA_STATUS_EEXIST       A counter of this type is already associated with this port/direction.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status set_egress_counter(la_counter_set::type_e type, la_counter_set* counter) = 0;

    /// @brief Get port's QoS/Port egress counter.
    ///
    /// @param[in]      type                Counter type.
    /// @param[out]     out_counter         Counter object to populate.
    ///
    /// @retval         LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval         LA_STATUS_EINVAL    Counter type is other than QOS or PORT.
    /// @retval         LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_egress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const = 0;

    /// @brief Attach a meter to the port.
    ///
    /// Attaches a meter to the port. The #silicon_one::la_ingress_qos_profile attached to this port or an ACL rule is needed to
    /// determine the meter offset; it is the user's responsibility to ensure the #silicon_one::la_ingress_qos_profile's offsets and
    /// ACL
    /// rule's offsets are in-range for the meter. Passing a nullptr meter removes an existing meter if there's one, and has no
    /// effect if there's none.
    ///
    /// A #silicon_one::la_meter_set::type_e::EXACT meter can be a attached only to a single #silicon_one::la_l3_port that accepts
    /// ingress
    /// traffic from a single #silicon_one::la_system_port. The aforementioned L3-AC port can be attached only with a
    /// #silicon_one::la_meter_set::type_e::EXACT or a #silicon_one::la_meter_set::type_e::STATISTICAL meter types.
    ///
    /// @param[in]  meter               Meter object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    An exact meter is invalid for this port.
    /// @retval     LA_STATUS_EBUSY     An exact meter is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_meter(const la_meter_set* meter) = 0;

    /// @brief Get the attached meter to the port.
    ///
    /// @param[out] out_meter           Meter to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_meter(const la_meter_set*& out_meter) const = 0;

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

    /// @brief Enable/Disable CSC (Carrier supporting Carrier) on the logical port
    ///
    /// param[in]   enabled                     true if CSC should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_csc_enabled(bool enabled) = 0;

    /// @brief Query CSC (Carrier supporting Carrier) on the logical port
    ///
    /// param[out]   out_enabled                true if CSC is enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_csc_enabled(bool& out_enabled) const = 0;

    /// @brief Get load balancing profile for this port.
    ///
    /// @param[out] out_lb_profile      Reference to #lb_profile_e to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_load_balancing_profile(lb_profile_e& out_lb_profile) const = 0;

    /// @brief Set load balancing profile for this port.
    ///
    /// Default is LB_PROFILE_MPLS.
    ///
    /// @param[in]  lb_profile          Load balancing profile.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_load_balancing_profile(lb_profile_e lb_profile) = 0;

    /// @brief Set ingress mirror command.
    ///
    /// @param[in]  mirror_cmd      Mirror command. If nullptr, mirroring will be disabled on this port.
    /// @param[in]  is_acl_conditioned  Indicating whether mirror command is always active, or only when a relevant ACL
    /// command is matching the packet.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) = 0;

    /// @brief Get ingress mirror command.
    ///
    /// @param[out]  out_mirror_cmd      Mirror command.
    /// @param[out]  out_is_acl_conditioned  Indicating whether mirror command is always active, or only when a relevant ACL
    /// command is matching the packet.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.

    virtual la_status get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const = 0;

    /// @brief Set egress mirror command.
    ///
    /// @param[in]  mirror_cmd                  Mirror command. If nullptr, mirroring will be disabled on this port.
    /// @param[in]  is_acl_conditioned          Indicating whether mirror command is always active,
    ///                                         or only when a relevant ACL command is matching the packet.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    /// @retval     LA_STATUS_ENOTINITIALIZED   Table object was not initialized.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS   output queue scheduler is on a different device.
    virtual la_status set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) = 0;

    /// @brief Get egress mirror command.
    ///
    /// @param[out]  out_mirror_cmd             Mirror command.
    /// @param[out]  out_is_acl_conditioned     Indicating whether mirror command is always active,
    ///                                         or only when a relevant ACL command is matching the packet.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    virtual la_status get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const = 0;

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
    /// @param[in]  stage                   Indicates whether the offset is for the ingress/egress ACL.
    /// @param[out] out_offset              Offset within the counter set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_drop_counter_offset(la_stage_e stage, size_t& out_offset) const = 0;

    /// @brief Set source-based forwarding.
    ///
    /// Enable source-based forwarding of incoming traffic to the provided L3 destination.
    /// When forwarding to a #silicon_one::la_ip_tunnel_destination over a #silicon_one::la_gre_port tunnel the provided MPLS label
    /// is imposed
    /// after the GRE header if label_present is true.
    ///
    /// @param[in]  l3_destination             L3 destination.
    /// @param[in]  label_present              True if an MPLS label should be imposed before forwarding to the destination.
    /// @param[in]  label                      MPLS outgoing label associated with the source interface.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL           Invalid arguments provided.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_source_based_forwarding(const la_l3_destination* l3_destination, bool label_present, la_mpls_label label)
        = 0;

    /// @brief Clear source-based forwarding.
    ///
    /// @retval    LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval    LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status clear_source_based_forwarding() = 0;

    /// @brief Retrieve source-based forwarding information.
    ///
    /// @param[out]  out_l3_destination       L3 destination.
    /// @param[out]  out_label_present        True if an MPLS label is imposed before forwarding to the destination.
    /// @param[out]  out_label                MPLS outgoing label associated with the source interface.
    ///
    /// @retval     LA_STATUS_SUCCESS         Operation completed successfully.
    /// @retval     LA_STATUS_ENOTINITIALIZED Source-based forwarding is not configured on this port.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    virtual la_status get_source_based_forwarding(const la_l3_destination*& out_l3_destination,
                                                  bool& out_label_present,
                                                  la_mpls_label& out_label) const = 0;

    /// @}
    /// @name HSRP and VRRP
    /// @{

    /// @brief Add virtual MAC on port.
    ///
    /// @param[in] mac_addr    Virtual MAC address.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_virtual_mac(const la_mac_addr_t& mac_addr) = 0;

    /// @brief Remove virtual MAC from port.
    ///
    /// @param[in] mac_addr    Virtual MAC address.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove_virtual_mac(const la_mac_addr_t& mac_addr) = 0;

    /// @brief Retrieve the virtual MACs associated with port.
    ///
    /// @param[out] out_mac_addresses   Vector of Virtual MAC addresses.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_mac_addr_vec contains port's virtual MAC addresses.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_virtual_macs(la_mac_addr_vec& out_mac_addresses) const = 0;

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

    /// @}

protected:
    ~la_l3_port() override = default;

    /// @}
};

/// @}
}

#endif
