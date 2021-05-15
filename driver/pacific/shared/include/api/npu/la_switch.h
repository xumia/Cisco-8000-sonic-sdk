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

#ifndef __LA_SWITCH_H__
#define __LA_SWITCH_H__

#include "api/npu/la_copc.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_object.h"
#include "la_ethernet_port.h"
#include "la_l2_multicast_group.h"

/// @file
/// @brief Leaba Switch API-s.
///
/// Defines API-s for managing a #silicon_one::la_switch object.

/// @addtogroup L2SWITCH
/// @{

namespace silicon_one
{

/// @brief      A switch.
///
/// @details    A switch handles L2 traffic.\n
///             It receives traffic on L2 ports (#silicon_one::la_l2_port), and forwards it to L2 destinations
///             (#silicon_one::la_l2_destination).\n
///             Switch properties include VLAN editing configuration; MAC table management modes (learning, aging, etc);
///             Broadcast/Unknown settings; and QoS settings.
class la_switch : public la_object
{
public:
    /// @name MAC learning
    /// @{

    /// Decap VNI profile
    enum class vxlan_termination_mode_e {
        CHECK_DMAC,  ///< Ethernet header is processed as normal.
        IGNORE_DMAC, ///< DMAC is ignored and Ethernet header is always terminated.
        LAST,
    };

    /// @brief Get switch's MAC aging time.
    ///
    /// Time is given in seconds.
    /// When the switch is set to never expire entries, out_aging_time will be set to 0.
    ///
    /// @param[out] out_aging_time      Reference to #la_uint64_t to
    /// populate. Will be populated with the result, in seconds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. Result is placed in out_aging_time.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac_aging_time(la_mac_aging_time_t& out_aging_time) = 0;

    /// @brief Set switch's MAC aging time.
    ///
    /// Learned entries in the MAC table are cleared when their aging time is reached.
    /// When aging_time = 0, entries do not expire.
    ///
    /// Static entries do not expire, regardless of the switch's aging time setting.
    ///
    /// @param[in]  aging_time          Aging time in seconds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_mac_aging_time(la_mac_aging_time_t aging_time) = 0;

    /// @brief Get switch's maximum number of MAC addresses.
    ///
    /// @param[out] out_max_addresses   Reference to #la_uint64_t.
    /// Will be populated with the result.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. Result is placed in out_max_addresses.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_max_switch_mac_addresses(la_uint64_t& out_max_addresses) = 0;

    /// @brief Set switch's maximum number of MAC addresses.
    ///
    /// Maximal number of addresses the switch can be keep in the MAC table at any given time.
    ///
    /// @param[in]  max_addresses       Maximum number of addresses the switch's MAC table should contain.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ERESOURCE Requested number cannot be supported by existing resources.
    ///                                 MAC table size for this switch exceeds maximum requested size.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_max_switch_mac_addresses(la_uint64_t max_addresses) = 0;

    /// @brief Get maximum number of MAC addresses per this (Switch, Port) configuration.
    ///
    /// @param[in]  lport               Layer 2 port to be queried.
    /// @param[out] out_max_addresses   Pointer to #la_uint64_t. Will be populated with the result.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. Result is placed in out_max_addresses.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_max_port_mac_addresses(const la_l2_port* lport, la_uint64_t* out_max_addresses) = 0;

    /// @brief Set switch's maximum number of MAC addresses.
    ///
    /// Maximal number of addresses the switch can be keep in the MAC table at any given time.
    ///
    /// @param[in]  lport               Layer 2 port to be configured.
    /// @param[in]  max_addresses       Maximum number of addresses the switch's MAC table should contain for the given port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Port is corrupt/invalid.
    /// @retval     LA_STATUS_ERESOURCE Requested number cannot be supported by existing resources.
    ///                                 MAC table size for this (switch, port) exceeds maximum requested size.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_max_port_mac_addresses(const la_l2_port* lport, la_uint64_t max_addresses) = 0;

    /// @}
    /// @name Broadcast
    /// @{

    /// @brief Set switch's unicast/multicast/broadcast flood destination.
    ///
    /// A nullptr destination will result in packet drop. Those drop are counted on
    /// #silicon_one::la_device::get_forwarding_drop_counter.
    ///
    /// @param[in]  destination         L2 destination for the switch.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Destination object is corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_flood_destination(la_l2_destination* destination) = 0;

    /// @brief Get switch's unicast/multicast flood destination.
    ///
    /// @param[in]  out_destination     #silicon_one::la_l2_destination* to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_flood_destination(la_l2_destination*& out_destination) const = 0;

    /// @}
    /// @name IPv4 local multicast
    /// @{

    /// @brief Get switch destination for an IPv4 local multicast address.
    ///
    /// Incoming packets with specified destination IPv4 local multicast address (224.0.0.0/24)
    /// will be sent to the L2 destination.
    ///
    /// @param[in]  gaddr               IPv4 local multicast group address.
    /// @param[out] out_dest            #silicon_one::la_l2_destination* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_dest populated with valid data.
    /// @retval     LA_STATUS_ENOTFOUND Switch does not contain an entry for the local multicast address.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv4_local_multicast_destination(la_ipv4_addr_t gaddr, la_l2_destination*& out_dest) = 0;

    /// @brief Set switch destination for an IPv4 local multicast address.
    ///
    /// Incoming packets with specified destination IPv4 local multicast address (224.0.0.0/24)
    /// will be sent to the L2 destination.
    ///
    /// @param[in]  gaddr               IPv4 local multicast group address.
    /// @param[in]  destination         L2 destination for IPv4 multicast address.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Destination object is corrupt/invalid; or\n
    ///                                 gaddr is not local multicast address (224.0.0.0/24).
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ipv4_local_multicast_destination(la_ipv4_addr_t gaddr, la_l2_destination* destination) = 0;

    /// @brief Clear switch destination for an IPv4 local multicast address.
    ///
    /// @param[in]  gaddr               IPv4 link local multicast group address.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. Local multicast address cleared successfully.
    /// @retval     LA_STATUS_ENOTFOUND Switch does not contain an entry for the local multicast address.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status delete_ipv4_local_multicast_destination(la_ipv4_addr_t gaddr) = 0;

    /// @brief Delete all IPv4 local multicast addresses for specific switch.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. All IPv4 local multicast addresses deleted successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_all_ipv4_local_multicast_destination() = 0;

    /// @}
    /// @name IPv6 link local multicast
    /// @{

    /// @brief Get switch destination for an IPv6 link local multicast address.
    ///
    /// Incoming packets with specified destination IPv6 link local multicast address (FF02:0:0:0::/64)
    /// will be sent to the L2 destination.
    ///
    /// @param[in]  gaddr               IPv6 link local multicast group address.
    /// @param[out] out_dest            #silicon_one::la_l2_destination* to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_dest populated with valid data.
    /// @retval     LA_STATUS_ENOTFOUND Switch does not contain an entry for the local multicast address.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_local_multicast_destination(la_ipv6_addr_t gaddr, la_l2_destination*& out_dest) = 0;

    /// @brief Set switch destination for an IPv6 link local multicast address.
    ///
    /// Incoming packets with specified destination IPv6 link local multicast address (FF02:0:0:0::/64)
    /// will be sent to the L2 destination.
    ///
    /// @param[in]  gaddr               IPv6 link local multicast group address.
    /// @param[in]  destination         L2 destination for IPv6 local multicast address.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Destination objects are corrupt/invalid; or\n
    ///                                 gaddr is not link local multicast address (FF02:0:0:0::/64).
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ipv6_local_multicast_destination(la_ipv6_addr_t gaddr, la_l2_destination* destination) = 0;

    /// @brief Clear switch destination for an IPv6 link local multicast address.
    ///
    /// @param[in]  gaddr               IPv6 link local multicast group address.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. Local multicast address cleared successfully.
    /// @retval     LA_STATUS_ENOTFOUND Switch does not contain an entry for the local multicast address.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status delete_ipv6_local_multicast_destination(la_ipv6_addr_t gaddr) = 0;

    /// @brief Delete all IPv6 link local multicast addresses for specific switch.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. All IPv6 link local multicast addresses deleted
    /// successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_all_ipv6_local_multicast_destination() = 0;

    /// @}
    /// @name Events
    /// @{

    /// @brief Enable/Disable trapping/snooping of switch events.
    ///
    /// @param[in]  event               Event to be enabled/disabled.
    /// @param[in]  enabled             true if event should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Event is not applicable to switch.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_event_enabled(la_event_e event, bool enabled) = 0;

    /// @brief Query trapping/snooping of switch events.
    ///
    /// @param[in]  event               Event to be queried.
    /// @param[in]  out_enabled         bool to be populated with true if trap enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Event is not applicable to switch.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_event_enabled(la_event_e event, bool& out_enabled) = 0;

    /// @}
    /// @name Destination
    /// @{

    /// @brief Set L2 destination for given destination MAC address on the switch.
    ///
    /// @param[in]  mac_addr            Address to register.
    /// @param[in]  l2_destination      L2 destination to send packets with DA=mac_addr to.
    /// @param[in]  mac_aging_time      Aging time in seconds for the entry. #LA_MAC_AGING_TIME_NEVER if entry never expires.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Destination is corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_mac_entry(la_mac_addr_t mac_addr, la_l2_destination* l2_destination, la_mac_aging_time_t mac_aging_time)
        = 0;

    /// @}
    /// @name Destination
    /// @{

    /// @brief Set L2 destination for given destination MAC address on the switch.
    ///
    /// @param[in]  mac_addr            Address to register.
    /// @param[in]  l2_destination      L2 destination to send packets with DA=mac_addr to.
    /// @param[in]  mac_aging_time      Aging time in seconds for the entry. #LA_MAC_AGING_TIME_NEVER if entry never expires.
    /// @param[in]  class_id            Class identifier associated with the MAC address.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Destination is corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_mac_entry(la_mac_addr_t mac_addr,
                                    la_l2_destination* l2_destination,
                                    la_mac_aging_time_t mac_aging_time,
                                    la_class_id_t class_id)
        = 0;

    /// @brief Set L2 destination for given destination MAC address on the switch.
    ///
    /// @param[in]  mac_addr            Address to register.
    /// @param[in]  l2_destination      L2 destination to send packets with DA=mac_addr to.
    /// @param[in]  mac_aging_time      Aging time in seconds for the entry. #LA_MAC_AGING_TIME_NEVER if entry never expires.
    /// @param[in]  owner               Influence System MAC Aging behavior in multi-device applications.
    ///                                 If owner is set for the MAC entry, age notification will be generated when entry aged.
    ///                                 If not set, age notification will not be generated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Destination is corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_mac_entry(la_mac_addr_t mac_addr,
                                    la_l2_destination* l2_destination,
                                    la_mac_aging_time_t mac_aging_time,
                                    bool owner)
        = 0;

    /// @brief remove mac_entry destination on the switch.
    ///
    /// @param[in]  mac_addr            Address to delete.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove_mac_entry(la_mac_addr_t mac_addr) = 0;

    /// @brief Get L2 destination and aging time for given destination MAC address on the switch.
    ///
    /// @param[in]  mac_addr            Address to be queried.
    /// @param[out] out_l2_destination  #silicon_one::la_l2_destination* to be populated.
    /// @param[out] out_mac_entry_info  #la_mac_age_info_t to be populated.
    ///                                 age_value         If entry never expires, this will return #LA_MAC_AGING_TIME_NEVER.
    ///                                 age_remaining     If entry never expires, this will return #LA_MAC_AGING_TIME_NEVER.
    ///                                 out_owner         bool to be populated. Indicates current device is the "master"
    ///                                                   entry owner in multi-device systems
    ///
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND MAC address has no destination associated with it.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac_entry(la_mac_addr_t mac_addr,
                                    la_l2_destination*& out_l2_destination,
                                    la_mac_age_info_t& out_mac_entry_info) const = 0;

    /// @brief Get L2 destination and aging time for given destination MAC address on the switch.
    ///
    /// @param[in]  mac_addr            Address to be queried.
    /// @param[out] out_l2_destination  #silicon_one::la_l2_destination* to be populated.
    /// @param[out] out_mac_entry_info  #la_mac_age_info_t to be populated.
    ///                                 age_value         If entry never expires, this will return #LA_MAC_AGING_TIME_NEVER.
    ///                                 age_remaining     If entry never expires, this will return #LA_MAC_AGING_TIME_NEVER.
    ///                                 out_owner         bool to be populated. Indicates current device is the "master"
    ///                                                   entry owner in multi-device systems
    /// @param[out] out_class_id        Class identifier associated with the MAC address.
    ///
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND MAC address has no destination associated with it.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac_entry(la_mac_addr_t mac_addr,
                                    la_l2_destination*& out_l2_destination,
                                    la_mac_age_info_t& out_mac_entry_info,
                                    la_class_id_t& out_class_id) const = 0;

    /// @brief Return a vector of all MAC entries on the switch.
    ///
    /// @param[out] out_count           #la_uint32_t count to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac_entries_count(la_uint32_t& out_count) = 0;

    /// @brief Return a vector of all MAC entries on the switch.
    ///
    /// @param[out] out_mac_entries     #la_mac_entry_vec to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac_entries(la_mac_entry_vec& out_mac_entries) = 0;

    /// @brief Delete all MAC entries on the switch.
    ///
    /// @param[out] out_mac_entries     #la_mac_entry_vec to be populated.
    /// @param[in] dynamic_only         Flush dynamic MAC entries only
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status flush_mac_entries(bool dynamic_only, la_mac_entry_vec& out_mac_entries) = 0;

    /// @brief Get VXLAN encapsulation VNI of the switch.
    ///
    /// @param[out]  out_vni            #la_vni_t vni to be populated
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_decap_vni(la_vni_t& out_vni) const = 0;

    /// @brief Set VXLAN decapsulation VNI of the switch.
    ///
    /// @param[in]  vni                     vni to set
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   VNI out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_decap_vni(la_vni_t vni) = 0;

    /// @brief Clear VXLAN decapsulation VNI of the switch.
    ///        It also remove the decapsulation counters
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_decap_vni() = 0;

    /// @brief Get VXLAN decapsulation VNI profile.
    ///
    /// @retval     The decapsulation VNI profile.
    virtual vxlan_termination_mode_e get_decap_vni_profile() const = 0;

    /// @brief Set VXLAN decapsulation VNI profile.
    ///
    /// @param[in]  vni_profile             VNI decapsulation profile.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_decap_vni_profile(vxlan_termination_mode_e vni_profile) = 0;

    /// @brief Get VXLAN encap counter
    ///
    /// @param[out]  counter            #silicon_one::la_counter_set to be populated
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_vxlan_encap_counter(la_counter_set*& counter) const = 0;

    /// @brief Set VXLAN encap counter
    ///
    /// @param[in]  counter             counter set for encap
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_vxlan_encap_counter(la_counter_set* counter) = 0;

    /// @brief Remove VXLAN encap counter
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove_vxlan_encap_counter() = 0;

    /// @brief Get VXLAN decap counter
    ///
    /// @param[out] counter            #silicon_one::la_counter_set to be populated
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_vxlan_decap_counter(la_counter_set*& counter) const = 0;

    /// @brief Set VXLAN decap counter
    ///
    /// @param[in]  counter             counter set for decap
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_vxlan_decap_counter(la_counter_set* counter) = 0;

    /// @brief Remove VXLAN decap counter
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove_vxlan_decap_counter() = 0;

    /// @brief Retrieve drop settings of unknown unicast packets on this switch
    ///
    /// @param[out] out_drop_unknown_uc_enabled  True if drop is enabled, False otherwise
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_drop_unknown_uc_enabled(bool& out_drop_unknown_uc_enabled) const = 0;

    /// @brief Enable/Disable drop settings of unknown unicast packets on this switch
    ///
    /// @param[in]  drop_unknown_uc_enabled  True if drop should be enabled, False otherwise
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_drop_unknown_uc_enabled(bool drop_unknown_uc_enabled) = 0;

    /// @brief Retrieve drop settings of unknown multicast packets on this switch
    ///
    /// @param[out] out_drop_unknown_mc_enabled  True if drop is enabled, False otherwise
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_drop_unknown_mc_enabled(bool& out_drop_unknown_mc_enabled) const = 0;

    /// @brief Enable/Disable drop settings of unknown multicast packets on this switch
    ///
    /// @param[in]  drop_unknown_mc_enabled  True if drop should be enabled, False otherwise
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_drop_unknown_mc_enabled(bool drop_unknown_mc_enabled) = 0;

    /// @brief Retrieve drop settings of unknown broadcast packets on this switch
    ///
    /// @param[out] out_drop_unknown_bc_enabled  True if drop is enabled, False otherwise
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_drop_unknown_bc_enabled(bool& out_drop_unknown_bc_enabled) const = 0;

    /// @brief Enable/Disable drop settings of unknown broadcast packets on this switch
    ///
    /// @param[in]  drop_unknown_bc_enabled  True if drop should be enabled, False otherwise
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_drop_unknown_bc_enabled(bool drop_unknown_bc_enabled) = 0;

    /// @brief Get COPC profile of the switch.
    ///
    /// @param[out] out_switch_profile_id COPC profile.
    ///
    /// @retval LA_STATUS_SUCCESS Operation completed successfully.
    /// @retval LA_STATUS_EUNKNOWN An unknown error occurred.
    virtual la_status get_copc_profile(la_control_plane_classifier::switch_profile_id_t& out_switch_profile_id) const = 0;

    /// @brief Set COPC profile on the switch.
    ///
    /// @param[in] switch_profile_id COPC profile. Default value is 0.
    ///
    /// @retval LA_STATUS_SUCCESS Operation completed successfully.
    /// @retval LA_STATUS_EOUTOFRANGE switch_profile_id is out of range.
    /// @retval LA_STATUS_EUNKNOWN An unknown error occurred.
    virtual la_status set_copc_profile(la_control_plane_classifier::switch_profile_id_t switch_profile_id) = 0;

    /// @brief Get switch's Global ID.
    ///
    /// @return Global ID of switch.
    virtual la_switch_gid_t get_gid() const = 0;

    /// @brief Enable/Disable IPv4 multicast.
    ///
    /// @param[in]  enabled             true if enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Event is not applicable to switch.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ipv4_multicast_enabled(bool enabled) = 0;

    /// @brief Retrieve settings for IPv4 multicast.
    ///
    /// @param[out]  out_enabled         bool to be populated with true if enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Event is not applicable to switch.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv4_multicast_enabled(bool& out_enabled) = 0;

    /// @brief Enable/Disable IPv6 multicast.
    ///
    /// @param[in]  enabled             true if enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Event is not applicable to switch.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ipv6_multicast_enabled(bool enabled) = 0;

    /// @brief Retrieve settings for IPv6 multicast.
    ///
    /// @param[out]  out_enabled         bool to be populated with true if enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Event is not applicable to switch.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_multicast_enabled(bool& out_enabled) = 0;

    /// @brief Delete IPv4 multicast route.
    ///
    /// @param[in]  gaddr               IPv4 multicast group address.
    ///
    /// @retval     LA_STATUS_SUCCESS   Multicast route deleted successfully.
    /// @retval     LA_STATUS_ENOTFOUND Does not contain a route for gaddr.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status delete_ipv4_multicast_route(la_ipv4_addr_t gaddr) = 0;

    /// @brief Retrieve multicast group for specific IPv4 multicast address.
    ///
    /// @param[in]  gaddr                   IPv4 multicast group address.
    /// @param[out] out_l2_mc_route_info    Returned L2 multicast route information.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Does not contain a route for gaddr.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv4_multicast_route(la_ipv4_addr_t gaddr, la_l2_mc_route_info& out_l2_mc_route_info) const = 0;

    /// @brief Add route for an IPv4 multicast address.
    ///
    /// Incoming packets with specified destination IPv4 multicast address
    /// will be sent to the given multicast group.
    ///
    /// @param[in]  gaddr               IPv4 multicast group address.
    /// @param[in]  mcg                 Multicast group object to send traffic to.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EINVAL    Either multicast group or port is corrupt/invalid.
    /// @retval     LA_STATUS_EEXIST    Route already exists.
    /// @retval     LA_STATUS_ERESOURCE No resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv4_multicast_route(la_ipv4_addr_t gaddr, la_l2_multicast_group* mcg) = 0;

    /// @brief Delete IPv6 multicast route.
    ///
    /// @param[in]  gaddr               IPv6 multicast group address.
    ///
    /// @retval     LA_STATUS_SUCCESS   Multicast route deleted successfully.
    /// @retval     LA_STATUS_ENOTFOUND Does not contain a route for gaddr.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status delete_ipv6_multicast_route(la_ipv6_addr_t gaddr) = 0;

    /// @brief Retrieve multicast group for specific IPv6 multicast address.
    ///
    /// @param[in]  gaddr                   IPv6 multicast group address.
    /// @param[out] out_l2_mc_route_info    Returned L2 multicast route information.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Does not contain a route for gaddr.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_multicast_route(la_ipv6_addr_t gaddr, la_l2_mc_route_info& out_l2_mc_route_info) const = 0;

    /// @brief Add route for an IPv6 multicast address.
    ///
    /// Incoming packets with specified destination IPv6 multicast address
    /// will be sent to the given multicast group.
    ///
    /// @param[in]  gaddr               IPv6 multicast group address.
    /// @param[in]  mcg                 Multicast group object to send traffic to.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EINVAL    Either multicast group or port is corrupt/invalid.
    /// @retval     LA_STATUS_EEXIST    Route already exists.
    /// @retval     LA_STATUS_ERESOURCE No resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv6_multicast_route(la_ipv6_addr_t gaddr, la_l2_multicast_group* mcg) = 0;

    /// @brief Set Security Group Policy enforcement.
    ///
    /// @param[in]  enforcement                Enable/Disable SGACL enforcement.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    virtual la_status set_security_group_policy_enforcement(bool enforcement) = 0;

    /// @brief Get Security Group Policy enforcement.
    ///
    /// @param[out] out_enforcement            Configured enforcement.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    virtual la_status get_security_group_policy_enforcement(bool& out_enforcement) const = 0;

    /// @brief Set the switch mode to always flood, i.e. no unicast allowed
    ///
    /// @param[in] enabled       Enable the mode of force_flood
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_ac_profile contains port's AC profile.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_force_flood_mode(bool enabled) = 0;

protected:
    ~la_switch() override = default;
};
}

/// @}

#endif
