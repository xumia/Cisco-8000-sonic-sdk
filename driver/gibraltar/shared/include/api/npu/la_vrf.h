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

#ifndef __LA_VRF_H__
#define __LA_VRF_H__

/// @file
/// @brief Leaba VRF API-s.
///
/// Defines API-s for managing an #la_vrf object.

#include "api/npu/la_vrf_redirect_destination.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_object.h"
#include "api/types/la_security_group_types.h"
#include "common/la_status.h"

/// @addtogroup VRF
/// @{

namespace silicon_one
{

class la_counter_set;
class la_acl;

/// Command to perform for prefix.
enum class la_route_entry_action_e {
    ADD,    ///< Add IP route.
    DELETE, ///< Delete IP route.
    MODIFY, ///< Modify IP route destination and user data
};

/// An IPv4 route entry parameters.
struct la_ipv4_route_entry_parameters {
    la_route_entry_action_e action;       ///< Command to perform for prefix.
    la_ipv4_prefix_t prefix;              ///< IPv4 network prefix.
    const la_l3_destination* destination; ///< Destination to send traffic to.
    bool is_class_id_set;                 ///< Class identifier associated with the route is set.
    la_class_id_t class_id;               ///< Class identifier associated with the route. Returned by the get-route function.
    bool is_user_data_set;                ///< Opaque data associated with the route is set.
    la_user_data_t user_data;             ///< Opaque data associated with the route. Returned by the get-route function.
    bool latency_sensitive;               ///< Prefix is latency sensitive.
};

/// An IPv6 route entry parameters.
struct la_ipv6_route_entry_parameters {
    la_route_entry_action_e action;       ///< Command to perform for prefix.
    la_ipv6_prefix_t prefix;              ///< IPv6 network prefix.
    const la_l3_destination* destination; ///< Destination to send traffic to.
    bool is_class_id_set;                 ///< Class identifier associated with the route is set.
    la_class_id_t class_id;               ///< Class identifier associated with the route. Returned by the get-route function.
    bool is_user_data_set;                ///< Opaque data associated with the route is set.
    la_user_data_t user_data;             ///< Opaque data associated with the route. Returned by the get-route function.
    bool latency_sensitive;               ///< Prefix is latency sensitive.
};

/// IPv4 routes entry parameters vector.
using la_ipv4_route_entry_parameters_vec = std::vector<la_ipv4_route_entry_parameters>;

/// IPv6 routes entry parameters vector.
using la_ipv6_route_entry_parameters_vec = std::vector<la_ipv6_route_entry_parameters>;

class la_vrf : public la_object
{

public:
    /// @brief Get global unique ID of VRF.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_vrf_gid contains the VRF global ID.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_vrf_gid_t get_gid() const = 0;

    /// @brief Delete an IPv4 route from VRF's FIB.
    ///
    /// @param[in]  prefix              Route prefix to be deleted.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route deleted successfully.
    /// @retval     LA_STATUS_ENOTFOUND VRF's FIB does not contain given route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status delete_ipv4_route(la_ipv4_prefix_t prefix) = 0;

    /// @brief Delete all IPv4 routes from VRF's FIB.
    ///
    ///
    /// @retval     LA_STATUS_SUCCESS   All routes deleted successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_all_ipv4_routes() = 0;

    /// @brief Add route for an IPv4 prefix to VRF.
    ///
    /// @param[in]  prefix              IPv4 prefix to perform routing for.
    /// @param[in]  destination         Destination to send traffic to.
    /// @param[in]  user_data           Opaque data associated with the route. Returned by the get-route function.
    /// @param[in]  latency_sensitive   True is prefix is latency sensitive, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EEXIST    Route already exists for this VRF.
    /// @retval     LA_STATUS_EINVAL    Destination is corrupt/invalid.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv4_route(la_ipv4_prefix_t prefix,
                                     const la_l3_destination* destination,
                                     la_user_data_t user_data,
                                     bool latency_sensitive)
        = 0;

    /// @brief Modify route and its user_data for an IPv4 prefix in VRF object
    ///
    /// @param[in]  prefix              IPv4 prefix to perform routing for.
    /// @param[in]  destination         Destination to send traffic to.
    /// @param[in]  user_data           Opaque data associated with the route. Returned by the get-route function.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route modified successfully.
    /// @retval     LA_STATUS_ENOTFOUND No route exists for given prefix.
    /// @retval     LA_STATUS_EINVAL    Destination is corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status modify_ipv4_route(la_ipv4_prefix_t prefix, const la_l3_destination* destination, la_user_data_t user_data)
        = 0;
    virtual la_status modify_ipv4_route(la_ipv4_prefix_t prefix, const la_l3_destination* destination) = 0;

    /// @brief Bulk programming of IPv4 routes to VRF.
    ///
    /// Preparation for route modification is done in order. Actual hardware update is performed in bulk.
    /// Count of number of successfully programmed routes is returned.
    /// If there is an error in programming routes, count of successful routes would be less than the requested routes to program.
    /// If route modification fails in the preparation step for a specific route, failure is returned for first failed route.
    /// All the route entries prior to the failed one are programmed to the hardware.
    /// If route modification fails in the subsequent step for bulk route programming, success is returned.
    /// All the route entries prior to the failed ones are still programmed to the hardware.
    ///
    /// @param[in]  route_entry_vec     IPv4 route entry vector to perform routing for.
    /// @param[out] out_count_success   Returns the number of successfully programmed routes.
    ///
    /// @retval     LA_STATUS_SUCCESS   All routes update performed successfully.
    /// @retval     LA_STATUS_EEXIST    Route already exists for this VRF.
    /// @retval     LA_STATUS_EINVAL    Destination is corrupt/invalid.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_ENOTFOUND No route exists for given prefix.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status ipv4_route_bulk_updates(la_ipv4_route_entry_parameters_vec route_entry_vec, size_t& out_count_success) = 0;

    /// @brief Retrieve IPv4 route for a given address from VRF's FIB.
    ///
    /// @param[in]  ip_addr             Address to query.
    /// @param[out] out_ip_route_info    Returned routing information.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route successfully found.
    /// @retval     LA_STATUS_ENOTFOUND No route exists for given prefix.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv4_route(la_ipv4_addr_t ip_addr, la_ip_route_info& out_ip_route_info) const = 0;

    /// @brief Retrieve IPv4 routing entry for the given prefix from VRF's FIB.
    ///
    /// @param[in]  prefix              Prefix to query.
    /// @param[out] out_ip_route_info    Returned routing information.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route successfully found.
    /// @retval     LA_STATUS_ENOTFOUND No route exists for given prefix.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv4_routing_entry(la_ipv4_prefix_t prefix, la_ip_route_info& out_ip_route_info) const = 0;

    /// @brief Return total count of IPv4 route entries.
    ///
    /// @param[out] out_count           #la_uint32_t count to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route successfully found.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv4_route_entries_count(la_uint32_t& out_count) const = 0;

    /// @brief Return a vector of all IPv4 route entries on the switch.
    ///
    /// @param[out] out_route_entries     #la_ipv4_route_entry_vec to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv4_route_entries(la_ipv4_route_entry_vec& out_route_entries) = 0;

    /// @brief Delete IPv4 multicast route.
    ///
    /// @param[in]  saddr               IPv4 source address. Use #LA_IPV4_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv4 multicast group address.
    ///
    /// @retval     LA_STATUS_SUCCESS   Multicast route added successfully.
    /// @retval     LA_STATUS_ENOTFOUND VRF's multicast FIB does not contain a route for saddr/gaddr.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status delete_ipv4_multicast_route(la_ipv4_addr_t saddr, la_ipv4_addr_t gaddr) = 0;

    /// @brief Delete all IPv4 multicast routes for specific VRF.
    ///
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_all_ipv4_multicast_routes() = 0;

    /// @brief Add route for an IPv4 multicast address to the VRF object.
    ///
    /// Incoming packets from specified source address and with specified destination IPv4 multicast address
    /// will be sent to the given multicast group.
    ///
    /// Multicast punting is achieved using the snoop mechanism.
    /// Punt destination is set by configuring #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER and #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER,
    /// using #silicon_one::la_device::set_snoop_configuration.
    ///
    /// If a packet fails the RPF test, and punt_on_rpf_fail is enabled, it raises an additional event. If the l3 port is an
    /// #silicon_one::la_l3_ac_port, #LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL is raised. #LA_EVENT_L3_IP_MC_DROP is also raised.
    /// If the l3 port is an #silicon_one::la_svi_port, #LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL is raised.
    ///
    /// @param[in]  saddr               IPv4 source address. Use #LA_IPV4_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv4 multicast group address.
    /// @param[in]  mcg                 Multicast group object to send traffic to.
    /// @param[in]  rpf                 Reverse Path Forwarding: Valid ingress L3 port for multicast packets.
    /// @param[in]  punt_on_rpf_fail    Punt on RPF failure.
    /// @param[in]  punt_and_forward    Punt the packet.
    /// @param[in]  counter             Counter.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EINVAL    Either multicast group or port is corrupt/invalid.
    /// @retval     LA_STATUS_EEXIST    Route already exists for this VRF.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                               la_ipv4_addr_t gaddr,
                                               la_ip_multicast_group* mcg,
                                               const la_l3_port* rpf,
                                               bool punt_on_rpf_fail,
                                               bool punt_and_forward,
                                               la_counter_set* counter)
        = 0;

    /// @brief Add route for an IPv4 multicast address to the VRF object.
    ///
    /// Incoming packets from specified source address and with specified destination IPv4 multicast address
    /// will be sent to the given multicast group.
    ///
    /// Multicast punting is achieved using the snoop mechanism.
    /// Punt destination is set by configuring #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER and #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER,
    /// using #silicon_one::la_device::set_snoop_configuration.
    ///
    /// If a packet fails the RPF test, and punt_on_rpf_fail is enabled, it raises an additional event. If the l3 port is an
    /// #silicon_one::la_l3_ac_port, #LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL is raised. #LA_EVENT_L3_IP_MC_DROP is also raised.
    /// If the l3 port is an #silicon_one::la_svi_port, #LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL is raised.
    ///
    /// @param[in]  saddr               IPv4 source address. Use #LA_IPV4_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv4 multicast group address.
    /// @param[in]  mcg                 Multicast group object to send traffic to.
    /// @param[in]  rpf                 Reverse Path Forwarding: Valid ingress L3 port for multicast packets.
    /// @param[in]  punt_on_rpf_fail    Punt on RPF failure.
    /// @param[in]  punt_and_forward    Punt the packet.
    /// @param[in]  enable_rpf_check    Enable/disable RPF check
    /// @param[in]  counter             Counter.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EINVAL    Either multicast group or port is corrupt/invalid.
    /// @retval     LA_STATUS_EEXIST    Route already exists for this VRF.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                               la_ipv4_addr_t gaddr,
                                               la_ip_multicast_group* mcg,
                                               const la_l3_port* rpf,
                                               bool punt_on_rpf_fail,
                                               bool punt_and_forward,
                                               bool enable_rpf_check,
                                               la_counter_set* counter)
        = 0;

    /// @brief Add route for an IPv4 multicast address to the VRF object.
    ///
    /// Incoming packets from specified source address and with specified destination IPv4 multicast address
    /// will be sent to the given multicast group.
    ///
    /// Multicast punting is achieved using the snoop mechanism.
    /// Punt destination is set by configuring #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER and #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER,
    /// using #silicon_one::la_device::set_snoop_configuration.
    ///
    /// If a packet fails the RPF test, and punt_on_rpf_fail is enabled, it raises an additional event. If the l3 port is an
    /// #silicon_one::la_l3_ac_port, #LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL is raised. #LA_EVENT_L3_IP_MC_DROP is also raised.
    /// If the l3 port is an #silicon_one::la_svi_port, #LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL is raised.
    ///
    /// @param[in]  saddr               IPv4 source address. Use #LA_IPV4_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv4 multicast group address.
    /// @param[in]  mcg                 Multicast group object to send traffic to.
    /// @param[in]  rpfid               Reverse Path Forwarding: User defined RPF ID used for MPLS tunnel termination
    /// @param[in]  punt_on_rpf_fail    Punt on RPF failure.
    /// @param[in]  punt_and_forward    Punt the packet.
    /// @param[in]  enable_rpf_check    Enable/disable RPF check
    /// @param[in]  counter             Counter.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EINVAL    Either multicast group or port is corrupt/invalid.
    /// @retval     LA_STATUS_EEXIST    Route already exists for this VRF.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                               la_ipv4_addr_t gaddr,
                                               la_ip_multicast_group* mcg,
                                               la_uint_t rpfid,
                                               bool punt_on_rpf_fail,
                                               bool punt_and_forward,
                                               bool enable_rpf_check,
                                               la_counter_set* counter)
        = 0;

    /// @brief Modify an existing route for an IPv4 multicast address in the VRF object.
    ///
    /// Incoming packets from specified source address and with specified destination IPv4 multicast address
    /// will be sent to the given multicast group.
    ///
    /// Multicast punting is achieved using the snoop mechanism.
    /// Punt destination is set by configuring #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER and #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER,
    /// using #silicon_one::la_device::set_snoop_configuration.
    ///
    /// If a packet fails the RPF test, and punt_on_rpf_fail is enabled, it raises an additional event. If the l3 port is an
    /// #silicon_one::la_l3_ac_port, #LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL is raised. #LA_EVENT_L3_IP_MC_DROP is also raised.
    /// If the l3 port is an #silicon_one::la_svi_port, #LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL is raised.
    ///
    /// @param[in]  saddr               IPv4 source address. Use #LA_IPV4_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv4 multicast group address.
    /// @param[in]  mcg                 Multicast group object to send traffic to.
    /// @param[in]  rpf                 Reverse Path Forwarding: Valid ingress L3 port for multicast packets.
    /// @param[in]  punt_on_rpf_fail    Punt on RPF failure.
    /// @param[in]  punt_and_forward    Punt the packet.
    /// @param[in]  counter             Counter.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EINVAL    Either multicast group or port is corrupt/invalid.
    /// @retval     LA_STATUS_ENOTFOUND Given route doesn't exist in the FIB.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status modify_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                                  la_ipv4_addr_t gaddr,
                                                  la_ip_multicast_group* mcg,
                                                  const la_l3_port* rpf,
                                                  bool punt_on_rpf_fail,
                                                  bool punt_and_forward,
                                                  la_counter_set* counter)
        = 0;

    /// @brief Modify an existing route for an IPv4 multicast address in the VRF object.
    ///
    /// Incoming packets from specified source address and with specified destination IPv4 multicast address
    /// will be sent to the given multicast group.
    ///
    /// Multicast punting is achieved using the snoop mechanism.
    /// Punt destination is set by configuring #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER and #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER,
    /// using #silicon_one::la_device::set_snoop_configuration.
    ///
    /// If a packet fails the RPF test, and punt_on_rpf_fail is enabled, it raises an additional event. If the l3 port is an
    /// #silicon_one::la_l3_ac_port, #LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL is raised. #LA_EVENT_L3_IP_MC_DROP is also raised.
    /// If the l3 port is an #silicon_one::la_svi_port, #LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL is raised.
    ///
    /// @param[in]  saddr               IPv4 source address. Use #LA_IPV4_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv4 multicast group address.
    /// @param[in]  mcg                 Multicast group object to send traffic to.
    /// @param[in]  rpf                 Reverse Path Forwarding: Valid ingress L3 port for multicast packets.
    /// @param[in]  punt_on_rpf_fail    Punt on RPF failure.
    /// @param[in]  punt_and_forward    Punt the packet.
    /// @param[in]  enable_rpf_check    Enable/disable RPF check
    /// @param[in]  counter             Counter.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EINVAL    Either multicast group or port is corrupt/invalid.
    /// @retval     LA_STATUS_ENOTFOUND Given route doesn't exist in the FIB.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status modify_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                                  la_ipv4_addr_t gaddr,
                                                  la_ip_multicast_group* mcg,
                                                  const la_l3_port* rpf,
                                                  bool punt_on_rpf_fail,
                                                  bool punt_and_forward,
                                                  bool enable_rpf_check,
                                                  la_counter_set* counter)
        = 0;

    /// @brief Modify an existing route for an IPv4 multicast address in the VRF object.
    ///
    /// Incoming packets from specified source address and with specified destination IPv4 multicast address
    /// will be sent to the given multicast group.
    ///
    /// Multicast punting is achieved using the snoop mechanism.
    /// Punt destination is set by configuring #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER and #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER,
    /// using #silicon_one::la_device::set_snoop_configuration.
    ///
    /// If a packet fails the RPF test, and punt_on_rpf_fail is enabled, it raises an additional event. If the l3 port is an
    /// #silicon_one::la_l3_ac_port, #LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL is raised. #LA_EVENT_L3_IP_MC_DROP is also raised.
    /// If the l3 port is an #silicon_one::la_svi_port, #LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL is raised.
    ///
    /// @param[in]  saddr               IPv4 source address. Use #LA_IPV4_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv4 multicast group address.
    /// @param[in]  mcg                 Multicast group object to send traffic to.
    /// @param[in]  rpfid               Reverse Path Forwarding: User defined RPF ID used for MPLS tunnel termination
    /// @param[in]  punt_on_rpf_fail    Punt on RPF failure.
    /// @param[in]  punt_and_forward    Punt the packet.
    /// @param[in]  enable_rpf_check    Enable/disable RPF check
    /// @param[in]  counter             Counter.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EINVAL    Either multicast group or port is corrupt/invalid.
    /// @retval     LA_STATUS_ENOTFOUND Given route doesn't exist in the FIB.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status modify_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                                  la_ipv4_addr_t gaddr,
                                                  la_ip_multicast_group* mcg,
                                                  la_uint_t rpfid,
                                                  bool punt_on_rpf_fail,
                                                  bool punt_and_forward,
                                                  bool enable_rpf_check,
                                                  la_counter_set* counter)
        = 0;

    /// @brief Retrieve IP multicast group for specific IPv4 multicast address, from VRF's table.
    ///
    /// @param[in]  saddr               IPv4 source address. Use #LA_IPV4_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv4 multicast group address.
    /// @param[out] out_ip_mc_route_info    Returned routing information.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND VRF's multicast FIB does not contain a route for saddr/gaddr.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                               la_ipv4_addr_t gaddr,
                                               la_ip_mc_route_info& out_ip_mc_route_info) const = 0;

    /// @brief Delete an IPv6 route from the VRF's FIB.
    ///
    /// @param[in]  prefix              Route prefix to be deleted.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route deleted successfully.
    /// @retval     LA_STATUS_ENOTFOUND VRF's FIB does not contain a route for saddr/gaddr.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status delete_ipv6_route(la_ipv6_prefix_t prefix) = 0;

    /// @brief Delete all IPv6 routes from the VRF's FIB.
    ///
    ///
    /// @retval     LA_STATUS_SUCCESS   All routes deleted successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_all_ipv6_routes() = 0;

    /// @}
    /// @name Fallback VRF
    /// @{
    ///
    /// @brief Set a fallback VRF for this VRF.
    ///
    /// In case a route lookup returns no result, a secondary lookup is performed in the fallback VRF.
    /// If nullptr, no fallback will happen for a route lookup miss.
    ///
    /// @param[in]  fallback_vrf        Pointer to the fallback VRF.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_fallback_vrf(const la_vrf* fallback_vrf) = 0;

    /// @brief Get the fallback VRF attached to this VRF.
    ///
    /// @param[out] out_vrf             Fallback VRF for this VRF.
    ///
    /// @retval     LA_STATUS_SUCCESS   Fallback VRF successfully retrieved.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_fallback_vrf(const la_vrf*& out_vrf) const = 0;

    /// @brief Add route for an IPv6 prefix to VRF object.
    ///
    /// @param[in]  prefix              IPv6 prefix to perform routing for.
    /// @param[in]  destination         Destination to send traffic to.
    /// @param[in]  user_data        Opaque data associated with the route. Returned by the get-route function
    /// @param[in]  latency_sensitive   True is prefix is latency sensitive, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EEXIST    Route already exists for this VRF.
    /// @retval     LA_STATUS_EINVAL    Destination is invalid.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv6_route(la_ipv6_prefix_t prefix,
                                     const la_l3_destination* destination,
                                     la_user_data_t user_data,
                                     bool latency_sensitive)
        = 0;

    /// @brief Modify route for an IPv6 prefix in a VRF object
    ///
    /// @param[in]  prefix              IPv6 prefix to perform routing for.
    /// @param[in]  destination         Destination to send traffic to.
    /// @param[in]  user_data           Opaque data associated with the route. Returned by the get-route function.

    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_ENOTFOUND No route exists for given prefix.
    /// @retval     LA_STATUS_EINVAL    Destination is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status modify_ipv6_route(la_ipv6_prefix_t prefix, const la_l3_destination* destination, la_user_data_t user_data)
        = 0;
    virtual la_status modify_ipv6_route(la_ipv6_prefix_t prefix, const la_l3_destination* destination) = 0;

    /// @brief Bulk programming of IPv6 routes to VRF.
    ///
    /// Preparation for route modification is done in order. Actual hardware update is performed in bulk.
    /// Count of number of successfully programmed routes is returned.
    /// If there is an error in programming routes, count of successful routes would be less than the requested routes to program.
    /// If route modification fails in the preparation step for a specific route, failure is returned for first failed route.
    /// All the route entries prior to the failed one are programmed to the hardware.
    /// If route modification fails in the subsequent step for bulk route programming, success is returned.
    /// All the route entries prior to the failed ones are still programmed to the hardware.
    ///
    /// @param[in]  route_entry_vec     IPv6 route entry vector to perform routing for.
    /// @param[out] out_count_success   Returns the number of successfully programmed routes.
    ///
    /// @retval     LA_STATUS_SUCCESS   All routes update performed successfully.
    /// @retval     LA_STATUS_EEXIST    Route already exists for this VRF.
    /// @retval     LA_STATUS_EINVAL    Destination is corrupt/invalid.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_ENOTFOUND No route exists for given prefix.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status ipv6_route_bulk_updates(la_ipv6_route_entry_parameters_vec route_entry_vec, size_t& out_count_success) = 0;

    /// @brief Retrieve IPv6 route from the VRF's route table.
    ///
    /// @param[in]  ip_addr             Address of route to retrieve.
    /// @param[out] out_ip_route_info    Returned routing information.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route was successfully found.
    /// @retval     LA_STATUS_ENOTFOUND No route exists for given prefix.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_route(la_ipv6_addr_t ip_addr, la_ip_route_info& out_ip_route_info) const = 0;

    /// @brief Retrieve IPv6 routing entry for the given prefix from VRF's FIB.
    ///
    /// @param[in]  prefix              Prefix to query.
    /// @param[out] out_ip_route_info    Returned routing information.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route successfully found.
    /// @retval     LA_STATUS_ENOTFOUND No route exists for given prefix.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_routing_entry(la_ipv6_prefix_t prefix, la_ip_route_info& out_ip_route_info) const = 0;

    /// @brief Return total count of IPv6 route entries.
    ///
    /// @param[out] out_count           #la_uint32_t count to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route successfully found.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_route_entries_count(la_uint32_t& out_count) const = 0;

    /// @brief Return a vector of all IPv6 route entries on the switch.
    ///
    /// @param[out] out_route_entries     #la_ipv6_route_entry_vec to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_route_entries(la_ipv6_route_entry_vec& out_route_entries) = 0;

    /// @brief Delete IPv6 multicast route.
    ///
    /// @param[in]  saddr               IPv6 source address. Use #LA_IPV6_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv6 multicast group address.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route deleted successfully.
    /// @retval     LA_STATUS_ENOTFOUND VRF's multicast FIB does not contain a route for saddr/gaddr.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status delete_ipv6_multicast_route(la_ipv6_addr_t saddr, la_ipv6_addr_t gaddr) = 0;

    /// @brief Delete all IPv6 multicast routes for specific VRF.
    ///
    ///
    /// @retval     LA_STATUS_SUCCESS   All routes deleted successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_all_ipv6_multicast_routes() = 0;

    /// @brief Add route for an IPv6 multicast address to VRF object.
    ///
    /// Incoming packets from specified source address and with specified destination IPv6 multicast address,
    /// will be sent to the given multicast group.
    ///
    /// Multicast punting is achieved using the snoop mechanism.
    /// Punt destination is set by configuring #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER and #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER,
    /// using #silicon_one::la_device::set_snoop_configuration.
    ///
    /// If a packet fails the RPF test, and punt_on_rpf_fail is enabled, it raises an additional event. If the l3 port is an
    /// #silicon_one::la_l3_ac_port, #LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL is raised. #LA_EVENT_L3_IP_MC_DROP is also raised.
    /// If the l3 port is an #silicon_one::la_svi_port, #LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL is raised.
    ///
    /// @note According to RFC3306 - Multicast group ID is defined by the lower 32 bits of the group address. Therefore,
    /// a route is defined by <saddr, gaddr's 32 LSbits>.
    ///
    /// @param[in]  saddr               IPv6 source address. Use #LA_IPV6_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv6 multicast group address.
    /// @param[in]  mcg                 Multicast group object to send traffic to.
    /// @param[in]  rpf                 Reverse Path Forwarding: valid ingress L3 port for multicast packets.
    /// @param[in]  punt_on_rpf_fail    Punt on RPF failure.
    /// @param[in]  punt_and_forward    Punt the packet.
    /// @param[in]  counter             Counter.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EINVAL    Either multicast group or port is corrupt/invalid.
    /// @retval     LA_STATUS_EEXIST    Route already exists for this VRF. See above comment about group-address.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                               la_ipv6_addr_t gaddr,
                                               la_ip_multicast_group* mcg,
                                               const la_l3_port* rpf,
                                               bool punt_on_rpf_fail,
                                               bool punt_and_forward,
                                               la_counter_set* counter)
        = 0;

    /// @brief Add route for an IPv6 multicast address to VRF object.
    ///
    /// Incoming packets from specified source address and with specified destination IPv6 multicast address,
    /// will be sent to the given multicast group.
    ///
    /// Multicast punting is achieved using the snoop mechanism.
    /// Punt destination is set by configuring #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER and #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER,
    /// using #silicon_one::la_device::set_snoop_configuration.
    ///
    /// If a packet fails the RPF test, and punt_on_rpf_fail is enabled, it raises an additional event. If the l3 port is an
    /// #silicon_one::la_l3_ac_port, #LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL is raised. #LA_EVENT_L3_IP_MC_DROP is also raised.
    /// If the l3 port is an #silicon_one::la_svi_port, #LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL is raised.
    ///
    /// @note According to RFC3306 - Multicast group ID is defined by the lower 32 bits of the group address. Therefore,
    /// a route is defined by <saddr, gaddr's 32 LSbits>.
    ///
    /// @param[in]  saddr               IPv6 source address. Use #LA_IPV6_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv6 multicast group address.
    /// @param[in]  mcg                 Multicast group object to send traffic to.
    /// @param[in]  rpf                 Reverse Path Forwarding: valid ingress L3 port for multicast packets.
    /// @param[in]  punt_on_rpf_fail    Punt on RPF failure.
    /// @param[in]  punt_and_forward    Punt the packet.
    /// @param[in]  enable_rpf_check    Enable/disable RPF check
    /// @param[in]  counter             Counter.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EINVAL    Either multicast group or port is corrupt/invalid.
    /// @retval     LA_STATUS_EEXIST    Route already exists for this VRF. See above comment about group-address.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                               la_ipv6_addr_t gaddr,
                                               la_ip_multicast_group* mcg,
                                               const la_l3_port* rpf,
                                               bool punt_on_rpf_fail,
                                               bool punt_and_forward,
                                               bool enable_rpf_check,
                                               la_counter_set* counter)
        = 0;

    /// @brief Add route for an IPv6 multicast address to VRF object.
    ///
    /// Incoming packets from specified source address and with specified destination IPv6 multicast address,
    /// will be sent to the given multicast group.
    ///
    /// Multicast punting is achieved using the snoop mechanism.
    /// Punt destination is set by configuring #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER and #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER,
    /// using #silicon_one::la_device::set_snoop_configuration.
    ///
    /// If a packet fails the RPF test, and punt_on_rpf_fail is enabled, it raises an additional event. If the l3 port is an
    /// #silicon_one::la_l3_ac_port, #LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL is raised. #LA_EVENT_L3_IP_MC_DROP is also raised.
    /// If the l3 port is an #silicon_one::la_svi_port, #LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL is raised.
    ///
    /// @note According to RFC3306 - Multicast group ID is defined by the lower 32 bits of the group address. Therefore,
    /// a route is defined by <saddr, gaddr's 32 LSbits>.
    ///
    /// @param[in]  saddr               IPv6 source address. Use #LA_IPV6_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv6 multicast group address.
    /// @param[in]  mcg                 Multicast group object to send traffic to.
    /// @param[in]  rpfid               Reverse Path Forwarding: User defined RPF ID used for MPLS tunnel termination
    /// @param[in]  punt_on_rpf_fail    Punt on RPF failure.
    /// @param[in]  punt_and_forward    Punt the packet.
    /// @param[in]  enable_rpf_check    Enable/disable RPF check
    /// @param[in]  counter             Counter.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EINVAL    Either multicast group or port is corrupt/invalid.
    /// @retval     LA_STATUS_EEXIST    Route already exists for this VRF. See above comment about group-address.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                               la_ipv6_addr_t gaddr,
                                               la_ip_multicast_group* mcg,
                                               la_uint_t rpfid,
                                               bool punt_on_rpf_fail,
                                               bool punt_and_forward,
                                               bool enable_rpf_check,
                                               la_counter_set* counter)
        = 0;

    /// @brief Modify an existing route for an IPv6 multicast address to VRF object.
    ///
    /// Incoming packets from specified source address and with specified destination IPv6 multicast address,
    /// will be sent to the given multicast group.
    ///
    /// Multicast punting is achieved using the snoop mechanism.
    /// Punt destination is set by configuring #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER and #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER,
    /// using #silicon_one::la_device::set_snoop_configuration.
    ///
    /// If a packet fails the RPF test, and punt_on_rpf_fail is enabled, it raises an additional event. If the l3 port is an
    /// #silicon_one::la_l3_ac_port, #LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL is raised. #LA_EVENT_L3_IP_MC_DROP is also raised.
    /// If the l3 port is an #silicon_one::la_svi_port, #LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL is raised.
    ///
    /// @param[in]  saddr               IPv6 source address. Use #LA_IPV6_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv6 multicast group address.
    /// @param[in]  mcg                 Multicast group object to send traffic to.
    /// @param[in]  rpf                 Reverse Path Forwarding: valid ingress L3 port for multicast packets.
    /// @param[in]  punt_on_rpf_fail    Punt on RPF failure.
    /// @param[in]  punt_and_forward    Punt the packet.
    /// @param[in]  counter             Counter.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EINVAL    Either multicast group or port is corrupt/invalid.
    /// @retval     LA_STATUS_ENOTFOUND Given route doesn't exist in the FIB.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status modify_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                                  la_ipv6_addr_t gaddr,
                                                  la_ip_multicast_group* mcg,
                                                  const la_l3_port* rpf,
                                                  bool punt_on_rpf_fail,
                                                  bool punt_and_forward,
                                                  la_counter_set* counter)
        = 0;

    /// @brief Modify an existing route for an IPv6 multicast address to VRF object.
    ///
    /// Incoming packets from specified source address and with specified destination IPv6 multicast address,
    /// will be sent to the given multicast group.
    ///
    /// Multicast punting is achieved using the snoop mechanism.
    /// Punt destination is set by configuring #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER and #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER,
    /// using #silicon_one::la_device::set_snoop_configuration.
    ///
    /// If a packet fails the RPF test, and punt_on_rpf_fail is enabled, it raises an additional event. If the l3 port is an
    /// #silicon_one::la_l3_ac_port, #LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL is raised. #LA_EVENT_L3_IP_MC_DROP is also raised.
    /// If the l3 port is an #silicon_one::la_svi_port, #LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL is raised.
    ///
    /// @param[in]  saddr               IPv6 source address. Use #LA_IPV6_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv6 multicast group address.
    /// @param[in]  mcg                 Multicast group object to send traffic to.
    /// @param[in]  rpf                 Reverse Path Forwarding: valid ingress L3 port for multicast packets.
    /// @param[in]  punt_on_rpf_fail    Punt on RPF failure.
    /// @param[in]  punt_and_forward    Punt the packet.
    /// @param[in]  enable_rpf_check    Enable/disable RPF check
    /// @param[in]  counter             Counter.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EINVAL    Either multicast group or port is corrupt/invalid.
    /// @retval     LA_STATUS_ENOTFOUND Given route doesn't exist in the FIB.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status modify_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                                  la_ipv6_addr_t gaddr,
                                                  la_ip_multicast_group* mcg,
                                                  const la_l3_port* rpf,
                                                  bool punt_on_rpf_fail,
                                                  bool punt_and_forward,
                                                  bool enable_rpf_check,
                                                  la_counter_set* counter)
        = 0;

    /// @brief Modify an existing route for an IPv6 multicast address to VRF object.
    ///
    /// Incoming packets from specified source address and with specified destination IPv6 multicast address,
    /// will be sent to the given multicast group.
    ///
    /// Multicast punting is achieved using the snoop mechanism.
    /// Punt destination is set by configuring #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER and #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER,
    /// using #silicon_one::la_device::set_snoop_configuration.
    ///
    /// If a packet fails the RPF test, and punt_on_rpf_fail is enabled, it raises an additional event. If the l3 port is an
    /// #silicon_one::la_l3_ac_port, #LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL is raised. #LA_EVENT_L3_IP_MC_DROP is also raised.
    /// If the l3 port is an #silicon_one::la_svi_port, #LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL is raised.
    ///
    /// @param[in]  saddr               IPv6 source address. Use #LA_IPV6_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv6 multicast group address.
    /// @param[in]  mcg                 Multicast group object to send traffic to.
    /// @param[in]  rpfid               Reverse Path Forwarding: User defined RPF ID used for MPLS tunnel termination
    /// @param[in]  punt_on_rpf_fail    Punt on RPF failure.
    /// @param[in]  punt_and_forward    Punt the packet.
    /// @param[in]  enable_rpf_check    Enable/disable RPF check
    /// @param[in]  counter             Counter.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route added successfully.
    /// @retval     LA_STATUS_EINVAL    Either multicast group or port is corrupt/invalid.
    /// @retval     LA_STATUS_ENOTFOUND Given route doesn't exist in the FIB.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this route.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status modify_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                                  la_ipv6_addr_t gaddr,
                                                  la_ip_multicast_group* mcg,
                                                  la_uint_t rpfid,
                                                  bool punt_on_rpf_fail,
                                                  bool punt_and_forward,
                                                  bool enable_rpf_check,
                                                  la_counter_set* counter)
        = 0;

    /// @brief Retrieve IP multicast group for specific IPv6 multicast route from VRF's table.
    ///
    /// @param[in]  saddr               IPv6 source address. Use #LA_IPV6_ANY_IP for any source IP.
    /// @param[in]  gaddr               IPv6 multicast group address.
    /// @param[out] out_ip_mc_route_info    Returned routing information.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND VRF's multicast FIB does not contain a route for saddr/gaddr.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                               la_ipv6_addr_t gaddr,
                                               la_ip_mc_route_info& out_ip_mc_route_info) const = 0;

    /// @brief Set unmatched IPv4 multicast punt.
    ///
    /// A multicast packet that doesn't match any routes configured in #silicon_one::la_vrf::add_ipv4_multicast_route raises an
    /// event.
    /// This API configures the event such packet should raise. The match-configuration is in IP prefixes of multicast-group
    /// addresses, where the match-criteria is LPM-based.
    /// If enabled, #LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL is raised for #silicon_one::la_l3_ac_port, and
    /// #LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL for
    /// #silicon_one::la_svi_port. Otherwise, #LA_EVENT_L3_IP_MULTICAST_NOT_FOUND is raised for #silicon_one::la_l3_ac_port and
    /// #LA_EVENT_L3_IP_MC_SNOOP_LOOKUP_MISS for #silicon_one::la_svi_port.
    /// If a packet doesn't match any prefix, the default event is #LA_EVENT_L3_IP_MULTICAST_NOT_FOUND for
    /// #silicon_one::la_l3_ac_port,
    /// and #LA_EVENT_L3_IP_MC_SNOOP_LOOKUP_MISS for #silicon_one::la_svi_port.
    ///
    /// @param[in]  group_prefix        IPv4 multicast group prefix.
    /// @param[in]  punt_enabled        True if punt event is to be raised, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Either group prefix or event are invalid.
    /// @retval     LA_STATUS_ERESOURCE There are no resources to add this prefix.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occured.
    virtual la_status set_unmatched_ipv4_multicast_punt_enabled(la_ipv4_prefix_t group_prefix, bool punt_enabled) = 0;

    /// @brief Get unmatched IPv4 multicast punt.
    ///
    /// @param[in]  group_prefix           IPv4 multicast group prefix.
    /// @param[out] out_punt_enabled       True if punt event is to be raised, false otherwise,
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Prefix not found.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occured.
    virtual la_status get_unmatched_ipv4_multicast_punt_enabled(la_ipv4_prefix_t group_prefix, bool& out_punt_enabled) const = 0;

    /// @brief Clear unmatched IPv4 multicast punt.
    ///
    /// @param[in]  group_prefix         IPv4 multicast group prefix.
    ///
    /// @retval     LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval     LA_STATUS_ENOUTFOUND Prefix not found.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occured.
    virtual la_status clear_unmatched_ipv4_multicast_punt_enabled(la_ipv4_prefix_t group_prefix) = 0;

    /// @brief Set unmatched IPv6 multicast punt.
    ///
    /// A multicast packet that doesn't match any routes configured in #silicon_one::la_vrf::add_ipv6_multicast_route raises an
    /// event.
    /// This API configures the event such packet should raise. The match-configuration is in IP prefixes of multicast-group
    /// addresses, where the match-criteria is LPM-based.
    /// If enabled, #LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL is raised for #silicon_one::la_l3_ac_port, and
    /// #LA_EVENT_L3_IP_MC_SNOOP_RPF_FAIL for
    /// #silicon_one::la_svi_port. Otherwise, #LA_EVENT_L3_IP_MULTICAST_NOT_FOUND is raised for #silicon_one::la_l3_ac_port and
    /// #LA_EVENT_L3_IP_MC_SNOOP_LOOKUP_MISS for #silicon_one::la_svi_port.
    /// If a packet doesn't match any prefix, the default event is #LA_EVENT_L3_IP_MULTICAST_NOT_FOUND for
    /// #silicon_one::la_l3_ac_port,
    /// and #LA_EVENT_L3_IP_MC_SNOOP_LOOKUP_MISS for #silicon_one::la_svi_port.
    ///
    /// @param[in]  group_prefix        IPv6 multicast group prefix.
    /// @param[in]  punt_enabled        True if punt event is to be raised, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Either group prefix or trap are invalid.
    /// @retval     LA_STATUS_ERESOURCE There are no resources to add this prefix.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occured.
    virtual la_status set_unmatched_ipv6_multicast_punt_enabled(la_ipv6_prefix_t group_prefix, bool punt_enabled) = 0;

    /// @brief Get unmatched IPv6 multicast punt.
    ///
    /// @param[in]  group_prefix           IPv6 multicast group prefix.
    /// @param[out] out_punt_enabled       True if punt event is to be raised, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Prefix not found.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occured.
    virtual la_status get_unmatched_ipv6_multicast_punt_enabled(la_ipv6_prefix_t group_prefix, bool& out_punt_enabled) const = 0;

    /// @brief Clear unmatched IPv6 multicast punt.
    ///
    /// @param[in]  group_prefix         IPv6 multicast group prefix.
    ///
    /// @retval     LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval     LA_STATUS_ENOUTFOUND Prefix not found.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occured.
    virtual la_status clear_unmatched_ipv6_multicast_punt_enabled(la_ipv6_prefix_t group_prefix) = 0;

    /// @brief Retrieve the VRF's IPv4 PBR (Policy Based Routing) ACL.
    ///
    /// @param[out] out_ipv4_pbr_acl    IPv4 PBR ACL.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv4_pbr_acl(la_acl*& out_ipv4_pbr_acl) = 0;

    /// @brief Retrieve the VRF's IPv6 PBR (Policy Based Routing) ACL.
    ///
    /// @param[out] out_ipv6_pbr_acl    IPv6 PBR ACL.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_pbr_acl(la_acl*& out_ipv6_pbr_acl) = 0;

    /// @brief Add a prefix to Security Group Tag (SGT) mapping with IPv4 prefix.
    ///
    /// @param[in]  prefix                     IPv4 prefix.
    /// @param[in]  sgt                        SGT.
    ///
    /// @retval     LA_STATUS_SUCCESS          Prefix added successfully.
    /// @retval     LA_STATUS_EEXIST           Prefix already exists.
    /// @retval     LA_STATUS_ERESOURCE        FIB has no resources to add this host.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status add_security_group_tag(la_ipv4_prefix_t prefix, la_sgt_t sgt) = 0;

    /// @brief Modify a prefix to Security Group Tag (SGT) mapping with IPv4 prefix .
    ///
    /// @param[in]  prefix                     IPv4 prefix.
    /// @param[in]  sgt                        SGT.
    ///
    /// @retval     LA_STATUS_SUCCESS          Prefix modified successfully.
    /// @retval     LA_STATUS_ENOUTFOUND       Prefix is not found.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status modify_security_group_tag(la_ipv4_prefix_t prefix, la_sgt_t sgt) = 0;

    /// @brief Delete a prefix to Security Group Tag (SGT) mapping with IPV4 prefix.
    ///
    /// @param[in]  prefix                     IPv4 prefix.
    ///
    /// @retval     LA_STATUS_SUCCESS          Prefix deleted successfully.
    /// @retval     LA_STATUS_ENOUTFOUND       Prefix is not found.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status delete_security_group_tag(la_ipv4_prefix_t prefix) = 0;

    /// @brief Get a prefix to Security Group Tag (SGT) mapping with IPv4 prefix.
    ///
    /// @param[in]   prefix                    IPv4 prefix.
    /// @param[out]  out_sgt                   Configured SGT.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation successfull.
    /// @retval     LA_STATUS_ENOUTFOUND       Prefix is not found.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_security_group_tag(la_ipv4_prefix_t prefix, la_sgt_t& out_sgt) const = 0;

    /// @brief Add a prefix to Security Group Tag (SGT) mapping with IPv6 prefix.
    ///
    /// @param[in]  prefix                     IPv6 prefix.
    /// @param[in]  sgt                        SGT.
    ///
    /// @retval     LA_STATUS_SUCCESS          Prefix added successfully.
    /// @retval     LA_STATUS_EEXIST           Prefix already exists in this port.
    /// @retval     LA_STATUS_ERESOURCE        FIB has no resources to add this host.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status add_security_group_tag(la_ipv6_prefix_t prefix, la_sgt_t sgt) = 0;

    /// @brief Modify a prefix to Security Group Tag (SGT) mapping with IPv6 prefix .
    ///
    /// @param[in]  prefix                     IPv6 prefix.
    /// @param[in]  sgt                        SGT.
    ///
    /// @retval     LA_STATUS_SUCCESS          Prefix modified successfully.
    /// @retval     LA_STATUS_ENOUTFOUND       Prefix is not found.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status modify_security_group_tag(la_ipv6_prefix_t prefix, la_sgt_t sgt) = 0;

    /// @brief Delete a prefix to Security Group Tag (SGT) mapping with IPv6 prefix.
    ///
    /// @param[in]  prefix                     IPv6 prefix.
    ///
    /// @retval     LA_STATUS_SUCCESS          Prefix deleted successfully.
    /// @retval     LA_STATUS_ENOUTFOUND       Prefix is not found.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status delete_security_group_tag(la_ipv6_prefix_t prefix) = 0;

    /// @brief Get a prefix to Security Group Tag (SGT) mapping with IPv6 address.
    ///
    /// @param[in]   prefix                    IPv6 prefix.
    /// @param[out]  out_sgt                   Configured SGT.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation successfull.
    /// @retval     LA_STATUS_ENOUTFOUND       Prefix is not found.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED  Not implemented for this device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_security_group_tag(la_ipv6_prefix_t prefix, la_sgt_t& out_sgt) const = 0;

    /// @brief Enable allow-default for uRPF.
    ///  param[in]  enable             Enable allow-default mode in uRPF.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mode set successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_urpf_allow_default(bool enable) = 0;

    /// @brief Determine allow-default mode for uRPF.
    ///
    /// @return     True if uRPF allows default route, false otherwise.
    virtual bool get_urpf_allow_default() const = 0;

protected:
    ~la_vrf() override = default;
};
}

/// @}

#endif // __LA_VRF_H__
