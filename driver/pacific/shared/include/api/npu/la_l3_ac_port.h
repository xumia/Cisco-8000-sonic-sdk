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

#ifndef __LA_L3_AC_PORT_H__
#define __LA_L3_AC_PORT_H__

#include "api/npu/la_l3_port.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_tm_types.h"

namespace silicon_one
{

/// @file
/// @brief Leaba L3 Attachment Circuit Port API-s.
///
/// Defines API-s for managing L3 Attachment Circuit port object.

class la_l3_ac_port : public la_l3_port
{

public:
    /// @addtogroup L3PORT_AC
    /// @{

    /// @brief Set the MAC associated with the port.
    ///
    /// @param[out] mac_addr    MAC to be associated with the port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_mac(const la_mac_addr_t& mac_addr) = 0;

    /// @brief Retrieve the MAC associated with the port.
    ///
    /// @param[out] out_mac_addr    MAC associated with the port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_mac_addr contains port's MAC address.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac(la_mac_addr_t& out_mac_addr) const = 0;

    /// @brief Configure egress VLAN tag for packets on the given
    /// port.  API supports double VLAN tags configuration
    /// Default is LA_VLAN_TAG_UNTAGGED which means VLAN tag won't be added to the packet.
    ///
    /// @param[in]  tag1                Egress VLAN outer tag.
    ///                                 If #LA_VLAN_TAG_UNTAGGED is used, no VLAN tag will be added.
    /// @param[in]  tag2                Egress VLAN inner tag.
    ///                                 If #LA_VLAN_TAG_UNTAGGED is used, no inner VLAN tag will be added.
    ///
    /// @retval     LA_STATUS_SUCCESS   Port's egress VLAN tag changed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_egress_vlan_tag(la_vlan_tag_t tag1, la_vlan_tag_t tag2) = 0;

    /// @brief Get the Configured egress VLAN tag for packets. API
    /// supports double VLAN tag.
    ///
    /// @param[out] out_tag1                Egress outer VLAN tag to populat
    /// @param[out] out_tag2                Egress inner VLAN tag to populat
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully. out_tag1 and out_tag2 contains port's egress VLAN tag.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_egress_vlan_tag(la_vlan_tag_t& out_tag1, la_vlan_tag_t& out_tag2) const = 0;

    /// @brief Return the ethernet port object that this port is attached to.
    ///
    /// @retval    The ethernet port object.
    virtual const la_ethernet_port* get_ethernet_port() const = 0;

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

    /// @brief Return the VRF object that this port is attached to.
    ///
    /// @retval    The VRF associated with this la_l3_ac_port.
    virtual const la_vrf* get_vrf() const = 0;

    /// @brief Set the VRF that this port is attached to.
    ///
    /// @param[in]  vrf               VRF to attach this port to.
    ///
    /// @retval    LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval    LA_STATUS_EINVAL           Invalid VRF specified.
    /// @retval    LA_STATUS_EBUSY            L3 port has subnets associated with it.
    /// @retval    LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_vrf(const la_vrf* vrf) = 0;

    /// @brief Attach an IPv4 subnet to the port.
    ///
    /// @param[in]  subnet              Subnet to attach.
    ///
    /// @retval     LA_STATUS_SUCCESS   Subnet added successfully.
    /// @retval     LA_STATUS_EEXIST    Subnet already exists.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this subnet.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv4_subnet(la_ipv4_prefix_t subnet) = 0;

    /// @brief Remove a subnet from the port.
    ///
    /// @param[in]  subnet              Subnet to remove.
    ///
    /// @retval     LA_STATUS_SUCCESS   Subnet removed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Subnet not found in the port.
    /// @retval     LA_STATUS_EBUSY     There are directly-attached hosts in this subnet.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status delete_ipv4_subnet(la_ipv4_prefix_t subnet) = 0;

    /// @brief Get the list of attached IPv4 subnets.
    ///
    /// @param[out] out_subnets         Subnets vector to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Subnets were read successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv4_subnets(la_ipv4_prefix_vec_t& out_subnets) const = 0;

    /// @brief Add a directly-attached host with IPV4 address.
    ///
    /// @param[in]  ip_addr             IP address of the host.
    /// @param[in]  mac_addr            MAC address of the host.
    ///
    /// @retval     LA_STATUS_SUCCESS   Host added successfully.
    /// @retval     LA_STATUS_EINVAL    Host is not part of an attached subnet.
    /// @retval     LA_STATUS_EEXIST    Host already exists in this port.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this host.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr) = 0;

    /// @brief Modify MAC of a directly-attached IPv4 host.
    ///
    /// @param[in]  ip_addr              IP address of the host to modify.
    /// @param[in]  mac_addr             MAC address to assign.
    ///
    /// @retval     LA_STATUS_SUCCESS    Host modified successfully.
    /// @retval     LA_STATUS_ENOTFOUND  No directly-attached IPv4 host matching this address.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occurred.
    virtual la_status modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr) = 0;

    /// @brief Add a directly-attached host with IPV4 address and an associated Class Identifier.
    ///
    /// @param[in]  ip_addr             IP address of the host.
    /// @param[in]  mac_addr            MAC address of the host.
    /// @param[in]  class_id            Class identifier associated with the host.
    ///
    /// @retval     LA_STATUS_SUCCESS   Host added successfully.
    /// @retval     LA_STATUS_EINVAL    Host is not part of an attached subnet.
    /// @retval     LA_STATUS_EEXIST    Host already exists in this port.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this host.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) = 0;

    /// @brief Modify MAC of a directly-attached IPv4 host with an associated Class Identifier.
    ///
    /// @param[in]  ip_addr              IP address of the host to modify.
    /// @param[in]  mac_addr             MAC address to assign.
    /// @param[in]  class_id            Class identifier associated with the host.
    ///
    /// @retval     LA_STATUS_SUCCESS    Host modified successfully.
    /// @retval     LA_STATUS_ENOTFOUND  No directly-attached IPv4 host matching this address.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occurred.
    virtual la_status modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) = 0;

    /// @brief Remove a directly-attached host from the port.
    ///
    /// @param[in]  ip_addr             Host to be deleted.
    ///
    /// @retval     LA_STATUS_SUCCESS   Host deleted successfully.
    /// @retval     LA_STATUS_ENOTFOUND Host is not connected to this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status delete_ipv4_host(la_ipv4_addr_t ip_addr) = 0;

    /// @brief Get MAC address attached to a given IP address.
    ///
    /// @param[in]  ip_addr             IP address of the host.
    /// @param[out] out_mac_addr        MAC address to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Host MAC address retrieved successfully.
    /// @retval     LA_STATUS_ENOTFOUND IP address is not connected to this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t& out_mac_addr) const = 0;

    /// @brief Get MAC address and class id attached to a given IP address.
    ///
    /// @param[in]  ip_addr             IP address of the host.
    /// @param[out] out_mac_addr        MAC address to populate.
    /// @param[out] out_class_id        Class identifier associated with the host.
    ///
    /// @retval     LA_STATUS_SUCCESS   Host MAC address retrieved successfully.
    /// @retval     LA_STATUS_ENOTFOUND IP address is not connected to this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv4_host_and_class_id(la_ipv4_addr_t ip_addr,
                                                 la_mac_addr_t& out_mac_addr,
                                                 la_class_id_t& out_class_id) const = 0;

    /// @brief Get all IPV4 protocol MAC addresses attached to the port.
    ///
    /// @param[out] out_mac_addresses   MAC addresses vector to populate.
    ///
    /// @retval     LA_STATUS_ENOTFOUND Host is not connected to this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv4_hosts(la_mac_addr_vec& out_mac_addresses) const = 0;

    /// @brief Get all IPV4 protocol ip addresses attached to the port.
    ///
    /// @param[out] out_ip_addresses   ipv4  addresses vector to populate.
    ///
    /// @retval     LA_STATUS_ENOTFOUND Host is not connected to this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv4_hosts(la_ipv4_addr_vec& out_ip_addresses) const = 0;

    /// @brief Attach an IPv6 subnet to the port.
    ///
    /// @param[in]  subnet              Subnet to attach.
    ///
    /// @retval     LA_STATUS_SUCCESS   Subnet added successfully.
    /// @retval     LA_STATUS_EEXIST    Subnet already exists.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this subnet.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv6_subnet(la_ipv6_prefix_t subnet) = 0;

    /// @brief Remove a subnet from the port.
    ///
    /// @param[in]  subnet              Subnet to remove.
    ///
    /// @retval     LA_STATUS_SUCCESS   Subnet removed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Subnet not found in the port.
    /// @retval     LA_STATUS_EBUSY     There are directly-attached hosts in this subnet.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status delete_ipv6_subnet(la_ipv6_prefix_t subnet) = 0;

    /// @brief Get the list of attached IPv6 subnets.
    ///
    /// @param[out] out_subnets         Subnets vector to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Subnets were read successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_subnets(la_ipv6_prefix_vec_t& out_subnets) const = 0;

    /// @brief Add a directly-attached host with IPv6 address.
    ///
    /// @param[in]  ip_addr             IP address of the host.
    /// @param[in]  mac_addr            MAC address of the host.
    ///
    /// @retval     LA_STATUS_SUCCESS   Host added successfully.
    /// @retval     LA_STATUS_EINVAL    Host is not part of an attached subnet.
    /// @retval     LA_STATUS_EEXIST    Host already exists in this port.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this host.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr) = 0;

    /// @brief Modify MAC of a directly-attached IPv6 host.
    ///
    /// @param[in]  ip_addr              IP address of the host to modify.
    /// @param[in]  mac_addr             New MAC address of the host.
    ///
    /// @retval     LA_STATUS_SUCCESS    Host modified successfully.
    /// @retval     LA_STATUS_ENOTFOUND  No directly-attached IPv6 host matching this address.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occurred.
    virtual la_status modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr) = 0;

    /// @brief Add a directly-attached host with IPv6 address and an associated Class Identifier.
    ///
    /// @param[in]  ip_addr             IP address of the host.
    /// @param[in]  mac_addr            MAC address of the host.
    /// @param[in]  class_id            Class identifier associated with the host.
    ///
    /// @retval     LA_STATUS_SUCCESS   Host added successfully.
    /// @retval     LA_STATUS_EINVAL    Host is not part of an attached subnet.
    /// @retval     LA_STATUS_EEXIST    Host already exists in this port.
    /// @retval     LA_STATUS_ERESOURCE FIB has no resources to add this host.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) = 0;

    /// @brief Modify MAC of a directly-attached IPv6 host with an associated Class Identifier.
    ///
    /// @param[in]  ip_addr              IP address of the host to modify.
    /// @param[in]  mac_addr             New MAC address of the host.
    /// @param[in]  class_id            Class identifier associated with the host.
    ///
    /// @retval     LA_STATUS_SUCCESS    Host modified successfully.
    /// @retval     LA_STATUS_ENOTFOUND  No directly-attached IPv6 host matching this address.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occurred.
    virtual la_status modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) = 0;

    /// @brief Remove a directly-attached host from the port.
    ///
    /// @param[in]  ip_addr             Host to be deleted.
    ///
    /// @retval     LA_STATUS_SUCCESS   Host deleted successfully.
    /// @retval     LA_STATUS_ENOTFOUND Host is not connected to this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status delete_ipv6_host(la_ipv6_addr_t ip_addr) = 0;

    /// @brief Get MAC address attached to a given IP address.
    ///
    /// @param[in]  ip_addr             IP address of the host.
    /// @param[out] out_mac_addr        MAC address to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Host MAC address retrieved successfully.
    /// @retval     LA_STATUS_ENOTFOUND IP address is not connected to this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t& out_mac_addr) const = 0;

    /// @brief Get MAC address and class id attached to a given IP address.
    ///
    /// @param[in]  ip_addr             IP address of the host.
    /// @param[out] out_mac_addr        MAC address to populate.
    /// @param[out] out_class_id        Class identifier associated with the host.
    ///
    /// @retval     LA_STATUS_SUCCESS   Host MAC address retrieved successfully.
    /// @retval     LA_STATUS_ENOTFOUND IP address is not connected to this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_host_and_class_id(la_ipv6_addr_t ip_addr,
                                                 la_mac_addr_t& out_mac_addr,
                                                 la_class_id_t& out_class_id) const = 0;

    /// @brief Get all IPV6 protocol MAC addresses attached to the port.
    ///
    /// @param[out] out_mac_addresses   MAC addresses vector to populate.
    ///
    /// @retval     LA_STATUS_ENOTFOUND Host is not connected to this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_hosts(la_mac_addr_vec& out_mac_addresses) const = 0;

    /// @brief Get all IPV6 protocol ip addresses attached to the port.
    ///
    /// @param[out] out_ip_addresses   ipv6  addresses vector to populate.
    ///
    /// @retval     LA_STATUS_ENOTFOUND Host is not connected to this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_hosts(la_ipv6_addr_vec& out_ip_addresses) const = 0;

    /// @brief Attach a VOQ set to the port.
    ///
    /// @param[in]  system_port         Destination system port.
    /// @param[in]  voq_set             Set of VOQs for (Port, TC)->VOQ mapping.
    ///
    /// @retval     LA_STATUS_EINVAL    nullptr argument provided or the VOQ set has different
    ///                                 device/slice/ifg than the system port.
    /// @retval     LA_STATUS_ERESOURCE There are no resources to attach this VOQ set.
    /// @retval     LA_STATUS_EBUSY     VOQ set is already in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// For non-aggregate, system_port should be #get_ethernet_port()->get_system_port().
    /// For aggregate, system_port should be one of of #get_ethernet_port()->get_spa_port()->get_members().
    virtual la_status set_system_port_voq_set(const la_system_port* system_port, la_voq_set* voq_set) = 0;

    /// @brief Clear a VOQ set attachment for this port
    ///
    /// @param[in]  system_port         System port associated with this voq set.
    ///
    /// @retval     LA_STATUS_EINVAL    nullptr argument provided.
    /// @retval     LA_STATUS_ENOTFOUND VOQ set is not attached for this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_system_port_voq_set(const la_system_port* system_port) = 0;

    /// @brief Get a VOQ set attached to this port
    ///
    /// @param[in]  system_port         Destination system port
    /// @param[out] out_voq_set         Pointer to #silicon_one::la_system_port to populate
    ///
    /// @retval     LA_STATUS_EINVAL    nullptr argument provided.
    /// @retval     LA_STATUS_ENOTFOUND No VOQ set exists for the destination system port
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_system_port_voq_set(const la_system_port* system_port, la_voq_set*& out_voq_set) const = 0;

    /// @brief Enable/Disable logical port queueing for remote AC
    ///
    /// @param[in]  system_port         Destination system port
    /// @param[in]  enabled             true if logical port queueing should be enabled; false otherwise.
    ///
    /// @retval      LA_STATUS_EINVAL   system_port is null, system_port is not a valid member of ethernet port, device is not
    /// configured to operate in svl mode, system_port is not remote.
    /// @retval      LA_STATUS_SUCCESS  Operation completed successfully.
    virtual la_status set_stack_remote_logical_port_queueing_enabled(const la_system_port* system_port, bool enabled) = 0;

    /// @brief Get all VOQ sets attached to the port.
    ///
    /// @param[out] out_voq_sets        Vector of #la_sysport_voq to populate.
    ///
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_voq_sets(la_sysport_voq_vec_t& out_voq_sets) const = 0;

    /// @brief Set traffic class mapping profile for logical port queuing.
    ///
    /// @param[in] tc_profile           Profile for (Port, TC)->VOQ mapping for flows.
    ///
    /// @retval     LA_STATUS_EINVAL    nullptr argument provided.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_tc_profile(la_tc_profile* tc_profile) = 0;

    /// @brief Get traffic class mapping profile for logical port queuing.
    ///
    /// @param[out] out_tc_profile      Pointer to #silicon_one::la_tc_profile to populate.
    ///
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_tc_profile(const la_tc_profile*& out_tc_profile) const = 0;

    /// @brief Remove service mapping entry for the underlying AC Common port and clear
    /// ethernet (Port, VLAN, VLAN) mapping.
    ///
    /// The object becomes invalid if the call is successful, and should not be used from that point on.
    ///
    /// @retval     LA_STATUS_SUCCESS   Object has been destroyed successfully.
    /// @retval     LA_STATUS_EINVAL    Object is corrupt or invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status disable() = 0;

    /// @brief Query MLDP BUD node termination for the port.
    ///
    /// @param[out] out_enabled         Pointer to bool to be populated with true if BUD node termination  enabled; false otherwise.
    ///
    /// @return status.
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mldp_bud_terminate_enabled(bool& out_enabled) const = 0;

    /// @brief Enable/Disable MLDP BUD node termination for the port.
    ///
    /// Default is disabled.
    ///
    /// @param[in]  enabled             true if BUD Node termination should be enabled; false otherwise.
    ///
    /// @return status.
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_mldp_bud_terminate_enabled(bool enabled) = 0;

protected:
    ~la_l3_ac_port() override = default;
    /// @}
};

} // namepace leaba

#endif // __LA_L3_AC_PORT_H__
