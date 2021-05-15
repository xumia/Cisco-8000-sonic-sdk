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

#ifndef __LA_SVI_PORT_H__
#define __LA_SVI_PORT_H__

#include "api/npu/la_l3_port.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"

/// @file
/// @brief Leaba SVI Port API-s.
///
/// Defines API-s for managing Switch VLAN Interface port [#silicon_one::la_svi_port] object.

namespace silicon_one
{

/// @addtogroup L3PORT_SVI
/// @{
///

class la_svi_port : public la_l3_port
{

public:
    /// @brief Set the MAC associated with the port.
    ///
    /// @param[in] mac_addr    MAC to be associated with the port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_mac(const la_mac_addr_t& mac_addr) = 0;

    /// @brief Retrieve the MAC associated with the port.
    ///
    /// @param[out] out_mac_addr        MAC to associated with port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_mac_addr contains port's MAC address.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac(la_mac_addr_t& out_mac_addr) const = 0;

    /// @brief Configure egress VLAN tag for packets on the given
    /// port.  API supports double VLAN tags configuration.
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

    /// @brief Get the Configured egress VLAN tag for packets on the givn
    /// port.  API supports double VLAN tags configuration.
    ///
    /// @param[out] out_tag1                Egress outter VLAN tag to populate
    /// @param[out] out_tag2                Egress inner VLAN tag to populate
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully. out_tag1 and out_tag2 contains port's egress VLAN tag.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_egress_vlan_tag(la_vlan_tag_t& out_tag1, la_vlan_tag_t& out_tag2) const = 0;

    /// @brief Return the switch object that this port is attached to
    ///
    /// @param[out] out_switch                  The switch object to populate.
    ///
    /// @retval    LA_STATUS_SUCCESS            Opertion completed successfuly
    /// @retval    LA_STATUS_ENOTINITIALIZED    This object is not initialized yet
    /// @retval    LA_STATUS_EUNKNOWN           An unknown error occurred.
    virtual la_status get_switch(const la_switch*& out_switch) const = 0;

    /// @brief Return the VRF object that this port is attached to
    ///
    /// @param[out] out_vrf                     The VRF object to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Opertion completed successfuly
    /// @retval     LA_STATUS_ENOTINITIALIZED   This object is not initialized yet
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_vrf(const la_vrf*& out_vrf) const = 0;

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
    /// @param[in]  mac_addr             New MAC address of the host.
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

    /// @brief Get MAC address attached to a given IP address.
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
    /// @param[out] out_ip_addresses   ip addresses vector to populate.
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

    /// @brief Get MAC address attached to a given IP address.
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

    /// @brief Get all IPV6 protocol IP addresses attached to the port.
    ///
    /// @param[out] out_ip_addresses  IP addresses vector to populate.
    ///
    /// @retval     LA_STATUS_ENOTFOUND Host is not connected to this port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_hosts(la_ipv6_addr_vec& out_ip_addresses) const = 0;

    /// @brief Get inject-up source port for this svi/switch.
    /// This port is used for SVI egress flooding.
    ///
    /// @param[out]  out_inject_up_source_port  L2 AC Service Port used for inject up
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    inject-up port not set for this svi/switch
    virtual la_status get_inject_up_source_port(la_l2_service_port*& out_inject_up_source_port) const = 0;

    /// @brief Set inject-up source port for this svi/switch.
    /// This port is used for SVI egress flooding.
    ///
    /// @param[in]  inject_up_source_port   L2 AC Service Port used for inject up
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EEXIST    inject-up port already set for this switch
    /// @retval     LA_STATUS_EINVAL    inject-up port's underlying system port is different or
    ///                                 inject-up port's service mapping vlans are invalid or
    ///                                 inject-up port and svi are not attached to same switch
    virtual la_status set_inject_up_source_port(la_l2_service_port* inject_up_source_port) = 0;

    /// @brief Set the VRF that this port is attached to.
    ///
    /// @param[in]  vrf               VRF to attach this port to.
    ///
    /// @retval    LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval    LA_STATUS_EINVAL           Invalid VRF specified.
    /// @retval    LA_STATUS_EBUSY            L3 port has subnets associated with it.
    /// @retval    LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_vrf(const la_vrf* vrf) = 0;

    /// @brief Enable/Disable DHCP snooping at egress.
    ///
    /// @param[in] enabled      True if DHCP snooping should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_egress_dhcp_snooping_enabled(bool enabled) = 0;

    /// @brief Return DHCP snooping status at egress.
    ///
    /// @param[out] out_enabled      True if DHCP snooping is enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_egress_dhcp_snooping_enabled(bool& out_enabled) const = 0;

protected:
    ~la_svi_port() override = default;
};

/// @}
}

#endif // __LA_SVI_PORT_H__
