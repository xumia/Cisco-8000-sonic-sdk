// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

extern "C" {
#include <sai.h>
}

#include <../../build/src/auto_gen_attr.h>
#include "common/gen_utils.h"
#include "nsim_provider/nsim_test_flow.h"
#include "nsim/nsim.h"
#include "user_space_kernel.h"
#include "sai_test_utils.h"
#include "gtest/gtest.h"
#include <algorithm>
#include <iterator>
#include <numeric>
#include <thread>
#include <vector>

using namespace std;
using namespace silicon_one;

class SimRouteV6Test : public ::testing::Test
{
public:
    nsim_provider* sim_ifc;
    user_space_kernel* m_kernel;
    sai_switch_api_t* switch_api = nullptr;
    sai_port_api_t* port_api = nullptr;
    sai_bridge_api_t* bridge_api = nullptr;

    sai_vlan_api_t* vlan_api = nullptr;
    sai_router_interface_api_t* rif_api = nullptr;
    sai_next_hop_api_t* nexthop_api = nullptr;
    sai_next_hop_group_api_t* nexthop_group_api = nullptr;
    sai_virtual_router_api_t* vrf_api = nullptr;
    sai_fdb_api_t* fdb_api = nullptr;
    sai_neighbor_api_t* neighbor_api = nullptr;
    sai_route_api_t* route_api = nullptr;
    sai_hostif_api_t* hostif_api = nullptr;

    vector<sai_object_id_t> ports;

    sai_object_id_t switch_id{};
    sai_object_id_t m_bridge_id;
    sai_object_id_t m_bridge_port_id;
    sai_object_id_t m_bridge_port_id2;
    sai_object_id_t m_default_vrf_id{};
    // sai_object_id_t m_svi_id{};
    sai_object_id_t m_rif_id_1;
    sai_object_id_t m_rif_id_2;
    sai_object_id_t m_svi_rif_id;
    sai_object_id_t m_svi_port_id;
    sai_object_id_t m_svi_router_rif;

    sai_object_id_t nh45_group;
    sai_object_id_t nh_id1, nh_id2, nh_id3;
    sai_object_id_t nh_id4, nh_id5;
    sai_object_id_t nh_svi_router;
    sai_object_id_t nh_group_mem_id4;
    sai_object_id_t nh_group_mem_id5;

    sai_object_id_t nh_ll;

    void configure_port(int first_serdes_id, int num_serdes)
    {
        sai_object_id_t port_id{};

        uint32_t lanes[num_serdes];
        std::iota(lanes, lanes + num_serdes, first_serdes_id);

        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        attr.id = SAI_PORT_ATTR_HW_LANE_LIST;
        attr.value.u32list.count = num_serdes;
        attr.value.u32list.list = lanes;
        attrs.push_back(attr);

        attr.id = SAI_PORT_ATTR_SPEED;
        set_attr_value(SAI_PORT_ATTR_SPEED, attr.value, 100000); // 100G
        attrs.push_back(attr);

        attr.id = SAI_PORT_ATTR_FEC_MODE;
        set_attr_value(SAI_PORT_ATTR_FEC_MODE, attr.value, sai_port_fec_mode_t::SAI_PORT_FEC_MODE_RS); // RS FEC
        attrs.push_back(attr);

        attr.id = SAI_PORT_ATTR_MTU;
        set_attr_value(SAI_PORT_ATTR_MTU, attr.value, 9600); // SAI default is 1514, change it back to Leaba SDK default.
        attrs.push_back(attr);

        attr.id = SAI_PORT_ATTR_ADMIN_STATE;
        set_attr_value(SAI_PORT_ATTR_ADMIN_STATE, attr.value, true);
        attrs.push_back(attr);

        sai_status_t status = port_api->create_port(&port_id, switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        ports.push_back(port_id);
    }

    void configure_ports()
    {
        int serdes_per_port = 2;
        for (int ifg_idx = 0; ifg_idx < 2; ifg_idx++) {
            for (int i = 0; i < 16; i = i + serdes_per_port) {
                int pif = (ifg_idx << 8) + i;
                configure_port(pif, serdes_per_port);
            }
        }
    }

    void deconfigure_ports()
    {
        for (auto p : ports) {
            port_api->remove_port(p);
        }
    }

    void get_apis()
    {
        sai_status_t status = sai_api_query(SAI_API_SWITCH, (void**)(&switch_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(switch_api, nullptr);

        status = sai_api_query(SAI_API_PORT, (void**)(&port_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(port_api, nullptr);

        status = sai_api_query(SAI_API_BRIDGE, (void**)(&bridge_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(bridge_api, nullptr);

        status = sai_api_query(SAI_API_ROUTER_INTERFACE, (void**)(&rif_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(rif_api, nullptr);

        status = sai_api_query(SAI_API_NEXT_HOP, (void**)(&nexthop_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(nexthop_api, nullptr);

        status = sai_api_query(SAI_API_NEXT_HOP_GROUP, (void**)(&nexthop_group_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(nexthop_group_api, nullptr);

        status = sai_api_query(SAI_API_VIRTUAL_ROUTER, (void**)(&vrf_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(vrf_api, nullptr);

        status = sai_api_query(SAI_API_ROUTE, (void**)(&route_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(route_api, nullptr);

        status = sai_api_query(SAI_API_NEIGHBOR, (void**)(&neighbor_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(neighbor_api, nullptr);

        status = sai_api_query(SAI_API_FDB, (void**)(&fdb_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(fdb_api, nullptr);

        status = sai_api_query(SAI_API_HOSTIF, (void**)(&hostif_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(hostif_api, nullptr);
    }

    void configure_router_port(sai_object_id_t& rif_id,
                               sai_object_id_t vrf_id,
                               int port_index,
                               sai_router_interface_type_t rif_type,
                               const char* mac_addr = nullptr)
    {
        std::vector<sai_attribute_t> attrs;
        sai_attribute_t attr{};

        attr.id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
        set_attr_value(SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID, attr.value, vrf_id);
        attrs.push_back(attr);

        attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
        set_attr_value(SAI_ROUTER_INTERFACE_ATTR_TYPE, attr.value, rif_type);
        attrs.push_back(attr);

        attr.id = SAI_ROUTER_INTERFACE_ATTR_PORT_ID;
        set_attr_value(SAI_ROUTER_INTERFACE_ATTR_PORT_ID, attr.value, ports.at(port_index));
        attrs.push_back(attr);

        if (mac_addr == nullptr) {
            attr.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
            str_to_mac(router_mac, attr.value.mac);
            attrs.push_back(attr);
        } else {
            attr.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
            str_to_mac(mac_addr, attr.value.mac);
            attrs.push_back(attr);
        }

        sai_status_t status = rif_api->create_router_interface(&rif_id, switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void create_neighbor(sai_object_id_t rif_id, const char* ip_addr, const char* mac_addr, bool no_host = false)
    {
        sai_neighbor_entry_t nbr;
        sai_ip6_t ip;

        sai_status_t status = str_to_ipv6(ip_addr, ip);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        nbr.switch_id = switch_id;
        nbr.rif_id = rif_id;
        nbr.ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(nbr.ip_address.addr.ip6, ip, sizeof(sai_ip6_t));

        std::vector<sai_attribute_t> attrs;
        sai_attribute_t attr{};

        attr.id = SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS;
        str_to_mac(mac_addr, attr.value.mac);
        attrs.push_back(attr);

        attr.id = SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE;
        set_attr_value(SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE, attr.value, no_host);
        attrs.push_back(attr);

        status = neighbor_api->create_neighbor_entry(&nbr, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void remove_neighbor(sai_object_id_t rif_id, const char* ip_addr)
    {
        sai_neighbor_entry_t nbr;
        sai_ip6_t ip;

        sai_status_t status = str_to_ipv6(ip_addr, ip);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        nbr.switch_id = switch_id;
        nbr.rif_id = rif_id;
        nbr.ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(nbr.ip_address.addr.ip6, ip, sizeof(sai_ip6_t));

        status = neighbor_api->remove_neighbor_entry(&nbr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void create_nexthop_group_member(sai_object_id_t& group_member_id, sai_object_id_t group, sai_object_id_t next_hop)
    {
        sai_status_t status;

        std::vector<sai_attribute_t> attrs;
        sai_attribute_t attr{};

        attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
        set_attr_value(SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID, attr.value, group);
        attrs.push_back(attr);

        attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
        set_attr_value(SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID, attr.value, next_hop);
        attrs.push_back(attr);

        status = nexthop_group_api->create_next_hop_group_member(&group_member_id, switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void create_nexthop_group(sai_object_id_t& nh_group)
    {
        sai_status_t status;

        std::vector<sai_attribute_t> attrs;
        sai_attribute_t attr{};

        attr.id = SAI_NEXT_HOP_GROUP_ATTR_TYPE;
        set_attr_value(SAI_NEXT_HOP_GROUP_ATTR_TYPE, attr.value, SAI_NEXT_HOP_GROUP_TYPE_ECMP);
        attrs.push_back(attr);

        status = nexthop_group_api->create_next_hop_group(&nh_group, switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void create_nexthop(sai_object_id_t& nh_id, const char* ip_addr, sai_object_id_t rif_id)
    {
        sai_ip6_t ip;

        std::vector<sai_attribute_t> attrs;
        sai_attribute_t attr{};

        attr.id = SAI_NEXT_HOP_ATTR_TYPE;
        set_attr_value(SAI_NEXT_HOP_ATTR_TYPE, attr.value, SAI_NEXT_HOP_TYPE_IP);
        attrs.push_back(attr);

        sai_status_t status = str_to_ipv6(ip_addr, ip);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        attr.id = SAI_NEXT_HOP_ATTR_IP;
        attr.value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(attr.value.ipaddr.addr.ip6, ip, sizeof(sai_ip6_t));
        attrs.push_back(attr);

        attr.id = SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID;
        set_attr_value(SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID, attr.value, rif_id);
        attrs.push_back(attr);

        status = nexthop_api->create_next_hop(&nh_id, switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void configure_router_mac(const char* macAddr)
    {
        sai_attribute_t attr;

        attr.id = SAI_SWITCH_ATTR_SRC_MAC_ADDRESS;
        memcpy(&attr.value.mac, macAddr, 6);
        str_to_mac(macAddr, attr.value.mac);

        sai_status_t status = switch_api->set_switch_attribute(switch_id, &attr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    // next hop id can be the following type:
    //
    // SAI_OBJECT_TYPE_NEXT_HOP
    // SAI_OBJECT_TYPE_NEXT_HOP_GROUP
    // SAI_OBJECT_TYPE_ROUTER_INTERFACE
    // SAI_OBJECT_TYPE_PORT
    void create_route(sai_object_id_t vrf_id, const char* route_prefix, const char* route_mask, sai_object_id_t nh_id)
    {
        sai_ip6_t ip, ipmask;

        sai_route_entry_t route_entry;
        route_entry.switch_id = switch_id;
        route_entry.vr_id = vrf_id;
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV6;

        sai_status_t status = str_to_ipv6(route_prefix, ip);
        memcpy(route_entry.destination.addr.ip6, ip, sizeof(sai_ip6_t));

        status = str_to_ipv6(route_mask, ipmask);
        memcpy(route_entry.destination.mask.ip6, ipmask, sizeof(sai_ip6_t));

        sai_attribute_t attr;

        attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
        set_attr_value(SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, attr.value, nh_id);

        status = route_api->create_route_entry(&route_entry, 1, &attr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        sai_attribute_t attr_ret{};
        attr_ret.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
        status = route_api->get_route_entry_attribute(&route_entry, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void modify_route(sai_object_id_t vrf_id, const char* route_prefix, const char* route_mask, sai_object_id_t nh_id)
    {
        sai_ip6_t ip, ipmask;

        sai_route_entry_t route_entry;
        route_entry.switch_id = switch_id;
        route_entry.vr_id = vrf_id;
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV6;

        sai_status_t status = str_to_ipv6(route_prefix, ip);
        memcpy(route_entry.destination.addr.ip6, ip, sizeof(sai_ip6_t));

        status = str_to_ipv6(route_mask, ipmask);
        memcpy(route_entry.destination.mask.ip6, ipmask, sizeof(sai_ip6_t));

        sai_attribute_t attr{};
        sai_attribute_t attr_ret{};
        attr.id = SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION;
        set_attr_value(SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, attr.value, SAI_PACKET_ACTION_DROP);

        status = route_api->set_route_entry_attribute(&route_entry, &attr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        attr_ret.id = SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION;
        status = route_api->get_route_entry_attribute(&route_entry, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.s32, SAI_PACKET_ACTION_DROP);

        attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
        set_attr_value(SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, attr.value, nh_id);

        status = route_api->set_route_entry_attribute(&route_entry, &attr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        attr_ret.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
        status = route_api->get_route_entry_attribute(&route_entry, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, nh_id);
    }

    void remove_route(sai_object_id_t vrf_id, const char* route_prefix, const char* route_mask)
    {
        sai_ip6_t ip, ipmask;

        sai_route_entry_t route_entry;
        route_entry.switch_id = switch_id;
        route_entry.vr_id = vrf_id;
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV6;

        sai_status_t status = str_to_ipv6(route_prefix, ip);
        memcpy(route_entry.destination.addr.ip6, ip, sizeof(sai_ip6_t));

        status = str_to_ipv6(route_mask, ipmask);
        memcpy(route_entry.destination.mask.ip6, ipmask, sizeof(sai_ip6_t));

        status = route_api->remove_route_entry(&route_entry);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    sai_status_t get_route(sai_object_id_t vrf_id, const char* route_prefix, const char* route_mask)
    {
        sai_ip6_t ip, ipmask;

        sai_route_entry_t route_entry;
        route_entry.switch_id = switch_id;
        route_entry.vr_id = vrf_id;
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV6;

        sai_status_t status = str_to_ipv6(route_prefix, ip);
        memcpy(route_entry.destination.addr.ip6, ip, sizeof(sai_ip6_t));

        status = str_to_ipv6(route_mask, ipmask);
        memcpy(route_entry.destination.mask.ip6, ipmask, sizeof(sai_ip6_t));

        status = route_api->get_route_entry_attribute(&route_entry, 0, nullptr);

        return status;
    }

    void create_bridge_port(sai_object_id_t& obj_bridge_port_id,
                            sai_bridge_port_type_t port_type,
                            sai_object_id_t obj_bridge_id,
                            sai_object_id_t obj_port_id,
                            uint16_t vlan_id = 0,
                            sai_object_id_t obj_rif = 0,
                            bool vlan_tag = false)
    {
        sai_status_t status;
        vector<sai_attribute_t> attrs;
        sai_attribute_t attr{};

        attr.id = SAI_BRIDGE_PORT_ATTR_TYPE;
        set_attr_value(SAI_BRIDGE_PORT_ATTR_TYPE, attr.value, port_type);
        attrs.push_back(attr);

        attr.id = SAI_BRIDGE_PORT_ATTR_BRIDGE_ID;
        set_attr_value(SAI_BRIDGE_PORT_ATTR_BRIDGE_ID, attr.value, m_bridge_id);
        attrs.push_back(attr);

        attr.id = SAI_BRIDGE_PORT_ATTR_PORT_ID;
        set_attr_value(SAI_BRIDGE_PORT_ATTR_PORT_ID, attr.value, obj_port_id);
        attrs.push_back(attr);

        if (vlan_id != 0) {
            attr.id = SAI_BRIDGE_PORT_ATTR_VLAN_ID;
            set_attr_value(SAI_BRIDGE_PORT_ATTR_VLAN_ID, attr.value, vlan_id);
            attrs.push_back(attr);
        }

        if (vlan_tag) {
            attr.id = SAI_BRIDGE_PORT_ATTR_TAGGING_MODE;
            set_attr_value(SAI_BRIDGE_PORT_ATTR_TAGGING_MODE, attr.value, SAI_BRIDGE_PORT_TAGGING_MODE_TAGGED);
            attrs.push_back(attr);
        }

        if (obj_rif != 0) {
            attr.id = SAI_BRIDGE_PORT_ATTR_RIF_ID;
            set_attr_value(SAI_BRIDGE_PORT_ATTR_RIF_ID, attr.value, obj_rif);
            attrs.push_back(attr);
        }

        status = bridge_api->create_bridge_port(&obj_bridge_port_id, switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void set_bridge_flood_type(sai_object_id_t obj_bridge, sai_bridge_flood_control_type_t flood_type)
    {
        sai_status_t status;
        sai_attribute_t attr;

        attr.id = SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE;
        set_attr_value(SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE, attr.value, flood_type);

        status = bridge_api->set_bridge_attribute(obj_bridge, &attr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void create_mac_entry(sai_object_id_t bridge, const char* bridge_mac, sai_object_id_t port_id)
    {
        sai_fdb_entry_t fdb_entry;
        vector<sai_attribute_t> attrs;

        fdb_entry.switch_id = switch_id;
        fdb_entry.bv_id = m_bridge_id;
        str_to_mac(bridge_mac, fdb_entry.mac_address);

        sai_attribute_t attr{};
        attr.id = SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID;
        set_attr_value(SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, attr.value, port_id);
        attrs.push_back(attr);

        attr.id = SAI_FDB_ENTRY_ATTR_TYPE;
        set_attr_value(SAI_FDB_ENTRY_ATTR_TYPE, attr.value, SAI_FDB_ENTRY_TYPE_STATIC);
        attrs.push_back(attr);

        sai_status_t status = fdb_api->create_fdb_entry(&fdb_entry, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void remove_mac_entry(sai_object_id_t bridge, const char* bridge_mac)
    {
        sai_fdb_entry_t fdb_entry;

        fdb_entry.switch_id = switch_id;
        fdb_entry.bv_id = m_bridge_id;
        str_to_mac(bridge_mac, fdb_entry.mac_address);

        sai_status_t status = fdb_api->remove_fdb_entry(&fdb_entry);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void setup_punt_path()
    {
        const char* default_mask = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF";
        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};
        attr.id = SAI_SWITCH_ATTR_CPU_PORT;
        attrs.push_back(attr);

        sai_status_t status = switch_api->get_switch_attribute(switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(status, SAI_STATUS_SUCCESS);

        sai_object_id_t cpu_port_id = attrs[0].value.oid;
        create_route(m_default_vrf_id, local_ip1, default_mask, cpu_port_id);
        create_route(m_default_vrf_id, local_ip2, default_mask, cpu_port_id);
    }

    void configure_topology()
    {
        sai_status_t status;
        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        attr.id = SAI_BRIDGE_ATTR_TYPE;
        set_attr_value(SAI_BRIDGE_ATTR_TYPE, attr.value, SAI_BRIDGE_TYPE_1D);
        attrs.push_back(attr);

        // create L2 configurationo
        status = bridge_api->create_bridge(&m_bridge_id, switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        create_bridge_port(
            m_bridge_port_id2, SAI_BRIDGE_PORT_TYPE_SUB_PORT, m_bridge_id, ports[port_5_for_bridge], VLAN_10, 0, false);
        create_bridge_port(
            m_bridge_port_id, SAI_BRIDGE_PORT_TYPE_SUB_PORT, m_bridge_id, ports[port_3_for_bridge], VLAN_10, 0, true);
        create_mac_entry(m_bridge_id, svi_dst_neighbor_mac, m_bridge_port_id);
        create_mac_entry(m_bridge_id, svi_dst_host1, m_bridge_port_id);
        create_mac_entry(m_bridge_id, svi_acc_host, m_bridge_port_id2);

        // create L3 configuration
        attr.id = SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID;

        status = switch_api->get_switch_attribute(switch_id, 1, &attr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        m_default_vrf_id = attr.value.oid;

        // create svi router port
        configure_router_port(m_svi_rif_id, m_default_vrf_id, 0, SAI_ROUTER_INTERFACE_TYPE_BRIDGE, svi_mac);

        // create svi bridge port
        create_bridge_port(m_svi_port_id, SAI_BRIDGE_PORT_TYPE_1D_ROUTER, m_bridge_id, 0, 0, m_svi_rif_id);

        // add_ipv6_route create route for a rif to assign subnet to the interface
        create_route(m_default_vrf_id, svi_dst_prefix, svi_dst_prefix_mask, m_svi_rif_id);
        // add_ipv6_host host require subnet to the interface
        create_neighbor(m_svi_rif_id, svi_dst_neighbor_ip, svi_dst_neighbor_mac);

        // create router port for svi test case
        configure_router_port(
            m_svi_router_rif, m_default_vrf_id, port_4_svi_router, SAI_ROUTER_INTERFACE_TYPE_PORT, svi_router_router_mac);

        create_route(m_default_vrf_id, svi_router_prefix, svi_router_prefix_mask, m_svi_router_rif);
        create_neighbor(m_svi_router_rif, svi_router_neighbor_ip, svi_router_neighbor_mac);

        create_nexthop(nh_svi_router, svi_router_neighbor_ip, m_svi_router_rif);

        configure_router_port(m_rif_id_1, m_default_vrf_id, port_1_for_router, SAI_ROUTER_INTERFACE_TYPE_PORT);
        configure_router_port(m_rif_id_2, m_default_vrf_id, port_2_for_router, SAI_ROUTER_INTERFACE_TYPE_PORT);

        create_route(m_default_vrf_id, route_prefix1, route_prefix1_mask, m_rif_id_1);
        create_route(m_default_vrf_id, route_prefix2, route_prefix2_mask, m_rif_id_2);

        // create_route(m_default_vrf_id, route_prefix1, route_prefix1_mask, nh_id1);
        // create_route(m_default_vrf_id, route_prefix2, route_prefix2_mask, nh_id2);

        create_neighbor(m_rif_id_1, neighbor_ip1, neighbor_mac1);
        create_neighbor(m_rif_id_2, neighbor_ip2, neighbor_mac2);

        create_neighbor(m_rif_id_1, link_local_ip, link_local_mac, true);

        create_nexthop(nh_id1, neighbor_ip1, m_rif_id_1);
        create_nexthop(nh_id2, neighbor_ip2, m_rif_id_2);
        create_nexthop(nh_id3, svi_dst_neighbor_ip, m_svi_rif_id);

        create_nexthop(nh_ll, link_local_ip, m_rif_id_1);
        create_route(m_default_vrf_id, inj_ll_ip, inj_ll_mask, nh_ll);

        create_route(m_default_vrf_id, svi_route2_prefix, svi_route2_mask, nh_id3);
        create_route(m_default_vrf_id, default_ip, default_ip_mask, SAI_NULL_OBJECT_ID);

        create_mac_entry(m_bridge_id, svi_mac1, m_bridge_port_id);
        create_mac_entry(m_bridge_id, svi_mac2, m_bridge_port_id2);
        create_neighbor(m_svi_rif_id, svi_ip1, svi_mac1);
        create_neighbor(m_svi_rif_id, svi_ip2, svi_mac2);
        create_nexthop(nh_id4, svi_ip1, m_svi_rif_id);
        create_nexthop(nh_id5, svi_ip2, m_svi_rif_id);

        create_nexthop_group(nh45_group);
        create_nexthop_group_member(nh_group_mem_id4, nh45_group, nh_id4);
        create_nexthop_group_member(nh_group_mem_id5, nh45_group, nh_id5);
        create_route(m_default_vrf_id, svi_ip_prefix, svi_ip_prefix_mask, nh_id5);
        modify_route(m_default_vrf_id, svi_ip_prefix, svi_ip_prefix_mask, nh45_group);

        setup_punt_path();
    }

    void deconfigure_topology()
    {
        sai_status_t status;

        remove_mac_entry(m_bridge_id, svi_dst_neighbor_mac);
        remove_mac_entry(m_bridge_id, svi_dst_host1);
        remove_mac_entry(m_bridge_id, svi_acc_host);
        remove_mac_entry(m_bridge_id, svi_mac1);
        remove_mac_entry(m_bridge_id, svi_mac2);

        remove_route(m_default_vrf_id, svi_dst_prefix, svi_dst_prefix_mask);
        remove_route(m_default_vrf_id, svi_router_prefix, svi_router_prefix_mask);
        remove_route(m_default_vrf_id, route_prefix1, route_prefix1_mask);
        remove_route(m_default_vrf_id, route_prefix2, route_prefix2_mask);
        remove_route(m_default_vrf_id, default_ip, default_ip_mask);
        remove_route(m_default_vrf_id, svi_ip_prefix, svi_ip_prefix_mask);
        remove_route(m_default_vrf_id, inj_ll_ip, inj_ll_mask);

        remove_neighbor(m_svi_rif_id, svi_ip1);
        remove_neighbor(m_svi_rif_id, svi_ip2);
        remove_neighbor(m_rif_id_1, neighbor_ip1);
        remove_neighbor(m_rif_id_2, neighbor_ip2);
        remove_neighbor(m_svi_router_rif, svi_router_neighbor_ip);
        remove_neighbor(m_svi_rif_id, svi_dst_neighbor_ip);
        remove_neighbor(m_rif_id_1, link_local_ip);

        status = nexthop_api->remove_next_hop(nh_svi_router);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = nexthop_api->remove_next_hop(nh_id1);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = nexthop_api->remove_next_hop(nh_id2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = nexthop_api->remove_next_hop(nh_id3);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = nexthop_api->remove_next_hop(nh_ll);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = nexthop_group_api->remove_next_hop_group_member(nh_group_mem_id4);
        status = nexthop_group_api->remove_next_hop_group_member(nh_group_mem_id5);
        status = nexthop_group_api->remove_next_hop_group(nh45_group);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = nexthop_api->remove_next_hop(nh_id4);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = nexthop_api->remove_next_hop(nh_id5);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = rif_api->remove_router_interface(m_rif_id_1);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = rif_api->remove_router_interface(m_rif_id_2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = rif_api->remove_router_interface(m_svi_rif_id);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = rif_api->remove_router_interface(m_svi_router_rif);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = bridge_api->remove_bridge_port(m_bridge_port_id2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = bridge_api->remove_bridge_port(m_bridge_port_id);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = bridge_api->remove_bridge_port(m_svi_port_id);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = bridge_api->remove_bridge(m_bridge_id);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void SetUp() override
    {

        // 1. Start simulator
        const char* dp = "/dev/testdev2";
        sim_ifc = create_and_run_simulator_server(nullptr, 0, dp);
        std::string sim_path = sim_ifc->get_connection_handle();
        sim_ifc->packet_dma_enable(true);
        sim_ifc->set_logging(true);

        // register the profile_get_value function
        sai_service_method_table_t service = {(sai_profile_get_value_fn)profile_get_value, nullptr};

        sai_status_t status = sai_api_initialize(0, &service);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        // 2. Initialize vrf
        get_apis();

        // Start user space kernel thread
        m_kernel = new user_space_kernel();
        ASSERT_NE(m_kernel, nullptr);
        int ret = m_kernel->initialize(1 /*dev_id*/, sim_path.c_str());
        ASSERT_EQ(ret, 0);
        ret = m_kernel->start_listening_for_packets();
        ASSERT_EQ(ret, 0);

        ASSERT_NE(switch_api->create_switch, nullptr);

        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        attr.id = SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO;
        attr.value.s8list.count = sim_path.length() + 1; // include null terminator
        attr.value.s8list.list = (int8_t*)sim_path.c_str();

        attrs.push_back(attr);

        switch_api->create_switch(&switch_id, attrs.size(), attrs.data());
        configure_router_mac(router_mac);
        configure_ports();
        configure_topology();

        // create_route(m_default_vrf_id, route_prefix3, route_prefix3_mask, nh_id2);

        std::this_thread::sleep_for(std::chrono::milliseconds{500});
    }

    void TearDown() override
    {
        m_kernel->destroy();
        deconfigure_topology();
        deconfigure_ports();
        switch_api->remove_switch(switch_id);
        delete sim_ifc;
    }

    const char* router_mac = "31:32:33:34:35:36";
    const char* neighbor_mac1 = "00:06:06:06:06:06";
    const char* neighbor_mac2 = "00:07:07:07:07:07";
    const char* svi_dst_host1 = "00:00:00:00:25:26";
    const char* svi_acc_host = "00:00:00:33:55:55";
    const char* neighbor_mac3 = "00:00:33:44:55:66";
    const char* link_local_mac = "40:41:43:45:47:49";
    const char* link_local_ip = "ff80:0db9:0a0b:12f0:4041:43ff:fe45:4749";

    const char* svi_mac1 = "00:55:55:56:66:13";
    const char* svi_mac2 = "00:77:77:78:88:14";
    const char* svi_ip1 = "2222:0db8:0a00:0000:0000:0000:3333:8888";
    const char* svi_ip2 = "2222:0db8:0a00:0000:0000:0000:3333:9999";
    const char* svi_ip_prefix = "2222:0db8:0a0b:12f0:3333:0000:0000:0000";
    const char* svi_ip_prefix_mask = "ffff:ffff:ffff:ffff:ffff:0000:0000:0000";

    const char* neighbor_ip1 = "1111:0db9:0a0b:12f0:0000:0000:0000:2222";
    const char* neighbor_ip2 = "1111:0db8:0a0b:12f0:0000:0000:0000:1111";
    const char* route_prefix1 = "1111:0db9:0a00:0000:0000:0000:0000:0000";
    const char* route_prefix1_mask = "ffff:ffff:ff00:0000:0000:0000:0000:0000";
    const char* route_prefix2 = "1111:0db8:0a00:0000:0000:0000:0000:0000";
    const char* route_prefix2_mask = "ffff:ffff:ff00:0000:0000:0000:0000:0000";
    const char* route_prefix3 = "1111:0000:0000:0000:0000:0000:0000:0000";
    const char* route_prefix3_mask = "ffff:0000:0000:0000:0000:0000:0000:0000";

    const char* svi_mac = "11:12:13:14:15:16";
    const char* svi_dst_neighbor_mac = "71:72:73:74:75:76";
    const char* svi_dst_prefix = "2222:0db8:0a00:0000:0000:0000:0000:0000";
    const char* svi_dst_prefix_mask = "ffff:ffff:ff00:0000:0000:0000:0000:0000";
    const char* svi_dst_neighbor_ip = "2222:0db8:0a0b:12f0:0000:0000:0000:2222";

    const char* svi_router_neighbor_mac = "a1:a2:a3:a4:a5:a6";
    const char* svi_router_router_mac = "21:22:23:24:25:26";
    const char* svi_router_prefix = "3333:0db8:0a00:0000:0000:0000:0000:0000";
    const char* svi_router_prefix_mask = "ffff:ffff:ff00:0000:0000:0000:0000:0000";
    const char* svi_router_neighbor_ip = "3333:0db8:0a0b:12f0:0000:0000:0000:3333";

    const char* svi_route2_prefix = "4444:0db8:0a00:0000:0000:0000:0000:0000";
    const char* svi_route2_mask = "ffff:ffff:ff00:0000:0000:0000:0000:0000";

    const char* inj_ll_ip = "5555:0db8:0a00:0000:0000:0000:0000:0000";
    const char* inj_ll_mask = "ffff:ffff:ff00:0000:0000:0000:0000:0000";

    const char* default_ip = "0000:0000:0000:0000:0000:0000:0000:0000";
    const char* default_ip_mask = "0000:0000:0000:0000:0000:0000:0000:0000";
    const char* local_ip1 = "fe80:0000:0000:0000:0059:f9ff:fecb:954f";
    const char* local_ip2 = "fe80:0000:0000:0000:0059:f9ff:fecb:954f";

    int port_1_for_router = 0;
    int port_2_for_router = 1;
    int port_3_for_bridge = 2;
    int port_4_svi_router = 3;
    int port_5_for_bridge = 4;
    uint16_t VLAN_10 = 10;
};

TEST_F(SimRouteV6Test, route_fwd_nexthop)
{
    const char inject_packet[] = "313233343536beef5d357a359100000186dd6000000000283b8022220db80a0b12f000000000000022225555"
                                 "0db80a0b12f0000000000000111188888888888888888888888888888888888888888888888888888888888888888888"
                                 "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                 "888888888888888888888888888888888888";
    const char ingress_packet[] = "313233343536beef5d357a359100000186dd6000000000283b8022220db80a0b12f000000000000022221111"
                                  "0db80a0b12f0000000000000111188888888888888888888888888888888888888888888888888888888888888888888"
                                  "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                  "888888888888888888888888888888888888";

    const char egress_packet[] = "00070707070731323334353686dd6000000000283b7f22220db80a0b12f0000000000000222211110db80a0b12f00000"
                                 "000000001111888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                 "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                 "88888888888888888888";

    const char svi_ingress_packet[] = "111213141516beef5d357a358100000a86dd6000000000283b8022220db80a0b12f00000000000002222"
                                      "33330db80a0b12f000000000000033338888888888888888888888888888888888888888888888888888"
                                      "888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                      "8888888888888888888888888888888888888888888888888888888888888888";

    const char svi_egress_packet[] = "a1a2a3a4a5a621222324252686dd6000000000283b7f22220db80a0b12f0000000000000222233330db80a0b"
                                     "12f0000000000000333388888888888888888888888888888888888888888888888888888888888888888888"
                                     "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                     "88888888888888888888888888888888888888888888";

    const char router_to_svi_in_packet[]
        = "212223242526beef5d35a52686dd6000000000283b7f33330db80a0b12f0000000000000333322220db80a0"
          "b12f0000000000000222288888888888888888888888888888888888888888888888888888888888888888888"
          "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
          "88888888888888888888888888888888888888888888";

    const char router_to_svi_out_packet[] = "71727374757611121314151686dd6000000000283b7e33330db80a0b12f00000000000003333"
                                            "22220db80a0b12f0000000000000222288888888888888888888888888888888888888888888"
                                            "8888888888888888888888888888888888888888888888888888888888888888888888888888"
                                            "88888888888888888888888888888888888888888888888888888888888888888888888888888888";

    const char bridge_in_packet[] = "000000002526beef5d35a52686dd6000000000283b7f33330db80a0b12f0000000000000333322220db80a0"
                                    "b12f0000000000000222288888888888888888888888888888888888888888888888888888888888888888888"
                                    "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                    "88888888888888888888888888888888888888888888";

    const char bridge_out_packet[]
        = "000000002526beef5d35a5268100600a86dd6000000000283b7f33330db80a0b12f0000000000000333322220db80a0"
          "b12f0000000000000222288888888888888888888888888888888888888888888888888888888888888888888"
          "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
          "88888888888888888888888888888888888888888888";

    const char bridge_acc_in_packet[]
        = "00000033555500005d35a5268100000a86dd6000000000283b7f33330db80a0b12f0000000000000333322220db80a0"
          "b12f0000000000000222288888888888888888888888888888888888888888888888888888888888888888888"
          "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
          "88888888888888888888888888888888888888888888";

    const char bridge_acc_out_packet[] = "00000033555500005d35a52686dd6000000000283b7f33330db80a0b12f0000000000000333322220db80a0"
                                         "b12f0000000000000222288888888888888888888888888888888888888888888888888888888888888888888"
                                         "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                         "88888888888888888888888888888888888888888888";

    const char test_route_in_packet[] = "212223242526beef5d35a52686dd6000000000283b7f33330db80a0b12f0000000000000333344440db80a0"
                                        "b12f0000000000000444488888888888888888888888888888888888888888888888888888888888888888888"
                                        "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                        "88888888888888888888888888888888888888888888";

    const char test_route_out_packet[] = "71727374757611121314151686dd6000000000283b7e33330db80a0b12f0000000000000"
                                         "333344440db80a0b12f00000000000004444888888888888888888888888888888888888"
                                         "8888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                         "8888888888888888888888888888888888888888888888888888888888888888888888888888888888";

    const char test_ecmp1_in_packet[] = "212223242526beef5d35a52686dd6000000000283b7f33330db80a0b12f0000000000000333322220db80a0"
                                        "b12f0333300000000777788888888888888888888888888888888888888888888888888888888888888888888"
                                        "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                        "88888888888888888888888888888888888888888888";

    const char test_ecmp1_out_packet[] = "00555556661311121314151686dd6000000000283b7e33330db80a0b12f0000000000000333322220db80a0b"
                                         "12f0333300000000777788888888888888888888888888888888888888888888888888888888888888888888"
                                         "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                         "88888888888888888888888888888888888888888888";

    const char test_ecmp2_in_packet[] = "212223242526beef5d35a52686dd6000000000283b7f33330db80a0b12f0000000000000333322220db80a0"
                                        "b12f0333300000000555588888888888888888888888888888888888888888888888888888888888888888888"
                                        "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                        "88888888888888888888888888888888888888888888";

    const char test_ecmp2_out_packet[] = "00777778881411121314151686dd6000000000283b7e33330db80a0b12f0000000000000333322220db80a0b"
                                         "12f0333300000000555588888888888888888888888888888888888888888888888888888888888888888888"
                                         "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                         "88888888888888888888888888888888888888888888";

    size_t inject_output_port = port_1_for_router;

    size_t input_port = port_1_for_router;
    size_t output_port = port_2_for_router;
    size_t svi_input_port = port_3_for_bridge;
    size_t svi_output_port = port_4_svi_router;
    size_t router_to_svi_in_port = port_4_svi_router;
    size_t router_to_svi_out_port = port_3_for_bridge;

    size_t bridge_input_port = port_5_for_bridge;
    size_t bridge_out_port = port_3_for_bridge;

    size_t bridge_acc_input_port = port_3_for_bridge;
    size_t bridge_acc_out_port = port_5_for_bridge;

    size_t test_route_in_port = port_4_svi_router;
    size_t test_route_out_port = port_3_for_bridge;

    size_t test_ecmp1_in_port = port_4_svi_router;
    size_t test_ecmp1_out_port = port_3_for_bridge;
    size_t test_ecmp2_in_port = port_4_svi_router;
    size_t test_ecmp2_out_port = port_5_for_bridge;

    // 2-lane ports for this testcase
    auto inject_expected_output_info = lane_to_slice_ifg_pif(inject_output_port * 2);

    auto input_info = lane_to_slice_ifg_pif(input_port * 2);
    auto expected_output_info = lane_to_slice_ifg_pif(output_port * 2);

    auto svi_input_info = lane_to_slice_ifg_pif(svi_input_port * 2);
    auto svi_expected_output_info = lane_to_slice_ifg_pif(svi_output_port * 2);

    auto router_to_svi_input_info = lane_to_slice_ifg_pif(router_to_svi_in_port * 2);
    auto router_to_svi_expected_output_info = lane_to_slice_ifg_pif(router_to_svi_out_port * 2);

    auto bridge_input_info = lane_to_slice_ifg_pif(bridge_input_port * 2);
    auto bridge_expected_output_info = lane_to_slice_ifg_pif(bridge_out_port * 2);

    auto bridge_acc_input_info = lane_to_slice_ifg_pif(bridge_acc_input_port * 2);
    auto bridge_acc_expected_output_info = lane_to_slice_ifg_pif(bridge_acc_out_port * 2);

    auto test_route_input_info = lane_to_slice_ifg_pif(test_route_in_port * 2);
    auto test_route_expected_output_info = lane_to_slice_ifg_pif(test_route_out_port * 2);

    auto test_ecmp1_input_info = lane_to_slice_ifg_pif(test_ecmp1_in_port * 2);
    auto test_ecmp1_expected_output_info = lane_to_slice_ifg_pif(test_ecmp1_out_port * 2);
    auto test_ecmp2_input_info = lane_to_slice_ifg_pif(test_ecmp2_in_port * 2);
    auto test_ecmp2_expected_output_info = lane_to_slice_ifg_pif(test_ecmp2_out_port * 2);

    sim_packet_info_desc packet_desc
        = {.packet = ingress_packet, .slice = input_info.slice, .ifg = input_info.ifg, .pif = input_info.pif};

    sim_packet_info_desc svi_packet_desc
        = {.packet = svi_ingress_packet, .slice = svi_input_info.slice, .ifg = svi_input_info.ifg, .pif = svi_input_info.pif};

    sim_packet_info_desc router_svi_packet_desc = {.packet = router_to_svi_in_packet,
                                                   .slice = router_to_svi_input_info.slice,
                                                   .ifg = router_to_svi_input_info.ifg,
                                                   .pif = router_to_svi_input_info.pif};

    sim_packet_info_desc bridge_packet_desc = {
        .packet = bridge_in_packet, .slice = bridge_input_info.slice, .ifg = bridge_input_info.ifg, .pif = bridge_input_info.pif};

    sim_packet_info_desc test_ecmp1_packet_desc = {.packet = test_ecmp1_in_packet,
                                                   .slice = test_ecmp1_input_info.slice,
                                                   .ifg = test_ecmp1_input_info.ifg,
                                                   .pif = test_ecmp1_input_info.pif};

    sim_packet_info_desc test_ecmp2_packet_desc = {.packet = test_ecmp2_in_packet,
                                                   .slice = test_ecmp2_input_info.slice,
                                                   .ifg = test_ecmp2_input_info.ifg,
                                                   .pif = test_ecmp2_input_info.pif};

    sim_packet_info_desc bridge_acc_packet_desc = {.packet = bridge_acc_in_packet,
                                                   .slice = bridge_acc_input_info.slice,
                                                   .ifg = bridge_acc_input_info.ifg,
                                                   .pif = bridge_acc_input_info.pif};

    sim_packet_info_desc test_route_packet_desc = {.packet = test_route_in_packet,
                                                   .slice = test_route_input_info.slice,
                                                   .ifg = test_route_input_info.ifg,
                                                   .pif = test_route_input_info.pif};
    //------- inject packet route through link local
    sai_attribute_t attr{};
    uint8_t inject_buf[1036];
    str_to_uint8(inject_packet, inject_buf, 1024);

    attr.id = SAI_HOSTIF_PACKET_ATTR_HOSTIF_TX_TYPE;
    set_attr_value(SAI_HOSTIF_PACKET_ATTR_HOSTIF_TX_TYPE, attr.value, SAI_HOSTIF_TX_TYPE_PIPELINE_LOOKUP);

    sai_status_t status = hostif_api->send_hostif_packet(switch_id, sizeof(inject_packet) / 2, inject_buf, 1, &attr);
    ASSERT_EQ(status, SAI_STATUS_SUCCESS);

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    auto output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 1U);

    // ASSERT_EQ(output_packets[0].packet, egress_packet);
    ASSERT_EQ(output_packets[0].slice, inject_expected_output_info.slice);
    ASSERT_EQ(output_packets[0].ifg, inject_expected_output_info.ifg);
    ASSERT_EQ(output_packets[0].pif, inject_expected_output_info.pif);

    const sai_router_interface_stat_t router_counter_ids[] = {SAI_ROUTER_INTERFACE_STAT_IN_PACKETS,
                                                              SAI_ROUTER_INTERFACE_STAT_IN_OCTETS,
                                                              SAI_ROUTER_INTERFACE_STAT_OUT_PACKETS,
                                                              SAI_ROUTER_INTERFACE_STAT_OUT_OCTETS};

    uint64_t counters[array_size(router_counter_ids)] = {};
    status = rif_api->get_router_interface_stats_ext(m_rif_id_1,
                                                     array_size(router_counter_ids),
                                                     (const sai_stat_id_t*)router_counter_ids,
                                                     SAI_STATS_MODE_READ_AND_CLEAR,
                                                     counters);

    ASSERT_EQ(status, SAI_STATUS_SUCCESS);
    ASSERT_EQ(counters[0], 0U);
    ASSERT_EQ(counters[1], 0U);
    ASSERT_EQ(counters[2], 1U);
    ASSERT_EQ(counters[3], 158U);

    //------- Send and receive the first router port to router port packet
    bool success = sim_ifc->inject_packet(packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 1U);

    ASSERT_EQ(output_packets[0].packet, egress_packet);
    ASSERT_EQ(output_packets[0].slice, expected_output_info.slice);
    ASSERT_EQ(output_packets[0].ifg, expected_output_info.ifg);
    ASSERT_EQ(output_packets[0].pif, expected_output_info.pif);

    status = rif_api->get_router_interface_stats_ext(m_rif_id_1,
                                                     array_size(router_counter_ids),
                                                     (const sai_stat_id_t*)router_counter_ids,
                                                     SAI_STATS_MODE_READ_AND_CLEAR,
                                                     counters);

    ASSERT_EQ(status, SAI_STATUS_SUCCESS);
    ASSERT_EQ(counters[0], 1U);
    ASSERT_EQ(counters[1], 162U);
    ASSERT_EQ(counters[2], 0U);
    ASSERT_EQ(counters[3], 0U);

    status = rif_api->get_router_interface_stats_ext(m_rif_id_2,
                                                     array_size(router_counter_ids),
                                                     (const sai_stat_id_t*)router_counter_ids,
                                                     SAI_STATS_MODE_READ_AND_CLEAR,
                                                     counters);

    ASSERT_EQ(status, SAI_STATUS_SUCCESS);
    ASSERT_EQ(counters[0], 0U);
    ASSERT_EQ(counters[1], 0U);
    ASSERT_EQ(counters[2], 1U);
    ASSERT_EQ(counters[3], 158U);

    // --------------------- Send and receive the svi to router port packet
    success = sim_ifc->inject_packet(svi_packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 1U);

    ASSERT_EQ(output_packets[0].packet, svi_egress_packet);
    ASSERT_EQ(output_packets[0].slice, svi_expected_output_info.slice);
    ASSERT_EQ(output_packets[0].ifg, svi_expected_output_info.ifg);
    ASSERT_EQ(output_packets[0].pif, svi_expected_output_info.pif);

    // --------------------- Send and receive the router to svi port packet
    success = sim_ifc->inject_packet(router_svi_packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 1U);

    ASSERT_EQ(output_packets[0].packet, router_to_svi_out_packet);
    ASSERT_EQ(output_packets[0].slice, router_to_svi_expected_output_info.slice);
    ASSERT_EQ(output_packets[0].ifg, router_to_svi_expected_output_info.ifg);
    ASSERT_EQ(output_packets[0].pif, router_to_svi_expected_output_info.pif);

    // --------------------- from the access to trunk port
    success = sim_ifc->inject_packet(bridge_packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 1U);

    ASSERT_EQ(output_packets[0].packet, bridge_out_packet);
    ASSERT_EQ(output_packets[0].slice, bridge_expected_output_info.slice);
    ASSERT_EQ(output_packets[0].ifg, bridge_expected_output_info.ifg);
    ASSERT_EQ(output_packets[0].pif, bridge_expected_output_info.pif);

    // --------------------- test ecmp packet 1
    success = sim_ifc->inject_packet(test_ecmp1_packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 1U);

    ASSERT_EQ(output_packets[0].packet, test_ecmp1_out_packet);
    ASSERT_EQ(output_packets[0].slice, test_ecmp1_expected_output_info.slice);
    ASSERT_EQ(output_packets[0].ifg, test_ecmp1_expected_output_info.ifg);
    ASSERT_EQ(output_packets[0].pif, test_ecmp1_expected_output_info.pif);

    // --------------------- test ecmp packet 2
    success = sim_ifc->inject_packet(test_ecmp2_packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 1U);

    ASSERT_EQ(output_packets[0].packet, test_ecmp2_out_packet);
    ASSERT_EQ(output_packets[0].slice, test_ecmp2_expected_output_info.slice);
    ASSERT_EQ(output_packets[0].ifg, test_ecmp2_expected_output_info.ifg);
    ASSERT_EQ(output_packets[0].pif, test_ecmp2_expected_output_info.pif);

    // --------------------- from the trunk to access port
    success = sim_ifc->inject_packet(bridge_acc_packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 1U);

    ASSERT_EQ(output_packets[0].packet, bridge_acc_out_packet);
    ASSERT_EQ(output_packets[0].slice, bridge_acc_expected_output_info.slice);
    ASSERT_EQ(output_packets[0].ifg, bridge_acc_expected_output_info.ifg);
    ASSERT_EQ(output_packets[0].pif, bridge_acc_expected_output_info.pif);

    set_bridge_flood_type(m_bridge_id, SAI_BRIDGE_FLOOD_CONTROL_TYPE_NONE);
    remove_mac_entry(m_bridge_id, svi_acc_host);
    std::this_thread::sleep_for(std::chrono::milliseconds{1000});

    success = sim_ifc->inject_packet(bridge_acc_packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    output_packets = sim_ifc->get_packets();
    // ASSERT_EQ(output_packets.size(), 0U);

    // --------------------- test remove route traffic to svi port
    success = sim_ifc->inject_packet(test_route_packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 1U);

    ASSERT_EQ(output_packets[0].packet, test_route_out_packet);
    ASSERT_EQ(output_packets[0].slice, test_route_expected_output_info.slice);
    ASSERT_EQ(output_packets[0].ifg, test_route_expected_output_info.ifg);
    ASSERT_EQ(output_packets[0].pif, test_route_expected_output_info.pif);

    remove_route(m_default_vrf_id, svi_route2_prefix, svi_route2_mask);
    std::this_thread::sleep_for(std::chrono::milliseconds{300});

    success = sim_ifc->inject_packet(test_route_packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 0U);
}
