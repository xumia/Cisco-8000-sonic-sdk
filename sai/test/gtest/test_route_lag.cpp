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
#include "sai_test_utils.h"
#include "gtest/gtest.h"
#include <algorithm>
#include <iterator>
#include <numeric>
#include <thread>
#include <vector>
#include "sai_test_base.h"

using namespace std;
using namespace silicon_one;

class SimLagRouteTest : public SaiTestBase
{
public:
    sai_object_id_t nh45_group{};
    sai_object_id_t nh_id4{}, nh_id5{};
    sai_object_id_t nh_svi_router{};
    sai_object_id_t nh_group_mem_id4{};
    sai_object_id_t nh_group_mem_id5{};

    sai_object_id_t vlan_1_obj{};
    sai_object_id_t vlan_10_obj{};

    sai_object_id_t m_vlan_mem_id1{};
    sai_object_id_t m_vlan_mem_id2{};

    void configure_vlan(uint16_t vlan_id, sai_object_id_t& vlan_obj)
    {
        if (vlan_id == 0) {
            return;
        }

        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        attr.id = SAI_VLAN_ATTR_VLAN_ID;
        set_attr_value(SAI_VLAN_ATTR_VLAN_ID, attr.value, vlan_id);
        attrs.push_back(attr);

        sai_status_t status = vlan_api->create_vlan(&vlan_obj, switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        sai_attribute_t attr_ret{};
        attr_ret.id = SAI_VLAN_ATTR_VLAN_ID;
        status = vlan_api->get_vlan_attribute(vlan_obj, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.u16, vlan_id);
    }

    void configure_vlan_member(sai_object_id_t& vlan_member, sai_object_id_t vlan_obj, sai_object_id_t bport_obj, bool is_tag)
    {

        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        attr.id = SAI_VLAN_MEMBER_ATTR_VLAN_ID;
        set_attr_value(SAI_VLAN_MEMBER_ATTR_VLAN_ID, attr.value, vlan_obj);
        attrs.push_back(attr);

        attr.id = SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID;
        set_attr_value(SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID, attr.value, bport_obj);
        attrs.push_back(attr);

        attr.id = SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE;
        set_attr_value(SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE,
                       attr.value,
                       ((is_tag) ? SAI_VLAN_TAGGING_MODE_TAGGED : SAI_VLAN_TAGGING_MODE_UNTAGGED));
        attrs.push_back(attr);

        sai_status_t status = vlan_api->create_vlan_member(&vlan_member, switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void create_lag(sai_object_id_t& lag_id)
    {
        // create spa with no attributes
        sai_status_t status = lag_api->create_lag(&lag_id, switch_id, 0, nullptr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void add_port_to_lag(sai_object_id_t& lag_mem, sai_object_id_t lag_id, sai_object_id_t port_id)
    {
        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        attr.id = SAI_LAG_MEMBER_ATTR_LAG_ID;
        set_attr_value(SAI_LAG_MEMBER_ATTR_LAG_ID, attr.value, lag_id);
        attrs.push_back(attr);

        attr.id = SAI_LAG_MEMBER_ATTR_PORT_ID;
        set_attr_value(SAI_LAG_MEMBER_ATTR_PORT_ID, attr.value, port_id);
        attrs.push_back(attr);

        sai_status_t status = lag_api->create_lag_member(&lag_mem, switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void configure_router_port(sai_object_id_t& rif_id,
                               sai_object_id_t vrf_id,
                               sai_object_id_t port_obj,
                               sai_router_interface_type_t rif_type,
                               const char* mac_addr = nullptr,
                               sai_object_id_t vlan_obj = 0)
    {
        std::vector<sai_attribute_t> attrs;
        sai_attribute_t attr{};

        attr.id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
        set_attr_value(SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID, attr.value, vrf_id);
        attrs.push_back(attr);

        attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
        set_attr_value(SAI_ROUTER_INTERFACE_ATTR_TYPE, attr.value, rif_type);
        attrs.push_back(attr);

        if (port_obj) {
            attr.id = SAI_ROUTER_INTERFACE_ATTR_PORT_ID;
            set_attr_value(SAI_ROUTER_INTERFACE_ATTR_PORT_ID, attr.value, port_obj);
            attrs.push_back(attr);
        }

        if (vlan_obj) {
            attr.id = SAI_ROUTER_INTERFACE_ATTR_VLAN_ID;
            set_attr_value(SAI_ROUTER_INTERFACE_ATTR_VLAN_ID, attr.value, vlan_obj);
            attrs.push_back(attr);
        }

        if (mac_addr != nullptr) {
            attr.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
            str_to_mac(mac_addr, attr.value.mac);
            attrs.push_back(attr);
        }

        sai_status_t status = rif_api->create_router_interface(&rif_id, switch_id, attrs.size(), attrs.data());
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

    void modify_route(sai_object_id_t vrf_id, const char* route_prefix, const char* route_mask, sai_object_id_t nh_id)
    {
        uint32_t ip, ipmask;

        sai_route_entry_t route_entry;
        route_entry.switch_id = switch_id;
        route_entry.vr_id = vrf_id;
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;

        sai_status_t status = str_to_ipv4(route_prefix, ip);
        route_entry.destination.addr.ip4 = ip;

        status = str_to_ipv4(route_mask, ipmask);
        route_entry.destination.mask.ip4 = ipmask;

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

        attr.id = SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION;
        set_attr_value(SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, attr.value, SAI_PACKET_ACTION_FORWARD);
        status = route_api->set_route_entry_attribute(&route_entry, &attr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        attr_ret.id = SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION;
        status = route_api->get_route_entry_attribute(&route_entry, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.s32, SAI_PACKET_ACTION_FORWARD);
    }

    void remove_route(sai_object_id_t vrf_id, const char* route_prefix, const char* route_mask)
    {
        uint32_t ip, ipmask;

        sai_route_entry_t route_entry;
        route_entry.switch_id = switch_id;
        route_entry.vr_id = vrf_id;
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;

        sai_status_t status = str_to_ipv4(route_prefix, ip);
        route_entry.destination.addr.ip4 = ip;

        status = str_to_ipv4(route_mask, ipmask);
        route_entry.destination.mask.ip4 = ipmask;

        status = route_api->remove_route_entry(&route_entry);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    sai_status_t get_route(sai_object_id_t vrf_id, const char* route_prefix, const char* route_mask)
    {
        uint32_t ip, ipmask;

        sai_route_entry_t route_entry;
        route_entry.switch_id = switch_id;
        route_entry.vr_id = vrf_id;
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;

        sai_status_t status = str_to_ipv4(route_prefix, ip);
        route_entry.destination.addr.ip4 = ip;

        status = str_to_ipv4(route_mask, ipmask);
        route_entry.destination.mask.ip4 = ipmask;

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
        fdb_entry.bv_id = bridge;
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
        fdb_entry.bv_id = bridge;
        str_to_mac(bridge_mac, fdb_entry.mac_address);

        sai_status_t status = fdb_api->remove_fdb_entry(&fdb_entry);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void configure_topology() override
    {
        sai_status_t status;
        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        // create lag ports
        create_lag(spa_1_for_router);

        add_port_to_lag(spa_mem_1_for_router, spa_1_for_router, ports[port_1_for_router]);
        add_port_to_lag(spa_mem_1_for_router_1, spa_1_for_router, ports[port_1_for_router_1]);
        add_port_to_lag(spa_mem_1_for_router_2, spa_1_for_router, ports[port_1_for_router_2]);

        create_lag(spa_2_for_router);

        add_port_to_lag(spa_mem_2_for_router, spa_2_for_router, ports[port_2_for_router]);
        add_port_to_lag(spa_mem_2_for_router_1, spa_2_for_router, ports[port_2_for_router_1]);
        add_port_to_lag(spa_mem_2_for_router_2, spa_2_for_router, ports[port_2_for_router_2]);

        create_lag(spa_3_for_bridge);

        add_port_to_lag(spa_mem_3_for_bridge, spa_3_for_bridge, ports[port_3_for_bridge]);
        add_port_to_lag(spa_mem_3_for_bridge_1, spa_3_for_bridge, ports[port_3_for_bridge_1]);
        add_port_to_lag(spa_mem_3_for_bridge_2, spa_3_for_bridge, ports[port_3_for_bridge_2]);

        create_lag(spa_5_for_bridge);

        add_port_to_lag(spa_mem_5_for_bridge, spa_5_for_bridge, ports[port_5_for_bridge]);
        add_port_to_lag(spa_mem_5_for_bridge_1, spa_5_for_bridge, ports[port_5_for_bridge_1]);
        add_port_to_lag(spa_mem_5_for_bridge_2, spa_5_for_bridge, ports[port_5_for_bridge_2]);

        // Get Default 1Q bridge id
        attr.id = SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID;
        status = switch_api->get_switch_attribute(switch_id, 1, &attr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        m_bridge_id = attr.value.oid;

        configure_vlan(1, vlan_1_obj);
        configure_vlan(10, vlan_10_obj);

        create_bridge_port(m_bridge_port_id2, SAI_BRIDGE_PORT_TYPE_PORT, m_bridge_id, spa_5_for_bridge, 0, 0, false);
        create_bridge_port(m_bridge_port_id, SAI_BRIDGE_PORT_TYPE_PORT, m_bridge_id, spa_3_for_bridge, 0, 0, false);
        // create_bridge_port(m_bridge_port_id2, SAI_BRIDGE_PORT_TYPE_PORT, m_bridge_id, ports[port_5_for_bridge], 0, 0, false);
        // create_bridge_port(m_bridge_port_id, SAI_BRIDGE_PORT_TYPE_PORT, m_bridge_id, ports[port_3_for_bridge], 0, 0, false);

        configure_vlan_member(m_vlan_mem_id2, vlan_10_obj, m_bridge_port_id2, false);
        configure_vlan_member(m_vlan_mem_id1, vlan_10_obj, m_bridge_port_id, true);

        // create L3 configuration
        status = vrf_api->create_virtual_router(&m_default_vrf_id, switch_id, 0, NULL);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        // create svi router port
        configure_router_port(m_svi_rif_id, m_default_vrf_id, 0, SAI_ROUTER_INTERFACE_TYPE_VLAN, svi_mac, vlan_10_obj);
        create_mac_entry(vlan_10_obj, svi_dst_neighbor_mac, m_bridge_port_id);
        create_mac_entry(vlan_10_obj, svi_dst_host1, m_bridge_port_id);
        create_mac_entry(vlan_10_obj, svi_acc_host, m_bridge_port_id2);

        // create svi bridge port
        create_bridge_port(m_svi_port_id, SAI_BRIDGE_PORT_TYPE_1Q_ROUTER, m_bridge_id, 0, 0, m_svi_rif_id);

        // add_ipv4_route create route for a rif to assign subnet to the interface
        create_route(m_default_vrf_id, svi_dst_prefix, svi_dst_prefix_mask, m_svi_rif_id);

        // add_ipv4_host host require subnet to the interface
        create_neighbor(m_svi_rif_id, svi_dst_neighbor_ip, svi_dst_neighbor_mac);

        // create router port for svi test case
        configure_router_port(
            m_svi_router_rif, m_default_vrf_id, ports[port_4_svi_router], SAI_ROUTER_INTERFACE_TYPE_PORT, svi_router_router_mac);

        create_route(m_default_vrf_id, svi_router_prefix, svi_router_prefix_mask, m_svi_router_rif);
        create_neighbor(m_svi_router_rif, svi_router_neighbor_ip, svi_router_neighbor_mac);

        create_nexthop(nh_svi_router, svi_router_neighbor_ip, m_svi_router_rif);

        configure_router_port(m_rif_id_1, m_default_vrf_id, spa_1_for_router, SAI_ROUTER_INTERFACE_TYPE_PORT);
        // configure_router_port(m_rif_id_1, m_default_vrf_id, ports[port_1_for_router], SAI_ROUTER_INTERFACE_TYPE_PORT);
        configure_router_port(m_rif_id_2, m_default_vrf_id, spa_2_for_router, SAI_ROUTER_INTERFACE_TYPE_PORT);
        // configure_router_port(m_rif_id_2, m_default_vrf_id, ports[port_2_for_router], SAI_ROUTER_INTERFACE_TYPE_PORT);

        create_route(m_default_vrf_id, route_prefix1, route_prefix1_mask, m_rif_id_1);
        create_route(m_default_vrf_id, route_prefix2, route_prefix2_mask, m_rif_id_2);

        // create_route(m_default_vrf_id, route_prefix1, route_prefix1_mask, nh_id1);
        // create_route(m_default_vrf_id, route_prefix2, route_prefix2_mask, nh_id2);

        create_neighbor(m_rif_id_1, neighbor_ip1, neighbor_mac1);
        create_neighbor(m_rif_id_2, neighbor_ip2, neighbor_mac2);

        create_nexthop(nh_id1, neighbor_ip1, m_rif_id_1);
        create_nexthop(nh_id2, neighbor_ip2, m_rif_id_2);
        create_nexthop(nh_id3, svi_dst_neighbor_ip, m_svi_rif_id);

        create_route(m_default_vrf_id, svi_route2_prefix, svi_route2_mask, nh_id3);
        create_route(m_default_vrf_id, default_ip, default_ip_mask, SAI_NULL_OBJECT_ID);

        // test ecmp
        create_mac_entry(vlan_10_obj, svi_mac1, m_bridge_port_id);
        create_mac_entry(vlan_10_obj, svi_mac2, m_bridge_port_id2);
        create_neighbor(m_svi_rif_id, svi_ip1, svi_mac1);
        create_neighbor(m_svi_rif_id, svi_ip2, svi_mac2);
        create_nexthop(nh_id4, svi_ip1, m_svi_rif_id);
        create_nexthop(nh_id5, svi_ip2, m_svi_rif_id);

        create_nexthop_group(nh45_group);
        create_nexthop_group_member(nh_group_mem_id5, nh45_group, nh_id5);
        create_nexthop_group_member(nh_group_mem_id4, nh45_group, nh_id4);
        create_route(m_default_vrf_id, svi_ip_prefix, svi_ip_prefix_mask, nh_id5);
        modify_route(m_default_vrf_id, svi_ip_prefix, svi_ip_prefix_mask, nh45_group);

        std::this_thread::sleep_for(std::chrono::milliseconds{700});
    }

    void deconfigure_topology() override
    {
        sai_status_t status;

        remove_mac_entry(vlan_10_obj, svi_dst_neighbor_mac);
        remove_mac_entry(vlan_10_obj, svi_dst_host1);
        remove_mac_entry(vlan_10_obj, svi_acc_host);
        remove_mac_entry(vlan_10_obj, svi_mac1);
        remove_mac_entry(vlan_10_obj, svi_mac2);

        remove_route(m_default_vrf_id, svi_dst_prefix, svi_dst_prefix_mask);
        remove_route(m_default_vrf_id, svi_router_prefix, svi_router_prefix_mask);
        remove_route(m_default_vrf_id, route_prefix1, route_prefix1_mask);
        remove_route(m_default_vrf_id, route_prefix2, route_prefix2_mask);
        remove_route(m_default_vrf_id, default_ip, default_ip_mask);
        remove_route(m_default_vrf_id, svi_ip_prefix, svi_ip_prefix_mask);

        remove_neighbor(m_svi_rif_id, svi_ip1);
        remove_neighbor(m_svi_rif_id, svi_ip2);
        remove_neighbor(m_rif_id_1, neighbor_ip1);
        remove_neighbor(m_rif_id_2, neighbor_ip2);
        remove_neighbor(m_svi_router_rif, svi_router_neighbor_ip);
        remove_neighbor(m_svi_rif_id, svi_dst_neighbor_ip);

        status = nexthop_api->remove_next_hop(nh_svi_router);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = nexthop_api->remove_next_hop(nh_id1);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = nexthop_api->remove_next_hop(nh_id2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = nexthop_api->remove_next_hop(nh_id3);
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

        status = vlan_api->remove_vlan_member(m_vlan_mem_id1);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = vlan_api->remove_vlan_member(m_vlan_mem_id2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = bridge_api->remove_bridge_port(m_bridge_port_id2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = bridge_api->remove_bridge_port(m_bridge_port_id);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = bridge_api->remove_bridge_port(m_svi_port_id);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = vrf_api->remove_virtual_router(m_default_vrf_id);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = vlan_api->remove_vlan(vlan_1_obj);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = vlan_api->remove_vlan(vlan_10_obj);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = bridge_api->remove_bridge(m_bridge_id);
        ASSERT_EQ(SAI_STATUS_OBJECT_IN_USE, status);

        status = lag_api->remove_lag_member(spa_mem_1_for_router);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = lag_api->remove_lag_member(spa_mem_1_for_router_1);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = lag_api->remove_lag_member(spa_mem_1_for_router_2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = lag_api->remove_lag(spa_1_for_router);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = lag_api->remove_lag_member(spa_mem_2_for_router);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = lag_api->remove_lag_member(spa_mem_2_for_router_1);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = lag_api->remove_lag_member(spa_mem_2_for_router_2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = lag_api->remove_lag(spa_2_for_router);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = lag_api->remove_lag_member(spa_mem_5_for_bridge);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = lag_api->remove_lag_member(spa_mem_5_for_bridge_1);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = lag_api->remove_lag_member(spa_mem_5_for_bridge_2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = lag_api->remove_lag(spa_5_for_bridge);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = lag_api->remove_lag_member(spa_mem_3_for_bridge);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = lag_api->remove_lag_member(spa_mem_3_for_bridge_1);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = lag_api->remove_lag_member(spa_mem_3_for_bridge_2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = lag_api->remove_lag(spa_3_for_bridge);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void test_attributes(sai_object_id_t switch_id) override
    {
        sai_status_t status;
        sai_attribute_t attr_ret{};

        // check switch api attributes
        attr_ret.id = SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID;
        status = switch_api->get_switch_attribute(switch_id, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        attr_ret.id = SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID;
        status = switch_api->get_switch_attribute(switch_id, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, m_bridge_id);

        attr_ret.id = SAI_SWITCH_ATTR_DEFAULT_VLAN_ID;
        status = switch_api->get_switch_attribute(switch_id, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, vlan_1_obj);

        attr_ret.id = SAI_SWITCH_ATTR_SRC_MAC_ADDRESS;
        status = switch_api->get_switch_attribute(switch_id, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        sai_mac_t mac_addr;
        str_to_mac(router_mac, mac_addr);
        int cmp_res = memcmp(attr_ret.value.mac, mac_addr, 6);
        ASSERT_EQ(cmp_res, 0);

        attr_ret.id = SAI_SWITCH_ATTR_CPU_PORT;
        status = switch_api->get_switch_attribute(switch_id, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        attr_ret.id = SAI_VLAN_ATTR_VLAN_ID;
        status = vlan_api->get_vlan_attribute(vlan_10_obj, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.u16, 10);

        attr_ret.id = SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID;
        status = vlan_api->get_vlan_member_attribute(m_vlan_mem_id1, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, m_bridge_port_id);
        status = vlan_api->get_vlan_member_attribute(m_vlan_mem_id2, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, m_bridge_port_id2);

        attr_ret.id = SAI_VLAN_MEMBER_ATTR_VLAN_ID;
        status = vlan_api->get_vlan_member_attribute(m_vlan_mem_id1, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, vlan_10_obj);
        status = vlan_api->get_vlan_member_attribute(m_vlan_mem_id2, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, vlan_10_obj);

        attr_ret.id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
        status = rif_api->get_router_interface_attribute(m_svi_rif_id, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, m_default_vrf_id);

        status = rif_api->get_router_interface_attribute(m_rif_id_1, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, m_default_vrf_id);

        attr_ret.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
        status = rif_api->get_router_interface_attribute(m_svi_rif_id, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.s32, SAI_ROUTER_INTERFACE_TYPE_VLAN);

        attr_ret.id = SAI_ROUTER_INTERFACE_ATTR_VLAN_ID;
        status = rif_api->get_router_interface_attribute(m_svi_rif_id, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, vlan_10_obj);

        attr_ret.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
        status = rif_api->get_router_interface_attribute(m_rif_id_1, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.s32, SAI_ROUTER_INTERFACE_TYPE_PORT);

        attr_ret.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
        status = rif_api->get_router_interface_attribute(m_svi_router_rif, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        sai_mac_t rmac;
        str_to_mac(svi_router_router_mac, rmac);
        cmp_res = memcmp(attr_ret.value.mac, rmac, 6);
        ASSERT_EQ(cmp_res, 0);

        // create_nexthop(nh_id1, neighbor_ip1, m_rif_id_1);
        // create_nexthop(nh_id2, neighbor_ip2, m_rif_id_2);
        // create_nexthop(nh_id3, svi_dst_neighbor_ip, m_svi_rif_id);
        attr_ret.id = SAI_NEXT_HOP_ATTR_TYPE;
        status = nexthop_api->get_next_hop_attribute(nh_id1, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.s32, SAI_NEXT_HOP_TYPE_IP);

        attr_ret.id = SAI_NEXT_HOP_ATTR_TYPE;
        status = nexthop_api->get_next_hop_attribute(nh_id2, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.s32, SAI_NEXT_HOP_TYPE_IP);

        attr_ret.id = SAI_NEXT_HOP_ATTR_TYPE;
        status = nexthop_api->get_next_hop_attribute(nh_id3, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.s32, SAI_NEXT_HOP_TYPE_IP);

        attr_ret.id = SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID;
        status = nexthop_api->get_next_hop_attribute(nh_id1, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, m_rif_id_1);

        attr_ret.id = SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID;
        status = nexthop_api->get_next_hop_attribute(nh_id2, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, m_rif_id_2);

        attr_ret.id = SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID;
        status = nexthop_api->get_next_hop_attribute(nh_id3, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, m_svi_rif_id);

        uint32_t ip;
        attr_ret.id = SAI_NEXT_HOP_ATTR_IP;
        status = nexthop_api->get_next_hop_attribute(nh_id1, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        str_to_ipv4(neighbor_ip1, ip);
        ASSERT_EQ(attr_ret.value.ipaddr.addr.ip4, ip);

        attr_ret.id = SAI_NEXT_HOP_ATTR_IP;
        status = nexthop_api->get_next_hop_attribute(nh_id2, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        str_to_ipv4(neighbor_ip2, ip);
        ASSERT_EQ(attr_ret.value.ipaddr.addr.ip4, ip);

        attr_ret.id = SAI_NEXT_HOP_ATTR_IP;
        status = nexthop_api->get_next_hop_attribute(nh_id3, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        str_to_ipv4(svi_dst_neighbor_ip, ip);
        ASSERT_EQ(attr_ret.value.ipaddr.addr.ip4, ip);

        attr_ret.id = SAI_NEXT_HOP_GROUP_ATTR_TYPE;
        status = nexthop_group_api->get_next_hop_group_attribute(nh45_group, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.s32, SAI_NEXT_HOP_GROUP_TYPE_ECMP);

        // create_nexthop_group_member(nh_group_mem_id5, nh45_group, nh_id5);
        // create_nexthop_group_member(nh_group_mem_id4, nh45_group, nh_id4);
        attr_ret.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
        status = nexthop_group_api->get_next_hop_group_member_attribute(nh_group_mem_id5, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, nh45_group);

        attr_ret.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
        status = nexthop_group_api->get_next_hop_group_member_attribute(nh_group_mem_id4, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, nh45_group);

        attr_ret.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
        status = nexthop_group_api->get_next_hop_group_member_attribute(nh_group_mem_id5, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, nh_id5);

        attr_ret.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
        status = nexthop_group_api->get_next_hop_group_member_attribute(nh_group_mem_id4, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, nh_id4);

        attr_ret.id = SAI_SWITCH_ATTR_PORT_NUMBER;
        status = switch_api->get_switch_attribute(switch_id, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.u16, 32);

        attr_ret.value.objlist.list = (sai_object_id_t*)calloc(50, sizeof(sai_object_id_t));
        attr_ret.value.objlist.count = 50;

        attr_ret.id = SAI_SWITCH_ATTR_PORT_LIST;
        status = switch_api->get_switch_attribute(switch_id, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        assert(attr_ret.value.objlist.count == 32);

        attr_ret.id = SAI_VLAN_ATTR_MEMBER_LIST;
        status = vlan_api->get_vlan_attribute(vlan_10_obj, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        assert(attr_ret.value.objlist.count == 3);
    }

    const char* router_mac = "00:01:02:03:04:05";
    const char* neighbor_mac1 = "00:06:06:06:06:06";
    const char* neighbor_mac2 = "00:07:07:07:07:07";
    const char* svi_dst_host1 = "00:00:00:00:25:26";
    const char* svi_acc_host = "00:00:00:33:55:55";
    const char* neighbor_mac3 = "00:00:33:44:55:66";

    const char* svi_mac1 = "00:55:55:56:66:13";
    const char* svi_mac2 = "00:77:77:78:88:14";
    const char* svi_ip1 = "12.10.3.3";
    const char* svi_ip2 = "12.10.3.9";
    const char* svi_ip_prefix = "12.10.3.0";
    const char* svi_ip_prefix_mask = "255.255.255.0";

    const char* neighbor_ip1 = "192.168.1.6";
    const char* neighbor_ip2 = "192.169.1.7";
    const char* route_prefix1 = "192.168.0.0";
    const char* route_prefix1_mask = "255.255.0.0";
    const char* route_prefix2 = "192.169.0.0";
    const char* route_prefix2_mask = "255.255.0.0";
    const char* route_prefix3 = "192.0.0.0";
    const char* route_prefix3_mask = "255.0.0.0";

    const char* svi_mac = "11:12:13:14:15:16";
    const char* svi_dst_neighbor_mac = "71:72:73:74:75:76";
    const char* svi_dst_prefix = "12.10.0.0";
    const char* svi_dst_prefix_mask = "255.255.0.0";
    const char* svi_dst_neighbor_ip = "12.10.12.10";

    const char* svi_router_neighbor_mac = "a1:a2:a3:a4:a5:a6";
    const char* svi_router_router_mac = "21:22:23:24:25:26";
    const char* svi_router_prefix = "82.81.0.0";
    const char* svi_router_prefix_mask = "255.255.0.0";
    const char* svi_router_neighbor_ip = "82.81.95.250";

    const char* svi_route2_prefix = "13.11.0.0";
    const char* svi_route2_mask = "255.255.0.0";

    const char* default_ip = "0.0.0.0";
    const char* default_ip_mask = "0.0.0.0";

    sai_object_id_t spa_1_for_router;
    sai_object_id_t spa_mem_1_for_router;
    sai_object_id_t spa_mem_1_for_router_1;
    sai_object_id_t spa_mem_1_for_router_2;

    sai_object_id_t spa_2_for_router;
    sai_object_id_t spa_mem_2_for_router;
    sai_object_id_t spa_mem_2_for_router_1;
    sai_object_id_t spa_mem_2_for_router_2;

    sai_object_id_t spa_3_for_bridge;
    sai_object_id_t spa_mem_3_for_bridge;
    sai_object_id_t spa_mem_3_for_bridge_1;
    sai_object_id_t spa_mem_3_for_bridge_2;

    sai_object_id_t spa_4_svi_router;

    sai_object_id_t spa_5_for_bridge;
    sai_object_id_t spa_mem_5_for_bridge;
    sai_object_id_t spa_mem_5_for_bridge_1;
    sai_object_id_t spa_mem_5_for_bridge_2;
    int port_1_for_router = 0;
    int port_2_for_router = 1;
    int port_3_for_bridge = 2;
    int port_4_svi_router = 3;
    int port_5_for_bridge = 4;

    int port_1_for_router_1 = 5;
    int port_2_for_router_1 = 6;
    int port_3_for_bridge_1 = 7;
    int port_4_svi_router_1 = 8;
    int port_5_for_bridge_1 = 9;

    int port_1_for_router_2 = 10;
    int port_2_for_router_2 = 11;
    int port_3_for_bridge_2 = 12;
    int port_4_svi_router_2 = 13;
    int port_5_for_bridge_2 = 14;

    uint16_t VLAN_10 = 10;
};

TEST_F(SimLagRouteTest, route_fwd_nexthop)
{
    const char ingress_packet[] = "00010203040500060606060608004500002e000000004011f760c0a80106c0a90107003f003f001a0000000102030405"
                                  "060708090a0b0c0d0e0f1011cae8a318";
    const char egress_packet[] = "00070707070700010203040508004500002e000000003f11f860c0a80106c0a90107003f003f001a00000001020304050"
                                 "60708090a0b0c0d0e0f1011cae8a318";

    const char svi_ingress_packet[] = "111213141516beef5d357a358100000a08004500007800010000800070260c0a0c0a52515ffa8888888888888888"
                                      "88888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                      "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                      "8";

    const char svi_egress_packet[] = "a1a2a3a4a5a6212223242526080045000078000100007f0071260c0a0c0a52515ffa8888888888888888888888888"
                                     "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                     "8888888888888888888888888888888888888888888888888888888888888888888888888888888888";

    const char router_to_svi_in_packet[] = "212223242526beef5d35a526080045000078000100007f00712652515ffa0c0a0c0a8888888888888888888"
                                           "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                           "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                           "8888888";

    const char router_to_svi_out_packet[] = "717273747576111213141516080045000078000100007e00722652515ffa0c0a0c0a888888888888888888"
                                            "88888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                            "88888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                            "8888888888";

    const char bridge_in_packet[] = "000000002526beef5d35a526080045000078000100007f00712652515ffa0c0a0c0a88888888888888888888888888"
                                    "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                    "88888888888888888888888888888888888888888888888888888888888888888888888888888888";

    const char bridge_out_packet[] = "000000002526beef5d35a526080045000078000100007f00712652515ffa0c0a0c0a88888888888888888"
                                     "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                     "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888";

    /*
            const char bridge_out_packet[] =
           "000000002526beef5d35a5268100400a080045000078000100007f00712652515ffa0c0a0c0a88888888888888888"
                                             "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                             "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888";
    */

    const char bridge_acc_in_packet[] = "00000033555500005d35a5268100000a080045000078000100007f00712652515ffa0c0a0c0a88888888888888"
                                        "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                        "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                        "888888";

    const char bridge_acc_out_packet[] = "00000033555500005d35a526080045000078000100007f00712652515ffa0c0a0c0a888888888888888888888"
                                         "88888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                         "88888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                         "8";

    const char test_route_in_packet[] = "212223242526beef5d35a526080045000078000100007f00702552515ffa0d0b0c0a8888888888888888888"
                                        "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                        "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                        "8888888";

    const char test_route_out_packet[] = "717273747576111213141516080045000078000100007e00712552515ffa0d0b0c0a8888888888888888888"
                                         "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                         "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                         "8888888";

    const char test_ecmp1_in_packet[] = "212223242526beef5d35a526080045000078000100007f007a2652515ffa0c0a030a8888888888888888888"
                                        "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                        "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                        "8888888";

    const char test_ecmp1_out_packet[] = "007777788814111213141516080045000078000100007e007b2652515ffa0c0a030a888888888888888888"
                                         "88888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                         "88888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                         "8888888888";

    const char test_ecmp2_in_packet[] = "212223242526beef5d35a526080045000078000100007f007a2452515ffa0c0a030c8888888888888888888"
                                        "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                        "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
                                        "8888888";

    const char test_ecmp2_out_packet[]
        = "005555566613111213141516080045000078000100007e007b2452515ffa0c0a030c8888888888888888888"
          "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
          "8888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888";

    size_t input_port = port_1_for_router;
    size_t output_port = port_2_for_router_1;
    size_t svi_input_port = port_3_for_bridge;
    size_t svi_output_port = port_4_svi_router;
    size_t router_to_svi_in_port = port_4_svi_router;
    size_t router_to_svi_out_port = port_3_for_bridge_2;

    size_t bridge_input_port = port_5_for_bridge;
    size_t bridge_out_port = port_3_for_bridge_1;

    size_t bridge_acc_input_port = port_3_for_bridge;
    size_t bridge_acc_out_port = port_5_for_bridge_1;

    size_t test_route_in_port = port_4_svi_router;
    size_t test_route_out_port = port_3_for_bridge_2;

    size_t test_ecmp1_in_port = port_4_svi_router;
    size_t test_ecmp1_out_port = port_5_for_bridge_2;
    size_t test_ecmp2_in_port = port_4_svi_router;
    size_t test_ecmp2_out_port = port_3_for_bridge_2;

    // 2-lane ports for this testcase
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

    //------- Send and receive the first router port to router port packet
    bool success = sim_ifc->inject_packet(packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    auto output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 1U);

    ASSERT_EQ(output_packets[0].packet, egress_packet);
    ASSERT_EQ(output_packets[0].slice, expected_output_info.slice);
    ASSERT_EQ(output_packets[0].ifg, expected_output_info.ifg);
    ASSERT_EQ(output_packets[0].pif, expected_output_info.pif);

    const sai_router_interface_stat_t router_counter_ids[] = {SAI_ROUTER_INTERFACE_STAT_IN_PACKETS,
                                                              SAI_ROUTER_INTERFACE_STAT_IN_OCTETS,
                                                              SAI_ROUTER_INTERFACE_STAT_OUT_PACKETS,
                                                              SAI_ROUTER_INTERFACE_STAT_OUT_OCTETS};

    uint64_t counters[array_size(router_counter_ids)] = {};
    sai_status_t status = rif_api->get_router_interface_stats_ext(m_rif_id_1,
                                                                  array_size(router_counter_ids),
                                                                  (const sai_stat_id_t*)router_counter_ids,
                                                                  SAI_STATS_MODE_READ_AND_CLEAR,
                                                                  counters);

    ASSERT_EQ(status, SAI_STATUS_SUCCESS);
    ASSERT_EQ(counters[0], 1U);
    ASSERT_EQ(counters[1], 68U);
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
    ASSERT_EQ(counters[3], 68U);

    sai_attribute_t attr{};
    sai_object_id_t obj_array[8];
    attr.value.objlist.list = obj_array;
    attr.value.objlist.count = 8;

    attr.id = SAI_PORT_ATTR_QOS_NUMBER_OF_QUEUES;
    status = port_api->get_port_attribute(ports[port_1_for_router], 1, &attr);
    ASSERT_EQ(status, SAI_STATUS_SUCCESS);
    int number_of_queue = get_attr_value(SAI_PORT_ATTR_QOS_NUMBER_OF_QUEUES, attr.value);
    ASSERT_EQ(number_of_queue, 8);

    attr.id = SAI_PORT_ATTR_QOS_QUEUE_LIST;
    status = port_api->get_port_attribute(ports[port_1_for_router], 1, &attr);
    ASSERT_EQ(status, SAI_STATUS_SUCCESS);

    std::vector<sai_object_id_t> vobj(attr.value.objlist.list, attr.value.objlist.list + attr.value.objlist.count);

    uint64_t q_counters[2];
    sai_queue_stat_t q_stat[2] = {SAI_QUEUE_STAT_PACKETS, SAI_QUEUE_STAT_DROPPED_PACKETS};
    for (auto q : vobj) {
        status = queue_api->get_queue_stats(q, 2, (const sai_stat_id_t*)q_stat, q_counters);
        ASSERT_EQ(status, SAI_STATUS_SUCCESS);
        // for now the stats always return error if we run on nsim
        // printf("obj = 0x%lx, enqueue = %ld, drop = %ld\n", q, q_counters[0], q_counters[1]);
    }

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

    // remove bridge flood system port
    status = lag_api->remove_lag_member(spa_mem_3_for_bridge_1);
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    std::this_thread::sleep_for(std::chrono::milliseconds{1000});

    /// send in flood packet again
    success = sim_ifc->inject_packet(bridge_packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 1U);

    size_t bridge_out_port2 = port_3_for_bridge_2;
    auto bridge_expected_output_info2 = lane_to_slice_ifg_pif(bridge_out_port2 * 2);
    ASSERT_EQ(output_packets[0].packet, bridge_out_packet);
    ASSERT_EQ(output_packets[0].slice, bridge_expected_output_info2.slice);
    ASSERT_EQ(output_packets[0].ifg, bridge_expected_output_info2.ifg);
    ASSERT_EQ(output_packets[0].pif, bridge_expected_output_info2.pif);

    add_port_to_lag(spa_mem_3_for_bridge_1, spa_3_for_bridge, ports[port_3_for_bridge_1]);

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

    /*
    set_bridge_flood_type(m_bridge_id, SAI_BRIDGE_FLOOD_CONTROL_TYPE_NONE);
    remove_mac_entry(vlan_10_obj, svi_acc_host);
    std::this_thread::sleep_for(std::chrono::milliseconds{200});

    success = sim_ifc->inject_packet(bridge_acc_packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 0U);
     */

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
    std::this_thread::sleep_for(std::chrono::milliseconds{500});

    success = sim_ifc->inject_packet(test_route_packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 0U);
}
