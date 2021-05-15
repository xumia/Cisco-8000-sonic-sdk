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

#include "common/gen_utils.h"
#include <../../build/src/auto_gen_attr.h>
#include "nsim_provider/nsim_test_flow.h"
#include "user_space_kernel.h"
#include "nsim/nsim.h"
#include "sai_test_utils.h"
#include "gtest/gtest.h"
#include <algorithm>
#include <iterator>
#include <numeric>
#include <string.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace std;
using namespace silicon_one;

class SimInjectSviTest : public ::testing::Test
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
    sai_virtual_router_api_t* vrf_api = nullptr;
    sai_fdb_api_t* fdb_api = nullptr;
    sai_neighbor_api_t* neighbor_api = nullptr;
    sai_route_api_t* route_api = nullptr;
    sai_hostif_api_t* hostif_api = nullptr;

    vector<sai_object_id_t> ports;

    sai_object_id_t switch_id{};
    sai_object_id_t vlan_1_obj{};
    sai_object_id_t vlan_10_obj{};

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

    sai_object_id_t nh_id1, nh_id2;

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
        configure_port(lane_from_slice_ifg_pif(3, 0, 8), 4); // Faceplate port 14
        configure_port(lane_from_slice_ifg_pif(1, 0, 8), 4); //
        // configure_port(lane_from_slice_ifg_pif(2, 1, 8), 4); // Faceplate port 16
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

        status = sai_api_query(SAI_API_BRIDGE, (void**)(&bridge_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(bridge_api, nullptr);

        status = sai_api_query(SAI_API_VLAN, (void**)(&vlan_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(vlan_api, nullptr);

        status = sai_api_query(SAI_API_BRIDGE, (void**)(&bridge_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(bridge_api, nullptr);

        status = sai_api_query(SAI_API_VLAN, (void**)(&vlan_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(vlan_api, nullptr);
    }

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

    void create_neighbor(sai_object_id_t rif_id, const char* ip_addr, const char* mac_addr)
    {
        sai_neighbor_entry_t nbr;
        uint32_t ip;

        sai_status_t status = str_to_ipv4(ip_addr, ip);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        nbr.switch_id = switch_id;
        nbr.rif_id = rif_id;
        nbr.ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        nbr.ip_address.addr.ip4 = ip;

        std::vector<sai_attribute_t> attrs;
        sai_attribute_t attr{};

        attr.id = SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS;
        str_to_mac(mac_addr, attr.value.mac);
        attrs.push_back(attr);

        status = neighbor_api->create_neighbor_entry(&nbr, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void remove_neighbor(sai_object_id_t rif_id, const char* ip_addr)
    {
        sai_neighbor_entry_t nbr;
        uint32_t ip;

        sai_status_t status = str_to_ipv4(ip_addr, ip);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        nbr.switch_id = switch_id;
        nbr.rif_id = rif_id;
        nbr.ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        nbr.ip_address.addr.ip4 = ip;

        status = neighbor_api->remove_neighbor_entry(&nbr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void create_nexthop(sai_object_id_t& nh_id, const char* ip_addr, sai_object_id_t rif_id)
    {
        uint32_t ip;

        std::vector<sai_attribute_t> attrs;
        sai_attribute_t attr{};

        attr.id = SAI_NEXT_HOP_ATTR_TYPE;
        set_attr_value(SAI_NEXT_HOP_ATTR_TYPE, attr.value, SAI_NEXT_HOP_TYPE_IP);
        attrs.push_back(attr);

        sai_status_t status = str_to_ipv4(ip_addr, ip);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        attr.id = SAI_NEXT_HOP_ATTR_IP;
        attr.value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        attr.value.ipaddr.addr.ip4 = ip;
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

        sai_status_t status = switch_api->set_switch_attribute(switch_id, (const sai_attribute_t*)&attr);
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
        uint32_t ip, ipmask;

        sai_route_entry_t route_entry;
        route_entry.switch_id = switch_id;
        route_entry.vr_id = vrf_id;
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;

        sai_status_t status = str_to_ipv4(route_prefix, ip);
        route_entry.destination.addr.ip4 = ip;

        status = str_to_ipv4(route_mask, ipmask);
        route_entry.destination.mask.ip4 = ipmask;

        sai_attribute_t attr;

        attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
        set_attr_value(SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, attr.value, nh_id);

        status = route_api->create_route_entry(&route_entry, 1, &attr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
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

    void setup_punt_path()
    {
        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};
        attr.id = SAI_SWITCH_ATTR_CPU_PORT;
        attrs.push_back(attr);

        sai_status_t status = switch_api->get_switch_attribute(switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(status, SAI_STATUS_SUCCESS);

        sai_object_id_t cpu_port_id = attrs[0].value.oid;
        create_route(m_default_vrf_id, local_ip1, "255.255.255.255", cpu_port_id);
        create_route(m_default_vrf_id, local_ip2, "255.255.255.255", cpu_port_id);
    }

    static void sai_packet_event_callback(sai_object_id_t switchid,
                                          sai_size_t buffer_size,
                                          const void* buffer,
                                          uint32_t attr_count,
                                          const sai_attribute_t* attr_list)
    {
        printf("switch id 0x%lx buffer size %lu buffer %p attr_count %u attr %p\n",
               switchid,
               buffer_size,
               buffer,
               attr_count,
               attr_list);

        if (attr_count > 0) {
            printf("attr id %d", attr_list->id);
            printf(" attr oid 0x%lx\n", attr_list->value.oid);
        }
    }

    void configure_notification()
    {
        sai_attribute_t attr{};
        attr.id = SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY;
        attr.value.ptr = (sai_pointer_t*)sai_packet_event_callback;

        sai_status_t status = switch_api->set_switch_attribute(switch_id, &attr);
        ASSERT_EQ(status, SAI_STATUS_SUCCESS);
    }

    void configure_topology()
    {
        sai_status_t status;
        // get default virtual router id for L3 configuration
        sai_attribute_t attr{};
        attr.id = SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID;

        status = switch_api->get_switch_attribute(switch_id, 1, &attr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        m_default_vrf_id = attr.value.oid;

        // Get Default 1Q bridge id
        attr.id = SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID;
        status = switch_api->get_switch_attribute(switch_id, 1, &attr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        m_bridge_id = attr.value.oid;

        configure_vlan(1, vlan_1_obj);
        configure_vlan(10, vlan_10_obj);

        // create svi router port
        configure_router_port(m_svi_rif_id, m_default_vrf_id, 0, SAI_ROUTER_INTERFACE_TYPE_VLAN, svi_mac, vlan_10_obj);
        create_bridge_port(m_svi_port_id, SAI_BRIDGE_PORT_TYPE_1Q_ROUTER, m_bridge_id, 0, 0, m_svi_rif_id);

        configure_router_port(m_rif_id_1, m_default_vrf_id, ports[port_1_for_router], SAI_ROUTER_INTERFACE_TYPE_PORT);
        configure_router_port(m_rif_id_2, m_default_vrf_id, ports[port_2_for_router], SAI_ROUTER_INTERFACE_TYPE_PORT);

        create_route(m_default_vrf_id, route_prefix1, route_prefix1_mask, m_rif_id_1);
        create_route(m_default_vrf_id, route_prefix2, route_prefix2_mask, m_rif_id_2);

        create_neighbor(m_rif_id_1, neighbor_ip1, neighbor_mac1);
        create_neighbor(m_rif_id_2, neighbor_ip2, neighbor_mac2);

        create_nexthop(nh_id1, neighbor_ip1, m_rif_id_1);
        create_nexthop(nh_id2, neighbor_ip2, m_rif_id_2);

        create_route(m_default_vrf_id, default_ip, default_ip_mask, SAI_NULL_OBJECT_ID);

        configure_notification();

        setup_punt_path();

        this_thread::sleep_for(chrono::seconds{1});
    }

    void deconfigure_topology()
    {
        sai_status_t status;

        // remove setup_punt_path
        remove_route(m_default_vrf_id, local_ip1, "255.255.255.255");
        remove_route(m_default_vrf_id, local_ip2, "255.255.255.255");

        remove_route(m_default_vrf_id, default_ip, default_ip_mask);

        status = nexthop_api->remove_next_hop(nh_id1);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = nexthop_api->remove_next_hop(nh_id2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        remove_neighbor(m_rif_id_1, neighbor_ip1);
        remove_neighbor(m_rif_id_2, neighbor_ip2);

        status = rif_api->remove_router_interface(m_rif_id_1);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = rif_api->remove_router_interface(m_rif_id_2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        // status = vrf_api->remove_virtual_router(m_default_vrf_id);
        // ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void SetUp()
    {
        vector<sai_attribute_t> attrs;
        sai_attribute_t attr{};
        sai_status_t status;

        // 1. Start simulator
        const char* dp = "/dev/testdev2";
        sim_ifc = create_and_run_simulator_server(nullptr, 0, dp);
        std::string sim_path = sim_ifc->get_connection_handle();
        sim_ifc->packet_dma_enable(true);
        // sim_ifc->set_log_file("/tmp/nsim.log", true);
        // sim_ifc->set_logging(true);

        // register the profile_get_value function
        sai_service_method_table_t service = {(sai_profile_get_value_fn)profile_get_value, nullptr};

        status = sai_api_initialize(0, &service);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        attr.value.s8list.count = sim_path.length() + 1; // include null terminator
        attr.value.s8list.list = (int8_t*)sim_path.c_str();

        // Start user space kernel thread
        m_kernel = new user_space_kernel();
        ASSERT_NE(m_kernel, nullptr);
        int ret = m_kernel->initialize(1 /*dev_id*/, sim_path.c_str());
        ASSERT_EQ(ret, 0);
        ret = m_kernel->start_listening_for_packets();
        ASSERT_EQ(ret, 0);
        attr.id = SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO;
        attrs.push_back(attr);

        get_apis();
        ASSERT_NE(switch_api->create_switch, nullptr);
        status = switch_api->create_switch(&switch_id, attrs.size(), attrs.data());
        if (status == SAI_STATUS_SUCCESS) {
            configure_ports();
        } else if (status == SAI_STATUS_ITEM_ALREADY_EXISTS) {
            for (int i = 0; i < 32; ++i) {
                ports.push_back(i + 1);
            }
        } else {
            ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        }
        configure_router_mac(router_mac);
        configure_topology();
    }

    void TearDown()
    {
        m_kernel->destroy();
        deconfigure_topology();
        deconfigure_ports();
        switch_api->remove_switch(switch_id);
        delete sim_ifc;
    }

    const char* router_mac = "00:01:02:03:04:05";
    const char* neighbor_mac1 = "00:06:06:06:06:06";
    const char* neighbor_mac2 = "00:07:07:07:07:07";
    const char* svi_mac = "10:12:13:14:15:16";

    const char* neighbor_ip1 = "192.168.1.6";
    const char* neighbor_ip2 = "192.169.1.7";
    const char* route_prefix1 = "192.168.0.0";
    const char* route_prefix1_mask = "255.255.0.0";
    const char* route_prefix2 = "192.169.0.0";
    const char* route_prefix2_mask = "255.255.0.0";

    const char* default_ip = "0.0.0.0";
    const char* default_ip_mask = "0.0.0.0";

    const char* local_ip1 = "192.168.0.1";
    const char* local_ip2 = "192.169.0.1";

    int port_1_for_router = 0;
    int port_2_for_router = 1;
};

TEST_F(SimInjectSviTest, route_fwd_nexthop)
{
    const char ingress_packet[]
        = "1012131415160006060606068100000a08004500002e000000004011f760c0a80106c0a90107003f003f001a0000000102030405"
          "060708090a0b0c0d0e0f1011cae8a318";
    // const char egress_packet[] =
    // "00070707070700010203040508004500002e000000003f11f860c0a80106c0a90107003f003f001a00000001020304050"
    //                            "60708090a0b0c0d0e0f1011cae8a318";

    // auto input_info = lane_to_slice_ifg_pif(port_1_for_router * 2);
    // auto expected_output_info = lane_to_slice_ifg_pif(port_2_for_router * 2);

    //------- inject up assumed received from the first router port to router port packet
    // const sai_router_interface_stat_t router_counter_ids[] = {SAI_ROUTER_INTERFACE_STAT_IN_PACKETS,
    //                                                         SAI_ROUTER_INTERFACE_STAT_IN_OCTETS,
    //                                                        SAI_ROUTER_INTERFACE_STAT_OUT_PACKETS,
    //                                                       SAI_ROUTER_INTERFACE_STAT_OUT_OCTETS};
    uint8_t ingress_pkt_buf[64];
    str_to_uint8(ingress_packet, ingress_pkt_buf, 64);

    sai_attribute_t attr_list[1];
    attr_list[0].id = SAI_HOSTIF_PACKET_ATTR_HOSTIF_TX_TYPE;

    // set up injectup type
    set_attr_value(SAI_HOSTIF_PACKET_ATTR_HOSTIF_TX_TYPE, attr_list[0].value, SAI_HOSTIF_TX_TYPE_PIPELINE_LOOKUP);

    // sai_log_set(SAI_API_SWITCH, SAI_LOG_LEVEL_DEBUG);

    sai_status_t status = hostif_api->send_hostif_packet(switch_id, 64, ingress_pkt_buf, 1 /*attr_list len*/, attr_list);
    ASSERT_EQ(status, SAI_STATUS_SUCCESS);

    std::this_thread::sleep_for(std::chrono::milliseconds{500});
}
