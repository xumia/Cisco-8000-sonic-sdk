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
#include "user_space_kernel.h"
#include "nsim_provider/nsim_test_flow.h"
#include "nsim/nsim.h"
#include "sai_test_utils.h"
#include "gtest/gtest.h"
#include <algorithm>
#include <../../build/src/auto_gen_attr.h>
#include <iterator>
#include <numeric>
#include <thread>
#include <vector>
#include "sai_test_base.h"

using namespace std;
using namespace silicon_one;

class SimPuntSviTest : public SaiTestBase
{
public:
    /*
        nsim_provider* sim_ifc;
        user_space_kernel *m_kernel;
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

        */

    sai_object_id_t vlan_1_obj{};
    sai_object_id_t vlan_10_obj{};
    sai_object_id_t m_vlan_mem_id1{};
    sai_object_id_t m_vlan_mem_id2{};

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
        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        // Get Default 1Q bridge id
        attr.id = SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID;
        status = switch_api->get_switch_attribute(switch_id, 1, &attr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        m_bridge_id = attr.value.oid;

        // configure_vlan(1, vlan_1_obj);
        configure_vlan(10, vlan_10_obj);

        create_bridge_port(m_bridge_port_id2, SAI_BRIDGE_PORT_TYPE_PORT, m_bridge_id, ports[port_5_for_bridge], 0, 0, false);
        create_bridge_port(m_bridge_port_id, SAI_BRIDGE_PORT_TYPE_PORT, m_bridge_id, ports[port_3_for_bridge], 0, 0, false);

        configure_vlan_member(m_vlan_mem_id2, vlan_10_obj, m_bridge_port_id2, false);
        configure_vlan_member(m_vlan_mem_id1, vlan_10_obj, m_bridge_port_id, true);

        create_mac_entry(vlan_10_obj, svi_acc_host, m_bridge_port_id2);

        // create L3 configuration
        attr.id = SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID;

        status = switch_api->get_switch_attribute(switch_id, 1, &attr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        m_default_vrf_id = attr.value.oid;

        // create svi router port

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

    void deconfigure_topology() override
    {
        sai_status_t status;

        // remove setup_punt_path
        remove_route(m_default_vrf_id, local_ip1, "255.255.255.255");
        remove_route(m_default_vrf_id, local_ip2, "255.255.255.255");
        remove_mac_entry(vlan_10_obj, svi_acc_host);

        remove_route(m_default_vrf_id, default_ip, default_ip_mask);

        remove_neighbor(m_rif_id_1, neighbor_ip1);
        remove_neighbor(m_rif_id_2, neighbor_ip2);

        status = nexthop_api->remove_next_hop(nh_id1);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = nexthop_api->remove_next_hop(nh_id2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = rif_api->remove_router_interface(m_rif_id_1);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = rif_api->remove_router_interface(m_rif_id_2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = rif_api->remove_router_interface(m_svi_rif_id);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = vlan_api->remove_vlan_member(m_vlan_mem_id1);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = vlan_api->remove_vlan_member(m_vlan_mem_id2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = bridge_api->remove_bridge_port(m_bridge_port_id2);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        status = bridge_api->remove_bridge_port(m_bridge_port_id);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        status = vlan_api->remove_vlan(vlan_10_obj);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    const char* router_mac = "00:01:02:03:04:05";
    const char* neighbor_mac1 = "00:06:06:06:06:06";
    const char* neighbor_mac2 = "00:07:07:07:07:07";

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

    const char* svi_mac = "11:12:13:14:15:16";

    const char* svi_acc_host = "00:00:00:33:55:55";

    int port_1_for_router = 0;
    int port_2_for_router = 1;
    int port_3_for_bridge = 2;
    int port_4_svi_router = 3;
    int port_5_for_bridge = 4;
    uint16_t VLAN_10 = 10;
};

TEST_F(SimPuntSviTest, basic_route)
{
    //------- punt packet tagged packet to tagged port
    const char punt_packet[]
        = "1112131415160006060606068100000a08004500002e000000004011f866c0a80106c0a90001003f003f001a0000000102030405"
          "060708090a0b0c0d0e0f1011cae8a318";

    auto input_info = lane_to_slice_ifg_pif(port_3_for_bridge * 2);

    sim_packet_info_desc punt_packet_desc
        = {.packet = punt_packet, .slice = input_info.slice, .ifg = input_info.ifg, .pif = input_info.pif};

    bool success = sim_ifc->inject_packet(punt_packet_desc);
    ASSERT_EQ(success, true);
    std::this_thread::sleep_for(std::chrono::milliseconds{500});

    success = sim_ifc->step_packet();

    auto output_packets = sim_ifc->get_packets();

    //------- punt packet untagged packet to untagged port
    const char untag_punt_packet[]
        = "11121314151600060606060608004500002e000000004011f866c0a80106c0a90001003f003f001a0000000102030405"
          "060708090a0b0c0d0e0f1011cae8a318";

    input_info = lane_to_slice_ifg_pif(port_5_for_bridge * 2);

    punt_packet_desc = {.packet = untag_punt_packet, .slice = input_info.slice, .ifg = input_info.ifg, .pif = input_info.pif};

    //------- punt packet
    success = sim_ifc->inject_packet(punt_packet_desc);
    ASSERT_EQ(success, true);
    std::this_thread::sleep_for(std::chrono::milliseconds{600});

    success = sim_ifc->step_packet();

    output_packets = sim_ifc->get_packets();
}
