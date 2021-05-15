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

#include <algorithm>
#include <../../build/src/auto_gen_attr.h>
#include <iterator>
#include <numeric>
#include <thread>
#include <vector>
#include "common/gen_utils.h"
#include "user_space_kernel.h"
#include "nsim_provider/nsim_test_flow.h"
#include "nsim/nsim.h"
#include "sai_test_utils.h"
#include "sai_test_base.h"
#include "gtest/gtest.h"

using namespace std;
using namespace silicon_one;

SaiTestBase* SaiTestBase::m_inst = nullptr;

void
SaiTestBase::configure_port(int first_serdes_id, int num_serdes)
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

    sai_status_t status = port_api->create_port(&port_id, switch_id, attrs.size(), attrs.data());
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);

    ports.push_back(port_id);
}

void
SaiTestBase::set_port_admin_state(sai_object_id_t port_id, bool enable)
{
    sai_attribute_t attr{};

    attr.id = SAI_PORT_ATTR_ADMIN_STATE;
    set_attr_value(SAI_PORT_ATTR_ADMIN_STATE, attr.value, enable);

    sai_status_t status = port_api->set_port_attribute(port_id, &attr);
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);
}

void
SaiTestBase::set_all_ports_admin_state(bool enable)
{
    for (auto p : ports) {
        set_port_admin_state(p, enable);
    }
}

void
SaiTestBase::configure_ports()
{
    int serdes_per_port = 2;
    for (int ifg_idx = 0; ifg_idx < 4; ifg_idx++) {
        for (int i = 0; i < 16; i = i + serdes_per_port) {
            int pif = (ifg_idx << 8) + i;
            configure_port(pif, serdes_per_port);
        }
    }
}

void
SaiTestBase::deconfigure_ports()
{
    for (auto p : ports) {
        port_api->remove_port(p);
    }
}

void
SaiTestBase::get_apis()
{
    sai_status_t status = sai_api_query(SAI_API_SWITCH, (void**)(&switch_api));
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    ASSERT_NE(switch_api, nullptr);

    status = sai_api_query(SAI_API_PORT, (void**)(&port_api));
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    ASSERT_NE(port_api, nullptr);

    status = sai_api_query(SAI_API_QUEUE, (void**)(&queue_api));
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    ASSERT_NE(queue_api, nullptr);

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

    status = sai_api_query(SAI_API_VLAN, (void**)(&vlan_api));
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    ASSERT_NE(vlan_api, nullptr);

    status = sai_api_query(SAI_API_HOSTIF, (void**)(&hostif_api));
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    ASSERT_NE(hostif_api, nullptr);

    status = sai_api_query(SAI_API_LAG, (void**)(&lag_api));
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    ASSERT_NE(lag_api, nullptr);
}

void
SaiTestBase::configure_router_port(sai_object_id_t& rif_id,
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

void
SaiTestBase::create_neighbor(sai_object_id_t rif_id, const char* ip_addr, const char* mac_addr)
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

    sai_attribute_t attr_ret{};
    attr_ret.id = SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS;
    status = neighbor_api->get_neighbor_entry_attribute(&nbr, 1, &attr_ret);
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    int cmp_res = memcmp(attr_ret.value.mac, attr.value.mac, 6);
    ASSERT_EQ(cmp_res, 0);
}

void
SaiTestBase::remove_neighbor(sai_object_id_t rif_id, const char* ip_addr)
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

void
SaiTestBase::create_nexthop(sai_object_id_t& nh_id, const char* ip_addr, sai_object_id_t rif_id)
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

void
SaiTestBase::configure_router_mac(const char* macAddr)
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
void
SaiTestBase::create_route(sai_object_id_t vrf_id, const char* route_prefix, const char* route_mask, sai_object_id_t nh_id)
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

    sai_attribute_t attr_ret{};
    attr_ret.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
    status = route_api->get_route_entry_attribute(&route_entry, 1, &attr_ret);
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);
}

void
SaiTestBase::remove_route(sai_object_id_t vrf_id, const char* route_prefix, const char* route_mask)
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

void
SaiTestBase::create_hostif_trap(sai_object_id_t& trap_obj, sai_hostif_trap_type_t trap_type, sai_packet_action_t action)
{
    vector<sai_attribute_t> attrs;

    sai_attribute_t attr{};

    attr.id = SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE;
    set_attr_value(SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE, attr.value, trap_type);
    attrs.push_back(attr);

    attr.id = SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION;
    set_attr_value(SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION, attr.value, action);
    attrs.push_back(attr);

    sai_status_t status = hostif_api->create_hostif_trap(&trap_obj, switch_id, attrs.size(), attrs.data());
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);
}

sai_status_t
SaiTestBase::get_route(sai_object_id_t vrf_id, const char* route_prefix, const char* route_mask)
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

sai_status_t
SaiTestBase::get_port_phy_loc(sai_object_id_t port_id, slice_ifg_pif& serdes_loc, uint32_t& num_of_serdes)
{
    sai_status_t status;
    uint32_t lanes[16];
    sai_attribute_t attr{};

    attr.id = SAI_PORT_ATTR_HW_LANE_LIST;
    attr.value.u32list.count = 16;
    attr.value.u32list.list = lanes;

    m_inst->port_api->get_port_attribute(port_id, 1, &attr);
    status = m_inst->port_api->get_port_attribute(port_id, 1, &attr);

    serdes_loc = lane_to_slice_ifg_pif(attr.value.u32list.list[0]);
    num_of_serdes = attr.value.u32list.count;

    return status;
}

void
SaiTestBase::setup_punt_path()
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

void
SaiTestBase::sai_packet_event_callback(sai_object_id_t switchid,
                                       sai_size_t buffer_size,
                                       const void* buffer,
                                       uint32_t attr_count,
                                       const sai_attribute_t* attr_list)
{
    printf(
        "switch id 0x%lx buffer size %lu buffer %p attr_count %u attr %p\n", switchid, buffer_size, buffer, attr_count, attr_list);

    if (attr_count > 0) {
        printf("attr id %d", attr_list->id);
        printf(" attr oid 0x%lx\n", attr_list->value.oid);
    }
}

void
SaiTestBase::sai_port_state_change_callback(uint32_t count, const sai_port_oper_status_notification_t* data)
{
    slice_ifg_pif serdes_loc{};
    uint32_t num_of_serdes = 0;

    sai_status_t status;
    for (uint32_t idx = 0; idx < count; idx++) {
        status = get_port_phy_loc(data[idx].port_id, serdes_loc, num_of_serdes);

        if (status != SAI_STATUS_SUCCESS) {
            printf("ERROR: unable to get_port_phy_loc: sai_object_id(0x%lx)", data[idx].port_id);
            continue;
        }

        printf("SAI_PORT_ID[0x%lx]: mac_port[%d/%d/%d] lanes(%d) : %s\n",
               data[idx].port_id,
               serdes_loc.slice,
               serdes_loc.ifg,
               serdes_loc.pif,
               num_of_serdes,
               (to_string(data[idx].port_state)).c_str());
    }
}

void
SaiTestBase::configure_notification()
{
    sai_attribute_t attr{};
    attr.id = SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY;
    attr.value.ptr = (sai_pointer_t)sai_packet_event_callback;

    sai_status_t status = switch_api->set_switch_attribute(switch_id, &attr);
    ASSERT_EQ(status, SAI_STATUS_SUCCESS);

    attr.id = SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY;
    attr.value.ptr = (sai_pointer_t)sai_port_state_change_callback;

    status = switch_api->set_switch_attribute(switch_id, &attr);
    ASSERT_EQ(status, SAI_STATUS_SUCCESS);
}

void
SaiTestBase::configure_topology()
{
    sai_status_t status;

    // create L3 configuration
    sai_attribute_t attr{};
    attr.id = SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID;

    status = switch_api->get_switch_attribute(switch_id, 1, &attr);
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);

    m_default_vrf_id = attr.value.oid;

    configure_router_port(m_rif_id_1, m_default_vrf_id, port_1_for_router, SAI_ROUTER_INTERFACE_TYPE_PORT);
    configure_router_port(m_rif_id_2, m_default_vrf_id, port_2_for_router, SAI_ROUTER_INTERFACE_TYPE_PORT);

    create_route(m_default_vrf_id, route_prefix1, route_prefix1_mask, m_rif_id_1);
    create_route(m_default_vrf_id, route_prefix2, route_prefix2_mask, m_rif_id_2);

    create_neighbor(m_rif_id_1, neighbor_ip1, neighbor_mac1);
    create_neighbor(m_rif_id_2, neighbor_ip2, neighbor_mac2);

    create_nexthop(nh_id1, neighbor_ip1, m_rif_id_1);
    create_nexthop(nh_id2, neighbor_ip2, m_rif_id_2);

    create_route(m_default_vrf_id, default_ip, default_ip_mask, SAI_NULL_OBJECT_ID);

    configure_notification();

    setup_punt_path();

    std::this_thread::sleep_for(std::chrono::milliseconds{600});
}

void
SaiTestBase::deconfigure_topology()
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

void
SaiTestBase::list_ports_info()
{
    printf("====================================================================================================\n"
           "==== list ports info ====\n");

    sai_status_t status;

    sai_attribute_t attr{};
    attr.id = SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS;
    status = switch_api->get_switch_attribute(switch_id, 1, &attr);
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    printf("SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS: %d\n", attr.value.u32);
    uint32_t num_of_active_port = attr.value.u32;

    struct print_t {
        sai_object_id_t oid;
        slice_ifg_pif serdes_loc;
        uint32_t num_of_serdes;
        bool admin_state;
        uint32_t port_speed;
        sai_port_internal_loopback_mode_t ilb_mode;
        sai_port_fec_mode_t fec_mode;
        sai_port_oper_status_t port_status;
        bool an_enable;
        uint32_t mtu_size;
    };

    print_t ports_info[num_of_active_port];

    // get activate port id
    attr.id = SAI_SWITCH_ATTR_PORT_LIST;
    sai_object_id_t port_id_list[num_of_active_port];
    attr.value.objlist.count = num_of_active_port;
    attr.value.objlist.list = port_id_list;
    status = switch_api->get_switch_attribute(switch_id, 1, &attr);
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    for (uint32_t i = 0; i < attr.value.objlist.count; i++) {
        ports_info[i].oid = port_id_list[i];
    }

    slice_ifg_pif serdes_loc = {0, 0, 0};
    uint32_t num_of_serdes = 0;
    for (uint32_t i = 0; i < num_of_active_port; i++) {
        status = get_port_phy_loc(ports_info[i].oid, serdes_loc, num_of_serdes);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ports_info[i].serdes_loc = serdes_loc;
        ports_info[i].num_of_serdes = num_of_serdes;
    }

    sai_attribute_t attr_list[10];
    attr_list[0].id = SAI_PORT_ATTR_OPER_STATUS;
    attr_list[1].id = SAI_PORT_ATTR_FEC_MODE;
    attr_list[2].id = SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE;
    attr_list[3].id = SAI_PORT_ATTR_AUTO_NEG_MODE;
    attr_list[4].id = SAI_PORT_ATTR_SPEED;
    attr_list[5].id = SAI_PORT_ATTR_MTU;
    attr_list[6].id = SAI_PORT_ATTR_ADMIN_STATE;
    uint32_t num_of_attr = 7;

    for (uint32_t i = 0; i < num_of_active_port; i++) {
        status = port_api->get_port_attribute(ports_info[i].oid, num_of_attr, attr_list);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        ports_info[i].port_status = get_attr_value(SAI_PORT_ATTR_OPER_STATUS, attr_list[0].value);
        ports_info[i].fec_mode = get_attr_value(SAI_PORT_ATTR_FEC_MODE, attr_list[1].value);
        ports_info[i].ilb_mode = get_attr_value(SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE, attr_list[2].value);
        ports_info[i].an_enable = get_attr_value(SAI_PORT_ATTR_AUTO_NEG_MODE, attr_list[3].value);
        ports_info[i].port_speed = get_attr_value(SAI_PORT_ATTR_SPEED, attr_list[4].value);
        ports_info[i].mtu_size = get_attr_value(SAI_PORT_ATTR_MTU, attr_list[5].value);
        ports_info[i].admin_state = get_attr_value(SAI_PORT_ATTR_ADMIN_STATE, attr_list[6].value);
    }

    // Now, we can print the information of each port...
    printf("SAI_SWITCH_ATTR_PORT_LIST:\n\tOBJ_ID\t\tLocation\tStatus\tSPEED(Gbps)\tFEC\tILB\tAN/LT\tMTU\n");
    for (uint32_t i = 0; i < num_of_active_port; i++) {
        printf("= 0x%lx\t[%d/%d/%d-%d]\t%s-%d\t%d\t\t%d\t%d\t%d\t%d\n",
               ports_info[i].oid,
               ports_info[i].serdes_loc.slice,
               ports_info[i].serdes_loc.ifg,
               ports_info[i].serdes_loc.pif,
               ports_info[i].num_of_serdes,
               (ports_info[i].admin_state == true) ? "EN" : "DIS",
               ports_info[i].port_status,
               ports_info[i].port_speed / 1000,
               ports_info[i].fec_mode,
               ports_info[i].ilb_mode,
               ports_info[i].an_enable,
               ports_info[i].mtu_size);
    }

    printf("====================================================================================================\n");
}

void
SaiTestBase::SetUp()
{
    vector<sai_attribute_t> attrs;
    sai_attribute_t attr{};
    sai_status_t status;

    const sai_service_method_table_t service = {(sai_profile_get_value_fn)profile_get_value, nullptr};

    if (is_sim) {
        // 1. Start simulator
        const char* dp = "/dev/testdev2";
        sim_ifc = create_and_run_simulator_server(nullptr, 0, dp);
        std::string sim_path = sim_ifc->get_connection_handle();
        sim_ifc->packet_dma_enable(true);
        // sim_ifc->set_log_file("/tmp/nsim.log", true);
        sim_ifc->set_logging(true);
        // sai_log_set(SAI_API_MAX, SAI_LOG_LEVEL_DEBUG);

        attr.value.s8list.count = sim_path.length() + 1; // include null terminator
        attr.value.s8list.list = (int8_t*)sim_path.c_str();

        // Start user space kernel thread
        m_kernel = new user_space_kernel();
        ASSERT_NE(m_kernel, nullptr);
        int ret = m_kernel->initialize(1 /*dev_id*/, sim_path.c_str());
        ASSERT_EQ(ret, 0);
        ret = m_kernel->start_listening_for_packets();
        ASSERT_EQ(ret, 0);
    } else {
        // Start HW
        const std::string dp = "/dev/uio0";
        attr.value.s8list.count = dp.length() + 1; // include null terminator
        attr.value.s8list.list = (int8_t*)dp.c_str();
    }

    attr.id = SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO;
    attrs.push_back(attr);

    // register the profile_get_value function
    status = sai_api_initialize(0, &service);
    ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    sai_logging_param_set(0, 1);

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
    set_all_ports_admin_state(true);

    // wait for all mac_port to come up
    if (is_sim) {
        std::this_thread::sleep_for(std::chrono::milliseconds{2000});
    } else {
        std::this_thread::sleep_for(std::chrono::milliseconds{10000});
    }

    if (print_ports) {
        list_ports_info();
    }

    test_attributes(switch_id);
}

void
SaiTestBase::TearDown()
{
    m_kernel->destroy();
    deconfigure_topology();
    deconfigure_ports();
    switch_api->remove_switch(switch_id);
    delete sim_ifc;
}
