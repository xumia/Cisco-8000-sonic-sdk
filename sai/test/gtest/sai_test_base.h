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

#ifndef __SAI_TEST_BASE_H__
#define __SAI_TEST_BASE_H__

extern "C" {
#include <sai.h>
}
#include "sai_extra_apis.h"

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

using namespace std;
using namespace silicon_one;

class SaiTestBase : public ::testing::Test
{
private:
    user_space_kernel* m_kernel;

public:
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

public:
    static SaiTestBase* m_inst;
    int port_1_for_router = 0;
    int port_2_for_router = 1;

    nsim_provider* sim_ifc;

    sai_switch_api_t* switch_api = nullptr;
    sai_port_api_t* port_api = nullptr;
    sai_queue_api_t* queue_api = nullptr;
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
    sai_lag_api_t* lag_api = nullptr;

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

    sai_object_id_t nh_id1, nh_id2, nh_id3;

    bool is_sim = true;
    bool print_ports = false;

public:
    SaiTestBase()
    {
        m_inst = this;
    }
    void configure_port(int first_serdes_id, int num_serdes);
    void set_port_admin_state(sai_object_id_t port_id, bool enable);
    void set_all_ports_admin_state(bool enable);
    void configure_ports();
    void deconfigure_ports();
    void get_apis();
    void configure_router_port(sai_object_id_t& rif_id,
                               sai_object_id_t vrf_id,
                               int port_index,
                               sai_router_interface_type_t rif_type,
                               const char* mac_addr);
    void create_neighbor(sai_object_id_t rif_id, const char* ip_addr, const char* mac_addr);
    void remove_neighbor(sai_object_id_t rif_id, const char* ip_addr);
    void create_nexthop(sai_object_id_t& nh_id, const char* ip_addr, sai_object_id_t rif_id);
    void configure_router_mac(const char* macAddr);
    void create_route(sai_object_id_t vrf_id, const char* route_prefix, const char* route_mask, sai_object_id_t nh_id);
    void remove_route(sai_object_id_t vrf_id, const char* route_prefix, const char* route_mask);
    sai_status_t get_route(sai_object_id_t vrf_id, const char* route_prefix, const char* route_mask);
    void create_hostif_trap(sai_object_id_t& trap_obj, sai_hostif_trap_type_t trap_type, sai_packet_action_t action);
    static sai_status_t get_port_phy_loc(sai_object_id_t port_id, slice_ifg_pif& serdes_loc, uint32_t& num_of_serdes);
    void setup_punt_path();
    static void sai_packet_event_callback(sai_object_id_t switchid,
                                          sai_size_t buffer_size,
                                          const void* buffer,
                                          uint32_t attr_count,
                                          const sai_attribute_t* attr_list);
    static void sai_port_state_change_callback(uint32_t count, const sai_port_oper_status_notification_t* data);
    virtual void configure_notification();
    virtual void configure_topology();
    virtual void deconfigure_topology();
    void list_ports_info();
    void SetUp() override;
    void TearDown() override;
    virtual void test_attributes(sai_object_id_t switch_id){};
};

#endif
