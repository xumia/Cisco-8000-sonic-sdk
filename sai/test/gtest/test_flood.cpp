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

/*
 * Note: SAI Lane list is a flat number space from 0 - 215 on Pacific, but
 * simulator expects slice/ifg/pif for packet input.
 *
 * Based on first lane:
 *
 * Slice is: (lane / 18) / 2
 * IFG is:   (lane / 18) % 2
 * Pif is:    lane % 18
 */

class SimFloodTest : public ::testing::Test
{
public:
    nsim_provider* sim_ifc;
    user_space_kernel* m_kernel;
    sai_switch_api_t* switch_api = nullptr;
    sai_port_api_t* port_api = nullptr;
    sai_bridge_api_t* bridge_api = nullptr;

    sai_object_id_t switch_id{};

    vector<sai_object_id_t> ports;
    vector<sai_object_id_t> bridges;
    vector<sai_object_id_t> bridge_ports;

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
        set_attr_value(SAI_PORT_ATTR_SPEED, attr.value, 25000); // 25G
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
        int serdes_per_port = 1;
        for (int ifg_idx = 0; ifg_idx < 12; ifg_idx++) {
            for (int i = 0; i < 18; i = i + serdes_per_port) {
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

    void configure_bridge()
    {
        sai_object_id_t bridge_id{};

        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        attr.id = SAI_BRIDGE_ATTR_TYPE;
        set_attr_value(SAI_BRIDGE_ATTR_TYPE, attr.value, SAI_BRIDGE_TYPE_1D);
        attrs.push_back(attr);

        sai_status_t status = bridge_api->create_bridge(&bridge_id, switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        bridges.push_back(bridge_id);
    }

    void configure_bridges()
    {
        for (int i = 0; i < 16; ++i) {
            configure_bridge();
        }
    }

    void deconfigure_bridges()
    {
        for (auto b : bridges) {
            bridge_api->remove_bridge(b);
        }
    }

    void configure_bridge_port(int bridge_index, int port_index)
    {
        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        attr.id = SAI_BRIDGE_PORT_ATTR_TYPE;
        set_attr_value(SAI_BRIDGE_PORT_ATTR_TYPE, attr.value, SAI_BRIDGE_PORT_TYPE_SUB_PORT);
        attrs.push_back(attr);

        attr.id = SAI_BRIDGE_PORT_ATTR_BRIDGE_ID;
        set_attr_value(SAI_BRIDGE_PORT_ATTR_BRIDGE_ID, attr.value, bridges[bridge_index]);
        attrs.push_back(attr);

        attr.id = SAI_BRIDGE_PORT_ATTR_PORT_ID;
        set_attr_value(SAI_BRIDGE_PORT_ATTR_PORT_ID, attr.value, ports[port_index]);
        attrs.push_back(attr);

        attr.id = SAI_BRIDGE_PORT_ATTR_VLAN_ID;
        set_attr_value(SAI_BRIDGE_PORT_ATTR_VLAN_ID, attr.value, (100 + bridge_index));
        attrs.push_back(attr);

        sai_object_id_t bridge_port_id{};

        sai_status_t status = bridge_api->create_bridge_port(&bridge_port_id, switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        bridge_ports.push_back(bridge_port_id);
    }

    void configure_bridge_ports()
    {
        for (int i = 0; i < 16; ++i) {
            configure_bridge_port(i, 2 * i);
            configure_bridge_port(i, 2 * i + 1);
        }
    }

    void deconfigure_bridge_ports()
    {
        for (auto bport : bridge_ports) {
            bridge_api->remove_bridge_port(bport);
        }
    }

    void configure_topology()
    {
        configure_ports();
        configure_bridges();
        configure_bridge_ports();
    }

    void deconfigure_topology()
    {
        deconfigure_bridge_ports();
        deconfigure_bridges();
        deconfigure_ports();
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
    }

    void SetUp() override
    {
        // 1. Start simulator
        const char* dp = "/dev/testdev2";
        sim_ifc = create_and_run_simulator_server(nullptr, 0, dp);
        std::string sim_path = sim_ifc->get_connection_handle();

        // register the profile_get_value function
        sai_service_method_table_t service = {(sai_profile_get_value_fn)profile_get_value, nullptr};

        sai_status_t status = sai_api_initialize(0, &service);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        // 2. Initialize switch, using sim_path as SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO
        get_apis();

        m_kernel = new user_space_kernel();
        ASSERT_NE(m_kernel, nullptr);
        int ret = m_kernel->initialize(1 /*dev_id*/, sim_path.c_str());
        ASSERT_EQ(ret, 0);
        ret = m_kernel->start_listening_for_packets();
        ASSERT_EQ(ret, 0);

        ASSERT_NE(switch_api->create_switch, nullptr);

        // sai_log_set(SAI_API_PORT, SAI_LOG_LEVEL_DEBUG);

        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        attr.id = SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO;
        attr.value.s8list.count = sim_path.length() + 1; // include null terminator
        attr.value.s8list.list = (int8_t*)sim_path.c_str();

        attrs.push_back(attr);

        status = switch_api->create_switch(&switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        // 3. Configure the topology.
        configure_topology();

        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }

    void TearDown() override
    {
        m_kernel->destroy();
        deconfigure_topology();
        switch_api->remove_switch(switch_id);
        delete sim_ifc;
    }
};

TEST_F(SimFloodTest, P2PTest)
{
    const char ingress_packet[] = "cafecafecafedeaddeaddead0800450000280001000040067ccd7f0000017f0000010014005000000000000000005002"
                                  "2000917c0000000000000000";
    const char egress_packet[] = "cafecafecafedeaddeaddead0800450000280001000040067ccd7f0000017f00000100140050000000000000000050022"
                                 "000917c0000000000000000";

    for (size_t input_port = 0; input_port < 18; ++input_port) {
        auto output_port = input_port ^ 0x1; // 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, ...

        // 1-lane ports for this testcase
        auto input_info = lane_to_slice_ifg_pif(input_port * 1);
        auto expected_output_info = lane_to_slice_ifg_pif(output_port * 1);

        sim_packet_info_desc packet_desc
            = {.packet = ingress_packet, .slice = input_info.slice, .ifg = input_info.ifg, .pif = input_info.pif};

        // Send and receive the packet
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

        const sai_bridge_port_stat_t counter_ids[] = {SAI_BRIDGE_PORT_STAT_IN_PACKETS,
                                                      SAI_BRIDGE_PORT_STAT_IN_OCTETS,
                                                      SAI_BRIDGE_PORT_STAT_OUT_PACKETS,
                                                      SAI_BRIDGE_PORT_STAT_OUT_OCTETS};
        uint64_t counters[array_size(counter_ids)] = {};

        sai_status_t status = bridge_api->get_bridge_port_stats_ext(bridge_ports[input_port],
                                                                    array_size(counter_ids),
                                                                    (const sai_stat_id_t*)counter_ids,
                                                                    SAI_STATS_MODE_READ_AND_CLEAR,
                                                                    counters);

        ASSERT_EQ(status, SAI_STATUS_SUCCESS);
        ASSERT_EQ(counters[0], 1U);
        ASSERT_GT(counters[1], 0U);
        ASSERT_EQ(counters[2], 0U);
        ASSERT_EQ(counters[3], 0U);

        status = bridge_api->get_bridge_port_stats_ext(bridge_ports[output_port],
                                                       array_size(counter_ids),
                                                       (const sai_stat_id_t*)counter_ids,
                                                       SAI_STATS_MODE_READ_AND_CLEAR,
                                                       counters);

        ASSERT_EQ(status, SAI_STATUS_SUCCESS);
        ASSERT_EQ(counters[0], 0U);
        ASSERT_EQ(counters[1], 0U);
        ASSERT_EQ(counters[2], 1U);
        ASSERT_GT(counters[3], 0U);
    }
}
