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

class SimFloodAndLearnTest : public ::testing::Test
{
public:
    nsim_provider* sim_ifc;
    user_space_kernel* m_kernel;
    sai_switch_api_t* switch_api = nullptr;
    sai_port_api_t* port_api = nullptr;
    sai_bridge_api_t* bridge_api = nullptr;
    sai_fdb_api_t* fdb_api = nullptr;
    sai_object_id_t switch_id{};

    vector<sai_object_id_t> ports;
    vector<sai_object_id_t> bridges;
    vector<sai_object_id_t> bridge_ports;

    vector<uint32_t> la_ports;

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

        // status = port_api->set_mac_learning_mode(silicon_one::la_l2_service_port::la_lp_mac_learning_mode_e::STANDALONE);
        // ASSERT_EQ(SAI_STATUS_SUCCESS, status);
    }

    void configure_ports()
    {
        // Create following ports to cover the combinations
        // Same slice same ifg
        // Same slice different ifg
        // Different slice even ifg
        // Different slice odd ifg
        // Rest of the slices
        la_ports.push_back(lane_from_slice_ifg_pif(1, 0, 0));
        la_ports.push_back(lane_from_slice_ifg_pif(1, 0, 2));
        la_ports.push_back(lane_from_slice_ifg_pif(1, 1, 0));
        la_ports.push_back(lane_from_slice_ifg_pif(3, 0, 0));
        la_ports.push_back(lane_from_slice_ifg_pif(4, 1, 0));
        la_ports.push_back(lane_from_slice_ifg_pif(0, 0, 0));
        la_ports.push_back(lane_from_slice_ifg_pif(0, 1, 0));
        la_ports.push_back(lane_from_slice_ifg_pif(2, 0, 0));
        la_ports.push_back(lane_from_slice_ifg_pif(2, 1, 0));
        la_ports.push_back(lane_from_slice_ifg_pif(5, 0, 0));
        la_ports.push_back(lane_from_slice_ifg_pif(5, 1, 0));

        for (auto p : la_ports) {
            configure_port(p, 2);
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
        set_attr_value(SAI_BRIDGE_PORT_ATTR_TYPE, attr.value, SAI_BRIDGE_PORT_TYPE_PORT);
        attrs.push_back(attr);

        attr.id = SAI_BRIDGE_PORT_ATTR_BRIDGE_ID;
        set_attr_value(SAI_BRIDGE_PORT_ATTR_BRIDGE_ID, attr.value, bridges[bridge_index]);
        attrs.push_back(attr);

        attr.id = SAI_BRIDGE_PORT_ATTR_PORT_ID;
        set_attr_value(SAI_BRIDGE_PORT_ATTR_PORT_ID, attr.value, ports[port_index]);
        attrs.push_back(attr);

        sai_object_id_t bridge_port_id{};

        sai_status_t status = bridge_api->create_bridge_port(&bridge_port_id, switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        bridge_ports.push_back(bridge_port_id);
    }

    void configure_bridge_ports()
    {
        for (uint i = 0; i < la_ports.size(); ++i) {
            configure_bridge_port(0, i);
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

        status = sai_api_query(SAI_API_FDB, (void**)(&fdb_api));
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_NE(fdb_api, nullptr);
    }

    void get_mac_entry(sai_object_id_t bridge, const char* bridge_mac, sai_object_id_t port_id)
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

        // sai_status_t status
        //     = fdb_api->get_fdb_entry_attribute(&fdb_entry, SAI_FDB_ENTRY_ATTR_END - SAI_FDB_ENTRY_ATTR_START, attrs.data());
        // ASSERT_NE(SAI_STATUS_SUCCESS, status);
    }

    void SetUp() override
    {
        // 1. Start simulator
        const char* dp = "/dev/testdev2";
        sim_ifc = create_and_run_simulator_server(nullptr, 0, dp);
        // sim_ifc->set_logging(true);
        std::string sim_path = sim_ifc->get_connection_handle();

        // register the profile_get_value function
        sai_service_method_table_t service = {(sai_profile_get_value_fn)profile_get_value, nullptr};

        sai_status_t status = sai_api_initialize(0, &service);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        // 2. Initialize switch, using sim_path as SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO
        get_apis();
        ASSERT_NE(switch_api->create_switch, nullptr);

        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        // Start user space kernel thread
        m_kernel = new user_space_kernel();
        ASSERT_NE(m_kernel, nullptr);
        int ret = m_kernel->initialize(1 /*dev_id*/, sim_path.c_str());
        ASSERT_EQ(ret, 0);
        ret = m_kernel->start_listening_for_packets();
        ASSERT_EQ(ret, 0);

        attr.id = SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO;
        attr.value.s8list.count = sim_path.length() + 1; // include null terminator
        attr.value.s8list.list = (int8_t*)sim_path.c_str();

        attrs.push_back(attr);

        status = switch_api->create_switch(&switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        // sai_log_set(SAI_API_ROUTE, SAI_LOG_LEVEL_DEBUG);

        // 3. Configure the topology.
        configure_topology();

        attr = {0};
        attr.id = SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE;
        attr.value.s32 = SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW;

        for (auto bport : bridge_ports) {
            status = bridge_api->set_bridge_port_attribute(bport, &attr);
            ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        }

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

TEST_F(SimFloodAndLearnTest, P2PTest)
{
    const char ingress_packet[] = "cafecafecafedeaddeaddead0800450000280001000040067ccd7f0000017f0000010014005000000000000000005002"
                                  "2000917c0000000000000000";
    const char egress_packet[] = "cafecafecafedeaddeaddead0800450000280001000040067ccd7f0000017f00000100140050000000000000000050022"
                                 "000917c0000000000000000";
    const char ingress_packet2[] = "deaddeaddeadcafecafecafe0800450000280001000040067ccd7f0000017f000001001400500000000000000000500"
                                   "22000917c0000000000000000";
    const char egress_packet2[] = "deaddeaddeadcafecafecafe0800450000280001000040067ccd7f0000017f0000010014005000000000000000005002"
                                  "2000917c0000000000000000";

    std::this_thread::sleep_for(std::chrono::milliseconds{1000});

    // 2-lane ports for this testcase
    auto input_info = lane_to_slice_ifg_pif(la_ports[0]); // port 0

    sim_packet_info_desc packet_desc
        = {.packet = ingress_packet, .slice = input_info.slice, .ifg = input_info.ifg, .pif = input_info.pif};

    // Send packet on port 0, expect packet received on port 1 and 2
    bool success = sim_ifc->inject_packet(packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    auto output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), la_ports.size() - 1); // exclude the input port
    // check payload for each packets
    for (uint i = 0; i < output_packets.size(); ++i) {
        ASSERT_EQ(output_packets[i].packet, egress_packet);
        bool matched = false;
        for (auto p : la_ports) {
            auto port_info = lane_to_slice_ifg_pif(p);
            if ((output_packets[i].slice == port_info.slice) && (output_packets[i].ifg == port_info.ifg)
                && (output_packets[i].pif == port_info.pif)) {
                matched = true;
                break;
            }
        }
        ASSERT_EQ(matched, true);
    }

    input_info = lane_to_slice_ifg_pif(la_ports[1]); // port 1
    sim_packet_info_desc packet_desc2
        = {.packet = ingress_packet2, .slice = input_info.slice, .ifg = input_info.ifg, .pif = input_info.pif};

    // Send packet on port 1, expect packet received on port 0
    success = sim_ifc->inject_packet(packet_desc2);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    auto expected_output_info = lane_to_slice_ifg_pif(la_ports[0]);
    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 1U);
    ASSERT_EQ(output_packets[0].packet, egress_packet2);
    ASSERT_EQ(output_packets[0].slice, expected_output_info.slice);
    ASSERT_EQ(output_packets[0].ifg, expected_output_info.ifg);
    ASSERT_EQ(output_packets[0].pif, expected_output_info.pif);

    input_info = lane_to_slice_ifg_pif(la_ports[0]); // port 0
    packet_desc = {.packet = ingress_packet, .slice = input_info.slice, .ifg = input_info.ifg, .pif = input_info.pif};

    // Send packet on port 0, expect packet received on port 1
    success = sim_ifc->inject_packet(packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();
    ASSERT_EQ(success, true);

    expected_output_info = lane_to_slice_ifg_pif(la_ports[1]);
    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 1U);
    ASSERT_EQ(output_packets[0].packet, egress_packet);
    ASSERT_EQ(output_packets[0].slice, expected_output_info.slice);
    ASSERT_EQ(output_packets[0].ifg, expected_output_info.ifg);
    ASSERT_EQ(output_packets[0].pif, expected_output_info.pif);

    const char* traffic_src_mac = "de:ad:de:ad:de:ad";
    get_mac_entry(0, traffic_src_mac, bridge_ports[0]);
}
