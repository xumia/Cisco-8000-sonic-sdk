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
#include "user_space_kernel.h"
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

class SimDot1QTest : public SaiTestBase
{
public:
    vector<sai_object_id_t> bridges;
    vector<sai_object_id_t> bridge_ports;
    vector<sai_object_id_t> vlans;
    vector<sai_object_id_t> vlan_members;

public:
    void configure_dot1q_bridge()
    {
        sai_object_id_t bridge_id{};

        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        // Get Default 1Q bridge id
        attr.id = SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID;
        sai_status_t status = switch_api->get_switch_attribute(switch_id, 1, &attr);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        bridge_id = attr.value.oid;

        bridges.push_back(bridge_id);
    }

    void configure_vlan_member(int vlan_idx, int bridge_port_idx)
    {
        sai_object_id_t vlan_member_id{};
        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        attr.id = SAI_VLAN_MEMBER_ATTR_VLAN_ID;
        set_attr_value(SAI_VLAN_MEMBER_ATTR_VLAN_ID, attr.value, vlans[vlan_idx]);
        attrs.push_back(attr);

        attr.id = SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID;
        set_attr_value(SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID, attr.value, bridge_ports[bridge_port_idx]);
        attrs.push_back(attr);

        sai_status_t status = vlan_api->create_vlan_member(&vlan_member_id, switch_id, attrs.size(), attrs.data());

        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        vlan_members.push_back(vlan_member_id);

        sai_attribute_t attr_ret{};

        attr_ret.id = SAI_VLAN_MEMBER_ATTR_VLAN_ID;
        status = vlan_api->get_vlan_member_attribute(vlan_member_id, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, vlans[vlan_idx]);

        attr_ret.id = SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID;
        status = vlan_api->get_vlan_member_attribute(vlan_member_id, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.oid, bridge_ports[bridge_port_idx]);
    }

    void configure_vlan_members()
    {
        for (int i = 0; i < 16; ++i) {
            configure_vlan_member(i, i * 2);
            configure_vlan_member(i, i * 2 + 1);
        }
    }

    void deconfigure_vlan_members()
    {
        for (auto v : vlan_members) {
            vlan_api->remove_vlan_member(v);
        }
    }

    void configure_vlan(int vlan_idx)
    {
        sai_object_id_t vlan_id{};

        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        attr.id = SAI_VLAN_ATTR_VLAN_ID;
        set_attr_value(SAI_VLAN_ATTR_VLAN_ID, attr.value, (vlan_idx + 1));
        attrs.push_back(attr);

        sai_status_t status = vlan_api->create_vlan(&vlan_id, switch_id, attrs.size(), attrs.data());
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);

        vlans.push_back(vlan_id);

        sai_attribute_t attr_ret{};
        attr_ret.id = SAI_VLAN_ATTR_VLAN_ID;
        status = vlan_api->get_vlan_attribute(vlan_id, 1, &attr_ret);
        ASSERT_EQ(SAI_STATUS_SUCCESS, status);
        ASSERT_EQ(attr_ret.value.u16, (vlan_idx + 1));
    }

    void configure_vlans()
    {
        for (int i = 0; i < 16; ++i) {
            configure_vlan(i);
        }
    }

    void deconfigure_vlans()
    {
        for (auto v : vlans) {
            vlan_api->remove_vlan(v);
        }
    }

    void configure_bridge_port(int port_index)
    {
        vector<sai_attribute_t> attrs;

        sai_attribute_t attr{};

        attr.id = SAI_BRIDGE_PORT_ATTR_TYPE;
        set_attr_value(SAI_BRIDGE_PORT_ATTR_TYPE, attr.value, SAI_BRIDGE_PORT_TYPE_PORT);
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
        for (int i = 0; i < 16; ++i) {
            configure_bridge_port(2 * i);
            configure_bridge_port(2 * i + 1);
        }
    }

    void deconfigure_bridge_ports()
    {
        for (auto bport : bridge_ports) {
            bridge_api->remove_bridge_port(bport);
        }
    }

    void configure_topology() override
    {
        configure_dot1q_bridge();
        configure_bridge_ports();
        configure_vlans();
        configure_vlan_members();
        std::this_thread::sleep_for(std::chrono::milliseconds{500});
    }

    void deconfigure_topology() override
    {
        deconfigure_vlan_members();
        deconfigure_bridge_ports();
        deconfigure_vlans();
    }
};

TEST_F(SimDot1QTest, P2PTest)
{
    const char ingress_packet[] = "cafecafecafedeaddeaddead0800450000280001000040067ccd7f0000017f0000010014005000000000000000005002"
                                  "2000917c0000000000000000";
    const char egress_packet[] = "cafecafecafedeaddeaddead0800450000280001000040067ccd7f0000017f00000100140050000000000000000050022"
                                 "000917c0000000000000000";

    for (size_t input_port = 0; input_port < 32; ++input_port) {
        auto output_port = input_port ^ 0x1; // 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, ...

        // 2-lane ports for this testcase
        auto input_info = lane_to_slice_ifg_pif(input_port * 2);
        auto expected_output_info = lane_to_slice_ifg_pif(output_port * 2);

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
