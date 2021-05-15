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

class SimInjectTest : public SaiTestBase
{
};

TEST_F(SimInjectTest, basic_route)
{
    const char ingress_packet[] = "00010203040500060606060608004500002e000000004011f760c0a80106c0a90107003f003f001a0000000102030405"
                                  "060708090a0b0c0d0e0f1011cae8a318";
    const char egress_packet[] = "00070707070700010203040508004500002e000000003f11f860c0a80106c0a90107003f003f001a00000001020304050"
                                 "60708090a0b0c0d0e0f1011cae8a318";

    auto input_info = lane_to_slice_ifg_pif(port_1_for_router * 2);
    auto expected_output_info = lane_to_slice_ifg_pif(port_2_for_router * 2);

    sim_packet_info_desc packet_desc
        = {.packet = ingress_packet, .slice = input_info.slice, .ifg = input_info.ifg, .pif = input_info.pif};

    //------- inject up assumed received from the first router port to router port packet
    const sai_router_interface_stat_t router_counter_ids[] = {SAI_ROUTER_INTERFACE_STAT_IN_PACKETS,
                                                              SAI_ROUTER_INTERFACE_STAT_IN_OCTETS,
                                                              SAI_ROUTER_INTERFACE_STAT_OUT_PACKETS,
                                                              SAI_ROUTER_INTERFACE_STAT_OUT_OCTETS};
    uint8_t ingress_pkt_buf[64];
    str_to_uint8(ingress_packet, ingress_pkt_buf, 64);

    sai_attribute_t attr_list[1];
    attr_list[0].id = SAI_HOSTIF_PACKET_ATTR_HOSTIF_TX_TYPE;

    // set up injectup type
    set_attr_value(SAI_HOSTIF_PACKET_ATTR_HOSTIF_TX_TYPE, attr_list[0].value, SAI_HOSTIF_TX_TYPE_PIPELINE_LOOKUP);

    // sai_log_set(SAI_API_SWITCH, SAI_LOG_LEVEL_DEBUG);
    sai_status_t status = hostif_api->send_hostif_packet(switch_id, 64, ingress_pkt_buf, 1 /*attr_list len*/, attr_list);
    ASSERT_EQ(status, SAI_STATUS_SUCCESS);

    std::this_thread::sleep_for(std::chrono::milliseconds{400});

    auto output_packets = sim_ifc->get_packets();
    ASSERT_EQ(output_packets.size(), 1U);

    ASSERT_EQ(output_packets[0].packet, egress_packet);
    ASSERT_EQ(output_packets[0].slice, expected_output_info.slice);
    ASSERT_EQ(output_packets[0].ifg, expected_output_info.ifg);
    ASSERT_EQ(output_packets[0].pif, expected_output_info.pif);

    uint64_t counters[array_size(router_counter_ids)] = {};
    status = rif_api->get_router_interface_stats_ext(m_rif_id_1,
                                                     array_size(router_counter_ids),
                                                     (const sai_stat_id_t*)router_counter_ids,
                                                     SAI_STATS_MODE_READ_AND_CLEAR,
                                                     counters);

    ASSERT_EQ(status, SAI_STATUS_SUCCESS);

    status = rif_api->get_router_interface_stats_ext(m_rif_id_2,
                                                     array_size(router_counter_ids),
                                                     (const sai_stat_id_t*)router_counter_ids,
                                                     SAI_STATS_MODE_READ_AND_CLEAR,
                                                     counters);

    ASSERT_EQ(status, SAI_STATUS_SUCCESS);
}
