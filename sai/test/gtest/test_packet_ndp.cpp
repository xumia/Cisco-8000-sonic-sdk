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
#include "nsim/nsim.h"
#include "nsim_provider/nsim_test_flow.h"
#include "sai_test_utils.h"
#include "gtest/gtest.h"
#include <../../build/src/auto_gen_attr.h>
#include <algorithm>
#include <iterator>
#include <numeric>
#include <thread>
#include <vector>
#include "sai_test_base.h"

using namespace std;
using namespace silicon_one;

static int callback_count = 0;

class SimPuntNdpTest : public SaiTestBase
{
    static void sai_ndp_packet_event_callback(sai_object_id_t switchid,
                                              sai_size_t buffer_size,
                                              const void* buffer,
                                              uint32_t attr_count,
                                              const sai_attribute_t* attr_list)
    {
        callback_count++;
        printf("switch id 0x%lx buffer size %lu buffer %p attr_count %u attr %p\n",
               switchid,
               buffer_size,
               buffer,
               attr_count,
               attr_list);

        if (attr_count > 0) {
            printf("attr id %d", attr_list[0].id);
            printf(" attr oid 0x%lx\n", attr_list[0].value.oid);
        }
        if (attr_count > 1) {
            printf("attr id %d", attr_list[1].id);
            printf(" attr oid 0x%lx\n", attr_list[1].value.oid);
        }
    }

    void configure_notification() override
    {
        sai_attribute_t attr{};
        attr.id = SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY;
        attr.value.ptr = (sai_pointer_t)sai_ndp_packet_event_callback;

        sai_status_t status = switch_api->set_switch_attribute(switch_id, &attr);
        ASSERT_EQ(status, SAI_STATUS_SUCCESS);
    }
};

TEST_F(SimPuntNdpTest, basic_route)
{
    // const char punt_packet[] = "00010203040500060606060608004500002e000000004011f866c0a80106c0a90001003f003f001a0000000102030405"
    //                           "060708090a0b0c0d0e0f1011cae8a318";
    const char ndp_packet[] = "3333ff480000c4000548000086dd6e00000000183aff00000000000000000000000000000000ff0200000000000000000001"
                              "ff4800008700b19600000000fe80000000000000c60005fffe480000";

    auto input_info = lane_to_slice_ifg_pif(port_1_for_router * 2);
    //------- ndp packet
    sim_packet_info_desc punt_packet_desc
        = {.packet = ndp_packet, .slice = input_info.slice, .ifg = input_info.ifg, .pif = input_info.pif};

    bool success = sim_ifc->inject_packet(punt_packet_desc);
    ASSERT_EQ(success, true);
    success = sim_ifc->step_packet();

    this_thread::sleep_for(chrono::milliseconds{600});
    auto output_packets = sim_ifc->get_packets();

    ASSERT_EQ(callback_count, 0);

    sai_object_id_t ndp_trap;
    sai_attribute_t attr;
    sai_status_t status;

    create_hostif_trap(ndp_trap, SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY, SAI_PACKET_ACTION_DROP);

    this_thread::sleep_for(chrono::milliseconds{600});

    success = sim_ifc->inject_packet(punt_packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();

    this_thread::sleep_for(chrono::milliseconds{600});

    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(callback_count, 0);

    attr.id = SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE;
    ;
    status = hostif_api->get_hostif_trap_attribute(ndp_trap, 1, &attr);
    ASSERT_EQ(status, SAI_STATUS_SUCCESS);
    auto trap_type = get_attr_value(SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE, attr.value);
    ASSERT_EQ(trap_type, SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY);
    // ASSERT_EQ(action, SAI_PACKET_ACTION_TRAP);

    attr.id = SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION;
    ;
    set_attr_value(SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION, attr.value, SAI_PACKET_ACTION_TRAP);
    status = hostif_api->set_hostif_trap_attribute(ndp_trap, &attr);
    ASSERT_EQ(status, SAI_STATUS_SUCCESS);

    this_thread::sleep_for(chrono::milliseconds{600});

    success = sim_ifc->inject_packet(punt_packet_desc);
    ASSERT_EQ(success, true);

    success = sim_ifc->step_packet();

    this_thread::sleep_for(chrono::milliseconds{600});

    output_packets = sim_ifc->get_packets();
    ASSERT_EQ(callback_count, 1);
}
