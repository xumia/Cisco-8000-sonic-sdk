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

class SimPuntTest : public SaiTestBase
{
};

TEST_F(SimPuntTest, basic_route)
{
    const char punt_packet[] = "00010203040500060606060608004500002e000000004011f866c0a80106c0a90001003f003f001a0000000102030405"
                               "060708090a0b0c0d0e0f1011cae8a318";

    auto input_info = lane_to_slice_ifg_pif(port_1_for_router * 2);

    sim_packet_info_desc punt_packet_desc
        = {.packet = punt_packet, .slice = input_info.slice, .ifg = input_info.ifg, .pif = input_info.pif};

    //------- punt packet
    bool success = sim_ifc->inject_packet(punt_packet_desc);
    ASSERT_EQ(success, true);
    success = sim_ifc->step_packet();

    auto output_packets = sim_ifc->get_packets();
}
