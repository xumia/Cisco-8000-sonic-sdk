// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "test_ra_flow.h"

#include "lld/ll_device.h"
#include "nplapi/translator_creator.h"

silicon_one::ra_device_simulator*
create_ra_simulator(const std::vector<size_t>& block_filter_vec,
                    la_device_id_t device_id,
                    silicon_one::simulator_options sim_options)
{
    silicon_one::ra_device_simulator* sim = new silicon_one::ra_device_simulator(block_filter_vec);

    if (!sim->initialize(device_id, sim_options)) {
        delete sim;
        return nullptr;
    }

    return sim;
}

std::string
ra_simulator_check_address(const silicon_one::ll_device* ldevice, size_t addr, const char* val, bool is_mem)
{
    const silicon_one::device_simulator* simulator = ldevice->get_device_simulator();
    const silicon_one::ra_device_simulator* ra_simulator = static_cast<const silicon_one::ra_device_simulator*>(simulator);

    return ra_simulator->check_address(addr, val, is_mem);
}
