// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "cam_manager.h"
#include "counters.h"

bool
insert_cam_entry(em_entry_data* rec)
{
    ffe_request(rec, (1 << EM_EVACUATION_BANK), false);
    uint16_t entry = rec->data.em_index;
    bool was_stored = ffe_and_store(rec, 0x0 /* no bitset for CAM */, true /* for CAM */);
    if (was_stored) {
        counter_shadow counter;
        counter.counter = entry;
        counter.addr = counters::FIRST_CAM_MAP_ENTRY + op_ctx.group_data.em_core * EM_ENTRIES_IN_CAM + rec->data.em_index;
        counter.is_write = 1;
        read_counter_data(&counter);
    }

    return was_stored;
}

void
get_cam_entry_collided_location(em_entry_data* rec, periodic_counter* out_collided_location)
{
    counter_shadow counter;
    counter.addr = counters::FIRST_CAM_MAP_ENTRY + op_ctx.group_data.em_core * EM_ENTRIES_IN_CAM + rec->data.em_index;
    counter.is_write = 0;
    read_counter_data(&counter);

    out_collided_location->data.bits.em_core = op_ctx.group_data.em_core;
    out_collided_location->data.bits.em_entry = counter.counter;
    out_collided_location->data.bits.em_bank = EM_EVACUATION_BANK;
    out_collided_location->data.bits.for_cam = 0;
}
