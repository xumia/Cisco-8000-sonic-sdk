// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "routine_counters.h"

#include "counters.h"

#include "test_if.h"

#ifdef TEST_MODE
extern int test_CEM_NUM_CORES;
extern int test_CEM_NUM_BANKS;
extern int test_CEM_NUM_ENTRIES;
#endif // TEST_MODE

//*********************************
// PERIODIC COUNTER
//*********************************

void
periodic_counter::next_allowed_bank()
{
    while (!data.bits.for_cam) {
        if ((1 << data.bits.em_bank) & active_banks) {
            // found next location
            return;
        }

        // it's the same as em_bank += 1
        data.count += EM_ENTRIES_IN_BANK;
    }
    // we're here - means that no more allowed banks found and the counter is set to CAM
    // iteration is done
    ASSERT(data.bits.em_bank == 0);
    ASSERT(data.bits.em_entry == 0);
}

void
periodic_counter::init(uint32_t core)
{
    data.count = 0;
    data.bits.em_core = core;
    next_allowed_bank();
}

bool
periodic_counter::incr()
{
    periodic_counter prev = *this;

#ifdef TEST_MODE
    // for testing purposes, mimic shorter banks, since no way we will test more than 10 entries
    if (data.bits.em_entry >= test_CEM_NUM_ENTRIES) {
        data.bits.em_entry = EM_ENTRIES_IN_BANK - 1;
    }
#endif // TEST_MODE

    if (data.bits.for_cam && data.bits.em_entry >= EM_ENTRIES_IN_CAM - 1) {
// mimic the last entry to proceed to the next core
#if defined(PACIFIC) || defined(ASIC3) || defined(ASIC5)
        data.bits.em_entry = EM_ENTRIES_IN_BANK - 1;
        data.bits.em_bank = EM_BANKS_IN_CORE - 1;
#else
        data.count |= LAST_CORE_PERIODIC_COUNTER;
#endif
    }

    data.count++;

    if (!is_valid()) {
        return false;
    }

    bool core_changed = (data.bits.em_core != prev.data.bits.em_core);
    bool bank_changed = (data.bits.em_bank != prev.data.bits.em_bank);

    if (core_changed || bank_changed) {
        // changed bank - find the next avaliable one
        next_allowed_bank();
    }

#ifdef TEST_MODE
    // for testing purposes, mimic less cores
    if (data.bits.em_core >= test_CEM_NUM_CORES) {
        data.bits.state = DONE;
        return false;
    }
#endif // TEST_MODE

    // even if no more available banks, it will switch to CAM
    return true;
}

bool
periodic_counter::next_cam_entry()
{
    if (data.bits.em_entry >= EM_ENTRIES_IN_CAM - 1) {
        data.bits.state = DONE;
        return false;
    }
    data.count++;
    return true;
}

//*********************************
// LOAD BALANCING
//*********************************

// TODO: implement initialization from CPU command
load_balance_request_data load_balance_request;

void
load_balance_data::init()
{
    em_group = load_balance_request.em_group;
    em_core = load_balance_request.em_core;

    dest_core = counters_get_most_vacant_core(em_core);
#ifdef TEST_MODE
    // in test_mode, it will always find a core which is not covered by test_hash
    int test_dest_core = em_core + 1;
    PRINT("load_balance_data::init replacing dest_core=%d with dest_core=%d\n", dest_core, test_dest_core);
    dest_core = test_dest_core;
#endif // TEST_MODE

    stage = COPY;

    counter.init(em_core);
}

bool
load_balance_data::incr()
{
    // skip entry increment if in REMAP stage
    if (stage == REMAP) {
        stage++;
        return true;
    }

    counter.incr();

    // either we switched core or it was the last core
    if (!counter.is_valid() || counter.data.bits.em_core != em_core) {
        stage++;
        counter.init(em_core);
    }

    return is_valid();
}
