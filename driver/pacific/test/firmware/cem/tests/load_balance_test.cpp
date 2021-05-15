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

#include "common.h"
#include "status_reg.h"
#include "test_cem_stub.h"
#include "test_if.h"

// for memcpy/memset
#include <string.h>

/// @file
/// @brief Unit test for load balancing routines
///
/// Test mimics receival of load balancing request.
/// As a result, part of the entries from one core are moved to another core.
void
test_load_balance_init()
{
    test_CEM_NUM_CORES = 2;
    test_CEM_NUM_BANKS = 2;
    test_CEM_NUM_ENTRIES = 3;
    test_init_cem();

    test_group2core[1] = 1;
}

void
test_load_balance_check()
{
    static const uint32_t expected[] = {0, 0xc0005, 0, 0xc000a, 0, 0xc0003, 0, 0, 0, 0xc0006, 0xc0004, 0xc0002};
    for (int core = 0; core < test_CEM_NUM_CORES; ++core) {
        for (int bnk = 0; bnk < test_CEM_NUM_BANKS; ++bnk) {
            for (int idx = 0; idx < test_CEM_NUM_ENTRIES; ++idx) {
                uint32_t test_val = test_get_cem_payload(core, bnk, idx);
                uint32_t exp_val = expected[(core * test_CEM_NUM_BANKS + bnk) * test_CEM_NUM_ENTRIES + idx];
                PRINT("-CHK- expect pl: 0x%06X at ", exp_val);
                test_print_cem(core, bnk, idx);
                ASSERT(exp_val == test_val);
            }
        }
    }

    test_check_counter(counters::OCCUPANCY, counters::occupancy_id::EM_CORE, 0, 3);
    test_check_counter(counters::OCCUPANCY, counters::occupancy_id::EM_CORE, 1, 3);
    test_check_counter(counters::OCCUPANCY, counters::occupancy_id::EM_GROUP, 0, 2);
    test_check_counter(counters::OCCUPANCY, counters::occupancy_id::EM_GROUP, 1, 1);
    test_check_counter(counters::OCCUPANCY, counters::occupancy_id::EM_GROUP, 2, 3);
}

void
test_load_balance_main_loop_poll()
{
    static int cycle_idx = 0;
    static const int learn_num = 8;
    static const int load_balance_num = learn_num + 1;

    // input: cmd, key, payload
    // key must be different for new-write
    static const int cmd_args[][3] = {{LEARN_COMMAND_NEW_WRITE, 0x0000_0101, 1},
                                      {LEARN_COMMAND_NEW_WRITE, 0x0200_0221, 2},
                                      {LEARN_COMMAND_UPDATE, 0x0000_0101, 10},
                                      {LEARN_COMMAND_NEW_WRITE, 0x0101_0301, 3},
                                      {LEARN_COMMAND_REFRESH, 0x0000_0101, 0xEE},
                                      {LEARN_COMMAND_NEW_WRITE, 0x0001_0421, 4},
                                      {LEARN_COMMAND_NEW_WRITE, 0x0101_0501, 5},
                                      {LEARN_COMMAND_NEW_WRITE, 0x0000_0611, 6}};
    status_reg_read();

    // for the sake of test, don't inject LEARN commands during AGE update
    if (status_reg_test(UAUX_REG_STATUS_LOAD_BALANCE)) {
        return;
    }

    if (!status_reg_test(UAUX_REG_STATUS_LEARN) && cycle_idx < learn_num) {
        uint32_t key;
        uint32_t payload;

        int idx = cycle_idx;
        learn_command_e cmd = (learn_command_e)cmd_args[idx][0];
        key = cmd_args[idx][1];
        payload = cmd_args[idx][2];
        test_create_learn_cmd(cmd, key, payload, 1 /*owner*/);
        cycle_idx++;
        return;
    }

    if (cycle_idx < load_balance_num) {
        test_create_load_balance_request(0 /* core */, 2 /* group */);
        status_reg_set(UAUX_REG_STATUS_LOAD_BALANCE);
        status_reg_write();
        cycle_idx++;
        return;
    }

    // test is done - perform checks
    test_load_balance_check();

    // everything is passed - exit normally
    test_exit(0);
}

// ******************************
// TEST
// ******************************
void __attribute__((used)) test_load_balance()
{
    // setup main loop polling
    test_main_loop_poll_callback = test_load_balance_main_loop_poll;

    test_load_balance_init();
}
