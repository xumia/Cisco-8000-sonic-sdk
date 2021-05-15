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
#include "counters.h"
#include "status_reg.h"

#include "test_cem_stub.h"
#include "test_if.h"

// for memcpy/memset
#include <string.h>

/// @file
/// @brief Unit test for HW learn routines
///
/// Tests adds/updates entries to CEM via HW learn interface
///
/// The test checks:
/// - new entry addition
/// - entry update
/// - entry age refresh
/// - Core and group occupacy counters
/// - MAC relay and AC port limit counters

void
test_learn_init()
{
    test_CEM_NUM_CORES = 1;
    test_CEM_NUM_BANKS = 2;
    test_CEM_NUM_ENTRIES = 3;
    test_init_cem();
}

void
test_learn_check()
{
    static const uint32_t expected[] = {0xc0002, 0xc0005, 0x0000, 0xc0001, 0xc000C, 0xc0003};
    for (int bank = 0; bank < test_CEM_NUM_BANKS; ++bank) {
        for (int entry = 0; entry < test_CEM_NUM_ENTRIES; ++entry) {
            uint32_t test_val = test_get_cem_payload(0 /*core*/, bank, entry);
            uint32_t exp_val = expected[bank * test_CEM_NUM_ENTRIES + entry];
            PRINT("-CHK- expect pl: 0x%06X at ", exp_val);
            test_print_cem(0, bank, entry);
            ASSERT(exp_val == test_val);
        }
    }
    PRINT("-CHK- expect age: 4 at ");
    test_print_cem(0, 1, 1);
    ASSERT(test_get_cem_age(0, 1, 1) == 4);

    PRINT("-CHK- expect age: 7 at ");
    test_print_cem(0, 0, 0);
    ASSERT(test_get_cem_age(0, 0, 0) == 7);

    PRINT("-CHK- expect age: 7 at ");
    test_print_cem(0, 0, 1);
    ASSERT(test_get_cem_age(0, 0, 1) == 7);

    PRINT("-CHK- expect age: 7 at ");
    test_print_cem(0, 1, 0);
    ASSERT(test_get_cem_age(0, 1, 0) == 7);

    test_check_counter(counters::AVAILABLE_AC_PORT, counters::occupancy_id::NONE, 2, 9);
    test_check_counter(counters::AVAILABLE_MAC_RELAY, counters::occupancy_id::NONE, 2, 4);
    test_check_counter(counters::OCCUPANCY, counters::occupancy_id::EM_CORE, 0, 6);
    test_check_counter(counters::OCCUPANCY, counters::occupancy_id::EM_GROUP, 0, 6);
}

/// @brief Tests em_learn routine
/// LEARN_COMMAND_NEW_WRITE
/// - requests 1-4 fill the hash
/// - request 5 forces two level relocation in order to find free entry
/// - request 6 fails to store to banks - goes to CAM
/// LEARN_COMMAND_UPDATE
/// - changes payload from 2 to 12
/// LEARN_COMMAND_REFRESH
/// - updates the same entry
void
test_learn_main_loop_poll()
{
    static int cmd_idx = 0;
    static const int cmd_num = 8;
    // input: cmd, key, payload
    // key must be different for new-write
    static const int cmd_args[cmd_num][3] = {{LEARN_COMMAND_NEW_WRITE, 0x0000_1001, 1},
                                             {LEARN_COMMAND_NEW_WRITE, 0x0200_2001, 2},
                                             {LEARN_COMMAND_NEW_WRITE, 0x0101_3001, 3},
                                             {LEARN_COMMAND_NEW_WRITE, 0x0001_4001, 4},
                                             {LEARN_COMMAND_NEW_WRITE, 0x0101_5001, 5},
                                             {LEARN_COMMAND_NEW_WRITE, 0x0000_6001, 6},
                                             {LEARN_COMMAND_UPDATE, 0x0001_4001, 12},
                                             {LEARN_COMMAND_REFRESH, 0x0001_4001, 12}};
    uint32_t key;
    uint32_t payload;

    status_reg_read();
    // Make sure that there is no LEARN command in flight
    if (!status_reg_test(UAUX_REG_STATUS_LEARN) && cmd_idx < cmd_num) {
        learn_command_e cmd = (learn_command_e)cmd_args[cmd_idx][0];
        key = cmd_args[cmd_idx][1];
        payload = cmd_args[cmd_idx][2];
        // age_owner bit: system learn: 1, local learn: 0
        test_create_learn_cmd(cmd, key, payload, 0 /*owner*/);
        cmd_idx++;
        return;
    }

    // test is done - perform checks
    test_learn_check();

    // everything is passed - exit normally
    test_exit(0);
}

// ******************************
// TEST
// ******************************
void __attribute__((used)) test_learn()
{
    // setup main loop polling
    test_main_loop_poll_callback = test_learn_main_loop_poll;

    test_learn_init();
}
