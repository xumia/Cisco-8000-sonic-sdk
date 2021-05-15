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
/// @brief Unit test for bulk update routines
///
/// Test adds new entries to CEM, then creating bulk update rules and then running bulk update cycle
///
/// The test checks:
/// - bulk update routines (update and delete)
///
/// The test does not check
/// - learn commands during bulk update cycle

void
test_bulk_update_init()
{
    test_CEM_NUM_CORES = 1;
    test_CEM_NUM_BANKS = 2;
    test_CEM_NUM_ENTRIES = 3;
    test_init_cem();
}

void
test_bulk_update_check()
{
    static const uint32_t expected[] = {0xc0002, 0xc0005, 0x0000, 0xc000a, 0xc000c, 0x0000};
    for (int bnk = 0; bnk < test_CEM_NUM_BANKS; ++bnk) {
        for (int idx = 0; idx < test_CEM_NUM_ENTRIES; ++idx) {
            uint32_t test_val = test_get_cem_payload(0 /*core*/, bnk, idx);
            uint32_t exp_val = expected[bnk * test_CEM_NUM_ENTRIES + idx];
            PRINT("-CHK- expect pl: 0x%06X at ", exp_val);
            test_print_cem(0 /*core*/, bnk, idx);
            ASSERT(exp_val == test_val);
        }
    }
}

void
test_bulk_update_main_loop_poll()
{
    static int cycle_idx = 0;
    static const int learn_num = 8;
    static const int bulk_num = 11;

    // same core for all commands
    static const int core = 0;

    // input: cmd, key, payload
    // key must be different for new-write
    static const int cmd_args[][3] = {{LEARN_COMMAND_NEW_WRITE, 0x0000_0101, 1},
                                      {LEARN_COMMAND_NEW_WRITE, 0x0200_0201, 2},
                                      {LEARN_COMMAND_UPDATE, 0x0000_0101, 10},
                                      {LEARN_COMMAND_NEW_WRITE, 0x0101_0301, 3},
                                      {LEARN_COMMAND_REFRESH, 0x0000_0101, 0xEE},
                                      {LEARN_COMMAND_NEW_WRITE, 0x0001_0401, 4},
                                      {LEARN_COMMAND_NEW_WRITE, 0x0101_0501, 5},
                                      {LEARN_COMMAND_NEW_WRITE, 0x0000_0601, 6},
                                      {BULK_COMMAND_UPDATE, 0x0001_0401, 12},
                                      {BULK_COMMAND_DELETE, 0x0101_0301, 0xEEEE},
                                      {BULK_COMMAND_SEND_TO_CPU, 0x0200_0201, 0xEEEE}};

    status_reg_read();

    // for the sake of test, don't inject LEARN commands during AGE update
    if (status_reg_test(UAUX_REG_STATUS_BULK)) {
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

    if (cycle_idx < bulk_num) {
        uint32_t key;
        uint32_t payload;

        int idx = cycle_idx;
        bulk_command_e cmd = (bulk_command_e)cmd_args[idx][0];
        key = cmd_args[idx][1];
        payload = cmd_args[idx][2];
        test_create_rule(cmd, key, payload);
        status_reg_set(UAUX_REG_STATUS_BULK);
        status_reg_write();
        cycle_idx++;
        return;
    }

    // test is done - perform checks
    test_bulk_update_check();

    // everything is passed - exit normally
    test_exit(0);
}

// ******************************
// TEST
// ******************************
void __attribute__((used)) test_bulk_update()
{
    // setup main loop polling
    test_main_loop_poll_callback = test_bulk_update_main_loop_poll;

    test_bulk_update_init();
}
