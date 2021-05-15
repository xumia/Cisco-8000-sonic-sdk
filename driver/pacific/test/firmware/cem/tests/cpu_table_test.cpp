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

#include "arc_cpu_common.h"
#include "common.h"
#include "counters.h"
#include "status_reg.h"
#include "test_cem_stub.h"
#include "test_if.h"

// for memcpy/memset
#include <string.h>

#include <time.h>

/// @file
/// @brief Unit test for CEM update routines (insert/erase) from CPU
///
/// The test checks:
/// - CPU-ARC interface
/// - single bank entry insertion/removal
///
/// The test does not check:
/// - double bank entry insertion/removal

static const int cmd_num = 5;
static const int cpu_reg_size = 8;
static const int cmd_args[cmd_num][cpu_reg_size]
    = {{ARC_CPU_COMMAND_INSERT_TABLE_SINGLE_ENTRY, 0x0000_0101, 0x2fffff, 0x3, 0, 0, 0x4, 0},
       {ARC_CPU_COMMAND_INSERT_TABLE_SINGLE_ENTRY, 0x0002_0201, 0x2fffff, 0x3, 0, 0, 0x5, 0},
       {ARC_CPU_COMMAND_INSERT_TABLE_SINGLE_ENTRY, 0x0001_0301, 0x2fffff, 0x3, 0, 0, 0x6, 0},
       {ARC_CPU_COMMAND_INSERT_TABLE_SINGLE_ENTRY, 0x0002_0201, 0x2fffff, 0x3, 0, 0, 0x7, 0},
       {ARC_CPU_COMMAND_ERASE_TABLE_SINGLE_ENTRY, 0x0000_0101, 0x2fffff, 0x3, 0, 0, 0, 0}};

void
test_cpu_table_init()
{
    test_CEM_NUM_CORES = 1;
    test_CEM_NUM_BANKS = 2;
    test_CEM_NUM_ENTRIES = 3;
    test_init_cem();
}

void
test_cpu_table_check()
{
// check status of operation
#define UT_ARC_RESPONSE_INTERVAL 10
    uint64_t arc_poll_duration;
    arc_cpu_status arc_status;
    arc_cpu_command_e arc_command_enum;
    arc_cpu_command_status_e arc_status_enum;
    arc_cpu_fsm_state_e arc_state;

    PRINT("-CHK- [%s] ARC-CPU wait for response\n", __func__);

    for (arc_poll_duration = 0; arc_poll_duration < UT_ARC_RESPONSE_INTERVAL; arc_poll_duration++) {
        memset(&arc_status, 0, sizeof(arc_status));
        read_reg(&arc_status, UAUX_CPU_REG);
        arc_command_enum = arc_status.command;
        arc_status_enum = arc_status.status;
        arc_state = arc_status.state;
        PRINT("-CHK- [%s] command: 0x%x status: 0x%x state: 0x%x, polling_duration: %lld\n",
              __func__,
              arc_command_enum,
              arc_status_enum,
              arc_state,
              arc_poll_duration);
        if (arc_status_enum <= ARC_CPU_COMMAND_STATUS_LAST && arc_state == ARC_CPU_FSM_STATE_CPU)
            break;
    }
    if (arc_poll_duration >= UT_ARC_RESPONSE_INTERVAL && arc_command_enum > ARC_CPU_COMMAND_NONE) {
        // Waited long enough, break the loop
        PRINT("-CHK- [%s] Wait for response expired, ARC-CPU command: 0x%x status: 0x%x state: 0x%x\n",
              __func__,
              arc_command_enum,
              arc_status_enum,
              arc_state);
        ASSERT((arc_status_enum == ARC_CPU_COMMAND_STATUS_SUCCESS) && arc_state == ARC_CPU_FSM_STATE_CPU);
    }
    PRINT("-CHK- [%s] ARC-CPU command: 0x%x status: 0x%x state: 0x%x, polling_duration: %lld\n",
          __func__,
          arc_command_enum,
          arc_status_enum,
          arc_state,
          arc_poll_duration);

    static const uint32_t expected_cpu[] = {0x00000, 0x00000, 0x00000, 0x00000, 0x00006, 0x00007};
    for (int bank = 0; bank < test_CEM_NUM_BANKS; ++bank) {
        for (int entry = 0; entry < test_CEM_NUM_ENTRIES; ++entry) {
            uint32_t test_val = test_get_cem_payload(0 /*core*/, bank, entry);
            uint32_t exp_val = expected_cpu[bank * test_CEM_NUM_ENTRIES + entry];
            PRINT("-CHK- expect pl: 0x%06X at ", exp_val);
            test_print_cem(0, bank, entry);
            ASSERT(exp_val == test_val);
        }
    }
}

void
test_cpu_table_main_loop_poll()
{
    static int cmd_idx = 0;
    uint32_t key;
    uint32_t payload;
    arc_cpu_command cmd;

    status_reg_read();

    // Make sure that there is no CPU command in flight
    read_cpu_status_reg((void*)&cmd);
    if (cmd.status != ARC_CPU_COMMAND_STATUS_NONE && cmd.state != ARC_CPU_FSM_STATE_CPU && cmd.state != ARC_CPU_FSM_STATE_ARC
        && cmd_idx < cmd_num) {
        for (size_t reg_index = 0; reg_index < cpu_reg_size - 1; ++reg_index) {
            cmd.params.flat[reg_index] = cmd_args[cmd_idx][reg_index + 1];
        }

        cmd.command = (arc_cpu_command_e)cmd_args[cmd_idx][0];
        // PRINT("-CHK- [test_cpu_table] cmd_idx: %d --> test_create_cpu_cmd\n", cmd_idx);
        test_create_cpu_cmd(&cmd);
        cmd_idx++;
        return;
    }

    // test is done - perform checks
    test_cpu_table_check();

    // everything is passed - exit normally
    test_exit(0);
}

// ******************************
// TEST
// ******************************
void __attribute__((used)) test_cpu_table()
{
    // setup main loop polling
    test_main_loop_poll_callback = test_cpu_table_main_loop_poll;

    test_cpu_table_init();
}
