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

/// @file
/// @file
/// @brief Unit test for CPU commands
///
/// The test checks:
/// - CPU-ARC interface
/// - MAC relay (switch) limit counters update
/// - MAC relay (switch) limit counters initialization
///

static const int cmd_num = 7;
static const int cpu_reg_size = 8;
static const int cmd_args[cmd_num][3]
    = {{ARC_CPU_COMMAND_SWITCH_INIT_MAC, 0x0000_0002, counters::MAX_COUNTER_VAL},
       {ARC_CPU_COMMAND_SWITCH_INIT_MAC, 0xb, counters::MAX_COUNTER_VAL},
       {ARC_CPU_COMMAND_SWITCH_INIT_MAC, 0xc, counters::MAX_COUNTER_VAL},
       {ARC_CPU_COMMAND_SWITCH_INIT_MAC, 0xd, counters::MAX_COUNTER_VAL},
       {ARC_CPU_COMMAND_SWITCH_MAX_MAC, 0x2, static_cast<int>(-(counters::MAX_COUNTER_VAL - 2)) /*set max_mac to 2*/},
       {ARC_CPU_COMMAND_SWITCH_MAX_MAC, 0x2, -3},
       {LEARN_COMMAND_NEW_WRITE, 0x0000_0002, 1}};

void
test_cpu_init()
{
    test_CEM_NUM_CORES = 1;
    test_CEM_NUM_BANKS = 2;
    test_CEM_NUM_ENTRIES = 3;
    test_init_cem();
}

void
test_cpu_check(int cmd_idx)
{
    static const uint32_t expected_counter[] = {counters::MAX_COUNTER_VAL,
                                                counters::MAX_COUNTER_VAL,
                                                counters::MAX_COUNTER_VAL,
                                                counters::MAX_COUNTER_VAL,
                                                2,
                                                static_cast<uint32_t>(-1),
                                                static_cast<uint32_t>(-1)};

// check status of operation
#define UT_ARC_RESPONSE_INTERVAL 1000000000
    uint64_t arc_poll_duration = 0;
    arc_cpu_status arc_status;
    arc_cpu_command_e arc_command_enum;
    arc_cpu_command_status_e arc_status_enum;
    arc_cpu_fsm_state_e arc_state;

    do {
        memset(&arc_status, 0, sizeof(arc_status));
        for (int i = 0; i < 1000000; i++) {
            arc_poll_duration++;
        }
        read_reg(&arc_status, UAUX_CPU_REG);
        arc_command_enum = arc_status.command;
        arc_status_enum = arc_status.status;
        arc_state = arc_status.state;
        if (arc_poll_duration > UT_ARC_RESPONSE_INTERVAL && arc_command_enum != ARC_CPU_COMMAND_NONE) {
            // Waited long enough, break the loop
            PRINT("-CHK- [%s] Wait for response expired, ARC-CPU command: 0x%x status: 0x%x state: 0x%x\n",
                  __func__,
                  arc_command_enum,
                  arc_status_enum,
                  arc_state);
            ASSERT((arc_status_enum == ARC_CPU_COMMAND_STATUS_SUCCESS) && arc_state == ARC_CPU_FSM_STATE_CPU);
        }
    } while (arc_command_enum > ARC_CPU_COMMAND_NONE && arc_state != ARC_CPU_FSM_STATE_CPU);
    PRINT("-CHK- [%s] ARC-CPU command: 0x%x status: 0x%x state: 0x%x, polling_duration: %lld\n",
          __func__,
          arc_command_enum,
          arc_status_enum,
          arc_state,
          arc_poll_duration);

    test_check_counter(counters::AVAILABLE_MAC_RELAY,
                       (counters::occupancy_id::type_e)0 /*ignored*/,
                       cmd_args[cmd_idx][1],
                       expected_counter[cmd_idx]);
}

void
test_cpu_main_loop_poll()
{
    static int cmd_idx = 0;
    uint32_t key;
    uint32_t payload;
    arc_cpu_command cmd;

    if (cmd_idx != 0) {
        PRINT("-CHK- [test_cpu] checking ARC-CPU command index: 0x%x\n", cmd_idx - 1);
        test_cpu_check(cmd_idx - 1);
    }

    status_reg_read();

    // Make sure that there is no CPU command in flight
    read_cpu_status_reg((void*)&cmd);
    if (cmd.status != ARC_CPU_COMMAND_STATUS_NONE && cmd.state != ARC_CPU_FSM_STATE_CPU && cmd.state != ARC_CPU_FSM_STATE_ARC
        && cmd_idx < cmd_num) {
        PRINT("-CHK- [test_cpu] ARC-CPU status and state ready\n");

        key = cmd_args[cmd_idx][1];
        payload = cmd_args[cmd_idx][2];

        if (cmd_idx < 6) {
            cmd.params.obj_params.object_id = key;
            cmd.params.obj_params.object_data = payload;

            cmd.command = (arc_cpu_command_e)cmd_args[cmd_idx][0];
            PRINT("-TST- [test_cpu] ARC-CPU cmd_idx: %d, command: 0x%x, key: 0x%x, pl: 0x%x\n",
                  cmd_idx,
                  cmd.command,
                  cmd.params.obj_params.object_id,
                  cmd.params.obj_params.object_data);
            test_create_cpu_cmd(&cmd);
        } else {
            learn_command_e cmd = (learn_command_e)cmd_args[cmd_idx][0];
            PRINT("-TST- [test_cpu] ARC-CPU learn command: 0x%x\n", cmd);
            test_create_learn_cmd(cmd, key, payload, 1 /*owner*/);
        }

        cmd_idx++;
        return;
    }

    // everything is passed - exit normally
    test_exit(0);
}

// ******************************
// TEST
// ******************************
void __attribute__((used)) test_cpu()
{
    // setup main loop polling
    test_main_loop_poll_callback = test_cpu_main_loop_poll;

    test_cpu_init();
}
