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

#include "arc_routines.h"
#include "debug_counters.h"
#include "status_reg.h"
#include "test_if.h"
#include "timer.h"
#include "uaux_regs.h"
#include "uaux_regs_commands.h"
#include "uaux_regs_mem.h"

#include <stdlib.h>
#include <string.h>

/// @file
/// @brief Main entry for Central Exact Match Management
///
/// @details ARC is looping on status register and waiting for
/// one of the input bits to turn on. The order of routines
/// defines the priority in which the tasks are performed.
/// Interrupt driven tasks will also raise one of the bits in
/// status register.
///

/// @brief Interrupt enabling bits
/// Overall interrupt enable bit + enabling interrupts up to priority 2 (0,1,2)
static const uint32_t IRQ_ENABLE_PTRN = (1 << 4) | 2;

/// @brief Initialization of CPU controlled ARC interrupt handlers.
void init_external_interrupts();

//************************
// DATA - store in separate section and make sure linker places it's first in the data space.
// Since the addresses are the API to CPU, we need to make sure, addresses are changed as few as possible.
//************************
#pragma Data(".cpu_io")

// Tracks current main routine iteration
volatile int32_t fw_main_loop_counter = -1;

// Tracks current command
volatile int32_t fw_current_command = 0;

/// CPU debug counters
volatile arc_debug_counters debug_counters = {.signature = 0x4442475f, .counter = {0}, .em_request_failure = {0}};

// Number of trials for polling of an EM REQUEST
volatile uint32_t fw_em_poll_timeout_iterations = 10000;

// Time interval between aging cycles in 100 milliseconds.
volatile uint32_t fw_aging_time_interval = 50;

// Enable aging timer. Although it's boolean, still store it as uint32_t to occupy the entire dword
volatile uint32_t fw_aging_timer_enabled = 0;

// Current value of the aging timer
volatile uint32_t fw_aging_timer = 0;

uint32_t cpu_cmd_reg = 0;

arc_cpu_feature_type_value feature_tlvs[ARC_CPU_FEATURE_MAX_TLV_COUNT];

uint16_t sram_per_core_utilization[EM_CORES_IN_CEM];
uint8_t cam_per_core_utilization[EM_CORES_IN_CEM];

#pragma Data()

/// @brief Check if aging timer passed the defined aging interval since the last update.
///
/// @retval true if the interval has passed. false otherwise, or if timer is disabled.
bool
check_aging_timer()
{
    if (fw_aging_timer_enabled == 0) {
        return false;
    }

    uint32_t curr_aging_timer = timer_read();
    if ((curr_aging_timer - fw_aging_timer) > fw_aging_time_interval) {
        fw_aging_timer = curr_aging_timer;
        return true;
    }

    return false;
}

void
configure_aging_params(uint32_t interval)
{
    // Disable timer for parameter change
    fw_aging_timer_enabled = 0;

    debug_counters.counter[arc_debug_counters::AGE_INTERVAL] = interval;

    if (interval == ARC_MAC_AGING_INTERVAL_DISABLE || interval == 0) {
        return;
    }

    fw_aging_time_interval = interval;
    fw_aging_timer_enabled = 1;
}

void
init_capabilities()
{
    size_t index = 0;
    feature_tlvs[index].type = ARC_CPU_FEATURE_TYPE_LEARN_MODE;
    feature_tlvs[index].value = ARC_CPU_FEATURE_CAPABLE;
    index++;
    feature_tlvs[index].type = ARC_CPU_FEATURE_TYPE_AGE_MODE;
    feature_tlvs[index].value = ARC_CPU_FEATURE_CAPABLE;
    index++;
    feature_tlvs[index].type = ARC_CPU_FEATURE_TYPE_AGE_NOTIFICATION;
    feature_tlvs[index].value = ARC_CPU_FEATURE_CAPABLE;
    index++;
    feature_tlvs[index].type = ARC_CPU_FEATURE_TYPE_AGE_INTERVAL;
    feature_tlvs[index].value = ARC_CPU_FEATURE_CAPABLE;
    index++;
    for (size_t rest_index = index; rest_index < ARC_CPU_FEATURE_MAX_TLV_COUNT; ++rest_index) {
        feature_tlvs[rest_index].type = ARC_CPU_FEATURE_TYPE_NONE;
        feature_tlvs[rest_index].value = ARC_CPU_FEATURE_INCAPABLE;
    }
}

void
init_utilization_counters()
{
    memset(sram_per_core_utilization, 0, sizeof(sram_per_core_utilization));
    memset(cam_per_core_utilization, 0, sizeof(cam_per_core_utilization));
}

int
main()
{
    arc_cpu_command cpu_cmd;

    _clri();                // Turn off interrupts
    _seti(IRQ_ENABLE_PTRN); // Enable ints and enable levels 2, 1, and 0

    status_reg_set_mask(UAUX_REG_STATUS_DEFAULT_MASK);

    // initialize_occupancy_counters();
    initialize_active_banks();

    // Initialize interrupt handlers
    init_external_interrupts();

    init_capabilities();

    init_utilization_counters();

    // Initialize aging timer
    timer_init();

    while (1) { /* event loop */
        fw_main_loop_counter++;
        debug_counter_incr(arc_debug_counters::MAIN_LOOP);

        if (check_aging_timer()) {
            init_aging_routine();
        }

        evacuate_if_need();

        status_reg_read();
        if (status_reg_test(UAUX_REG_STATUS_COMMAND)) {

            if (status_reg_test(UAUX_REG_STATUS_LEARN)) {
                fw_current_command = UAUX_REG_STATUS_LEARN;
                em_learn_routine();
                fw_current_command = 0;
            }
            if (status_reg_test(UAUX_REG_STATUS_AGE)) {
                fw_current_command = UAUX_REG_STATUS_AGE;
                aging_routine();
                fw_current_command = 0;
            }
            if (status_reg_test(UAUX_REG_STATUS_BULK)) {
                fw_current_command = UAUX_REG_STATUS_BULK;
                bulk_update_routine();
                fw_current_command = 0;
            }
            if (status_reg_test(UAUX_REG_STATUS_LOAD_BALANCE)) {
                fw_current_command = UAUX_REG_STATUS_LOAD_BALANCE;
                load_balance_routine();
                fw_current_command = 0;
            }
        }

        // ARC CPU commands will not use valid_reg for communications
        // SDK and ARC will use CPU registers (access_reg[36-43]),
        // especially access_reg[36] for command and status communications
        read_cpu_status_reg((void*)&cpu_cmd);
        if (cpu_cmd.command > ARC_CPU_COMMAND_NONE && cpu_cmd.command <= ARC_CPU_COMMAND_LAST
            && cpu_cmd.state == ARC_CPU_FSM_STATE_ARC) {
            fw_current_command = UAUX_REG_STATUS_CPU_CMD;
            debug_counter_incr(arc_debug_counters::CPU_COMMAND);
            cpu_cmd_routine();
            fw_current_command = 0;
        }

        // active only in test mode
        TEST_MODE_POLL();
    } /* end of event loop */

    return 0;
}
