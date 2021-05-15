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

/// @file
/// @brief FW test for VCS simulation
/// @details The test initiates series of LEARN requests (instead of waiting for HW to initiate them) that are being handled by FW.
///

#include "common.h"
#include "status_reg.h"
#include "uaux_regs.h"
#include "uaux_regs_commands.h"

#include "arc_routines.h"
#include "counters.h"
#include "em_commands.h"
#include "test_if.h"

#include <stdlib.h>
#include <string.h>

// number of LEARN queries
static const int NUM_LEARN_CMD_TO_EXECUTE = 8;

// Capture of the commands to run self check after the test
em_request_data sim_store_requests[NUM_LEARN_CMD_TO_EXECUTE];

#pragma Data(".cpu_io")
/// @brief Status of the simulation and result check.
///
/// Storing status in the dedicated section to make sure it's address isn't changing frequently
/// The test updates "sim_status" on progress and later on result check.
///  - "sim_status" starts as 0xffff_ffff.
///  - Higher bits (16) are reserved for progress. If upper 16 bits remain 0xffff - means the test was terminated in the middle
///         8 commands - write
///         8 commands - read and compare
///  - Lower bits (16) are reserved for result check. If are cleared - there is a problem with one of the checks
///         result status is 0xbbff since commands 3 and 7 have their values updates - check fails on check value
volatile uint32_t sim_status = 0xabcd;

#pragma Data()

void
update_progress()
{
    sim_status &= ~(1 << (16 + fw_main_loop_counter));
    uint32_t cpu_status = sim_status;
    write_cpu_status_reg(&cpu_status);
}

void
check_assert(bool expr)
{
    if (!expr) {
        sim_status &= ~(1 << fw_main_loop_counter);
    }
}

void
sim_store_prev_command(int cmd_idx)
{
    if (cmd_idx < 0 || cmd_idx >= NUM_LEARN_CMD_TO_EXECUTE) {
        return;
    }
    // store command resides at em_request at the end of the cycle.
    memcpy(&sim_store_requests[cmd_idx], &op_ctx.em_request_reg, sizeof(em_request_data));
}

/// @brief Generation of single Learn command
void
sim_create_em_learn_cmd(learn_command_e cmd, uint32_t key, uint32_t payload, bool owner)
{
    learn_data learn_reg;
    learn_data* reg = &learn_reg;

    short_key_encoding* key_enc = (short_key_encoding*)reg->key;
    short_payload_encoding* pl_enc = (short_payload_encoding*)reg->payload;

    reg->key0 = key;
    key_enc->code = 1;
    key_enc->mac_addr1 = 0xf_ffff;
    // set relay id to funky index - we don't count it anyway
    key_enc->mac_relay = 0xabc;
    // make sure top 2 bits are on
    key_enc->mac_relay_ext = 0x3;
    key_enc->key_padding = 0;
    key_enc->padding0 = 0;

    pl_enc->code = 0x2;
    pl_enc->l2_port = payload;
    pl_enc->padding0 = 0;

    reg->command = cmd;
    reg->owner = owner;
    reg->padding1 = 0;

    write_reg(UAUX_LEARN_REG, reg);
    status_reg_set(UAUX_REG_STATUS_LEARN);
    status_reg_write();
}

/// @brief Learn command generation and result check
void
sim_main_loop_poll()
{
    static int cmd_idx = 0;
    // input: cmd, key, payload
    // key must be different for new-write
    static const int cmd_args[][3] = {{LEARN_COMMAND_NEW_WRITE, 0x2344_2329, 0x2341},
                                      {LEARN_COMMAND_NEW_WRITE, 0x7564_aef4, 0x2ade},
                                      {LEARN_COMMAND_NEW_WRITE, 0x9878_4552, 0x9771},
                                      {LEARN_COMMAND_NEW_WRITE, 0x9782_0908, 0x2845},
                                      {LEARN_COMMAND_NEW_WRITE, 0x2339_7541, 0x2845},
                                      {LEARN_COMMAND_NEW_WRITE, 0x2092_4423, 0x2333},
                                      {LEARN_COMMAND_REFRESH, 0x9878_4552, 0xdead},
                                      {LEARN_COMMAND_UPDATE, 0x9878_4552, 0xabcd}};

    uint32_t key;
    uint32_t payload;

    sim_store_prev_command(cmd_idx - 1);

    // Create learn commands
    if (cmd_idx < NUM_LEARN_CMD_TO_EXECUTE) {
        learn_command_e cmd = (learn_command_e)cmd_args[cmd_idx][0];
        key = cmd_args[cmd_idx][1];
        payload = cmd_args[cmd_idx][2];
        sim_create_em_learn_cmd(cmd, key, payload, 1 /*owner*/);
        cmd_idx++;
        update_progress();
        return;
    }

    if (cmd_idx == NUM_LEARN_CMD_TO_EXECUTE) {
        // Check that learn commands succeeded
        for (int i = 0; i < NUM_LEARN_CMD_TO_EXECUTE; ++i) {
            em_request_data* reg = &sim_store_requests[i];

            if (reg->command != EM_COMMAND_WRITE && reg->command != EM_COMMAND_AGE_WRITE) {
                check_assert(false);
                continue;
            }

            memcpy(&op_ctx.em_request_reg, reg, sizeof(em_request_data));
            op_ctx.em_request_reg.command = EM_COMMAND_LOOKUP;

            memset(&op_ctx.em_response_reg, 0, sizeof(em_response_data));
            em_request();

            check_assert(1 == op_ctx.em_response_reg.hit);
            check_assert(reg->for_cam == op_ctx.em_response_reg.for_cam);
            check_assert(reg->em_bank_bitset == (1 << op_ctx.em_response_reg.em_bank));
            check_assert(reg->em_index == op_ctx.em_response_reg.em_index);
            check_assert(reg->rec.payload0 == op_ctx.em_response_reg.rec.payload0);

            op_ctx.em_request_reg.command = EM_COMMAND_READ;

            memset(&op_ctx.em_response_reg, 0, sizeof(em_response_data));
            em_request();

            check_assert(reg->age_value == op_ctx.em_response_reg.age_value);

            update_progress();
            fw_main_loop_counter++;
        }

        cmd_idx++;
    }
}

//*******************************
// MAIN
//*******************************
int
main()
{
    sim_status = 0xffff_ffff;

    // first iteration is empty
    fw_main_loop_counter = -1;

    while (1) { /* event loop */

        status_reg_read();
        if (status_reg_test(UAUX_REG_STATUS_COMMAND)) {

            if (status_reg_test(UAUX_REG_STATUS_LEARN)) {
                em_learn_routine();
            }
            if (status_reg_test(UAUX_REG_STATUS_AGE)) {
                aging_routine();
            }
            if (status_reg_test(UAUX_REG_STATUS_BULK)) {
                bulk_update_routine();
            }
            if (status_reg_test(UAUX_REG_STATUS_LOAD_BALANCE)) {
                load_balance_routine();
            }
        }

        fw_main_loop_counter++;
        sim_main_loop_poll();
    } /* end of event loop */

    return 0;
}
