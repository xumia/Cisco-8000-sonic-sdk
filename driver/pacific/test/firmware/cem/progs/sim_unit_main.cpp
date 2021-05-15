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
/// @details The test checks all queries that are used by FW.
///

#include <inttypes.h>
#include <string.h>

#include "common.h"
#include "uaux_regs.h"
#include "uaux_regs_commands.h"
#include "uaux_regs_mem.h"

#include "counters.h"
#include "em_commands.h"
#include "status_reg.h"

#include "test_if.h"

#pragma Data(".cpu_io")
/// Test iteration counter
volatile uint32_t sim_loop_counter = -1;

/// @brief Status of the simulation and result check.
///
/// Storing status in the dedicated section to make sure it's address isn't changing frequently
/// The test updates "sim_status" on progress and later on result check.
///  - "sim_status" starts as 0xffff_ffff.
///  - Higher bits (16) are reserved for progress. If upper 16 bits remain 0xffff - means the test was terminated in the middle
///  - Lower bits (16) are reserved for result check. If are cleared - there is a problem with one of the checks
///
volatile uint32_t sim_status = 0xabcd;

/// shadow of all uaux registers for debug and validation
volatile uint8_t sim_uaux_regs[TOTAL_REG_OFFSET * MEM_ALIGN];
#pragma Data()

void
check_res_compare(void* tst, void* exp, uint32_t len_in_bytes)
{
    int fail = memcmp(tst, exp, len_in_bytes);
    if (fail != 0) {
        sim_status &= ~(1 << sim_loop_counter);
    }
}

void
check_assert(bool expr)
{
    if (!expr) {
        sim_status &= ~(1 << sim_loop_counter);
    }
}

void
update_progress()
{
    sim_status &= ~(1 << (16 + sim_loop_counter));
    uint32_t cpu_status = sim_status;
    write_cpu_status_reg(&cpu_status);
    sim_loop_counter++;
}

//*******************************
// MAIN
//*******************************
int
main()
{
    sim_loop_counter = 0;
    sim_status = 0xffff_ffff;
    memset((void*)sim_uaux_regs, 0, sizeof(sim_uaux_regs));

    // 0 - status
    uint32_t* stat_reg = (uint32_t*)&sim_uaux_regs[STATUS_REG_OFFSET * MEM_ALIGN];
    read_reg(stat_reg, UAUX_STATUS_REG);
    check_assert(*stat_reg == 0x00);
    update_progress();

    // 1 - CPU - write and read
    uint32_t cpu_val = 0x2323;
    uint32_t* cpu_reg = (uint32_t*)&sim_uaux_regs[CPU_REG_OFFSET * MEM_ALIGN];
    cpu_reg[1] = cpu_val;
    cpu_reg[7] = cpu_val * 2;
    write_reg(UAUX_CPU_REG, cpu_reg);
    cpu_reg[1] = 0;
    cpu_reg[7] = 0;
    read_reg(cpu_reg, UAUX_CPU_REG);
    check_assert(cpu_reg[1] == cpu_val);
    check_assert(cpu_reg[7] == cpu_val * 2);
    update_progress();

    // 2 - counter read
    uint32_t counter_val = 0x1234;
    counter_request_data* creq = (counter_request_data*)&sim_uaux_regs[COUNTERS_REQUEST_REG_OFFSET * MEM_ALIGN];
    counter_response_data* cresp = (counter_response_data*)&sim_uaux_regs[COUNTERS_RESPONSE_REG_OFFSET * MEM_ALIGN];

    //****************************
    // COUNTER
    //****************************
    counters::occupancy_id occ_id;
    occ_id.occ_type = counters::occupancy_id::EM_CORE;
    occ_id.occ_id = 7;
    occ_id.padding0 = 0;

    counters::address addr;
    addr.type = counters::OCCUPANCY;
    addr.id = occ_id.val;
    creq->addr_bits = addr.val;
    creq->is_write = 0;
    //****************************

    creq->counter = 0xdead;
    cresp->counter = 0xbeaf;

    request_and_poll(creq, UAUX_COUNTERS_REQUEST_REG, UAUX_REG_STATUS_COUNTERS_REQUEST, UAUX_REG_STATUS_COUNTERS_RESPONSE);
    read_reg(cresp, UAUX_COUNTERS_RESPONSE_REG);

    check_assert(cresp->counter == 0);
    update_progress();

    // 3 - counter write/read
    creq->is_write = 1;
    creq->counter = counter_val;

    request_and_poll(creq, UAUX_COUNTERS_REQUEST_REG, UAUX_REG_STATUS_COUNTERS_REQUEST, UAUX_REG_STATUS_COUNTERS_RESPONSE);

    creq->is_write = 0;
    creq->counter = 0xdead;
    cresp->counter = 0xbeaf;

    request_and_poll(creq, UAUX_COUNTERS_REQUEST_REG, UAUX_REG_STATUS_COUNTERS_REQUEST, UAUX_REG_STATUS_COUNTERS_RESPONSE);
    read_reg(cresp, UAUX_COUNTERS_RESPONSE_REG);

    check_assert(cresp->counter == counter_val);
    update_progress();

    //****************************
    // KEY/PAYLOAD
    //****************************
    short_key_encoding key;
    key.code = 1;              // 4
    key.mac_addr0 = 0x1234567; // 28
    key.mac_addr1 = 0xabcde;   // 20
    key.mac_relay = 0x543;     // 12
    key.mac_relay_ext = 0x2;   // 2
    key.key_padding = 0;       // 18
    key.padding0 = 0;

    short_payload_encoding payload;
    payload.l2_port = 0x3efef; // 18
    payload.code = 2;          // 2
    payload.padding0 = 0;
    //****************************

    // 4 - group
    memset(&op_ctx, 0, sizeof(routine_context));

    group_request_data* greq = (group_request_data*)&sim_uaux_regs[GROUP_REQUEST_REG_OFFSET * MEM_ALIGN];
    group_response_data* gresp = (group_response_data*)&sim_uaux_regs[GROUP_RESPONSE_REG_OFFSET * MEM_ALIGN];

    memcpy(greq->key, &key, EM_SHORT_KEY);

    request_and_poll(greq, UAUX_GROUP_REQUEST_REG, UAUX_REG_STATUS_GROUP_REQUEST, UAUX_REG_STATUS_GROUP_RESPONSE);
    read_reg(&op_ctx.group_data, UAUX_GROUP_RESPONSE_REG);

    memcpy(gresp, &op_ctx.group_data, sizeof(group_response_data));

    check_assert(op_ctx.group_data.allowed_bank_bitset == 0xffff);
    update_progress();

    // 5 - em FFE
    em_request_data* em_req = (em_request_data*)&sim_uaux_regs[EM_REQUEST_REG_OFFSET * MEM_ALIGN];
    em_response_data* em_resp = (em_response_data*)&sim_uaux_regs[EM_RESPONSE_REG_OFFSET * MEM_ALIGN];

    memcpy(op_ctx.em_request_reg.rec.key, &key, EM_SHORT_KEY);
    op_ctx.em_request_reg.command = EM_COMMAND_FFE;
    op_ctx.em_request_reg.em_core = op_ctx.group_data.em_core;
    op_ctx.em_request_reg.em_bank_bitset = op_ctx.group_data.allowed_bank_bitset;
    op_ctx.em_request_reg.for_cam = 0;

    memset(&op_ctx.em_response_reg, 0, sizeof(em_response_data));
    em_request();

    memcpy(em_req, &op_ctx.em_request_reg, sizeof(em_request_data));
    memcpy(em_resp, &op_ctx.em_response_reg, sizeof(em_response_data));

    check_assert(op_ctx.em_response_reg.hit == 1);
    update_progress();

    // 6 - em WRITE
    memcpy(op_ctx.em_request_reg.rec.payload, &payload, EM_SHORT_PAYLOAD);

    op_ctx.em_request_reg.command = EM_COMMAND_WRITE;
    op_ctx.em_request_reg.age_owner = 1;
    op_ctx.em_request_reg.age_value = 2;
    op_ctx.em_request_reg.age_valid = 1;

    op_ctx.em_request_reg.em_index = op_ctx.em_response_reg.em_index;
    op_ctx.em_request_reg.em_bank_bitset = 1 << op_ctx.em_response_reg.em_bank;

    memset(&op_ctx.em_response_reg, 0, sizeof(em_response_data));
    em_request();

    memcpy(em_req, &op_ctx.em_request_reg, sizeof(em_request_data));
    memcpy(em_resp, &op_ctx.em_response_reg, sizeof(em_response_data));

    check_assert(op_ctx.em_response_reg.hit == 1);
    update_progress();

    // 7 - em READ
    op_ctx.em_request_reg.command = EM_COMMAND_READ;

    memset(&op_ctx.em_response_reg, 0, sizeof(em_response_data));
    em_request();

    memcpy(em_req, &op_ctx.em_request_reg, sizeof(em_request_data));
    memcpy(em_resp, &op_ctx.em_response_reg, sizeof(em_response_data));

    check_res_compare(op_ctx.em_response_reg.rec.key, &key, EM_SHORT_KEY);
    check_res_compare(op_ctx.em_response_reg.rec.payload, &payload, EM_SHORT_PAYLOAD);
    check_assert(op_ctx.em_response_reg.hit == 1);
    check_assert(op_ctx.em_response_reg.age_value == 2);
    check_assert(op_ctx.em_response_reg.age_owner == 1);
    update_progress();

    // 8 - em AGE_WRITE
    memset(op_ctx.em_request_reg.rec.payload, 0, EM_SHORT_PAYLOAD);
    memset(op_ctx.em_request_reg.rec.key, 0, EM_SHORT_KEY);

    op_ctx.em_request_reg.command = EM_COMMAND_AGE_WRITE;
    op_ctx.em_request_reg.age_value = EM_NEW_MAX_AGE;

    memset(&op_ctx.em_response_reg, 0, sizeof(em_response_data));
    em_request();

    memcpy(em_req, &op_ctx.em_request_reg, sizeof(em_request_data));
    memcpy(em_resp, &op_ctx.em_response_reg, sizeof(em_response_data));

    check_assert(op_ctx.em_response_reg.hit == 1);
    update_progress();

    // 9 - em READ2
    op_ctx.em_request_reg.command = EM_COMMAND_READ;

    memset(&op_ctx.em_response_reg, 0, sizeof(em_response_data));
    em_request();

    check_res_compare(op_ctx.em_response_reg.rec.key, &key, EM_SHORT_KEY);
    check_res_compare(op_ctx.em_response_reg.rec.payload, &payload, EM_SHORT_PAYLOAD);
    check_assert(op_ctx.em_response_reg.age_value == EM_NEW_MAX_AGE);
    check_assert(op_ctx.em_response_reg.hit == 1);
    update_progress();

    // 10 - em LOOKUP
    memcpy(op_ctx.em_request_reg.rec.key, &key, EM_SHORT_KEY);

    op_ctx.em_request_reg.command = EM_COMMAND_LOOKUP;

    memset(&op_ctx.em_response_reg, 0, sizeof(em_response_data));
    em_request();

    memcpy(em_req, &op_ctx.em_request_reg, sizeof(em_request_data));
    memcpy(em_resp, &op_ctx.em_response_reg, sizeof(em_response_data));

    check_res_compare(op_ctx.em_response_reg.rec.payload, &payload, EM_SHORT_PAYLOAD);
    check_assert(op_ctx.em_response_reg.hit == 1);
    update_progress();

    // 11 - em DELETE
    op_ctx.em_request_reg.command = EM_COMMAND_DELETE;

    memset(&op_ctx.em_response_reg, 0, sizeof(em_response_data));
    em_request();

    memcpy(em_req, &op_ctx.em_request_reg, sizeof(em_request_data));
    memcpy(em_resp, &op_ctx.em_response_reg, sizeof(em_response_data));

    // nothing to check
    update_progress();

    // 12 - em LOOKUP2
    op_ctx.em_request_reg.command = EM_COMMAND_LOOKUP;

    memset(&op_ctx.em_response_reg, 0, sizeof(em_response_data));
    em_request();

    memcpy(em_req, &op_ctx.em_request_reg, sizeof(em_request_data));
    memcpy(em_resp, &op_ctx.em_response_reg, sizeof(em_response_data));

    check_assert(op_ctx.em_response_reg.hit == 0);
    update_progress();

    // 13 - raise interrupt to CPU.
    *stat_reg |= UAUX_REG_STATUS_CPU_INT;
    write_reg(UAUX_STATUS_REG, stat_reg);
    // make sure status is off
    read_reg(stat_reg, UAUX_STATUS_REG);
    check_assert(*stat_reg == 0);
    update_progress();

    // LAST progress is 0xc000_<status>

    return 0;
}
