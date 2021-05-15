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

#include "arc_cpu_common.h"
#include "common.h"
#include "counters.h"
#include "status_reg.h"
#include "test_cem_stub.h"
#include "test_if.h"
#include "uaux_regs.h"
#include "uaux_regs_commands.h"

// for memcpy/memset
#include <string.h>
// for exit
#include <stdlib.h>

/// @file
/// @brief Implementation of Testing stubs for CEM hash and
/// learning routines. Enabled only in TEST_MODE

//*****************************************
// CEM STUB data
//*****************************************

// default values for CEM-hash dimentions
int test_CEM_NUM_CORES = 1;
int test_CEM_NUM_BANKS = 2;
int test_CEM_NUM_ENTRIES = 3;

// group <--> core mapping
int test_group2core[10];

// CEM hash - response format is the most convenient for storage
// do not store more than 10 entries of data total
static const int test_CEM_NUM_IDXS = 20;
cem_data test_hash_data[test_CEM_NUM_IDXS];

// CEM rule table
cem_data test_rule_table;

// Counters
int32_t test_l2_port_limit_cntr[16];
int32_t test_mac_relay_limit_cntr[16];
int32_t test_occupancy_cntr[2][16];

// shadow registers
em_request_data test_em_request_reg;
em_response_data test_em_response_reg;

extern load_balance_request_data load_balance_request;

//*****************************************
// CEM STUB functions
//*****************************************

// calculating hash based on two first bytes after the huffman prefix in key: first is initial value, second is step
uint32_t
calculate_hash(uint8_t* key, uint32_t bank)
{
    return (key[0] + key[1] * bank) % test_CEM_NUM_ENTRIES;
}

// index of entry within the data
uint32_t
calculate_idx(uint32_t core, uint32_t bank, uint32_t entry)
{
    ASSERT(core < test_CEM_NUM_CORES);
    ASSERT(bank < test_CEM_NUM_BANKS);
    ASSERT(entry < test_CEM_NUM_ENTRIES);

    int data_idx = (core * test_CEM_NUM_BANKS + bank) * test_CEM_NUM_ENTRIES + entry;
    ASSERT(data_idx < test_CEM_NUM_IDXS);
    return data_idx;
}

cem_data*
test_get_cem(uint32_t core, uint32_t bank, uint32_t entry)
{
    return &test_hash_data[calculate_idx(core, bank, entry)];
}

uint32_t
test_get_cem_payload(uint32_t core, uint32_t bank, uint32_t entry)
{
    return test_hash_data[calculate_idx(core, bank, entry)].rec.payload0;
}

uint32_t
test_get_cem_age(uint32_t core, uint32_t bank, uint32_t entry)
{
    return test_hash_data[calculate_idx(core, bank, entry)].data.age_value;
}

void
test_print_cem(uint32_t core, uint32_t bank, uint32_t entry)
{
    cem_data* curr = test_get_cem(core, bank, entry);
    uint32_t key = curr->rec.key0;
    uint32_t pl = curr->rec.payload0;
    uint32_t age = curr->data.age_value;

    PRINT("cem(%d, %d, %d) k: 0x%08X, pl: 0x%06X, age: %d\n", core, bank, entry, key, pl, age);
}

uint32_t
test_get_counter(counters::type_e type, counters::occupancy_id::type_e occ_type, uint32_t id)
{
    if (type == counters::AVAILABLE_MAC_RELAY) {
        return test_mac_relay_limit_cntr[id];
    }

    if (type == counters::AVAILABLE_AC_PORT) {
        return test_l2_port_limit_cntr[id];
    }

    return test_occupancy_cntr[occ_type][id];
}

void
test_print_counter(counters::type_e type, counters::occupancy_id::type_e occ_type, uint32_t id)
{
    static const char* type2str[] = {"MAC_RELAY", "AC_PORT", "OCCUPANCY"};
    static const char* occ_type2str[] = {"em_group", "em_core", "__none__"};

    PRINT("counter(%s", type2str[type]);
    if (type == counters::OCCUPANCY) {
        PRINT("::%s", occ_type2str[occ_type]);
    }
    PRINT(", %2d) is %2d\n", id, test_get_counter(type, occ_type, id));
}

void
test_check_counter(counters::type_e type, counters::occupancy_id::type_e occ_type, uint32_t id, uint32_t exp_val)
{
    int exp_count, count;
    count = test_get_counter(type, occ_type, id);
    PRINT("-COUNT- expect val: %2d at ", exp_val);
    test_print_counter(type, occ_type, id);
    ASSERT(count == exp_val);
}

//*****************************************
// AUX
//*****************************************

bool
compare_keys(long_entry_data* d1, long_entry_data* d2)
{
    return (d1->key0 == d2->key0) && (d1->key1 == d2->key1) && (d1->key2 == d2->key2);
}

void
apply_rule_table()
{
    // check if rule table is full
    uint32_t* cand_key = (uint32_t*)test_em_response_reg.rec.key;
    uint32_t* rule_key = (uint32_t*)test_rule_table.rec.key;
    if (*cand_key != *rule_key) {
        return;
    }

    test_em_response_reg.rec.payload0 = test_rule_table.rec.payload0;
    test_em_response_reg.data.rule_hit = test_rule_table.data.rule_hit;
}

//*****************************************
// RESPONSES
//*****************************************

void
ffe_response()
{
    if (test_em_request_reg.data.for_cam) {
        // for testing purposes, assume that writing to CAM always succeeds
        test_em_response_reg.data.hit = 1;
        test_em_response_reg.data.em_index = 0;
        write_reg(UAUX_EM_RESPONSE_REG, &test_em_response_reg);
        return;
    }

    cem_data* candidate = 0;
    int core = test_em_request_reg.data.em_core;

    for (int bank = 0; bank < test_CEM_NUM_BANKS; ++bank) {
        // check if bank is a part of request
        if (!(test_em_request_reg.data.em_bank_bitset & (1 << bank))) {
            continue;
        }
        int entry = calculate_hash(&test_em_request_reg.rec.key[2], bank);
        if (!test_get_cem_payload(core, bank, entry)) {
            test_em_response_reg.data.em_index = entry;
            test_em_response_reg.data.em_bank = bank;
            test_em_response_reg.data.hit = 1;
            write_reg(UAUX_EM_RESPONSE_REG, &test_em_response_reg);
            return;
        }
        // else - remember the candidate
        if (!candidate) {
            candidate = test_get_cem(core, bank, entry);
        }
    }

    // no hit found - report the candidate
    memcpy(&test_em_response_reg, candidate, 28);
    test_em_response_reg.data.em_index = candidate->data.em_index;
    test_em_response_reg.data.em_bank = candidate->data.em_bank;
    test_em_response_reg.data.key_size = candidate->data.key_size;

    // age values are not returned - screw them
    test_em_response_reg.data.age_value = 1;
    test_em_response_reg.data.age_owner = 0;
    test_em_response_reg.data.hit = 0;

    apply_rule_table();

    write_reg(UAUX_EM_RESPONSE_REG, &test_em_response_reg);
}

void
delete_response()
{
    if (test_em_request_reg.data.for_cam) {
        // for testing purposes, assume that writing to CAM always succeeds
        return;
    }

    int core = test_em_request_reg.data.em_core;
    int entry = test_em_request_reg.data.em_index;
    int bank = 0;

    while (!(test_em_request_reg.data.em_bank_bitset & (1 << bank)) && (bank < test_CEM_NUM_BANKS)) {
        ++bank;
    }

    if ((bank >= test_CEM_NUM_BANKS) || entry >= test_CEM_NUM_ENTRIES || !test_get_cem_payload(core, bank, entry)) {
        test_em_response_reg.data.hit = 0;
        write_reg(UAUX_EM_RESPONSE_REG, &test_em_response_reg);
        return;
    }

    cem_data* curr = test_get_cem(core, bank, entry);
    memset(curr, 0, sizeof(cem_data));

    return;
}

void
read_response()
{
    if (test_em_request_reg.data.for_cam) {
        // not testing CAM
        test_em_response_reg.data.hit = 0;
        test_em_response_reg.data.em_index = 0;
        write_reg(UAUX_EM_RESPONSE_REG, &test_em_response_reg);
        return;
    }

    int core = test_em_request_reg.data.em_core;
    int entry = test_em_request_reg.data.em_index;
    int bank = 0;

    while (!(test_em_request_reg.data.em_bank_bitset & (1 << bank)) && (bank < test_CEM_NUM_BANKS)) {
        ++bank;
    }

    if ((bank >= test_CEM_NUM_BANKS) || entry >= test_CEM_NUM_ENTRIES || !test_get_cem_payload(core, bank, entry)) {
        test_em_response_reg.data.hit = 0;
        write_reg(UAUX_EM_RESPONSE_REG, &test_em_response_reg);
        return;
    }

    cem_data* curr = test_get_cem(core, bank, entry);

    memcpy(&test_em_response_reg, curr, EM_LONG_KEY + EM_LONG_PAYLOAD);
    test_em_response_reg.data.em_bank = bank;
    test_em_response_reg.data.em_index = entry;
    test_em_response_reg.data.key_size = curr->data.key_size;

    test_em_response_reg.data.age_value = curr->data.age_value;
    test_em_response_reg.data.age_owner = curr->data.age_owner;
    test_em_response_reg.data.hit = 1;

    apply_rule_table();

    write_reg(UAUX_EM_RESPONSE_REG, &test_em_response_reg);
    return;
}

void
lookup_response()
{
    if (test_em_request_reg.data.for_cam) {
        // not testing CAM
        test_em_response_reg.data.hit = 0;
        test_em_response_reg.data.em_index = 0;
        write_reg(UAUX_EM_RESPONSE_REG, &test_em_response_reg);
        return;
    }

    int core = test_em_request_reg.data.em_core;

    for (int bank = 0; bank < test_CEM_NUM_BANKS; ++bank) {

        int entry = calculate_hash(&test_em_request_reg.rec.key[2], bank);
        cem_data* curr = test_get_cem(core, bank, entry);

        if (compare_keys(&test_em_request_reg.rec, &curr->rec)) {
            memcpy(&test_em_response_reg, curr, EM_LONG_KEY + EM_LONG_PAYLOAD);
            test_em_response_reg.data.em_bank = bank;
            test_em_response_reg.data.em_index = entry;
            bool is_mac = is_mac_entry(&curr->rec);
            test_em_response_reg.data.key_size = (is_mac) ? EM_LEARN_KEY_SIZE : EM_WIDE_KEY_SIZE;

            // age values are not returned - screw them
            test_em_response_reg.data.age_value = 1;
            test_em_response_reg.data.age_owner = 0;
            test_em_response_reg.data.hit = 1;

            apply_rule_table();

            write_reg(UAUX_EM_RESPONSE_REG, &test_em_response_reg);
            return;
        }
    }
    test_em_response_reg.data.hit = 0;
    write_reg(UAUX_EM_RESPONSE_REG, &test_em_response_reg);
}

void
store_response(bool is_only_age)
{
    if (test_em_request_reg.data.for_cam) {
        // assume success
        return;
    }

    int core = test_em_request_reg.data.em_core;
    int bank = 0;
    while (!(test_em_request_reg.data.em_bank_bitset & (1 << bank)) && (bank < test_CEM_NUM_BANKS)) {
        ++bank;
    }
    if (bank >= test_CEM_NUM_BANKS) {
        return;
    }

    cem_data* candidate;

    if (!is_only_age) {
        int entry = calculate_hash(&test_em_request_reg.rec.key[2], bank);
        candidate = test_get_cem(core, bank, entry);
        memcpy(candidate, &test_em_request_reg, 28);
        candidate->rec.padding0 = 0;
        candidate->data.em_bank = bank;
        candidate->data.em_index = entry;
        bool is_mac = is_mac_entry(&test_em_request_reg.rec);
        candidate->data.key_size = (is_mac) ? EM_LEARN_KEY_SIZE : EM_WIDE_KEY_SIZE;
    } else {
        // for age store, the entry is provided
        candidate = test_get_cem(core, bank, test_em_request_reg.data.em_index);
    }
    candidate->data.age_value = test_em_request_reg.data.age_value;
    candidate->data.age_owner = test_em_request_reg.data.age_owner;

    test_em_response_reg.data.hit = 1;
    write_reg(UAUX_EM_RESPONSE_REG, &test_em_response_reg);
}

void
no_response()
{
    write_reg(UAUX_EM_RESPONSE_REG, &test_em_response_reg);
}

void
em_response()
{
    memset(&test_em_response_reg, 0, sizeof(em_response_data));
    read_reg(&test_em_request_reg, UAUX_EM_REQUEST_REG);
    switch (test_em_request_reg.data.command) {
    case EM_COMMAND_FFE:
        ffe_response();
        break;
    case EM_COMMAND_WRITE:
        store_response(0 /*not only age*/);
        break;
    case EM_COMMAND_AGE_WRITE:
        store_response(1 /*only age*/);
        break;
    case EM_COMMAND_LOOKUP:
        lookup_response();
        break;
    case EM_COMMAND_READ:
    case EM_COMMAND_AGE_READ:
        read_response();
        break;
    case EM_COMMAND_DELETE:
        delete_response();
        break;
    default:
        PRINT("Missing command %d\n", test_em_request_reg.data.command);
        ASSERT(0);
    }
    status_reg_clear(UAUX_REG_STATUS_EM_REQUEST);
    status_reg_set(UAUX_REG_STATUS_EM_RESPONSE);
    status_reg_write();
}

void
group_response()
{
    group_request_data req;
    group_response_data resp;
    read_reg(&req, UAUX_GROUP_REQUEST_REG);
    // core is the second half of the first byte of the key.
    resp.em_group = req.key[0] >> 4;
    resp.em_core = test_group2core[resp.em_group];
    resp.allowed_bank_bitset = (1 << test_CEM_NUM_BANKS) - 1;
    write_reg(UAUX_GROUP_RESPONSE_REG, &resp);

    status_reg_clear(UAUX_REG_STATUS_GROUP_REQUEST);
    status_reg_set(UAUX_REG_STATUS_GROUP_RESPONSE);
    status_reg_write();
}

void
counter_response_write(uint32_t rw, int32_t* cntr, uint32_t id, uint32_t count)
{
    counter_request_data data;
    switch (rw) {
    case counters::READ:
        data.counter = cntr[id];
        write_reg(UAUX_COUNTERS_RESPONSE_REG, &data.counter);
        break;
    case counters::WRITE:
        cntr[id] = count;
        break;
    default:
        ASSERT(false);
    }
}

void
counter_response()
{
    counter_request_data req;
    read_reg(&req, UAUX_COUNTERS_REQUEST_REG);

    counters::address addr = {.val = 0};
    addr.val = req.addr;
    switch (addr.type) {
    case counters::AVAILABLE_AC_PORT:
        ASSERT(addr.id < 16);
        counter_response_write(addr.rw, test_l2_port_limit_cntr, addr.id, req.counter);
        break;
    case counters::AVAILABLE_MAC_RELAY:
        ASSERT(addr.id < 16);
        counter_response_write(addr.rw, test_mac_relay_limit_cntr, addr.id, req.counter);
        break;
    case counters::OCCUPANCY:
        counters::occupancy_id occ_id = {.val = 0};
        occ_id.val = addr.id;
        if (occ_id.occ_type == counters::occupancy_id::EM_CORE) {
            ASSERT(occ_id.occ_id < 16);
        } else if (occ_id.occ_type == counters::occupancy_id::EM_GROUP) {
            ASSERT(occ_id.occ_id < 256);
        }

        if (occ_id.occ_id < 16) {
            counter_response_write(addr.rw, test_occupancy_cntr[occ_id.occ_type], occ_id.occ_id, req.counter);
        }
        break;
    }

    status_reg_clear(UAUX_REG_STATUS_COUNTERS_REQUEST);
    status_reg_set(UAUX_REG_STATUS_COUNTERS_RESPONSE);
    /*
    if ( addr.rw != counters::WRITE ) {
        // In case of WRITE to counters, HW does not respond.
        // Modeling the same behavior here
        status_reg_set(UAUX_REG_STATUS_COUNTERS_RESPONSE);
    }
    */
    status_reg_write();
}

//*****************************************
// INTERFACES
//*****************************************

volatile int test_status = 0;
void
test_exit(int status)
{
    test_status = status;
    if (status) {
        printf("TEST DONE. Test existed abnormally. Status: %d\n", status);
    } else {
        printf("TEST DONE. Test existed normally.\n");
    }
    exit(0);
}

void
test_assert_brk()
{
    /* Breakpoint placeholder */
    test_exit(1);
}

void
test_init_cem()
{
    // init banks (hash)
    memset(&test_hash_data, 0, sizeof(test_hash_data));
    memset(&test_rule_table, 0, sizeof(test_rule_table));
    // all groups will go to core 0
    memset(&test_group2core, 0, sizeof(test_group2core));

    // Counters
    memset(&test_occupancy_cntr, 0, sizeof(test_occupancy_cntr));
    for (int i = 0; i < 16; ++i) {
        test_l2_port_limit_cntr[i] = test_mac_relay_limit_cntr[i] = 10;
    }
}

void
test_cem_response_poll()
{
    if (status_reg_test(UAUX_REG_STATUS_GROUP_REQUEST)) {
        group_response();
        return;
    }
    if (status_reg_test(UAUX_REG_STATUS_EM_REQUEST)) {
        em_response();
        return;
    }
    if (status_reg_test(UAUX_REG_STATUS_COUNTERS_REQUEST)) {
        counter_response();
        return;
    }
}

// The pointer will be initialized during the test
test_main_loop_poll_func_ptr test_main_loop_poll_callback;
// Stub responses to all the requests
void
test_poll()
{
    status_reg_read();

    // first priority is to respond to data requests
    if (status_reg_test(UAUX_REG_STATUS_REQUEST)) {
        test_cem_response_poll();
        return;
    }

    // second priority - acknoledge Done statuses
    // actually nothing to do here. For stub - we don't care about that
    if (status_reg_test(UAUX_REG_STATUS_DONE)) {
        status_reg_clear(UAUX_REG_STATUS_DONE);
        status_reg_write();
    }

    // check if can send new command
    // even if there is a command during execution, test should handle that
    test_main_loop_poll_callback();
}

void
test_create_learn_cmd(learn_command_e cmd, uint32_t key, uint32_t payload, bool owner)
{
    static const char* cmd_str[] = {"ADD_NEW", "UPDATE ", "REFRESH"};
    learn_data reg;

    reg.command = cmd;
    reg.key0 = key;
    reg.owner = owner;

    short_key_encoding* key_enc = (short_key_encoding*)reg.key;
    short_payload_encoding* pl_enc = (short_payload_encoding*)reg.payload;

    key_enc->mac_addr1 = 0xf_ffff;
    // set relay id to funky index - we don't count it anyway
    key_enc->mac_relay = 0x2;
    // make sure top 2 bits are on
    key_enc->mac_relay_ext = 0x3;
    key_enc->key_padding = 0;
    // make sure top 2 bits are on
    pl_enc->code = 0x3;
    pl_enc->l2_port = payload;

    write_reg(UAUX_LEARN_REG, &reg);
    status_reg_set(UAUX_REG_STATUS_LEARN);
    status_reg_write();

    PRINT("-TST- em_learn( %s k: 0x%08X, pl: 0x%06X )\n", cmd_str[cmd], reg.key0, reg.payload0);
}

void
test_create_cpu_cmd(arc_cpu_command* reg)
{
    static const char* cmd_str[] = {"ARC_CPU_COMMAND_SWITCH_MAX_MAC",
                                    "ARC_CPU_COMMAND_SWITCH_INIT_MAC",
                                    "ARC_CPU_COMMAND_LOOKUP_KEY",
                                    "ARC_CPU_COMMAND_LAST_LOOKUP_LOCATION",
                                    "ARC_CPU_COMMAND_READ_ENTRY",
                                    "ARC_CPU_COMMAND_AGE_READ_ENTRY",
                                    "ARC_CPU_COMMAND_INSERT_TABLE_SINGLE_ENTRY",
                                    "ARC_CPU_COMMAND_ERASE_TABLE_SINGLE_ENTRY",
                                    "ARC_CPU_COMMAND_INSERT_TABLE_DOUBLE_ENTRY",
                                    "ARC_CPU_COMMAND_ERASE_TABLE_DOUBLE_ENTRY",
                                    "ARC_CPU_COMMAND_SET_ACTIVE_REDUCED_BANKS",
                                    "ARC_CPU_COMMAND_SET_ACTIVE_FULL_BANKS"};

    PRINT("-TST- reg: 0x%08x cmd: 0x%x em_cpu( %s )\n", *(uint32_t*)reg, reg->command, cmd_str[reg->command]);
    ASSERT(reg->command > ARC_CPU_COMMAND_NONE && reg->command <= ARC_CPU_COMMAND_LAST);
    reg->state = ARC_CPU_FSM_STATE_CPU;
    write_reg(UAUX_CPU_REG, reg);
    reg->state = ARC_CPU_FSM_STATE_ARC;
    write_cpu_status_reg((void*)reg);
}

void
test_create_rule(bulk_command_e cmd, uint32_t key, uint32_t payload)
{
    static const char* cmd_str[] = {"NONE   ", "UPDATE ", "DELETE ", "SEND   "};

    test_rule_table.data.rule_hit = cmd;
    test_rule_table.rec.key0 = key;

    short_key_encoding* key_enc = (short_key_encoding*)test_rule_table.rec.key;
    short_payload_encoding* pl_enc = (short_payload_encoding*)test_rule_table.rec.payload;

    key_enc->mac_addr1 = 0xf_ffff;
    // set relay id to funky index - we don't count it anyway
    key_enc->mac_relay = 0x2;
    // make sure top 2 bits are on
    key_enc->mac_relay_ext = 0x3;
    key_enc->key_padding = 0;

    // make sure top 2 bits are on
    pl_enc->code = 0x3;
    pl_enc->l2_port = payload;

    PRINT("-TST-     rule( %s k: 0x%08X, pl: 0x%06X )\n", cmd_str[cmd], test_rule_table.rec.key0, test_rule_table.rec.payload0);
}

void
test_create_load_balance_request(uint32_t core, uint32_t group)
{
    load_balance_request.em_core = core;
    load_balance_request.em_group = group;

    PRINT("-TST- load_balance( core: %d, group: %d )\n", core, group);
}
