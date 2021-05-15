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

#include "arc_cpu_common.h"
#include "common.h"
#include "status_reg.h"
#include "uaux_regs.h"
#include "uaux_regs_commands.h"
#include "uaux_regs_mem.h"

#include "routine_counters.h"

#include "arc_routines.h"
#include "cam_manager.h"
#include "counters.h"
#include "debug_counters.h"
#include "em_commands.h"
#include "test_if.h"

// for memcpy/memset
#include <string.h>

/// @file
/// @brief Implementation of EM Routines: learn, aging, bulk update and load balancing

//*********************************
// GLOBAL DATA
//*********************************

/// @brief bitset for all the cores which has new available entry since last evacuation
uint32_t erase_bitset = 0;

uint32_t key_size_map = 0;

/// @brief Progress cam-counter for evacuation
periodic_counter evacuation_count = {.data.bits.state = periodic_counter::DONE};

/// @brief Progress counter for periodic aging update
periodic_counter aging_count = {.data.bits.state = periodic_counter::DONE};

/// @brief Progress counter for periodic bulk update
periodic_counter bulk_count = {.data.bits.state = periodic_counter::DONE};

/// @brief Progress counter for load balancing
load_balance_data load_balance_count = {.stage = load_balance_data::DONE};

/// @brief CPU return status data
arc_cpu_status cpu_status = {.status = ARC_CPU_COMMAND_STATUS_SUCCESS};

/// @brief Global variable to store last CPU lookup location, since it's done in two requests.
arc_cpu_command last_lookup_location;

/// @brief CPU command to corresponding key size mapping
const uint32_t cpu_command_to_key_size[ARC_CPU_COMMAND_LAST + 1] = {
        [ARC_CPU_COMMAND_SWITCH_MAX_MAC] = EM_NO_KEY_SIZE,
        [ARC_CPU_COMMAND_SWITCH_INIT_MAC] = EM_NO_KEY_SIZE,
        [ARC_CPU_COMMAND_INSERT_TABLE_SINGLE_ENTRY] = EM_LEARN_KEY_SIZE,
        [ARC_CPU_COMMAND_ERASE_TABLE_SINGLE_ENTRY] = EM_LEARN_KEY_SIZE,
        [ARC_CPU_COMMAND_INSERT_TABLE_DOUBLE_ENTRY] = EM_WIDE_KEY_SIZE,
        [ARC_CPU_COMMAND_ERASE_TABLE_DOUBLE_ENTRY] = EM_WIDE_KEY_SIZE,
};

// extract age_value field from payload to influence age_value
//
// refer to leaba_defined.npl, mact_result_t
//
// header_type mac_forwarding_table_payload_t
// age_value is located on the 21th bit from LSB
#define ARC_CPU_APPLICATION_SPECIFIC_FIELDS_STARTS 20

//*********************************
// ROUTINES
//*********************************
static inline void
new_entry_counters_incr_cond(bool status, bool is_mac, const em_entry_data* rec)
{
    if (!status) {
        return;
    }

    // MAC entries are single wide, IPv6 entries should be double wide
    int num_entries = (rec->data.key_size == EM_WIDE_KEY_SIZE && !is_mac) ? 2 : 1;
    update_counters(num_entries, is_mac);
}

static inline void
delete_entry_counters_decr(bool is_mac, const em_entry_data* rec)
{
    // MAC entries are single wide, IPv6 entries should be double wide
    int num_entries = (rec->data.key_size == EM_WIDE_KEY_SIZE && !is_mac) ? -2 : -1;
    update_counters(num_entries, is_mac);
}

static inline void
set_cpu_status(arc_cpu_command_status_e status)
{
    cpu_status.status = status;
    cpu_status.core = op_ctx.group_data.em_core;

    cpu_status.stage.load_balance_stage = load_balance_count.stage;
}

static void
get_application_specific_field(uint32_t* payload, arc_cpu_application_specific_fields* fields)
{
    // application specific field starts after 20b destination
    fields->flat = 0;
    // OR in the 12b in the payload
    fields->flat |= *payload >> ARC_CPU_APPLICATION_SPECIFIC_FIELDS_STARTS;
    // OR in the rest of the bits in payload
    fields->flat |= *(payload + 1) << (32 - ARC_CPU_APPLICATION_SPECIFIC_FIELDS_STARTS);
}

void
initialize_active_banks()
{
    // Init active banks by reading arbitrary (0) entry from group register
    group_request_data request_reg;

    // request_and_poll function writes once and read status for 10000 times max
    // cdb->top->validreg could be overwritten by LDB after ARC set the register.
    // If this happens, request_and_poll should time out waiting for response.
    // Retry once before ARC's mainloop processing of LDB-set requests.
    bool ret = false;
    ret = request_and_poll(&request_reg, UAUX_GROUP_REQUEST_REG, UAUX_REG_STATUS_GROUP_REQUEST, UAUX_REG_STATUS_GROUP_RESPONSE);
    if (!ret) {
        ret = request_and_poll(&request_reg, UAUX_GROUP_REQUEST_REG, UAUX_REG_STATUS_GROUP_REQUEST, UAUX_REG_STATUS_GROUP_RESPONSE);
    }

    if (ret) {
        group_response_data ret;
        read_reg(&ret, UAUX_GROUP_RESPONSE_REG);
        active_banks = ret.allowed_bank_bitset;
#ifdef GIBRALTAR
        // Full details are in "common.h". Workaround for GB errata 3.1.10
        // 8 MSB are always zero due to HW bug
        // CEM always get mor than 8 banks so we assume the missing bits to be ones
        active_banks |= WORKAROUND_ENABLE_CLEARED_CEM_BANKS;
#endif
    }
}

void
initialize_occupancy_counters()
{
    counter_shadow counter = {.counter = 0};

    counters::occupancy_id id = {.val = 0};
    counters::address addr = {.val = 0};
    addr.type = counters::OCCUPANCY;
    addr.rw = true;
    counter.counter = 0;
    id.occ_type = counters::occupancy_id::EM_CORE;
    for (size_t index = 0; index < counters::NUM_OF_CORES_IN_CEM; ++index) {
        id.occ_id = index;
        addr.id = id.val;
        counter.addr = addr.val;
        // request_and_poll function writes once and read status for 10000 times max
        // cdb->top->validreg could be overwritten by LDB after ARC set the register.
        // If this happens, request_and_poll should time out waiting for response.
        // Retry once before ARC's mainloop processing of LDB-set requests.
        bool ret = false;
        ret = request_and_poll(
            &counter, UAUX_COUNTERS_REQUEST_REG, UAUX_REG_STATUS_COUNTERS_REQUEST, UAUX_REG_STATUS_COUNTERS_RESPONSE);
        if (!ret) {
            ret = request_and_poll(
                &counter, UAUX_COUNTERS_REQUEST_REG, UAUX_REG_STATUS_COUNTERS_REQUEST, UAUX_REG_STATUS_COUNTERS_RESPONSE);
        }
    }

    id.val = 0;
    addr.val = 0;
    id.occ_type = counters::occupancy_id::EM_GROUP;
    addr.type = counters::OCCUPANCY;
    addr.rw = true;
    counter.counter = 0;
    for (size_t index = 0; index < counters::NUM_OF_GROUPS_IN_CEM; ++index) {
        id.occ_id = index;
        addr.id = id.val;
        counter.addr = addr.val;
        // request_and_poll function writes once and read status for 10000 times max
        // cdb->top->validreg could be overwritten by LDB after ARC set the register.
        // If this happens, request_and_poll should time out waiting for response.
        // Retry once before ARC's mainloop processing of LDB-set requests.
        bool ret = false;
        ret = request_and_poll(
            &counter, UAUX_COUNTERS_REQUEST_REG, UAUX_REG_STATUS_COUNTERS_REQUEST, UAUX_REG_STATUS_COUNTERS_RESPONSE);
        if (!ret) {
            ret = request_and_poll(
                &counter, UAUX_COUNTERS_REQUEST_REG, UAUX_REG_STATUS_COUNTERS_REQUEST, UAUX_REG_STATUS_COUNTERS_RESPONSE);
        }
    }
}

/// @brief data initiaization helper
void
init_entry_from_response_reg(em_entry_data* next, int32_t orig_index)
{
    // the structure is the same, therefore, we can copy payload and key as one
    memset(next, 0, sizeof(em_entry_data));
    memcpy(&next->rec, &op_ctx.em_response_reg.rec, sizeof(long_entry_data));

    next->data.orig_index = orig_index;
    next->data.orig_bank = op_ctx.em_response_reg.data.em_bank;
    next->data.orig_for_cam = op_ctx.em_response_reg.data.for_cam;
    next->data.em_index = op_ctx.em_response_reg.data.em_index;
    next->data.em_bank = op_ctx.em_response_reg.data.em_bank;

    next->data.age_owner = op_ctx.em_response_reg.data.age_owner & 0x1;
    next->data.age_value = op_ctx.em_response_reg.data.age_value & 0x7;
    next->data.age_valid = true;

    next->data.key_size = op_ctx.em_response_reg.data.key_size;
}

/// @brief data initiaization helper
void
init_entry_from_learn_reg(learn_data* learn_reg, em_entry_data* next)
{
    memset(next, 0, sizeof(em_entry_data));
    // PAYLOAD: copying short payload to long one. The first field of destination should be enough
    next->rec.payload0 = learn_reg->payload0;

    // KEY: copying short key to long key.
    learn_reg->padding0 = 0;
    memcpy(next->rec.key, learn_reg->key, EM_SHORT_KEY);
    // take only the first 14 bits of the 3rd key register (key size is 78 = 32X2 + 14)
    next->rec.key2 = next->rec.key2 & 0x3fff;
    next->data.orig_index = EM_NONE;
    next->data.orig_bank = EM_NONE;

    // if command is WRITE_NEW or UPDATE, owner is updated and the age is accordingly
    // if command is REFRESH, the owner is not updated but it's essentially ==false
    // NOTE: age_owner passed from LDB has different logic of system learn entry = True,
    //       and local learn entry = False
    next->data.age_owner = (learn_reg->command == LEARN_COMMAND_REFRESH) ? 0 : !learn_reg->owner;
    next->data.age_value = next->data.age_owner ? EM_NEW_MAX_AGE : (EM_REFRESH_AGE - 1);
    next->data.age_valid = 1;

    next->data.key_size = EM_LEARN_KEY_SIZE;
}

/// @brief data initiaization helper
void
init_new_entry_from_cpu(arc_cpu_command* cpu_reg, em_entry_data* next)
{
    memset(next, 0, sizeof(em_entry_data));

    memcpy(next->rec.payload, cpu_reg->params.table_params.payload, MAX_TABLE_PAYLOAD_LEN_IN_BYTES);
    memcpy(next->rec.key, cpu_reg->params.table_params.key, MAX_TABLE_KEY_LEN_IN_BYTES);

    next->data.orig_index = EM_NONE;
    next->data.orig_bank = EM_NONE;

    next->data.key_size = cpu_command_to_key_size[cpu_reg->command];
    next->data.cores_bitmap = cpu_reg->candidate_cores_bitmap;

    // learn commands from cpu can have age value or not, initialize with default
    next->data.age_owner = 1;
    next->data.age_value = EM_NO_AGING_AGE;
    next->data.age_valid = 1;

    if (cpu_reg->command == ARC_CPU_COMMAND_INSERT_TABLE_SINGLE_ENTRY && is_mac_entry(&next->rec)) {
        // change age_value only for MAC entries
        //
        // extract age_value field from payload to influence age_value
        //
        // refer to leaba_defined.npl, mact_result_t
        //
        // header_type mac_forwarding_table_payload_t
        // age_value is located on the 21th bit from LSB
        arc_cpu_application_specific_fields asf;
        get_application_specific_field((uint32_t*)next->rec.payload, &asf);
        next->data.age_value = asf.fields.age_value;
        next->data.age_owner = asf.fields.age_owner;
        // Clear the ASF so that we only put destination (20b) into EM entry data
        *(uint32_t*)next->rec.payload = (*(uint32_t*)next->rec.payload << (32 - ARC_CPU_APPLICATION_SPECIFIC_FIELDS_STARTS))
                                        >> (32 - ARC_CPU_APPLICATION_SPECIFIC_FIELDS_STARTS);
        *((uint32_t*)next->rec.payload + 1) = 0;

        if (asf.fields.age_value == EM_NO_AGING_AGE) {
            debug_counter_incr(arc_debug_counters::STATIC_MAC_ENTRIES);
        } else {
            debug_counter_incr(arc_debug_counters::DYNAMIC_MAC_ENTRIES);
        }
    }
}

/// @brief Recursive search for free entry to store new
/// candidate
///
/// @param[in]  curr        entry to relocate
/// @param[in]  depth       recursion depth
///
bool
relocate_entry_dfs(em_entry_data* curr, uint32_t bank_bitset, int depth)
{
    // first check if possible
    if (depth > EM_FFE_SEARCH_DEPTH) {
        return false;
    }

    uint32_t curr_bank_bitset = bank_bitset;
    // check all possible banks if can relocate
    if (curr->data.orig_bank != EM_NONE) {
        curr_bank_bitset &= ~(1 << curr->data.orig_bank);
    }

    // not found - check if can relocate each one of the banks
    // the first candidate is already in response_reg
    while (curr_bank_bitset) {
        curr_bank_bitset &= ~(1 << op_ctx.em_response_reg.data.em_bank);

        if (op_ctx.em_response_reg.data.key_size != EM_WIDE_KEY_SIZE) {
            em_entry_data candidate;
            init_entry_from_response_reg(&candidate, curr->data.em_index);

            uint32_t candidate_bitset = bank_bitset & ~(1 << candidate.data.orig_bank);
            if (!candidate_bitset) {
                // corner case, only 1 bank allowed in core
                return false;
            }
            // check if can store it in other banks
            bool store_success = ffe_and_store(&candidate, candidate_bitset, false /* not for CAM */);

            // Check age_value again
            if (store_success && op_ctx.em_response_reg.data.hit) {
                age_value_check(NULL, &candidate, 0, true, EM_CHECK_RECORD_AGE_VALUE);
            }

            // if not successful, try to relocate the candidate
            store_success = store_success || relocate_entry_dfs(&candidate, bank_bitset, depth + 1);

            if (store_success) {
                // succeeded to relocate candidate
                // now can store the original record and return
                store_request(EM_COMMAND_WRITE, curr, false /* not for CAM */);
                return true;
            }
        }

        // next candidate
        if (curr_bank_bitset) {
            ffe_request(curr, curr_bank_bitset, false /* not for CAM */);
            // make sure candidate is provided - means no hit
            ASSERT(!op_ctx.em_response_reg.data.hit);
        }
    }
    return false;
}

/// @brief Try to insert new entry to Exact Match (LEARN_COMMAND_NEW_WRITE).
/// If the entry was stored successfully, it returns true, otherwise false.
///
/// Algorithm:
/// 1. Identify core group this entry belongs to.
/// 2. If free entry exists, store in it and return true.
/// 3. If no free entry exists:
///    a. Attempt to recursively relocate existing entries to different banks.
///    b. If successful, use the freed entry.
///    c. If unsuccessful, store to CAM.
///    d. If no place in CAM, return false.
///
bool
do_new_insert(em_entry_data* rec)
{
    // store to odd banks first
    bool was_stored = ffe_and_store(rec, op_ctx.group_data.allowed_bank_bitset & ODD_BANKS, false /* not for CAM */);
    if (was_stored) {
        ++sram_per_core_utilization[op_ctx.group_data.em_core];
        debug_counter_incr(arc_debug_counters::SIMPLE_INSERT);
        age_value_check(NULL, rec, 0, true, EM_CHECK_RECORD_AGE_VALUE);
        return true;
    }

    // store to all banks
    was_stored = ffe_and_store(rec, op_ctx.group_data.allowed_bank_bitset, false /* not for CAM */);
    if (was_stored) {
        ++sram_per_core_utilization[op_ctx.group_data.em_core];
        debug_counter_incr(arc_debug_counters::SIMPLE_INSERT);
        age_value_check(NULL, rec, 0, true, EM_CHECK_RECORD_AGE_VALUE);
        return true;
    }

    // if not successful, try to relocate entries to store
    was_stored = relocate_entry_dfs(rec, op_ctx.group_data.allowed_bank_bitset, 1 /* depth */);
    if (was_stored) {
        ++sram_per_core_utilization[op_ctx.group_data.em_core];
        debug_counter_incr(arc_debug_counters::RELOCATE);
        return true;
    }

    // if not successful, try to store to CAM
    was_stored = insert_cam_entry(rec);
    if (was_stored) {
        ++cam_per_core_utilization[op_ctx.group_data.em_core];
        cpu_status.inserted_to_cam = 1;
        debug_counter_incr(arc_debug_counters::CAM_INSERT);
        age_value_check(NULL, rec, 0, true, EM_CHECK_RECORD_AGE_VALUE);
        return true;
    }
    return false;
}

/// @brief Inserts new entry to Exact Match (LEARN_COMMAND_NEW_WRITE)
///
/// Try to insert the entry, if no place was found, then raise interrupt for host.
///
bool
new_insert(em_entry_data* rec)
{
    bool was_stored = do_new_insert(rec);

    if (!was_stored) {
        set_cpu_status(ARC_CPU_COMMAND_STATUS_ERESOURCE);
        cpu_status.stage.new_entry_insert_failure = 1;
        debug_counter_incr(arc_debug_counters::NEW_INSERT_FAILS);
        return false;
    }

    // Check age_value again
    if (op_ctx.em_response_reg.data.hit) {
        age_value_check(NULL, rec, (cpu_status.inserted_to_cam) ? 1 : 0, true, EM_CHECK_RECORD_AGE_VALUE);
    }
    return was_stored;

    // TODO - implement interrupt to CPU (could not store)
}

bool
try_new_insert_double_entry_to_banks(em_entry_data* rec)
{
    uint32_t banks_bitset = op_ctx.group_data.allowed_bank_bitset & EVEN_BANKS;
    ffe_request(rec, banks_bitset, false /*for_cam*/);

    if (!op_ctx.em_response_reg.data.hit) {
        // Did't find empty entry in even banks, so, insertion failed.
        return false;
    }
    // Found empty even bank - check odd bank as well
    periodic_counter location;
    location.data.bits.em_core = op_ctx.group_data.em_core;
    location.data.bits.em_entry = rec->data.em_index;
    location.data.bits.em_bank = rec->data.em_bank + 1;
    location.data.bits.for_cam = 0;
    em_entry_data odd_rec;
    read_request(&location, &odd_rec);

    // If no-hit, means odd bank is also empty.
    bool was_stored = !op_ctx.em_response_reg.data.hit;
    if (op_ctx.em_response_reg.data.hit) {
        // Odd bank is full - try to relocate
        uint32_t odd_rec_bitset = op_ctx.group_data.allowed_bank_bitset & ~(1 << rec->data.em_bank);
        was_stored = relocate_entry_dfs(&odd_rec, odd_rec_bitset, 1 /* depth */);
        debug_counter_incr_cond(arc_debug_counters::RELOCATE_FOR_DOUBLE, was_stored);
    }

    if (!was_stored) {
        return false;
    }

    store_request(EM_COMMAND_WRITE, rec, false /*for_cam*/);
    debug_counter_incr(arc_debug_counters::DOUBLE_INSERT);
    return true;
}

struct move_state {
    em_bank_bitmap_t explored_bank_bitmask;
    periodic_counter em_entry_location;
};

/// @brief Move entries as result of double entry relocation list relocation, and install a new entry.
///
/// Accepts a set of moves to perform (move_list), and moves them from last
/// to first, in order to make sure an entry gets placed in its new bank before
/// being removed from the old one.
///
/// That ensures all entries will be valid at any point in time.
/// After all existing entries are relocated, the empty slot created is used to install
/// the new entry (passed 'rec').
///
/// @param[in] rec          New record to install.
/// @param[in] move_list    List of relocation operations to perform.
/// @param[in] total_moves  Number of relocation operations in the list.
static bool
perform_double_entry_moves(em_entry_data* rec, move_state* move_list, uint8_t total_moves)
{
    if (!total_moves) {
        return true;
    }
    for (size_t current_move_index = total_moves - 1; current_move_index > 0; --current_move_index) {
        em_entry_data to_move_entry;
        em_entry_data* moved_entry = nullptr;
        read_request(&move_list[current_move_index - 1].em_entry_location, &to_move_entry);
        debug_counter_incr(arc_debug_counters::DBL_RELO_READ_TOTAL);

        // Install entry into new location before deleting it.
        to_move_entry.data.em_bank = move_list[current_move_index].em_entry_location.data.bits.em_bank;
        to_move_entry.data.em_index = move_list[current_move_index].em_entry_location.data.bits.em_entry;
        store_request(EM_COMMAND_WRITE, &to_move_entry, false /*for_cam*/);

        // Delete the moved entry
        moved_entry = &to_move_entry;
        moved_entry->data.em_bank = move_list[current_move_index - 1].em_entry_location.data.bits.em_bank;
        moved_entry->data.em_index = move_list[current_move_index - 1].em_entry_location.data.bits.em_entry;
        delete_request(moved_entry);
        debug_counter_incr(arc_debug_counters::DBL_RELO_BACKWALKS);
    }

    rec->data.em_bank = move_list[0].em_entry_location.data.bits.em_bank;
    rec->data.em_index = move_list[0].em_entry_location.data.bits.em_entry;
    store_request(EM_COMMAND_WRITE, rec, false /*for_cam*/);
    debug_counter_incr(arc_debug_counters::RELOCATE_DOUBLE);
    return true;
}

static inline uint8_t
get_double_entry_unexplored_bank(em_bank_bitmap_t explored_bank_bitmask)
{
    em_bank_bitmap_t unexplored_bank_mask = DOUBLE_ENTRY_EVEN_BANKS ^ explored_bank_bitmask;

    // find position of first high bit
    uint8_t bank = 0;
    while (unexplored_bank_mask) {
        if (unexplored_bank_mask & 0x1) {
            return bank;
        }
        ++bank;
        unexplored_bank_mask >>= 1;
    }

    return EM_BANKS_IN_CORE; // return max bank# so that caller can check
}

/// @brief The function find location where the entry_record can be installed in bank
///
/// If the hash collision occurs, the function returns record where the collision occured
///
/// @param[in] entry_record     Record that is used to find index in a bank
/// @param[in] memory_bank      Memory bank where entry_record will be hashed to.
/// @param[in] move_entry       move list record that stores location of
///                             entry_record to used for performing relocations.
/// @param[out] collided_entry  Record that is already present where entry_record hashed to.
/// @param[out] out_entry_type  Memory entry occpancy type where entry_record hashed to.

static void
get_hashed_entry_location_details(em_entry_data* entry_record,
                                  uint8_t memory_bank,
                                  move_state* move_entry,
                                  em_entry_data* collided_entry,
                                  em_entry_location_type& out_entry_type)
{
    // The function finds entry location in the specified bank.
    ffe_request(entry_record, 1 << memory_bank, false /*for_cam*/);

    periodic_counter* collided_loc = &move_entry->em_entry_location;
    collided_loc->data.bits.em_core = op_ctx.group_data.em_core;
    collided_loc->data.bits.em_entry = op_ctx.em_response_reg.data.em_index;
    collided_loc->data.bits.em_bank = op_ctx.em_response_reg.data.em_bank;
    collided_loc->data.bits.for_cam = 0;

    periodic_counter odd_bank_location;
    odd_bank_location.data.bits.em_core = collided_loc->data.bits.em_core;
    odd_bank_location.data.bits.em_entry = collided_loc->data.bits.em_entry;
    odd_bank_location.data.bits.em_bank = collided_loc->data.bits.em_bank + 1;
    odd_bank_location.data.bits.for_cam = 0;

    read_request(collided_loc, collided_entry);

    if (op_ctx.em_response_reg.data.hit) {
        if (collided_entry->data.key_size == EM_WIDE_KEY_SIZE) {
            // Even bank entry occupied by double entry key.
            out_entry_type = EM_DOUBLE_ENTRY;
        } else {
            // Even bank entry is occupied by single entry key... Check odd bank entry.
            read_request(&odd_bank_location, collided_entry);
            if (op_ctx.em_response_reg.data.hit) {
                out_entry_type = EM_SINGLE_ENTRY_BOTH_BANKS;
            } else {
                // last read was the odd bank and it's not occupied
                // bring response register to the collided entry in the even bank
                read_request(collided_loc, collided_entry);
                out_entry_type = EM_SINGLE_ENTRY_EVEN_BANK;
            }
        }
    } else {
        // Even bank entry is unoccupied... Check odd bank entry.
        read_request(&odd_bank_location, collided_entry);
        if (op_ctx.em_response_reg.data.hit) {
            out_entry_type = EM_SINGLE_ENTRY_ODD_BANK;
        } else {
            out_entry_type = EM_EMPTY_ENTRY;
        }
    }
}

/// @brief Check if the last element in move list caused loop
static inline bool
check_move_list_loop(move_state* move_list, size_t move_list_size)
{
    for (size_t j = 0; j < move_list_size - 1; ++j) {
        if (move_list[j].em_entry_location.data.bits.em_bank == move_list[move_list_size - 1].em_entry_location.data.bits.em_bank
            && move_list[j].em_entry_location.data.bits.em_entry
                   == move_list[move_list_size - 1].em_entry_location.data.bits.em_entry) {
            debug_counter_incr(arc_debug_counters::DBL_RELO_BST_LOOPS);
            return true;
        }
    }
    return false;
}

/// @brief Function builds move list and returns number of move
/// location in the move list. When the function is not able to
/// locate installable entry before exhausting allowed number of
/// moves, the function returns zero.
static int
build_double_entry_move_list(em_entry_data* entry, move_state* move_list)
{
    em_entry_data current_entry;
    em_entry_data collided_entry;
    em_entry_location_type entry_type;

    uint8_t moves = 1;

    for (size_t i = moves + 1; i <= EM_DBL_ENTRY_RELOCATION_DEPTH; ++i) {
        move_list[i].explored_bank_bitmask = 0;
    }

    while (moves > 0) {
        move_state* curr_state = &move_list[moves - 1];
        move_state* next_state = &move_list[moves];

        read_request(&curr_state->em_entry_location, &current_entry);

        uint8_t explore_bank = get_double_entry_unexplored_bank(next_state->explored_bank_bitmask);
        if (explore_bank == EM_BANKS_IN_CORE) {
            moves--;
            continue;
        }

        next_state->explored_bank_bitmask |= 1 << explore_bank;

        get_hashed_entry_location_details(&current_entry, explore_bank, next_state, &collided_entry, entry_type);
        uint8_t collided_entry_even_bank = next_state->em_entry_location.data.bits.em_bank;

        if (entry_type == EM_EMPTY_ENTRY) {
            return moves + 1;
        } else if (entry_type == EM_SINGLE_ENTRY_EVEN_BANK || entry_type == EM_SINGLE_ENTRY_ODD_BANK) {
            uint8_t block_bank = (entry_type == EM_SINGLE_ENTRY_ODD_BANK) ? collided_entry_even_bank : collided_entry_even_bank + 1;
            if (relocate_entry_dfs(
                    &collided_entry, op_ctx.group_data.allowed_bank_bitset & ~(1 << block_bank), EM_FFE_SEARCH_DEPTH /* depth */)) {
                return moves + 1;
            }
            moves--;
            continue;
        } else if (entry_type == EM_SINGLE_ENTRY_BOTH_BANKS) {
            if (relocate_entry_dfs(&collided_entry, op_ctx.group_data.allowed_bank_bitset, EM_FFE_SEARCH_DEPTH /* depth */)) {
                delete_request(&collided_entry);

                em_entry_data even_bank_entry;
                read_request(&next_state->em_entry_location, &even_bank_entry);

                if (relocate_entry_dfs(&even_bank_entry,
                                       op_ctx.group_data.allowed_bank_bitset & ~(1 << (collided_entry_even_bank + 1)),
                                       EM_FFE_SEARCH_DEPTH /* depth */)) {
                    return moves + 1;
                }
            }
            moves--;
            continue;
        }

        // Check for loop in moves list.
        // If most recent location is already seen/present in movelist, then its loop.
        bool loop_detected = check_move_list_loop(move_list, moves + 1 /* size of move list */);
        if (loop_detected) {
            moves--;
            continue;
        }

        if (moves >= EM_DBL_ENTRY_RELOCATION_DEPTH) {
            moves--;
            continue;
        }

        move_list[moves + 1].explored_bank_bitmask = 1 << explore_bank;
        moves++;
    }

    return 0;
}

/// @brief Function builds move list. If does sucessfully build
/// a move list, it returns size of move list else returns zero.
static int
build_double_entry_moves(em_entry_data* double_rec, move_state* move_list)
{
    // A new double entry can be installed in one of the n-way double banks.
    // Attempt to build move list in one of the n-ways.
    // Perform move computation until either empty slot is detected
    // or maximum number of relocation depth are searched.
    // If its not possible to build move list, then return zero.
    // If move list is prepared, then return length of move list.
    uint8_t move_list_size = 0;
    em_entry_location_type entry_type;
    em_entry_data collided_entry;
    uint8_t explore_bank = get_double_entry_unexplored_bank(0);

    move_list[0].explored_bank_bitmask = 0;
    while (explore_bank != EM_BANKS_IN_CORE) {
        move_list[0].explored_bank_bitmask |= 1 << explore_bank;
        get_hashed_entry_location_details(double_rec, explore_bank, &move_list[0], &collided_entry, entry_type);
        uint8_t collided_entry_even_bank = move_list[0].em_entry_location.data.bits.em_bank;

        if (entry_type == EM_DOUBLE_ENTRY && EM_DBL_ENTRY_RELOCATION_DEPTH > 0) {
            move_list[1].explored_bank_bitmask = 1 << explore_bank;
            move_list_size = build_double_entry_move_list(&collided_entry, move_list);
            if (move_list_size > 0) {
                // built a non empty move list using which new entry can be installed.
                return move_list_size;
            }
        } else if (entry_type == EM_SINGLE_ENTRY_EVEN_BANK || entry_type == EM_SINGLE_ENTRY_ODD_BANK) {
            uint8_t block_bank = (entry_type == EM_SINGLE_ENTRY_ODD_BANK) ? collided_entry_even_bank : collided_entry_even_bank + 1;

            if (relocate_entry_dfs(&collided_entry, op_ctx.group_data.allowed_bank_bitset & ~(1 << block_bank), 1 /* depth */)) {
                double_rec->data.em_bank = move_list[0].em_entry_location.data.bits.em_bank;
                double_rec->data.em_index = move_list[0].em_entry_location.data.bits.em_entry;
                store_request(EM_COMMAND_WRITE, double_rec, false /*for_cam*/);
                return 1;
            }
        } else if (entry_type == EM_SINGLE_ENTRY_BOTH_BANKS) {
            // start with the odd bank
            if (relocate_entry_dfs(&collided_entry, op_ctx.group_data.allowed_bank_bitset, 1 /* depth */)) {
                delete_request(&collided_entry);

                em_entry_data even_bank_entry;
                read_request(&move_list[0].em_entry_location, &even_bank_entry);
                if (relocate_entry_dfs(&even_bank_entry,
                                       op_ctx.group_data.allowed_bank_bitset & ~(1 << (collided_entry_even_bank + 1)),
                                       1 /* depth */)) {
                    double_rec->data.em_bank = move_list[0].em_entry_location.data.bits.em_bank;
                    double_rec->data.em_index = move_list[0].em_entry_location.data.bits.em_entry;
                    store_request(EM_COMMAND_WRITE, double_rec, false /*for_cam*/);
                    return 1;
                }
            }
        } else if (entry_type == EM_EMPTY_ENTRY) {
            double_rec->data.em_bank = move_list[0].em_entry_location.data.bits.em_bank;
            double_rec->data.em_index = move_list[0].em_entry_location.data.bits.em_entry;
            store_request(EM_COMMAND_WRITE, double_rec, false /*for_cam*/);
            return 1;
        }

        explore_bank = get_double_entry_unexplored_bank(move_list[0].explored_bank_bitmask);
    }

    return 0;
}

static bool
install_double_entry(em_entry_data* rec)
{
    move_state move_list[EM_DBL_ENTRY_RELOCATION_DEPTH + 1];

    debug_counter_incr(arc_debug_counters::DBL_INSERT_FFE_TOTAL);
    int moves = build_double_entry_moves(rec, move_list);
    if (moves > 1 && moves <= EM_DBL_ENTRY_RELOCATION_DEPTH + 1) {
        // perform movelist backward walk and install entries as per move list.
        return perform_double_entry_moves(rec, move_list, moves);
    }
    if (!moves) {
        // Could not install in SRAM. Try TCAM
        return false;
    }
    // No backwalk to perform as double entry is already installed at first location
    // after evicting single entry.
    return true;
}

/// @brief Inserts new double entry to Exact Match (LEARN_COMMAND_NEW_WRITE)
/// Double entry is an entry that takes two consequent banks in EM. It always starts at even bank (0,2,4..), while the second part
/// of the entry resides at the odd bank.
///
/// The insertion algorithm is the same as for single entry except the following details:
/// 1. The result of FFE request need to be checked:
///  - if no-hit is returned (empty spot), odd bank can still be occupied. This must be checked separately.
///  - if hit is returned, but the returned candidate is a single entry - odd bank can be vacant.
/// Therefore, the search for the free entry or relocation candidate becomes more cumbersome
/// 2. FFE request must be done only on even banks. Search for double entry in odd banks is undefined.
///
/// Because of HW issue (see description on #arc_cpu_common.h:arc_cpu_command:cores_bitmap) we need to
/// check the core that this entry should be inserted to, if it is not one of the valid cores, then the entry
/// must be inserted to CAM (if possible, otherwise return no place was found).
bool
new_insert_double_entry(em_entry_data* rec)
{
    // Check if the core that this entry is candidated to be inserted to, appears in the cores bitmap
    bool was_stored = false;
    bool can_insert_to_banks = (rec->data.cores_bitmap >> op_ctx.group_data.em_core) & 1;
    if (can_insert_to_banks) {
        // Install in SRAM wide/double entry. The function also
        // performs relocations if needed.
        // Search for empty table entry is terminated if more than
        // allowed/defined number of relocations are to be performed.
        was_stored = install_double_entry(rec);
        if (was_stored) {
            sram_per_core_utilization[op_ctx.group_data.em_core] += 2;
        }
    }

    if (!was_stored) {
        // No bank was found, try to store to CAM
        was_stored = insert_cam_entry(rec);
        if (was_stored) {
            ++cam_per_core_utilization[op_ctx.group_data.em_core];
            cpu_status.inserted_to_cam = 1;
            debug_counter_incr(arc_debug_counters::CAM_INSERT);
            return true;
        }
    }

    if (!was_stored) {
        set_cpu_status(ARC_CPU_COMMAND_STATUS_ERESOURCE);
        cpu_status.stage.new_entry_insert_failure = 1;
        debug_counter_incr(arc_debug_counters::NEW_INSERT_FAILS);
        return false;
    }

    return true;

    // TODO - implement interrupt to CPU (could not store)
}

///@brief Helper to learn_entry_update
bool
update_entry(em_command_e cmd, em_entry_data* rec, bool cpu_update)
{
    lookup_request(rec);
    // for_cam - response to lookup request returns whether found in CAM
    // if no space in new l2_port silently delete the entry
    ASSERT(op_ctx.em_response_reg.data.hit);
    debug_counter_incr_cond(arc_debug_counters::UPDATE_LOOKUP_FAIL, !op_ctx.em_response_reg.data.hit);

    bool mac_entry = is_mac_entry(&rec->rec);
    if (cmd != EM_COMMAND_AGE_WRITE && mac_entry) {
        if (!cpu_update) {
            // Retrieve entry's age value to determine if it's static/dynamic
            periodic_counter location;
            location.data.bits.em_core = op_ctx.group_data.em_core;
            location.data.bits.em_entry = rec->data.em_index;
            location.data.bits.em_bank = rec->data.em_bank;
            location.data.bits.for_cam = rec->data.orig_for_cam;
            em_entry_data org_rec;
            read_request(&location, &org_rec);
            if (!op_ctx.em_response_reg.data.hit) {
                debug_counter_incr(arc_debug_counters::UPDATE_LOOKUP_FAIL);
                return false;
            }
            if (org_rec.data.age_value == EM_NO_AGING_AGE && org_rec.data.age_owner == 1) {
                // HW should not update CPU installed entries
                debug_counter_incr(arc_debug_counters::UPDATE_CONFLICTS);
                return false;
            }
        }
        read_counters_from_op_context();
        counters_decr_payload();

        read_counter_from_entry_data(rec, counters::AVAILABLE_AC_PORT);
        bool status = counter_check_limit(&counter_ctx.l2_port);
        if (!status) {
            delete_request(rec);
            erase_bitset |= (1 << op_ctx.group_data.em_core);
            debug_counter_incr(arc_debug_counters::UPDATE_LIMIT_EXCEEDS);
            set_cpu_status(ARC_CPU_COMMAND_STATUS_ELIMIT);
            cpu_status.stage.update_entry_counter_limit = 1;
            return false;
        }

        counters_incr_payload();
    }

    store_request(cmd, rec, rec->data.orig_for_cam);

    // Check age_value again
    if (op_ctx.em_response_reg.data.hit) {
        // Found empty even bank - check odd bank as well
        age_value_check(NULL, rec, rec->data.orig_for_cam, true, EM_CHECK_RECORD_AGE_VALUE);
    }
    return true;
}

/// @brief Updates payload or age of the existing record.
///
/// @param[in]  cmd     can be either EM_COMMAND_WRITE or EM_COMMAND_AGE_WRITE
///
void
learn_entry_update(em_command_e cmd, em_entry_data* rec, bool cpu_update)
{
    bool status = update_entry(cmd, rec, cpu_update);
    cpu_status.inserted_to_cam = op_ctx.em_response_reg.data.for_cam;
    if (!status) {
        return;
    }

    // if Load balancing in progress and the entry is already copied to the new location, update both
    if (load_balance_count.stage == load_balance_data::COPY && load_balance_count.em_group == op_ctx.group_data.em_group) {
        // create temp counter to ease the comparison
        periodic_counter tmp;

        tmp.data.bits.em_entry = rec->data.em_index;
        tmp.data.bits.em_bank = rec->data.em_bank;
        tmp.data.bits.for_cam = op_ctx.em_response_reg.data.for_cam;
        tmp.data.bits.em_core = op_ctx.group_data.em_core;

        // load balance index is more advanced than the one we update - means the data exists in two locations
        if (tmp.data.count < load_balance_count.counter.data.count) {
            op_ctx.group_data.em_core = load_balance_count.dest_core;
            update_entry(cmd, rec, cpu_update);
        }
    }
}

/// @brief Adds new entry.
///
void
learn_new_insert(em_entry_data* rec)
{

    // if Load balancing in progress for the group, don't add new entries
    if (load_balance_count.stage == load_balance_data::COPY && load_balance_count.em_group == op_ctx.group_data.em_group) {
        return;
    }

    read_counter_from_entry_data(rec, counters::AVAILABLE_MAC_RELAY);
    read_counter_from_entry_data(rec, counters::AVAILABLE_AC_PORT);

    // silently ignore learn command if no space in banks or counters
    bool status = counters_check_limit();
    if (!status) {
        return;
    }

    lookup_request(rec);
    if (op_ctx.em_response_reg.data.hit) {
        learn_entry_update(EM_COMMAND_AGE_WRITE, rec, false); // update from HW
        return;
    }

    // continue only if succeeded
    status = new_insert(rec);
    new_entry_counters_incr_cond(status, true /* is_mac */, rec);
    debug_counter_incr(arc_debug_counters::LEARN_NEW);
}

void
em_learn_routine()
{
    // clear the global data
    memset(&op_ctx, 0, sizeof(op_ctx));
    memset(&counter_ctx, 0, sizeof(counter_context));

    // reading the entry and the command
    learn_data learn_reg;
    read_reg(&learn_reg, UAUX_LEARN_REG);
    em_entry_data rec;
    init_entry_from_learn_reg(&learn_reg, &rec);
    // get the core and the group
    group_request(&rec);

    int cmd = learn_reg.command;

    switch (cmd) {
    case LEARN_COMMAND_NEW_WRITE:
        learn_new_insert(&rec);
        debug_counter_incr(arc_debug_counters::LEARN_NEW_EVENTS);
        break;
    case LEARN_COMMAND_UPDATE:
        learn_entry_update(EM_COMMAND_WRITE, &rec, false); // update from HW
        debug_counter_incr(arc_debug_counters::LEARN_UPDATE_EVENTS);
        break;
    case LEARN_COMMAND_REFRESH:
        learn_entry_update(EM_COMMAND_AGE_WRITE, &rec, false); // update from HW
        debug_counter_incr(arc_debug_counters::LEARN_REFRESH_EVENTS);
        break;
    }

    status_reg_set_mask(UAUX_REG_STATUS_LEARN | UAUX_REG_STATUS_LEARN_DONE);

#ifndef CEM_SIM
    // In real use case, Learn commands are submitted to FW by Learn Manager (HW block), which expects "DONE" on each command
    // In simulation/test runs, Learn commands are submitted by FW. As a result, if we report "DONE", HW crashes
    status_reg_set(UAUX_REG_STATUS_LEARN_DONE);
#endif // CEM_SIM

    status_reg_clear(UAUX_REG_STATUS_LEARN);
    // update register
    status_reg_write();
    // return mask to default
    status_reg_set_mask(UAUX_REG_STATUS_DEFAULT_MASK);
}

void
mac_relay_counter_init(arc_cpu_command* cpu_reg)
{
    counters::address addr = {.val = 0};
    addr.id = cpu_reg->params.obj_params.object_id;
    addr.type = counters::AVAILABLE_MAC_RELAY;
    addr.rw = counters::WRITE;

    counter_ctx.mac_relay.addr = addr.val;
    int32_t limit = cpu_reg->params.obj_params.object_data;

    initialize_limit_counter(&counter_ctx.mac_relay, limit);
    // ARC CPU commands nedd to update status and state fields in cpu_status
    // to communicate properly with CPU(SDK)
    read_counters_from_op_context();
    set_cpu_status(ARC_CPU_COMMAND_STATUS_SUCCESS);
}

void
mac_relay_counter_update(arc_cpu_command* cpu_reg)
{
    read_counter_from_arc_cpu_command(cpu_reg, counters::AVAILABLE_MAC_RELAY);
    int32_t delta = cpu_reg->params.obj_params.object_data;

    // mac_relay update can set the counter to negative values
    // if so, the mac_relay will not be able to learn untill enough entries had been aged out/deleted
    update_limit_counter(&counter_ctx.mac_relay, delta);
    // ARC CPU commands nedd to update status and state fields in cpu_status
    // to communicate properly with CPU(SDK)
    set_cpu_status(ARC_CPU_COMMAND_STATUS_SUCCESS);
}

void
cpu_lookup_key(arc_cpu_command* cpu_reg)
{
    em_entry_data rec;
    debug_counter_incr(arc_debug_counters::CPU_LOOKUPS);
    init_new_entry_from_cpu(cpu_reg, &rec);
    // get the core and the group
    group_request(&rec);

    lookup_request(&rec);
    if (!op_ctx.em_response_reg.data.hit) {
        debug_counter_incr(arc_debug_counters::CPU_LOOKUP_NOT_FOUND);
        set_cpu_status(ARC_CPU_COMMAND_STATUS_ENOTFOUND);
        return;
    }

    arc_cpu_command resp;
    memcpy(resp.params.table_params.payload, op_ctx.em_response_reg.rec.payload, MAX_TABLE_PAYLOAD_LEN_IN_BYTES);
    memcpy(resp.params.table_params.key, rec.rec.key, MAX_TABLE_KEY_LEN_IN_BYTES);

    // Store data for next request
    last_lookup_location.params.location_params.core = op_ctx.group_data.em_core;
    last_lookup_location.params.location_params.bank = (rec.data.orig_for_cam) ? ARC_CAM_BANK_IDX : rec.data.orig_bank;
    last_lookup_location.params.location_params.index = rec.data.orig_index;
    last_lookup_location.params.location_params.key_size = rec.data.key_size;

    write_reg(UAUX_CPU_REG, &resp);

    // ARC CPU commands nedd to update status and state fields in cpu_status
    // to communicate properly with CPU(SDK)
    set_cpu_status(ARC_CPU_COMMAND_STATUS_SUCCESS);
}

void
cpu_lookup_location(arc_cpu_command* cpu_reg)
{
    debug_counter_incr(arc_debug_counters::CPU_LOOKUP_LOC);
    write_reg(UAUX_CPU_REG, &last_lookup_location);
    // ARC CPU commands nedd to update status and state fields in cpu_status
    // to communicate properly with CPU(SDK)
    set_cpu_status(ARC_CPU_COMMAND_STATUS_SUCCESS);
}

void
cpu_read_entry(arc_cpu_command* cpu_reg, bool read_age)
{
    periodic_counter location;
    location.data.bits.em_entry = cpu_reg->params.location_params.index;
    location.data.bits.for_cam = (cpu_reg->params.location_params.bank == ARC_CAM_BANK_IDX);
    location.data.bits.em_bank = (location.data.bits.for_cam) ? 0 : cpu_reg->params.location_params.bank;
    location.data.bits.em_core = cpu_reg->params.location_params.core;

    em_entry_data rec;
    read_request(&location, &rec);
    if (!op_ctx.em_response_reg.data.hit) {
        debug_counter_incr(arc_debug_counters::CPU_READ_NOT_FOUND);
        set_cpu_status(ARC_CPU_COMMAND_STATUS_ENOTFOUND);
        return;
    }

    arc_cpu_command resp;
    if (read_age) {
        resp.params.table_age_params.age = rec.data.age_value & 0x7;
        resp.params.table_age_params.age_owner = rec.data.age_owner & 0x1;
    } else {
        memcpy(resp.params.table_params.payload, rec.rec.payload, MAX_TABLE_PAYLOAD_LEN_IN_BYTES);
        memcpy(resp.params.table_params.key, rec.rec.key, MAX_TABLE_KEY_LEN_IN_BYTES);
    }

    write_reg(UAUX_CPU_REG, &resp);
    // ARC CPU commands need to update status and state fields in cpu_status
    // to communicate properly with CPU(SDK)
    set_cpu_status(ARC_CPU_COMMAND_STATUS_SUCCESS);
}

void
cpu_read_entry_with_age(arc_cpu_command* cpu_reg)
{
    em_entry_data rec;
    debug_counter_incr(arc_debug_counters::CPU_LOOKUPS);
    init_new_entry_from_cpu(cpu_reg, &rec);
    // get the core and the group
    group_request(&rec);

    lookup_request(&rec);
    if (!op_ctx.em_response_reg.data.hit) {
        debug_counter_incr(arc_debug_counters::CPU_LOOKUP_NOT_FOUND);
        set_cpu_status(ARC_CPU_COMMAND_STATUS_ENOTFOUND);
        return;
    }

    periodic_counter location;
    location.data.bits.em_entry = rec.data.orig_index;
    location.data.bits.for_cam = rec.data.orig_for_cam;
    location.data.bits.em_bank = (rec.data.orig_for_cam) ? ARC_CAM_BANK_IDX : rec.data.orig_bank;
    location.data.bits.em_core = op_ctx.group_data.em_core;

    read_request(&location, &rec);
    if (!op_ctx.em_response_reg.data.hit) {
        debug_counter_incr(arc_debug_counters::CPU_READ_NOT_FOUND);
        set_cpu_status(ARC_CPU_COMMAND_STATUS_ENOTFOUND);
        return;
    }

    arc_cpu_command resp;
    resp.params.table_age_params.age = rec.data.age_value & 0x7;
    resp.params.table_age_params.age_owner = rec.data.age_owner & 0x1;

    write_reg(UAUX_CPU_REG, &resp);
    // ARC CPU commands need to update status and state fields in cpu_status
    // to communicate properly with CPU(SDK)
    set_cpu_status(ARC_CPU_COMMAND_STATUS_SUCCESS);
}

void
learn_new_insert_cpu(em_entry_data* rec)
{
    // if entry is already in table, need to update payload
    lookup_request(rec);
    if (op_ctx.em_response_reg.data.hit) {
        learn_entry_update(EM_COMMAND_WRITE, rec, true); // update from CPU
        debug_counter_incr(arc_debug_counters::CPU_ENTRY_OVERWRITE);
        return;
    }

    // In case the rebalancing is proccessing the relevent group set the learn core to the new core for the balancing proccess.
    if (load_balance_count.stage == load_balance_data::COPY && load_balance_count.em_group == op_ctx.group_data.em_group) {
        op_ctx.group_data.em_core = load_balance_count.dest_core;
    }

    bool status = true;
    bool mac_entry = is_mac_entry(&rec->rec);
    if (mac_entry) {
        read_counter_from_entry_data(rec, counters::AVAILABLE_MAC_RELAY);
        read_counter_from_entry_data(rec, counters::AVAILABLE_AC_PORT);

        // if no space in counters return ERESOURCE
        status = counters_check_limit();
        if (!status) {
            set_cpu_status(ARC_CPU_COMMAND_STATUS_ELIMIT);
            cpu_status.stage.new_entry_counter_limit = 1;
            return;
        }
    }

    status = new_insert(rec);
    new_entry_counters_incr_cond(status, mac_entry, rec);
    // ARC CPU commands nedd to update status and state fields in cpu_status
    // to communicate properly with CPU(SDK)
    if (status) {
        set_cpu_status(ARC_CPU_COMMAND_STATUS_SUCCESS);
    } else {
        set_cpu_status(cpu_status.status); // we call it to update group and core
    }
}

void
learn_new_insert_cpu_double_entry(em_entry_data* rec)
{
    // if entry is already in table, need to update payload
    lookup_request(rec);
    if (op_ctx.em_response_reg.data.hit) {
        learn_entry_update(EM_COMMAND_WRITE, rec, true);
        return;
    }

    bool status = new_insert_double_entry(rec);
    new_entry_counters_incr_cond(status, false /*is_mac*/, rec);
    // ARC CPU commands nedd to update status and state fields in cpu_status
    // to communicate properly with CPU(SDK)
    if (status) {
        set_cpu_status(ARC_CPU_COMMAND_STATUS_SUCCESS);
    } else {
        set_cpu_status(cpu_status.status); // we call it to update group and core
    }
}

void
learn_erase_cpu(em_entry_data* rec)
{
    // entry may have been aged out
    lookup_request(rec);
    if (!op_ctx.em_response_reg.data.hit) {
        return;
    }
    uint32_t rec_core = op_ctx.group_data.em_core;
    if (rec->data.orig_for_cam) {
        cpu_status.inserted_to_cam = 1;
        --cam_per_core_utilization[op_ctx.group_data.em_core];
    } else {
        if (rec->data.key_size != EM_WIDE_KEY_SIZE) {
            --sram_per_core_utilization[op_ctx.group_data.em_core];
        } else {
            sram_per_core_utilization[op_ctx.group_data.em_core] -= 2;
        }
    }

    // In case the rebalancing is proccessing the relevent group and has already passed this entry, the entry is in the new core
    if (load_balance_count.stage == load_balance_data::COPY && load_balance_count.em_group == op_ctx.group_data.em_group) {
        // create temp counter to ease the comparison
        periodic_counter tmp;

        tmp.data.bits.em_entry = rec->data.em_index;
        tmp.data.bits.em_bank = rec->data.em_bank;
        tmp.data.bits.for_cam = op_ctx.em_response_reg.data.for_cam;
        tmp.data.bits.em_core = op_ctx.group_data.em_core;

        if (tmp.data.count < load_balance_count.counter.data.count) {
            op_ctx.group_data.em_core = load_balance_count.dest_core;
        }
    }

    bool mac_entry = is_mac_entry(&rec->rec);
    if (mac_entry) {
        read_counters_from_op_context();
    }

    delete_entry_counters_decr(mac_entry, rec);
    delete_request(rec);
    erase_bitset |= (1 << rec_core);
}

void
learn_command_from_cpu(arc_cpu_command* cpu_reg)
{
    em_entry_data rec;
    init_new_entry_from_cpu(cpu_reg, &rec);
    // get the core and the group
    group_request(&rec);
    switch (cpu_reg->command) {

    case ARC_CPU_COMMAND_INSERT_TABLE_SINGLE_ENTRY:
        learn_new_insert_cpu(&rec);
        debug_counter_incr(arc_debug_counters::CPU_INSERT);
        break;

    case ARC_CPU_COMMAND_INSERT_TABLE_DOUBLE_ENTRY:
        learn_new_insert_cpu_double_entry(&rec);
        debug_counter_incr(arc_debug_counters::CPU_INSERT_DOUBLE);
        break;

    case ARC_CPU_COMMAND_ERASE_TABLE_SINGLE_ENTRY:
    case ARC_CPU_COMMAND_ERASE_TABLE_DOUBLE_ENTRY:
        learn_erase_cpu(&rec);
        debug_counter_incr(arc_debug_counters::CPU_ERASE);
        break;

    default:
        set_cpu_status(ARC_CPU_COMMAND_STATUS_EINVAL);
        break;
    }
    set_cpu_status(cpu_status.status);
}

void
aging_params_from_cpu(arc_cpu_command* cpu_reg)
{
    configure_aging_params(cpu_reg->params.table_age_params.age_timer_inverval);
    debug_counter_incr(arc_debug_counters::AGE_CONFIGS);
}

uint32_t
get_feature(arc_cpu_feature_e feature)
{
    for (size_t index = 0; index < ARC_CPU_FEATURE_MAX_TLV_COUNT; ++index) {
        if (feature_tlvs[index].type == feature) {
            return feature_tlvs[index].value;
        }
    }
    return ARC_CPU_FEATURE_VALUE_INVALID;
}

bool
is_capable_feature(arc_cpu_feature_e feature)
{
    if (feature == ARC_CPU_FEATURE_TYPE_AGE_INTERVAL) {
        return true;
    }

    for (size_t index = 0; index < ARC_CPU_FEATURE_MAX_TLV_COUNT; ++index) {
        if (feature_tlvs[index].type == feature && feature_tlvs[index].value != ARC_CPU_FEATURE_INCAPABLE) {
            return true;
        }
    }

    return false;
}

bool
set_feature(arc_cpu_feature_e feature, uint32_t value)
{
    for (size_t index = 0; index < ARC_CPU_FEATURE_MAX_TLV_COUNT; ++index) {
        if (feature_tlvs[index].type == feature) {
            feature_tlvs[index].value = value & ARC_CPU_FEATURE_VALUE_MASK;
            return true;
        }
    }
    return false;
}

void
feature_params_from_cpu(arc_cpu_command* cpu_reg)
{
    arc_cpu_feature_type_value* tlvs = cpu_reg->params.feature_params.type_values;

    for (size_t index = 0; index < ARC_CPU_FEATURE_MAX_TLV_COUNT; ++index) {
        arc_cpu_feature_e current_type = tlvs[index].type;
        uint32_t current_value = tlvs[index].value;
        if (current_type < ARC_CPU_FEATURE_TYPE_FIRST || current_type > ARC_CPU_FEATURE_TYPE_LAST) {
            // Incorrect TLV
            continue;
        }
        if (!is_capable_feature(current_type)) {
            set_cpu_status(ARC_CPU_COMMAND_STATUS_ENOTIMPLEMENTED);
            return;
        }

        // Synchronous feature handling
        if (current_type == ARC_CPU_FEATURE_TYPE_AGE_INTERVAL) {
            configure_aging_params(current_value);
        }

        // Store feature value for ARC usage asynchronously
        if (!set_feature(current_type, current_value)) {
            debug_counter_incr(arc_debug_counters::SET_FEATURE_FAILS);
            set_cpu_status(ARC_CPU_COMMAND_STATUS_EUNKNOWN);
            return;
        }
    }
    set_cpu_status(ARC_CPU_COMMAND_STATUS_SUCCESS);
}

void
return_feature_params_to_cpu(arc_cpu_command* cpu_reg)
{
    arc_cpu_command resp;

    for (size_t index = 0; index < ARC_CPU_FEATURE_MAX_TLV_COUNT; ++index) {
        resp.params.feature_params.type_values[index].type = feature_tlvs[index].type;
        resp.params.feature_params.type_values[index].value = feature_tlvs[index].value;
    }
    write_reg(UAUX_CPU_REG, &resp);
    set_cpu_status(ARC_CPU_COMMAND_STATUS_SUCCESS);
}

void
return_utilization_data_to_cpu()
{
    arc_cpu_command resp;
    memset(&resp, 0, sizeof(resp));

    uint8_t max_cam_value = 0;
    uint16_t max_sram_value = 0;
    uint32_t total_sram_value = 0;

    for (size_t i = 0; i < EM_CORES_IN_CEM; ++i) {
        if (cam_per_core_utilization[i] > max_cam_value) {
            max_cam_value = cam_per_core_utilization[i];
        }
        if (sram_per_core_utilization[i] > max_sram_value) {
            max_sram_value = sram_per_core_utilization[i];
        }
        total_sram_value += sram_per_core_utilization[i];
    }

    resp.params.utilization_params.cam_utilization = max_cam_value;
    resp.params.utilization_params.sram_utilization = max_sram_value;
    resp.params.utilization_params.total_sram_utilization = total_sram_value;
    write_reg(UAUX_CPU_REG, &resp);
    set_cpu_status(ARC_CPU_COMMAND_STATUS_SUCCESS);
}

void
point_to_evacuation_bank(em_entry_data* dst, uint16_t entry)
{
    dst->data.orig_index = entry;
    dst->data.orig_bank = EM_EVACUATION_BANK;
    dst->data.orig_for_cam = 0;
    dst->data.em_index = entry;
    dst->data.em_bank = EM_EVACUATION_BANK;
}

// This function trying to free entry at odd evacuation bank *without using even bank*.
bool
free_odd_evacuation_bank(uint16_t entry)
{
    em_entry_data rec;
    periodic_counter counter;
    counter.data.bits.em_core = op_ctx.group_data.em_core;
    counter.data.bits.em_entry = entry;
    counter.data.bits.em_bank = EM_EVACUATION_BANK + 1;
    counter.data.bits.for_cam = 0;
    read_request(&counter, &rec);
    bool odd_bank_is_free
        = !op_ctx.em_response_reg.data.hit
          || relocate_entry_dfs(&rec, op_ctx.group_data.allowed_bank_bitset & ~(1 << EM_EVACUATION_BANK), 0 /* depth */);
    return odd_bank_is_free;
}

bool
apply_double_entry_evacuation(em_entry_data* rec)
{
    debug_counter_incr(arc_debug_counters::TOTAL_EVACUATION_TRIES);
    em_entry_data make_way_rec;
    em_entry_data rec_to_store;
    periodic_counter counter;
    get_cam_entry_collided_location(rec, &counter);
    read_request(&counter, &make_way_rec);
    memcpy(&rec_to_store.data, &make_way_rec.data, sizeof(em_entry_data::data_fields));

    bool free_entry = !op_ctx.em_response_reg.data.hit;

    if (free_entry) {
        free_entry = free_odd_evacuation_bank(counter.data.bits.em_entry);
        if (free_entry) {
            point_to_evacuation_bank(&rec_to_store, counter.data.bits.em_entry);
        }
    } else if (make_way_rec.data.key_size == EM_WIDE_KEY_SIZE) {
        free_entry = install_double_entry(&make_way_rec);
    } else {
        free_entry = relocate_entry_dfs(&make_way_rec, op_ctx.group_data.allowed_bank_bitset, 0 /* depth */);
        if (free_entry) {
            free_entry = free_odd_evacuation_bank(counter.data.bits.em_entry);
        }
    }

    if (!free_entry) {
        return false;
    }

    memcpy(&rec_to_store.rec, &rec->rec, sizeof(long_entry_data));
    rec_to_store.data.key_size = rec->data.key_size;
    store_request(EM_COMMAND_WRITE, &rec_to_store, 0);
    delete_request(rec);
    --cam_per_core_utilization[op_ctx.group_data.em_core];
    sram_per_core_utilization[op_ctx.group_data.em_core] += 2;
    return true;
}

bool
double_entry_evacuation(em_entry_data* rec)
{
    lookup_request(rec);
    if (rec->data.em_index >= EM_ENTRIES_IN_CAM) {
        return false;
    }
    periodic_counter read_payload;
    read_payload.data.bits.em_core = op_ctx.group_data.em_core;
    read_payload.data.bits.em_entry = rec->data.em_index;
    read_payload.data.bits.for_cam = 1;
    read_request(&read_payload, rec);
    return apply_double_entry_evacuation(rec);
}

void
cpu_double_entry_evacuation(arc_cpu_command* cpu_reg)
{
    em_entry_data rec;

    init_new_entry_from_cpu(cpu_reg, &rec);
    // get the core and the group
    group_request(&rec);

    // ARC CPU commands need to update status and state fields in cpu_status
    // to communicate properly with CPU(SDK)
    if (double_entry_evacuation(&rec)) {
        set_cpu_status(ARC_CPU_COMMAND_STATUS_SUCCESS);
    } else {
        set_cpu_status(ARC_CPU_COMMAND_STATUS_ERESOURCE);
    }
}

void
save_em_key_size_map_value(arc_cpu_command* cpu_reg)
{
    key_size_map = cpu_reg->params.location_params.key_size;

    // ARC CPU commands nedd to update status and state fields in cpu_status
    // to communicate properly with CPU(SDK)
    set_cpu_status(ARC_CPU_COMMAND_STATUS_SUCCESS);
}

// Entry to the cpu command routine UAUX_REG_STATUS_CPU_CMD
void
cpu_cmd_routine()
{
    // clear the global data
    memset(&op_ctx, 0, sizeof(op_ctx));
    memset(&counter_ctx, 0, sizeof(counter_context));
    memset(&cpu_status, 0, sizeof(arc_cpu_status));

    // reading the entry and the command
    arc_cpu_command cpu_reg;

    read_reg(&cpu_reg, UAUX_CPU_REG);

    switch (cpu_reg.command) {

    case ARC_CPU_COMMAND_SWITCH_INIT_MAC:
        mac_relay_counter_init(&cpu_reg);
        break;

    case ARC_CPU_COMMAND_SWITCH_MAX_MAC:
        mac_relay_counter_update(&cpu_reg);
        break;

    case ARC_CPU_COMMAND_LOOKUP_KEY:
        cpu_lookup_key(&cpu_reg);
        break;

    case ARC_CPU_COMMAND_LAST_LOOKUP_LOCATION:
        cpu_lookup_location(&cpu_reg);
        break;

    case ARC_CPU_COMMAND_READ_ENTRY:
        cpu_read_entry(&cpu_reg, false /* age read */);
        break;

    case ARC_CPU_COMMAND_AGE_READ_ENTRY:
        cpu_read_entry_with_age(&cpu_reg);
        break;

    case ARC_CPU_COMMAND_INSERT_TABLE_SINGLE_ENTRY:
    case ARC_CPU_COMMAND_ERASE_TABLE_SINGLE_ENTRY:
    case ARC_CPU_COMMAND_INSERT_TABLE_DOUBLE_ENTRY:
    case ARC_CPU_COMMAND_ERASE_TABLE_DOUBLE_ENTRY:
        learn_command_from_cpu(&cpu_reg);
        break;

    case ARC_CPU_COMMAND_EVACUATE_TABLE_DOUBLE_ENTRY:
        cpu_double_entry_evacuation(&cpu_reg);
        break;

    case ARC_CPU_COMMAND_SET_KEY_SIZE_MAP_VALUE:
        save_em_key_size_map_value(&cpu_reg);
        break;

    case ARC_CPU_COMMAND_SET_FEATURES:
        feature_params_from_cpu(&cpu_reg);
        break;
    case ARC_CPU_COMMAND_GET_FEATURES:
        return_feature_params_to_cpu(&cpu_reg);
        break;

    case ARC_CPU_COMMAND_GET_UTILIZATION_STATE:
        return_utilization_data_to_cpu();
        break;

    default:
        break;
    }

    // state needs to be set to DONE
    // status needs to be set according to ARC CPU subroutines above
    cpu_status.state = ARC_CPU_FSM_STATE_CPU;
    write_cpu_status_reg(&cpu_status);
    debug_counter_incr(arc_debug_counters::CPU_RESPONSE);
}

void
init_aging_routine()
{
    status_reg_set_mask(UAUX_REG_STATUS_AGE);
    status_reg_set(UAUX_REG_STATUS_AGE);
    status_reg_write();
    status_reg_set_mask(UAUX_REG_STATUS_DEFAULT_MASK);
}

void
resume_aging_routine()
{
    status_reg_set_mask(UAUX_REG_STATUS_AGE);
    status_reg_clear(UAUX_REG_STATUS_AGE);
    status_reg_write();
    status_reg_set_mask(UAUX_REG_STATUS_DEFAULT_MASK);
    debug_counter_incr(arc_debug_counters::AGE_SWEEP);
}

static void
refresh_request(em_entry_data* rec)
{
    refresh_data reg;
    // copying from long key/payload data to short key/payload data
    memcpy(reg.key, rec->rec.key, EM_SHORT_KEY);
    memcpy(reg.payload, rec->rec.payload, EM_SHORT_PAYLOAD);
    write_reg(UAUX_REFRESH_REG, &reg);
    status_reg_set(UAUX_REG_STATUS_REFRESH);
    status_reg_write();

    // ARC WORKAROUND: Learn request can potentially overwrite valid reg
    // Read valid reg immediately to see if learn bit is set in order to
    // decide if we need to resubmit refresh
    status_reg_read();
    if (status_reg_test(UAUX_REG_STATUS_COMMAND) && status_reg_test(UAUX_REG_STATUS_LEARN)) {
        write_reg(UAUX_REFRESH_REG, &reg);
        status_reg_set(UAUX_REG_STATUS_REFRESH);
        status_reg_write();
    }
}

static void
store_updated_age_value(em_entry_data* rec, int age_value)
{
    rec->data.age_value = age_value & 0x7;
    store_request(EM_COMMAND_AGE_WRITE, rec, rec->data.orig_for_cam);
    age_value_check(&aging_count, rec, rec->data.orig_for_cam, false, EM_CHECK_RECORD_AGE_VALUE);
}

/// @brief Aging algorithm
/// Operates directly on request/response
/// If record is static (NO_AGING) - do nothing
/// Otherwise, reduce age and check if need to be deleted.
void
apply_aging_algorithm(em_entry_data* rec)
{
    int age_value = rec->data.age_value & 0x7;
    if (age_value == EM_NO_AGING_AGE) {
        return;
    }

    if ((rec->data.key_size == EM_WIDE_KEY_SIZE) && ((rec->data.em_bank % 2) == 1)) {
        // This is the second part of double entry. Don't handle it.
        return;
    }

    int org_age_value = age_value;
    // NOTE:
    // refresh_request is not used for the original purpose of notifying other
    // devices since NPUH sends notification packet to CPU today
    // Following code is disabled because refresh_request is repurposed for age notification
    //
    // if the age is on EM_REFRESH_AGE, owner device is sending refresh message
    // if (age_value == EM_REFRESH_AGE && rec->data.age_owner) {
    //     refresh_request(rec);
    // }

    age_value = (age_value == EM_NEW_MAX_AGE) ? EM_REFRESH_AGE - 1 : age_value - 1;
    age_value = (age_value > 0) ? age_value : 0;
    if (!age_value) {
        if (get_feature(ARC_CPU_FEATURE_TYPE_AGE_MODE) == ARC_CPU_FEATURE_VALUE_AGE_MODE_DELETE_ENTRY) {
            read_counters_from_op_context();

            delete_entry_counters_decr(true /*is_mac*/, rec);
            delete_request(rec);
            erase_bitset |= (1 << op_ctx.group_data.em_core);
            if (rec->data.orig_for_cam) {
                --cam_per_core_utilization[op_ctx.group_data.em_core];
            } else {
                --sram_per_core_utilization[op_ctx.group_data.em_core];
            }
            debug_counter_incr(arc_debug_counters::AGED_ENTRIES);
        }

        // NOTE:
        //
        // Generate refresh event and send to NPUH for CPU notification
        // Learn record contains payload and EM lookup key, plus MACT-LDB
        // This is different than other learn records since payload was replaced
        // with SLP in regular new learns
        //
        // age_owner bit needs to be set in order to let CDB age refresh logic update age_value
        // If age_owner bit is not set, age refresh will not happen, entry can reach age_value 0 while traffic is flowing
        //
        // Generate age notification only on the age_owner-enabled device
        if (get_feature(ARC_CPU_FEATURE_TYPE_LEARN_MODE) == ARC_CPU_FEATURE_VALUE_LEARN_MODE_SYSTEM
            && get_feature(ARC_CPU_FEATURE_TYPE_AGE_NOTIFICATION) == ARC_CPU_FEATURE_VALUE_AGE_NOTIFICATION_ON) {
            if (rec->data.age_owner) {
                // Generate a refresh request only in system learning mode with age notification enabled
                refresh_request(rec);
            }
        }
    }
    // Decrease amount of cem_age_table access by storing changed age_value only
    if (age_value != 0 || (age_value == 0 && org_age_value != 0)) {
        store_updated_age_value(rec, age_value);
    }
}

// Entry to the aging routine UAUX_REG_STATUS_AGE
void
aging_routine()
{
    if (!aging_count.is_valid()) {
        // starting new sweep
        aging_count.init(0 /* core */);
    }

    // clear the global data
    memset(&op_ctx, 0, sizeof(op_ctx));
    memset(&counter_ctx, 0, sizeof(counter_context));

    // Read entry twice for age_value stability
    em_entry_data rec, rec1;
    read_request(&aging_count, &rec);
    if (op_ctx.em_response_reg.data.hit) {
        read_request(&aging_count, &rec1);
        if (op_ctx.em_response_reg.data.hit && rec.data.age_value != rec1.data.age_value) {
            debug_counter_incr(arc_debug_counters::AGE_READ_MISMATCHES);
        }
        // change the age and store/delete accordingly
        apply_aging_algorithm(&rec);
    }

    bool ok = aging_count.incr();
    if (!ok) {
        // sweep is done
        resume_aging_routine();
    }
}

void
bulk_update_payload(const em_entry_data* rec)
{
    op_ctx.group_data.em_core = bulk_count.data.bits.em_core;
    store_request(EM_COMMAND_WRITE, rec, rec->data.orig_for_cam);
    counters_incr_payload();
}

void
bulk_update_delete(const em_entry_data* rec)
{
    erase_bitset |= (1 << op_ctx.group_data.em_core);
    bool mac_entry = is_mac_entry(&rec->rec);
    delete_entry_counters_decr(mac_entry, rec);
    delete_request(rec);
}

// Entry to the bulk update routine UAUX_REG_STATUS_BULK
void
bulk_update_routine()
{
    if (!bulk_count.is_valid()) {
        // starting new sweep
        bulk_count.init(0 /* core */);
    }

    // clear the global data
    memset(&op_ctx, 0, sizeof(op_ctx));

    em_entry_data rec;
    read_request(&bulk_count, &rec);
    bool valid_entry
        = op_ctx.em_response_reg.data.hit && !((rec.data.key_size == EM_WIDE_KEY_SIZE) && ((rec.data.em_bank % 2) == 1));

    if (valid_entry) {
        switch (op_ctx.em_response_reg.data.rule_hit) {
        case BULK_COMMAND_NONE:
            break;
        case BULK_COMMAND_UPDATE:
            bulk_update_payload(&rec);
            break;
        case BULK_COMMAND_DELETE:
            bulk_update_delete(&rec);
            break;
        case BULK_COMMAND_SEND_TO_CPU:
            PRINT("bulk_update::send_to_cpu key: 0x%08X, payload: 0x%02X )\n",
                  op_ctx.em_response_reg.rec.key0,
                  op_ctx.em_response_reg.rec.payload0);
            break;
        }
    }

    bool ok = bulk_count.incr();
    if (!ok) {
        // sweep is done
        status_reg_clear(UAUX_REG_STATUS_BULK);
        status_reg_write();
    }
}

void
load_balance_copy(em_entry_data* rec)
{
    group_request(rec);
    if (op_ctx.group_data.em_group != load_balance_count.em_group) {
        // wrong group - skip
        return;
    }

    // copy == insert new entry to the destination core
    op_ctx.group_data.em_core = load_balance_count.dest_core;

    rec->data.orig_index = EM_NONE;
    bool status = new_insert(rec);

    // Do not update limit counters as the data is not really changing.
    // No update will happend on load_balance_delete as well
    new_entry_counters_incr_cond(status, false /*is_mac*/, rec);
}

void
load_balance_remap(em_entry_data* rec)
{
    // TODO: implement remap group to the new core
    PRINT("load_balance::remap group: %d, from core: %d, to core: %d\n",
          load_balance_count.em_group,
          load_balance_count.em_core,
          load_balance_count.dest_core);
}

void
load_balance_delete(em_entry_data* rec)
{
    group_request(rec);
    if (op_ctx.group_data.em_group != load_balance_count.em_group) {
        // wrong group - skip
        return;
    }

    // Do not update limit counters as the data is not really changing.
    // No update had happend on load_balance_copy as well
    delete_entry_counters_decr(false /*is_mac*/, rec);
    // delete entry
    erase_bitset |= (1 << op_ctx.group_data.em_core);
    delete_request(rec);
}

// Entry to the load balancing routine UAUX_REG_STATUS_LOAD_BALANCE
void
load_balance_routine()
{
    if (!load_balance_count.is_valid()) {
        // starting new sweep
        load_balance_count.init();
    }

    // clear the global data
    memset(&op_ctx, 0, sizeof(op_ctx));

    em_entry_data rec;
    read_request(&load_balance_count.counter, &rec);
    bool valid_entry
        = op_ctx.em_response_reg.data.hit && !((rec.data.key_size == EM_WIDE_KEY_SIZE) && ((rec.data.em_bank % 2) == 1));

    if (valid_entry) {
        switch (load_balance_count.stage) {
        case load_balance_data::COPY:
            load_balance_copy(&rec);
            break;
        case load_balance_data::REMAP:
            load_balance_remap(&rec);
            break;
        case load_balance_data::DELETE:
            load_balance_delete(&rec);
            break;
        default:
            ASSERT(false);
        }
    }
    bool ok = load_balance_count.incr();
    if (!ok) {
        // sweep is done
        status_reg_clear(UAUX_REG_STATUS_LOAD_BALANCE);
        status_reg_write();
    }
}

/// @brief evacuation algorithm
/// Tries to evacuate one entry from CAM to SRAM
void
apply_evacuation_algorithm(em_entry_data* rec)
{
    if (rec->data.key_size == EM_WIDE_KEY_SIZE) {
#ifndef PACIFIC
        // This is double entry.
        apply_double_entry_evacuation(rec);
#endif
    } else {
        // This is single entry.
        debug_counter_incr(arc_debug_counters::TOTAL_EVACUATION_TRIES);
        em_entry_data make_way_rec;
        em_entry_data rec_to_store;
        periodic_counter counter;
        get_cam_entry_collided_location(rec, &counter);
        read_request(&counter, &make_way_rec);
        memcpy(&rec_to_store.data, &make_way_rec.data, sizeof(em_entry_data::data_fields));

        bool free_entry = !op_ctx.em_response_reg.data.hit;

        if (free_entry) {
            point_to_evacuation_bank(&rec_to_store, counter.data.bits.em_entry);
        } else {
            if (make_way_rec.data.key_size != EM_WIDE_KEY_SIZE) {
                free_entry = relocate_entry_dfs(&make_way_rec, op_ctx.group_data.allowed_bank_bitset, 0 /* depth */);
            } else {
                free_entry = install_double_entry(&make_way_rec);
                if (free_entry) {
                    // delete old double entry from rec_to_store entry before storing there single entry
                    delete_request(&rec_to_store);
                }
            }
        }

        if (free_entry) {
            memcpy(&rec_to_store.rec, &rec->rec, sizeof(long_entry_data));
            rec_to_store.data.key_size = rec->data.key_size;
            store_request(EM_COMMAND_WRITE, &rec_to_store, 0);
            delete_request(rec);
            --cam_per_core_utilization[op_ctx.group_data.em_core];
            ++sram_per_core_utilization[op_ctx.group_data.em_core];
        }
    }
}

void
evacuation_routine()
{

    // clear the global data
    memset(&op_ctx, 0, sizeof(op_ctx));
    // Read entry
    em_entry_data rec;
    read_request(&evacuation_count, &rec);
    if (op_ctx.em_response_reg.data.hit) {
        // Entry exist, try to evacuate according to key size
        apply_evacuation_algorithm(&rec);
    }
    evacuation_count.next_cam_entry();
}

void
evacuate_if_need()
{
    static int curr_core_index = 0;
    if (evacuation_count.is_valid()) {
        evacuation_routine();
    } else {
        // check all cores until the first erased-core
        while (erase_bitset) {
            curr_core_index = (curr_core_index + 1) % EM_CORES_IN_CEM;
            uint32_t curr_core_bit = (1 << curr_core_index);
            if (erase_bitset & curr_core_bit) {
                erase_bitset &= ~curr_core_bit;
                evacuation_count.init(curr_core_index);
                evacuation_count.set_to_cam();
                evacuation_routine();
                break;
            }
        }
    }
}
