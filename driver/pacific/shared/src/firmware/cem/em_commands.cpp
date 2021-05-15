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
#include "uaux_regs.h"
#include "uaux_regs_commands.h"

#include "debug_counters.h"
#include "em_commands.h"
#include "test_if.h"

// for memcpy/memset
#include <string.h>

/// @file
/// @brief Queries that are available by CEM HW

/// @brief EM active banks
uint32_t active_banks;

//*********************************
// FUNCTIONS
//*********************************
static bool
request_and_poll_loop()
{
    bool ret = false;
    for (int i = 0; i < EM_TRANSACTION_RETRY_MAX && !ret; ++i) {
        ret = request_and_poll(
            &op_ctx.em_request_reg, UAUX_EM_REQUEST_REG, UAUX_REG_STATUS_EM_REQUEST, UAUX_REG_STATUS_EM_RESPONSE);
        if (i == 1 && !ret) {
            // If the request failed, push a notification to the host requesting a bubble.
            // Then, continue executing.
            arc_cpu_status cpu_status;
            read_cpu_status_reg(&cpu_status);
            if (cpu_status.state == ARC_CPU_FSM_STATE_ARC) {
                // In case of reaching here by non cpu command (learning/aging...)
                // we should not update the CPU status register
                cpu_status.status = ARC_CPU_COMMAND_STATUS_REQUEST_BUBBLE;
                write_cpu_status_reg(&cpu_status);
            }
        }
    }
    debug_em_failure_incr_cond(op_ctx.em_request_reg.data.command, !ret);
    return ret;
}

static bool
em_check_response()
{
    read_reg(&op_ctx.em_response_reg, UAUX_EM_RESPONSE_REG);
    /// There are two possibilities of this indication
    /// 1. Real ECC error
    /// 2. cem_age_table access collision resulted in data corruption
    ///
    /// Recovery: retry request_and_poll_loop
    bool retry_needed
        = ((op_ctx.em_request_reg.data.command == EM_COMMAND_READ) || (op_ctx.em_request_reg.data.command == EM_COMMAND_AGE_READ))
          & op_ctx.em_response_reg.data.hit & op_ctx.em_response_reg.data.age_ecc_err;
    debug_counter_incr_cond(arc_debug_counters::AGE_READ_RETRY, retry_needed);
    return retry_needed;
}

static inline void
reset_age_value(const em_entry_data* rec)
{
    em_entry_data local_rec;
    // Only reset age value on MAC entries
    if (!is_mac_entry(&rec->rec)) {
        return;
    }
    memcpy(&local_rec, rec, sizeof(local_rec));
    local_rec.data.age_value = 0;
    local_rec.data.age_owner = 0;
    store_request(EM_COMMAND_AGE_WRITE, &local_rec, local_rec.data.orig_for_cam);

    // make sure age value is reset to 0
    age_value_check(NULL, &local_rec, local_rec.data.orig_for_cam, true, 0);
}

static inline bool
has_dynamic_age_value(const em_entry_data* rec)
{
    return (rec->data.age_value != EM_NO_AGING_AGE);
}

static inline bool
has_static_age_value(const em_entry_data* rec)
{
    return (rec->data.age_value == EM_NO_AGING_AGE);
}

bool
em_request()
{
    // This additional retry would handle corner cases where some requests might
    // take longer than usual to complete or get ECC error
    for (int i = 0; i < EM_TRANSACTION_AGE_ECC_ERROR_RETRY_MAX; i++) {
        bool request_succeed = request_and_poll_loop();
        if (!request_succeed) {
            continue;
        }

        bool ecc_error = em_check_response();
        if (ecc_error) {
            debug_counter_incr(arc_debug_counters::AGE_ECC_ERROR);
            continue;
        }

        return true;
    }

    return false;
}

void
store_request(em_command_e cmd, const em_entry_data* curr, bool for_cam)
{
    uint32_t* src_payload = (uint32_t*)curr->rec.payload;
    uint32_t* dest_payload = (uint32_t*)op_ctx.em_request_reg.rec.payload;

    switch (cmd) {
    case EM_COMMAND_WRITE:
        // the structure is the same, therefore, we can copy payload and key as one
        memcpy(&op_ctx.em_request_reg.rec, &curr->rec, sizeof(long_entry_data));
        break;
    case EM_COMMAND_AGE_WRITE:
        break;
    default:
        ASSERT(false);
    }

    op_ctx.em_request_reg.data.command = cmd;
    op_ctx.em_request_reg.data.age_owner = curr->data.age_owner & 0x1;
    op_ctx.em_request_reg.data.age_value = curr->data.age_value & 0x7;
    op_ctx.em_request_reg.data.age_valid = 1;

    op_ctx.em_request_reg.data.em_core = op_ctx.group_data.em_core;
    op_ctx.em_request_reg.data.em_index = curr->data.em_index;
    op_ctx.em_request_reg.data.for_cam = for_cam;

    bool em_req_result = true;

    if (curr->data.key_size == EM_WIDE_KEY_SIZE && !for_cam) {
        // for double entries, store is done in two writes
        // even bank writes payload[63:32]
        // odd bank writes payload[31:0]
        // due to Pacific HW lookup bug, LSB part of the entry (odd bank) need to be stored first
        dest_payload[0] = src_payload[0];
        dest_payload[1] = 0;
        op_ctx.em_request_reg.data.em_bank_bitset = (1 << (curr->data.em_bank + 1));

        em_req_result = em_request();
    }

    // for cam, em_bank_bitset = 0x0;
    op_ctx.em_request_reg.data.em_bank_bitset = (for_cam == false) ? (1 << curr->data.em_bank) : 0x0;

    if (em_req_result && curr->data.key_size == EM_WIDE_KEY_SIZE && !for_cam) {
        // store MSB payload of double entry
        dest_payload[0] = src_payload[1];
        dest_payload[1] = 0;
    }

    em_request();
}

void
delete_request(const em_entry_data* curr)
{
    reset_age_value(curr);

    // delete the entry
    op_ctx.em_request_reg.data.command = EM_COMMAND_DELETE;
    op_ctx.em_request_reg.data.em_core = op_ctx.group_data.em_core;
    op_ctx.em_request_reg.data.em_bank_bitset = (curr->data.orig_for_cam == false) ? (1 << curr->data.orig_bank) : 0x0;
    op_ctx.em_request_reg.data.em_index = curr->data.orig_index;
    op_ctx.em_request_reg.data.for_cam = curr->data.orig_for_cam;

    bool em_req_result = em_request();

    if (em_req_result && curr->data.key_size == EM_WIDE_KEY_SIZE && !curr->data.orig_for_cam) {
        op_ctx.em_request_reg.data.em_bank_bitset = (1 << (curr->data.em_bank + 1));

        em_request();
    }
}

void
ffe_request(em_entry_data* curr, uint32_t bitset, bool for_cam)
{
    // bitset should have values if it's not for_CAM. Otherwise can be 0
    ASSERT(bitset || for_cam);
    memcpy(op_ctx.em_request_reg.rec.key, curr->rec.key, EM_LONG_KEY);

    op_ctx.em_request_reg.data.command = EM_COMMAND_FFE;

    op_ctx.em_request_reg.data.em_core = op_ctx.group_data.em_core;
    op_ctx.em_request_reg.data.em_bank_bitset = bitset;
    op_ctx.em_request_reg.data.for_cam = for_cam;

    em_request();

    // HW issue: FFE is not returning candidate key/payload on no-hit.
    // Workaround: call read (updates key, payload and age) and return no-hit.
    if (!op_ctx.em_response_reg.data.hit && !for_cam) {
        op_ctx.em_request_reg.data.command = EM_COMMAND_READ;
        op_ctx.em_request_reg.data.em_index = op_ctx.em_response_reg.data.em_index;
        op_ctx.em_request_reg.data.em_bank_bitset = (1 << op_ctx.em_response_reg.data.em_bank);

        em_request();
        ASSERT(op_ctx.em_response_reg.data.hit);

        // Tricky, since we have to mimic outside that the entry was not found
        op_ctx.em_response_reg.data.hit = 0;
    }

    curr->data.em_index = op_ctx.em_response_reg.data.em_index;
    curr->data.em_bank = op_ctx.em_response_reg.data.em_bank;
}

void
lookup_request(em_entry_data* curr)
{
    memcpy(op_ctx.em_request_reg.rec.key, curr->rec.key, EM_LONG_KEY);

    op_ctx.em_request_reg.data.command = EM_COMMAND_LOOKUP;

    op_ctx.em_request_reg.data.em_core = op_ctx.group_data.em_core;
    op_ctx.em_request_reg.data.em_bank_bitset = op_ctx.group_data.allowed_bank_bitset;
    op_ctx.em_request_reg.data.for_cam = 0;

    em_request();

    if (!op_ctx.em_response_reg.data.hit) {
        return;
    }

    curr->data.orig_index = op_ctx.em_response_reg.data.em_index;
    curr->data.orig_bank = op_ctx.em_response_reg.data.em_bank;
    curr->data.orig_for_cam = op_ctx.em_response_reg.data.for_cam;
    curr->data.em_index = op_ctx.em_response_reg.data.em_index;
    curr->data.em_bank = op_ctx.em_response_reg.data.em_bank;

    curr->data.key_size = op_ctx.em_response_reg.data.key_size;
    if (curr->data.key_size == EM_WIDE_KEY_SIZE && !curr->data.orig_for_cam) {
        // For wide key entries, HW returns the second bank (odd)
        // However, for the rest of the interfaces, even bank is expected.
        curr->data.orig_bank -= 1;
        curr->data.em_bank -= 1;
    }
}

// Double entries are stored in banks in the following way:
// even bank (msb) stores:
//      payload[63:32]
//      key[141:64] ^ (key[63:0] << 14)
// odd bank (lsb) stores:
//      payload[31:0]
//      key[141:75]
//
// The result is retured in msb
void
construct_wide_entry(long_entry_data* msb, long_entry_data* lsb)
{
    // payload
    uint32_t* dest_payload = (uint32_t*)msb->payload;
    uint32_t* src_payload = (uint32_t*)lsb->payload;

    dest_payload[1] = dest_payload[0]; // copy [63:32] to msb
    dest_payload[0] = src_payload[0];  // copy [31:0] to lsb

    // get {[141:75], 11b'0} by shifting LSB 11 bits left
    uint8_t bits_141_75_shift_11[EM_SHORT_KEY] = {0};
    for (int i = EM_SHORT_KEY - 1; i > 0; --i) {
        bits_141_75_shift_11[i] = (lsb->key[i - 1] << 3);
        if (i > 1) {
            bits_141_75_shift_11[i] += (lsb->key[i - 2] >> 5);
        }
    }

    // get {[63:0], 14b'0} by {[141:75], 11b'0} xor LSB (and clearing out 14 last bits.
    uint8_t bits_63_0_shift_14[EM_SHORT_KEY] = {0};
    for (int i = 1; i < EM_LONG_KEY; ++i) {
        bits_63_0_shift_14[i] = bits_141_75_shift_11[i] ^ msb->key[i];
    }
    bits_63_0_shift_14[0] = 0;     // clear out 8 lsb
    bits_63_0_shift_14[1] &= 0xc0; // clear out next 6 bits

    // get [141:64] by {[63:0], 14b'0} xor MSB
    uint8_t bits_141_64[EM_SHORT_KEY] = {0};
    for (int i = 0; i < EM_LONG_KEY; ++i) {
        bits_141_64[i] = bits_63_0_shift_14[i] ^ msb->key[i];
    }

    // RECONSTRUCT THE KEY
    // shift 14
    for (int i = 0; i < EM_SHORT_KEY - 2; ++i) {
        // copy one byte + shift another 6 (6 + 8 = 14)
        msb->key[i] = (bits_63_0_shift_14[i + 1] >> 6) + (bits_63_0_shift_14[i + 2] << 2);
    }

    // copy the key[141:64]
    for (int i = 0; i < EM_SHORT_KEY; ++i) {
        msb->key[i + 8] = bits_141_64[i];
    }
}

void
read_request(const periodic_counter* counter, em_entry_data* ret)
{
    op_ctx.em_request_reg.data.command = EM_COMMAND_READ;

    op_ctx.em_request_reg.data.em_core = counter->data.bits.em_core;
    op_ctx.em_request_reg.data.em_index = counter->data.bits.em_entry;
    // for cam, em_bank_bitset = 0x0;
    op_ctx.em_request_reg.data.em_bank_bitset = (counter->data.bits.for_cam) ? 0x0 : 1 << counter->data.bits.em_bank;
    op_ctx.em_request_reg.data.for_cam = counter->data.bits.for_cam;

    bool em_ret = em_request();

    // Callers rely on hit indication
    if (!em_ret) {
        op_ctx.em_response_reg.data.hit = false;
    }
    if (!op_ctx.em_response_reg.data.hit) {
        return;
    }

    memcpy(&ret->rec, &op_ctx.em_response_reg.rec, sizeof(long_entry_data));
    ret->data.orig_index = counter->data.bits.em_entry;
    ret->data.orig_bank = (counter->data.bits.for_cam) ? EM_NONE : counter->data.bits.em_bank;
    ret->data.orig_for_cam = counter->data.bits.for_cam;

    ret->data.em_index = counter->data.bits.em_entry;
    ret->data.em_bank = counter->data.bits.em_bank;

    ret->data.age_value = op_ctx.em_response_reg.data.age_value & 0x7;
    ret->data.age_owner = op_ctx.em_response_reg.data.age_owner & 0x1;
    ret->data.age_valid = 1;

    // HW issue: all key sizes in CAM returned as double-entry size after em_request().
    // WA: Using the same computation as HW should do for key size of CAM's entries.
    if (counter->data.bits.for_cam) {
        uint8_t index = ret->rec.key0 & 0xF;
        // taking the 2 bits in index from key_size_map
        op_ctx.em_response_reg.data.key_size = (key_size_map >> index * 2) & 3;
    }
    ret->data.key_size = op_ctx.em_response_reg.data.key_size;

    if (ret->data.key_size == EM_WIDE_KEY_SIZE && !ret->data.orig_for_cam) {
        if ((counter->data.bits.em_bank % 2) == 1) {
            // Read was performed on an odd bank.
            // There was no intention to read the entire entry
            return;
        }
        // Double entries are stored in banks in the following way:
        // even bank (msb) stores:
        //      payload[63:32]
        //      key[141:64] ^ (key[63:0] << 14)
        // odd bank (lsb) stores:
        //      payload[31:0]
        //      key[141:75]
        op_ctx.em_request_reg.data.em_bank_bitset = (1 << (counter->data.bits.em_bank + 1));

        em_request();

        construct_wide_entry(&ret->rec, &op_ctx.em_response_reg.rec);
    }

    group_request(ret);
    debug_counter_incr_cond(arc_debug_counters::READ_REQUEST, op_ctx.em_response_reg.data.hit);
}

void
group_request(const em_entry_data* curr)
{
    group_request_data request_reg;

    memcpy(&request_reg, &curr->rec.key, EM_LONG_KEY);
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
        read_reg(&op_ctx.group_data, UAUX_GROUP_RESPONSE_REG);
#ifdef GIBRALTAR
        // Full details are in "common.h". Workaround for GB errata 3.1.10
        // 8 MSB are always zero due to HW bug
        // CEM always get mor than 8 banks so we assume the missing bits to be ones
        op_ctx.group_data.allowed_bank_bitset = op_ctx.group_data.allowed_bank_bitset | WORKAROUND_ENABLE_CLEARED_CEM_BANKS;
#endif
    }
}

bool
ffe_and_store(em_entry_data* curr, uint32_t bank_bitset, bool for_cam)
{
    ffe_request(curr, bank_bitset, for_cam);
    // check if succeeded
    if (!op_ctx.em_response_reg.data.hit) {
        return false;
    }

    // success - store
    store_request(EM_COMMAND_WRITE, curr, for_cam);

    return true;
}

bool
request_and_poll(const void* shadow_reg, uaux_reg_name_e reg, uaux_reg_status_e request_stat, uaux_reg_status_e response_stat)
{
    // assuming the shadow register is ready
    write_reg(reg, shadow_reg);
    status_reg_set(request_stat);
    status_reg_write();

    uint32_t timeout_iterations = EM_TRANSACTION_WAIT_RESPONSE_MAX;

    while (!status_reg_test(response_stat) && timeout_iterations > 0) {
        TEST_MODE_POLL();
        status_reg_read();
        timeout_iterations--;
    }

    bool ok = (timeout_iterations != 0);

    // failure
    if (!ok) {
        status_reg_clear(request_stat);
        debug_counter_incr(arc_debug_counters::RESPONSE_POLL_TIMEOUT);
    }

    status_reg_clear(response_stat);
    status_reg_write();

    return ok;
}

bool
age_value_check(periodic_counter* location, const em_entry_data* rec, uint8_t for_cam, bool hit_expected, uint8_t expected_value)
{
    em_entry_data rec_read;
    periodic_counter tmp_location;

    if (location == NULL) {
        tmp_location.data.bits.em_core = op_ctx.group_data.em_core;
        tmp_location.data.bits.em_entry = rec->data.em_index;
        tmp_location.data.bits.em_bank = rec->data.em_bank;
        tmp_location.data.bits.for_cam = for_cam;
    }

    for (int i = 0; i < ARC_AGE_CHECK_RETRY_MAX; i++) {
        if (location == NULL) {
            read_request(&tmp_location, &rec_read);
        } else {
            read_request(location, &rec_read);
        }

        // entry not located
        if (!op_ctx.em_response_reg.data.hit) {
            if (!hit_expected) {
                // could be aged out already
                return true;
            }
            // Log when entry is expected to hit but not
            // Since entry it not found, we don't store the age value
            debug_counter_incr(arc_debug_counters::AGE_CHECK_INVALID_ENTRIES);
            return false;
        }
        if (expected_value == EM_CHECK_RECORD_AGE_VALUE && !(has_static_age_value(rec) && has_static_age_value(&rec_read))) {
            // Use the source record's age value for checking
            if (has_static_age_value(rec) && has_dynamic_age_value(&rec_read)) {
                debug_counter_incr(arc_debug_counters::AGE_STATIC_MISMATCHES);
                // rewrite the entry
                store_request(EM_COMMAND_AGE_WRITE, rec, rec->data.orig_for_cam);
                return false;
            } else if ((has_dynamic_age_value(rec) && has_static_age_value(&rec_read))) {
                debug_counter_incr(arc_debug_counters::AGE_DYNAMIC_MISMATCHES);
                // rewrite the entry
                store_request(EM_COMMAND_AGE_WRITE, &rec_read, rec->data.orig_for_cam);
                return false;
            } else {
                // age table collisions
                if (rec_read.data.age_value == EM_REFRESH_AGE) {
                    // it's updated by HW back to refresh value, no need to age write
                    return true;
                }

                if (rec->data.age_value != 1 && rec_read.data.age_value != rec->data.age_value) {
                    // It is possible age_owner bit is not retrieved correctly
                    rec_read.data.age_owner = rec->data.age_owner;
                    if (rec->data.age_value == EM_NEW_MAX_AGE) {
                        rec_read.data.age_value = EM_NEW_MAX_AGE;
                    } else {
                        // Pick the larger age value to write
                        rec_read.data.age_value = MAX(rec->data.age_value, rec_read.data.age_value);
                        // Bracket the age_value between 1 and EM_REFRESH_AGE
                        rec_read.data.age_value = MAX(1, rec_read.data.age_value);
                        rec_read.data.age_value = MIN(EM_REFRESH_AGE, rec_read.data.age_value);
                    }
                    store_request(EM_COMMAND_AGE_WRITE, &rec_read, rec->data.orig_for_cam);
                    debug_counter_incr(arc_debug_counters::AGE_WRITE_MISMATCHES);
                    return false;
                }
            }
        } else {
            // Use exact value for age value checking
            if (rec->data.age_value != rec_read.data.age_value) {
                debug_counter_incr(arc_debug_counters::AGE_VALUE_MISMATCHES);
                // Use the expected value for storing
                rec_read.data.age_value = expected_value;

                store_request(EM_COMMAND_AGE_WRITE, &rec_read, rec->data.orig_for_cam);
                return false;
            }
        }
        return true;
    }
    debug_counter_incr(arc_debug_counters::AGE_CHECK_FAILURES);
    return false;
}
