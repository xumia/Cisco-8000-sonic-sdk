// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "arc_access_eng.h"
#include "arc_command_queue.h"
#include "arc_types.h"
#include "npu_host_em.h"
#include "poll_nh_eventq.h"

#include "nplapi/npl_enums.h"

#define BITMASK(x) ((1 << x) - 1)

#define arc_return_void_on_error(X)                                                                                                \
    do {                                                                                                                           \
        if (X != ERR_OK) {                                                                                                         \
            return;                                                                                                                \
        }                                                                                                                          \
    } while (0)

static void
handle_npu_host_scanner_event(arc_context_t* ctx, uint32_t* event)
{
    int rc;

    // Pass all scanner events directly to the CPU.
    rc = arc_command_send(ctx, arc_cmd_type_e::ARC_CMD_NPUH_SCANNER_EVENT, event, 12);
    if (rc == -1) {
        dbg_count(ctx, ARC_DBG_SEND_FAILED);
    }
}

static void
npuh_pfc_build_key(uint64_t destination, uint64_t tc, uint64_t slice, uint64_t cong_state, uint64_t* key)
{
    *key = (NPL_PFC_CONG_TBL_ID << 0) | ((destination & 0x3f) << 2) | ((destination & 0xfff) << 8) | ((destination & 0xfff) << 20)
           | ((destination & 0xfff) << 32) | ((tc & 0x7) << 44) | ((slice & 0x7) << 47);
}

static void
npuh_extract_pfc_from_event(uint32_t* event, uint64_t* destination, uint64_t* tc, uint64_t* slice, uint64_t* cong_state)
{
    // JWB Remove magic numbers.
    *destination = (event[0] >> 3) & 0xfff;
    *tc = (event[0] >> 15) & 0x7;
    *cong_state = (event[0] >> 18) & 0x1;
    *slice = (event[0] >> 19) & 0x7;
}

static uint8_t
build_hash_key(uint64_t destination, uint64_t tc, uint64_t slice)
{
    uint8_t hash_key;
    // The hash key is picked as follows:
    // tc[0] : From the proposed config there will be 2 TCs uses which are seperated by 1 bit.
    // slice[1:0] : Will be used on LC where slice is limited to 0-2.
    // destination[6:2] : The 2 lsb of the destination is not used. For many of the forwarding scenarios,
    // the ECMP will be to the same set of cards, so the entropy in the destination should be mostly in the
    // lsb bits.
    hash_key = ((tc & 1) << 7) | ((slice & 0x3) << 5) | ((destination >> 2) & 0x1f);

    return hash_key;
}

static void
add_hash_table_entry(arc_context_t* ctx, uint64_t destination, uint64_t tc, uint64_t slice, uint64_t cong_state)
{
    pfc_hash_table_t* hash_table;
    uint8_t hash_key;

    hash_table = ctx->arc_specific.arc0.pfc_hash_table;
    hash_key = build_hash_key(destination, tc, slice);

    hash_table[hash_key].valid = 1;
    hash_table[hash_key].destination = destination;
    hash_table[hash_key].slice = slice;
    hash_table[hash_key].tc = tc;
    hash_table[hash_key].cong_state = cong_state;
    hash_table[hash_key].counter = 0;
}

static void
delete_hash_table_entry(arc_context_t* ctx, uint64_t destination, uint64_t tc, uint64_t slice)
{
    pfc_hash_table_t* hash_table;
    uint8_t hash_key;

    hash_table = ctx->arc_specific.arc0.pfc_hash_table;
    hash_key = build_hash_key(destination, tc, slice);

    hash_table[hash_key].valid = 0;
}

static bool
check_hash_table(arc_context_t* ctx, uint64_t destination, uint64_t tc, uint64_t slice, uint64_t cong_state)
{
    pfc_hash_table_t* hash_table;
    uint8_t hash_key;

    hash_table = ctx->arc_specific.arc0.pfc_hash_table;
    hash_key = build_hash_key(destination, tc, slice);

    if ((hash_table[hash_key].destination == destination) && (hash_table[hash_key].slice == slice)
        && (hash_table[hash_key].tc == tc)
        && (hash_table[hash_key].valid == 1)
        && (hash_table[hash_key].cong_state == cong_state)) {
        // Protect against potential mismatch between hw and sw table.
        // If there is an excessive number of hits, it may mean we are out of sync.
        hash_table[hash_key].counter++;

        // Age the entry after 32 hits.
        if (hash_table[hash_key].counter >= 32) {
            // reset the counter and return false to trigger the hw operation.
            hash_table[hash_key].counter = 0;
            dbg_count(ctx, ARC_DBG_PFC_HASH_TABLE_AGE);
            return false;
        }
        return true;
    }

    return false;
}

static void
handle_pfc_packet_event(arc_context_t* ctx, uint32_t* event)
{
    uint64_t cong_state;
    uint64_t key;
    uint64_t tc;
    uint64_t slice;
    uint64_t destination;
    bool result = false;

    // Exact the EM key and the congestion state from the event.
    npuh_extract_pfc_from_event(event, &destination, &tc, &slice, &cong_state);
    if (check_hash_table(ctx, destination, tc, slice, cong_state)) {
        dbg_count(ctx, ARC_DBG_PFC_HASH_TABLE_MATCH);
        return;
    }

    npuh_pfc_build_key(destination, tc, slice, cong_state, &key);

    if (cong_state) {
        dbg_count(ctx, ARC_DBG_PFC_ADD_EVENT);
        result = npuh_em_add_entry(ctx, key);
    } else {
        dbg_count(ctx, ARC_DBG_PFC_DEL_EVENT);
        result = npuh_em_delete_entry(ctx, key);
    }

    if (result) {
        // Add the entry to the sw hash table if the operation succeeded.
        add_hash_table_entry(ctx, destination, tc, slice, cong_state);
    } else {
        // If the hw command failed, if the cong_state is zero, the delete failed,
        // which means that the entry wasn't present. Update the sw hash table to reflect that.
        if (cong_state == 0) {
            add_hash_table_entry(ctx, destination, tc, slice, cong_state);
        } else {
            // If the add failed, remove it from the sw hash table and count it.
            // This shouldn't happen.
            delete_hash_table_entry(ctx, destination, tc, slice);
            dbg_count(ctx, ARC_DBG_SW_HASH_TABLE_DELETE);
        }
    }
}

static void
handle_bfd_packet_event(arc_context_t* ctx, uint32_t* event)
{
    int rc;

    // Pass all BFD events directly to the CPU.
    rc = arc_command_send(ctx, arc_cmd_type_e::ARC_CMD_NPUH_PACKET_EVENT, event, 12);
    if (rc == -1) {
        dbg_count(ctx, ARC_DBG_SEND_FAILED);
    }
}

static void
handle_npu_host_packet_event(arc_context_t* ctx, uint32_t* event)
{

    switch ((event[0] >> NPL_NPUH_EVENTQ_ID_SHIFT) & BITMASK(NPL_NPUH_EVENTQ_ID_WIDTH)) {
    case NPL_NPUH_EVENTQ_BFD_ID:
        handle_bfd_packet_event(ctx, event);
        break;
    case NPL_NPUH_EVENTQ_PFC_ID:
        handle_pfc_packet_event(ctx, event);
        break;
    default:
        break;
    }
}

static void
handle_npu_host_event(arc_context_t* ctx, uint32_t* event)
{
    if (event[0] & 0x1) {
        handle_npu_host_scanner_event(ctx, event);
        dbg_count(ctx, ARC_DBG_NH_EVENTQ_SCANNER_EVENTS);
    } else {
        handle_npu_host_packet_event(ctx, event);
        dbg_count(ctx, ARC_DBG_NH_EVENTQ_PKT_EVENTS);
    }
}

void
poll_nh_eventq(arc_context_t* ctx)
{
    ae_error_t status;

    uint32_t full_read_address;
    uint32_t full_write_address;

    dbg_count(ctx, ARC_DBG_NH_POLL_TIMES);

    // Read the read/write ptr from the eventq.
    status = ae_read_register(ctx, &pacific_tree.npuh.cpu_q_config_read_adress, &full_read_address);
    arc_return_void_on_error(status);

    status = ae_read_register(ctx, &pacific_tree.npuh.cpu_q_config_write_adress, &full_write_address);
    arc_return_void_on_error(status);

    if (full_read_address == full_write_address) {
        // Nothing to do
        return;
    }

    // Chop and loop using 10 bits, to wrap around the ring.
    struct evq_address {
        uint32_t val : 10;
    };

    evq_address write_address = {full_write_address};
    evq_address read_address = {full_read_address};

    // If the msb of the read/write ptrs are different and
    // the write 10b is greater than the read 10b
    // we have wrapped.
    if (((full_write_address & (1 << 10)) != (full_read_address & (1 << 10))) && (write_address.val >= read_address.val)) {
        uint32_t evq_counter[2];

        // Save some debug counters from the eventq.
        dbg_count(ctx, ARC_DBG_EVQ_WRAPPED);
        ae_read_register(ctx, &pacific_tree.npuh.evq_counters, evq_counter);
        dbg_inc(ctx, ARC_DBG_ARRIVED_TO_EVQ, evq_counter[0]);
        dbg_inc(ctx, ARC_DBG_DROPPED_IN_EVQ, evq_counter[1]);

        if (write_address.val == read_address.val) {
            // If we wrapped and the ptr are equal, bump the read ptr ahead by one
            // to do some work.
            read_address.val++;
        }
        // Continue processing messages even though there was a wrap.
    }

    uint32_t msgs_handled = 0;

    for (; read_address.val != write_address.val; ++read_address.val) {
        uint32_t result[3];

        status = ae_read_memory(ctx, &pacific_tree.npuh.event_queue, read_address.val, result);
        if (status != ERR_OK) {
            dbg_count(ctx, ARC_DBG_NH_RD_ERROR);
            continue;
        }

        handle_npu_host_event(ctx, result);
        msgs_handled++;
    }

    // Update event queue, use full 11-bit value
    ae_write_register(ctx, &pacific_tree.npuh.cpu_q_config_read_adress, &full_write_address);

    // Update the hwm
    dbg_hwm(ctx, ARC_DBG_EVENTQ_HWM, msgs_handled);
}

void
clear_pfc_congestion_state(arc_context_t* ctx, void* msg, uint32_t length)
{
    uint64_t key;
    uint64_t destination;
    uint64_t tc;
    uint64_t slice;

    // Extract the destination, tc, slice from the message.
    arc_cmd_msg_pfc_clear_cong_t* pfc_msg = (arc_cmd_msg_pfc_clear_cong_t*)msg;
    destination = pfc_msg->destination;
    tc = pfc_msg->tc;
    slice = pfc_msg->slice;

    // Build the key for the exact match table.
    npuh_pfc_build_key(destination, tc, slice, 0, &key);

    // Delete the entry from the table.
    npuh_em_delete_entry(ctx, key);

    // Delete the entry from the hash table.
    delete_hash_table_entry(ctx, destination, tc, slice);
}
