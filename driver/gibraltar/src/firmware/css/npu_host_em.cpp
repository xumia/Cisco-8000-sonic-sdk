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
#include "arc_types.h"
#include "npu_host_em.h"

enum {
    EM_TRANSACTION_RETRY_MAX = 10000,
    EM_REQ_LOOP_RETRY_MAX = 300,
};

static bool
check_response_validity(em_response_data* response_data)
{
    return (response_data->valid == 1);
}

static void
read_em_response(arc_context_t* ctx, em_response_data* response_data)
{
    ae_read_register(ctx, &pacific_tree.npuh.eth_mp_em_response_register, (uint32_t*)response_data);
}

static bool
poll_response(arc_context_t* ctx, em_response_data* response_data)
{
    uint32_t timeout_iterations = EM_TRANSACTION_RETRY_MAX;

    read_em_response(ctx, response_data);
    while (!check_response_validity(response_data) && timeout_iterations > 0) {
        read_em_response(ctx, response_data);
        timeout_iterations--;
    }

    bool ok = (timeout_iterations != 0);

    // failure
    if (!ok) {
        dbg_count(ctx, ARC_DBG_RESPONSE_POLL_TIMEOUT);
    }

    return ok;
}

bool
npuh_em_add_entry(arc_context_t* ctx, uint64_t key)
{
    // Try to do a find first entry.
    em_request_data request_data;
    memset(&request_data, 0, sizeof(request_data));

    request_data.key = key;
    request_data.command = EM_COMMAND_FFE;
    request_data.em_bank_bitset = 0xf;
    ae_write_register(ctx, &pacific_tree.npuh.eth_mp_em_access_register, (uint32_t*)&request_data);

    // Read the response
    em_response_data response_data;
    if (!poll_response(ctx, &response_data)) {
        dbg_count(ctx, ARC_DBG_PFC_ADD1_ERROR);
        return false;
    }

    // nothing free
    if (!response_data.hit) {
        dbg_count(ctx, ARC_DBG_PFC_ADD2_ERROR);
        return false;
    }

    // Write the entry in the EM.
    request_data.command = EM_COMMAND_WRITE;
    request_data.em_bank_bitset = (1 << response_data.em_bank);
    request_data.em_index = response_data.em_index;
    ae_write_register(ctx, &pacific_tree.npuh.eth_mp_em_access_register, (uint32_t*)&request_data);

    // Read the response
    if (!poll_response(ctx, &response_data)) {
        dbg_count(ctx, ARC_DBG_PFC_ADD3_ERROR);
        return false;
    }

    // nothing free
    if (!response_data.hit) {
        dbg_count(ctx, ARC_DBG_PFC_ADD4_ERROR);
        return false;
    }

    dbg_count(ctx, ARC_DBG_PFC_ADD_GOOD);
    return true;
}

bool
npuh_em_delete_entry(arc_context_t* ctx, uint64_t key)
{
    em_request_data request_data;
    memset(&request_data, 0, sizeof(request_data));

    // Do a lookup on the entry
    request_data.key = key;
    request_data.command = EM_COMMAND_LOOKUP;
    request_data.em_bank_bitset = 0xf;
    ae_write_register(ctx, &pacific_tree.npuh.eth_mp_em_access_register, (uint32_t*)&request_data);

    // Read the response
    em_response_data response_data;
    if (!poll_response(ctx, &response_data)) {
        dbg_count(ctx, ARC_DBG_PFC_DEL1_ERROR);
        return false;
    }

    // not found
    if (!response_data.hit) {
        // This is not major since this entry was most likely removed already.
        return false;
    }

    request_data.command = EM_COMMAND_DELETE;
    request_data.em_bank_bitset = (1 << response_data.em_bank);
    request_data.em_index = response_data.em_index;
    ae_write_register(ctx, &pacific_tree.npuh.eth_mp_em_access_register, (uint32_t*)&request_data);

    // Read the response
    if (!poll_response(ctx, &response_data)) {
        dbg_count(ctx, ARC_DBG_PFC_DEL2_ERROR);
        return false;
    }

    dbg_count(ctx, ARC_DBG_PFC_DEL_GOOD);
    return true;
}
