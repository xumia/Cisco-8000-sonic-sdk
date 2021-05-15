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

#include "counters.h"
#include "arc_cpu_common.h"
#include "common.h"
#include "debug_counters.h"
#include "em_commands.h"
#include "status_reg.h"
#include "test_if.h"
#include "uaux_regs.h"

// for memcpy/memset
#include <string.h>

// Counter context
counter_context counter_ctx;

void
read_counter_data(counter_shadow* counter)
{
    // request_and_poll function writes once and read status for 10000 times max
    // cdb->top->validreg could be overwritten by LDB after ARC set the register.
    // If this happens, request_and_poll should time out waiting for response.
    // Retry once before ARC's mainloop processing of LDB-set requests.
    bool ret = false;
    ret = request_and_poll(counter, UAUX_COUNTERS_REQUEST_REG, UAUX_REG_STATUS_COUNTERS_REQUEST, UAUX_REG_STATUS_COUNTERS_RESPONSE);
    if (!ret) {
        ret = request_and_poll(
            counter, UAUX_COUNTERS_REQUEST_REG, UAUX_REG_STATUS_COUNTERS_REQUEST, UAUX_REG_STATUS_COUNTERS_RESPONSE);
    }
    if (ret) {
        read_reg(&counter->counter, UAUX_COUNTERS_RESPONSE_REG);
    }
}

void
read_counters_from_op_context()
{
    // build address
    short_key_encoding* key = (short_key_encoding*)&op_ctx.em_response_reg.rec.key;
    short_payload_encoding* payload = (short_payload_encoding*)&op_ctx.em_response_reg.rec.payload;
    counters::address addr = {.val = 0};

    // construct MAC relay
    addr.id = key->mac_relay;
    addr.type = counters::AVAILABLE_MAC_RELAY;
    addr.rw = counters::READ;
    addr.valid = (key->mac_relay_ext == 0);

    counter_ctx.mac_relay.addr = addr.val;
    read_counter_data(&counter_ctx.mac_relay);

    // construct l2_port
    addr.id = payload->l2_port;
    addr.type = counters::AVAILABLE_AC_PORT;
    addr.rw = counters::READ;
    addr.valid = (payload->l2_port > counters::MAX_LIMIT_COUNTER_ID);

    counter_ctx.l2_port.addr = addr.val;
    read_counter_data(&counter_ctx.l2_port);
}

void
read_counter_from_arc_cpu_command(arc_cpu_command* command, counters::type_e type)
{
    counters::address addr = {.val = 0};
    addr.id = command->params.obj_params.object_id;
    addr.type = type;
    addr.rw = counters::READ;
    addr.valid = (command->params.obj_params.object_id > counters::MAX_LIMIT_COUNTER_ID);

    counter_shadow* counter = (type == counters::AVAILABLE_MAC_RELAY) ? &counter_ctx.mac_relay : &counter_ctx.l2_port;
    counter->addr = addr.val;
    read_counter_data(counter);
}

void
read_counter_from_entry_data(em_entry_data* rec, counters::type_e type)
{
    // build address
    short_key_encoding* key = (short_key_encoding*)&rec->rec.key;
    short_payload_encoding* payload = (short_payload_encoding*)&rec->rec.payload;

    uint32_t obj_id = (type == counters::AVAILABLE_MAC_RELAY) ? (key->mac_relay_ext << 12) | key->mac_relay : payload->l2_port;
    counters::address addr = {.val = 0};
    addr.id = obj_id;
    addr.type = type;
    addr.rw = counters::READ;
    addr.valid = (obj_id <= counters::MAX_LIMIT_COUNTER_ID);

    counter_shadow* counter = (type == counters::AVAILABLE_MAC_RELAY) ? &counter_ctx.mac_relay : &counter_ctx.l2_port;

    counter->addr = addr.val;
#ifdef TEST_MODE
    PRINT("-ARC- %s --> read_counter_data, obj_id: 0x%x type: %d valid: %s \n", __func__, obj_id, type, addr.valid ? "YES" : "NO");
#endif
    read_counter_data(counter);
}

bool
counter_check_limit(counter_shadow* counter)
{
    // Check if id is within the counter limits. If beyond, skip this check.
    counters::address* address = (counters::address*)&counter->addr;
    if (address->id > counters::MAX_LIMIT_COUNTER_ID) {
        return true;
    }

    // Limit counters are inverse, they start from max-value and decreased on each addition. Once counter=0, limit is reached.
    if (counter->counter_bits > 0) {
        return true;
    }

    return false;
}

bool
counters_check_limit()
{
    bool ok = counter_check_limit(&counter_ctx.mac_relay);
    if (!ok) {
        return false;
    }
    // NOTE: disable AC port counter update because there is no
    // initialization for this counter, it would go negative and block operations
    // ok = counter_check_limit(&counter_ctx.l2_port);

    return ok;
}

void
initialize_limit_counter(counter_shadow* counter, uint32_t limit)
{

    // Check if id is within the counter limits. If beyond, skip this initialization.
    counters::address* address = (counters::address*)&counter->addr;
    if (address->id > counters::MAX_LIMIT_COUNTER_ID) {
        return;
    }
    counter->counter = limit;

    // request_and_poll function writes once and read status for 10000 times max
    // cdb->top->validreg could be overwritten by LDB after ARC set the register.
    // If this happens, request_and_poll should time out waiting for response.
    // Retry once before ARC's mainloop processing of LDB-set requests.
    bool ret = false;
    ret = request_and_poll(counter, UAUX_COUNTERS_REQUEST_REG, UAUX_REG_STATUS_COUNTERS_REQUEST, UAUX_REG_STATUS_COUNTERS_RESPONSE);
    if (!ret) {
        ret = request_and_poll(
            counter, UAUX_COUNTERS_REQUEST_REG, UAUX_REG_STATUS_COUNTERS_REQUEST, UAUX_REG_STATUS_COUNTERS_RESPONSE);
    }
}

void
update_limit_counter(counter_shadow* counter, int32_t delta)
{
    // Check if id is within the counter limits. If beyond, skip this check.
    counters::address* address = (counters::address*)&counter->addr;
    if (address->id > counters::MAX_LIMIT_COUNTER_ID) {
        return;
    }

    if (counter->counter == 0 && delta < 0) {
        debug_counter_incr(arc_debug_counters::LIMIT_COUNTER_UNDERFLOWS);
        return;
    }
    counter->counter += delta;
    counter->is_write = 1;

    // request_and_poll function writes once and read status for 10000 times max
    // cdb->top->validreg could be overwritten by LDB after ARC set the register.
    // If this happens, request_and_poll should time out waiting for response.
    // Retry once before ARC's mainloop processing of LDB-set requests.
    bool ret = false;
    ret = request_and_poll(counter, UAUX_COUNTERS_REQUEST_REG, UAUX_REG_STATUS_COUNTERS_REQUEST, UAUX_REG_STATUS_COUNTERS_RESPONSE);
    if (!ret) {
        ret = request_and_poll(
            counter, UAUX_COUNTERS_REQUEST_REG, UAUX_REG_STATUS_COUNTERS_REQUEST, UAUX_REG_STATUS_COUNTERS_RESPONSE);
    }
}

void
update_occupancy_counter(uint32_t occ_id, counters::occupancy_id::type_e occ_type, int32_t delta)
{
    counters::occupancy_id id = {.val = 0};
    id.occ_id = occ_id;
    id.occ_type = occ_type;

    counters::address addr = {.val = 0};
    addr.id = id.val;
    addr.type = counters::OCCUPANCY;

    counter_request_data counter;
    counter.addr = addr.val;

    read_counter_data(&counter);

    if (counter.counter == 0 && delta < 0) {
        debug_counter_incr(arc_debug_counters::OCC_COUNTER_UNDERFLOWS);
        return;
    }

    counter.counter += delta;
    counter.is_write = 1;

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

void
update_counters(int delta, bool update_limits)
{
    if (update_limits) {
        update_limit_counter(&counter_ctx.mac_relay, -delta);
        update_limit_counter(&counter_ctx.l2_port, -delta);
    }

    update_occupancy_counter(op_ctx.group_data.em_group, counters::occupancy_id::EM_GROUP, delta);
    update_occupancy_counter(op_ctx.group_data.em_core, counters::occupancy_id::EM_CORE, delta);
}

void
counters_incr(bool is_mac)
{
    update_counters(1, is_mac);
}

void
counters_incr_payload()
{
    update_limit_counter(&counter_ctx.l2_port, -1);
}

void
counters_decr(bool is_mac)
{
    update_counters(-1, is_mac);
}

void
counters_decr_payload()
{
    update_limit_counter(&counter_ctx.l2_port, 1);
}

int32_t
counters_get_most_vacant_core(int32_t except_this_core)
{
    int32_t vacant_core = EM_NONE;
    int32_t vacant_core_occupancy = counters::MAX_COUNTER_VAL;

    counters::address addr = {.val = 0};
    addr.type = counters::OCCUPANCY;
    addr.rw = counters::READ;

    counters::occupancy_id occ_id = {.val = 0};
    occ_id.occ_type = counters::occupancy_id::EM_CORE;

    for (int32_t core = 0; core < EM_CORES_IN_CEM; ++core) {
        counter_request_data counter;

        if (core == except_this_core) {
            continue;
        }

        // complete the ID
        occ_id.occ_id = core;
        addr.id = occ_id.val;

        // read
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
        if (ret) {
            read_reg(&counter.counter, UAUX_COUNTERS_RESPONSE_REG);
        }

        if (counter.counter < vacant_core_occupancy) {
            vacant_core_occupancy = counter.counter;
            vacant_core = core;
        }
    }

    return vacant_core;
}
