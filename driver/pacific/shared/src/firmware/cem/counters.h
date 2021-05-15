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

#ifndef __CEM_COUNTERS_H__
#define __CEM_COUNTERS_H__

/// @file
/// @brief Occupancy counters implementation
/// CEM management maintains the following counters:
///     4k  mac_relay           - limit of em_entries per MAC relay for the first 4k relays. The limit is set from CPU
///     4k  logic_port          - limit or em_entries per AC port for the first 4K ports. The limit is set from CPU
///     16  em_core_occupancy   - occupancy per core, needed take load balancing decisions.
///     256 em_group_occupancy  - occupancy per group, needed to take load balancing decisions.
///     512 cam_to_sram_map     - cam entry to evacuation bank entry mapping.

#include "arc_cpu_common.h"
#include "common.h"
#include "em_commands.h"
#include "uaux_regs.h"

struct counters {

    static const uint32_t MAX_LIMIT_COUNTER_ID = (1 << 12) - 1;
    static const uint32_t MAX_COUNTER_VAL = (1 << 19) - 1;
    static const uint32_t NUM_OF_CORES_IN_CEM = 16;
    static const uint32_t NUM_OF_GROUPS_IN_CEM = 256;
    static const uint32_t FIRST_CAM_MAP_ENTRY = 8464;

    // Counter types
    enum type_e { AVAILABLE_MAC_RELAY = 0, AVAILABLE_AC_PORT, OCCUPANCY };

    // Counter operations
    enum operation_e { READ = 0, WRITE };

    // Counter's address encoding
    // type == AVAILABLE_MAC_RELAY, AVAILABLE_AC_PORT, OCCUPANCY
    // clang-format off
    union address {
        struct {
            uint32_t id                     : 12;
            uint32_t type                   : 2;
            uint32_t rw                     : 1;
            uint32_t valid                  : 1;
            uint32_t padding0               : 16;
        } FW_PACKED;
        uint32_t val;
    };

    // id field encoding if type == OCCUPANCY
    union occupancy_id {
        enum type_e { EM_GROUP, EM_CORE, NONE };
        struct {
            uint32_t occ_id                 : 8;
            uint32_t occ_type               : 2;
            uint32_t padding0               : 22;
        } FW_PACKED;

        uint32_t val;
    };
    // clang-format on
};

/// @brief Global context for COUNTER operations.
typedef counter_request_data counter_shadow;
struct counter_context {
    // COUNTER_REQUEST/COUNTER_RESPONSE shadow registers
    counter_shadow mac_relay;
    counter_shadow l2_port;
};

extern counter_context counter_ctx;

/// @brief Check MAC relay and AC port limits before addition of new entry to EM
///
/// @return     true        if addition is possible
///             false       if limit is reached and addition is impossible
bool counters_check_limit();

/// @brief Check if availability counter allows addition of new entry
///
/// @param[in]  counter     ID and type of counter being evaluated.
///
/// @return     true        entry can be inserted
///             false       limit is reached - entry cannot be inserted.
bool counter_check_limit(counter_shadow* counter);

/// @brief Read counter data and update shadow.
///
/// @param[in]  counter     Counter queried
void read_counter_data(counter_shadow* counter);

/// @brief Read counters based on current op_context.
///
/// Result will be stored in global counter_ctx.
void read_counters_from_op_context();

/// @brief Read counter data based on em_entry_data, depends on provided counter type.
///
/// Result will be stored in global counter_ctx.
/// Assumed that type is AVAILABLE_MAC_RELAY or AVAILABLE_AC_PORT
///
/// @param[in]  rec    em_entry_data to get counter data from
/// @param[in]  type   counter type
void read_counter_from_entry_data(em_entry_data* rec, counters::type_e type);

/// @brief Read counter data based on arc_cpu command.
///
/// Result will be stored in global counter_ctx.
/// Assumed that type is AVAILABLE_MAC_RELAY or AVAILABLE_AC_PORT
///
/// @param[in]  command    arc_cpu_command to get counter data from
/// @param[in]  type       counter type
void read_counter_from_arc_cpu_command(arc_cpu_command* command, counters::type_e type);

/// @brief Update limit and occupancy counters on an addition of new entry.
///
/// Limit counters (MAC and AC port) are updated only in case of MAC entry addition.
///
/// @param[in]  is_mac      true if this is mac entry.
///
/// Taking data from em_request - assuming that the operation happens AFTER command EM_COMMAND_WRITE.
/// Means that:
///      key/payload are updated in em_request
///      core/group are updated in group_data
/// Note: not all store command cause counter increase.
///
void counters_incr(bool is_mac);

/// @brief Update limits on payload update - increasing count of the new payload
/// Taking data from em_request - assuming that the operation happens AFTER command EM_COMMAND_WRITE
///
void counters_incr_payload();

/// @brief Update limit and occupancy counters on entry removal.
///
/// Limit counters (MAC and AC port) are updated only in case of MAC entry addition.
///
/// @param[in]  is_mac      true if this is mac entry.
///
// Taking data from em_response - assuming that the operation happens AFTER command EM_COMMAND_READ/LOOKUP
/// Means that:
///      key/payload are updated in em_response
///      core/group are updated in group_data
///
void counters_decr(bool is_mac);

/// @brief Update limits on payload update - decreasing count of the old payload
/// Note: this command will not work for Bulk Update
// Taking data from em_response - assuming that the operation happens AFTER command EM_COMMAND_LOOKUP/EM_COMMAND_READ
///
void counters_decr_payload();

/// @brief Update counters by delta
///
/// @param[in]  delta           New counter value will be the current - delta.
/// @param[in]  update_limits   Update limit counters.
///
void update_counters(int delta, bool update_limits);

/// @brief Update counter by delta
///        Assumed that update will succeed since limits are checked before in the flow.
///
/// @param[in]  counter      Counter to be updated
/// @param[in]  delta        New counter value will be the current - delta.
///
void update_limit_counter(counter_shadow* counter, int32_t delta);

/// @brief Initialize counter with Maximum value
///
/// @param[in]  counter          Counter to be initialized.
/// @param[in]  limit            Counter's limit to be initialized.
///
void initialize_limit_counter(counter_shadow* counter, uint32_t limit);

/// @brief Returns the most vacant core based on occupancy
///
/// @param[in]  except_this_core    returns most vacant core except this core.
int32_t counters_get_most_vacant_core(int32_t except_this_core);

#endif // __CEM_COUNTERS_H__
