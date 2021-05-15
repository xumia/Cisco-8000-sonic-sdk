// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __ARC_CPU_COMMON_H__
#define __ARC_CPU_COMMON_H__

#include <stdint.h>

/// @file
/// @brief common shared definitions between C arc firemware and sdk

/// @brief cem protocol constants of the device.
enum {
    ARC_CPU_COMMAND_REG_LEN = 8,                 ///< Length of ARC CPU command register in dwords.
                                                 ///< TODO - In pacific its 8. In GB it can be 9.
    ARC_EM_REQUEST_COMMANDS = 9,                 ///< Number of EM commands that CDB supports.
    MAX_MAC_PER_SWITCH_NO_LIMIT_VALUE = 0x7ffff, ///< ARC count up to half-million MAC addresses per switch
    ///< Counter value width is 20 bits, but since we'd like to track also negative values,
    ///< Max value uses only 19 bits.
    MAX_TABLE_KEY_LEN = 5, ///< Maximal length of table keys in dwords.
    MAX_TABLE_KEY_LEN_IN_BYTES = MAX_TABLE_KEY_LEN * sizeof(uint32_t),
    MAX_TABLE_PAYLOAD_LEN = 2, ///< Maximal length of table payloads in dwords.
    MAX_TABLE_PAYLOAD_LEN_IN_BYTES = MAX_TABLE_PAYLOAD_LEN * sizeof(uint32_t),
    MAC_FORWARDING_TABLE_CODE = 1, ///< Prefix code for cem table to identify mac_forwarding key-payload
    ARC_CAM_BANK_IDX = 255,
    NUM_EM_CORES = 16, ///< Number of cores in CEM table.
};

/// @brief ARC-CPU commands
enum arc_cpu_command_e {
    ARC_CPU_COMMAND_NONE = 0,
    ARC_CPU_COMMAND_SWITCH_MAX_MAC,       ///< Set max MAC entries associated with a switch. ARC recieves (current_max - new_max)
    ARC_CPU_COMMAND_SWITCH_INIT_MAC,      ///< Initialize switch in cem with no_limit MAC addresses.
    ARC_CPU_COMMAND_LOOKUP_KEY,           ///< Perform lookup in CEM. Return (key, payload).
    ARC_CPU_COMMAND_LAST_LOOKUP_LOCATION, ///< Returns location of the last lookup.
    ARC_CPU_COMMAND_READ_ENTRY,           ///< Read single or double entry from given core/bank/index or CAM.
    ARC_CPU_COMMAND_AGE_READ_ENTRY,       ///< Read age data from given core/bank/index or CAM.
    ARC_CPU_COMMAND_INSERT_TABLE_SINGLE_ENTRY,   ///< Insert CEM tables occupying single CEM bank (key sizes 0, 1)
    ARC_CPU_COMMAND_ERASE_TABLE_SINGLE_ENTRY,    ///< Delete CEM tables occupying single CEM bank (key sizes 0, 1)
    ARC_CPU_COMMAND_INSERT_TABLE_DOUBLE_ENTRY,   ///< Insert CEM table occupying two CEM banks (key size 2)
    ARC_CPU_COMMAND_ERASE_TABLE_DOUBLE_ENTRY,    ///< Delete CEM table occupying two CEM banks (key size 2)
    ARC_CPU_COMMAND_EVACUATE_TABLE_DOUBLE_ENTRY, ///< Try to Evacuate From CAM to SRAM (key size 2)
    ARC_CPU_COMMAND_SET_KEY_SIZE_MAP_VALUE,      ///< Transfer em_key_width which used to map key to key size.
    ARC_CPU_COMMAND_GET_FEATURES,                ///< Retrieve CEM ARC features and confiurations
    ARC_CPU_COMMAND_SET_FEATURES,                ///< Controls CEM ARC features by CPU
    ARC_CPU_COMMAND_GET_UTILIZATION_STATE,       ///< Get needed utilization details to calculate usage percentage
    ARC_CPU_COMMAND_LAST = ARC_CPU_COMMAND_GET_UTILIZATION_STATE,
};

/// @brief ARC-CPU command status
enum arc_cpu_command_status_e {
    ARC_CPU_COMMAND_STATUS_SUCCESS,         ///< Operation completed successfully.
    ARC_CPU_COMMAND_STATUS_EUNKNOWN,        ///< Unknown error occurred while attempting to perform requested operation.
    ARC_CPU_COMMAND_STATUS_ERESOURCE,       ///< Out of resources.
    ARC_CPU_COMMAND_STATUS_ELIMIT,          ///< Blocked by defined limit counter.
    ARC_CPU_COMMAND_STATUS_EEXIST,          ///< Entry already exists.
    ARC_CPU_COMMAND_STATUS_ENOTFOUND,       ///< Entry not found.
    ARC_CPU_COMMAND_STATUS_EINVAL,          ///< Invalid command was provided
    ARC_CPU_COMMAND_STATUS_ENOTIMPLEMENTED, ///< API is not implemented.
    ARC_CPU_COMMAND_STATUS_REQUEST_BUBBLE,  ///< ARC unable to write on CEM, CPU needs to ensure HW bubble
    ARC_CPU_COMMAND_STATUS_NONE,
    ARC_CPU_COMMAND_STATUS_LAST = ARC_CPU_COMMAND_STATUS_NONE,
};

/// @brief ARC-CPU FSM states
///
/// Valid state transitions:
///   Initial state: CPU
///   CPU --> ARC
///   ARC --> CPU
enum arc_cpu_fsm_state_e {
    ARC_CPU_FSM_STATE_CPU = 0,
    ARC_CPU_FSM_STATE_ARC,
};

/// @brief bitmap of CEM ARC features enabled/disabled by CPU
enum arc_cpu_feature_e {
    ARC_CPU_FEATURE_TYPE_NONE = 0, ///< Feature type starts from one
    ARC_CPU_FEATURE_TYPE_FIRST,
    ARC_CPU_FEATURE_TYPE_LEARN_MODE = ARC_CPU_FEATURE_TYPE_FIRST, ///< Current MAC learning mode configured on ASIC
    ARC_CPU_FEATURE_TYPE_AGE_MODE,                                ///< Enable/disable CEM ARC entry deletion in aging routine
    ARC_CPU_FEATURE_TYPE_AGE_NOTIFICATION,                        ///< Enable/disable CEM ARC notification on aged entries
    ARC_CPU_FEATURE_TYPE_AGE_INTERVAL,                            ///< Enable/disable/configure CEM ARC age scanning and intervals
    ARC_CPU_FEATURE_TYPE_LAST = ARC_CPU_FEATURE_TYPE_AGE_INTERVAL,
};

/// @brief Feature TLV with fixed length at 32b, each TVL will fit into one of the
///        ARC CPU registers
struct arc_cpu_feature_type_value {
    arc_cpu_feature_e type : 4;
    uint32_t value : 28;
};

#define ARC_CPU_FEATURE_INCAPABLE 0
#define ARC_CPU_FEATURE_CAPABLE 1
#define ARC_CPU_FEATURE_VALUE_INVALID 0xFFFFFFFF
#define ARC_CPU_FEATURE_VALUE_LEARN_MODE_LOCAL (ARC_CPU_FEATURE_CAPABLE + 1)
#define ARC_CPU_FEATURE_VALUE_LEARN_MODE_SYSTEM (ARC_CPU_FEATURE_CAPABLE + 2)
#define ARC_CPU_FEATURE_VALUE_AGE_MODE_DELETE_ENTRY (ARC_CPU_FEATURE_CAPABLE + 1)
#define ARC_CPU_FEATURE_VALUE_AGE_MODE_KEEP_ENTRY (ARC_CPU_FEATURE_CAPABLE + 2)
#define ARC_CPU_FEATURE_VALUE_AGE_NOTIFICATION_OFF (ARC_CPU_FEATURE_CAPABLE + 1)
#define ARC_CPU_FEATURE_VALUE_AGE_NOTIFICATION_ON (ARC_CPU_FEATURE_CAPABLE + 2)
#define ARC_CPU_FEATURE_VALUE_MASK 0x0FFFFFFF
#define ARC_MAC_AGING_INTERVAL_DISABLE ARC_CPU_FEATURE_VALUE_MASK
#define ARC_CPU_FEATURE_MAX_TLV_COUNT                                                                                              \
    (ARC_CPU_COMMAND_REG_LEN - 1) ///< First ARC CPU register is used for command, state and status...

#pragma pack(push, 4)

// ARC status for CPU commands
struct arc_cpu_status {
    arc_cpu_fsm_state_e state : 4;       ///< FSM state.
    arc_cpu_command_e command : 4;       ///< Command
    arc_cpu_command_status_e status : 4; ///< Status
    uint32_t core : 4;                   ///< CDB core.
    uint32_t inserted_to_cam : 1;        ///< Indicates that the entry was inserted to CAM.
    uint32_t padding : 7;

    // Debug information regarding the exact failing stage
    struct stage_s {
        uint32_t load_balance_stage : 2;         ///< Load balancing stage (DONE = 11).
        uint32_t update_entry_counter_limit : 1; ///< Failure in counter limit check for
                                                 ///< existing entry update (ac_port counter).
        uint32_t new_entry_counter_limit : 1;    ///< Failure in counter limit check for
                                                 ///< new entry insertion (ac_port or mac_relay counter).
        uint32_t new_entry_insert_failure : 1;   ///< Failure in new entry insertion. No room in banks and cam even after relocation
                                                 /// algorithm.
        uint32_t em_response_timeout : 1;        ///< Failure due to a timeout of EM request/response.
        uint32_t padding : 2;
    } stage;
};

// Debug counters.
struct arc_debug_counters {
    enum {
        MAIN_LOOP,                    ///< CEM ARC active indicator
        CPU_COMMAND,                  ///< CPU-to-ARC commands
        CPU_RESPONSE,                 ///< ARC-to-CPU responses
        LEARN_NEW_EVENTS,             ///< Learn new entry events from HW.
        LEARN_UPDATE_EVENTS,          ///< Updated existing entry events from HW.
        LEARN_REFRESH_EVENTS,         ///< Refresh age of the existing entry events from HW.
        LEARN_NEW,                    ///< Learn new entry from HW.
        SIMPLE_INSERT,                ///< Insert new entry success without relocating other entries.
        CPU_INSERT,                   ///< CPU-inserted entries
        DOUBLE_INSERT,                ///< Insert new double entry success (with or without) relocating other entries.
        CPU_INSERT_DOUBLE,            ///< CPU-inserted double-wide entries
        RELOCATE,                     ///< Insert new entry success after relocating other entries.
        RELOCATE_FOR_DOUBLE,          ///< Relocate existing single entries to insert double enty.
        RELOCATE_DOUBLE,              ///< Relocate existing double entries.
        CAM_INSERT,                   ///< Insert to CAM success.
        CPU_ERASE,                    ///< CPU-deleted entries.
        CPU_ERASE_NOT_FOUND,          ///< Non-existent entries requested for CPU deletion.
        NEW_INSERT_FAILS,             ///< Number of entries failed installation.
        UPDATE_LOOKUP_FAIL,           ///< Entry not found on update command.
        UPDATE_CONFLICTS,             ///< CPU installed entry updated by HW
        RESPONSE_POLL_TIMEOUT,        ///< Timeout on request poll.
        READ_REQUEST,                 ///< Number of EM read requests
        STATIC_MAC_ENTRIES,           ///< Number of statis MAC entries installed by CPU
        DYNAMIC_MAC_ENTRIES,          ///< Number of dynamic MAC entries installed by CPU
        AGE_SWEEP,                    ///< Number of completed age sweeps
        AGE_CONFIGS,                  ///< Number of aging config changes from SDK
        AGE_INTERVAL,                 ///< Current aging interval value
        AGED_ENTRIES,                 ///< Number of aged entries
        AGE_ECC_ERROR,                ///< Number of cem_age_table ECC errors
        AGE_READ_RETRY,               ///< Number of cem_age_table read retries because of ECC errors
        AGE_READ_MISMATCHES,          ///< Two sequential reads of the same entry resulted in age_value difference
        AGE_WRITE_MISMATCHES,         ///< During entry installation, age_value can be inconsistent
        AGE_STATIC_MISMATCHES,        ///< Attempt to change static MAC entry's age_value to dynamic
        AGE_DYNAMIC_MISMATCHES,       ///< Attempt to change dynamic MAC entry's age_value to static
        AGE_VALUE_MISMATCHES,         ///< Difference between intended and actual age_value of a MAC entry
        AGE_CHECK_INVALID_ENTRIES,    ///< Age value check on a non-existent entry
        AGE_CHECK_FAILURES,           ///< After retry attempts in read_request() we still can't verify age_value
        UPDATE_LIMIT_EXCEEDS,         ///< L2 AC limit reached during entry update
        LIMIT_COUNTER_UNDERFLOWS,     ///< L2 AC limit counter update underflows
        OCC_COUNTER_UNDERFLOWS,       ///< Occupancy counter update underflows
        CPU_LOOKUPS,                  ///< Number of CPU entry lookups on HW
        CPU_LOOKUP_LOC,               ///< Number of the previous CPU entry lookups on HW
        CPU_LOOKUP_NOT_FOUND,         ///< Number of CPU entry lookups without positive result
        CPU_ENTRY_OVERWRITE,          ///< Number of CPU entry updates on existing HW entries
        CPU_READ_NOT_FOUND,           ///< Number of CPU entry read on non-existent HW entries
        DBL_RELO_FFE_TOTAL,           ///< Number of EM FFE requests during double relocations
        DBL_RELO_READ_TOTAL,          ///< Number of EM READ requests during double relocations
        DBL_RELO_READ_FAILS,          ///< Number of EM READ failures during double relocations
        DBL_RELO_STORE_TOTAL,         ///< Number of EM STORE requests during double relocations
        DBL_RELO_STORE_FAILS,         ///< Number of EM STORE failures during double relocations
        DBL_INSERT_FFE_TOTAL,         ///< Number of EM FFE requests during double insertions
        DBL_INSERT_READ_TOTAL,        ///< Number of EM READ requests during double insertions
        DBL_INSERT_READ_FAILS,        ///< Number of EM READ failures during double insertions
        DBL_INSERT_SINGLE_RELO_FAILS, ///< Number of single relocation failures during double insertions
        DBL_RELO_BACKWALKS,           ///< Number of double relocation parent-node backwalks
        DBL_RELO_BST_LOOPS,           ///< Number of loops encountered in double relocation binary search tree
        TOTAL_EVACUATION_TRIES,       ///< Number of actual tries of evacuation
        SET_FEATURE_FAILS,
        NUM_DEBUG_COUNTERS,
    };

    // signature for identifying debug counter starting location
    // it is "DBG_" in ASCII hex
    uint32_t signature;
    uint32_t counter[NUM_DEBUG_COUNTERS];
    uint32_t em_request_failure[ARC_EM_REQUEST_COMMANDS];
};

// The first field of command struct must be command_code, int32 alignment is applied (CPU registers are 32bit wide)
// cpu has 256 bits in arc registers, 32 for command and rest for payload
struct arc_cpu_command {

    // Parameters of object API
    struct obj_params_data {
        uint32_t object_id;
        int32_t object_data;
    };

    // Parameters of table API [1]
    struct table_param_data {
        uint32_t key[MAX_TABLE_KEY_LEN];
        uint32_t payload[MAX_TABLE_PAYLOAD_LEN];
    };

    // Parameters of table API [2]
    struct table_age_param_data {
        uint32_t age;
        uint32_t age_owner;
        uint32_t age_timer_inverval;
    };

    // Parameters of location API
    struct location_param_data {
        uint32_t core;
        uint32_t bank;
        uint32_t index;
        uint32_t key_size;
    };

    // Parameters of feature API
    struct feature_params_data {
        arc_cpu_feature_type_value type_values[ARC_CPU_FEATURE_MAX_TLV_COUNT];
    };

    struct utilization_params_data {
        uint32_t cam_utilization : 8;
        uint32_t sram_utilization : 16;
        uint32_t padding : 8;
        uint32_t total_sram_utilization : 32;
    };

    arc_cpu_fsm_state_e state : 4;
    arc_cpu_command_e command : 4;
    arc_cpu_command_status_e status : 4;
    uint32_t candidate_cores_bitmap : NUM_EM_CORES; ///< Indication whether entry can be inserted to banks or only to the CAM.
    uint32_t padding : 4;

    union command_params_u {
        obj_params_data obj_params;
        table_param_data table_params;
        table_age_param_data table_age_params;
        location_param_data location_params;
        feature_params_data feature_params;
        utilization_params_data utilization_params;

        uint32_t flat[ARC_CPU_COMMAND_REG_LEN - 1]; ///< One dward goes to command/status.

    } params;
};

union arc_cpu_application_specific_fields {
    struct fields_s {
        // starting from LSB
        uint32_t age_value : 3;
        uint32_t age_owner : 1;
    } fields;
    uint64_t flat : 36;
};

// all cores share the same debug counter number space
enum arc_debug_counters_e {
    // Debug events
    ARC_DBG_LOOP = 0,
    ARC_DBG_TEST_SECOND_COUNT,
    ARC_DBG_TEST,
    ARC_DBG_CMD_RCV_COUNT,
    ARC_DBG_PFC_ADD_GOOD,
    ARC_DBG_PFC_DEL_GOOD,
    ARC_DBG_NH_POLL_TIMES,
    ARC_DBG_NH_EVENTQ_SCANNER_EVENTS,
    ARC_DBG_NH_EVENTQ_PKT_EVENTS,
    ARC_DBG_ARRIVED_TO_EVQ,
    ARC_DBG_PFC_ADD_EVENT,
    ARC_DBG_PFC_DEL_EVENT,
    ARC_DBG_PFC_HASH_TABLE_MATCH,
    ARC_DBG_EVENTQ_HWM,
    ARC_DBG_PFC_HASH_TABLE_AGE,

    // Error events
    ARC_DBG_LOOP_EXCEEDED,
    ARC_DBG_CMD_RCV_OUT_OF_RANGE,
    ARC_DBG_CMD_SND_QUEUE_FULL,
    ARC_DBG_CMD_SND_MSG_BUF_FULL,
    ARC_DBG_SEND_FAILED,
    ARC_DBG_NH_RD_ERROR,
    ARC_DBG_EVQ_WRAPPED,
    ARC_DBG_DROPPED_IN_EVQ,
    ARC_DBG_PFC_ADD1_ERROR,
    ARC_DBG_PFC_ADD2_ERROR,
    ARC_DBG_PFC_ADD3_ERROR,
    ARC_DBG_PFC_ADD4_ERROR,
    ARC_DBG_RESPONSE_POLL_TIMEOUT,
    ARC_DBG_PFC_DEL1_ERROR,
    ARC_DBG_PFC_DEL2_ERROR,
    ARC_DBG_CMD_MSG_TOO_BIG,
    ARC_DBG_SW_HASH_TABLE_DELETE,

    // Unused events (to keep alignment)
    ARC_DBG_UNUSED1,
    ARC_DBG_UNUSED2,
    ARC_DBG_UNUSED3,
    ARC_DBG_UNUSED4,
    ARC_DBG_UNUSED5,
    ARC_DBG_UNUSED6,
    ARC_DBG_UNUSED7,
    ARC_DBG_MAX,
};

// ARC command message types.
enum arc_cmd_type_e {
    ARC_CMD_INVALID = 0,
    ARC_CMD_PING,                // Test message.
    ARC_CMD_PONG,                // Test response.
    ARC_CMD_NPUH_SCANNER_EVENT,  // Session tmeout messages from the NPU host processor.
    ARC_CMD_NPUH_PACKET_EVENT,   // Packet events from the NPU host processor.
    ARC_CMD_NPUH_CLEAR_PFC_CONG, // Message to clear PFC congestion table.
    ARC_CMD_MAX
};

struct arc_cmd_t {
    uint16_t type;
    uint16_t msg_length;
};

#define CMD_QUEUE_SIZE (1024)        // commands
#define CMD_MSG_BUF_SIZE (1024 * 12) // bytes

// The largest From CPU msg size.
#define ARC_FROM_CPU_MAX_MSG_LENGTH 32

#define CMD_INDEX_INCR(x)                                                                                                          \
    do {                                                                                                                           \
        if ((++x) >= CMD_QUEUE_SIZE) {                                                                                             \
            x = 0;                                                                                                                 \
        }                                                                                                                          \
    } while (0)

struct arc_cmd_queue_t {
    uint32_t cmd_read;
    uint32_t cmd_write;
    arc_cmd_t commands[CMD_QUEUE_SIZE];
    uint32_t msg_read;
    uint32_t msg_write;
    uint8_t msg_buffer[CMD_MSG_BUF_SIZE];
};

// a magic marker is added to the CSS memory, 00 gets replaced with the core id
#define MAGIC_SIZE 8 // 32bit words
#define MAGIC_VALUE 0xbeef00ee

struct css_arc_mem_t {
    uint32_t magic[MAGIC_SIZE]; // initialized to a magic number on boot
    uint32_t dbg_counters[ARC_DBG_MAX];
    uint32_t id;
    arc_cmd_queue_t from_cpu;
    arc_cmd_queue_t to_cpu;
};

struct arc_cmd_msg_pfc_clear_cong_t {
    uint16_t destination;
    uint8_t slice;
    uint8_t tc;
};

#pragma pack(pop)
#endif // __ARC_CPU_COMMON_H__
