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
/// @brief UAUX registers definitions for Exact Match Management
///
/// @details Central Exact Match Management (CEM) software is
/// running on a dedicated ARC processor. It interacts with CEM
/// hardware via set of UAUX registers. The register structures
/// and command encodings are defined in this file.
///

#ifndef __CEM_UAUX_REGS_H__
#define __CEM_UAUX_REGS_H__

#include "common.h"
#include "uaux_regs_commands.h"

/// @brief Ordered list of UAUX registers
///
enum uaux_reg_name_e {
    UAUX_LEARN_REG,
    UAUX_REFRESH_REG,
    UAUX_AGING_REG,
    UAUX_BULK_UDATE_REG,
    UAUX_COUNTERS_REQUEST_REG,
    UAUX_COUNTERS_RESPONSE_REG,
    UAUX_GROUP_REQUEST_REG,
    UAUX_GROUP_RESPONSE_REG,
    UAUX_EM_REQUEST_REG,
    UAUX_EM_RESPONSE_REG,
    UAUX_CPU_REG,
    UAUX_STATUS_REG,
    UAUX_STATUS_MASK_REG,
    UAUX_REG_NUM,
};

// Length in bytes of 78 bits key
static const int EM_SHORT_KEY = 12;

// Length in bytes of 142 bits key
static const int EM_LONG_KEY = 20;

// Length in bytes of 64 bits payload
static const int EM_LONG_PAYLOAD = 8;

// Length in bytes of 20 bits payload
static const int EM_SHORT_PAYLOAD = 4;

// clang-format off

/// @brief Short key encoding
struct short_key_encoding {
    // word 0
    uint32_t code                       : 4;  ///< for keys, used in EM_LEARN, it should be 0001
    uint32_t mac_addr0                  : 28;
    // word 1
    uint32_t mac_addr1                  : 20;
    uint32_t mac_relay                  : 12;
    // word 2
    uint32_t mac_relay_ext              : 2;
    uint32_t key_padding                : 12;
    uint32_t padding0                   : 18;
} FW_PACKED;

/// @brief Short payload encoding
struct short_payload_encoding {
    // word 0
    uint32_t l2_port                    : 18;
    uint32_t code                       : 2;  ///< for keys, used in EM_LEARN, it should be 10
    uint32_t padding0                   : 12;
} FW_PACKED;


/// @brief UAUX register shadow structures
///
/// @details The content of UAUX register is copied to a shadow
/// stucture for read/write to conveniently access bit fields.
/// There is dual representation to access key and payload by
/// address
///

/// @brief Common definition for key-payload entry
union long_entry_data {
    struct {
        // word 0
        uint32_t payload0               : 32;
        // word 1
        uint32_t payload1               : 32; // total 64
        // word 2
        uint32_t key0                   : 32;
        // word 3
        uint32_t key1                   : 32;
        // word 4
        uint32_t key2                   : 32;
        // word 5
        uint32_t key3                   : 32;
        // word 6
        uint32_t key4                   : 14; // total 142
        uint32_t padding0               : 18;
    } FW_PACKED;
    struct {
        uint8_t payload[EM_LONG_PAYLOAD];
        uint8_t key[EM_LONG_KEY];
    };
};

/// @brief Learn register (128)
union learn_data {
    struct {
        // word 0
        uint32_t key0                   : 32;
        // word 1
        uint32_t key1                   : 32;
        // word 2
        uint32_t key2                   : 14; // total 78
        uint32_t padding0               : 18;
        // word 3
        uint32_t payload0               : 20;
        uint32_t command                : 2;
        uint32_t owner                  : 1;
        uint32_t padding1               : 9;
    } FW_PACKED;

    struct {
        uint8_t key[EM_SHORT_KEY];
        uint8_t payload[EM_SHORT_PAYLOAD];
    };
};

/// @brief Refresh register (64)
union refresh_data {
    struct {
        // word 0
        uint32_t key0                   : 32;
        // word 1
        uint32_t key1                   : 32;
        // word 2
        uint32_t key2                   : 14; // total 78
        uint32_t padding0               : 18;
        // word 3
        uint32_t payload0               : 20;
        uint32_t padding1               : 12;
    } FW_PACKED;

    struct {
        uint8_t key[EM_SHORT_KEY];
        uint8_t payload[EM_SHORT_PAYLOAD];
    };
};

/// @brief Data for periodic scan registers (32)
/// such as Age and Bulk Update
struct scan_data {
    uint32_t em_core                    :4;
    uint32_t em_index                   :11;
    uint32_t em_bank                    :4;
    uint32_t for_cam                    :1;
    uint32_t padding0                   :12;
};

/// @brief Group request register (160)
struct group_request_data {
    uint8_t key[EM_LONG_KEY];
};

/// @brief Group response register (32)
struct group_response_data {
    uint32_t em_group                   : 8;
    uint32_t em_core                    : 4;
    uint32_t allowed_bank_bitset        : 16;
    uint32_t padding0                   : 4;
} FW_PACKED;

/// @brief EM request register (288)
struct em_request_data {
    struct data_fields {
        // word 7
        uint32_t command                : 4;
        uint32_t age_owner              : 1;
        uint32_t age_value              : 3;
        uint32_t age_valid              : 1;
        uint32_t padding1               : 23;
        // word 8
        uint32_t em_core                : 4;
        uint32_t em_index               : 11;
        uint32_t em_bank_bitset         : 16;
        uint32_t for_cam                : 1;
    } FW_PACKED;

    long_entry_data rec;
    data_fields data;
};

/// @brief EM response register (256)
struct em_response_data {
    struct data_fields {
        // word 7
        uint32_t key_size               : 2;
        uint32_t em_index               : 11;
        uint32_t em_bank                : 4;
        uint32_t match                  : 1;   /// << matching payloads. Irrelevant for CEM
        uint32_t for_cam                : 1;
        uint32_t rule_hit               : 2;   /// < which rule was hit in the rule table (defined in RULE_HIT_COMMANDS)
        uint32_t ecc_err                : 1;
        uint32_t age_value              : 3;
        uint32_t age_owner              : 1;
        uint32_t age_ecc_err            : 1;
        uint32_t hit                    : 1;   /// < command success
        uint32_t padding2               : 4;
    } FW_PACKED;

    long_entry_data rec;
    data_fields data;
};

/// @brief Counter request (64)
union counter_request_data {
    struct {
        // counter can be negative
        int32_t counter_bits            : 20;
        uint32_t padding0               : 12;
        uint32_t addr_bits              : 14;
        uint32_t is_write               : 1;
        uint32_t padding1               : 17;
    } FW_PACKED;

    struct {
        uint32_t counter;
        uint32_t addr;
    };
};

// clang-format on

//*********************************
// AUX UTILITIES
//*********************************

/// @brief Checks if the key is of MAC entry type.
///
/// @param[in]  rec     Key/payload record
bool is_mac_entry(const long_entry_data* rec);

//*********************************
// REGISTER OPERATIONS
//*********************************

/// @brief Read from UAUX register to shadow
///
void read_reg(void* dest, uaux_reg_name_e reg);

/// @brief Write from shadow to a UAUX register
///
void write_reg(uaux_reg_name_e reg, const void* src);

//*********************************
// GLOBAL DATA
//*********************************

/// @brief Global context for EM routines and commands. EM request/response and group_response is widely used in all proceduces.
///
struct routine_context {
    // EM_REQUEST/EM_RESPONSE shadow registers
    em_request_data em_request_reg;
    em_response_data em_response_reg;

    // core, group and allowed banks in the context of current operation
    group_response_data group_data;

    // HW failure to respond to a request.
    // Sticky bit that is cleaned out at the beginning of each new command.
    bool em_request_fail;
};
extern routine_context op_ctx;

#endif //  __CEM_UAUX_REGS_H__
