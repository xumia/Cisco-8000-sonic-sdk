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

#ifndef __CEM_STATUS_REG_H__
#define __CEM_STATUS_REG_H__

#include "inttypes.h"
#include "uaux_regs.h"

// clang-format off
/// @brief Status register encoding
///
enum uaux_reg_status_e {
    UAUX_REG_STATUS_LEARN                   = 1 << 0,       ///< In: Learn request
    UAUX_REG_STATUS_LEARN_DONE              = 1 << 1,       ///< Out: Learn request is done
    UAUX_REG_STATUS_REFRESH                 = 1 << 2,       ///< Out: Refresh request for NPU
    UAUX_REG_STATUS_EM_REQUEST              = 1 << 3,       ///< Out: Request to perform EM query (add, delete, ffe, lookup etc)
    UAUX_REG_STATUS_EM_RESPONSE             = 1 << 4,       ///< In: Response to EM query
    UAUX_REG_STATUS_AGE_HW                  = 1 << 5,       ///< Periodic Age Update in flight (HW - not in use)
    UAUX_REG_STATUS_RESERVED0               = 1 << 6,       ///< Reserved - [was Age Done]
    UAUX_REG_STATUS_BULK                    = 1 << 7,       ///< Internal: Periodic Bulk Update in flight
    UAUX_REG_STATUS_RESERVED1               = 1 << 8,       ///< Reserved - [was Bulk Update Done]
    UAUX_REG_STATUS_COUNTERS_REQUEST        = 1 << 9,       ///< Out: Fetching Counter data
    UAUX_REG_STATUS_COUNTERS_RESPONSE       = 1 << 10,      ///< In: Restonse to Counter query
    UAUX_REG_STATUS_LOAD_BALANCE            = 1 << 11,      ///< Internal: Load Balancing in flight
    UAUX_REG_STATUS_GROUP_REQUEST           = 1 << 12,      ///< Out: Request to get core, group for a key
    UAUX_REG_STATUS_GROUP_RESPONSE          = 1 << 13,      ///< In: Response to Group query
    UAUX_REG_STATUS_CPU_CMD                 = 1 << 14,      ///< CPU interaction
    UAUX_REG_STATUS_CPU_INT                 = 1 << 15,      ///< Out: Raise CPU interrupt
    UAUX_REG_STATUS_ARC_INIT                = 1 << 16,      ///< In: Arc init stage is ongoing
    UAUX_REG_STATUS_AGE                     = 1 << 17,       ///< Periodic Age Update in flight

    // Interternally used bits
    UAUX_REG_STATUS_INTERNAL = \
                UAUX_REG_STATUS_AGE | \
                UAUX_REG_STATUS_BULK | \
                UAUX_REG_STATUS_LOAD_BALANCE,

    // Input: commands for ARC routines
    UAUX_REG_STATUS_COMMAND = \
                UAUX_REG_STATUS_LEARN | \
                UAUX_REG_STATUS_AGE | \
                UAUX_REG_STATUS_BULK | \
                UAUX_REG_STATUS_LOAD_BALANCE | \
                UAUX_REG_STATUS_CPU_CMD,

    // Input: responses for CEM queries
    UAUX_REG_STATUS_RESPONSE = \
                UAUX_REG_STATUS_EM_RESPONSE | \
                UAUX_REG_STATUS_GROUP_RESPONSE | \
                UAUX_REG_STATUS_COUNTERS_RESPONSE,

    // Output: Requests for CEM queries
    UAUX_REG_STATUS_REQUEST = \
                UAUX_REG_STATUS_EM_REQUEST | \
                UAUX_REG_STATUS_GROUP_REQUEST | \
                UAUX_REG_STATUS_COUNTERS_REQUEST,

    // Output: Done for ARC routines
    UAUX_REG_STATUS_DONE = \
                UAUX_REG_STATUS_LEARN_DONE,

    // Default mask for Status Mask Register
    // Status mask register defines which status bits are
    // going to be udpated by ARC, it order to prevent an update to
    // the input bits of the status register. By default, these are
    // all the Output bits (Requests + Done) + all the Responses.
    UAUX_REG_STATUS_DEFAULT_MASK = \
                UAUX_REG_STATUS_DONE | \
                UAUX_REG_STATUS_REQUEST | \
                UAUX_REG_STATUS_RESPONSE,
};

/// @brief The shadow copy of UAUX status register. Global to avoid read-write operations.
/// STATUS register (32)
// Shadow structure
union status_reg_data {
    // for debug purposes
    struct bit_array {
        uint32_t learn                   :1;
        uint32_t learn_done              :1;
        uint32_t refresh                 :1;
        uint32_t em_request              :1;
        uint32_t em_response             :1;
        uint32_t age                     :1;
        uint32_t reserved0               :1;
        uint32_t bulk                    :1;
        uint32_t reserved1               :1;
        uint32_t counter_request         :1;
        uint32_t counter_response        :1;
        uint32_t load_balance            :1;
        uint32_t group_request           :1;
        uint32_t group_response          :1;
    } FW_PACKED;
    bit_array bits;
    uint32_t val;
};
// clang-format on
extern status_reg_data status_reg;

///////////////////////////////////
// Status register operations
///////////////////////////////////

/// @brief Custom implementation of read/write operations for UAUX status register to make them faster
void status_reg_read();
void status_reg_write();
void read_cpu_status_reg(void* status);
void write_cpu_status_reg(const void* status);

/// @brief sets and writes the mask for UAUX status register.
/// Mask is needed to prevent update on input bits of the status
/// register. On update, only bits that has 1-mask are written
/// to HW.
///
/// @param[in]  ptrn        bitmask. 1 means that bit is going to be updated
///
void status_reg_set_mask(uint32_t mask);

/// @brief Set on status register.
/// The data is not written to UAUX register
///
static inline void
status_reg_set(uint32_t ptrn)
{
    status_reg.val |= ptrn;
}

/// @brief Clear on status register.
/// The data is not written to UAUX register
///
static inline void
status_reg_clear(uint32_t ptrn)
{
    status_reg.val &= ~ptrn;
}

/// @brief Test on status register.
///
static inline uint32_t
status_reg_test(uint32_t ptrn)
{
    return status_reg.val & ptrn;
}

#endif // __CEM_STATUS_REG_H__
