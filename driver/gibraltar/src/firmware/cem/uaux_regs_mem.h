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

#ifndef __CEM_UAUX_REGS_MEM_H__
#define __CEM_UAUX_REGS_MEM_H__

/// @file
/// @brief Memory layout of UAUX registers

#include "common.h"

// ********************************
// UAUX REGISTERS MEMORY MAPPING
// ********************************

/// @brief Defines the addresses and sizes of all UAUX
/// registers.
///
// clang-format off
enum {
    LEARN_REG_OFFSET                    =                                0,
    REFRESH_REG_OFFSET                  = LEARN_REG_OFFSET             + 4,
    AGING_REG_OFFSET                    = REFRESH_REG_OFFSET           + 4,
    BULK_UDATE_REG_OFFSET               = AGING_REG_OFFSET             + 1,
    COUNTERS_REQUEST_REG_OFFSET         = BULK_UDATE_REG_OFFSET        + 1,
    COUNTERS_RESPONSE_REG_OFFSET        = COUNTERS_REQUEST_REG_OFFSET  + 2,
    GROUP_REQUEST_REG_OFFSET            = COUNTERS_RESPONSE_REG_OFFSET + 1,
    GROUP_RESPONSE_REG_OFFSET           = GROUP_REQUEST_REG_OFFSET     + 5,
    EM_REQUEST_REG_OFFSET               = GROUP_RESPONSE_REG_OFFSET    + 2,
    EM_RESPONSE_REG_OFFSET              = EM_REQUEST_REG_OFFSET        + 10,
    CPU_REG_OFFSET                      = EM_RESPONSE_REG_OFFSET       + 8,
    STATUS_REG_OFFSET                   = CPU_REG_OFFSET               + 9,
    STATUS_MASK_REG_OFFSET              = STATUS_REG_OFFSET            + 1,
    TOTAL_REG_OFFSET                    = STATUS_MASK_REG_OFFSET       + 1
};

#ifdef TEST_MODE
// in test mode, map the addresses to DCCM
extern uint8_t test_uaux_regs[];
static const uint32_t BASE_REG_ADDR          = (uint32_t)test_uaux_regs;
#else
static const uint32_t BASE_REG_ADDR          = 0x8000_0000;
#endif

// clang-format on
static const uint32_t REG_ADDR_ARRAY[UAUX_REG_NUM + 1] = {LEARN_REG_OFFSET,
                                                          REFRESH_REG_OFFSET,
                                                          AGING_REG_OFFSET,
                                                          BULK_UDATE_REG_OFFSET,
                                                          COUNTERS_REQUEST_REG_OFFSET,
                                                          COUNTERS_RESPONSE_REG_OFFSET,
                                                          GROUP_REQUEST_REG_OFFSET,
                                                          GROUP_RESPONSE_REG_OFFSET,
                                                          EM_REQUEST_REG_OFFSET,
                                                          EM_RESPONSE_REG_OFFSET,
                                                          CPU_REG_OFFSET,
                                                          STATUS_REG_OFFSET,
                                                          STATUS_MASK_REG_OFFSET,
                                                          TOTAL_REG_OFFSET};

// ARC memory alingment
static const uint32_t MEM_ALIGN = sizeof(uint32_t);

/// @brief Returns the address of UAUX register
///
static inline uint32_t
reg_addr(uaux_reg_name_e reg)
{
#ifdef TEST_MODE
    return BASE_REG_ADDR + MEM_ALIGN * REG_ADDR_ARRAY[reg];
#else
    return BASE_REG_ADDR + REG_ADDR_ARRAY[reg];
#endif
}

/// @brief Returns the size in dwords of UAUX register
///
static inline uint32_t
reg_size(uaux_reg_name_e reg)
{
    return REG_ADDR_ARRAY[reg + 1] - REG_ADDR_ARRAY[reg];
}

#endif //  __CEM_UAUX_REGS_MEM_H__
