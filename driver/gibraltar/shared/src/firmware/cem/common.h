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

#ifndef __CEM_COMMON_H__
#define __CEM_COMMON_H__

/// @file
/// @brief Common definition for CEM formware
///

// for uint / int typedefs
#include <inttypes.h>

#define FW_PACKED __attribute__((__aligned_packed__));

typedef _Uncached void* uncached_ptr_t;

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#endif

// clang-format off
/// @brief Interrupts
enum irq_vector_e {
  IRQ_MEM_RESET      = 0,
  IRQ_MEM_ERROR      = 1,
  IRQ_INSTR_ERROR    = 2,
  IRQ_SWI            = 8,
  IRQ_TIMER0         = 16,
  IRQ_EXT_17         = 17,
  IRQ_EXT_18         = 18,
  IRQ_EXT_19         = 19,
  IRQ_EXT_20         = 20,
  IRQ_EXT_21         = 21,
  IRQ_SW_22          = 22,
  IRQ_SW_23          = 23,
  IRQ_SW_24          = 24
};
// clang-format on

/// @brief Initial age values according to Exact Match spec.docx. Age field is 3 bits wide.
///
enum {
    EM_NEW_MAX_AGE = 7,                   ///< Max age for new record from owner device
    EM_NO_AGING_AGE = EM_NEW_MAX_AGE - 1, ///< No-aging value static records coming from CPU
    EM_REFRESH_AGE = EM_NEW_MAX_AGE - 2,  ///< Refresh age - next value after MAX_AGE
    EM_TRANSACTION_RETRY_MAX = 1000,
    EM_TRANSACTION_WAIT_RESPONSE_MAX = 1000,
    EM_TRANSACTION_AGE_ECC_ERROR_RETRY_MAX = 1000,
    ARC_AGE_CHECK_RETRY_MAX = 100,
    EM_CHECK_RECORD_AGE_VALUE = 0xff,
};

// The max depth of entry relocation
static const uint32_t EM_FFE_SEARCH_DEPTH = 2;

// Double entry relocation depth
static const uint32_t EM_DBL_ENTRY_RELOCATION_DEPTH = 5;

// Key size option for learn commands
static const uint32_t EM_NO_KEY_SIZE = (uint32_t)-1;
static const uint32_t EM_LEARN_KEY_SIZE = 1;
static const uint32_t EM_WIDE_KEY_SIZE = 0;

// Illegal value
static const int32_t EM_NONE = -1;

// Entries in core's CAM
static const uint32_t EM_ENTRIES_IN_CAM = 32;

typedef uint64_t em_bank_bitmap_t;

// Per project configs

#ifdef GIBRALTAR

// Entries per one bank in core
static const uint32_t EM_ENTRIES_IN_BANK = 1 << 11;
static const uint32_t EM_BITS_TO_REPRESENT_BANK_ENTRY = 11;

// Banks in core
static const uint32_t EM_BANKS_IN_CORE = 28;
static const uint32_t EM_BITS_TO_REPRESENT_BANK = 5;

// Number of cores in CEM
static const uint32_t EM_CORES_IN_CEM = 16;
static const uint32_t EM_BITS_TO_REPRESENT_CORE = 4;

static const uint32_t EVEN_BANKS = 0x5555555;
static const uint32_t ODD_BANKS = 0xaaaaaaa;
static const uint32_t DOUBLE_ENTRY_EVEN_BANKS = 0x5555400;

static const uint32_t LAST_CORE_PERIODIC_COUNTER = 0x1FFFF;

/// @brief Workaround for GB errata 3.1.10
///
/// Before the ARC can send a request to the CEM cores it send a request to the CEM management module to figure out to which core
/// the key is assigned to, and which banks are active in it. The management returns to the ARC the following data: {active banks
/// (28b), target EM core (4b), EM group (8 bit)}. The bottom 32 bits in the response are written to register 18 of the
/// management/arc interface. The top 8 bits of the response should be written to register 19. Due to this erratum the top 8 bits
/// are not written to register 19. This means that the ARC cannot tell whether the top 8 banks of the target CEM are active or
/// not.
///
/// Workaround:
/// iF the CEM always gets more than 8 banks the arc just can assume the missing bits to be ones. When sharing SRAM between
/// the LPM and CEM, the assignment of SRAMS to the CEM starts from SRAM 27 and downwards. If 8 SRAMS are assigned to the CEM they
/// must be SRAMS 20-27 which correspond to the faulty bits.
#define WORKAROUND_ENABLE_CLEARED_CEM_BANKS 0x0FF00000

#endif

#ifdef PACIFIC

// Entries per one bank in core
static const uint32_t EM_ENTRIES_IN_BANK = 1 << 11;
static const uint32_t EM_BITS_TO_REPRESENT_BANK_ENTRY = 11;

// Banks in core
static const uint32_t EM_BANKS_IN_CORE = 16;
static const uint32_t EM_BITS_TO_REPRESENT_BANK = 4;

// Number of cores in CEM
static const uint32_t EM_CORES_IN_CEM = 16;
static const uint32_t EM_BITS_TO_REPRESENT_CORE = 4;

static const uint16_t EVEN_BANKS = 0x5555;
static const uint16_t ODD_BANKS = 0xaaaa;
static const uint16_t DOUBLE_ENTRY_EVEN_BANKS = 0x5500;

#endif

#ifdef ASIC3

// Entries per one bank in core
static const uint32_t EM_ENTRIES_IN_BANK = 1 << 11;
static const uint32_t EM_BITS_TO_REPRESENT_BANK_ENTRY = 11;

// Banks in core
static const uint32_t EM_BANKS_IN_CORE = 16;
static const uint32_t EM_BITS_TO_REPRESENT_BANK = 4;

// Number of cores in CEM
static const uint32_t EM_CORES_IN_CEM = 12;
static const uint32_t EM_BITS_TO_REPRESENT_CORE = 4;

static const uint16_t EVEN_BANKS = 0x5555;
static const uint16_t ODD_BANKS = 0xaaaa;
static const uint16_t DOUBLE_ENTRY_EVEN_BANKS = 0x5500;

#endif

#ifdef ASIC4

// Entries per one bank in core
static const uint32_t EM_ENTRIES_IN_BANK = 1 << 11;
static const uint32_t EM_BITS_TO_REPRESENT_BANK_ENTRY = 11;

// Banks in core
static const uint32_t EM_BANKS_IN_CORE = 28;
static const uint32_t EM_BITS_TO_REPRESENT_BANK = 5;

// Number of cores in CEM
static const uint32_t EM_CORES_IN_CEM = 16;
static const uint32_t EM_BITS_TO_REPRESENT_CORE = 4;

static const uint32_t EVEN_BANKS = 0x5555555;
static const uint32_t ODD_BANKS = 0xaaaaaaa;
static const uint32_t DOUBLE_ENTRY_EVEN_BANKS = 0x5555400;

static const uint32_t LAST_CORE_PERIODIC_COUNTER = 0x1FFFF;

#endif

#ifdef ASIC5

// Entries per one bank in core
static const uint32_t EM_ENTRIES_IN_BANK = 1 << 15;
static const uint32_t EM_BITS_TO_REPRESENT_BANK_ENTRY = 15;

// Banks in core
static const uint32_t EM_BANKS_IN_CORE = 8;
static const uint32_t EM_BITS_TO_REPRESENT_BANK = 3;

// Number of cores in CEM
static const uint32_t EM_CORES_IN_CEM = 1;
static const uint32_t EM_BITS_TO_REPRESENT_CORE = 1;

static const uint32_t EVEN_BANKS = 0x55; // even banks bitset = 0b01010101
static const uint32_t ODD_BANKS = 0xaa;
static const uint32_t DOUBLE_ENTRY_EVEN_BANKS = EVEN_BANKS;

#endif
/// @brief Exact match entry kind. EM bank entry/index occupancy state.
///
enum em_entry_location_type {
    EM_EMPTY_ENTRY = 0,
    EM_SINGLE_ENTRY_EVEN_BANK,
    EM_SINGLE_ENTRY_ODD_BANK,
    EM_SINGLE_ENTRY_BOTH_BANKS,
    EM_DOUBLE_ENTRY
};

static const uint32_t EM_EVACUATION_BANK = EM_BANKS_IN_CORE - 2;

#endif // __CEM_COMMON_H__
