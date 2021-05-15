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

#ifndef __FIRMWARE_SCREENING_H__
#define __FIRMWARE_SCREENING_H__

#include <inttypes.h>

#ifdef SCREENING_DEBUG

enum DEBUG_LEVEL { DEBUG_LEVEL_ERROR = 0, DEBUG_LEVEL_INFO = 1, DEBUG_LEVEL_VERBOSE = 2 };
extern int scr_debug_level;
#define LOG_LEVEL(level, format, ...)                                                                                              \
    do {                                                                                                                           \
        if (level >= scr_debug_level) {                                                                                            \
            printf(format, ##__VA_ARGS__);                                                                                         \
        }                                                                                                                          \
    } while (0)

#define LOG_E(format, ...) LOG_LEVEL(DEBUG_LEVEL_ERROR, format, ##__VA_ARGS__)
#define LOG_I(format, ...) LOG_LEVEL(DEBUG_LEVEL_INFO, format, ##__VA_ARGS__)
#define LOG_D(format, ...) LOG_LEVEL(DEBUG_LEVEL_VERBOSE, format, ##__VA_ARGS__)

#else

#define LOG_E(...)
#define LOG_I(...)
#define LOG_D(...)

#endif

enum exec_cmd {
    CMD_NONE = 0,
    CMD_WRITE_REG,
    CMD_WRITE_MEM,
    CMD_CHECK_REG,
    CMD_CHECK_MEM,
};

// Maximum width of register or memory entry
enum max_val_size {
    MAX_VAL_BITS = 0x1000,
    MAX_VAL_BYTES = MAX_VAL_BITS >> 3,
    MAX_VAL_DWORDS = MAX_VAL_BITS >> 5,
};

typedef struct __attribute__((packed)) {
    uint32_t cmd;
    uint16_t block_id;
    uint32_t addr;
    uint16_t width_bytes;
} cmd_header_t;

// screening error codes
typedef enum {
    ERR_OK = 0,
    ERR_STORAGE = 1,
    ERR_ACCESS_ENGINE = 1,
    ERR_RW_MISMATCH = 3,
} scr_error_t;

// SBIF addresses and sizes
enum sbif_addresses_and_sizes {
    SBIF_ACC_ENG_DATA_MEM = (1 << 24) | 0x3F00,
    SBIF_ACC_ENG_DATA_MEM_ENTRIES = 512,

    SBIF_ACC_ENG_CMD_MEM = (1 << 24) | 0x7F00,
    SBIF_ACC_ENG_CMD_MEM_ENTRIES = 512,

    SBIF_ACC_ENG_RESET_REG = (1 << 24) | 0x0150,
    SBIF_ACC_ENG_GO_REG = (1 << 24) | 0x0170,
    SBIF_ACC_ENG_CMD_PTR_REG = (1 << 24) | 0x0190,
    SBIF_ACC_ENG_STATUS_REG = (1 << 24) | 0x01B0,

    SBIF_SPI_CTRL_CFG_REG = (1 << 24) | 0x065C,
    SBIF_SPI_CTRL_ADDR_REG = (1 << 24) | 0x0660,
    SBIF_SPI_CTRL_DATA_REG_0 = (1 << 24) | 0x0664, // 0th instance, there are 16 instances in total
    SBIF_SPI_CTRL_EXEC_REG = (1 << 24) | 0x06A4,

    SBIF_LED_INTERFACE_CFG_REG = (1 << 24) | 0x0608,
    SBIF_LED_INTERFACE_DATA_REG = (1 << 24) | 0x06AC,

    CSS_MEM_TEST_ADDR = 0x8000,
};

// Platform-specific operations, implemented in main_xxx
struct platform_ops {
    // Storage for commands - file or flash
    void storage_rewind(uint32_t base_addr);
    int storage_read_dwords(uint32_t dwords_n, uint32_t* dwords);

    // SBIF interface
    int sbif_write_dword(uint32_t addr, uint32_t dword);
    int sbif_write_dwords(uint32_t addr, uint32_t dwords_n, const uint32_t* dwords);
    int sbif_read_dword(uint32_t addr, uint32_t* dword);
    int sbif_read_dwords(uint32_t addr, uint32_t dwords_n, uint32_t* dwords);

    // Used in polling loops
    void yield();
};

extern platform_ops ops;

// Read commands from storage (file or flash) and optionally execute
scr_error_t scr_read_from_storage_and_exec(uint32_t storage_base, int is_exec);

#endif
