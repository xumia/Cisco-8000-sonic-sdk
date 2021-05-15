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

#ifndef __SIM_COMMAND_H__
#define __SIM_COMMAND_H__

#include "api/types/la_common_types.h"
#include <string.h>

namespace silicon_one
{

/// @brief Command structures used by Simulators.
namespace sim_command
{
// max register field length in bytes
static const int LONG_FIELD_LEN = 512;

enum class nsim_command_e {
    // table commands
    TABLE_INSERT = 1 << 0,
    TABLE_ERASE = 1 << 1,
    TABLE_UPDATE = 1 << 2,
    // lpm table commands
    LPM_TABLE_INSERT = 1 << 3,
    LPM_TABLE_ERASE = 1 << 4,
    LPM_TABLE_UPDATE = 1 << 5,
    // ternary table commands
    TERNARY_TABLE_INSERT = 1 << 6,
    TERNARY_TABLE_ERASE = 1 << 7,
    TERNARY_TABLE_UPDATE = 1 << 8
};

union reg_data {
    struct long_cmd_s {
        size_t width;
        uint8_t value;
    } long_cmd;

    uint8_t flat[LONG_FIELD_LEN + sizeof(size_t)];
};

/// @brief Aggregation of all simulator command fields.
struct command {
    nsim_command_e cmd; ///< NSIM command.
    size_t table_id;    ///< NPL table enum.
    size_t slice_idx;   ///< Slice index.
    size_t key_len;     ///< Key length for LPM commands.
    size_t line;        ///< Table line for ternary commands.
    reg_data key;       ///< Table key.
    reg_data value;     ///< Table value.
    reg_data key_mask;  ///< Key mask for ternary commands.

    // C'tors
    command()
    {
        memset(this, 0, sizeof(command));
    }
};

/// @brief Data structure to communicate #silicon_one::nsim_device_simulator commands via socket
struct socket_command {
    // max length for reading status request.
    static constexpr size_t MAX_STATUS_LEN = 256;

    // size of status request
    static constexpr size_t STATUS_LEN = sizeof(size_t);

    // size of nsim command
    static constexpr size_t COMMAND_LEN = sizeof(command);

    // Available commands
    enum class command_e { WRITE_MEMORY, READ_MEMORY, WRITE_REGISTER, READ_REGISTER };

    command_e cmd;               ///< Command code.
    la_block_id_t block_id;      ///< Target block ID.
    la_entry_addr_t address;     ///< Register/Memory address within the block.
    la_entry_width_t addr_width; ///< Width of the register/memory line.
    size_t entries;              ///< Number of entries.
    uint8_t buff[COMMAND_LEN];   ///< Data buffer.

    // C'tors
    socket_command()
    {
        memset(this, 0, sizeof(socket_command));
    }

    // The socket_command is passed to another process using the write() call.
    //
    // Due to struct alignment issues, some padding exists in this class, and remains uninitialized during construction.
    // Valgrind identifies this as uninitialized and emits an error.
    //
    // Reset the entire struct to make sure this error is suppressed.

    socket_command(command_e _cmd,
                   la_block_id_t _block_id,
                   la_entry_addr_t _address,
                   la_entry_width_t _addr_width,
                   size_t _entries,
                   const void* val)
        : socket_command()
    {
        cmd = _cmd;
        block_id = _block_id;
        address = _address;
        addr_width = _addr_width;
        entries = _entries;

        if (cmd == command_e::WRITE_MEMORY || cmd == command_e::WRITE_REGISTER) {
            memcpy(buff, val, _entries * _addr_width);
        }
    }
};

} // namespace sim_command

} // namespace silicon_one

#endif // __SIM_COMMAND_H__
