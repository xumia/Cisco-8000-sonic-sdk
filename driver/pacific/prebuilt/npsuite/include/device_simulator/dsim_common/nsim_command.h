// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __NSIM_COMMAND_H__
#define __NSIM_COMMAND_H__

#ifdef __GNUC__
#define ATTR_UNUSED __attribute__((unused))
#else
#define ATTR_UNUSED
#endif
#include <string.h>
#include "utils/nsim_bv.h"

namespace nsim
{
/// @brief calculates bytes from bits.

/// @brief Command structure used by nsim.
namespace nsim_command
{
// max register field length in bytes
static const int MAX_RAW_DATA_FIELD_LEN_BYTES = 16 * 32;

static size_t calc_bytes_from_bits(size_t bits) ATTR_UNUSED;

static size_t
calc_bytes_from_bits(size_t bits)
{
    return (bits + 7) / 8;
}
typedef uint8_t nsim_command_type;
// table commands
static const nsim_command_type NSIM_COMMAND_TYPE_TABLE_INSERT = 0;
static const nsim_command_type NSIM_COMMAND_TYPE_TABLE_ERASE = 1;
static const nsim_command_type NSIM_COMMAND_TYPE_TABLE_UPDATE = 2;
// lpm table commands
static const nsim_command_type NSIM_COMMAND_TYPE_LPM_TABLE_INSERT = 3;
static const nsim_command_type NSIM_COMMAND_TYPE_LPM_TABLE_ERASE = 4;
static const nsim_command_type NSIM_COMMAND_TYPE_LPM_TABLE_UPDATE = 5;
// ternary table commands
static const nsim_command_type NSIM_COMMAND_TYPE_TERNARY_TABLE_INSERT = 6;
static const nsim_command_type NSIM_COMMAND_TYPE_TERNARY_TABLE_ERASE = 7;
static const nsim_command_type NSIM_COMMAND_TYPE_TERNARY_TABLE_UPDATE = 8;
// error command type
static const nsim_command_type NSIM_COMMAND_TYPE_ERROR = 10;

/// @brief Aggregation of all simulator command fields.
struct command { /// Don't add any complex members - this struct is being copied and processed as raw data
    // size of nsim command

    nsim_command_type cmd_type; ///< NSIM command.
    uint16_t table_id;          ///< NPL table enum.
    uint8_t slice_idx;          ///< Slice index.
    uint16_t key_len;
    uint16_t value_len;
    uint8_t values[MAX_RAW_DATA_FIELD_LEN_BYTES * 3
                   + sizeof(uint32_t)]; // max length of ternary command - max key, value and mask + line

    // C'tors
    command()
    {
        memset(this, 0, sizeof(command));
    }
    // non-trivial constructor to allow creation of parametered command from outside
    command(nsim_command_type _cmd_type,
            uint16_t _table_id,
            uint8_t _slice_idx,
            uint16_t _lpm_key_len,
            uint32_t _line,
            nsim::bit_vector& _key,
            nsim::bit_vector& _val,
            nsim::bit_vector& _mask)
        : command()
    {
        cmd_type = _cmd_type;
        table_id = _table_id;
        slice_idx = _slice_idx;
        key_len = (uint16_t)_key.get_width();
        value_len = (uint16_t)_val.get_width();
        size_t key_len_bytes = _key.get_width_in_bytes();
        size_t val_len_bytes = _val.get_width_in_bytes();
        switch (cmd_type) {
        case NSIM_COMMAND_TYPE_TABLE_INSERT:
        case NSIM_COMMAND_TYPE_TABLE_UPDATE:
            memcpy(values, _key.byte_array(), key_len_bytes);
            memcpy(values + key_len_bytes, _val.byte_array(), val_len_bytes);
            break;
        case NSIM_COMMAND_TYPE_TABLE_ERASE:
            memcpy(values, _key.byte_array(), key_len_bytes);
            break;
        case NSIM_COMMAND_TYPE_LPM_TABLE_INSERT:
        case NSIM_COMMAND_TYPE_LPM_TABLE_UPDATE:
            memcpy(values, _key.byte_array(), key_len_bytes);
            memcpy(values + key_len_bytes, _val.byte_array(), val_len_bytes);
            memcpy(values + key_len_bytes + val_len_bytes, &_lpm_key_len, sizeof(_lpm_key_len));
            break;
        case NSIM_COMMAND_TYPE_LPM_TABLE_ERASE:
            memcpy(values, _key.byte_array(), key_len_bytes);
            memcpy(values + key_len_bytes, &_lpm_key_len, sizeof(_lpm_key_len));
            break;
        case NSIM_COMMAND_TYPE_TERNARY_TABLE_INSERT:
            memcpy(values, _key.byte_array(), key_len_bytes);
            memcpy(values + key_len_bytes, _val.byte_array(), val_len_bytes);
            memcpy(values + key_len_bytes + val_len_bytes, _mask.byte_array(), key_len_bytes); // copy mask
            memcpy(values + 2 * key_len_bytes + val_len_bytes, &_line, sizeof(_line));         // copy line
            break;
        case NSIM_COMMAND_TYPE_TERNARY_TABLE_ERASE:
            memcpy(values, &_line, sizeof(_line)); // copy line
            break;
        case NSIM_COMMAND_TYPE_TERNARY_TABLE_UPDATE:
            memcpy(values, _val.byte_array(), val_len_bytes);
            memcpy(values + val_len_bytes, &_line, sizeof(_line)); // copy line
            break;
        default:
            memset(this, 0, sizeof(command)); // unknown command
        }
    }
};

} // namespace nsim_command
} // namespace nsim

size_t calculate_command_len(const nsim::nsim_command::command& cmd);

#endif // __NSIM_COMMAND_H__
