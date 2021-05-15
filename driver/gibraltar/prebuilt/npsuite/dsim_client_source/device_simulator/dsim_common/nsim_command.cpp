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

#include <string.h>
#include "device_simulator/dsim_common/nsim_command.h"

size_t
calculate_command_len(const nsim::nsim_command::command& cmd)
{
    size_t len = sizeof(nsim::nsim_command::command) - sizeof(cmd.values);
    size_t key_len_bytes = nsim::nsim_command::calc_bytes_from_bits(cmd.key_len);
    size_t value_len_bytes = nsim::nsim_command::calc_bytes_from_bits(cmd.value_len);
    switch (cmd.cmd_type) {
    case nsim::nsim_command::NSIM_COMMAND_TYPE_TABLE_INSERT:
    case nsim::nsim_command::NSIM_COMMAND_TYPE_TABLE_UPDATE:
        len += (key_len_bytes + value_len_bytes);
        break;
    case nsim::nsim_command::NSIM_COMMAND_TYPE_TABLE_ERASE:
        len += (key_len_bytes);
        break;
    case nsim::nsim_command::NSIM_COMMAND_TYPE_LPM_TABLE_INSERT:
    case nsim::nsim_command::NSIM_COMMAND_TYPE_LPM_TABLE_UPDATE:
        len += (key_len_bytes + value_len_bytes + sizeof(uint16_t));
        break;
    case nsim::nsim_command::NSIM_COMMAND_TYPE_LPM_TABLE_ERASE:
        len += (key_len_bytes + sizeof(uint16_t));
        break;
    case nsim::nsim_command::NSIM_COMMAND_TYPE_TERNARY_TABLE_INSERT:
        len += (key_len_bytes * 2 + value_len_bytes + sizeof(uint32_t));
        break;
    case nsim::nsim_command::NSIM_COMMAND_TYPE_TERNARY_TABLE_ERASE:
        len += sizeof(uint32_t);
        break;
    case nsim::nsim_command::NSIM_COMMAND_TYPE_TERNARY_TABLE_UPDATE:
        len += (value_len_bytes + sizeof(uint32_t));
        break;
    default:
        return -1;
    }
    return len;
}
