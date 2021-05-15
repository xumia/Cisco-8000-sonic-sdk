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

#include "npl_tables_compiler_generated_config_types.h"

silicon_one::table_compiler_generated_config_t::table_compiler_generated_config_t()
    : is_internal(false), is_exact_match(false), has_default_action(false)
{
}

silicon_one::single_table_compiler_generated_config_t::single_table_compiler_generated_config_t(uint16_t key_size,
                                                                                                             uint16_t payload_size)
    : payload_width_in_bits(payload_size), key_width_in_bits(key_size), default_action(key_size, payload_size)
{
}

silicon_one::ternary_table_compiler_generated_config_t::ternary_table_compiler_generated_config_t()
    : is_internal(false), is_traps_table(false), has_default_action(false)
{
}

silicon_one::single_ternary_table_compiler_generated_config_t::single_ternary_table_compiler_generated_config_t(
    uint16_t key_size,
    uint16_t payload_size)
    : payload_width_in_bits(payload_size), key_width_in_bits(key_size), default_action(key_size, payload_size)
{
}
