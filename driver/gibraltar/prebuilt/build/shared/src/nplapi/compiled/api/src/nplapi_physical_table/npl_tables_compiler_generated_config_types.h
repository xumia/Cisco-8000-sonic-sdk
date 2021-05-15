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

#ifndef __NPL_TABLES_COMPILER_GENERATED_CONFIG_TYPES_H__
#define __NPL_TABLES_COMPILER_GENERATED_CONFIG_TYPES_H__

#include <stdint.h>
#include <vector>
#include "nplapi_physical_table/database_enum.h"
#include "nplapi_translator/npl_generic_data_structs.h" // TODO remove this dependency

namespace silicon_one
{

struct internal_table_config_t {
    uint16_t index; // in sram it's sram index, in reg-tcam sram it's reg tcam index in level
    uint32_t start_line;
    uint16_t offset_in_line;
    uint16_t width_in_bits;
    bool payload_needs_rmw_operation;
    bool msb_aligned;
};

struct internal_ternary_table_config_t {
    uint16_t index_in_level; // releveant only for reg-tcam
    uint32_t start_line;
    uint16_t width_in_bits;
    bool is_reverse_order;
};

struct single_table_compiler_generated_config_t {
    single_table_compiler_generated_config_t(uint16_t key_size, uint16_t payload_size);

    uint16_t payload_width_in_bits;
    uint16_t key_width_in_bits;
    uint32_t database_id;
    bool is_ene_table;
    databases_e database;

    table_generic_entry_t default_action;

    // all the following are valid only when is_internal == true
    uint32_t table_size;
    internal_table_config_t sram_config;
};

struct table_compiler_generated_config_t {

    table_compiler_generated_config_t();

    bool is_internal;
    bool is_exact_match;
    bool has_default_action;

    std::vector<single_table_compiler_generated_config_t> tables_config;
};

struct single_ternary_table_compiler_generated_config_t {

    single_ternary_table_compiler_generated_config_t(uint16_t key_size, uint16_t payload_size);

    uint16_t payload_width_in_bits;
    uint16_t key_width_in_bits;
    uint32_t database_id;
    databases_e database;

    ternary_table_generic_entry_t default_action;

    // all the following are valid only when is_internal == true
    uint32_t table_size;
    bool is_reg_tcam;
    uint16_t level_in_engine; // releveant only for reg-tcam
    internal_ternary_table_config_t tcam_config;
    internal_table_config_t sram_config;
};

struct ternary_table_compiler_generated_config_t {

    ternary_table_compiler_generated_config_t();

    bool is_internal;
    bool is_traps_table;
    bool has_default_action;
    std::vector<single_ternary_table_compiler_generated_config_t> tables_config;
};
}

#endif
