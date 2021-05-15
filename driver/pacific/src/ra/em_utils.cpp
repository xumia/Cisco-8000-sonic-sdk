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

#include "em_utils.h"

#include <algorithm>

namespace silicon_one
{

size_t
em_utils::get_primary_key_width(database_e db)
{
    std::vector<size_t> options = get_key_width_options(db);
    return (options.empty()) ? 0 : options[0];
}

size_t
em_utils::get_key_width(database_e db, size_t table_key_width, size_t table_payload_width)
{
    std::vector<size_t> options = get_key_width_options(db);
    size_t idx = get_key_width_idx(db, table_key_width, table_payload_width);

    return options[idx];
}

size_t
em_utils::get_payload_width(database_e db, size_t table_key_width, size_t table_payload_width)
{
    std::vector<size_t> options = get_key_width_options(db);
    size_t idx = get_key_width_idx(db, table_key_width, table_payload_width);

    if (db == DATABASE_CENTRAL_EM && idx == 0) {
        // This is primary key of central EM, means that
        // the key is wide and the entry takes 2 EM banks.
        // In this case, the payload is 64 bit.
        return 64;
    }

    size_t entry_width = get_entry_width(db);
    return (entry_width > options[idx]) ? entry_width - options[idx] : 0;
}

size_t
em_utils::get_key_width_idx(database_e db, size_t table_key_width, size_t table_payload_width)
{
    std::vector<size_t> options = get_key_width_options(db);

    // The keys are ordered from largest to smallest.
    // Going backward will find the smallest key that fits.
    for (int i = options.size() - 1; i >= 0; --i) {
        if (options[i] < table_key_width) {
            continue;
        }

        if (db == DATABASE_CENTRAL_EM && (options[i] + table_payload_width) > get_entry_width(db)) {
            // Use 2-bank entry
            return 0;
        }

        return (size_t)i;
    }
    return 0;
}

size_t
em_utils::get_line_config_idx(database_e db, size_t table_key_width, size_t table_payload_width)
{
    return get_key_width_idx(db, table_key_width, table_payload_width);
}

size_t
em_utils::get_num_keys(database_e db)
{
    std::vector<size_t> options = get_key_width_options(db);
    return options.size();
}

size_t
em_utils::get_entry_width(database_e db)
{
    switch (db) {
    case DATABASE_EGRESS_SMALL_EM:
        return 146;
    case DATABASE_MAC_SERVICE_MAPPING_0_EM:
    case DATABASE_MAC_SERVICE_MAPPING_1_EM:
        return 82;
    case DATABASE_TUNNEL_0_EM:
    case DATABASE_TUNNEL_1_EM:
        return 209;
    case DATABASE_EGRESS_LARGE_EM:
        return 146;
    case DATABASE_EGRESS_L3_DLP0_EM:
        return 158;
    case DATABASE_MAC_TERMINATION_EM:
        return 161;
    case DATABASE_RESOLUTION_NATIVE_LB_EM:
        return 79;
    case DATABASE_RESOLUTION_PATH_LB_EM:
        return 59;
    case DATABASE_RESOLUTION_PORT_DSPA_EM:
        return 45;
    case DATABASE_CENTRAL_EM:
        // Entry width is relevant only for single bank entry. For two bank entry this number is irrelevant:
        // 1. There are no multiple key sizes for two bank entries.
        // 2. Key + payload do not sum up to 2*entry_width.
        return 110;
    case DATABASE_TM_MC_EM:
        return 104;
    case DATABASE_RESOLUTION_PORT_NPP_LB_EM:
        return 70;
    case DATABASE_NPUH_ETH_MP_EM:
        return 90;
    default:
        dassert_crit(false);
    }

    return 0;
}

size_t
em_utils::get_per_em_register_width(size_t num_of_keys)
{
    size_t key_option_field_width = get_key_option_register_field_width(num_of_keys);

    return MAX_TABLES_PER_EM * key_option_field_width + AUTO_BUBBLE_REG_FIELD_WIDTH + BUBBLE_THRESHOLD_REG_FIELD_WIDTH;
}

size_t
em_utils::get_key_option_register_field_width(size_t num_of_keys)
{
    dassert_crit(num_of_keys);
    return bit_utils::bits_to_represent(num_of_keys - 1);
}

bool
em_utils::is_flexible_entry_supported(database_e db)
{
    return false;
}

std::vector<std::pair<size_t, size_t> >
em_utils::get_em_line_config_options(database_e db)
{
    // NOT IMPLEMENTED
    return std::vector<std::pair<size_t, size_t> >();
}

void
em_utils::add_table_to_per_em_reg(size_t table_logical_id,
                                  size_t table_logical_id_width,
                                  size_t em_keys_num,
                                  size_t key_width_option,
                                  bit_vector& per_em_reg)
{
    // Logical ID might be wider than max width.
    // In these cases, mask out the MSB-s.
    table_logical_id_width = std::min(table_logical_id_width, (size_t)MAX_LOGICAL_ID_WIDTH);
    table_logical_id = table_logical_id % MAX_TABLES_PER_EM;

    size_t key_size_field_width = get_key_option_register_field_width(em_keys_num);

    size_t missing_msb = MAX_LOGICAL_ID_WIDTH - table_logical_id_width;
    size_t msb_permutations_num = 1 << missing_msb;

    for (size_t msb_permutation = 0; msb_permutation < msb_permutations_num; ++msb_permutation) {
        size_t config_offset = ((msb_permutation << table_logical_id_width) | table_logical_id) * key_size_field_width;

        per_em_reg.set_bits(config_offset + key_size_field_width - 1, config_offset, key_width_option);
    }
}

std::vector<size_t>
em_utils::get_key_width_options(database_e db)
{
    switch (db) {
    case DATABASE_EGRESS_SMALL_EM:
        return {42, 26};
    case DATABASE_MAC_SERVICE_MAPPING_0_EM:
    case DATABASE_MAC_SERVICE_MAPPING_1_EM:
        return {50, 22};
    case DATABASE_TUNNEL_0_EM:
    case DATABASE_TUNNEL_1_EM:
        return {80};
    case DATABASE_EGRESS_LARGE_EM:
        return {42, 26};
    case DATABASE_EGRESS_L3_DLP0_EM:
        return {32, 16};
    case DATABASE_MAC_TERMINATION_EM:
        return {40};
    case DATABASE_RESOLUTION_NATIVE_LB_EM:
        return {30};
    case DATABASE_RESOLUTION_PATH_LB_EM:
        return {30};
    case DATABASE_RESOLUTION_PORT_DSPA_EM:
        return {30};
    case DATABASE_CENTRAL_EM:
        return {142, 78, 46};
    case DATABASE_TM_MC_EM:
        return {32};
    case DATABASE_RESOLUTION_PORT_NPP_LB_EM:
        return {30};
    case DATABASE_NPUH_ETH_MP_EM:
        return {50};
    default:
        dassert_crit(false);
    }

    return std::vector<size_t>();
}

} // namespace silicon_one
