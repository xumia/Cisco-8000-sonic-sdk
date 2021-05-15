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

#ifndef __RA_EM_UTILS_H__
#define __RA_EM_UTILS_H__

#include <stddef.h>
#include <vector>

#include "common/bit_vector.h"
#include "ra_enums.h"

namespace silicon_one
{

namespace em_utils
{
enum {
    MAX_LOGICAL_ID_WIDTH = 4,                      ///< Maximum bits in logical table ID for EM key width identification.
    MAX_TABLES_PER_EM = 1 << MAX_LOGICAL_ID_WIDTH, ///< Maximum number of tables that can be placed on the same Exact Match (16)
    AUTO_BUBBLE_REG_FIELD_WIDTH = 1,               ///< Width in bits of auto_bubble field in per-em register.
    BUBBLE_THRESHOLD_REG_FIELD_WIDTH = 16,         ///< Width in bits of bubble threshold field in per-em register.
    INVALID_OPTIONS_INDEX = (size_t)-1,            ///< Invalid options index
};

/// @brief Return primary key width (longest) for given EM.
///
/// @param[in]  db      EM database ID.
///
/// @retval     width of the primary key in bits or 0 if database is not in the list.
size_t get_primary_key_width(database_e db);

/// @brief Return entry width in bits (key + payload) for given EM.
/// For each EM, the entry width remains constant. For larger keys, payload width is reduced.
///
/// @param[in]  db      EM database ID.
///
/// @retval     width of the data or 0 if database is not in the list.
size_t get_entry_width(database_e db);

/// @brief Return EM key width in bits for given table key width.
/// EM has fixed key sizes (1-3 sizes). Given table key, finds the minimal option that matches.
///
/// @param[in]  db                  EM database ID.
/// @param[in]  table_key_width     table key width in bits.
/// @param[in]  table_payload_width table payload width in bits.
///
/// @retval     EM key width or 0  if database is not in the list or table key is larger than maximal EM key.
size_t get_key_width(database_e db, size_t table_key_width, size_t table_payload_width);

/// @brief Return EM payload width in bits for given table key width.
/// Usually, payload width is calculated as <entry_width> - <key_width>.
/// For wide keys of central EM (which occupy 2 entries), the calculation is different
///
/// @param[in]  db                  EM database ID.
/// @param[in]  table_key_width     table key width in bits.
/// @param[in]  table_payload_width table payload width in bits.
///
/// @retval     EM payload width or 0  if database is not in the list or table key is larger than maximal EM key.
size_t get_payload_width(database_e db, size_t table_key_width, size_t table_payload_width);

/// @brief Return EM key index for given table key width.
/// EM has fixed key sizes (1-3 sizes). Given table key, finds the minimal option that matches and returns its index.
/// The options are sorted from largest to smallest. Primary (largest) key has index 0.
///
/// @param[in]  db                  EM database ID.
/// @param[in]  table_key_width     table key width in bits.
/// @param[in]  table_payload_width table payload width in bits.
///
/// @retval     EM key width index.
size_t get_key_width_idx(database_e db, size_t table_key_width, size_t table_payload_width);

/// @brief Return EM line config index for given table key width and payload width
/// Flexible EM has fixed key and value sizes. Given table key, finds the best option that matches and return its index.
/// The options are arranged as they appear in LBR.
///
/// @param[in]  db                  EM database ID.
/// @param[in]  table_key_width     table key width in bits.
/// @param[in]  table_payload_width table payload width in bits.
///
/// @retval     line config index
size_t get_line_config_idx(database_e db, size_t table_key_width, size_t table_payload_width);

/// @brief Return number of different key sizes, the database supports.
///
/// @param[in]  db                  EM database ID.
/// @param[in]  table_key_width     table key width in bits.
///
/// @retval     number of EM key width options.
size_t get_num_keys(database_e db);

/// @brief Return per-em register width.
/// The width of the register depends on the number of keys, the database supports.
///
/// @param[in]  num_of_keys         Number of key options.
///
/// @retval     width in bits for per-em register.
size_t get_per_em_register_width(size_t num_of_keys);

/// @brief Return key option register field width in per-em register.
/// Key option width depends on number of keys, the database suppors.
///
/// @param[in]  num_of_keys         Number of key options.
///
/// @retval     width in bits for per-em register.
size_t get_key_option_register_field_width(size_t num_of_keys);

/// @brief Writes table key option to per-em register.
/// Table key option might be written several times to the register, depends on table logical ID width.
///
/// @param[in]  table_logical_id         Table logical ID.
/// @param[in]  table_logical_id_width   Table logical ID width in bits.
/// @param[in]  em_keys_num              Number of key options in EM.
/// @param[in]  key_width_option         Key option to be written.
///
/// @param[out] per_em_reg               Content of per-em register to append with table data.
void add_table_to_per_em_reg(size_t table_logical_id,
                             size_t table_logical_id_width,
                             size_t em_keys_num,
                             size_t key_width_option,
                             bit_vector& per_em_reg);

/// @brief Returs list of all available key widths for given EM database.
///
/// @param[in]  db                  EM database ID.
///
/// @retval List of key widths sorted from largest to smallest. Primary key is option 0.
std::vector<size_t> get_key_width_options(database_e db);

/// @brief Returs list of all available payload widths for given EM database and key width.
///
/// @param[in]  db                  EM database ID.
///
/// @retval List of key/payload width pair options as they appear in the LBR
std::vector<std::pair<size_t, size_t> > get_em_line_config_options(database_e db);

/// @brief Returs whether the EM supported flexible entry.
///
/// @param[in]  db                  EM database ID.
///
/// @retval true if flexible entry supported, false if not
bool is_flexible_entry_supported(database_e db);
};

} // namespace silicon_one

#endif // __RA_EM_UTILS_H__
