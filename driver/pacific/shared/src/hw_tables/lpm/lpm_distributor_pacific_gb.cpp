// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "lpm_distributor_pacific_gb.h"
#include "common/logger.h"
#include "common/transaction.h"

#include <jansson.h>

/// The distributor is a simple TCAM.
/// In Pacific, a hardware bug results in distributor key not having the is_ipv6 bit in IPv6 entries.
/// As a work around: IPv4 entries must be allocated in the top (before IPv6 entries).
/// In order to enforce this order, we treat distributor as if it were 2 logical TCAMs (IPv4 and IPv6),
/// which compete on the actual physical resource.
/// This class has these 2 logical TCAMs, and dynamically moves the ownership of physical rows between them,
/// Keeping IPv4 entries always on the top of the TCAM table.

namespace silicon_one
{

constexpr const char* JSON_NUM_IPV4_ROWS = "num_ipv4_rows";

lpm_distributor_pacific_gb::lpm_distributor_pacific_gb(std::string name, size_t num_hw_lines, size_t max_key_width)
    : lpm_distributor(name, num_hw_lines, max_key_width, num_hw_lines, num_hw_lines)
{
    m_num_ipv4_rows = num_hw_lines;
}

la_status
lpm_distributor_pacific_gb::update(const lpm_implementation_desc_vec& updates, hardware_instruction_vec& out_instructions)
{
    log_debug(TABLES, "%s: %s", m_name.c_str(), __func__);
    transaction txn;
    txn.on_fail([=]() { withdraw(); });

    for (const auto& update : updates) {
        switch (update.m_action) {
        case lpm_implementation_action_e::INSERT: {
            distributor_hw_instruction instruction;
            instruction.instruction_data
                = distributor_hw_instruction::update_group_to_core_data{.group_id = update.m_payload, .core_id = update.m_core_id};
            out_instructions.push_back(instruction);

            txn.status = insert(update.m_key, update.m_payload, out_instructions);
            return_on_error(txn.status);
            break;
        }

        case lpm_implementation_action_e::REMOVE: {
            txn.status = remove(update.m_key, out_instructions);
            return_on_error(txn.status);
            break;
        }

        case lpm_implementation_action_e::MODIFY_GROUP_TO_CORE: {
            distributor_hw_instruction instruction;
            instruction.instruction_data
                = distributor_hw_instruction::update_group_to_core_data{.group_id = update.m_payload, .core_id = update.m_core_id};
            out_instructions.push_back(instruction);

            break;
        }

        default:
            return LA_STATUS_EINVAL;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_distributor_pacific_gb::get_entry(distributor_cell_location location, lpm_key_payload& out_key_payload) const
{
    dassert_crit(location.bank == 0);
    dassert_crit(location.cell < m_num_cells_per_bank);
    size_t row = location.cell;
    bool is_ipv6 = is_row_ipv6(row);
    la_status status = m_logical_tcams[is_ipv6].get_entry(row, out_key_payload);
    return status;
}

la_status
lpm_distributor_pacific_gb::make_space_for_logical_tcam(bool is_ipv6, lpm_logical_tcam::logical_instruction_vec& out_instructions)
{
    size_t num_free_rows = m_logical_tcams[is_ipv6].get_num_free_rows();
    if (num_free_rows > 0) {
        return LA_STATUS_SUCCESS;
    }

    size_t num_of_my_rows = is_ipv6 ? (m_num_cells_per_bank - m_num_ipv4_rows) : m_num_ipv4_rows;
    if (num_of_my_rows == m_num_cells_per_bank) { // I already own all rows
        return LA_STATUS_ERESOURCE;
    }

    // IPv4 entries are located in the top.
    // If we need to make space for IPv6 entry, we need to block the last IPv4 row.
    // If we need to make space for IPv4 entry, we need to block the first IPv6 row.
    size_t row_to_switch_ownership = is_ipv6 ? (m_num_ipv4_rows - 1) : m_num_ipv4_rows;

    la_status status = m_logical_tcams[!is_ipv6].block(row_to_switch_ownership, out_instructions);
    return_on_error(status);

    status = m_logical_tcams[is_ipv6].unblock(row_to_switch_ownership);
    dassert_crit(status == LA_STATUS_SUCCESS);

    size_t new_num_ipv4_rows = is_ipv6 ? (m_num_ipv4_rows - 1) : m_num_ipv4_rows + 1;
    atom_update_num_ipv4_rows(new_num_ipv4_rows);

    return LA_STATUS_SUCCESS;
}

distributor_cell_location
lpm_distributor_pacific_gb::translate_logical_row_to_cell_location(size_t logical_row, bool is_ipv6) const
{
    dassert_crit(logical_row < m_num_cells_per_bank);
    distributor_cell_location location = {.bank = 0, .cell = logical_row};
    return location;
}

void
lpm_distributor_pacific_gb::atom_update_num_ipv4_rows(size_t new_value)
{
    withdraw_action waction;
    waction.action_type = withdraw_action::withdraw_action_type_e::WITHDRAW_UPDATE_NUM_IPV4_ROWS;
    waction.action_data = withdraw_action::withdraw_update_num_ipv4_rows{.num_ipv4_rows = m_num_ipv4_rows};
    m_withdraw_stack.push_back(waction);

    m_num_ipv4_rows = new_value;
}

bool
lpm_distributor_pacific_gb::is_row_ipv6(size_t row) const
{
    return (row >= m_num_ipv4_rows);
}

void
lpm_distributor_pacific_gb::commit()
{

    if (!m_withdraw_stack.empty()) {
        log_debug(TABLES, "%s: %s", m_name.c_str(), __func__);
    }

    for (auto& logical_tcam : m_logical_tcams) {
        logical_tcam.commit();
    }

    m_withdraw_stack.clear();
}

void
lpm_distributor_pacific_gb::withdraw()
{
    log_debug(TABLES, "%s: %s", m_name.c_str(), __func__);
    for (auto& logical_tcam : m_logical_tcams) {
        logical_tcam.withdraw();
    }

    while (!m_withdraw_stack.empty()) {
        const withdraw_action waction = m_withdraw_stack.back();
        m_withdraw_stack.pop_back();

        withdraw_one_action(waction);
    }
}

void
lpm_distributor_pacific_gb::withdraw_one_action(const withdraw_action& waction)
{
    switch (waction.action_type) {
    case withdraw_action::withdraw_action_type_e::WITHDRAW_UPDATE_NUM_IPV4_ROWS: {
        auto action_data = boost::get<withdraw_action::withdraw_update_num_ipv4_rows>(waction.action_data);
        size_t num_ipv4_rows = action_data.num_ipv4_rows;

        m_num_ipv4_rows = num_ipv4_rows;
        return;
    }
    }
}

json_t*
lpm_distributor_pacific_gb::save_state() const
{
    json_t* json_distributor = json_object();
    json_object_set_new(json_distributor, JSON_NUM_IPV4_ROWS, json_integer(m_num_ipv4_rows));
    json_t* json_ipv4_tcam = m_logical_tcams[0 /* = IPv4 */].save_state();
    json_object_set_new(json_distributor, JSON_IPV4_TCAM, json_ipv4_tcam);
    json_t* json_ipv6_tcam = m_logical_tcams[1 /* = IPv6 */].save_state();
    json_object_set_new(json_distributor, JSON_IPV6_TCAM, json_ipv6_tcam);

    return json_distributor;
}

void
lpm_distributor_pacific_gb::load_state(json_t* json_distributor, hardware_instruction_vec& out_instructions)
{
    reset_state(out_instructions);
    size_t num_ipv4_rows = json_integer_value(json_object_get(json_distributor, JSON_NUM_IPV4_ROWS));
    atom_update_num_ipv4_rows(num_ipv4_rows);

    LA_UNUSED la_status status = LA_STATUS_SUCCESS;

    // unblock rows which belong to IPv4
    for (size_t row = 0; row < m_num_ipv4_rows; row++) {
        status = m_logical_tcams[0 /* = IPv4 */].unblock(row);
        dassert_crit(status == LA_STATUS_SUCCESS);
    }

    // unblock rows which belong to IPv6
    for (size_t row = m_num_ipv4_rows; row < m_num_cells_per_bank; row++) {
        status = m_logical_tcams[1 /* = IPv6 */].unblock(row);
        dassert_crit(status == LA_STATUS_SUCCESS);
    }

    dassert_crit(m_logical_tcams[0 /* = IPv4 */].get_num_free_rows() == m_num_ipv4_rows);
    dassert_crit(m_logical_tcams[1 /* = IPv6 */].get_num_free_rows() == (m_num_cells_per_bank - m_num_ipv4_rows));

    lpm_logical_tcam::logical_instruction_vec logical_instructions;
    json_t* json_ipv4_tcam = json_object_get(json_distributor, JSON_IPV4_TCAM);
    m_logical_tcams[0 /* = IPv4 */].load_state(json_ipv4_tcam, logical_instructions);
    json_t* json_ipv6_tcam = json_object_get(json_distributor, JSON_IPV6_TCAM);
    m_logical_tcams[1 /* = IPv6 */].load_state(json_ipv6_tcam, logical_instructions);

    translate_logical_to_physical_instructions(logical_instructions, out_instructions);
}

} // namespace silicon_one
