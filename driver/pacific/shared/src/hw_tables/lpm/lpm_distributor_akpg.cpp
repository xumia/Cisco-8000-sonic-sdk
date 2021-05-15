// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "lpm_distributor_akpg.h"
#include "common/logger.h"
#include "common/transaction.h"

#include <jansson.h>

namespace silicon_one
{

constexpr const char* JSON_NUM_IPV6_BLOCKS = "num_ipv6_blocks";

lpm_distributor_akpg::lpm_distributor_akpg(std::string name, size_t num_hw_lines, size_t max_key_width)
    : lpm_distributor(name, num_hw_lines, max_key_width, num_hw_lines * NUM_BANKS / 2, num_hw_lines * NUM_BANKS / 4)
{
    m_num_ipv6_blocks = 0;
}

la_status
lpm_distributor_akpg::modify(const lpm_key_t& key, lpm_payload_t payload, hardware_instruction_vec& out_instructions)
{
    log_debug(
        TABLES, "%s: %s: key=0x%s/%zu  payload=%u", m_name.c_str(), __func__, key.to_string().c_str(), key.get_width(), payload);

    bool is_ipv6 = key.bit_from_msb(0);
    dassert_crit(payload != static_cast<lpm_payload_t>(CORE_ID_NONE));

    lpm_logical_tcam::logical_instruction_vec logical_instructions;

    la_status status = m_logical_tcams[is_ipv6].modify(key, payload, logical_instructions);
    return_on_error(status);

    translate_logical_to_physical_instructions(logical_instructions, out_instructions);
    return LA_STATUS_SUCCESS;
}

la_status
lpm_distributor_akpg::update(const lpm_implementation_desc_vec& updates, hardware_instruction_vec& out_instructions)
{
    log_debug(TABLES, "%s: %s", m_name.c_str(), __func__);
    transaction txn;
    txn.on_fail([=]() { withdraw(); });

    for (const auto& update : updates) {
        switch (update.m_action) {
        case lpm_implementation_action_e::INSERT: {
            txn.status = insert(update.m_key, update.m_payload, out_instructions);
            return_on_error(txn.status);
            break;
        }

        case lpm_implementation_action_e::REMOVE: {
            txn.status = remove(update.m_key, out_instructions);
            return_on_error(txn.status);
            break;
        }

        case lpm_implementation_action_e::MODIFY_GROUP_TO_CORE:
            txn.status = modify(update.m_key, update.m_payload, out_instructions);
            return_on_error(txn.status);
            break;

        default:
            return LA_STATUS_EINVAL;
        }
    }

    return LA_STATUS_SUCCESS;
}

// Converts two logical IPv4 rows into one IPv6 or one IPv6 into two IPv4 rows.
la_status
lpm_distributor_akpg::make_space_for_logical_tcam(bool is_ipv6, lpm_logical_tcam::logical_instruction_vec& out_instructions)
{
    size_t num_free_blocks = m_logical_tcams[is_ipv6].get_num_free_rows();
    if (num_free_blocks > 0) {
        return LA_STATUS_SUCCESS;
    }

    bool current_owner = !is_ipv6;
    size_t needed_rows_from_current_owner = is_ipv6 ? 2 : 1;
    if (m_logical_tcams[!is_ipv6].get_num_free_rows() < needed_rows_from_current_owner) {
        return LA_STATUS_ERESOURCE;
    }

    size_t block_group_to_switch = is_ipv6 ? m_num_ipv6_blocks : m_num_ipv6_blocks - 1;

    size_t num_cells_per_block = get_num_cells_in_block(current_owner);

    // Give up ownership
    size_t num_blocks_to_release = NUM_BANKS / num_cells_per_block;
    for (size_t block = 0; block < num_blocks_to_release; block++) {
        size_t logical_row = block_group_to_switch + block * m_num_cells_per_bank;
        la_status status = m_logical_tcams[current_owner].block(logical_row, out_instructions);
        return_on_error(status);
    }

    // Take ownership for new owner
    num_cells_per_block = get_num_cells_in_block(is_ipv6);
    size_t num_blocks_to_occupy = NUM_BANKS / num_cells_per_block;
    for (size_t block = 0; block < num_blocks_to_occupy; block++) {
        size_t logical_row = block_group_to_switch + block * m_num_cells_per_bank;
        la_status status = m_logical_tcams[is_ipv6].unblock(logical_row);
        dassert_crit(status == LA_STATUS_SUCCESS);
        return_on_error(status);
    }

    size_t new_num_ipv6_blocks = is_ipv6 ? (m_num_ipv6_blocks + 1) : (m_num_ipv6_blocks - 1);
    atom_update_num_ipv6_blocks(new_num_ipv6_blocks);
    return LA_STATUS_SUCCESS;
}

uint8_t
lpm_distributor_akpg::get_num_cells_in_block(bool is_ipv6) const
{
    return (is_ipv6 ? 4 : 2);
}

void
lpm_distributor_akpg::atom_update_num_ipv6_blocks(size_t new_value)
{

    withdraw_action waction;
    waction.action_type = withdraw_action::withdraw_action_type_e::WITHDRAW_UPDATE_NUM_IPV6_BLOCKS;
    waction.action_data = withdraw_action::withdraw_update_num_ipv6_blocks{.old_num_blocks = m_num_ipv6_blocks};
    m_withdraw_stack.push_back(waction);

    m_num_ipv6_blocks = new_value;
}

distributor_cell_location
lpm_distributor_akpg::translate_logical_row_to_cell_location(size_t logical_row, bool is_ipv6) const
{
    distributor_cell_location location;
    size_t num_cells_in_block = get_num_cells_in_block(is_ipv6);
    location.bank = (logical_row / m_num_cells_per_bank) * num_cells_in_block;
    location.cell = logical_row % m_num_cells_per_bank;

    return location;
}

la_status
lpm_distributor_akpg::get_entry(distributor_cell_location location, lpm_key_payload& out_key_payload) const
{
    dassert_crit(location.cell < m_num_cells_per_bank);
    bool is_ipv6 = (location.cell < m_num_ipv6_blocks);
    size_t bank_id = location.bank;
    dassert_crit(bank_id < NUM_BANKS);
    if ((is_ipv6 && ((bank_id % 4) != 0)) || ((bank_id % 2) != 0)) {
        return LA_STATUS_ENOTFOUND;
    }

    size_t num_cells_in_block = get_num_cells_in_block(is_ipv6);

    // Translate cell to logical row
    size_t logical_row = (bank_id / num_cells_in_block) * m_num_cells_per_bank + location.cell;
    la_status status = m_logical_tcams[is_ipv6].get_entry(logical_row, out_key_payload);
    return status;
}

void
lpm_distributor_akpg::commit()
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
lpm_distributor_akpg::withdraw()
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
lpm_distributor_akpg::withdraw_one_action(const withdraw_action& waction)
{
    switch (waction.action_type) {
    case withdraw_action::withdraw_action_type_e::WITHDRAW_UPDATE_NUM_IPV6_BLOCKS: {
        auto action_data = boost::get<withdraw_action::withdraw_update_num_ipv6_blocks>(waction.action_data);
        size_t num_ipv6_blocks = action_data.old_num_blocks;

        m_num_ipv6_blocks = num_ipv6_blocks;
        return;
    }
    }
}

json_t*
lpm_distributor_akpg::save_state() const
{
    json_t* json_distributor = json_object();
    json_object_set_new(json_distributor, JSON_NUM_IPV6_BLOCKS, json_integer(m_num_ipv6_blocks));
    json_t* json_ipv4_tcam = m_logical_tcams[0 /* = IPv4 */].save_state();
    json_object_set_new(json_distributor, JSON_IPV4_TCAM, json_ipv4_tcam);
    json_t* json_ipv6_tcam = m_logical_tcams[1 /* = IPv6 */].save_state();
    json_object_set_new(json_distributor, JSON_IPV6_TCAM, json_ipv6_tcam);

    return json_distributor;
}

void
lpm_distributor_akpg::load_state(json_t* json_distributor, hardware_instruction_vec& out_instructions)
{
    reset_state(out_instructions);

    size_t m_num_ipv6_blocks = json_integer_value(json_object_get(json_distributor, JSON_NUM_IPV6_BLOCKS));
    atom_update_num_ipv6_blocks(m_num_ipv6_blocks);

    // unblock rows which belong to IPv6
    for (size_t block = 0; block < m_num_ipv6_blocks; block++) {
        la_status status = m_logical_tcams[1 /* = IPv6 */].unblock(block);
        dassert_crit(status == LA_STATUS_SUCCESS);
    }

    size_t max_ipv6_blocks = NUM_BANKS * m_num_cells_per_bank / 4;

    // unblock rows which belong to IPv4
    for (size_t block = m_num_ipv6_blocks; block < max_ipv6_blocks; block++) {
        la_status status = m_logical_tcams[0 /* = IPv4 */].unblock(block); // first IPv4 row in block
        dassert_crit(status == LA_STATUS_SUCCESS);
        status = m_logical_tcams[0 /* = IPv4 */].unblock(block + m_num_cells_per_bank); // second IPv4 row in block
        dassert_crit(status == LA_STATUS_SUCCESS);
    }

    dassert_crit(m_logical_tcams[1 /* = IPv6 */].get_num_free_rows() == m_num_ipv6_blocks);

    lpm_logical_tcam::logical_instruction_vec logical_instructions;
    json_t* json_ipv4_tcam = json_object_get(json_distributor, JSON_IPV4_TCAM);
    m_logical_tcams[0 /* = IPv4 */].load_state(json_ipv4_tcam, logical_instructions);
    json_t* json_ipv6_tcam = json_object_get(json_distributor, JSON_IPV6_TCAM);
    m_logical_tcams[1 /* = IPv6 */].load_state(json_ipv6_tcam, logical_instructions);

    translate_logical_to_physical_instructions(logical_instructions, out_instructions);
}

} // namespace silicon_one
