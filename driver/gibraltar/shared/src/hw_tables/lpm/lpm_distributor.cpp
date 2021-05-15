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

#include "lpm_distributor.h"
#include "common/logger.h"

namespace silicon_one
{

lpm_distributor::lpm_distributor(std::string name,
                                 size_t num_hw_lines,
                                 size_t max_key_width,
                                 size_t num_ipv4_rows,
                                 size_t num_ipv6_rows)
    : m_name(name), m_num_cells_per_bank(num_hw_lines), m_max_key_width(max_key_width)
{
    m_logical_tcams.reserve(2); // IPv4 + IPv6

    m_logical_tcams.emplace_back(name + "::IPv4 Logical TCAM", num_ipv4_rows);
    m_logical_tcams.emplace_back(name + "::IPv6 Logical TCAM", num_ipv6_rows);

    // Initially, we give all rows to IPv6.
    m_logical_tcams[1 /* =IPV6 */].block_all_free_rows();
    m_logical_tcams[1 /* =IPv6 */].commit();
}

lpm_distributor::~lpm_distributor()
{
    return;
}

la_status
lpm_distributor::insert(const lpm_key_t& key, lpm_payload_t payload, hardware_instruction_vec& out_instructions)
{
    log_debug(
        TABLES, "%s: %s: key=0x%s/%zu  payload=%u", m_name.c_str(), __func__, key.to_string().c_str(), key.get_width(), payload);

    dassert_crit(key.get_width() <= m_max_key_width);
    bool is_ipv6 = key.bit_from_msb(0);

    lpm_logical_tcam::logical_instruction_vec logical_instructions;

    la_status status = make_space_for_logical_tcam(is_ipv6, logical_instructions);
    return_on_error(status);

    status = m_logical_tcams[is_ipv6].insert(key, payload, logical_instructions);
    return_on_error(status);

    translate_logical_to_physical_instructions(logical_instructions, out_instructions);
    return LA_STATUS_SUCCESS;
}

la_status
lpm_distributor::remove(const lpm_key_t& key, hardware_instruction_vec& out_instructions)
{
    log_debug(TABLES, "%s: %s: key=0x%s/%zu", m_name.c_str(), __func__, key.to_string().c_str(), key.get_width());

    dassert_crit(key.get_width() <= m_max_key_width);
    bool is_ipv6 = key.bit_from_msb(0);

    lpm_logical_tcam::logical_instruction_vec logical_instructions;
    la_status status = m_logical_tcams[is_ipv6].remove(key, logical_instructions);
    translate_logical_to_physical_instructions(logical_instructions, out_instructions);
    return status;
}

void
lpm_distributor::translate_logical_to_physical_instructions(lpm_logical_tcam::logical_instruction_vec logical_instructions,
                                                            hardware_instruction_vec& out_instructions) const
{
    for (lpm_logical_tcam::logical_instruction& instruction : logical_instructions) {
        bool is_ipv6 = instruction.key.bit_from_msb(0);
        distributor_cell_location cell_location = translate_logical_row_to_cell_location(instruction.row, is_ipv6);
        distributor_hw_instruction hw_instruction;
        switch (instruction.instruction_type) {
        case lpm_logical_tcam::logical_instruction::type_e::INSERT:
            hw_instruction.instruction_data = distributor_hw_instruction::insert_data{
                .key = instruction.key, .payload = instruction.payload, .location = cell_location};
            break;
        case lpm_logical_tcam::logical_instruction::type_e::REMOVE:
            hw_instruction.instruction_data
                = distributor_hw_instruction::remove_data{.key = instruction.key, .location = cell_location};
            break;
        case lpm_logical_tcam::logical_instruction::type_e::MODIFY_PAYLOAD:
            hw_instruction.instruction_data = distributor_hw_instruction::modify_payload_data{
                .key = instruction.key, .payload = instruction.payload, .location = cell_location};
            break;
        }

        out_instructions.push_back(hw_instruction);
    }
}

la_status
lpm_distributor::lookup_tcam_tree(const lpm_key_t& key,
                                  lpm_key_t& out_hit_key,
                                  lpm_payload_t& out_hit_payload,
                                  distributor_cell_location& out_hit_location) const
{
    bool is_ipv6 = key.bit_from_msb(0);
    size_t hit_row;
    la_status status = m_logical_tcams[is_ipv6].lookup_tcam_tree(key, out_hit_key, out_hit_payload, hit_row);
    out_hit_location = translate_logical_row_to_cell_location(hit_row, is_ipv6);
    return status;
}

la_status
lpm_distributor::lookup_tcam_table(const lpm_key_t& key,
                                   lpm_key_t& out_hit_key,
                                   lpm_payload_t& out_hit_payload,
                                   distributor_cell_location& out_hit_location) const
{
    bool is_ipv6 = key.bit_from_msb(0);
    size_t hit_row;
    la_status status = m_logical_tcams[is_ipv6].lookup_tcam_table(key, out_hit_key, out_hit_payload, hit_row);
    out_hit_location = translate_logical_row_to_cell_location(hit_row, is_ipv6);
    return status;
}

const lpm_logical_tcam_tree_node*
lpm_distributor::find(const lpm_key_t& key) const
{
    bool is_ipv6 = key.bit_from_msb(0);
    const lpm_logical_tcam_tree_node* node = m_logical_tcams[is_ipv6].find(key);
    return node;
}

const lpm_logical_tcam_tree_node*
lpm_distributor::get_root_node(bool is_ipv6) const
{
    const lpm_logical_tcam_tree_node* node = m_logical_tcams[is_ipv6].get_root_node();
    return node;
}

la_status
lpm_distributor::get_payload_of_node(const lpm_logical_tcam_tree_node* node, lpm_payload_t& out_payload) const
{
    dassert_crit(node != nullptr);
    bool is_ipv6 = node->get_key().bit_from_msb(0);
    la_status status = m_logical_tcams[is_ipv6].get_payload_of_node(node, out_payload);
    return status;
}

void
lpm_distributor::reset_state(hardware_instruction_vec& out_instructions)
{
    lpm_logical_tcam::logical_instruction_vec logical_instructions;
    for (auto& logical_tcam : m_logical_tcams) {
        logical_tcam.reset_state(logical_instructions);
    }

    translate_logical_to_physical_instructions(logical_instructions, out_instructions);
}

vector_alloc<lpm_key_payload_location>
lpm_distributor::get_entries() const
{
    vector_alloc<lpm_key_payload_location> entries;
    for (bool is_ipv6 : {false, true}) {
        vector_alloc<lpm_key_payload_row> tcam_entries = m_logical_tcams[is_ipv6].get_entries();
        for (lpm_key_payload_row& tcam_entrie : tcam_entries) {
            lpm_key_payload_location key_location;
            key_location.key = tcam_entrie.key;
            key_location.payload = tcam_entrie.payload;
            key_location.location = translate_logical_row_to_cell_location(tcam_entrie.row, is_ipv6);
            entries.push_back(key_location);
        }
    }

    return entries;
}

} // namespace silicon_one
