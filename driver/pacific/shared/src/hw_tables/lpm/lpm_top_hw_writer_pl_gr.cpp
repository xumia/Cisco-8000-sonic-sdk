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

#include "lpm_top_hw_writer_pl_gr.h"
#include "common/defines.h"
#include "common/logger.h"
#include "lld/ll_device.h"
#include "lld/lld_memory.h"

namespace silicon_one
{

const ll_device_sptr&
lpm_top_hw_writer_pl_gr::get_ll_device() const
{
    return m_ll_device;
}

lpm_top_hw_writer_pl_gr::lpm_top_hw_writer_pl_gr(const ll_device_sptr& ldevice) : m_ll_device(ldevice)
{
}

la_status
lpm_top_hw_writer_pl_gr::update_index_to_core(const distributor_cell_location& location,
                                              const lpm_key_t& key,
                                              lpm_payload_t payload)
{
    log_debug(TABLES, "%s (bank = %hhu, cell = %lu, core = %u)", __func__, location.bank, location.cell, payload);

    bool is_ipv6 = key.bit_from_msb(0);
    size_t num_banks_for_key = is_ipv6 ? NUM_BANKS_FOR_IPV6_ENTRY : NUM_BANKS_FOR_IPV4_ENTRY;
    dassert_crit(!is_ipv6 || location.bank == 0);

    // The HW resolver selects the first cell of the entry. For 80-bits-entry the valid values are 0-511.
    size_t payload_flat_location = ((location.bank / num_banks_for_key) * NUM_CELLS_IN_BANK + location.cell);
    size_t core = payload;

    bit_vector val(core, CORE_ENTRY_WIDTH);

    size_t sram_line = payload_flat_location / m_number_indexes_per_line;
    size_t index_in_line = payload_flat_location % m_number_indexes_per_line;
    size_t lsb = index_in_line * CORE_ENTRY_WIDTH;
    size_t msb = lsb + CORE_ENTRY_WIDTH - 1;
    for (size_t cdb_idx = 0; cdb_idx < m_cdb_top.size(); cdb_idx++) {
        const lld_memory_array_container& group_to_core_map = *m_cdb_top[cdb_idx].lpm_tcam_index_to_core;
        for (size_t ifc_idx = 0; ifc_idx < group_to_core_map.size(); ++ifc_idx) {
            la_status status = m_ll_device->read_modify_write_memory(*(group_to_core_map[ifc_idx]), sram_line, msb, lsb, val);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_top_hw_writer_pl_gr::set_distributor_line(const distributor_cell_location& location,
                                              const lpm_key_t& key,
                                              lpm_payload_t payload)
{
    log_debug(TABLES,
              "%s (bank = %hhu, cell = %lu, key = %s, key width = %lu, payload = 0x%x)",
              __func__,
              location.bank,
              location.cell,
              key.to_string().c_str(),
              key.get_width(),
              payload);

    // Update index to core
    update_index_to_core(location, key, payload);

    bool is_ipv6 = key.bit_from_msb(0);

    size_t num_banks_for_key = is_ipv6 ? NUM_BANKS_FOR_IPV6_ENTRY : NUM_BANKS_FOR_IPV4_ENTRY;

    // Write to TCAM
    size_t key_width = key.get_width();
    dassert_crit(key_width <= (num_banks_for_key * (m_distributor_row_width - 1) + 1));

    size_t remaining_width = key_width - 1;
    size_t line = location.cell;
    size_t start_bank_idx = location.bank;
    size_t end_bank_idx = start_bank_idx + num_banks_for_key - 1;
    for (size_t bank_idx = start_bank_idx; bank_idx <= end_bank_idx; bank_idx++) {
        bit_vector tcam_key(0, m_distributor_row_width);
        bit_vector tcam_mask(0, m_distributor_row_width);

        size_t width_to_write = std::min(remaining_width, m_distributor_row_width - 1);
        size_t msb_offset = key_width - remaining_width;
        lpm_key_t key_to_write = key.bits_from_msb(msb_offset, width_to_write);
        tcam_key.set_bits_from_msb(0, width_to_write, key_to_write);
        tcam_key.set_bit(0 /* is_ipv6 bit */, is_ipv6);

        tcam_mask.set_bits_from_msb(0, width_to_write, bit_vector::ones(width_to_write));
        tcam_mask.set_bit(0 /* is_ipv6 bit */, true);

        for (size_t cdb_idx = 0; cdb_idx < m_cdb_top.size(); cdb_idx++) {
            const lld_memory_array_container& core_map_tcam = *(m_cdb_top[cdb_idx].lpm_core_map_tcam);
            for (size_t tcam_per_slice_idx = bank_idx; tcam_per_slice_idx < m_number_of_tcams;
                 tcam_per_slice_idx += NUM_TCAMS_PER_LOOKUP_INTERFACE) {
                la_status status = m_ll_device->write_tcam(*(core_map_tcam[tcam_per_slice_idx]), line, tcam_key, tcam_mask);
                return_on_error(status);
            }
        }

        remaining_width -= width_to_write;
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_top_hw_writer_pl_gr::remove_distributor_line(const distributor_cell_location& location, const lpm_key_t& key)
{
    log_debug(TABLES, "%s (bank = %hhu, cell = %lu)", __func__, location.bank, location.cell);

    size_t num_banks_for_key = key.bit_from_msb(0) ? NUM_BANKS_FOR_IPV6_ENTRY : NUM_BANKS_FOR_IPV4_ENTRY;

    // Write to TCAM
    size_t line = location.cell;
    size_t start_bank_idx = location.bank;
    size_t end_bank_idx = start_bank_idx + num_banks_for_key - 1;
    for (size_t bank_idx = start_bank_idx; bank_idx <= end_bank_idx; bank_idx++) {
        for (size_t cdb_idx = 0; cdb_idx < m_cdb_top.size(); cdb_idx++) {
            const lld_memory_array_container& core_map_tcam = *m_cdb_top[cdb_idx].lpm_core_map_tcam;
            for (size_t tcam_per_slice_idx = bank_idx; tcam_per_slice_idx < m_number_of_tcams;
                 tcam_per_slice_idx += NUM_TCAMS_PER_LOOKUP_INTERFACE) {
                la_status status = m_ll_device->invalidate_tcam(*(core_map_tcam[tcam_per_slice_idx]), line);
                return_on_error(status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_top_hw_writer_pl_gr::update_distributor(const lpm_distributor::hardware_instruction_vec& instructions)
{
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = LA_STATUS_SUCCESS;

    for (const lpm_distributor::distributor_hw_instruction& curr : instructions) {
        auto type = boost::apply_visitor(lpm_distributor::visitor_distributor_hw_instruction(), curr.instruction_data);
        switch (type) {
        case lpm_distributor::distributor_hw_instruction::type_e::MODIFY_PAYLOAD: {
            auto curr_data = boost::get<lpm_distributor::distributor_hw_instruction::modify_payload_data>(curr.instruction_data);
            status = update_index_to_core(curr_data.location, curr_data.key, curr_data.payload);
            return_on_error(status);
            break;
        }

        case lpm_distributor::distributor_hw_instruction::type_e::INSERT: {
            auto curr_data = boost::get<lpm_distributor::distributor_hw_instruction::insert_data>(curr.instruction_data);
            status = set_distributor_line(curr_data.location, curr_data.key, curr_data.payload);
            return_on_error(status);
            break;
        }

        case lpm_distributor::distributor_hw_instruction::type_e::REMOVE: {
            auto curr_data = boost::get<lpm_distributor::distributor_hw_instruction::remove_data>(curr.instruction_data);
            status = remove_distributor_line(curr_data.location, curr_data.key);
            return_on_error(status);
            break;
        }

        default:
            dassert_crit(false);
            return LA_STATUS_EUNKNOWN;
        }
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
