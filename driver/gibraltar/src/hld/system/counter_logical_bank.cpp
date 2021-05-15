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

#include "counter_logical_bank.h"
#include "common/bit_vector.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_types.h"
#include "hld_utils.h"
#include "la_device_impl.h"
#include "la_strings.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

/// @brief HW encoding to each user type.
enum bank_user_type_e {
    BANK_USER_RX = 0,  ///< Bank is used as RX counter bank.
    BANK_USER_TX = 1,  ///< Bank is used as TX counter bank.
    BANK_USER_VOQ = 2, ///< Bank is used as VOQ counter bank.
};

physical_bank_entry::physical_bank_entry(const la_device_impl_wptr& device, size_t phys_bank_index, size_t offset_in_bank)
    : m_device(device), is_enabled(false), bytes_count(0), packet_count(0), m_token_size(METER_TOKEN_DISTRIBUTER_MAX_SIZE)
{
    m_counter_address.c.bank_id = phys_bank_index;
    m_counter_address.c.offset_in_bank = offset_in_bank;
}

const la_device*
physical_bank_entry::get_device() const
{
    return m_device.get();
}

inline void
physical_bank_entry::disable()
{
    is_enabled = false;
}

size_t
physical_bank_entry::get_token_size()
{
    return m_token_size;
}

inline void
physical_bank_entry::enable()
{
    clear();

    bytes_count = 0;
    packet_count = 0;
    is_enabled = true;
}

inline void
physical_bank_entry::add(size_t bytes, size_t packets)
{
    bytes_count += bytes;
    packet_count += packets;
}

inline void
physical_bank_entry::read(bool force_update, bool clear_on_read, size_t& out_bytes, size_t& out_packets)
{
    if (force_update) {
        update_counter_values_from_device();
    }

    out_bytes = bytes_count;
    out_packets = packet_count;

    if (clear_on_read) {
        bytes_count = 0;
        packet_count = 0;
    }
}

inline void
physical_bank_entry::update_counter_values_from_device()
{
    size_t bytes, packets;

    read_counter_values_from_device(bytes, packets);

    bytes_count += bytes;
    packet_count += packets;
}

inline void
physical_bank_entry::clear()
{
    counter_bank_utils::dispatch_read_counter_command(m_device, SPECIFIC_COUNTER_READ, m_counter_address.flat);
}

void
physical_bank_entry::read_counter_values_from_device(size_t& out_bytes, size_t& out_packets)
{
    out_bytes = 0;
    out_packets = 0;

    counter_bank_utils::dispatch_read_counter_command(m_device, SPECIFIC_COUNTER_READ, m_counter_address.flat);

    // Read the counter value
    gibraltar::counters_cpu_counter_read_result_register result_reg;

    la_status status
        = m_device->m_ll_device->read_register(m_device->m_gb_tree->counters->top->cpu_counter_read_result, result_reg);
    if (status != LA_STATUS_SUCCESS) {
        log_err(COUNTERS, "%s: read_register cpu_counter_read_result failed: %d\n", __func__, status.value());
        return;
    }

    out_packets = result_reg.fields.counter_read_result_packet_count;
    out_bytes = result_reg.fields.counter_read_result_byte_count;

    return;
}

counter_logical_bank::counter_logical_bank(const la_device_impl_wptr& device,
                                           size_t first_index,
                                           size_t first_slice,
                                           bool is_slice_pair,
                                           counter_direction_e direction,
                                           const counter_user_group_vec& allowed_user_types)
    : m_device(device),
      m_first_index(first_index),
      m_first_slice(first_slice),
      m_direction(direction),
      m_num_of_slices(is_slice_pair ? 2 : 1),
      m_num_of_busy_phys_entries(0),
      m_last_shadow_update(std::chrono::steady_clock::now())
{

    for (auto& user_type : allowed_user_types) {
        m_allowed_user_types.set(user_type);
    }

    m_num_logical_rows_in_bank = is_user_type_meter() ? MAX_LOGICAL_ROWS_IN_METER_BANK : MAX_LOGICAL_ROWS_IN_COUNTER_BANK;

    if (m_device->get_counter_bank_type() == NPL_COUNTER_TYPE_PC64_BC64) {
        m_num_logical_rows_in_bank /= 2;
    }

    m_num_physical_rows_in_bank = m_num_logical_rows_in_bank * phys_per_logical();

    // Counter allocation accounting per physical bank for each allowed user type.
    m_num_allocated_entries.resize(m_num_of_slices * NUM_IFGS_PER_SLICE);
}

const la_device*
counter_logical_bank::get_device() const
{
    return m_device.get();
}

la_status
counter_logical_bank::initialize()
{
    size_t row_width = m_num_of_slices * 2;
    la_status status;

    for (size_t i = 0; i < row_width; ++i) {
        m_physical_bank_shadow.push_back(bit_vector(0, ROWS_IN_HARDWARE_COUNTERS_BANK * 18));
        m_last_clear_bank.push_back(bit_vector(0, ROWS_IN_HARDWARE_COUNTERS_BANK * 18));
    }

    for (size_t offset_in_bank = 0; offset_in_bank < m_num_physical_rows_in_bank; offset_in_bank++) {
        m_phys_entries.push_back(phys_entry_row_t());

        for (size_t phys_bank_index = m_first_index; phys_bank_index < m_first_index + row_width; phys_bank_index++) {
            m_phys_entries[offset_in_bank].push_back(physical_bank_entry(m_device, phys_bank_index, offset_in_bank));
        }
    }

    // Workaround to HW issue - bank-id 0/index 0 are treated as nop counter
    // In order to allocate symmetric indices on all the banks skip index 0,
    // as nop counter in all the banks.
    if ((m_first_index == 0) || is_user_type_global()) {
        for (size_t phys_bank_index = 0; phys_bank_index < row_width; phys_bank_index++) {
            m_phys_entries[0][phys_bank_index].is_enabled = true;
        }
    }

    status = configure_counters_block_config_table(m_first_slice, m_num_of_slices, m_first_index);
    return_on_error(status);

    // VOQ bank doesn't need specific configuration.
    if (is_user_type_allowed(counter_user_type_e::COUNTER_USER_TYPE_VOQ)) {
        return LA_STATUS_SUCCESS;
    }

    if (m_direction == counter_direction_e::COUNTER_DIRECTION_INGRESS) {
        bool is_meter = is_user_type_allowed(counter_user_type_e::COUNTER_USER_TYPE_METER);
        status = configure_rx_counter_table(m_first_slice, m_num_of_slices, m_first_index, is_meter);
    } else {
        status = configure_tx_counter_table(m_first_slice, m_num_of_slices, m_first_index);
    }

    return status;
}

la_status
counter_logical_bank::configure_counters_block_config_table(size_t first_slice, size_t num_of_slices, size_t first_index)
{
    const auto& table(m_device->m_tables.counters_block_config_table);
    npl_counters_block_config_table_key_t key;
    npl_counters_block_config_table_value_t value;
    npl_counters_block_config_t& v(value.payloads.counters_block_config);
    npl_counters_block_config_table_entry_t* entry;
    size_t index = first_index;

    for (la_slice_id_t slice = first_slice; slice < first_slice + num_of_slices; slice++) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {

            key.counter_bank_id = index;

            v.lm_count_and_read = 0;
            v.reset_on_max_counter_read = 1;
            v.bank_counter_type = m_device->get_counter_bank_type();
            v.compensation = get_npl_byte_count_compensation(m_direction);
            v.ignore_pd_compensation = 1;
            v.wraparound = 0;
            v.cpu_read_cc_wait_before_create_bubble = 2;
            v.bank_pipe_client_allocation = get_user_type_encoding();
            v.bank_slice_allocation = slice;

            la_status status = table->insert(key, value, entry);
            return_on_error(status);

            gibraltar::counters_bank_allocation_config_register cfg_reg;
            cfg_reg.fields.bank_client_allocation = v.bank_pipe_client_allocation;
            cfg_reg.fields.bank_slice_allocation = slice;

            status = m_device->m_ll_device->write_register((*m_device->m_gb_tree->counters->top->bank_allocation_config)[index],
                                                           cfg_reg);
            return_on_error(status);

            index++;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
counter_logical_bank::configure_rx_counter_table(size_t first_slice, size_t num_of_slices, size_t first_index, bool is_meter)
{
    npl_rx_counters_block_config_table_key_t key;
    npl_rx_counters_block_config_table_value_t value;
    npl_rx_counters_block_config_table_entry_t* entry = nullptr;

    value.payloads.config.inc_addr_for_set = 1;
    value.payloads.config.bank_set_type = is_meter ? NPL_RX_COUNTERS_SET_TYPE_COLOR_AWARE : NPL_RX_COUNTERS_SET_TYPE_NO_SET;

    for (size_t bank_offset = 0; bank_offset < (num_of_slices * NUM_IFGS_PER_SLICE); bank_offset++) {
        key.counter_bank_id = first_index + bank_offset;
        const auto& table(m_device->m_tables.rx_counters_block_config_table);
        la_status status = table->insert(key, value, entry);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
counter_logical_bank::configure_tx_counter_table(size_t first_slice, size_t num_of_slices, size_t first_index)
{
    npl_tx_counters_block_config_table_key_t key;
    npl_tx_counters_block_config_table_value_t value;
    npl_tx_counters_block_config_table_entry_t* entry = nullptr;

    value.payloads.config.inc_addr_for_set = 1;
    value.payloads.config.bank_set_type = NPL_TX_COUNTERS_SET_TYPE_NO_SET;

    for (size_t bank_offset = 0; bank_offset < (num_of_slices * NUM_IFGS_PER_SLICE); bank_offset++) {
        key.counter_bank_id = first_index + bank_offset;
        const auto& table(m_device->m_tables.tx_counters_block_config_table);
        la_status status = table->insert(key, value, entry);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
counter_logical_bank::update_shadow(size_t physical_bank_index, size_t physical_bank_id)
{
    if (physical_bank_id >= METER_BANK_BASE) {
        return LA_STATUS_SUCCESS;
    }
    ll_device_sptr ll_device = m_device->get_ll_device_sptr();
    const gibraltar_tree* tree = ll_device->get_gibraltar_tree();
    auto bank_triblate_address = *(tree->counters->bank_8k[physical_bank_id / 3]->counters_table); // Bank triblate
    auto physical_bank_address = *(bank_triblate_address)[physical_bank_id % 3];

    return ll_device->read_memory(
        physical_bank_address, 0, ROWS_IN_HARDWARE_COUNTERS_BANK, m_physical_bank_shadow[physical_bank_index]);
}

// Physically counter's bank is 4K lines each line is 137b wide
// Read line returns 144b:
//   line[136:0]   - physical line from memory
//   line[143:137] - padding to full byte
//
// We support 2 types of counters:
//   64 bit counter (narrow counter) - in this mode each memory line have up to 2 counters
//     [63:0]    - first counter value
//     [127:64]  - seound counter value
//     [136:128] - ECC (error correction code)
//     in addition each narrow counter contains two separate sub-counters:
//       counter[28:0] used for packet counting
//       counter[63:29] used for byte counting
//
//   128 bit counter - in this mode each memory line have up to one counter
//     [127:0]   - counter value
//     [136:128] - ECC..
//     in this mode :
//       counter[63:0] used for packet counting
//       counter[127:64] used for byte counting
//
// Each bank fully can be allocated for only one type of counters (narrow or wide)
// So when we converting logical counter index to physical bank location
// we assume all counters in the bank as the given logical id counter
//
void
counter_logical_bank::get_shadow_indexes(size_t counter_index_in_logical_bank,
                                         size_t& bytes_counter_msb,
                                         size_t& bytes_counter_lsb,
                                         size_t& packets_counter_msb,
                                         size_t& packets_counter_lsb) const
{
    bool is_narrow_counter = m_device->get_counter_bank_type() == NPL_COUNTER_TYPE_PC29_BC35;
    constexpr size_t LINE_WIDTH = 144;
    size_t counters_per_line = is_narrow_counter ? 2 : 1;
    size_t counter_size = is_narrow_counter ? 64 : 128;
    size_t offset_in_physical_line = counter_size * (counter_index_in_logical_bank % counters_per_line);
    size_t offset_in_physical_bank = LINE_WIDTH * (counter_index_in_logical_bank / counters_per_line);

    size_t packets_counter_size = is_narrow_counter ? 29 : 64;
    size_t bytes_counter_size = is_narrow_counter ? 35 : 64;

    packets_counter_lsb = offset_in_physical_bank + offset_in_physical_line;
    packets_counter_msb = packets_counter_lsb + packets_counter_size - 1;
    bytes_counter_lsb = packets_counter_msb + 1;
    bytes_counter_msb = bytes_counter_lsb + bytes_counter_size - 1;
}

void
counter_logical_bank::clear_counter_shadow_entry(size_t ifg, size_t bank_id, size_t offset_in_bank)
{
    if (bank_id >= METER_BANK_BASE) {
        return;
    }

    size_t bytes_counter_msb = 0, bytes_counter_lsb = 0, packets_counter_msb = 0, packets_counter_lsb = 0;
    get_shadow_indexes(offset_in_bank, bytes_counter_msb, bytes_counter_lsb, packets_counter_msb, packets_counter_lsb);

    m_physical_bank_shadow[ifg].set_bits(bytes_counter_msb, packets_counter_lsb, 0);
}

void
counter_logical_bank::update_clear_bank_entry(size_t ifg, size_t bank_id, size_t offset_in_bank)
{
    if (bank_id >= METER_BANK_BASE) {
        return;
    }

    size_t bytes_counter_msb = 0, bytes_counter_lsb = 0, packets_counter_msb = 0, packets_counter_lsb = 0;
    get_shadow_indexes(offset_in_bank, bytes_counter_msb, bytes_counter_lsb, packets_counter_msb, packets_counter_lsb);
    bit_vector shadow_val = m_physical_bank_shadow[ifg].bits(bytes_counter_msb, packets_counter_lsb);

    m_last_clear_bank[ifg].set_bits(bytes_counter_msb, packets_counter_lsb, shadow_val);
}

la_status
counter_logical_bank::destroy()
{
    la_status status = erase_counters_block_config_table(m_first_slice, m_num_of_slices, m_first_index);
    return_on_error(status);

    if (is_user_type_allowed(counter_user_type_e::COUNTER_USER_TYPE_VOQ)) {
        return LA_STATUS_SUCCESS;
    }

    if (m_direction == counter_direction_e::COUNTER_DIRECTION_INGRESS) {
        status = erase_rx_counter_table(m_first_slice, m_num_of_slices, m_first_index);
    } else {
        status = erase_tx_counter_table(m_first_slice, m_num_of_slices, m_first_index);
    }

    return status;
}

la_status
counter_logical_bank::erase_counters_block_config_table(size_t first_slice, size_t num_of_slices, size_t first_index)
{
    const auto& table(m_device->m_tables.counters_block_config_table);
    npl_counters_block_config_table_key_t key;
    size_t index = first_index;

    for (la_slice_id_t slice = first_slice; slice < first_slice + num_of_slices; slice++) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            key.counter_bank_id = index;
            la_status status = table->erase(key);
            return_on_error(status);

            index++;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
counter_logical_bank::erase_rx_counter_table(size_t first_slice, size_t num_of_slices, size_t first_index)
{
    npl_rx_counters_block_config_table_key_t key;

    for (size_t bank_offset = 0; bank_offset < (num_of_slices * NUM_IFGS_PER_SLICE); bank_offset++) {
        key.counter_bank_id = first_index + bank_offset;
        const auto& table(m_device->m_tables.rx_counters_block_config_table);
        la_status status = table->erase(key);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
counter_logical_bank::erase_tx_counter_table(size_t first_slice, size_t num_of_slices, size_t first_index)
{
    npl_tx_counters_block_config_table_key_t key;
    for (size_t bank_offset = 0; bank_offset < (num_of_slices * NUM_IFGS_PER_SLICE); bank_offset++) {
        key.counter_bank_id = first_index + bank_offset;
        const auto& table(m_device->m_tables.tx_counters_block_config_table);
        la_status status = table->erase(key);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

size_t
counter_logical_bank::get_user_type_encoding()
{
    if (is_user_type_allowed(counter_user_type_e::COUNTER_USER_TYPE_VOQ)) {
        return BANK_USER_VOQ;
    }

    if (m_direction == counter_direction_e::COUNTER_DIRECTION_INGRESS) {
        return BANK_USER_RX;
    }

    return BANK_USER_TX;
}

size_t
counter_logical_bank::get_npl_byte_count_compensation(counter_direction_e direction) const
{
    // CRC header is stripped in MAC port, so it is not included in the packet size.
    return direction == counter_direction_e::COUNTER_DIRECTION_INGRESS
               ? la_device_impl::NPU_HEADER_SIZE - la_device_impl::CRC_HEADER_SIZE
               : 0;
}

bool
counter_logical_bank::allocate(const counter_allocation& allocation, counter_user_type_e user_type, size_t& out_base_row_index)
{
    const size_t INVALID_INDEX = (size_t)-1;
    size_t base_logical_index = INVALID_INDEX;
    size_t set_size = 0;

    for (size_t logical_row_index = 0; logical_row_index < m_num_logical_rows_in_bank; logical_row_index++) {
        if (!is_free_entries_in_row(logical_row_index, allocation)) {
            base_logical_index = INVALID_INDEX;
            continue;
        }

        if (base_logical_index == INVALID_INDEX) {
            base_logical_index = logical_row_index;
            set_size = 1;
        } else {
            set_size++;
        }

        if (set_size == allocation.set_size) {
            for (size_t i = 0; i < allocation.set_size; i++) {
                size_t logical_index = base_logical_index + i;
                enable_phys_counters(logical_index, user_type, allocation);
            }

            // Allocation holds logical row
            out_base_row_index = base_logical_index;

            return true;
        }
    }

    return false;
}

size_t
counter_logical_bank::get_first_ifg(const counter_allocation& allocation)
{
    size_t first_ifg;

    switch (allocation.num_of_ifgs) {
    case 1:
        first_ifg = (allocation.ifg.slice - m_first_slice) * NUM_IFGS_PER_SLICE + allocation.ifg.ifg;
        break;
    case 2:
        first_ifg = (allocation.ifg.slice - m_first_slice) * NUM_IFGS_PER_SLICE;
        break;
    default: // 4
        first_ifg = 0;
        break;
    }

    return first_ifg;
}

bool
counter_logical_bank::is_free_entries_in_row(size_t logical_row_index, const counter_allocation& allocation)
{
    bool is_free = true;
    size_t first_ifg = get_first_ifg(allocation);
    size_t phys_row_index = logical_row_index * phys_per_logical();
    // a logical row is a series of physical rows, all of them are either busy or free.
    // therefore, it's enough to check the first phys row in the set of logical rows
    phys_entry_row_t& phys_row(m_phys_entries[phys_row_index]);

    for (size_t i = first_ifg; i < (first_ifg + allocation.num_of_ifgs); i++) {
        if (phys_row[i].is_enabled) {
            is_free = false;
            break;
        }
    }

    return is_free;
}

void
counter_logical_bank::enable_phys_counters(size_t logical_row_index,
                                           counter_user_type_e user_type,
                                           const counter_allocation& allocation)
{
    const size_t ppl = phys_per_logical();
    size_t first_ifg = get_first_ifg(allocation);
    size_t phys_row_index = logical_row_index * ppl;

    for (size_t j = phys_row_index; j < phys_row_index + ppl; j++) {
        phys_entry_row_t& phys_row(m_phys_entries[j]);

        for (size_t i = first_ifg; i < (first_ifg + allocation.num_of_ifgs); i++) {
            phys_row[i].enable();
            m_num_of_busy_phys_entries++;
            m_num_allocated_entries[i][user_type]++;
        }
    }
}

void
counter_logical_bank::release(counter_user_type_e user_type, const counter_allocation& allocation)
{
    const size_t ppl = phys_per_logical();
    size_t first_ifg = get_first_ifg(allocation);

    for (size_t i = 0; i < allocation.set_size; i++) {
        size_t logical_row_index = allocation.base_row_index + i;
        size_t phys_row_index = logical_row_index * ppl;

        for (size_t j = phys_row_index; j < phys_row_index + ppl; j++) {
            phys_entry_row_t& phys_row(m_phys_entries[j]);
            for (size_t col_index = first_ifg; col_index < (first_ifg + allocation.num_of_ifgs); col_index++) {
                phys_row[col_index].disable();
                m_num_of_busy_phys_entries--;
                m_num_allocated_entries[col_index][user_type]--;
            }
        }
    }
}

void
counter_logical_bank::do_read_ifg(const counter_allocation& allocation,
                                  la_slice_ifg ifg,
                                  size_t sub_counter_index,
                                  size_t phys_row,
                                  bool force_update,
                                  bool clear_on_read,
                                  size_t& out_bytes,
                                  size_t& out_packets)
{
    size_t gifg = ifg.slice * NUM_IFGS_PER_SLICE + ifg.ifg;
    size_t column = gifg - (m_first_slice * NUM_IFGS_PER_SLICE);
    size_t first_ifg = get_first_ifg(allocation);
    size_t shadow_bank_idx = column - first_ifg;

    if (column >= allocation.num_of_ifgs) {
        // if the given allocation doesn't cover the given ifg then return immediately.
        // size_t is unsigned so negative column is represented as a large integer
        out_bytes = 0;
        out_packets = 0;
        return;
    }

    phys_entry_row_t& phys_entry_row(m_phys_entries[phys_row]);
    auto counters_shadow_age_out = m_device->get_counter_shadow_duration_until_age_out();

    if (counters_shadow_age_out.count() != 0) {
        auto time_since_last_update = std::chrono::steady_clock::now() - m_last_shadow_update;
        if (time_since_last_update >= counters_shadow_age_out) {
            for (size_t i = first_ifg; i < (first_ifg + allocation.num_of_ifgs); ++i) {
                physical_bank_entry& phys_counter(phys_entry_row[i]);
                update_shadow(i - first_ifg, phys_counter.m_counter_address.c.bank_id);
            }
            m_last_shadow_update = std::chrono::steady_clock::now();
        }
    }

    physical_bank_entry& phys_counter(phys_entry_row[column]);

    size_t offset_in_bank = phys_counter.m_counter_address.c.offset_in_bank;
    size_t bank_id = phys_counter.m_counter_address.c.bank_id;

    size_t bytes_counter_msb = 0, bytes_counter_lsb = 0, packets_counter_msb = 0, packets_counter_lsb = 0;
    get_shadow_indexes(offset_in_bank, bytes_counter_msb, bytes_counter_lsb, packets_counter_msb, packets_counter_lsb);

    phys_counter.read(force_update, clear_on_read, out_bytes, out_packets);

    if (force_update) {
        clear_counter_shadow_entry(shadow_bank_idx, bank_id, offset_in_bank);
    }

    out_bytes += m_physical_bank_shadow[shadow_bank_idx].bits(bytes_counter_msb, bytes_counter_lsb).get_value();
    out_packets += m_physical_bank_shadow[shadow_bank_idx].bits(packets_counter_msb, packets_counter_lsb).get_value();

    out_bytes -= m_last_clear_bank[shadow_bank_idx].bits(bytes_counter_msb, bytes_counter_lsb).get_value();
    out_packets -= m_last_clear_bank[shadow_bank_idx].bits(packets_counter_msb, packets_counter_lsb).get_value();

    if (clear_on_read) {
        update_clear_bank_entry(shadow_bank_idx, bank_id, offset_in_bank);
    }
}

void
counter_logical_bank::read_meter_ifg(const counter_allocation& allocation,
                                     la_slice_ifg ifg,
                                     size_t sub_counter_index,
                                     la_qos_color_e color,
                                     size_t& out_bytes,
                                     size_t& out_packets)
{
    if (!is_user_type_meter()) {
        log_err(COUNTERS, "counter_logical_bank::%s: Attempt to read a counter using meter read API", __func__);
        return;
    }

    size_t phys_row = get_phys_row(allocation, sub_counter_index, color);
    do_read_ifg(
        allocation, ifg, sub_counter_index, phys_row, true /* force_update */, false /* clear_on_read */, out_bytes, out_packets);
}

void
counter_logical_bank::read_counter_ifg(const counter_allocation& allocation,
                                       la_slice_ifg ifg,
                                       size_t sub_counter_index,
                                       bool force_update,
                                       bool clear_on_read,
                                       size_t& out_bytes,
                                       size_t& out_packets)
{
    if (is_user_type_meter()) {
        log_err(COUNTERS, "counter_logical_bank::%s: Attempt to read a meter using counter read API", __func__);
        return;
    }

    size_t phys_row = get_phys_row(allocation, sub_counter_index);
    do_read_ifg(allocation, ifg, sub_counter_index, phys_row, force_update, clear_on_read, out_bytes, out_packets);
}

void
counter_logical_bank::do_read(const counter_allocation& allocation,
                              size_t phys_row,
                              bool force_update,
                              bool clear_on_read,
                              uint64_t& out_bytes,
                              uint64_t& out_packets)
{
    size_t first_ifg = get_first_ifg(allocation);
    phys_entry_row_t& phys_entry_row(m_phys_entries[phys_row]);
    size_t total_bytes = 0;
    size_t total_packets = 0;

    auto counters_shadow_age_out = m_device->get_counter_shadow_duration_until_age_out();

    if (counters_shadow_age_out.count() != 0) {
        auto time_since_last_update = std::chrono::steady_clock::now() - m_last_shadow_update;
        if (time_since_last_update >= counters_shadow_age_out) {
            for (size_t i = first_ifg; i < (first_ifg + allocation.num_of_ifgs); ++i) {
                physical_bank_entry& phys_counter(phys_entry_row[i]);
                update_shadow(i - first_ifg, phys_counter.m_counter_address.c.bank_id);
            }
            m_last_shadow_update = std::chrono::steady_clock::now();
        }
    }

    for (size_t i = first_ifg; i < (first_ifg + allocation.num_of_ifgs); i++) {
        physical_bank_entry& phys_counter = phys_entry_row[i];
        size_t bytes = 0;
        size_t packets = 0;

        size_t offset_in_bank = phys_counter.m_counter_address.c.offset_in_bank;
        size_t bank_id = phys_counter.m_counter_address.c.bank_id;

        size_t bytes_counter_msb = 0, bytes_counter_lsb = 0, packets_counter_msb = 0, packets_counter_lsb = 0;
        get_shadow_indexes(offset_in_bank, bytes_counter_msb, bytes_counter_lsb, packets_counter_msb, packets_counter_lsb);

        phys_counter.read(force_update, clear_on_read, bytes, packets);
        if (force_update) {
            clear_counter_shadow_entry(i - first_ifg, bank_id, offset_in_bank);
        }

        bytes += m_physical_bank_shadow[i - first_ifg].bits(bytes_counter_msb, bytes_counter_lsb).get_value();
        packets += m_physical_bank_shadow[i - first_ifg].bits(packets_counter_msb, packets_counter_lsb).get_value();

        bytes -= m_last_clear_bank[i - first_ifg].bits(bytes_counter_msb, bytes_counter_lsb).get_value();
        packets -= m_last_clear_bank[i - first_ifg].bits(packets_counter_msb, packets_counter_lsb).get_value();

        if (clear_on_read) {
            update_clear_bank_entry(i - first_ifg, bank_id, offset_in_bank);
        }

        total_bytes += bytes;
        total_packets += packets;
    }

    out_bytes = total_bytes;
    out_packets = total_packets;
}

void
counter_logical_bank::read_counter(const counter_allocation& allocation,
                                   size_t sub_counter_index,
                                   bool force_update,
                                   bool clear_on_read,
                                   size_t& out_bytes,
                                   size_t& out_packets)
{
    if (is_user_type_meter()) {
        log_err(COUNTERS, "counter_logical_bank::%s: Attempt to read a meter using counter read API", __func__);
        return;
    }

    size_t phys_row = allocation.base_row_index * phys_per_logical() + sub_counter_index;
    do_read(allocation, phys_row, force_update, clear_on_read, out_bytes, out_packets);
}

void
counter_logical_bank::read_meter(const counter_allocation& allocation,
                                 size_t sub_counter_index,
                                 la_qos_color_e color,
                                 bool force_update,
                                 bool clear_on_read,
                                 uint64_t& out_bytes,
                                 uint64_t& out_packets)
{
    if (!is_user_type_meter()) {
        log_err(COUNTERS, "counter_logical_bank::%s: Attempt to read a counter using meter read API", __func__);
        return;
    }

    size_t phys_base_row = (allocation.base_row_index + sub_counter_index) * phys_per_logical();
    size_t phys_row = phys_base_row + (size_t)color;

    do_read(allocation, phys_row, force_update, clear_on_read, out_bytes, out_packets);
}

void
counter_logical_bank::add(size_t slice, la_ifg_id_t ifg, size_t phys_row_index, size_t bytes, size_t packets)
{
    if (phys_row_index >= m_num_physical_rows_in_bank) {
        log_err(COUNTERS,
                "counter_logical_bank::%s: Attempt to set a counter using "
                "invalid phy_row_index:%lu, max_row_index:%lu, slice:%lu, ifg:%u",
                __func__,
                phys_row_index,
                m_num_physical_rows_in_bank,
                slice,
                ifg);
        return;
    }

    phys_entry_row_t& phys_entry_row(m_phys_entries[phys_row_index]);
    physical_bank_entry& phys_counter(phys_entry_row[(slice - m_first_slice) * NUM_IFGS_PER_SLICE + ifg]);
    phys_counter.add(bytes, packets);
}

bool
counter_logical_bank::is_empty() const
{
    return m_num_of_busy_phys_entries == 0;
}

size_t
counter_logical_bank::get_first_index() const
{
    return m_first_index;
}

size_t
counter_logical_bank::get_first_slice() const
{
    return m_first_slice;
}

size_t
counter_logical_bank::get_num_of_slices() const
{
    return m_num_of_slices;
}

const counter_user_group_bitset&
counter_logical_bank::get_allowed_user_types() const
{
    return m_allowed_user_types;
}

bool
counter_logical_bank::is_user_type_meter() const
{
    // Meter counters don't share the bank with other users.
    return is_user_type_allowed(COUNTER_USER_TYPE_METER);
}

bool
counter_logical_bank::is_user_type_global() const
{
    // Check for global user.
    return is_user_type_allowed(COUNTER_USER_TYPE_SECURITY_GROUP_CELL);
}

bool
counter_logical_bank::is_user_type_allowed(counter_user_type_e user_type) const
{
    return m_allowed_user_types.test(user_type);
}

counter_direction_e
counter_logical_bank::get_direction() const
{
    return m_direction;
}

size_t
counter_logical_bank::phys_per_logical() const
{
    return (is_user_type_meter()) ? la_meter_set::NUM_COLOR_AWARE_GAUGES : 1;
}

size_t
counter_logical_bank::get_phys_row(const counter_allocation& allocation, size_t sub_counter_index) const
{
    size_t phys_row = allocation.base_row_index * phys_per_logical() + sub_counter_index;

    return phys_row;
}

size_t
counter_logical_bank::get_phys_row(const counter_allocation& allocation, size_t sub_counter_index, la_qos_color_e color) const
{
    size_t phys_base_row = (allocation.base_row_index + sub_counter_index) * phys_per_logical();
    size_t phys_row = phys_base_row + (size_t)color;

    return phys_row;
}

const vector_alloc<std::array<size_t, COUNTER_USER_TYPE_NUM> >&
counter_logical_bank::size() const
{
    return m_num_allocated_entries;
}

size_t
counter_logical_bank::num_of_allocated_counters_for_user(counter_user_type_e user_type) const
{
    size_t num_of_allocated_counters = 0;
    const auto num_of_phys_banks = m_num_allocated_entries.size();
    for (size_t phys_bank = 0; phys_bank < num_of_phys_banks; phys_bank++) {
        num_of_allocated_counters += m_num_allocated_entries[phys_bank][user_type];
    }

    return num_of_allocated_counters;
}

size_t
counter_logical_bank::max_size() const
{
    // m_phys_entries is a two-dimensional vector of size m_num_physical_rows_in_bank * row_width.
    size_t max_size = m_phys_entries.size() * m_phys_entries[0].size();
    return max_size;
}

std::string
counter_logical_bank::to_string() const
{
    std::stringstream allowed_user_types;
    auto temp_allowed_user_types = m_allowed_user_types;
    bool is_first = true;
    for (size_t i = 0; temp_allowed_user_types.any(); i++) {
        if (temp_allowed_user_types[0]) {
            auto user_type = (counter_user_type_e)i;
            if (is_first) {
                is_first = false;
            } else {
                allowed_user_types << ",";
            }
            allowed_user_types << silicon_one::to_string(user_type);
        }
        temp_allowed_user_types >>= 1;
    }

    std::stringstream s;
    s << "first_index=" << m_first_index;
    s << " first_slice=" << m_first_slice;
    s << " allowed_user_types=[" << allowed_user_types.str() << "]";
    s << " direction=" << silicon_one::to_string(m_direction);
    s << " num_of_slices=" << m_num_of_slices;
    s << " num_of_busy_phys_entries=" << m_num_of_busy_phys_entries;
    s << " num_logical_rows_in_bank=" << m_num_logical_rows_in_bank;
    s << " num_physical_rows_in_bank=" << m_num_physical_rows_in_bank;
    s << " num_allocated_entries=[ ";
    for (size_t phys_bank = 0; phys_bank < m_num_of_slices * NUM_IFGS_PER_SLICE; phys_bank++) {
        s << "bank" << m_first_index + phys_bank << "{";
        for (size_t user_type_int = 0; user_type_int < COUNTER_USER_TYPE_LAST; user_type_int++) {
            auto user_type = (counter_user_type_e)user_type_int;
            if (user_type_int > 0) {
                s << ",";
            }
            s << silicon_one::to_string(user_type);
            s << ":";
            s << m_num_allocated_entries[phys_bank][user_type_int];
        }
        s << "} ";
    }
    s << "]";

    return s.str();
}

} // namespace silicon_one
