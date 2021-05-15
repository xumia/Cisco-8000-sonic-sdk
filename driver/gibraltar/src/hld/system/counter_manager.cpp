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

#include <algorithm>

#include "api/types/la_status_info_types.h"
#include "common/defines.h"
#include "common/gen_operators.h"
#include "common/la_status.h"
#include "common/resource_monitor.h"
#include "counter_manager.h"
#include "hld_types.h"
#include "hld_utils.h"
#include "lld/gibraltar_mem_structs.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "system/counter_bank_utils.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

counter_manager::counter_manager(const la_device_impl_wptr& device)
    : m_device(device), m_busy_phys_banks(0), m_resource_monitor(nullptr)
{
    for (size_t i = 0; i < array_size(m_mcg_bank_profiles); i++) {
        for (size_t j = 0; j < array_size(m_mcg_bank_profiles[i]); j++) {
            m_mcg_bank_profiles[i][j] = (size_t)-1;
        }
    }
}

counter_manager::~counter_manager()
{
}

la_status
counter_manager::initialize()
{
    la_status status = initialize_counters_bank_id_map_config();
    return_on_error(status);
    status = initialize_meter_offset_bank_map();
    return status;
}

la_status
counter_manager::allocate(bool is_slice_pair,
                          counter_direction_e direction,
                          size_t set_size,
                          la_slice_ifg ifg,
                          size_t num_of_ifgs,
                          counter_user_type_e user_type,
                          counter_allocation& out_counter_allocation)
{
    counter_allocation allocation(set_size, ifg, num_of_ifgs);

    la_status status = do_allocate(is_slice_pair, direction, user_type, allocation);
    return_on_error(status);

    out_counter_allocation = allocation;

    return LA_STATUS_SUCCESS;
}

void
counter_manager::release(counter_user_type_e user_type, const counter_allocation& allocation)
{
    const auto& bank = allocation.bank;

    bank->release(user_type, allocation);

    if (user_type == COUNTER_USER_TYPE_MCG) {
        size_t num_of_mcg_counters = bank->num_of_allocated_counters_for_user(user_type);

        if (num_of_mcg_counters == 0) {
            size_t first_index = bank->get_first_index();
            la_status status = remove_bank_from_mcg_bank_profiles(first_index, allocation.ifg.slice);
            dassert_crit(status == LA_STATUS_SUCCESS);
        }
    }

    if (bank->is_empty()) {
        release_bank(bank);
    }
}

void
counter_manager::read_counter(const counter_allocation& allocation,
                              size_t sub_counter_index,
                              bool force_update,
                              bool clear_on_read,
                              size_t& out_bytes_count,
                              size_t& out_packet_count)
{
    allocation.bank->read_counter(allocation, sub_counter_index, force_update, clear_on_read, out_bytes_count, out_packet_count);
}

void
counter_manager::read_counter_ifg(const counter_allocation& allocation,
                                  la_slice_ifg ifg,
                                  size_t sub_counter_index,
                                  bool force_update,
                                  bool clear_on_read,
                                  size_t& out_bytes_count,
                                  size_t& out_packet_count)
{
    allocation.bank->read_counter_ifg(
        allocation, ifg, sub_counter_index, force_update, clear_on_read, out_bytes_count, out_packet_count);
}

void
counter_manager::read_meter(const counter_allocation& allocation,
                            size_t sub_counter_index,
                            la_qos_color_e color,
                            bool force_update,
                            bool clear_on_read,
                            uint64_t& out_bytes_count,
                            uint64_t& out_packet_count)
{
    allocation.bank->read_meter(
        allocation, sub_counter_index, color, force_update, clear_on_read, out_bytes_count, out_packet_count);
}

void
counter_manager::read_meter_ifg(const counter_allocation& allocation,
                                la_slice_ifg ifg,
                                size_t sub_counter_index,
                                la_qos_color_e color,
                                uint64_t& out_bytes_count,
                                uint64_t& out_packet_count)
{
    allocation.bank->read_meter_ifg(allocation, ifg, sub_counter_index, color, out_bytes_count, out_packet_count);
}

void
counter_manager::get_counter_user_group(counter_user_type_e user_type,
                                        counter_direction_e direction,
                                        counter_user_group_vec& out_user_group)
{
    for (auto& user_group : counter_user_groups[direction]) {
        auto found = std::find(user_group.begin(), user_group.end(), user_type);
        if (found != user_group.end()) {
            out_user_group = user_group;
            return;
        }
    }
}

bool
counter_manager::check_bank_match(const counter_logical_bank_wcptr& bank,
                                  bool is_slice_pair,
                                  la_slice_id_t slice,
                                  counter_direction_e direction,
                                  counter_user_type_e user_type)
{
    size_t num_of_slices = is_slice_pair ? 2 : 1;
    bool match = ((bank->get_num_of_slices() == num_of_slices) && (bank->get_direction() == direction)
                  && (bank->is_user_type_allowed(user_type)));

    if (!match) {
        return false;
    }

    size_t first_slice = bank->get_first_slice();
    size_t last_slice = first_slice + bank->get_num_of_slices() - 1;

    return (slice >= first_slice && slice <= last_slice);
}

bool
counter_manager::is_meter_bank_user(counter_direction_e direction, counter_user_type_e type)
{
    if ((type == COUNTER_USER_TYPE_METER) || (type == COUNTER_USER_TYPE_QOS && direction == COUNTER_DIRECTION_INGRESS)) {
        return true;
    }
    return false;
}

counter_logical_bank_wptr
counter_manager::get_new_bank(bool is_slice_pair, la_slice_id_t slice, counter_direction_e direction, counter_user_type_e user_type)
{
    size_t first_slice = is_slice_pair ? slice & ~0x1 : slice;
    size_t num_of_required_phys_banks = is_slice_pair ? 4 : 2;

    size_t range_begin, range_end;
    if (!is_meter_bank_user(direction, user_type)) {
        range_begin = COUNTER_BANK_BASE;
        range_end = METER_BANK_BASE;
    } else {
        // la_meter_profile and la_meter_action_profile attached to a la_meter_set must be on the
        // same bank# as the meter. but the current implementation of the profiles is looking at IFG#
        // instead of the bank#, hence the static mapping.
        // TODO In LC mode, this implementation statically allocates banks to fabric IFGs which don't use
        // them, which can be improved.
        range_begin = METER_BANK_BASE + first_slice * NUM_IFGS_PER_SLICE;
        range_end = range_begin + num_of_required_phys_banks;
    }

    if (user_type == COUNTER_USER_TYPE_MCG) {
        bool can_allocate_new_mcg_bank = false;

        for (size_t mcg_bank_index = 0; mcg_bank_index < NUM_MCG_BANK_PROFILES_PER_SLICE; mcg_bank_index++) {
            if (m_mcg_bank_profiles[slice][mcg_bank_index] == (size_t)-1) {
                can_allocate_new_mcg_bank = true;
                break;
            }
        }

        if (!can_allocate_new_mcg_bank) {
            return nullptr;
        }
    }

    bool found = false;
    size_t first_free_bank = (size_t)-1;

    // Look for 'num_of_required_phys_banks' free indices, starting with an index that is assigned to 'first_slice'
    size_t i = range_begin;
    while (!found && (i < range_end)) {
        if (!m_busy_phys_banks[i]) {
            size_t j = i + 1;
            size_t num_of_free_banks = 1;

            while (!found && (j < range_end)) {
                if (!m_busy_phys_banks[j]) {
                    // Next num_of_required_phys_banks-1 banks should be free
                    num_of_free_banks++;
                } else {
                    // Else we can't use this block
                    break;
                }
                if (num_of_free_banks == num_of_required_phys_banks) {
                    found = true;
                    first_free_bank = i;
                }
                j++;
            }
        }
        i += num_of_required_phys_banks;
    }

    if (!found) {
        return nullptr;
    }

    // Create a new logical bank starting at first-free-bank that was found above, spanning num-of-required-phys-banks
    counter_user_group_vec user_group;
    get_counter_user_group(user_type, direction, user_group);
    dassert_crit(!user_group.empty(), "Unsupported counter user type %s", silicon_one::to_string(user_type).c_str());

    // use 'new' instead of make_shared because counter_logical_bank ctor is private
    auto new_bank_raw = new counter_logical_bank(m_device, first_free_bank, first_slice, is_slice_pair, direction, user_group);
    auto new_bank = counter_logical_bank_sptr(new_bank_raw);
    la_status status = new_bank->initialize();
    if (status != LA_STATUS_SUCCESS) {
        return nullptr;
    }

    // Mark the newly used physical banks as busy
    for (size_t j = first_free_bank; j < first_free_bank + num_of_required_phys_banks; j++) {
        m_busy_phys_banks[j] = 1;
        m_banks[j] = new_bank;
    }

    // Add the bank to the list
    m_logical_banks.insert(new_bank);

    // Update resource_monitor for bank allocation
    if (m_resource_monitor != nullptr) {
        size_t current_size = size();
        m_resource_monitor->update_size(current_size);
    }

    log_debug(COUNTERS, "%s: %s", __func__, new_bank->to_string().c_str());
    return new_bank;
}

void
counter_manager::release_bank(const counter_logical_bank_wptr& bank)
{
    log_debug(COUNTERS, "%s: %s", __func__, bank->to_string().c_str());
    // Find which physical banks were used by the to-be-removed logical bank
    size_t first_index = bank->get_first_index();
    size_t phys_banks_nr = bank->get_num_of_slices() * NUM_IFGS_PER_SLICE;

    // Release the logical bank
    la_status status = bank->destroy();
    if (status != LA_STATUS_SUCCESS) {
        log_warning(COUNTERS, "%s: bank destroy failed %s", __func__, la_status2str(status).c_str());
        return;
    }

    // Remove from the list
    m_logical_banks.erase(bank);

    // Mark the newly released physical banks as free
    for (size_t i = first_index; i < first_index + phys_banks_nr; i++) {
        m_busy_phys_banks[i] = 0;
        m_banks[i] = nullptr;
    }

    // Update resource_monitor for bank release
    if (m_resource_monitor != nullptr) {
        size_t current_size = size();
        m_resource_monitor->update_size(current_size);
    }
}

bool
counter_manager::bank_allocate(const counter_logical_bank_wptr& bank,
                               counter_user_type_e user_type,
                               counter_allocation& in_out_allocation)
{
    bool is_success = bank->allocate(in_out_allocation, user_type, in_out_allocation.base_row_index);
    if (is_success) {
        size_t first_index = bank->get_first_index();
        if (user_type == COUNTER_USER_TYPE_MCG) {
            la_status status = add_bank_to_mcg_bank_profiles(first_index, in_out_allocation.ifg.slice);
            if (status != LA_STATUS_SUCCESS) {
                bank->release(user_type, in_out_allocation);
                return false;
            }
        }

        in_out_allocation.bank = bank;
        in_out_allocation.phys_bank_index = first_index;
    }

    return is_success;
}

la_status
counter_manager::do_allocate(bool is_slice_pair,
                             counter_direction_e direction,
                             counter_user_type_e user_type,
                             counter_allocation& in_out_allocation)
{
    // Look for a bank that matches the allocation request
    for (const auto& bank : m_logical_banks) {
        bool is_match = check_bank_match(bank, is_slice_pair, in_out_allocation.ifg.slice, direction, user_type);

        if (!is_match) {
            continue;
        }

        bool is_success = bank_allocate(bank, user_type, in_out_allocation);
        if (is_success) {
            return LA_STATUS_SUCCESS;
        }
    }

    // Allocate a new bank
    auto bank = get_new_bank(is_slice_pair, in_out_allocation.ifg.slice, direction, user_type);
    if (bank == nullptr) {
        return create_e_resource_status_with_counter_info(user_type, in_out_allocation.ifg.slice, in_out_allocation.ifg.ifg);
    }

    // The new bank can surely accomodate the allocation
    bool is_success = bank_allocate(bank, user_type, in_out_allocation);
    if (!is_success) {
        return LA_STATUS_EUNKNOWN; // Shouldn't happen
    }

    return LA_STATUS_SUCCESS;
}

size_t
counter_manager::size() const
{
    return m_busy_phys_banks.count();
}

size_t
counter_manager::max_size() const
{
    return NUM_OF_BANKS;
}

void
counter_manager::set_resource_monitor(const resource_monitor_sptr& monitor)
{
    m_resource_monitor = monitor;
}

void
counter_manager::get_resource_monitor(resource_monitor_sptr& out_monitor)
{
    out_monitor = m_resource_monitor;
}

size_t
counter_manager::get_num_of_network_slices()
{
    size_t num_of_network_slices = 0;
    for (la_slice_id_t index : m_device->get_used_slices()) {
        la_slice_mode_e mode;
        m_device->get_slice_mode(index, mode);
        if (is_network_slice(mode)) {
            num_of_network_slices++;
        }
    }
    return num_of_network_slices;
}

const la_device*
counter_manager::get_device() const
{
    return m_device.get();
}

la_status
counter_manager::refresh_max_counters()
{
    // Lock to protect against counter set api calls that change the counters caches.
    std::lock_guard<std::recursive_mutex> lock(m_device->m_mutex);

    counter_bank_utils::dispatch_read_counter_command(m_device, MAX_COUNTER_READ, 0 /* Don't care */);

    gibraltar::counters_max_counters_table_memory max_counter;
    for (size_t bank_phy_id = 0; bank_phy_id < NUM_OF_BANKS; bank_phy_id++) {
        la_status status
            = m_device->m_ll_device->read_memory(m_device->m_gb_tree->counters->top->max_counters_table, bank_phy_id, max_counter);
        return_on_error(status);

        // bank with max counter zero must be avoided as it may be a non-allocated HW bank
        if (max_counter.fields.packet_count == 0 && max_counter.fields.byte_count == 0) {
            continue;
        }

        const size_t PACKET_COUNT_MAX_VAL
            = bit_utils::ones(gibraltar::counters_max_counters_table_memory::fields::PACKET_COUNT_WIDTH);
        const size_t BYTE_COUNT_MAX_VAL = bit_utils::ones(gibraltar::counters_max_counters_table_memory::fields::BYTE_COUNT_WIDTH);
        if (max_counter.fields.packet_count == PACKET_COUNT_MAX_VAL || max_counter.fields.byte_count == BYTE_COUNT_MAX_VAL) {
            log_err(COUNTERS,
                    "Counter wrap-around: bank_phy_id=%ld max_counter=%ld packet_count=%ld byte_count=%ld",
                    bank_phy_id,
                    max_counter.fields.counter_address,
                    max_counter.fields.packet_count,
                    max_counter.fields.byte_count);
        }

        auto bank = m_banks[bank_phy_id];
        if (bank == nullptr) {
            log_err(COUNTERS, "no valid logical bank found for this bank_phy_id=%ld", bank_phy_id);
            continue;
        }

        size_t slice = bank->get_first_slice() + (bank_phy_id - bank->get_first_index()) / NUM_IFGS_PER_SLICE;
        size_t ifg = (bank_phy_id - bank->get_first_index()) % NUM_IFGS_PER_SLICE;
        bank->add(slice, ifg, max_counter.fields.counter_address, max_counter.fields.byte_count, max_counter.fields.packet_count);

        // Clear memory shadow
        if (bank_phy_id < METER_BANK_BASE) {
            bank->clear_counter_shadow_entry(ifg, bank_phy_id, max_counter.fields.counter_address);
        }
    }

    return LA_STATUS_SUCCESS;
}

// Per request from HW team, we will initialize counters and meters bank offset maps with same values.
la_status
counter_manager::initialize_counters_bank_id_map_config()
{
    la_status status;
    const size_t stat_meter_bank_base = counter_manager::NUM_OF_BANKS;

    npl_tx_counters_bank_id_map_config_key_t tx_k;
    npl_tx_counters_bank_id_map_config_value_t tx_v;
    npl_tx_counters_bank_id_map_config_entry_t* tx_dummy_entry = nullptr;
    npl_rx_counters_bank_id_map_config_key_t rx_k;
    npl_rx_counters_bank_id_map_config_value_t rx_v;
    npl_rx_counters_bank_id_map_config_entry_t* rx_dummy_entry = nullptr;

    for (la_slice_id_t slice : m_device->get_used_slices()) {
        for (size_t npu_bank_id = 0; npu_bank_id < counter_manager::NUM_OF_BANKS / 2; npu_bank_id++) {
            for (size_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {

                tx_k.npu_bank_id = npu_bank_id;
                tx_k.ifg = ifg;
                tx_v.payloads.counter_bank_id = npu_bank_id_to_counter_bank_id(npu_bank_id, slice, ifg);
                tx_v.action = NPL_TX_COUNTERS_BANK_ID_MAP_CONFIG_ACTION_WRITE;
                status = m_device->m_tables.tx_counters_bank_id_map_config[slice]->insert(tx_k, tx_v, tx_dummy_entry);
                return_on_error(status);

                rx_k.npu_bank_id = tx_k.npu_bank_id;
                rx_k.ifg = tx_k.ifg;
                rx_v.payloads.counter_bank_id = tx_v.payloads.counter_bank_id;
                rx_v.action = NPL_RX_COUNTERS_BANK_ID_MAP_CONFIG_ACTION_WRITE;
                status = m_device->m_tables.rx_counters_bank_id_map_config[slice]->insert(rx_k, rx_v, rx_dummy_entry);
                return_on_error(status);
            }
        }
    }

    /* For mapping compact bank ids to statistical meter bank offsets we use a different approach.
    /   |      key     |   payload     |
    /   +--------------+---------------+
    /   | bank_id, ifg | final_bank_id |
    /   +--------------+---------------+
    /   |    {54, 0}   |      108      |
    /   |    {54, 1}   |      108      |
    /   |      ...     |               |
    /   |    {57, 0}   |      111      |
    /   |    {57, 1}   |      111      |
    /   +--------------+---------------+
     */
    for (la_slice_id_t slice : m_device->get_used_slices()) {
        for (size_t i = 0; i < NUM_STATISTICAL_METER_BANKS; i++) {
            for (size_t j = 0; j < NUM_IFGS_PER_SLICE; j++) {
                tx_k.npu_bank_id = stat_meter_bank_base / 2 + i;
                tx_k.ifg = j;
                tx_v.payloads.counter_bank_id = stat_meter_bank_base + i;
                status = m_device->m_tables.tx_counters_bank_id_map_config[slice]->insert(tx_k, tx_v, tx_dummy_entry);
                return_on_error(status);

                rx_k.npu_bank_id = stat_meter_bank_base / 2 + i;
                rx_k.ifg = j;
                rx_v.payloads.counter_bank_id = stat_meter_bank_base + i;
                status = m_device->m_tables.rx_counters_bank_id_map_config[slice]->insert(rx_k, rx_v, rx_dummy_entry);
                return_on_error(status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

// Per request from HW team, we will initialize counters and meters bank offset maps with same values.
la_status
counter_manager::initialize_meter_offset_bank_map()
{
    la_status status;
    const size_t stat_meter_bank_base = counter_manager::NUM_OF_BANKS;

    npl_rx_meter_bank_offset_map_key_t k;
    npl_rx_meter_bank_offset_map_value_t v;
    npl_rx_meter_bank_offset_map_entry_t* dummy_entry = nullptr;

    v.action = NPL_RX_METER_BANK_OFFSET_MAP_ACTION_WRITE;

    for (size_t slice : m_device->get_used_slices()) {
        for (size_t npu_bank_id = 0; npu_bank_id < counter_manager::NUM_OF_BANKS / 2; npu_bank_id++) {
            for (size_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
                k.npu_bank_id = npu_bank_id;
                k.ifg = ifg;
                v.payloads.counter_bank_id = npu_bank_id_to_counter_bank_id(npu_bank_id, slice, ifg);
                status = m_device->m_tables.rx_meter_bank_offset_map[slice]->insert(k, v, dummy_entry);
                return_on_error(status);
            }
        }
    }

    /* For mapping compact bank ids to statistical meter bank offsets we use a different approach.
    /   |      key     |   payload     |
    /   +--------------+---------------+
    /   | bank_id, ifg | final_bank_id |
    /   +--------------+---------------+
    /   |    {54, 0}   |      108      |
    /   |    {54, 1}   |      108      |
    /   |      ...     |               |
    /   |    {57, 0}   |      111      |
    /   |    {57, 1}   |      111      |
    /   +--------------+---------------+
     */

    for (la_slice_ifg ifg_id : m_device->get_used_ifgs()) {
        for (size_t i = 0; i < NUM_STATISTICAL_METER_BANKS; i++) {
            k.npu_bank_id = stat_meter_bank_base / 2 + i;
            k.ifg = ifg_id.ifg;
            v.payloads.counter_bank_id = stat_meter_bank_base + i;
            status = m_device->m_tables.rx_meter_bank_offset_map[ifg_id.slice]->insert(k, v, dummy_entry);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

size_t
counter_manager::counter_bank_id_to_npu_bank_id(size_t counter_bank_id)
{
    /* First, process the Bank IDs belonging to statistical meters
     * because they use a different mapping than regular banks
     * counter bank id -> npu bank id
     *             108 -> 54
     *             109 -> 55
     *             110 -> 56
     *             111 -> 57
     */
    if (counter_bank_id >= counter_manager::NUM_OF_BANKS) {
        return counter_manager::NUM_OF_BANKS / 2 + counter_bank_id - counter_manager::NUM_OF_BANKS;
    }

    return counter_bank_id >> 1;
}

size_t
counter_manager::npu_bank_id_to_counter_bank_id(size_t npu_bank_id, la_slice_id_t slice, la_ifg_id_t ifg)
{
    return (npu_bank_id << 1) | ((slice % 2) << 1) | ifg;
}

la_status
counter_manager::get_logical_banks(std::set<const counter_logical_bank*>& out_banks) const
{
    out_banks.clear();

    for (const auto& bank : m_logical_banks) {
        out_banks.insert(bank.get());
    }

    return LA_STATUS_SUCCESS;
}

la_status
counter_manager::add_bank_to_mcg_bank_profiles(size_t bank_index, la_slice_id_t slice)
{
    for (size_t i = 0; i < array_size(m_mcg_bank_profiles[slice]); i++) {
        if (m_mcg_bank_profiles[slice][i] == bank_index) {
            // If bank_index already in use - no need to add it
            return LA_STATUS_SUCCESS;
        }
    }

    size_t empty_index = array_size(m_mcg_bank_profiles[slice]);
    for (size_t i = 0; i < array_size(m_mcg_bank_profiles[slice]); i++) {
        if (m_mcg_bank_profiles[slice][i] == (size_t)-1) {
            empty_index = i;
            break;
        }
    }

    // bank_index is new for mcg counter use. If profile full it can't be added
    if (empty_index >= array_size(m_mcg_bank_profiles[slice])) {
        log_err(COUNTERS, "%s: MCG counter profile is full", __func__);
        return LA_STATUS_ERESOURCE;
    }

    m_mcg_bank_profiles[slice][empty_index] = bank_index;

    return LA_STATUS_SUCCESS;
}

la_status
counter_manager::get_mcg_bank_profile(size_t bank_index, la_slice_id_t slice, size_t& out_mcg_bank_profile) const
{
    for (size_t i = 0; i < NUM_MCG_BANK_PROFILES_PER_SLICE; i++) {
        if (m_mcg_bank_profiles[slice][i] == bank_index) {
            out_mcg_bank_profile = i;
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_ENOTFOUND;
}

la_status
counter_manager::remove_bank_from_mcg_bank_profiles(size_t bank_index, la_slice_id_t slice)
{
    for (size_t i = 0; i < NUM_MCG_BANK_PROFILES_PER_SLICE; i++) {
        if (m_mcg_bank_profiles[slice][i] == bank_index) {
            m_mcg_bank_profiles[slice][i] = (size_t)-1;
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_ENOTFOUND;
}

la_status
counter_manager::create_e_resource_status_with_counter_info(counter_user_type_e user_type,
                                                            la_slice_id_t slice,
                                                            la_ifg_id_t ifg) const
{
    la_resource_descriptor::type_e resource_type;
    if (m_resource_monitor != nullptr) {
        resource_type = static_cast<la_resource_descriptor::type_e>(m_resource_monitor->get_resource_type());
    } else {
        resource_type = la_resource_descriptor::type_e::UNSPECIFIED;
    }

    std::shared_ptr<la_status_info> oor_counter_info
        = std::make_shared<la_status_info_e_resource_counter>(resource_type,                     // resource enum
                                                              silicon_one::to_string(user_type), // counter user enum
                                                              slice,                             // slice
                                                              ifg                                // ifg
                                                              );

    return LA_STATUS_ERESOURCE_INFO(oor_counter_info);
}

} // namespace silicon_one
