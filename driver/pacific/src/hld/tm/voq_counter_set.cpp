// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include <array>

#include "common/defines.h"
#include "common/logger.h"
#include "common/math_utils.h"
#include "common/transaction.h"
#include "hld_types.h"
#include "lld/pacific_mem_structs.h"
#include "lld/pacific_tree.h"
#include "system/la_device_impl.h"
#include "voq_counter_set.h"

#include <sstream>

namespace silicon_one
{

enum {
    GROUP_SIZE = 4,
    NUM_VOQS = 8,
};

std::array<std::array<size_t, GROUP_SIZE>, NUM_VOQS> valid_one_counter_group_size{{{{1, 0, 0, 0}},
                                                                                   {{2, 1, 0, 0}},
                                                                                   {{3, 0, 0, 0}},
                                                                                   {{4, 2, 1, 0}},
                                                                                   {{5, 0, 0, 0}},
                                                                                   {{6, 0, 0, 0}},
                                                                                   {{7, 0, 0, 0}},
                                                                                   {{8, 4, 2, 1}}}};

std::array<std::array<size_t, GROUP_SIZE>, NUM_VOQS> valid_two_counter_group_size{{{{2, 0, 0, 0}},
                                                                                   {{4, 2, 0, 0}},
                                                                                   {{6, 0, 0, 0}},
                                                                                   {{8, 4, 2, 0}},
                                                                                   {{10, 0, 0, 0}},
                                                                                   {{12, 0, 0, 0}},
                                                                                   {{14, 0, 0, 0}},
                                                                                   {{16, 8, 4, 2}}}};

voq_counter_set::voq_counter_set(const la_device_impl_wptr& device) : m_device(device), m_voq_counter_set_users(0)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    for (auto counter_cache : m_counter_cache) {
        counter_cache.is_valid = false;
    }
}

voq_counter_set::~voq_counter_set()
{
}

la_status
voq_counter_set::validate_num_counters(la_voq_set::voq_counter_type_e type,
                                       size_t group_size,
                                       size_t voq_set_size,
                                       size_t counter_set_size)
{
    if (type != la_voq_set::voq_counter_type_e::BOTH) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    size_t col = 0;
    while (((size_t)(1 << col)) != group_size) {
        col++;
    }

    if (valid_two_counter_group_size[voq_set_size - 1][col] != counter_set_size) {
        log_err(HLD,
                "%s(): counter_set_size:%zu does not match expected counter size %zu",
                __func__,
                counter_set_size,
                valid_two_counter_group_size[voq_set_size - 1][col]);
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
voq_counter_set::validate_params(la_voq_set::voq_counter_type_e type,
                                 size_t group_size,
                                 size_t voq_set_size,
                                 size_t counter_set_size)
{
    if (group_size != m_group_size) {
        log_err(HLD, "%s(): new group_size: %zu does not match existing group size: %zu", __func__, group_size, m_group_size);
        return LA_STATUS_EINVAL;
    }

    if (type != m_type) {
        return LA_STATUS_EINVAL;
    }

    la_status status = validate_num_counters(type, group_size, voq_set_size, counter_set_size);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
voq_counter_set::add_ifg(la_slice_ifg ifg)
{
    bool ifg_added, slice_added, slice_pair_added;
    transaction txn;

    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([=]() {
        bool dummy;
        m_ifg_use_count->remove_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (!slice_added) {
        return LA_STATUS_SUCCESS;
    }

    size_t num_of_ifgs = 2;

    log_debug(HLD,
              "voq_counter_set::add_ifg: allocate - size %zd, slice %u, ifg %d, num %zd",
              m_num_physical_counters,
              ifg.slice,
              ifg.ifg,
              num_of_ifgs);

    txn.status = m_device->m_counter_bank_manager->allocate(false /*is_slice_pair*/,
                                                            COUNTER_DIRECTION_INGRESS,
                                                            m_num_physical_counters,
                                                            ifg,
                                                            num_of_ifgs,
                                                            COUNTER_USER_TYPE_VOQ,
                                                            m_allocations[ifg.slice]);

    // Allocate the per slice counter cache.
    if (txn.status == LA_STATUS_SUCCESS) {
        m_counter_cache[ifg.slice].is_valid = true;
        m_counter_cache[ifg.slice].cached_packets.resize(m_num_physical_counters, 0);
        m_counter_cache[ifg.slice].cached_bytes.resize(m_num_physical_counters, 0);
    }

    log_debug(HLD,
              "la_counter_set_impl::add_ifg: allocate => result %d, %s",
              txn.status.value(),
              m_allocations[ifg.slice].to_string().c_str());

    return txn.status;
}

la_status
voq_counter_set::remove_ifg(la_slice_ifg ifg)
{
    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);

    if (!slice_removed) {
        return LA_STATUS_SUCCESS;
    }

    // Release the allocation
    m_device->m_counter_bank_manager->release(COUNTER_USER_TYPE_VOQ, m_allocations[ifg.slice]);

    // Release the per slice counter cache.
    m_counter_cache[ifg.slice].is_valid = false;
    m_counter_cache[ifg.slice].cached_packets.resize(0);
    m_counter_cache[ifg.slice].cached_bytes.resize(0);

    return LA_STATUS_SUCCESS;
}

la_status
voq_counter_set::add_voq_counter_set(la_voq_set::voq_counter_type_e type,
                                     size_t group_size,
                                     la_voq_gid_t base_voq_id,
                                     size_t voq_set_size,
                                     size_t counter_set_size)
{
    // Verify arguments
    if (group_size != 1 && group_size != 2 && group_size != 4 && group_size != 8) {
        log_err(HLD, "%s(): incorrect group_size:%zu", __func__, group_size);
        return LA_STATUS_EINVAL;
    }

    la_status status = validate_num_counters(type, group_size, voq_set_size, counter_set_size);
    return_on_error(status);

    m_type = type;
    m_group_size = group_size;
    m_voq_msbs = base_voq_id / NUM_VOQS_IN_SET;
    m_num_physical_counters = NUM_VOQS_IN_SET / group_size;
    if (type == la_voq_set::voq_counter_type_e::BOTH) {
        m_num_physical_counters *= 2;
    }

    transaction txn;
    auto nw_slices = get_slices(m_device, la_slice_mode_e::NETWORK);
    for (la_slice_id_t slice : nw_slices) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            la_slice_ifg slice_ifg = {.slice = slice, .ifg = ifg};
            txn.status = add_ifg(slice_ifg);
            if (txn.status != LA_STATUS_SUCCESS) {
                return txn.status;
            }
            txn.on_fail([=]() { remove_ifg(slice_ifg); });
        }
    }

    // We use one logical global table to all slices
    update_counters_voq_block_map_table();

    return LA_STATUS_SUCCESS;
}

la_status
voq_counter_set::remove_voq_counter_set()
{
    auto nw_slices = get_slices(m_device, la_slice_mode_e::NETWORK);
    for (la_slice_id_t slice : nw_slices) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            la_slice_ifg slice_ifg = {.slice = slice, .ifg = ifg};
            la_status status = remove_ifg(slice_ifg);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
voq_counter_set::register_voq_counter_set_user(la_voq_set::voq_counter_type_e type,
                                               size_t group_size,
                                               la_voq_gid_t base_voq_id,
                                               size_t voq_set_size,
                                               size_t counter_set_size)
{
    la_status status;

    if (!m_voq_counter_set_users) {
        status = add_voq_counter_set(type, group_size, base_voq_id, voq_set_size, counter_set_size);
        return_on_error(status);
    } else {
        status = validate_params(type, group_size, voq_set_size, counter_set_size);
        return_on_error(status);
    }

    status = update_voq_sets_alloced(base_voq_id, voq_set_size, true);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
voq_counter_set::deregister_voq_counter_set_user(la_voq_gid_t base_voq_id, size_t voq_set_size)
{
    la_status status;

    // VOQ counters are allocated for a block of 64 VOQs and freed when all the VOQs are freed, Counters are
    // cleared only at the point of allocation. If a subset of the 64 VOQs are freed, corresponding counters
    // are not cleared and subsequently if the same VOQs are re-allocated, they will retain these stale counts.
    // In order to prevent it, when this function gets invoked as part of freeing VOQs, a read of the
    // corresponding counters is performed from hardware and the local cache is cleared. When the same VOQs are
    // re-allocated, this ensures there are no stale counts.
    size_t num_counters_to_clear = voq_set_size / m_group_size;
    if (m_type == la_voq_set::voq_counter_type_e::BOTH) {
        num_counters_to_clear *= 2;
    }
    for (size_t counter_index = 0; counter_index < num_counters_to_clear; counter_index++) {
        size_t pkts;
        size_t bytes;
        read(base_voq_id, counter_index, true /* force_update */, true /* clear_on_read */, pkts, bytes); // Will always succeed
    }

    status = update_voq_sets_alloced(base_voq_id, voq_set_size, false);
    return_on_error(status);

    if (!m_voq_counter_set_users) {
        status = remove_voq_counter_set();
    }

    return status;
}

la_status
voq_counter_set::update_voq_sets_alloced(la_voq_gid_t base_voq_id, size_t set_size, bool alloc)
{
    uint64_t val;

    dassert_crit((base_voq_id % NUM_VOQS_IN_SET) + set_size - 1 < NUM_VOQS_IN_SET);

    val = ((1ULL << set_size) - 1) << (base_voq_id % NUM_VOQS_IN_SET);

    if (alloc) {
        if (m_voq_counter_set_users & val) {
            log_err(HLD, "%s(): bitmap already set. voq_set already has counter", __func__);
            return LA_STATUS_EINVAL;
        }
        m_voq_counter_set_users |= val;
    } else {
        if (!(m_voq_counter_set_users & val)) {
            log_err(HLD, "%s(): bitmap already cleared. voq_set does not have counter to clear", __func__);
            return LA_STATUS_EINVAL;
        }
        m_voq_counter_set_users &= ~val;
    }

    return LA_STATUS_SUCCESS;
}

la_status
voq_counter_set::update_counters_voq_block_map_table()
{
    // Prepare arguments
    npl_counters_voq_block_map_table_t::key_type k;
    npl_counters_voq_block_map_table_t::value_type v;
    npl_counters_voq_block_map_table_t::entry_pointer_type entry_ptr = nullptr;

    k.voq_base_id = m_voq_msbs;

    // Shared data to all slices
    v.payloads.counters_voq_block_map_result.map_groups_size = int_log(m_group_size);
    v.payloads.counters_voq_block_map_result.tc_profile = 0;
    v.action = NPL_COUNTERS_VOQ_BLOCK_MAP_TABLE_ACTION_WRITE;

    auto nw_slices = get_slices(m_device, la_slice_mode_e::NETWORK);
    for (la_slice_id_t slice : nw_slices) {
        counter_allocation allocation = m_allocations[slice];
        v.payloads.counters_voq_block_map_result.bank_id = allocation.get_bank_id();
        v.payloads.counters_voq_block_map_result.counter_offset = allocation.get_index();

        // Choose table
        const auto& table(m_device->m_tables.counters_voq_block_map_table[slice]);

        la_status write_status = table->set(k, v, entry_ptr);
        return_on_error(write_status);
    }

    return LA_STATUS_SUCCESS;
}

size_t
voq_counter_set::get_base_counter_offset(size_t base_voq)
{
    size_t base_voq_in_voq_counter_set = m_voq_msbs << NUM_VOQ_SET_BITS;
    size_t group_offset = (base_voq - base_voq_in_voq_counter_set) / m_group_size;
    if (m_type == la_voq_set::voq_counter_type_e::BOTH) {
        group_offset <<= 1;
    }
    return group_offset;
}

la_status
voq_counter_set::read(la_voq_gid_t base_voq_id,
                      la_slice_id_t slice_id,
                      size_t counter_index,
                      bool force_update,
                      bool clear_on_read,
                      size_t& out_packets,
                      size_t& out_bytes)
{

    if (!m_allocations[slice_id].valid() || !m_counter_cache[slice_id].is_valid) {
        return LA_STATUS_EINVAL;
    }

    size_t group_offset = get_base_counter_offset(base_voq_id);
    size_t total_offset = group_offset + counter_index;

    out_packets = m_counter_cache[slice_id].cached_packets[total_offset];
    out_bytes = m_counter_cache[slice_id].cached_bytes[total_offset];

    uint64_t bytes;
    uint64_t packets;
    auto allocation = m_allocations[slice_id];

    m_device->m_counter_bank_manager->read_counter(allocation, total_offset, force_update, clear_on_read, bytes, packets);

    out_bytes += bytes;
    out_packets += packets;

    if (clear_on_read) {
        m_counter_cache[slice_id].cached_packets[total_offset] = 0;
        m_counter_cache[slice_id].cached_bytes[total_offset] = 0;
    }

    return LA_STATUS_SUCCESS;
}

la_status
voq_counter_set::read(la_voq_gid_t base_voq_id,
                      size_t counter_index,
                      bool force_update,
                      bool clear_on_read,
                      size_t& out_packets,
                      size_t& out_bytes)
{
    out_packets = 0;
    out_bytes = 0;

    // Reading from all slices
    for (la_slice_id_t slice_id : m_device->get_used_slices()) {

        size_t bytes;
        size_t packets;

        la_status status = read(base_voq_id, slice_id, counter_index, force_update, clear_on_read, packets, bytes);

        if (status != LA_STATUS_SUCCESS) {
            continue;
        }

        out_bytes += bytes;
        out_packets += packets;
    }

    return LA_STATUS_SUCCESS;
}

la_voq_gid_t
voq_counter_set::get_voq_msbs() const
{
    return m_voq_msbs;
}

size_t
voq_counter_set::get_group_size() const
{
    return m_group_size;
}

la_voq_set::voq_counter_type_e
voq_counter_set::get_type() const
{
    return m_type;
}

uint64_t
voq_counter_set::get_registered_voq_counter_set_users() const
{
    return m_voq_counter_set_users;
}

const la_device*
voq_counter_set::get_device() const
{
    return m_device.get();
}

la_status
voq_counter_set::destroy()
{
    npl_counters_voq_block_map_table_t::key_type k;
    npl_counters_voq_block_map_table_t::value_type v;
    npl_counters_voq_block_map_table_t::entry_pointer_type entry_ptr = nullptr;

    k.voq_base_id = m_voq_msbs;
    v.payloads.counters_voq_block_map_result.bank_id = la_device_impl::COUNTERS_VOQ_BLOCK_MAP_TABLE_INVALID_BANK_ID;
    v.payloads.counters_voq_block_map_result.map_groups_size = 0;
    v.payloads.counters_voq_block_map_result.tc_profile = 0;
    v.payloads.counters_voq_block_map_result.counter_offset = 0;

    auto nw_slices = get_slices(m_device, la_slice_mode_e::NETWORK);
    for (la_slice_id_t slice : nw_slices) {
        const auto& table(m_device->m_tables.counters_voq_block_map_table[slice]);
        la_status status = table->set(k, v, entry_ptr);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
