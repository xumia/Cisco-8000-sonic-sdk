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

#include "lpm_core.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/la_profile.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "lpm_string.h"

#include "lpm_core_hw_writer_gb.h"
#include "lpm_core_hw_writer_pacific.h"

#include "lpm_core_tcam_akpg.h"
#include "lpm_core_tcam_pacific_gb.h"

#include <algorithm>
#include <iostream>
#include <type_traits>

using namespace std;

namespace silicon_one
{

constexpr size_t FREE_SRAM_BUCKETS_TO_RESERVE_DEFAULT = 200;

lpm_core::lpm_core(const ll_device_sptr& ldevice,
                   lpm_core_id_t core_id,
                   const bucketing_tree_sptr& tree,
                   size_t l2_double_bucket_size,
                   size_t l2_max_number_of_sram_buckets,
                   size_t tcam_num_banksets,
                   size_t tcam_bank_size,
                   size_t max_tcam_quad_entries,
                   lpm_payload_t trap_destination,
                   const lpm_core_tcam_utils_scptr& core_tcam_utils)
    : m_ll_device(ldevice),
      m_tree(tree),
      m_core_id(core_id),
      m_hbm_address_offset(l2_max_number_of_sram_buckets),
      m_l2_sram_free_buckets_to_reserve(FREE_SRAM_BUCKETS_TO_RESERVE_DEFAULT),
      m_hw_writer(nullptr),
      m_tcam_writes(0),
      m_l1_writes(0),
      m_l2_writes(0),
      m_ecc_err_handling_in_progress(false)
{
    std::string tcam_name = "Core " + std::to_string(core_id) + "::TCAM";
    if (is_gibraltar_revision(ldevice)) {
        m_hw_writer = make_shared<lpm_core_hw_writer_gb>(ldevice, core_id, l2_double_bucket_size, tcam_num_banksets);
        m_tcam = make_shared<lpm_core_tcam_pacific_gb>(
            tcam_name, tcam_num_banksets, tcam_bank_size, max_tcam_quad_entries, core_tcam_utils);
    } else if (is_pacific_revision(ldevice)) {
        m_hw_writer = make_shared<lpm_core_hw_writer_pacific>(
            ldevice, core_id, l2_double_bucket_size, tcam_num_banksets, trap_destination, m_hbm_address_offset);
        m_tcam = make_shared<lpm_core_tcam_pacific_gb>(
            tcam_name, tcam_num_banksets, tcam_bank_size, max_tcam_quad_entries, core_tcam_utils);
    } else {
        dassert_crit(false, "Unsuported device!");
    }
}

lpm_core::lpm_core() : m_hbm_address_offset()
{
}

lpm_core::~lpm_core()
{
}

const ll_device_sptr&
lpm_core::get_ll_device() const
{
    return m_ll_device;
}

size_t
lpm_core::get_id() const
{
    return m_core_id;
}

la_status
lpm_core::update_tcam(lpm_implementation_desc_vec& l1_actions)
{
    transaction txn;
    txn.on_fail([=]() { clear_iteration_members(); });

    // Get TCAM updates.
    lpm_implementation_desc_vec& tcam_updates_in(l1_actions);
    int action_priority[static_cast<int>(lpm_implementation_action_e::LAST) + 1] = {-1};
    action_priority[static_cast<int>(lpm_implementation_action_e::INSERT)] = 0;
    action_priority[static_cast<int>(lpm_implementation_action_e::MODIFY)] = 1;
    action_priority[static_cast<int>(lpm_implementation_action_e::REFRESH)] = 1;
    action_priority[static_cast<int>(lpm_implementation_action_e::REMOVE)] = 2;
    std::stable_sort(tcam_updates_in.begin(),
                     tcam_updates_in.end(),
                     [&action_priority](const lpm_action_desc_internal& a, const lpm_action_desc_internal& b) -> bool {
                         dassert_crit(action_priority[static_cast<int>(a.m_action)] != -1);
                         dassert_crit(action_priority[static_cast<int>(b.m_action)] != -1);
                         if (a.m_action == b.m_action) {
                             if (a.m_action == lpm_implementation_action_e::INSERT) {
                                 // Insert more specific prefix before less specific prefix.
                                 return (a.m_key.get_width() > b.m_key.get_width());
                             } else if (a.m_action == lpm_implementation_action_e::REMOVE) {
                                 // Remove less specific prefix before more specific prefix.
                                 return (a.m_key.get_width() < b.m_key.get_width());
                             }
                         }
                         return (action_priority[static_cast<int>(a.m_action)] < action_priority[static_cast<int>(b.m_action)]);
                     });

    txn.status = m_tcam->update(tcam_updates_in, m_tcam_updates);
    return_on_error(txn.status, TABLES, ERROR, "Core #%u: failed to update TCAM", m_core_id);

    return txn.status;
}

la_status
lpm_core::commit_hw_updates(const lpm_implementation_desc_vec_levels& l1_l2_actions)
{
    transaction txn;
    txn.on_fail([=]() { withdraw(); });

    if (l1_l2_actions[LEVEL2].empty()) {
        dassert_crit(l1_l2_actions[LEVEL1].empty());
        dassert_crit(m_tcam_updates.empty());
        return LA_STATUS_SUCCESS;
    }

    txn.status = update_hardware(l1_l2_actions[LEVEL2], l1_l2_actions[LEVEL1], m_tcam_updates);
    if (txn.status != LA_STATUS_SUCCESS) {
        return txn.status;
    }

    m_tcam->commit();

    clear_iteration_members();

    return LA_STATUS_SUCCESS;
}

void
lpm_core::withdraw()
{
    m_tcam->withdraw();
    clear_iteration_members();
}

void
lpm_core::clear_iteration_members()
{
    m_tcam_updates.clear();
}

la_status
lpm_core::lookup(const lpm_key_t& key, lpm_key_t& out_hit_key, lpm_payload_t& out_hit_payload) const
{
    lpm_key_t dummy_key;
    tcam_cell_location dummy_location;
    lpm_payload_t l1_bucket_index;

    la_status status = m_tcam->lookup_tcam_tree(key, dummy_key, l1_bucket_index, dummy_location);
    return_on_error(status);

    lpm_key_t l1_hit_key;
    lpm_payload_t l1_hit_payload;
    bool is_l1_default;
    status = m_tree->lookup(key, m_core_id, lpm_level_e::L1, l1_bucket_index, l1_hit_key, l1_hit_payload, is_l1_default);
    return_on_error(status);

    if (is_l1_default && is_pacific_revision(m_ll_device)) {
        out_hit_key = l1_hit_key;
        out_hit_payload = l1_hit_payload;
        return LA_STATUS_SUCCESS;
    }

    bool out_is_l2_default;
    status = m_tree->lookup(key, m_core_id, lpm_level_e::L2, l1_hit_payload, out_hit_key, out_hit_payload, out_is_l2_default);

    return status;
}

const bucketing_tree&
lpm_core::get_tree() const
{
    return *m_tree;
}

const lpm_core_tcam&
lpm_core::get_tcam() const
{
    return *m_tcam;
}

lpm_hbm_cache_manager&
lpm_core::get_hbm_cache_manager()
{
    lpm_hbm_cache_manager& hbm_cache_manager = m_tree->get_hbm_cache_manager(m_core_id);
    return hbm_cache_manager;
}

const lpm_core_hw_writer&
lpm_core::get_core_hw_writer() const
{
    return *m_hw_writer;
}

void
lpm_core::log_bucket_debug(lpm_level_e level, lpm_bucket_index_t hw_index, const lpm_bucket* bucket) const
{
    if (!logger::instance().is_logging(m_ll_device->get_device_id(), la_logger_component_e::TABLES, la_logger_level_e::DEBUG)) {
        return;
    }

    if (bucket == nullptr) {
        log_debug(TABLES, "LPM Core %u Write %s Bucket Line %d = Null", m_core_id, to_string(level).c_str(), hw_index);
        return;
    }

    dassert_crit(hw_index == bucket->get_hw_index());
    dassert_crit(bucket->get_level() == level);

    lpm_key_payload_vec entries = bucket->get_entries();
    log_debug(TABLES,
              "LPM Core %u Write %s Bucket Line %d  #Nodes %lu  root width %lu:",
              m_core_id,
              to_string(level).c_str(),
              bucket->get_hw_index(),
              entries.size(),
              bucket->get_root_width());
    for (auto& entry : entries) {
        log_debug(TABLES, "Node: key %s width %lu payload %u", entry.key.to_string().c_str(), entry.key.get_width(), entry.payload);
    }

    lpm_key_payload default_key_payload = bucket->get_default_entry();
    log_debug(TABLES, "Default bucket payload %u", default_key_payload.payload);
}

la_status
lpm_core::write_bucket(const lpm_bucket* bucket) const
{
    dassert_crit(bucket);
    lpm_level_e level = bucket->get_level();
    log_debug(TABLES, "write_bucket(hw_index %d, level=%s)", bucket->get_hw_index(), to_string(level).c_str());
    la_status status;
    lpm_bucket_index_t hw_index = bucket->get_hw_index();

    log_bucket_debug(level, hw_index, bucket);

    dassert_slow(!bucket || bucket->sanity_widths());

    if (level == lpm_level_e::L2) {
        // WA for false ECC errors
        if (is_pacific_or_gibraltar_revision(m_ll_device)) {
            status = set_l2_sram_ecc_regs_interrupts_enabled(false /* enable */);
            return_on_error(status);
        }

        // Actual useful code
        bool is_hbm = is_location_in_hbm(lpm_level_e::L2, hw_index, m_hbm_address_offset);
        if (is_hbm) {
            status = m_hw_writer->write_l2_hbm_bucket(bucket);
        } else {
            const lpm_bucket* neighbor_bucket = m_tree->get_neighbor_bucket(m_core_id, level, hw_index);
            log_bucket_debug(level, hw_index ^ 1, neighbor_bucket);
            dassert_slow(!neighbor_bucket || neighbor_bucket->sanity_widths());
            status = m_hw_writer->write_l2_sram_buckets(bucket, neighbor_bucket);
        }

        m_l2_writes++;

    } else {
        const lpm_bucket* neighbor_bucket = m_tree->get_neighbor_bucket(m_core_id, level, hw_index);
        log_bucket_debug(level, hw_index ^ 1, neighbor_bucket);
        dassert_slow(!neighbor_bucket || neighbor_bucket->sanity_widths());

        status = m_hw_writer->write_l1_line(bucket, neighbor_bucket);
        m_l1_writes++;
    }

    return_on_error(status, TABLES, ERROR, "%s HW writing failed for bucket with HW index %d", to_string(level).c_str(), hw_index);

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core::move_l2_bucket(lpm_bucket_index_t src_hw_index, l2_bucket_location_e destination)
{
    log_debug(TABLES,
              "core %d  %s(src_hw_index = %d, destination = %s)",
              m_core_id,
              __func__,
              src_hw_index,
              (destination == l2_bucket_location_e::HBM) ? "HBM" : "SRAM");

    lpm_bucket* l2_bucket;
    lpm_bucket_raw_ptr_vec l1_buckets_to_write;
    la_status status
        = m_tree->move_l2_bucket_between_sram_and_hbm(m_core_id, src_hw_index, destination, l2_bucket, l1_buckets_to_write);
    return_on_error(status,
                    TABLES,
                    ERROR,
                    "core=%d  m_tree->move_l2_bucket_between_sram_and_hbm(l2_bucket=%d, destination=%s)",
                    m_core_id,
                    src_hw_index,
                    (destination == l2_bucket_location_e::HBM) ? "HBM" : "SRAM");

    m_tree->commit(); // make bucket allocator release the old bucket.

    status = write_bucket(l2_bucket);
    return_on_error(status, TABLES, ERROR, "Failed to writing L2 bucket to HW");

    for (auto l1_bucket : l1_buckets_to_write) {
        status = write_bucket(l1_bucket);
        return_on_error(status, TABLES, ERROR, "Failed to writing L1 bucket to HW");
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core::move_l2_bucket_to_row(lpm_bucket_index_t src_hw_index, lpm_bucket_index_t dst_hw_index)
{
    log_debug(TABLES, "core %d  %s(src_hw_index = %d, dst_hw_index = %d)", m_core_id, __func__, src_hw_index, dst_hw_index);
    if (src_hw_index == dst_hw_index) {
        return LA_STATUS_SUCCESS;
    }

    lpm_bucket* l2_bucket;
    lpm_bucket_raw_ptr_vec l1_buckets_to_write;
    la_status status = m_tree->move_l2_bucket_to_row(m_core_id, src_hw_index, dst_hw_index, l2_bucket, l1_buckets_to_write);
    return_on_error(status,
                    TABLES,
                    ERROR,
                    "core=%d  mm_tree->move_l2_bucket_to_row(l2_bucket=%d, dst_hw_index=%d)",
                    m_core_id,
                    src_hw_index,
                    dst_hw_index);

    m_tree->commit(); // make bucket allocator release the old bucket.

    status = write_bucket(l2_bucket);
    return_on_error(status, TABLES, ERROR, "Failed to writing L2 bucket to HW");

    for (auto l1_bucket : l1_buckets_to_write) {
        status = write_bucket(l1_bucket);
        return_on_error(status, TABLES, ERROR, "Failed to writing L1 bucket to HW");
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core::invalidate_tcam_row(const tcam_cell_location& location, const lpm_key_t& key)
{
    log_debug(TABLES, "LPM: TCAM Iv    core = %u    location = %s", m_core_id, location.to_string().c_str());
    la_status status = m_hw_writer->invalidate_tcam(location, key);

    if (status != LA_STATUS_SUCCESS) {
        log_err(TABLES, "TCAM HW invalidation failed for location %s", location.to_string().c_str());
    }

    m_tcam_writes++;
    return status;
}

la_status
lpm_core::write_tcam_row(const tcam_cell_location& location, const lpm_key_t& key, lpm_payload_t payload, bool only_update_payload)
{
    log_debug(TABLES,
              "LPM: TCAM Wr    core = %u     location = %s    key = 0x%s    key width = %lu      payload = %u    "
              "only_update_payload? %s",
              m_core_id,
              location.to_string().c_str(),
              key.to_string().c_str(),
              key.get_width(),
              payload,
              only_update_payload ? "YES" : "NO");
    la_status status = m_hw_writer->write_tcam(location, key, payload, only_update_payload);

    return_on_error(status, TABLES, ERROR, "failed to write to TCAM");

    m_tcam_writes++;
    return LA_STATUS_SUCCESS;
}

lpm_core::lpm_indices_vec_t
lpm_core::get_insertion_indices(const lpm_implementation_desc_vec& updates) const
{
    lpm_indices_vec_t insertions;
    for (auto& update : updates) {
        lpm_implementation_action_e action = update.m_action;
        if (action == lpm_implementation_action_e::INSERT || action == lpm_implementation_action_e::MODIFY) {
            insertions.push_back(update.m_index);
        }
    }

    return insertions;
}

lpm_core::lpm_indices_vec_t
lpm_core::get_refresh_indices(const lpm_implementation_desc_vec& updates) const
{
    lpm_indices_vec_t refreshes;
    for (auto& update : updates) {
        if (update.m_action == lpm_implementation_action_e::REFRESH) {
            refreshes.push_back(update.m_index);
        }
    }

    return refreshes;
}

lpm_core::lpm_indices_vec_t
lpm_core::get_remove_indices(const lpm_implementation_desc_vec& updates) const
{
    lpm_indices_vec_t removes;
    for (auto& update : updates) {
        if (update.m_action == lpm_implementation_action_e::REMOVE) {
            removes.push_back(update.m_index);
        }
    }

    return removes;
}

la_status
lpm_core::update_tree_insertions(const lpm_implementation_desc_vec& tree_updates, lpm_level_e level) const
{
    lpm_indices_vec_t insertions(get_insertion_indices(tree_updates));

    log_debug(TABLES, "LPM level=%d Tree core %u: Performing insertions", (int)level, m_core_id);

    size_t insertions_size = insertions.size();
    for (size_t i = 0; i < insertions_size; i++) {
        lpm_bucket_index_t bucket_idx = insertions[i];
        const lpm_bucket* bucket = m_tree->get_bucket_by_hw_index(m_core_id, level, bucket_idx);
        la_status status = write_bucket(bucket);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core::update_tree_refreshes(const lpm_implementation_desc_vec& tree_updates, lpm_level_e level) const
{
    lpm_indices_vec_t refreshes(get_refresh_indices(tree_updates));

    log_debug(TABLES, "LPM level=%d, Tree core %u: Performing refreshes", (int)level, m_core_id);

    size_t refreshes_size = refreshes.size();
    for (size_t i = 0; i < refreshes_size; i++) {
        lpm_bucket_index_t bucket_idx = refreshes[i];
        const lpm_bucket* bucket = m_tree->get_bucket_by_hw_index(m_core_id, level, bucket_idx);
        la_status status = write_bucket(bucket);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core::update_tcam_instructions(const lpm_core_tcam::hardware_instruction_vec& tcam_updates)
{

    lpm_core_tcam::hardware_instruction_vec updates(tcam_updates);

    for (auto& update : updates) {
        switch (update.instruction_type) {
        case lpm_core_tcam::hardware_instruction::type_e::INSERT: {
            auto instruction_data = boost::get<lpm_core_tcam::hardware_instruction::insert>(update.instruction_data);
            la_status status = write_tcam_row(
                instruction_data.location, instruction_data.key, instruction_data.payload, false /* only_update_payload */);
            return_on_error(status);
            break;
        }

        case lpm_core_tcam::hardware_instruction::type_e::MODIFY_PAYLOAD: {
            auto instruction_data = boost::get<lpm_core_tcam::hardware_instruction::modify_payload>(update.instruction_data);
            la_status status = write_tcam_row(
                instruction_data.location, instruction_data.key, instruction_data.payload, true /* only_update_payload */);
            return_on_error(status);
            break;
        }

        case lpm_core_tcam::hardware_instruction::type_e::REMOVE: {
            auto instruction_data = boost::get<lpm_core_tcam::hardware_instruction::remove>(update.instruction_data);
            la_status status = invalidate_tcam_row(instruction_data.location, instruction_data.key);
            return_on_error(status);
            break;
        }

        default:
            dassert_crit(false);
            break;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core::set_l2_sram_ecc_regs_interrupts_enabled(bool enable) const
{
    if (m_ecc_err_handling_in_progress != enable) {
        return LA_STATUS_SUCCESS;
    }

    m_ecc_err_handling_in_progress = !enable;
    lpm_core_hw_writer_pacific_gb* hw_writer_pacific_gb = static_cast<lpm_core_hw_writer_pacific_gb*>(m_hw_writer.get());
    la_status status = hw_writer_pacific_gb->set_l2_sram_ecc_regs_interrupts_enabled(enable);
    return status;
}

la_status
lpm_core::update_hardware(const lpm_implementation_desc_vec& l2_bucket_updates,
                          const lpm_implementation_desc_vec& l1_bucket_updates,
                          const lpm_core_tcam::hardware_instruction_vec& tcam_instructions)
{
    /// Important: The order of hardware updates, namely, the fact that we first perform tree inserts, then TCAM updates, and keep
    /// refreshes to the end, is important for keeping LPM structure consistent at all times.
    /// This is related to the fact that we write buckets in pairs.
    /// Take this scenario for example (for simplicity, we will assume 2 levels only: TCAM and L1):
    /// Initial state:  L1 row 0 has 2 buckets: {A, B}, there is some TCAM line pointing to bucket B.
    /// Final state: A is refreshed to become A', and B is relocated to another row. So final state of row 0 is {A', x}. There is
    /// some TCAM line pointing to the new location of bucket B.
    /// Intermediate state: If we, by mistake, perform the refreshes before TCAM updates,  in particular we refresh bucket A->A',
    /// this operation will result in deleting bucket B from its original location. (When we refresh bucket A we write the whole
    /// SRAM line. When the tree wants to decide what to write next to A', the tree will tell it that it has no neighbor anymore,
    /// and we will end up writing nothing in the neighbor. Even if we remembered that B was A's neighbor, there is no guarantee
    /// that we will have space for B after A->A' refresh). The solution to this is to first point the TCAM to the new location of
    /// B. Now, after we updated the TCAM, we can perform the refresh and delete the original B without worrying, because TCAM is
    /// not pointing to it anymore.
    /// Now, you might ask: OK mister, this makes since, but a similar problem might happen without refreshes:
    /// Initial state: L1 row 0 = {x, A},  L1 row 1 = {C, x}
    /// Final state: L1 row 0 = {B, x}, L1 row 1 = {C, A} : That's 2 inserts: insert B to row 0, and insert A to row 1
    /// let's focus on L1 row 0:
    /// If we perform write_bucket(B) first, we will result in deleting bucket A from 0, before we write it to row 1. And we have a
    /// similar problem like before.
    /// You would be correct, but our super-duper bucket allocator would not allow us to get such a sequence of events, by
    /// preventing buckets from rows with deleted buckets to be allocated.
    /// But then again, another person might say: then don't do write_bucket(B) first. Do write_bucket(A) first.
    /// To that we will answer: You might be correct. But for now we do not have a sophisticated dependency tracking of buckets so
    /// we can choose the correct order of writes (assuming such order even exists). That is a task for another day.

    start_profiling("HW unpdates");

    la_status status = update_tree_insertions(l2_bucket_updates, lpm_level_e::L2);
    return_on_error(status);

    status = update_tree_insertions(l1_bucket_updates, lpm_level_e::L1);
    return_on_error(status);

    status = update_tcam_instructions(tcam_instructions);
    return_on_error(status);

    status = update_tree_refreshes(l2_bucket_updates, lpm_level_e::L2);
    return_on_error(status);

    status = update_tree_refreshes(l1_bucket_updates, lpm_level_e::L1);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core::enable_force_l2_node_is_leaf(const lpm_key_t& key, bool is_leaf)
{
    lpm_bucket* bucket_to_refresh = m_tree->get_bucket(key, lpm_level_e::L2);

    if (bucket_to_refresh == nullptr) {
        log_err(TABLES, "could not find bucket for key %s/%zu", key.to_string().c_str(), key.get_width());
        return LA_STATUS_ENOTFOUND;
    }

    lpm_key_t hit_key;
    lpm_payload_t dummy_hit_payload;
    bool dummy_is_default;
    la_status status = bucket_to_refresh->lookup(key, hit_key, dummy_hit_payload, dummy_is_default);
    return_on_error(status);

    if (key != hit_key) {
        return LA_STATUS_ENOTFOUND;
    }

    m_hw_writer->m_key_to_force_is_leaf[key] = is_leaf;

    return write_bucket(bucket_to_refresh);
}

la_status
lpm_core::disable_force_l2_node_is_leaf(const lpm_key_t& key)
{
    lpm_bucket* bucket_to_refresh = m_tree->get_bucket(key, lpm_level_e::L2);

    if (bucket_to_refresh == nullptr) {
        log_err(TABLES, "could not find bucket for key %s/%zu", key.to_string().c_str(), key.get_width());
        return LA_STATUS_ENOTFOUND;
    }

    lpm_key_t hit_key;
    lpm_payload_t dummy_hit_payload;
    bool dummy_is_default;
    la_status status = bucket_to_refresh->lookup(key, hit_key, dummy_hit_payload, dummy_is_default);
    return_on_error(status);

    if (key != hit_key) {
        return LA_STATUS_ENOTFOUND;
    }

    size_t ret = m_hw_writer->m_key_to_force_is_leaf.erase(key);
    if (ret == 0) {
        return LA_STATUS_ENOTFOUND;
    }

    return write_bucket(bucket_to_refresh);
}

void
lpm_core::collect_bucket_hotness_stats()
{
    vector_alloc<size_t> bucket_indexes;
    la_status status = m_hw_writer->read_index_of_last_accessed_l2_sram_buckets(bucket_indexes);
    if (status != LA_STATUS_SUCCESS) {
        return;
    }

    for (auto& bucket_idx : bucket_indexes) {
        notify_l2_bucket_accessed(bucket_idx);
    }
}

void
lpm_core::notify_l2_bucket_accessed(size_t hw_index)
{
    lpm_hbm_cache_manager& hbm_cache_manager = get_hbm_cache_manager();
    hbm_cache_manager.notify_bucket_accessed(hw_index);
}

vector_alloc<lpm_bucket_index_t>
lpm_core::get_buckets_to_cache()
{
    const lpm_hbm_cache_manager& hbm_cache_manager = get_hbm_cache_manager();
    vector_alloc<lpm_bucket_index_t> buckets_to_cache = hbm_cache_manager.get_buckets_to_cache();
    size_t n_buckets_to_cache = buckets_to_cache.size();
    if (n_buckets_to_cache == 0) {
        log_spam(TABLES,
                 "HBM Caching: Core %d: No candidates for caching. Free space in SRAM: %zu",
                 m_core_id,
                 m_tree->get_free_space_in_sram(m_core_id));
    }
    return buckets_to_cache;
}

vector_alloc<lpm_bucket_index_t>
lpm_core::get_buckets_to_evict(size_t required_space)
{
    size_t free_space = m_tree->get_free_space_in_sram(m_core_id);
    size_t n_buckets_to_evict = (required_space <= free_space) ? 0 : (required_space - free_space);
    const lpm_hbm_cache_manager& hbm_cache_manager = get_hbm_cache_manager();
    vector_alloc<lpm_bucket_index_t> buckets_to_evict = hbm_cache_manager.get_buckets_to_evict(n_buckets_to_evict);
    return buckets_to_evict;
}

void
lpm_core::cache_buckets(vector_alloc<lpm_bucket_index_t>& buckets_to_cache)
{
    size_t n_buckets_to_cache = buckets_to_cache.size();
    if (n_buckets_to_cache == 0) {
        return;
    }

    size_t free_space = m_tree->get_free_space_in_sram(m_core_id);
    log_spam(TABLES,
             "HBM Caching: Core %d: SRAM space stats: Caching candidates %zu, Current free space in SRAM %zu",
             m_core_id,
             n_buckets_to_cache,
             free_space);

    if (free_space < n_buckets_to_cache) {
        log_spam(TABLES, "HBM Caching: Core %d: No enough space in SRAM to allow caching of all new cache candidates", m_core_id);
        buckets_to_cache.resize(free_space);
    }

    for (lpm_bucket_index_t hw_index : buckets_to_cache) {
        log_debug(TABLES, "HBM Caching: Core %d: Caching bucket hw_index %d to SRAM", m_core_id, hw_index);
        la_status status = move_l2_bucket(hw_index, l2_bucket_location_e::SRAM);
        if (status != LA_STATUS_SUCCESS) {
            log_warning(TABLES, "HBM Caching: failed to cache L2 bucket to SRAM");
        }
    }
}

void
lpm_core::evict_buckets(vector_alloc<lpm_bucket_index_t>& buckets_to_evict)
{
    for (lpm_bucket_index_t hw_index : buckets_to_evict) {
        log_debug(TABLES, "HBM Caching: Core %d: Evicting bucket hw_index %d to HBM", m_core_id, hw_index);
        la_status status = move_l2_bucket(hw_index, l2_bucket_location_e::HBM);
        if (status != LA_STATUS_SUCCESS) {
            log_warning(TABLES, "HBM Caching: failed to evict L2 bucket to HBM");
        }
    }
}

void
lpm_core::perform_caching()
{
    lpm_hbm_cache_manager& hbm_cache_manager = get_hbm_cache_manager();
    hbm_cache_manager.cool_down_buckets();

    vector_alloc<lpm_bucket_index_t> buckets_to_cache = get_buckets_to_cache();

    size_t required_space = buckets_to_cache.size() + m_l2_sram_free_buckets_to_reserve;
    vector_alloc<lpm_bucket_index_t> buckets_to_evict = get_buckets_to_evict(required_space);

    evict_buckets(buckets_to_evict);

    cache_buckets(buckets_to_cache);
}

void
lpm_core::unmask_and_clear_l2_ecc_interrupt_registers() const
{
    set_l2_sram_ecc_regs_interrupts_enabled(true /* enable*/);
}

size_t
lpm_core::get_used_tcam_lines() const
{
    lpm_core_tcam::lpm_core_tcam_occupancy occupancy = m_tcam->get_occupancy();
    return occupancy.occupied_cells;
}

size_t
lpm_core::get_free_l2_sram_buckets_to_reserve() const
{
    return m_l2_sram_free_buckets_to_reserve;
}

void
lpm_core::set_free_l2_sram_buckets_to_reserve(size_t num_buckets_to_reserve)
{
    m_l2_sram_free_buckets_to_reserve = num_buckets_to_reserve;
}

} // namespace silicon_one
