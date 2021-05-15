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

#ifndef __LEABA_LPM_CORE_H__
#define __LEABA_LPM_CORE_H__

#include "bucketing_tree.h"
#include "common/stopwatch.h"
#include "hw_tables/lpm_types.h"
#include "lld/ll_device.h"
#include "lpm_core_hw_writer.h"
#include "lpm_core_tcam.h"
#include "lpm_internal_types.h"

/// @file

namespace silicon_one
{

class ll_device_impl;

/// @brief LPM core
///
/// An LPM core representation. Holds two LPM trees and one TCAM object.
/// Calculates updates to L1 and L2 levels buckets and to TCAM entries.
/// Instruct the HW specifically according to the calculated updates.
class lpm_core
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Construct an empty LPM core.
    ///
    /// @param[in]      ldevice                       Low level device to write to.
    /// @param[in]      core_id                       LPM core id.
    /// @param[in]      l2_buckets_per_sram_row       Number of L2 buckets in SRAM row.
    /// @param[in]      l2_double_bucket_size         The size of a pair of buckets in L2.
    /// @param[in]      l2_max_bucket_size            The maximum size of a bucket in L2.
    /// @param[in]      l2_max_number_of_sram_buckets The maximum number of buckets in L2 on die SRAM.
    /// @param[in]      l2_max_number_of_hbm_buckets  The maximum number of buckets in L2 HBM.
    /// @param[in]      l2_hbm_address_offset         First bucket hardware index of HBM.
    /// @param[in]      l1_double_bucket_size         The size of a pair of buckets in L1.
    /// @param[in]      l1_max_bucket_size            The maximum size of a bucket in L1.
    /// @param[in]      l1_max_number_of_buckets      The maximum number of a buckets in L1.
    /// @param[in]      l1_buckets_per_sram_line      Number of L1 buckets in SRAM row.
    /// @param[in]      max_bucket_depth              The number of comparable bits in bucket.
    /// @param[in]      tcam_num_banksets             The number of banksets in the core TCAM.
    /// @param[in]      tcam_bank_size                The number of rows in TCAM bank.
    /// @param[in]      max_tcam_quad_entries         The maximum allowed number of quad entries in TCAM.
    /// @param[in]      tcam_single_width_key_weight  Weighted load on TCAM of a single width key.
    /// @param[in]      tcam_double_width_key_weight  Weighted load on TCAM of a double width key.
    /// @param[in]      tcam_quad_width_key_weight    Weighted load on TCAM of a quad width key.
    /// @param[in]      trap_destination              Payload of destination to raise a trap.
    /// @param[in]      core_tcam_utils               Pointer to TCAM utils object.
    lpm_core(const ll_device_sptr& ldevice,
             lpm_core_id_t core_id,
             const bucketing_tree_sptr& tree,
             size_t l2_double_bucket_size,
             size_t l2_max_number_of_sram_buckets,
             size_t tcam_num_banksets,
             size_t tcam_bank_size,
             size_t max_tcam_quad_entries,
             lpm_payload_t trap_destination,
             const lpm_core_tcam_utils_scptr& core_tcam_utils);

    /// @brief Destructor of LPM core.
    ~lpm_core();

    /// @brief      Get device of this LPM core.
    ///
    /// @return     ll_device_sptr of the LPM core's device.
    const ll_device_sptr& get_ll_device() const;

    /// @brief      Get the core ID.
    ///
    /// @return Core ID.
    size_t get_id() const;

    /// @name Update API-s
    /// @{

    /// @brief Calculate HW updates needed as a result of a series of actions.
    ///
    /// @param[in]      actions                 Action list to perform on core.
    ///
    /// @return #la_status.
    la_status update_tcam(lpm_implementation_desc_vec& l1_actions);

    /// @brief Write the HW changes calculated in last update.
    ///
    /// @param[in]      l1_l2_actions           L1 and L2 buckets to write to the HW.
    ///
    /// @return #la_status.
    la_status commit_hw_updates(const lpm_implementation_desc_vec_levels& l1_l2_actions);

    /// @brief Rollback every software change of the last update performed.
    void withdraw();

    /// @}

    /// @name Data access
    /// @{

    /// @brief Find longest prefix match of given key.
    ///
    /// If no match found, hit key and hit payload are set to be zero width bit vectors.
    ///
    /// @param[in]      key                     Key to lookup.
    /// @param[out]     out_hit_key             Key of hit entry.
    /// @param[out]     out_hit_payload         Payload of hit entry.
    ///
    /// @return #la_status.
    la_status lookup(const lpm_key_t& key, lpm_key_t& out_hit_key, lpm_payload_t& out_hit_payload) const;

    /// @brief Get LPM tree.
    ///
    /// @return LPM tree.
    const bucketing_tree& get_tree() const;

    /// @brief Get TCAM.
    ///
    /// @return TCAM.
    const lpm_core_tcam& get_tcam() const;

    /// @brief Get LPM HBM Cache Manager.
    ///
    /// @return LPM HBM Cache Manager.
    lpm_hbm_cache_manager& get_hbm_cache_manager();

    /// @brief Get Core HW writer.
    ///
    /// @return core HW writer.
    const lpm_core_hw_writer& get_core_hw_writer() const;

    /// @brief Move L2 bucket from SRAM/HBM to HBM/SRAM.
    ///
    /// @param[in]      src_hw_index            HW index of bucket to move.
    /// @param[in]      destination             Destination of movement.
    ///
    /// @return #la_status.
    la_status move_l2_bucket(lpm_bucket_index_t src_hw_index, l2_bucket_location_e destination);

    /// @brief Move L2 bucket to a new row.
    ///
    /// @param[in]      src_hw_index            HW index of bucket to move.
    /// @param[in]      dst_hw_index            HW index to move bucket to.
    ///
    /// @return #la_status.
    la_status move_l2_bucket_to_row(lpm_bucket_index_t src_hw_index, lpm_bucket_index_t dst_hw_index);

    ///@ brief L2 bucket was accessed.
    ///
    /// @param[in]     hw_index                HW Index of bucket which was accessed.
    void notify_l2_bucket_accessed(size_t hw_index);

    /// @brief loop to collect LPM-HBM caching related statistics.
    void collect_bucket_hotness_stats();

    /// @brief loop to perform LPM-HBM caching.
    void perform_caching();

    /// @brief Disable interrupt masking and clear error registers.
    void unmask_and_clear_l2_ecc_interrupt_registers() const;

    /// @}

    /// @brief Force overriding the is_leaf field in HW representation of L2 node.
    ///
    /// @param[in]        key           Key to force is_leaf for.
    /// @param[in]        is_leaf       Value of is_leaf to force.
    ///
    /// @return #la_status;
    la_status enable_force_l2_node_is_leaf(const lpm_key_t& key, bool is_leaf);

    /// @brief Stop overriding the is_leaf field in HW representation of L2 node.
    ///
    /// @param[in]        key         Key to force is_leaf for.
    ///
    /// @return #la_status;
    la_status disable_force_l2_node_is_leaf(const lpm_key_t& key);

    /// @brief Get TCAM lines.
    ///
    /// @return size of used TCAM lines.
    size_t get_used_tcam_lines() const;

    /// @brief Get number of SRAM buckets to reserve.
    ///
    /// @return Number of SRAM buckets to reserve.
    size_t get_free_l2_sram_buckets_to_reserve() const;

    /// @brief Set number of SRAM buckets to reserve.
    ///
    /// @param[in]      num_buckets_to_reserve  Number of buckets to reserve.
    void set_free_l2_sram_buckets_to_reserve(size_t num_buckets_to_reserve);

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_core();

    /// @brief Clear all data needed for the current iteration.
    void clear_iteration_members();

    /// @brief Update HW according to changes on all three levels.
    ///
    /// Generate a series of update instructions for the HW.
    /// The order of the instructions provided must preserve indirection correctness in every cycle.
    /// L1 entries changelist dictates the L2 bucket changes, and TCAM entries changelist dictates L1 bucket changes.
    ///
    /// @param[in]      l2_updates      L2 updates.
    /// @param[in]      l1_updates      L1 updates.
    /// @param[in]      tcam_updates    TCAM updates.
    ///
    /// @return #la_status.
    la_status update_hardware(const lpm_implementation_desc_vec& l2_updates,
                              const lpm_implementation_desc_vec& l1_updates,
                              const lpm_core_tcam::hardware_instruction_vec& tcam_updates);

    /// @brief Instruct the HW only of the insertion actions of a specific tree level.
    ///
    /// @param[in]      tree_updates      Tree updates.
    /// @param[in]      level             Level of the tree to update.
    ///
    /// @return #la_status.
    la_status update_tree_insertions(const lpm_implementation_desc_vec& tree_updates, lpm_level_e level) const;

    /// @brief Instruct the HW only of the refresh actions of a specific tree level.
    ///
    /// @param[in]      tree_updates      Tree updates.
    /// @param[in]      level             Level of the tree to update.
    ///
    /// @return #la_status.
    la_status update_tree_refreshes(const lpm_implementation_desc_vec& tree_updates, lpm_level_e level) const;

    /// @brief Instruct the HW to perform updates to the TCAM.
    ///
    /// @param[in]      tcam_updates    TCAM updates.
    ///
    /// @return #la_status.
    la_status update_tcam_instructions(const lpm_core_tcam::hardware_instruction_vec& tcam_updates);

    // Vector of size_t to hold indices of actions.
    typedef vector_alloc<size_t> lpm_indices_vec_t;

    /// @brief Find insertion indices in vector of action descriptors.
    ///
    /// @params[in]     updates         Vector of action descriptors.
    ///
    /// @return Vector of indices of insertion actions.
    lpm_indices_vec_t get_insertion_indices(const lpm_implementation_desc_vec& updates) const;

    /// @brief Find refresh indices in vector of action descriptors.
    ///
    /// @params[in]     updates         Vector of action descriptors.
    ///
    /// @return Vector of indices of refresh actions.
    lpm_indices_vec_t get_refresh_indices(const lpm_implementation_desc_vec& updates) const;

    /// @brief Find remove indices in vector of action descriptors.
    ///
    /// @params[in]     updates         Vector of action descriptors.
    ///
    /// @return Vector of indices of remove actions.
    lpm_indices_vec_t get_remove_indices(const lpm_implementation_desc_vec& updates) const;

    /// @brief Log bucket nodes.
    ///
    /// @param[in]      level           Level of Bucket to log (used if bucket is null).
    /// @param[in]      hw_index        HW index of Bucket to log (used if bucket is null).
    /// @param[in]      lpm_bucket      Bucket to log.
    void log_bucket_debug(lpm_level_e level, lpm_bucket_index_t hw_index, const lpm_bucket* bucket) const;

    /// @brief Write bucket to HW according to its HW index and its level.
    ///
    /// @param[in]      bucket          Bucket to write.
    ///
    /// @return #la_status.
    la_status write_bucket(const lpm_bucket* bucket) const;

    /// @brief Write a TCAM block to HW.
    ///
    /// @param[in]      location               TCAM block location to write to.
    /// @param[in]      key                    TCAM key.
    /// @param[in]      payload                TCAM payload.
    /// @param[in]      only_update_payload    Don't modify key/mask, only payload.
    ///
    /// @return #la_status.
    la_status write_tcam_row(const tcam_cell_location& location,
                             const lpm_key_t& key,
                             lpm_payload_t payload,
                             bool only_update_payload);

    /// @brief Invalidate a TCAM block in HW.
    ///
    /// @param[in]      location               TCAM block location to write to.
    /// @param[in]      key                    Key in the TCAM block.
    ///
    /// @return #la_status.
    la_status invalidate_tcam_row(const tcam_cell_location& location, const lpm_key_t& key);

    /// @brief Get a list of L2 buckets which should be cached into on-die SRAM.
    ///
    /// @return Vector of bucket indices to cache.
    vector_alloc<lpm_bucket_index_t> get_buckets_to_cache();

    /// @brief Get a list of L2 buckets which should be evicted to HBM.
    ///
    /// @param[in]      required_space             Required free space in SRAM.
    ///
    /// @return Vector of bucket indices to evict.
    vector_alloc<lpm_bucket_index_t> get_buckets_to_evict(size_t required_space);

    /// @brief Perform caching to SRAM of a given list of L2 buckets.
    ///
    /// @param[in]      buckets_to_cache           Vector of indices of L2 buckets to cache to SRAM.
    void cache_buckets(vector_alloc<lpm_bucket_index_t>& buckets_to_cache);

    /// @brief Perform eviction to HBM of a given list of L2 buckets.
    ///
    /// @param[in]      buckets_to_evict           Vector of indices of L2 buckets to evict to HBM.
    void evict_buckets(vector_alloc<lpm_bucket_index_t>& buckets_to_evict);

    /// @brief Mask/unmask L2 ECC registers.
    ///
    /// In Pacific, false ECC error notification is raised when writing to LPM. This is part of the WA.
    ///
    /// @param[in]     enable          Boolean specifies whether to mask or unmask the interrupt.
    ///
    /// @return #la_status.
    la_status set_l2_sram_ecc_regs_interrupts_enabled(bool enable) const;

    // Members
    ll_device_sptr m_ll_device;        ///< ll_device this core belongs to.
    bucketing_tree_wptr m_tree;        ///< L1/L2 LPM tree.
    lpm_core_tcam_sptr m_tcam;         ///< LPM TCAM.
    lpm_core_id_t m_core_id;           ///< Core ID.
    const size_t m_hbm_address_offset; ///< Offset to first index in HBM.

    size_t m_l2_sram_free_buckets_to_reserve; ///< Number of SRAM buckets to keep free.

    lpm_core_tcam::hardware_instruction_vec m_tcam_updates;

    lpm_core_hw_writer_sptr m_hw_writer; ///< Helper class for HW writing.

    // Statistics
    mutable size_t m_tcam_writes;
    mutable size_t m_l1_writes;
    mutable size_t m_l2_writes;

    // L2 ECC error handling
    mutable bool m_ecc_err_handling_in_progress; ///< Are ECC errors aleardy being handled.
};

} // namespace silicon_one

#endif // __LEABA_LPM_CORE_H__
