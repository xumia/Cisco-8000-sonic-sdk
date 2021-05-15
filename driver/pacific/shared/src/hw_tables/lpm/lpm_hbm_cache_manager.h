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

#ifndef __LEABA_LPM_HBM_CACHE_MANAGER_H__
#define __LEABA_LPM_HBM_CACHE_MANAGER_H__

#include <chrono>
#include <list>

#include "common/allocator_wrapper.h"
#include "common/la_status.h"
#include "lld/ll_device.h"
#include "lpm_internal_types.h"

/// @file

namespace silicon_one
{

class lpm_hbm_cache_manager
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    static constexpr size_t NUM_HOTNESS_LEVELS = 21;
    static constexpr size_t NUM_CACHING_HOTNESS_LEVELS = NUM_HOTNESS_LEVELS - 1;
    static constexpr size_t HOTNESS_LEVEL_ALWAYS_HOT = NUM_HOTNESS_LEVELS - 1;
    static constexpr size_t MAX_CACHABLE_HOTNESS_LEVEL = HOTNESS_LEVEL_ALWAYS_HOT - 1;

    ///@ Brief Caching parameters. Initialized to default values.
    struct lpm_hbm_caching_params {
        size_t hotness_increase_on_hit_hbm
            = 5; ///< Whenever a bucket is observed being accessed in HBM, increase its hotness by this amount.
        size_t hotness_increase_on_hit_sram
            = 5; ///< Whenever a bucket is observed being accessed in SRAM, increase its hotness by this amount.
        size_t initial_bucket_hotness = 0;              ///< A new bucket will start with this hotness.
        size_t usecs_until_hotness_decrease = 10000000; ///< Decrase hotness of all buckets every this amound of microseconds.
        size_t hotness_threshold_to_cache
            = 7; ///< A bucket with hotness greater than or equal to this value is considered hot and should cached in SRAM.
        size_t hotness_threshold_to_evict
            = 1; ///< A bucket with hotness less than this value is considered cold and can be evicted from SRAM.
        size_t max_buckets_to_cache = 0;                       ///< Maximum buckets to cahce in one shot. 0 = no max.
        size_t max_hotness_level = MAX_CACHABLE_HOTNESS_LEVEL; ///< Maximum hotness a bucket is allowed to reach.
    };

    struct lpm_hbm_caching_stats {
        size_t cachings = 0;
        size_t evictions = 0;
        size_t sram_num_cold_buckets = 0;
        size_t sram_num_moderate_buckets = 0;
        size_t sram_num_hot_buckets = 0;
        size_t sram_num_buckets = 0;
        size_t hbm_num_cold_buckets = 0;
        size_t hbm_num_moderate_buckets = 0;
        size_t hbm_num_hot_buckets = 0;
        size_t hbm_num_buckets = 0;
        std::vector<size_t> sram_hotness_histogram = std::vector<size_t>(NUM_CACHING_HOTNESS_LEVELS, 0);
        std::vector<size_t> hbm_hotness_histogram = std::vector<size_t>(NUM_CACHING_HOTNESS_LEVELS, 0);
    };

    /// @brief Construct a LPM HBM Cache manager
    lpm_hbm_cache_manager(const ll_device_sptr& ldevice,
                          std::string name,
                          size_t max_num_of_sram_buckets,
                          size_t max_num_of_hbm_buckets);

    /// @brief Default c'tor - shouldn't be called, allowed only for serialization purposes.
    lpm_hbm_cache_manager() = default;

    /// @brief      Get ll_device of this LPM HBM Cache Manager.
    ///
    /// @return     ll_device_sptr of this object's device.
    const ll_device_sptr& get_ll_device() const;

    /// @brief Notify that bucket was created.
    ///
    /// @param[in]     hw_index         HW index of bucket.
    void notify_bucket_created(lpm_bucket_index_t hw_index);

    /// @brief Notify that bucket was created.
    ///
    /// @param[in]     hw_index         HW index of bucket.
    ///
    /// @param[in]     hotness          Hotness of the bucket in the previous core.
    void notify_bucket_created(lpm_bucket_index_t hw_index, size_t hotness);

    /// @brief Notify that bucket was removed from tree.
    ///
    /// @param[in]     hw_index         HW index of bucket.
    void notify_bucket_removed(lpm_bucket_index_t hw_index);

    /// @brief Notify that bucket was moved between SRAM and HBM.
    ///
    /// @param[in]     hw_index         HW index of bucket.
    void notify_bucket_moved(lpm_bucket_index_t src_hw_index, lpm_bucket_index_t dst_hw_index);

    /// @brief Notify that bucket was accessed by a packet lookup.
    ///
    /// @param[in]     hw_index         HW index of bucket.
    void notify_bucket_accessed(lpm_bucket_index_t hw_index);

    /// @brief Enable/Disable bucket eviction to HBM.
    ///
    /// @param[in]     hw_index         HW index of bucket.
    /// @param[in]     is_evictable     Enable/Disable eviction of the given bucket.
    void set_bucket_eviction_enable(lpm_bucket_index_t hw_index, bool is_evictable);

    /// @brief Get a number of buckets which can be eviceted from SRAM to HBM.
    ///
    /// @param[in]     max_buckets      Maximum number of buckets to get
    ///
    /// @return Vector of buckets to Evict.
    const vector_alloc<lpm_bucket_index_t> get_buckets_to_evict(size_t max_buckets) const;

    /// @brief Get a number of buckets which should be cached in SRAM.
    ///
    /// @return Vector of buckets to Cache.
    const vector_alloc<lpm_bucket_index_t> get_buckets_to_cache() const;

    /// @brief Cool down all buckets based on how much time has past since last time.
    void cool_down_buckets();

    /// @brief Cool down all buckets given that a given amount of time has passed.
    ///
    /// @param[in]      usecs_passed   Number of usecs which passed since last update.
    ///
    /// @return Whether buckets were cooled.
    bool cool_down_buckets(size_t usecs_passed);

    /// @brief Get caching parameters.
    ///
    /// @return Caching paramters.
    lpm_hbm_caching_params get_caching_params() const;

    /// @brief Set caching parameters.
    ///
    /// @param[in]      lpm_hbm_caching_params Caching parametrs.
    void set_caching_params(lpm_hbm_caching_params params);

    /// @brief Get statistics about caching.
    ///
    /// @param[in]      reset_counters          Whether to reset the counters after reporting them.
    ///
    /// @return Caching statistics
    lpm_hbm_caching_stats get_statistics(bool reset_counters);

    /// @brief Toggle simulated time mode on/off.
    /// Simulated time gives more control and accuracy to tests.
    ///
    /// @param[in]      on      Whether to toggle the simulated time on or off.
    void toggle_simulated_time_mode(bool on);

    /// @brief Return hotness of a bucket.
    ///
    /// @param[in]     hw_index   HW index of the bucket.
    ///
    /// @return Bucket hotness.
    size_t get_hotness_of_bucket(lpm_bucket_index_t hw_index);

    /// @brief Return if bucket is evictable.
    ///
    /// @param[in]     hw_index   HW index of the bucket.
    ///
    /// @return if the bucket with the given hw_index is evictable.
    bool get_is_evictable(lpm_bucket_index_t hw_index) const;

    /// @brief Get HBM start address.
    ///
    /// @return HBM address offset value.
    size_t get_hbm_address_offset() const;

private:
    struct bucket_hotness_data {
        size_t hotness_group = HOTNESS_GROUP_NONE; ///< Hotness group of bucket.
        std::list<lpm_bucket_index_t>::const_iterator
            hotness_group_it; ///< Iterator pointing to bucket's item within hotness group.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(bucket_hotness_data)

    static constexpr size_t HOTNESS_GROUP_NONE = static_cast<size_t>(-1);

    /// @brief Remove bucket from caching statistics.
    ///
    /// @param[in]     hw_index         HW index of bucket.
    void remove_bucket_from_stats(lpm_bucket_index_t hw_index);

    /// @brief Add bucket to caching statistics.
    ///
    /// @param[in]     hw_index         HW index of bucket.
    /// @param[in]     hotness_group    Hotness group to add bucket to.
    void add_bucket_to_stats(lpm_bucket_index_t hw_index, size_t hotness_group);

    /// @ brief Return hotness group index of a given hotness.
    ///
    /// @param[in]    hotness      Desired hotness.
    ///
    /// @return Index of group with desired hotness.
    size_t get_hotness_group_by_hotness(size_t hotness) const;

    /// @ brief Return hotness of a given group index.
    ///
    /// @param[in]    group_index       Hotness group index.
    ///
    /// @return Hotness of group.
    size_t get_hotness_of_group(size_t group_index) const;

    /// @ brief Initialize hotness of a bucket.
    ///
    /// @param[in]    hw_index          Hardware index of the bucket.
    void init_bucket_hotness(lpm_bucket_index_t hw_index);

    /// @ brief Make a bucket hotter by.
    ///
    /// @param[in]    hw_index          Hardware index of the bucket.
    void make_bucket_hotter(lpm_bucket_index_t hw_index);

    /// @ brief Append buckets of one hotness group to another group
    ///
    /// @param[in]    src_group         Group to move buckets from.
    /// @param[in]    dst_group         Group to move buckets to.
    void move_buckets_between_hotness_groups(size_t src_group, size_t dst_group);

    /// @brief Check if Bucket's HW index is in HBM.
    ///
    /// @param[in]     hw_index        Bucket's HW index.
    ///
    /// @return true if index is in HBM, false otherwise.
    bool is_hw_index_in_hbm(lpm_bucket_index_t hw_index) const;

    /// @brief Check if hotness group has a valid value
    ///
    /// @param[in]    hotness_group    Hotness group to check.
    ///
    /// @return true if hotness group has a valid value, false otherwise.
    bool is_valid_hotness_group(size_t hotness_group) const;

    /// @brief Manually serialize m_bucket_hw_index_to_hotness_group.
    ///
    /// @return m_bucket_hw_index_to_hotness_group to be partially automatically serialized.
    const vector_alloc<bucket_hotness_data>& save_m_bucket_hw_index_to_hotness_group() const
    {
        return m_bucket_hw_index_to_hotness_group;
    }

    /// @brief Manually deserialize of the data in m_bucket_hw_index_to_hotness_group.
    ///
    /// @param[in]    Partially deserialized m_bucket_hw_index_to_hotness_group.
    void load_m_bucket_hw_index_to_hotness_group(const vector_alloc<bucket_hotness_data>& serialized_data);

    // Members
    ll_device_sptr m_ll_device; ///< ll_device.
    std::string m_name;         ///< Name.

    size_t m_num_of_hbm_buckets;           ///< Number of buckets in HBM.
    const size_t m_hbm_address_offset = 0; ///< Address offset of HBM.

    enum { SRAM = 0, HBM = 1 };

    // For performance optimization this is a cyclic vector of NUM_CACHING_HOTNESS_LEVELS and the last element is for static for
    // HOTNESS_LEVEL_ALWAYS_HOT.
    std::list<lpm_bucket_index_t> m_bucket_hotness_groups[2 /* 0 = SRAM, 1 = HBM */]
                                                         [NUM_HOTNESS_LEVELS]; ///< Hotness group -> bucket HW index. For
                                                                               /// performance optimization this is a cyclic vector
    /// of NUM_CACHING_HOTNESS_LEVELS and the last element
    /// is for static for HOTNESS_LEVEL_ALWAYS_HOT.
    std::list<lpm_bucket_index_t> m_bucket_hotness_invalid_list;          ///< An empty list to provide an invalid iterator
    vector_alloc<bucket_hotness_data> m_bucket_hw_index_to_hotness_group; ///< Bucket HW index -> Hotness group.
    size_t m_frozen_bucket_group;                                         ///< Hotness group of coldest buckets.

    std::chrono::steady_clock::time_point m_last_hotness_update_time; ///< Time of last evaluation of hotness stats.

    lpm_hbm_caching_params m_lpm_hbm_caching_params; ///< Caching parameters.

    size_t m_counter_cachings;
    size_t m_counter_evictions;

    bool m_simulated_time_mode;
};

} // namespace silicon_one

#endif
