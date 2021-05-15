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

#include "lpm_hbm_cache_manager.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"

namespace silicon_one
{

lpm_hbm_cache_manager::lpm_hbm_cache_manager(const ll_device_sptr& ldevice,
                                             std::string name,
                                             size_t max_num_of_sram_buckets,
                                             size_t max_num_of_hbm_buckets)
    : m_ll_device(ldevice),
      m_name(name),
      m_num_of_hbm_buckets(max_num_of_hbm_buckets),
      m_hbm_address_offset(max_num_of_sram_buckets),
      m_bucket_hw_index_to_hotness_group(m_hbm_address_offset + m_num_of_hbm_buckets),
      m_frozen_bucket_group(0),
      m_counter_cachings(0),
      m_counter_evictions(0),
      m_simulated_time_mode(false)
{
    for (size_t i = 0; i < m_bucket_hw_index_to_hotness_group.size(); i++) {
        m_bucket_hw_index_to_hotness_group[i].hotness_group_it = m_bucket_hotness_invalid_list.end();
    }
    m_last_hotness_update_time = std::chrono::steady_clock::now();
}

void
lpm_hbm_cache_manager::notify_bucket_created(lpm_bucket_index_t hw_index)
{
    log_debug(TABLES, "%s: %s(hw_index=%d)", m_name.c_str(), __func__, hw_index);

    dassert_crit(hw_index >= 0);
    init_bucket_hotness(hw_index);
}

void
lpm_hbm_cache_manager::notify_bucket_created(lpm_bucket_index_t hw_index, size_t hotness)
{
    log_debug(TABLES, "%s: %s(hw_index=%d, hotness=%zu)", m_name.c_str(), __func__, hw_index, hotness);
    dassert_crit(hw_index >= 0);

    size_t hotness_group = get_hotness_group_by_hotness(hotness);
    dassert_crit(is_valid_hotness_group(hotness_group));

    add_bucket_to_stats(hw_index, hotness_group);
}

void
lpm_hbm_cache_manager::init_bucket_hotness(lpm_bucket_index_t hw_index)
{
    dassert_crit(hw_index >= 0);
    size_t hotness_group = get_hotness_group_by_hotness(m_lpm_hbm_caching_params.initial_bucket_hotness);
    add_bucket_to_stats(hw_index, hotness_group);
}

void
lpm_hbm_cache_manager::notify_bucket_removed(lpm_bucket_index_t hw_index)
{
    log_debug(TABLES, "%s: %s(hw_index=%d)", m_name.c_str(), __func__, hw_index);

    dassert_crit(hw_index >= 0);
    remove_bucket_from_stats(hw_index);
}

void
lpm_hbm_cache_manager::notify_bucket_moved(lpm_bucket_index_t src_hw_index, lpm_bucket_index_t dst_hw_index)
{
    log_debug(TABLES, "%s: %s(src_hw_index=%d, dst_hw_index=%d)", m_name.c_str(), __func__, src_hw_index, dst_hw_index);
    dassert_crit(src_hw_index >= 0);
    dassert_crit(dst_hw_index >= 0);

    size_t hotness_group = m_bucket_hw_index_to_hotness_group[src_hw_index].hotness_group;
    dassert_crit(is_valid_hotness_group(hotness_group));

    add_bucket_to_stats(dst_hw_index, hotness_group);
    remove_bucket_from_stats(src_hw_index);

    bool is_src_in_hbm = is_hw_index_in_hbm(src_hw_index);
    bool is_dst_in_hbm = is_hw_index_in_hbm(dst_hw_index);
    if (is_src_in_hbm && !is_dst_in_hbm) {
        m_counter_cachings++;
    } else if (!is_src_in_hbm && is_dst_in_hbm) {
        m_counter_evictions++;
    }
}

void
lpm_hbm_cache_manager::set_bucket_eviction_enable(lpm_bucket_index_t hw_index, bool is_evictable)
{
    dassert_crit(hw_index >= 0);
    dassert_crit(m_bucket_hw_index_to_hotness_group[hw_index].hotness_group_it != m_bucket_hotness_invalid_list.end());

    log_debug(TABLES, "%s::%s: hw_index=%d caching enable is now %d", m_name.c_str(), __func__, hw_index, is_evictable);

    bool already_is_evictable = get_is_evictable(hw_index);
    if (is_evictable == already_is_evictable) {
        return;
    }

    size_t new_hotness;
    if (is_evictable) {
        new_hotness = get_hotness_group_by_hotness(m_lpm_hbm_caching_params.initial_bucket_hotness);
    } else {
        new_hotness = HOTNESS_LEVEL_ALWAYS_HOT;
    }

    remove_bucket_from_stats(hw_index);
    add_bucket_to_stats(hw_index, new_hotness);
}

bool
lpm_hbm_cache_manager::get_is_evictable(lpm_bucket_index_t hw_index) const
{
    dassert_crit(hw_index >= 0);
    dassert_crit(m_bucket_hw_index_to_hotness_group[hw_index].hotness_group_it != m_bucket_hotness_invalid_list.end());

    size_t current_hotness_group = m_bucket_hw_index_to_hotness_group[hw_index].hotness_group;
    size_t current_hotness = get_hotness_of_group(current_hotness_group);
    bool is_evictable = (current_hotness != HOTNESS_LEVEL_ALWAYS_HOT);
    return is_evictable;
}

void
lpm_hbm_cache_manager::notify_bucket_accessed(lpm_bucket_index_t hw_index)
{
    dassert_crit(hw_index >= 0);

    // skip if stats register has garbage data
    if (static_cast<size_t>(hw_index) >= m_hbm_address_offset + m_num_of_hbm_buckets) {
        return;
    }

    log_spam(TABLES,
             "%s: L2 Bucket Accessed: hw_index = %d (location: %s)",
             m_name.c_str(),
             hw_index,
             is_hw_index_in_hbm(hw_index) ? "HBM" : "SRAM");
    make_bucket_hotter(hw_index);
}

const vector_alloc<lpm_bucket_index_t>
lpm_hbm_cache_manager::get_buckets_to_evict(size_t max_buckets) const
{
    vector_alloc<lpm_bucket_index_t> bucket_indices;
    size_t nbuckets = 0;

    for (size_t hotness = 0; hotness < m_lpm_hbm_caching_params.hotness_threshold_to_evict; hotness++) {
        size_t hotness_group = get_hotness_group_by_hotness(hotness);
        dassert_crit(is_valid_hotness_group(hotness_group));

        for (const auto& hw_index : m_bucket_hotness_groups[SRAM][hotness_group]) {
            dassert_crit(!is_hw_index_in_hbm(hw_index));

            if (nbuckets == max_buckets) {
                return bucket_indices;
            }

            log_xdebug(TABLES,
                       "%s: reporting bucket %d for eviction to HBM. Hotness: %zu (group %zu)  "
                       "Eviction hotness theshold: %zu  Trying to evict up-to %zu buckets",
                       m_name.c_str(),
                       hw_index,
                       hotness,
                       hotness_group,
                       m_lpm_hbm_caching_params.hotness_threshold_to_evict,
                       max_buckets);
            bucket_indices.push_back(hw_index);
            nbuckets++;
        }
    }
    return bucket_indices;
}

const vector_alloc<lpm_bucket_index_t>
lpm_hbm_cache_manager::get_buckets_to_cache() const
{
    vector_alloc<lpm_bucket_index_t> bucket_indices;
    for (size_t hotness = NUM_HOTNESS_LEVELS - 1; hotness >= m_lpm_hbm_caching_params.hotness_threshold_to_cache; hotness--) {
        size_t hotness_group = get_hotness_group_by_hotness(hotness);
        dassert_crit(is_valid_hotness_group(hotness_group));

        for (const auto& hw_index : m_bucket_hotness_groups[HBM][hotness_group]) {
            dassert_crit(is_hw_index_in_hbm(hw_index));

            log_xdebug(TABLES,
                       "%s: reporting bucket %d for caching to SRAM. Hotness: %zu (group %zu)  "
                       "Caching hotness theshold: %zu",
                       m_name.c_str(),
                       hw_index,
                       hotness,
                       hotness_group,
                       m_lpm_hbm_caching_params.hotness_threshold_to_cache);
            bucket_indices.push_back(hw_index);
            if (bucket_indices.size() == m_lpm_hbm_caching_params.max_buckets_to_cache) {
                return bucket_indices;
            }
        }
    }
    return bucket_indices;
}

void
lpm_hbm_cache_manager::cool_down_buckets()
{
    if (m_simulated_time_mode) {
        return;
    }
    auto now = std::chrono::steady_clock::now();
    auto usecs = std::chrono::duration_cast<std::chrono::microseconds>(now - m_last_hotness_update_time).count();
    bool updated = cool_down_buckets(usecs);
    if (updated) {
        m_last_hotness_update_time = now;
    }
}

bool
lpm_hbm_cache_manager::cool_down_buckets(size_t usecs_passed)
{
    size_t how_much_to_cool = usecs_passed / m_lpm_hbm_caching_params.usecs_until_hotness_decrease;
    if (how_much_to_cool == 0) {
        return false;
    }

    if (how_much_to_cool > NUM_CACHING_HOTNESS_LEVELS) {
        how_much_to_cool = NUM_CACHING_HOTNESS_LEVELS;
    }

    log_spam(TABLES, "%s: Making all buckets colder by %zu", m_name.c_str(), how_much_to_cool);

    for (size_t i = 0; i < how_much_to_cool; i++) {
        size_t next_frozen_group = (m_frozen_bucket_group + 1) % NUM_CACHING_HOTNESS_LEVELS;
        move_buckets_between_hotness_groups(m_frozen_bucket_group, next_frozen_group);
        m_frozen_bucket_group = next_frozen_group;
    }

    return true;
}

void
lpm_hbm_cache_manager::make_bucket_hotter(lpm_bucket_index_t hw_index)
{
    dassert_crit(hw_index >= 0);

    size_t current_hotness_group = m_bucket_hw_index_to_hotness_group[hw_index].hotness_group;
    if (current_hotness_group == HOTNESS_GROUP_NONE) {
        return;
    }

    size_t current_hotness = get_hotness_of_group(current_hotness_group);

    if (current_hotness >= m_lpm_hbm_caching_params.max_hotness_level) {
        return;
    }

    remove_bucket_from_stats(hw_index);

    bool is_hbm = is_hw_index_in_hbm(hw_index);
    const size_t hotness_increment
        = is_hbm ? m_lpm_hbm_caching_params.hotness_increase_on_hit_hbm : m_lpm_hbm_caching_params.hotness_increase_on_hit_sram;
    size_t new_hotness = std::min(current_hotness + hotness_increment, static_cast<size_t>(MAX_CACHABLE_HOTNESS_LEVEL));
    size_t new_hotness_group = get_hotness_group_by_hotness(new_hotness);

    add_bucket_to_stats(hw_index, new_hotness_group);

    log_spam(TABLES,
             "%s: Bucket %d became hotter: %zu -> %zu (group: %zu -> %zu)",
             m_name.c_str(),
             hw_index,
             current_hotness,
             new_hotness,
             current_hotness_group,
             new_hotness_group);
}

void
lpm_hbm_cache_manager::remove_bucket_from_stats(lpm_bucket_index_t hw_index)
{
    dassert_crit(hw_index >= 0);

    bool is_hbm = is_hw_index_in_hbm(hw_index);
    size_t hotness_group = m_bucket_hw_index_to_hotness_group[hw_index].hotness_group;
    dassert_crit(is_valid_hotness_group(hotness_group));

    log_xdebug(TABLES,
               "%s: Removing bucket %d  from stats.  is_hbm? %s  hotness group %zu",
               m_name.c_str(),
               hw_index,
               is_hbm ? "Yes" : "No",
               hotness_group);

    std::list<lpm_bucket_index_t>::const_iterator it = m_bucket_hw_index_to_hotness_group[hw_index].hotness_group_it;
    dassert_crit(it != m_bucket_hotness_invalid_list.end());

    m_bucket_hotness_groups[is_hbm][hotness_group].erase(it);
    m_bucket_hw_index_to_hotness_group[hw_index].hotness_group = HOTNESS_GROUP_NONE;
    m_bucket_hw_index_to_hotness_group[hw_index].hotness_group_it = m_bucket_hotness_invalid_list.end();
}

void
lpm_hbm_cache_manager::add_bucket_to_stats(lpm_bucket_index_t hw_index, size_t hotness_group)
{
    dassert_crit(hw_index >= 0);
    bool is_hbm = is_hw_index_in_hbm(hw_index);
    dassert_crit(is_valid_hotness_group(hotness_group));

    log_xdebug(TABLES,
               "%s: Adding bucket %d  to stats.  is_hbm? %s  hotness group %zu",
               m_name.c_str(),
               hw_index,
               is_hbm ? "Yes" : "No",
               hotness_group);

    std::list<lpm_bucket_index_t>& group_list = m_bucket_hotness_groups[is_hbm][hotness_group];
    dassert_slow(!contains(group_list, hw_index));
    dassert_crit(m_bucket_hw_index_to_hotness_group[hw_index].hotness_group == HOTNESS_GROUP_NONE);

    auto it = group_list.insert(group_list.begin(), hw_index);

    m_bucket_hw_index_to_hotness_group[hw_index].hotness_group = hotness_group;
    m_bucket_hw_index_to_hotness_group[hw_index].hotness_group_it = it;
}

void
lpm_hbm_cache_manager::move_buckets_between_hotness_groups(size_t src_group, size_t dst_group)
{
    dassert_crit(is_valid_hotness_group(src_group));
    dassert_crit(is_valid_hotness_group(dst_group));

    for (size_t location : {lpm_hbm_cache_manager::SRAM, lpm_hbm_cache_manager::HBM}) {

        for (auto hw_index : m_bucket_hotness_groups[location][src_group]) {
            m_bucket_hw_index_to_hotness_group[hw_index].hotness_group = dst_group;
        }

        m_bucket_hotness_groups[location][dst_group].splice(m_bucket_hotness_groups[location][dst_group].end(),
                                                            m_bucket_hotness_groups[location][src_group]);
    }
}

size_t
lpm_hbm_cache_manager::get_hotness_group_by_hotness(size_t hotness) const
{
    dassert_crit(hotness < NUM_HOTNESS_LEVELS);
    if (hotness == HOTNESS_LEVEL_ALWAYS_HOT) {
        return HOTNESS_LEVEL_ALWAYS_HOT;
    }
    return (hotness + m_frozen_bucket_group) % NUM_CACHING_HOTNESS_LEVELS;
}

size_t
lpm_hbm_cache_manager::get_hotness_of_group(size_t group_index) const
{
    dassert_crit(is_valid_hotness_group(group_index));
    if (group_index == HOTNESS_LEVEL_ALWAYS_HOT) {
        return HOTNESS_LEVEL_ALWAYS_HOT;
    }
    return (group_index + NUM_CACHING_HOTNESS_LEVELS - m_frozen_bucket_group) % NUM_CACHING_HOTNESS_LEVELS;
}

bool
lpm_hbm_cache_manager::is_hw_index_in_hbm(lpm_bucket_index_t hw_index) const
{
    dassert_crit(hw_index >= 0);
    return (static_cast<size_t>(hw_index) >= m_hbm_address_offset);
}

const ll_device_sptr&
lpm_hbm_cache_manager::get_ll_device() const
{
    return m_ll_device;
}

lpm_hbm_cache_manager::lpm_hbm_caching_params
lpm_hbm_cache_manager::get_caching_params() const
{
    return m_lpm_hbm_caching_params;
}

void
lpm_hbm_cache_manager::set_caching_params(lpm_hbm_cache_manager::lpm_hbm_caching_params params)
{
    if (params.initial_bucket_hotness >= NUM_CACHING_HOTNESS_LEVELS) {
        params.initial_bucket_hotness = NUM_CACHING_HOTNESS_LEVELS - 1;
    }
    if (params.hotness_threshold_to_cache >= NUM_CACHING_HOTNESS_LEVELS) {
        params.hotness_threshold_to_cache = NUM_CACHING_HOTNESS_LEVELS;
    }
    if (params.hotness_threshold_to_evict > NUM_CACHING_HOTNESS_LEVELS) {
        params.hotness_threshold_to_evict = NUM_CACHING_HOTNESS_LEVELS;
    }
    if (params.max_hotness_level >= NUM_CACHING_HOTNESS_LEVELS) {
        params.max_hotness_level = NUM_CACHING_HOTNESS_LEVELS - 1;
    }
    m_lpm_hbm_caching_params = params;
}

lpm_hbm_cache_manager::lpm_hbm_caching_stats
lpm_hbm_cache_manager::get_statistics(bool reset_counters)
{
    lpm_hbm_caching_stats stats;
    for (size_t hotness = 0; hotness < NUM_CACHING_HOTNESS_LEVELS; hotness++) {
        size_t group = get_hotness_group_by_hotness(hotness);
        dassert_crit(is_valid_hotness_group(group));

        stats.sram_hotness_histogram[hotness] = m_bucket_hotness_groups[SRAM][group].size();
        stats.hbm_hotness_histogram[hotness] = m_bucket_hotness_groups[HBM][group].size();

        if (hotness < m_lpm_hbm_caching_params.hotness_threshold_to_evict) {
            stats.sram_num_cold_buckets += stats.sram_hotness_histogram[hotness];
            stats.hbm_num_cold_buckets += stats.hbm_hotness_histogram[hotness];
        } else if (hotness >= m_lpm_hbm_caching_params.hotness_threshold_to_cache) {
            stats.sram_num_hot_buckets += stats.sram_hotness_histogram[hotness];
            stats.hbm_num_hot_buckets += stats.hbm_hotness_histogram[hotness];
        } else {
            stats.sram_num_moderate_buckets += stats.sram_hotness_histogram[hotness];
            stats.hbm_num_moderate_buckets += stats.hbm_hotness_histogram[hotness];
        }

        stats.sram_num_buckets += stats.sram_hotness_histogram[hotness];
        stats.hbm_num_buckets += stats.hbm_hotness_histogram[hotness];
    }

    stats.cachings = m_counter_cachings;
    stats.evictions = m_counter_evictions;

    if (reset_counters) {
        m_counter_cachings = 0;
        m_counter_evictions = 0;
    }

    return stats;
}

bool
lpm_hbm_cache_manager::is_valid_hotness_group(size_t hotness_group) const
{
    if (hotness_group == HOTNESS_GROUP_NONE) {
        log_debug(TABLES, "%s: hotness group is NONE", __func__);
        return false;
    }

    if (hotness_group >= NUM_HOTNESS_LEVELS) {
        log_debug(TABLES,
                  "%s: hotness group %zu is > NUM_HOTNESS_LEVELS(%zu)",
                  __func__,
                  hotness_group,
                  static_cast<size_t>(NUM_HOTNESS_LEVELS));
        return false;
    }
    return true;
}

void
lpm_hbm_cache_manager::load_m_bucket_hw_index_to_hotness_group(
    const vector_alloc<lpm_hbm_cache_manager::bucket_hotness_data>& serialized_data)
{
    m_bucket_hw_index_to_hotness_group = serialized_data;
    for (size_t bucket_hw_index = 0; bucket_hw_index < m_bucket_hw_index_to_hotness_group.size(); bucket_hw_index++) {
        m_bucket_hw_index_to_hotness_group[bucket_hw_index].hotness_group_it = m_bucket_hotness_invalid_list.end();
    }
    for (auto& location : m_bucket_hotness_groups) {
        for (auto& bucket_hotness_group : location) {
            for (auto it = bucket_hotness_group.begin(); it != bucket_hotness_group.end(); ++it) {
                auto bucket_index = *it;
                m_bucket_hw_index_to_hotness_group[bucket_index].hotness_group_it = it;
            }
        }
    }
}

void
lpm_hbm_cache_manager::toggle_simulated_time_mode(bool on)
{
    m_simulated_time_mode = on;
}

size_t
lpm_hbm_cache_manager::get_hotness_of_bucket(lpm_bucket_index_t hw_index)
{
    if ((hw_index < 0) || (static_cast<size_t>(hw_index) >= m_bucket_hw_index_to_hotness_group.size())) {
        return HOTNESS_GROUP_NONE;
    }

    size_t hotness_group = m_bucket_hw_index_to_hotness_group[hw_index].hotness_group;
    if (hotness_group == HOTNESS_GROUP_NONE) {
        return HOTNESS_GROUP_NONE;
    }

    size_t hotness = get_hotness_of_group(hotness_group);
    return hotness;
}

size_t
lpm_hbm_cache_manager::get_hbm_address_offset() const
{
    return m_hbm_address_offset;
}

} // namespace silicon_one
