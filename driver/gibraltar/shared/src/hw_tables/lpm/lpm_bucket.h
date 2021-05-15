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

#ifndef __LEABA_LPM_BUCKET_H__
#define __LEABA_LPM_BUCKET_H__

#include "common/la_status.h"
#include "hw_tables/lpm_types.h"
#include "lpm_bucketing_data.h"
#include "lpm_common.h"
#include "lpm_internal_types.h"
#include <list>

/// @file

namespace silicon_one
{

/// @brief LPM bucket.
///
/// Describes a single LPM bucket, as represented in memory.
/// Basic operations include adding/removing nodes, getting a bucket's root, etc.
class lpm_bucket : public std::enable_shared_from_this<lpm_bucket>
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Contains occupancy data.
    ///
    /// Contains number of occupied and vacant entries per type.
    struct occupancy_data {
        size_t total_entries = 0;
        size_t single_entries = 0;
        size_t double_entries = 0;
    };

    virtual ~lpm_bucket()
    {
    }

    /// @brief Get bucket entries.
    ///
    /// Get a vector containing nodes of the bucket.
    ///
    /// @return         Vector of the nodes in bucket.
    virtual lpm_key_payload_vec get_entries() const = 0;

    /// @brief Get width of widest entry in bucket.
    ///
    /// @return Maximum width.
    virtual size_t get_max_width() const = 0;

    /// @brief String representation of the bucket.
    ///
    /// @return string representing the bucket.
    virtual std::string to_string() const;

    /// @brief Find longest prefix matching entry of given key.
    ///
    /// @param[in]      key                     Key to lookup.
    /// @param[out]     out_hit_key             Key the lookup hit.
    /// @param[out]     out_hit_payload         Payload of the hit.
    /// @param[out]     out_is_default          True if the bucket returns its default value, false if hit a contained entry.
    ///
    /// @return node with longest match.
    la_status lookup(const lpm_key_t& key, lpm_key_t& out_hit_key, lpm_payload_t& out_hit_payload, bool& out_is_default) const;

    /// @brief Get number of entries in bucket.
    ///
    /// This function counts each entry as a single entry regardless of its width.
    ///
    /// @return Number of entries
    size_t size() const;

    /// @brief Return width of the bucket's root.
    ///
    /// @return         width in bits.
    virtual size_t get_root_width() const = 0;

    /// @brief Reset the bucket to its initial state.
    virtual void reset() = 0;

    /// @brief Check if bucket is empty.
    ///
    /// Bucket is empty if it has no entries.
    ///
    /// @return true if empty, false otherwise.
    bool empty() const;

    /// @brief Return the SW index of the bucket.
    ///
    /// @return         SW index.
    lpm_bucket_index_t get_sw_index() const
    {
        return m_sw_index;
    }

    /// @brief Set HW index to the bucket.
    ///
    /// @param[in]      hw_index            HW index to set.
    void set_hw_index(lpm_bucket_index_t hw_index)
    {
        m_hw_index = hw_index;
    }

    /// @brief Return the HW index of the bucket.
    ///
    /// @return         HW index.
    lpm_bucket_index_t get_hw_index() const
    {
        return m_hw_index;
    }

    /// @brief Set the core this bucket belongs to.
    ///
    /// @param[in]      core_id            Core ID to set.
    void set_core(size_t core_id)
    {
        m_core_id = core_id;
    }

    /// @brief Return the core ID this bucket belongs to.
    ///
    /// @return         Core ID.
    size_t get_core() const
    {
        return m_core_id;
    }

    /// @brief Return the level this bucket belongs to.
    ///
    /// @return         Level of the bucket.
    lpm_level_e get_level() const
    {
        return m_level;
    }

    /// @brief Set root to the bucket.
    ///
    /// @param[in]      root            lpm_key_t to set as root.
    void set_root(const lpm_key_t& root)
    {
        m_root = root;
    }

    /// @brief Get the root of the bucket.
    ///
    /// @return         The root of the bucket.
    const lpm_key_t& get_root() const
    {
        return m_root;
    }

    /// @brief Set the default entry of the bucket.
    ///
    /// @param[in]      default_entry            Default entry to the bucket.
    void set_default_entry(const lpm_key_payload& default_entry)
    {
        m_default_entry = default_entry;
    }

    /// @brief Get the default entry of the bucket.
    ///
    /// @return         The default entry of the bucket.
    const lpm_key_payload& get_default_entry() const
    {
        return m_default_entry;
    }

    /// @brief Check if bucket nodes have legal width.
    ///
    /// @return true if bucket is OK, false otherwise.
    bool sanity_widths() const;

protected:
    // State members
    uint8_t m_num_of_entries; ///< Number of entries in bucket.
    size_t m_max_width;       ///< Width of widest entry in bucket.

    /// @brief Construct an empty LPM bucket.
    ///
    /// @param[in]      sw_index                        Index of bucket.
    /// @param[in]      level                           HW bucket index.
    lpm_bucket(lpm_bucket_index_t sw_index, lpm_level_e level);

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_bucket() = default;

    // Members
    lpm_bucket_index_t m_sw_index;   ///< Bucket index, unique for each bucket.
    lpm_bucket_index_t m_hw_index;   ///< HW index of the bucket.
    size_t m_core_id;                ///< Core ID this bucket belongs to.
    lpm_level_e m_level;             ///< Level this bucket represents.
    lpm_key_t m_root;                ///< Root key node of the bucket.
    lpm_key_payload m_default_entry; ///< Default entry of the bucket, used in case there is no hit.
};

} // namespace silicon_one

#endif
