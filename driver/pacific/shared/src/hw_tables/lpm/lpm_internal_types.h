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

#ifndef __LEABA_LPM_INTERNAL_TYPES_H__
#define __LEABA_LPM_INTERNAL_TYPES_H__

#include "common/weak_ptr_unsafe.h"
#include "hw_tables/lpm_types.h"
#include <memory>

/// @file
/// @brief LPM implementations types.

namespace silicon_one
{

/// @brief Constants for invalid values.
constexpr size_t GROUP_ID_NONE = static_cast<size_t>(-1);
static constexpr size_t LPM_NULL_ROW = static_cast<size_t>(-1);
static constexpr size_t CORE_ID_NONE = static_cast<size_t>(-1);
static constexpr uint32_t INVALID_PAYLOAD = static_cast<uint32_t>(-1);
static const int LPM_NULL_INDEX = -1; // TODO deprecate once we finish TCAM rewrite

struct lpm_key_payload {
    lpm_key_t key;
    lpm_payload_t payload;
};

struct lpm_key_payload_row {
    lpm_key_t key;
    lpm_payload_t payload;
    size_t row;
};

/// @brief LPM core index and group index.
struct lpm_core_group_data {
    size_t core_index;
    size_t group_index;

    bool operator==(const lpm_core_group_data& core_group) const
    {
        return ((core_index == core_group.core_index) && (group_index == core_group.group_index));
    }
};

using lpm_key_payload_vec = std::vector<lpm_key_payload, allocator_wrapper<lpm_key_payload> >;

typedef int lpm_bucket_index_t;
typedef int lpm_tcam_row_t;
typedef uint8_t lpm_core_id_t;

constexpr const char* JSON_CORE_ID = "core_id";
constexpr const char* JSON_KEY_VALUE = "key";
constexpr const char* JSON_KEY_WIDTH = "key_width";
constexpr const char* JSON_PAYLOAD = "payload";
constexpr const char* JSON_GROUP_ID = "group_id";

/// @brief LPM action enum.
enum class lpm_implementation_action_e {
    INSERT,               ///< Insert entry.
    REMOVE,               ///< Remove entry.
    MODIFY,               ///< Modify payload.
    ADD_GROUP_ROOT,       ///< Add subtree to the tree.
    REMOVE_GROUP_ROOT,    ///< Remove subtree where stop points are groups' roots.
    MODIFY_GROUP_TO_CORE, ///< Modify group's core.
    REFRESH,              ///< Re-write bucket to HW.
    LAST = REFRESH,       ///< Last action.
};

/// @brief LPM action descriptor.
///
/// Specify an action: action, key and payload.
struct lpm_action_desc_internal {

    /// @brief Construct a (action, key, payload, index) action descriptor from another descriptor.
    ///
    /// @param[in]      index           Index of action.
    /// @param[in]      action_desc     Action type.
    lpm_action_desc_internal(const lpm_action_desc& api_action_desc)
        : m_key(api_action_desc.m_key),
          m_payload(api_action_desc.m_payload),
          m_index(0),
          m_sram_only(api_action_desc.m_latency_sensitive)
    {
        switch (api_action_desc.m_action) {
        case lpm_action_e::INSERT:
            m_action = lpm_implementation_action_e::INSERT;
            break;
        case lpm_action_e::REMOVE:
            m_action = lpm_implementation_action_e::REMOVE;
            break;
        case lpm_action_e::MODIFY:
            m_action = lpm_implementation_action_e::MODIFY;
            break;
        default:
            dassert_crit(false);
        }
    }

    /// @brief Construct a (action, key, payload, index) action descriptor from another descriptor.
    ///
    /// @param[in]      index           Index of action.
    /// @param[in]      action_desc     Action type.
    lpm_action_desc_internal(size_t index, const lpm_action_desc_internal& action_desc)
        : m_action(action_desc.m_action),
          m_key(action_desc.m_key),
          m_payload(action_desc.m_payload),
          m_index(index),
          m_sram_only(false)
    {
    }

    /// @brief Construct a (action, key, payload, sram_only?) action descriptor.
    ///
    /// @param[in]      action          Action type.
    /// @param[in]      key             Prefix to perform action on.
    /// @param[in]      payload         Payload of action.
    /// @param[in]      sram_only       Predicate whether this prefix must be in the SRAM.
    lpm_action_desc_internal(lpm_action_e action, const lpm_key_t& key, lpm_payload_t payload, bool sram_only)
        : m_key(key), m_sram_only(sram_only)
    {
        switch (action) {
        case lpm_action_e::INSERT:
            m_action = lpm_implementation_action_e::INSERT;
            m_payload = payload;
            break;
        case lpm_action_e::REMOVE:
            m_action = lpm_implementation_action_e::REMOVE;
            break;
        case lpm_action_e::MODIFY:
            m_action = lpm_implementation_action_e::MODIFY;
            m_payload = payload;
            break;
        default:
            dassert_crit(false);
        }
    }

    /// @brief Construct a (action, key, payload, index) action descriptor.
    ///
    /// @param[in]      action          Action type.
    /// @param[in]      key             Prefix to perform action on.
    /// @param[in]      payload         Payload of action.
    /// @param[in]      index           Index of action.
    lpm_action_desc_internal(lpm_implementation_action_e action, const lpm_key_t& key, lpm_payload_t payload, size_t index)
        : m_action(action), m_key(key), m_payload(payload), m_index(index), m_sram_only(false)
    {
    }

    /// @brief Construct a (action, key, payload) action descriptor.
    ///
    /// @param[in]      action          Action type.
    /// @param[in]      key             Prefix to perform action on.
    /// @param[in]      payload         Payload of action.
    lpm_action_desc_internal(lpm_implementation_action_e action, const lpm_key_t& key, lpm_payload_t payload)
        : m_action(action), m_key(key), m_payload(payload), m_index(0), m_sram_only(false)
    {
    }

    /// @brief Construct a (action, key) action descriptor.
    ///
    /// @param[in]      action          Action type.
    /// @param[in]      key             Prefix to perform action on.
    lpm_action_desc_internal(lpm_implementation_action_e action, const lpm_key_t& key)
        : m_action(action), m_key(key), m_payload(INVALID_PAYLOAD), m_sram_only(false)
    {
    }

    /// @brief Construct an empty action descriptor.
    lpm_action_desc_internal()
    {
    }

    lpm_implementation_action_e m_action; ///< Action type.
    lpm_key_t m_key;                      ///< Prefix to perform action on.
    lpm_payload_t m_payload;              ///< Action payload.
    size_t m_index;                       ///< Index of action.
    size_t m_group_id;                    ///< Group ID for add_group_root action.
    size_t m_core_id;                     ///< Core ID to add the group root (applicable for GROUP_ROOT actions).
    bool m_sram_only;                     ///< Predicate whether this prefix must be in the SRAM.
};

using lpm_key_vec = vector_alloc<lpm_key_t>;
using lpm_implementation_desc_vec = std::vector<lpm_action_desc_internal>;
using lpm_implementation_desc_vec_levels = std::array<lpm_implementation_desc_vec, NUM_LEVELS>;
using lpm_implementation_desc_vec_levels_cores = std::vector<lpm_implementation_desc_vec_levels>;

using lpm_bucket_index_list = list_alloc<lpm_bucket_index_t>;
using hw_index_list_it = lpm_bucket_index_list::iterator;

/// @brief Resource type.
enum class resource_type {
    PREFIXES,   ///< Count number of prefixes.
    TCAM_LINES, ///< Count the number of TCAM lines.
};

/// @brief Resource descriptor: type, count.
struct resource_descriptor {
    resource_type type;
    size_t count;
};

struct core_buckets_occupancy {
    size_t sram_single_entries = 0;
    size_t sram_double_entries = 0;
    size_t sram_ipv4_entries = 0;
    size_t sram_ipv6_entries = 0;
    size_t sram_buckets = 0;
    size_t sram_unpaired_buckets = 0;
    size_t sram_rows = 0;

    size_t hbm_entries = 0;
    size_t hbm_ipv4_entries = 0;
    size_t hbm_ipv6_entries = 0;
    size_t hbm_buckets = 0;
};

using core_buckets_occupancy_vec = vector_alloc<core_buckets_occupancy>;

// Shared pointer types
class lpm_bucket;
using lpm_bucket_sptr = std::shared_ptr<lpm_bucket>;
using lpm_bucket_scptr = std::shared_ptr<const lpm_bucket>;
using lpm_bucket_wptr = weak_ptr_unsafe<lpm_bucket>;

class lpm_buckets_bucket;
using lpm_buckets_bucket_sptr = std::shared_ptr<lpm_buckets_bucket>;
using lpm_buckets_bucket_scptr = std::shared_ptr<const lpm_buckets_bucket>;
using lpm_buckets_bucket_wptr = weak_ptr_unsafe<lpm_buckets_bucket>;

class lpm_nodes_bucket;
using lpm_nodes_bucket_sptr = std::shared_ptr<lpm_nodes_bucket>;
using lpm_nodes_bucket_scptr = std::shared_ptr<const lpm_nodes_bucket>;
using lpm_nodes_bucket_wptr = weak_ptr_unsafe<lpm_nodes_bucket>;

template <class data_t>
class tree_node;
struct lpm_bucketing_data;
using lpm_node = tree_node<lpm_bucketing_data>;
using lpm_node_sptr = std::shared_ptr<lpm_node>;
using lpm_node_scptr = std::shared_ptr<const lpm_node>;
using lpm_node_wptr = weak_ptr_unsafe<lpm_node>;
using lpm_node_wcptr = weak_ptr_unsafe<const lpm_node>;

using lpm_bucketing_data_sptr = std::shared_ptr<lpm_bucketing_data>;

class lpm_core_hw_writer;
using lpm_core_hw_writer_sptr = std::shared_ptr<lpm_core_hw_writer>;

class bucketing_tree;
using bucketing_tree_sptr = std::shared_ptr<bucketing_tree>;
using bucketing_tree_scptr = std::shared_ptr<const bucketing_tree>;
using bucketing_tree_wptr = weak_ptr_unsafe<bucketing_tree>;
using bucketing_tree_wcptr = weak_ptr_unsafe<const bucketing_tree>;

class lpm_hw_index_allocator;
using lpm_hw_index_allocator_sptr = std::shared_ptr<lpm_hw_index_allocator>;

class lpm_hw_index_allocator_adapter;
using lpm_hw_index_allocator_adapter_sptr = std::shared_ptr<lpm_hw_index_allocator_adapter>;

class lpm_hw_index_allocator_adapter_hbm;
using lpm_hw_index_allocator_adapter_hbm_sptr = std::shared_ptr<lpm_hw_index_allocator_adapter_hbm>;

class lpm_hw_index_allocator_sram_pinning;
using lpm_hw_index_allocator_sram_pinning_sptr = std::shared_ptr<lpm_hw_index_allocator_sram_pinning>;

struct lpm_logical_tcam_tree_data;
using lpm_logical_tcam_tree_node = tree_node<lpm_logical_tcam_tree_data>;
using lpm_logical_tcam_tree_node_sptr = std::shared_ptr<lpm_logical_tcam_tree_node>;
using lpm_logical_tcam_tree_node_scptr = std::shared_ptr<const lpm_logical_tcam_tree_node>;
using lpm_logical_tcam_tree_node_wptr = weak_ptr_unsafe<lpm_logical_tcam_tree_node>;
using lpm_logical_tcam_tree_node_wcptr = weak_ptr_unsafe<const lpm_logical_tcam_tree_node>;

class lpm_core_tcam;
using lpm_core_tcam_sptr = std::shared_ptr<lpm_core_tcam>;

class lpm_core_tcam_allocator;
using lpm_core_tcam_allocator_sptr = std::shared_ptr<lpm_core_tcam_allocator>;

class lpm_core_tcam_utils_base;
using lpm_core_tcam_utils_scptr = std::shared_ptr<lpm_core_tcam_utils_base>;
using lpm_core_tcam_utils_wcptr = weak_ptr_unsafe<const lpm_core_tcam_utils_base>;

// End of shared pointer types

using lpm_bucket_raw_ptr_vec = vector_alloc<lpm_bucket*>;
using lpm_bucket_ptr_vec = vector_alloc<lpm_bucket_sptr>;
using lpm_bucket_const_ptr_vec = vector_alloc<lpm_bucket_scptr>;
using lpm_bucket_ptr_list = list_alloc<lpm_nodes_bucket_sptr>;

using lpm_node_wptr_list = list_alloc<lpm_node_wptr>;
using lpm_node_vec = vector_alloc<lpm_node*>;

/// @brief Type of Logical TCAM in core TCAM
enum class logical_tcam_type_e {
    SINGLE = 0, ///< SINGLE TCAM.
    DOUBLE = 1, ///< DOUBLE TCAM.
    QUAD = 2,   ///< QUAD (wide IPv6) TCAM.
    NOBODY = 3, ///< No TCAM.
};

/// @brief Location of L2 bucket.
enum class l2_bucket_location_e {
    SRAM, ///< L2 Bucket is in SRAM.
    HBM   ///< L2 Bucket is in HBM.
};

// Shortcuts
static constexpr size_t SINGLE_IDX = static_cast<size_t>(logical_tcam_type_e::SINGLE);
static constexpr size_t DOUBLE_IDX = static_cast<size_t>(logical_tcam_type_e::DOUBLE);
static constexpr size_t QUAD_IDX = static_cast<size_t>(logical_tcam_type_e::QUAD);
static constexpr size_t NOBODY_IDX = static_cast<size_t>(logical_tcam_type_e::NOBODY);

} // namespace silicon_one

#endif
