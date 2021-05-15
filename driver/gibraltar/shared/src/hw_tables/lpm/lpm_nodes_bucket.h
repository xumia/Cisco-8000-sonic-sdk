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

#ifndef __LEABA_LPM_NODES_BUCKET_H__
#define __LEABA_LPM_NODES_BUCKET_H__

#include "common/la_status.h"
#include "hw_tables/lpm_types.h"
#include "lpm_bucket.h"

/// @file

namespace silicon_one
{

/// @brief LPM nodes bucket.
///
/// Describes a single LPM bucket of nodes, as represented in memory.
/// This type of bucket owns prefixes from the lpm_tree.
class lpm_nodes_bucket : public lpm_bucket
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Construct an empty LPM bucket.
    ///
    /// @param[in]      index                           Index of bucket.
    explicit lpm_nodes_bucket(lpm_bucket_index_t index);

    /// @name Nodes management
    /// @{

    /// @brief Insert an LPM node to bucket.
    ///
    /// Update node's bucket. In case node is valid: update entries counter and widths counter.
    /// As a side effect, updates the node's rebucketing data to point to the bucket.
    ///
    /// @param[in]      node            Node to be inserted.
    void insert(lpm_node* node);

    /// @brief Remove an LPM node from bucket.
    ///
    /// Update node's bucket. In case node is valid: update entries counter and widths counter.
    /// As a side effect, updates the node's rebucketing data to point to the bucket.
    ///
    /// @param[in]      node            Node to be removed.
    void remove(lpm_node* node);

    /// @brief Get bucket nodes.
    ///
    /// Get a vector containing nodes of the bucket.
    ///
    /// @return         Vector of the nodes in bucket.
    lpm_node_vec get_nodes() const;

    /// @brief Get bucket nodes.
    ///
    /// Get a list containing nodes of the bucket.
    ///
    /// @return         List of the nodes in bucket.
    lpm_node_wptr_list get_nodes_list() const
    {
        return m_nodes;
    }

    /// @brief Merge other lpm_nodes_bucket's nodes.
    ///
    /// @param[in]      other_bucket            Buckets to merge its nodes.
    void merge_bucket_members(lpm_nodes_bucket* other_bucket);

    /// @brief Set the top node of the bucket.
    ///
    /// @param[in]      top_node            Node to be the top node.
    void set_top_node(const lpm_node_sptr& top_node)
    {
        m_top_node = top_node;
    }

    /// @brief Get top node.
    ///
    /// @return         The top node of the bucket.
    lpm_node* get_top_node() const
    {
        return m_top_node.get();
    }

    /// @brief Check if this bucket is SRAM pinned.
    ///
    /// @return         Boolean specifies if this bucket is SRAM pinned.
    bool is_pinned() const
    {
        return (m_num_pinned_nodes > 0);
    }

    /// @brief Number of pinned nodes in this bucket.
    ///
    /// @return         Number of pinned nodes in this bucket.
    uint8_t get_num_pinned_nodes() const
    {
        return m_num_pinned_nodes;
    }

    /// @brief Remove all the nodes from the bucket.
    void clear_members()
    {
        m_nodes.clear();
        m_num_of_entries = 0;
        m_max_width = 0;
        m_num_pinned_nodes = 0;
    }

    // lpm_bucket.h API-s
    size_t get_root_width() const override;
    lpm_key_payload_vec get_entries() const override;
    size_t get_max_width() const override;
    void reset() override;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_nodes_bucket() = default;

    // State members
    lpm_node_wptr m_top_node;   ///< Top node in bucket. Top node is the common ancestor to all hw_destined nodes in this bucket.
    lpm_node_wptr_list m_nodes; ///< Widths of entries in bucket.
    uint8_t m_num_pinned_nodes; ///< Number of prefixes must be in the SRAM.

    /// @brief Calculate maximum width according to entries in bucket.
    void reduce_max_width();
};

} // namespace silicon_one

#endif
