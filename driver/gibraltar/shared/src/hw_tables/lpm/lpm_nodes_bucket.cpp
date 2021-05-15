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

#include "lpm_nodes_bucket.h"
#include "binary_lpm_tree.h"
#include "common/gen_utils.h"
#include "lpm_common.h"

#include <algorithm>

using namespace std;

namespace silicon_one
{

lpm_nodes_bucket::lpm_nodes_bucket(lpm_bucket_index_t index)
    : lpm_bucket(index, lpm_level_e::L2), m_top_node(nullptr), m_num_pinned_nodes(0)
{
}

void
lpm_nodes_bucket::insert(lpm_node* node)
{
    dassert_crit(node->is_valid());
    dassert_slow(!contains(m_nodes, node));

    m_nodes.push_back(node->shared_from_this());

    const lpm_bucketing_data& node_data = node->data();
    if (node_data.is_sram_only) {
        m_num_pinned_nodes++;
    }

    const lpm_key_t& node_key = node->get_key();
    size_t width = node_key.get_width();
    m_max_width = std::max(m_max_width, width);
    m_num_of_entries++;
}

void
lpm_nodes_bucket::remove(lpm_node* node)
{
    dassert_slow(contains(m_nodes, node));

    m_nodes.remove(node->shared_from_this());

    const lpm_bucketing_data& node_data = node->data();
    if (node_data.is_sram_only) {
        m_num_pinned_nodes--;
    }

    size_t width = node->get_width();
    m_num_of_entries--;
    if (width == m_max_width) {
        reduce_max_width();
    }
}

void
lpm_nodes_bucket::reduce_max_width()
{
    size_t prev_max = m_max_width;
    m_max_width = 0;
    for (const auto& node : m_nodes) {
        m_max_width = std::max(m_max_width, node->get_width());
        if (m_max_width == prev_max) {
            break;
        }
    }
}

lpm_node_vec
lpm_nodes_bucket::get_nodes() const
{
    lpm_node_vec nodes;
    nodes.reserve(m_num_of_entries);
    for (const auto& node : m_nodes) {
        nodes.push_back(node.get());
    }

    return nodes;
}

lpm_key_payload_vec
lpm_nodes_bucket::get_entries() const
{
    dassert_crit(!empty());

    lpm_key_payload_vec entries;
    entries.reserve(m_num_of_entries);

    for (const auto& node : m_nodes) {
        const lpm_key_t& node_key = node->get_key();
        const lpm_bucketing_data& node_data = node->data();
        lpm_key_payload entry = {.key = lpm_key_t(node_key), .payload = node_data.payload};
        entries.push_back(entry);
    }

    dassert_crit(entries.size() == m_num_of_entries);

    return entries;
}

void
lpm_nodes_bucket::merge_bucket_members(lpm_nodes_bucket* other_bucket)
{
    m_max_width = std::max(m_max_width, other_bucket->get_max_width());
    m_num_of_entries += other_bucket->size();
    m_num_pinned_nodes += other_bucket->get_num_pinned_nodes();
    m_nodes.splice(m_nodes.end(), other_bucket->m_nodes);
    other_bucket->clear_members();
}

void
lpm_nodes_bucket::reset()
{
    dassert_crit(m_nodes.empty());
    dassert_crit(m_num_pinned_nodes == 0);
    m_root = lpm_key_t();
    m_top_node = nullptr;
    m_max_width = 0;
    m_hw_index = LPM_NULL_INDEX;
    m_core_id = CORE_ID_NONE;
    m_default_entry = {.key = lpm_key_t(), .payload = INVALID_PAYLOAD};
}

size_t
lpm_nodes_bucket::get_max_width() const
{
    return m_max_width;
}

size_t
lpm_nodes_bucket::get_root_width() const
{
    return m_root.get_width();
}

} // namespace silicon_one
