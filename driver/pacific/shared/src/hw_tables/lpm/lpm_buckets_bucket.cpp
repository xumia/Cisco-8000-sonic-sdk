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

#include "lpm_buckets_bucket.h"
#include "lpm_nodes_bucket.h"

#include <algorithm>

using namespace std;

namespace silicon_one
{

void
lpm_buckets_bucket::reset()
{
    m_root = lpm_key_t();
    m_max_width = 0;
    m_hw_index = LPM_NULL_INDEX;
    m_core_id = CORE_ID_NONE;
    m_default_entry = {.key = lpm_key_t(), .payload = INVALID_PAYLOAD};
}

lpm_buckets_bucket::lpm_buckets_bucket(lpm_bucket_index_t index) : lpm_bucket(index, lpm_level_e::L1), m_sub_buckets()
{
}

size_t
lpm_buckets_bucket::get_root_width() const
{
    return m_root.get_width();
}

size_t
lpm_buckets_bucket::get_max_width() const
{
    size_t max_key_width = 0;
    for (const auto& sub_bucket : m_sub_buckets) {
        size_t sub_bucket_width = sub_bucket->get_root_width();
        max_key_width = std::max(max_key_width, sub_bucket_width);
    }

    return max_key_width;
}

void
lpm_buckets_bucket::insert(const lpm_nodes_bucket_sptr& bucket)
{
    dassert_slow(std::find(m_sub_buckets.begin(), m_sub_buckets.end(), bucket) == m_sub_buckets.end());

    m_sub_buckets.push_back(bucket);
    m_num_of_entries++;
}

void
lpm_buckets_bucket::remove(const lpm_nodes_bucket_sptr& bucket)
{
    auto it = std::find(m_sub_buckets.begin(), m_sub_buckets.end(), bucket);
    dassert_crit(it != m_sub_buckets.end());

    m_sub_buckets.erase(it);
    m_num_of_entries--;
}

void
lpm_buckets_bucket::remove(const lpm_nodes_bucket_wptr& bucket)
{
    auto it = std::find(m_sub_buckets.begin(), m_sub_buckets.end(), bucket);
    dassert_crit(it != m_sub_buckets.end());

    m_sub_buckets.erase(it);
    m_num_of_entries--;
}

const lpm_bucket_ptr_list&
lpm_buckets_bucket::get_members() const
{
    return m_sub_buckets;
}

lpm_key_payload_vec
lpm_buckets_bucket::get_entries() const
{
    lpm_key_payload_vec entries;
    for (auto& l2_bucket : m_sub_buckets) {
        lpm_key_payload entry
            = {.key = lpm_key_t(l2_bucket->get_root()), .payload = static_cast<lpm_payload_t>(l2_bucket->get_hw_index())};
        entries.push_back(entry);
    }

    return entries;
}

void
lpm_buckets_bucket::merge_bucket_members(lpm_buckets_bucket* other_bucket)
{
    m_max_width = std::max(m_max_width, other_bucket->get_max_width());
    m_num_of_entries += other_bucket->size();
    m_sub_buckets.splice(m_sub_buckets.end(), other_bucket->m_sub_buckets);
    other_bucket->clear_sub_buckets();
}

} // namespace silicon_one
