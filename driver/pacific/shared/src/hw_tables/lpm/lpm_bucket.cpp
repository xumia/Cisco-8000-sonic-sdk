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

#include "lpm_bucket.h"
#include "lpm_common.h"

#include <algorithm>
#include <sstream>

using namespace std;

namespace silicon_one
{

lpm_bucket::lpm_bucket(lpm_bucket_index_t sw_index, lpm_level_e level)
    : m_num_of_entries(0), m_max_width(0), m_sw_index(sw_index), m_hw_index(LPM_NULL_INDEX), m_level(level), m_root()
{
}

bool
lpm_bucket::empty() const
{
    return m_num_of_entries == 0;
}

la_status
lpm_bucket::lookup(const lpm_key_t& key, lpm_key_t& out_hit_key, lpm_payload_t& out_hit_payload, bool& out_is_default) const
{
    out_is_default = true;
    out_hit_key = lpm_key_t();
    const lpm_key_payload_vec& entries = get_entries();
    for (const lpm_key_payload& entry : entries) {
        bool contained = is_contained(entry.key, key);
        if (contained && entry.key.get_width() >= out_hit_key.get_width()) {
            out_hit_key = entry.key;
            out_hit_payload = entry.payload;
            out_is_default = false;
        }
    }

    if (out_is_default) {
        out_hit_key = m_default_entry.key;
        out_hit_payload = m_default_entry.payload;
    }

    return LA_STATUS_SUCCESS;
}

size_t
lpm_bucket::size() const
{
    return m_num_of_entries;
}

bool
lpm_bucket::sanity_widths() const
{
    if (empty()) {
        return true;
    }
    size_t root_width = get_root_width();
    auto entries = get_entries();

    for (auto& entry : entries) {
        size_t entry_width = entry.key.get_width();
        dassert_crit(entry_width >= root_width);
        if (entry_width < root_width) {
            return false;
        }
    }
    return true;
}

std::string
lpm_bucket::to_string() const
{
    std::stringstream s;
    lpm_key_payload_vec entries = get_entries();
    s << "bucket=" << m_sw_index << ", hw_index=" << m_hw_index << ", root=" << m_root.to_string() << ", entries= { ";
    for (const lpm_key_payload& entry : entries) {
        s << "(" << entry.key.to_string() << "," << entry.payload << ") ";
    }

    s << "}";

    return s.str();
}

} // namespace silicon_one
