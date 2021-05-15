// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "lpm_core_tcam_utils_pacific_gb.h"

namespace silicon_one
{

logical_tcam_type_e
lpm_core_tcam_utils_pacific_gb::get_logical_tcam_type_of_key(const lpm_key_t& key) const
{
    const map_alloc<size_t, logical_tcam_type_e> ipv4_ranges{{40, logical_tcam_type_e::SINGLE}};
    const map_alloc<size_t, logical_tcam_type_e> ipv6_ranges{{79, logical_tcam_type_e::DOUBLE}, {157, logical_tcam_type_e::QUAD}};

    size_t key_width = key.get_width();
    dassert_crit(key_width > 0);

    bool is_ipv6 = key.bit_from_msb(0);
    const map_alloc<size_t, logical_tcam_type_e>& key_ranges_map = is_ipv6 ? ipv6_ranges : ipv4_ranges;
    auto it = key_ranges_map.lower_bound(key_width);
    dassert_crit(it != key_ranges_map.end());

    return it->second;
}

} // namespace silicon_one
