// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "slice_mapping_types.h"
#include "api/types/la_common_types.h"
#include "common/defines.h"
#include "common/gen_utils.h"
// #include "hld_types.h"
// #include "hld_types_fwd.h"

#include <algorithm>
#include <vector>

namespace silicon_one
{

la_status
slice_mapping::map_slice_serdices(la_slice_serdices& map_this) const
{
    la_slice_ifg orig_s_ifg = {.slice = map_this.slice, .ifg = map_this.ifg};
    map_this.slice = slice._to;
    if (ifg_map.size() == 0) {
        return LA_STATUS_ENOTINITIALIZED;
    }
    if (map_this.ifg >= ifg_map.size()) {
        // let somone else handle this problem
        return LA_STATUS_SUCCESS;
    }

    auto& ifg_mapping = ifg_map[orig_s_ifg.ifg];
    map_this.ifg = ifg_mapping.ifg._to;
    if (ifg_mapping.serdes_map.size() == 0) {
        return LA_STATUS_ENOTINITIALIZED;
    }
    if (map_this.first_serdes >= ifg_mapping.serdes_map.size()) {
        // let somone else handle this problem
        return LA_STATUS_SUCCESS;
    }
    if (map_this.last_serdes >= ifg_mapping.serdes_map.size()) {
        map_this.first_serdes = ifg_mapping.serdes_map[map_this.first_serdes]._to;
        // let somone else handle this problem
        return LA_STATUS_SUCCESS;
    }

    if (map_this.last_serdes == map_this.first_serdes) {
        map_this.first_serdes = ifg_mapping.serdes_map[map_this.first_serdes]._to;
        map_this.last_serdes = map_this.first_serdes;
    } else {
        // size_t num_serdices=map_this.last_serdes-map_this.first_serdes;
        // size_t all_mapped_serdices[num_serdices];
        size_t first = 9999, last = 0;
        for (size_t i = map_this.first_serdes; i <= map_this.last_serdes; i++) {
            size_t current = ifg_mapping.serdes_map[i]._to;
            if (first > current) {
                first = current;
            }
            if (last < current) {
                last = current;
            }
        }
        map_this.first_serdes = first;
        map_this.last_serdes = last;
    }

    return LA_STATUS_SUCCESS;
}

la_status
slice_mapping::map_ifg_from_slice(la_slice_ifg& ifg) const
{
    if (ifg_map.size() == 0) {
        return LA_STATUS_ENOTINITIALIZED;
    }
    if (ifg.ifg >= ifg_map.size()) {
        ifg.slice = slice._to;
        // let somone else handle this problem
        return LA_STATUS_SUCCESS;
    }
    auto& ifg_mapping = ifg_map[ifg.ifg];
    ifg.slice = slice._to;
    ifg.ifg = ifg_mapping.ifg._to;
    return LA_STATUS_SUCCESS;
}

ifg_mapping::ifg_mapping(size_t from, size_t to)
{
    ifg._from = from;
    ifg._to = to;
}

slice_mapping::slice_mapping(size_t from, size_t to)
{
    slice._from = from;
    slice._to = to;
}

single_idx_mapping& ifg_mapping::operator[](int ind)
{
    return serdes_map[ind];
}

const single_idx_mapping& ifg_mapping::operator[](int ind) const
{
    return serdes_map[ind];
}

ifg_mapping& slice_mapping::operator[](int ind)
{
    return ifg_map[ind];
}

const ifg_mapping& slice_mapping::operator[](int ind) const
{
    return ifg_map[ind];
}

} // namespace silicon_one
