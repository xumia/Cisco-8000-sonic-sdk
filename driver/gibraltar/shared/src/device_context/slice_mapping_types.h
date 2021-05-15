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

#ifndef __SLICE_MAPPING_H__
#define __SLICE_MAPPING_H__

#include "api/types/la_common_types.h"
#include <vector>

namespace silicon_one
{

// Maps a single external index to internal index and vice versa.
struct single_idx_mapping {
    size_t _from, _to;
};

// Maps an external IFG index to an internal IFG index,
// And also each serdes in the external IFG layout, to a serdesx in the internal IFG layout.
struct ifg_mapping {
    ifg_mapping(){};
    ifg_mapping(size_t from, size_t to);
    single_idx_mapping& operator[](int ind);
    const single_idx_mapping& operator[](int ind) const;
    single_idx_mapping ifg;
    std::vector<single_idx_mapping> serdes_map;
};

// Maps an external Slice index to an internal Slice index,
// And also maps each of the external slice's IFGs (0,1) to one of the internal slice's IFGs.
struct slice_mapping {
public:
    slice_mapping(){};
    slice_mapping(size_t from, size_t to);
    ifg_mapping& operator[](int ind);
    const ifg_mapping& operator[](int ind) const;

    la_status map_slice_serdices(la_slice_serdices& map_this) const;
    la_status map_ifg_from_slice(la_slice_ifg& ifg) const;

public:
    single_idx_mapping slice;
    std::vector<ifg_mapping> ifg_map;
};

} // namespace silicon_one

#endif // __SLICE_MAPPING_H__
