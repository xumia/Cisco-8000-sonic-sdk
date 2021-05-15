// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __CTM_COMMON_TCAM_H__
#define __CTM_COMMON_TCAM_H__

#include "ctm/ctm_common.h"

namespace silicon_one
{
struct tcam_desc {
    size_t ring_idx;
    size_t subring_idx;
    size_t tcam_idx;

    tcam_desc() : ring_idx(0), subring_idx(0), tcam_idx(0){};
    tcam_desc(size_t in_ring_idx, size_t in_subring_idx, size_t in_tcam_idx)
        : ring_idx(in_ring_idx), subring_idx(in_subring_idx), tcam_idx(in_tcam_idx){};

    bool operator==(const tcam_desc& ref) const
    {
        return std::tie(ring_idx, subring_idx, tcam_idx) == std::tie(ref.ring_idx, ref.subring_idx, ref.tcam_idx);
    }

    bool operator<(const tcam_desc& ref) const
    {
        if (ring_idx != ref.ring_idx) {
            return ring_idx > ref.ring_idx;
        } else if (subring_idx != ref.subring_idx) {
            return subring_idx < ref.subring_idx;
        } else {
            return tcam_idx < ref.tcam_idx;
        }
    }

    bool operator>(const tcam_desc& ref) const
    {
        return !(*this < ref) && !(*this == ref);
    }
};

using tcams_container = std::vector<tcam_desc>;
using tcams_container_vec = std::vector<tcams_container>;
using priority_to_tcams_map = std::map<size_t, tcams_container_vec, std::greater<size_t> >;
using groups_container = vector_alloc<ctm::group_desc>;

/// @brief SRAM data descriptor.
struct sram_desc {
    size_t result_channel; ///< SRAM result channel (0-4)
    bool is_msb;           ///< Whether SRAM result (32 bits) should be written to LSB or MSB of the result channel
};

}; // namespace silicon_one

#endif // __CTM_COMMON_TCAM_H__
