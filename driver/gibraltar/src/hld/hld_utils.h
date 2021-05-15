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

#ifndef __HLD_UTILS_H__
#define __HLD_UTILS_H__

#include "hld_types_fwd.h"
#include "npu/la_acl_impl.h"
#include "system/hld_utils_base.h"
#include "system/hld_utils_templates_base.h"

namespace silicon_one
{

/// @brief Find a slice pair where the slice belongs.
static inline la_slice_pair_id_t
get_slice_pair(la_slice_id_t slice)
{
    la_slice_pair_id_t slice_pair = slice / 2;

    return slice_pair;
}

/// @brief Return all slices in a slice pair.
///
/// Returns a vector of all slices belonging to the given slice pair.
static inline la_slice_id_vec_t
get_slices_in_slice_pair(la_slice_pair_id_t slice_pair)
{
    la_slice_id_vec_t slices = {slice_pair * 2, slice_pair * 2 + 1};

    return slices;
}

/// @brief Convert logical IFG index to physical IFG index.
///
/// The Gibraltar has several slices (1, 2, 5) with flipped IFG. For these slices, logical (NPL) IFG 0 maps to physical IFG 1, and
/// vice versa.
static inline la_ifg_id_t
get_physical_ifg(la_slice_id_t slice, la_ifg_id_t ifg)
{
    if ((slice == 0) || (slice == 3) || (slice == 4)) {
        return ifg;
    }

    dassert_crit((ifg == 0) || (ifg == 1));

    return (ifg ^ 1);
}

/// @brief Get the IFGs on which the RCY port for the given PCI system port may reside.
///
/// PACKET-DMA-WA. A PCI port must have a RCY port in the same slice pair.
static inline slice_ifg_vec_t
get_possible_rcy_port_slice(la_slice_id_t port_slice)
{
    slice_ifg_vec_t vect;
    add_all_slice_ifgs_to_vect(port_slice, vect);

    if ((port_slice & 1) == 0) {
        add_all_slice_ifgs_to_vect(port_slice + 1, vect);
    } else {
        add_all_slice_ifgs_to_vect(port_slice - 1, vect);
    }
    return vect;
}

/// @brief Get all IFGs where an object is configured.
slice_ifg_vec_t get_ifgs(const la_object_wcptr& obj);

} // namespace silicon_one

#endif // __HLD_UTILS_H__
