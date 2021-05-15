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

#include "api/types/la_common_types.h"
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
/// The Pacific has several slices (0, 3, 4) with flipped IFG.
/// For these slices, logical (NPL) IFG 0 maps to physical IFG 1, and vice versa.
static inline la_ifg_id_t
get_physical_ifg(la_slice_id_t slice, la_ifg_id_t ifg)
{
    if ((slice == 1) || (slice == 2) || (slice == 5)) {
        return ifg;
    }

    dassert_crit((ifg == 0) || (ifg == 1));

    return (ifg ^ 1);
}

static inline npl_wred_action_e
la_2_npl_wred_action(la_voq_cgm_profile::wred_action_e action)
{
    switch (action) {
    case la_voq_cgm_profile::wred_action_e::PASS:
        return NPL_WRED_ACTION_PASS;
    case la_voq_cgm_profile::wred_action_e::DROP:
        return NPL_WRED_ACTION_DROP;
    case la_voq_cgm_profile::wred_action_e::MARK_ECN:
        return NPL_WRED_ACTION_MARK;
    }

    // Shouldn't reach here
    return NPL_WRED_ACTION_PASS;
}

static inline la_voq_cgm_profile::wred_action_e
npl_2_la_wred_action(npl_wred_action_e action)
{
    switch (action) {
    case NPL_WRED_ACTION_PASS:
        return la_voq_cgm_profile::wred_action_e::PASS;
    case NPL_WRED_ACTION_MARK:
        return la_voq_cgm_profile::wred_action_e::MARK_ECN;
    case NPL_WRED_ACTION_DROP:
        return la_voq_cgm_profile::wred_action_e::DROP;
    }

    // Shouldn't reach here
    return la_voq_cgm_profile::wred_action_e::DROP;
}

/// @brief Get the IFGs on which the RCY port for the given PCI system port may reside.
///
/// PACKET-DMA-WA. A PCI port must have a RCY port in the subsequent slice.
static inline slice_ifg_vec_t
get_possible_rcy_port_slice(la_slice_id_t pci_port_slice)
{
    slice_ifg_vec_t vect;
    if ((pci_port_slice & 1) == 0) { // PCI ports can be configured on even numbered slices only
        vect.push_back({.slice = pci_port_slice + 1, .ifg = RCYCLE_PORT_IFG});
    }
    return vect;
}

/// @brief Get all IFGs where an object is configured.
slice_ifg_vec_t get_ifgs(const la_object_wcptr& obj);

} // namespace silicon_one

#endif // __HLD_UTILS_H__
