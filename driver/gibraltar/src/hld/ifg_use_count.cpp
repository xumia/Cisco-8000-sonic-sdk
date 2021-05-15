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

#include "ifg_use_count.h"
#include "common/defines.h"
#include "hld_types.h"
#include "hld_utils.h"
#include "system/la_device_impl.h"
#include "system/slice_id_manager_base.h"
#include <exception>

namespace silicon_one
{

ifg_use_count::ifg_use_count(const slice_manager_smart_ptr& sid_mgr) : m_ifgs({{0}})
{
    m_slice_id_manager = sid_mgr;
}

size_t
ifg_use_count::get_index(la_slice_ifg ifg) const
{
    return m_slice_id_manager->slice_ifg_2_global_ifg(ifg);
}

bool
ifg_use_count::is_ifg_in_use(la_slice_ifg ifg) const
{
    size_t index = get_index(ifg);

    return m_ifgs[index] > 0;
}

bool
ifg_use_count::is_in_use() const
{
    for (size_t ifg = 0; ifg < m_ifgs.size(); ifg++) {
        if (m_ifgs[ifg] > 0) {
            return true;
        }
    }
    return false;
}

bool
ifg_use_count::is_slice_in_use(la_slice_id_t slice) const
{
    la_slice_ifg ifg0 = {slice, 0};

    bool in_use = is_ifg_in_use(ifg0);

    if (NUM_IFGS_PER_SLICE > 1) {
        la_slice_ifg ifg1 = {slice, 1};
        in_use = in_use || is_ifg_in_use(ifg1);
    }

    return in_use;
}

bool
ifg_use_count::is_slice_pair_in_use(la_slice_pair_id_t slice_pair) const
{
    bool in_use = false;
    for (la_slice_id_t slice : m_slice_id_manager->get_active_slices_in_pair(slice_pair)) {
        in_use = in_use || is_slice_in_use(slice);
    }

    return in_use;
}

la_status
ifg_use_count::add_ifg_user(la_slice_ifg ifg, bool& out_ifg_added, bool& out_slice_added, bool& out_slice_pair_added)
{
    out_ifg_added = false;
    out_slice_added = false;
    out_slice_pair_added = false;
    la_status status = m_slice_id_manager->is_slice_ifg_valid(ifg);
    return_on_error(status);

    size_t ifg_index = get_index(ifg);

    out_ifg_added = !is_ifg_in_use(ifg);
    out_slice_added = !is_slice_in_use(ifg.slice);
    out_slice_pair_added = !is_slice_pair_in_use(ifg.slice / 2);

    m_ifgs[ifg_index]++;
    return LA_STATUS_SUCCESS;
}

la_status
ifg_use_count::remove_ifg_user(la_slice_ifg ifg, bool& out_ifg_removed, bool& out_slice_removed, bool& out_slice_pair_removed)
{
    out_ifg_removed = false;
    out_slice_removed = false;
    out_slice_pair_removed = false;
    la_status status = m_slice_id_manager->is_slice_ifg_valid(ifg);
    return_on_error(status);

    size_t ifg_index = get_index(ifg);

    if (m_ifgs[ifg_index] > 0) {
        m_ifgs[ifg_index]--;
        out_ifg_removed = !is_ifg_in_use(ifg);
        out_slice_removed = !is_slice_in_use(ifg.slice);
        out_slice_pair_removed = !is_slice_pair_in_use(ifg.slice / 2);
    }
    return LA_STATUS_SUCCESS;
}

slice_ifg_vec_t
ifg_use_count::get_ifgs() const
{
    slice_ifg_vec_t enabled_ifgs;

    for (auto i : m_slice_id_manager->get_used_ifgs_gifg_id()) {
        if (m_ifgs[i] > 0) {
            la_slice_ifg ifg = m_slice_id_manager->global_ifg_2_slice_ifg(i);
            enabled_ifgs.push_back(ifg);
        }
    }

    return enabled_ifgs;
}

la_status
ifg_use_count::for_each_ifg(per_ifg_function_t func)
{
    for (auto ifg : get_ifgs()) {
        la_status status = func(ifg);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_slice_id_vec_t
ifg_use_count::get_slices() const
{
    la_slice_id_vec_t slices;
    for (la_slice_id_t slice : m_slice_id_manager->get_used_slices_internal()) {
        if (is_slice_in_use(slice)) {
            slices.push_back(slice);
        }
    }
    return slices;
}

la_slice_pair_id_vec_t
ifg_use_count::get_slice_pairs() const
{
    la_slice_pair_id_vec_t slice_pairs;
    for (la_slice_pair_id_t pair_idx : m_slice_id_manager->get_used_slice_pairs_internal()) {
        if (is_slice_pair_in_use(pair_idx)) {
            slice_pairs.push_back(pair_idx);
        }
    }
    return slice_pairs;
}
} // namespace silicon_one
