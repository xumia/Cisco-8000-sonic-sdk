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

#ifndef __IFG_USE_COUNT_H__
#define __IFG_USE_COUNT_H__

#include <array>
#include <functional>
#include <vector>

#include "api/types/la_common_types.h"
#include "common/la_status.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "system/slice_manager_smart_ptr_base.h"
namespace silicon_one
{

class ifg_use_count
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    ifg_use_count(const slice_manager_smart_ptr&);
    ~ifg_use_count() = default;

    /// @brief Add IFG user to use count.
    ///
    /// @param[in]    ifg            IFG to add user for.
    /// @param[out]   ifg_added         IFG is switching from unused to used.
    /// @param[out]   slice_added       Slice is switching from unused to used.
    /// @param[out]   slice_pair_added  Slice pair is switching from unused to used.
    ///
    /// @retval     LA_STATUS_SUCCESS       IFG user added successfully
    /// @retval     LA_STATUS_EOUTOFRANGE   Slice id is out-of-range, or IFG id in Slice is out-of-range
    /// @retval     LA_STATUS_EINVAL        trying to add an IFG corosponding to an invalid Slice
    la_status add_ifg_user(la_slice_ifg ifg, bool& out_ifg_added, bool& out_slice_added, bool& out_slice_pair_added);

    /// @brief Remove IFG user to use count.
    ///
    /// @param[in]    ifg            IFG to remove user from.
    /// @param[out]   ifg_removed          IFG is switching from used to unused.
    /// @param[out]   slice_removed        Slice is switching from used to unused.
    /// @param[out]   slice_pair_removed   Slice pair is switching from used to unused.
    la_status remove_ifg_user(la_slice_ifg ifg, bool& out_ifg_removed, bool& out_slice_removed, bool& out_slice_pair_removed);

    /// @brief True iff the given IFG is being used.
    bool is_ifg_in_use(la_slice_ifg ifg) const;

    /// @brief True iff there's an active IFG in the given slice.
    bool is_slice_in_use(la_slice_id_t slice) const;

    /// @brief True iff there's an active IFG in the given slice-pair.
    bool is_slice_pair_in_use(la_slice_pair_id_t pair_idx) const;

    /// @brief True iff there's an active IFG.
    bool is_in_use() const;

    /// @brief Return a list of IFGs in use.
    slice_ifg_vec_t get_ifgs() const;

    /// @brief Return a list of Slices in use.
    la_slice_id_vec_t get_slices() const;

    /// @brief Return a list of Slice-pairs in use.
    la_slice_pair_id_vec_t get_slice_pairs() const;

    // Return the global index of the given IFG
    size_t get_index(la_slice_ifg ifg) const;

    using per_ifg_function_t = std::function<la_status(la_slice_ifg)>;

    /// @brief Calls func for all IFGs in m_ifgs.
    ///
    /// @param[in] func         Function that will be called on all IFGs.
    ///
    /// @retval     LA_STATUS_SUCCESS   all Function calls finished successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status for_each_ifg(per_ifg_function_t func);

private:
    ifg_use_count() = default;
    // IFGs use-count
    std::array<size_t, NUM_IFGS_PER_DEVICE> m_ifgs;
    slice_manager_smart_ptr m_slice_id_manager;
};

using ifg_use_count_uptr = std::unique_ptr<ifg_use_count>;
using ifg_use_count_sptr = std::shared_ptr<ifg_use_count>;

} // namespace silicon_one

#endif // __IFG_USE_COUNT_H__
