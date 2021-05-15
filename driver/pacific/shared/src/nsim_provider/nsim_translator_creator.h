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

#ifndef __NSIM_TRANSLATOR_CREATOR_H__
#define __NSIM_TRANSLATOR_CREATOR_H__

#include "lld/device_simulator.h"
#include "lld/ll_device.h"
#include "nplapi/translator_creator.h"

#include "nsim_provider/nsim_translator_creator_base.h"

#include "nsim_lpm_translator.h"
#include "nsim_ternary_translator.h"
#include "nsim_translator.h"

#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

namespace simulator
{

template <class _Table, class _Translator>
la_status
create_table_translator(_Table& table, translator_creator& creator, const std::vector<size_t>& indices)
{
    ll_device_sptr lld = creator.get_ll_device();

    if (lld->get_pacific_tree() == nullptr && lld->get_gibraltar_tree() == nullptr && lld->get_asic4_tree() == nullptr
        && lld->get_asic3_tree() == nullptr
        && lld->get_asic5_tree() == nullptr) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    typename _Table::table_translator_sptr_vec_t translator_vec;
    for (const size_t index : indices) {
        typename _Table::table_translator_sptr_t translator = std::make_shared<_Translator>(index, lld);
        translator_vec.push_back(translator);
    }

    table.initialize(translator_vec);
    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
init_table_per_type(npl_table<_Trait>& table, translator_creator& creator, const std::vector<size_t>& indices)
{
    return create_table_translator<npl_table<_Trait>, nsim_translator<_Trait> >(table, creator, indices);
}

template <class _Trait>
la_status
init_table_per_type(npl_lpm_table<_Trait>& table, translator_creator& creator, const std::vector<size_t>& indices)
{
    return create_table_translator<npl_lpm_table<_Trait>, nsim_lpm_translator<_Trait> >(table, creator, indices);
}

template <class _Trait>
la_status
init_table_per_type(npl_ternary_table<_Trait>& table, translator_creator& creator, const std::vector<size_t>& indices)
{
    return create_table_translator<npl_ternary_table<_Trait>, nsim_ternary_translator<_Trait> >(table, creator, indices);
}

template <class _Table>
la_status
init_table(_Table& table, translator_creator& creator, const std::vector<size_t>& indices)
{
    return init_table_per_type(table, creator, indices);
}

} // namespace simulator

/// @brief NSIM translator creator
///
/// @details Implements #silicon_one::translator_creator interface
class nsim_translator_creator : public simulator::translator_creator_impl
{
public:
    /// @brief NSIM translator creator constructor
    ///
    /// @param[in]  lld                     Low-level device.
    /// @param[in]  npl_context_slices      NPL context mode of slices.
    nsim_translator_creator(ll_device_sptr lld, const std::vector<npl_context_e>& npl_context_slices)
        : simulator::translator_creator_impl(lld, npl_context_slices)
    {
    }
};

} // namespace silicon_one

#endif //  __NSIM_TRANSLATOR_CREATOR_H__
