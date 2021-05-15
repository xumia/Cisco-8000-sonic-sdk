// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include <algorithm>

#include "common/defines.h"
#include "common/gen_operators.h"
#include "system/compound_translator_creator.h"

namespace silicon_one
{

compound_translator_creator::compound_translator_creator(ll_device_sptr lld,
                                                         const std::vector<npl_context_e>& npl_context_slices,
                                                         vector_alloc<translator_creator_sptr> creators_vec)
    : translator_creator(lld, npl_context_slices), m_translator_creators(creators_vec)
{
}
compound_translator_creator::~compound_translator_creator()
{
}

la_status
compound_translator_creator::pre_table_init()
{
    for (const auto& creator : m_translator_creators) {
        la_status status = creator->pre_table_init();
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
compound_translator_creator::post_table_init()
{
    for (const auto& creator : m_translator_creators) {
        la_status status = creator->post_table_init();
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
compound_translator_creator::initialize_table(void* table, npl_tables_e table_type, const std::vector<size_t>& indices)
{
    for (const auto& creator : m_translator_creators) {
        la_status status = creator->initialize_table(table, table_type, indices);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
compound_translator_creator::load_microcode(const std::vector<size_t>& slices, npl_context_e context)
{
    for (const auto& creator : m_translator_creators) {
        la_status status = creator->load_microcode(slices, context);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

npl_context_e
compound_translator_creator::get_slice_context(size_t slice_index)
{
    // Call get_slice_context for one creator since table placement will be
    // same for all creators.m_translator_creatorsm_translator_creators
    const auto& creator = m_translator_creators.front();
    return creator->get_slice_context(slice_index);
}

} // namespace silicon_one
