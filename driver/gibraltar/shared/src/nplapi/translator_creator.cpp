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

#include <stdio.h>
#include <string.h>

#include "common/logger.h"

#include "nplapi/translator_creator.h"

#include "lld/ll_device.h"

namespace silicon_one
{

translator_creator::translator_creator(ll_device_sptr lld, const std::vector<npl_context_e>& npl_context_slices)
    : m_npl_context_slices(npl_context_slices), m_ll_device(lld)
{
    dassert_crit(lld);
}

translator_creator::~translator_creator()
{
}

ll_device_sptr
translator_creator::get_ll_device() const
{
    return m_ll_device;
}

la_status
translator_creator::pre_table_init()
{
    return LA_STATUS_SUCCESS;
}

la_status
translator_creator::post_table_init()
{
    return LA_STATUS_SUCCESS;
}

npl_context_e
translator_creator::get_slice_context(size_t slice_index)
{
    if (slice_index >= m_npl_context_slices.size()) {
        return NPL_NONE_CONTEXT;
    }

    return m_npl_context_slices[slice_index];
}

la_status
translator_creator::load_microcode(const std::vector<size_t>& slices, npl_context_e context)
{
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
