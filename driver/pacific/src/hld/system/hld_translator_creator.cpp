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

#include "system/hld_translator_creator.h"

namespace silicon_one
{

hld_translator_creator::hld_translator_creator(ll_device_sptr lld, const std::vector<npl_context_e>& npl_context_slices)
    : translator_creator(lld, npl_context_slices)
{
}

la_status
hld_translator_creator::initialize_table(void* table, npl_tables_e table_type, const std::vector<size_t>& indices)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

} // namespace silicon_one
