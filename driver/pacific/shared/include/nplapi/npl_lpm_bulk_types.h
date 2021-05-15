// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __NPL_LPM_BULK_TYPES_H__
#define __NPL_LPM_BULK_TYPES_H__

#include "api/types/la_common_types.h"
#include "common/allocator_wrapper.h"
#include "common/defines.h"
#include "common/gen_operators.h"
#include "common/la_status.h"
#include "nplapi/npl_api_types.h"

namespace silicon_one
{

template <class _Trait>
struct npl_lpm_bulk_entry {
    typedef typename _Trait::key_type key_type;
    typedef typename _Trait::value_type value_type;

    npl_lpm_bulk_entry();

    npl_action_e action;
    key_type key;
    size_t length;
    value_type value;
    la_user_data_t user_data;
    bool latency_sensitive;

    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(action);
        ar(key);
        ar(length);
        ar(value);
        ar(user_data);
        ar(latency_sensitive);
    }
};

template <class _Trait>
using npl_lpm_bulk_entries_vec = vector_alloc<npl_lpm_bulk_entry<_Trait> >;

// npl_lpm_table_entry implementation
template <class _Trait>
npl_lpm_bulk_entry<_Trait>::npl_lpm_bulk_entry()
{
}
}

#endif
