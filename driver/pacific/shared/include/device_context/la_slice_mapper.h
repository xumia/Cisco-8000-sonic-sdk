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

#ifndef __LA_SLICE_MAPPER_H__
#define __LA_SLICE_MAPPER_H__

#include "api/types/la_common_types.h"

struct json_t;

namespace silicon_one
{

class la_slice_mapper
{
public:
    la_slice_mapper(){};
    virtual ~la_slice_mapper(){};

    /// mapping functions
    virtual la_slice_pair_id_t map_slice_pair(la_slice_pair_id_t id) const = 0;
    virtual la_slice_pair_id_t map_back_slice_pair(la_slice_pair_id_t id) const = 0;

    virtual la_slice_id_t map_slice(la_slice_id_t id) const = 0;
    virtual la_slice_id_t map_back_slice(la_slice_id_t id) const = 0;

    virtual la_status map_slice_ifg(la_slice_ifg& ifg) const = 0;
    virtual la_status map_back_slice_ifg(la_slice_ifg& ifg) const = 0;

    virtual la_status map_serdices(la_slice_serdices& map_this) const = 0;
    virtual la_status map_back_serdices(la_slice_serdices& map_this) const = 0;

    virtual la_status map_pif(la_slice_pif& map_this) const = 0;
    virtual la_status map_back_pif(la_slice_pif& map_this) const = 0;

    virtual bool is_mapping_active() const = 0;

    virtual size_t max_num_slices_per_device() const = 0;

protected:
};

} // namespace silicon_one

#endif // __LA_SLICE_MAPPER_H__
