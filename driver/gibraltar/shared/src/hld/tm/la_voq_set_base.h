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

#ifndef __LA_VOQ_SET_BASE_H__
#define __LA_VOQ_SET_BASE_H__

#include <vector>

#include "api/tm/la_voq_set.h"
#include "api/types/la_tm_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

#include "lld/lld_memory.h"

namespace silicon_one
{

class la_voq_set_base : public la_voq_set
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_voq_set_base(const la_device_impl_wptr& device);

    ~la_voq_set_base() override;

    la_device_id_t get_destination_device() const override;
    la_slice_id_t get_destination_slice() const override;
    la_ifg_id_t get_destination_ifg() const override;
    la_voq_gid_t get_base_voq_id() const override;
    size_t get_set_size() const override;
    // la_voq_set API-s
    const la_device* get_device() const override;
    la_object_id_t oid() const override;

protected:
    la_voq_set_base() = default;
    // Device this VOQ belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid{LA_OBJECT_ID_INVALID};

    // VOQ ID
    la_voq_gid_t m_base_voq;

    // Set size
    size_t m_set_size;

    // Destination device
    la_device_id_t m_dest_device;

    // Destination slice
    la_slice_id_t m_dest_slice;

    // Destination IFG
    la_ifg_id_t m_dest_ifg;

}; // class la_voq_set_impl

} // namespace silicon_one

#endif // __LA_VOQ_SET_BASE_H__
