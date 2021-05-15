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

#ifndef __LA_FILTER_GROUP_IMPL_H__
#define __LA_FILTER_GROUP_IMPL_H__

#include "api/npu/la_filter_group.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

#include <map>
#include <stdint.h>
#include <vector>

namespace silicon_one
{

class la_filter_group_impl : public la_filter_group
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_filter_group_impl() = default;
    //////////////////////////////
public:
    explicit la_filter_group_impl(const la_device_impl_wptr& device);
    ~la_filter_group_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, uint64_t filter_group_index);
    la_status destroy();

    // la_filter_group API-s
    la_status get_filtering_mode(const la_filter_group* dest_group, filtering_mode_e& out_mode) override;
    la_status set_filtering_mode(const la_filter_group* dest_group, filtering_mode_e mode) override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    /// @brief Get group ID.
    ///
    /// @return Group ID in hardware.
    uint64_t get_id() const;

private:
    /// Device this AC profle belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    /// Profile index
    uint64_t m_index;
};
}

#endif
