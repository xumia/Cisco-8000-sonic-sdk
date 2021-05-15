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

#ifndef __LA_TC_PROFILE_IMPL_H__
#define __LA_TC_PROFILE_IMPL_H__

#include "api/tm/la_unicast_tc_profile.h"
#include "api/types/la_qos_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_device_impl;

class la_tc_profile_impl : public la_tc_profile
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_tc_profile_impl(const la_device_impl_wptr& device);
    ~la_tc_profile_impl() override;

    la_status initialize(la_object_id_t oid);
    la_status destroy();
    uint64_t get_id() const;

    // la_tc_profile API's
    la_status set_mapping(la_traffic_class_t tc, la_uint8_t offset) override;
    la_status get_mapping(la_traffic_class_t tc, la_uint8_t& out_offset) const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

private:
    // Device this port belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Profile ID
    uint64_t m_id;

    la_tc_profile_impl() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif // __LA_TC_PROFILE_IMPL_H__
