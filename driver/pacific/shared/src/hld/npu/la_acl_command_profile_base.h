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

#ifndef __LA_ACL_COMMAND_PROFILE_BASE_H__
#define __LA_ACL_COMMAND_PROFILE_BASE_H__

#include <vector>

#include "api/npu/la_acl_command_profile.h"
#include "hld_types.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_device_impl;

class la_acl_command_profile_base : public la_acl_command_profile
{
    ///////////// Serialization /////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_acl_command_profile_base() = default;
    /////////////////////////////////////////

public:
    explicit la_acl_command_profile_base(const la_device_impl_wptr& device);
    ~la_acl_command_profile_base() override;
    la_status initialize(la_object_id_t oid, const la_acl_command_def_vec_t& command_def);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_acl_command_profile API-s
    la_status get_command_definition(la_acl_command_def_vec_t& out_command_def_vec) const override;
    la_status get_hw_command_profile(uint32_t& out_hw_command_profile) const override;

private:
    bool is_command_actions_subset(const la_acl_command_def_vec_t& command_def_vec1,
                                   const la_acl_command_def_vec_t& command_def_vec2) const;
    // Containing device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // ACL command
    la_acl_command_def_vec_t m_acl_command;
};

} // namespace silicon_one

#endif //  __LA_ACL_COMMAND_PROFILE_BASE_H__
