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

#ifndef __LA_ACL_KEY_PROFILE_PACIFIC_H__
#define __LA_ACL_KEY_PROFILE_PACIFIC_H__

#include "hld_types_fwd.h"
#include "npu/la_acl_key_profile_base.h"

namespace silicon_one
{

class la_device_impl;

class la_acl_key_profile_pacific : public la_acl_key_profile_base
{
    ////////// Serialization ///////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_acl_key_profile_pacific() = default;
    ////////////////////////////////////
public:
    explicit la_acl_key_profile_pacific(const la_device_impl_wptr& device);
    ~la_acl_key_profile_pacific() override;

private:
    int8_t get_vlan_outer_offset() const override;
    int8_t get_vlan_inner_offset() const override;

    la_status fill_ethernet_udk_components(std::vector<udk_component>& udk_components,
                                           const la_acl_key_def_vec_t& key_def) override;
    la_status fill_v4_udk_components(std::vector<udk_component>& udk_components, const la_acl_key_def_vec_t& key_def) override;
    la_status fill_v6_udk_components(std::vector<udk_component>& udk_components, const la_acl_key_def_vec_t& key_def) override;
};

} // namespace silicon_one

#endif //  __LA_ACL_KEY_PROFILE_PACIFIC_H__
