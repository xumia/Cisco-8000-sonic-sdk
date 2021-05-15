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

#ifndef __LA_ACL_GROUP_PACIFIC_H__
#define __LA_ACL_GROUP_PACIFIC_H__

#include "npu/la_acl_group_base.h"

namespace silicon_one
{

class la_acl_group_pacific : public la_acl_group_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_acl_group_pacific(const la_device_impl_wptr& device);
    ~la_acl_group_pacific() override;

private:
    // For serialization
    la_acl_group_pacific() = default;

    virtual npl_rtf_stage_and_type_e get_next_rtf_stage(la_acl_packet_format_e packet_format,
                                                        const la_acl_wptr_vec_t& acls,
                                                        uint16_t acl_index) const override;
    virtual npl_rtf_stage_and_type_e get_init_eth_rtf_stage(la_acl_packet_format_e packet_format,
                                                            const la_acl_wptr_vec_t& acls) const override;
    virtual la_status get_post_fwd_rtf_stage(la_acl_packet_format_e packet_format,
                                             const la_acl_wptr_vec_t& acls,
                                             npl_rtf_stage_and_type_e& post_fwd_rtf_stage) const override;
};

} // namespace silicon_one

#endif // __LA_ACL_GROUP_PACIFIC_H__
