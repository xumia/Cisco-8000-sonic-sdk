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

#ifndef __LA_L2_MIRROR_COMMAND_PACIFIC_H__
#define __LA_L2_MIRROR_COMMAND_PACIFIC_H__

#include "la_l2_mirror_command_pacgb.h"

namespace silicon_one
{

class la_l2_mirror_command_pacific : public la_l2_mirror_command_pacgb
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_l2_mirror_command_pacific() = default;
    //////////////////////////////
public:
    explicit la_l2_mirror_command_pacific(const la_device_impl_wptr& device);
    ~la_l2_mirror_command_pacific() override;

    la_status set_truncate(bool truncate) override;

protected:
    la_status populate_punt_encap_data(la_uint_t mirror_gid,
                                       npl_punt_encap_data_t& punt_encap_data,
                                       la_uint_t encap_ptr) const override;
    la_status configure_stack_remote_mirror_destination_map(la_uint_t mirror_gid, npl_destination_t destination) override;
    la_status teardown_stack_remote_mirror_destination_map(la_uint_t mirror_gid) override;

private:
    la_status configure_cud_entry(la_uint_t mirror_hw_id, la_uint_t mirror_gid, la_uint_t encap_ptr) override;
    la_status teardown_cud_entry(la_uint_t mirror_hw_id) override;
    la_status configure_cud_wide_hw_entry(la_uint_t mirror_hw_id, la_uint_t mirror_gid, la_uint_t encap_ptr);
    la_status teardown_cud_wide_hw_entry(la_uint_t mirror_hw_id);
    la_status configure_redirect_code(uint64_t redirect_code, npl_punt_nw_encap_type_e redirect_type, la_uint_t encap_ptr) override;
    la_status configure_recycle_override_entry(la_uint_t mirror_hw_id) override;
    la_status remove_recycle_override_entry(la_uint_t mirror_hw_id) override;
};

} // namespace silicon_one

#endif // __LA_L2_MIRROR_COMMAND_PACIFIC_H__
