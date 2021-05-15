// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_IP_MULTICAST_GROUP_GIBRALTAR_H__
#define __LA_IP_MULTICAST_GROUP_GIBRALTAR_H__

#include "npu/la_ip_multicast_group_base.h"

namespace silicon_one
{

class la_device_impl;

class la_ip_multicast_group_gibraltar : public la_ip_multicast_group_base
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_ip_multicast_group_gibraltar() = default;
    //////////////////////////////
public:
    explicit la_ip_multicast_group_gibraltar(la_device_impl_wptr device);
    ~la_ip_multicast_group_gibraltar() override;

private:
    enum {
        COUNTER_MC_COPY_ID_PREFIX = 0xa,    // Prefix that is added to the MCG counter pointer, marking it as a counter MC-COPY-ID
        COUNTER_PTR_WIDTH = 13,             // Counter pointer bank offset index width in bits for Gibraltar
        COUNTER_PTR_BANK_PROFILE_WIDTH = 1, // Counter bank profile width in bits for Gibraltar
    };

    // Configure CUD mapping table
    la_status configure_cud_mapping(const member_t& member, la_slice_id_t dest_slice, uint64_t mc_copy_id) override;
    la_status teardown_cud_mapping(const member_t& member, la_slice_id_t dest_slice, uint64_t mc_copy_id) override;

    // Helper functions with MC copy ID management
    la_status allocate_mc_copy_id(const member_t& member, la_slice_id_t dest_slice, uint64_t& out_mc_copy_id) override;
    la_status release_mc_copy_id(const member_t& member, la_slice_id_t dest_slice) override;

    // stack copy
    la_status configure_stack_copy_cud_mapping(la_slice_id_t slice, uint64_t mc_copy_id);
};

} // namespace silicon_one

#endif // __LA_IP_MULTICAST_GROUP_GIBRALTAR_H__
