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

#ifndef __LA_NPU_HOST_PORT_PACIFIC_H__
#define __LA_NPU_HOST_PORT_PACIFIC_H__

#include "hld_types_fwd.h"
#include "la_npu_host_port_base.h"

namespace silicon_one
{

class la_npu_host_port_pacific : public la_npu_host_port_base
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_npu_host_port_pacific() = default;
    //////////////////////////////
public:
    explicit la_npu_host_port_pacific(const la_device_impl_wptr& device);
    ~la_npu_host_port_pacific() override;

    la_status initialize(la_object_id_t oid,
                         la_remote_device* remote_device,
                         la_system_port_gid_t system_port,
                         la_voq_set* voq_set,
                         const la_tc_profile* tc_profile) override;

private:
    la_status set_slice_source_pif_entry() override;
    la_status erase_slice_source_pif_entry() override;

    la_status initialize_remote(la_remote_device* remote_device,
                                la_system_port_gid_t system_port_gid,
                                la_voq_set* voq_set,
                                const la_tc_profile* tc_profile) override;
};

} // namespace silicon_one

#endif // __LA_NPU_HOST_PORT_PACIFIC_H__
