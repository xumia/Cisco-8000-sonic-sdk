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

#ifndef __LA_NPU_HOST_DESTINATION_IMPL_H__
#define __LA_NPU_HOST_DESTINATION_IMPL_H__

/// @file
/// @brief Leaba NPU host destination

#include "api/system/la_npu_host_destination.h"
#include "api/types/la_common_types.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_npu_host_destination_impl : public la_npu_host_destination
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_npu_host_destination_impl() = default;
    //////////////////////////////
public:
    explicit la_npu_host_destination_impl(const la_device_impl_wptr& device);
    ~la_npu_host_destination_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, la_npu_host_port* npu_host_port);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    const la_npu_host_port_base* get_npu_host_port() const;

private:
    // Device this port belongs to
    la_device_impl_wptr m_device{};

    // Object ID
    la_object_id_t m_oid{LA_OBJECT_ID_INVALID};

    // System Port
    la_npu_host_port_base_wptr m_npu_host_port{};
};
}

#endif // __LA_NPU_HOST_DESTINATION_IMPL_H__
