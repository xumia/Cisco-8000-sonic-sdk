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

#ifndef __LA_MPLS_LABEL_DESTINATION_IMPL_H__
#define __LA_MPLS_LABEL_DESTINATION_IMPL_H__

#include "api/npu/la_mpls_label_destination.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_mpls_label_destination_impl : public la_mpls_label_destination
{
    ///////////Serialization//////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_mpls_label_destination_impl() = default;
    //////////////////////////////////
public:
    explicit la_mpls_label_destination_impl(const la_device_impl_wptr& device);
    ~la_mpls_label_destination_impl() override;
    la_status initialize(la_object_id_t oid,
                         size_t native_ce_ptr_table_index,
                         la_l3_destination_gid_t vpn_label_ptr,
                         la_mpls_label label,
                         const la_l3_destination_wptr& destination);
    la_status destroy();
    la_l3_destination_gid_t get_gid() const;
    la_status instantiate(resolution_step_e prev_step);
    la_status uninstantiate(resolution_step_e prev_step);

    // la_object APIs
    const la_device* get_device() const override;
    object_type_e type() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_mpls_label_destination APIs
    la_mpls_label get_label() const override;
    la_l3_destination* get_destination() const override;

private:
    // Creating device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Global ID
    la_l3_destination_gid_t m_vpn_label_ptr;

    // Associated label
    la_mpls_label m_label;

    // Associated destination
    la_l3_destination_wptr m_destination;

private:
};

} // namespace silicon_one

#endif // __LA_MPLS_LABEL_DESTINATION_IMPL_H__
