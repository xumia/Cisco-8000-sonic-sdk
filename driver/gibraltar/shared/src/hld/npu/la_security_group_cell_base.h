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

#ifndef __LA_SECURITY_GROUP_CELL_BASE_H__
#define __LA_SECURITY_GROUP_CELL_BASE_H__

#include "api/npu/la_counter_set.h"
#include "api/npu/la_security_group_cell.h"
#include "common/cereal_utils.h"
#include "hld_types_fwd.h"
#include "npu/la_acl_delegate.h"
#include <vector>

namespace silicon_one
{

class la_security_group_cell_base : public la_security_group_cell
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_security_group_cell_base(const la_device_impl_wptr& device);

    ~la_security_group_cell_base() override;

    virtual la_status initialize(la_object_id_t oid,
                                 la_sgt_t sgt,
                                 la_dgt_t dgt,
                                 la_ip_version_e ip_version,
                                 const la_counter_set_wptr& counter)
        = 0;
    virtual la_status destroy() = 0;

    // la_object APIs
    const la_device* get_device() const override;
    object_type_e type() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    la_status set_counter(la_counter_set* counter) override;
    la_status get_counter(la_counter_set*& out_counter) const override;
    la_status set_monitor_mode(bool allow_drop) override;
    la_status get_monitor_mode(bool& out_allow_drop) const override;
    la_status set_acl(la_acl* sgacl) override;
    la_status clear_acl() override;
    la_status get_acl(la_acl*& out_sgacl) const override;
    la_status set_bincode(la_uint32_t bincode) override;
    la_status get_bincode(la_uint32_t& out_bincode) const override;

protected:
    la_security_group_cell_base() = default; // For serialization purposes only.

    // Creating device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // SGT
    la_sgt_t m_sgt;

    // DGT
    la_dgt_t m_dgt;

    // IP Version
    la_ip_version_e m_ip_version;

    // Security Group ACL
    la_acl_delegate_wptr m_sgacl;

    // Allow Drop (for SGACL Monitor mode)
    bool m_allow_drop;

    // Security Group ACL ID
    la_uint32_t m_sgacl_id;

    // Security Group Bincode
    la_uint32_t m_sgacl_bincode;

    // Counters
    la_counter_set_wptr m_counter;
};

} // namespace silicon_one

#endif // __LA_SECURITY_GROUP_CELL_BASE_H__
