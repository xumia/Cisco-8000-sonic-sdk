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

#ifndef __LA_L2_PROTECTION_GROUP_BASE_H__
#define __LA_L2_PROTECTION_GROUP_BASE_H__

#include "api/npu/la_l2_protection_group.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_l2_protection_group_base : public la_l2_protection_group
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // la_l2_protection_group_base API-s
    explicit la_l2_protection_group_base(const la_device_impl_wptr& device);

    ~la_l2_protection_group_base() override;

    virtual la_status initialize(la_object_id_t oid,
                                 la_l2_port_gid_t group_gid,
                                 const la_l2_destination_wcptr& primary_destination,
                                 const la_l2_destination_wcptr& backup_destination,
                                 const la_protection_monitor_wcptr& protection_monitor)
        = 0;

    virtual la_status destroy() = 0;

    // la_l2_protection_group API-s
    la_status get_monitor(const la_protection_monitor*& out_protection_monitor) const override;
    la_status set_monitor(const la_protection_monitor* protection_monitor) override;
    la_l2_port_gid_t get_gid() const override;

    la_status get_primary_destination(const la_l2_destination*& out_destination) const override;
    la_status get_backup_destination(const la_l2_destination*& out_destination) const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;

protected:
    // Owner device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid{LA_OBJECT_ID_INVALID};
    // L2 protection group GID
    la_l2_port_gid_t m_gid;

    // L2 protection group primary destination
    la_l2_destination_wcptr m_primary_destination;

    // L2 protection group backup destination
    la_l2_destination_wcptr m_backup_destination;

    // L2 protection group protection monitor
    la_protection_monitor_impl_wcptr m_protection_monitor;

    la_l2_protection_group_base() = default; // For serialization only.
};

} // namespace silicon_one

#endif // __LA_L2_PROTECTION_GROUP_BASE_H__
