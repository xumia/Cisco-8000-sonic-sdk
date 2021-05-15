// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_MULTICAST_PROTECTION_MONITOR_BASE_H__
#define __LA_MULTICAST_PROTECTION_MONITOR_BASE_H__

#include "api/npu/la_multicast_protection_monitor.h"
#include "common/la_status.h"
#include "hld_types.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_multicast_protection_monitor_base : public la_multicast_protection_monitor
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_multicast_protection_monitor_base(const la_device_impl_wptr& device);
    ~la_multicast_protection_monitor_base() override;
    la_status initialize(la_object_id_t oid, la_uint_t protection_monitor_gid);
    la_status destroy();
    la_uint_t get_gid() const;

    // la_multicast_protection_monitor API-s
    la_status set_state(bool primary_active, bool backup_active) override;
    la_status get_state(bool& out_primary_active, bool& out_backup_active) const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

private:
    la_device_impl_wptr m_device;

    // Primary/Backup state
    bool m_primary_state;
    bool m_backup_state;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // Monitor ID
    la_uint_t m_monitor_gid;

    // Table management
    la_status configure_mldp_protection_table(bool primary_active, bool backup_active);

    la_multicast_protection_monitor_base() = default; // For serialization only.
};

} // namespace  silicon_one

#endif // __LA_MULTICAST_PROTECTION_MONITOR_BASE_H__
