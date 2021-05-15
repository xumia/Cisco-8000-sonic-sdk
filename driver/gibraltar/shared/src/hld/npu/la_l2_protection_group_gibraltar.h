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

#ifndef __LA_L2_PROTECTION_GROUP_GIBRALTAR_H__
#define __LA_L2_PROTECTION_GROUP_GIBRALTAR_H__

#include "hld_types_fwd.h"
#include "la_l2_protection_group_base.h"
#include "nplapi/nplapi_tables.h"
#include "npu/resolution_configurator.h"

namespace silicon_one
{

class la_l2_protection_group_gibraltar : public la_l2_protection_group_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    // la_l2_protection_group_gibraltar API-s
    explicit la_l2_protection_group_gibraltar(const la_device_impl_wptr& device);

    ~la_l2_protection_group_gibraltar() override;

    la_status initialize(la_object_id_t oid,
                         la_l2_port_gid_t group_gid,
                         const la_l2_destination_wcptr& primary_destination,
                         const la_l2_destination_wcptr& backup_destination,
                         const la_protection_monitor_wcptr& protection_monitor) override;

    la_status destroy() override;

    // la_object API-s
    std::string to_string() const override;

protected:
    la_l2_protection_group_gibraltar() = default; // For serialization purposes only

    // Resolution helper functions
    la_status get_stage0_table_protection_member_value(const la_l2_destination_wcptr& protection_member_dest,
                                                       npl_wide_protection_entry_t& value);
    // Address of table entry
    resolution_cfg_handle_t m_cfg_handle;
};

} // namespace silicon_one

#endif // __LA_L2_PROTECTION_GROUP_GIBRALTAR_H__
