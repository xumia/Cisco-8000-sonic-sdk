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

#include "la_l2_protection_group_base.h"
#include "npu/la_protection_monitor_impl.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"

#include "common/defines.h"

namespace silicon_one
{

la_l2_protection_group_base::la_l2_protection_group_base(const la_device_impl_wptr& device)
    : m_device(device),
      m_gid(LA_L2_PORT_GID_INVALID),
      m_primary_destination(nullptr),
      m_backup_destination(nullptr),
      m_protection_monitor(nullptr)
{
}

la_l2_protection_group_base::~la_l2_protection_group_base()
{
}

la_l2_port_gid_t
la_l2_protection_group_base::get_gid() const
{
    return m_gid;
}

la_status
la_l2_protection_group_base::get_primary_destination(const la_l2_destination*& out_destination) const
{
    out_destination = m_primary_destination.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_protection_group_base::get_backup_destination(const la_l2_destination*& out_destination) const
{
    out_destination = m_backup_destination.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_protection_group_base::get_monitor(const la_protection_monitor*& out_protection_monitor) const
{
    out_protection_monitor = m_protection_monitor.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_protection_group_base::set_monitor(const la_protection_monitor* protection_monitor)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_object::object_type_e
la_l2_protection_group_base::type() const
{
    return object_type_e::L2_PROTECTION_GROUP;
}

la_object_id_t
la_l2_protection_group_base::oid() const
{
    return m_oid;
}

const la_device*
la_l2_protection_group_base::get_device() const
{
    return m_device.get();
}

} // namespace silicon_one
