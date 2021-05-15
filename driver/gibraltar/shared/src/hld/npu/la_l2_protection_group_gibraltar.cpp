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

#include "npu/la_l2_protection_group_gibraltar.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_protection_monitor_impl.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"

#include "common/defines.h"

#include <sstream>

namespace silicon_one
{

la_l2_protection_group_gibraltar::la_l2_protection_group_gibraltar(const la_device_impl_wptr& device)
    : la_l2_protection_group_base(device)
{
}

la_l2_protection_group_gibraltar::~la_l2_protection_group_gibraltar()
{
}

la_status
la_l2_protection_group_gibraltar::initialize(la_object_id_t oid,
                                             la_l2_port_gid_t group_gid,
                                             const la_l2_destination_wcptr& primary_destination,
                                             const la_l2_destination_wcptr& backup_destination,
                                             const la_protection_monitor_wcptr& protection_monitor)
{
    m_oid = oid;
    npl_resolution_stage_assoc_data_wide_protection_record_t protection_record{};
    npl_wide_protection_entry_t& primary_entry(protection_record.primary_entry);
    npl_wide_protection_entry_t& protecting_entry(protection_record.protect_entry);
    la_status status;

    auto protection_monitor_impl = protection_monitor.weak_ptr_static_cast<const la_protection_monitor_impl>();

    // Set value
    status = get_stage0_table_protection_member_value(primary_destination, primary_entry);
    return_on_error(status);

    status = get_stage0_table_protection_member_value(backup_destination, protecting_entry);
    return_on_error(status);

    status = instantiate_resolution_object(protection_monitor_impl, RESOLUTION_STEP_STAGE0_PROTECTION);
    return_on_error(status);

    protection_record.id = protection_monitor_impl->get_gid();
    protection_record.path = NPL_PROTECTION_SELECTOR_PRIMARY;

    m_gid = group_gid;
    destination_id dest = get_destination_id(this, RESOLUTION_STEP_FORWARD_L2);
    status = m_device->m_resolution_configurators[0].configure_dest_map_entry(dest, protection_record, m_cfg_handle);
    return_on_error(status);

    // Set object dependencies
    m_device->add_object_dependency(primary_destination, this);
    m_device->add_object_dependency(backup_destination, this);
    m_device->add_object_dependency(protection_monitor_impl, this);

    // Store parameters
    m_primary_destination = primary_destination;
    m_backup_destination = backup_destination;
    m_protection_monitor = protection_monitor_impl;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_protection_group_gibraltar::get_stage0_table_protection_member_value(const la_l2_destination_wcptr& protection_member_dest,
                                                                           npl_wide_protection_entry_t& value)
{
    if (protection_member_dest->type() != la_object::object_type_e::L2_SERVICE_PORT) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    const auto& protection_member_srvp = protection_member_dest.weak_ptr_static_cast<const la_l2_service_port_base>();

    la_l2_service_port_base::port_type_e port_type = protection_member_srvp->get_port_type();
    if (port_type != la_l2_service_port::port_type_e::AC) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    const auto protection_member_ep = protection_member_srvp->get_ethernet_port();

    npl_stage0_l2_dlp_destination_l2_dlp_t& sp_value(value.stage0_l2_dlp_dest_l2_dlp);
    destination_id dest_id = get_destination_id(protection_member_ep, RESOLUTION_STEP_FORWARD_L2);
    sp_value.destination = dest_id.val;
    sp_value.l2_dlp = protection_member_srvp->get_gid();
    sp_value.enc_type = NPL_NPU_ENCAP_L2_HEADER_TYPE_AC;
    sp_value.type = NPL_ENTRY_TYPE_STAGE0_L2_DLP_DESTINATION_L2_DLP;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_protection_group_gibraltar::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    m_device->remove_object_dependency(m_primary_destination, this);
    m_device->remove_object_dependency(m_backup_destination, this);
    m_device->remove_object_dependency(m_protection_monitor, this);

    m_device->m_resolution_configurators[0].unconfigure_entry(m_cfg_handle);

    la_status status;
    status = uninstantiate_resolution_object(m_protection_monitor, RESOLUTION_STEP_STAGE0_PROTECTION);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

std::string
la_l2_protection_group_gibraltar::to_string() const
{
    std::stringstream log_message;
    log_message << "la_l2_protection_group_gibraltar(oid=" << m_oid << ")";
    return log_message.str();
}

} // namespace silicon_one
