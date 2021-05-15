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

#include "npu/la_l2_protection_group_pacific.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_protection_monitor_impl.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"
#include "system/la_system_port_base.h"

#include "common/defines.h"

#include <sstream>

namespace silicon_one
{

la_l2_protection_group_pacific::la_l2_protection_group_pacific(const la_device_impl_wptr& device)
    : la_l2_protection_group_base(device), m_table_entry(nullptr)
{
}

la_l2_protection_group_pacific::~la_l2_protection_group_pacific()
{
}

la_status
la_l2_protection_group_pacific::initialize(la_object_id_t oid,
                                           la_l2_port_gid_t group_gid,
                                           const la_l2_destination_wcptr& primary_destination,
                                           const la_l2_destination_wcptr& backup_destination,
                                           const la_protection_monitor_wcptr& protection_monitor)
{
    m_oid = oid;
    la_status status;
    auto protection_monitor_impl = protection_monitor.weak_ptr_static_cast<const la_protection_monitor_impl>();

    npl_native_l2_lp_table_t::key_type k;
    npl_native_l2_lp_table_t::value_type v;

    // Set key
    k.l2_dlp.id = group_gid;

    // Set value
    npl_native_l2_lp_table_result_protected_t& protection_data(v.payloads.protected_entry.data);
    npl_native_l2_lp_table_protection_entry_t& primary_entry_value(protection_data.primary);
    npl_native_l2_lp_table_protection_entry_t& protecting_entry_value(protection_data.protecting);

    status = get_native_l2_lp_table_protection_member_value(primary_destination, primary_entry_value);
    return_on_error(status);

    status = get_native_l2_lp_table_protection_member_value(backup_destination, protecting_entry_value);
    return_on_error(status);

    protection_data.type = 0;
    protection_data.path.sel = NPL_PROTECTION_SELECTOR_PRIMARY;

    status = instantiate_resolution_object(protection_monitor_impl, RESOLUTION_STEP_NATIVE_L2_LP);
    return_on_error(status);

    protection_data.protection_id.id = protection_monitor_impl->get_gid();
    v.action = NPL_NATIVE_L2_LP_TABLE_ACTION_PROTECTED_ENTRY;

    // Write to table
    npl_native_l2_lp_table_t::entry_wptr_type new_entry_ptr = nullptr;
    status = m_device->m_tables.native_l2_lp_table->insert(k, v, new_entry_ptr);

    return_on_error(status);

    // Set object dependencies
    m_device->add_object_dependency(primary_destination, this);
    m_device->add_object_dependency(backup_destination, this);
    m_device->add_object_dependency(protection_monitor_impl, this);

    // Store parameters
    m_gid = group_gid;
    m_primary_destination = primary_destination;
    m_backup_destination = backup_destination;
    m_protection_monitor = protection_monitor_impl;
    m_table_entry = new_entry_ptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_protection_group_pacific::get_native_l2_lp_table_protection_member_value(
    const la_l2_destination_wcptr& protection_member_dest,
    npl_native_l2_lp_table_protection_entry_t& value)
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

    const la_system_port_base* protection_member_sp
        = static_cast<const la_system_port_base*>(protection_member_ep->get_system_port());
    if (protection_member_sp != nullptr) { // if ethernet over system port
        npl_native_l2_lp_dsp_l2_dlp_t& sp_value(value.dsp_l2_dlp);

        sp_value.dsp = protection_member_sp->get_gid();
        sp_value.l2_dlp = protection_member_srvp->get_gid();
        sp_value.enc_type = NPL_NPU_ENCAP_L2_HEADER_TYPE_AC;
        sp_value.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_DSP_L2_DLP;

        return LA_STATUS_SUCCESS;
    }

    const la_spa_port_base* protection_member_spa = static_cast<const la_spa_port_base*>(protection_member_ep->get_spa_port());
    if (protection_member_spa != nullptr) { // if ethernet over spa port
        npl_native_l2_lp_dspa_l2_dlp_t& spa_value(value.dspa_l2_dlp);

        spa_value.dspa = protection_member_spa->get_gid();
        spa_value.l2_dlp = protection_member_srvp->get_gid();
        spa_value.enc_type = NPL_NPU_ENCAP_L2_HEADER_TYPE_AC;
        spa_value.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_DSPA_L2_DLP;

        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_EINVAL;
}

la_status
la_l2_protection_group_pacific::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    m_device->remove_object_dependency(m_primary_destination, this);
    m_device->remove_object_dependency(m_backup_destination, this);
    m_device->remove_object_dependency(m_protection_monitor, this);

    npl_native_l2_lp_table_key_t key = m_table_entry->key();
    la_status status = m_device->m_tables.native_l2_lp_table->erase(key);
    return_on_error(status);
    m_table_entry = nullptr;

    status = uninstantiate_resolution_object(m_protection_monitor, RESOLUTION_STEP_NATIVE_L2_LP);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

std::string
la_l2_protection_group_pacific::to_string() const
{
    std::stringstream log_message;
    log_message << "la_l2_protection_group_pacific(oid=" << m_oid << ")";
    return log_message.str();
}

} // namespace silicon_one
