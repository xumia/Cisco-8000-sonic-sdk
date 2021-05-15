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

#include <algorithm>

#include "api_tracer.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "hld_types.h"
#include "hld_utils.h"
#include "la_spa_port_pacgb.h"
#include "la_strings.h"
#include "la_system_port_pacgb.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_base.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_pci_port_base.h"
#include "system/la_recycle_port_base.h"
#include "system/la_remote_port_impl.h"

#include <sstream>

using namespace std;
namespace silicon_one
{

la_spa_port_pacgb::la_spa_port_pacgb(const la_device_impl_wptr& device)
    : la_spa_port_base(device), m_source_pif_hw_table_value_valid(false)
{
}

la_spa_port_pacgb::~la_spa_port_pacgb()
{
}

la_status
la_spa_port_pacgb::set_source_pif_table(npl_source_pif_hw_table_value_t value)
{
    m_source_pif_hw_table_value = value;
    m_source_pif_hw_table_value_valid = true;

    for (auto& sp_data : m_system_ports_data) {
        const auto& system_port_pacgb = sp_data->system_port.weak_ptr_static_cast<la_system_port_pacgb>();
        la_system_port_base::port_type_e sys_port_type = system_port_pacgb->get_port_type();
        if (sys_port_type == la_system_port_base::port_type_e::REMOTE) {
            continue;
        }
        la_status status = system_port_pacgb->set_source_pif_table(value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_pacgb::clear_source_pif()
{

    for (auto& sp_data : m_system_ports_data) {
        const auto& system_port_base = sp_data->system_port;
        la_system_port_base::port_type_e sys_port_type = system_port_base->get_port_type();
        if (sys_port_type == la_system_port_base::port_type_e::REMOTE) {
            continue;
        }
        la_status status = system_port_base->erase_source_pif_table_entries();
        return_on_error(status);
    }
    m_source_pif_hw_table_value_valid = false;
    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_pacgb::add(const la_system_port* system_port)
{
    start_api_call("system_port=", system_port);

    transaction txn;

    if (system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (system_port->get_device() != m_device) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_system_port_pacgb_wptr system_port_wptr = m_device->get_sptr<la_system_port_pacgb>(const_cast<la_system_port*>(system_port));

    if (system_port_wptr->has_port_dependency()) {
        return LA_STATUS_EBUSY;
    }

    if (system_port_wptr->get_base_pif() == HOST_PIF_ID) { // PACKET-DMA-WA
        return LA_STATUS_EINVAL;
    }

    // Add underlying port speed dependency:
    register_attribute_dependency(system_port_wptr);
    txn.on_fail([&]() { remove_attribute_dependency(system_port_wptr); });

    la_mac_port::port_speed_e port_speed;
    txn.status = get_underlying_port_speed(system_port_wptr, port_speed);
    return_on_error(txn.status);

    auto new_sp_data = make_shared<system_port_base_data>(system_port_base_data{
        system_port_wptr, 0 /*num_of_dspa_table_entries*/, port_speed, false /*is_active*/, true /*is_receive_enabled*/});
    m_system_ports_data.push_back(move(new_sp_data));
    txn.on_fail([&]() { m_system_ports_data.pop_back(); });

    la_system_port_pacgb::port_type_e sys_port_type = system_port_wptr->get_port_type();

    txn.status = add_ifg_user(system_port_wptr);
    return_on_error(txn.status);
    txn.on_fail([=]() { remove_ifg_user(system_port_wptr); });

    // A remote system port doesn't have any local IFG info, and shouldn't be configured in the RX tables (source_pif_table)
    if (sys_port_type != la_system_port_pacgb::port_type_e::REMOTE) {

        if (m_source_pif_hw_table_value_valid) {
            txn.status = system_port_wptr->set_source_pif_table(m_source_pif_hw_table_value);
            return_on_error(txn.status);
            txn.on_fail([=]() { system_port_wptr->erase_source_pif_table_entries(); });
        }
        if (m_mac_af_npp_attributes_table_value_valid) {
            txn.status = system_port_wptr->set_mac_af_npp_attributes(m_mac_af_npp_attributes_table_value);
            return_on_error(txn.status);
        }
        txn.status = system_port_wptr->set_mtu(m_mtu);
        return_on_error(txn.status);

        txn.status = system_port_wptr->set_mask_eve(m_mask_eve);
        return_on_error(txn.status);
    }

    m_device->add_object_dependency(system_port_wptr, this);
    txn.on_fail([=]() { m_device->remove_object_dependency(system_port_wptr, this); });

    attribute_management_details amd;
    amd.op = attribute_management_op::SPA_MEMBERSHIP_CHANGED;
    amd.spa.l2_ac_port = nullptr;
    amd.spa.l3_ac_port = nullptr;
    amd.spa.is_added = true;
    amd.spa.sys_port = system_port_wptr.get();

    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) {
        amd.spa.is_added = false;
        return amd;
    };
    txn.status = m_device->notify_attribute_changed(this, amd, undo);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_pacgb::remove(const la_system_port* system_port)
{
    transaction txn;
    start_api_call("system_port=", system_port);
    if (system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (system_port->get_device() != m_device) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_system_port_wcptr system_port_wptr = m_device->get_sptr(system_port);

    auto sp_data_to_remove_it = get_system_port_data_it(system_port_wptr);
    if (sp_data_to_remove_it == m_system_ports_data.end()) {
        return LA_STATUS_ENOTFOUND;
    }
    auto sp_data_to_remove = *sp_data_to_remove_it;

    if (sp_data_to_remove->is_active) {
        return LA_STATUS_EBUSY;
    }

    m_system_ports_data.erase(sp_data_to_remove_it);
    txn.on_fail([=]() { m_system_ports_data.push_back(move(sp_data_to_remove)); });

    // Remove underlying port speed dependency:
    remove_attribute_dependency(system_port_wptr);
    txn.on_fail([&]() { register_attribute_dependency(system_port_wptr); });

    const auto& system_port_pacgb = sp_data_to_remove->system_port.weak_ptr_static_cast<la_system_port_pacgb>();
    la_system_port_pacgb::port_type_e sys_port_type = system_port_pacgb->get_port_type();
    if (sys_port_type != la_system_port_pacgb::port_type_e::REMOTE) {
        // If the source_pif_table stored data is not yet valid (hasn't been initialized by an upper object, i.e., ethernet_port)
        // then don't update the system_port
        if (m_source_pif_hw_table_value_valid) {
            txn.status = system_port_pacgb->erase_source_pif_table_entries();
            return_on_error(txn.status);
            txn.on_fail([&]() { system_port_pacgb->set_source_pif_table(m_source_pif_hw_table_value); });
        }
    }

    txn.status = remove_ifg_user(system_port_pacgb);
    return_on_error(txn.status);
    txn.on_fail([=]() { add_ifg_user(system_port_pacgb); });

    m_device->remove_object_dependency(system_port_pacgb, this);
    txn.on_fail([&]() { m_device->add_object_dependency(system_port_pacgb, this); });

    attribute_management_details amd;
    amd.op = attribute_management_op::SPA_MEMBERSHIP_CHANGED;
    amd.spa.is_added = false;
    amd.spa.sys_port = system_port_pacgb.get();
    amd.spa.l2_ac_port = nullptr;
    amd.spa.l3_ac_port = nullptr;

    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) {
        amd.spa.is_added = true;
        return amd;
    };
    txn.status = m_device->notify_attribute_changed(this, amd, undo);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_pacgb::configure_system_port_source_pif_table(const la_system_port* system_port, bool enabled)
{
    la_system_port_pacgb_wptr system_port_wptr = m_device->get_sptr<la_system_port_pacgb>(const_cast<la_system_port*>(system_port));

    if (m_source_pif_hw_table_value_valid) {
        npl_source_pif_hw_table_value_t source_pif_hw_table_value;
        source_pif_hw_table_value = m_source_pif_hw_table_value;
        // np_macro_id is the in-engine, 6-bit ID and not the full 8-bit ID; truncate the MSB-s
        if (!enabled) {
            source_pif_hw_table_value.payloads.init_rx_data.np_macro_id = (NPL_NETWORK_TERMINATION_ERROR_MACRO & 0x3F);
        }
        la_status status = system_port_wptr->set_source_pif_table(source_pif_hw_table_value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
