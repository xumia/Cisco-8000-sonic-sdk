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
#include "la_strings.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_base.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_pci_port_base.h"
#include "system/la_recycle_port_base.h"
#include "system/la_remote_port_impl.h"
#include "system/la_spa_port_akpg.h"
#include "system/la_system_port_akpg.h"

#include <sstream>

using namespace std;
namespace silicon_one
{

la_spa_port_akpg::la_spa_port_akpg(const la_device_impl_wptr& device) : la_spa_port_base(device)
{
}

la_spa_port_akpg::~la_spa_port_akpg()
{
}

la_status
la_spa_port_akpg::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    la_status status;
    status = erase_port_dspa_group_size_table_entry();
    return_on_error(status);

    for (size_t i = 0; i < m_index_to_system_port.size(); i++) {
        status = pop_port_dspa_table_entry();
        return_on_error(status);
    }

    for (auto& sp_data : m_system_ports_data) {
        const auto& system_port_base = sp_data->system_port;

        status = remove_ifg_user(system_port_base);
        return_on_error(status);

        m_device->remove_object_dependency(system_port_base, this);
    }

    m_device = nullptr;
    m_gid = LA_SPA_PORT_GID_INVALID;

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_akpg::add_system_port_to_dspa_table(std::shared_ptr<system_port_base_data>& sp_data_to_update,
                                                size_t num_of_entries_to_add,
                                                transaction& txn)
{
    size_t dspa_table_size = m_index_to_system_port.size();
    const auto& sp = sp_data_to_update->system_port;

    for (size_t i = 0; i < num_of_entries_to_add; i++) {
        // Configure the new system port entry in resolution tables
        la_status status = set_port_dspa_table_entry(sp, dspa_table_size + i);
        txn.on_fail([=] { pop_port_dspa_table_entry(); });
        return_on_error(status);

        m_index_to_system_port.push_back(sp);
        txn.on_fail([&] { m_index_to_system_port.pop_back(); });
    }

    sp_data_to_update->num_of_dspa_table_entries += num_of_entries_to_add;
    txn.on_fail([=] { sp_data_to_update->num_of_dspa_table_entries -= num_of_entries_to_add; });

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_akpg::clear_table_tail(size_t start_index, transaction& txn)
{
    for (size_t idx = m_index_to_system_port.size(); idx > start_index; --idx) {
        auto sp_to_delete = m_index_to_system_port.back();
        m_index_to_system_port.pop_back();
        txn.on_fail([=]() { m_index_to_system_port.push_back(sp_to_delete); });

        // Erase the last member entry
        la_status status = pop_port_dspa_table_entry();
        txn.on_fail([=]() { set_port_dspa_table_entry(sp_to_delete, idx - 1); });
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_akpg::init_port_dspa_group_size_table_entry()
{
    la_status status;
    if (m_gid < UCMP_GROUP_SIZE) {
        status
            = m_device->m_resolution_configurators[3].set_ucmp_group_size(m_gid, 0, NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED);
    } else {
        status = m_device->m_resolution_configurators[3].set_group_size(
            m_gid - UCMP_GROUP_SIZE, 0, NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED);
    }
    return status;
}

la_status
la_spa_port_akpg::erase_port_dspa_group_size_table_entry()
{
    if (m_gid < UCMP_GROUP_SIZE) {
        return m_device->m_resolution_configurators[3].erase_ucmp_group_size(m_gid);
    }

    return m_device->m_resolution_configurators[3].erase_group_size(m_gid - UCMP_GROUP_SIZE);
}

la_status
la_spa_port_akpg::set_port_dspa_group_size_table_entry(size_t lbg_group_size)
{
    la_status status = LA_STATUS_SUCCESS;
    if (m_gid < UCMP_GROUP_SIZE) {
        status = m_device->m_resolution_configurators[3].set_ucmp_group_size(
            m_gid, lbg_group_size, NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED);
    } else {
        status = m_device->m_resolution_configurators[3].set_group_size(
            m_gid - UCMP_GROUP_SIZE, lbg_group_size, NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED);
    }

    return status;
}

destination_id
la_spa_port_akpg::get_destination_id(resolution_step_e prev_step) const
{
    return destination_id(NPL_DESTINATION_MASK_DSPA | get_gid());
}

la_status
la_spa_port_akpg::set_port_dspa_table_entry(const la_system_port_wcptr& system_port, size_t lbg_member_id)
{
    resolution_cfg_handle_t res_cfg_handle;

    npl_resolution_stage_assoc_data_narrow_entry_t entry{{0}};
    entry.stage3_dspa_dest.destination = silicon_one::get_destination_id(system_port, RESOLUTION_STEP_STAGE3_DSPA).val;
    entry.stage3_dspa_dest.type = NPL_ENTRY_TYPE_STAGE3_DSPA_DESTINATION;
    la_status status = m_device->m_resolution_configurators[3].configure_lb_entry(get_gid(), lbg_member_id, entry, res_cfg_handle);
    return_on_error(status);

    if (lbg_member_id < m_resolution_cfg_handles.size()) {
        m_resolution_cfg_handles[lbg_member_id] = res_cfg_handle;
    } else if (lbg_member_id == m_resolution_cfg_handles.size()) {
        m_resolution_cfg_handles.push_back(res_cfg_handle);
    } else {
        dassert_crit(false);
        return LA_STATUS_EUNKNOWN;
    }

    return status;
}

la_status
la_spa_port_akpg::pop_port_dspa_table_entry()
{
    la_status status = m_device->m_resolution_configurators[3].unconfigure_entry(m_resolution_cfg_handles.back());
    m_resolution_cfg_handles.pop_back();
    return status;
}

la_status
la_spa_port_akpg::set_lb_mode(la_lb_mode_e lb_mode)
{
    start_api_call("lb_mode=", lb_mode);
    la_uint32_t group_size;
    npl_lb_consistency_mode_e lb_consistency_mode;
    la_status status;
    if (m_gid < UCMP_GROUP_SIZE) {
        status = m_device->m_resolution_configurators[3].get_ucmp_group_size(m_gid, group_size, lb_consistency_mode);
    } else {
        status = m_device->m_resolution_configurators[3].get_group_size(m_gid - UCMP_GROUP_SIZE, group_size, lb_consistency_mode);
    }

    return_on_error(status);

    switch (lb_mode) {
    case la_lb_mode_e::CONSISTENT:
        lb_consistency_mode = NPL_LB_CONSISTENCY_MODE_CONSISTENCE_ENABLED;
        break;

    case la_lb_mode_e::DYNAMIC:
        lb_consistency_mode = NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED;
        break;

    default:
        return LA_STATUS_EUNKNOWN;
    }

    if (m_gid < UCMP_GROUP_SIZE) {
        status = m_device->m_resolution_configurators[3].set_ucmp_group_size(m_gid, group_size, lb_consistency_mode);
    } else {
        status = m_device->m_resolution_configurators[3].set_group_size(m_gid - UCMP_GROUP_SIZE, group_size, lb_consistency_mode);
    }
    return status;
}

la_status
la_spa_port_akpg::get_lb_mode(la_lb_mode_e& out_lb_mode) const
{
    la_uint32_t group_size;
    npl_lb_consistency_mode_e lb_consistency_mode;
    la_status status;
    if (m_gid < UCMP_GROUP_SIZE) {
        status = m_device->m_resolution_configurators[3].get_ucmp_group_size(m_gid, group_size, lb_consistency_mode);
    } else {
        status = m_device->m_resolution_configurators[3].get_group_size(m_gid - UCMP_GROUP_SIZE, group_size, lb_consistency_mode);
    }
    return_on_error(status);

    switch (lb_consistency_mode) {
    case NPL_LB_CONSISTENCY_MODE_CONSISTENCE_ENABLED:
        out_lb_mode = la_lb_mode_e::CONSISTENT;
        break;

    case NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED:
        out_lb_mode = la_lb_mode_e::DYNAMIC;
        break;

    default:
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_akpg::set_source_pif_table(npl_ifg0_ssp_mapping_table_value_t value)
{
    m_ifg0_ssp_mapping_table_value = value;
    m_ifg0_ssp_mapping_table_value_valid = true;

    for (auto& sp_data : m_system_ports_data) {
        const auto& system_port_akpg = sp_data->system_port.weak_ptr_static_cast<la_system_port_akpg>();
        la_system_port_akpg::port_type_e sys_port_type = system_port_akpg->get_port_type();
        if (sys_port_type == la_system_port_akpg::port_type_e::REMOTE) {
            continue;
        }
        la_status status = system_port_akpg->set_source_pif_table(value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_akpg::clear_source_pif()
{
    for (auto& sp_data : m_system_ports_data) {
        const auto& system_port_akpg = sp_data->system_port.weak_ptr_static_cast<la_system_port_akpg>();
        la_system_port_akpg::port_type_e sys_port_type = system_port_akpg->get_port_type();
        if (sys_port_type == la_system_port_akpg::port_type_e::REMOTE) {
            continue;
        }
        la_status status = system_port_akpg->erase_source_pif_table_entries();
        return_on_error(status);
    }
    m_ifg0_ssp_mapping_table_value_valid = false;
    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_akpg::get_lb_resolution(const la_lb_pak_fields_vec& lb_vector, size_t& member, const la_object*& out_object) const
{
    npl_lb_consistency_mode_e lb_consistency_mode;
    la_uint32_t group_size;

    la_status status;
    if (m_gid < UCMP_GROUP_SIZE) {
        status = m_device->m_resolution_configurators[3].get_ucmp_group_size(m_gid, group_size, lb_consistency_mode);
    } else {
        status = m_device->m_resolution_configurators[3].get_group_size(m_gid - UCMP_GROUP_SIZE, group_size, lb_consistency_mode);
    }
    return_on_error(status);

    size_t member_id = 0;
    uint16_t seed;
    uint16_t shift_amount;
    m_device->get_spa_hash_seed(seed);
    m_device->get_lb_hash_shift_amount(shift_amount);

    status
        = do_lb_resolution(lb_vector, group_size, lb_consistency_mode, RESOLUTION_STEP_STAGE3_DSPA, seed, shift_amount, member_id);
    return_on_error(status);

    member = member_id;
    la_system_port_wcptr out_system_port;
    status = get_dspa_table_member(member_id, out_system_port);
    out_object = out_system_port.get();

    return status;
}

la_status
la_spa_port_akpg::add(const la_system_port* system_port)
{
    start_api_call("system_port=", system_port);

    transaction txn;

    if (system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (system_port->get_device() != m_device) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_system_port_akpg_wptr system_port_wptr = m_device->get_sptr<la_system_port_akpg>(const_cast<la_system_port*>(system_port));

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

    la_system_port_akpg::port_type_e sys_port_type = system_port_wptr->get_port_type();

    txn.status = add_ifg_user(system_port_wptr);
    return_on_error(txn.status);
    txn.on_fail([=]() { remove_ifg_user(system_port_wptr); });

    // A remote system port doesn't have any local IFG info, and shouldn't be configured in the RX tables (source_pif_table)
    if (sys_port_type != la_system_port_akpg::port_type_e::REMOTE) {

        if (m_ifg0_ssp_mapping_table_value_valid) {
            txn.status = system_port_wptr->set_source_pif_table(m_ifg0_ssp_mapping_table_value);
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

    la_amd_undo_callback_funct_t undo = [this](attribute_management_details amd) { return amd; };
    txn.status = m_device->notify_attribute_changed(this, amd, undo);
    txn.on_fail([&]() {
        amd.spa.is_added = false;
        m_device->notify_attribute_changed(this, amd, undo);
    });
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_akpg::remove(const la_system_port* system_port)
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

    const auto& system_port_akpg = sp_data_to_remove->system_port.weak_ptr_static_cast<la_system_port_akpg>();
    la_system_port_akpg::port_type_e sys_port_type = system_port_akpg->get_port_type();
    if (sys_port_type != la_system_port_akpg::port_type_e::REMOTE) {
        // If the source_pif_table stored data is not yet valid
        // (hasn't been initialized by an upper object, i.e., ethernet_port)
        // then don't update the system_port
        if (m_ifg0_ssp_mapping_table_value_valid) {
            txn.status = system_port_akpg->erase_source_pif_table_entries();
            return_on_error(txn.status);
            txn.on_fail([&]() { system_port_akpg->set_source_pif_table(m_ifg0_ssp_mapping_table_value); });
        }
    }

    txn.status = remove_ifg_user(system_port_akpg);
    return_on_error(txn.status);
    txn.on_fail([=]() { add_ifg_user(system_port_akpg); });

    m_device->remove_object_dependency(system_port_akpg, this);
    txn.on_fail([&]() { m_device->add_object_dependency(system_port_akpg, this); });

    attribute_management_details amd;
    amd.op = attribute_management_op::SPA_MEMBERSHIP_CHANGED;
    amd.spa.is_added = false;
    amd.spa.sys_port = system_port_akpg.get();
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
la_spa_port_akpg::configure_system_port_source_pif_table(const la_system_port* system_port, bool enabled)
{
    la_system_port_akpg_wptr system_port_wptr = m_device->get_sptr<la_system_port_akpg>(const_cast<la_system_port*>(system_port));

    if (m_ifg0_ssp_mapping_table_value_valid) {
        npl_ifg0_ssp_mapping_table_value_t ifg0_ssp_mapping_table_value;
        ifg0_ssp_mapping_table_value = m_ifg0_ssp_mapping_table_value;
        // np_macro_id is the in-engine, 6-bit ID and not the full 8-bit ID; truncate the MSB-s
        if (!enabled) {
            ifg0_ssp_mapping_table_value.payloads.init_rx_data.np_macro_id = (NPL_NETWORK_TERMINATION_ERROR_MACRO & 0x3F);
        }
        la_status status = system_port_wptr->set_source_pif_table(ifg0_ssp_mapping_table_value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
