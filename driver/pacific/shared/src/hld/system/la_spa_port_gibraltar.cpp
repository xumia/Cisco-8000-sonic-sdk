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
#include "la_spa_port_gibraltar.h"
#include "la_strings.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_base.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_pci_port_base.h"
#include "system/la_recycle_port_base.h"
#include "system/la_remote_port_impl.h"
#include "system/la_system_port_gibraltar.h"

#include <sstream>

using namespace std;
namespace silicon_one
{

la_spa_port_gibraltar::la_spa_port_gibraltar(const la_device_impl_wptr& device) : la_spa_port_pacgb(device)
{
}

la_spa_port_gibraltar::~la_spa_port_gibraltar()
{
}

la_status
la_spa_port_gibraltar::destroy()
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
la_spa_port_gibraltar::add_system_port_to_dspa_table(std::shared_ptr<system_port_base_data>& sp_data_to_update,
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
la_spa_port_gibraltar::clear_table_tail(size_t start_index, transaction& txn)
{
    for (size_t idx = m_index_to_system_port.size(); idx > start_index; --idx) {
        const auto& sp_to_delete = m_index_to_system_port.back();
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
la_spa_port_gibraltar::init_port_dspa_group_size_table_entry()
{
    la_status status
        = m_device->m_resolution_configurators[3].set_group_size(m_gid, 0, NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED);
    return status;
}

la_status
la_spa_port_gibraltar::erase_port_dspa_group_size_table_entry()
{
    la_status status = m_device->m_resolution_configurators[3].erase_group_size(m_gid);
    return status;
}

la_status
la_spa_port_gibraltar::set_port_dspa_group_size_table_entry(size_t lbg_group_size)
{
    la_status status = m_device->m_resolution_configurators[3].set_group_size(
        m_gid, lbg_group_size, NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED);
    return status;
}

destination_id
la_spa_port_gibraltar::get_destination_id(resolution_step_e prev_step) const
{
    return destination_id(NPL_DESTINATION_MASK_DSPA | get_gid());
}

la_status
la_spa_port_gibraltar::set_port_dspa_table_entry(const la_system_port_wcptr& system_port, size_t lbg_member_id)
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
la_spa_port_gibraltar::pop_port_dspa_table_entry()
{
    la_status status = m_device->m_resolution_configurators[3].unconfigure_entry(m_resolution_cfg_handles.back());
    m_resolution_cfg_handles.pop_back();
    return status;
}

la_status
la_spa_port_gibraltar::set_lb_mode(la_lb_mode_e lb_mode)
{
    start_api_call("lb_mode=", lb_mode);
    la_uint32_t group_size;
    npl_lb_consistency_mode_e lb_consistency_mode;
    la_status status = m_device->m_resolution_configurators[3].get_group_size(m_gid, group_size, lb_consistency_mode);
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

    status = m_device->m_resolution_configurators[3].set_group_size(m_gid, group_size, lb_consistency_mode);
    return status;
}

la_status
la_spa_port_gibraltar::get_lb_mode(la_lb_mode_e& out_lb_mode) const
{
    la_uint32_t group_size;
    npl_lb_consistency_mode_e lb_consistency_mode;
    la_status status = m_device->m_resolution_configurators[3].get_group_size(m_gid, group_size, lb_consistency_mode);
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
la_spa_port_gibraltar::get_lb_resolution(const la_lb_pak_fields_vec& lb_vector, size_t& member, const la_object*& out_object) const
{
    npl_lb_consistency_mode_e lb_consistency_mode;
    la_uint32_t group_size;

    la_status status = m_device->m_resolution_configurators[3].get_group_size(m_gid, group_size, lb_consistency_mode);
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
la_spa_port_gibraltar::update_npp_sgt_attributes(la_sgt_t security_group_tag)
{
    la_status status = LA_STATUS_SUCCESS;

    for (auto& sp_data : m_system_ports_data) {
        const auto& system_port = sp_data->system_port;

        la_system_port_base::port_type_e sys_port_type = system_port->get_port_type();
        if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
            auto system_port_gibraltar = system_port.weak_ptr_static_cast<la_system_port_gibraltar>();
            status = system_port_gibraltar->update_npp_sgt_attributes(security_group_tag);
            return_on_error(status);
        }
    }

    return status;
}

la_status
la_spa_port_gibraltar::update_dsp_sgt_attributes(bool security_group_policy_enforcement)
{
    la_status status = LA_STATUS_SUCCESS;

    for (auto& sp_data : m_system_ports_data) {
        const auto& system_port = sp_data->system_port;

        la_system_port_base::port_type_e sys_port_type = system_port->get_port_type();
        if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
            auto system_port_gibraltar = system_port.weak_ptr_static_cast<la_system_port_gibraltar>();
            status = system_port_gibraltar->update_dsp_sgt_attributes(security_group_policy_enforcement);
            return_on_error(status);
        }
    }

    return status;
}

} // namespace silicon_one
