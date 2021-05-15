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
#include "la_spa_port_pacific.h"
#include "la_strings.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_base.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_pci_port_base.h"
#include "system/la_recycle_port_base.h"
#include "system/la_remote_port_impl.h"
#include "system/la_system_port_pacific.h"

#include <sstream>

using namespace std;
namespace silicon_one
{

la_spa_port_pacific::la_spa_port_pacific(const la_device_impl_wptr& device) : la_spa_port_pacgb(device)
{
}

la_spa_port_pacific::~la_spa_port_pacific()
{
}

la_status
la_spa_port_pacific::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    la_status status;
    status = erase_port_dspa_group_size_table_entry();
    return_on_error(status);

    for (size_t i = m_index_to_system_port.size(); i > 0; --i) {
        status = erase_port_dspa_table_entry(i - 1);
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
la_spa_port_pacific::add_system_port_to_dspa_table(std::shared_ptr<system_port_base_data>& sp_data_to_update,
                                                   size_t num_of_entries_to_add,
                                                   transaction& txn)
{
    size_t dspa_table_size = m_index_to_system_port.size();
    const auto& sp = sp_data_to_update->system_port;

    for (size_t i = 0; i < num_of_entries_to_add; i++) {
        // Configure the new system port entry in resolution tables
        la_status status = set_port_dspa_table_entry(sp, dspa_table_size + i);
        txn.on_fail([=] { erase_port_dspa_table_entry(dspa_table_size + i); });
        return_on_error(status);

        m_index_to_system_port.push_back(sp);
        txn.on_fail([&] { m_index_to_system_port.pop_back(); });
    }

    sp_data_to_update->num_of_dspa_table_entries += num_of_entries_to_add;
    txn.on_fail([=] { sp_data_to_update->num_of_dspa_table_entries -= num_of_entries_to_add; });

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_pacific::clear_table_tail(size_t start_index, transaction& txn)
{
    for (size_t idx = m_index_to_system_port.size(); idx > start_index; --idx) {
        const auto& sp_to_delete = m_index_to_system_port.back();
        m_index_to_system_port.pop_back();
        txn.on_fail([=]() { m_index_to_system_port.push_back(sp_to_delete); });

        // Erase the last member entry
        la_status status = erase_port_dspa_table_entry(idx - 1);
        txn.on_fail([=]() { set_port_dspa_table_entry(sp_to_delete, idx - 1); });
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_pacific::init_port_dspa_group_size_table_entry()
{
    // Configure port_dspa_group_size_table
    npl_port_dspa_group_size_table_t::key_type k;
    npl_port_dspa_group_size_table_t::value_type v;

    // Set key
    k.dspa = m_gid;

    // Set value
    v.action = NPL_PORT_DSPA_GROUP_SIZE_TABLE_ACTION_WRITE;
    v.payloads.dspa_group_size_table_result.curr_group_size = 0;
    v.payloads.dspa_group_size_table_result.consistency_mode = NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED;

    // Write to table
    npl_port_dspa_group_size_table_t::entry_wptr_type new_entry_ptr;
    la_status status = m_device->m_tables.port_dspa_group_size_table->insert(k, v, new_entry_ptr);

    return_on_error(status);

    m_size_table_entry = new_entry_ptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_pacific::erase_port_dspa_group_size_table_entry()
{
    npl_port_dspa_group_size_table_t::key_type k;
    k.dspa = m_gid;

    la_status status = m_device->m_tables.port_dspa_group_size_table->erase(k);

    return status;
}

la_status
la_spa_port_pacific::set_port_dspa_group_size_table_entry(size_t lbg_group_size)
{
    npl_port_dspa_group_size_table_t::value_type v = m_size_table_entry->value();
    v.payloads.dspa_group_size_table_result.curr_group_size = lbg_group_size;

    la_status status = m_size_table_entry->update(v);

    return status;
}

la_status
la_spa_port_pacific::set_port_dspa_table_entry(const la_system_port_wcptr& system_port, size_t lbg_member_id)
{
    // Configure port_dspa_table
    npl_port_dspa_table_t::key_type k;
    npl_port_dspa_table_t::value_type v;

    // Set key
    k.group_id = m_gid;
    k.member_id = lbg_member_id;

    // Set value
    v.action = NPL_PORT_DSPA_TABLE_ACTION_WRITE;
    v.payloads.port_dspa_result.dsp.dsp = system_port->get_gid();
    v.payloads.port_dspa_result.dsp.type = NPL_PORT_DSPA_ENTRY_TYPE_PORT_DSPA_DSP;

    // Write to table
    npl_port_dspa_table_t::entry_pointer_type existing_entry_ptr = nullptr;
    la_status status = m_device->m_tables.port_dspa_table->set(k, v, existing_entry_ptr);

    return status;
}

la_status
la_spa_port_pacific::erase_port_dspa_table_entry(size_t lbg_member_id)
{
    // Configure port_dspa_table
    npl_port_dspa_table_t::key_type k;

    // Set key
    k.group_id = m_gid;
    k.member_id = lbg_member_id;

    la_status status = m_device->m_tables.port_dspa_table->erase(k);

    return status;
}

la_status
la_spa_port_pacific::set_lb_mode(la_lb_mode_e lb_mode)
{
    start_api_call("lb_mode=", lb_mode);
    npl_port_dspa_group_size_table_t::value_type v = m_size_table_entry->value();

    switch (lb_mode) {
    case la_lb_mode_e::CONSISTENT:
        v.payloads.dspa_group_size_table_result.consistency_mode = NPL_LB_CONSISTENCY_MODE_CONSISTENCE_ENABLED;
        break;

    case la_lb_mode_e::DYNAMIC:
        v.payloads.dspa_group_size_table_result.consistency_mode = NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED;
        break;

    default:
        return LA_STATUS_EUNKNOWN;
    }

    la_status status = m_size_table_entry->update(v);

    return status;
}

la_status
la_spa_port_pacific::get_lb_mode(la_lb_mode_e& out_lb_mode) const
{
    npl_port_dspa_group_size_table_t::value_type v = m_size_table_entry->value();

    switch (v.payloads.dspa_group_size_table_result.consistency_mode) {
    case NPL_LB_CONSISTENCY_MODE_CONSISTENCE_ENABLED:
        out_lb_mode = la_lb_mode_e::CONSISTENT;
        break;

    case NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED:
        v.payloads.dspa_group_size_table_result.consistency_mode = NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED;
        out_lb_mode = la_lb_mode_e::DYNAMIC;
        break;

    default:
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_pacific::get_lb_resolution(const la_lb_pak_fields_vec& lb_vector, size_t& member, const la_object*& out_object) const
{
    la_status status = LA_STATUS_SUCCESS;

    npl_port_dspa_group_size_table_t::value_type v = m_size_table_entry->value();

    size_t group_size = v.payloads.dspa_group_size_table_result.curr_group_size;
    npl_lb_consistency_mode_e consistency_mode = v.payloads.dspa_group_size_table_result.consistency_mode;

    size_t member_id = 0;
    uint16_t seed;
    uint16_t shift_amount;
    m_device->get_spa_hash_seed(seed);
    m_device->get_lb_hash_shift_amount(shift_amount);
    status = do_lb_resolution(lb_vector, group_size, consistency_mode, RESOLUTION_STEP_PORT_DSPA, seed, shift_amount, member_id);
    return_on_error(status);

    member = member_id;
    la_system_port_wcptr out_system_port;
    status = get_dspa_table_member(member_id, out_system_port);
    out_object = out_system_port.get();

    return status;
}
} // namespace silicon_one
