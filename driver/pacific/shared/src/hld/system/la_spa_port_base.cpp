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
#include "system/la_spa_port_base.h"
#include "system/la_system_port_base.h"

#include <sstream>

using namespace std;
namespace silicon_one
{

la_spa_port_base::la_spa_port_base(const la_device_impl_wptr& device)
    : m_mac_af_npp_attributes_table_value_valid(false),
      m_device(device),
      m_gid(LA_SPA_PORT_GID_INVALID),
      m_mtu(LA_MTU_MAX),
      m_mask_eve(false),
      m_stack_prune(false)
{
}

la_spa_port_base::~la_spa_port_base()
{
}

la_status
la_spa_port_base::initialize(la_object_id_t oid, la_spa_port_gid_t spa_port_gid)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_oid = oid;
    m_gid = spa_port_gid;

    la_status status = init_port_dspa_group_size_table_entry();
    if (status != LA_STATUS_SUCCESS) {
        m_gid = LA_SPA_PORT_GID_INVALID;
        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_base::get_member_receive_enabled(const la_system_port* system_port, bool& out_enabled) const
{
    start_api_getter_call();
    if (system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(system_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!is_member(m_device->get_sptr(system_port))) {
        return LA_STATUS_ENOTFOUND;
    }

    out_enabled = is_receive_enabled(m_device->get_sptr(system_port));

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_base::set_member_receive_enabled(const la_system_port* system_port, bool enabled)
{
    start_api_call("system_port=", system_port, "enabled=", enabled);

    transaction txn;

    if (system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(system_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!is_member(m_device->get_sptr(system_port))) {
        return LA_STATUS_ENOTFOUND;
    }

    la_system_port_wcptr system_port_wptr = m_device->get_sptr(system_port);

    for (auto& sp_data : m_system_ports_data) {
        const auto& spds
            = sp_data->system_port
                  .weak_ptr_static_cast<const la_system_port>(); // compiler will not call the '!=' operator below without this cast
        if (spds != system_port_wptr) {
            continue;
        }

        const auto& system_port_base = sp_data->system_port;
        la_system_port_base::port_type_e sys_port_type = system_port_base->get_port_type();
        if (sys_port_type == la_system_port_base::port_type_e::REMOTE) {
            return LA_STATUS_EINVAL;
        }

        if (sp_data->is_receive_enabled == enabled) {
            continue;
        }

        sp_data->is_receive_enabled = enabled;
        txn.on_fail([&]() { sp_data->is_receive_enabled = !enabled; });

        la_status status = configure_system_port_source_pif_table(system_port, enabled);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_base::get_member_transmit_enabled(const la_system_port* system_port, bool& out_enabled) const
{
    start_api_getter_call();
    if (system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(system_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    out_enabled = is_transmit_enabled(m_device->get_sptr(system_port));

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_base::set_member_transmit_enabled(const la_system_port* system_port, bool enabled)
{
    start_api_call("system_port=", system_port, "enabled=", enabled);

    transaction txn;

    if (system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(system_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!is_member(m_device->get_sptr(system_port))) {
        return LA_STATUS_ENOTFOUND;
    }
    la_system_port_wcptr system_port_wptr = m_device->get_sptr(system_port);
    for (auto& sp_data : m_system_ports_data) {
        const auto& spds
            = sp_data->system_port
                  .weak_ptr_static_cast<const la_system_port>(); // compiler will not call the '!=' operator below without this cast
        if (spds != system_port_wptr) {
            continue;
        }

        if (sp_data->is_active == enabled) {
            continue;
        }

        sp_data->is_active = enabled;
        txn.on_fail([&]() { sp_data->is_active = !enabled; });

        if (enabled == true) {
            txn.status = add_transmit_enabled_member_to_dspa_table(sp_data);
            return_on_error(txn.status);
        } else {
            txn.status = remove_transmit_enabled_member_from_dspa_table(sp_data);
            return_on_error(txn.status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_base::add_transmit_enabled_member_to_dspa_table(std::shared_ptr<system_port_base_data>& sp_data_to_update)
{
    // Update dspa table to maintain each sp's relative portion of entries, for example:
    // spa with 2 system ports is added with a third one.
    // Before: sp0 = 100G, sp1 = 50 -> qu (quantization unit) = 50 -> 2 sp0 entries, 1 sp1 entry
    // After: sp2 = 10G is added -> qu = 10 -> 10 sp0 entries, 5 sp1 entries, 1 sp2 entry

    transaction txn;

    if (sp_data_to_update == nullptr) {
        return LA_STATUS_EUNKNOWN;
    }

    if (!sp_data_to_update->is_active) {
        return LA_STATUS_EINVAL;
    }

    uint32_t port_speed = la_2_port_speed(sp_data_to_update->underlying_port_speed);

    // calculate new quantization unit:
    uint32_t extension_ratio = 1;
    if (m_index_to_system_port.size() == 0) {
        m_qu = port_speed;
    } else {
        uint32_t old_qu = m_qu;
        m_qu = gcd(m_qu, port_speed);
        txn.on_fail([=]() { m_qu = old_qu; });

        // since m_qu is a factor of (or equivalent to) old_qu, the result is a whole number:
        extension_ratio = old_qu / m_qu;
    }

    size_t recovery_table_size = m_index_to_system_port.size();

    // Extend existing system ports entries & add the new ones:
    for (auto& sp_data : m_system_ports_data) {
        if (!sp_data->is_active) {
            continue;
        }

        size_t num_of_entries_to_add;
        if (sp_data == sp_data_to_update) {
            // Add new system_port's entries:
            num_of_entries_to_add = port_speed / m_qu;
        } else {
            // Extend existing one:
            num_of_entries_to_add = (extension_ratio - 1) * sp_data->num_of_dspa_table_entries;
        }

        txn.status = add_system_port_to_dspa_table(sp_data, num_of_entries_to_add, txn);
        return_on_error(txn.status);
    }

    // Update the SPA group size in Resolution table
    txn.status = set_port_dspa_group_size_table_entry(m_index_to_system_port.size());
    txn.on_fail([&]() { set_port_dspa_group_size_table_entry(recovery_table_size); });
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_spa_port_base::system_port_base_data_vec_t::iterator
la_spa_port_base::get_system_port_data_it(const la_system_port_wcptr& system_port)
{
    la_spa_port_base::system_port_base_data_vec_t::iterator it;
    for (it = m_system_ports_data.begin(); it != m_system_ports_data.end(); it++) {
        const auto& sp_d = *it;
        const auto& spds
            = sp_d->system_port
                  .weak_ptr_static_cast<const la_system_port>(); // compiler will not call the '==' operator without this cast
        if (spds == system_port) {
            break;
        }
    }

    return it;
}

la_spa_port_base::system_port_base_data_vec_t::const_iterator
la_spa_port_base::get_system_port_data_it(const la_system_port_wcptr& system_port) const
{
    la_spa_port_base::system_port_base_data_vec_t::const_iterator it;
    for (it = m_system_ports_data.begin(); it != m_system_ports_data.end(); it++) {
        const auto& sp_d = *it;
        const auto& spds
            = sp_d->system_port
                  .weak_ptr_static_cast<const la_system_port>(); // compiler will not call the '==' operator without this cast
        if (spds == system_port) {
            break;
        }
    }

    return it;
}

la_status
la_spa_port_base::get_underlying_port_speed(const la_system_port_wcptr& system_port, la_mac_port::port_speed_e& out_port_speed)
{
    const la_object* underlying_port = system_port->get_underlying_port();
    dassert_crit(underlying_port != nullptr);
    object_type_e port_type = underlying_port->type();

    switch (port_type) {
    case object_type_e::MAC_PORT: {
        const la_mac_port_base* mac_port = dynamic_cast<const la_mac_port_base*>(underlying_port);
        dassert_crit(mac_port != nullptr);
        la_status status = mac_port->get_speed(out_port_speed);
        return_on_error(status);
        break;
    }
    case object_type_e::NPU_HOST_PORT: {
        const la_npu_host_port_base* npu_host_port = dynamic_cast<const la_npu_host_port_base*>(underlying_port);
        dassert_crit(npu_host_port != nullptr);
        la_status status = npu_host_port->get_speed(out_port_speed);
        return_on_error(status);
        break;
    }
    case object_type_e::PCI_PORT: {
        const la_pci_port_base* pci_port = dynamic_cast<const la_pci_port_base*>(underlying_port);
        dassert_crit(pci_port != nullptr);
        la_status status = pci_port->get_speed(out_port_speed);
        return_on_error(status);
        break;
    }
    case object_type_e::RECYCLE_PORT: {
        const la_recycle_port_base* recycle_port = dynamic_cast<const la_recycle_port_base*>(underlying_port);
        dassert_crit(recycle_port != nullptr);
        la_status status = recycle_port->get_speed(out_port_speed);
        return_on_error(status);
        break;
    }
    case object_type_e::REMOTE_PORT: {
        const la_remote_port_impl* remote_port = dynamic_cast<const la_remote_port_impl*>(underlying_port);
        dassert_crit(remote_port != nullptr);
        la_status status = remote_port->get_speed(out_port_speed);
        return_on_error(status);
        break;
    }
    default:
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_base::remove_transmit_enabled_member_from_dspa_table(std::shared_ptr<system_port_base_data>& sp_data_to_update)
{
    // Dilute entries (for example: qu=50 [400|8,  100|2, 50|1]  ->  qu=100 [400|4, 100|1]) by swapping needed amount of entries to
    // the beginning of the table -> commit size.

    transaction txn;

    if (sp_data_to_update == nullptr) {
        return LA_STATUS_EUNKNOWN;
    }

    if (sp_data_to_update->is_active) {
        return LA_STATUS_EBUSY;
    }

    uint32_t old_qu = m_qu;
    recalculate_qu();
    txn.on_fail([&]() { m_qu = old_qu; });

    // since old_qu is a factor of (or equivalent to) m_qu, the result is a whole number:
    uint32_t dilution_ratio = m_qu / old_qu;

    // Dilute by swapping needed amount of system ports to the beginning of the table and updating the table size:
    size_t start_index_to_swap = 0;
    for (auto& sp_data : m_system_ports_data) {
        if (!sp_data->is_active) {
            continue;
        }

        size_t num_of_entries_to_swap = sp_data->num_of_dspa_table_entries / dilution_ratio;
        txn.status
            = swap_to_index(sp_data->system_port, num_of_entries_to_swap, start_index_to_swap, txn, true /* swap_from_end */);
        return_on_error(txn.status);

        sp_data->num_of_dspa_table_entries = num_of_entries_to_swap;
        txn.on_fail([=] { sp_data->num_of_dspa_table_entries *= dilution_ratio; });

        start_index_to_swap += num_of_entries_to_swap;
    }

    size_t new_table_size = start_index_to_swap;
    size_t old_table_size = m_index_to_system_port.size();

    // Set the SPA group size
    txn.status = set_port_dspa_group_size_table_entry(new_table_size);
    txn.on_fail([=]() { set_port_dspa_group_size_table_entry(old_table_size); });
    return_on_error(txn.status);

    // Delete the remaining 'tail'
    txn.status = clear_table_tail(new_table_size, txn);
    return_on_error(txn.status);

    // Nullify sp_data_to_update->num_of_dspa_table_entries:
    size_t old_num_of_sp_to_update_entries = sp_data_to_update->num_of_dspa_table_entries;
    sp_data_to_update->num_of_dspa_table_entries = 0;
    txn.on_fail([=] { sp_data_to_update->num_of_dspa_table_entries = old_num_of_sp_to_update_entries; });

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_base::swap_to_index(const la_system_port_base_wptr& system_port_to_swap,
                                size_t num_of_entries,
                                size_t start_index,
                                transaction& txn,
                                bool swap_from_end)
{
    size_t index_to_swap_to = start_index;
    size_t index_to_swap_from = swap_from_end ? (m_index_to_system_port.size() - 1) : 0;

    for (size_t i = 0; i < num_of_entries; ++i) {
        const auto sp_to_swap_with = m_index_to_system_port[index_to_swap_to];
        if (sp_to_swap_with == system_port_to_swap) {
            ++index_to_swap_to;
            continue;
        }

        if (swap_from_end) {
            while (index_to_swap_from != index_to_swap_to) {
                if (m_index_to_system_port[index_to_swap_from] == system_port_to_swap) {
                    break;
                }
                --index_to_swap_from;
            }

            if (index_to_swap_from == index_to_swap_to) {
                return LA_STATUS_ENOTFOUND;
            }
        } else {
            while (index_to_swap_from != start_index) {
                if (m_index_to_system_port[index_to_swap_from] == system_port_to_swap) {
                    break;
                }
                ++index_to_swap_from;
            }

            if (index_to_swap_from == start_index) {
                return LA_STATUS_ENOTFOUND;
            }
        }

        // Perform the swap (both in 'm_index_to_system_port' and 'dspa_table'):
        m_index_to_system_port[index_to_swap_from] = sp_to_swap_with;
        txn.on_fail([=]() { m_index_to_system_port[index_to_swap_from] = system_port_to_swap; });

        m_index_to_system_port[index_to_swap_to] = system_port_to_swap;
        txn.on_fail([=]() { m_index_to_system_port[index_to_swap_to] = sp_to_swap_with; });

        la_status status = set_port_dspa_table_entry(sp_to_swap_with, index_to_swap_from);
        txn.on_fail([=]() { set_port_dspa_table_entry(system_port_to_swap, index_to_swap_from); });
        return_on_error(status);

        status = set_port_dspa_table_entry(system_port_to_swap, index_to_swap_to);
        txn.on_fail([=]() { set_port_dspa_table_entry(sp_to_swap_with, index_to_swap_to); });
        return_on_error(status);

        // Update indices for next iteration:
        swap_from_end ? --index_to_swap_from : ++index_to_swap_from;
        ++index_to_swap_to;
    }

    return LA_STATUS_SUCCESS;
}

void
la_spa_port_base::recalculate_qu()
{
    bool is_qu_first_val = true;
    for (auto& sp_data : m_system_ports_data) {
        if (sp_data->is_active) {
            if (is_qu_first_val) {
                is_qu_first_val = false;
                m_qu = la_2_port_speed(sp_data->underlying_port_speed);
            } else {
                m_qu = gcd(m_qu, la_2_port_speed(sp_data->underlying_port_speed));
            }
        }
    }
}

la_status
la_spa_port_base::update_system_port_speed(std::shared_ptr<system_port_base_data>& sp_data_to_update,
                                           la_mac_port::port_speed_e new_port_speed)
{
    // The following update algorithm takes into account the need of keeping optimum ratio between affecting system ports entries
    // (affecting dspa_table entries are those with index lower than dspa_table_size), even for a short time during the update
    // process
    // to avoid potential system port overload.
    //
    // When an existing system port speed is updated it may impact independently on two groups:
    // 1. The updated system port entries 	   - will be denoted as {U}
    // 2. The rest of the system ports entries - will be denoted as {R}
    // Given each of the groups can be extended/diluted independently we end up with 4 possible pairs of <{R}, {U}> trends, each has
    // its own handling:
    //
    // <EXTENSION, EXTENSION> - Example: qu=50  [400|8,  100|2, 50|1]  ->  qu=20  [400|20, 100|5, 40|2]:
    // Add both new {U} and {R} entries -> size commit.
    //
    // <DILUTION,  DILUTION>  - Example: qu=20  [400|20, 100|5, 40|2]  ->  qu=50  [400|8,  100|2, 50|1]:
    // Both {R} and {U} diluted entries will be swapped to the beginning of the table -> size commit.
    //
    // <DILUTION,  EXTENSION> - Example: qu=50  [400|8,  100|2, 50|1]  ->  qu=100 [400|4,  100|1, 200|2]:
    // {R} diluted entries and {U} existing entries will be swapped to the beginning of the table -> size commit -> {U} new entries
    // are added -> size commit.
    //
    // <EXTENSION, DILUTION>  - Example: qu=100 [400|4,  100|1, 200|2] ->  qu=50  [400|8,  100|2, 50|1]]:
    // {U} diluted entries will be swapped to the end of the table -> size commit -> {R} new entries are added -> size commit.

    transaction txn;

    if (sp_data_to_update == nullptr) {
        return LA_STATUS_EUNKNOWN;
    }

    if (sp_data_to_update->underlying_port_speed == new_port_speed) {
        // Nothing to be done
        return LA_STATUS_SUCCESS;
    }

    // update new port speed in sp_data_to_update:
    la_mac_port::port_speed_e old_speed = sp_data_to_update->underlying_port_speed;
    sp_data_to_update->underlying_port_speed = new_port_speed;
    txn.on_fail([&]() { sp_data_to_update->underlying_port_speed = old_speed; });

    if (!sp_data_to_update->is_active) {
        return LA_STATUS_SUCCESS;
    }

    uint32_t old_qu = m_qu;
    recalculate_qu();
    txn.on_fail([&]() { m_qu = old_qu; });

    uint32_t new_speed = la_2_port_speed(new_port_speed);
    size_t updated_sp_new_num_of_entries = new_speed / m_qu;
    bool is_updated_sp_extended = (updated_sp_new_num_of_entries > sp_data_to_update->num_of_dspa_table_entries);
    bool is_rest_of_sps_extended = (m_qu < old_qu);

    if (is_rest_of_sps_extended) {
        size_t recovery_dspa_table_size = m_index_to_system_port.size();
        if (is_updated_sp_extended) {
            // <{R}, {U}> = <EXTENSION, EXTENSION>
            // Extend {U}:
            size_t num_of_entries_to_add = updated_sp_new_num_of_entries - sp_data_to_update->num_of_dspa_table_entries;
            txn.status = add_system_port_to_dspa_table(sp_data_to_update, num_of_entries_to_add, txn);
            return_on_error(txn.status);
        } else {
            // <{R}, {U}> = <EXTENSION, DILUTION>
            // Dilute {U}:
            // Dilute by swapping needed amount of system ports to the END of the table and updating the table size:
            size_t num_of_entries_to_delete = sp_data_to_update->num_of_dspa_table_entries - updated_sp_new_num_of_entries;
            size_t start_index_to_swap = m_index_to_system_port.size() - num_of_entries_to_delete;
            txn.status = swap_to_index(
                sp_data_to_update->system_port, num_of_entries_to_delete, start_index_to_swap, txn, false /* swap_from_end */);
            return_on_error(txn.status);

            // Update sp_data_to_update->num_of_dspa_table_entries:
            sp_data_to_update->num_of_dspa_table_entries = updated_sp_new_num_of_entries;
            txn.on_fail([=] { sp_data_to_update->num_of_dspa_table_entries += num_of_entries_to_delete; });

            // 1st SPA group size update in Resolution table:
            txn.status = set_port_dspa_group_size_table_entry(start_index_to_swap);
            txn.on_fail([=]() { set_port_dspa_group_size_table_entry(recovery_dspa_table_size); });
            return_on_error(txn.status);

            // Update 'recovery_dspa_table_size' for the next size commit:
            recovery_dspa_table_size = start_index_to_swap;

            // Delete the remaining 'tail'
            txn.status = clear_table_tail(start_index_to_swap, txn);
            return_on_error(txn.status);
        }

        // Extend {R}:
        // since m_qu is a factor of (or equivalent to) old_qu, the result is a whole number:
        size_t extension_ratio = old_qu / m_qu;
        for (auto& sp_data : m_system_ports_data) {
            if (!sp_data->is_active || (sp_data == sp_data_to_update)) {
                continue;
            }

            size_t num_of_entries_to_add = (extension_ratio - 1) * sp_data->num_of_dspa_table_entries;
            txn.status = add_system_port_to_dspa_table(sp_data, num_of_entries_to_add, txn);
            return_on_error(txn.status);
        }

        // Update the SPA group size in Resolution table
        txn.status = set_port_dspa_group_size_table_entry(m_index_to_system_port.size());
        txn.on_fail([=]() { set_port_dspa_group_size_table_entry(recovery_dspa_table_size); });
        return_on_error(txn.status);

    } else {
        // Dilute {R}:
        // since old_qu is a factor of (or equivalent to) m_qu, the result is a whole number:
        uint32_t dilution_ratio = m_qu / old_qu;

        // Dilute by swapping needed amount of system ports to the beginning of the table and updating the table size:
        size_t start_index_to_swap = 0;
        for (auto& sp_data : m_system_ports_data) {
            if (!sp_data->is_active || (sp_data == sp_data_to_update)) {
                continue;
            }

            size_t num_of_entries_to_swap = sp_data->num_of_dspa_table_entries / dilution_ratio;
            txn.status
                = swap_to_index(sp_data->system_port, num_of_entries_to_swap, start_index_to_swap, txn, true /* swap_from_end */);
            return_on_error(txn.status);

            // Update sp_data->num_of_dspa_table_entries:
            sp_data->num_of_dspa_table_entries = num_of_entries_to_swap;
            txn.on_fail([=] { sp_data->num_of_dspa_table_entries *= dilution_ratio; });

            start_index_to_swap += num_of_entries_to_swap;
        }

        if (is_updated_sp_extended) {
            // <{R}, {U}> = <DILUTION, EXTENSION>
            // First, swap existing {U}:
            txn.status = swap_to_index(sp_data_to_update->system_port,
                                       sp_data_to_update->num_of_dspa_table_entries,
                                       start_index_to_swap,
                                       txn,
                                       true /* swap_from_end */);
            return_on_error(txn.status);

            // 1st SPA group size update in Resolution table:
            size_t intermediate_table_size = start_index_to_swap + sp_data_to_update->num_of_dspa_table_entries;
            txn.status = set_port_dspa_group_size_table_entry(intermediate_table_size);
            txn.on_fail([=]() { set_port_dspa_group_size_table_entry(m_index_to_system_port.size()); });
            return_on_error(txn.status);

            // Delete the remaining 'tail'
            txn.status = clear_table_tail(intermediate_table_size, txn);
            return_on_error(txn.status);

            // Extend {U}:
            size_t num_of_entries_to_add = updated_sp_new_num_of_entries - sp_data_to_update->num_of_dspa_table_entries;
            txn.status = add_system_port_to_dspa_table(sp_data_to_update, num_of_entries_to_add, txn);
            return_on_error(txn.status);

            // Update the SPA group size in Resolution table
            size_t new_dspa_table_size = intermediate_table_size + num_of_entries_to_add;
            txn.status = set_port_dspa_group_size_table_entry(new_dspa_table_size);
            txn.on_fail([=]() { set_port_dspa_group_size_table_entry(intermediate_table_size); });
            return_on_error(txn.status);

        } else {
            // <{R}, {U}> = <DILUTION, DILUTION>
            // Dilute {U}:
            txn.status = swap_to_index(
                sp_data_to_update->system_port, updated_sp_new_num_of_entries, start_index_to_swap, txn, true /* swap_from_end */);
            return_on_error(txn.status);

            // Update sp_data_to_update->num_of_dspa_table_entries:
            size_t updated_sp_old_num_of_entries = sp_data_to_update->num_of_dspa_table_entries;
            sp_data_to_update->num_of_dspa_table_entries = updated_sp_new_num_of_entries;
            txn.on_fail([=] { sp_data_to_update->num_of_dspa_table_entries = updated_sp_old_num_of_entries; });

            // Update the SPA group size in Resolution table
            size_t new_dspa_table_size = start_index_to_swap + updated_sp_new_num_of_entries;
            txn.status = set_port_dspa_group_size_table_entry(new_dspa_table_size);
            txn.on_fail([=]() { set_port_dspa_group_size_table_entry(m_index_to_system_port.size()); });
            return_on_error(txn.status);

            // Delete the remaining 'tail'
            txn.status = clear_table_tail(new_dspa_table_size, txn);
            return_on_error(txn.status);
        }
    }

    return LA_STATUS_SUCCESS;
}

void
la_spa_port_base::register_attribute_dependency(const la_system_port_wcptr& system_port)
{
    const la_object* underlying_port = system_port->get_underlying_port();
    dassert_crit(underlying_port != nullptr);

    bit_vector registered_attributes((la_uint64_t)attribute_management_op::PORT_SPEED_CHANGED);
    m_device->add_attribute_dependency(underlying_port, this, registered_attributes);

    return;
}

void
la_spa_port_base::remove_attribute_dependency(const la_system_port_wcptr& system_port)
{
    const la_object* underlying_port = system_port->get_underlying_port();
    dassert_crit(underlying_port != nullptr);

    bit_vector registered_attributes((la_uint64_t)attribute_management_op::PORT_SPEED_CHANGED);
    m_device->remove_attribute_dependency(underlying_port, this, registered_attributes);

    return;
}

la_status
la_spa_port_base::notify_change(dependency_management_op op)
{
    switch (op.type_e) {
    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT: {
        la_status status = update_dependent_attributes(op);
        return_on_error(status);
        return LA_STATUS_SUCCESS;
    }
    default: {
        log_err(HLD, "%s: received unsupported notification (%s)", __PRETTY_FUNCTION__, silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
    }
}

la_status
la_spa_port_base::update_dependent_attributes(dependency_management_op op)
{
    switch (op.action.attribute_management.op) {
    case (attribute_management_op::PORT_SPEED_CHANGED): {
        la_status status = handle_speed_change(m_device->get_sptr(op.dependee), op.action.attribute_management.mac_port_speed);
        return status;
    }

    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
la_spa_port_base::handle_speed_change(const la_object_wcptr& changed_port, la_mac_port::port_speed_e new_port_speed)
{
    transaction txn;

    for (auto& sp_data : m_system_ports_data) {
        la_mac_port::port_speed_e old_port_speed = sp_data->underlying_port_speed;
        la_object* underlying_port = sp_data->system_port->get_underlying_port();
        if (underlying_port == changed_port) {
            txn.status = update_system_port_speed(sp_data, new_port_speed);
            txn.on_fail([&]() { update_system_port_speed(sp_data, old_port_speed); });
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_base::get_member(size_t member_idx, const la_system_port*& out_system_port) const
{
    if (member_idx >= m_system_ports_data.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_system_port = m_system_ports_data[member_idx]->system_port.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_base::get_members(system_port_vec_t& out_system_ports) const
{
    out_system_ports.clear();

    for (auto& sp_data : m_system_ports_data) {
        out_system_ports.push_back(sp_data->system_port.get());
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_base::get_dspa_table_member(size_t member_idx, la_system_port_wcptr& out_system_port) const
{
    if (member_idx >= m_index_to_system_port.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_system_port = m_index_to_system_port[member_idx];
    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_base::get_dspa_table_members(system_port_vec_t& out_system_ports) const
{
    out_system_ports.clear();
    for (auto it = m_index_to_system_port.begin(); it != m_index_to_system_port.end(); it++) {
        out_system_ports.push_back(it->get());
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_base::get_transmit_enabled_members(system_port_vec_t& out_system_ports) const
{
    start_api_getter_call();

    for (auto& sp_data : m_system_ports_data) {
        if (sp_data->is_active) {
            out_system_ports.push_back(sp_data->system_port.get());
        }
    }

    return LA_STATUS_SUCCESS;
}

slice_ifg_vec_t
la_spa_port_base::get_ifgs() const
{
    return m_ifg_use_count->get_ifgs();
}

la_status
la_spa_port_base::add_ifg_user(const la_system_port_base_wptr& system_port_base)
{
    transaction txn;
    la_system_port_base::port_type_e sys_port_type = system_port_base->get_port_type();
    if (sys_port_type == la_system_port_base::port_type_e::REMOTE) {
        // No need to add remote IFGs
        return LA_STATUS_SUCCESS;
    }

    la_slice_ifg ifg = {.slice = system_port_base->get_slice(), .ifg = system_port_base->get_ifg()};
    bool ifg_added, slice_added, slice_pair_added;
    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([&]() {
        bool dummy;
        m_ifg_use_count->remove_ifg_user(ifg, dummy, dummy, dummy);
    });

    // Propagate slice change upwards
    if (ifg_added) {
        txn.status = m_device->notify_ifg_added(this, ifg);
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_base::remove_ifg_user(const la_system_port_base_wptr& system_port_base)
{
    transaction txn;
    la_system_port_base::port_type_e sys_port_type = system_port_base->get_port_type();

    if (sys_port_type == la_system_port_base::port_type_e::REMOTE) {
        return LA_STATUS_SUCCESS;
    }

    la_slice_id_t slice = system_port_base->get_slice();
    la_ifg_id_t ifg = system_port_base->get_ifg();
    la_slice_ifg slice_ifg = {.slice = slice, .ifg = ifg};
    bool ifg_removed, slice_removed, slice_pair_removed;

    m_ifg_use_count->remove_ifg_user(slice_ifg, ifg_removed, slice_removed, slice_pair_removed);
    txn.on_fail([&]() {
        bool dummy;
        m_ifg_use_count->add_ifg_user(slice_ifg, dummy, dummy, dummy);
    });

    if (ifg_removed) {
        txn.status = m_device->notify_ifg_removed(this, slice_ifg);
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_spa_port_gid_t
la_spa_port_base::get_gid() const
{
    return m_gid;
}

la_object::object_type_e
la_spa_port_base::type() const
{
    return object_type_e::SPA_PORT;
}

std::string
la_spa_port_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_spa_port_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_spa_port_base::oid() const
{
    return m_oid;
}

la_device*
la_spa_port_base::get_device() const
{
    return m_device.get();
}

la_status
la_spa_port_base::set_representative_mc(la_multicast_group_gid_t mc_gid, la_system_port* system_port)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_spa_port_base::clear_representative_mc(la_multicast_group_gid_t mc_gid)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_mtu_t
la_spa_port_base::get_mtu() const
{
    return m_mtu;
}

la_status
la_spa_port_base::set_mtu(la_mtu_t mtu)
{
    la_status status = LA_STATUS_SUCCESS;

    m_mtu = mtu;

    for (auto& sp_data : m_system_ports_data) {
        const auto& system_port_base = sp_data->system_port;
        status = system_port_base->set_mtu(mtu);
        return_on_error(status);
    }

    return status;
}

la_status
la_spa_port_base::set_mask_eve(bool mask_eve)
{
    m_mask_eve = mask_eve;

    for (auto& sp_data : m_system_ports_data) {
        const auto& system_port_base = sp_data->system_port;
        auto status = system_port_base->set_mask_eve(mask_eve);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_spa_port_base::set_mac_af_npp_attributes(npl_mac_af_npp_attributes_table_value_t value)
{
    m_mac_af_npp_attributes_table_value = value;
    m_mac_af_npp_attributes_table_value_valid = true;

    for (auto& sp_data : m_system_ports_data) {
        const auto& system_port_base = sp_data->system_port;
        la_system_port_base::port_type_e sys_port_type = system_port_base->get_port_type();
        if (sys_port_type == la_system_port_base::port_type_e::REMOTE) {
            continue;
        }
        la_status status = system_port_base->set_mac_af_npp_attributes(value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

bool
la_spa_port_base::is_member(const la_system_port_wcptr& system_port) const
{
    auto sp_data_it = get_system_port_data_it(system_port);

    if (sp_data_it == m_system_ports_data.end()) {
        return false;
    }

    return true;
}

bool
la_spa_port_base::is_transmit_enabled(const la_system_port_wcptr& system_port) const
{
    auto sp_data_it = get_system_port_data_it(system_port);
    if (sp_data_it == m_system_ports_data.cend()) {
        return false;
    }

    return (*sp_data_it)->is_active;
}

bool
la_spa_port_base::is_receive_enabled(const la_system_port_wcptr& system_port) const
{
    auto sp_data_it = get_system_port_data_it(system_port);
    if (sp_data_it == m_system_ports_data.cend()) {
        return false;
    }

    return (*sp_data_it)->is_receive_enabled;
}

bool
la_spa_port_base::get_decrement_ttl() const
{
    return m_decrement_ttl;
}

la_status
la_spa_port_base::set_decrement_ttl(bool decrement_ttl)
{
    la_status status = LA_STATUS_SUCCESS;

    for (auto& sp_data : m_system_ports_data) {
        const auto& system_port_base = sp_data->system_port;
        status = system_port_base->set_decrement_ttl(decrement_ttl);
        return_on_error(status);
    }
    m_decrement_ttl = decrement_ttl;
    return status;
}

la_status
la_spa_port_base::set_stack_prune(bool prune)
{
    la_status status = LA_STATUS_SUCCESS;

    m_stack_prune = prune;

    for (auto& sp_data : m_system_ports_data) {
        const auto& system_port_base = sp_data->system_port;
        status = system_port_base->set_stack_prune(prune);
        return_on_error(status);
    }

    return status;
}

la_status
la_spa_port_base::get_stack_prune(bool& prune) const
{
    prune = m_stack_prune;
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
