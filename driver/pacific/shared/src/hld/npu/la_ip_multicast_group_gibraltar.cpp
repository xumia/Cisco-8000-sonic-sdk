// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include <sstream>

#include "api/system/la_spa_port.h"
#include "api/types/la_ethernet_types.h"
#include "npu/la_counter_set_impl.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_ip_multicast_group_gibraltar.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_svi_port_base.h"
#include "npu/mc_copy_id_manager.h"
#include "npu/resolution_utils.h"
#include "system/counter_allocation.h"
#include "system/la_device_impl.h"
#include "system/la_system_port_gibraltar.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_strings.h"

namespace silicon_one
{

la_ip_multicast_group_gibraltar::la_ip_multicast_group_gibraltar(la_device_impl_wptr device) : la_ip_multicast_group_base(device)
{
}

la_ip_multicast_group_gibraltar::~la_ip_multicast_group_gibraltar()
{
}

la_status
la_ip_multicast_group_gibraltar::configure_stack_copy_cud_mapping(la_slice_id_t slice, uint64_t mc_copy_id)
{
    const auto& table(m_device->m_tables.mc_cud_table[slice]);
    npl_mc_cud_table_key_t key;
    npl_mc_cud_table_value_t value;
    npl_mc_cud_table_entry_wptr_t entry;
    npl_l2_mc_cud_narrow_t payload;

    key.cud_mapping_local_vars_exp_mc_copy_id_14_1_ = mc_copy_id_manager::get_mc_cud_table_key(mc_copy_id);
    value.action = NPL_MC_CUD_TABLE_ACTION_UPDATE;
    payload.l2_encapsulation_type = NPL_NPU_ENCAP_L2_HEADER_TYPE_SVL;
    payload.l2_ac_encdap.l2_dlp.l2_dlp.id = 0;

    la_status status = table->lookup(key, entry);
    if ((status != LA_STATUS_SUCCESS) && (status != LA_STATUS_ENOTFOUND)) {
        // Unexpected failure
        return status;
    }

    if (status == LA_STATUS_SUCCESS) {
        value = entry->value();
    }

    value.payloads.update.mapped_cud_is_narrow = 1;

    npl_l2_mc_cud_narrow_t& target_encap_header = ((mc_copy_id & 1) == 0)
                                                      ? value.payloads.update.mapped_cud.app_mc_cud_narrow_odd_and_even.even.l2
                                                      : value.payloads.update.mapped_cud.app_mc_cud_narrow_odd_and_even.odd.l2;
    target_encap_header = payload;

    return table->set(key, value, entry);
}

la_status
la_ip_multicast_group_gibraltar::allocate_mc_copy_id(const member_t& member, la_slice_id_t dest_slice, uint64_t& out_mc_copy_id)
{
    la_status status;

    if (member.counter != nullptr) { // MCG counter member case
        counter_allocation allocation;
        const auto& counter = member.counter.weak_ptr_static_cast<const la_counter_set_impl>();
        status = counter->get_allocation(dest_slice, COUNTER_DIRECTION_EGRESS, allocation);
        return_on_error_log(status, HLD, ERROR, "%s: get_allocation failed. slice=%u", this->to_string().c_str(), dest_slice);

        size_t bank_id = allocation.get_bank_id();
        size_t ptr_offset = allocation.get_index();
        size_t bank_profile;
        status = m_device->m_counter_bank_manager->get_mcg_bank_profile(bank_id, dest_slice, bank_profile);
        return_on_error_log(status,
                            HLD,
                            ERROR,
                            "%s: No allocated bank profile for MCG counter. slice = %u, bank_id = %lu",
                            this->to_string().c_str(),
                            dest_slice,
                            bank_id);

        out_mc_copy_id = (COUNTER_MC_COPY_ID_PREFIX << (COUNTER_PTR_BANK_PROFILE_WIDTH + COUNTER_PTR_WIDTH));
        out_mc_copy_id |= (bank_profile << COUNTER_PTR_WIDTH);
        out_mc_copy_id |= ptr_offset;

        status = m_device->add_to_mc_copy_id_table(dest_slice, out_mc_copy_id, bank_id);
        return_on_error(status);
    } else {
        la_l3_port_wcptr l3_port = (member.is_punt || member.stackport) ? nullptr : member.l3_port;
        bool is_wide = false; // narrow for SVI and punt, don't care for L3-AC
        la_status status;
        if (member.stackport) {
            status = m_device->m_mc_copy_id_manager[dest_slice]->get_stack_mc_copy_id(out_mc_copy_id);
        } else {
            status = m_device->m_mc_copy_id_manager[dest_slice]->get_mc_copy_id(l3_port, is_wide, out_mc_copy_id);
        }
        return_on_error(status);
    }

    dassert_crit(m_mc_copy_id_mapping[dest_slice].find(member) == m_mc_copy_id_mapping[dest_slice].end());
    m_mc_copy_id_mapping[dest_slice][member] = out_mc_copy_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_gibraltar::release_mc_copy_id(const member_t& member, la_slice_id_t dest_slice)
{
    la_status status;
    const auto& mc_copy_id_it = m_mc_copy_id_mapping[dest_slice].find(member);
    if (mc_copy_id_it == m_mc_copy_id_mapping[dest_slice].end()) {
        log_err(HLD, "member not found in mc_copy_id mapping");

        return LA_STATUS_EUNKNOWN;
    }

    uint64_t mc_copy_id = mc_copy_id_it->second;

    if (member.counter != nullptr) {
        status = m_device->remove_from_mc_copy_id_table(dest_slice, mc_copy_id);
        return_on_error(status);
    } else {
        status = m_device->m_mc_copy_id_manager[dest_slice]->release_mc_copy_id(mc_copy_id);
        return_on_error(status);
    }

    m_mc_copy_id_mapping[dest_slice].erase(mc_copy_id_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_gibraltar::configure_cud_mapping(const member_t& member, la_slice_id_t dest_slice, uint64_t mc_copy_id)
{
    if ((member.l3_port != nullptr) && (member.l3_port->type() == la_object::object_type_e::L3_AC_PORT)
        && (member.is_punt == false)) {
        // No CUD mapping is needed for L3-AC if not egress punt
        return LA_STATUS_SUCCESS;
    }

    if (member.counter != nullptr) {
        // No CUD mapping is needed for MCG counter
        return LA_STATUS_SUCCESS;
    }

    if (member.stackport != nullptr) {
        return configure_stack_copy_cud_mapping(dest_slice, mc_copy_id);
    }

    la_status status = m_mc_common->configure_cud_mapping(member, dest_slice, mc_copy_id);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_gibraltar::teardown_cud_mapping(const member_t& member, la_slice_id_t dest_slice, uint64_t mc_copy_id)
{
    la_status status = m_mc_common->teardown_cud_mapping(member, dest_slice, mc_copy_id);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
