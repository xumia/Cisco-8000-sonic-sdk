// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "lpm_top_hw_writer_pacific.h"
#include "common/defines.h"
#include "lld/ll_device.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"

namespace silicon_one
{

const ll_device_sptr&
lpm_top_hw_writer_pacific::get_ll_device() const
{
    return m_ll_device;
}

lpm_top_hw_writer_pacific::lpm_top_hw_writer_pacific(const ll_device_sptr& ldevice)
    : m_ll_device(ldevice), m_entries(NUM_DISTRIBUTER_ENTRIES / 2)
{
}

la_status
lpm_top_hw_writer_pacific::update_group_to_core_map(size_t group, size_t core)
{
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }
    log_debug(TABLES, "assigning group %lu to core %lu", group, core);

    const pacific_tree* tree = m_ll_device->get_pacific_tree();
    const lld_register_array_sptr& group_to_core_map = tree->cdb->top->lpm_group_map_table;
    const lld_register_desc_t* desc = group_to_core_map->get_desc();

    bit_vector val(core, desc->width_in_bits);
    la_status status = m_ll_device->write_register(*(*group_to_core_map)[group], val);

    return status;
}

la_status
lpm_top_hw_writer_pacific::set_distributor_line(size_t line, const lpm_key_t& key, lpm_payload_t payload)
{
    la_status status = LA_STATUS_SUCCESS;
    const pacific_tree* tree = m_ll_device->get_pacific_tree();

    log_debug(TABLES,
              "set_distributor_line(line = %lu, key = %s, key width = %lu, payload = 0x%x)",
              line,
              key.to_string().c_str(),
              key.get_width(),
              payload);

    // Write to SRAM
    const lld_memory_scptr& sram = tree->cdb->top->clpm_group_map_regs;
    bit_vector sram_val(payload);
    status = m_ll_device->write_memory(*sram, line, sram_val);
    return_on_error(status);

    // Write to TCAM
    const lld_memory_array_sptr& tcam = tree->cdb->top->clpm_group_map_tcam;
    const lld_memory_desc_t* tcam_desc = tcam->get_desc();

    size_t tcam_length = tcam_desc->width_bits;

    bit_vector tcam_key(0, tcam_length);
    bit_vector tcam_mask(0, tcam_length);

    dassert_crit(tcam_desc->width_bits >= key.get_width() - 1);

    bool is_ipv6 = key.bit_from_msb(0);
    size_t key_width = key.get_width();
    size_t width_to_write = key_width - 1;
    lpm_key_t key_to_write = key.bits_from_msb(1 /*no key type*/, width_to_write);

    if (is_ipv6) {
        if (width_to_write > 0) {
            tcam_key.set_bits_from_msb(0, width_to_write, key_to_write);
            tcam_mask.set_bits_from_msb(0, width_to_write, bit_vector::ones(width_to_write));
        }
    } else /* IPv4 */ {
        // In Pacific, the bit indicating V6 for long IPv6 prefixes in the distributor is missing.
        // As WA we write in the MSB 0xfff for IPv4 and block vrf=0x7ff for V6.
        // The outcome is that IPv4 lookup looks like: {0xfff,garbage,VRF,prefix}.

        tcam_key.set_bits_from_msb(IPV4_KEY_MSB_OFFSET, width_to_write, key_to_write);
        tcam_key.set_bits_from_msb(0 /* offset */, 12 /* width */, 0xfff);

        tcam_mask.set_bits_from_msb(IPV4_KEY_MSB_OFFSET, width_to_write, bit_vector::ones(width_to_write));
        tcam_mask.set_bits_from_msb(0 /* offset */, 12 /* width */, 0xfff);
    }

    for (size_t ifc_idx = 0; ifc_idx < tcam->size(); ++ifc_idx) {
        status = m_ll_device->write_tcam(*(*tcam)[ifc_idx], line, tcam_key, tcam_mask);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
lpm_top_hw_writer_pacific::remove_distributor_line(size_t line)
{
    la_status status = LA_STATUS_SUCCESS;
    const pacific_tree* tree = m_ll_device->get_pacific_tree();

    log_debug(TABLES, "remove_distributor_line(line = %lu)", line);

    // Write to TCAM
    lld_memory_array_sptr& tcam = tree->cdb->top->clpm_group_map_tcam;
    for (size_t ifc_idx = 0; ifc_idx < tcam->size(); ++ifc_idx) {
        status = m_ll_device->invalidate_tcam(*(*tcam)[ifc_idx], line);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_top_hw_writer_pacific::read_indices_of_last_accessed_hbm_buckets(vector_alloc<size_t>& out_hw_indices)
{
    const pacific_tree* tree = m_ll_device->get_pacific_tree();
    cdb_top_cdb_last_4_hbm_requests_ptrs_register reg;
    la_status status = m_ll_device->read_register(*tree->cdb->top->cdb_last_4_hbm_requests_ptrs, reg);

    return_on_error(status);

    out_hw_indices.push_back(reg.fields.last_hbm_bucket_req0);
    out_hw_indices.push_back(reg.fields.last_hbm_bucket_req1);
    out_hw_indices.push_back(reg.fields.last_hbm_bucket_req2);
    out_hw_indices.push_back(reg.fields.last_hbm_bucket_req3);

    return LA_STATUS_SUCCESS;
}

la_status
lpm_top_hw_writer_pacific::update_distributor(const lpm_distributor::hardware_instruction_vec& instructions)
{
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = LA_STATUS_SUCCESS;

    for (const lpm_distributor::distributor_hw_instruction& curr : instructions) {
        auto type = boost::apply_visitor(lpm_distributor::visitor_distributor_hw_instruction(), curr.instruction_data);
        switch (type) {
        case lpm_distributor::distributor_hw_instruction::type_e::MODIFY_PAYLOAD:
            dassert_crit(false); // shouldn't happen to modify the payload(group);
            return LA_STATUS_EUNKNOWN;

        case lpm_distributor::distributor_hw_instruction::type_e::INSERT: {
            auto curr_data = boost::get<lpm_distributor::distributor_hw_instruction::insert_data>(curr.instruction_data);
            size_t line = curr_data.location.cell;
            status = set_distributor_line(line, curr_data.key, curr_data.payload);
            return_on_error(status);
            break;
        }

        case lpm_distributor::distributor_hw_instruction::type_e::REMOVE: {
            auto curr_data = boost::get<lpm_distributor::distributor_hw_instruction::remove_data>(curr.instruction_data);
            size_t line = curr_data.location.cell;
            status = remove_distributor_line(line);
            return_on_error(status);
            break;
        }

        case lpm_distributor::distributor_hw_instruction::type_e::UPDATE_GROUP_TO_CORE: {
            auto curr_data
                = boost::get<lpm_distributor::distributor_hw_instruction::update_group_to_core_data>(curr.instruction_data);
            status = update_group_to_core_map(curr_data.group_id, curr_data.core_id);
            return_on_error(status);
            break;
        }

        default:
            dassert_crit(false);
            return LA_STATUS_EUNKNOWN;
        }
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
