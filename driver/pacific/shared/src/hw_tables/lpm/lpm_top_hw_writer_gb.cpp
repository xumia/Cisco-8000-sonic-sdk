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

#include "lpm_top_hw_writer_gb.h"
#include "common/defines.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"

namespace silicon_one
{

static constexpr size_t DISTRIBUTOR_IPV4_KEY_MSB_OFFSET = 1;
static constexpr size_t DISTRIBUTOR_IPV6_KEY_MSB_OFFSET = 2;

const ll_device_sptr&
lpm_top_hw_writer_gb::get_ll_device() const
{
    return m_ll_device;
}

lpm_top_hw_writer_gb::lpm_top_hw_writer_gb(const ll_device_sptr& ldevice)
    : m_ll_device(ldevice), m_entries(NUM_DISTRIBUTER_ENTRIES / 2)
{
}

la_status
lpm_top_hw_writer_gb::update_group_to_core_map(size_t group, size_t core)
{
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }
    log_debug(TABLES, "assigning group %lu to core %lu", group, core);

    const gibraltar_tree* tree = m_ll_device->get_gibraltar_tree();
    const lld_memory_array_sptr& group_to_core_map = tree->cdb->top->clpm_group_to_lpm_core_map_regs;
    const lld_memory_desc_t* desc = group_to_core_map->get_desc();

    bit_vector val(core, desc->width_bits);

    for (size_t ifc_idx = 0; ifc_idx < group_to_core_map->size(); ++ifc_idx) {
        la_status status = m_ll_device->write_memory(*(*group_to_core_map)[ifc_idx], group, val);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
    ;
}

la_status
lpm_top_hw_writer_gb::set_distributor_line(size_t line, const lpm_key_t& key, lpm_payload_t payload)
{
    la_status status = LA_STATUS_SUCCESS;
    const gibraltar_tree* tree = m_ll_device->get_gibraltar_tree();

    log_debug(TABLES,
              "set_distributor_line(line = %lu, key = %s, key width = %lu, payload = 0x%x)",
              line,
              key.to_string().c_str(),
              key.get_width(),
              payload);

    // Write to SRAM
    const lld_memory_array_sptr& sram = tree->cdb->top->clpm_tcam_index_to_lpm_group_map_regs;
    bit_vector sram_val(payload);
    for (size_t ifc_idx = 0; ifc_idx < sram->size(); ++ifc_idx) {
        status = m_ll_device->write_memory(*(*sram)[ifc_idx], line, sram_val);
        return_on_error(status);
    }

    // Write to TCAM
    const lld_memory_array_sptr& tcam = tree->cdb->top->clpm_group_map_tcam;
    const lld_memory_desc_t* tcam_desc = tcam->get_desc();

    bit_vector tcam_key(0, tcam_desc->width_bits);
    bit_vector tcam_mask(0, tcam_desc->width_bits);

    size_t key_width = key.get_width() - 1;
    size_t distributor_line_width = static_cast<size_t>(tcam_desc->width_bits);
    dassert_crit(distributor_line_width > key_width);

    bool is_ipv6 = key.bit_from_msb(0);
    size_t msb_offset = is_ipv6 ? DISTRIBUTOR_IPV6_KEY_MSB_OFFSET : DISTRIBUTOR_IPV4_KEY_MSB_OFFSET;
    size_t space_for_key_in_distributor = distributor_line_width - msb_offset;
    size_t width_to_write = std::min(space_for_key_in_distributor, key_width);

    tcam_key.set_bits_from_msb(0 /* pos */, 1 /* width */, is_ipv6);
    lpm_key_t key_to_write = key.bits_from_msb(1 /*no key type*/, width_to_write);
    tcam_key.set_bits_from_msb(msb_offset, width_to_write, key_to_write);

    tcam_mask.resize(width_to_write + msb_offset);
    tcam_mask.negate();
    tcam_mask = tcam_mask << (tcam_desc->width_bits - width_to_write - msb_offset);
    tcam_mask.resize(tcam_desc->width_bits);

    for (size_t ifc_idx = 0; ifc_idx < tcam->size(); ++ifc_idx) {
        status = m_ll_device->write_tcam(*(*tcam)[ifc_idx], line, tcam_key, tcam_mask);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
lpm_top_hw_writer_gb::remove_distributor_line(size_t line)
{
    la_status status = LA_STATUS_SUCCESS;
    const gibraltar_tree* tree = m_ll_device->get_gibraltar_tree();

    log_debug(TABLES, "remove_distributor_line(line = %lu)", line);

    // Write to TCAM
    const lld_memory_array_sptr& tcam = tree->cdb->top->clpm_group_map_tcam;
    for (size_t ifc_idx = 0; ifc_idx < tcam->size(); ++ifc_idx) {
        status = m_ll_device->invalidate_tcam(*(*tcam)[ifc_idx], line);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_top_hw_writer_gb::read_indices_of_last_accessed_hbm_buckets(vector_alloc<size_t>& out_hw_indices)
{
    constexpr size_t MAX_NUM_BUCKETS = 128;
    constexpr size_t HBM_BUCKET_IDX_WIDTH = 19; // 4 bits for CORE ID and 15 bits for bucket index.

    const gibraltar_tree* tree = m_ll_device->get_gibraltar_tree();

    // load accessed buckets and clear for next read
    la_status status
        = m_ll_device->write_register(*tree->cdb->top->hbm_accessed_buckets_wr, bit_vector(1 /* value */, 1 /* width */));
    return_on_error(status);

    gibraltar::cdb_top_accessed_hbm_buckets_register reg;
    status = m_ll_device->read_register(*tree->cdb->top->accessed_hbm_buckets, reg);
    return_on_error(status);

    size_t num = reg.fields.accessed_hbm_buckets_num;
    dassert_crit(num <= MAX_NUM_BUCKETS);

    uint64_t bucket_index_array[reg.fields.ACCESSED_HBM_BUCKETS_ARRAY_WIDTH];
    reg.fields.get_accessed_hbm_buckets_array(bucket_index_array);

    out_hw_indices.reserve(num);

    for (size_t i = 0; i < num; i++) {
        size_t lsb = i * HBM_BUCKET_IDX_WIDTH;
        size_t msb = lsb + HBM_BUCKET_IDX_WIDTH - 1;

        size_t bucket_idx;
        bit_utils::get_bits(bucket_index_array, msb, lsb, &bucket_idx);

        out_hw_indices.push_back(bucket_idx);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_top_hw_writer_gb::update_distributor(const lpm_distributor::hardware_instruction_vec& instructions)
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
