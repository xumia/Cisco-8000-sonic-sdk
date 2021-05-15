// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "lpm_device_simulator.h"
#include "common/bit_vector.h"
#include "common/logger.h"
#include "lld/pacific_tree.h"

namespace silicon_one
{

silicon_one::device_simulator*
create_lpm_device_simulator()
{
    return new lpm_device_simulator();
}

la_status
lpm_device_simulator::open_device(int& device_fd, int& interrupt_fd, size_t& interrupt_width_bytes)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
lpm_device_simulator::add_property(std::string key, std::string value)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

void
lpm_device_simulator::close_device(int device_fd, int interrupt_fd)
{
}

la_device_revision_e
lpm_device_simulator::get_device_revision() const
{
    // TODO
    return la_device_revision_e::NONE;
}

la_status
lpm_device_simulator::do_read_storage(la_block_id_t block_id,
                                      la_entry_addr_t storage_address,
                                      la_entry_width_t storage_width,
                                      size_t num_entries,
                                      void* out_val)
{
    sim_address abs_addr = get_absolute_address(block_id, storage_address);
    memset(out_val, 0, storage_width * num_entries);
    for (size_t entry_idx = 0; entry_idx < num_entries; entry_idx++) {
        bit_vector& storage = m_storages[abs_addr + entry_idx];
        uint8_t* byte_array = storage.byte_array();
        size_t bytes_to_read = std::min((size_t)storage_width, storage.get_width_in_bytes());
        memmove(out_val, byte_array, bytes_to_read);
        out_val = ((uint8_t*)out_val) + storage_width;
    }
    return LA_STATUS_SUCCESS;
}

la_status
lpm_device_simulator::read_memory(la_block_id_t block_id,
                                  la_entry_addr_t mem_address,
                                  la_entry_width_t mem_width,
                                  size_t mem_entries,
                                  void* out_val)
{
    return do_read_storage(block_id, mem_address, mem_width, mem_entries, out_val);
}

la_status
lpm_device_simulator::do_write_storage(la_block_id_t block_id,
                                       la_entry_addr_t storage_address,
                                       la_entry_width_t storage_width,
                                       size_t num_entries,
                                       const void* in_val)
{
    sim_address abs_addr = get_absolute_address(block_id, storage_address);
    for (size_t entry_idx = 0; entry_idx < num_entries; entry_idx++) {
        bit_vector& mem = m_storages[abs_addr + entry_idx];
        size_t size_to_write_in_bits = storage_width * 8;

        dassert_crit(mem.get_width() == 0 || mem.get_width() == size_to_write_in_bits);

        if (mem.get_width() == 0) {
            mem.resize(size_to_write_in_bits);
        }

        uint8_t* byte_array = mem.byte_array();
        memmove(byte_array, in_val, storage_width);
        in_val = ((uint8_t*)in_val) + storage_width;
    }

    do_storage_write_callback(abs_addr);

    return LA_STATUS_SUCCESS;
}

la_status
lpm_device_simulator::write_memory(la_block_id_t block_id,
                                   la_entry_addr_t mem_address,
                                   la_entry_width_t mem_width,
                                   size_t mem_entries,
                                   const void* in_val)
{
    return do_write_storage(block_id, mem_address, mem_width, mem_entries, in_val);
}

la_status
lpm_device_simulator::read_register(la_block_id_t block_id,
                                    la_entry_addr_t reg_address,
                                    la_entry_width_t reg_width,
                                    size_t count,
                                    void* out_val)
{
    if (count != 1) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    return do_read_storage(block_id, reg_address, reg_width, count, out_val);
}

la_status
lpm_device_simulator::write_register(la_block_id_t block_id,
                                     la_entry_addr_t reg_address,
                                     la_entry_width_t reg_width,
                                     size_t count,
                                     const void* in_val)
{

    if (count != 1) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    return do_write_storage(block_id, reg_address, reg_width, count, in_val);
}

void
lpm_device_simulator::set_pacific_tree(const pacific_tree* tree)
{
    m_pacific_tree = tree;

    for (size_t core_id = 0; core_id < NUM_OF_LPM_CORES; core_id++) {

        lpm_core_context core_context;
        core_context.core_id = core_id;
        l2_mems_struct& l2_core_mems = core_context.l2_mems;

        const size_t is_full_core = core_id & 0x2; // second bit
        const size_t lpm_core_idx = core_id & 0x1; // first bit
        const size_t cdb_core_idx = core_id >> 2;  // idx in cdb core array

        if (is_full_core) {
            // Full core

            // L2
            l2_core_mems.rd_mod_wr_valid
                = lld_register_scptr2mem_properties((*tree->cdb->core[cdb_core_idx]->lpm_rd_mod_wr)[lpm_core_idx]);
            l2_core_mems.rd_mod_wr_addr
                = lld_register_scptr2mem_properties((*tree->cdb->core[cdb_core_idx]->lpm_rd_mod_wr_address_reg)[lpm_core_idx]);
            l2_core_mems.rd_mod_wr_non_entry_data = lld_register_scptr2mem_properties(
                (*tree->cdb->core[cdb_core_idx]->lpm_rd_mod_wr_non_entry_data_reg)[lpm_core_idx]);
            const auto& srams_group
                = (lpm_core_idx == 0) ? tree->cdb->core[cdb_core_idx]->srams_group0 : tree->cdb->core[cdb_core_idx]->srams_group1;

            size_t num_of_sram_banks = srams_group->get_desc()->instances;
            l2_core_mems.sram_groups.resize(num_of_sram_banks);
            for (size_t sram_idx = 0; sram_idx < num_of_sram_banks; sram_idx++) {
                l2_core_mems.sram_groups[sram_idx] = lld_mem_scptr2mem_properties((*srams_group)[sram_idx]);
            }

            // Only pacific relevant registers

            const auto& lpm_rd_mod_wr_entry_0_1_reg
                = (*tree->cdb->core[cdb_core_idx]->lpm_rd_mod_wr_entry0_entry1_data_reg)[lpm_core_idx];

            l2_core_mems.lpm_rd_mod_wr_entry_0_1_reg = lld_register_scptr2mem_properties(lpm_rd_mod_wr_entry_0_1_reg);

            const auto& lpm_rd_mod_wr_entry_regs = (lpm_core_idx == 0)
                                                       ? tree->cdb->core[cdb_core_idx]->lpm0_rd_mod_wr_entry_data_reg
                                                       : tree->cdb->core[cdb_core_idx]->lpm1_rd_mod_wr_entry_data_reg;

            size_t num_of_rd_md_wr_entry_regs = lpm_rd_mod_wr_entry_regs->get_desc()->instances;
            l2_core_mems.rd_md_wr_entry_regs.resize(num_of_rd_md_wr_entry_regs);

            for (size_t reg_idx = 0; reg_idx < PACIFIC_NUM_RD_MD_ENTRY_REGS; reg_idx++) {
                l2_core_mems.rd_md_wr_entry_regs[reg_idx] = lld_register_scptr2mem_properties((*lpm_rd_mod_wr_entry_regs)[reg_idx]);
            }

        } else {
            // Reduced core

            // L2
            l2_core_mems.rd_mod_wr_valid
                = lld_register_scptr2mem_properties((*tree->cdb->core_reduced[cdb_core_idx]->lpm_rd_mod_wr)[lpm_core_idx]);
            l2_core_mems.rd_mod_wr_addr = lld_register_scptr2mem_properties(
                (*tree->cdb->core_reduced[cdb_core_idx]->lpm_rd_mod_wr_address_reg)[lpm_core_idx]);
            l2_core_mems.rd_mod_wr_non_entry_data = lld_register_scptr2mem_properties(
                (*tree->cdb->core_reduced[cdb_core_idx]->lpm_rd_mod_wr_non_entry_data_reg)[lpm_core_idx]);
            const auto& srams_group = (lpm_core_idx == 0) ? tree->cdb->core_reduced[cdb_core_idx]->srams_group0
                                                          : tree->cdb->core_reduced[cdb_core_idx]->srams_group1;

            size_t num_of_sram_banks = srams_group->get_desc()->instances;
            l2_core_mems.sram_groups.resize(num_of_sram_banks);
            for (size_t sram_idx = 0; sram_idx < num_of_sram_banks; sram_idx++) {
                l2_core_mems.sram_groups[sram_idx] = lld_mem_scptr2mem_properties((*srams_group)[sram_idx]);
            }

            // Only pacific relevant registers
            const auto& lpm_rd_mod_wr_entry_0_1_reg
                = (*tree->cdb->core_reduced[cdb_core_idx]->lpm_rd_mod_wr_entry0_entry1_data_reg)[lpm_core_idx];

            l2_core_mems.lpm_rd_mod_wr_entry_0_1_reg = lld_register_scptr2mem_properties(lpm_rd_mod_wr_entry_0_1_reg);

            const auto& lpm_rd_mod_wr_entry_regs = (lpm_core_idx == 0)
                                                       ? tree->cdb->core_reduced[cdb_core_idx]->lpm0_rd_mod_wr_entry_data_reg
                                                       : tree->cdb->core_reduced[cdb_core_idx]->lpm1_rd_mod_wr_entry_data_reg;

            size_t num_of_rd_md_wr_entry_regs = lpm_rd_mod_wr_entry_regs->get_desc()->instances;
            l2_core_mems.rd_md_wr_entry_regs.resize(num_of_rd_md_wr_entry_regs);

            for (size_t reg_idx = 0; reg_idx < PACIFIC_NUM_RD_MD_ENTRY_REGS; reg_idx++) {
                l2_core_mems.rd_md_wr_entry_regs[reg_idx] = lld_register_scptr2mem_properties((*lpm_rd_mod_wr_entry_regs)[reg_idx]);
            }
        }

        add_reg_write_callback(
            l2_core_mems.rd_mod_wr_valid.addr, &lpm_device_simulator::l2_read_mod_wr_write_callback, core_context);
    }
}

void
lpm_device_simulator::do_storage_write_callback(sim_address addr)
{
    if (m_write_address_to_callbacks[addr] == nullptr) {
        return;
    }

    m_write_address_to_callbacks[addr]();
}

void
lpm_device_simulator::add_reg_write_callback(sim_address addr, mem_modified_callback callback, lpm_core_context context)
{
    dassert_crit(m_write_address_to_callbacks[addr] == nullptr);

    m_write_address_to_callbacks[addr] = [=]() -> void { (this->*callback)(addr, context); };
}

void
lpm_device_simulator::l2_read_mod_wr_write_callback(sim_address addr, lpm_core_context core_context)
{

    if (m_storages[addr].get_value() == 0) {
        log_err(TABLES, "Write 0 to LPM L2 rd_mod_wr valid register, LPM should only write 1 to this register.");
        return;
    }

    dassert_crit(m_pacific_tree);
    const mem_properties& addr_reg_prop = core_context.l2_mems.rd_mod_wr_addr;

    // First bit is "write_full_row" bit, for now, this is the only mode supported.
    dassert_crit(m_storages[addr_reg_prop.addr].get_value() & 1);
    size_t hw_row = m_storages[addr_reg_prop.addr].get_value() >> 1;

    const mem_properties& non_entry_data_reg_prop = core_context.l2_mems.rd_mod_wr_non_entry_data;

    // Compose L2 line from the rd_mod_wr regs.
    size_t offset = 0;
    const bit_vector& non_entry_data_reg_bv = mem_properties2bv(non_entry_data_reg_prop);
    bit_vector l2_line(non_entry_data_reg_bv);
    l2_line.set_bits(offset + non_entry_data_reg_prop.width - 1, offset, m_storages[non_entry_data_reg_prop.addr]);
    offset += non_entry_data_reg_prop.width;

    const mem_properties& entry_0_1_prop = core_context.l2_mems.lpm_rd_mod_wr_entry_0_1_reg;

    l2_line.set_bits(offset + entry_0_1_prop.width - 1, offset, m_storages[entry_0_1_prop.addr]);
    offset += entry_0_1_prop.width;

    for (const auto& reg_prop : core_context.l2_mems.rd_md_wr_entry_regs) {
        l2_line.set_bits(offset + reg_prop.width - 1, offset, m_storages[reg_prop.addr]);
        offset += reg_prop.width;
    }

    // Add ECC bits like HW does.
    l2_line = l2_line << PACIFIC_L2_ECC;

    // Write bucket to SRAM banks.
    size_t bank_idx = 0;
    size_t sram_bank_width = core_context.l2_mems.sram_groups[0].width;
    size_t lsb = 0;
    while (lsb < l2_line.get_width()) {
        mem_properties sram_bank_properties = core_context.l2_mems.sram_groups[bank_idx];
        bit_vector& sram_bank_mem = m_storages[sram_bank_properties.addr + hw_row];
        sram_bank_mem = l2_line.bits(lsb + sram_bank_width - 1, lsb);
        bank_idx += 1;
        lsb += sram_bank_width;
    }

    // Set valid reg to 0 after write to HW is done.
    size_t current_reg_width = m_storages[addr].get_width();
    m_storages[addr].set_bits(current_reg_width - 1, 0, 0);
}

lpm_device_simulator::mem_properties
lpm_device_simulator::lld_register_scptr2mem_properties(lld_register_scptr lld_reg_scptr)
{
    sim_address addr = get_absolute_address(lld_reg_scptr->get_block_id(), lld_reg_scptr->get_desc()->addr);
    return {.addr = addr, .width = lld_reg_scptr->get_desc()->width_in_bits};
}

bit_vector&
lpm_device_simulator::mem_properties2bv(mem_properties mem_properties)
{
    return m_storages[mem_properties.addr];
}

lpm_device_simulator::mem_properties
lpm_device_simulator::lld_mem_scptr2mem_properties(lld_memory_scptr lld_memory_scptr)
{
    sim_address addr = get_absolute_address(lld_memory_scptr->get_block_id(), lld_memory_scptr->get_desc()->addr);
    return {.addr = addr, .width = lld_memory_scptr->get_desc()->width_bits};
}

uint64_t
lpm_device_simulator::get_absolute_address(la_block_id_t block_id, la_entry_addr_t address)
{
    return (((uint64_t)block_id) << bit_utils::BITS_IN_UINT32 | address);
}

} // namespace silicon_one
