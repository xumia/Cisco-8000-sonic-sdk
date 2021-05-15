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

#ifndef __LPM_DEVICE_SIMULATOR_H__
#define __LPM_DEVICE_SIMULATOR_H__

#include "common/bit_vector.h"
#include "lld/device_simulator.h"
#include "lld/lld_memory.h"

#include <map>

namespace silicon_one
{

class lpm_device_simulator : public device_simulator
{
public:
    // device_simulator virtual functions.

    la_status open_device(int& device_fd, int& interrupt_fd, size_t& interrupt_width_bytes) override;

    void close_device(int device_fd, int interrupt_fd) override;

    la_status write_register(la_block_id_t block_id,
                             la_entry_addr_t reg_address,
                             la_entry_width_t reg_width,
                             size_t count,
                             const void* in_val) override;

    la_status read_register(la_block_id_t block_id,
                            la_entry_addr_t reg_address,
                            la_entry_width_t reg_width,
                            size_t count,
                            void* out_val) override;

    la_status write_memory(la_block_id_t block_id,
                           la_entry_addr_t mem_address,
                           la_entry_width_t mem_width,
                           size_t mem_entries,
                           const void* in_val) override;

    la_status read_memory(la_block_id_t block_id,
                          la_entry_addr_t mem_address,
                          la_entry_width_t mem_width,
                          size_t mem_entries,
                          void* out_val) override;

    la_status add_property(std::string key, std::string value) override;

    void set_pacific_tree(const pacific_tree* pt) override;

    la_device_revision_e get_device_revision() const override;

private:
    using sim_address = uint64_t;

    struct mem_properties {
        sim_address addr;
        size_t width;
    };

    struct l2_mems_struct {
        mem_properties rd_mod_wr_valid;
        mem_properties rd_mod_wr_addr;
        mem_properties rd_mod_wr_non_entry_data;
        vector_alloc<mem_properties> sram_groups;

        // Pacific only
        vector_alloc<mem_properties> rd_md_wr_entry_regs;
        mem_properties lpm_rd_mod_wr_entry_0_1_reg;
    };

    struct lpm_core_context {
        size_t core_id;
        l2_mems_struct l2_mems;
    };

    enum {
        NUM_OF_LPM_CORES = 16,
        PACIFIC_NUM_RD_MD_ENTRY_REGS = 7,
        PACIFIC_L2_ECC = 22,
    };

    // Callback function type.
    // The function's arguments are the address the callback is assigned to and the LPM's core context that the function needs.
    using mem_modified_callback = void (lpm_device_simulator::*)(sim_address, lpm_core_context);

    using mem_modified_callback_lambda = std::function<void()>;

    using sim_addr_to_storage_map = std::map<sim_address, bit_vector>;

    using sim_addr_to_callback = std::map<sim_address, mem_modified_callback_lambda>;

    /// @brief Call 'after storage write' callback function.
    ///
    /// @param[in]      addr              Storage's absoulute address.
    void do_storage_write_callback(sim_address addr);

    /// @brief Add callback function to a given register address.
    ///
    /// @param[in]      addr                     Address of the register.
    /// @param[in]      callback                 Callback function to call after register write.
    /// @param[in]      context                  LPM core's context of the device.
    void add_reg_write_callback(sim_address addr, mem_modified_callback callback, lpm_core_context context);

    /// @brief Convert lld_register_scptr to mem_properties struct.
    ///
    /// @param[in]      lld_reg_scptr                 lld_register_scptr to convert.
    /// @param[out]     mem_properties                mem_properties struct.
    mem_properties lld_register_scptr2mem_properties(lld_register_scptr lld_reg_scptr);

    /// @brief Convert lld_memory_scptr to mem_properties struct.
    ///
    /// @param[in]      lld_memory_scptr              lld_memory_scptr to convert.
    /// @param[out]     mem_properties                mem_properties struct.
    mem_properties lld_mem_scptr2mem_properties(lld_memory_scptr lld_memory_scptr);

    /// @brief Return content of a given memory properties.
    ///
    /// @param[in]      mem_properties                mem_properties to return its content.
    /// @param[out]     bit_vector                    Content of the given memory.
    bit_vector& mem_properties2bv(mem_properties mem_properties);

    /// @brief Return Absoulute address composed of block ID and address.
    ///
    /// @param[in]      block_id                 Block ID of the memory.
    /// @param[in]      address                  Address of the memory.
    /// @param[out]     absoulute_address        Absoulute Address of the memory.
    uint64_t get_absolute_address(la_block_id_t block_id, la_entry_addr_t address);

    /// @brief Read value from storage.
    ///
    /// @param[in]      block_id                 Block ID of the storage.
    /// @param[in]      storage_address          Address of the storage.
    /// @param[in]      storage_width            Storage width.
    /// @param[in]      num_entries              Number of entries to read
    /// @param[out]     out_val                  Buffer for the read result.
    ///
    /// @return la_status
    la_status do_read_storage(la_block_id_t block_id,
                              la_entry_addr_t storage_address,
                              la_entry_width_t storage_width,
                              size_t num_entries,
                              void* out_val);

    /// @brief Write value to storage.
    ///
    /// @param[in]      block_id                 Block ID of the storage.
    /// @param[in]      storage_address          Address of the storage.
    /// @param[in]      storage_width            Storage width
    /// @param[in]      num_entries              Number of entries to write
    /// @param[in]      in_val                   Value to write
    ///
    /// @return la_status
    la_status do_write_storage(la_block_id_t block_id,
                               la_entry_addr_t storage_address,
                               la_entry_width_t storage_width,
                               size_t num_entries,
                               const void* in_val);

    // Simulator members
    sim_addr_to_storage_map m_storages; ///> Map between absolute address of storage to its bit vector value.

    sim_addr_to_callback
        m_write_address_to_callbacks; ///> Map between absolute address of storage to its "after write" callback function.

    // Callback functions

    /// @brief read_mod_wr callback to apply after rd_md__wr valid reg is written.
    ///
    /// This function writes the data from the rd_mod_wr regs into the L2 SRAM banks.
    ///
    /// @param[in]      addr                     Register's address.
    /// @param[in]      core_context                  LPM core's context of the device.
    void l2_read_mod_wr_write_callback(sim_address addr, lpm_core_context core_context);
};

/// @brief Creates new LPM device simulator.
///
/// @param[out]     device_simulator    new LPM device simulator.
silicon_one::device_simulator* create_lpm_device_simulator();

} // namespace silicon_one

#endif // __LPM_DEVICE_SIMULATOR_H__
