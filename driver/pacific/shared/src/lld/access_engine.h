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

#ifndef __LEABA_LLD_ACCESS_ENGINE_H__
#define __LEABA_LLD_ACCESS_ENGINE_H__

#include <stdint.h>
#include <stdlib.h>
#include <string>

#include "lld/ll_device.h"
#include "lld_types_internal.h"

#include <memory>
#include <vector>

namespace silicon_one
{

class ll_device_impl;

class access_engine
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief      Create access engine with a specified engine ID
    access_engine(ll_device_impl_wptr lld, uint16_t engine_id, const access_engine_info& ae_info, const la_dma_desc& dma_desc);

    // Disallow copy c'tor. Default construct is private, in order to support serialization
    access_engine(const access_engine&) = delete;

    void initialize(const access_engine_info& ae_info);

    /// @brief Get access engine id
    ///
    /// @retval Ending ID
    uint16_t get_engine_id() const;

    /// @brief Reset access engine
    ///
    /// @retval     LA_STATUS_SUCCESS   Completed successfully.
    /// @retval     LA_STATUS_EBUSY     Access engine is busy.
    /// @retval     LA_STATUS_EUNKNOWN  Access engine is in error state.
    la_status reset();

    /// @brief Wait till access engine becomes inactive or wait times out.
    ///
    /// @retval     LA_STATUS_SUCCESS   Flush completed successfully.
    /// @retval     LA_STATUS_EBUSY     Access engine is still busy, operation has timed out.
    /// @retval     LA_STATUS_NODEV     Device interface is not present.
    /// @retval     LA_STATUS_EUNKNOWN  Access engine has detected an error and stopped.
    la_status flush();

    /// @brief Access Engine state.
    enum class state_e {
        NONE = 0, ///< Initial state.
        READY,    ///< Access engine is ready and idle.
        BUSY,     ///< Access engine is busy executing commands.
        FAIL,     ///< Access engine in failure state.
        NODEV,    ///< Device is not present.
    };

    /// @brief Update Access Engine's state.
    ///
    /// @retval Access Engine state, see #silicon_one::access_engine::state_e
    state_e update_state();

    /// @brief Read from a register/memory of a CIF block.
    ///
    /// @param[in]  block_id        Block ID.
    /// @param[in]  addr            Offset of the register/memory within the block.
    /// @param[in]  width           Width in bytes.
    /// @param[in]  count           Number of entries to read.
    /// @param[in]  peek            Whether to peek at register (i.e. read w/o side effects like clearing).
    /// @param[out] read_cookie     Handle that will be used for copying the read result after the operation completes.
    ///
    /// @return                     Status code.
    la_status read(la_block_id_t block_id,
                   la_entry_addr_t addr,
                   la_entry_width_t width,
                   size_t count,
                   bool peek,
                   uint32_t& read_cookie);

    /// @brief Copy data after completion of read operation.
    ///
    /// @param[in]  read_cookie     Handle created by read().
    /// @param[in]  width           Width of entry in bytes.
    /// @param[in]  count           Number of entries to read.
    /// @param[out] out_val         Value buffer.
    ///
    /// @return                     Status code.
    la_status copy_read_result(uint32_t read_cookie, la_entry_width_t width, size_t count, void* out_val);

    /// @brief Write to a register/memory of a CIF block.
    ///
    /// @param[in]  block_id        Block ID.
    /// @param[in]  addr            Offset of the register/memory within the block.
    /// @param[in]  width           Width of entry in bytes.
    /// @param[in]  count           Number of entries to write.
    /// @param[in]  in_val          Value buffer.
    ///
    /// @return                     Status code.
    la_status write(la_block_id_t block_id, la_entry_addr_t addr, la_entry_width_t width, size_t count, const void* in_val);

    /// @brief Write zeros or ones to a register/memory of a CIF block.
    ///
    /// @param[in]  block_id        Block ID.
    /// @param[in]  addr            Offset of the register/memory within the block.
    /// @param[in]  width           Width of entry in bytes.
    /// @param[in]  count           Number of entries to write.
    /// @param[in]  in_val          Value buffer.
    ///
    /// @return                     Status code.
    la_status write_fill(la_block_id_t block_id, la_entry_addr_t addr, la_entry_width_t width, size_t count, const void* in_val);

    /// @brief Write a 32bit value to a register/memory of a CIF block.
    ///
    /// @note  This is a single-phase operation, the data is encoded into the
    ///        command frame and there is no additional data payload.
    ///
    /// @param[in]  block_id        Block ID.
    /// @param[in]  addr            Offset of the register/memory within the block.
    /// @param[in]  width           Width of entry in bytes.
    /// @param[in]  count           Number of entries to write.
    /// @param[in]  in_val          Value buffer.
    ///
    /// @return                     Status code.
    la_status write_immediate(la_block_id_t block_id,
                              la_entry_addr_t addr,
                              la_entry_width_t width,
                              size_t count,
                              const void* in_val);

    /// @brief Wait for value to become equal or not equal.
    ///
    /// @note  On successful return, the value of @wait_ok indicates if wait condition was satisfied or not.
    ///
    /// @param[in]  block_id        Block ID.
    /// @param[in]  addr            Offset of the register/memory within the block.
    /// @param[in]  equal           Wait for value to become equal or not.
    /// @param[in]  poll_count      Number of times to poll before stopping.
    /// @param[in]  val             Value to compare with.
    /// @param[in]  mask            Comparison mask.
    ///
    /// @return                     Status code.
    la_status wait_for_value(la_block_id_t block_id,
                             la_entry_addr_t addr,
                             bool equal,
                             uint8_t poll_cnt,
                             uint16_t val,
                             uint16_t mask);

    /// @brief Wait for a specified number of device-side cycles.
    ///
    /// @param[in]  cycles  Number of device-side cycles to wait.
    ///
    /// @return Status code.
    la_status delay(uint64_t cycles);

    /// @brief Acquire semaphore with a specified index.
    ///
    /// @param[in]  sem_index  Semaphore index between 0 and 63.
    ///
    /// @return Status code.
    la_status acquire_semaphore(uint8_t sem_index);

    /// @brief Release semaphore with a specified index.
    ///
    /// @param[in]  sem_index  Semaphore index between 0 and 63.
    ///
    /// @return Status code.
    la_status release_semaphore(uint8_t sem_index);

    uint32_t get_data_mem_entries_number() const
    {
        return m_data_mem_entries;
    };

private:
    ll_device_impl_wptr m_ll_device;
    uint16_t m_engine_id;
    la_dma_desc m_dma_desc;
    uint32_t m_data_pos;
    uint32_t m_cmd_pos;
    uint32_t m_cmd_fifo_w;

    // access engine addresses and sizes
    la_entry_addr_t m_cmd_mem_addr;
    la_entry_addr_t m_data_mem_addr;
    uint32_t m_data_mem_entries;
    la_entry_addr_t m_go_reg_addr;
    la_entry_addr_t m_cmd_ptr_reg_addr;
    la_entry_addr_t m_status_reg_addr;

    /// @brief Command fifo shadow
    std::vector<uint32_t> m_cmd_fifo_shadow;

    /// @brief Forward declaration of Access Engine command frame that is written to Access Engine command memory.
    union mem_cmd;

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    access_engine() = default;

    /// @brief Encode access engine command into SBIF command buffer.
    ///
    /// @param[in]  cmd Reference to access engine command frame.
    void encode(const mem_cmd& cmd);

    /// @brief Encode multiple access engine commands into SBIF command buffer.
    ///
    /// @param[in]  cmd  Array of access engine command frames.
    /// @param[in]  n    Size of array.
    void encode(const mem_cmd cmd[], size_t n);

    /// @brief Continuously execute commands as they are pushed to Access Engine's command buffer.
    void go();

    /// @brief Return data memory value from the access context memory.
    ///
    /// @param[in]  mem_offset      Value offset in the data memory.
    /// @return uint32_t memory value
    uint32_t get_data_memory_value(int mem_offset) const;

    /// @brief Set data memory value of the access context memory.
    ///
    /// @param[in]  mem_offset      Value offset in the data memory.
    /// @param[in]  val             Value to set.
    void set_data_memory_value(int mem_offset, uint32_t val);

    la_status semaphore(uint32_t op, uint8_t sem_index);

    /// @brief Make room for commands with no data.
    ///
    /// @param[in]  commands_count  Commands count to fit in AE command fifo.
    ///
    /// @return Status code.
    la_status make_room(size_t commands_count);

    /// @brief Make room for commands with data.
    ///
    /// @param[in]  commands_count  Number of command to fit in AE command fifo.
    /// @param[in]  data_dwords     Number of data dwords to fit in AE data memory.
    ///
    /// @return Status code.
    la_status make_room(size_t commands_count, la_entry_width_t data_dwords);

    /// @brief Wait till access engine becomes inactive or wait times out.
    ///
    /// @retval  Status code.
    la_status wait_completion();

    /// @brief Read command from AE fifo.
    ///
    /// @return AE command frame (3 dwords).
    mem_cmd read_command_from_fifo(uint16_t fifo_read_pointer) const;

    /// @brief Log all commands that were posted since the last flush.
    void log_posted_commands() const;

    /// @brief Restart the command that has failed.
    void restart_failed_command();

    static const char* to_string(state_e s);
    static std::string to_string(mem_cmd cmd);

    /// @brief Access Engine state.
    state_e m_state;

    /// @brief Opcode, block_id and address, captured when AE error is detected.
    uint32_t m_error_opcode;
    la_block_id_t m_error_block_id;
    la_entry_addr_t m_error_address;

    /// @brief Check if a memory is eligible for Pacific B0 LPM workaround.
    ///
    /// @param[in]     block_id     Memory block_id.
    /// @param[in]     addr         Memory address.
    /// @return  True if memory with the given block_id and address is eligible for Pacific B0 LPM workaround.
    bool pacific_b0_lpm_bubble_errata_workaround_eligible(la_block_id_t block_id, la_entry_addr_t addr) const;

    /// @brief Perform the lpm bubble workaround.
    state_e pacific_b0_lpm_bubble_errata_perform_workaround();

    /// @brief Check if a memory is eligible for Gibraltar LogicalPortProfileMappingVerifier workaround.
    ///
    /// @param[in]     block_id     Memory block_id.
    /// @param[in]     addr         Memory address.
    /// @return  True if memory with the given block_id and address is eligible for Gibraltar LogicalPortProfileMappingVerifier
    /// workaround.
    bool gibraltar_lp_profile_mapping_verifier_workaround_eligible(la_block_id_t block_id, la_entry_addr_t addr) const;

    /// @brief Perform the Gibraltar LogicalPortProfileMappingVerifier workaround.
    state_e gibraltar_lp_profile_mapping_verifier_perform_workaround();

}; // class access_engine

} // namespace silicon_one

#endif // __LEABA_LLD_ACCESS_ENGINE_H__
