// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __RA_DEVICE_SIMULATOR_H__
#define __RA_DEVICE_SIMULATOR_H__

#include "lld/device_simulator.h"

#include <set>
#include <stdio.h>
#include <vector>

namespace silicon_one
{

class pacific_tree;
class ll_device;

struct simulator_options {
    bool use_socket_in_mems_init = false;          ///< If set, socket will be opened from the beginning of the test
    bool use_socket_in_rest_of_init = false;       ///< If set, socket will be opened after config memories initialization is
                                                   ///  done, butbefore doing other initializations.
    bool use_socket_in_load_arc_microcode = false; ///< If set, will use socket while loading arc microcode to read and write
                                                   ///  registers and memories.
    bool use_socket = false;                       ///< If set, socket will be used to read and write registers and memories,
                                                   ///  if not set, all above fields will be ignored.
    size_t port = 0;                               ///< The port to be used when the socket is opened.
};

//////////////////////////////////
// Logging function to override logger
//////////////////////////////////

/// @brief Enable logger w/wo socket
bool ra_logger_on(la_device_id_t device_id, const char* file_path);

/// @brief Disable logger (if with socket, destroy the socket also)
void ra_logger_off(la_device_id_t device_id);

bool set_logger_file(const char* file_path);

/// Helper functions
///////////////////////

/// @brief Constructs absolute address from block ID and address within a block.
///
/// @param[in]  block_id        Block UID.
/// @param[in]  addr            Memory line or Register address within a block.
///
/// @retval     absolute address.
size_t construct_absolute_address(size_t block_id, size_t addr);

/// @brief Extracts Block UID from an absolute address.
///
/// @param[in]  addr            Absolute Memory line or Register address.
///
/// @retval     block UID.
la_block_id_t address_get_block_id(size_t addr);

/// @brief Extracts Memory/Register address from an absolute address.
///
/// @param[in]  addr            Absolute Memory line or Register address.
///
/// @retval     Memory/Register address.
la_entry_addr_t address_get_entry_address(size_t addr);

/// @brief Translates byte array into string in hex format without leading 0x.
/// The result is stored in the provided buffer. Buffer length should be sufficient to store the data.
/// Each byte is stored as 2 hexa literals.
///
/// @param[in]  bytes           Byte array.
/// @param[in]  len             Array length in bytes.
std::string bytes_to_str(const uint8_t* bytes, size_t bytes_len);

/// @brief Implementation of #silicon_one::device_imulator interface for RA testing with AV flow.
///
/// Creates a register/memory read/write access trace.
class ra_device_simulator : public device_simulator
{
public:
    ra_device_simulator(const std::vector<size_t>& block_filter_vec);

    ~ra_device_simulator();

    bool initialize(la_device_id_t device_id, simulator_options& sim_options);

    la_device_revision_e get_device_revision() const override;

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

    /// @brief Switch from device initialization phase to flow phase
    bool init_device_done() const;

    /// @brief Checks content of the provided address vrt to expected value.
    ///
    /// @param[in]  address     Memory/Register address including block offset.
    /// @param[in]  val         String, representing expected hex value.
    /// @param[in]  is_mem      true if memory
    ///
    /// @retval     true if address content matches the expected value.
    std::string check_address(size_t address, const std::string& val, bool is_mem) const;

private:
    bool send_write_rtl_command(const char* cmd, size_t block_id, size_t addr, const uint8_t* val, size_t val_size);

    bool send_read_rtl_command(const char* cmd, size_t block_id, size_t addr, uint8_t* out_val, size_t val_size);

    la_status handle_special_registers(la_block_id_t block_id,
                                       la_entry_addr_t reg_address,
                                       la_entry_width_t reg_width,
                                       void* out_val);

    la_status handle_special_memories(la_block_id_t block_id,
                                      la_entry_addr_t mem_address,
                                      la_entry_width_t mem_width,
                                      void* out_val);

private:
    std::set<size_t> m_block_filter;
    la_device_id_t m_device_id;
};

} // namespace silicon_one

#endif // __RA_DEVICE_SIMULATOR_H__
