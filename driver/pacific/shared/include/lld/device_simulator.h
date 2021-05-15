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

#ifndef __DEVICE_SIMULATOR_H__
#define __DEVICE_SIMULATOR_H__

#include "api/types/la_common_types.h"

namespace silicon_one
{

class pacific_tree;
class gibraltar_tree;
class asic3_tree;
class asic4_tree;
class asic5_tree;

/// @brief Simulator interface
///
/// @details Provides register/memory read/write callbacks to be used during simulation.
///
class device_simulator
{
public:
    /// @brief c'tor
    device_simulator() = default;

    /// @brief d'tor
    virtual ~device_simulator() = default;

    /// @brief  Get device revision
    ///
    /// @retval Device revision
    virtual la_device_revision_e get_device_revision() const = 0;

    /// @brief  Set a pointer to Pacific tree.
    ///
    /// @param[in]  pt  Pointer to Pacific tree
    virtual void set_pacific_tree(const pacific_tree* pt);

    /// @brief  Set a pointer to Gibraltar tree.
    ///
    /// @param[in]  gt  Pointer to Gibraltar tree
    virtual void set_gibraltar_tree(const gibraltar_tree* gt);

    /// @brief  Set a pointer to asic3 tree.
    ///
    /// @param[in]  grt Pointer to asic3 tree
    virtual void set_asic3_tree(const asic3_tree* grt);

    /// @brief  Set a pointer to asic4 tree.
    ///
    /// @param[in]  pd  Pointer to Asic4 tree
    virtual void set_asic4_tree(const asic4_tree* pd);

    /// @brief  Set a pointer to asic5 tree.
    ///
    /// @param[in]  ar  Pointer to Asic5 tree
    virtual void set_asic5_tree(const asic5_tree* ar);

    /// @brief Open device and interrupt file descriptors.
    ///
    /// @param[out] device_fd             An open file descriptor that can be used with mmap().
    /// @param[out] interrupt_fd          An open interrupt file descriptor.
    /// @param[out] interrupt_width_bytes Width of interrupt counter.
    //
    /// @retval Status code.
    virtual la_status open_device(int& device_fd, int& interrupt_fd, size_t& interrupt_width_bytes) = 0;

    /// @brief Close device and interrupt file descriptors.
    ///
    /// @param[in]  device_fd      An open device file descriptor.
    /// @param[in]  interrupt_fd An open interrupt file descriptor.
    virtual void close_device(int device_fd, int interrupt_fd) = 0;

    /// @brief Read register callback.
    ///
    /// @param[in]  block_id               Block ID of the register.
    /// @param[in]  reg_address            Register address in the block.
    /// @param[in]  reg_width              Width in byte resolution.
    /// @param[in]  count                  Number of consecutive entries to be read.
    /// @param[out] out_val                Return value destination buffer.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_register(la_block_id_t block_id,
                                    la_entry_addr_t reg_address,
                                    la_entry_width_t reg_width,
                                    size_t count,
                                    void* out_val)
        = 0;

    /// @brief Write register callback.
    ///
    /// @param[in]  block_id               Block ID of the register.
    /// @param[in]  reg_address            Register address in the block.
    /// @param[in]  reg_width              Width in byte resolution.
    /// @param[in]  count                  Number of consecutive entries to be read.
    /// @param[out] in_val                 Value to be written to the register.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status write_register(la_block_id_t block_id,
                                     la_entry_addr_t reg_address,
                                     la_entry_width_t reg_width,
                                     size_t count,
                                     const void* in_val)
        = 0;

    /// @brief Read memory callback.
    ///
    /// @param[in]  block_id               Block ID of the memory.
    /// @param[in]  mem_address            Memory address in the block.
    /// @param[in]  mem_width              Memory entry width in byte resolution.
    /// @param[in]  mem_entries            Number of consecutive entries to be read.
    /// @param[out] out_val                Return value destination buffer.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status read_memory(la_block_id_t block_id,
                                  la_entry_addr_t mem_address,
                                  la_entry_width_t mem_width,
                                  size_t mem_entries,
                                  void* out_val)
        = 0;

    /// @brief Write memory callback.
    ///
    /// @param[in]  block_id               Block ID of the memory.
    /// @param[in]  mem_address            Memory address in the block.
    /// @param[in]  mem_width              Memory entry width in byte resolution.
    /// @param[in]  mem_entries            Number of consecutive entries to be read.
    /// @param[out] in_val                 Value to be written.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status write_memory(la_block_id_t block_id,
                                   la_entry_addr_t mem_address,
                                   la_entry_width_t mem_width,
                                   size_t mem_entries,
                                   const void* in_val)
        = 0;

    /// @brief Add property callback.
    ///
    /// @param[in] key                     Property key.
    /// @param[in] value                   Property value.
    ///
    /// @retval    LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval    LA_STATUS_EINVAL     One of the parameters is invalid.
    /// @retval    LA_STATUS_EUNKNOWN   An unknown error occurred.
    virtual la_status add_property(std::string key, std::string value);

protected:
    const pacific_tree* m_pacific_tree = nullptr;
    const gibraltar_tree* m_gibraltar_tree = nullptr;
    const asic4_tree* m_asic4_tree = nullptr;
    const asic3_tree* m_asic3_tree = nullptr;
    const asic5_tree* m_asic5_tree = nullptr;
};

} // namespace silicon_one

#endif // __DEVICE_SIMULATOR_H__
