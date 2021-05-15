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

#ifndef __DSIM_CONFIG_INTERFACE_H__
#define __DSIM_CONFIG_INTERFACE_H__
#include <stdint.h>
#include <stddef.h>
#include <string>
#include <utility> // std::pair
#include <vector>
#include <map>
#include "utils/list_macros.h"

namespace dsim
{

static constexpr uint64_t MEMORY_BASE_ADDRESS{0x100000};

// clang-format off
#define DSIM_STATUS_E(list_macro) \
    list_macro(DSIM_STATUS_SUCCESS,         0),  /* ///< Operation completed successfully. */ \
    list_macro(DSIM_STATUS_EEXIST,          17), /* ///< Key already exists in table. */ \
    list_macro(DSIM_STATUS_EINVAL,          22), /* ///< Invalid parameter given. */ \
    list_macro(DSIM_STATUS_ENOTFOUND,       25), /* ///< Entry requested not found. */ \
    list_macro(DSIM_STATUS_ENOTIMPLEMENTED, 26), /* ///< API is not implemented. */ \
    list_macro(DSIM_STATUS_EUNKNOWN,        27), /* ///< Unknown error occurred while attempting to perform requested operation. */ \
    list_macro(DSIM_STATUS_ESIZE,           28), /* ///< Wrong buffer size */ \
    list_macro(DSIM_STATUS_ENOTINITIALIZED, 29), /* ///< Object is not initialized */ \
    list_macro(DSIM_STATUS_EVERSION,        30), /* ///< Unsupported version */ \
    list_macro(DSIM_STATUS_ESERIALIZE,      31), /* ///< Serialize error */ \
    list_macro(DSIM_STATUS_EDESERIALIZE,    32), /* ///< Deserialize error */ \

// clang-format off
enum dsim_status_e { DSIM_STATUS_E(LIST_MACRO_FIXED_ENUM_VALUE) };

//
// Convert dsim_status_e to a string.
//
static inline const std::string to_string(enum dsim_status_e v) {
    static std::map<enum dsim_status_e, std::string> enum_map;
    if (enum_map.empty()) {
        std::initializer_list<std::pair<std::string, int> > init = { DSIM_STATUS_E(LIST_MACRO_FIXED_ENUM_STD_PAIR) };
        static const std::vector<std::pair<std::string, int> > vals(init);
        for (const auto & val : vals) {
            enum_map[(enum dsim_status_e)val.second] = val.first;
        }
    }
    if (enum_map.find(v) == enum_map.end()) {
        return std::string("DSIM_STATUS_EUNKNOWN") + ":" + std::to_string((int)v);
    }
    return enum_map[v];
}

class dsim_config_interface
{
public:
    virtual ~dsim_config_interface()
    {
    }
    /// @brief Write register callback.
    ///
    /// @param[in]  block_id               Block ID of the register.
    /// @param[in]  reg_address            Register address in the block.
    /// @param[in]  reg_width              Width in byte resolution.
    /// @param[in]  count                  Number of consecutive entries to be written.
    /// @param[out] out_val                Return value destination buffer.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e write_register(uint32_t block_id,
                                         uint32_t reg_address,
                                         uint16_t reg_width,
                                         size_t count,
                                         const void* in_val)
        = 0;
    /// @brief Write register by name callback.
    ///
    /// @param[in]  reg_name               Register name
    /// @param[in]  reg_index              Register index
    /// @param[in]  reg_width              Width in byte resolution.
    /// @param[in]  count                  Number of consecutive entries to be written.
    /// @param[out] out_val                Return value destination buffer.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e write_register_by_name(const std::string& name,
                                                 size_t reg_index,
                                                 uint16_t reg_width,
                                                 size_t count,
                                                 const void* in_val)
        = 0;
    /// @brief Read register callback.
    ///
    /// @param[in]  block_id               Block ID of the register.
    /// @param[in]  reg_address            Register address in the block.
    /// @param[in]  reg_width              Width in byte resolution.
    /// @param[in]  count                  Number of consecutive entries to be read.
    /// @param[out] out_val                Return value destination buffer.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e read_register(uint32_t block_id, uint32_t reg_address, uint16_t reg_width, size_t count, void* out_val)
        = 0;
    /// @brief Read register by name callback.
    ///
    /// @param[in]  reg_name               Register name
    /// @param[in]  reg_index              Register index
    /// @param[in]  reg_width              Width in byte resolution.
    /// @param[in]  count                  Number of consecutive entries to be read.
    /// @param[out] out_val                Return value destination buffer.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e read_register_by_name(const std::string& name,
                                                size_t reg_index,
                                                uint16_t reg_width,
                                                size_t count,
                                                void* out_val)
        = 0;
    /// @brief Write memory callback.
    ///
    /// @param[in]  block_id               Block ID of the memory.
    /// @param[in]  mem_address            Memory address in the block.
    /// @param[in]  mem_width              Memory entry width in byte resolution.
    /// @param[in]  mem_entries            Number of consecutive entries to be written.
    /// @param[out] in_val                 Value to be written.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e write_memory(uint32_t block_id,
                                       uint32_t mem_address,
                                       uint16_t mem_width,
                                       size_t mem_entries,
                                       const void* in_val)
        = 0;
    /// @brief Write memory callback.
    ///
    /// @param[in]  mem_name               Name of the block ID of the memory.
    /// @param[in]  slice_id               Slice ID
    /// @param[in]  mem_entry              Memory address in the block.
    /// @param[in]  mem_width              Memory entry width in byte resolution.
    /// @param[in]  mem_entries            Number of consecutive entries to be written.
    /// @param[out] in_val                 Value to be written.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e write_memory_by_name(const std::string& mem_name,
                                               size_t mem_index,
                                               uint32_t mem_entry,
                                               uint16_t mem_width,
                                               size_t mem_entries,
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
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e read_memory(uint32_t block_id,
                                      uint32_t mem_address,
                                      uint16_t mem_width,
                                      size_t mem_entries,
                                      void* out_val)
        = 0;
    /// @brief Read memory callback.
    ///
    /// @param[in]  mem_name               Name of the block ID of the memory.
    /// @param[in]  slice_id               Slice ID
    /// @param[in]  mem_entry              Memory address in the block.
    /// @param[in]  mem_width              Memory entry width in byte resolution.
    /// @param[in]  mem_entries            Number of consecutive entries to be read.
    /// @param[out] out_val                Return value destination buffer.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e read_memory_by_name(const std::string& mem_name,
                                              size_t mem_index,
                                              uint32_t mem_entry,
                                              uint16_t mem_width,
                                              size_t mem_entries,
                                              void* out_val)
        = 0;

    /// @brief Add property callback.
    ///
    /// @param[in] key                     Property key.
    /// @param[in] value                   Property value.
    ///
    /// @retval    DSIM_STATUS_SUCCESS    Operation completed successfully.
    /// @retval    DSIM_STATUS_EINVAL     One of the parameters is invalid.
    /// @retval    DSIM_STATUS_EUNKNOWN   An unknown error occurred.
    virtual dsim_status_e add_property(std::string key, std::string value) = 0;

protected:
    /// @brief Calculate full key(address) from the block ID and address
    ///
    /// @param[in]  block_id               Block ID of the memory.
    /// @param[in]  address                Memory address in the block.
    ///
    /// @retval     Full register/memory address
    uint64_t calculate_key(uint64_t block_id, uint64_t address)
    {
        return (uint64_t)block_id << 32 | (uint64_t)address;
    }
};

} // namespace dsim
#endif //__DSIM_CONFIG_INTERFACE_H__
