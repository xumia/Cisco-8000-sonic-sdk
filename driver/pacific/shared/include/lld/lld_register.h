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

#ifndef __LEABA_LLD_REGISTER_H__
#define __LEABA_LLD_REGISTER_H__

#include <string>
#include <vector>

#include "common/bit_vector.h"
#include "common/gen_operators.h"
#include "common/weak_ptr_unsafe.h"

#include "lld/lld_fwd.h"
#include "lld/lld_storage.h"

namespace silicon_one
{

/// @brief Leaba register types
enum class lld_register_type_e {
    CONFIG = 0,     ///< General purpose register. Non-volatile.
    INTERRUPT_TEST, ///< Register that triggers interrupts. Non-volatile.
    INTERRUPT_MASK, ///< Register that masks interrupts. Non-volatile.
    INTERRUPT,      ///< Register that indicates that an interrupt occured. Volatile.
    EXTERNAL,       ///< General purpose register. Volatile.
    READONLY,       ///< General purpose register. Volatile. Cannot be written to.
    HISTOGRAM,      ///< A document-only register. Does not represent a real register.

    LAST = HISTOGRAM
};

/// @brief Leaba register information
struct lld_register_desc_t {
    la_entry_addr_t addr;                      ///< Address of an instance
    la_entry_width_t width;                    ///< Width in bytes of single entry
    uint16_t instances;                        ///< Number of instances of same register
    std::string name;                          ///< Name of the register
    std::string desc;                          ///< Description of the register
    lld_register_type_e type;                  ///< The type of register
    bool writable;                             ///< Whether this register can be written to
    bool include_counter;                      ///< At least one counter field in the register
    bool include_status;                       ///< At least one status field in the register
    std::vector<uint8_t> default_value;        ///< The default value in hexadecimal representation
    uint32_t width_in_bits;                    ///< Width of a single entry in bits
    instance_allocation_e instance_allocation; ///< Register's instance allocation

    std::vector<lld_field_desc> fields; ///< Bit fields

    /// @brief Indicates whether the register is volatile.
    ///
    /// Volatile register can change between reads/writes.
    ///
    /// @see #silicon_one::lld_register_type_e
    ///
    /// @return true if the register is volatile, false otherwise.
    bool is_volatile() const
    {
        // array that indicates, for each register type, whether its volatile
        const bool is_volatile_type[] = {[(int)lld_register_type_e::CONFIG] = false,
                                         [(int)lld_register_type_e::INTERRUPT_TEST] = false,
                                         [(int)lld_register_type_e::INTERRUPT_MASK] = false,
                                         [(int)lld_register_type_e::INTERRUPT] = true,
                                         [(int)lld_register_type_e::EXTERNAL] = true,
                                         [(int)lld_register_type_e::READONLY] = true,
                                         [(int)lld_register_type_e::HISTOGRAM] = true};
        return is_volatile_type[(int)type];
    }
};

/// @brief Register class that saves shadow data
class lld_register : public lld_storage
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    static constexpr la_entry_addr_t MASTER_INTERRUPT = 0x0;               ///< Block's master interrupt
    static constexpr la_entry_addr_t MEM_PROTECT_INTERRUPT = 0x1;          ///< Memory protection interrupt
    static constexpr la_entry_addr_t MEM_PROTECT_INTERRUPT_TEST = 0x2;     ///< Memory protection interrupt test
    static constexpr la_entry_addr_t ECC_1B_ERR_INTERRUPT_MASK = 0x3;      ///< ECC 1b memory protection interrupt masks
    static constexpr la_entry_addr_t ECC_2B_ERR_INTERRUPT_MASK = 0x4;      ///< ECC 2b memory protection interrupt masks
    static constexpr la_entry_addr_t PARITY_ERR_INTERRUPT_MASK = 0x5;      ///< Parity memory protection interrupt masks
    static constexpr la_entry_addr_t ECC_1B_ERR_INITIATE = 0x30;           ///< ECC 1b error initiate
    static constexpr la_entry_addr_t ECC_2B_ERR_INITIATE = 0x31;           ///< ECC 2b error initiate
    static constexpr la_entry_addr_t PARITY_ERR_INITIATE = 0x32;           ///< Parity error initiate
    static constexpr la_entry_addr_t MEM_PROTECT_ERR_STATUS = 0x33;        ///< Memory protection error status
    static constexpr la_entry_addr_t SELECTED_SER_ERROR_INFO = 0x34;       ///< Address and type of error of selecte memory
    static constexpr la_entry_addr_t SER_ERROR_DEBUG_CONFIGURATION = 0x35; ///< Memory selector & an error reset
    static constexpr la_entry_addr_t ECC_1B_ERR_DEBUG = 0x36;              ///< ECC 1b error counter
    static constexpr la_entry_addr_t ECC_2B_ERR_DEBUG = 0x37;              ///< ECC 2b error counter
    static constexpr la_entry_addr_t PARITY_ERR_DEBUG = 0x38;              ///< Parity error counter
    static constexpr la_entry_addr_t RSTN = 0x45;                          ///< Reset

    /// @brief Private register constructor.
    ///
    /// @param[in]  parent_block     Pointer to the block of this register.
    /// @param[in]  name             Register name w/o block name.
    /// @param[in]  register_desc    Register descriptor.
    /// @param[in]  is_valid         Whether this register is valid.
    /// @param[in]  index            Index in an array.
    lld_register(const lld_block_wcptr& parent_block,
                 const std::string& name,
                 const lld_register_desc_t& register_desc,
                 bool is_valid,
                 size_t index = 0);

    /// @brief Register constructor.
    ///
    /// Register contructor for a register in an array. Updates the addr field based on the index.
    ///
    /// @param[in]  parent_block     Pointer to the block of this register.
    /// @param[in]  name             Register name w/o block name.
    /// @param[in]  register_desc    Register descriptor.
    /// @param[in]  index            Index in an array.
    /// @param[in]  is_valid         Whether this register is valid.
    lld_register(const lld_block_wcptr& parent_block,
                 const std::string& name,
                 const lld_register_desc_t& register_desc,
                 size_t index,
                 bool is_valid);

    /// @brief Returns the register information struct.
    ///
    /// @return The register information struct.
    const lld_register_desc_t* get_desc() const
    {
        return &m_register_desc;
    }

    /// @brief Get register field descriptor.
    ///
    /// @param[in]  pos     Any bit position in a field, [lsb:msb]
    ///
    /// @return Field descriptor.
    lld_field_desc get_field(size_t pos) const
    {
        return lld_storage::get_field(m_register_desc.fields, pos);
    }

    /// @brief Returns absolute address of the register including block offset.
    ///
    /// @retval absolute address
    size_t get_absolute_address() const override;

    /// @brief Writes a value to the shadow.
    ///
    /// Copies the value in the input byte array into the shadow.
    ///
    /// @param[in]  in_val_sz   The number of bytes from the input byte array to write to the shadow.
    /// @param[in]  in_val      Input byte array
    void write_shadow(size_t in_val_sz, const void* in_val) const;

    /// @brief Reads a value from the shadow into a byte array.
    ///
    /// Copies the value from the shadow into the output byte array.
    ///
    /// @param[in]  out_val_sz  The size of the output byte array
    /// @param[out] out_val     Output byte array
    ///
    /// @retval     LA_STATUS_SUCCESS       The shadow value was successfully read.
    /// @retval     LA_STATUS_ENOTFOUND     The shadow value was not read. The register is volatile.
    /// @retval     LA_STATUS_EINVAL        The shadow value was not read. The output buffer is too small.
    la_status read_shadow(size_t out_val_sz, void* out_val) const;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lld_register() = default;

    /// Register information struct.
    lld_register_desc_t m_register_desc;
};

using lld_register_sptr_ops = handle_ops<lld_register_sptr>;
using lld_register_scptr_ops = handle_ops<const lld_register_scptr>;

/// @brief Register array class.
///
/// Represents an array of registers of the same type, and provides general info on that type of registers.
class lld_register_array_container
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Register array constructor.
    ///
    /// Builds an array of registers and updates the address of each register based on its index in the array. Stores the parent
    /// block and register information struct both in self and in each of the registers.
    ///
    /// @param[in]  parent_block     Pointer to the block of this register.
    /// @param[in]  name             Register array name w/o block name.
    /// @param[in]  register_desc    Register descriptor.
    /// @param[in]  size             Size of the array.
    /// @param[in]  is_valid         Whether the array is valid.
    lld_register_array_container(const lld_block_wcptr& parent_block,
                                 const std::string& name,
                                 const lld_register_desc_t& register_desc,
                                 size_t size,
                                 bool is_valid);

    /// @brief Index operator.
    /// @return The i-th item in the array
    const lld_register_sptr operator[](size_t idx) const
    {
        return m_array[idx];
    };

    /// @brief Index operator.
    /// @return The i-th item in the array
    lld_register_sptr operator[](size_t idx)
    {
        return m_array[idx];
    };

    /// @brief Returns the block ID.
    ///
    /// @return The block ID.
    la_block_id_t get_block_id() const;

    /// @brief Get the parent block.
    ///
    /// @see #silicon_one::lld_block
    ///
    /// @return The block parent block.
    lld_block_wcptr get_block() const
    {
        return m_parent_block;
    }

    /// @brief Check if resource is valid.
    ///
    /// @return true if valid, false if not.
    bool is_valid() const
    {
        return m_array[0]->is_valid();
    }

    /// @brief Returns the register information struct.
    ///
    /// @return The register information struct.
    const lld_register_desc_t* get_desc() const
    {
        return &m_register_desc;
    }

    /// @brief Returns the size of the array.
    ///
    /// @return The size of the array.
    size_t size() const;

    void write_shadow(size_t first, size_t count, const void* in_val) const;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lld_register_array_container() = default;

    /// @brief Parent block pointer.
    lld_block_wcptr m_parent_block;

    /// @brief Register information struct.
    lld_register_desc_t m_register_desc;

    /// @brief Array of registers.
    std::vector<lld_register_sptr> m_array;
};

} // namespace silicon_one
#endif // __LEABA_LLD_REGISTER_H__
