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

#ifndef __LEABA_LLD_MEMORY_H__
#define __LEABA_LLD_MEMORY_H__

#include <string>
#include <vector>

#include "common/bit_vector.h"
#include "common/gen_operators.h"
#include "common/weak_ptr_unsafe.h"

#include "lld/lld_fwd.h"
#include "lld/lld_storage.h"

namespace silicon_one
{

/// @brief Leaba memory types
enum class lld_memory_type_e : uint8_t {
    CONFIG = 0, ///< Non-volatile memory
    DYNAMIC,    ///< Volatile memory
    DOC_ONLY,   ///< Memory entry that references an already defined memory (existing address) but provides a
                /// different fields layout

    LAST = DOC_ONLY
};

/// @brief Memory sub-type.
///
/// Extra information about memory's implementation.
enum class lld_memory_subtype_e : uint8_t {
    NONE = 0,      ///< Default subtype
    X_Y_TCAM,      ///< X-Y TCAM, used in Pacific
    KEY_MASK_TCAM, ///< KEY-MASK TCAM, used in Gibraltar
    REG_TCAM,      ///< Register-based TCAM
    REG_CAM,       ///< Register-based CAM
};

/// @brief Leaba memory protection types
enum class lld_memory_protection_e : uint8_t {
    NONE = 0,   ///< No memory protection
    ECC,        ///< ECC memory protection
    EXT_ECC,    ///< External ECC memory protection
    PARITY,     ///< Parity memory protection
    EXT_PARITY, ///< Extername parity memory protection

    LAST = EXT_PARITY
};

/// @brief Leaba memory information
struct lld_memory_desc_t {
    la_entry_addr_t addr;                      ///< Address of an instance
    la_entry_width_t width_bits;               ///< Logical width in bits of single entry
    la_entry_width_t width_total;              ///< Total width in bytes of single entry (with ECC bits)
    la_entry_width_t width_total_bits;         ///< Total width in bits of single entry (with ECC bits)
    uint32_t entries;                          ///< Number of entries
    uint16_t instances;                        ///< Number of instances of same memory
    std::string wrapper;                       ///< Memory wrapper name
    std::string name;                          ///< Name of the memory
    std::string desc;                          ///< Description of the memory
    lld_memory_type_e type;                    ///< The type of memory
    lld_memory_subtype_e subtype;              ///< The subtype of memory
    lld_memory_protection_e protection;        ///< Memory protection of this memory
    bool readable;                             ///< Whether this memory can be read from
    bool writable;                             ///< Whether this memory can be written to
    instance_allocation_e instance_allocation; ///< Memory's instance allocation

    std::vector<lld_field_desc> fields; ///< Bit fields

    /// @brief Offset between successive instances of a memory array
    enum { ARRAY_INSTANCE_OFFSET = 0x100000 };

    /// @brief Indicates whether the memory is volatile.
    ///
    /// Volatile memory can change between reads/writes.
    ///
    /// @see #silicon_one::lld_memory_type_e
    ///
    /// @return true if the memory is volatile, false otherwise.
    bool is_volatile() const
    {
        // array that indicates, for each memory type, whether its volatile
        const bool is_volatile_type[] = {
                [(int)lld_memory_type_e::CONFIG] = false,
                [(int)lld_memory_type_e::DYNAMIC] = true,
                [(int)lld_memory_type_e::DOC_ONLY] = true,
        };

        return is_volatile_type[(int)type];
    };
};

/// @brief Memory class that saves shadow data
class lld_memory : public lld_storage
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Memory constructor.
    ///
    /// @param[in]  parent_block    Pointer to the block of this memory.
    /// @param[in]  name            Memory name w/o block name.
    /// @param[in]  memory_desc     Memory descriptor.
    /// @param[in]  is_valid        Whether this memory is valid.
    /// @param[in]  index           Index in an array
    lld_memory(const lld_block_wcptr& parent_block,
               const std::string& name,
               const lld_memory_desc_t& memory_desc,
               bool is_valid,
               size_t index);

    /// @brief Memory constructor.
    ///
    /// @param[in]  parent_block    Pointer to the block of this memory.
    /// @param[in]  name            Memory name w/o block name.
    /// @param[in]  memory_desc     Memory descriptor.
    /// @param[in]  is_valid        Whether this memory is valid.
    lld_memory(const lld_block_wcptr& parent_block, const std::string& name, const lld_memory_desc_t& memory_desc, bool is_valid);

    /// @brief Memory constructor.
    ///
    /// Memory contructor for a memory in an array. Updates the addr field based on the index.
    ///
    /// @param[in]  parent_block    Pointer to the block of this register.
    /// @param[in]  name            Memory name w/o block name.
    /// @param[in]  memory_desc     Memory descriptor.
    /// @param[in]  index           Index in an array.
    /// @param[in]  is_valid        Whether this memory is valid.
    lld_memory(const lld_block_wcptr& parent_block,
               const std::string& name,
               const lld_memory_desc_t& memory_desc,
               size_t index,
               bool is_valid);

    /// @brief Returns the memory information struct.
    ///
    /// @return The memory information struct.
    const lld_memory_desc_t* get_desc() const
    {
        return &m_memory_desc;
    }

    /// @brief Get memory field descriptor.
    ///
    /// @param[in]  pos     Any bit position in a field, [lsb:msb]
    ///
    /// @return Field descriptor.
    lld_field_desc get_field(size_t pos) const
    {
        return lld_storage::get_field(m_memory_desc.fields, pos);
    }

    /// @brief Returns absolute address of the memory including block offset.
    ///
    /// @retval absolute address
    size_t get_absolute_address() const override;

    /// @brief Write a value to the shadow.
    ///
    /// Copies the value in the input byte array into the shadow at memory lines in the range:
    ///     [first_entry, first_entry + count - 1]
    ///
    /// @param[in]  first_entry         The first memory line to write.
    /// @param[in]  count               The number of lines to write.
    /// @param[in]  in_val              Input byte array
    void write_shadow(size_t first_entry, size_t count, const void* in_val) const;

    /// @brief Write a value to entries in range.
    ///
    /// @param[in]  first_entry     The first memory line to write.
    /// @param[in]  count           The number of lines to write.
    /// @param[in]  in_bv           Value to fill with.
    void fill_shadow(size_t first_entry, size_t count, const bit_vector& in_bv) const;

    /// @brief Read value from the shadow
    ///
    /// Copies the value from the shadow at memory lines in the range:
    ///     [first_entry, first_entry + count - 1]
    ///
    /// @param[in]  first_entry         The first line to read.
    /// @param[in]  count               The number of lines to read.
    /// @param[out] out_val             Output byte array.
    ///
    /// @retval     LA_STATUS_SUCCESS       The shadow value was successfully read.
    /// @retval     LA_STATUS_ENOTFOUND     The shadow value was not read. The memory is volatile.
    /// @retval     LA_STATUS_EINVAL        The shadow value was not read. The output buffer is too small, or the requested
    ///                                     entries don't exist.
    /// @retval     LA_STATUS_EUNKNOWN      The shadow value was not read. Internal problem.
    la_status read_shadow(size_t first_entry, size_t count, void* out_val) const;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lld_memory() = default;

    /// @brief Writes a value to the shadow of a memory line.
    ///
    /// @param[in]  mem_entry_idx   The memory line number.
    /// @param[in]  in_val          Input byte array
    void write_shadow_entry(size_t mem_entry_idx, const void* in_val) const;

    /// @brief Reads a value from the shadow of a memory line into a byte array.
    ///
    /// @param[in]  mem_entry_idx           The memory line number.
    /// @param[in]  out_val                 Output byte array.
    ///
    /// @retval     None
    void read_shadow_entry(size_t mem_entry_idx, void* out_val) const;

    /// Memory information struct.
    lld_memory_desc_t m_memory_desc;
};

using lld_memory_sptr_ops = handle_ops<lld_memory_sptr>;
using lld_memory_scptr_ops = handle_ops<lld_memory_scptr>;

/// @brief Memory array class.
///
/// Represents an array of memories of the same type, and provides general info on that type of memories.
class lld_memory_array_container
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Memory array constructor.
    ///
    /// Builds an array of memories and updates the address of each memory based on its index in the array. Stores the parent
    /// block and memory information struct both in self and in each of the memories.
    ///
    /// @param[in]  parent_block    Pointer to the block of this memory.
    /// @param[in]  name            Memory array name w/o block name.
    /// @param[in]  memory_desc     Memory descriptor.
    /// @param[in]  size            Size of the array.
    /// @param[in]  is_valid        Whether the array is valid.
    lld_memory_array_container(const lld_block_wcptr& parent_block,
                               const std::string& name,
                               const lld_memory_desc_t& memory_desc,
                               size_t size,
                               bool is_valid);

    /// @brief Index operator.
    /// @return The i-th item in the array
    const lld_memory_sptr operator[](size_t idx) const
    {
        return m_array[idx];
    };

    /// @brief Index operator.
    /// @return The i-th item in the array
    lld_memory_sptr operator[](size_t idx)
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

    /// @brief Returns the memory information struct.
    ///
    /// @return The memory information struct.
    const lld_memory_desc_t* get_desc() const
    {
        return &m_memory_desc;
    }

    /// @brief Returns the size of the array.
    ///
    /// @return The size of the array.
    size_t size() const;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lld_memory_array_container() = default;

    /// @brief Parent block pointer.
    lld_block_wcptr m_parent_block;

    /// @brief Memory information struct.
    lld_memory_desc_t m_memory_desc;

    /// @brief Array of memories.
    std::vector<lld_memory_sptr> m_array;
};

} // namespace silicon_one
#endif // __LEABA_LLD_MEMORY_H__
