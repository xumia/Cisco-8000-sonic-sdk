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

#ifndef __LEABA_LLD_STORAGE_H__
#define __LEABA_LLD_STORAGE_H__

#include <stdint.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

#include "api/types/la_common_types.h"
#include "common/bit_vector.h"
#include "lld/lld_fwd.h"
#include "lld/lld_init_expression.h"

namespace silicon_one
{

/// @brief Leaba storage field types
enum class lld_storage_field_type_e : uint8_t {
    CONFIG,         ///< General purpose register.
    INTERRUPT_TEST, ///< trigger interrput
    INTERRUPT_MASK, ///< masked interrupt
    INTERRUPT,      ///< interrupt status
    EXTERNAL,       ///< General purpose
    STATUS,         ///< General purpose
    COUNTER,        ///< various counters fields
    MAX_WMK,        ///< Maximum Watermark
    MIN_WMK,        ///< Minimum Watermark
    CAPTURE,        ///< Debug Capture utility fields
    EVENT,          ///< various event status fields
    MIXED,          ///< Mix of different types
    LAST = MIXED
};

/// @brief Leaba register/memory field
struct lld_field_desc {
    std::string name;
    uint32_t lsb;
    uint32_t width_in_bits;
    lld_storage_field_type_e type;
    const lld_field_init_expression_data* init_expression_data;
};

class lld_register;
class lld_memory;

/// @brief Abstract storage class serving as base for lld_register, lld_memory objects.
class lld_storage : public std::enable_shared_from_this<lld_storage>
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Leaba storage types
    enum class lld_storage_type_e : uint8_t {
        REGISTER = 0, ///< Registers
        MEMORY,       ///< memory

        LAST = MEMORY
    };

    /// @brief Storage constructor.
    ///
    /// @param[in]  parent_block    Pointer to the block of this storage.
    /// @param[in]  name            Storage name w/o block name.
    /// @param[in]  initial_value   A bit_vector that is used as initial value of this storage object.
    /// @param[in]  is_valid        Whether this storage is valid in the current device revision.
    /// @param[in]  type            storage type of this block (register or memory)
    /// @param[in]  index           Index in an array
    lld_storage(const lld_block_wcptr& parent_block,
                const std::string& name,
                const bit_vector& initial_value,
                bool is_valid,
                lld_storage_type_e type,
                size_t index)
        : m_parent_block(parent_block), m_name(name), m_shadow(initial_value), m_is_valid(is_valid), m_type(type), m_index(index)
    {
    }

    // lld_storage destructor.
    virtual ~lld_storage() = default;

    /// @brief Returns the block ID.
    ///
    /// @return The block ID.
    la_block_id_t get_block_id() const;

    /// @brief Get the parent block.
    ///
    /// @see #silicon_one::lld_block
    ///
    /// @return The block parent block.
    const lld_block_scptr get_block() const
    {
        return m_parent_block.lock();
    }

    /// @brief Returns hierarchical name of this object.
    ///
    /// For example, hierarchical name = "slice[0].ifg[0].sch.last_data".
    ///              short name = "last_data".
    ///
    /// @return Storage hierarchical name.
    std::string get_name() const;

    /// @brief Returns short name of this object.
    ///
    /// For example, hierarchical name = "slice[0].ifg[0].sch.last_data".
    ///              short name = "last_data".
    ///
    /// @return Storage name.
    std::string get_short_name() const
    {
        return m_name;
    }

    /// @brief Check if resource is valid.
    ///
    /// @return true if valid, false if not.
    bool is_valid() const;

    /// @brief Returns absolute address of this object including block offset.
    ///
    /// @retval absolute address
    virtual size_t get_absolute_address() const = 0;

    /// @brief Returns storage type
    ///
    /// @retval storage type
    lld_storage_type_e get_storage_type() const
    {
        return m_type;
    }

    bool is_register() const
    {
        return (m_type == lld_storage_type_e::REGISTER);
    }

    /// @brief Get storage field descriptor.
    ///
    /// @param[in]  fields  A vector of all field descriptors for this storage.
    /// @param[in]  pos     Any bit position in a field, [lsb:msb]
    ///
    /// @return Field descriptor.
    static lld_field_desc get_field(std::vector<lld_field_desc> const& fields, size_t pos);

    /// @brief Returns index in storage array
    ///
    /// @retval index in storage array
    size_t get_index() const;

protected:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lld_storage() = default;

    /// Parent block pointer.
    lld_block_wcptr m_parent_block;

    /// Storage instance name w/o block.
    std::string m_name;

    /// Shadow copy of the device's storage value.
    mutable bit_vector m_shadow;

    /// Whether this storage is valid.
    bool m_is_valid;

    lld_storage_type_e m_type;

    size_t m_index;
};

} // namespace silicon_one
#endif // __LEABA_LLD_STORAGE_H__
