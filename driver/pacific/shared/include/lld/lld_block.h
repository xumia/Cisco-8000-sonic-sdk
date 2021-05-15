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

#ifndef __LEABA_LLD_BLOCK_H__
#define __LEABA_LLD_BLOCK_H__

#include <map>
#include <memory>
#include <vector>

#include "api/types/la_common_types.h"

#include "lld/lld_fwd.h"

struct json_t;

namespace silicon_one
{

class lld_register;
class lld_memory;
class ll_device;

/// @brief Base struct for blocks with registers and memories.
class lld_block : public std::enable_shared_from_this<lld_block>
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    typedef std::vector<lld_register_scptr> lld_register_vec_t;
    typedef std::vector<lld_memory_scptr> lld_memory_vec_t;
    typedef std::vector<lld_block_scptr> lld_block_vec_t;

    // Identifies a specific block instance within a same-block-type array.
    typedef la_uint_t block_instance_t;
    static const block_instance_t BLOCK_INSTANCE_INVALID = (block_instance_t)(-1);

    struct block_indices_struct {
        la_slice_pair_id_t slice_pair_index;
        la_slice_id_t slice_index;
        la_ifg_id_t ifg_index;
        block_instance_t block_index;
    };

    lld_block(size_t register_step, bool need_memory_padding, la_device_revision_e device_revision)
        : m_block_id(LA_BLOCK_ID_INVALID),
          m_register_step(register_step),
          m_need_memory_padding(need_memory_padding),
          m_blocks(),
          m_revision(device_revision)
    {
    }

    virtual ~lld_block() = default;

    /// @brief Returns the block ID.
    ///
    /// @return The block ID.
    la_block_id_t get_block_id() const
    {
        return m_block_id;
    }

    /// @brief Get absolute address of this block's entry.
    ///
    /// @return Absolute address.
    uint64_t get_absolute_address(la_entry_addr_t addr) const;

    /// @brief Check if block is valid.
    ///
    /// @return true if valid, false if not.
    bool is_valid() const
    {
        return (m_block_id != LA_BLOCK_ID_INVALID);
    }

    /// @brief Returns the revision of the device that this block belongs to.
    ///
    /// @return The device's revision.
    la_device_revision_e get_revision() const
    {
        return m_revision;
    }

    /// @brief Returns the block instance name.
    ///
    /// @return The block instance name.
    std::string get_name() const;

    /// @brief Returns the block template (LBR) name.
    ///
    /// @return The block template name.
    std::string get_template_name() const;

    /// @brief Initializes the block object.
    ///
    /// @param[in]  block_id     	Block ID.
    /// @param[in]  lbr_name     	Block's LBR.
    /// @param[in]  name         	Block name.
    /// @param[in]  block_indices 	Holds  slice pair/slice/ifg/block indices (as appears in sw path ('name')).
    void initialize(la_block_id_t block_id, const char* lbr_name, const std::string& name, block_indices_struct block_indices);

    /// @brief Initializes the block object.
    ///
    /// @param[in]  block_id     	Block ID.
    /// @param[in]  lbr_name     	Block's LBR.
    /// @param[in]  name         	Block name.
    void initialize(la_block_id_t block_id, const char* lbr_name, const std::string& name);

    /// @brief Returns a pointer to a register object based on its address.
    ///
    /// @param[in]  addr    The address of the register.
    ///
    /// @return The pointer to the register object based on its address.
    lld_register_scptr get_register(la_entry_addr_t addr) const;

    /// @brief Returns a pointer to a memory object based on an address of one of its lines.
    ///
    /// @param[in]  addr    The address of a memory line.
    ///
    /// @return The pointer to the memory object based on the address of one of its lines.
    lld_memory_scptr get_memory(la_entry_addr_t addr) const;

    /// @brief Return a container of all valid leaf blocks.
    ///
    /// @return Vector of all valid blocks under this hierarchy.
    lld_block_vec_t get_leaf_blocks() const;

    /// @brief Returns the distance between registers in the current block.
    ///
    /// @retval The distance between registers in the current block.
    size_t get_register_step() const
    {
        return m_register_step;
    }

    /// @brief Returns true iff the block requires memory padding
    ///
    /// @retval True iff the block requires memory padding
    bool need_memory_padding() const
    {
        return m_need_memory_padding;
    }

    /// @brief Return a container of all direct sub-blocks.
    ///
    /// @retval Vector of all sub-blocks.
    lld_block_vec_t get_blocks() const
    {
        return m_blocks;
    }

    /// @brief Returns a container of all block's registers.
    ///
    /// @return Vector of registers.
    lld_register_vec_t get_registers() const;

    /// @brief Returns a container of all block's memories.
    ///
    /// @return Vector of memories.
    lld_memory_vec_t get_memories() const;

    /// @brief Returns the block's indices (slice pair, slice, ifg, block instance)
    ///
    /// @return Struct of block indices
    const block_indices_struct& get_block_indices() const;

protected:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lld_block() = default;

    typedef std::map<la_entry_addr_t, lld_register_scptr> map_addr_to_register_t;
    typedef std::map<la_entry_addr_t, lld_memory_scptr> map_addr_to_memory_t;

    /// Block ID of the block
    la_block_id_t m_block_id;

    /// Block instance name
    std::string m_name;

    /// Block LBR name
    std::string m_lbr_name;

    /// Distance between registers in the LBR file
    size_t m_register_step;

    /// True iff the block requires memory padding
    bool m_need_memory_padding;

    /// Map of registers keyed by their address.
    map_addr_to_register_t m_registers;

    /// Map of memories keyed by their base address.
    map_addr_to_memory_t m_memories;

    /// Vector of all sub-blocks.
    lld_block_vec_t m_blocks;

    // The device revision this block blongs to.
    la_device_revision_e m_revision;

    // block indices as appears in the sw path ('m_name')
    block_indices_struct m_block_indices;
};

} // namespace silicon_one
#endif // __LEABA_LLD_BLOCK_H__
