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

#ifndef __ENGINE_BLOCK_MAPPER_H__
#define __ENGINE_BLOCK_MAPPER_H__

#include "api/types/la_common_types.h"
#include "common/la_status.h"

#include "lld/gibraltar_tree.h"
#include "lld/lld_block.h"
#include "lld/lld_memory.h"

#include "nplapi/npl_enums.h"
#include "ra_enums.h"

#include <vector>

namespace silicon_one
{

/// @brief Mapper of database identifiers into a list of HW blocks in the given physical device.
class engine_block_mapper
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    static const size_t ASIC_MAX_SLICES_PER_DEVICE_NUM = 6;
    static const size_t NUM_SLICE_PAIRS_PER_DEVICE = ASIC_MAX_SLICES_PER_DEVICE_NUM / 2;
    static const size_t NUM_IFGS_PER_SLICE = 2;

    typedef lld_block::lld_block_vec_t lld_block_vec_t;

    /// @brief C'tor
    ///
    /// @param[in]  ptree                   Pointer to a device tree for the low level device.
    engine_block_mapper(gibraltar_tree_scptr tree);

    /// @brief Returns whether engine is internal to NPE.
    ///
    /// @param[in]  engine                  Database/engine name.
    ///
    /// @retval     true                    internal.
    /// @retval     false                   external.
    bool is_internal(database_block_e engine) const;

    /// @brief Returns number of block instantiations.
    ///
    /// @param[in]  block_id                  Database block id.
    ///
    /// @retval     number of block instantiations in device.
    size_t get_num_block_instances(database_block_e block_id) const;

    /// @brief Get engine blocks for a given engine ID for a given slice.
    ///
    /// @param[in]  block                   Block id.
    /// @param[in]  slice_idx               Slice/Slice-pair index according to engine context. For device allocation, expecting 0.
    /// @param[in]  inst_idx                Block instance index.
    /// @param[out] ret                     List of block pointers corresponding to the given ID.
    ///
    /// @retval     true                    Found block mapping to the given engine and slice.
    /// @retval     false                   Slice index is out of bounds or no mapping is found for given slice index.
    bool get_blocks(database_block_e block, la_slice_id_t slice_idx, size_t inst_idx, lld_block_vec_t& ret) const;

    /// @brief Return CTM tcam according to CDB core and ring index.
    ///
    /// @param[in]  cdb_core                CDB core index (0-reduced[0], 1-full(0) etc).
    /// @param[in]  subring_idx             Subring index.
    /// @param[in]  idx                     TCAM index.
    ///
    /// @retval     List of memories constructing 160bit tcam.
    std::vector<lld_memory_scptr> get_ctm_tcam(size_t cdb_core, size_t subring_idx, size_t idx) const;

    /// @brief Return CTM tcam according to CDB core and array index.
    ///
    /// @param[in]  cdb_core                CDB core index (0-reduced[0], 1-full(0) etc).
    /// @param[in]  subring_idx             Subring index.
    /// @param[in]  idx                     Associated memory index.
    ///
    /// @retval     List of memories constructing 160bit tcam.
    std::vector<lld_memory_scptr> get_ctm_sram(size_t cdb_core, size_t subring_idx, size_t idx) const;

    /// @brief Return size of memory array.
    ///
    /// @param[in]  mem_id      Memory ID for all memories in the array.
    ///
    /// @retval     array size
    size_t get_memory_array_size(size_t mem_id) const;

    /// @brief Return size of register array.
    ///
    /// @param[in]  reg_id      Register ID for all registers in the array.
    ///
    /// @retval     array size
    size_t get_register_array_size(size_t reg_id) const;

    engine_block_mapper() = default; // For serializaiton purposes only.
private:
    // Device tree pointer
    gibraltar_tree_scptr m_gibraltar_tree;
};

} // namespace silicon_one

#endif // __ENGINE_BLOCK_MAPPER_H__
