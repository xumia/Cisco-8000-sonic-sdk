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

#include "ra_translator_creator.h"
#include "ra/ra_types_fwd.h"

#include "hw_tables/composite_em.h"
#include "hw_tables/composite_tcam.h"
#include "hw_tables/em_common.h"
#include "hw_tables/em_core.h"
#include "hw_tables/hw_tables_fwd.h"
#include "hw_tables/memory_sram.h"
#include "hw_tables/memory_tcam.h"
#include "hw_tables/physical_locations.h"
#include "hw_tables/register_array_sram.h"

#include "special_tables/cem_em.h"
#include "special_tables/ctm_mgr.h"
#include "special_tables/ctm_tcam.h"
#include "special_tables/loopback_table_sram.h"
#include "special_tables/lpm_config.h"
#include "special_tables/mc_emdb_em.h"
#include "special_tables/mc_fe_links_bmp_sram.h"

#include "em_utils.h"
#include "table_init_helper.h"

#include "ra/ra_flow.h"

#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"

#include "api/types/la_system_types.h"

#include <climits>

namespace silicon_one
{

//************************************
// ra interfaces
//************************************
translator_creator_sptr
create_ra_translator_creator(const resource_manager_sptr& resource_mgr,
                             const ll_device_sptr& lld,
                             const std::vector<npl_context_e>& npl_context_slices,
                             const std::vector<udk_translation_info_sptr>& trans_info)
{
    ra_translator_creator_sptr creator = std::make_shared<ra_translator_creator>(resource_mgr, lld, npl_context_slices, trans_info);

    la_status ret = creator->initialize();
    if (ret) {
        return nullptr;
    }

    return creator;
}

//************************************
// Utilities
//************************************

/// @brief Returns max number of memory lines of the given resource.
///
/// @param[in]  res                 #silicon_one::physical_sram or #silicon_one::physical_tcam.
///
/// @retval     max size.
template <class _Resource>
size_t
calc_max_resource_size(const _Resource& res)
{
    // take representative memory - all memories are the same
    const lld_memory_desc_t* mem_desc = res.memories[0]->get_desc();
    size_t max_size = mem_desc->entries - res.start_line;

    return max_size;
}

/// Helper functions to perform single-data-multiple-memories writes.
la_status
write_to_srams(const ll_device_sptr& ldevice,
               std::vector<lld_memory_scptr>& memories,
               size_t line,
               size_t offset,
               const bit_vector& data)
{
    size_t lsb = offset;
    size_t msb = offset + data.get_width() - 1;
    for (const lld_memory_scptr& mem : memories) {
        la_status status = ldevice->read_modify_write_memory(*mem, line, msb, lsb, data);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
write_to_tcams(const ll_device_sptr& ldevice,
               std::vector<lld_memory_scptr>& memories,
               size_t line,
               const bit_vector& key,
               const bit_vector& mask)
{
    for (const lld_memory_scptr& mem : memories) {
        la_status status = ldevice->write_tcam(*mem, line, key, mask);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

//************************************
// ra_translator_creator
//************************************
ra_translator_creator::ra_translator_creator(const silicon_one::resource_manager_sptr& resource_mgr,
                                             const ll_device_sptr& lld,
                                             const std::vector<npl_context_e>& npl_context_slices,
                                             const std::vector<udk_translation_info_sptr>& trans_info)
    : ra::translator_creator_impl(lld, npl_context_slices),
      m_block_mapper(nullptr),
      m_resource_manager(resource_mgr),
      m_udk_translator_info(trans_info)
{
}

ra_translator_creator::~ra_translator_creator()
{
}

const size_t ra_translator_creator::EM_CORE_MOVING_DEPTH = 4;

la_status
ra_translator_creator::initialize()
{
    const ll_device_sptr& ldevice = get_ll_device();
    auto pt = ldevice->get_gibraltar_tree();
    la_status status = m_microcode_parser.initialize(pt->get_revision());
    m_block_mapper = std::make_shared<engine_block_mapper>(ldevice->get_gibraltar_tree_scptr());

    build_mem_reg_maps();

    return status;
}

bool
ra_translator_creator::has_network_slice() const
{
    for (npl_context_e slice_context : m_npl_context_slices) {
        if (slice_context == NPL_NETWORK_CONTEXT) {
            return true;
        }
    }

    return false;
}

la_status
ra_translator_creator::pre_table_init()
{
    dassert_crit(m_resource_manager);
    la_status status = m_resource_manager->pre_table_init();

    return status;
}

la_status
ra_translator_creator::post_table_init()
{
    la_status status = m_resource_manager->post_table_init();
    return_on_error(status);

    for (auto it : m_trap_tcams) {
        status = it.second->initialize();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

void
ra_translator_creator::build_mem_reg_maps()
{
    for (size_t i = 0; i <= gibraltar_tree::LLD_MEMORY_LAST; ++i) {
        const lld_memory_desc_t& mem_desc = gibraltar_tree::get_memory_desc(i);
        memory_desc_map_entry_t entry(mem_desc.name, (gibraltar_tree::lld_memory_e)i);

        m_memory_desc_map.insert(entry);
    }

    for (size_t i = 0; i <= gibraltar_tree::LLD_REGISTER_LAST; ++i) {
        const lld_register_desc_t& reg_desc = gibraltar_tree::get_register_desc(i);
        register_desc_map_entry_t entry(reg_desc.name, (gibraltar_tree::lld_register_e)i);

        m_register_desc_map.insert(entry);
    }
}

std::string
ra_translator_creator::get_resource_desc_name(const lld_block_scptr& block, const std::string& res_name)
{
    std::string block_prefix_name = block->get_template_name();

    std::string full_name = block_prefix_name + "_" + res_name;
    std::transform(full_name.begin(), full_name.end(), full_name.begin(), ::toupper);

    return full_name;
}

gibraltar_tree::lld_memory_e
ra_translator_creator::get_memory_enum(const lld_block_scptr& block, const std::string& res_name)
{
    std::string enum_str = "LLD_MEMORY_" + get_resource_desc_name(block, res_name);

    gibraltar_tree::lld_memory_e ret = gibraltar_tree::LLD_MEMORY_LAST;
    auto found_entry = m_memory_desc_map.find(enum_str);
    if (found_entry == m_memory_desc_map.end()) {
        log_crit(
            RA, "Could not find memory descriptor for block=%s, memory=%s", block->get_template_name().c_str(), res_name.c_str());
        return ret;
    }

    ret = found_entry->second;
    return ret;
}

gibraltar_tree::lld_register_e
ra_translator_creator::get_register_enum(const lld_block_scptr& block, const std::string& res_name)
{
    std::string enum_str = "LLD_REGISTER_" + get_resource_desc_name(block, res_name);

    gibraltar_tree::lld_register_e ret = gibraltar_tree::LLD_REGISTER_LAST;
    auto found_entry = m_register_desc_map.find(enum_str);
    if (found_entry == m_register_desc_map.end()) {
        log_crit(
            RA, "Could not find register descriptor for block=%s, memory=%s", block->get_template_name().c_str(), res_name.c_str());
        return ret;
    }

    ret = found_entry->second;
    return ret;
}

la_status
ra_translator_creator::load_microcode(const std::vector<size_t>& slices, npl_context_e context)
{
    log_debug(RA, "ra_translator_creator::load_microcode(context: %d)", context);

    const microcode_parser::ucode_t& ucode = m_microcode_parser.get_ucode(context);

    for (const microcode_parser::ucode_engine_desc& engine_desc : ucode) {
        lld_block_vec_t blocks;
        bool found_blocks = get_blocks(engine_desc.engine_id, slices, 0 /*no multi-instance*/, blocks);
        if (!found_blocks) {
            log_err(RA, "Failed to find HW blocks during microcode loading.");
            return LA_STATUS_EINVAL;
        }

        for (const microcode_parser::ucode_resource_desc& res_desc : engine_desc.resources[RESOURCE_TYPE_SRAM]) {
            la_status status = load_sram_microcode(res_desc, blocks);
            return_on_error(status);
        }

        for (const microcode_parser::ucode_resource_desc& res_desc : engine_desc.resources[RESOURCE_TYPE_TCAM]) {
            la_status status = load_tcam_microcode(res_desc, blocks);
            return_on_error(status);
        }

        for (const microcode_parser::ucode_resource_desc& res_desc : engine_desc.resources[RESOURCE_TYPE_REGISTER]) {
            la_status status = load_register_microcode(res_desc, blocks);
            return_on_error(status);
        }
    }

    log_debug(RA, "ra_translator_creator::load_microcode(context: %d) done", context);

    return LA_STATUS_SUCCESS;
}

microcode_parser&
ra_translator_creator::get_microcode_parser()
{
    return m_microcode_parser;
}

bool
ra_translator_creator::get_blocks(database_block_e engine,
                                  const std::vector<size_t>& indices,
                                  size_t inst_idx,
                                  ra_translator_creator::lld_block_vec_t& ret)
{
    for (size_t slice : indices) {
        bool is_ok = m_block_mapper->get_blocks(engine, slice, inst_idx, ret);
        if (!is_ok) {
            return false;
        }
    }

    return (ret.size() != 0);
}

ra_translator_creator::lld_memory_vec_t
ra_translator_creator::get_memories(const lld_block_vec_t& blocks, const std::string& mem_name, size_t arr_idx)
{
    ra_translator_creator::lld_memory_vec_t ret;

    const ll_device_sptr& ldevice = get_ll_device();
    const gibraltar_tree* gb_tree = ldevice->get_gibraltar_tree();

    for (const lld_block_scptr& block : blocks) {
        gibraltar_tree::lld_memory_e mem_id = get_memory_enum(block, mem_name);
        if (arr_idx != microcode_parser::ALL_ARRAY_IDXS) {
            // push single index
            const lld_memory_scptr& mem = gb_tree->get_memory(block->get_block_id(), mem_id, arr_idx);
            dassert_crit(mem);
            ret.push_back(mem);
            continue;
        }

        // push all indices
        size_t array_size = m_block_mapper->get_memory_array_size(mem_id);
        for (size_t curr_arr_idx = 0; curr_arr_idx < array_size; ++curr_arr_idx) {
            const lld_memory_scptr& mem = gb_tree->get_memory(block->get_block_id(), mem_id, curr_arr_idx);
            dassert_crit(mem);
            ret.push_back(mem);
        }
    }

    return ret;
}

ra_translator_creator::lld_register_vec_t
ra_translator_creator::get_registers(const lld_block_vec_t& blocks, const std::string& reg_name, size_t arr_idx)
{
    ra_translator_creator::lld_register_vec_t ret;

    const ll_device_sptr& ldevice = get_ll_device();
    const gibraltar_tree* gb_tree = ldevice->get_gibraltar_tree();

    for (const lld_block_scptr& block : blocks) {
        gibraltar_tree::lld_register_e reg_id = get_register_enum(block, reg_name);
        if (arr_idx != microcode_parser::ALL_ARRAY_IDXS) {
            // push single index
            const lld_register_scptr& reg = gb_tree->get_register(block->get_block_id(), reg_id, arr_idx);
            dassert_crit(reg);
            ret.push_back(reg);
            continue;
        }

        // push all indices
        size_t array_size = m_block_mapper->get_register_array_size(reg_id);
        for (size_t curr_arr_idx = 0; curr_arr_idx < array_size; ++curr_arr_idx) {
            const lld_register_scptr& reg = gb_tree->get_register(block->get_block_id(), reg_id, curr_arr_idx);
            dassert_crit(reg);
            ret.push_back(reg);
        }
    }

    return ret;
}

bool
ra_translator_creator::get_fi_sram_memories(database_e db, la_slice_id_t slice_id, lld_memory_vec_t& ret)
{
    const ll_device_sptr& ldevice = get_ll_device();
    const gibraltar_tree* pt = ldevice->get_gibraltar_tree();

    switch (db) {
    case DATABASE_LIGHT_FI_NPU_BASE_SRAM:
        ret.push_back(pt->slice[slice_id]->npu->txpp->top->light_fi_npu_base_lookup);
        return true;

    case DATABASE_LIGHT_FI_NPU_ENCAP_SRAM: {
        const size_t NUM_MEMORIES_PER_BLOCK = pt->slice[slice_id]->npu->txpp->top->light_fi_npu_encap_lookup->size();
        for (size_t mem_idx = 0; mem_idx < NUM_MEMORIES_PER_BLOCK; mem_idx++) {
            ret.push_back((*pt->slice[slice_id]->npu->txpp->top->light_fi_npu_encap_lookup)[mem_idx]);
        }
        return true;
    }

    case DATABASE_FI_MACRO_CONFIG_SRAM: {
        if (slice_id == 6) {
            ret.push_back(pt->npuh->fi->fi_core_macro_config_table);
            return true;
        }
        const size_t NUM_FI_ENG_PER_SLICE = array_size(pt->slice[slice_id]->npu->rxpp_term->fi_eng);
        for (size_t fi_eng_id = 0; fi_eng_id < NUM_FI_ENG_PER_SLICE; fi_eng_id++) {
            ret.push_back(pt->slice[slice_id]->npu->rxpp_term->fi_eng[fi_eng_id]->fi_core_macro_config_table);
        }
        return true;
    }

    default:
        return false;
    }

    return false;
}

bool
ra_translator_creator::get_fi_registers(database_e db, la_slice_id_t slice_id, lld_register_vec_t& ret)
{
    const ll_device_sptr& ldevice = get_ll_device();
    const gibraltar_tree* pt = ldevice->get_gibraltar_tree();

    switch (db) {
    case DATABASE_LIGHT_FI_FABRIC_SRAM:
        ret.push_back(pt->slice[slice_id]->npu->txpp->top->light_fi_fabric_lookup);
        return true;

    case DATABASE_LIGHT_FI_TM_SRAM:
        ret.push_back(pt->slice[slice_id]->npu->txpp->top->light_fi_tm_lookup);
        return true;

    default:
        return false;
    }

    return false;
}

std::vector<size_t>
ra_translator_creator::translate_indices_to_block_indices(const microcode_parser::npl_table_translator_desc& desc,
                                                          const std::vector<size_t>& indices)
{
    if (desc.block_id == DATABASE_BLOCK_NUM) { // Invalid block
        return {};
    }
    static const size_t GLOBAL_IDX = 0;

    size_t num_blocks = m_block_mapper->get_num_block_instances(desc.block_id);
    allocation_e table_allocation = desc.allocation_id;
    size_t replication_idx = desc.replication_idx;

    std::vector<size_t> ret;

    // Global device tables
    if (indices.size() == 0) {
        return ret;
    }

    if (num_blocks != engine_block_mapper::ASIC_MAX_SLICES_PER_DEVICE_NUM && table_allocation == ALLOCATION_SLICE) {
        // If block is per slice-pair:
        // replication 0 will be mapped to even indices (0, 2, 4),
        // replication 1 will be mapped to odd indices (1, 3, 5)

        // If block is per device:
        // each replication will be mapped to exactly one slice.

        // This is HW speciality in GB. For IDB per-slice tables, for IDB[2] only (slices 4, 5), the slices are inverted in HW.
        static const size_t idb_slice_indices[engine_block_mapper::ASIC_MAX_SLICES_PER_DEVICE_NUM] = {0, 1, 2, 3, 5, 4};

        size_t tables_per_block = engine_block_mapper::ASIC_MAX_SLICES_PER_DEVICE_NUM / num_blocks;
        for (size_t idx : indices) {
            if (desc.block_id == DATABASE_BLOCK_EXTERNAL_IDB_RES || desc.block_id == DATABASE_BLOCK_EXTERNAL_IDB_MACDB
                || desc.block_id == DATABASE_BLOCK_EXTERNAL_IDB_ENCDB) {
                idx = idb_slice_indices[idx];
            }

            if (idx % tables_per_block == replication_idx) {
                ret.push_back(idx / tables_per_block);
            }
        }
        return ret;
    }

    if (desc.block_id == DATABASE_BLOCK_INTERNAL_NPUH) {
        // Sometimes the same table reside in slices and NPU host.
        // In such cases, it's being initialized as part of per-slice table.
        // Therefore, we need to filter out only the first occurence (0)
        for (size_t idx : indices) {
            if (idx == GLOBAL_IDX) {
                ret.push_back(GLOBAL_IDX);
            }
        }
        return ret;
    }

    // For the rest of the cases, the translation is straight-forward.
    return indices;
}

bool
ra_translator_creator::get_blocks_and_resources(const microcode_parser::npl_table_translator_desc& desc,
                                                const std::vector<size_t>& indices,
                                                size_t inst_idx,
                                                lld_block_vec_t& blocks,
                                                microcode_parser::table_resource_desc_vec_t& resource_vec)
{
    if (!desc.has_placements) {
        // the descriptor doesn't contain information about blocks and resources
        return false;
    }

    std::vector<size_t> slices = translate_indices_to_block_indices(desc, indices);
    if (slices.empty()) {
        // No matching slice found for given replication and index list.
        return false;
    }

    bool found_blocks = get_blocks(desc.block_id, slices, inst_idx, blocks);
    if (!found_blocks) {
        log_err(RA, "Failed to find HW blocks for table %s, inst_idx %zu", desc.npl_table_name.c_str(), inst_idx);
        return false;
    }

    resource_vec = m_microcode_parser.get_table_resource_descriptors(desc.translator_idx);

    if (resource_vec.empty()) {
        log_err(RA, "No resources mapped for for table %s.", desc.npl_table_name.c_str());
        return false;
    }

    return true;
}

physical_sram
ra_translator_creator::create_physical_sram(const microcode_parser::table_resource_desc& res_desc, const lld_block_vec_t& blocks)
{
    physical_sram ret;

    ret.start_line = res_desc.start_line;
    ret.width = res_desc.width;
    ret.offset = res_desc.offset;
    ret.memories = get_memories(blocks, res_desc.memory_name, res_desc.array_idx);

    // take representative memory - all memories are the same
    const lld_memory_desc_t* mem_desc = ret.memories[0]->get_desc();

    // if width was not pre-set, update it to the entire resource.
    if (ret.width == 0) {
        ret.width = mem_desc->width_bits;
    }

    return ret;
}

physical_tcam
ra_translator_creator::create_physical_tcam(const microcode_parser::table_resource_desc& res_desc, const lld_block_vec_t& blocks)
{
    physical_tcam ret;

    ret.start_line = res_desc.start_line;
    ret.width = res_desc.width;
    ret.memories = get_memories(blocks, res_desc.memory_name, res_desc.array_idx);

    // take representative memory - all memories are the same
    const lld_memory_desc_t* mem_desc = ret.memories[0]->get_desc();

    // if width was not pre-set, update it to the entire resource.
    if (ret.width == 0) {
        ret.width = mem_desc->width_bits;
    }

    return ret;
}

physical_em
ra_translator_creator::create_physical_em(microcode_parser::table_resource_desc_vec_t::iterator begin,
                                          microcode_parser::table_resource_desc_vec_t::iterator end,
                                          const lld_block_vec_t& blocks)
{
    physical_em ret;

    // The structure should be:
    // 1. EM configuration register
    // 2. Per-bank configuration register base address + index
    // 3. List of banks
    // 4. CAM

    // EM config register
    microcode_parser::table_resource_desc_vec_t::iterator curr = begin;
    const microcode_parser::table_resource_desc& em_config_reg_desc = *curr;
    ret.config_regs = get_registers(blocks, em_config_reg_desc.register_name, em_config_reg_desc.array_idx);
    dassert_crit(ret.config_regs.size() == 1);
    ++curr;
    dassert_crit(curr != end);

    // Bank config register base - will create as a part of bank
    const microcode_parser::table_resource_desc& bank_config_reg_base_desc = *curr;
    ++curr;
    dassert_crit(curr != end);

    // Banks
    size_t bank_idx = 0;
    while (curr->type_id == RESOURCE_TYPE_SRAM && curr != end) {
        const microcode_parser::table_resource_desc& bank_sram_desc = *curr;
        physical_em::bank bnk;
        lld_register_vec_t bnk_config_regs
            = get_registers(blocks, bank_config_reg_base_desc.register_name, bank_config_reg_base_desc.array_idx + bank_idx);
        dassert_crit(bnk_config_regs.size() == 1);
        bnk.config_reg = bnk_config_regs[0];

        lld_memory_vec_t memories = get_memories(blocks, bank_sram_desc.memory_name, bank_sram_desc.array_idx);
        dassert_crit(memories.size() == 1);
        bnk.memory = memories[0];
        bnk.is_active = true;
        ret.banks.push_back(bnk);
        ++curr;
        ++bank_idx;
    }
    dassert_crit(curr != end);

    // CAM
    const microcode_parser::table_resource_desc& cam = *curr;
    ret.cams = get_memories(blocks, cam.memory_name, cam.array_idx);
    dassert_crit(ret.cams.size() == 1);

    return ret;
}

std::vector<physical_em>
ra_translator_creator::create_mc_emdb_physical_ems(const microcode_parser::npl_table_translator_desc& desc)
{
    std::vector<physical_em> ret_phy_ems;
    const ll_device_sptr& ldevice = get_ll_device();
    const gibraltar_tree* gb_tree = ldevice->get_gibraltar_tree();

    // external_npl_tables.json has the following registers and memory for mc_em_db:
    // 1. EM configuration register (shared_db_per_em_reg)
    // 2. Per-bank configuration register base address + index (shared_db_per_bank_reg)
    // 3. Four banks (shared_db_verifier)
    // 4. CAM (shared_db_cam)

    // 1. EM configuration register (shared_db_per_em_reg)
    for (size_t tbl_idx = 0; tbl_idx < array_size(gb_tree->rx_pdr_mc_db); tbl_idx++) {
        physical_em em;
        em.config_regs = {(*gb_tree->rx_pdr_mc_db[tbl_idx]->shared_db_per_em_reg)[0]};

        // 2. Per-bank configuration register base address + index (shared_db_per_bank_reg)
        // 3. Four banks (shared_db_verifier)
        for (size_t bank_idx = 0; bank_idx < gb_tree->rx_pdr_mc_db[tbl_idx]->shared_db_verifier->size(); bank_idx++) {
            physical_em::bank bnk;
            bnk.config_reg = (*gb_tree->rx_pdr_mc_db[tbl_idx]->shared_db_per_bank_reg)[bank_idx];
            bnk.memory = (*gb_tree->rx_pdr_mc_db[tbl_idx]->shared_db_verifier)[bank_idx];
            bnk.is_active = true;
            em.banks.push_back(bnk);
        }

        // 4. CAM (shared_db_cam)
        em.cams = {(gb_tree->rx_pdr_mc_db[tbl_idx]->shared_db_cam)};

        // Update the rest of the fields.
        update_physical_em(desc, em);
        ret_phy_ems.push_back(em);
    }
    return ret_phy_ems;
}

std::vector<physical_em>
ra_translator_creator::create_physical_ems(const microcode_parser::npl_table_translator_desc& desc, size_t index)
{
    std::vector<physical_em> ret;

    lld_block_vec_t blocks;
    microcode_parser::table_resource_desc_vec_t resource_vec;

    bool success = get_blocks_and_resources(desc, {index}, 0 /*no multi-instance*/, blocks, resource_vec);
    if (!success) {
        return std::vector<physical_em>();
    }

    auto curr_em = resource_vec.begin();
    auto end_it = resource_vec.end();
    while (curr_em != end_it) {
        auto next_em = find_em_resource(curr_em, end_it);

        physical_em em = create_physical_em(curr_em, next_em, blocks);
        // Update the rest of the fields.
        update_physical_em(desc, em);

        bool resources_ok = check_physical_em(desc, em);
        if (!resources_ok) {
            return std::vector<physical_em>();
        }

        ret.push_back(em);
        curr_em = next_em;
    }

    return ret;
}

physical_em
ra_translator_creator::compress_physical_ems(const std::vector<physical_em>& ems)
{
    // Construct single EM core from all provided cores by copying the data from the first one.
    physical_em ret(ems[0]);
    for (size_t em_idx = 1; em_idx < ems.size(); ++em_idx) {
        // Append cam sections and cam size.
        ret.cam_size += ems[em_idx].cam_size;
        ret.cams.insert(ret.cams.end(), ems[em_idx].cams.begin(), ems[em_idx].cams.end());

        // Append banks.
        ret.banks.insert(ret.banks.end(), ems[em_idx].banks.begin(), ems[em_idx].banks.end());

        // Append per-em configuration registers.
        ret.config_regs.insert(ret.config_regs.end(), ems[em_idx].config_regs.begin(), ems[em_idx].config_regs.end());
    }

    return ret;
}

void
ra_translator_creator::update_sram_section_size(std::vector<sram_section>& mem_sram, size_t value_width, bool is_multival)
{
    for (sram_section& section : mem_sram) {
        size_t width = 0;
        size_t size = INT_MAX;
        for (physical_sram& sram : section.srams) {
            size_t resource_size = calc_max_resource_size(sram);
            size = std::min(size, resource_size);

            width += sram.width;
        }

        if (section.size == 0) {
            // If size is not zero, it was already externally set. No need to update.
            // The size is zero - set it to match minimal physical dimensions of all resources.
            section.size = size;
        }

        section.entries_per_line = 1;

        if (is_multival) {
            // dassert_crit(width % value_width == 0);
            if (width % value_width != 0) {
                log_err(RA, "value width (= %lu) is not a multiplier of width (=%lu)", value_width, width);
                return;
            }
            section.entries_per_line = width / value_width;
            section.size *= section.entries_per_line;
        }
    }
}

void
ra_translator_creator::update_tcam_section_size(std::vector<tcam_section>& mem_tcam)
{
    for (tcam_section& section : mem_tcam) {
        size_t size = section.size;
        if (size != 0) {
            // If size is not zero, it was already externally set. No need to update
            continue;
        }

        // The size is zero - set it to match minimal physical dimensions of all resources.
        size = INT_MAX;
        for (physical_sram& sram : section.srams) {
            size_t resource_size = calc_max_resource_size(sram);
            size = std::min(size, resource_size);
        }

        for (physical_tcam& tcam : section.tcams) {
            size_t resource_size = calc_max_resource_size(tcam);
            size = std::min(size, resource_size);
        }

        section.size = size;
    }
}

void
ra_translator_creator::update_physical_em(const microcode_parser::npl_table_translator_desc& desc, physical_em& em)
{
    em.data_width = em_utils::get_entry_width(desc.database_id);
    em.key_widths = em_utils::get_key_width_options(desc.database_id);

    const lld_memory_desc_t* mem_desc = em.banks[0].memory->get_desc();
    em.bank_size = mem_desc->entries;
    em.bank_width = mem_desc->width_bits;
    em.cam_size = em.cams[0]->get_desc()->entries;

    size_t bank_addr_width = bit_utils::bits_to_represent(em.bank_size - 1);
    // field width contains additional option - valid
    size_t key_size_field_width = bit_utils::bits_to_represent(em.key_widths.size());
    size_t all_fields_width = em.data_width - bank_addr_width + key_size_field_width;
    size_t ecc_additional_width = bit_utils::bits_to_represent(all_fields_width - 1) + 1;
    em.ecc_width = bit_utils::bits_to_represent(all_fields_width + ecc_additional_width - 1) + 1;
    em.skip_ecc_calc = 0;

    if (mem_desc->width_bits != mem_desc->width_total_bits) {
        // TODO: the below assert should be uncommented
        // dassert_crit(mem_desc->width_total_bits == mem_desc->width_bits + em.ecc_width);
        em.skip_ecc_calc = 1;
        em.ecc_width = 0;
    }

    size_t primary_key_width = em_utils::get_primary_key_width(desc.database_id);
    for (size_t bank_idx = 0; bank_idx < em.banks.size(); ++bank_idx) {
        em.banks[bank_idx].rc5 = em::generate_pseudo_rc5(primary_key_width, bank_idx);
    }
}

void
ra_translator_creator::update_cores_for_service_mapping_em(size_t slice_idx, size_t port_idx, std::vector<physical_em>& em_cores)
{
    std::vector<physical_em> ret_em_cores;
    std::vector<size_t> em_core_idxs = {0, 1};

    for (size_t em_core_idx : em_core_idxs) {
        bit_vector active_banks(0 /*value*/, em_cores[em_core_idx].banks.size() /*width*/);
        if (port_idx == 0) {
            active_banks.set_bits(3, 0, (1 << 4) - 1);
        } else { // port_idx == 1
            active_banks.set_bits(7, 4, (1 << 4) - 1);
        }

        for (size_t bank_idx = 0; bank_idx < em_cores[em_core_idx].banks.size(); ++bank_idx) {
            em_cores[em_core_idx].banks[bank_idx].is_active = active_banks.bit(bank_idx);
        }

        ret_em_cores.push_back(em_cores[em_core_idx]);
    }

    dassert_crit(ret_em_cores.size() > 0);
    em_cores = ret_em_cores;
}

void
ra_translator_creator::update_cores_for_special_em_tables(database_e database_id, size_t index, std::vector<physical_em>& em_cores)
{
    switch (database_id) {
    case DATABASE_MAC_SERVICE_MAPPING_0_EM:
        update_cores_for_service_mapping_em(index, 0 /*port_idx*/, em_cores);
        break;
    case DATABASE_MAC_SERVICE_MAPPING_1_EM:
        update_cores_for_service_mapping_em(index, 1 /*port_idx*/, em_cores);
        break;
    default:
        // nothing to update
        break;
    }
}

void
ra_translator_creator::register_em_db_with_resource_manager(database_e database_id, const logical_em_wptr& em_db, size_t index)
{
    switch (database_id) {
    case DATABASE_EGRESS_LARGE_EM:
        m_resource_manager->set_em_db(la_resource_descriptor::type_e::EGRESS_LARGE_ENCAP_EM, em_db, index);
        break;
    case DATABASE_EGRESS_SMALL_EM:
        m_resource_manager->set_em_db(la_resource_descriptor::type_e::EGRESS_SMALL_ENCAP_EM, em_db, index);
        break;
    case DATABASE_EGRESS_L3_DLP0_EM:
        m_resource_manager->set_em_db(la_resource_descriptor::type_e::EGRESS_L3_DLP0_EM, em_db, index);
        break;
    case DATABASE_TUNNEL_0_EM:
        m_resource_manager->set_em_db(la_resource_descriptor::type_e::TUNNEL_0_EM, em_db, index);
        break;
    case DATABASE_TM_MC_EM:
        m_resource_manager->set_mc_emdb(em_db);
        break;
    default:
        break;
    }
}

std::unique_ptr<logical_sram>
ra_translator_creator::create_memory_sram(const microcode_parser::npl_table_translator_desc& desc,
                                          bool is_multival,
                                          const std::vector<size_t>& indices)
{
    // 1. manually create memory sram for fi and special tables
    database_e db = desc.database_id;
    if (db == DATABASE_FI_MACRO_CONFIG_SRAM      /* fi_macro_config */
        || db == DATABASE_LIGHT_FI_NPU_BASE_SRAM /* light_fi_npu_base */
        || db == DATABASE_LIGHT_FI_NPU_ENCAP_SRAM /* light_fi_npu_encap */) {

        return create_fi_memory_sram(db, indices);
    } else if (db == DATABASE_MC_FE_LINKS_BMP_SRAM) {
        return silicon_one::make_unique<mc_fe_links_bmp_sram>(get_ll_device());
    }

    // 2. create memory sram by descriptor info
    std::vector<sram_section> sections;
    size_t section_base_idx = 0;

    size_t block_inst_num = 1;

    // these are multi-instance blocks
    if (desc.block_id == DATABASE_BLOCK_EXTERNAL_RX_METER_BLOCK || desc.block_id == DATABASE_BLOCK_EXTERNAL_COUNTERS_BANK_GROUP) {
        block_inst_num = m_block_mapper->get_num_block_instances(desc.block_id);
    }

    for (size_t inst_idx = 0; inst_idx < block_inst_num; ++inst_idx) {
        lld_block_vec_t blocks;
        microcode_parser::table_resource_desc_vec_t resource_vec;
        bool success = get_blocks_and_resources(desc, indices, inst_idx, blocks, resource_vec);
        if (!success) {
            return nullptr;
        }

        const microcode_parser::table_resource_desc& last_resource = resource_vec.back();
        size_t num_sections = last_resource.section_idx + 1;
        sections.resize(sections.size() + num_sections);

        for (const microcode_parser::table_resource_desc& res : resource_vec) {
            size_t section_idx = section_base_idx + res.section_idx;
            if (res.type_id != RESOURCE_TYPE_SRAM) {
                log_err(RA, "Only SRAM resources are supported for table %s", desc.npl_table_name.c_str());
                return nullptr;
            }

            sections[section_idx].size = res.size;
            sections[section_idx].is_valid = true;

            physical_sram sram = create_physical_sram(res, blocks);
            sections[section_idx].srams.push_back(sram);
        }

        section_base_idx += num_sections;
    }

    update_sram_section_size(sections, desc.payload_width, is_multival);

    bool resources_ok = check_sram_sections(desc, sections);
    if (!resources_ok) {
        return nullptr;
    }

    const ll_device_sptr& ldevice = get_ll_device();
    std::unique_ptr<logical_sram> lsram
        = silicon_one::make_unique<memory_sram>(ldevice, desc.payload_width, sections, desc.section_line_reversed);

    return lsram;
}

std::unique_ptr<logical_sram>
ra_translator_creator::create_register_array_sram(const microcode_parser::npl_table_translator_desc& desc,
                                                  bool is_multival,
                                                  const std::vector<size_t>& indices)
{
    // 1. manually create register array sram for fi tables
    database_e db = desc.database_id;
    if (db == DATABASE_LIGHT_FI_STAGES_CFG_SRAM /* light_fi_stages_cfg */) {
        return create_light_fi_stages_cfg_sram(indices);

    } else if (db == DATABASE_LIGHT_FI_FABRIC_SRAM /* light_fi_fabric_table */
               || db == DATABASE_LIGHT_FI_TM_SRAM /* light_fi_tm_table */) {
        return create_fi_register_array_sram(db, indices);
    }

    // 2. create register array sram by descriptor info
    register_array regs;
    regs.size = 0;
    regs.entries_per_line = 1;

    size_t block_inst_num = 1;

    // these are multi-instance blocks
    if (desc.block_id == DATABASE_BLOCK_EXTERNAL_RX_METER_BLOCK || desc.block_id == DATABASE_BLOCK_EXTERNAL_COUNTERS_BANK_GROUP) {
        block_inst_num = m_block_mapper->get_num_block_instances(desc.block_id);
    }

    for (size_t inst_idx = 0; inst_idx < block_inst_num; ++inst_idx) {
        lld_block_vec_t blocks;
        microcode_parser::table_resource_desc_vec_t resource_vec;
        bool success = get_blocks_and_resources(desc, indices, inst_idx, blocks, resource_vec);
        if (!success) {
            return nullptr;
        }

        if (resource_vec.size() != 1) {
            log_err(RA, "Only single resource is supported for table %s", desc.npl_table_name.c_str());
            return nullptr;
        }

        const microcode_parser::table_resource_desc& res = resource_vec.back();
        if (res.type_id != RESOURCE_TYPE_REGISTER) {
            log_err(RA, "Only Register resource is supported for table %s", desc.npl_table_name.c_str());
            return nullptr;
        }

        regs.width = res.width;
        regs.offset = res.offset;
        regs.size += res.size;

        for (size_t idx = 0; idx < res.size; ++idx) {
            lld_register_vec_t mem_line = get_registers(blocks, res.register_name, res.array_idx + idx);
            regs.memories.push_back(mem_line);
        }
    }

    if (regs.width == 0) {
        // if width was not provided - take the entire resource.
        regs.width = regs.memories[0][0]->get_desc()->width_in_bits;
    }

    if (is_multival) {
        dassert_crit(regs.width % desc.payload_width == 0);
        regs.entries_per_line = regs.width / desc.payload_width;
        regs.size *= regs.entries_per_line;
    }

    // 3. create register array sram section
    register_array_section section
        = {.entries_per_line = regs.entries_per_line, .width = regs.width, .size = regs.size, .srams = {regs}};

    const ll_device_sptr& ldevice = get_ll_device();
    std::unique_ptr<logical_sram> lsram = silicon_one::make_unique<register_array_sram>(ldevice, section);

    return lsram;
}

logical_tcam_sptr
ra_translator_creator::create_memory_tcam(const microcode_parser::npl_table_translator_desc& desc,
                                          const std::vector<size_t>& indices)
{
    // 1. manually create memory tcam for fi tables
    database_e db = desc.database_id;
    if (db == DATABASE_FI_CORE_TCAM) {
        // fi_core_tcam_table
        return create_fi_core_tcam(indices);
    }

    la_uint8_t fi_nw_id;
    la_status status = get_light_fi_nw_id(db, fi_nw_id);
    if (status == LA_STATUS_SUCCESS) {
        return create_light_fi_nw_tcam(fi_nw_id, indices);
    }

    // 2. create memory tcam by descriptor info
    std::vector<tcam_section> sections;
    lld_block_vec_t blocks;
    microcode_parser::table_resource_desc_vec_t resource_vec;

    bool success = get_blocks_and_resources(desc, indices, 0 /*no multi-instance*/, blocks, resource_vec);
    if (!success) {
        return nullptr;
    }

    const microcode_parser::table_resource_desc& last_resource = resource_vec.back();
    size_t num_sections = last_resource.section_idx + 1;
    sections.resize(num_sections);

    for (const microcode_parser::table_resource_desc& res : resource_vec) {

        sections[res.section_idx].size = res.size;

        if (res.type_id == RESOURCE_TYPE_SRAM) {
            physical_sram sram = create_physical_sram(res, blocks);
            sections[res.section_idx].srams.push_back(sram);
        } else {
            physical_tcam tcam = create_physical_tcam(res, blocks);
            sections[res.section_idx].tcams.push_back(tcam);
        }
    }

    update_tcam_section_size(sections);

    bool resources_ok = check_tcam_sections(desc, sections);
    if (!resources_ok || sections.empty()) {
        return nullptr;
    }

    const ll_device_sptr& ldevice = get_ll_device();
    logical_tcam_sptr ltcam = std::make_shared<memory_tcam>(ldevice, desc.key_width, desc.payload_width, sections);

    return ltcam;
}

logical_tcam_sptr
ra_translator_creator::create_ctm_tcam(npl_tables_e npl_table_id,
                                       const microcode_parser::npl_table_translator_desc& desc,
                                       const std::vector<size_t>& indices)
{
    dassert_crit(!indices.empty());

    std::vector<logical_tcam_sptr> ret;
    const auto& ctm_mgr_desc = m_resource_manager->get_ctm_mgr();

    for (size_t idx : indices) {
        ctm::group_desc::group_ifs_e interface;
        size_t logical_id;
        bool is_valid = m_resource_manager->get_table_map(npl_table_id, interface, logical_id);
        // If npl table not mapped, fail.
        if (!is_valid) {
            return nullptr;
        }

        ctm::group_desc group_id(idx, interface);
        ctm::table_desc table(idx, npl_table_id);
        logical_tcam_sptr ltcam
            = std::make_shared<ctm_tcam>(table, group_id, logical_id, desc.key_width, desc.payload_width, ctm_mgr_desc);
        ret.push_back(ltcam);
    }

    dassert_crit(!ret.empty());

    return (ret.size() == 1) ? ret.back() : std::make_shared<composite_tcam>(ret);
}

trap_tcam_sptr
ra_translator_creator::create_trap_tcam(const microcode_parser::npl_table_translator_desc& desc, const std::vector<size_t>& indices)
{
    trap_tcam_key_t tcam_key(desc.block_id, desc.context_id);
    auto it = m_trap_tcams.find(tcam_key);
    if (it != m_trap_tcams.end()) {
        return it->second;
    }

    // Not found - create new
    lld_block_vec_t blocks;
    microcode_parser::table_resource_desc_vec_t resource_vec;

    bool success = get_blocks_and_resources(desc, indices, 0 /*no multi-instance*/, blocks, resource_vec);
    if (!success || resource_vec.size() != 2) {
        // for trap/snoop, expecting exactly two resources.
        return nullptr;
    }

    std::vector<tcam_section> sections(1);

    sections[0].size = trap_tcam::NUM_ENTRIES;
    for (const microcode_parser::table_resource_desc& res : resource_vec) {
        if (res.type_id == RESOURCE_TYPE_SRAM) {
            physical_sram sram = create_physical_sram(res, blocks);
            // NPC is setting start_line to last line for reversed tables. We need both straight and reversed tables be the same
            sram.start_line = 0;
            sections[0].srams.push_back(sram);
        } else {
            physical_tcam tcam = create_physical_tcam(res, blocks);
            // NPC is setting start_line to last line for reversed tables. We need both straight and reversed tables be the same
            tcam.start_line = 0;
            sections[0].tcams.push_back(tcam);
        }
    }

    lld_register_vec_t size_cfg_regs = get_registers(blocks, "traps_tcam_cfg", 0 /*arr_idx*/);

    ll_device_sptr ldevice = get_ll_device();
    trap_tcam_sptr ttcam = std::make_shared<trap_tcam>(ldevice, desc.key_width, desc.payload_width, sections, size_cfg_regs);

    m_trap_tcams.insert(std::make_pair(tcam_key, ttcam));

    return ttcam;
}

logical_em_sptr
ra_translator_creator::create_em(const microcode_parser::npl_table_translator_desc& desc, const std::vector<size_t>& indices)
{
    // Get logical EM for each index.
    std::vector<logical_em_sptr> logical_ems;
    for (size_t idx : indices) {
        logical_em_sptr em = create_logical_em(desc, idx);
        if (em) {
            logical_ems.push_back(em);
        }
    }

    if (logical_ems.empty()) {
        return nullptr;
    }

    if (logical_ems.size() == 1) {
        return logical_ems.back();
    }

    return logical_em_sptr(new composite_em(logical_ems));
}

// Current code flow passes 0 index only
la_status
ra_translator_creator::create_mc_emdb_logical_ems(const microcode_parser::npl_table_translator_desc& desc,
                                                  std::vector<logical_em_sptr>& out_ems)
{
    dassert_crit(m_resource_manager);

    std::vector<physical_em> phy_ems = create_mc_emdb_physical_ems(desc);

    // Do not compress phisical_em as we need separate logical em for
    // table selection logic to work
    for (const physical_em phy_em_core : phy_ems) {
        // Register banks.
        la_status status = m_resource_manager->register_em_banks(phy_em_core);
        if (status != LA_STATUS_SUCCESS) {
            log_err(RA, "Failed to register MC-EMDB banks: %s", la_status2str(status).c_str());
            return status;
        }
        const ll_device_sptr& ldevice = get_ll_device();
        em_core_sptr new_core = std::make_shared<em_core>(ldevice, phy_em_core, EM_CORE_MOVING_DEPTH);
        size_t key_width_idx = em_utils::get_key_width_idx(desc.database_id, desc.key_width, desc.payload_width);
        status = m_resource_manager->register_em_table(phy_em_core, key_width_idx, desc.logical_table_id_columns_values);
        if (status != LA_STATUS_SUCCESS) {
            log_err(RA, "Failed to register MC-EMDB table: %s", la_status2str(status).c_str());
            return status;
        }
        out_ems.push_back(new_core);
    }

    return LA_STATUS_SUCCESS;
}

logical_em_sptr
ra_translator_creator::create_logical_em(const microcode_parser::npl_table_translator_desc& desc, size_t index)
{
    dassert_crit(m_resource_manager);

    em_db_key_t db_key(desc.database_id, desc.replication_idx, index);
    auto it = m_em_dbs.find(db_key);
    if (it == m_em_dbs.end()) {
        // EM was not found - build it.
        std::vector<physical_em> em_cores = create_physical_ems(desc, index);
        if (em_cores.empty()) {
            return nullptr;
        }

        // Manipulate EM core list for special tables.
        update_cores_for_special_em_tables(desc.database_id, index, em_cores);

        // Compress the list into single core.
        physical_em aggregate_em_core = compress_physical_ems(em_cores);

        // Register banks.
        la_status status = m_resource_manager->register_em_banks(aggregate_em_core);
        if (status != LA_STATUS_SUCCESS) {
            return nullptr;
        }

        const ll_device_sptr& ldevice = get_ll_device();

        // TODO Mahmoud - temp workaround until I understand how to do it correctly
        if (desc.database_id == DATABASE_MAC_SERVICE_MAPPING_0_EM || desc.database_id == DATABASE_MAC_SERVICE_MAPPING_1_EM) {
            for (size_t em_idx = 0; em_idx < em_cores.size(); em_idx++) {
                physical_em em = em_cores[em_idx];
                for (size_t i = 0; i < em.banks.size(); i++) {
                    const physical_em::bank& bank = em.banks[i];
                    const lld_register_desc_t* desc = bank.config_reg->get_desc();
                    bit_vector per_bank_reg_value(0, desc->width_in_bits);
                    ldevice->read_register(*bank.config_reg, per_bank_reg_value);
                    per_bank_reg_value.set_bit(0, bank.is_active ^ em_idx);
                    ldevice->write_register(*bank.config_reg, per_bank_reg_value);
                }
            }
        }

        em_core_sptr new_core = std::make_shared<em_core>(ldevice, aggregate_em_core, EM_CORE_MOVING_DEPTH);
        auto ins_it = m_em_dbs.insert(std::make_pair(db_key, new_core));
        it = ins_it.first;
        logical_em_wptr logical_em_core(new_core);

        register_em_db_with_resource_manager(desc.database_id, logical_em_core, index);
    }

    // Register new table, even if EM existed before.
    const auto& core = it->second;
    const physical_em* phys_em = core->get_physical_em();
    size_t key_width_idx = em_utils::get_key_width_idx(desc.database_id, desc.key_width, desc.payload_width);

    la_status status = m_resource_manager->register_em_table(*phys_em, key_width_idx, desc.logical_table_id_columns_values);
    if (status != LA_STATUS_SUCCESS) {
        return nullptr;
    }

    return core;
}

std::unique_ptr<logical_sram>
ra_translator_creator::create_fi_memory_sram(database_e db, const std::vector<size_t>& indices)
{
    const ll_device_sptr& ldevice = get_ll_device();
    lld_memory_vec_t memories;
    bool status;

    for (size_t slice_id : indices) {
        status = get_fi_sram_memories(db, slice_id, memories);
        if (!status) {
            return nullptr;
        }
    }

    // Take representative memory - all memories are the same
    const lld_memory_desc_t* mem_desc = memories[0]->get_desc();
    size_t width_bits = mem_desc->width_bits;

    // Create the physical sram
    physical_sram sram = {.start_line = 0, .offset = 0, .width = width_bits, .memories = memories};

    // Create a section for the physical sram
    sram_section section{.size = mem_desc->entries, .entries_per_line = 1, .srams = {sram}, .is_valid = true};

    std::vector<sram_section> sections = {section};
    std::unique_ptr<logical_sram> lsram = silicon_one::make_unique<memory_sram>(ldevice, width_bits, sections);

    return lsram;
}

std::unique_ptr<logical_sram>
ra_translator_creator::create_light_fi_stages_cfg_sram(const std::vector<size_t>& indices)
{
    const ll_device_sptr& ldevice = get_ll_device();
    const gibraltar_tree* pt = ldevice->get_gibraltar_tree();
    const size_t NUM_REGS_PER_BLOCK = pt->slice[0]->npu->txpp->top->light_fi_stages_cfg->size();

    // 1. get registers and create register_array sram
    register_array regs;
    for (size_t reg_idx = 0; reg_idx < NUM_REGS_PER_BLOCK; reg_idx++) {
        lld_register_vec_t mem_line;
        for (size_t slice_id : indices) {
            mem_line.push_back((*pt->slice[slice_id]->npu->txpp->top->light_fi_stages_cfg)[reg_idx]);
        }
        regs.memories.push_back(mem_line);
    }

    const lld_register_desc_t* desc = regs.memories[0][0]->get_desc();
    regs.entries_per_line = 1;
    regs.offset = 0;
    regs.width = desc->width_in_bits;
    regs.size = desc->instances;

    // 2. create register array sram section
    register_array_section section
        = {.entries_per_line = regs.entries_per_line, .width = regs.width, .size = regs.size, .srams = {regs}};
    std::unique_ptr<logical_sram> lsram = silicon_one::make_unique<register_array_sram>(ldevice, section);

    return lsram;
}

std::unique_ptr<logical_sram>
ra_translator_creator::create_fi_register_array_sram(database_e db, const std::vector<size_t>& indices)
{
    if (indices.size() == 0) {
        return nullptr;
    }

    const ll_device_sptr& ldevice = get_ll_device();
    lld_register_vec_t mem_line;
    bool status;

    for (size_t slice_id : indices) {
        status = get_fi_registers(db, slice_id, mem_line);
        if (!status) {
            return nullptr;
        }
    }

    const lld_register_desc_t* desc = mem_line[0]->get_desc();
    const size_t num_fields = 9;

    register_array_section section;
    section.width = desc->width_in_bits; // entire resource width
    section.entries_per_line = 16;
    section.size = num_fields * desc->instances * section.entries_per_line;

    size_t reg_fields_widths[num_fields] = {128 /* header_format */,
                                            128 /* next_header_format */,
                                            16 /* npe_macro_id_valid */,
                                            128 /* npe_macro_id */,
                                            48 /* next_fi_macro_id */,
                                            16 /* is_protocol_layer */,
                                            16 /* next_is_protocol_layer */,
                                            112 /* base_size */,
                                            16 /* use_additional_size */};

    size_t sram_offset = 0;
    // create register array per field
    for (size_t width : reg_fields_widths) {
        register_array reg_arr
            = {.entries_per_line = 16, .offset = sram_offset, .width = width, .size = 16, .memories = {mem_line}};
        section.srams.push_back(reg_arr);
        sram_offset += width;
    }

    std::unique_ptr<logical_sram> lsram = silicon_one::make_unique<register_array_sram>(ldevice, section);

    return lsram;
}

logical_tcam_sptr
ra_translator_creator::create_fi_core_tcam(const std::vector<size_t>& indices)
{
    const ll_device_sptr& ldevice = get_ll_device();
    const gibraltar_tree* pt = ldevice->get_gibraltar_tree();
    const size_t NUM_FI_ENG_PER_SLICE = array_size(pt->slice[0]->npu->rxpp_term->fi_eng);

    // 1. get sram memories and create physical sram
    lld_memory_vec_t sram_memories;
    for (size_t slice_id : indices) {
        if (slice_id == 6) {
            sram_memories.push_back(pt->npuh->fi->fi_core_tcam_assoc_data);
        } else {
            for (size_t fi_eng_id = 0; fi_eng_id < NUM_FI_ENG_PER_SLICE; fi_eng_id++) {
                sram_memories.push_back(pt->slice[slice_id]->npu->rxpp_term->fi_eng[fi_eng_id]->fi_core_tcam_assoc_data);
            }
        }
    }

    const lld_memory_desc_t* mem_desc = sram_memories[0]->get_desc();
    size_t sram_width = mem_desc->width_bits;

    physical_sram sram = {.start_line = 0, .offset = 0, .width = sram_width, .memories = sram_memories};

    // 2. get tcam memories and create physical tcam
    lld_memory_vec_t tcam_memories;
    for (size_t slice_id : indices) {
        if (slice_id == 6) {
            tcam_memories.push_back(pt->npuh->fi->fi_core_tcam);
        } else {
            for (size_t fi_eng_id = 0; fi_eng_id < NUM_FI_ENG_PER_SLICE; fi_eng_id++) {
                tcam_memories.push_back(pt->slice[slice_id]->npu->rxpp_term->fi_eng[fi_eng_id]->fi_core_tcam);
            }
        }
    }

    mem_desc = tcam_memories[0]->get_desc();
    size_t tcam_width = mem_desc->width_bits;

    physical_tcam tcam = {.start_line = 0, .width = tcam_width, .memories = tcam_memories};

    // 3. create tcam section
    tcam_section section = {.size = mem_desc->entries, .tcams = {tcam}, .srams = {sram}};

    std::vector<tcam_section> sections = {section};
    logical_tcam_sptr ltcam = std::make_shared<memory_tcam>(ldevice, tcam_width, sram_width, sections);

    return ltcam;
}

logical_tcam_sptr
ra_translator_creator::create_light_fi_nw_tcam(size_t nw_id, const std::vector<size_t>& indices)
{
    if (indices.size() == 0) {
        return nullptr;
    }

    const ll_device_sptr& ldevice = get_ll_device();
    const gibraltar_tree* pt = ldevice->get_gibraltar_tree();

    // Create physical sram
    lld_memory_vec_t sram_memories;
    for (size_t slice_id : indices) {
        sram_memories.push_back((*pt->slice[slice_id]->npu->txpp->top->light_fi_nw_lookup_table_tcam_mem)[nw_id]);
    }

    const lld_memory_desc_t* mem_desc = sram_memories[0]->get_desc();
    size_t sram_width = mem_desc->width_bits;

    physical_sram sram = {.start_line = 0, .offset = 0, .width = sram_width, .memories = sram_memories};

    // Create physical tcam
    lld_memory_vec_t tcam_memories;
    for (size_t slice_id : indices) {
        tcam_memories.push_back((*pt->slice[slice_id]->npu->txpp->top->light_fi_nw_lookup_table_tcam)[nw_id]);
    }

    mem_desc = tcam_memories[0]->get_desc();
    size_t tcam_width = mem_desc->width_bits;

    physical_tcam tcam = {.start_line = 0, .width = tcam_width, .memories = tcam_memories};

    // Create tcam section
    tcam_section section = {.size = mem_desc->entries, .tcams = {tcam}, .srams = {sram}};

    std::vector<tcam_section> sections = {section};
    logical_tcam_sptr ltcam = std::make_shared<memory_tcam>(ldevice, tcam_width, sram_width, sections);

    return ltcam;
}

logical_em_sptr
ra_translator_creator::create_cem_em(const microcode_parser::npl_table_translator_desc& desc, const std::vector<size_t>& indices)
{
    const ll_device_sptr& ldevice = get_ll_device();

    int32_t em_entry_width = em_utils::get_entry_width(desc.database_id);
    // Derive key width by offsetting application specific field width since
    // CEM does not physically have space for application specific field
    int32_t em_key_width
        = em_utils::get_key_width(desc.database_id, desc.key_width, desc.payload_width - desc.application_specific_fields_width);

    // Derive entry type by offsetting application specific field width
    cem::entry_type_e entry_type
        = (em_entry_width - em_key_width - (int32_t)desc.payload_width + (int32_t)desc.application_specific_fields_width >= 0)
              ? cem::entry_type_e::SINGLE_ENTRY
              : cem::entry_type_e::DOUBLE_ENTRY;
    const auto& cem_db = m_resource_manager->get_cem();
    dassert_crit(cem_db);
    cem_em_sptr cem = std::make_shared<cem_em>(ldevice, cem_db, entry_type);

    return logical_em_sptr(cem);
}

logical_em_sptr
ra_translator_creator::create_mc_emdb_em(const microcode_parser::npl_table_translator_desc& desc,
                                         const std::vector<size_t>& indices)
{
    log_debug(RA, "Create logical and physical EM tables...");

    std::vector<logical_em_sptr> logical_ems;
    la_status status = create_mc_emdb_logical_ems(desc, logical_ems);
    if (status != LA_STATUS_SUCCESS) {
        log_err(RA, "failed to create logical EMs: %s", la_status2str(status).c_str());
        return nullptr;
    }

    const ll_device_sptr& ldevice = get_ll_device();
    logical_em_sptr mc_em = std::make_shared<mc_emdb>(ldevice, logical_ems);

    register_em_db_with_resource_manager(desc.database_id, mc_em, 0);

    return mc_em;
}

std::unique_ptr<lpm_db>
ra_translator_creator::create_lpm_table(size_t prefix_len, lpm_ip_protocol_e protocol)
{
    const ll_device_sptr& ldevice = get_ll_device();
    const logical_lpm_wptr& lpm = m_resource_manager->get_lpm();
    dassert_crit(lpm);
    std::unique_ptr<lpm_db> db = silicon_one::make_unique<lpm_db>(ldevice, prefix_len, protocol, lpm);

    return db;
}

microcode_parser::table_resource_desc_vec_t::iterator
ra_translator_creator::find_em_resource(microcode_parser::table_resource_desc_vec_t::iterator begin,
                                        microcode_parser::table_resource_desc_vec_t::iterator end)
{
    microcode_parser::table_resource_desc_vec_t::iterator ret = begin;
    while (ret != end) {
        if (ret->type_id == RESOURCE_TYPE_TCAM) {
            return ret + 1;
        }
        ++ret;
    }
    return ret;
}

bool
ra_translator_creator::check_sram(const microcode_parser::npl_table_translator_desc& desc, const physical_sram& sram, size_t size)
{
    // take representative memory
    const lld_memory_desc_t* mem_desc = sram.memories[0]->get_desc();

    size_t expected_size = sram.start_line + size;

    if (expected_size > mem_desc->entries) {
        log_err(RA,
                "Expected size %ld for memory %s is greater that memory size %d for table %s",
                expected_size,
                mem_desc->name.c_str(),
                mem_desc->entries,
                desc.npl_table_name.c_str());
        return false;
    }

    size_t expected_width = sram.offset + sram.width;
    if (expected_width > mem_desc->width_bits) {
        log_err(RA,
                "Expected width %ld for memory %s is greater that memory width %d for table %s",
                expected_width,
                mem_desc->name.c_str(),
                mem_desc->width_bits,
                desc.npl_table_name.c_str());
        return false;
    }
    return true;
}

bool
ra_translator_creator::check_tcam(const microcode_parser::npl_table_translator_desc& desc,
                                  const physical_tcam& tcam,
                                  size_t size,
                                  bool is_reg_tcam)
{
    // take representative memory
    const lld_memory_desc_t* mem_desc = tcam.memories[0]->get_desc();

    size_t expected_size = tcam.start_line + size;

    if (expected_size > mem_desc->entries) {
        log_err(RA,
                "Expected size %ld for memory %s is greater that memory size %d for table %s",
                expected_size,
                mem_desc->name.c_str(),
                mem_desc->entries,
                desc.npl_table_name.c_str());
        return false;
    }

    size_t expected_width = tcam.width;
    if (is_reg_tcam) {
        // for register tcams, each line contains both key and mask
        expected_width *= 2;
    }
    // in addition to key/mask, each tcam line contains valid bit
    expected_width += 1;

    if (expected_width > mem_desc->width_total_bits) {
        log_err(RA,
                "Expected width %ld for memory %s is greater that memory width %d for table %s",
                expected_width,
                mem_desc->name.c_str(),
                mem_desc->width_total_bits,
                desc.npl_table_name.c_str());
        return false;
    }
    return true;
}

bool
ra_translator_creator::check_sram_sections(const microcode_parser::npl_table_translator_desc& desc,
                                           const std::vector<sram_section>& sections)
{
    size_t total_size = 0;
    for (size_t i = 0; i < sections.size(); ++i) {
        const sram_section& section = sections[i];
        total_size += section.size;
        size_t width = 0;

        for (const physical_sram& sram : section.srams) {

            bool is_ok = check_sram(desc, sram, section.size / section.entries_per_line);
            if (!is_ok) {
                return false;
            }

            width += sram.width;
        }

        if (width < desc.payload_width) {
            log_err(RA,
                    "Total width of the provided resources in section %d does not match payload width for table %s",
                    (int)i,
                    desc.npl_table_name.c_str());
            return false;
        }
    }

    size_t key_range = (1ULL << desc.key_width);

    if (total_size > key_range) {
        log_err(RA,
                "Key width %d does not match provided table size %d for table %s",
                (int)desc.key_width,
                (int)total_size,
                desc.npl_table_name.c_str());
        return false;
    }

    return true;
}

bool
ra_translator_creator::check_tcam_sections(const microcode_parser::npl_table_translator_desc& desc,
                                           const std::vector<tcam_section>& sections)
{
    size_t total_size = 0;
    for (size_t i = 0; i < sections.size(); ++i) {
        const tcam_section& section = sections[i];
        total_size += section.size;
        size_t sram_width = 0;
        size_t tcam_width = 0;

        // srams
        for (const physical_sram& sram : section.srams) {

            bool is_ok = check_sram(desc, sram, section.size);
            if (!is_ok) {
                return false;
            }

            sram_width += sram.width;
        }

        // tcams
        for (const physical_tcam& tcam : section.tcams) {

            bool is_ok = check_tcam(desc, tcam, section.size, false /*is_reg_tcam*/);
            if (!is_ok) {
                return false;
            }

            tcam_width += tcam.width;
        }

        if (tcam_width < desc.key_width) {
            log_err(RA,
                    "Total width of the provided TCAM resources in section %d does not match key width for table %s",
                    (int)i,
                    desc.npl_table_name.c_str());
            return false;
        }

        if (sram_width < desc.payload_width) {
            log_err(RA,
                    "Total width of the provided SRAM resources in section %d does not match payload width for table %s",
                    (int)i,
                    desc.npl_table_name.c_str());
            return false;
        }
    }

    size_t key_range = (1ULL << desc.key_width);

    if (total_size > key_range) {
        log_err(RA,
                "Key width %d does not match provided table size %d for table %s",
                (int)desc.key_width,
                (int)total_size,
                desc.npl_table_name.c_str());
        return false;
    }

    return true;
}

bool
ra_translator_creator::check_physical_em(const microcode_parser::npl_table_translator_desc& desc, const physical_em& em)
{
    size_t em_key_width = em_utils::get_key_width(desc.database_id, desc.key_width, desc.payload_width);

    if (desc.key_width > em_key_width) {
        log_err(RA, "EM key width does not match key width for table %s", desc.npl_table_name.c_str());
        return false;
    }

    if (desc.payload_width > em.data_width - em_key_width) {
        log_err(RA, "EM payload width does not match payload width for table %s", desc.npl_table_name.c_str());
        return false;
    }

    // field width contains additional option - valid
    size_t key_size_field_width = bit_utils::bits_to_represent(em.key_widths.size());
    size_t bank_addr_width = bit_utils::bits_to_represent(em.bank_size - 1);
    size_t calculated_total_width = em.data_width + key_size_field_width + em.ecc_width - bank_addr_width;

    if (calculated_total_width != em.bank_width) {
        log_err(RA, "Something went wrong with width calculations for table %s", desc.npl_table_name.c_str());
        return false;
    }

    return true;
}

la_status
ra_translator_creator::load_sram_microcode(const microcode_parser::ucode_resource_desc& res_desc, const lld_block_vec_t& blocks)
{
    const ll_device_sptr& ldevice = get_ll_device();
    log_debug(
        RA, "ra_translator_creator::load_sram_microcode(mem: %s, arr_idx: %zd)", res_desc.memory_name.c_str(), res_desc.array_idx);

    lld_memory_vec_t mems = get_memories(blocks, res_desc.memory_name, res_desc.array_idx);
    for (const microcode_parser::ucode_entry_desc& entry_desc : res_desc.entries) {
        la_status status = write_to_srams(ldevice, mems, entry_desc.line, entry_desc.offset, entry_desc.data);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ra_translator_creator::load_tcam_microcode(const microcode_parser::ucode_resource_desc& res_desc, const lld_block_vec_t& blocks)
{
    const ll_device_sptr& ldevice = get_ll_device();
    log_debug(
        RA, "ra_translator_creator::load_tcam_microcode(mem: %s, arr_idx: %zd)", res_desc.memory_name.c_str(), res_desc.array_idx);

    lld_memory_vec_t mems = get_memories(blocks, res_desc.memory_name, res_desc.array_idx);
    for (const microcode_parser::ucode_entry_desc& entry_desc : res_desc.entries) {
        la_status status = write_to_tcams(ldevice, mems, entry_desc.line, entry_desc.key, entry_desc.mask);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ra_translator_creator::load_register_microcode(const microcode_parser::ucode_resource_desc& res_desc, const lld_block_vec_t& blocks)
{
    const ll_device_sptr& ldevice = get_ll_device();
    log_debug(RA,
              "ra_translator_creator::load_register_microcode(reg: %s, arr_idx: %zd)",
              res_desc.register_name.c_str(),
              res_desc.array_idx);

    lld_register_vec_t regs = get_registers(blocks, res_desc.register_name, res_desc.array_idx);
    dassert_crit(res_desc.entries.size() == 1);
    const microcode_parser::ucode_entry_desc& entry_desc = res_desc.entries.back();
    for (const lld_register_scptr& reg : regs) {
        la_status status = ldevice->write_register(*reg, entry_desc.data);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

std::unique_ptr<logical_sram>
ra_translator_creator::create_loopback_table(npl_tables_e table_id, size_t index)
{
    std::unique_ptr<logical_sram> sram = silicon_one::make_unique<loopback_table_sram>(get_ll_device(), table_id, index);

    return sram;
}

la_status
ra_translator_creator::get_light_fi_nw_id(database_e db, la_uint8_t& out_id)
{
    switch (db) {
    case DATABASE_LIGHT_FI_NW0_TCAM:
    case DATABASE_LIGHT_FI_NW1_TCAM:
    case DATABASE_LIGHT_FI_NW2_TCAM:
    case DATABASE_LIGHT_FI_NW3_TCAM:
        out_id = db - DATABASE_LIGHT_FI_NW0_TCAM;
        return LA_STATUS_SUCCESS;

    default:
        return LA_STATUS_ENOTFOUND;
    }
}

bool
ra_translator_creator::should_create_translator_on_slice(npl_context_e desc_context, npl_context_e slice_context) const
{
    return ((desc_context == slice_context) || ((desc_context == NPL_NETWORK_CONTEXT) && (slice_context == NPL_UDC_CONTEXT)));
}

la_status
ra_translator_creator::filter_indices_by_npl_context(const microcode_parser::npl_table_translator_desc& desc,
                                                     const std::vector<size_t>& indices,
                                                     std::vector<size_t>& out_filtered_indices)
{
    out_filtered_indices.clear();

    // Tables of type NPL_HOST_CONTEXT and NPL_NONE_CONTEXT should appear on all requested slices
    if ((desc.context_id == NPL_HOST_CONTEXT) || (desc.context_id == NPL_NONE_CONTEXT)) {
        out_filtered_indices = indices;
        return LA_STATUS_SUCCESS;
    }

    switch (desc.allocation_id) {
    case ALLOCATION_SLICE: {
        for (size_t index : indices) {
            if (index >= m_npl_context_slices.size()) {
                return LA_STATUS_EUNKNOWN;
            }

            if (should_create_translator_on_slice(desc.context_id, m_npl_context_slices[index])) {
                out_filtered_indices.push_back(index);
            }
        }

        break;
    }

    case ALLOCATION_SLICE_PAIR: {
        // A slice-pair table should appear on a slice-pair instance if the tables's context type matches ANY of the slices the
        // table is on.
        for (size_t index : indices) {
            vector_alloc<la_slice_id_t> slices_in_pair;
            slices_in_pair.push_back(index * 2);
            slices_in_pair.push_back(index * 2 + 1);
            for (auto slice : slices_in_pair) {
                if (slice >= m_npl_context_slices.size()) {
                    return LA_STATUS_EUNKNOWN;
                }

                if (should_create_translator_on_slice(desc.context_id, m_npl_context_slices[slice])) {
                    out_filtered_indices.push_back(index);
                    break;
                }
            }
        }

        break;
    }

    case ALLOCATION_DEVICE: {
        // A device-allocation table should appear if the tables's context type matches ANY of the slices in the device.
        dassert_crit(indices.size() == 1 && indices[0] == 0);
        for (npl_context_e slice_context : m_npl_context_slices) {
            if (should_create_translator_on_slice(desc.context_id, slice_context)) {
                out_filtered_indices.push_back(indices[0]);
                break;
            }
        }

        break;
    }

    default:
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

udk_translation_info_sptr
ra_translator_creator::get_udk_translator_info(npl_tables_e table_id)
{
    switch (table_id) {
    case NPL_TABLES_INGRESS_RTF_IPV4_DB1_160_F0_TABLE:
        return m_udk_translator_info[0];
    case NPL_TABLES_INGRESS_RTF_IPV4_DB1_320_F0_TABLE:
        return m_udk_translator_info[1];
    case NPL_TABLES_INGRESS_RTF_IPV4_DB2_160_F0_TABLE:
        return m_udk_translator_info[2];
    case NPL_TABLES_INGRESS_RTF_IPV4_DB2_320_F0_TABLE:
        return m_udk_translator_info[3];
    case NPL_TABLES_INGRESS_RTF_IPV4_DB3_160_F0_TABLE:
        return m_udk_translator_info[4];
    case NPL_TABLES_INGRESS_RTF_IPV4_DB3_320_F0_TABLE:
        return m_udk_translator_info[5];
    case NPL_TABLES_INGRESS_RTF_IPV4_DB4_160_F0_TABLE:
        return m_udk_translator_info[6];
    case NPL_TABLES_INGRESS_RTF_IPV4_DB4_320_F0_TABLE:
        return m_udk_translator_info[7];
    case NPL_TABLES_INGRESS_RTF_IPV6_DB1_160_F0_TABLE:
        return m_udk_translator_info[8];
    case NPL_TABLES_INGRESS_RTF_IPV6_DB1_320_F0_TABLE:
        return m_udk_translator_info[9];
    case NPL_TABLES_INGRESS_RTF_IPV6_DB2_160_F0_TABLE:
        return m_udk_translator_info[10];
    case NPL_TABLES_INGRESS_RTF_IPV6_DB2_320_F0_TABLE:
        return m_udk_translator_info[11];
    case NPL_TABLES_INGRESS_RTF_IPV6_DB3_160_F0_TABLE:
        return m_udk_translator_info[12];
    case NPL_TABLES_INGRESS_RTF_IPV6_DB3_320_F0_TABLE:
        return m_udk_translator_info[13];
    case NPL_TABLES_INGRESS_RTF_IPV6_DB4_160_F0_TABLE:
        return m_udk_translator_info[14];
    case NPL_TABLES_INGRESS_RTF_IPV6_DB4_320_F0_TABLE:
        return m_udk_translator_info[15];
    case NPL_TABLES_INGRESS_RTF_ETH_DB1_160_F0_TABLE:
        return m_udk_translator_info[16];
    case NPL_TABLES_INGRESS_RTF_ETH_DB2_160_F0_TABLE:
        return m_udk_translator_info[17];
    default:
        return nullptr;
    }
}

} // namespace silicon_one
