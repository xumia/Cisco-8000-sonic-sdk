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

#ifndef __RA_TRANSLATOR_CREATOR_H__
#define __RA_TRANSLATOR_CREATOR_H__

#include "ra/ra_types_fwd.h"

#include "lld/ll_device.h"
#include "lld/pacific_tree.h"
#include "nplapi/nplapi_fwd.h"
#include "nplapi/translator_creator.h"

#include "hw_tables/hw_tables_fwd.h"
#include "hw_tables/logical_em.h"
#include "hw_tables/logical_sram.h"
#include "hw_tables/logical_tcam.h"

#include "special_tables/lpm_db.h"
#include "special_tables/trap_tcam.h"

#include "ra/ra_translator_creator_base.h"

#include "engine_block_mapper.h"
#include "microcode_parser.h"
#include "ra/resource_manager.h"

#include "ra_direct_translator.h"
#include "ra_em_translator.h"
#include "ra_lpm_translator.h"
#include "ra_ternary_translator.h"
#include "ra_trap_ternary_translator.h"

#include "ra_empty_translators.h"

namespace silicon_one
{

/// @brief Creator for RA translators
///
/// @details Implements translator_creator interface and creates translators which access physical resources
class ra_translator_creator : public ra::translator_creator_impl
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS
    using udk_translation_info_sptr = std::shared_ptr<udk_translation_info>;

public:
    /// @brief RA translator creator constructor
    ///
    /// @param[in]  lld                     Low-level device.
    /// @param[in]  npl_context_slices      NPL context mode of slices.
    ra_translator_creator(const resource_manager_sptr& resource_mgr,
                          const ll_device_sptr& lld,
                          const std::vector<npl_context_e>& npl_context_slices,
                          const std::vector<udk_translation_info_sptr>& trans_info);

    // d'tor
    ~ra_translator_creator();

    // translator_creator API
    virtual la_status pre_table_init();
    virtual la_status post_table_init();
    virtual la_status load_microcode(const std::vector<size_t>& slices, npl_context_e context);

    /// @brief Initialize object.
    ///
    /// @retval status.
    la_status initialize();

    /// @brief Factory function to create memory SRAM object for a given descriptor.
    ///
    /// @param[in]  desc        translator descriptor object representing logical table replication.
    /// @param[in]  is_multival whether SRAM will store multiple values per single SRAM line.
    /// @param[in]  indices     list of slice indices, where the functional table is instantiated.
    ///
    /// @retval     pointer to the newly created #silicon_one::logical_sram object.
    std::unique_ptr<logical_sram> create_memory_sram(const microcode_parser::npl_table_translator_desc& desc,
                                                     bool is_multival,
                                                     const std::vector<size_t>& indices);

    /// @brief Factory function to create register array SRAM object for a given descriptor.
    ///
    /// @param[in]  desc        translator descriptor object representing logical table replication.
    /// @param[in]  is_multival whether SRAM will store multiple values per single SRAM line.
    /// @param[in]  indices     list of slice indices, where the functional table is instantiated.
    ///
    /// @retval     pointer to the newly created #silicon_one::logical_sram object.
    std::unique_ptr<logical_sram> create_register_array_sram(const microcode_parser::npl_table_translator_desc& desc,
                                                             bool is_multival,
                                                             const std::vector<size_t>& indices);

    /// @brief Factory function to create memory TCAM object for a given descriptor.
    ///
    /// @param[in]  desc        translator descriptor object representing logical table replication.
    /// @param[in]  indices     list of slice indices, where the functional table is instantiated.
    ///
    /// @retval     pointer to the newly created #silicon_one::logical_tcam object.
    logical_tcam_sptr create_memory_tcam(const microcode_parser::npl_table_translator_desc& desc,
                                         const std::vector<size_t>& indices);

    /// @brief Factory function to create EM object for a given descriptor.
    ///
    /// @param[in]  desc        translator descriptor object representing logical table replication.
    /// @param[in]  indices     list of slice indices, where the functional table is instantiated.
    ///
    /// @retval     shared handle for #silicon_one::simple_em object.
    logical_em_sptr create_em(const microcode_parser::npl_table_translator_desc& desc, const std::vector<size_t>& indices);

    /// @brief Filter table instance indices based on table descriptor.
    ///
    /// Returns a vector of table instance indices on which the table should be written, based on the table's NPL context and the
    /// device's slice modes.
    ///
    /// @param[in]  desc                        translator descriptor object representing logical table replication.
    /// @param[in]  indices                     list of slice indices, where the functional table is instantiated.
    /// @param[out] indicout_filtered_indices   filtered list of slice indices, where the translators of the table will write.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            Requested index does not have a slice NPL context configuration
    la_status filter_indices_by_npl_context(const microcode_parser::npl_table_translator_desc& desc,
                                            const std::vector<size_t>& indices,
                                            std::vector<size_t>& out_filtered_indices);

    /// @brief Check if one of the slices is facing to the network.
    ///
    /// @retval     True, if one of the slices is facing to the network.
    bool has_network_slice() const;

    //----------------
    // SPECIAL TABLES
    //----------------
    std::unique_ptr<logical_sram> create_service_lp_attribute_sram(const microcode_parser::npl_table_translator_desc& desc,
                                                                   const std::vector<size_t>& indices);

    std::unique_ptr<logical_sram> create_resolution_lp_sram(const microcode_parser::npl_table_translator_desc& desc,
                                                            const std::vector<size_t>& indices,
                                                            resource_manager::resolution_lp_db db,
                                                            size_t table_id);

    logical_tcam_sptr create_ctm_tcam(npl_tables_e table_id,
                                      const microcode_parser::npl_table_translator_desc& desc,
                                      const std::vector<size_t>& indices);

    trap_tcam_sptr create_trap_tcam(const microcode_parser::npl_table_translator_desc& desc, const std::vector<size_t>& indices);

    logical_em_sptr create_cem_em(const microcode_parser::npl_table_translator_desc& desc, const std::vector<size_t>& indices);
    logical_em_sptr create_mc_emdb_em(const microcode_parser::npl_table_translator_desc& desc, const std::vector<size_t>& indices);

    std::unique_ptr<lpm_db> create_lpm_table(size_t prefix_len, lpm_ip_protocol_e protocol);

    std::unique_ptr<logical_sram> create_loopback_table(npl_tables_e table_id, size_t index);

    // accessors
    microcode_parser& get_microcode_parser();
    udk_translation_info_sptr get_udk_translator_info(npl_tables_e table_id);

private:
    ra_translator_creator() = default;

    using lld_memory_vec_t = lld_block::lld_memory_vec_t;
    using lld_register_vec_t = lld_block::lld_register_vec_t;

    // forbid copy
    ra_translator_creator(const ra_translator_creator& o);
    ra_translator_creator& operator=(const ra_translator_creator& o);

    typedef engine_block_mapper::lld_block_vec_t lld_block_vec_t;

    //----------------
    // SPECIAL TABLES
    //----------------
    std::unique_ptr<logical_sram> create_fi_memory_sram(database_e db, const std::vector<size_t>& indices);

    std::unique_ptr<logical_sram> create_light_fi_stages_cfg_sram(const std::vector<size_t>& indices);

    std::unique_ptr<logical_sram> create_fi_register_array_sram(database_e db, const std::vector<size_t>& indices);

    logical_tcam_sptr create_fi_core_tcam(const std::vector<size_t>& indices);

    logical_tcam_sptr create_light_fi_nw_tcam(size_t nw_id, const std::vector<size_t>& indices);

    // Helpers
    //////////////////

    // builds memory/register descriptor maps.
    void build_mem_reg_maps();
    // Combine resource and block names into resource occurence name.
    std::string get_resource_desc_name(const lld_block_scptr& block, const std::string& res_name);
    pacific_tree::lld_memory_e get_memory_enum(const lld_block_scptr& block, const std::string& res_name);
    pacific_tree::lld_register_e get_register_enum(const lld_block_scptr& block, const std::string& res_name);
    bool get_fi_sram_memories(database_e db, la_slice_id_t slice_id, lld_memory_vec_t& ret);
    bool get_fi_registers(database_e db, la_slice_id_t slice_id, lld_register_vec_t& ret);
    la_status get_light_fi_nw_id(database_e db, la_uint8_t& out_id);

    // Microcode helpers
    //////////

    // Load microcode for sram resources.
    la_status load_sram_microcode(const microcode_parser::ucode_resource_desc& desc, const lld_block_vec_t& blocks);

    // Load microcode for sram resources.
    la_status load_tcam_microcode(const microcode_parser::ucode_resource_desc& desc, const lld_block_vec_t& blocks);

    // Load microcode for sram resources.
    la_status load_register_microcode(const microcode_parser::ucode_resource_desc& desc, const lld_block_vec_t& blocks);

    // Translator Creation helpers
    //////////

    // Collects all lld_block occurences for the given translator replication.
    bool get_blocks(const database_block_e engine, const std::vector<size_t>& indices, size_t inst_idx, lld_block_vec_t& ret);

    // Translate from indices to block indeces for block arrays according to table allocation
    std::vector<size_t> translate_indices_to_block_indices(const microcode_parser::npl_table_translator_desc& desc,
                                                           const std::vector<size_t>& indices);

    // Collect all lld_memories given memory ID and list of blocks.
    lld_memory_vec_t get_memories(const lld_block_vec_t& blocks, const std::string& mem_name, size_t arr_idx);

    // Collect all lld_registers given register ID and list of blocks.
    lld_register_vec_t get_registers(const lld_block_vec_t& blocks, const std::string& reg_name, size_t arr_idx);

    // Aux utility to find all HW blocks and resource descriptors for given translator descriptor.
    bool get_blocks_and_resources(const microcode_parser::npl_table_translator_desc& desc,
                                  const std::vector<size_t>& indices,
                                  size_t inst_idx,
                                  lld_block_vec_t& blocks,
                                  microcode_parser::table_resource_desc_vec_t& resource_vec);

    // Create physical resource from resource descriptor
    physical_sram create_physical_sram(const microcode_parser::table_resource_desc& res_desc, const lld_block_vec_t& blocks);

    physical_tcam create_physical_tcam(const microcode_parser::table_resource_desc& res_desc, const lld_block_vec_t& blocks);

    physical_em create_physical_em(microcode_parser::table_resource_desc_vec_t::iterator begin,
                                   microcode_parser::table_resource_desc_vec_t::iterator end,
                                   const lld_block_vec_t& blocks);

    std::vector<physical_em> create_physical_ems(const microcode_parser::npl_table_translator_desc& desc, size_t index);

    // Builds one aggregate core from the list of em cores
    physical_em compress_physical_ems(const std::vector<physical_em>& em_cores);

    // Returns logical EM from interal map, if exists, otherwise creates new.
    logical_em_sptr create_logical_em(const microcode_parser::npl_table_translator_desc& desc, size_t index);

    // Update section size, if size was not set.
    void update_sram_section_size(std::vector<sram_section>& mem_sram, size_t value_width, bool is_multival);
    void update_tcam_section_size(std::vector<tcam_section>& mem_tcam);

    // Update size/width parameters of physical em
    void update_physical_em(const microcode_parser::npl_table_translator_desc& desc, physical_em& em);

    // Update physical EM core list for special tables.
    // Updated list is in em_cores.
    void update_cores_for_special_em_tables(database_e database_id, size_t index, std::vector<physical_em>& em_cores);
    void update_cores_for_service_mapping_em(size_t slice_idx, size_t port_idx, std::vector<physical_em>& em_cores);
    void update_cores_for_large_enc_db_em(size_t slice_pair_idx, std::vector<physical_em>& em_cores);

    // Register EM database with resource_manager.
    void register_em_db_with_resource_manager(database_e database_id, const logical_em_wptr& em_db, size_t index);

    // Helper function to filter translators with different contexts.
    bool should_create_translator_on_slice(npl_context_e desc_context, npl_context_e slice_context) const;

    // Sanity checking
    //////////////////////
    // Check widths, lengths and match of all physical resources constructing the logical resource.

    // Sanity check for physical sram.
    bool check_sram(const microcode_parser::npl_table_translator_desc& desc, const physical_sram& sram, size_t size);

    // Sanity check for physical tcam.
    bool check_tcam(const microcode_parser::npl_table_translator_desc& desc,
                    const physical_tcam& tcam,
                    size_t size,
                    bool is_reg_tcam);

    // Sanity check for physical em.
    bool check_physical_em(const microcode_parser::npl_table_translator_desc& desc, const physical_em& em);

    // Sanity check for resource data correctness for logical sram.
    bool check_sram_sections(const microcode_parser::npl_table_translator_desc& desc, const std::vector<sram_section>& sections);

    // Sanity check for resource data correctness for logical tcam.
    bool check_tcam_sections(const microcode_parser::npl_table_translator_desc& desc, const std::vector<tcam_section>& sections);

    // Find all resources belonging to the one EM structure.
    // Returns iterator the the first element of the next structure (or end).
    microcode_parser::table_resource_desc_vec_t::iterator find_em_resource(
        microcode_parser::table_resource_desc_vec_t::iterator begin,
        microcode_parser::table_resource_desc_vec_t::iterator end);

    la_status create_mc_emdb_logical_ems(const microcode_parser::npl_table_translator_desc& desc,
                                         std::vector<logical_em_sptr>& out_ems);
    std::vector<physical_em> create_mc_emdb_physical_ems(const microcode_parser::npl_table_translator_desc& desc);

private:
    // NPU microcode parser
    microcode_parser m_microcode_parser;
    // Engine <-> lld_block mapper.
    engine_block_mapper_sptr m_block_mapper;
    // Shared resource manager.
    resource_manager_wptr m_resource_manager;

    // Map memory name -> LLD memory descriptor
    typedef std::map<std::string, pacific_tree::lld_memory_e> memory_desc_map_t;
    typedef typename memory_desc_map_t::value_type memory_desc_map_entry_t;

    memory_desc_map_t m_memory_desc_map;

    // Map register name -> LLD register descriptor
    typedef std::map<std::string, pacific_tree::lld_register_e> register_desc_map_t;
    typedef typename register_desc_map_t::value_type register_desc_map_entry_t;

    register_desc_map_t m_register_desc_map;

    // Moving depth for EM core insertion.
    static const size_t EM_CORE_MOVING_DEPTH;

    // Map between database/replication/slice and its logical EM.
    // Avoiding multiple instantiation of the same physical location,
    // which will lead to independent invocation of EM insert algorithm and wrong writes into the same physical address.
    typedef std::tuple<database_e, size_t, size_t> em_db_key_t;
    typedef std::shared_ptr<em_core> em_core_sptr;
    typedef std::map<em_db_key_t, em_core_sptr> em_db_occurence_map_t;
    em_db_occurence_map_t m_em_dbs;

    // Map between engine/context and trap_tcam.
    // Since the table is the same for all the slices, slice_id is not a part of the key.
    // trap_tcam is shared between redirect and snoop tables
    // and dynamically allocate sections between them.
    typedef std::tuple<database_block_e, npl_context_e> trap_tcam_key_t;
    typedef std::map<trap_tcam_key_t, trap_tcam_sptr> trap_tcam_occurence_map_t;
    trap_tcam_occurence_map_t m_trap_tcams;

    std::vector<udk_translation_info_sptr> m_udk_translator_info;
};

} // namespace silicon_one

#endif // __RA_TRANSLATOR_CREATOR_H__
