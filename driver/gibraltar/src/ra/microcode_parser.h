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

#ifndef __RA_MICROCODE_PARSER_H__
#define __RA_MICROCODE_PARSER_H__

#include "lld/pacific_tree.h"

#include "api/types/la_common_types.h"
#include "nplapi/npl_tables_enum.h"
#include "nplapi/nplapi_tables.h"

#include "ra/ra_types.h"
#include "ra_enums.h"

struct json_t;

namespace silicon_one
{

struct lld_memory_desc_t;

/// @brief Maps table translators and microcode to their associated resources.
///
/// - Maps between functional table and its corresponding logical replication.
/// - Maps between logical table and its resources.
/// - Map microcode to its resources
class microcode_parser
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    static const size_t ALL_ARRAY_IDXS = -1;

    /// @brief Physical Resource Descriptor for NPL table mapping.
    ///
    /// SRAM/TCAM resource's location in hardware.
    struct table_resource_desc {
        std::string memory_name;   ///< Memory name.
        std::string register_name; ///< Register name.
        resource_type_e type_id;   ///< sram, tcam or register.
        size_t section_idx;        ///< Section index of the resource.
        size_t resource_idx;       ///< Index of the resource within the section.
        size_t array_idx;          ///< Index of the resource in memory/register array.
        size_t size;               ///< Section size/ number of lines in the resource.
        size_t start_line;         ///< Start line.
        size_t offset;             ///< Offset in bits.
        size_t width;              ///< Width in bits.
    };

    /// @brief Table Translator Descriptior.
    ///
    /// Per-translator NPL table data descriptor.
    struct npl_table_translator_desc {
        size_t translator_idx; ///< Translator/Logical table index.

        std::string npl_table_name;        ///< Corresponding functional NPL table name.
        database_block_e block_id;         ///< Database engine.
        database_e database_id;            ///< Database ID (for shared databases)
        translation_type_e translation_id; ///< Translation type.
        npl_context_e context_id;          ///< Table context (fabric, network, fabric element, host, none)
        allocation_e allocation_id;        ///< Allocation per-slice, slice pair, or all slices.

        size_t replication_idx; ///< Replication ID within the same table location.

        size_t key_width;                         ///< Functional table key width in bits.
        size_t payload_width;                     ///< Functional table payload width in bits.
        size_t application_specific_fields_width; ///< Functional table application-specific fields width in bits.

        size_t logical_table_id;       ///< Logical Table ID in NPL, used as key prefix is several types of tables, such as EM.
        size_t logical_table_id_width; ///< Logical Table ID width.
        logical_table_id_columns_values_t logical_table_id_columns_values; ///< Constant columns in NPL table key
        bool has_default_value;                                            ///< Whether table has default value.
        bool has_placements;                                               ///< Whether table has placements in microcode.
        bool section_line_reversed;     ///< if to write content to section line in reversed order
        bool has_non_conforming_fabric; ///< if we need a desc per slice due differences between fabric and network slices
    };

    typedef std::vector<table_resource_desc> table_resource_desc_vec_t;
    typedef std::vector<npl_table_translator_desc> translator_desc_vec_t;

    /// @brief Ucode entry descriptor.
    ///
    /// Represents single line of micro-code. Can represent SRAM, TCAM or register.
    struct ucode_entry_desc {
        size_t line;     ///< Memory line. Relevant for SRAM and TCAM.
        size_t offset;   ///< Offset of data, in bits, from LSB. Relevant for SRAM.
        bit_vector data; ///< Entry data. Relevant for SRAM and register.
        bit_vector key;  ///< Ternary key. Relevant for TCAM.
        bit_vector mask; ///< Ternary mask. Relevant for TCAM.
    };

    /// @brief Ucode resource descriptor.
    ///
    /// Represents collection of Ucode lines for a single resource. Can represent SRAM, TCAM or register.
    struct ucode_resource_desc {
        std::string memory_name;               ///< Memory name.
        std::string register_name;             ///< Register name.
        size_t array_idx;                      ///< Index of the resource in memory/register array.
        std::vector<ucode_entry_desc> entries; ///< Collection of ucode lines.
    };

    typedef std::vector<ucode_resource_desc> ucode_resource_desc_vec_t;

    /// @brief Ucode engine descriptor.
    ///
    /// Represents collection of Ucode resources, residing in single block/engine.
    struct ucode_engine_desc {
        database_block_e engine_id;                                         ///< Database engine.
        std::array<ucode_resource_desc_vec_t, RESOURCE_TYPE_NUM> resources; ///< Collection of resources.
    };

    typedef std::vector<ucode_engine_desc> ucode_t;

    // C'tor
    microcode_parser();

    /// @brief Initialize object.
    ///
    /// @retval status.
    la_status initialize(la_device_revision_e device_revision);

    /// @brief Gets Translator Descriptors for a given functional table name.
    ///
    /// @param[in]  table_name      Functional NPL table name.
    ///
    /// @retval                     List of translator descriptors of the corresponding replications.
    translator_desc_vec_t get_translator_descriptors(const std::string& table_name) const;

    /// @brief Returns a list of resources given translator index.
    ///
    /// @param[in]  translator_idx  Translator/Logical table index.
    ///
    /// @retval                     List of resource descriptors.
    table_resource_desc_vec_t get_table_resource_descriptors(size_t translator_idx) const;

    /// @brief Returns ucode descriptors for given context (fabric, network, etc)
    ///
    /// @param[in]  context         Ucode context.
    ///
    /// @retval     Reference to ucode descripton for provided context.
    const ucode_t& get_ucode(npl_context_e context) const;

private:
    // Mappers
    //////////////////////

    // Builds table-translator and translator-resources maps and reads u-code.
    la_status build_resource_maps();

    // shared database -> enum mapper
    bool get_database_enum(const std::string& database_name, database_e& ret);

    // database block -> enum mapper
    bool get_database_block_enum(const std::string& block_name, database_block_e& ret);

    // resource type -> enum mapper
    bool get_resource_type_enum(const std::string& resource_type_name, resource_type_e& ret);

    // translation type -> enum mapper
    bool get_translation_type_enum(const std::string& type_name, translation_type_e& ret);

    // context -> enum mapper
    bool get_npl_context_enum(const std::string& context_name, npl_context_e& ret) const;

    // allocation -> enum mapper
    bool get_allocation_enum(const std::string& allocation, allocation_e& ret);

    // location -> enum mapper
    bool string_to_location(const std::string& location, location_e& out_location);

    // Helper functions to read json metadata file.
    //////////////////////

    // Reads microcode section from metadata file.
    bool read_ucode(json_t* root);

    // Reads microcode for specified context (fabric, network).
    bool read_ucode_for_context(const char* context, json_t* ucode_root);

    // Reads microcode for provided engine and fills engine descriptor.
    bool read_ucode_engine(const char* engine_name, json_t* ucode_engine_root, ucode_engine_desc& engine);

    // Reads microcode for provided sram resource and fills resource descriptor.
    bool read_ucode_sram_resource(const char* engine_name, json_t* ucode_resource_root, ucode_resource_desc& res_desc);

    // Reads microcode for provided tcam resource and fills resource descriptor.
    bool read_ucode_tcam_resource(const char* engine_name, json_t* ucode_resource_root, ucode_resource_desc& res_desc);

    // Reads microcode for provided register resource and fills resource descriptor.
    bool read_ucode_register_resource(const char* engine_name, json_t* ucode_resource_root, ucode_resource_desc& res_desc);

    // Helper function to read and check validity of common ucode resource fields.
    bool read_resource_name_and_arr_idx(json_t* ucode_resource_root, const char*& res_name, size_t& arr_idx);

    // Reads tables section from metadata file.
    bool read_tables(json_t* root, size_t& table_count);

    // Reads single table from metadata file.
    bool read_table(const char* table_name, json_t* table_data);

    // Reads single replication data from metadata file.
    bool read_table_placement(const char* table_name,
                              location_e location_id,
                              const char* database,
                              npl_context_e context,
                              bool non_conforming_fab,
                              const char* allocation,
                              size_t logical_id,
                              size_t logical_id_width,
                              const logical_table_id_columns_values_t& logical_table_id_columns_values,
                              size_t application_specific_fields_width,
                              bool has_default_value,
                              json_t* placement_data,
                              json_t* translation_type_node,
                              json_t* key_width_node,
                              json_t* payload_width_node);

    // Reads single table data from metadata file. placements are missing.
    bool read_table_without_placement(const char* table_name,
                                      const char* database,
                                      const vector_alloc<npl_context_e>& contexts,
                                      const char* allocation,
                                      size_t logical_id,
                                      size_t logical_id_width,
                                      const logical_table_id_columns_values_t& logical_table_id_columns_values,
                                      bool has_default_value,
                                      json_t* translation_type_node,
                                      json_t* key_width_node,
                                      json_t* payload_width_node);

    bool get_contexts_table_is_accessed_from(const char* table_name,
                                             json_t* table_data,
                                             vector_alloc<npl_context_e>& out_valid_contexts) const;

    // Reads single resource data from metadata file.
    bool read_table_resource(const char* table_name,
                             const char* engine_name,
                             json_t* resource_data,
                             size_t size,
                             size_t section_idx,
                             size_t resource_idx);

    // Create table resources descriptor
    bool create_table_resources_desc(const std::string& table_name,
                                     const std::string& res_name,
                                     const std::string& type,
                                     size_t offset,
                                     size_t start_line,
                                     size_t width,
                                     size_t arr_idx,
                                     size_t size,
                                     size_t section_idx,
                                     size_t resource_idx);

    // Reads single json object from metadata file.
    json_t* read_object(json_t* data, const char* tag) const;

private:
    // Map table -> translator descriptors
    typedef std::multimap<std::string, npl_table_translator_desc> translator_desc_multimap_t;
    typedef typename translator_desc_multimap_t::value_type translator_desc_multimap_entry_t;

    translator_desc_multimap_t m_translator_multimap;

    // Map translator -> resources
    typedef std::multimap<size_t, table_resource_desc> table_resource_desc_multimap_t;
    typedef typename table_resource_desc_multimap_t::value_type table_resource_desc_multimap_entry_t;

    table_resource_desc_multimap_t m_resource_multimap;

    // Ucode per context
    std::array<ucode_t, NPL_NONE_CONTEXT> m_ucode;

    // Currently parsed ucode context for reporting purposes.
    std::string m_curr_ucode_context;

    // Total count of table translators
    size_t m_translator_count;

    // Low-level device's version
    la_device_revision_e m_device_revision;
};

} // namespace silicon_one

#endif // __RA_MICROCODE_PARSER_H__
