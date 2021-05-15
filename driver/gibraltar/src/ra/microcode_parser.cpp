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

#include "microcode_parser.h"

#include "common/logger.h"

#include <jansson.h>
#include <sstream>
#include <stdlib.h>

static const char DEFAULT_MICROCODE_METADATA_FILE[] = "res/microcode_metadata_file.json";
static const char DEFAULT_BASE_OUTPUT_DIR[] = "out/noopt-debug";

static const char MICROCODE_METADATA_FILE_ENVVAR[] = "MICROCODE_METADATA_FILE";
static const char BASE_OUTPUT_DIR_ENVVAR[] = "BASE_OUTPUT_DIR";

namespace silicon_one
{

bool
ucode_engine_desc_compare(const microcode_parser::ucode_engine_desc& d1, const microcode_parser::ucode_engine_desc& d2)
{
    return d1.engine_id < d2.engine_id;
}

//*****************************
// resource_mapper
//*****************************
microcode_parser::microcode_parser()
    : m_curr_ucode_context("none"), m_translator_count(0), m_device_revision(la_device_revision_e::NONE)
{
}

la_status
microcode_parser::initialize(la_device_revision_e device_revision)
{
    m_device_revision = device_revision;
    la_status status = build_resource_maps();

    return status;
}

microcode_parser::translator_desc_vec_t
microcode_parser::get_translator_descriptors(const std::string& table) const
{
    translator_desc_vec_t ret;
    auto found_entries = m_translator_multimap.equal_range(table);
    for (auto it = found_entries.first; it != found_entries.second; ++it) {
        ret.push_back(it->second);
    }

    return ret;
}

microcode_parser::table_resource_desc_vec_t
microcode_parser::get_table_resource_descriptors(size_t translator_idx) const
{
    table_resource_desc_vec_t ret;

    auto found_entries = m_resource_multimap.equal_range(translator_idx);
    for (auto it = found_entries.first; it != found_entries.second; ++it) {
        ret.push_back(it->second);
    }

    return ret;
}

const microcode_parser::ucode_t&
microcode_parser::get_ucode(npl_context_e context) const
{
    return m_ucode[context];
}

bool
microcode_parser::get_database_enum(const std::string& database_name, database_e& ret)
{
    static const std::map<std::string, database_e> database_enum_map{
        {"external_mac_lp", DATABASE_MAC_SERVICE_LP_SRAM},
        {"external_fi_core_macro_config", DATABASE_FI_MACRO_CONFIG_SRAM},
        {"external_light_fi_npu_base_table", DATABASE_LIGHT_FI_NPU_BASE_SRAM},
        {"external_light_fi_npu_encap_table", DATABASE_LIGHT_FI_NPU_ENCAP_SRAM},
        {"external_light_fi_fabric_table", DATABASE_LIGHT_FI_FABRIC_SRAM},
        {"external_light_fi_tm_table", DATABASE_LIGHT_FI_TM_SRAM},
        {"external_light_fi_stages_cfg", DATABASE_LIGHT_FI_STAGES_CFG_SRAM},
        {"external_mc_fe_links_bmp", DATABASE_MC_FE_LINKS_BMP_SRAM},
        {"external_mac_service_mapping_em_0", DATABASE_MAC_SERVICE_MAPPING_0_EM},
        {"external_mac_service_mapping_em_1", DATABASE_MAC_SERVICE_MAPPING_1_EM},
        {"external_egress_small_em", DATABASE_EGRESS_SMALL_EM},
        {"external_egress_large_em", DATABASE_EGRESS_LARGE_EM},
        {"external_egress_l3_dlp0", DATABASE_EGRESS_L3_DLP0_EM},
        {"external_mac_termination_em", DATABASE_MAC_TERMINATION_EM},
        {"external_npuh_eth_mp_em", DATABASE_NPUH_ETH_MP_EM},
        {"external_tunnel0", DATABASE_TUNNEL_0_EM},
        {"external_tunnel1", DATABASE_TUNNEL_1_EM},
        {"external_resolution_stage0_em", DATABASE_RESOLUTION_STAGE0_EM},
        {"external_resolution_stage1_em", DATABASE_RESOLUTION_STAGE1_EM},
        {"external_resolution_stage2_em", DATABASE_RESOLUTION_STAGE2_EM},
        {"external_resolution_stage3_em", DATABASE_RESOLUTION_STAGE3_EM},
        {"external_resolution_stage0_map_table_pbts", DATABASE_RESOLUTION_STAGE0_MAP_TABLE_PBTS},
        {"external_resolution_stage1_map_table_pbts", DATABASE_RESOLUTION_STAGE1_MAP_TABLE_PBTS},
        {"external_resolution_stage2_map_table_pbts", DATABASE_RESOLUTION_STAGE2_MAP_TABLE_PBTS},
        {"external_resolution_stage3_map_table_pbts", DATABASE_RESOLUTION_STAGE3_MAP_TABLE_PBTS},
        {"external_lp_queuing_em", DATABASE_LP_QUEUING_EM},
        {"external_mc_em_db", DATABASE_TM_MC_EM},
        {"external_central_em", DATABASE_CENTRAL_EM},
        {"external_central_tcam", DATABASE_CENTRAL_TCAM},
        {"external_fi_core_tcam", DATABASE_FI_CORE_TCAM},
        {"external_light_fi_nw_0_table", DATABASE_LIGHT_FI_NW0_TCAM},
        {"external_light_fi_nw_1_table", DATABASE_LIGHT_FI_NW1_TCAM},
        {"external_light_fi_nw_2_table", DATABASE_LIGHT_FI_NW2_TCAM},
        {"external_light_fi_nw_3_table", DATABASE_LIGHT_FI_NW3_TCAM},
        {"external_em_dlp_profile_hw_table", DATABASE_DLP_PROFILE_EM}};

    auto it = database_enum_map.find(database_name);
    if (it != database_enum_map.end()) {
        ret = it->second;
        return true;
    }

    // this is a valid option
    ret = DATABASE_NONE;
    return true;
}

bool
microcode_parser::get_database_block_enum(const std::string& block_name, database_block_e& ret)
{
    static const std::map<std::string, database_block_e> db_block_enum_map{
        {"rxpp_fwd.npe", DATABASE_BLOCK_INTERNAL_RXPP_FWD},
        {"rxpp_term.npe", DATABASE_BLOCK_INTERNAL_RXPP_TERM},
        {"txpp.npe", DATABASE_BLOCK_INTERNAL_TXPP},
        {"npuh.npe", DATABASE_BLOCK_INTERNAL_NPUH},
        {"cdb_top", DATABASE_BLOCK_EXTERNAL_CDB_TOP},
        {"cdb_core", DATABASE_BLOCK_EXTERNAL_CDB_CORE},
        {"idb_res", DATABASE_BLOCK_EXTERNAL_IDB_RES},
        {"idb_macdb", DATABASE_BLOCK_EXTERNAL_IDB_MACDB},
        {"idb_encdb", DATABASE_BLOCK_EXTERNAL_IDB_ENCDB},
        {"rxpp_fwd", DATABASE_BLOCK_EXTERNAL_RXPP_FWD},
        {"rxpp_fwd.flc_queues", DATABASE_BLOCK_EXTERNAL_RXPP_FWD_FLC_QUEUES},
        {"rxpp_fwd.cdb_cache", DATABASE_BLOCK_EXTERNAL_RXPP_FWD_CDB_CACHE},
        {"rxpp_term", DATABASE_BLOCK_EXTERNAL_RXPP_TERM},
        {"rxpp_term.fi", DATABASE_BLOCK_EXTERNAL_RXPP_TERM_FI_ENG},
        {"rxpp_term.sna", DATABASE_BLOCK_EXTERNAL_RXPP_TERM_SNA},
        {"rxpp_term.flc_db", DATABASE_BLOCK_EXTERNAL_RXPP_TERM_FLC_DB},
        {"txpp", DATABASE_BLOCK_EXTERNAL_TXPP},
        {"ene_cluster", DATABASE_BLOCK_EXTERNAL_ENE_CLUSTER},
        {"fi_stage", DATABASE_BLOCK_EXTERNAL_RXPP_TERM_FI_STAGE},
        {"npu_host", DATABASE_BLOCK_EXTERNAL_NPUH_HOST},
        {"npu_host.fi", DATABASE_BLOCK_EXTERNAL_NPUH_FI_ENG},
        {"pdvoq_slice", DATABASE_BLOCK_EXTERNAL_PDVOQ_SLICE},
        {"dram_cgm", DATABASE_BLOCK_EXTERNAL_DRAM_CGM},
        {"rx_pdr_2_slices", DATABASE_BLOCK_EXTERNAL_RX_PDR_2_SLICES},
        {"pdoq", DATABASE_BLOCK_EXTERNAL_PDOQ},
        {"filb_slice", DATABASE_BLOCK_EXTERNAL_FILB_SLICE},
        {"rx_pdr_shared_db", DATABASE_BLOCK_EXTERNAL_RX_PDR_SHARED_DB},
        {"counters", DATABASE_BLOCK_EXTERNAL_COUNTERS},
        {"counters_bank_group", DATABASE_BLOCK_EXTERNAL_COUNTERS_BANK_GROUP},
        {"rx_counters", DATABASE_BLOCK_EXTERNAL_RX_COUNTERS},
        {"txpdr", DATABASE_BLOCK_EXTERNAL_TXPDR},
        {"rx_meter", DATABASE_BLOCK_EXTERNAL_RX_METER},
        {"reassembly", DATABASE_BLOCK_EXTERNAL_REASSEMBLY},
        {"rx_meter_block", DATABASE_BLOCK_EXTERNAL_RX_METER_BLOCK},
        {"frm", DATABASE_BLOCK_EXTERNAL_FRM}};

    ret = DATABASE_BLOCK_NUM;

    auto it = db_block_enum_map.find(block_name);
    if (it != db_block_enum_map.end()) {
        ret = it->second;
        return true;
    }

    return false;
}

bool
microcode_parser::get_resource_type_enum(const std::string& resource_type_name, resource_type_e& ret)
{
    static const std::map<std::string, resource_type_e> resource_type_enum_map{
        {"tcam", RESOURCE_TYPE_TCAM},
        // Compiler provides "reg_tcam" as a type, while we don't need it anymore.
        // Therefore setting "tcam" as type.
        {"reg_tcam", RESOURCE_TYPE_TCAM},
        {"sram", RESOURCE_TYPE_SRAM},
        {"register", RESOURCE_TYPE_REGISTER}};

    auto it = resource_type_enum_map.find(resource_type_name);
    if (it != resource_type_enum_map.end()) {
        ret = it->second;
        return true;
    }

    return false;
}

bool
microcode_parser::get_translation_type_enum(const std::string& translation_name, translation_type_e& ret)
{
    static const std::map<std::string, translation_type_e> translation_type_enum_map{
        {"exact", TRANSLATION_TYPE_EXACT},
        {"ternary", TRANSLATION_TYPE_TERNARY},
        {"reg_tcam", TRANSLATION_TYPE_REG_TCAM},
        {"reg_sram", TRANSLATION_TYPE_REG_SRAM},
        {"multival_reg", TRANSLATION_TYPE_MULTIVAL_REG},
        {"cem_arc", TRANSLATION_TYPE_CEM_ARC},
        {"ctm", TRANSLATION_TYPE_CTM},
        {"lpm", TRANSLATION_TYPE_LPM},
        {"multival_sram", TRANSLATION_TYPE_MULTIVAL_SRAM},
        {"none", TRANSLATION_TYPE_NONE}};

    auto it = translation_type_enum_map.find(translation_name);
    if (it != translation_type_enum_map.end()) {
        ret = it->second;
        return true;
    }

    return false;
}

bool
microcode_parser::get_npl_context_enum(const std::string& context_name, npl_context_e& ret) const
{
    static const std::map<std::string, npl_context_e> npl_context_enum_map{{"fabric", NPL_FABRIC_CONTEXT},
                                                                           {"fabric_element", NPL_FABRIC_ELEMENT_CONTEXT},
                                                                           {"network", NPL_NETWORK_CONTEXT},
                                                                           {"host", NPL_HOST_CONTEXT},
                                                                           {"udc", NPL_UDC_CONTEXT}};

    auto it = npl_context_enum_map.find(context_name);
    if (it != npl_context_enum_map.end()) {
        ret = it->second;
        return true;
    }

    // the rest does not have context
    ret = NPL_NONE_CONTEXT;
    return true;
}

bool
microcode_parser::get_allocation_enum(const std::string& allocation, allocation_e& ret)
{
    static const std::map<std::string, allocation_e> allocation_type_enum_map{
        {"device", ALLOCATION_DEVICE}, {"slice", ALLOCATION_SLICE}, {"slice_pair", ALLOCATION_SLICE_PAIR}};

    auto it = allocation_type_enum_map.find(allocation);
    if (it != allocation_type_enum_map.end()) {
        ret = it->second;
        return true;
    }

    return false;
}

bool
microcode_parser::string_to_location(const std::string& location, location_e& out_location)
{
    static const std::map<std::string, location_e> location_enum_map{{"external", LOCATION_EXTERNAL},
                                                                     {"internal", LOCATION_INTERNAL}};

    auto it = location_enum_map.find(location);
    if (it != location_enum_map.end()) {
        out_location = it->second;
        return true;
    }

    return false;
}

la_status
microcode_parser::build_resource_maps()
{
    const char* metadata_filename_env = getenv(MICROCODE_METADATA_FILE_ENVVAR);
    const char* base_outdir_env = getenv(BASE_OUTPUT_DIR_ENVVAR);

    std::stringstream ss;
    if (metadata_filename_env) {
        ss << metadata_filename_env;
    } else if (base_outdir_env) {
        ss << base_outdir_env << "/" << DEFAULT_MICROCODE_METADATA_FILE;
    } else {
        ss << DEFAULT_BASE_OUTPUT_DIR << "/" << DEFAULT_MICROCODE_METADATA_FILE;
    }

    std::string metadata_filename = ss.str();

    log_info(RA, "Initializing NPL Resource Mapping from %s.", metadata_filename.c_str());

    json_t* root;
    json_error_t error;

    root = json_load_file(metadata_filename.c_str(), 0, &error);
    if (!root) {
        log_err(RA, "NPL resource initialization failed. Could not open placement metadata file %s.", metadata_filename.c_str());
        return LA_STATUS_ENOTFOUND;
    }

    size_t table_count = 0;
    bool tables_ok = read_tables(root, table_count);
    if (!tables_ok) {
        log_err(RA, "Table initialization failed. Placement metadata file format is wrong.");
    }

    bool ucode_ok = read_ucode(root);
    if (!ucode_ok) {
        log_err(RA, "Microcode load failed. Placement metadata file format is wrong.");
    }

    json_decref(root);

    bool status = tables_ok && ucode_ok;
    if (!status) {
        return LA_STATUS_EINVAL;
    }

    log_info(RA, "Done initializing NPL Resource Mapping.");
    log_info(RA, "Microcode is loaded successfully. Tables are mapped. Found %ld table records.", table_count);

    return LA_STATUS_SUCCESS;
}

json_t*
microcode_parser::read_object(json_t* data, const char* tag) const
{
    json_t* ret = json_object_get(data, tag);
    dassert_crit(ret != nullptr, "Could not read tag: %s", tag);
    return ret;
}

bool
microcode_parser::create_table_resources_desc(const std::string& table_name,
                                              const std::string& res_name,
                                              const std::string& type,
                                              size_t offset,
                                              size_t start_line,
                                              size_t width,
                                              size_t arr_idx,
                                              size_t size,
                                              size_t section_idx,
                                              size_t resource_idx)
{
    table_resource_desc_multimap_entry_t entry(m_translator_count, table_resource_desc());
    table_resource_desc& desc(entry.second);

    bool type_status = get_resource_type_enum(type, desc.type_id);
    if (!type_status) {
        log_err(RA, "Could not find resource type by tag: %s in table: %s", type.c_str(), table_name.c_str());
        return false;
    }

    if (desc.type_id == RESOURCE_TYPE_REGISTER) {
        desc.register_name = res_name;
    } else {
        desc.memory_name = res_name;
    }

    desc.section_idx = section_idx;
    desc.resource_idx = resource_idx;
    desc.size = size;
    desc.start_line = start_line;
    desc.offset = offset;
    desc.width = width;
    desc.array_idx = arr_idx;

    m_resource_multimap.insert(entry);

    return true;
}

bool
microcode_parser::read_table_resource(const char* table_name,
                                      const char* engine_name,
                                      json_t* resource_data,
                                      size_t size,
                                      size_t section_idx,
                                      size_t resource_idx)
{
    bool ret = true;

    json_t* res_name_tag = read_object(resource_data, "name");
    std::string res_name = json_string_value(res_name_tag);

    json_t* type_tag = read_object(resource_data, "type");
    std::string type = json_string_value(type_tag);

    // the following fields are optional and have default value of zero.
    json_t* offset_tag = json_object_get(resource_data, "offset");
    size_t offset = (offset_tag) ? json_integer_value(offset_tag) : 0;

    json_t* start_line_tag = json_object_get(resource_data, "start_line");
    size_t start_line = (start_line_tag) ? json_integer_value(start_line_tag) : 0;

    json_t* width_tag = json_object_get(resource_data, "width");
    size_t width = (width_tag) ? json_integer_value(width_tag) : 0;

    json_t* arr_indices_tag = json_object_get(resource_data, "arr_idx");
    size_t arr_idx;

    if (!json_is_array(arr_indices_tag)) { // single index
        arr_idx = (arr_indices_tag) ? json_integer_value(arr_indices_tag) : 0;
        ret = create_table_resources_desc(
            table_name, res_name, type, offset, start_line, width, arr_idx, size, section_idx, resource_idx);
        return ret;
    }

    // multiple indices
    for (size_t i = 0; i < json_array_size(arr_indices_tag); i++) {
        json_t* arr_idx_tag = json_array_get(arr_indices_tag, i);
        arr_idx = json_integer_value(arr_idx_tag);
        ret &= create_table_resources_desc(
            table_name, res_name, type, offset, start_line, width, arr_idx, size, section_idx, resource_idx);
    }

    return ret;
}

bool
microcode_parser::read_table_placement(const char* table_name,
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
                                       json_t* payload_width_node)
{
    bool ret = true;

    // For external table, key width, payload width and translation type are properties of the table.
    // For internal table, they are properties of the placements (can be different between placements).
    if (location_id == LOCATION_INTERNAL) {
        translation_type_node = read_object(placement_data, "type");
        key_width_node = read_object(placement_data, "key_width");
        payload_width_node = read_object(placement_data, "payload_width");
    }

    json_t* block_node = read_object(placement_data, "engine");
    json_t* replication_idx_node = read_object(placement_data, "id");
    json_t* section_line_reversed = json_object_get(placement_data, "section_line_reversed");

    // TODO IGORS - some changes on the external_table_mappin cause a table with placements{} still think that there is a placement,
    // and translation_type gets nullptr.
    if (!translation_type_node) {
        return false;
    }

    translator_desc_multimap_entry_t entry(table_name, npl_table_translator_desc());
    npl_table_translator_desc& desc(entry.second);

    desc.replication_idx = json_integer_value(replication_idx_node);
    desc.translator_idx = m_translator_count;
    desc.npl_table_name = table_name;
    desc.context_id = context;
    desc.application_specific_fields_width = application_specific_fields_width;
    desc.logical_table_id = logical_id;
    desc.logical_table_id_width = logical_id_width;
    desc.logical_table_id_columns_values = logical_table_id_columns_values;
    desc.has_default_value = has_default_value;
    desc.has_placements = true;
    desc.section_line_reversed = (section_line_reversed == nullptr) ? false : json_boolean_value(section_line_reversed);
    desc.payload_width = json_integer_value(payload_width_node);

    // A physical table key can be wider than the NPL table using it.
    // For external tables, width in key_width_node includes the logical table ID bits.
    // For internal tables, width in key_width_node does not include the logical table ID bits.
    desc.key_width = (location_id == LOCATION_EXTERNAL) ? json_integer_value(key_width_node)
                                                        : json_integer_value(key_width_node) + desc.logical_table_id_width;

    const char* block_name = json_string_value(block_node);
    bool status = get_database_block_enum(block_name, desc.block_id);
    if (!status) {
        log_err(RA, "Could not map engine id by tag: %s in table: %s", block_name, table_name);
        return false;
    }

    std::string type_name = json_string_value(translation_type_node);
    status = get_translation_type_enum(type_name, desc.translation_id);
    if (!status) {
        log_err(RA, "Could not map line translation type id by tag: %s in table: %s", type_name.c_str(), table_name);
        return false;
    }

    status = get_allocation_enum(allocation, desc.allocation_id);
    if (!status) {
        log_err(RA, "Could not map allocation id by tag: %s in table: %s", allocation, table_name);
        return false;
    }

    status = get_database_enum(database, desc.database_id);
    if (!status) {
        log_err(RA, "Could not map database id by tag: %s in table: %s", database, table_name);
        return false;
    }

    m_translator_multimap.insert(entry);

    json_t* section_arr = read_object(placement_data, "sections");
    for (size_t i = 0; i < json_array_size(section_arr); i++) {
        json_t* section = json_array_get(section_arr, i);
        json_t* size_obj = json_object_get(section, "size");
        size_t size = (size_obj) ? json_integer_value(size_obj) : 0;
        json_t* resource_arr = read_object(section, "resources");

        for (size_t j = 0; j < json_array_size(resource_arr); j++) {
            json_t* resource = json_array_get(resource_arr, j);
            ret &= read_table_resource(table_name, block_name, resource, size, i, j);
        }
    }

    return ret;
}

bool
microcode_parser::get_contexts_table_is_accessed_from(const char* table_name,
                                                      json_t* table_data,
                                                      vector_alloc<npl_context_e>& out_valid_contexts) const
{
    json_t* accessed_from_contexts_arr = read_object(table_data, "accessed_from_contexts");

    for (size_t j = 0; j < json_array_size(accessed_from_contexts_arr); j++) {
        json_t* context_json = json_array_get(accessed_from_contexts_arr, j);
        std::string context_name = json_string_value(context_json);

        npl_context_e current_npl_context;
        bool status = get_npl_context_enum(context_name.c_str(), current_npl_context);
        if (!status) {
            log_err(RA, "Could not map context id by tag: %s in table: %s", context_name.c_str(), table_name);
            return false;
        }

        out_valid_contexts.push_back(current_npl_context);
    }

    if (out_valid_contexts.empty()) {
        out_valid_contexts.push_back(NPL_NONE_CONTEXT);
    }

    return true;
}

bool
microcode_parser::read_table_without_placement(const char* table_name,
                                               const char* database,
                                               const vector_alloc<npl_context_e>& contexts,
                                               const char* allocation,
                                               size_t logical_id,
                                               size_t logical_id_width,
                                               const logical_table_id_columns_values_t& logical_table_id_columns_values,
                                               bool has_default_value,
                                               json_t* translation_type_node,
                                               json_t* key_width_node,
                                               json_t* payload_width_node)
{
    dassert_crit(!contexts.empty());
    for (npl_context_e context : contexts) {
        translator_desc_multimap_entry_t entry(table_name, npl_table_translator_desc());
        npl_table_translator_desc& desc(entry.second);

        // partial descriptor
        desc.npl_table_name = table_name;
        desc.block_id = DATABASE_BLOCK_UNKNOWN;
        desc.context_id = context;
        desc.logical_table_id = logical_id;
        desc.logical_table_id_width = logical_id_width;
        desc.logical_table_id_columns_values = logical_table_id_columns_values;
        desc.has_default_value = has_default_value;
        desc.has_placements = false;
        desc.application_specific_fields_width = 0;

        bool status = get_allocation_enum(allocation, desc.allocation_id);
        if (!status) {
            log_err(RA, "Could not map allocation id by tag: %s in table: %s", allocation, table_name);
            return false;
        }

        const char* type = json_string_value(translation_type_node);
        status = get_translation_type_enum(type, desc.translation_id);
        if (!status) {
            log_err(RA, "Could not map line translation type id by tag: %s in table: %s", type, table_name);
            return false;
        }

        status = get_database_enum(database, desc.database_id);
        if (!status) {
            log_err(RA, "Could not map database id by tag: %s in table: %s", database, table_name);
            return false;
        }

        m_translator_multimap.insert(entry);
    }

    return true;
}

bool
microcode_parser::read_table(const char* table_name, json_t* table_data)
{
    bool ret = true;

    // Read table properties
    json_t* location_tag = json_object_get(table_data, "location");
    const char* location = (location_tag) ? json_string_value(location_tag) : "none";
    location_e location_id;
    ret = string_to_location(location, location_id);
    if (!ret) {
        log_err(RA, "Could not map location id by tag: %s in table: %s", location, table_name);
        return false;
    }

    json_t* allocation_tag = json_object_get(table_data, "allocation");
    const char* allocation = (allocation_tag) ? json_string_value(allocation_tag) : "slice";

    json_t* database_tag = json_object_get(table_data, "database");
    const char* database = (database_tag) ? json_string_value(database_tag) : "none";

    json_t* logical_id_tag = json_object_get(table_data, "logical_table_id_value");
    size_t logical_id = (logical_id_tag) ? json_integer_value(logical_id_tag) : 0;

    json_t* logical_id_width_tag = json_object_get(table_data, "logical_table_id_width");
    size_t logical_id_width = (logical_id_width_tag) ? json_integer_value(logical_id_width_tag) : 0;

    json_t* key_consts_per_opt_tag = json_object_get(table_data, "key_consts_per_opt");
    logical_table_id_columns_values_t logical_table_id_columns_values;
    if (key_consts_per_opt_tag) {
        size_t logical_key_index;
        json_t* logical_key_tag;
        json_array_foreach(key_consts_per_opt_tag, logical_key_index, logical_key_tag)
        {
            size_t index;
            json_t* logical_key_column_val;
            json_array_foreach(logical_key_tag, index, logical_key_column_val)
            {
                size_t lsb = json_integer_value(read_object(logical_key_column_val, "lsb"));
                const char* val = json_string_value(read_object(logical_key_column_val, "value_in_hex"));
                size_t width = json_integer_value(read_object(logical_key_column_val, "width"));

                logical_table_id_columns_values[lsb] = bit_vector(val, width);
                dassert_crit(logical_table_id_columns_values[lsb].get_width() == width,
                             "value_in_hex %s need more than %d bits to represent",
                             val,
                             width);
            }
        }
    }

    // Optional fields
    json_t* has_default_value_tag = json_object_get(table_data, "has_default_action");
    bool has_default_value = (has_default_value_tag) ? json_boolean_value(has_default_value_tag) : false;

    json_t* application_specific_fields_width_tag = json_object_get(table_data, "application_specific_fields_width");
    size_t application_specific_fields_width
        = (application_specific_fields_width_tag) ? json_integer_value(application_specific_fields_width_tag) : 0;

    // For internal tables, the following fields are given only inside the placements data
    json_t* translation_type_node = (location_id == LOCATION_EXTERNAL) ? json_object_get(table_data, "translation_type") : nullptr;
    json_t* key_width_node = (location_id == LOCATION_EXTERNAL) ? json_object_get(table_data, "translated_key_width") : nullptr;
    json_t* payload_width_node
        = (location_id == LOCATION_EXTERNAL) ? json_object_get(table_data, "translated_payload_width") : nullptr;

    json_t* placements = json_object_get(table_data, "placements");

    // Could not read table placements
    if (!placements) {
        vector_alloc<npl_context_e> valid_contexts;
        ret &= get_contexts_table_is_accessed_from(table_name, table_data, valid_contexts);
        ret &= read_table_without_placement(table_name,
                                            database,
                                            valid_contexts,
                                            allocation,
                                            logical_id,
                                            logical_id_width,
                                            logical_table_id_columns_values,
                                            has_default_value,
                                            translation_type_node,
                                            key_width_node,
                                            payload_width_node);
        m_translator_count++;
        return ret;
    }

    // Read and store table's placements properties
    const char* placement;
    json_t* placement_arr;
    json_object_foreach(placements, placement, placement_arr)
    {
        for (size_t i = 0; i < json_array_size(placement_arr); i++) {
            json_t* placement_data = json_array_get(placement_arr, i);
            vector_alloc<npl_context_e> valid_contexts;

            // Each placement should have context. In case the compiler doesn't know the context of the placement we will check from
            // which context this table is accessed from and create the table accordingly.
            // If the compiler doesn't knows the context it will always be NPL_NONE_CONTEXT, while if it knows it will never be
            // NPL_NONE_CONTEXT.
            npl_context_e placement_context;
            bool status = get_npl_context_enum(placement, placement_context);
            if (!status) {
                log_err(RA, "Could not map microcode context id by tag: %s.", placement);
                return false;
            }

            if (placement_context != NPL_NONE_CONTEXT) {
                valid_contexts.push_back(placement_context);
            } else {
                ret &= get_contexts_table_is_accessed_from(table_name, table_data, valid_contexts);
            }

            for (npl_context_e context : valid_contexts) {
                ret &= read_table_placement(table_name,
                                            location_id,
                                            database,
                                            context,
                                            false,
                                            allocation,
                                            logical_id,
                                            logical_id_width,
                                            logical_table_id_columns_values,
                                            application_specific_fields_width,
                                            has_default_value,
                                            placement_data,
                                            translation_type_node,
                                            key_width_node,
                                            payload_width_node);
                m_translator_count++;
            }
        }
    }

    return ret;
}

bool
microcode_parser::read_tables(json_t* root, size_t& table_count)
{
    table_count = 0;

    json_t* table_list = json_object_get(root, "tables");
    if (!table_list) {
        return false;
    }

    const char* table_name;
    json_t* data;
    json_object_foreach(table_list, table_name, data)
    {
        bool ret = read_table(table_name, data);
        if (!ret) {
            log_err(RA, "Could not read table: %s", table_name);
            continue;
        }
        table_count++;
    }

    // TODO: Currently we are tolerant for GB, but it should be strict like Pacific.
    return true;
}

bool
microcode_parser::read_resource_name_and_arr_idx(json_t* ucode_resource_root, const char*& res_name, size_t& arr_idx)
{
    json_t* res_name_obj = read_object(ucode_resource_root, "name");
    json_t* res_arr_idx_obj = read_object(ucode_resource_root, "arr_idx");

    if (!res_name_obj || !res_arr_idx_obj) {
        return false;
    }
    arr_idx = json_integer_value(res_arr_idx_obj);
    res_name = json_string_value(res_name_obj);

    return true;
}

bool
microcode_parser::read_ucode_sram_resource(const char* engine_name, json_t* ucode_resource_root, ucode_resource_desc& res_desc)
{
    const char* res_name;
    bool status = read_resource_name_and_arr_idx(ucode_resource_root, res_name, res_desc.array_idx);
    if (!status) {
        return false;
    }

    res_desc.memory_name = res_name;

    json_t* entries = read_object(ucode_resource_root, "entries");
    for (size_t i = 0; i < json_array_size(entries); i++) {
        res_desc.entries.push_back(ucode_entry_desc());
        ucode_entry_desc& entry_desc = res_desc.entries.back();

        json_t* entry = json_array_get(entries, i);

        json_t* line = read_object(entry, "line");
        json_t* width = read_object(entry, "width_in_bits");
        json_t* offset = read_object(entry, "offset_from_lsb");
        json_t* data = read_object(entry, "data");

        entry_desc.line = json_integer_value(line);
        entry_desc.offset = json_integer_value(offset);
        size_t data_width = json_integer_value(width);
        std::string data_value = json_string_value(data);
        entry_desc.data = bit_vector(data_value, data_width);
    }

    return true;
}

bool
microcode_parser::read_ucode_tcam_resource(const char* engine_name, json_t* ucode_resource_root, ucode_resource_desc& res_desc)
{
    const char* res_name;
    bool status = read_resource_name_and_arr_idx(ucode_resource_root, res_name, res_desc.array_idx);
    if (!status) {
        return false;
    }

    res_desc.memory_name = res_name;

    json_t* entries = read_object(ucode_resource_root, "entries");
    for (size_t i = 0; i < json_array_size(entries); i++) {
        res_desc.entries.push_back(ucode_entry_desc());
        ucode_entry_desc& entry_desc = res_desc.entries.back();

        json_t* entry = json_array_get(entries, i);

        json_t* line = read_object(entry, "line");
        json_t* key = read_object(entry, "key");
        json_t* mask = read_object(entry, "mask_n");

        entry_desc.line = json_integer_value(line);
        std::string key_value = json_string_value(key);
        std::string mask_value = json_string_value(mask);
        entry_desc.key = bit_vector(key_value);
        entry_desc.mask = bit_vector(mask_value);
    }

    return true;
}

bool
microcode_parser::read_ucode_register_resource(const char* engine_name, json_t* ucode_resource_root, ucode_resource_desc& res_desc)
{
    const char* res_name;
    bool status = read_resource_name_and_arr_idx(ucode_resource_root, res_name, res_desc.array_idx);
    if (!status) {
        return false;
    }

    res_desc.register_name = res_name;

    res_desc.entries.push_back(ucode_entry_desc());
    ucode_entry_desc& entry_desc = res_desc.entries.back();

    json_t* data = read_object(ucode_resource_root, "data");
    std::string data_value = json_string_value(data);
    entry_desc.data = bit_vector(data_value);

    return true;
}

bool
microcode_parser::read_ucode_engine(const char* engine_name, json_t* ucode_engine_root, ucode_engine_desc& engine)
{
    bool ret = true;
    for (size_t i = 0; i < json_array_size(ucode_engine_root); i++) {
        json_t* resource = json_array_get(ucode_engine_root, i);

        resource_type_e type;
        json_t* res_type = read_object(resource, "type");
        const char* res_type_str = json_string_value(res_type);
        bool status = get_resource_type_enum(res_type_str, type);
        if (!status) {
            log_err(RA, "Could not find microcode resource type by tag: %s", res_type_str);
            ret = false;
            continue;
        }

        engine.resources[type].push_back(ucode_resource_desc());
        ucode_resource_desc& res_desc = engine.resources[type].back();

        switch (type) {
        case RESOURCE_TYPE_SRAM:
            ret &= read_ucode_sram_resource(engine_name, resource, res_desc);
            break;
        case RESOURCE_TYPE_TCAM:
            ret &= read_ucode_tcam_resource(engine_name, resource, res_desc);
            break;
        case RESOURCE_TYPE_REGISTER:
            ret &= read_ucode_register_resource(engine_name, resource, res_desc);
            break;
        default:
            dassert_crit(false);
            break;
        }
    }

    return ret;
}

bool
microcode_parser::read_ucode_for_context(const char* context_name, json_t* ucode_context_root)
{
    bool status = true;

    npl_context_e context;
    status = get_npl_context_enum(context_name, context);
    if (!status) {
        log_err(RA, "Could not map microcode context id by tag: %s.", context_name);
        return false;
    }

    ucode_t& ucode = m_ucode[context];
    m_curr_ucode_context = context_name;

    const char* engine_name;
    json_t* data;
    json_t* default_root = nullptr;
    if (is_gibraltar(m_device_revision)) {
        default_root = json_object_get(ucode_context_root, "default");
    } else {
        log_err(RA, "Unsupported device revision %d - this is not a Gibraltar device.", (int)m_device_revision);
        return false;
    }

    json_object_foreach(default_root, engine_name, data)
    {
        ucode.push_back(ucode_engine_desc());
        ucode_engine_desc& engine = ucode.back();
        status = get_database_block_enum(engine_name, engine.engine_id);
        if (!status) {
            log_err(RA, "Could not map microcode engine id by tag: %s in context: %s", engine_name, m_curr_ucode_context.c_str());
            return false;
        }

        status &= read_ucode_engine(engine_name, data, engine);
    }

    std::sort(ucode.begin(), ucode.end(), ucode_engine_desc_compare);
    m_curr_ucode_context = "none";

    return status;
}

bool
microcode_parser::read_ucode(json_t* root)
{
    bool ret = true;

    json_t* ucodes = json_object_get(root, "microcode");
    if (!ucodes) {
        return false;
    }

    const char* context_name;
    json_t* data;
    json_object_foreach(ucodes, context_name, data)
    {
        ret &= read_ucode_for_context(context_name, data);
    }

    return ret;
}

} // namespace silicon_one
