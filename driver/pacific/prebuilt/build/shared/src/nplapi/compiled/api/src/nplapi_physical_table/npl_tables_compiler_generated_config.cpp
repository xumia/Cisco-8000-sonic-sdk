
// This file has been automatically generated using nplc.py. Do not edit it manually.
// Version: 1.76.2_0.0.0.0 generated on devsrv15.leaba.local at 2021-05-12 16:09:15


#include "npl_tables_compiler_generated_config.h"
#include "av_lld/lld_addresses_enums.h" // TODO remove this!
#include <assert.h>
#include <stdint.h>

using namespace silicon_one;

table_compiler_generated_config_t npl_tables_compiler_generated_config::get_table_config(npl_tables_e table_name, npl_context_e context)
{
    if (table_name == NPL_TABLES_ACL_MAP_FI_HEADER_TYPE_TO_PROTOCOL_NUMBER_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 32;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 256;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_ADDITIONAL_LABELS_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(16 /* key_width */, 120 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_SMALL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_ALL_REACHABLE_VECTOR) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 108 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_DUMMY_ALL_REACHABLE_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_DESIRED_TX_INTERVAL_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 8;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 288;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_DETECTION_MULTIPLE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 8;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 96;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_EVENT_QUEUE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(72 /* key_width */, 0 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_NPUH_CPU_EVQ;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_INJECT_INNER_DA_HIGH_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_INJECT_INNER_DA_LOW_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_INJECT_INNER_ETHERNET_HEADER_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 60 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 60;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_INJECT_TTL_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 64;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_IPV6_SIP_A_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_IPV6_SIP_B_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_IPV6_SIP_C_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 32;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_IPV6_SIP_D_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 60;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_PUNT_ENCAP_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 28 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 256;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 28;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_REQUIRED_TX_INTERVAL_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 8;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 256;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_RX_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(49 /* key_width */, 44 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_SET_INJECT_TYPE_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 64;
            curr_entry->sram_config.offset_in_line = 44;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BFD_UDP_PORT_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 48 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 32;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 48;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BITMAP_OQG_MAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 8 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_TXPDR_OQG_MAP_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_BVN_TC_MAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 64;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 20;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_CALC_CHECKSUM_ENABLE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 1 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CALC_CHECKSUM_ENABLE_HW_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_CCM_FLAGS_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 64;
            curr_entry->sram_config.offset_in_line = 8;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_CIF2NPA_C_LRI_MACRO) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 8 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LRI_FIRST_MACRO_ID;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_CIF2NPA_C_MPS_MACRO) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 8 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_NPU_HOST_FIRST_MACRO_ID;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_COUNTERS_BLOCK_CONFIG_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(7 /* key_width */, 24 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_COUNTERS_BLOCK_CONFIG;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_COUNTERS_VOQ_BLOCK_MAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(10 /* key_width */, 23 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_VOQ_COUNTERS_VOQ_BLOCK_MAP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_CUD_IS_MULTICAST_BITMAP) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 1 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CUD_IS_MULTICAST_BITMAP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_CUD_NARROW_HW_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 40 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CUD_NARROW_HW_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_CUD_WIDE_HW_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(12 /* key_width */, 80 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CUD_WIDE_HW_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_DEST_SLICE_VOQ_MAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 16 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_DEST_SLICE_VOQ_MAP_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_DESTINATION_DECODING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 8 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_DESTINATION_DECODING;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_DEVICE_MODE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 2 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_DUMMY_DEVICE_MODE_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_DSP_L2_ATTRIBUTES_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 52 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 64;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 52;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_DSP_L3_ATTRIBUTES_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 40 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 64;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 64;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 40;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_DUMMY_DIP_INDEX_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(9 /* key_width */, 1 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_DIP_INDEX;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_EGRESS_NH_AND_SVI_DIRECT0_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(12 /* key_width */, 119 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_DIRECT0;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_EGRESS_NH_AND_SVI_DIRECT1_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(10 /* key_width */, 119 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_DIRECT1;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_EM_MP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(50 /* key_width */, 40 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_NPUH_ETH_MP_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_EM_PFC_CONG_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(50 /* key_width */, 40 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_NPUH_ETH_MP_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_ENE_MACRO_CODE_TPID_PROFILE_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 24 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 64;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 24;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_ETH_METER_PROFILE_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 256;
            curr_entry->sram_config.offset_in_line = 32;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_ETH_OAM_SET_DA_MC2_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 32;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_ETH_OAM_SET_DA_MC_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 320;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_ETH_RTF_CONF_SET_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(10 /* key_width */, 12 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 1024;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 12;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_EVE_BYTE_ADDITION_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 32;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_EVE_TO_ETHERNET_ENE_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(7 /* key_width */, 24 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 128;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 1600;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 24;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_EVENT_QUEUE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(10 /* key_width */, 61 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_NPUH_CPU_EVQ;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_EXTERNAL_AUX_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(12 /* key_width */, 160 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_NPUH_AUX;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_HEADER_TYPES_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_RX_FWD_ERROR_HANDLING_COUNTER_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_RX_FWD_ERROR_HANDLING_DESTINATION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_RX_TERM_ERROR_HANDLING_COUNTER_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_RX_TERM_ERROR_HANDLING_DESTINATION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_SCALED_MC_MAP_TO_NETORK_SLICE_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_SMCID_THRESHOLD_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 32;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_TM_HEADERS_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(7 /* key_width */, 12 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 128;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 12;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FB_LINK_2_LINK_BUNDLE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(7 /* key_width */, 6 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_FB_LINK_2_LINK_BUNDLE_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FE_BROADCAST_BMP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(7 /* key_width */, 108 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_FE_BROADCAST_BMP_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FE_RLB_UC_TX_FB_LINK_TO_OQ_MAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(7 /* key_width */, 9 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_FE_RLB_UC_TX_FB_LINK_TO_OQ_MAP_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FE_SMCID_THRESHOLD_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_ELEMENT_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_FABRIC_ELEMENT;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FE_SMCID_TO_MCID_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(15 /* key_width */, 128 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_LP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FE_UC_LINK_BUNDLE_DESC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 88 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_FE_UC_LINK_BUNDLE_DESC_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FI_MACRO_CONFIG_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 72 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_FI_CORE_MACRO_CONFIG;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FILB_VOQ_MAPPING) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(16 /* key_width */, 26 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_FILB_VOQ_MAPPING_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FIRST_ENE_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 8;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 32;
            curr_entry->sram_config.offset_in_line = 8;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FRM_DB_FABRIC_ROUTING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(9 /* key_width */, 108 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_FRM_DB_FABRIC_ROUTING_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FWD_DESTINATION_TO_TM_RESULT_DATA) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(20 /* key_width */, 33 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RX_TO_TX_DESTINATION;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FWD_TYPE_TO_IVE_ENABLE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 1 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_FWD_TYPE_TO_IVE_ENABLE_HW_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_GET_ECM_METER_PTR_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 32;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_GET_INGRESS_PTP_INFO_AND_IS_SLP_DM_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 256;
            curr_entry->sram_config.offset_in_line = 20;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_GET_L2_RTF_CONF_SET_AND_INIT_STAGES) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_GET_NON_COMP_MC_VALUE_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 4;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_GRE_PROTO_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 24 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 64;
            curr_entry->sram_config.offset_in_line = 40;
            curr_entry->sram_config.width_in_bits = 24;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_HMC_CGM_CGM_LUT_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(12 /* key_width */, 3 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_VOQ_CGM_CGMLUT;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_HMC_CGM_PROFILE_GLOBAL_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 284 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_VOQ_CGM_PROFILE_GLOBAL;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IBM_CMD_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 49 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_IBM_CMD_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IBM_MC_CMD_TO_ENCAP_DATA_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 28 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 32;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 28;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IBM_UC_CMD_TO_ENCAP_DATA_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 80 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 32;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 80;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IFGB_TC_LUT_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(11 /* key_width */, 6 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_IFGB_TC_LUT;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_IP_QOS_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(11 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2048;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INJECT_DOWN_TX_REDIRECT_COUNTER_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(12 /* key_width */, 21 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_EM_1;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INJECT_MACT_LDB_TO_OUTPUT_LR) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 4 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MACT_LDB;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INJECT_UP_PIF_IFG_INIT_DATA_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(16 /* key_width */, 59 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_EM_1;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INJECT_UP_SSP_INIT_DATA_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(17 /* key_width */, 48 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_EM_1;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INNER_TPID_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IP_FWD_HEADER_MAPPING_TO_ETHTYPE_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 52;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IP_MC_LOCAL_INJECT_TYPE_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 32;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 32;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IP_MC_NEXT_MACRO_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 12 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 4;
            curr_entry->sram_config.width_in_bits = 12;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IP_METER_PROFILE_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 256;
            curr_entry->sram_config.offset_in_line = 36;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IP_PREFIX_DESTINATION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(24 /* key_width */, 20 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IP_RELAY_TO_VNI_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(25 /* key_width */, 112 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IP_RX_GLOBAL_COUNTER_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 256;
            curr_entry->sram_config.offset_in_line = 44;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV4_ACL_SPORT_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 8;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 32;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV4_IP_TUNNEL_TERMINATION_DIP_INDEX_TT0_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(25 /* key_width */, 129 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_TUNNEL0;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV4_IP_TUNNEL_TERMINATION_SIP_DIP_INDEX_TT0_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(57 /* key_width */, 129 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_TUNNEL0;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV4_IP_TUNNEL_TERMINATION_SIP_DIP_INDEX_TT1_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(57 /* key_width */, 129 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_TUNNEL1;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV4_OG_PCL_EM_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(46 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV4_RTF_CONF_SET_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(10 /* key_width */, 24 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 1024;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 24;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV4_VRF_DIP_EM_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(46 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV4_VRF_S_G_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(76 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV6_ACL_SPORT_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 8;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 32;
            curr_entry->sram_config.offset_in_line = 8;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV6_MC_SELECT_QOS_ID) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 8 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_UNKNOWN;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV6_OG_PCL_EM_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(142 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV6_RTF_CONF_SET_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(10 /* key_width */, 24 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 1024;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 24;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV6_VRF_DIP_EM_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(142 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV6_VRF_S_G_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(65 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IS_PACIFIC_B1_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 96;
            curr_entry->sram_config.offset_in_line = 8;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L2_DLP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(22 /* key_width */, 118 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L2_LP_PROFILE_FILTER_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 24;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L2_LPTS_IP_FRAGMENT_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 384;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L2_LPTS_SKIP_P2P_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 8;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L2_TUNNEL_TERM_NEXT_MACRO_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 12 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 32;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 12;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L3_DLP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(15 /* key_width */, 138 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_L3_DLP0;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L3_VXLAN_OVERLAY_SA_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LARGE_ENCAP_GLOBAL_LSP_PREFIX_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(20 /* key_width */, 80 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LARGE_ENCAP_IP_TUNNEL_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(20 /* key_width */, 120 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LARGE_ENCAP_MPLS_HE_NO_LDP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(32 /* key_width */, 80 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LARGE_ENCAP_MPLS_LDP_OVER_TE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(36 /* key_width */, 45 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LARGE_ENCAP_TE_HE_TUNNEL_ID_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(32 /* key_width */, 80 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LATEST_LEARN_RECORDS_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 88 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LATEST_LR;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LEARN_MANAGER_CFG_MAX_LEARN_TYPE_REG) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 2 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LM_CFG_MAX_REG;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LEARN_RECORD_FIFO_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 88 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LR_FIFO;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LIGHT_FI_FABRIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 37 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LIGHT_FI_FABRIC_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LIGHT_FI_NPU_BASE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 37 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LIGHT_FI_NPU_BASE_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LIGHT_FI_NPU_ENCAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 37 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LIGHT_FI_NPU_ENCAP_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LIGHT_FI_STAGES_CFG_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 20 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LIGHT_FI_STAGES_CFG;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LIGHT_FI_TM_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 37 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LIGHT_FI_TM_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LINK_RELAY_ATTRIBUTES_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(12 /* key_width */, 54 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_LINK_RELAY;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LINK_UP_VECTOR) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 108 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_DUMMY_LINK_UP_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LP_OVER_LAG_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(41 /* key_width */, 20 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LPM_DESTINATION_PREFIX_MAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 7 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LPM_DEST_PREFIX_MAP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LPTS_2ND_LOOKUP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 28 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 32;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 288;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 28;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LPTS_METER_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LR_FILTER_WRITE_PTR_REG) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 5 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LRC_FILTER_FIFO_WRITE_PTR_REG;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LR_WRITE_PTR_REG) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 4 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LRC_FIFO_WRITE_PTR_REG;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAC_AF_NPP_ATTRIBUTES_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 52 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 52;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAC_FORWARDING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(66 /* key_width */, 32 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAC_MC_EM_TERMINATION_ATTRIBUTES_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(16 /* key_width */, 120 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_TERMINATION_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAC_QOS_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAC_RELAY_G_IPV4_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(49 /* key_width */, 20 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAC_RELAY_G_IPV6_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(141 /* key_width */, 20 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAC_RELAY_TO_VNI_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(18 /* key_width */, 44 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAC_TERMINATION_EM_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(40 /* key_width */, 120 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_TERMINATION_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAC_TERMINATION_NO_DA_EM_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(16 /* key_width */, 120 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_TERMINATION_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAP_ENE_SUBCODE_TO8BIT_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 32;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 96;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAP_MORE_LABELS_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 24 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 256;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 24;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAP_RECYLE_TX_TO_RX_DATA_ON_PD_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 32;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAP_TM_DP_ECN_TO_WA_ECN_DP_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MC_BITMAP_BASE_VOQ_LOOKUP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 18 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MC_BITMAP_BASE_VOQ_LOOKUP_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MC_BITMAP_TC_MAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 3 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MC_BITMAP_TC_MAP_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MC_COPY_ID_MAP) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 13 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MC_COPY_ID_MAP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MC_CUD_IS_WIDE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 1 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CUD_IS_WIDE_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MC_EM_DB) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(32 /* key_width */, 72 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MC_EM_DB;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MC_EMDB_TC_MAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 3 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MC_EMDB_TC_MAP_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MC_FE_LINKS_BMP) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(16 /* key_width */, 109 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MC_FE_LINKS_BMP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MC_IBM_CUD_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(9 /* key_width */, 129 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_DIP_INDEX;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MC_SLICE_BITMAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(16 /* key_width */, 12 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MC_SLICE_BITMAP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MEP_ADDRESS_PREFIX_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 320;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MII_LOOPBACK_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 2 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MII_LOOPBACK_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MIRROR_CODE_HW_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 5 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MIRROR_CODE_HW_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MIRROR_EGRESS_ATTRIBUTES_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(9 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 512;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 512;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MIRROR_TO_DSP_IN_NPU_SOFT_HEADER_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 32;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 64;
            curr_entry->sram_config.offset_in_line = 4;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MLDP_PROTECTION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(9 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 512;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MP_AUX_DATA_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(12 /* key_width */, 160 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_NPUH_AUX;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MP_DATA_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 200 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_NPUH_MP_DATA;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MPLS_ENCAP_CONTROL_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 64;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 32;
            curr_entry->sram_config.offset_in_line = 8;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MPLS_FORWARDING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(27 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MPLS_HEADER_OFFSET_IN_BYTES_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 32;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MPLS_L3_LSP_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 8;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MPLS_LABELS_1_TO_4_JUMP_OFFSET_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 64;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MPLS_LSP_LABELS_CONFIG_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 64;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 1728;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MPLS_QOS_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(7 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 128;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 52;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MPLS_TERMINATION_EM0_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(22 /* key_width */, 49 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_EM_0;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MPLS_TERMINATION_EM1_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(22 /* key_width */, 49 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_EM_1;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MS_VOQ_FABRIC_CONTEXT_OFFSET_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 16 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MS_VOQ_FABRIC_CONTEXT_OFFSET_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NATIVE_CE_PTR_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(17 /* key_width */, 99 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_NATIVE_LP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NATIVE_FEC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(12 /* key_width */, 56 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_NATIVE_FEC;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NATIVE_FEC_TYPE_DECODING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 63 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_NATIVE_FEC_TYPE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NATIVE_FRR_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 119 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_NATIVE_FRR;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NATIVE_FRR_TYPE_DECODING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 63 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_NATIVE_FRR_TYPE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NATIVE_L2_LP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(18 /* key_width */, 99 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_NATIVE_LP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NATIVE_L2_LP_TYPE_DECODING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 63 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_NATIVE_L2_LP_TYPE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NATIVE_LB_GROUP_SIZE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 10 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_NATIVE_LB_GROUP_SIZE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NATIVE_LB_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(30 /* key_width */, 49 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_NATIVE_LB;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NATIVE_LB_TYPE_DECODING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 63 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_NATIVE_LB_TYPE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NATIVE_LP_IS_PBTS_PREFIX_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 1 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_NATIVE_LP_IS_PBTS_PREFIX;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NATIVE_LP_PBTS_MAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 8 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_NATIVE_LP_PBTS_MAP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NATIVE_PROTECTION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 1 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_NATIVE_PROTECTION;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NEXT_HEADER_1_IS_L4_OVER_IPV4_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 24;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NH_MACRO_CODE_TO_ID_L6_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 288;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NHLFE_TYPE_MAPPING_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 24 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 320;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 24;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NW_SMCID_THRESHOLD_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 1344;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_OAMP_DROP_DESTINATION_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 352;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_OAMP_EVENT_QUEUE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(34 /* key_width */, 0 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_NPUH_CPU_EVQ;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_OAMP_REDIRECT_GET_COUNTER_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 352;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_OAMP_REDIRECT_PUNT_ETH_HDR_1_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 288;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_OAMP_REDIRECT_PUNT_ETH_HDR_2_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 256;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_OAMP_REDIRECT_PUNT_ETH_HDR_3_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_OAMP_REDIRECT_PUNT_ETH_HDR_4_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 32;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_OAMP_REDIRECT_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 44 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 64;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 44;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_OUTER_TPID_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 608;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_OVERLAY_IPV4_SIP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(40 /* key_width */, 16 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_EM_0;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PATH_LB_TYPE_DECODING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 63 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_PATH_LB_TYPE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PATH_LP_IS_PBTS_PREFIX_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 1 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_PATH_LP_IS_PBTS_PREFIX;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PATH_LP_PBTS_MAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 8 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_PATH_LP_PBTS_MAP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PATH_LP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(15 /* key_width */, 85 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_PATH_LP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PATH_LP_TYPE_DECODING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 63 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_PATH_LP_TYPE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PATH_PROTECTION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 1 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_PATH_PROTECTION;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PDOQ_OQ_IFC_MAPPING) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(9 /* key_width */, 15 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_PDOQ_IFC_MAPPING;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PDVOQ_BANK_PAIR_OFFSET_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 108 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_DUMMY_PDVOQ_BANK_PAIR_OFFSET_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PDVOQ_SLICE_VOQ_PROPERTIES_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(16 /* key_width */, 8 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_PDVOQ_SLICE_VOQ_PROPERTIES_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PER_ASBR_AND_DPE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(36 /* key_width */, 45 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PER_PE_AND_PREFIX_VPN_KEY_LARGE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(37 /* key_width */, 76 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PER_PE_AND_VRF_VPN_KEY_LARGE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(31 /* key_width */, 76 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PER_PORT_DESTINATION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_UDC_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_UDC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 64;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PER_VRF_MPLS_FORWARDING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(38 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PFC_DESTINATION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(56 /* key_width */, 40 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PFC_EVENT_QUEUE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(22 /* key_width */, 0 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_NPUH_CPU_EVQ;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PFC_TC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 320;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PFC_VECTOR_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 8;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 128;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PIN_START_OFFSET_MACROS) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 4 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_NPU_HOST_PIN_START_OFFSET_MACROS;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PMA_LOOPBACK_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 2 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_PMA_LOOPBACK_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PORT_DSPA_GROUP_SIZE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 10 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_PORT_DSPA_GROUP_SIZE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PORT_DSPA_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(30 /* key_width */, 15 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_PORT_DSPA;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PORT_DSPA_TYPE_DECODING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 63 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_PORT_DSPA_TYPE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PORT_NPP_PROTECTION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(10 /* key_width */, 92 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_PORT_NPP_PROTECTION;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PORT_NPP_PROTECTION_TYPE_DECODING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 63 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_PORT_NPP_PROTECTION_TYPE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PORT_PROTECTION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(10 /* key_width */, 1 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_PORT_PROTECTION;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PUNT_RCY_INJECT_HEADER_ENE_ENCAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 28 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 28;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PUNT_SELECT_NW_ENE_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 32;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 1568;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PUNT_TUNNEL_TRANSPORT_ENCAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(12 /* key_width */, 120 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PUNT_TUNNEL_TRANSPORT_EXTENDED_ENCAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(12 /* key_width */, 80 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_SMALL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PUNT_TUNNEL_TRANSPORT_EXTENDED_ENCAP_TABLE2) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(10 /* key_width */, 48 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_L3_DLP1;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PWE_LABEL_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(18 /* key_width */, 76 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PWE_TO_L3_DEST_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(27 /* key_width */, 20 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PWE_VPLS_LABEL_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(38 /* key_width */, 76 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PWE_VPLS_TUNNEL_LABEL_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(38 /* key_width */, 76 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_REASSEMBLY_SOURCE_PORT_MAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 6 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_SOURCE_PORT_MAP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RECYCLE_OVERRIDE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 34 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RECYCLE_OVERRIDE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RECYCLED_INJECT_UP_INFO_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 64;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 320;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_REDIRECT_DESTINATION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 2 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_REDIRECT_DEST_REG;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RESOLUTION_SET_NEXT_MACRO_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 12 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 256;
            curr_entry->sram_config.offset_in_line = 20;
            curr_entry->sram_config.width_in_bits = 12;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_REWRITE_SA_PREFIX_INDEX_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 32;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RMEP_LAST_TIME_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 32 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_NPUH_RMEP_LAST_TIME;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RMEP_STATE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 16 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_NPUH_RMEP_STATE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RPF_FEC_ACCESS_MAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 1 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RPF_FEC_ACCESS_MAP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RPF_FEC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(12 /* key_width */, 20 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RPF_FEC;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RTF_CONF_SET_TO_OG_PCL_COMPRESS_BITS_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(10 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 1024;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 24;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RTF_CONF_SET_TO_OG_PCL_IDS_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(10 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 1024;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 1024;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RTF_CONF_SET_TO_POST_FWD_STAGE_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(9 /* key_width */, 6 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_UNKNOWN;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_COUNTERS_BLOCK_CONFIG_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(7 /* key_width */, 4 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RX_COUNTERS_CONFIG;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_FWD_ERROR_HANDLING_COUNTER_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 64;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 1280;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_FWD_ERROR_HANDLING_DESTINATION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 352;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_IP_P_COUNTER_OFFSET_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 8;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 64;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_MAP_NPP_TO_SSP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 28 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 1024;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 28;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_METER_BLOCK_METER_ATTRIBUTE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(15 /* key_width */, 7 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RX_METER_BLOCK_METER_ATTRIBUTE_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_METER_BLOCK_METER_PROFILE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 39 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RX_METER_BLOCK_METER_PROFILE_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_METER_BLOCK_METER_SHAPER_CONFIGURATION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(15 /* key_width */, 20 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RX_METER_BLOCK_METER_SHAPER_CONFIGURATION_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_METER_DISTRIBUTED_METER_PROFILE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 77 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RX_METER_DISTRIBUTED_METER_PROFILE_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_METER_EXACT_METER_DECISION_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(7 /* key_width */, 7 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RX_METER_DECISION_MAPPING_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_METER_METER_PROFILE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 39 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RX_METER_METER_PROFILE_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_METER_METER_SHAPER_CONFIGURATION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 20 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RX_METER_METER_SHAPER_CONFIGURATION_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_METER_METERS_ATTRIBUTE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 7 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RX_METER_METERS_ATTRIBUTE_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_METER_RATE_LIMITER_SHAPER_CONFIGURATION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(11 /* key_width */, 10 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RX_METER_RATE_LIMITER_SHAPER_CONFIGURATION_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_METER_STAT_METER_DECISION_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 7 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RX_STAT_METER_DECISION_MAPPING_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_NPU_TO_TM_DEST_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 6 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RX_NPU_TO_TM_DEST_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_OBM_CODE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 44 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 256;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 44;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_OBM_PUNT_SRC_AND_CODE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(18 /* key_width */, 65 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_TERMINATION_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_REDIRECT_CODE_EXT_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_REDIRECT_CODE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 96 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 96;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_TERM_ERROR_HANDLING_COUNTER_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 64;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 256;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_TERM_ERROR_HANDLING_DESTINATION_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 128;
            curr_entry->sram_config.offset_in_line = 52;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RXPDR_DSP_LOOKUP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 28 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RXPDR_DSP_LUT_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RXPDR_DSP_TC_MAP) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 4 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RXPDR_DSP_TC_MAP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SCH_OQSE_CFG) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(9 /* key_width */, 72 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_SCH_OQSE_CFG;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SERVICE_LP_ATTRIBUTES_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(16 /* key_width */, 144 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_LP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SERVICE_MAPPING_EM0_AC_PORT_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(20 /* key_width */, 30 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_EM_0;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SERVICE_MAPPING_EM0_AC_PORT_TAG_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(32 /* key_width */, 30 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_EM_0;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SERVICE_MAPPING_EM0_AC_PORT_TAG_TAG_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(44 /* key_width */, 30 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_EM_0;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SERVICE_MAPPING_EM0_PWE_TAG_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(32 /* key_width */, 30 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_EM_0;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SERVICE_MAPPING_EM1_AC_PORT_TAG_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(32 /* key_width */, 30 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_EM_1;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SERVICE_RELAY_ATTRIBUTES_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(14 /* key_width */, 54 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_RELAY;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SET_ENE_MACRO_AND_BYTES_TO_REMOVE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_ELEMENT_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_FABRIC_ELEMENT;
            curr_entry->database_id = 0;
            curr_entry->table_size = 32;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SIP_INDEX_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 1536;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SLICE_MODES_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(3 /* key_width */, 1 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_SLICE_MODES_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SLP_BASED_FORWARDING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(21 /* key_width */, 44 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SMALL_ENCAP_MPLS_HE_ASBR_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(32 /* key_width */, 80 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_SMALL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SMALL_ENCAP_MPLS_HE_TE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(32 /* key_width */, 80 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_SMALL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SNOOP_CODE_HW_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 5 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_SNOOP_CODE_HW_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SNOOP_TO_DSP_IN_NPU_SOFT_HEADER_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 4 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 12;
            curr_entry->sram_config.width_in_bits = 4;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SOURCE_PIF_HW_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 68 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_SOURCE_PIF;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_STAGE2_LB_GROUP_SIZE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 10 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_PATH_LB_GROUP_SIZE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_STAGE2_LB_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(30 /* key_width */, 29 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_PATH_LB;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_STAGE3_LB_GROUP_SIZE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 10 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_STAGE3_LB_GROUP_SIZE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_STAGE3_LB_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(30 /* key_width */, 40 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_STAGE3_LB;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_STAGE3_LB_TYPE_DECODING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 63 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RESOLUTION_STAGE3_LB_TYPE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TERMINATION_TO_FORWARDING_FI_HARDWIRED_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 2 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_TERMINATION_TO_FORWARDING_FI_HARDWIRED;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TM_IBM_CMD_TO_DESTINATION) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 9 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_TM_IBM_TO_DESTINATION;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TS_CMD_HW_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 8 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_TS_CMD_HW_STATIC_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TUNNEL_QOS_STATIC_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 16;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TX_COUNTERS_BLOCK_CONFIG_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(7 /* key_width */, 4 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_TX_COUNTERS_CONFIG;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TX_ERROR_HANDLING_COUNTER_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 64;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 5;
            curr_entry->sram_config.start_line = 128;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TX_PUNT_ETH_ENCAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(9 /* key_width */, 129 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_DIP_INDEX;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TX_REDIRECT_CODE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(12 /* key_width */, 40 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_LARGE_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TXPDR_MC_LIST_SIZE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(16 /* key_width */, 11 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_TXPDR_MC_LIST_SIZE_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TXPDR_TC_MAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 3 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_TXPDR_OQ_TC_MAP_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TXPP_DLP_PROFILE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(14 /* key_width */, 8 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_DLP_PROFILE_HW_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TXPP_ENCAP_QOS_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 7 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_ENCAP_QOS_MAPPING_HW_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TXPP_FIRST_ENC_TYPE_TO_SECOND_ENC_TYPE_OFFSET) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(4 /* key_width */, 1 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_FIRST_ENC_TYPE_TO_SECOND_ENC_TYPE_OFFSET;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TXPP_FWD_HEADER_TYPE_IS_L2_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(8 /* key_width */, 1 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_FWD_HEADER_TYPE_IS_L2_HW_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TXPP_FWD_QOS_MAPPING_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(13 /* key_width */, 7 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_FWD_QOS_MAPPING_HW_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TXPP_IBM_ENABLES_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(1 /* key_width */, 159 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_TXPP_IBM_ENABLES_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TXPP_MAPPING_QOS_TAG_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_table_compiler_generated_config_t(11 /* key_width */, 32 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 1536;
            
            curr_entry->is_ene_table = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 32;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_UC_IBM_TC_MAP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(6 /* key_width */, 4 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_RXPDR_IBM_TC_MAP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_VLAN_EDIT_TPID1_PROFILE_HW_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 16 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_VLAN_EDIT_TPID1;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_VLAN_EDIT_TPID2_PROFILE_HW_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(2 /* key_width */, 16 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_VLAN_EDIT_TPID2;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_VNI_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(28 /* key_width */, 38 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_TUNNEL1;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_VOQ_CGM_SLICE_BUFFERS_CONSUMPTION_LUT_FOR_ENQ_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(11 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_VOQ_CGM_BCLFE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_VOQ_CGM_SLICE_DRAM_CGM_PROFILE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 106 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_VOQ_CGM_DCP;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_VOQ_CGM_SLICE_PD_CONSUMPTION_LUT_FOR_ENQ_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(10 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_VOQ_CGM_PCLFE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_VOQ_CGM_SLICE_PROFILE_BUFF_REGION_THRESHOLDS_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 98 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_VOQ_CGM_PBRT;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_VOQ_CGM_SLICE_PROFILE_PKT_ENQ_TIME_REGION_THRESHOLDS_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 120 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_VOQ_CGM_PPETRT;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_VOQ_CGM_SLICE_PROFILE_PKT_REGION_THRESHOLDS_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 98 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_VOQ_CGM_PPRT;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_VOQ_CGM_SLICE_SLICE_CGM_PROFILE_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(5 /* key_width */, 3 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_VOQ_CGM_SLICE_SLICE_CGM_PROFILE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_VSID_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(28 /* key_width */, 14 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_EM_1;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_VXLAN_L2_DLP_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = true;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(22 /* key_width */, 75 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_EGRESS_SMALL_EM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    
    assert(0 && "called get_table_config(npl_tables_e table_name, npl_context_e context) with wrong table name!");
    return table_compiler_generated_config_t();
}

ternary_table_compiler_generated_config_t npl_tables_compiler_generated_config::get_ternary_table_config(npl_tables_e table_name, npl_context_e context)
{
    if (table_name == NPL_TABLES_BFD_UDP_PORT_MAP_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(40 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 9;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 3;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 40;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_DEFAULT_EGRESS_IPV4_SEC_ACL_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(133 /* key_width */, 24 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_DEFAULT_EGRESS_IPV6_ACL_SEC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(320 /* key_width */, 24 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_ECN_REMARK_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 10;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 1;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_EGRESS_MAC_IPV4_SEC_ACL_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(135 /* key_width */, 24 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_ENE_BYTE_ADDITION_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 13;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 2;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_ERPP_FABRIC_COUNTERS_OFFSET_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(48 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 1;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 48;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_ERPP_FABRIC_COUNTERS_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(140 /* key_width */, 24 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->default_action.mask.set_bits(1, 0, 0x3ULL);
            curr_entry->table_size = 128;
            
            curr_entry->is_reg_tcam = false;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 140;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 4;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 24;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_AND_TM_HEADER_SIZE_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(16 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 5;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 3;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 16;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_HEADER_ENE_MACRO_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 12;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 3;
            curr_entry->tcam_config.index_in_level = 1;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_HEADERS_TYPE_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(48 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 1;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 48;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_INIT_CFG) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(20 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 20;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(20 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_FABRIC;
            curr_entry->database_id = 1;
            curr_entry->table_size = 2;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 20;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_NPUH_SIZE_CALCULATION_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->default_action.payload.set_bits(8, 8, 0x1ULL);
            curr_entry->default_action.payload.set_bits(6, 0, 0x20ULL);
            curr_entry->table_size = 6;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 1;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_OUT_COLOR_MAP_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 2;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_TERM_ERROR_CHECKER_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(16 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 7;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 3;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 16;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FABRIC_TRANSMIT_ERROR_CHECKER_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_FABRIC_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(16 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_FABRIC;
            curr_entry->database_id = 0;
            curr_entry->table_size = 5;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 4;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 16;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_FI_CORE_TCAM_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(40 /* key_width */, 54 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_FI_CORE_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_ETH_DB1_160_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_ETH_DB2_160_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV4_DB1_160_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV4_DB1_160_F1_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV4_DB1_320_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(320 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV4_DB2_160_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV4_DB2_160_F1_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV4_DB2_320_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(320 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV4_DB3_160_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV4_DB3_160_F1_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV4_DB3_320_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(320 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV4_DB4_160_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV4_DB4_160_F1_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV4_DB4_320_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(320 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV6_DB1_160_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV6_DB1_160_F1_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV6_DB1_320_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(320 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV6_DB2_160_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV6_DB2_160_F1_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV6_DB2_320_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(320 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV6_DB3_160_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV6_DB3_160_F1_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV6_DB3_320_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(320 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV6_DB4_160_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV6_DB4_160_F1_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(160 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INGRESS_RTF_IPV6_DB4_320_F0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(320 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_INJECT_DOWN_SELECT_ENE_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(16 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 5;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 3;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 16;
            curr_entry->tcam_config.width_in_bits = 16;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 16;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IP_INGRESS_CMP_MCID_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(16 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 4;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 16;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IP_VER_MC_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 6;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 1;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV4_ACL_MAP_PROTOCOL_TYPE_TO_PROTOCOL_NUMBER_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(20 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 9;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 2;
            curr_entry->tcam_config.width_in_bits = 20;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 2;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV4_LPTS_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(157 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        curr_entry->default_action.key.set_bits(3, 0, 0xcULL);
        curr_entry->default_action.mask.set_bits(3, 0, 0xfULL);
        curr_entry->default_action.key.set_bits(5, 4, 0x2ULL);
        curr_entry->default_action.mask.set_bits(5, 4, 0x3ULL);
        curr_entry->default_action.payload.set_bits(63, 48, 0x70ULL);
        curr_entry->default_action.payload.set_bits(31, 0, 0xfff7f000ULL);
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV6_FIRST_FRAGMENT_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(48 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 6;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 1;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 48;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV6_LPTS_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(319 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        curr_entry->default_action.key.set_bits(163, 160, 0xdULL);
        curr_entry->default_action.mask.set_bits(163, 160, 0xfULL);
        curr_entry->default_action.mask.set_bits(16, 4, 0x1fffULL);
        curr_entry->default_action.key.set_bits(3, 0, 0xdULL);
        curr_entry->default_action.mask.set_bits(3, 0, 0xfULL);
        curr_entry->default_action.payload.set_bits(63, 48, 0x70ULL);
        curr_entry->default_action.payload.set_bits(31, 0, 0xfff7f000ULL);
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV6_SIP_COMPRESSION_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(132 /* key_width */, 16 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        curr_entry->default_action.mask.set_bits(3, 0, 0xfULL);
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L2_LPTS_CTRL_FIELDS_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(48 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 1;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 48;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L2_LPTS_IPV4_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(106 /* key_width */, 32 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        curr_entry->default_action.key.set_bits(3, 0, 0x8ULL);
        curr_entry->default_action.mask.set_bits(3, 0, 0xfULL);
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L2_LPTS_IPV6_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(138 /* key_width */, 32 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        curr_entry->default_action.key.set_bits(3, 0, 0xcULL);
        curr_entry->default_action.mask.set_bits(3, 0, 0xfULL);
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L2_LPTS_MAC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(88 /* key_width */, 32 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        curr_entry->default_action.key.set_bits(3, 0, 0x4ULL);
        curr_entry->default_action.mask.set_bits(3, 0, 0xfULL);
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L2_LPTS_NEXT_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(16 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->default_action.key.set_bits(0, 0, 0x1ULL);
            curr_entry->default_action.mask.set_bits(0, 0, 0x1ULL);
            curr_entry->table_size = 10;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 4;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 14;
            curr_entry->tcam_config.width_in_bits = 16;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 14;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L2_LPTS_PROTOCOL_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->default_action.key.set_bits(0, 0, 0x1ULL);
            curr_entry->default_action.mask.set_bits(0, 0, 0x1ULL);
            curr_entry->table_size = 30;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 3;
            curr_entry->tcam_config.index_in_level = 1;
            curr_entry->tcam_config.start_line = 2;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 2;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L2_TERMINATION_NEXT_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 10;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 2;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L3_DLP_P_COUNTER_OFFSET_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(20 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 20;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 20;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L3_TERMINATION_CLASSIFY_IP_TUNNELS_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 10;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 1;
            curr_entry->tcam_config.start_line = 8;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 8;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L3_TERMINATION_NEXT_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(16 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 14;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 4;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 16;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_L3_TUNNEL_TERMINATION_NEXT_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(16 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 12;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 3;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 4;
            curr_entry->tcam_config.width_in_bits = 16;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 4;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LIGHT_FI_NW_0_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(21 /* key_width */, 44 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LIGHT_FI_NW_0_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LIGHT_FI_NW_1_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(21 /* key_width */, 44 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LIGHT_FI_NW_1_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LIGHT_FI_NW_2_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(21 /* key_width */, 44 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LIGHT_FI_NW_2_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LIGHT_FI_NW_3_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(21 /* key_width */, 44 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_LIGHT_FI_NW_3_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_LPTS_OG_APPLICATION_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(140 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->default_action.mask.set_bits(1, 0, 0x3ULL);
            curr_entry->table_size = 32;
            
            curr_entry->is_reg_tcam = false;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 140;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAC_DA_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(140 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->default_action.key.set_bits(1, 0, 0x1ULL);
            curr_entry->default_action.mask.set_bits(1, 0, 0x3ULL);
            curr_entry->table_size = 32;
            
            curr_entry->is_reg_tcam = false;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 64;
            curr_entry->tcam_config.width_in_bits = 140;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAC_ETHERNET_RATE_LIMIT_TYPE_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(16 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 5;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 4;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 4;
            curr_entry->tcam_config.width_in_bits = 16;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 4;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAC_MC_TCAM_TERMINATION_ATTRIBUTES_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(16 /* key_width */, 120 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_TERMINATION_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAC_TERMINATION_NEXT_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->default_action.mask.set_bits(0, 0, 0x1ULL);
            curr_entry->table_size = 8;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 1;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAC_TERMINATION_TCAM_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(40 /* key_width */, 120 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_TERMINATION_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAP_INJECT_CCM_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(20 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 3;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 20;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAP_TX_PUNT_NEXT_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(140 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 19;
            
            curr_entry->is_reg_tcam = false;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 140;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 96;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MAP_TX_PUNT_RCY_NEXT_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(48 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 3;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 1;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 6;
            curr_entry->tcam_config.width_in_bits = 48;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 6;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MEG_ID_FORMAT_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->default_action.payload.set_bits(0, 0, 0x1ULL);
            curr_entry->table_size = 2;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 3;
            curr_entry->tcam_config.index_in_level = 1;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MLDP_PROTECTION_ENABLED_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(20 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 20;
            curr_entry->tcam_config.width_in_bits = 20;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 20;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MPLS_RESOLVE_SERVICE_LABELS_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(16 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 8;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 4;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 8;
            curr_entry->tcam_config.width_in_bits = 16;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 8;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MPLS_VPN_ENABLED_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(48 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 6;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 1;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 48;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_MY_IPV4_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(140 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 64;
            
            curr_entry->is_reg_tcam = false;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 140;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 6;
            curr_entry->sram_config.start_line = 256;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_NULL_RTF_NEXT_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 9;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 1;
            curr_entry->tcam_config.start_line = 6;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 6;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_OBM_NEXT_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(40 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 3;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 3;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 40;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_OG_NEXT_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(20 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 20;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PAD_MTU_INJ_CHECK_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(16 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->default_action.mask.set_bits(0, 0, 0x1ULL);
            curr_entry->table_size = 8;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 4;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 16;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PFC_FILTER_WD_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(140 /* key_width */, 20 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_reg_tcam = false;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 32;
            curr_entry->tcam_config.width_in_bits = 140;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 384;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 20;
            curr_entry->sram_config.payload_needs_rmw_operation = true;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PFC_OFFSET_FROM_VECTOR_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 9;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 1;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PFC_SSP_SLICE_MAP_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(140 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 36;
            
            curr_entry->is_reg_tcam = false;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 140;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 64;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PFC_TC_LATENCY_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(20 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 8;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 3;
            curr_entry->tcam_config.width_in_bits = 20;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 3;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PFC_TC_WRAP_LATENCY_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 8;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 1;
            curr_entry->tcam_config.start_line = 9;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 9;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_PUNT_ETHERTYPE_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(40 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 3;
            curr_entry->tcam_config.start_line = 4;
            curr_entry->tcam_config.width_in_bits = 40;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 4;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_REDIRECT_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.is_traps_table = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_HOST_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(96 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_NPU_HOST_HOST;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 4;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 127;
            curr_entry->tcam_config.width_in_bits = 96;
            curr_entry->tcam_config.is_reverse_order = true;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 127;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(96 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 256;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 4;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 127;
            curr_entry->tcam_config.width_in_bits = 96;
            curr_entry->tcam_config.is_reverse_order = true;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 127;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(96 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 1;
            curr_entry->table_size = 256;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 4;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 127;
            curr_entry->tcam_config.width_in_bits = 96;
            curr_entry->tcam_config.is_reverse_order = true;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 127;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(96 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 2;
            curr_entry->table_size = 256;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 4;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 127;
            curr_entry->tcam_config.width_in_bits = 96;
            curr_entry->tcam_config.is_reverse_order = true;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 127;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RESOLUTION_PFC_SELECT_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->default_action.mask.set_bits(0, 0, 0x1ULL);
            curr_entry->table_size = 8;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 2;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RTF_NEXT_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 19;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 3;
            curr_entry->tcam_config.index_in_level = 1;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_RX_REDIRECT_NEXT_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 6;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 2;
            curr_entry->tcam_config.start_line = 8;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 8;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SECOND_ENE_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(40 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 4;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 3;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 40;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SELECT_INJECT_NEXT_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = true;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(40 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->default_action.key.set_bits(0, 0, 0x1ULL);
            curr_entry->default_action.mask.set_bits(0, 0, 0x1ULL);
            curr_entry->table_size = 16;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 3;
            curr_entry->tcam_config.start_line = 3;
            curr_entry->tcam_config.width_in_bits = 40;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 3;
            curr_entry->sram_config.start_line = 3;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SERVICE_MAPPING_TCAM_AC_PORT_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(20 /* key_width */, 228 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SERVICE_MAPPING_TCAM_AC_PORT_TAG_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 228 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SERVICE_MAPPING_TCAM_AC_PORT_TAG_TAG_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(44 /* key_width */, 228 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SERVICE_MAPPING_TCAM_PWE_TAG_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 228 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_MAC_SERVICE_MAPPING_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SGACL_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(11 /* key_width */, 64 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_TCAM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SNOOP_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.is_traps_table = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(96 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 64;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 4;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 96;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(96 /* key_width */, 8 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 1;
            curr_entry->table_size = 64;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 4;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 96;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 8;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_SVL_NEXT_MACRO_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 5;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 2;
            curr_entry->tcam_config.start_line = 10;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 2;
            curr_entry->sram_config.start_line = 10;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TE_HEADEND_LSP_COUNTER_OFFSET_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(32 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 14;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 1;
            curr_entry->tcam_config.start_line = 10;
            curr_entry->tcam_config.width_in_bits = 32;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 1;
            curr_entry->sram_config.start_line = 10;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TUNNEL_DLP_P_COUNTER_OFFSET_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(16 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TRANSMIT_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 16;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 3;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 16;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_TXPP_INITIAL_NPE_MACRO_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(13 /* key_width */, 6 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_TXPP_INITIAL_NPE_MACRO_TABLE;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_URPF_IPSA_DEST_IS_LPTS_STATIC_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(16 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_FORWARDING_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 2;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 3;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 2;
            curr_entry->tcam_config.width_in_bits = 16;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 2;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    if (table_name == NPL_TABLES_VLAN_FORMAT_TABLE) {
        ternary_table_compiler_generated_config_t result;
        
        result.is_internal = true;
        result.has_default_action = false;
        
        single_ternary_table_compiler_generated_config_t* curr_entry = nullptr;
        if (context == NPL_NETWORK_CONTEXT) {
            result.tables_config.push_back(single_ternary_table_compiler_generated_config_t(20 /* key_width */, 16 /*payload_width */));
            curr_entry = &(result.tables_config.back());
            
            curr_entry->database = DATABASES_ENGINE_TERMINATION_NETWORK;
            curr_entry->database_id = 0;
            curr_entry->table_size = 32;
            
            curr_entry->is_reg_tcam = true;
            curr_entry->level_in_engine = 0;
            curr_entry->tcam_config.index_in_level = 0;
            curr_entry->tcam_config.start_line = 0;
            curr_entry->tcam_config.width_in_bits = 20;
            curr_entry->tcam_config.is_reverse_order = false;
            curr_entry->sram_config.index = 0;
            curr_entry->sram_config.start_line = 0;
            curr_entry->sram_config.offset_in_line = 0;
            curr_entry->sram_config.width_in_bits = 16;
            curr_entry->sram_config.payload_needs_rmw_operation = false;
            curr_entry->sram_config.msb_aligned = false;
        }
        
        return result;
    }
    
    
    assert(0 && "called get_ternary_table_config(npl_tables_e table_name, npl_context_e context) with wrong table name!");
    return ternary_table_compiler_generated_config_t();
}

table_compiler_generated_config_t npl_tables_compiler_generated_config::get_lpm_table_config(npl_tables_e table_name)
{
    if (table_name == NPL_TABLES_IPV4_LPM_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(45 /* key_width */, 20 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_LPM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV4_OG_PCL_LPM_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(45 /* key_width */, 20 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_LPM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV6_LPM_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(141 /* key_width */, 20 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_LPM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    if (table_name == NPL_TABLES_IPV6_OG_PCL_LPM_TABLE) {
        table_compiler_generated_config_t result;
        
        result.is_internal = false;
        result.has_default_action = false;
        result.is_exact_match = false;
        
        single_table_compiler_generated_config_t* curr_entry = nullptr;
        result.tables_config.push_back(single_table_compiler_generated_config_t(141 /* key_width */, 20 /*payload_width */));
        curr_entry = &(result.tables_config.back());
        
        curr_entry->database = DATABASES_EXTERNAL_CENTRAL_LPM;
        curr_entry->database_id = 0;
        
        return result;
    }
    
    
    assert(0 && "called get_lpm_table_config(npl_tables_e table_name) with wrong table name!");
    return table_compiler_generated_config_t();
}

