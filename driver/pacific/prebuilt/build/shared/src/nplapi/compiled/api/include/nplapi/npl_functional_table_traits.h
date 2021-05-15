
// This file has been automatically generated using nplc.py. Do not edit it manually.
// Version: 1.76.2_0.0.0.0 generated on devsrv15.leaba.local at 2021-05-12 16:09:15



#ifndef __NPL_FUNCTIONAL_TABLE_TRAITS_H__
#define __NPL_FUNCTIONAL_TABLE_TRAITS_H__

#include <string>
#include "nplapi/npl_table_types.h"
#include "nplapi/npl_tables_enum.h"

namespace silicon_one {
    typedef enum {
        TABLE_TYPE_DIRECT,
        TABLE_TYPE_EM,
        TABLE_TYPE_TERNARY,
        TABLE_TYPE_LPM
    } table_type_e;
    
    
    struct npl_acl_map_fi_header_type_to_protocol_number_table_functional_traits_t {
        typedef npl_acl_map_fi_header_type_to_protocol_number_table_key_t key_type;
        typedef npl_acl_map_fi_header_type_to_protocol_number_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_ACL_MAP_FI_HEADER_TYPE_TO_PROTOCOL_NUMBER_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("acl_map_fi_header_type_to_protocol_number_table");
            return table_name;
        }
    };
    
    struct npl_additional_labels_table_functional_traits_t {
        typedef npl_additional_labels_table_key_t key_type;
        typedef npl_additional_labels_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_ADDITIONAL_LABELS_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("additional_labels_table");
            return table_name;
        }
    };
    
    struct npl_all_reachable_vector_functional_traits_t {
        typedef npl_all_reachable_vector_key_t key_type;
        typedef npl_all_reachable_vector_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_ALL_REACHABLE_VECTOR;
        static const std::string& get_table_name() {
            static const std::string table_name("all_reachable_vector");
            return table_name;
        }
    };
    
    struct npl_bfd_desired_tx_interval_table_functional_traits_t {
        typedef npl_bfd_desired_tx_interval_table_key_t key_type;
        typedef npl_bfd_desired_tx_interval_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_DESIRED_TX_INTERVAL_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_desired_tx_interval_table");
            return table_name;
        }
    };
    
    struct npl_bfd_detection_multiple_table_functional_traits_t {
        typedef npl_bfd_detection_multiple_table_key_t key_type;
        typedef npl_bfd_detection_multiple_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_DETECTION_MULTIPLE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_detection_multiple_table");
            return table_name;
        }
    };
    
    struct npl_bfd_event_queue_table_functional_traits_t {
        typedef npl_bfd_event_queue_table_key_t key_type;
        typedef npl_bfd_event_queue_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_EVENT_QUEUE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_event_queue_table");
            return table_name;
        }
    };
    
    struct npl_bfd_inject_inner_da_high_table_functional_traits_t {
        typedef npl_bfd_inject_inner_da_high_table_key_t key_type;
        typedef npl_bfd_inject_inner_da_high_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_INJECT_INNER_DA_HIGH_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_inject_inner_da_high_table");
            return table_name;
        }
    };
    
    struct npl_bfd_inject_inner_da_low_table_functional_traits_t {
        typedef npl_bfd_inject_inner_da_low_table_key_t key_type;
        typedef npl_bfd_inject_inner_da_low_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_INJECT_INNER_DA_LOW_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_inject_inner_da_low_table");
            return table_name;
        }
    };
    
    struct npl_bfd_inject_inner_ethernet_header_static_table_functional_traits_t {
        typedef npl_bfd_inject_inner_ethernet_header_static_table_key_t key_type;
        typedef npl_bfd_inject_inner_ethernet_header_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_INJECT_INNER_ETHERNET_HEADER_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_inject_inner_ethernet_header_static_table");
            return table_name;
        }
    };
    
    struct npl_bfd_inject_ttl_static_table_functional_traits_t {
        typedef npl_bfd_inject_ttl_static_table_key_t key_type;
        typedef npl_bfd_inject_ttl_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_INJECT_TTL_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_inject_ttl_static_table");
            return table_name;
        }
    };
    
    struct npl_bfd_ipv6_sip_A_table_functional_traits_t {
        typedef npl_bfd_ipv6_sip_A_table_key_t key_type;
        typedef npl_bfd_ipv6_sip_A_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_IPV6_SIP_A_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_ipv6_sip_A_table");
            return table_name;
        }
    };
    
    struct npl_bfd_ipv6_sip_B_table_functional_traits_t {
        typedef npl_bfd_ipv6_sip_B_table_key_t key_type;
        typedef npl_bfd_ipv6_sip_B_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_IPV6_SIP_B_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_ipv6_sip_B_table");
            return table_name;
        }
    };
    
    struct npl_bfd_ipv6_sip_C_table_functional_traits_t {
        typedef npl_bfd_ipv6_sip_C_table_key_t key_type;
        typedef npl_bfd_ipv6_sip_C_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_IPV6_SIP_C_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_ipv6_sip_C_table");
            return table_name;
        }
    };
    
    struct npl_bfd_ipv6_sip_D_table_functional_traits_t {
        typedef npl_bfd_ipv6_sip_D_table_key_t key_type;
        typedef npl_bfd_ipv6_sip_D_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_IPV6_SIP_D_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_ipv6_sip_D_table");
            return table_name;
        }
    };
    
    struct npl_bfd_punt_encap_static_table_functional_traits_t {
        typedef npl_bfd_punt_encap_static_table_key_t key_type;
        typedef npl_bfd_punt_encap_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_PUNT_ENCAP_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_punt_encap_static_table");
            return table_name;
        }
    };
    
    struct npl_bfd_required_tx_interval_table_functional_traits_t {
        typedef npl_bfd_required_tx_interval_table_key_t key_type;
        typedef npl_bfd_required_tx_interval_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_REQUIRED_TX_INTERVAL_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_required_tx_interval_table");
            return table_name;
        }
    };
    
    struct npl_bfd_rx_table_functional_traits_t {
        typedef npl_bfd_rx_table_key_t key_type;
        typedef npl_bfd_rx_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_BFD_RX_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_rx_table");
            return table_name;
        }
    };
    
    struct npl_bfd_set_inject_type_static_table_functional_traits_t {
        typedef npl_bfd_set_inject_type_static_table_key_t key_type;
        typedef npl_bfd_set_inject_type_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_SET_INJECT_TYPE_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_set_inject_type_static_table");
            return table_name;
        }
    };
    
    struct npl_bfd_udp_port_map_static_table_functional_traits_t {
        typedef npl_bfd_udp_port_map_static_table_key_t key_type;
        typedef npl_bfd_udp_port_map_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_BFD_UDP_PORT_MAP_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_udp_port_map_static_table");
            return table_name;
        }
        static const size_t table_size = 9;
        static bool key_match(const npl_bfd_udp_port_map_static_table_key_t& lookup_key, const npl_bfd_udp_port_map_static_table_key_t& table_key, const npl_bfd_udp_port_map_static_table_key_t& table_mask);
    };
    
    struct npl_bfd_udp_port_static_table_functional_traits_t {
        typedef npl_bfd_udp_port_static_table_key_t key_type;
        typedef npl_bfd_udp_port_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BFD_UDP_PORT_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bfd_udp_port_static_table");
            return table_name;
        }
    };
    
    struct npl_bitmap_oqg_map_table_functional_traits_t {
        typedef npl_bitmap_oqg_map_table_key_t key_type;
        typedef npl_bitmap_oqg_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BITMAP_OQG_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bitmap_oqg_map_table");
            return table_name;
        }
    };
    
    struct npl_bvn_tc_map_table_functional_traits_t {
        typedef npl_bvn_tc_map_table_key_t key_type;
        typedef npl_bvn_tc_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_BVN_TC_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("bvn_tc_map_table");
            return table_name;
        }
    };
    
    struct npl_calc_checksum_enable_table_functional_traits_t {
        typedef npl_calc_checksum_enable_table_key_t key_type;
        typedef npl_calc_checksum_enable_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_CALC_CHECKSUM_ENABLE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("calc_checksum_enable_table");
            return table_name;
        }
    };
    
    struct npl_ccm_flags_table_functional_traits_t {
        typedef npl_ccm_flags_table_key_t key_type;
        typedef npl_ccm_flags_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_CCM_FLAGS_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ccm_flags_table");
            return table_name;
        }
    };
    
    struct npl_cif2npa_c_lri_macro_functional_traits_t {
        typedef npl_cif2npa_c_lri_macro_key_t key_type;
        typedef npl_cif2npa_c_lri_macro_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_CIF2NPA_C_LRI_MACRO;
        static const std::string& get_table_name() {
            static const std::string table_name("cif2npa_c_lri_macro");
            return table_name;
        }
    };
    
    struct npl_cif2npa_c_mps_macro_functional_traits_t {
        typedef npl_cif2npa_c_mps_macro_key_t key_type;
        typedef npl_cif2npa_c_mps_macro_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_CIF2NPA_C_MPS_MACRO;
        static const std::string& get_table_name() {
            static const std::string table_name("cif2npa_c_mps_macro");
            return table_name;
        }
    };
    
    struct npl_counters_block_config_table_functional_traits_t {
        typedef npl_counters_block_config_table_key_t key_type;
        typedef npl_counters_block_config_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_COUNTERS_BLOCK_CONFIG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("counters_block_config_table");
            return table_name;
        }
    };
    
    struct npl_counters_voq_block_map_table_functional_traits_t {
        typedef npl_counters_voq_block_map_table_key_t key_type;
        typedef npl_counters_voq_block_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_COUNTERS_VOQ_BLOCK_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("counters_voq_block_map_table");
            return table_name;
        }
    };
    
    struct npl_cud_is_multicast_bitmap_functional_traits_t {
        typedef npl_cud_is_multicast_bitmap_key_t key_type;
        typedef npl_cud_is_multicast_bitmap_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_CUD_IS_MULTICAST_BITMAP;
        static const std::string& get_table_name() {
            static const std::string table_name("cud_is_multicast_bitmap");
            return table_name;
        }
    };
    
    struct npl_cud_narrow_hw_table_functional_traits_t {
        typedef npl_cud_narrow_hw_table_key_t key_type;
        typedef npl_cud_narrow_hw_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_CUD_NARROW_HW_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("cud_narrow_hw_table");
            return table_name;
        }
    };
    
    struct npl_cud_wide_hw_table_functional_traits_t {
        typedef npl_cud_wide_hw_table_key_t key_type;
        typedef npl_cud_wide_hw_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_CUD_WIDE_HW_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("cud_wide_hw_table");
            return table_name;
        }
    };
    
    struct npl_default_egress_ipv4_sec_acl_table_functional_traits_t {
        typedef npl_default_egress_ipv4_sec_acl_table_key_t key_type;
        typedef npl_default_egress_ipv4_sec_acl_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_DEFAULT_EGRESS_IPV4_SEC_ACL_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("default_egress_ipv4_sec_acl_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_default_egress_ipv4_sec_acl_table_key_t& lookup_key, const npl_default_egress_ipv4_sec_acl_table_key_t& table_key, const npl_default_egress_ipv4_sec_acl_table_key_t& table_mask);
    };
    
    struct npl_default_egress_ipv6_acl_sec_table_functional_traits_t {
        typedef npl_default_egress_ipv6_acl_sec_table_key_t key_type;
        typedef npl_default_egress_ipv6_acl_sec_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_DEFAULT_EGRESS_IPV6_ACL_SEC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("default_egress_ipv6_acl_sec_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_default_egress_ipv6_acl_sec_table_key_t& lookup_key, const npl_default_egress_ipv6_acl_sec_table_key_t& table_key, const npl_default_egress_ipv6_acl_sec_table_key_t& table_mask);
    };
    
    struct npl_dest_slice_voq_map_table_functional_traits_t {
        typedef npl_dest_slice_voq_map_table_key_t key_type;
        typedef npl_dest_slice_voq_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_DEST_SLICE_VOQ_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("dest_slice_voq_map_table");
            return table_name;
        }
    };
    
    struct npl_destination_decoding_table_functional_traits_t {
        typedef npl_destination_decoding_table_key_t key_type;
        typedef npl_destination_decoding_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_DESTINATION_DECODING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("destination_decoding_table");
            return table_name;
        }
    };
    
    struct npl_device_mode_table_functional_traits_t {
        typedef npl_device_mode_table_key_t key_type;
        typedef npl_device_mode_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_DEVICE_MODE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("device_mode_table");
            return table_name;
        }
    };
    
    struct npl_dsp_l2_attributes_table_functional_traits_t {
        typedef npl_dsp_l2_attributes_table_key_t key_type;
        typedef npl_dsp_l2_attributes_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_DSP_L2_ATTRIBUTES_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("dsp_l2_attributes_table");
            return table_name;
        }
    };
    
    struct npl_dsp_l3_attributes_table_functional_traits_t {
        typedef npl_dsp_l3_attributes_table_key_t key_type;
        typedef npl_dsp_l3_attributes_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_DSP_L3_ATTRIBUTES_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("dsp_l3_attributes_table");
            return table_name;
        }
    };
    
    struct npl_dummy_dip_index_table_functional_traits_t {
        typedef npl_dummy_dip_index_table_key_t key_type;
        typedef npl_dummy_dip_index_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_DUMMY_DIP_INDEX_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("dummy_dip_index_table");
            return table_name;
        }
    };
    
    struct npl_ecn_remark_static_table_functional_traits_t {
        typedef npl_ecn_remark_static_table_key_t key_type;
        typedef npl_ecn_remark_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_ECN_REMARK_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ecn_remark_static_table");
            return table_name;
        }
        static const size_t table_size = 10;
        static bool key_match(const npl_ecn_remark_static_table_key_t& lookup_key, const npl_ecn_remark_static_table_key_t& table_key, const npl_ecn_remark_static_table_key_t& table_mask);
    };
    
    struct npl_egress_mac_ipv4_sec_acl_table_functional_traits_t {
        typedef npl_egress_mac_ipv4_sec_acl_table_key_t key_type;
        typedef npl_egress_mac_ipv4_sec_acl_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_EGRESS_MAC_IPV4_SEC_ACL_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("egress_mac_ipv4_sec_acl_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_egress_mac_ipv4_sec_acl_table_key_t& lookup_key, const npl_egress_mac_ipv4_sec_acl_table_key_t& table_key, const npl_egress_mac_ipv4_sec_acl_table_key_t& table_mask);
    };
    
    struct npl_egress_nh_and_svi_direct0_table_functional_traits_t {
        typedef npl_egress_nh_and_svi_direct0_table_key_t key_type;
        typedef npl_egress_nh_and_svi_direct0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_EGRESS_NH_AND_SVI_DIRECT0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("egress_nh_and_svi_direct0_table");
            return table_name;
        }
    };
    
    struct npl_egress_nh_and_svi_direct1_table_functional_traits_t {
        typedef npl_egress_nh_and_svi_direct1_table_key_t key_type;
        typedef npl_egress_nh_and_svi_direct1_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_EGRESS_NH_AND_SVI_DIRECT1_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("egress_nh_and_svi_direct1_table");
            return table_name;
        }
    };
    
    struct npl_em_mp_table_functional_traits_t {
        typedef npl_em_mp_table_key_t key_type;
        typedef npl_em_mp_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_EM_MP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("em_mp_table");
            return table_name;
        }
    };
    
    struct npl_em_pfc_cong_table_functional_traits_t {
        typedef npl_em_pfc_cong_table_key_t key_type;
        typedef npl_em_pfc_cong_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_EM_PFC_CONG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("em_pfc_cong_table");
            return table_name;
        }
    };
    
    struct npl_ene_byte_addition_static_table_functional_traits_t {
        typedef npl_ene_byte_addition_static_table_key_t key_type;
        typedef npl_ene_byte_addition_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_ENE_BYTE_ADDITION_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ene_byte_addition_static_table");
            return table_name;
        }
        static const size_t table_size = 13;
        static bool key_match(const npl_ene_byte_addition_static_table_key_t& lookup_key, const npl_ene_byte_addition_static_table_key_t& table_key, const npl_ene_byte_addition_static_table_key_t& table_mask);
    };
    
    struct npl_ene_macro_code_tpid_profile_static_table_functional_traits_t {
        typedef npl_ene_macro_code_tpid_profile_static_table_key_t key_type;
        typedef npl_ene_macro_code_tpid_profile_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_ENE_MACRO_CODE_TPID_PROFILE_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ene_macro_code_tpid_profile_static_table");
            return table_name;
        }
    };
    
    struct npl_erpp_fabric_counters_offset_table_functional_traits_t {
        typedef npl_erpp_fabric_counters_offset_table_key_t key_type;
        typedef npl_erpp_fabric_counters_offset_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_ERPP_FABRIC_COUNTERS_OFFSET_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("erpp_fabric_counters_offset_table");
            return table_name;
        }
        static const size_t table_size = 15;
        static bool key_match(const npl_erpp_fabric_counters_offset_table_key_t& lookup_key, const npl_erpp_fabric_counters_offset_table_key_t& table_key, const npl_erpp_fabric_counters_offset_table_key_t& table_mask);
    };
    
    struct npl_erpp_fabric_counters_table_functional_traits_t {
        typedef npl_erpp_fabric_counters_table_key_t key_type;
        typedef npl_erpp_fabric_counters_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_ERPP_FABRIC_COUNTERS_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("erpp_fabric_counters_table");
            return table_name;
        }
        static const size_t table_size = 127;
        static bool key_match(const npl_erpp_fabric_counters_table_key_t& lookup_key, const npl_erpp_fabric_counters_table_key_t& table_key, const npl_erpp_fabric_counters_table_key_t& table_mask);
    };
    
    struct npl_eth_meter_profile_mapping_table_functional_traits_t {
        typedef npl_eth_meter_profile_mapping_table_key_t key_type;
        typedef npl_eth_meter_profile_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_ETH_METER_PROFILE_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("eth_meter_profile_mapping_table");
            return table_name;
        }
    };
    
    struct npl_eth_oam_set_da_mc2_static_table_functional_traits_t {
        typedef npl_eth_oam_set_da_mc2_static_table_key_t key_type;
        typedef npl_eth_oam_set_da_mc2_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_ETH_OAM_SET_DA_MC2_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("eth_oam_set_da_mc2_static_table");
            return table_name;
        }
    };
    
    struct npl_eth_oam_set_da_mc_static_table_functional_traits_t {
        typedef npl_eth_oam_set_da_mc_static_table_key_t key_type;
        typedef npl_eth_oam_set_da_mc_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_ETH_OAM_SET_DA_MC_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("eth_oam_set_da_mc_static_table");
            return table_name;
        }
    };
    
    struct npl_eth_rtf_conf_set_mapping_table_functional_traits_t {
        typedef npl_eth_rtf_conf_set_mapping_table_key_t key_type;
        typedef npl_eth_rtf_conf_set_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_ETH_RTF_CONF_SET_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("eth_rtf_conf_set_mapping_table");
            return table_name;
        }
    };
    
    struct npl_eve_byte_addition_static_table_functional_traits_t {
        typedef npl_eve_byte_addition_static_table_key_t key_type;
        typedef npl_eve_byte_addition_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_EVE_BYTE_ADDITION_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("eve_byte_addition_static_table");
            return table_name;
        }
    };
    
    struct npl_eve_to_ethernet_ene_static_table_functional_traits_t {
        typedef npl_eve_to_ethernet_ene_static_table_key_t key_type;
        typedef npl_eve_to_ethernet_ene_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_EVE_TO_ETHERNET_ENE_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("eve_to_ethernet_ene_static_table");
            return table_name;
        }
    };
    
    struct npl_event_queue_table_functional_traits_t {
        typedef npl_event_queue_table_key_t key_type;
        typedef npl_event_queue_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_EVENT_QUEUE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("event_queue_table");
            return table_name;
        }
    };
    
    struct npl_external_aux_table_functional_traits_t {
        typedef npl_external_aux_table_key_t key_type;
        typedef npl_external_aux_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_EXTERNAL_AUX_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("external_aux_table");
            return table_name;
        }
    };
    
    struct npl_fabric_and_tm_header_size_static_table_functional_traits_t {
        typedef npl_fabric_and_tm_header_size_static_table_key_t key_type;
        typedef npl_fabric_and_tm_header_size_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_AND_TM_HEADER_SIZE_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_and_tm_header_size_static_table");
            return table_name;
        }
        static const size_t table_size = 4;
        static bool key_match(const npl_fabric_and_tm_header_size_static_table_key_t& lookup_key, const npl_fabric_and_tm_header_size_static_table_key_t& table_key, const npl_fabric_and_tm_header_size_static_table_key_t& table_mask);
    };
    
    struct npl_fabric_header_ene_macro_table_functional_traits_t {
        typedef npl_fabric_header_ene_macro_table_key_t key_type;
        typedef npl_fabric_header_ene_macro_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_HEADER_ENE_MACRO_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_header_ene_macro_table");
            return table_name;
        }
        static const size_t table_size = 12;
        static bool key_match(const npl_fabric_header_ene_macro_table_key_t& lookup_key, const npl_fabric_header_ene_macro_table_key_t& table_key, const npl_fabric_header_ene_macro_table_key_t& table_mask);
    };
    
    struct npl_fabric_header_types_static_table_functional_traits_t {
        typedef npl_fabric_header_types_static_table_key_t key_type;
        typedef npl_fabric_header_types_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_HEADER_TYPES_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_header_types_static_table");
            return table_name;
        }
    };
    
    struct npl_fabric_headers_type_table_functional_traits_t {
        typedef npl_fabric_headers_type_table_key_t key_type;
        typedef npl_fabric_headers_type_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_HEADERS_TYPE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_headers_type_table");
            return table_name;
        }
        static const size_t table_size = 15;
        static bool key_match(const npl_fabric_headers_type_table_key_t& lookup_key, const npl_fabric_headers_type_table_key_t& table_key, const npl_fabric_headers_type_table_key_t& table_mask);
    };
    
    struct npl_fabric_init_cfg_functional_traits_t {
        typedef npl_fabric_init_cfg_key_t key_type;
        typedef npl_fabric_init_cfg_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_INIT_CFG;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_init_cfg");
            return table_name;
        }
        static const size_t table_size = 1;
        static bool key_match(const npl_fabric_init_cfg_key_t& lookup_key, const npl_fabric_init_cfg_key_t& table_key, const npl_fabric_init_cfg_key_t& table_mask);
    };
    
    struct npl_fabric_npuh_size_calculation_static_table_functional_traits_t {
        typedef npl_fabric_npuh_size_calculation_static_table_key_t key_type;
        typedef npl_fabric_npuh_size_calculation_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_NPUH_SIZE_CALCULATION_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_npuh_size_calculation_static_table");
            return table_name;
        }
        static const size_t table_size = 5;
        static bool key_match(const npl_fabric_npuh_size_calculation_static_table_key_t& lookup_key, const npl_fabric_npuh_size_calculation_static_table_key_t& table_key, const npl_fabric_npuh_size_calculation_static_table_key_t& table_mask);
    };
    
    struct npl_fabric_out_color_map_table_functional_traits_t {
        typedef npl_fabric_out_color_map_table_key_t key_type;
        typedef npl_fabric_out_color_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_OUT_COLOR_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_out_color_map_table");
            return table_name;
        }
        static const size_t table_size = 4;
        static bool key_match(const npl_fabric_out_color_map_table_key_t& lookup_key, const npl_fabric_out_color_map_table_key_t& table_key, const npl_fabric_out_color_map_table_key_t& table_mask);
    };
    
    struct npl_fabric_rx_fwd_error_handling_counter_table_functional_traits_t {
        typedef npl_fabric_rx_fwd_error_handling_counter_table_key_t key_type;
        typedef npl_fabric_rx_fwd_error_handling_counter_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_RX_FWD_ERROR_HANDLING_COUNTER_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_rx_fwd_error_handling_counter_table");
            return table_name;
        }
    };
    
    struct npl_fabric_rx_fwd_error_handling_destination_table_functional_traits_t {
        typedef npl_fabric_rx_fwd_error_handling_destination_table_key_t key_type;
        typedef npl_fabric_rx_fwd_error_handling_destination_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_RX_FWD_ERROR_HANDLING_DESTINATION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_rx_fwd_error_handling_destination_table");
            return table_name;
        }
    };
    
    struct npl_fabric_rx_term_error_handling_counter_table_functional_traits_t {
        typedef npl_fabric_rx_term_error_handling_counter_table_key_t key_type;
        typedef npl_fabric_rx_term_error_handling_counter_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_RX_TERM_ERROR_HANDLING_COUNTER_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_rx_term_error_handling_counter_table");
            return table_name;
        }
    };
    
    struct npl_fabric_rx_term_error_handling_destination_table_functional_traits_t {
        typedef npl_fabric_rx_term_error_handling_destination_table_key_t key_type;
        typedef npl_fabric_rx_term_error_handling_destination_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_RX_TERM_ERROR_HANDLING_DESTINATION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_rx_term_error_handling_destination_table");
            return table_name;
        }
    };
    
    struct npl_fabric_scaled_mc_map_to_netork_slice_static_table_functional_traits_t {
        typedef npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t key_type;
        typedef npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_SCALED_MC_MAP_TO_NETORK_SLICE_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_scaled_mc_map_to_netork_slice_static_table");
            return table_name;
        }
    };
    
    struct npl_fabric_smcid_threshold_table_functional_traits_t {
        typedef npl_fabric_smcid_threshold_table_key_t key_type;
        typedef npl_fabric_smcid_threshold_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_SMCID_THRESHOLD_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_smcid_threshold_table");
            return table_name;
        }
    };
    
    struct npl_fabric_term_error_checker_static_table_functional_traits_t {
        typedef npl_fabric_term_error_checker_static_table_key_t key_type;
        typedef npl_fabric_term_error_checker_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_TERM_ERROR_CHECKER_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_term_error_checker_static_table");
            return table_name;
        }
        static const size_t table_size = 7;
        static bool key_match(const npl_fabric_term_error_checker_static_table_key_t& lookup_key, const npl_fabric_term_error_checker_static_table_key_t& table_key, const npl_fabric_term_error_checker_static_table_key_t& table_mask);
    };
    
    struct npl_fabric_tm_headers_table_functional_traits_t {
        typedef npl_fabric_tm_headers_table_key_t key_type;
        typedef npl_fabric_tm_headers_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_TM_HEADERS_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_tm_headers_table");
            return table_name;
        }
    };
    
    struct npl_fabric_transmit_error_checker_static_table_functional_traits_t {
        typedef npl_fabric_transmit_error_checker_static_table_key_t key_type;
        typedef npl_fabric_transmit_error_checker_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_FABRIC_TRANSMIT_ERROR_CHECKER_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fabric_transmit_error_checker_static_table");
            return table_name;
        }
        static const size_t table_size = 5;
        static bool key_match(const npl_fabric_transmit_error_checker_static_table_key_t& lookup_key, const npl_fabric_transmit_error_checker_static_table_key_t& table_key, const npl_fabric_transmit_error_checker_static_table_key_t& table_mask);
    };
    
    struct npl_fb_link_2_link_bundle_table_functional_traits_t {
        typedef npl_fb_link_2_link_bundle_table_key_t key_type;
        typedef npl_fb_link_2_link_bundle_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FB_LINK_2_LINK_BUNDLE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fb_link_2_link_bundle_table");
            return table_name;
        }
    };
    
    struct npl_fe_broadcast_bmp_table_functional_traits_t {
        typedef npl_fe_broadcast_bmp_table_key_t key_type;
        typedef npl_fe_broadcast_bmp_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FE_BROADCAST_BMP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fe_broadcast_bmp_table");
            return table_name;
        }
    };
    
    struct npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_functional_traits_t {
        typedef npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t key_type;
        typedef npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FE_RLB_UC_TX_FB_LINK_TO_OQ_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fe_rlb_uc_tx_fb_link_to_oq_map_table");
            return table_name;
        }
    };
    
    struct npl_fe_smcid_threshold_table_functional_traits_t {
        typedef npl_fe_smcid_threshold_table_key_t key_type;
        typedef npl_fe_smcid_threshold_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FE_SMCID_THRESHOLD_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fe_smcid_threshold_table");
            return table_name;
        }
    };
    
    struct npl_fe_smcid_to_mcid_table_functional_traits_t {
        typedef npl_fe_smcid_to_mcid_table_key_t key_type;
        typedef npl_fe_smcid_to_mcid_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FE_SMCID_TO_MCID_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fe_smcid_to_mcid_table");
            return table_name;
        }
    };
    
    struct npl_fe_uc_link_bundle_desc_table_functional_traits_t {
        typedef npl_fe_uc_link_bundle_desc_table_key_t key_type;
        typedef npl_fe_uc_link_bundle_desc_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FE_UC_LINK_BUNDLE_DESC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fe_uc_link_bundle_desc_table");
            return table_name;
        }
    };
    
    struct npl_fi_core_tcam_table_functional_traits_t {
        typedef npl_fi_core_tcam_table_key_t key_type;
        typedef npl_fi_core_tcam_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_FI_CORE_TCAM_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fi_core_tcam_table");
            return table_name;
        }
        static const size_t table_size = 128;
        static bool key_match(const npl_fi_core_tcam_table_key_t& lookup_key, const npl_fi_core_tcam_table_key_t& table_key, const npl_fi_core_tcam_table_key_t& table_mask);
    };
    
    struct npl_fi_macro_config_table_functional_traits_t {
        typedef npl_fi_macro_config_table_key_t key_type;
        typedef npl_fi_macro_config_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FI_MACRO_CONFIG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fi_macro_config_table");
            return table_name;
        }
    };
    
    struct npl_filb_voq_mapping_functional_traits_t {
        typedef npl_filb_voq_mapping_key_t key_type;
        typedef npl_filb_voq_mapping_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FILB_VOQ_MAPPING;
        static const std::string& get_table_name() {
            static const std::string table_name("filb_voq_mapping");
            return table_name;
        }
    };
    
    struct npl_first_ene_static_table_functional_traits_t {
        typedef npl_first_ene_static_table_key_t key_type;
        typedef npl_first_ene_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FIRST_ENE_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("first_ene_static_table");
            return table_name;
        }
    };
    
    struct npl_frm_db_fabric_routing_table_functional_traits_t {
        typedef npl_frm_db_fabric_routing_table_key_t key_type;
        typedef npl_frm_db_fabric_routing_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FRM_DB_FABRIC_ROUTING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("frm_db_fabric_routing_table");
            return table_name;
        }
    };
    
    struct npl_fwd_destination_to_tm_result_data_functional_traits_t {
        typedef npl_fwd_destination_to_tm_result_data_key_t key_type;
        typedef npl_fwd_destination_to_tm_result_data_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_FWD_DESTINATION_TO_TM_RESULT_DATA;
        static const std::string& get_table_name() {
            static const std::string table_name("fwd_destination_to_tm_result_data");
            return table_name;
        }
    };
    
    struct npl_fwd_type_to_ive_enable_table_functional_traits_t {
        typedef npl_fwd_type_to_ive_enable_table_key_t key_type;
        typedef npl_fwd_type_to_ive_enable_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_FWD_TYPE_TO_IVE_ENABLE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("fwd_type_to_ive_enable_table");
            return table_name;
        }
    };
    
    struct npl_get_ecm_meter_ptr_table_functional_traits_t {
        typedef npl_get_ecm_meter_ptr_table_key_t key_type;
        typedef npl_get_ecm_meter_ptr_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_GET_ECM_METER_PTR_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("get_ecm_meter_ptr_table");
            return table_name;
        }
    };
    
    struct npl_get_ingress_ptp_info_and_is_slp_dm_static_table_functional_traits_t {
        typedef npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t key_type;
        typedef npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_GET_INGRESS_PTP_INFO_AND_IS_SLP_DM_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("get_ingress_ptp_info_and_is_slp_dm_static_table");
            return table_name;
        }
    };
    
    struct npl_get_l2_rtf_conf_set_and_init_stages_functional_traits_t {
        typedef npl_get_l2_rtf_conf_set_and_init_stages_key_t key_type;
        typedef npl_get_l2_rtf_conf_set_and_init_stages_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_GET_L2_RTF_CONF_SET_AND_INIT_STAGES;
        static const std::string& get_table_name() {
            static const std::string table_name("get_l2_rtf_conf_set_and_init_stages");
            return table_name;
        }
    };
    
    struct npl_get_non_comp_mc_value_static_table_functional_traits_t {
        typedef npl_get_non_comp_mc_value_static_table_key_t key_type;
        typedef npl_get_non_comp_mc_value_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_GET_NON_COMP_MC_VALUE_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("get_non_comp_mc_value_static_table");
            return table_name;
        }
    };
    
    struct npl_gre_proto_static_table_functional_traits_t {
        typedef npl_gre_proto_static_table_key_t key_type;
        typedef npl_gre_proto_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_GRE_PROTO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("gre_proto_static_table");
            return table_name;
        }
    };
    
    struct npl_hmc_cgm_cgm_lut_table_functional_traits_t {
        typedef npl_hmc_cgm_cgm_lut_table_key_t key_type;
        typedef npl_hmc_cgm_cgm_lut_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_HMC_CGM_CGM_LUT_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("hmc_cgm_cgm_lut_table");
            return table_name;
        }
    };
    
    struct npl_hmc_cgm_profile_global_table_functional_traits_t {
        typedef npl_hmc_cgm_profile_global_table_key_t key_type;
        typedef npl_hmc_cgm_profile_global_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_HMC_CGM_PROFILE_GLOBAL_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("hmc_cgm_profile_global_table");
            return table_name;
        }
    };
    
    struct npl_ibm_cmd_table_functional_traits_t {
        typedef npl_ibm_cmd_table_key_t key_type;
        typedef npl_ibm_cmd_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IBM_CMD_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ibm_cmd_table");
            return table_name;
        }
    };
    
    struct npl_ibm_mc_cmd_to_encap_data_table_functional_traits_t {
        typedef npl_ibm_mc_cmd_to_encap_data_table_key_t key_type;
        typedef npl_ibm_mc_cmd_to_encap_data_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IBM_MC_CMD_TO_ENCAP_DATA_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ibm_mc_cmd_to_encap_data_table");
            return table_name;
        }
    };
    
    struct npl_ibm_uc_cmd_to_encap_data_table_functional_traits_t {
        typedef npl_ibm_uc_cmd_to_encap_data_table_key_t key_type;
        typedef npl_ibm_uc_cmd_to_encap_data_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IBM_UC_CMD_TO_ENCAP_DATA_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ibm_uc_cmd_to_encap_data_table");
            return table_name;
        }
    };
    
    struct npl_ifgb_tc_lut_table_functional_traits_t {
        typedef npl_ifgb_tc_lut_table_key_t key_type;
        typedef npl_ifgb_tc_lut_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IFGB_TC_LUT_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ifgb_tc_lut_table");
            return table_name;
        }
    };
    
    struct npl_ingress_ip_qos_mapping_table_functional_traits_t {
        typedef npl_ingress_ip_qos_mapping_table_key_t key_type;
        typedef npl_ingress_ip_qos_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_IP_QOS_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_ip_qos_mapping_table");
            return table_name;
        }
    };
    
    struct npl_ingress_rtf_eth_db1_160_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_eth_db1_160_f0_table_key_t key_type;
        typedef npl_ingress_rtf_eth_db1_160_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_ETH_DB1_160_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_eth_db1_160_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_eth_db1_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_eth_db1_160_f0_table_key_t& table_key, const npl_ingress_rtf_eth_db1_160_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_eth_db2_160_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_eth_db2_160_f0_table_key_t key_type;
        typedef npl_ingress_rtf_eth_db2_160_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_ETH_DB2_160_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_eth_db2_160_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_eth_db2_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_eth_db2_160_f0_table_key_t& table_key, const npl_ingress_rtf_eth_db2_160_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv4_db1_160_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv4_db1_160_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv4_db1_160_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV4_DB1_160_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv4_db1_160_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv4_db1_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db1_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db1_160_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv4_db1_160_f1_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv4_db1_160_f1_table_key_t key_type;
        typedef npl_ingress_rtf_ipv4_db1_160_f1_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV4_DB1_160_F1_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv4_db1_160_f1_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv4_db1_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db1_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv4_db1_160_f1_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv4_db1_320_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv4_db1_320_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv4_db1_320_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV4_DB1_320_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv4_db1_320_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv4_db1_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db1_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db1_320_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv4_db2_160_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv4_db2_160_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv4_db2_160_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV4_DB2_160_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv4_db2_160_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv4_db2_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db2_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db2_160_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv4_db2_160_f1_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv4_db2_160_f1_table_key_t key_type;
        typedef npl_ingress_rtf_ipv4_db2_160_f1_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV4_DB2_160_F1_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv4_db2_160_f1_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv4_db2_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db2_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv4_db2_160_f1_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv4_db2_320_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv4_db2_320_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv4_db2_320_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV4_DB2_320_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv4_db2_320_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv4_db2_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db2_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db2_320_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv4_db3_160_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv4_db3_160_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv4_db3_160_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV4_DB3_160_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv4_db3_160_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv4_db3_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db3_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db3_160_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv4_db3_160_f1_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv4_db3_160_f1_table_key_t key_type;
        typedef npl_ingress_rtf_ipv4_db3_160_f1_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV4_DB3_160_F1_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv4_db3_160_f1_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv4_db3_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db3_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv4_db3_160_f1_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv4_db3_320_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv4_db3_320_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv4_db3_320_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV4_DB3_320_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv4_db3_320_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv4_db3_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db3_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db3_320_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv4_db4_160_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv4_db4_160_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv4_db4_160_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV4_DB4_160_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv4_db4_160_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv4_db4_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db4_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db4_160_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv4_db4_160_f1_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv4_db4_160_f1_table_key_t key_type;
        typedef npl_ingress_rtf_ipv4_db4_160_f1_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV4_DB4_160_F1_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv4_db4_160_f1_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv4_db4_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db4_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv4_db4_160_f1_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv4_db4_320_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv4_db4_320_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv4_db4_320_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV4_DB4_320_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv4_db4_320_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv4_db4_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv4_db4_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv4_db4_320_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv6_db1_160_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv6_db1_160_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv6_db1_160_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV6_DB1_160_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv6_db1_160_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv6_db1_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db1_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db1_160_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv6_db1_160_f1_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv6_db1_160_f1_table_key_t key_type;
        typedef npl_ingress_rtf_ipv6_db1_160_f1_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV6_DB1_160_F1_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv6_db1_160_f1_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv6_db1_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db1_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv6_db1_160_f1_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv6_db1_320_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv6_db1_320_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv6_db1_320_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV6_DB1_320_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv6_db1_320_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv6_db1_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db1_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db1_320_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv6_db2_160_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv6_db2_160_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv6_db2_160_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV6_DB2_160_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv6_db2_160_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv6_db2_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db2_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db2_160_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv6_db2_160_f1_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv6_db2_160_f1_table_key_t key_type;
        typedef npl_ingress_rtf_ipv6_db2_160_f1_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV6_DB2_160_F1_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv6_db2_160_f1_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv6_db2_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db2_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv6_db2_160_f1_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv6_db2_320_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv6_db2_320_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv6_db2_320_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV6_DB2_320_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv6_db2_320_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv6_db2_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db2_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db2_320_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv6_db3_160_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv6_db3_160_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv6_db3_160_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV6_DB3_160_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv6_db3_160_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv6_db3_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db3_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db3_160_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv6_db3_160_f1_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv6_db3_160_f1_table_key_t key_type;
        typedef npl_ingress_rtf_ipv6_db3_160_f1_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV6_DB3_160_F1_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv6_db3_160_f1_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv6_db3_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db3_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv6_db3_160_f1_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv6_db3_320_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv6_db3_320_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv6_db3_320_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV6_DB3_320_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv6_db3_320_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv6_db3_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db3_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db3_320_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv6_db4_160_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv6_db4_160_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv6_db4_160_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV6_DB4_160_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv6_db4_160_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv6_db4_160_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db4_160_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db4_160_f0_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv6_db4_160_f1_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv6_db4_160_f1_table_key_t key_type;
        typedef npl_ingress_rtf_ipv6_db4_160_f1_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV6_DB4_160_F1_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv6_db4_160_f1_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv6_db4_160_f1_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db4_160_f1_table_key_t& table_key, const npl_ingress_rtf_ipv6_db4_160_f1_table_key_t& table_mask);
    };
    
    struct npl_ingress_rtf_ipv6_db4_320_f0_table_functional_traits_t {
        typedef npl_ingress_rtf_ipv6_db4_320_f0_table_key_t key_type;
        typedef npl_ingress_rtf_ipv6_db4_320_f0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INGRESS_RTF_IPV6_DB4_320_F0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ingress_rtf_ipv6_db4_320_f0_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_ingress_rtf_ipv6_db4_320_f0_table_key_t& lookup_key, const npl_ingress_rtf_ipv6_db4_320_f0_table_key_t& table_key, const npl_ingress_rtf_ipv6_db4_320_f0_table_key_t& table_mask);
    };
    
    struct npl_inject_down_select_ene_static_table_functional_traits_t {
        typedef npl_inject_down_select_ene_static_table_key_t key_type;
        typedef npl_inject_down_select_ene_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_INJECT_DOWN_SELECT_ENE_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("inject_down_select_ene_static_table");
            return table_name;
        }
        static const size_t table_size = 5;
        static bool key_match(const npl_inject_down_select_ene_static_table_key_t& lookup_key, const npl_inject_down_select_ene_static_table_key_t& table_key, const npl_inject_down_select_ene_static_table_key_t& table_mask);
    };
    
    struct npl_inject_down_tx_redirect_counter_table_functional_traits_t {
        typedef npl_inject_down_tx_redirect_counter_table_key_t key_type;
        typedef npl_inject_down_tx_redirect_counter_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_INJECT_DOWN_TX_REDIRECT_COUNTER_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("inject_down_tx_redirect_counter_table");
            return table_name;
        }
    };
    
    struct npl_inject_mact_ldb_to_output_lr_functional_traits_t {
        typedef npl_inject_mact_ldb_to_output_lr_key_t key_type;
        typedef npl_inject_mact_ldb_to_output_lr_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_INJECT_MACT_LDB_TO_OUTPUT_LR;
        static const std::string& get_table_name() {
            static const std::string table_name("inject_mact_ldb_to_output_lr");
            return table_name;
        }
    };
    
    struct npl_inject_up_pif_ifg_init_data_table_functional_traits_t {
        typedef npl_inject_up_pif_ifg_init_data_table_key_t key_type;
        typedef npl_inject_up_pif_ifg_init_data_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_INJECT_UP_PIF_IFG_INIT_DATA_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("inject_up_pif_ifg_init_data_table");
            return table_name;
        }
    };
    
    struct npl_inject_up_ssp_init_data_table_functional_traits_t {
        typedef npl_inject_up_ssp_init_data_table_key_t key_type;
        typedef npl_inject_up_ssp_init_data_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_INJECT_UP_SSP_INIT_DATA_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("inject_up_ssp_init_data_table");
            return table_name;
        }
    };
    
    struct npl_inner_tpid_table_functional_traits_t {
        typedef npl_inner_tpid_table_key_t key_type;
        typedef npl_inner_tpid_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_INNER_TPID_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("inner_tpid_table");
            return table_name;
        }
    };
    
    struct npl_ip_fwd_header_mapping_to_ethtype_static_table_functional_traits_t {
        typedef npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t key_type;
        typedef npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IP_FWD_HEADER_MAPPING_TO_ETHTYPE_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ip_fwd_header_mapping_to_ethtype_static_table");
            return table_name;
        }
    };
    
    struct npl_ip_ingress_cmp_mcid_static_table_functional_traits_t {
        typedef npl_ip_ingress_cmp_mcid_static_table_key_t key_type;
        typedef npl_ip_ingress_cmp_mcid_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_IP_INGRESS_CMP_MCID_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ip_ingress_cmp_mcid_static_table");
            return table_name;
        }
        static const size_t table_size = 4;
        static bool key_match(const npl_ip_ingress_cmp_mcid_static_table_key_t& lookup_key, const npl_ip_ingress_cmp_mcid_static_table_key_t& table_key, const npl_ip_ingress_cmp_mcid_static_table_key_t& table_mask);
    };
    
    struct npl_ip_mc_local_inject_type_static_table_functional_traits_t {
        typedef npl_ip_mc_local_inject_type_static_table_key_t key_type;
        typedef npl_ip_mc_local_inject_type_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IP_MC_LOCAL_INJECT_TYPE_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ip_mc_local_inject_type_static_table");
            return table_name;
        }
    };
    
    struct npl_ip_mc_next_macro_static_table_functional_traits_t {
        typedef npl_ip_mc_next_macro_static_table_key_t key_type;
        typedef npl_ip_mc_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IP_MC_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ip_mc_next_macro_static_table");
            return table_name;
        }
    };
    
    struct npl_ip_meter_profile_mapping_table_functional_traits_t {
        typedef npl_ip_meter_profile_mapping_table_key_t key_type;
        typedef npl_ip_meter_profile_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IP_METER_PROFILE_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ip_meter_profile_mapping_table");
            return table_name;
        }
    };
    
    struct npl_ip_prefix_destination_table_functional_traits_t {
        typedef npl_ip_prefix_destination_table_key_t key_type;
        typedef npl_ip_prefix_destination_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_IP_PREFIX_DESTINATION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ip_prefix_destination_table");
            return table_name;
        }
    };
    
    struct npl_ip_relay_to_vni_table_functional_traits_t {
        typedef npl_ip_relay_to_vni_table_key_t key_type;
        typedef npl_ip_relay_to_vni_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_IP_RELAY_TO_VNI_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ip_relay_to_vni_table");
            return table_name;
        }
    };
    
    struct npl_ip_rx_global_counter_table_functional_traits_t {
        typedef npl_ip_rx_global_counter_table_key_t key_type;
        typedef npl_ip_rx_global_counter_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IP_RX_GLOBAL_COUNTER_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ip_rx_global_counter_table");
            return table_name;
        }
    };
    
    struct npl_ip_ver_mc_static_table_functional_traits_t {
        typedef npl_ip_ver_mc_static_table_key_t key_type;
        typedef npl_ip_ver_mc_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_IP_VER_MC_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ip_ver_mc_static_table");
            return table_name;
        }
        static const size_t table_size = 6;
        static bool key_match(const npl_ip_ver_mc_static_table_key_t& lookup_key, const npl_ip_ver_mc_static_table_key_t& table_key, const npl_ip_ver_mc_static_table_key_t& table_mask);
    };
    
    struct npl_ipv4_acl_map_protocol_type_to_protocol_number_table_functional_traits_t {
        typedef npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t key_type;
        typedef npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_IPV4_ACL_MAP_PROTOCOL_TYPE_TO_PROTOCOL_NUMBER_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv4_acl_map_protocol_type_to_protocol_number_table");
            return table_name;
        }
        static const size_t table_size = 9;
        static bool key_match(const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t& lookup_key, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t& table_key, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t& table_mask);
    };
    
    struct npl_ipv4_acl_sport_static_table_functional_traits_t {
        typedef npl_ipv4_acl_sport_static_table_key_t key_type;
        typedef npl_ipv4_acl_sport_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IPV4_ACL_SPORT_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv4_acl_sport_static_table");
            return table_name;
        }
    };
    
    struct npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_functional_traits_t {
        typedef npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t key_type;
        typedef npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_IPV4_IP_TUNNEL_TERMINATION_DIP_INDEX_TT0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv4_ip_tunnel_termination_dip_index_tt0_table");
            return table_name;
        }
    };
    
    struct npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_functional_traits_t {
        typedef npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t key_type;
        typedef npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_IPV4_IP_TUNNEL_TERMINATION_SIP_DIP_INDEX_TT0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv4_ip_tunnel_termination_sip_dip_index_tt0_table");
            return table_name;
        }
    };
    
    struct npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_functional_traits_t {
        typedef npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t key_type;
        typedef npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_IPV4_IP_TUNNEL_TERMINATION_SIP_DIP_INDEX_TT1_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv4_ip_tunnel_termination_sip_dip_index_tt1_table");
            return table_name;
        }
    };
    
    struct npl_ipv4_lpm_table_functional_traits_t {
        typedef npl_ipv4_lpm_table_key_t key_type;
        typedef npl_ipv4_lpm_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_LPM;
        static const npl_tables_e table_id = NPL_TABLES_IPV4_LPM_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv4_lpm_table");
            return table_name;
        }
        static void mask_key(npl_ipv4_lpm_table_key_t* key, size_t length);
    };
    
    struct npl_ipv4_lpts_table_functional_traits_t {
        typedef npl_ipv4_lpts_table_key_t key_type;
        typedef npl_ipv4_lpts_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_IPV4_LPTS_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv4_lpts_table");
            return table_name;
        }
        static const size_t table_size = 32767;
        static bool key_match(const npl_ipv4_lpts_table_key_t& lookup_key, const npl_ipv4_lpts_table_key_t& table_key, const npl_ipv4_lpts_table_key_t& table_mask);
    };
    
    struct npl_ipv4_og_pcl_em_table_functional_traits_t {
        typedef npl_ipv4_og_pcl_em_table_key_t key_type;
        typedef npl_ipv4_og_pcl_em_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_IPV4_OG_PCL_EM_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv4_og_pcl_em_table");
            return table_name;
        }
    };
    
    struct npl_ipv4_og_pcl_lpm_table_functional_traits_t {
        typedef npl_ipv4_og_pcl_lpm_table_key_t key_type;
        typedef npl_ipv4_og_pcl_lpm_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_LPM;
        static const npl_tables_e table_id = NPL_TABLES_IPV4_OG_PCL_LPM_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv4_og_pcl_lpm_table");
            return table_name;
        }
        static void mask_key(npl_ipv4_og_pcl_lpm_table_key_t* key, size_t length);
    };
    
    struct npl_ipv4_rtf_conf_set_mapping_table_functional_traits_t {
        typedef npl_ipv4_rtf_conf_set_mapping_table_key_t key_type;
        typedef npl_ipv4_rtf_conf_set_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IPV4_RTF_CONF_SET_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv4_rtf_conf_set_mapping_table");
            return table_name;
        }
    };
    
    struct npl_ipv4_vrf_dip_em_table_functional_traits_t {
        typedef npl_ipv4_vrf_dip_em_table_key_t key_type;
        typedef npl_ipv4_vrf_dip_em_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_IPV4_VRF_DIP_EM_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv4_vrf_dip_em_table");
            return table_name;
        }
    };
    
    struct npl_ipv4_vrf_s_g_table_functional_traits_t {
        typedef npl_ipv4_vrf_s_g_table_key_t key_type;
        typedef npl_ipv4_vrf_s_g_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_IPV4_VRF_S_G_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv4_vrf_s_g_table");
            return table_name;
        }
    };
    
    struct npl_ipv6_acl_sport_static_table_functional_traits_t {
        typedef npl_ipv6_acl_sport_static_table_key_t key_type;
        typedef npl_ipv6_acl_sport_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IPV6_ACL_SPORT_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv6_acl_sport_static_table");
            return table_name;
        }
    };
    
    struct npl_ipv6_first_fragment_static_table_functional_traits_t {
        typedef npl_ipv6_first_fragment_static_table_key_t key_type;
        typedef npl_ipv6_first_fragment_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_IPV6_FIRST_FRAGMENT_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv6_first_fragment_static_table");
            return table_name;
        }
        static const size_t table_size = 6;
        static bool key_match(const npl_ipv6_first_fragment_static_table_key_t& lookup_key, const npl_ipv6_first_fragment_static_table_key_t& table_key, const npl_ipv6_first_fragment_static_table_key_t& table_mask);
    };
    
    struct npl_ipv6_lpm_table_functional_traits_t {
        typedef npl_ipv6_lpm_table_key_t key_type;
        typedef npl_ipv6_lpm_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_LPM;
        static const npl_tables_e table_id = NPL_TABLES_IPV6_LPM_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv6_lpm_table");
            return table_name;
        }
        static void mask_key(npl_ipv6_lpm_table_key_t* key, size_t length);
    };
    
    struct npl_ipv6_lpts_table_functional_traits_t {
        typedef npl_ipv6_lpts_table_key_t key_type;
        typedef npl_ipv6_lpts_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_IPV6_LPTS_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv6_lpts_table");
            return table_name;
        }
        static const size_t table_size = 32767;
        static bool key_match(const npl_ipv6_lpts_table_key_t& lookup_key, const npl_ipv6_lpts_table_key_t& table_key, const npl_ipv6_lpts_table_key_t& table_mask);
    };
    
    struct npl_ipv6_mc_select_qos_id_functional_traits_t {
        typedef npl_ipv6_mc_select_qos_id_key_t key_type;
        typedef npl_ipv6_mc_select_qos_id_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IPV6_MC_SELECT_QOS_ID;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv6_mc_select_qos_id");
            return table_name;
        }
    };
    
    struct npl_ipv6_og_pcl_em_table_functional_traits_t {
        typedef npl_ipv6_og_pcl_em_table_key_t key_type;
        typedef npl_ipv6_og_pcl_em_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_IPV6_OG_PCL_EM_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv6_og_pcl_em_table");
            return table_name;
        }
    };
    
    struct npl_ipv6_og_pcl_lpm_table_functional_traits_t {
        typedef npl_ipv6_og_pcl_lpm_table_key_t key_type;
        typedef npl_ipv6_og_pcl_lpm_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_LPM;
        static const npl_tables_e table_id = NPL_TABLES_IPV6_OG_PCL_LPM_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv6_og_pcl_lpm_table");
            return table_name;
        }
        static void mask_key(npl_ipv6_og_pcl_lpm_table_key_t* key, size_t length);
    };
    
    struct npl_ipv6_rtf_conf_set_mapping_table_functional_traits_t {
        typedef npl_ipv6_rtf_conf_set_mapping_table_key_t key_type;
        typedef npl_ipv6_rtf_conf_set_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IPV6_RTF_CONF_SET_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv6_rtf_conf_set_mapping_table");
            return table_name;
        }
    };
    
    struct npl_ipv6_sip_compression_table_functional_traits_t {
        typedef npl_ipv6_sip_compression_table_key_t key_type;
        typedef npl_ipv6_sip_compression_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_IPV6_SIP_COMPRESSION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv6_sip_compression_table");
            return table_name;
        }
        static const size_t table_size = 32767;
        static bool key_match(const npl_ipv6_sip_compression_table_key_t& lookup_key, const npl_ipv6_sip_compression_table_key_t& table_key, const npl_ipv6_sip_compression_table_key_t& table_mask);
    };
    
    struct npl_ipv6_vrf_dip_em_table_functional_traits_t {
        typedef npl_ipv6_vrf_dip_em_table_key_t key_type;
        typedef npl_ipv6_vrf_dip_em_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_IPV6_VRF_DIP_EM_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv6_vrf_dip_em_table");
            return table_name;
        }
    };
    
    struct npl_ipv6_vrf_s_g_table_functional_traits_t {
        typedef npl_ipv6_vrf_s_g_table_key_t key_type;
        typedef npl_ipv6_vrf_s_g_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_IPV6_VRF_S_G_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ipv6_vrf_s_g_table");
            return table_name;
        }
    };
    
    struct npl_is_pacific_b1_static_table_functional_traits_t {
        typedef npl_is_pacific_b1_static_table_key_t key_type;
        typedef npl_is_pacific_b1_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_IS_PACIFIC_B1_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("is_pacific_b1_static_table");
            return table_name;
        }
    };
    
    struct npl_l2_dlp_table_functional_traits_t {
        typedef npl_l2_dlp_table_key_t key_type;
        typedef npl_l2_dlp_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_L2_DLP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l2_dlp_table");
            return table_name;
        }
    };
    
    struct npl_l2_lp_profile_filter_table_functional_traits_t {
        typedef npl_l2_lp_profile_filter_table_key_t key_type;
        typedef npl_l2_lp_profile_filter_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_L2_LP_PROFILE_FILTER_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l2_lp_profile_filter_table");
            return table_name;
        }
    };
    
    struct npl_l2_lpts_ctrl_fields_static_table_functional_traits_t {
        typedef npl_l2_lpts_ctrl_fields_static_table_key_t key_type;
        typedef npl_l2_lpts_ctrl_fields_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_L2_LPTS_CTRL_FIELDS_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l2_lpts_ctrl_fields_static_table");
            return table_name;
        }
        static const size_t table_size = 15;
        static bool key_match(const npl_l2_lpts_ctrl_fields_static_table_key_t& lookup_key, const npl_l2_lpts_ctrl_fields_static_table_key_t& table_key, const npl_l2_lpts_ctrl_fields_static_table_key_t& table_mask);
    };
    
    struct npl_l2_lpts_ip_fragment_static_table_functional_traits_t {
        typedef npl_l2_lpts_ip_fragment_static_table_key_t key_type;
        typedef npl_l2_lpts_ip_fragment_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_L2_LPTS_IP_FRAGMENT_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l2_lpts_ip_fragment_static_table");
            return table_name;
        }
    };
    
    struct npl_l2_lpts_ipv4_table_functional_traits_t {
        typedef npl_l2_lpts_ipv4_table_key_t key_type;
        typedef npl_l2_lpts_ipv4_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_L2_LPTS_IPV4_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l2_lpts_ipv4_table");
            return table_name;
        }
        static const size_t table_size = 32767;
        static bool key_match(const npl_l2_lpts_ipv4_table_key_t& lookup_key, const npl_l2_lpts_ipv4_table_key_t& table_key, const npl_l2_lpts_ipv4_table_key_t& table_mask);
    };
    
    struct npl_l2_lpts_ipv6_table_functional_traits_t {
        typedef npl_l2_lpts_ipv6_table_key_t key_type;
        typedef npl_l2_lpts_ipv6_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_L2_LPTS_IPV6_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l2_lpts_ipv6_table");
            return table_name;
        }
        static const size_t table_size = 32767;
        static bool key_match(const npl_l2_lpts_ipv6_table_key_t& lookup_key, const npl_l2_lpts_ipv6_table_key_t& table_key, const npl_l2_lpts_ipv6_table_key_t& table_mask);
    };
    
    struct npl_l2_lpts_mac_table_functional_traits_t {
        typedef npl_l2_lpts_mac_table_key_t key_type;
        typedef npl_l2_lpts_mac_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_L2_LPTS_MAC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l2_lpts_mac_table");
            return table_name;
        }
        static const size_t table_size = 32767;
        static bool key_match(const npl_l2_lpts_mac_table_key_t& lookup_key, const npl_l2_lpts_mac_table_key_t& table_key, const npl_l2_lpts_mac_table_key_t& table_mask);
    };
    
    struct npl_l2_lpts_next_macro_static_table_functional_traits_t {
        typedef npl_l2_lpts_next_macro_static_table_key_t key_type;
        typedef npl_l2_lpts_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_L2_LPTS_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l2_lpts_next_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 9;
        static bool key_match(const npl_l2_lpts_next_macro_static_table_key_t& lookup_key, const npl_l2_lpts_next_macro_static_table_key_t& table_key, const npl_l2_lpts_next_macro_static_table_key_t& table_mask);
    };
    
    struct npl_l2_lpts_protocol_table_functional_traits_t {
        typedef npl_l2_lpts_protocol_table_key_t key_type;
        typedef npl_l2_lpts_protocol_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_L2_LPTS_PROTOCOL_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l2_lpts_protocol_table");
            return table_name;
        }
        static const size_t table_size = 29;
        static bool key_match(const npl_l2_lpts_protocol_table_key_t& lookup_key, const npl_l2_lpts_protocol_table_key_t& table_key, const npl_l2_lpts_protocol_table_key_t& table_mask);
    };
    
    struct npl_l2_lpts_skip_p2p_static_table_functional_traits_t {
        typedef npl_l2_lpts_skip_p2p_static_table_key_t key_type;
        typedef npl_l2_lpts_skip_p2p_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_L2_LPTS_SKIP_P2P_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l2_lpts_skip_p2p_static_table");
            return table_name;
        }
    };
    
    struct npl_l2_termination_next_macro_static_table_functional_traits_t {
        typedef npl_l2_termination_next_macro_static_table_key_t key_type;
        typedef npl_l2_termination_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_L2_TERMINATION_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l2_termination_next_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 10;
        static bool key_match(const npl_l2_termination_next_macro_static_table_key_t& lookup_key, const npl_l2_termination_next_macro_static_table_key_t& table_key, const npl_l2_termination_next_macro_static_table_key_t& table_mask);
    };
    
    struct npl_l2_tunnel_term_next_macro_static_table_functional_traits_t {
        typedef npl_l2_tunnel_term_next_macro_static_table_key_t key_type;
        typedef npl_l2_tunnel_term_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_L2_TUNNEL_TERM_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l2_tunnel_term_next_macro_static_table");
            return table_name;
        }
    };
    
    struct npl_l3_dlp_p_counter_offset_table_functional_traits_t {
        typedef npl_l3_dlp_p_counter_offset_table_key_t key_type;
        typedef npl_l3_dlp_p_counter_offset_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_L3_DLP_P_COUNTER_OFFSET_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l3_dlp_p_counter_offset_table");
            return table_name;
        }
        static const size_t table_size = 20;
        static bool key_match(const npl_l3_dlp_p_counter_offset_table_key_t& lookup_key, const npl_l3_dlp_p_counter_offset_table_key_t& table_key, const npl_l3_dlp_p_counter_offset_table_key_t& table_mask);
    };
    
    struct npl_l3_dlp_table_functional_traits_t {
        typedef npl_l3_dlp_table_key_t key_type;
        typedef npl_l3_dlp_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_L3_DLP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l3_dlp_table");
            return table_name;
        }
    };
    
    struct npl_l3_termination_classify_ip_tunnels_table_functional_traits_t {
        typedef npl_l3_termination_classify_ip_tunnels_table_key_t key_type;
        typedef npl_l3_termination_classify_ip_tunnels_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_L3_TERMINATION_CLASSIFY_IP_TUNNELS_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l3_termination_classify_ip_tunnels_table");
            return table_name;
        }
        static const size_t table_size = 10;
        static bool key_match(const npl_l3_termination_classify_ip_tunnels_table_key_t& lookup_key, const npl_l3_termination_classify_ip_tunnels_table_key_t& table_key, const npl_l3_termination_classify_ip_tunnels_table_key_t& table_mask);
    };
    
    struct npl_l3_termination_next_macro_static_table_functional_traits_t {
        typedef npl_l3_termination_next_macro_static_table_key_t key_type;
        typedef npl_l3_termination_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_L3_TERMINATION_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l3_termination_next_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 14;
        static bool key_match(const npl_l3_termination_next_macro_static_table_key_t& lookup_key, const npl_l3_termination_next_macro_static_table_key_t& table_key, const npl_l3_termination_next_macro_static_table_key_t& table_mask);
    };
    
    struct npl_l3_tunnel_termination_next_macro_static_table_functional_traits_t {
        typedef npl_l3_tunnel_termination_next_macro_static_table_key_t key_type;
        typedef npl_l3_tunnel_termination_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_L3_TUNNEL_TERMINATION_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l3_tunnel_termination_next_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 12;
        static bool key_match(const npl_l3_tunnel_termination_next_macro_static_table_key_t& lookup_key, const npl_l3_tunnel_termination_next_macro_static_table_key_t& table_key, const npl_l3_tunnel_termination_next_macro_static_table_key_t& table_mask);
    };
    
    struct npl_l3_vxlan_overlay_sa_table_functional_traits_t {
        typedef npl_l3_vxlan_overlay_sa_table_key_t key_type;
        typedef npl_l3_vxlan_overlay_sa_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_L3_VXLAN_OVERLAY_SA_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("l3_vxlan_overlay_sa_table");
            return table_name;
        }
    };
    
    struct npl_large_encap_global_lsp_prefix_table_functional_traits_t {
        typedef npl_large_encap_global_lsp_prefix_table_key_t key_type;
        typedef npl_large_encap_global_lsp_prefix_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_LARGE_ENCAP_GLOBAL_LSP_PREFIX_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("large_encap_global_lsp_prefix_table");
            return table_name;
        }
    };
    
    struct npl_large_encap_ip_tunnel_table_functional_traits_t {
        typedef npl_large_encap_ip_tunnel_table_key_t key_type;
        typedef npl_large_encap_ip_tunnel_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_LARGE_ENCAP_IP_TUNNEL_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("large_encap_ip_tunnel_table");
            return table_name;
        }
    };
    
    struct npl_large_encap_mpls_he_no_ldp_table_functional_traits_t {
        typedef npl_large_encap_mpls_he_no_ldp_table_key_t key_type;
        typedef npl_large_encap_mpls_he_no_ldp_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_LARGE_ENCAP_MPLS_HE_NO_LDP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("large_encap_mpls_he_no_ldp_table");
            return table_name;
        }
    };
    
    struct npl_large_encap_mpls_ldp_over_te_table_functional_traits_t {
        typedef npl_large_encap_mpls_ldp_over_te_table_key_t key_type;
        typedef npl_large_encap_mpls_ldp_over_te_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_LARGE_ENCAP_MPLS_LDP_OVER_TE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("large_encap_mpls_ldp_over_te_table");
            return table_name;
        }
    };
    
    struct npl_large_encap_te_he_tunnel_id_table_functional_traits_t {
        typedef npl_large_encap_te_he_tunnel_id_table_key_t key_type;
        typedef npl_large_encap_te_he_tunnel_id_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_LARGE_ENCAP_TE_HE_TUNNEL_ID_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("large_encap_te_he_tunnel_id_table");
            return table_name;
        }
    };
    
    struct npl_latest_learn_records_table_functional_traits_t {
        typedef npl_latest_learn_records_table_key_t key_type;
        typedef npl_latest_learn_records_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LATEST_LEARN_RECORDS_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("latest_learn_records_table");
            return table_name;
        }
    };
    
    struct npl_learn_manager_cfg_max_learn_type_reg_functional_traits_t {
        typedef npl_learn_manager_cfg_max_learn_type_reg_key_t key_type;
        typedef npl_learn_manager_cfg_max_learn_type_reg_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LEARN_MANAGER_CFG_MAX_LEARN_TYPE_REG;
        static const std::string& get_table_name() {
            static const std::string table_name("learn_manager_cfg_max_learn_type_reg");
            return table_name;
        }
    };
    
    struct npl_learn_record_fifo_table_functional_traits_t {
        typedef npl_learn_record_fifo_table_key_t key_type;
        typedef npl_learn_record_fifo_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LEARN_RECORD_FIFO_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("learn_record_fifo_table");
            return table_name;
        }
    };
    
    struct npl_light_fi_fabric_table_functional_traits_t {
        typedef npl_light_fi_fabric_table_key_t key_type;
        typedef npl_light_fi_fabric_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LIGHT_FI_FABRIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("light_fi_fabric_table");
            return table_name;
        }
    };
    
    struct npl_light_fi_npu_base_table_functional_traits_t {
        typedef npl_light_fi_npu_base_table_key_t key_type;
        typedef npl_light_fi_npu_base_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LIGHT_FI_NPU_BASE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("light_fi_npu_base_table");
            return table_name;
        }
    };
    
    struct npl_light_fi_npu_encap_table_functional_traits_t {
        typedef npl_light_fi_npu_encap_table_key_t key_type;
        typedef npl_light_fi_npu_encap_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LIGHT_FI_NPU_ENCAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("light_fi_npu_encap_table");
            return table_name;
        }
    };
    
    struct npl_light_fi_nw_0_table_functional_traits_t {
        typedef npl_light_fi_nw_0_table_key_t key_type;
        typedef npl_light_fi_nw_0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_LIGHT_FI_NW_0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("light_fi_nw_0_table");
            return table_name;
        }
        static const size_t table_size = 16;
        static bool key_match(const npl_light_fi_nw_0_table_key_t& lookup_key, const npl_light_fi_nw_0_table_key_t& table_key, const npl_light_fi_nw_0_table_key_t& table_mask);
    };
    
    struct npl_light_fi_nw_1_table_functional_traits_t {
        typedef npl_light_fi_nw_1_table_key_t key_type;
        typedef npl_light_fi_nw_1_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_LIGHT_FI_NW_1_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("light_fi_nw_1_table");
            return table_name;
        }
        static const size_t table_size = 16;
        static bool key_match(const npl_light_fi_nw_1_table_key_t& lookup_key, const npl_light_fi_nw_1_table_key_t& table_key, const npl_light_fi_nw_1_table_key_t& table_mask);
    };
    
    struct npl_light_fi_nw_2_table_functional_traits_t {
        typedef npl_light_fi_nw_2_table_key_t key_type;
        typedef npl_light_fi_nw_2_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_LIGHT_FI_NW_2_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("light_fi_nw_2_table");
            return table_name;
        }
        static const size_t table_size = 16;
        static bool key_match(const npl_light_fi_nw_2_table_key_t& lookup_key, const npl_light_fi_nw_2_table_key_t& table_key, const npl_light_fi_nw_2_table_key_t& table_mask);
    };
    
    struct npl_light_fi_nw_3_table_functional_traits_t {
        typedef npl_light_fi_nw_3_table_key_t key_type;
        typedef npl_light_fi_nw_3_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_LIGHT_FI_NW_3_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("light_fi_nw_3_table");
            return table_name;
        }
        static const size_t table_size = 16;
        static bool key_match(const npl_light_fi_nw_3_table_key_t& lookup_key, const npl_light_fi_nw_3_table_key_t& table_key, const npl_light_fi_nw_3_table_key_t& table_mask);
    };
    
    struct npl_light_fi_stages_cfg_table_functional_traits_t {
        typedef npl_light_fi_stages_cfg_table_key_t key_type;
        typedef npl_light_fi_stages_cfg_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LIGHT_FI_STAGES_CFG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("light_fi_stages_cfg_table");
            return table_name;
        }
    };
    
    struct npl_light_fi_tm_table_functional_traits_t {
        typedef npl_light_fi_tm_table_key_t key_type;
        typedef npl_light_fi_tm_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LIGHT_FI_TM_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("light_fi_tm_table");
            return table_name;
        }
    };
    
    struct npl_link_relay_attributes_table_functional_traits_t {
        typedef npl_link_relay_attributes_table_key_t key_type;
        typedef npl_link_relay_attributes_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LINK_RELAY_ATTRIBUTES_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("link_relay_attributes_table");
            return table_name;
        }
    };
    
    struct npl_link_up_vector_functional_traits_t {
        typedef npl_link_up_vector_key_t key_type;
        typedef npl_link_up_vector_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LINK_UP_VECTOR;
        static const std::string& get_table_name() {
            static const std::string table_name("link_up_vector");
            return table_name;
        }
    };
    
    struct npl_lp_over_lag_table_functional_traits_t {
        typedef npl_lp_over_lag_table_key_t key_type;
        typedef npl_lp_over_lag_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_LP_OVER_LAG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("lp_over_lag_table");
            return table_name;
        }
    };
    
    struct npl_lpm_destination_prefix_map_table_functional_traits_t {
        typedef npl_lpm_destination_prefix_map_table_key_t key_type;
        typedef npl_lpm_destination_prefix_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LPM_DESTINATION_PREFIX_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("lpm_destination_prefix_map_table");
            return table_name;
        }
    };
    
    struct npl_lpts_2nd_lookup_table_functional_traits_t {
        typedef npl_lpts_2nd_lookup_table_key_t key_type;
        typedef npl_lpts_2nd_lookup_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LPTS_2ND_LOOKUP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("lpts_2nd_lookup_table");
            return table_name;
        }
    };
    
    struct npl_lpts_meter_table_functional_traits_t {
        typedef npl_lpts_meter_table_key_t key_type;
        typedef npl_lpts_meter_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LPTS_METER_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("lpts_meter_table");
            return table_name;
        }
    };
    
    struct npl_lpts_og_application_table_functional_traits_t {
        typedef npl_lpts_og_application_table_key_t key_type;
        typedef npl_lpts_og_application_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_LPTS_OG_APPLICATION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("lpts_og_application_table");
            return table_name;
        }
        static const size_t table_size = 31;
        static bool key_match(const npl_lpts_og_application_table_key_t& lookup_key, const npl_lpts_og_application_table_key_t& table_key, const npl_lpts_og_application_table_key_t& table_mask);
    };
    
    struct npl_lr_filter_write_ptr_reg_functional_traits_t {
        typedef npl_lr_filter_write_ptr_reg_key_t key_type;
        typedef npl_lr_filter_write_ptr_reg_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LR_FILTER_WRITE_PTR_REG;
        static const std::string& get_table_name() {
            static const std::string table_name("lr_filter_write_ptr_reg");
            return table_name;
        }
    };
    
    struct npl_lr_write_ptr_reg_functional_traits_t {
        typedef npl_lr_write_ptr_reg_key_t key_type;
        typedef npl_lr_write_ptr_reg_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_LR_WRITE_PTR_REG;
        static const std::string& get_table_name() {
            static const std::string table_name("lr_write_ptr_reg");
            return table_name;
        }
    };
    
    struct npl_mac_af_npp_attributes_table_functional_traits_t {
        typedef npl_mac_af_npp_attributes_table_key_t key_type;
        typedef npl_mac_af_npp_attributes_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MAC_AF_NPP_ATTRIBUTES_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mac_af_npp_attributes_table");
            return table_name;
        }
    };
    
    struct npl_mac_da_table_functional_traits_t {
        typedef npl_mac_da_table_key_t key_type;
        typedef npl_mac_da_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_MAC_DA_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mac_da_table");
            return table_name;
        }
        static const size_t table_size = 31;
        static bool key_match(const npl_mac_da_table_key_t& lookup_key, const npl_mac_da_table_key_t& table_key, const npl_mac_da_table_key_t& table_mask);
    };
    
    struct npl_mac_ethernet_rate_limit_type_static_table_functional_traits_t {
        typedef npl_mac_ethernet_rate_limit_type_static_table_key_t key_type;
        typedef npl_mac_ethernet_rate_limit_type_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_MAC_ETHERNET_RATE_LIMIT_TYPE_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mac_ethernet_rate_limit_type_static_table");
            return table_name;
        }
        static const size_t table_size = 5;
        static bool key_match(const npl_mac_ethernet_rate_limit_type_static_table_key_t& lookup_key, const npl_mac_ethernet_rate_limit_type_static_table_key_t& table_key, const npl_mac_ethernet_rate_limit_type_static_table_key_t& table_mask);
    };
    
    struct npl_mac_forwarding_table_functional_traits_t {
        typedef npl_mac_forwarding_table_key_t key_type;
        typedef npl_mac_forwarding_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_MAC_FORWARDING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mac_forwarding_table");
            return table_name;
        }
    };
    
    struct npl_mac_mc_em_termination_attributes_table_functional_traits_t {
        typedef npl_mac_mc_em_termination_attributes_table_key_t key_type;
        typedef npl_mac_mc_em_termination_attributes_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_MAC_MC_EM_TERMINATION_ATTRIBUTES_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mac_mc_em_termination_attributes_table");
            return table_name;
        }
    };
    
    struct npl_mac_mc_tcam_termination_attributes_table_functional_traits_t {
        typedef npl_mac_mc_tcam_termination_attributes_table_key_t key_type;
        typedef npl_mac_mc_tcam_termination_attributes_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_MAC_MC_TCAM_TERMINATION_ATTRIBUTES_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mac_mc_tcam_termination_attributes_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_mac_mc_tcam_termination_attributes_table_key_t& lookup_key, const npl_mac_mc_tcam_termination_attributes_table_key_t& table_key, const npl_mac_mc_tcam_termination_attributes_table_key_t& table_mask);
    };
    
    struct npl_mac_qos_mapping_table_functional_traits_t {
        typedef npl_mac_qos_mapping_table_key_t key_type;
        typedef npl_mac_qos_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MAC_QOS_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mac_qos_mapping_table");
            return table_name;
        }
    };
    
    struct npl_mac_relay_g_ipv4_table_functional_traits_t {
        typedef npl_mac_relay_g_ipv4_table_key_t key_type;
        typedef npl_mac_relay_g_ipv4_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_MAC_RELAY_G_IPV4_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mac_relay_g_ipv4_table");
            return table_name;
        }
    };
    
    struct npl_mac_relay_g_ipv6_table_functional_traits_t {
        typedef npl_mac_relay_g_ipv6_table_key_t key_type;
        typedef npl_mac_relay_g_ipv6_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_MAC_RELAY_G_IPV6_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mac_relay_g_ipv6_table");
            return table_name;
        }
    };
    
    struct npl_mac_relay_to_vni_table_functional_traits_t {
        typedef npl_mac_relay_to_vni_table_key_t key_type;
        typedef npl_mac_relay_to_vni_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_MAC_RELAY_TO_VNI_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mac_relay_to_vni_table");
            return table_name;
        }
    };
    
    struct npl_mac_termination_em_table_functional_traits_t {
        typedef npl_mac_termination_em_table_key_t key_type;
        typedef npl_mac_termination_em_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_MAC_TERMINATION_EM_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mac_termination_em_table");
            return table_name;
        }
    };
    
    struct npl_mac_termination_next_macro_static_table_functional_traits_t {
        typedef npl_mac_termination_next_macro_static_table_key_t key_type;
        typedef npl_mac_termination_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_MAC_TERMINATION_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mac_termination_next_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 7;
        static bool key_match(const npl_mac_termination_next_macro_static_table_key_t& lookup_key, const npl_mac_termination_next_macro_static_table_key_t& table_key, const npl_mac_termination_next_macro_static_table_key_t& table_mask);
    };
    
    struct npl_mac_termination_no_da_em_table_functional_traits_t {
        typedef npl_mac_termination_no_da_em_table_key_t key_type;
        typedef npl_mac_termination_no_da_em_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_MAC_TERMINATION_NO_DA_EM_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mac_termination_no_da_em_table");
            return table_name;
        }
    };
    
    struct npl_mac_termination_tcam_table_functional_traits_t {
        typedef npl_mac_termination_tcam_table_key_t key_type;
        typedef npl_mac_termination_tcam_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_MAC_TERMINATION_TCAM_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mac_termination_tcam_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_mac_termination_tcam_table_key_t& lookup_key, const npl_mac_termination_tcam_table_key_t& table_key, const npl_mac_termination_tcam_table_key_t& table_mask);
    };
    
    struct npl_map_ene_subcode_to8bit_static_table_functional_traits_t {
        typedef npl_map_ene_subcode_to8bit_static_table_key_t key_type;
        typedef npl_map_ene_subcode_to8bit_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MAP_ENE_SUBCODE_TO8BIT_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("map_ene_subcode_to8bit_static_table");
            return table_name;
        }
    };
    
    struct npl_map_inject_ccm_macro_static_table_functional_traits_t {
        typedef npl_map_inject_ccm_macro_static_table_key_t key_type;
        typedef npl_map_inject_ccm_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_MAP_INJECT_CCM_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("map_inject_ccm_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 3;
        static bool key_match(const npl_map_inject_ccm_macro_static_table_key_t& lookup_key, const npl_map_inject_ccm_macro_static_table_key_t& table_key, const npl_map_inject_ccm_macro_static_table_key_t& table_mask);
    };
    
    struct npl_map_more_labels_static_table_functional_traits_t {
        typedef npl_map_more_labels_static_table_key_t key_type;
        typedef npl_map_more_labels_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MAP_MORE_LABELS_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("map_more_labels_static_table");
            return table_name;
        }
    };
    
    struct npl_map_recyle_tx_to_rx_data_on_pd_static_table_functional_traits_t {
        typedef npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t key_type;
        typedef npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MAP_RECYLE_TX_TO_RX_DATA_ON_PD_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("map_recyle_tx_to_rx_data_on_pd_static_table");
            return table_name;
        }
    };
    
    struct npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_functional_traits_t {
        typedef npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t key_type;
        typedef npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MAP_TM_DP_ECN_TO_WA_ECN_DP_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("map_tm_dp_ecn_to_wa_ecn_dp_static_table");
            return table_name;
        }
    };
    
    struct npl_map_tx_punt_next_macro_static_table_functional_traits_t {
        typedef npl_map_tx_punt_next_macro_static_table_key_t key_type;
        typedef npl_map_tx_punt_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_MAP_TX_PUNT_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("map_tx_punt_next_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 19;
        static bool key_match(const npl_map_tx_punt_next_macro_static_table_key_t& lookup_key, const npl_map_tx_punt_next_macro_static_table_key_t& table_key, const npl_map_tx_punt_next_macro_static_table_key_t& table_mask);
    };
    
    struct npl_map_tx_punt_rcy_next_macro_static_table_functional_traits_t {
        typedef npl_map_tx_punt_rcy_next_macro_static_table_key_t key_type;
        typedef npl_map_tx_punt_rcy_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_MAP_TX_PUNT_RCY_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("map_tx_punt_rcy_next_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 3;
        static bool key_match(const npl_map_tx_punt_rcy_next_macro_static_table_key_t& lookup_key, const npl_map_tx_punt_rcy_next_macro_static_table_key_t& table_key, const npl_map_tx_punt_rcy_next_macro_static_table_key_t& table_mask);
    };
    
    struct npl_mc_bitmap_base_voq_lookup_table_functional_traits_t {
        typedef npl_mc_bitmap_base_voq_lookup_table_key_t key_type;
        typedef npl_mc_bitmap_base_voq_lookup_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MC_BITMAP_BASE_VOQ_LOOKUP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mc_bitmap_base_voq_lookup_table");
            return table_name;
        }
    };
    
    struct npl_mc_bitmap_tc_map_table_functional_traits_t {
        typedef npl_mc_bitmap_tc_map_table_key_t key_type;
        typedef npl_mc_bitmap_tc_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MC_BITMAP_TC_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mc_bitmap_tc_map_table");
            return table_name;
        }
    };
    
    struct npl_mc_copy_id_map_functional_traits_t {
        typedef npl_mc_copy_id_map_key_t key_type;
        typedef npl_mc_copy_id_map_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MC_COPY_ID_MAP;
        static const std::string& get_table_name() {
            static const std::string table_name("mc_copy_id_map");
            return table_name;
        }
    };
    
    struct npl_mc_cud_is_wide_table_functional_traits_t {
        typedef npl_mc_cud_is_wide_table_key_t key_type;
        typedef npl_mc_cud_is_wide_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MC_CUD_IS_WIDE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mc_cud_is_wide_table");
            return table_name;
        }
    };
    
    struct npl_mc_em_db_functional_traits_t {
        typedef npl_mc_em_db_key_t key_type;
        typedef npl_mc_em_db_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_MC_EM_DB;
        static const std::string& get_table_name() {
            static const std::string table_name("mc_em_db");
            return table_name;
        }
    };
    
    struct npl_mc_emdb_tc_map_table_functional_traits_t {
        typedef npl_mc_emdb_tc_map_table_key_t key_type;
        typedef npl_mc_emdb_tc_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MC_EMDB_TC_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mc_emdb_tc_map_table");
            return table_name;
        }
    };
    
    struct npl_mc_fe_links_bmp_functional_traits_t {
        typedef npl_mc_fe_links_bmp_key_t key_type;
        typedef npl_mc_fe_links_bmp_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MC_FE_LINKS_BMP;
        static const std::string& get_table_name() {
            static const std::string table_name("mc_fe_links_bmp");
            return table_name;
        }
    };
    
    struct npl_mc_ibm_cud_mapping_table_functional_traits_t {
        typedef npl_mc_ibm_cud_mapping_table_key_t key_type;
        typedef npl_mc_ibm_cud_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MC_IBM_CUD_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mc_ibm_cud_mapping_table");
            return table_name;
        }
    };
    
    struct npl_mc_slice_bitmap_table_functional_traits_t {
        typedef npl_mc_slice_bitmap_table_key_t key_type;
        typedef npl_mc_slice_bitmap_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MC_SLICE_BITMAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mc_slice_bitmap_table");
            return table_name;
        }
    };
    
    struct npl_meg_id_format_table_functional_traits_t {
        typedef npl_meg_id_format_table_key_t key_type;
        typedef npl_meg_id_format_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_MEG_ID_FORMAT_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("meg_id_format_table");
            return table_name;
        }
        static const size_t table_size = 1;
        static bool key_match(const npl_meg_id_format_table_key_t& lookup_key, const npl_meg_id_format_table_key_t& table_key, const npl_meg_id_format_table_key_t& table_mask);
    };
    
    struct npl_mep_address_prefix_table_functional_traits_t {
        typedef npl_mep_address_prefix_table_key_t key_type;
        typedef npl_mep_address_prefix_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MEP_ADDRESS_PREFIX_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mep_address_prefix_table");
            return table_name;
        }
    };
    
    struct npl_mii_loopback_table_functional_traits_t {
        typedef npl_mii_loopback_table_key_t key_type;
        typedef npl_mii_loopback_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MII_LOOPBACK_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mii_loopback_table");
            return table_name;
        }
    };
    
    struct npl_mirror_code_hw_table_functional_traits_t {
        typedef npl_mirror_code_hw_table_key_t key_type;
        typedef npl_mirror_code_hw_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MIRROR_CODE_HW_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mirror_code_hw_table");
            return table_name;
        }
    };
    
    struct npl_mirror_egress_attributes_table_functional_traits_t {
        typedef npl_mirror_egress_attributes_table_key_t key_type;
        typedef npl_mirror_egress_attributes_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MIRROR_EGRESS_ATTRIBUTES_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mirror_egress_attributes_table");
            return table_name;
        }
    };
    
    struct npl_mirror_to_dsp_in_npu_soft_header_table_functional_traits_t {
        typedef npl_mirror_to_dsp_in_npu_soft_header_table_key_t key_type;
        typedef npl_mirror_to_dsp_in_npu_soft_header_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MIRROR_TO_DSP_IN_NPU_SOFT_HEADER_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mirror_to_dsp_in_npu_soft_header_table");
            return table_name;
        }
    };
    
    struct npl_mldp_protection_enabled_static_table_functional_traits_t {
        typedef npl_mldp_protection_enabled_static_table_key_t key_type;
        typedef npl_mldp_protection_enabled_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_MLDP_PROTECTION_ENABLED_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mldp_protection_enabled_static_table");
            return table_name;
        }
        static const size_t table_size = 4;
        static bool key_match(const npl_mldp_protection_enabled_static_table_key_t& lookup_key, const npl_mldp_protection_enabled_static_table_key_t& table_key, const npl_mldp_protection_enabled_static_table_key_t& table_mask);
    };
    
    struct npl_mldp_protection_table_functional_traits_t {
        typedef npl_mldp_protection_table_key_t key_type;
        typedef npl_mldp_protection_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MLDP_PROTECTION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mldp_protection_table");
            return table_name;
        }
    };
    
    struct npl_mp_aux_data_table_functional_traits_t {
        typedef npl_mp_aux_data_table_key_t key_type;
        typedef npl_mp_aux_data_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MP_AUX_DATA_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mp_aux_data_table");
            return table_name;
        }
    };
    
    struct npl_mp_data_table_functional_traits_t {
        typedef npl_mp_data_table_key_t key_type;
        typedef npl_mp_data_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MP_DATA_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mp_data_table");
            return table_name;
        }
    };
    
    struct npl_mpls_encap_control_static_table_functional_traits_t {
        typedef npl_mpls_encap_control_static_table_key_t key_type;
        typedef npl_mpls_encap_control_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MPLS_ENCAP_CONTROL_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mpls_encap_control_static_table");
            return table_name;
        }
    };
    
    struct npl_mpls_forwarding_table_functional_traits_t {
        typedef npl_mpls_forwarding_table_key_t key_type;
        typedef npl_mpls_forwarding_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_MPLS_FORWARDING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mpls_forwarding_table");
            return table_name;
        }
    };
    
    struct npl_mpls_header_offset_in_bytes_static_table_functional_traits_t {
        typedef npl_mpls_header_offset_in_bytes_static_table_key_t key_type;
        typedef npl_mpls_header_offset_in_bytes_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MPLS_HEADER_OFFSET_IN_BYTES_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mpls_header_offset_in_bytes_static_table");
            return table_name;
        }
    };
    
    struct npl_mpls_l3_lsp_static_table_functional_traits_t {
        typedef npl_mpls_l3_lsp_static_table_key_t key_type;
        typedef npl_mpls_l3_lsp_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MPLS_L3_LSP_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mpls_l3_lsp_static_table");
            return table_name;
        }
    };
    
    struct npl_mpls_labels_1_to_4_jump_offset_static_table_functional_traits_t {
        typedef npl_mpls_labels_1_to_4_jump_offset_static_table_key_t key_type;
        typedef npl_mpls_labels_1_to_4_jump_offset_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MPLS_LABELS_1_TO_4_JUMP_OFFSET_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mpls_labels_1_to_4_jump_offset_static_table");
            return table_name;
        }
    };
    
    struct npl_mpls_lsp_labels_config_static_table_functional_traits_t {
        typedef npl_mpls_lsp_labels_config_static_table_key_t key_type;
        typedef npl_mpls_lsp_labels_config_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MPLS_LSP_LABELS_CONFIG_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mpls_lsp_labels_config_static_table");
            return table_name;
        }
    };
    
    struct npl_mpls_qos_mapping_table_functional_traits_t {
        typedef npl_mpls_qos_mapping_table_key_t key_type;
        typedef npl_mpls_qos_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MPLS_QOS_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mpls_qos_mapping_table");
            return table_name;
        }
    };
    
    struct npl_mpls_resolve_service_labels_static_table_functional_traits_t {
        typedef npl_mpls_resolve_service_labels_static_table_key_t key_type;
        typedef npl_mpls_resolve_service_labels_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_MPLS_RESOLVE_SERVICE_LABELS_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mpls_resolve_service_labels_static_table");
            return table_name;
        }
        static const size_t table_size = 8;
        static bool key_match(const npl_mpls_resolve_service_labels_static_table_key_t& lookup_key, const npl_mpls_resolve_service_labels_static_table_key_t& table_key, const npl_mpls_resolve_service_labels_static_table_key_t& table_mask);
    };
    
    struct npl_mpls_termination_em0_table_functional_traits_t {
        typedef npl_mpls_termination_em0_table_key_t key_type;
        typedef npl_mpls_termination_em0_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_MPLS_TERMINATION_EM0_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mpls_termination_em0_table");
            return table_name;
        }
    };
    
    struct npl_mpls_termination_em1_table_functional_traits_t {
        typedef npl_mpls_termination_em1_table_key_t key_type;
        typedef npl_mpls_termination_em1_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_MPLS_TERMINATION_EM1_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mpls_termination_em1_table");
            return table_name;
        }
    };
    
    struct npl_mpls_vpn_enabled_static_table_functional_traits_t {
        typedef npl_mpls_vpn_enabled_static_table_key_t key_type;
        typedef npl_mpls_vpn_enabled_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_MPLS_VPN_ENABLED_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("mpls_vpn_enabled_static_table");
            return table_name;
        }
        static const size_t table_size = 6;
        static bool key_match(const npl_mpls_vpn_enabled_static_table_key_t& lookup_key, const npl_mpls_vpn_enabled_static_table_key_t& table_key, const npl_mpls_vpn_enabled_static_table_key_t& table_mask);
    };
    
    struct npl_ms_voq_fabric_context_offset_table_functional_traits_t {
        typedef npl_ms_voq_fabric_context_offset_table_key_t key_type;
        typedef npl_ms_voq_fabric_context_offset_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_MS_VOQ_FABRIC_CONTEXT_OFFSET_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ms_voq_fabric_context_offset_table");
            return table_name;
        }
    };
    
    struct npl_my_ipv4_table_functional_traits_t {
        typedef npl_my_ipv4_table_key_t key_type;
        typedef npl_my_ipv4_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_MY_IPV4_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("my_ipv4_table");
            return table_name;
        }
        static const size_t table_size = 64;
        static bool key_match(const npl_my_ipv4_table_key_t& lookup_key, const npl_my_ipv4_table_key_t& table_key, const npl_my_ipv4_table_key_t& table_mask);
    };
    
    struct npl_native_ce_ptr_table_functional_traits_t {
        typedef npl_native_ce_ptr_table_key_t key_type;
        typedef npl_native_ce_ptr_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NATIVE_CE_PTR_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("native_ce_ptr_table");
            return table_name;
        }
    };
    
    struct npl_native_fec_table_functional_traits_t {
        typedef npl_native_fec_table_key_t key_type;
        typedef npl_native_fec_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NATIVE_FEC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("native_fec_table");
            return table_name;
        }
    };
    
    struct npl_native_fec_type_decoding_table_functional_traits_t {
        typedef npl_native_fec_type_decoding_table_key_t key_type;
        typedef npl_native_fec_type_decoding_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NATIVE_FEC_TYPE_DECODING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("native_fec_type_decoding_table");
            return table_name;
        }
    };
    
    struct npl_native_frr_table_functional_traits_t {
        typedef npl_native_frr_table_key_t key_type;
        typedef npl_native_frr_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NATIVE_FRR_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("native_frr_table");
            return table_name;
        }
    };
    
    struct npl_native_frr_type_decoding_table_functional_traits_t {
        typedef npl_native_frr_type_decoding_table_key_t key_type;
        typedef npl_native_frr_type_decoding_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NATIVE_FRR_TYPE_DECODING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("native_frr_type_decoding_table");
            return table_name;
        }
    };
    
    struct npl_native_l2_lp_table_functional_traits_t {
        typedef npl_native_l2_lp_table_key_t key_type;
        typedef npl_native_l2_lp_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NATIVE_L2_LP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("native_l2_lp_table");
            return table_name;
        }
    };
    
    struct npl_native_l2_lp_type_decoding_table_functional_traits_t {
        typedef npl_native_l2_lp_type_decoding_table_key_t key_type;
        typedef npl_native_l2_lp_type_decoding_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NATIVE_L2_LP_TYPE_DECODING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("native_l2_lp_type_decoding_table");
            return table_name;
        }
    };
    
    struct npl_native_lb_group_size_table_functional_traits_t {
        typedef npl_native_lb_group_size_table_key_t key_type;
        typedef npl_native_lb_group_size_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NATIVE_LB_GROUP_SIZE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("native_lb_group_size_table");
            return table_name;
        }
    };
    
    struct npl_native_lb_table_functional_traits_t {
        typedef npl_native_lb_table_key_t key_type;
        typedef npl_native_lb_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_NATIVE_LB_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("native_lb_table");
            return table_name;
        }
    };
    
    struct npl_native_lb_type_decoding_table_functional_traits_t {
        typedef npl_native_lb_type_decoding_table_key_t key_type;
        typedef npl_native_lb_type_decoding_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NATIVE_LB_TYPE_DECODING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("native_lb_type_decoding_table");
            return table_name;
        }
    };
    
    struct npl_native_lp_is_pbts_prefix_table_functional_traits_t {
        typedef npl_native_lp_is_pbts_prefix_table_key_t key_type;
        typedef npl_native_lp_is_pbts_prefix_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NATIVE_LP_IS_PBTS_PREFIX_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("native_lp_is_pbts_prefix_table");
            return table_name;
        }
    };
    
    struct npl_native_lp_pbts_map_table_functional_traits_t {
        typedef npl_native_lp_pbts_map_table_key_t key_type;
        typedef npl_native_lp_pbts_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NATIVE_LP_PBTS_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("native_lp_pbts_map_table");
            return table_name;
        }
    };
    
    struct npl_native_protection_table_functional_traits_t {
        typedef npl_native_protection_table_key_t key_type;
        typedef npl_native_protection_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NATIVE_PROTECTION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("native_protection_table");
            return table_name;
        }
    };
    
    struct npl_next_header_1_is_l4_over_ipv4_static_table_functional_traits_t {
        typedef npl_next_header_1_is_l4_over_ipv4_static_table_key_t key_type;
        typedef npl_next_header_1_is_l4_over_ipv4_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NEXT_HEADER_1_IS_L4_OVER_IPV4_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("next_header_1_is_l4_over_ipv4_static_table");
            return table_name;
        }
    };
    
    struct npl_nh_macro_code_to_id_l6_static_table_functional_traits_t {
        typedef npl_nh_macro_code_to_id_l6_static_table_key_t key_type;
        typedef npl_nh_macro_code_to_id_l6_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NH_MACRO_CODE_TO_ID_L6_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("nh_macro_code_to_id_l6_static_table");
            return table_name;
        }
    };
    
    struct npl_nhlfe_type_mapping_static_table_functional_traits_t {
        typedef npl_nhlfe_type_mapping_static_table_key_t key_type;
        typedef npl_nhlfe_type_mapping_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NHLFE_TYPE_MAPPING_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("nhlfe_type_mapping_static_table");
            return table_name;
        }
    };
    
    struct npl_null_rtf_next_macro_static_table_functional_traits_t {
        typedef npl_null_rtf_next_macro_static_table_key_t key_type;
        typedef npl_null_rtf_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_NULL_RTF_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("null_rtf_next_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 9;
        static bool key_match(const npl_null_rtf_next_macro_static_table_key_t& lookup_key, const npl_null_rtf_next_macro_static_table_key_t& table_key, const npl_null_rtf_next_macro_static_table_key_t& table_mask);
    };
    
    struct npl_nw_smcid_threshold_table_functional_traits_t {
        typedef npl_nw_smcid_threshold_table_key_t key_type;
        typedef npl_nw_smcid_threshold_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_NW_SMCID_THRESHOLD_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("nw_smcid_threshold_table");
            return table_name;
        }
    };
    
    struct npl_oamp_drop_destination_static_table_functional_traits_t {
        typedef npl_oamp_drop_destination_static_table_key_t key_type;
        typedef npl_oamp_drop_destination_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_OAMP_DROP_DESTINATION_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("oamp_drop_destination_static_table");
            return table_name;
        }
    };
    
    struct npl_oamp_event_queue_table_functional_traits_t {
        typedef npl_oamp_event_queue_table_key_t key_type;
        typedef npl_oamp_event_queue_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_OAMP_EVENT_QUEUE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("oamp_event_queue_table");
            return table_name;
        }
    };
    
    struct npl_oamp_redirect_get_counter_table_functional_traits_t {
        typedef npl_oamp_redirect_get_counter_table_key_t key_type;
        typedef npl_oamp_redirect_get_counter_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_OAMP_REDIRECT_GET_COUNTER_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("oamp_redirect_get_counter_table");
            return table_name;
        }
    };
    
    struct npl_oamp_redirect_punt_eth_hdr_1_table_functional_traits_t {
        typedef npl_oamp_redirect_punt_eth_hdr_1_table_key_t key_type;
        typedef npl_oamp_redirect_punt_eth_hdr_1_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_OAMP_REDIRECT_PUNT_ETH_HDR_1_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("oamp_redirect_punt_eth_hdr_1_table");
            return table_name;
        }
    };
    
    struct npl_oamp_redirect_punt_eth_hdr_2_table_functional_traits_t {
        typedef npl_oamp_redirect_punt_eth_hdr_2_table_key_t key_type;
        typedef npl_oamp_redirect_punt_eth_hdr_2_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_OAMP_REDIRECT_PUNT_ETH_HDR_2_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("oamp_redirect_punt_eth_hdr_2_table");
            return table_name;
        }
    };
    
    struct npl_oamp_redirect_punt_eth_hdr_3_table_functional_traits_t {
        typedef npl_oamp_redirect_punt_eth_hdr_3_table_key_t key_type;
        typedef npl_oamp_redirect_punt_eth_hdr_3_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_OAMP_REDIRECT_PUNT_ETH_HDR_3_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("oamp_redirect_punt_eth_hdr_3_table");
            return table_name;
        }
    };
    
    struct npl_oamp_redirect_punt_eth_hdr_4_table_functional_traits_t {
        typedef npl_oamp_redirect_punt_eth_hdr_4_table_key_t key_type;
        typedef npl_oamp_redirect_punt_eth_hdr_4_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_OAMP_REDIRECT_PUNT_ETH_HDR_4_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("oamp_redirect_punt_eth_hdr_4_table");
            return table_name;
        }
    };
    
    struct npl_oamp_redirect_table_functional_traits_t {
        typedef npl_oamp_redirect_table_key_t key_type;
        typedef npl_oamp_redirect_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_OAMP_REDIRECT_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("oamp_redirect_table");
            return table_name;
        }
    };
    
    struct npl_obm_next_macro_static_table_functional_traits_t {
        typedef npl_obm_next_macro_static_table_key_t key_type;
        typedef npl_obm_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_OBM_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("obm_next_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 3;
        static bool key_match(const npl_obm_next_macro_static_table_key_t& lookup_key, const npl_obm_next_macro_static_table_key_t& table_key, const npl_obm_next_macro_static_table_key_t& table_mask);
    };
    
    struct npl_og_next_macro_static_table_functional_traits_t {
        typedef npl_og_next_macro_static_table_key_t key_type;
        typedef npl_og_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_OG_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("og_next_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 2;
        static bool key_match(const npl_og_next_macro_static_table_key_t& lookup_key, const npl_og_next_macro_static_table_key_t& table_key, const npl_og_next_macro_static_table_key_t& table_mask);
    };
    
    struct npl_outer_tpid_table_functional_traits_t {
        typedef npl_outer_tpid_table_key_t key_type;
        typedef npl_outer_tpid_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_OUTER_TPID_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("outer_tpid_table");
            return table_name;
        }
    };
    
    struct npl_overlay_ipv4_sip_table_functional_traits_t {
        typedef npl_overlay_ipv4_sip_table_key_t key_type;
        typedef npl_overlay_ipv4_sip_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_OVERLAY_IPV4_SIP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("overlay_ipv4_sip_table");
            return table_name;
        }
    };
    
    struct npl_pad_mtu_inj_check_static_table_functional_traits_t {
        typedef npl_pad_mtu_inj_check_static_table_key_t key_type;
        typedef npl_pad_mtu_inj_check_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_PAD_MTU_INJ_CHECK_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pad_mtu_inj_check_static_table");
            return table_name;
        }
        static const size_t table_size = 7;
        static bool key_match(const npl_pad_mtu_inj_check_static_table_key_t& lookup_key, const npl_pad_mtu_inj_check_static_table_key_t& table_key, const npl_pad_mtu_inj_check_static_table_key_t& table_mask);
    };
    
    struct npl_path_lb_type_decoding_table_functional_traits_t {
        typedef npl_path_lb_type_decoding_table_key_t key_type;
        typedef npl_path_lb_type_decoding_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PATH_LB_TYPE_DECODING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("path_lb_type_decoding_table");
            return table_name;
        }
    };
    
    struct npl_path_lp_is_pbts_prefix_table_functional_traits_t {
        typedef npl_path_lp_is_pbts_prefix_table_key_t key_type;
        typedef npl_path_lp_is_pbts_prefix_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PATH_LP_IS_PBTS_PREFIX_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("path_lp_is_pbts_prefix_table");
            return table_name;
        }
    };
    
    struct npl_path_lp_pbts_map_table_functional_traits_t {
        typedef npl_path_lp_pbts_map_table_key_t key_type;
        typedef npl_path_lp_pbts_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PATH_LP_PBTS_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("path_lp_pbts_map_table");
            return table_name;
        }
    };
    
    struct npl_path_lp_table_functional_traits_t {
        typedef npl_path_lp_table_key_t key_type;
        typedef npl_path_lp_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PATH_LP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("path_lp_table");
            return table_name;
        }
    };
    
    struct npl_path_lp_type_decoding_table_functional_traits_t {
        typedef npl_path_lp_type_decoding_table_key_t key_type;
        typedef npl_path_lp_type_decoding_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PATH_LP_TYPE_DECODING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("path_lp_type_decoding_table");
            return table_name;
        }
    };
    
    struct npl_path_protection_table_functional_traits_t {
        typedef npl_path_protection_table_key_t key_type;
        typedef npl_path_protection_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PATH_PROTECTION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("path_protection_table");
            return table_name;
        }
    };
    
    struct npl_pdoq_oq_ifc_mapping_functional_traits_t {
        typedef npl_pdoq_oq_ifc_mapping_key_t key_type;
        typedef npl_pdoq_oq_ifc_mapping_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PDOQ_OQ_IFC_MAPPING;
        static const std::string& get_table_name() {
            static const std::string table_name("pdoq_oq_ifc_mapping");
            return table_name;
        }
    };
    
    struct npl_pdvoq_bank_pair_offset_table_functional_traits_t {
        typedef npl_pdvoq_bank_pair_offset_table_key_t key_type;
        typedef npl_pdvoq_bank_pair_offset_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PDVOQ_BANK_PAIR_OFFSET_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pdvoq_bank_pair_offset_table");
            return table_name;
        }
    };
    
    struct npl_pdvoq_slice_voq_properties_table_functional_traits_t {
        typedef npl_pdvoq_slice_voq_properties_table_key_t key_type;
        typedef npl_pdvoq_slice_voq_properties_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PDVOQ_SLICE_VOQ_PROPERTIES_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pdvoq_slice_voq_properties_table");
            return table_name;
        }
    };
    
    struct npl_per_asbr_and_dpe_table_functional_traits_t {
        typedef npl_per_asbr_and_dpe_table_key_t key_type;
        typedef npl_per_asbr_and_dpe_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_PER_ASBR_AND_DPE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("per_asbr_and_dpe_table");
            return table_name;
        }
    };
    
    struct npl_per_pe_and_prefix_vpn_key_large_table_functional_traits_t {
        typedef npl_per_pe_and_prefix_vpn_key_large_table_key_t key_type;
        typedef npl_per_pe_and_prefix_vpn_key_large_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_PER_PE_AND_PREFIX_VPN_KEY_LARGE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("per_pe_and_prefix_vpn_key_large_table");
            return table_name;
        }
    };
    
    struct npl_per_pe_and_vrf_vpn_key_large_table_functional_traits_t {
        typedef npl_per_pe_and_vrf_vpn_key_large_table_key_t key_type;
        typedef npl_per_pe_and_vrf_vpn_key_large_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_PER_PE_AND_VRF_VPN_KEY_LARGE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("per_pe_and_vrf_vpn_key_large_table");
            return table_name;
        }
    };
    
    struct npl_per_port_destination_table_functional_traits_t {
        typedef npl_per_port_destination_table_key_t key_type;
        typedef npl_per_port_destination_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PER_PORT_DESTINATION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("per_port_destination_table");
            return table_name;
        }
    };
    
    struct npl_per_vrf_mpls_forwarding_table_functional_traits_t {
        typedef npl_per_vrf_mpls_forwarding_table_key_t key_type;
        typedef npl_per_vrf_mpls_forwarding_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_PER_VRF_MPLS_FORWARDING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("per_vrf_mpls_forwarding_table");
            return table_name;
        }
    };
    
    struct npl_pfc_destination_table_functional_traits_t {
        typedef npl_pfc_destination_table_key_t key_type;
        typedef npl_pfc_destination_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_PFC_DESTINATION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pfc_destination_table");
            return table_name;
        }
    };
    
    struct npl_pfc_event_queue_table_functional_traits_t {
        typedef npl_pfc_event_queue_table_key_t key_type;
        typedef npl_pfc_event_queue_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PFC_EVENT_QUEUE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pfc_event_queue_table");
            return table_name;
        }
    };
    
    struct npl_pfc_filter_wd_table_functional_traits_t {
        typedef npl_pfc_filter_wd_table_key_t key_type;
        typedef npl_pfc_filter_wd_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_PFC_FILTER_WD_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pfc_filter_wd_table");
            return table_name;
        }
        static const size_t table_size = 16;
        static bool key_match(const npl_pfc_filter_wd_table_key_t& lookup_key, const npl_pfc_filter_wd_table_key_t& table_key, const npl_pfc_filter_wd_table_key_t& table_mask);
    };
    
    struct npl_pfc_offset_from_vector_static_table_functional_traits_t {
        typedef npl_pfc_offset_from_vector_static_table_key_t key_type;
        typedef npl_pfc_offset_from_vector_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_PFC_OFFSET_FROM_VECTOR_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pfc_offset_from_vector_static_table");
            return table_name;
        }
        static const size_t table_size = 9;
        static bool key_match(const npl_pfc_offset_from_vector_static_table_key_t& lookup_key, const npl_pfc_offset_from_vector_static_table_key_t& table_key, const npl_pfc_offset_from_vector_static_table_key_t& table_mask);
    };
    
    struct npl_pfc_ssp_slice_map_table_functional_traits_t {
        typedef npl_pfc_ssp_slice_map_table_key_t key_type;
        typedef npl_pfc_ssp_slice_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_PFC_SSP_SLICE_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pfc_ssp_slice_map_table");
            return table_name;
        }
        static const size_t table_size = 36;
        static bool key_match(const npl_pfc_ssp_slice_map_table_key_t& lookup_key, const npl_pfc_ssp_slice_map_table_key_t& table_key, const npl_pfc_ssp_slice_map_table_key_t& table_mask);
    };
    
    struct npl_pfc_tc_latency_table_functional_traits_t {
        typedef npl_pfc_tc_latency_table_key_t key_type;
        typedef npl_pfc_tc_latency_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_PFC_TC_LATENCY_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pfc_tc_latency_table");
            return table_name;
        }
        static const size_t table_size = 8;
        static bool key_match(const npl_pfc_tc_latency_table_key_t& lookup_key, const npl_pfc_tc_latency_table_key_t& table_key, const npl_pfc_tc_latency_table_key_t& table_mask);
    };
    
    struct npl_pfc_tc_table_functional_traits_t {
        typedef npl_pfc_tc_table_key_t key_type;
        typedef npl_pfc_tc_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PFC_TC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pfc_tc_table");
            return table_name;
        }
    };
    
    struct npl_pfc_tc_wrap_latency_table_functional_traits_t {
        typedef npl_pfc_tc_wrap_latency_table_key_t key_type;
        typedef npl_pfc_tc_wrap_latency_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_PFC_TC_WRAP_LATENCY_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pfc_tc_wrap_latency_table");
            return table_name;
        }
        static const size_t table_size = 8;
        static bool key_match(const npl_pfc_tc_wrap_latency_table_key_t& lookup_key, const npl_pfc_tc_wrap_latency_table_key_t& table_key, const npl_pfc_tc_wrap_latency_table_key_t& table_mask);
    };
    
    struct npl_pfc_vector_static_table_functional_traits_t {
        typedef npl_pfc_vector_static_table_key_t key_type;
        typedef npl_pfc_vector_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PFC_VECTOR_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pfc_vector_static_table");
            return table_name;
        }
    };
    
    struct npl_pin_start_offset_macros_functional_traits_t {
        typedef npl_pin_start_offset_macros_key_t key_type;
        typedef npl_pin_start_offset_macros_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PIN_START_OFFSET_MACROS;
        static const std::string& get_table_name() {
            static const std::string table_name("pin_start_offset_macros");
            return table_name;
        }
    };
    
    struct npl_pma_loopback_table_functional_traits_t {
        typedef npl_pma_loopback_table_key_t key_type;
        typedef npl_pma_loopback_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PMA_LOOPBACK_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pma_loopback_table");
            return table_name;
        }
    };
    
    struct npl_port_dspa_group_size_table_functional_traits_t {
        typedef npl_port_dspa_group_size_table_key_t key_type;
        typedef npl_port_dspa_group_size_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PORT_DSPA_GROUP_SIZE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("port_dspa_group_size_table");
            return table_name;
        }
    };
    
    struct npl_port_dspa_table_functional_traits_t {
        typedef npl_port_dspa_table_key_t key_type;
        typedef npl_port_dspa_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_PORT_DSPA_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("port_dspa_table");
            return table_name;
        }
    };
    
    struct npl_port_dspa_type_decoding_table_functional_traits_t {
        typedef npl_port_dspa_type_decoding_table_key_t key_type;
        typedef npl_port_dspa_type_decoding_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PORT_DSPA_TYPE_DECODING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("port_dspa_type_decoding_table");
            return table_name;
        }
    };
    
    struct npl_port_npp_protection_table_functional_traits_t {
        typedef npl_port_npp_protection_table_key_t key_type;
        typedef npl_port_npp_protection_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PORT_NPP_PROTECTION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("port_npp_protection_table");
            return table_name;
        }
    };
    
    struct npl_port_npp_protection_type_decoding_table_functional_traits_t {
        typedef npl_port_npp_protection_type_decoding_table_key_t key_type;
        typedef npl_port_npp_protection_type_decoding_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PORT_NPP_PROTECTION_TYPE_DECODING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("port_npp_protection_type_decoding_table");
            return table_name;
        }
    };
    
    struct npl_port_protection_table_functional_traits_t {
        typedef npl_port_protection_table_key_t key_type;
        typedef npl_port_protection_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PORT_PROTECTION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("port_protection_table");
            return table_name;
        }
    };
    
    struct npl_punt_ethertype_static_table_functional_traits_t {
        typedef npl_punt_ethertype_static_table_key_t key_type;
        typedef npl_punt_ethertype_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_PUNT_ETHERTYPE_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("punt_ethertype_static_table");
            return table_name;
        }
        static const size_t table_size = 4;
        static bool key_match(const npl_punt_ethertype_static_table_key_t& lookup_key, const npl_punt_ethertype_static_table_key_t& table_key, const npl_punt_ethertype_static_table_key_t& table_mask);
    };
    
    struct npl_punt_rcy_inject_header_ene_encap_table_functional_traits_t {
        typedef npl_punt_rcy_inject_header_ene_encap_table_key_t key_type;
        typedef npl_punt_rcy_inject_header_ene_encap_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PUNT_RCY_INJECT_HEADER_ENE_ENCAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("punt_rcy_inject_header_ene_encap_table");
            return table_name;
        }
    };
    
    struct npl_punt_select_nw_ene_static_table_functional_traits_t {
        typedef npl_punt_select_nw_ene_static_table_key_t key_type;
        typedef npl_punt_select_nw_ene_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PUNT_SELECT_NW_ENE_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("punt_select_nw_ene_static_table");
            return table_name;
        }
    };
    
    struct npl_punt_tunnel_transport_encap_table_functional_traits_t {
        typedef npl_punt_tunnel_transport_encap_table_key_t key_type;
        typedef npl_punt_tunnel_transport_encap_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_PUNT_TUNNEL_TRANSPORT_ENCAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("punt_tunnel_transport_encap_table");
            return table_name;
        }
    };
    
    struct npl_punt_tunnel_transport_extended_encap_table_functional_traits_t {
        typedef npl_punt_tunnel_transport_extended_encap_table_key_t key_type;
        typedef npl_punt_tunnel_transport_extended_encap_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_PUNT_TUNNEL_TRANSPORT_EXTENDED_ENCAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("punt_tunnel_transport_extended_encap_table");
            return table_name;
        }
    };
    
    struct npl_punt_tunnel_transport_extended_encap_table2_functional_traits_t {
        typedef npl_punt_tunnel_transport_extended_encap_table2_key_t key_type;
        typedef npl_punt_tunnel_transport_extended_encap_table2_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_PUNT_TUNNEL_TRANSPORT_EXTENDED_ENCAP_TABLE2;
        static const std::string& get_table_name() {
            static const std::string table_name("punt_tunnel_transport_extended_encap_table2");
            return table_name;
        }
    };
    
    struct npl_pwe_label_table_functional_traits_t {
        typedef npl_pwe_label_table_key_t key_type;
        typedef npl_pwe_label_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_PWE_LABEL_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pwe_label_table");
            return table_name;
        }
    };
    
    struct npl_pwe_to_l3_dest_table_functional_traits_t {
        typedef npl_pwe_to_l3_dest_table_key_t key_type;
        typedef npl_pwe_to_l3_dest_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_PWE_TO_L3_DEST_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pwe_to_l3_dest_table");
            return table_name;
        }
    };
    
    struct npl_pwe_vpls_label_table_functional_traits_t {
        typedef npl_pwe_vpls_label_table_key_t key_type;
        typedef npl_pwe_vpls_label_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_PWE_VPLS_LABEL_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pwe_vpls_label_table");
            return table_name;
        }
    };
    
    struct npl_pwe_vpls_tunnel_label_table_functional_traits_t {
        typedef npl_pwe_vpls_tunnel_label_table_key_t key_type;
        typedef npl_pwe_vpls_tunnel_label_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_PWE_VPLS_TUNNEL_LABEL_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("pwe_vpls_tunnel_label_table");
            return table_name;
        }
    };
    
    struct npl_reassembly_source_port_map_table_functional_traits_t {
        typedef npl_reassembly_source_port_map_table_key_t key_type;
        typedef npl_reassembly_source_port_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_REASSEMBLY_SOURCE_PORT_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("reassembly_source_port_map_table");
            return table_name;
        }
    };
    
    struct npl_recycle_override_table_functional_traits_t {
        typedef npl_recycle_override_table_key_t key_type;
        typedef npl_recycle_override_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RECYCLE_OVERRIDE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("recycle_override_table");
            return table_name;
        }
    };
    
    struct npl_recycled_inject_up_info_table_functional_traits_t {
        typedef npl_recycled_inject_up_info_table_key_t key_type;
        typedef npl_recycled_inject_up_info_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RECYCLED_INJECT_UP_INFO_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("recycled_inject_up_info_table");
            return table_name;
        }
    };
    
    struct npl_redirect_destination_table_functional_traits_t {
        typedef npl_redirect_destination_table_key_t key_type;
        typedef npl_redirect_destination_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_REDIRECT_DESTINATION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("redirect_destination_table");
            return table_name;
        }
    };
    
    struct npl_redirect_table_functional_traits_t {
        typedef npl_redirect_table_key_t key_type;
        typedef npl_redirect_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_REDIRECT_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("redirect_table");
            return table_name;
        }
        static const size_t table_size = 256;
        static bool key_match(const npl_redirect_table_key_t& lookup_key, const npl_redirect_table_key_t& table_key, const npl_redirect_table_key_t& table_mask);
    };
    
    struct npl_resolution_pfc_select_table_functional_traits_t {
        typedef npl_resolution_pfc_select_table_key_t key_type;
        typedef npl_resolution_pfc_select_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_RESOLUTION_PFC_SELECT_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("resolution_pfc_select_table");
            return table_name;
        }
        static const size_t table_size = 7;
        static bool key_match(const npl_resolution_pfc_select_table_key_t& lookup_key, const npl_resolution_pfc_select_table_key_t& table_key, const npl_resolution_pfc_select_table_key_t& table_mask);
    };
    
    struct npl_resolution_set_next_macro_table_functional_traits_t {
        typedef npl_resolution_set_next_macro_table_key_t key_type;
        typedef npl_resolution_set_next_macro_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RESOLUTION_SET_NEXT_MACRO_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("resolution_set_next_macro_table");
            return table_name;
        }
    };
    
    struct npl_rewrite_sa_prefix_index_table_functional_traits_t {
        typedef npl_rewrite_sa_prefix_index_table_key_t key_type;
        typedef npl_rewrite_sa_prefix_index_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_REWRITE_SA_PREFIX_INDEX_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rewrite_sa_prefix_index_table");
            return table_name;
        }
    };
    
    struct npl_rmep_last_time_table_functional_traits_t {
        typedef npl_rmep_last_time_table_key_t key_type;
        typedef npl_rmep_last_time_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RMEP_LAST_TIME_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rmep_last_time_table");
            return table_name;
        }
    };
    
    struct npl_rmep_state_table_functional_traits_t {
        typedef npl_rmep_state_table_key_t key_type;
        typedef npl_rmep_state_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RMEP_STATE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rmep_state_table");
            return table_name;
        }
    };
    
    struct npl_rpf_fec_access_map_table_functional_traits_t {
        typedef npl_rpf_fec_access_map_table_key_t key_type;
        typedef npl_rpf_fec_access_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RPF_FEC_ACCESS_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rpf_fec_access_map_table");
            return table_name;
        }
    };
    
    struct npl_rpf_fec_table_functional_traits_t {
        typedef npl_rpf_fec_table_key_t key_type;
        typedef npl_rpf_fec_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RPF_FEC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rpf_fec_table");
            return table_name;
        }
    };
    
    struct npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_functional_traits_t {
        typedef npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t key_type;
        typedef npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RTF_CONF_SET_TO_OG_PCL_COMPRESS_BITS_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rtf_conf_set_to_og_pcl_compress_bits_mapping_table");
            return table_name;
        }
    };
    
    struct npl_rtf_conf_set_to_og_pcl_ids_mapping_table_functional_traits_t {
        typedef npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t key_type;
        typedef npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RTF_CONF_SET_TO_OG_PCL_IDS_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rtf_conf_set_to_og_pcl_ids_mapping_table");
            return table_name;
        }
    };
    
    struct npl_rtf_conf_set_to_post_fwd_stage_mapping_table_functional_traits_t {
        typedef npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t key_type;
        typedef npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RTF_CONF_SET_TO_POST_FWD_STAGE_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rtf_conf_set_to_post_fwd_stage_mapping_table");
            return table_name;
        }
    };
    
    struct npl_rtf_next_macro_static_table_functional_traits_t {
        typedef npl_rtf_next_macro_static_table_key_t key_type;
        typedef npl_rtf_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_RTF_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rtf_next_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 19;
        static bool key_match(const npl_rtf_next_macro_static_table_key_t& lookup_key, const npl_rtf_next_macro_static_table_key_t& table_key, const npl_rtf_next_macro_static_table_key_t& table_mask);
    };
    
    struct npl_rx_counters_block_config_table_functional_traits_t {
        typedef npl_rx_counters_block_config_table_key_t key_type;
        typedef npl_rx_counters_block_config_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_COUNTERS_BLOCK_CONFIG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_counters_block_config_table");
            return table_name;
        }
    };
    
    struct npl_rx_fwd_error_handling_counter_table_functional_traits_t {
        typedef npl_rx_fwd_error_handling_counter_table_key_t key_type;
        typedef npl_rx_fwd_error_handling_counter_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_FWD_ERROR_HANDLING_COUNTER_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_fwd_error_handling_counter_table");
            return table_name;
        }
    };
    
    struct npl_rx_fwd_error_handling_destination_table_functional_traits_t {
        typedef npl_rx_fwd_error_handling_destination_table_key_t key_type;
        typedef npl_rx_fwd_error_handling_destination_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_FWD_ERROR_HANDLING_DESTINATION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_fwd_error_handling_destination_table");
            return table_name;
        }
    };
    
    struct npl_rx_ip_p_counter_offset_static_table_functional_traits_t {
        typedef npl_rx_ip_p_counter_offset_static_table_key_t key_type;
        typedef npl_rx_ip_p_counter_offset_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_IP_P_COUNTER_OFFSET_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_ip_p_counter_offset_static_table");
            return table_name;
        }
    };
    
    struct npl_rx_map_npp_to_ssp_table_functional_traits_t {
        typedef npl_rx_map_npp_to_ssp_table_key_t key_type;
        typedef npl_rx_map_npp_to_ssp_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_MAP_NPP_TO_SSP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_map_npp_to_ssp_table");
            return table_name;
        }
    };
    
    struct npl_rx_meter_block_meter_attribute_table_functional_traits_t {
        typedef npl_rx_meter_block_meter_attribute_table_key_t key_type;
        typedef npl_rx_meter_block_meter_attribute_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_METER_BLOCK_METER_ATTRIBUTE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_meter_block_meter_attribute_table");
            return table_name;
        }
    };
    
    struct npl_rx_meter_block_meter_profile_table_functional_traits_t {
        typedef npl_rx_meter_block_meter_profile_table_key_t key_type;
        typedef npl_rx_meter_block_meter_profile_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_METER_BLOCK_METER_PROFILE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_meter_block_meter_profile_table");
            return table_name;
        }
    };
    
    struct npl_rx_meter_block_meter_shaper_configuration_table_functional_traits_t {
        typedef npl_rx_meter_block_meter_shaper_configuration_table_key_t key_type;
        typedef npl_rx_meter_block_meter_shaper_configuration_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_METER_BLOCK_METER_SHAPER_CONFIGURATION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_meter_block_meter_shaper_configuration_table");
            return table_name;
        }
    };
    
    struct npl_rx_meter_distributed_meter_profile_table_functional_traits_t {
        typedef npl_rx_meter_distributed_meter_profile_table_key_t key_type;
        typedef npl_rx_meter_distributed_meter_profile_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_METER_DISTRIBUTED_METER_PROFILE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_meter_distributed_meter_profile_table");
            return table_name;
        }
    };
    
    struct npl_rx_meter_exact_meter_decision_mapping_table_functional_traits_t {
        typedef npl_rx_meter_exact_meter_decision_mapping_table_key_t key_type;
        typedef npl_rx_meter_exact_meter_decision_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_METER_EXACT_METER_DECISION_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_meter_exact_meter_decision_mapping_table");
            return table_name;
        }
    };
    
    struct npl_rx_meter_meter_profile_table_functional_traits_t {
        typedef npl_rx_meter_meter_profile_table_key_t key_type;
        typedef npl_rx_meter_meter_profile_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_METER_METER_PROFILE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_meter_meter_profile_table");
            return table_name;
        }
    };
    
    struct npl_rx_meter_meter_shaper_configuration_table_functional_traits_t {
        typedef npl_rx_meter_meter_shaper_configuration_table_key_t key_type;
        typedef npl_rx_meter_meter_shaper_configuration_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_METER_METER_SHAPER_CONFIGURATION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_meter_meter_shaper_configuration_table");
            return table_name;
        }
    };
    
    struct npl_rx_meter_meters_attribute_table_functional_traits_t {
        typedef npl_rx_meter_meters_attribute_table_key_t key_type;
        typedef npl_rx_meter_meters_attribute_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_METER_METERS_ATTRIBUTE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_meter_meters_attribute_table");
            return table_name;
        }
    };
    
    struct npl_rx_meter_rate_limiter_shaper_configuration_table_functional_traits_t {
        typedef npl_rx_meter_rate_limiter_shaper_configuration_table_key_t key_type;
        typedef npl_rx_meter_rate_limiter_shaper_configuration_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_METER_RATE_LIMITER_SHAPER_CONFIGURATION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_meter_rate_limiter_shaper_configuration_table");
            return table_name;
        }
    };
    
    struct npl_rx_meter_stat_meter_decision_mapping_table_functional_traits_t {
        typedef npl_rx_meter_stat_meter_decision_mapping_table_key_t key_type;
        typedef npl_rx_meter_stat_meter_decision_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_METER_STAT_METER_DECISION_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_meter_stat_meter_decision_mapping_table");
            return table_name;
        }
    };
    
    struct npl_rx_npu_to_tm_dest_table_functional_traits_t {
        typedef npl_rx_npu_to_tm_dest_table_key_t key_type;
        typedef npl_rx_npu_to_tm_dest_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_NPU_TO_TM_DEST_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_npu_to_tm_dest_table");
            return table_name;
        }
    };
    
    struct npl_rx_obm_code_table_functional_traits_t {
        typedef npl_rx_obm_code_table_key_t key_type;
        typedef npl_rx_obm_code_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_OBM_CODE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_obm_code_table");
            return table_name;
        }
    };
    
    struct npl_rx_obm_punt_src_and_code_table_functional_traits_t {
        typedef npl_rx_obm_punt_src_and_code_table_key_t key_type;
        typedef npl_rx_obm_punt_src_and_code_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_RX_OBM_PUNT_SRC_AND_CODE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_obm_punt_src_and_code_table");
            return table_name;
        }
    };
    
    struct npl_rx_redirect_code_ext_table_functional_traits_t {
        typedef npl_rx_redirect_code_ext_table_key_t key_type;
        typedef npl_rx_redirect_code_ext_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_REDIRECT_CODE_EXT_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_redirect_code_ext_table");
            return table_name;
        }
    };
    
    struct npl_rx_redirect_code_table_functional_traits_t {
        typedef npl_rx_redirect_code_table_key_t key_type;
        typedef npl_rx_redirect_code_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_REDIRECT_CODE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_redirect_code_table");
            return table_name;
        }
    };
    
    struct npl_rx_redirect_next_macro_static_table_functional_traits_t {
        typedef npl_rx_redirect_next_macro_static_table_key_t key_type;
        typedef npl_rx_redirect_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_RX_REDIRECT_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_redirect_next_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 6;
        static bool key_match(const npl_rx_redirect_next_macro_static_table_key_t& lookup_key, const npl_rx_redirect_next_macro_static_table_key_t& table_key, const npl_rx_redirect_next_macro_static_table_key_t& table_mask);
    };
    
    struct npl_rx_term_error_handling_counter_table_functional_traits_t {
        typedef npl_rx_term_error_handling_counter_table_key_t key_type;
        typedef npl_rx_term_error_handling_counter_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_TERM_ERROR_HANDLING_COUNTER_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_term_error_handling_counter_table");
            return table_name;
        }
    };
    
    struct npl_rx_term_error_handling_destination_table_functional_traits_t {
        typedef npl_rx_term_error_handling_destination_table_key_t key_type;
        typedef npl_rx_term_error_handling_destination_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RX_TERM_ERROR_HANDLING_DESTINATION_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rx_term_error_handling_destination_table");
            return table_name;
        }
    };
    
    struct npl_rxpdr_dsp_lookup_table_functional_traits_t {
        typedef npl_rxpdr_dsp_lookup_table_key_t key_type;
        typedef npl_rxpdr_dsp_lookup_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RXPDR_DSP_LOOKUP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("rxpdr_dsp_lookup_table");
            return table_name;
        }
    };
    
    struct npl_rxpdr_dsp_tc_map_functional_traits_t {
        typedef npl_rxpdr_dsp_tc_map_key_t key_type;
        typedef npl_rxpdr_dsp_tc_map_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_RXPDR_DSP_TC_MAP;
        static const std::string& get_table_name() {
            static const std::string table_name("rxpdr_dsp_tc_map");
            return table_name;
        }
    };
    
    struct npl_sch_oqse_cfg_functional_traits_t {
        typedef npl_sch_oqse_cfg_key_t key_type;
        typedef npl_sch_oqse_cfg_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_SCH_OQSE_CFG;
        static const std::string& get_table_name() {
            static const std::string table_name("sch_oqse_cfg");
            return table_name;
        }
    };
    
    struct npl_second_ene_static_table_functional_traits_t {
        typedef npl_second_ene_static_table_key_t key_type;
        typedef npl_second_ene_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_SECOND_ENE_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("second_ene_static_table");
            return table_name;
        }
        static const size_t table_size = 4;
        static bool key_match(const npl_second_ene_static_table_key_t& lookup_key, const npl_second_ene_static_table_key_t& table_key, const npl_second_ene_static_table_key_t& table_mask);
    };
    
    struct npl_select_inject_next_macro_static_table_functional_traits_t {
        typedef npl_select_inject_next_macro_static_table_key_t key_type;
        typedef npl_select_inject_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_SELECT_INJECT_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("select_inject_next_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 15;
        static bool key_match(const npl_select_inject_next_macro_static_table_key_t& lookup_key, const npl_select_inject_next_macro_static_table_key_t& table_key, const npl_select_inject_next_macro_static_table_key_t& table_mask);
    };
    
    struct npl_service_lp_attributes_table_functional_traits_t {
        typedef npl_service_lp_attributes_table_key_t key_type;
        typedef npl_service_lp_attributes_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_SERVICE_LP_ATTRIBUTES_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("service_lp_attributes_table");
            return table_name;
        }
    };
    
    struct npl_service_mapping_em0_ac_port_table_functional_traits_t {
        typedef npl_service_mapping_em0_ac_port_table_key_t key_type;
        typedef npl_service_mapping_em0_ac_port_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_SERVICE_MAPPING_EM0_AC_PORT_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("service_mapping_em0_ac_port_table");
            return table_name;
        }
    };
    
    struct npl_service_mapping_em0_ac_port_tag_table_functional_traits_t {
        typedef npl_service_mapping_em0_ac_port_tag_table_key_t key_type;
        typedef npl_service_mapping_em0_ac_port_tag_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_SERVICE_MAPPING_EM0_AC_PORT_TAG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("service_mapping_em0_ac_port_tag_table");
            return table_name;
        }
    };
    
    struct npl_service_mapping_em0_ac_port_tag_tag_table_functional_traits_t {
        typedef npl_service_mapping_em0_ac_port_tag_tag_table_key_t key_type;
        typedef npl_service_mapping_em0_ac_port_tag_tag_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_SERVICE_MAPPING_EM0_AC_PORT_TAG_TAG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("service_mapping_em0_ac_port_tag_tag_table");
            return table_name;
        }
    };
    
    struct npl_service_mapping_em0_pwe_tag_table_functional_traits_t {
        typedef npl_service_mapping_em0_pwe_tag_table_key_t key_type;
        typedef npl_service_mapping_em0_pwe_tag_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_SERVICE_MAPPING_EM0_PWE_TAG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("service_mapping_em0_pwe_tag_table");
            return table_name;
        }
    };
    
    struct npl_service_mapping_em1_ac_port_tag_table_functional_traits_t {
        typedef npl_service_mapping_em1_ac_port_tag_table_key_t key_type;
        typedef npl_service_mapping_em1_ac_port_tag_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_SERVICE_MAPPING_EM1_AC_PORT_TAG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("service_mapping_em1_ac_port_tag_table");
            return table_name;
        }
    };
    
    struct npl_service_mapping_tcam_ac_port_table_functional_traits_t {
        typedef npl_service_mapping_tcam_ac_port_table_key_t key_type;
        typedef npl_service_mapping_tcam_ac_port_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_SERVICE_MAPPING_TCAM_AC_PORT_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("service_mapping_tcam_ac_port_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_service_mapping_tcam_ac_port_table_key_t& lookup_key, const npl_service_mapping_tcam_ac_port_table_key_t& table_key, const npl_service_mapping_tcam_ac_port_table_key_t& table_mask);
    };
    
    struct npl_service_mapping_tcam_ac_port_tag_table_functional_traits_t {
        typedef npl_service_mapping_tcam_ac_port_tag_table_key_t key_type;
        typedef npl_service_mapping_tcam_ac_port_tag_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_SERVICE_MAPPING_TCAM_AC_PORT_TAG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("service_mapping_tcam_ac_port_tag_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_service_mapping_tcam_ac_port_tag_table_key_t& lookup_key, const npl_service_mapping_tcam_ac_port_tag_table_key_t& table_key, const npl_service_mapping_tcam_ac_port_tag_table_key_t& table_mask);
    };
    
    struct npl_service_mapping_tcam_ac_port_tag_tag_table_functional_traits_t {
        typedef npl_service_mapping_tcam_ac_port_tag_tag_table_key_t key_type;
        typedef npl_service_mapping_tcam_ac_port_tag_tag_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_SERVICE_MAPPING_TCAM_AC_PORT_TAG_TAG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("service_mapping_tcam_ac_port_tag_tag_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_service_mapping_tcam_ac_port_tag_tag_table_key_t& lookup_key, const npl_service_mapping_tcam_ac_port_tag_tag_table_key_t& table_key, const npl_service_mapping_tcam_ac_port_tag_tag_table_key_t& table_mask);
    };
    
    struct npl_service_mapping_tcam_pwe_tag_table_functional_traits_t {
        typedef npl_service_mapping_tcam_pwe_tag_table_key_t key_type;
        typedef npl_service_mapping_tcam_pwe_tag_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_SERVICE_MAPPING_TCAM_PWE_TAG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("service_mapping_tcam_pwe_tag_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_service_mapping_tcam_pwe_tag_table_key_t& lookup_key, const npl_service_mapping_tcam_pwe_tag_table_key_t& table_key, const npl_service_mapping_tcam_pwe_tag_table_key_t& table_mask);
    };
    
    struct npl_service_relay_attributes_table_functional_traits_t {
        typedef npl_service_relay_attributes_table_key_t key_type;
        typedef npl_service_relay_attributes_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_SERVICE_RELAY_ATTRIBUTES_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("service_relay_attributes_table");
            return table_name;
        }
    };
    
    struct npl_set_ene_macro_and_bytes_to_remove_table_functional_traits_t {
        typedef npl_set_ene_macro_and_bytes_to_remove_table_key_t key_type;
        typedef npl_set_ene_macro_and_bytes_to_remove_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_SET_ENE_MACRO_AND_BYTES_TO_REMOVE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("set_ene_macro_and_bytes_to_remove_table");
            return table_name;
        }
    };
    
    struct npl_sgacl_table_functional_traits_t {
        typedef npl_sgacl_table_key_t key_type;
        typedef npl_sgacl_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_SGACL_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("sgacl_table");
            return table_name;
        }
        static const size_t table_size = 32768;
        static bool key_match(const npl_sgacl_table_key_t& lookup_key, const npl_sgacl_table_key_t& table_key, const npl_sgacl_table_key_t& table_mask);
    };
    
    struct npl_sip_index_table_functional_traits_t {
        typedef npl_sip_index_table_key_t key_type;
        typedef npl_sip_index_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_SIP_INDEX_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("sip_index_table");
            return table_name;
        }
    };
    
    struct npl_slice_modes_table_functional_traits_t {
        typedef npl_slice_modes_table_key_t key_type;
        typedef npl_slice_modes_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_SLICE_MODES_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("slice_modes_table");
            return table_name;
        }
    };
    
    struct npl_slp_based_forwarding_table_functional_traits_t {
        typedef npl_slp_based_forwarding_table_key_t key_type;
        typedef npl_slp_based_forwarding_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_SLP_BASED_FORWARDING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("slp_based_forwarding_table");
            return table_name;
        }
    };
    
    struct npl_small_encap_mpls_he_asbr_table_functional_traits_t {
        typedef npl_small_encap_mpls_he_asbr_table_key_t key_type;
        typedef npl_small_encap_mpls_he_asbr_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_SMALL_ENCAP_MPLS_HE_ASBR_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("small_encap_mpls_he_asbr_table");
            return table_name;
        }
    };
    
    struct npl_small_encap_mpls_he_te_table_functional_traits_t {
        typedef npl_small_encap_mpls_he_te_table_key_t key_type;
        typedef npl_small_encap_mpls_he_te_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_SMALL_ENCAP_MPLS_HE_TE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("small_encap_mpls_he_te_table");
            return table_name;
        }
    };
    
    struct npl_snoop_code_hw_table_functional_traits_t {
        typedef npl_snoop_code_hw_table_key_t key_type;
        typedef npl_snoop_code_hw_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_SNOOP_CODE_HW_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("snoop_code_hw_table");
            return table_name;
        }
    };
    
    struct npl_snoop_table_functional_traits_t {
        typedef npl_snoop_table_key_t key_type;
        typedef npl_snoop_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_SNOOP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("snoop_table");
            return table_name;
        }
        static const size_t table_size = 64;
        static bool key_match(const npl_snoop_table_key_t& lookup_key, const npl_snoop_table_key_t& table_key, const npl_snoop_table_key_t& table_mask);
    };
    
    struct npl_snoop_to_dsp_in_npu_soft_header_table_functional_traits_t {
        typedef npl_snoop_to_dsp_in_npu_soft_header_table_key_t key_type;
        typedef npl_snoop_to_dsp_in_npu_soft_header_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_SNOOP_TO_DSP_IN_NPU_SOFT_HEADER_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("snoop_to_dsp_in_npu_soft_header_table");
            return table_name;
        }
    };
    
    struct npl_source_pif_hw_table_functional_traits_t {
        typedef npl_source_pif_hw_table_key_t key_type;
        typedef npl_source_pif_hw_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_SOURCE_PIF_HW_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("source_pif_hw_table");
            return table_name;
        }
    };
    
    struct npl_stage2_lb_group_size_table_functional_traits_t {
        typedef npl_stage2_lb_group_size_table_key_t key_type;
        typedef npl_stage2_lb_group_size_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_STAGE2_LB_GROUP_SIZE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("stage2_lb_group_size_table");
            return table_name;
        }
    };
    
    struct npl_stage2_lb_table_functional_traits_t {
        typedef npl_stage2_lb_table_key_t key_type;
        typedef npl_stage2_lb_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_STAGE2_LB_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("stage2_lb_table");
            return table_name;
        }
    };
    
    struct npl_stage3_lb_group_size_table_functional_traits_t {
        typedef npl_stage3_lb_group_size_table_key_t key_type;
        typedef npl_stage3_lb_group_size_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_STAGE3_LB_GROUP_SIZE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("stage3_lb_group_size_table");
            return table_name;
        }
    };
    
    struct npl_stage3_lb_table_functional_traits_t {
        typedef npl_stage3_lb_table_key_t key_type;
        typedef npl_stage3_lb_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_STAGE3_LB_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("stage3_lb_table");
            return table_name;
        }
    };
    
    struct npl_stage3_lb_type_decoding_table_functional_traits_t {
        typedef npl_stage3_lb_type_decoding_table_key_t key_type;
        typedef npl_stage3_lb_type_decoding_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_STAGE3_LB_TYPE_DECODING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("stage3_lb_type_decoding_table");
            return table_name;
        }
    };
    
    struct npl_svl_next_macro_static_table_functional_traits_t {
        typedef npl_svl_next_macro_static_table_key_t key_type;
        typedef npl_svl_next_macro_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_SVL_NEXT_MACRO_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("svl_next_macro_static_table");
            return table_name;
        }
        static const size_t table_size = 5;
        static bool key_match(const npl_svl_next_macro_static_table_key_t& lookup_key, const npl_svl_next_macro_static_table_key_t& table_key, const npl_svl_next_macro_static_table_key_t& table_mask);
    };
    
    struct npl_te_headend_lsp_counter_offset_table_functional_traits_t {
        typedef npl_te_headend_lsp_counter_offset_table_key_t key_type;
        typedef npl_te_headend_lsp_counter_offset_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_TE_HEADEND_LSP_COUNTER_OFFSET_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("te_headend_lsp_counter_offset_table");
            return table_name;
        }
        static const size_t table_size = 14;
        static bool key_match(const npl_te_headend_lsp_counter_offset_table_key_t& lookup_key, const npl_te_headend_lsp_counter_offset_table_key_t& table_key, const npl_te_headend_lsp_counter_offset_table_key_t& table_mask);
    };
    
    struct npl_termination_to_forwarding_fi_hardwired_table_functional_traits_t {
        typedef npl_termination_to_forwarding_fi_hardwired_table_key_t key_type;
        typedef npl_termination_to_forwarding_fi_hardwired_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TERMINATION_TO_FORWARDING_FI_HARDWIRED_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("termination_to_forwarding_fi_hardwired_table");
            return table_name;
        }
    };
    
    struct npl_tm_ibm_cmd_to_destination_functional_traits_t {
        typedef npl_tm_ibm_cmd_to_destination_key_t key_type;
        typedef npl_tm_ibm_cmd_to_destination_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TM_IBM_CMD_TO_DESTINATION;
        static const std::string& get_table_name() {
            static const std::string table_name("tm_ibm_cmd_to_destination");
            return table_name;
        }
    };
    
    struct npl_ts_cmd_hw_static_table_functional_traits_t {
        typedef npl_ts_cmd_hw_static_table_key_t key_type;
        typedef npl_ts_cmd_hw_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TS_CMD_HW_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("ts_cmd_hw_static_table");
            return table_name;
        }
    };
    
    struct npl_tunnel_dlp_p_counter_offset_table_functional_traits_t {
        typedef npl_tunnel_dlp_p_counter_offset_table_key_t key_type;
        typedef npl_tunnel_dlp_p_counter_offset_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_TUNNEL_DLP_P_COUNTER_OFFSET_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("tunnel_dlp_p_counter_offset_table");
            return table_name;
        }
        static const size_t table_size = 16;
        static bool key_match(const npl_tunnel_dlp_p_counter_offset_table_key_t& lookup_key, const npl_tunnel_dlp_p_counter_offset_table_key_t& table_key, const npl_tunnel_dlp_p_counter_offset_table_key_t& table_mask);
    };
    
    struct npl_tunnel_qos_static_table_functional_traits_t {
        typedef npl_tunnel_qos_static_table_key_t key_type;
        typedef npl_tunnel_qos_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TUNNEL_QOS_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("tunnel_qos_static_table");
            return table_name;
        }
    };
    
    struct npl_tx_counters_block_config_table_functional_traits_t {
        typedef npl_tx_counters_block_config_table_key_t key_type;
        typedef npl_tx_counters_block_config_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TX_COUNTERS_BLOCK_CONFIG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("tx_counters_block_config_table");
            return table_name;
        }
    };
    
    struct npl_tx_error_handling_counter_table_functional_traits_t {
        typedef npl_tx_error_handling_counter_table_key_t key_type;
        typedef npl_tx_error_handling_counter_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TX_ERROR_HANDLING_COUNTER_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("tx_error_handling_counter_table");
            return table_name;
        }
    };
    
    struct npl_tx_punt_eth_encap_table_functional_traits_t {
        typedef npl_tx_punt_eth_encap_table_key_t key_type;
        typedef npl_tx_punt_eth_encap_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TX_PUNT_ETH_ENCAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("tx_punt_eth_encap_table");
            return table_name;
        }
    };
    
    struct npl_tx_redirect_code_table_functional_traits_t {
        typedef npl_tx_redirect_code_table_key_t key_type;
        typedef npl_tx_redirect_code_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_TX_REDIRECT_CODE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("tx_redirect_code_table");
            return table_name;
        }
    };
    
    struct npl_txpdr_mc_list_size_table_functional_traits_t {
        typedef npl_txpdr_mc_list_size_table_key_t key_type;
        typedef npl_txpdr_mc_list_size_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TXPDR_MC_LIST_SIZE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("txpdr_mc_list_size_table");
            return table_name;
        }
    };
    
    struct npl_txpdr_tc_map_table_functional_traits_t {
        typedef npl_txpdr_tc_map_table_key_t key_type;
        typedef npl_txpdr_tc_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TXPDR_TC_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("txpdr_tc_map_table");
            return table_name;
        }
    };
    
    struct npl_txpp_dlp_profile_table_functional_traits_t {
        typedef npl_txpp_dlp_profile_table_key_t key_type;
        typedef npl_txpp_dlp_profile_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TXPP_DLP_PROFILE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("txpp_dlp_profile_table");
            return table_name;
        }
    };
    
    struct npl_txpp_encap_qos_mapping_table_functional_traits_t {
        typedef npl_txpp_encap_qos_mapping_table_key_t key_type;
        typedef npl_txpp_encap_qos_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TXPP_ENCAP_QOS_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("txpp_encap_qos_mapping_table");
            return table_name;
        }
    };
    
    struct npl_txpp_first_enc_type_to_second_enc_type_offset_functional_traits_t {
        typedef npl_txpp_first_enc_type_to_second_enc_type_offset_key_t key_type;
        typedef npl_txpp_first_enc_type_to_second_enc_type_offset_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TXPP_FIRST_ENC_TYPE_TO_SECOND_ENC_TYPE_OFFSET;
        static const std::string& get_table_name() {
            static const std::string table_name("txpp_first_enc_type_to_second_enc_type_offset");
            return table_name;
        }
    };
    
    struct npl_txpp_fwd_header_type_is_l2_table_functional_traits_t {
        typedef npl_txpp_fwd_header_type_is_l2_table_key_t key_type;
        typedef npl_txpp_fwd_header_type_is_l2_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TXPP_FWD_HEADER_TYPE_IS_L2_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("txpp_fwd_header_type_is_l2_table");
            return table_name;
        }
    };
    
    struct npl_txpp_fwd_qos_mapping_table_functional_traits_t {
        typedef npl_txpp_fwd_qos_mapping_table_key_t key_type;
        typedef npl_txpp_fwd_qos_mapping_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TXPP_FWD_QOS_MAPPING_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("txpp_fwd_qos_mapping_table");
            return table_name;
        }
    };
    
    struct npl_txpp_ibm_enables_table_functional_traits_t {
        typedef npl_txpp_ibm_enables_table_key_t key_type;
        typedef npl_txpp_ibm_enables_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TXPP_IBM_ENABLES_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("txpp_ibm_enables_table");
            return table_name;
        }
    };
    
    struct npl_txpp_initial_npe_macro_table_functional_traits_t {
        typedef npl_txpp_initial_npe_macro_table_key_t key_type;
        typedef npl_txpp_initial_npe_macro_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_TXPP_INITIAL_NPE_MACRO_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("txpp_initial_npe_macro_table");
            return table_name;
        }
        static const size_t table_size = 40;
        static bool key_match(const npl_txpp_initial_npe_macro_table_key_t& lookup_key, const npl_txpp_initial_npe_macro_table_key_t& table_key, const npl_txpp_initial_npe_macro_table_key_t& table_mask);
    };
    
    struct npl_txpp_mapping_qos_tag_table_functional_traits_t {
        typedef npl_txpp_mapping_qos_tag_table_key_t key_type;
        typedef npl_txpp_mapping_qos_tag_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_TXPP_MAPPING_QOS_TAG_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("txpp_mapping_qos_tag_table");
            return table_name;
        }
    };
    
    struct npl_uc_ibm_tc_map_table_functional_traits_t {
        typedef npl_uc_ibm_tc_map_table_key_t key_type;
        typedef npl_uc_ibm_tc_map_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_UC_IBM_TC_MAP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("uc_ibm_tc_map_table");
            return table_name;
        }
    };
    
    struct npl_urpf_ipsa_dest_is_lpts_static_table_functional_traits_t {
        typedef npl_urpf_ipsa_dest_is_lpts_static_table_key_t key_type;
        typedef npl_urpf_ipsa_dest_is_lpts_static_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_URPF_IPSA_DEST_IS_LPTS_STATIC_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("urpf_ipsa_dest_is_lpts_static_table");
            return table_name;
        }
        static const size_t table_size = 2;
        static bool key_match(const npl_urpf_ipsa_dest_is_lpts_static_table_key_t& lookup_key, const npl_urpf_ipsa_dest_is_lpts_static_table_key_t& table_key, const npl_urpf_ipsa_dest_is_lpts_static_table_key_t& table_mask);
    };
    
    struct npl_vlan_edit_tpid1_profile_hw_table_functional_traits_t {
        typedef npl_vlan_edit_tpid1_profile_hw_table_key_t key_type;
        typedef npl_vlan_edit_tpid1_profile_hw_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_VLAN_EDIT_TPID1_PROFILE_HW_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("vlan_edit_tpid1_profile_hw_table");
            return table_name;
        }
    };
    
    struct npl_vlan_edit_tpid2_profile_hw_table_functional_traits_t {
        typedef npl_vlan_edit_tpid2_profile_hw_table_key_t key_type;
        typedef npl_vlan_edit_tpid2_profile_hw_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_VLAN_EDIT_TPID2_PROFILE_HW_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("vlan_edit_tpid2_profile_hw_table");
            return table_name;
        }
    };
    
    struct npl_vlan_format_table_functional_traits_t {
        typedef npl_vlan_format_table_key_t key_type;
        typedef npl_vlan_format_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_TERNARY;
        static const npl_tables_e table_id = NPL_TABLES_VLAN_FORMAT_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("vlan_format_table");
            return table_name;
        }
        static const size_t table_size = 32;
        static bool key_match(const npl_vlan_format_table_key_t& lookup_key, const npl_vlan_format_table_key_t& table_key, const npl_vlan_format_table_key_t& table_mask);
    };
    
    struct npl_vni_table_functional_traits_t {
        typedef npl_vni_table_key_t key_type;
        typedef npl_vni_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_VNI_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("vni_table");
            return table_name;
        }
    };
    
    struct npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_functional_traits_t {
        typedef npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t key_type;
        typedef npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_VOQ_CGM_SLICE_BUFFERS_CONSUMPTION_LUT_FOR_ENQ_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("voq_cgm_slice_buffers_consumption_lut_for_enq_table");
            return table_name;
        }
    };
    
    struct npl_voq_cgm_slice_dram_cgm_profile_table_functional_traits_t {
        typedef npl_voq_cgm_slice_dram_cgm_profile_table_key_t key_type;
        typedef npl_voq_cgm_slice_dram_cgm_profile_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_VOQ_CGM_SLICE_DRAM_CGM_PROFILE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("voq_cgm_slice_dram_cgm_profile_table");
            return table_name;
        }
    };
    
    struct npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_functional_traits_t {
        typedef npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t key_type;
        typedef npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_VOQ_CGM_SLICE_PD_CONSUMPTION_LUT_FOR_ENQ_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("voq_cgm_slice_pd_consumption_lut_for_enq_table");
            return table_name;
        }
    };
    
    struct npl_voq_cgm_slice_profile_buff_region_thresholds_table_functional_traits_t {
        typedef npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t key_type;
        typedef npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_VOQ_CGM_SLICE_PROFILE_BUFF_REGION_THRESHOLDS_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("voq_cgm_slice_profile_buff_region_thresholds_table");
            return table_name;
        }
    };
    
    struct npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_functional_traits_t {
        typedef npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t key_type;
        typedef npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_VOQ_CGM_SLICE_PROFILE_PKT_ENQ_TIME_REGION_THRESHOLDS_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table");
            return table_name;
        }
    };
    
    struct npl_voq_cgm_slice_profile_pkt_region_thresholds_table_functional_traits_t {
        typedef npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t key_type;
        typedef npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_VOQ_CGM_SLICE_PROFILE_PKT_REGION_THRESHOLDS_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("voq_cgm_slice_profile_pkt_region_thresholds_table");
            return table_name;
        }
    };
    
    struct npl_voq_cgm_slice_slice_cgm_profile_table_functional_traits_t {
        typedef npl_voq_cgm_slice_slice_cgm_profile_table_key_t key_type;
        typedef npl_voq_cgm_slice_slice_cgm_profile_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_DIRECT;
        static const npl_tables_e table_id = NPL_TABLES_VOQ_CGM_SLICE_SLICE_CGM_PROFILE_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("voq_cgm_slice_slice_cgm_profile_table");
            return table_name;
        }
    };
    
    struct npl_vsid_table_functional_traits_t {
        typedef npl_vsid_table_key_t key_type;
        typedef npl_vsid_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_VSID_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("vsid_table");
            return table_name;
        }
    };
    
    struct npl_vxlan_l2_dlp_table_functional_traits_t {
        typedef npl_vxlan_l2_dlp_table_key_t key_type;
        typedef npl_vxlan_l2_dlp_table_value_t value_type;
        static const table_type_e table_type = TABLE_TYPE_EM;
        static const npl_tables_e table_id = NPL_TABLES_VXLAN_L2_DLP_TABLE;
        static const std::string& get_table_name() {
            static const std::string table_name("vxlan_l2_dlp_table");
            return table_name;
        }
    };
    
} // namespace silicon_one

#endif
