
// This file has been automatically generated using nplc.py. Do not edit it manually.
// Version: 1.76.2_0.0.0.0 generated on devsrv15.leaba.local at 2021-05-12 16:04:51


#include "nplapi/npl_enums.h"
#include "nplapi/npl_enum_to_string.h"

std::string npl_enum_to_string(const npl_acl_destination_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ACL_DESTINATION_INVALID:
        {
            return "NPL_ACL_DESTINATION_INVALID(0x0)";
            break;
        }
        case NPL_ACL_DESTINATION_UC:
        {
            return "NPL_ACL_DESTINATION_UC(0x1)";
            break;
        }
        case NPL_ACL_DESTINATION_MC:
        {
            return "NPL_ACL_DESTINATION_MC(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_acl_destination_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_acl_l4_protocol_compress_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ACL_OTHER:
        {
            return "NPL_ACL_OTHER(0x0)";
            break;
        }
        case NPL_ACL_ICMP:
        {
            return "NPL_ACL_ICMP(0x1)";
            break;
        }
        case NPL_ACL_TCP:
        {
            return "NPL_ACL_TCP(0x2)";
            break;
        }
        case NPL_ACL_UDP:
        {
            return "NPL_ACL_UDP(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_acl_l4_protocol_compress_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_acl_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ACL_TYPE_DISABLED:
        {
            return "NPL_ACL_TYPE_DISABLED(0x0)";
            break;
        }
        case NPL_ACL_TYPE_DEFAULT:
        {
            return "NPL_ACL_TYPE_DEFAULT(0x1)";
            break;
        }
        case NPL_ACL_TYPE_RTF:
        {
            return "NPL_ACL_TYPE_RTF(0x2)";
            break;
        }
        case NPL_ACL_TYPE_OG:
        {
            return "NPL_ACL_TYPE_OG(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_acl_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_all_devices_reachable_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ALL_DEVICES_REACHABLE_FALSE:
        {
            return "NPL_ALL_DEVICES_REACHABLE_FALSE(0x0)";
            break;
        }
        case NPL_ALL_DEVICES_REACHABLE_TRUE:
        {
            return "NPL_ALL_DEVICES_REACHABLE_TRUE(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_all_devices_reachable_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_append_relay_e enum_instance)
{
    switch(enum_instance) {
        case NPL_DONT_APPEND_RELAY:
        {
            return "NPL_DONT_APPEND_RELAY(0x0)";
            break;
        }
        case NPL_APPEND_RELAY:
        {
            return "NPL_APPEND_RELAY(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_append_relay_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_bfd_channel_e enum_instance)
{
    switch(enum_instance) {
        case NPL_BFD_CHANNEL_NONE:
        {
            return "NPL_BFD_CHANNEL_NONE(0x0)";
            break;
        }
        case NPL_BFD_CHANNEL_ACH:
        {
            return "NPL_BFD_CHANNEL_ACH(0x2)";
            break;
        }
        case NPL_BFD_CHANNEL_TTL:
        {
            return "NPL_BFD_CHANNEL_TTL(0x4)";
            break;
        }
        case NPL_BFD_CHANNEL_RA:
        {
            return "NPL_BFD_CHANNEL_RA(0x8)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_bfd_channel_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_bfd_selector_e enum_instance)
{
    switch(enum_instance) {
        case NPL_BFD_SINGLE_HOP_SELECTOR:
        {
            return "NPL_BFD_SINGLE_HOP_SELECTOR(0x0)";
            break;
        }
        case NPL_BFD_MULTI_HOP_SELECTOR:
        {
            return "NPL_BFD_MULTI_HOP_SELECTOR(0x1)";
            break;
        }
        case NPL_BFD_MICRO_SELECTOR:
        {
            return "NPL_BFD_MICRO_SELECTOR(0x2)";
            break;
        }
        case NPL_BFD_ECHO_SELECTOR:
        {
            return "NPL_BFD_ECHO_SELECTOR(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_bfd_selector_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_bfd_session_protocol_e enum_instance)
{
    switch(enum_instance) {
        case NPL_BFD_SESSION_IPV4:
        {
            return "NPL_BFD_SESSION_IPV4(0x0)";
            break;
        }
        case NPL_BFD_SESSION_IPV6:
        {
            return "NPL_BFD_SESSION_IPV6(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_bfd_session_protocol_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_bfd_session_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_BFD_TYPE_MICRO:
        {
            return "NPL_BFD_TYPE_MICRO(0x0)";
            break;
        }
        case NPL_BFD_TYPE_SINGLE_HOP:
        {
            return "NPL_BFD_TYPE_SINGLE_HOP(0x1)";
            break;
        }
        case NPL_BFD_TYPE_MULTI_HOP:
        {
            return "NPL_BFD_TYPE_MULTI_HOP(0x2)";
            break;
        }
        case NPL_BFD_TYPE_ECHO:
        {
            return "NPL_BFD_TYPE_ECHO(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_bfd_session_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_bfd_transport_e enum_instance)
{
    switch(enum_instance) {
        case NPL_BFD_TRANSPORT_IPV4:
        {
            return "NPL_BFD_TRANSPORT_IPV4(0x0)";
            break;
        }
        case NPL_BFD_TRANSPORT_IPV6:
        {
            return "NPL_BFD_TRANSPORT_IPV6(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_bfd_transport_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_bool_e enum_instance)
{
    switch(enum_instance) {
        case NPL_FALSE_VALUE:
        {
            return "NPL_FALSE_VALUE(0x0)";
            break;
        }
        case NPL_TRUE_VALUE:
        {
            return "NPL_TRUE_VALUE(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_bool_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_const_cntr_ethernet_rate_limiter_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_CONST_CNTR_ETH_RATE_LIMITER_BC:
        {
            return "NPL_CONST_CNTR_ETH_RATE_LIMITER_BC(0x0)";
            break;
        }
        case NPL_CONST_CNTR_ETH_RATE_LIMITER_UNKNOWN_MC:
        {
            return "NPL_CONST_CNTR_ETH_RATE_LIMITER_UNKNOWN_MC(0x1)";
            break;
        }
        case NPL_CONST_CNTR_ETH_RATE_LIMITER_UNKNOWN_UC:
        {
            return "NPL_CONST_CNTR_ETH_RATE_LIMITER_UNKNOWN_UC(0x2)";
            break;
        }
        case NPL_CONST_CNTR_ETH_RATE_LIMITER_KNOWN_MC:
        {
            return "NPL_CONST_CNTR_ETH_RATE_LIMITER_KNOWN_MC(0x3)";
            break;
        }
        case NPL_CONST_CNTR_ETH_RATE_LIMITER_KNOWN_UC:
        {
            return "NPL_CONST_CNTR_ETH_RATE_LIMITER_KNOWN_UC(0x4)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_const_cntr_ethernet_rate_limiter_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_counter_action_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_NO_ACTION:
        {
            return "NPL_NO_ACTION(0x0)";
            break;
        }
        case NPL_METERING:
        {
            return "NPL_METERING(0x1)";
            break;
        }
        case NPL_COUNTING:
        {
            return "NPL_COUNTING(0x2)";
            break;
        }
        case NPL_OVERRIDE_POLICER:
        {
            return "NPL_OVERRIDE_POLICER(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_counter_action_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_counter_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_COUNTER_TYPE_PC29_BC35:
        {
            return "NPL_COUNTER_TYPE_PC29_BC35(0x0)";
            break;
        }
        case NPL_COUNTER_TYPE_PC64:
        {
            return "NPL_COUNTER_TYPE_PC64(0x1)";
            break;
        }
        case NPL_COUNTER_TYPE_PC64_BC64:
        {
            return "NPL_COUNTER_TYPE_PC64_BC64(0x2)";
            break;
        }
        case NPL_COUNTER_TYPE_PC32:
        {
            return "NPL_COUNTER_TYPE_PC32(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_counter_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_cs_fabric_context_e enum_instance)
{
    switch(enum_instance) {
        case NPL_CS_FABRIC_CONTEXT_PLB_UC_H:
        {
            return "NPL_CS_FABRIC_CONTEXT_PLB_UC_H(0x0)";
            break;
        }
        case NPL_CS_FABRIC_CONTEXT_PLB_UC_L:
        {
            return "NPL_CS_FABRIC_CONTEXT_PLB_UC_L(0x1)";
            break;
        }
        case NPL_CS_FABRIC_CONTEXT_PLB_MC:
        {
            return "NPL_CS_FABRIC_CONTEXT_PLB_MC(0x2)";
            break;
        }
        case NPL_CS_FABRIC_CONTEXT_FLB_L:
        {
            return "NPL_CS_FABRIC_CONTEXT_FLB_L(0x3)";
            break;
        }
        case NPL_CS_FABRIC_CONTEXT_FLB_H:
        {
            return "NPL_CS_FABRIC_CONTEXT_FLB_H(0x4)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_cs_fabric_context_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_cud_encap_size_e enum_instance)
{
    switch(enum_instance) {
        case NPL_CUD_ENCAP_SIZE_20:
        {
            return "NPL_CUD_ENCAP_SIZE_20(0x0)";
            break;
        }
        case NPL_CUD_ENCAP_SIZE_16:
        {
            return "NPL_CUD_ENCAP_SIZE_16(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_cud_encap_size_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_dsp_dest_msbs_e enum_instance)
{
    switch(enum_instance) {
        case NPL_DSP_DEST_MSBS_DEFAULT:
        {
            return "NPL_DSP_DEST_MSBS_DEFAULT(0x8)";
            break;
        }
        case NPL_DSP_DEST_MSBS_ALTERNATE:
        {
            return "NPL_DSP_DEST_MSBS_ALTERNATE(0x9)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_dsp_dest_msbs_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_egress0_acl_db_ids_t enum_instance)
{
    switch(enum_instance) {
        case NPL_EGRESS_ACL_DB_IPV6_MASTER_DEFAULT:
        {
            return "NPL_EGRESS_ACL_DB_IPV6_MASTER_DEFAULT(0x1)";
            break;
        }
        case NPL_EGRESS_ACL_DB_MAC_IPV6_MASTER:
        {
            return "NPL_EGRESS_ACL_DB_MAC_IPV6_MASTER(0x3)";
            break;
        }
        case NPL_EGRESS_ACL_DB_IPV4_SEC_DEFAULT:
        {
            return "NPL_EGRESS_ACL_DB_IPV4_SEC_DEFAULT(0x2)";
            break;
        }
        case NPL_EGRESS_ACL_DB_MAC_SEC_DEFAULT:
        {
            return "NPL_EGRESS_ACL_DB_MAC_SEC_DEFAULT(0x6)";
            break;
        }
        case NPL_EGRESS_ACL_DB_MAC_SEC_IPV4:
        {
            return "NPL_EGRESS_ACL_DB_MAC_SEC_IPV4(0xa)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_egress0_acl_db_ids_t");
    }
    return "";
}


std::string npl_enum_to_string(const npl_egress1_acl_db_ids_t enum_instance)
{
    switch(enum_instance) {
        case NPL_EGRESS_ACL_DB_IPV4_QOS_DEFAULT:
        {
            return "NPL_EGRESS_ACL_DB_IPV4_QOS_DEFAULT(0x0)";
            break;
        }
        case NPL_EGRESS_ACL_DB_MAC_QOS_DEFAULT:
        {
            return "NPL_EGRESS_ACL_DB_MAC_QOS_DEFAULT(0x4)";
            break;
        }
        case NPL_EGRESS_ACL_DB_MAC_QOS_IPV4:
        {
            return "NPL_EGRESS_ACL_DB_MAC_QOS_IPV4(0x8)";
            break;
        }
        case NPL_EGRESS_QOS_TCAM_DB:
        {
            return "NPL_EGRESS_QOS_TCAM_DB(0xc)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_egress1_acl_db_ids_t");
    }
    return "";
}


std::string npl_enum_to_string(const npl_egress_acl_values_e enum_instance)
{
    switch(enum_instance) {
        case NPL_EGRESS_SEC_ACL_DEFAULT_PAYLOAD:
        {
            return "NPL_EGRESS_SEC_ACL_DEFAULT_PAYLOAD(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_egress_acl_values_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_egress_large_em_logical_database_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LARGE_EM_MPLS_ENCAP_LDB:
        {
            return "NPL_LARGE_EM_MPLS_ENCAP_LDB(0x1)";
            break;
        }
        case NPL_LARGE_EM_MPLS_TE_ENCAP_LDB:
        {
            return "NPL_LARGE_EM_MPLS_TE_ENCAP_LDB(0x2)";
            break;
        }
        case NPL_LARGE_EM_MPLS_LDP_OVER_TE_ENCAP_LDB:
        {
            return "NPL_LARGE_EM_MPLS_LDP_OVER_TE_ENCAP_LDB(0x3)";
            break;
        }
        case NPL_LARGE_EM_PER_PE_AND_VRF_VPN_LDB:
        {
            return "NPL_LARGE_EM_PER_PE_AND_VRF_VPN_LDB(0x4)";
            break;
        }
        case NPL_LARGE_EM_PER_PE_AND_PREFIX_VPN_LDB:
        {
            return "NPL_LARGE_EM_PER_PE_AND_PREFIX_VPN_LDB(0x5)";
            break;
        }
        case NPL_LARGE_EM_MPLS_SRV4_ENCAP_LDB:
        {
            return "NPL_LARGE_EM_MPLS_SRV4_ENCAP_LDB(0x6)";
            break;
        }
        case NPL_LARGE_EM_L2_DLP_TABLE_LDB:
        {
            return "NPL_LARGE_EM_L2_DLP_TABLE_LDB(0x7)";
            break;
        }
        case NPL_LARGE_EM_TX_REDIRECT_TABLE_LDB:
        {
            return "NPL_LARGE_EM_TX_REDIRECT_TABLE_LDB(0x8)";
            break;
        }
        case NPL_LARGE_EM_TX_PUNT_GRE_TABLE_LDB:
        {
            return "NPL_LARGE_EM_TX_PUNT_GRE_TABLE_LDB(0x9)";
            break;
        }
        case NPL_LARGE_EM_VXLAN_L2_VNI_TABLE_LDB:
        {
            return "NPL_LARGE_EM_VXLAN_L2_VNI_TABLE_LDB(0xa)";
            break;
        }
        case NPL_LARGE_EM_VXLAN_L3_VNI_TABLE_LDB:
        {
            return "NPL_LARGE_EM_VXLAN_L3_VNI_TABLE_LDB(0xb)";
            break;
        }
        case NPL_LARGE_EM_L2_VPN_LDB:
        {
            return "NPL_LARGE_EM_L2_VPN_LDB(0xc)";
            break;
        }
        case NPL_LARGE_EM_L2_VPN_VPLS_LDB:
        {
            return "NPL_LARGE_EM_L2_VPN_VPLS_LDB(0xd)";
            break;
        }
        case NPL_LARGE_EM_IP_TUNNEL_LDB:
        {
            return "NPL_LARGE_EM_IP_TUNNEL_LDB(0xe)";
            break;
        }
        case NPL_LARGE_EM_MPLS_ASBR_LABEL_LDB:
        {
            return "NPL_LARGE_EM_MPLS_ASBR_LABEL_LDB(0xf)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_egress_large_em_logical_database_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_egress_small_em_logical_database_e enum_instance)
{
    switch(enum_instance) {
        case NPL_SMALL_EM_VXLAN_L2_DLP_TABLE_LDB:
        {
            return "NPL_SMALL_EM_VXLAN_L2_DLP_TABLE_LDB(0x0)";
            break;
        }
        case NPL_SMALL_EM_PER_PE_AND_VRF_VPN_LDB:
        {
            return "NPL_SMALL_EM_PER_PE_AND_VRF_VPN_LDB(0x2)";
            break;
        }
        case NPL_SMALL_EM_PER_ASBR_NH_LDB:
        {
            return "NPL_SMALL_EM_PER_ASBR_NH_LDB(0x3)";
            break;
        }
        case NPL_SMALL_EM_PER_PE_AND_PREFIX_VPN_LDB:
        {
            return "NPL_SMALL_EM_PER_PE_AND_PREFIX_VPN_LDB(0x4)";
            break;
        }
        case NPL_SMALL_EM_ADDITIONAL_LABELS_LDB:
        {
            return "NPL_SMALL_EM_ADDITIONAL_LABELS_LDB(0x5)";
            break;
        }
        case NPL_SMALL_EM_TX_PUNT_EXTENDED_ENCAP_LDB:
        {
            return "NPL_SMALL_EM_TX_PUNT_EXTENDED_ENCAP_LDB(0x6)";
            break;
        }
        case NPL_SMALL_EM_PER_TE_NH_LDB:
        {
            return "NPL_SMALL_EM_PER_TE_NH_LDB(0x7)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_egress_small_em_logical_database_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ene_five_labels_jump_offset_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FIFTH_LABEL_NO_JUMP:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FIFTH_LABEL_NO_JUMP(0x0)";
            break;
        }
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FIFTH_LABEL:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FIFTH_LABEL(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ene_five_labels_jump_offset_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ene_four_labels_jump_offset_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FOURTH_LABEL_NO_JUMP:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FOURTH_LABEL_NO_JUMP(0x0)";
            break;
        }
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FOURTH_LABEL:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FOURTH_LABEL(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ene_four_labels_jump_offset_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ene_jump_offset_code_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENE_JUMP_OFFSET_0:
        {
            return "NPL_ENE_JUMP_OFFSET_0(0x0)";
            break;
        }
        case NPL_ENE_JUMP_OFFSET_1:
        {
            return "NPL_ENE_JUMP_OFFSET_1(0x1)";
            break;
        }
        case NPL_ENE_JUMP_OFFSET_2:
        {
            return "NPL_ENE_JUMP_OFFSET_2(0x2)";
            break;
        }
        case NPL_ENE_JUMP_OFFSET_3:
        {
            return "NPL_ENE_JUMP_OFFSET_3(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ene_jump_offset_code_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ene_macro_ids_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ADD_ONE_VLAN_ENE_MACRO:
        {
            return "NPL_ADD_ONE_VLAN_ENE_MACRO(0x40)";
            break;
        }
        case NPL_ADD_TWO_VLANS_ENE_MACRO:
        {
            return "NPL_ADD_TWO_VLANS_ENE_MACRO(0x41)";
            break;
        }
        case NPL_ENE_10_INSTRUCTIONS_MACRO:
        {
            return "NPL_ENE_10_INSTRUCTIONS_MACRO(0x42)";
            break;
        }
        case NPL_ENE_16_INSTRUCTIONS_MACRO:
        {
            return "NPL_ENE_16_INSTRUCTIONS_MACRO(0x43)";
            break;
        }
        case NPL_ENE_20_INSTRUCTIONS_MACRO:
        {
            return "NPL_ENE_20_INSTRUCTIONS_MACRO(0x44)";
            break;
        }
        case NPL_ENE_26_INSTRUCTIONS_MACRO:
        {
            return "NPL_ENE_26_INSTRUCTIONS_MACRO(0x45)";
            break;
        }
        case NPL_ENE_30_INSTRUCTIONS_MACRO:
        {
            return "NPL_ENE_30_INSTRUCTIONS_MACRO(0x46)";
            break;
        }
        case NPL_ENE_48_INSTRUCTIONS_MACRO:
        {
            return "NPL_ENE_48_INSTRUCTIONS_MACRO(0x47)";
            break;
        }
        case NPL_ENE_6_INSTRUCTIONS_MACRO:
        {
            return "NPL_ENE_6_INSTRUCTIONS_MACRO(0x48)";
            break;
        }
        case NPL_ENE_8_INSTRUCTIONS_MACRO:
        {
            return "NPL_ENE_8_INSTRUCTIONS_MACRO(0x49)";
            break;
        }
        case NPL_ENE_DMA_8BYTES_HEADER_MACRO:
        {
            return "NPL_ENE_DMA_8BYTES_HEADER_MACRO(0x4a)";
            break;
        }
        case NPL_ENE_MACRO:
        {
            return "NPL_ENE_MACRO(0x4b)";
            break;
        }
        case NPL_ENE_NOP_AND_COUNT_MACRO:
        {
            return "NPL_ENE_NOP_AND_COUNT_MACRO(0x4c)";
            break;
        }
        case NPL_ENE_NOP_MACRO:
        {
            return "NPL_ENE_NOP_MACRO(0x4d)";
            break;
        }
        case NPL_ENE_NPU_HOST_LRI2LRO_MACRO:
        {
            return "NPL_ENE_NPU_HOST_LRI2LRO_MACRO(0x4e)";
            break;
        }
        case NPL_ENE_SVL_NPU_HEADER_MACRO:
        {
            return "NPL_ENE_SVL_NPU_HEADER_MACRO(0x4f)";
            break;
        }
        case NPL_ERSPAN_II_HEADER_ENE_MACRO:
        {
            return "NPL_ERSPAN_II_HEADER_ENE_MACRO(0x50)";
            break;
        }
        case NPL_FABRIC_ELEMENT_KEEPALIVE_ENE_MACRO:
        {
            return "NPL_FABRIC_ELEMENT_KEEPALIVE_ENE_MACRO(0x51)";
            break;
        }
        case NPL_FABRIC_ELEMENT_TS1_ENE_MACRO:
        {
            return "NPL_FABRIC_ELEMENT_TS1_ENE_MACRO(0x52)";
            break;
        }
        case NPL_FABRIC_ELEMENT_TS3_ENE_MACRO:
        {
            return "NPL_FABRIC_ELEMENT_TS3_ENE_MACRO(0x53)";
            break;
        }
        case NPL_FLB_FABRIC_HEADER_ENE_MACRO:
        {
            return "NPL_FLB_FABRIC_HEADER_ENE_MACRO(0x54)";
            break;
        }
        case NPL_FLB_MLP_FABRIC_HEADER_ENE_MACRO:
        {
            return "NPL_FLB_MLP_FABRIC_HEADER_ENE_MACRO(0x55)";
            break;
        }
        case NPL_GRE_MPLS_ENE_MACRO:
        {
            return "NPL_GRE_MPLS_ENE_MACRO(0x56)";
            break;
        }
        case NPL_GRE_NO_KEY_ENE_MACRO:
        {
            return "NPL_GRE_NO_KEY_ENE_MACRO(0x57)";
            break;
        }
        case NPL_GRE_WITH_SN_ENE_MACRO:
        {
            return "NPL_GRE_WITH_SN_ENE_MACRO(0x58)";
            break;
        }
        case NPL_IPV4_ENE_MACRO:
        {
            return "NPL_IPV4_ENE_MACRO(0x59)";
            break;
        }
        case NPL_IPV6_ENE_MACRO:
        {
            return "NPL_IPV6_ENE_MACRO(0x5a)";
            break;
        }
        case NPL_KEEPALIVE_FABRIC_HEADER_ENE_MACRO:
        {
            return "NPL_KEEPALIVE_FABRIC_HEADER_ENE_MACRO(0x5b)";
            break;
        }
        case NPL_KEEPALIVE_MLP_ENE_MACRO:
        {
            return "NPL_KEEPALIVE_MLP_ENE_MACRO(0x5c)";
            break;
        }
        case NPL_MMM_TM_HEADER_ENE_MACRO:
        {
            return "NPL_MMM_TM_HEADER_ENE_MACRO(0x5d)";
            break;
        }
        case NPL_MMM_TM_HEADER_WITH_SOFT_NPUH_ENE_MACRO:
        {
            return "NPL_MMM_TM_HEADER_WITH_SOFT_NPUH_ENE_MACRO(0x5e)";
            break;
        }
        case NPL_MPLS_IMPOSE_1_TO_4_FIRST_LABELS_ENE_MACRO:
        {
            return "NPL_MPLS_IMPOSE_1_TO_4_FIRST_LABELS_ENE_MACRO(0x5f)";
            break;
        }
        case NPL_MPLS_IMPOSE_3_TO_8_LABELS_ENE_MACRO:
        {
            return "NPL_MPLS_IMPOSE_3_TO_8_LABELS_ENE_MACRO(0x60)";
            break;
        }
        case NPL_MPLS_IMPOSE_INNER_AND_1_TO_4_LABELS_ENE_MACRO:
        {
            return "NPL_MPLS_IMPOSE_INNER_AND_1_TO_4_LABELS_ENE_MACRO(0x61)";
            break;
        }
        case NPL_MPLS_IMPOSE_INNER_LABEL_ENE_MACRO:
        {
            return "NPL_MPLS_IMPOSE_INNER_LABEL_ENE_MACRO(0x62)";
            break;
        }
        case NPL_MUM_TM_HEADER_ENE_MACRO:
        {
            return "NPL_MUM_TM_HEADER_ENE_MACRO(0x63)";
            break;
        }
        case NPL_MUM_TM_HEADER_WITH_SOFT_NPUH_ENE_MACRO:
        {
            return "NPL_MUM_TM_HEADER_WITH_SOFT_NPUH_ENE_MACRO(0x64)";
            break;
        }
        case NPL_NH_ETHERNET_NO_VLAN_ENE_MACRO:
        {
            return "NPL_NH_ETHERNET_NO_VLAN_ENE_MACRO(0x65)";
            break;
        }
        case NPL_NH_ETHERNET_NO_VLAN_INNER_VXLAN_ENE_MACRO:
        {
            return "NPL_NH_ETHERNET_NO_VLAN_INNER_VXLAN_ENE_MACRO(0x66)";
            break;
        }
        case NPL_NH_ETHERNET_WITH_ONE_VLAN_ENE_MACRO:
        {
            return "NPL_NH_ETHERNET_WITH_ONE_VLAN_ENE_MACRO(0x67)";
            break;
        }
        case NPL_NH_ETHERNET_WITH_TWO_VLAN_ENE_MACRO:
        {
            return "NPL_NH_ETHERNET_WITH_TWO_VLAN_ENE_MACRO(0x68)";
            break;
        }
        case NPL_NPU_HEADER_ENE_MACRO:
        {
            return "NPL_NPU_HEADER_ENE_MACRO(0x69)";
            break;
        }
        case NPL_NPU_HEADER_WITH_SOFT_NPUH_ENE_MACRO:
        {
            return "NPL_NPU_HEADER_WITH_SOFT_NPUH_ENE_MACRO(0x6a)";
            break;
        }
        case NPL_OAMP_PFC_ETH_ENE_MACRO:
        {
            return "NPL_OAMP_PFC_ETH_ENE_MACRO(0x6b)";
            break;
        }
        case NPL_OAMP_PUNT_ETH_ENE_MACRO:
        {
            return "NPL_OAMP_PUNT_ETH_ENE_MACRO(0x6c)";
            break;
        }
        case NPL_PUNT_VLAN_ENE_MACRO:
        {
            return "NPL_PUNT_VLAN_ENE_MACRO(0x6d)";
            break;
        }
        case NPL_PUSH_INJECT_ETH_HEADER_ENE_MACRO:
        {
            return "NPL_PUSH_INJECT_ETH_HEADER_ENE_MACRO(0x6e)";
            break;
        }
        case NPL_PUSH_INJECT_HEADER_ENE_MACRO:
        {
            return "NPL_PUSH_INJECT_HEADER_ENE_MACRO(0x6f)";
            break;
        }
        case NPL_PWE_NO_CW_WITH_FAT_ENE_MACRO:
        {
            return "NPL_PWE_NO_CW_WITH_FAT_ENE_MACRO(0x70)";
            break;
        }
        case NPL_PWE_WITH_CW_NO_FAT_ENE_MACRO:
        {
            return "NPL_PWE_WITH_CW_NO_FAT_ENE_MACRO(0x71)";
            break;
        }
        case NPL_PWE_WITH_CW_WITH_FAT_ENE_MACRO:
        {
            return "NPL_PWE_WITH_CW_WITH_FAT_ENE_MACRO(0x72)";
            break;
        }
        case NPL_REMOVE_PUNT_HEADER_ENE_MACRO:
        {
            return "NPL_REMOVE_PUNT_HEADER_ENE_MACRO(0x73)";
            break;
        }
        case NPL_SN_PLB_FABRIC_HEADER_ONE_PACKET_ENE_MACRO:
        {
            return "NPL_SN_PLB_FABRIC_HEADER_ONE_PACKET_ENE_MACRO(0x74)";
            break;
        }
        case NPL_SN_PLB_FABRIC_HEADER_TWO_PACKETS_ENE_MACRO:
        {
            return "NPL_SN_PLB_FABRIC_HEADER_TWO_PACKETS_ENE_MACRO(0x75)";
            break;
        }
        case NPL_TS1_PLB_FABRIC_HEADER_ONE_PACKET_ENE_MACRO:
        {
            return "NPL_TS1_PLB_FABRIC_HEADER_ONE_PACKET_ENE_MACRO(0x76)";
            break;
        }
        case NPL_TS1_PLB_FABRIC_HEADER_TWO_PACKETS_ENE_MACRO:
        {
            return "NPL_TS1_PLB_FABRIC_HEADER_TWO_PACKETS_ENE_MACRO(0x77)";
            break;
        }
        case NPL_TS3_PLB_FABRIC_HEADER_ONE_PACKET_ENE_MACRO:
        {
            return "NPL_TS3_PLB_FABRIC_HEADER_ONE_PACKET_ENE_MACRO(0x78)";
            break;
        }
        case NPL_TS3_PLB_FABRIC_HEADER_TWO_PACKETS_ENE_MACRO:
        {
            return "NPL_TS3_PLB_FABRIC_HEADER_TWO_PACKETS_ENE_MACRO(0x79)";
            break;
        }
        case NPL_TX_INJECT_HEADER_AND_ETH_HEADER_ENE_MACRO:
        {
            return "NPL_TX_INJECT_HEADER_AND_ETH_HEADER_ENE_MACRO(0x7a)";
            break;
        }
        case NPL_TX_INJECT_HEADER_WITH_NPUH_ENE_MACRO:
        {
            return "NPL_TX_INJECT_HEADER_WITH_NPUH_ENE_MACRO(0x7b)";
            break;
        }
        case NPL_TX_PUNT_ETH_ENE_MACRO:
        {
            return "NPL_TX_PUNT_ETH_ENE_MACRO(0x7c)";
            break;
        }
        case NPL_TX_PUNT_ETH_NO_VLAN_ENE_MACRO:
        {
            return "NPL_TX_PUNT_ETH_NO_VLAN_ENE_MACRO(0x7d)";
            break;
        }
        case NPL_TX_PUNT_HEADER_ENE_MACRO:
        {
            return "NPL_TX_PUNT_HEADER_ENE_MACRO(0x7e)";
            break;
        }
        case NPL_TX_PUNT_METADATA_ENE_MACRO:
        {
            return "NPL_TX_PUNT_METADATA_ENE_MACRO(0x7f)";
            break;
        }
        case NPL_TX_PUNT_NPU_HOST_HEADER_ENE_MACRO:
        {
            return "NPL_TX_PUNT_NPU_HOST_HEADER_ENE_MACRO(0x80)";
            break;
        }
        case NPL_UDP_ENE_MACRO:
        {
            return "NPL_UDP_ENE_MACRO(0x81)";
            break;
        }
        case NPL_UNICAST_FLB_TM_HEADER_ENE_MACRO:
        {
            return "NPL_UNICAST_FLB_TM_HEADER_ENE_MACRO(0x82)";
            break;
        }
        case NPL_UNICAST_FLB_TM_HEADER_WITH_SOFT_NPUH_ENE_MACRO:
        {
            return "NPL_UNICAST_FLB_TM_HEADER_WITH_SOFT_NPUH_ENE_MACRO(0x83)";
            break;
        }
        case NPL_UNICAST_PLB_TM_HEADER_ENE_MACRO:
        {
            return "NPL_UNICAST_PLB_TM_HEADER_ENE_MACRO(0x84)";
            break;
        }
        case NPL_UNICAST_PLB_TM_HEADER_WITH_SOFT_NPUH_ENE_MACRO:
        {
            return "NPL_UNICAST_PLB_TM_HEADER_WITH_SOFT_NPUH_ENE_MACRO(0x85)";
            break;
        }
        case NPL_VPN_OR_6PE_LABEL_ENE_MACRO:
        {
            return "NPL_VPN_OR_6PE_LABEL_ENE_MACRO(0x86)";
            break;
        }
        case NPL_VXLAN_UDP_ENE_MACRO:
        {
            return "NPL_VXLAN_UDP_ENE_MACRO(0x87)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ene_macro_ids_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ene_seven_labels_jump_offset_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SEVENTH_LABEL_NO_JUMP:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SEVENTH_LABEL_NO_JUMP(0x0)";
            break;
        }
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SEVENTH_LABEL:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SEVENTH_LABEL(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ene_seven_labels_jump_offset_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ene_six_labels_jump_offset_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SIXTH_LABEL_NO_JUMP:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SIXTH_LABEL_NO_JUMP(0x0)";
            break;
        }
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SIXTH_LABEL:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SIXTH_LABEL(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ene_six_labels_jump_offset_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ene_three_labels_jump_offset_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_THIRD_LABEL_NO_JUMP:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_THIRD_LABEL_NO_JUMP(0x0)";
            break;
        }
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_THIRD_LABEL:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_THIRD_LABEL(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ene_three_labels_jump_offset_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ene_vid2_jump_offset_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENE_JUMP_OFFSET_PUSH_TWO_VLAN:
        {
            return "NPL_ENE_JUMP_OFFSET_PUSH_TWO_VLAN(0x0)";
            break;
        }
        case NPL_ENE_JUMP_OFFSET_PUSH_ONE_VLAN_ONLY:
        {
            return "NPL_ENE_JUMP_OFFSET_PUSH_ONE_VLAN_ONLY(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ene_vid2_jump_offset_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_eth_mep_mapping_selector_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MEP_MAPPING_SELECTOR_CCM_UP:
        {
            return "NPL_MEP_MAPPING_SELECTOR_CCM_UP(0x0)";
            break;
        }
        case NPL_MEP_MAPPING_SELECTOR_CCM_DOWN:
        {
            return "NPL_MEP_MAPPING_SELECTOR_CCM_DOWN(0x1)";
            break;
        }
        case NPL_MEP_MAPPING_SELECTOR_NOT_CCM_UP:
        {
            return "NPL_MEP_MAPPING_SELECTOR_NOT_CCM_UP(0x2)";
            break;
        }
        case NPL_MEP_MAPPING_SELECTOR_NOT_CCM_DOWN:
        {
            return "NPL_MEP_MAPPING_SELECTOR_NOT_CCM_DOWN(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_eth_mep_mapping_selector_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_eth_oam_counter_stamp_commands_e enum_instance)
{
    switch(enum_instance) {
        case NPL_COUNTER_STAMP_NONE:
        {
            return "NPL_COUNTER_STAMP_NONE(0x0)";
            break;
        }
        case NPL_COUNTER_STAMP_LMR:
        {
            return "NPL_COUNTER_STAMP_LMR(0xfff)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_eth_oam_counter_stamp_commands_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_eth_oam_da_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ETH_OAM_DA_UC:
        {
            return "NPL_ETH_OAM_DA_UC(0x0)";
            break;
        }
        case NPL_ETH_OAM_DA_MC:
        {
            return "NPL_ETH_OAM_DA_MC(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_eth_oam_da_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_eth_oam_opcode_e enum_instance)
{
    switch(enum_instance) {
        case NPL_OAM_OPCODE_CCM:
        {
            return "NPL_OAM_OPCODE_CCM(0x1)";
            break;
        }
        case NPL_OAM_OPCODE_LBM:
        {
            return "NPL_OAM_OPCODE_LBM(0x3)";
            break;
        }
        case NPL_OAM_OPCODE_TST:
        {
            return "NPL_OAM_OPCODE_TST(0x25)";
            break;
        }
        case NPL_OAM_OPCODE_LMM:
        {
            return "NPL_OAM_OPCODE_LMM(0x2b)";
            break;
        }
        case NPL_OAM_OPCODE_LMR:
        {
            return "NPL_OAM_OPCODE_LMR(0x2a)";
            break;
        }
        case NPL_OAM_OPCODE_1DM:
        {
            return "NPL_OAM_OPCODE_1DM(0x2d)";
            break;
        }
        case NPL_OAM_OPCODE_DMM:
        {
            return "NPL_OAM_OPCODE_DMM(0x2f)";
            break;
        }
        case NPL_OAM_OPCODE_DMR:
        {
            return "NPL_OAM_OPCODE_DMR(0x2e)";
            break;
        }
        case NPL_OAM_OPCODE_SLM:
        {
            return "NPL_OAM_OPCODE_SLM(0x37)";
            break;
        }
        case NPL_OAM_OPCODE_SLR:
        {
            return "NPL_OAM_OPCODE_SLR(0x36)";
            break;
        }
        case NPL_OAM_OPCODE_LBR:
        {
            return "NPL_OAM_OPCODE_LBR(0x2)";
            break;
        }
        case NPL_OAM_OPCODE_LTR:
        {
            return "NPL_OAM_OPCODE_LTR(0x4)";
            break;
        }
        case NPL_OAM_OPCODE_LTM:
        {
            return "NPL_OAM_OPCODE_LTM(0x5)";
            break;
        }
        case NPL_OAM_OPCODE_AIS:
        {
            return "NPL_OAM_OPCODE_AIS(0x21)";
            break;
        }
        case NPL_OAM_OPCODE_LCK:
        {
            return "NPL_OAM_OPCODE_LCK(0x23)";
            break;
        }
        case NPL_OAM_OPCODE_APS:
        {
            return "NPL_OAM_OPCODE_APS(0x27)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_eth_oam_opcode_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_eth_oam_time_stamp_commands_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TIME_STAMP_NONE:
        {
            return "NPL_TIME_STAMP_NONE(0x0)";
            break;
        }
        case NPL_TIME_STAMP_DMR:
        {
            return "NPL_TIME_STAMP_DMR(0xfff)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_eth_oam_time_stamp_commands_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_eth_table_index_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ETH_RTF_DB1_160_TABLE:
        {
            return "NPL_ETH_RTF_DB1_160_TABLE(0x0)";
            break;
        }
        case NPL_ETH_RTF_DB2_160_TABLE:
        {
            return "NPL_ETH_RTF_DB2_160_TABLE(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_eth_table_index_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ether_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ETHER_TYPE_IPV4:
        {
            return "NPL_ETHER_TYPE_IPV4(0x800)";
            break;
        }
        case NPL_ETHER_TYPE_IPV6:
        {
            return "NPL_ETHER_TYPE_IPV6(0x86dd)";
            break;
        }
        case NPL_ETHER_TYPE_PUNT_MAC:
        {
            return "NPL_ETHER_TYPE_PUNT_MAC(0x7102)";
            break;
        }
        case NPL_ETHER_TYPE_INJECT_MAC:
        {
            return "NPL_ETHER_TYPE_INJECT_MAC(0x7103)";
            break;
        }
        case NPL_ETHER_TYPE_SVL:
        {
            return "NPL_ETHER_TYPE_SVL(0x7104)";
            break;
        }
        case NPL_ETHER_TYPE_ERSPAN_II:
        {
            return "NPL_ETHER_TYPE_ERSPAN_II(0x88be)";
            break;
        }
        case NPL_ETHER_TYPE_ARP:
        {
            return "NPL_ETHER_TYPE_ARP(0x806)";
            break;
        }
        case NPL_ETHER_TYPE_MPLS_UC:
        {
            return "NPL_ETHER_TYPE_MPLS_UC(0x8847)";
            break;
        }
        case NPL_ETHER_TYPE_FLOW_CNTRL:
        {
            return "NPL_ETHER_TYPE_FLOW_CNTRL(0x8808)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ether_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ethernet_rate_limiter_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ETH_RATE_LIMITER_BC:
        {
            return "NPL_ETH_RATE_LIMITER_BC(0x0)";
            break;
        }
        case NPL_ETH_RATE_LIMITER_UNKNOWN_MC:
        {
            return "NPL_ETH_RATE_LIMITER_UNKNOWN_MC(0x1)";
            break;
        }
        case NPL_ETH_RATE_LIMITER_UNKNOWN_UC:
        {
            return "NPL_ETH_RATE_LIMITER_UNKNOWN_UC(0x2)";
            break;
        }
        case NPL_ETH_RATE_LIMITER_KNOWN_MC:
        {
            return "NPL_ETH_RATE_LIMITER_KNOWN_MC(0x3)";
            break;
        }
        case NPL_ETH_RATE_LIMITER_KNOWN_UC:
        {
            return "NPL_ETH_RATE_LIMITER_KNOWN_UC(0x4)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ethernet_rate_limiter_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fabric_context_e enum_instance)
{
    switch(enum_instance) {
        case NPL_FABRIC_CONTEXT_PLB_UC_H:
        {
            return "NPL_FABRIC_CONTEXT_PLB_UC_H(0x0)";
            break;
        }
        case NPL_FABRIC_CONTEXT_PLB_UC_L:
        {
            return "NPL_FABRIC_CONTEXT_PLB_UC_L(0x1)";
            break;
        }
        case NPL_FABRIC_CONTEXT_PLB_MC:
        {
            return "NPL_FABRIC_CONTEXT_PLB_MC(0x2)";
            break;
        }
        case NPL_FABRIC_CONTEXT_FLB:
        {
            return "NPL_FABRIC_CONTEXT_FLB(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fabric_context_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fabric_header_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_FABRIC_HEADER_TYPE_NPU_WITH_IVE:
        {
            return "NPL_FABRIC_HEADER_TYPE_NPU_WITH_IVE(0x0)";
            break;
        }
        case NPL_FABRIC_HEADER_TYPE_NPU_NO_IVE:
        {
            return "NPL_FABRIC_HEADER_TYPE_NPU_NO_IVE(0x1)";
            break;
        }
        case NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET:
        {
            return "NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_ONE_PACKET(0x2)";
            break;
        }
        case NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS:
        {
            return "NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS(0x3)";
            break;
        }
        case NPL_FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET:
        {
            return "NPL_FABRIC_HEADER_TYPE_TS3_PLB_ONE_PACKET(0x4)";
            break;
        }
        case NPL_FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS:
        {
            return "NPL_FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS(0x5)";
            break;
        }
        case NPL_FABRIC_HEADER_TYPE_SN_TS_PLB_KEEPALIVE:
        {
            return "NPL_FABRIC_HEADER_TYPE_SN_TS_PLB_KEEPALIVE(0x6)";
            break;
        }
        case NPL_FABRIC_HEADER_TYPE_FLB:
        {
            return "NPL_FABRIC_HEADER_TYPE_FLB(0x7)";
            break;
        }
        case NPL_FABRIC_HEADER_TYPE_PEER_DELAY_REQUEST:
        {
            return "NPL_FABRIC_HEADER_TYPE_PEER_DELAY_REQUEST(0x8)";
            break;
        }
        case NPL_FABRIC_HEADER_TYPE_PEER_DELAY_REPLY:
        {
            return "NPL_FABRIC_HEADER_TYPE_PEER_DELAY_REPLY(0x9)";
            break;
        }
        case NPL_FABRIC_HEADER_TYPE_FABRIC_TIME_SYNC:
        {
            return "NPL_FABRIC_HEADER_TYPE_FABRIC_TIME_SYNC(0xa)";
            break;
        }
        case NPL_FABRIC_HEADER_TYPE_CREDIT_SCHEDULER_CONTROL:
        {
            return "NPL_FABRIC_HEADER_TYPE_CREDIT_SCHEDULER_CONTROL(0xb)";
            break;
        }
        case NPL_FABRIC_HEADER_TYPE_FABRIC_ROUTING_PROTOCOL:
        {
            return "NPL_FABRIC_HEADER_TYPE_FABRIC_ROUTING_PROTOCOL(0xc)";
            break;
        }
        case NPL_FABRIC_HEADER_TYPE_SOURCE_ROUTED:
        {
            return "NPL_FABRIC_HEADER_TYPE_SOURCE_ROUTED(0xd)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fabric_header_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fabric_oq_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_FABRIC_OQ_TYPE_PLB_MC:
        {
            return "NPL_FABRIC_OQ_TYPE_PLB_MC(0x0)";
            break;
        }
        case NPL_FABRIC_OQ_TYPE_FLB_MC_LOW:
        {
            return "NPL_FABRIC_OQ_TYPE_FLB_MC_LOW(0x1)";
            break;
        }
        case NPL_FABRIC_OQ_TYPE_FLB_MC_HIGH:
        {
            return "NPL_FABRIC_OQ_TYPE_FLB_MC_HIGH(0x2)";
            break;
        }
        case NPL_FABRIC_OQ_TYPE_FLB_UC_LOW:
        {
            return "NPL_FABRIC_OQ_TYPE_FLB_UC_LOW(0x3)";
            break;
        }
        case NPL_FABRIC_OQ_TYPE_FLB_UC_HIGH:
        {
            return "NPL_FABRIC_OQ_TYPE_FLB_UC_HIGH(0x4)";
            break;
        }
        case NPL_FABRIC_OQ_TYPE_PLB_UC_LOW:
        {
            return "NPL_FABRIC_OQ_TYPE_PLB_UC_LOW(0x5)";
            break;
        }
        case NPL_FABRIC_OQ_TYPE_PLB_UC_HIGH:
        {
            return "NPL_FABRIC_OQ_TYPE_PLB_UC_HIGH(0x6)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fabric_oq_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fabric_port_can_reach_device_e enum_instance)
{
    switch(enum_instance) {
        case NPL_FABRIC_PORT_CAN_REACH_DEVICE_FALSE:
        {
            return "NPL_FABRIC_PORT_CAN_REACH_DEVICE_FALSE(0x0)";
            break;
        }
        case NPL_FABRIC_PORT_CAN_REACH_DEVICE_TRUE:
        {
            return "NPL_FABRIC_PORT_CAN_REACH_DEVICE_TRUE(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fabric_port_can_reach_device_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fabric_port_mode_e enum_instance)
{
    switch(enum_instance) {
        case NPL_FABRIC_PORT_100G_MODE:
        {
            return "NPL_FABRIC_PORT_100G_MODE(0x0)";
            break;
        }
        case NPL_FABRIC_PORT_200G_MODE:
        {
            return "NPL_FABRIC_PORT_200G_MODE(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fabric_port_mode_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fabric_ts_plb_ctxt_e enum_instance)
{
    switch(enum_instance) {
        case NPL_FABRIC_TS_PLB_CTXT_UC_HIGH:
        {
            return "NPL_FABRIC_TS_PLB_CTXT_UC_HIGH(0x0)";
            break;
        }
        case NPL_FABRIC_TS_PLB_CTXT_UC_LOW:
        {
            return "NPL_FABRIC_TS_PLB_CTXT_UC_LOW(0x1)";
            break;
        }
        case NPL_FABRIC_TS_PLB_CTXT_MC:
        {
            return "NPL_FABRIC_TS_PLB_CTXT_MC(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fabric_ts_plb_ctxt_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fec_entry_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENTRY_TYPE_FEC_FEC_DESTINATION:
        {
            return "NPL_ENTRY_TYPE_FEC_FEC_DESTINATION(0x0)";
            break;
        }
        case NPL_ENTRY_TYPE_FEC_DESTINATION1:
        {
            return "NPL_ENTRY_TYPE_FEC_DESTINATION1(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fec_entry_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fi_hardwired_logic_e enum_instance)
{
    switch(enum_instance) {
        case NPL_FI_HARDWIRED_LOGIC_ETHERNET:
        {
            return "NPL_FI_HARDWIRED_LOGIC_ETHERNET(0x0)";
            break;
        }
        case NPL_FI_HARDWIRED_LOGIC_VLAN:
        {
            return "NPL_FI_HARDWIRED_LOGIC_VLAN(0x1)";
            break;
        }
        case NPL_FI_HARDWIRED_LOGIC_IPV4:
        {
            return "NPL_FI_HARDWIRED_LOGIC_IPV4(0x2)";
            break;
        }
        case NPL_FI_HARDWIRED_LOGIC_MPLS:
        {
            return "NPL_FI_HARDWIRED_LOGIC_MPLS(0x3)";
            break;
        }
        case NPL_FI_HARDWIRED_LOGIC_NONE:
        {
            return "NPL_FI_HARDWIRED_LOGIC_NONE(0x4)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fi_hardwired_logic_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fi_hardwired_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_FI_ETHERNET_HARDWIRED:
        {
            return "NPL_FI_ETHERNET_HARDWIRED(0x0)";
            break;
        }
        case NPL_FI_IPV4_HARDWIRED:
        {
            return "NPL_FI_IPV4_HARDWIRED(0x1)";
            break;
        }
        case NPL_FI_NO_HARDWIRED:
        {
            return "NPL_FI_NO_HARDWIRED(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fi_hardwired_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fi_macro_ids_e enum_instance)
{
    switch(enum_instance) {
        case NPL_FI_MACRO_ID_ETH:
        {
            return "NPL_FI_MACRO_ID_ETH(0x0)";
            break;
        }
        case NPL_FI_MACRO_ID_VLAN_0:
        {
            return "NPL_FI_MACRO_ID_VLAN_0(0x1)";
            break;
        }
        case NPL_FI_MACRO_ID_VLAN_1:
        {
            return "NPL_FI_MACRO_ID_VLAN_1(0x2)";
            break;
        }
        case NPL_FI_MACRO_ID_ETHERTYPE:
        {
            return "NPL_FI_MACRO_ID_ETHERTYPE(0x7)";
            break;
        }
        case NPL_FI_MACRO_ID_ARP:
        {
            return "NPL_FI_MACRO_ID_ARP(0x3)";
            break;
        }
        case NPL_FI_MACRO_ID_IPV4:
        {
            return "NPL_FI_MACRO_ID_IPV4(0x4)";
            break;
        }
        case NPL_FI_MACRO_ID_IPV6_FIRST:
        {
            return "NPL_FI_MACRO_ID_IPV6_FIRST(0x5)";
            break;
        }
        case NPL_FI_MACRO_ID_IPV6_SECOND:
        {
            return "NPL_FI_MACRO_ID_IPV6_SECOND(0xf)";
            break;
        }
        case NPL_FI_MACRO_ID_IPV6_EH:
        {
            return "NPL_FI_MACRO_ID_IPV6_EH(0x12)";
            break;
        }
        case NPL_FI_MACRO_ID_IPV6_FRAG_EH:
        {
            return "NPL_FI_MACRO_ID_IPV6_FRAG_EH(0x13)";
            break;
        }
        case NPL_FI_MACRO_ID_GRE:
        {
            return "NPL_FI_MACRO_ID_GRE(0x6)";
            break;
        }
        case NPL_FI_MACRO_ID_MPLS_0:
        {
            return "NPL_FI_MACRO_ID_MPLS_0(0x8)";
            break;
        }
        case NPL_FI_MACRO_ID_MPLS_1:
        {
            return "NPL_FI_MACRO_ID_MPLS_1(0x9)";
            break;
        }
        case NPL_FI_MACRO_ID_MPLS_2:
        {
            return "NPL_FI_MACRO_ID_MPLS_2(0xa)";
            break;
        }
        case NPL_FI_MACRO_ID_MPLS_3_SPECULATIVE:
        {
            return "NPL_FI_MACRO_ID_MPLS_3_SPECULATIVE(0xb)";
            break;
        }
        case NPL_FI_MACRO_ID_MPLS_EL:
        {
            return "NPL_FI_MACRO_ID_MPLS_EL(0x10)";
            break;
        }
        case NPL_FI_MACRO_ID_UDP:
        {
            return "NPL_FI_MACRO_ID_UDP(0xc)";
            break;
        }
        case NPL_FI_MACRO_ID_IP_OVER_UDP:
        {
            return "NPL_FI_MACRO_ID_IP_OVER_UDP(0x22)";
            break;
        }
        case NPL_FI_MACRO_ID_TCP:
        {
            return "NPL_FI_MACRO_ID_TCP(0xd)";
            break;
        }
        case NPL_FI_MACRO_ID_VXLAN:
        {
            return "NPL_FI_MACRO_ID_VXLAN(0xe)";
            break;
        }
        case NPL_FI_MACRO_ID_MACSEC:
        {
            return "NPL_FI_MACRO_ID_MACSEC(0x11)";
            break;
        }
        case NPL_FI_MACRO_ID_SYSTEM_INJECT:
        {
            return "NPL_FI_MACRO_ID_SYSTEM_INJECT(0x14)";
            break;
        }
        case NPL_FI_MACRO_ID_EXTENDED_VLAN:
        {
            return "NPL_FI_MACRO_ID_EXTENDED_VLAN(0x15)";
            break;
        }
        case NPL_FI_MACRO_ID_SYSTEM_PUNT_PHASE1:
        {
            return "NPL_FI_MACRO_ID_SYSTEM_PUNT_PHASE1(0x16)";
            break;
        }
        case NPL_FI_MACRO_ID_SYSTEM_PUNT_PHASE2:
        {
            return "NPL_FI_MACRO_ID_SYSTEM_PUNT_PHASE2(0x17)";
            break;
        }
        case NPL_FI_MACRO_ID_FABRIC:
        {
            return "NPL_FI_MACRO_ID_FABRIC(0x18)";
            break;
        }
        case NPL_FI_MACRO_ID_TM:
        {
            return "NPL_FI_MACRO_ID_TM(0x19)";
            break;
        }
        case NPL_FI_MACRO_ID_CFM:
        {
            return "NPL_FI_MACRO_ID_CFM(0x1a)";
            break;
        }
        case NPL_FI_MACRO_ID_PTP:
        {
            return "NPL_FI_MACRO_ID_PTP(0x1b)";
            break;
        }
        case NPL_FI_MACRO_ID_OAMP:
        {
            return "NPL_FI_MACRO_ID_OAMP(0x1c)";
            break;
        }
        case NPL_FI_MACRO_ID_ICMP:
        {
            return "NPL_FI_MACRO_ID_ICMP(0x1d)";
            break;
        }
        case NPL_FI_MACRO_ID_PFC:
        {
            return "NPL_FI_MACRO_ID_PFC(0x1e)";
            break;
        }
        case NPL_FI_MACRO_ID_IGMP:
        {
            return "NPL_FI_MACRO_ID_IGMP(0x1f)";
            break;
        }
        case NPL_FI_MACRO_ID_GTP:
        {
            return "NPL_FI_MACRO_ID_GTP(0x20)";
            break;
        }
        case NPL_FI_MACRO_ID_SVL_TM:
        {
            return "NPL_FI_MACRO_ID_SVL_TM(0x21)";
            break;
        }
        case NPL_FI_MACRO_ID_UNDEF:
        {
            return "NPL_FI_MACRO_ID_UNDEF(0x3f)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fi_macro_ids_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd0_acl_db_ids_t enum_instance)
{
    switch(enum_instance) {
        case NPL_FWD0_LPTS_TABLE_ID_IPV6:
        {
            return "NPL_FWD0_LPTS_TABLE_ID_IPV6(0xd)";
            break;
        }
        case NPL_FWD0_LPTS_TABLE_ID_IPV4:
        {
            return "NPL_FWD0_LPTS_TABLE_ID_IPV4(0xc)";
            break;
        }
        case NPL_FWD0_INGRESS_ACL_RTF_DB1_160:
        {
            return "NPL_FWD0_INGRESS_ACL_RTF_DB1_160(0x2)";
            break;
        }
        case NPL_FWD0_INGRESS_ACL_RTF_DB1_320:
        {
            return "NPL_FWD0_INGRESS_ACL_RTF_DB1_320(0x3)";
            break;
        }
        case NPL_FWD0_INGRESS_ACL_RTF_DB2_160:
        {
            return "NPL_FWD0_INGRESS_ACL_RTF_DB2_160(0x4)";
            break;
        }
        case NPL_FWD0_INGRESS_ACL_RTF_DB2_320:
        {
            return "NPL_FWD0_INGRESS_ACL_RTF_DB2_320(0x5)";
            break;
        }
        case NPL_FWD0_INGRESS_ACL_RTF_DB3_160:
        {
            return "NPL_FWD0_INGRESS_ACL_RTF_DB3_160(0x6)";
            break;
        }
        case NPL_FWD0_INGRESS_ACL_RTF_DB3_320:
        {
            return "NPL_FWD0_INGRESS_ACL_RTF_DB3_320(0x7)";
            break;
        }
        case NPL_FWD0_INGRESS_ACL_RTF_DB4_160:
        {
            return "NPL_FWD0_INGRESS_ACL_RTF_DB4_160(0x8)";
            break;
        }
        case NPL_FWD0_INGRESS_ACL_RTF_DB4_320:
        {
            return "NPL_FWD0_INGRESS_ACL_RTF_DB4_320(0x9)";
            break;
        }
        case NPL_FWD0_INGRESS_ACL_ETH_RTF_DB1_160:
        {
            return "NPL_FWD0_INGRESS_ACL_ETH_RTF_DB1_160(0xa)";
            break;
        }
        case NPL_FWD0_INGRESS_ACL_ETH_RTF_DB2_160:
        {
            return "NPL_FWD0_INGRESS_ACL_ETH_RTF_DB2_160(0xe)";
            break;
        }
        case NPL_FWD0_INGRESS_SGACL_DB_160:
        {
            return "NPL_FWD0_INGRESS_SGACL_DB_160(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd0_acl_db_ids_t");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd0_table_index_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RTF_DB1_160_FWD0_TABLE:
        {
            return "NPL_RTF_DB1_160_FWD0_TABLE(0x0)";
            break;
        }
        case NPL_RTF_DB2_160_FWD0_TABLE:
        {
            return "NPL_RTF_DB2_160_FWD0_TABLE(0x1)";
            break;
        }
        case NPL_RTF_DB3_160_FWD0_TABLE:
        {
            return "NPL_RTF_DB3_160_FWD0_TABLE(0x2)";
            break;
        }
        case NPL_RTF_DB4_160_FWD0_TABLE:
        {
            return "NPL_RTF_DB4_160_FWD0_TABLE(0x3)";
            break;
        }
        case NPL_RTF_DB1_320_FWD0_TABLE:
        {
            return "NPL_RTF_DB1_320_FWD0_TABLE(0x4)";
            break;
        }
        case NPL_RTF_DB2_320_FWD0_TABLE:
        {
            return "NPL_RTF_DB2_320_FWD0_TABLE(0x5)";
            break;
        }
        case NPL_RTF_DB3_320_FWD0_TABLE:
        {
            return "NPL_RTF_DB3_320_FWD0_TABLE(0x6)";
            break;
        }
        case NPL_RTF_DB4_320_FWD0_TABLE:
        {
            return "NPL_RTF_DB4_320_FWD0_TABLE(0x7)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd0_table_index_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd1_acl_db_ids_t enum_instance)
{
    switch(enum_instance) {
        case NPL_FWD1_LPTS_TABLE_ID_IPV6:
        {
            return "NPL_FWD1_LPTS_TABLE_ID_IPV6(0xd)";
            break;
        }
        case NPL_FWD1_LPTS_TABLE_ID_IPV4:
        {
            return "NPL_FWD1_LPTS_TABLE_ID_IPV4(0xc)";
            break;
        }
        case NPL_FWD1_INGRESS_ACL_RTF_DB1_160:
        {
            return "NPL_FWD1_INGRESS_ACL_RTF_DB1_160(0x2)";
            break;
        }
        case NPL_FWD1_INGRESS_ACL_RTF_DB1_320:
        {
            return "NPL_FWD1_INGRESS_ACL_RTF_DB1_320(0x3)";
            break;
        }
        case NPL_FWD1_INGRESS_ACL_RTF_DB2_160:
        {
            return "NPL_FWD1_INGRESS_ACL_RTF_DB2_160(0x4)";
            break;
        }
        case NPL_FWD1_INGRESS_ACL_RTF_DB2_320:
        {
            return "NPL_FWD1_INGRESS_ACL_RTF_DB2_320(0x5)";
            break;
        }
        case NPL_FWD1_INGRESS_ACL_RTF_DB3_160:
        {
            return "NPL_FWD1_INGRESS_ACL_RTF_DB3_160(0x6)";
            break;
        }
        case NPL_FWD1_INGRESS_ACL_RTF_DB3_320:
        {
            return "NPL_FWD1_INGRESS_ACL_RTF_DB3_320(0x7)";
            break;
        }
        case NPL_FWD1_INGRESS_ACL_RTF_DB4_160:
        {
            return "NPL_FWD1_INGRESS_ACL_RTF_DB4_160(0x8)";
            break;
        }
        case NPL_FWD1_INGRESS_ACL_RTF_DB4_320:
        {
            return "NPL_FWD1_INGRESS_ACL_RTF_DB4_320(0x9)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd1_acl_db_ids_t");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd1_table_index_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RTF_DB1_160_FWD1_TABLE:
        {
            return "NPL_RTF_DB1_160_FWD1_TABLE(0x0)";
            break;
        }
        case NPL_RTF_DB2_160_FWD1_TABLE:
        {
            return "NPL_RTF_DB2_160_FWD1_TABLE(0x1)";
            break;
        }
        case NPL_RTF_DB3_160_FWD1_TABLE:
        {
            return "NPL_RTF_DB3_160_FWD1_TABLE(0x2)";
            break;
        }
        case NPL_RTF_DB4_160_FWD1_TABLE:
        {
            return "NPL_RTF_DB4_160_FWD1_TABLE(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd1_table_index_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd_bucket_a_lu_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LU_A_CENTRAL_TCAM_F0:
        {
            return "NPL_LU_A_CENTRAL_TCAM_F0(0x1)";
            break;
        }
        case NPL_LU_A_CENTRAL_TCAM_F0_EXT:
        {
            return "NPL_LU_A_CENTRAL_TCAM_F0_EXT(0x2)";
            break;
        }
        case NPL_LU_A_CENTRAL_EM_COMPOUND:
        {
            return "NPL_LU_A_CENTRAL_EM_COMPOUND(0x3)";
            break;
        }
        case NPL_LU_A_CENTRAL_LPM_COMPOUND:
        {
            return "NPL_LU_A_CENTRAL_LPM_COMPOUND(0x4)";
            break;
        }
        case NPL_LU_A_RESOLUTION0_COMPOUND:
        {
            return "NPL_LU_A_RESOLUTION0_COMPOUND(0x5)";
            break;
        }
        case NPL_LU_A_FWD_NOP:
        {
            return "NPL_LU_A_FWD_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd_bucket_a_lu_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd_bucket_a_result_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RES_A_CENTRAL_TCAM_F0:
        {
            return "NPL_RES_A_CENTRAL_TCAM_F0(0x1)";
            break;
        }
        case NPL_RES_A_CENTRAL_EM_COMPOUND:
        {
            return "NPL_RES_A_CENTRAL_EM_COMPOUND(0x2)";
            break;
        }
        case NPL_RES_A_CENTRAL_LPM_COMPOUND:
        {
            return "NPL_RES_A_CENTRAL_LPM_COMPOUND(0x3)";
            break;
        }
        case NPL_RES_A_FWD_FRAGMENT:
        {
            return "NPL_RES_A_FWD_FRAGMENT(0x4)";
            break;
        }
        case NPL_RES_A_FWD_NOP:
        {
            return "NPL_RES_A_FWD_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd_bucket_a_result_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd_bucket_b_lu_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LU_B_CENTRAL_TCAM_F1:
        {
            return "NPL_LU_B_CENTRAL_TCAM_F1(0x1)";
            break;
        }
        case NPL_LU_B_CENTRAL_TCAM_F1_EXT:
        {
            return "NPL_LU_B_CENTRAL_TCAM_F1_EXT(0x2)";
            break;
        }
        case NPL_LU_B_CENTRAL_EM_LPM_ACC_BOTH_COMPOUND:
        {
            return "NPL_LU_B_CENTRAL_EM_LPM_ACC_BOTH_COMPOUND(0x3)";
            break;
        }
        case NPL_LU_B_CENTRAL_EM_LPM_LPM_ONLY_COMPOUND:
        {
            return "NPL_LU_B_CENTRAL_EM_LPM_LPM_ONLY_COMPOUND(0x4)";
            break;
        }
        case NPL_LU_B_CENTRAL_EM_LPM_EM_ONLY_COMPOUND:
        {
            return "NPL_LU_B_CENTRAL_EM_LPM_EM_ONLY_COMPOUND(0x5)";
            break;
        }
        case NPL_LU_B_RESOLUTION1_COMPOUND:
        {
            return "NPL_LU_B_RESOLUTION1_COMPOUND(0x6)";
            break;
        }
        case NPL_LU_B_FWD_NOP:
        {
            return "NPL_LU_B_FWD_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd_bucket_b_lu_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd_bucket_b_result_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RES_B_CENTRAL_TCAM_F1:
        {
            return "NPL_RES_B_CENTRAL_TCAM_F1(0x1)";
            break;
        }
        case NPL_RES_B_CENTRAL_EM_LPM_COMPOUND:
        {
            return "NPL_RES_B_CENTRAL_EM_LPM_COMPOUND(0x2)";
            break;
        }
        case NPL_RES_B_RESOLUTION_COMPOUND:
        {
            return "NPL_RES_B_RESOLUTION_COMPOUND(0x3)";
            break;
        }
        case NPL_RES_B_FWD_NOP:
        {
            return "NPL_RES_B_FWD_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd_bucket_b_result_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd_bucket_c_lu_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LU_C_CENTRAL_EM_COMPOUND:
        {
            return "NPL_LU_C_CENTRAL_EM_COMPOUND(0x1)";
            break;
        }
        case NPL_LU_C_CENTRAL_LPM_COMPOUND:
        {
            return "NPL_LU_C_CENTRAL_LPM_COMPOUND(0x2)";
            break;
        }
        case NPL_LU_C_RESOLUTION0_COMPOUND:
        {
            return "NPL_LU_C_RESOLUTION0_COMPOUND(0x3)";
            break;
        }
        case NPL_LU_C_FWD_FRAGMENT_IFG:
        {
            return "NPL_LU_C_FWD_FRAGMENT_IFG(0x4)";
            break;
        }
        case NPL_LU_C_FWD_NOP:
        {
            return "NPL_LU_C_FWD_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd_bucket_c_lu_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd_bucket_c_result_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RES_C_CENTRAL_TCAM_F0:
        {
            return "NPL_RES_C_CENTRAL_TCAM_F0(0x1)";
            break;
        }
        case NPL_RES_C_CENTRAL_EM_COMPOUND:
        {
            return "NPL_RES_C_CENTRAL_EM_COMPOUND(0x2)";
            break;
        }
        case NPL_RES_C_CENTRAL_LPM_COMPOUND:
        {
            return "NPL_RES_C_CENTRAL_LPM_COMPOUND(0x3)";
            break;
        }
        case NPL_RES_C_FWD_NOP:
        {
            return "NPL_RES_C_FWD_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd_bucket_c_result_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd_bucket_d_lu_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LU_D_CENTRAL_EM_LPM_ACC_BOTH_COMPOUND:
        {
            return "NPL_LU_D_CENTRAL_EM_LPM_ACC_BOTH_COMPOUND(0x1)";
            break;
        }
        case NPL_LU_D_CENTRAL_EM_LPM_LPM_ONLY_COMPOUND:
        {
            return "NPL_LU_D_CENTRAL_EM_LPM_LPM_ONLY_COMPOUND(0x2)";
            break;
        }
        case NPL_LU_D_CENTRAL_EM_LPM_EM_ONLY_COMPOUND:
        {
            return "NPL_LU_D_CENTRAL_EM_LPM_EM_ONLY_COMPOUND(0x3)";
            break;
        }
        case NPL_LU_D_FWD_NOP:
        {
            return "NPL_LU_D_FWD_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd_bucket_d_lu_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd_bucket_d_result_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RES_D_CENTRAL_EM_LPM_COMPOUND:
        {
            return "NPL_RES_D_CENTRAL_EM_LPM_COMPOUND(0x1)";
            break;
        }
        case NPL_RES_D_CENTRAL_TCAM_F1:
        {
            return "NPL_RES_D_CENTRAL_TCAM_F1(0x2)";
            break;
        }
        case NPL_RES_D_FWD_NOP:
        {
            return "NPL_RES_D_FWD_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd_bucket_d_result_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd_header_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_FWD_HEADER_TYPE_ETHERNET:
        {
            return "NPL_FWD_HEADER_TYPE_ETHERNET(0x0)";
            break;
        }
        case NPL_FWD_HEADER_TYPE_IPV4:
        {
            return "NPL_FWD_HEADER_TYPE_IPV4(0x2)";
            break;
        }
        case NPL_FWD_HEADER_TYPE_IPV4_COLLAPSED_MC:
        {
            return "NPL_FWD_HEADER_TYPE_IPV4_COLLAPSED_MC(0x3)";
            break;
        }
        case NPL_FWD_HEADER_TYPE_IPV6:
        {
            return "NPL_FWD_HEADER_TYPE_IPV6(0x4)";
            break;
        }
        case NPL_FWD_HEADER_TYPE_IPV6_COLLAPSED_MC:
        {
            return "NPL_FWD_HEADER_TYPE_IPV6_COLLAPSED_MC(0x5)";
            break;
        }
        case NPL_FWD_HEADER_TYPE_MPLS_NO_BOS:
        {
            return "NPL_FWD_HEADER_TYPE_MPLS_NO_BOS(0x8)";
            break;
        }
        case NPL_FWD_HEADER_TYPE_MPLS_BOS_IPV4:
        {
            return "NPL_FWD_HEADER_TYPE_MPLS_BOS_IPV4(0x9)";
            break;
        }
        case NPL_FWD_HEADER_TYPE_MPLS_BOS_IPV6:
        {
            return "NPL_FWD_HEADER_TYPE_MPLS_BOS_IPV6(0xa)";
            break;
        }
        case NPL_FWD_HEADER_TYPE_MPLS_BOS_ETHERNET:
        {
            return "NPL_FWD_HEADER_TYPE_MPLS_BOS_ETHERNET(0xb)";
            break;
        }
        case NPL_FWD_HEADER_TYPE_INJECT_DOWN:
        {
            return "NPL_FWD_HEADER_TYPE_INJECT_DOWN(0xc)";
            break;
        }
        case NPL_FWD_HEADER_TYPE_SVL:
        {
            return "NPL_FWD_HEADER_TYPE_SVL(0xd)";
            break;
        }
        case NPL_FWD_HEADER_TYPE_REDIRECT:
        {
            return "NPL_FWD_HEADER_TYPE_REDIRECT(0xf)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd_header_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd_layer_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IP_FWD:
        {
            return "NPL_IP_FWD(0x0)";
            break;
        }
        case NPL_MAC_FWD:
        {
            return "NPL_MAC_FWD(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd_layer_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_fwd_offset_cmd_e enum_instance)
{
    switch(enum_instance) {
        case NPL_FWD_OFFSET_CMD_CONST:
        {
            return "NPL_FWD_OFFSET_CMD_CONST(0x0)";
            break;
        }
        case NPL_FWD_OFFSET_CMD_INCR_PL0:
        {
            return "NPL_FWD_OFFSET_CMD_INCR_PL0(0x1)";
            break;
        }
        case NPL_FWD_OFFSET_CMD_INCR_PL_CUR:
        {
            return "NPL_FWD_OFFSET_CMD_INCR_PL_CUR(0x2)";
            break;
        }
        case NPL_FWD_OFFSET_CMD_INCR_PL_1:
        {
            return "NPL_FWD_OFFSET_CMD_INCR_PL_1(0x3)";
            break;
        }
        case NPL_FWD_OFFSET_CMD_INCR_PL_2:
        {
            return "NPL_FWD_OFFSET_CMD_INCR_PL_2(0x4)";
            break;
        }
        case NPL_FWD_OFFSET_CMD_INCR_PL_3:
        {
            return "NPL_FWD_OFFSET_CMD_INCR_PL_3(0x5)";
            break;
        }
        case NPL_FWD_OFFSET_CMD_INCR_PL1:
        {
            return "NPL_FWD_OFFSET_CMD_INCR_PL1(0x6)";
            break;
        }
        case NPL_FWD_OFFSET_CMD_INCR_PL2:
        {
            return "NPL_FWD_OFFSET_CMD_INCR_PL2(0x7)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_fwd_offset_cmd_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_gre_dip_entropy_e enum_instance)
{
    switch(enum_instance) {
        case NPL_GRE_DIP_ENTROPY_NONE:
        {
            return "NPL_GRE_DIP_ENTROPY_NONE(0x0)";
            break;
        }
        case NPL_GRE_DIP_ENTROPY_24:
        {
            return "NPL_GRE_DIP_ENTROPY_24(0x1)";
            break;
        }
        case NPL_GRE_DIP_ENTROPY_28:
        {
            return "NPL_GRE_DIP_ENTROPY_28(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_gre_dip_entropy_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_hdr_type_prefix_for_rtf_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IPV4_HDR_PREFIX:
        {
            return "NPL_IPV4_HDR_PREFIX(0x0)";
            break;
        }
        case NPL_IPV6_HDR_PREFIX:
        {
            return "NPL_IPV6_HDR_PREFIX(0x2)";
            break;
        }
        case NPL_ETH_HDR_PREFIX:
        {
            return "NPL_ETH_HDR_PREFIX(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_hdr_type_prefix_for_rtf_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_hw_fi_stage_e enum_instance)
{
    switch(enum_instance) {
        case NPL_HW_FI_STAGE_VLAN_PE:
        {
            return "NPL_HW_FI_STAGE_VLAN_PE(0x0)";
            break;
        }
        case NPL_HW_FI_STAGE_ETHERNET:
        {
            return "NPL_HW_FI_STAGE_ETHERNET(0x1)";
            break;
        }
        case NPL_HW_FI_STAGE_VLAN_0:
        {
            return "NPL_HW_FI_STAGE_VLAN_0(0x2)";
            break;
        }
        case NPL_HW_FI_STAGE_VLAN_1:
        {
            return "NPL_HW_FI_STAGE_VLAN_1(0x3)";
            break;
        }
        case NPL_HW_FI_STAGE_IP:
        {
            return "NPL_HW_FI_STAGE_IP(0x4)";
            break;
        }
        case NPL_HW_FI_STAGE_UDP:
        {
            return "NPL_HW_FI_STAGE_UDP(0x5)";
            break;
        }
        case NPL_HW_FI_STAGE_RTC:
        {
            return "NPL_HW_FI_STAGE_RTC(0x6)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_hw_fi_stage_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ifg_ts_cmd_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IFG_TS_CMD_OP_NOP:
        {
            return "NPL_IFG_TS_CMD_OP_NOP(0x0)";
            break;
        }
        case NPL_IFG_TS_CMD_OP_TOD_UPDATE:
        {
            return "NPL_IFG_TS_CMD_OP_TOD_UPDATE(0x1)";
            break;
        }
        case NPL_IFG_TS_CMD_OP_UPDATE_CF:
        {
            return "NPL_IFG_TS_CMD_OP_UPDATE_CF(0x2)";
            break;
        }
        case NPL_IFG_TS_CMD_OP_TOD_RECORD:
        {
            return "NPL_IFG_TS_CMD_OP_TOD_RECORD(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ifg_ts_cmd_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ingress_acl_values_e enum_instance)
{
    switch(enum_instance) {
        case NPL_INGRESS_SEC_ACL_DEFAULT_PAYLOAD:
        {
            return "NPL_INGRESS_SEC_ACL_DEFAULT_PAYLOAD(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ingress_acl_values_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_init_data_selector_e enum_instance)
{
    switch(enum_instance) {
        case NPL_INIT_DATA_FROM_SSP:
        {
            return "NPL_INIT_DATA_FROM_SSP(0x0)";
            break;
        }
        case NPL_INIT_DATA_FROM_PIF_IFG:
        {
            return "NPL_INIT_DATA_FROM_PIF_IFG(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_init_data_selector_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_init_rtf_stage_and_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_INIT_RTF_NONE:
        {
            return "NPL_INIT_RTF_NONE(0x0)";
            break;
        }
        case NPL_INIT_RTF_OG:
        {
            return "NPL_INIT_RTF_OG(0x1)";
            break;
        }
        case NPL_INIT_RTF_PRE_FWD_L2:
        {
            return "NPL_INIT_RTF_PRE_FWD_L2(0x2)";
            break;
        }
        case NPL_INIT_RTF_PRE_FWD_L3:
        {
            return "NPL_INIT_RTF_PRE_FWD_L3(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_init_rtf_stage_and_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_inject_down_encap_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_INJECT_DOWN_ENCAP_TYPE_NONE:
        {
            return "NPL_INJECT_DOWN_ENCAP_TYPE_NONE(0x0)";
            break;
        }
        case NPL_INJECT_DOWN_ENCAP_TYPE_DLP_NH_TO_ETH:
        {
            return "NPL_INJECT_DOWN_ENCAP_TYPE_DLP_NH_TO_ETH(0x1)";
            break;
        }
        case NPL_INJECT_DOWN_ENCAP_TYPE_PUNT_TO_IP_TUNNEL:
        {
            return "NPL_INJECT_DOWN_ENCAP_TYPE_PUNT_TO_IP_TUNNEL(0x4)";
            break;
        }
        case NPL_INJECT_DOWN_ENCAP_TYPE_PUNT:
        {
            return "NPL_INJECT_DOWN_ENCAP_TYPE_PUNT(0x2)";
            break;
        }
        case NPL_INJECT_DOWN_ENCAP_TYPE_TO_DMA:
        {
            return "NPL_INJECT_DOWN_ENCAP_TYPE_TO_DMA(0x7)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_inject_down_encap_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_inject_header_trailer_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_INJECT_HEADER_TRIALER_SIZE_ZERO:
        {
            return "NPL_INJECT_HEADER_TRIALER_SIZE_ZERO(0x0)";
            break;
        }
        case NPL_INJECT_HEADER_TRIALER_SIZE_8:
        {
            return "NPL_INJECT_HEADER_TRIALER_SIZE_8(0x8)";
            break;
        }
        case NPL_INJECT_HEADER_TRIALER_SIZE_4:
        {
            return "NPL_INJECT_HEADER_TRIALER_SIZE_4(0x4)";
            break;
        }
        case NPL_INJECT_HEADER_TRIALER_SIZE_12:
        {
            return "NPL_INJECT_HEADER_TRIALER_SIZE_12(0xc)";
            break;
        }
        case NPL_INJECT_HEADER_TRIALER_SIZE_24:
        {
            return "NPL_INJECT_HEADER_TRIALER_SIZE_24(0x18)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_inject_header_trailer_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_inject_header_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_INJECT_HEADER_TYPE_DOWN:
        {
            return "NPL_INJECT_HEADER_TYPE_DOWN(0x0)";
            break;
        }
        case NPL_INJECT_HEADER_TYPE_TX_REDIRECT_DOWN:
        {
            return "NPL_INJECT_HEADER_TYPE_TX_REDIRECT_DOWN(0x1)";
            break;
        }
        case NPL_INJECT_HEADER_TYPE_DOWN_RX_COUNT:
        {
            return "NPL_INJECT_HEADER_TYPE_DOWN_RX_COUNT(0x80)";
            break;
        }
        case NPL_INJECT_HEADER_TYPE_UP_ETH:
        {
            return "NPL_INJECT_HEADER_TYPE_UP_ETH(0x22)";
            break;
        }
        case NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS:
        {
            return "NPL_INJECT_HEADER_TYPE_UP_STD_PROCESS(0x26)";
            break;
        }
        case NPL_INJECT_HEADER_TYPE_UP_DESTINATION_OVERRIDE:
        {
            return "NPL_INJECT_HEADER_TYPE_UP_DESTINATION_OVERRIDE(0x2e)";
            break;
        }
        case NPL_INJECT_HEADER_TYPE_UP_IP:
        {
            return "NPL_INJECT_HEADER_TYPE_UP_IP(0x25)";
            break;
        }
        case NPL_INJECT_HEADER_TYPE_UP_MC_VXLAN:
        {
            return "NPL_INJECT_HEADER_TYPE_UP_MC_VXLAN(0x32)";
            break;
        }
        case NPL_INJECT_HEADER_TYPE_UP_LEARN_RECORD:
        {
            return "NPL_INJECT_HEADER_TYPE_UP_LEARN_RECORD(0x2f)";
            break;
        }
        case NPL_INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_ETH:
        {
            return "NPL_INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_ETH(0x36)";
            break;
        }
        case NPL_INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_V4:
        {
            return "NPL_INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_V4(0x35)";
            break;
        }
        case NPL_INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_V6:
        {
            return "NPL_INJECT_HEADER_TYPE_UP_IP_LOCAL_MC_V6(0x34)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_inject_header_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_inject_header_up_ip_local_mc_prefix_e enum_instance)
{
    switch(enum_instance) {
        case NPL_INJECT_HEADER_UP_IP_LOCAL_MC_PREFIX:
        {
            return "NPL_INJECT_HEADER_UP_IP_LOCAL_MC_PREFIX(0xd)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_inject_header_up_ip_local_mc_prefix_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_inject_msg_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_INJECT_CCM:
        {
            return "NPL_INJECT_CCM(0x1)";
            break;
        }
        case NPL_INJECT_DMM:
        {
            return "NPL_INJECT_DMM(0x2)";
            break;
        }
        case NPL_INJECT_LMM:
        {
            return "NPL_INJECT_LMM(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_inject_msg_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_inject_pkt_size_e enum_instance)
{
    switch(enum_instance) {
        case NPL_INJECT_PKT_SIZE_CCM:
        {
            return "NPL_INJECT_PKT_SIZE_CCM(0x54)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_inject_pkt_size_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_inject_up_hdr_phb_src_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PHB_FROM_INJECTED_PACKET:
        {
            return "NPL_PHB_FROM_INJECTED_PACKET(0x0)";
            break;
        }
        case NPL_PHB_FROM_PACKET_PROCESSING:
        {
            return "NPL_PHB_FROM_PACKET_PROCESSING(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_inject_up_hdr_phb_src_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_inject_up_mapping_db_e enum_instance)
{
    switch(enum_instance) {
        case NPL_SM_LDB_INJECT_UP_SSP_MAPPING:
        {
            return "NPL_SM_LDB_INJECT_UP_SSP_MAPPING(0xb)";
            break;
        }
        case NPL_SM_LDB_INJECT_UP_PIF_IFG_MAPPING:
        {
            return "NPL_SM_LDB_INJECT_UP_PIF_IFG_MAPPING(0x1b)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_inject_up_mapping_db_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ip_acl_macro_control_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IP_ROUTING_TO_NH_UC:
        {
            return "NPL_IP_ROUTING_TO_NH_UC(0x0)";
            break;
        }
        case NPL_MPLS_ADDITIONAL_LABELS:
        {
            return "NPL_MPLS_ADDITIONAL_LABELS(0xc)";
            break;
        }
        case NPL_MPLS_ADDITIONAL_8_LABELS:
        {
            return "NPL_MPLS_ADDITIONAL_8_LABELS(0xd)";
            break;
        }
        case NPL_MPLS_PHP:
        {
            return "NPL_MPLS_PHP(0x7)";
            break;
        }
        case NPL_IP_TO_IP_THROUGH_MPLS:
        {
            return "NPL_IP_TO_IP_THROUGH_MPLS(0x1)";
            break;
        }
        case NPL_ROUTING_THROUGH_MPLS:
        {
            return "NPL_ROUTING_THROUGH_MPLS(0x9)";
            break;
        }
        case NPL_IP_ROUTING_TO_IPV4_TUNNEL:
        {
            return "NPL_IP_ROUTING_TO_IPV4_TUNNEL(0x3)";
            break;
        }
        case NPL_IP_ROUTING_TO_VXLAN:
        {
            return "NPL_IP_ROUTING_TO_VXLAN(0x5)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ip_acl_macro_control_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ip_em_lpm_result_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IP_EM_LPM_RESULT_TYPE_DESTINATION_FROM_EM:
        {
            return "NPL_IP_EM_LPM_RESULT_TYPE_DESTINATION_FROM_EM(0x0)";
            break;
        }
        case NPL_IP_EM_LPM_RESULT_TYPE_HOST_PTR_AND_L3_DLP:
        {
            return "NPL_IP_EM_LPM_RESULT_TYPE_HOST_PTR_AND_L3_DLP(0x1)";
            break;
        }
        case NPL_IP_EM_LPM_RESULT_TYPE_HOST_MAC_AND_L3_DLP:
        {
            return "NPL_IP_EM_LPM_RESULT_TYPE_HOST_MAC_AND_L3_DLP(0x2)";
            break;
        }
        case NPL_IP_EM_LPM_RESULT_TYPE_DESTINATION_FROM_LPM:
        {
            return "NPL_IP_EM_LPM_RESULT_TYPE_DESTINATION_FROM_LPM(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ip_em_lpm_result_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ip_lpm_result_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IP_LPM_RESULT_TYPE_DESTINATION_FROM_LPM:
        {
            return "NPL_IP_LPM_RESULT_TYPE_DESTINATION_FROM_LPM(0x0)";
            break;
        }
        case NPL_IP_LPM_RESULT_TYPE_DESTINATION_FROM_FEC:
        {
            return "NPL_IP_LPM_RESULT_TYPE_DESTINATION_FROM_FEC(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ip_lpm_result_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ip_qos_tag_selector_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IP_QOS_TAG_SELECT_FWD_QOS_TAG:
        {
            return "NPL_IP_QOS_TAG_SELECT_FWD_QOS_TAG(0x0)";
            break;
        }
        case NPL_IP_QOS_TAG_SELECT_QOS_GROUP:
        {
            return "NPL_IP_QOS_TAG_SELECT_QOS_GROUP(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ip_qos_tag_selector_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ip_tunnel_encap_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IP_TUNNEL_ENCAP_TYPE_GRE:
        {
            return "NPL_IP_TUNNEL_ENCAP_TYPE_GRE(0x0)";
            break;
        }
        case NPL_IP_TUNNEL_ENCAP_TYPE_IP:
        {
            return "NPL_IP_TUNNEL_ENCAP_TYPE_IP(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ip_tunnel_encap_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ip_tunnel_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IP_TUNNEL_TYPE_IPV4:
        {
            return "NPL_IP_TUNNEL_TYPE_IPV4(0x0)";
            break;
        }
        case NPL_IP_TUNNEL_TYPE_IPV6:
        {
            return "NPL_IP_TUNNEL_TYPE_IPV6(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ip_tunnel_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ip_uc_em_result_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IP_UC_EM_RESULT_TYPE_HOST_PTR_AND_L3_DLP:
        {
            return "NPL_IP_UC_EM_RESULT_TYPE_HOST_PTR_AND_L3_DLP(0x0)";
            break;
        }
        case NPL_IP_UC_EM_RESULT_TYPE_HOST_MAC_AND_L3_DLP:
        {
            return "NPL_IP_UC_EM_RESULT_TYPE_HOST_MAC_AND_L3_DLP(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ip_uc_em_result_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ip_version_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IP_VERSION_IPV4:
        {
            return "NPL_IP_VERSION_IPV4(0x0)";
            break;
        }
        case NPL_IP_VERSION_IPV6:
        {
            return "NPL_IP_VERSION_IPV6(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ip_version_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ipv4_acl_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IPV4_ACL_TYPE_NONE:
        {
            return "NPL_IPV4_ACL_TYPE_NONE(0x0)";
            break;
        }
        case NPL_IPV4_ACL_TYPE_DEFAULT:
        {
            return "NPL_IPV4_ACL_TYPE_DEFAULT(0x1)";
            break;
        }
        case NPL_IPV4_ACL_TYPE_RTF:
        {
            return "NPL_IPV4_ACL_TYPE_RTF(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ipv4_acl_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ipv6_master_acl_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IPV6_ACL_TYPE_MASTER_NONE:
        {
            return "NPL_IPV6_ACL_TYPE_MASTER_NONE(0x0)";
            break;
        }
        case NPL_IPV6_ACL_TYPE_MASTER_DEFAULT:
        {
            return "NPL_IPV6_ACL_TYPE_MASTER_DEFAULT(0x1)";
            break;
        }
        case NPL_IPV6_ACL_TYPE_MASTER_RTF:
        {
            return "NPL_IPV6_ACL_TYPE_MASTER_RTF(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ipv6_master_acl_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_l2_lp_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_L2_LP_TYPE_NPP:
        {
            return "NPL_L2_LP_TYPE_NPP(0x1)";
            break;
        }
        case NPL_L2_LP_TYPE_PWE:
        {
            return "NPL_L2_LP_TYPE_PWE(0x4)";
            break;
        }
        case NPL_L2_LP_TYPE_OVERLAY:
        {
            return "NPL_L2_LP_TYPE_OVERLAY(0x8)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_l2_lp_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_l2vpn_cw_fat_exists_e enum_instance)
{
    switch(enum_instance) {
        case NPL_L2VPN_NO_CW_NO_FAT:
        {
            return "NPL_L2VPN_NO_CW_NO_FAT(0x0)";
            break;
        }
        case NPL_L2VPN_NO_CW_WITH_FAT:
        {
            return "NPL_L2VPN_NO_CW_WITH_FAT(0x1)";
            break;
        }
        case NPL_L2VPN_WITH_CW_NO_FAT:
        {
            return "NPL_L2VPN_WITH_CW_NO_FAT(0x2)";
            break;
        }
        case NPL_L2VPN_WITH_CW_WITH_FAT:
        {
            return "NPL_L2VPN_WITH_CW_WITH_FAT(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_l2vpn_cw_fat_exists_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_l3_dlp_ip_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IPV4_L3_DLP:
        {
            return "NPL_IPV4_L3_DLP(0x0)";
            break;
        }
        case NPL_IPV6_L3_DLP:
        {
            return "NPL_IPV6_L3_DLP(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_l3_dlp_ip_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_l3_p_counter_offset_e enum_instance)
{
    switch(enum_instance) {
        case NPL_P_COUNT_OFFSET_IPV4_UC:
        {
            return "NPL_P_COUNT_OFFSET_IPV4_UC(0x0)";
            break;
        }
        case NPL_P_COUNT_OFFSET_IPV6_UC:
        {
            return "NPL_P_COUNT_OFFSET_IPV6_UC(0x1)";
            break;
        }
        case NPL_P_COUNT_OFFSET_MPLS:
        {
            return "NPL_P_COUNT_OFFSET_MPLS(0x2)";
            break;
        }
        case NPL_P_COUNT_OFFSET_IPV4_MC:
        {
            return "NPL_P_COUNT_OFFSET_IPV4_MC(0x3)";
            break;
        }
        case NPL_P_COUNT_OFFSET_IPV6_MC:
        {
            return "NPL_P_COUNT_OFFSET_IPV6_MC(0x4)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_l3_p_counter_offset_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_lb_consistency_mode_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED:
        {
            return "NPL_LB_CONSISTENCY_MODE_CONSISTENCE_DISABLED(0x0)";
            break;
        }
        case NPL_LB_CONSISTENCY_MODE_CONSISTENCE_ENABLED:
        {
            return "NPL_LB_CONSISTENCY_MODE_CONSISTENCE_ENABLED(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_lb_consistency_mode_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_lb_profile_enum_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LB_PROFILE_MPLS:
        {
            return "NPL_LB_PROFILE_MPLS(0x1)";
            break;
        }
        case NPL_LB_PROFILE_IP:
        {
            return "NPL_LB_PROFILE_IP(0x0)";
            break;
        }
        case NPL_LB_PROFILE_EL_ELI:
        {
            return "NPL_LB_PROFILE_EL_ELI(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_lb_profile_enum_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_learn_prob_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ALWAYS_LEARN:
        {
            return "NPL_ALWAYS_LEARN(0x0)";
            break;
        }
        case NPL_STAT_LEARN:
        {
            return "NPL_STAT_LEARN(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_learn_prob_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_learn_record_result_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LEARN_RECORD_RESULT_INSERT:
        {
            return "NPL_LEARN_RECORD_RESULT_INSERT(0x0)";
            break;
        }
        case NPL_LEARN_RECORD_RESULT_UPDATE:
        {
            return "NPL_LEARN_RECORD_RESULT_UPDATE(0x1)";
            break;
        }
        case NPL_LEARN_RECORD_RESULT_REFRESH:
        {
            return "NPL_LEARN_RECORD_RESULT_REFRESH(0x2)";
            break;
        }
        case NPL_LEARN_RECORD_RESULT_AGED:
        {
            return "NPL_LEARN_RECORD_RESULT_AGED(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_learn_record_result_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_learn_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LEARN_TYPE_NONE:
        {
            return "NPL_LEARN_TYPE_NONE(0x0)";
            break;
        }
        case NPL_LEARN_TYPE_HW:
        {
            return "NPL_LEARN_TYPE_HW(0x1)";
            break;
        }
        case NPL_LEARN_TYPE_CPU:
        {
            return "NPL_LEARN_TYPE_CPU(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_learn_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_light_fi_stage_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LIGHT_FI_STAGE_FABRIC:
        {
            return "NPL_LIGHT_FI_STAGE_FABRIC(0x0)";
            break;
        }
        case NPL_LIGHT_FI_STAGE_TM:
        {
            return "NPL_LIGHT_FI_STAGE_TM(0x1)";
            break;
        }
        case NPL_LIGHT_FI_STAGE_NPU_BASE:
        {
            return "NPL_LIGHT_FI_STAGE_NPU_BASE(0x2)";
            break;
        }
        case NPL_LIGHT_FI_STAGE_NPU_EXTENDED:
        {
            return "NPL_LIGHT_FI_STAGE_NPU_EXTENDED(0x3)";
            break;
        }
        case NPL_LIGHT_FI_STAGE_NETWORK_0:
        {
            return "NPL_LIGHT_FI_STAGE_NETWORK_0(0x4)";
            break;
        }
        case NPL_LIGHT_FI_STAGE_NETWORK_1:
        {
            return "NPL_LIGHT_FI_STAGE_NETWORK_1(0x5)";
            break;
        }
        case NPL_LIGHT_FI_STAGE_NETWORK_2:
        {
            return "NPL_LIGHT_FI_STAGE_NETWORK_2(0x6)";
            break;
        }
        case NPL_LIGHT_FI_STAGE_NETWORK_3:
        {
            return "NPL_LIGHT_FI_STAGE_NETWORK_3(0x7)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_light_fi_stage_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_link_state_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LINK_STATE_DOWN:
        {
            return "NPL_LINK_STATE_DOWN(0x0)";
            break;
        }
        case NPL_LINK_STATE_UP:
        {
            return "NPL_LINK_STATE_UP(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_link_state_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_loopback_mode_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LOOPBACK_MODE_NONE:
        {
            return "NPL_LOOPBACK_MODE_NONE(0x0)";
            break;
        }
        case NPL_LOOPBACK_MODE_CORE_CLK:
        {
            return "NPL_LOOPBACK_MODE_CORE_CLK(0x1)";
            break;
        }
        case NPL_LOOPBACK_MODE_SRDS_CLK:
        {
            return "NPL_LOOPBACK_MODE_SRDS_CLK(0x2)";
            break;
        }
        case NPL_LOOPBACK_MODE_REMOTE:
        {
            return "NPL_LOOPBACK_MODE_REMOTE(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_loopback_mode_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_lpts_first_lookup_cal_result_default_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LPTS_FIRST_LOOKUP_CAL_RESULT_DEFAULT:
        {
            return "NPL_LPTS_FIRST_LOOKUP_CAL_RESULT_DEFAULT(0xfff7f000)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_lpts_first_lookup_cal_result_default_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_lpts_first_lookup_result_default_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LPTS_FIRST_LOOKUP_RESULT_DEFAULT:
        {
            return "NPL_LPTS_FIRST_LOOKUP_RESULT_DEFAULT(0x70)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_lpts_first_lookup_result_default_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_lpts_l4_protocol_compress_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ICMP:
        {
            return "NPL_ICMP(0x0)";
            break;
        }
        case NPL_IGMP:
        {
            return "NPL_IGMP(0x1)";
            break;
        }
        case NPL_TCP:
        {
            return "NPL_TCP(0x2)";
            break;
        }
        case NPL_UDP:
        {
            return "NPL_UDP(0x3)";
            break;
        }
        case NPL_RSVP:
        {
            return "NPL_RSVP(0x4)";
            break;
        }
        case NPL_GRE:
        {
            return "NPL_GRE(0x5)";
            break;
        }
        case NPL_IPV6_ICMP:
        {
            return "NPL_IPV6_ICMP(0x6)";
            break;
        }
        case NPL_EIGRP:
        {
            return "NPL_EIGRP(0x7)";
            break;
        }
        case NPL_OSPF:
        {
            return "NPL_OSPF(0x8)";
            break;
        }
        case NPL_PIM:
        {
            return "NPL_PIM(0x9)";
            break;
        }
        case NPL_VRRP:
        {
            return "NPL_VRRP(0xa)";
            break;
        }
        case NPL_L2TPV3:
        {
            return "NPL_L2TPV3(0xb)";
            break;
        }
        case NPL_FRAGMENT:
        {
            return "NPL_FRAGMENT(0xc)";
            break;
        }
        case NPL_OTHER_L4_PROTOCOL:
        {
            return "NPL_OTHER_L4_PROTOCOL(0xd)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_lpts_l4_protocol_compress_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_lpts_padded_table_id_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PADDED_LPTS_TABLE_ID_IPV6:
        {
            return "NPL_PADDED_LPTS_TABLE_ID_IPV6(0xd)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_lpts_padded_table_id_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_lpts_reason_code_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LPTS_REASON_CODE_INVALID:
        {
            return "NPL_LPTS_REASON_CODE_INVALID(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_lpts_reason_code_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_lsp_one_label_and_inner_ene_jump_offset_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FIRST_LABEL_AND_INNER_NO_JUMP:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FIRST_LABEL_AND_INNER_NO_JUMP(0x0)";
            break;
        }
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FIRST_LABEL_AND_INNER:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FIRST_LABEL_AND_INNER(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_lsp_one_label_and_inner_ene_jump_offset_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_lsp_one_label_ene_jump_offset_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FIRST_LABEL_NO_JUMP:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FIRST_LABEL_NO_JUMP(0x0)";
            break;
        }
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FIRST_LABEL:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_FIRST_LABEL(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_lsp_one_label_ene_jump_offset_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_lsp_three_labels_and_inner_ene_jump_offset_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_THIRD_LABEL_AND_INNER_NO_JUMP:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_THIRD_LABEL_AND_INNER_NO_JUMP(0x0)";
            break;
        }
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_THIRD_LABEL_AND_INNER:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_THIRD_LABEL_AND_INNER(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_lsp_three_labels_and_inner_ene_jump_offset_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_lsp_two_labels_and_inner_ene_jump_offset_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SECOND_LABEL_AND_INNER_NO_JUMP:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SECOND_LABEL_AND_INNER_NO_JUMP(0x0)";
            break;
        }
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SECOND_LABEL_AND_INNER:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SECOND_LABEL_AND_INNER(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_lsp_two_labels_and_inner_ene_jump_offset_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_lsp_two_labels_ene_jump_offset_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SECOND_LABEL_NO_JUMP:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SECOND_LABEL_NO_JUMP(0x0)";
            break;
        }
        case NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SECOND_LABEL:
        {
            return "NPL_ENE_JUMP_OFFSET_MPLS_IMPOSED_SECOND_LABEL(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_lsp_two_labels_ene_jump_offset_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mac_acl_macro_control_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MAC_BRIDGING_AC_UC:
        {
            return "NPL_MAC_BRIDGING_AC_UC(0x0)";
            break;
        }
        case NPL_MAC_BRIDGING_COLLAPSED_MC:
        {
            return "NPL_MAC_BRIDGING_COLLAPSED_MC(0x1)";
            break;
        }
        case NPL_MAC_BRIDGING_TO_PWE:
        {
            return "NPL_MAC_BRIDGING_TO_PWE(0x6)";
            break;
        }
        case NPL_MAC_P2P_TO_PWE:
        {
            return "NPL_MAC_P2P_TO_PWE(0x2)";
            break;
        }
        case NPL_MAC_BRIDGING_TO_PWE_TUNNEL:
        {
            return "NPL_MAC_BRIDGING_TO_PWE_TUNNEL(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mac_acl_macro_control_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mac_da_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MAC_DA_TYPE_NOT_ROUTABLE:
        {
            return "NPL_MAC_DA_TYPE_NOT_ROUTABLE(0x0)";
            break;
        }
        case NPL_MAC_DA_TYPE_UC:
        {
            return "NPL_MAC_DA_TYPE_UC(0x1)";
            break;
        }
        case NPL_MAC_DA_TYPE_IPV4_COMP_MC:
        {
            return "NPL_MAC_DA_TYPE_IPV4_COMP_MC(0x2)";
            break;
        }
        case NPL_MAC_DA_TYPE_IPV6_COMP_MC:
        {
            return "NPL_MAC_DA_TYPE_IPV6_COMP_MC(0x3)";
            break;
        }
        case NPL_MAC_DA_TYPE_VRRP:
        {
            return "NPL_MAC_DA_TYPE_VRRP(0x4)";
            break;
        }
        case NPL_MAC_DA_TYPE_PTP:
        {
            return "NPL_MAC_DA_TYPE_PTP(0x5)";
            break;
        }
        case NPL_MAC_DA_TYPE_ISIS:
        {
            return "NPL_MAC_DA_TYPE_ISIS(0x6)";
            break;
        }
        case NPL_MAC_DA_TYPE_SYSTEM:
        {
            return "NPL_MAC_DA_TYPE_SYSTEM(0x7)";
            break;
        }
        case NPL_MAC_DA_TYPE_CISCO_PROTOCOLS:
        {
            return "NPL_MAC_DA_TYPE_CISCO_PROTOCOLS(0x8)";
            break;
        }
        case NPL_MAC_DA_TYPE_LACP:
        {
            return "NPL_MAC_DA_TYPE_LACP(0x9)";
            break;
        }
        case NPL_MAC_DA_TYPE_L2CP:
        {
            return "NPL_MAC_DA_TYPE_L2CP(0xa)";
            break;
        }
        case NPL_MAC_DA_TYPE_ZERO:
        {
            return "NPL_MAC_DA_TYPE_ZERO(0xb)";
            break;
        }
        case NPL_MAC_DA_TYPE_L2CP_CFM:
        {
            return "NPL_MAC_DA_TYPE_L2CP_CFM(0xc)";
            break;
        }
        case NPL_MAC_DA_TYPE_BCAST:
        {
            return "NPL_MAC_DA_TYPE_BCAST(0xd)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mac_da_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mac_lp_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LP_TYPE_LAYER_2:
        {
            return "NPL_LP_TYPE_LAYER_2(0x0)";
            break;
        }
        case NPL_LP_TYPE_LAYER_3:
        {
            return "NPL_LP_TYPE_LAYER_3(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mac_lp_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mac_mapping_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_L2_SERVICE_MAPPING:
        {
            return "NPL_L2_SERVICE_MAPPING(0x1)";
            break;
        }
        case NPL_L2_TCAM_MAPPING:
        {
            return "NPL_L2_TCAM_MAPPING(0x2)";
            break;
        }
        case NPL_L2_VLAN_MAPPING:
        {
            return "NPL_L2_VLAN_MAPPING(0x4)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mac_mapping_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mac_qos_acl_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MAC_QOS_ACL_TYPE_NONE:
        {
            return "NPL_MAC_QOS_ACL_TYPE_NONE(0x0)";
            break;
        }
        case NPL_MAC_QOS_ACL_TYPE_DEFAULT:
        {
            return "NPL_MAC_QOS_ACL_TYPE_DEFAULT(0x1)";
            break;
        }
        case NPL_MAC_QOS_ACL_TYPE_IPV4:
        {
            return "NPL_MAC_QOS_ACL_TYPE_IPV4(0x2)";
            break;
        }
        case NPL_MAC_MASTER_ACL_TYPE_IPV6:
        {
            return "NPL_MAC_MASTER_ACL_TYPE_IPV6(0x4)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mac_qos_acl_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mac_relay_flood_meter_offset_e enum_instance)
{
    switch(enum_instance) {
        case NPL_FLOOD_OFFSET_BC:
        {
            return "NPL_FLOOD_OFFSET_BC(0x0)";
            break;
        }
        case NPL_FLOOD_OFFSET_MC:
        {
            return "NPL_FLOOD_OFFSET_MC(0x1)";
            break;
        }
        case NPL_FLOOD_OFFSET_UC:
        {
            return "NPL_FLOOD_OFFSET_UC(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mac_relay_flood_meter_offset_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mac_sec_acl_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MAC_SEC_ACL_TYPE_NONE:
        {
            return "NPL_MAC_SEC_ACL_TYPE_NONE(0x0)";
            break;
        }
        case NPL_MAC_SEC_ACL_TYPE_DEFAULT:
        {
            return "NPL_MAC_SEC_ACL_TYPE_DEFAULT(0x1)";
            break;
        }
        case NPL_MAC_SEC_ACL_TYPE_IPV4:
        {
            return "NPL_MAC_SEC_ACL_TYPE_IPV4(0x2)";
            break;
        }
        case NPL_MAC_SEC_ACL_TYPE_IPV6:
        {
            return "NPL_MAC_SEC_ACL_TYPE_IPV6(0x4)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mac_sec_acl_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mac_termination_em_logical_db_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MAC_TERM_EM_LDB_UC_WITH_DA:
        {
            return "NPL_MAC_TERM_EM_LDB_UC_WITH_DA(0x0)";
            break;
        }
        case NPL_MAC_TERM_EM_LDB_MC_NO_DA:
        {
            return "NPL_MAC_TERM_EM_LDB_MC_NO_DA(0x1)";
            break;
        }
        case NPL_MAC_TERM_EM_LDB_OBM_PUNT:
        {
            return "NPL_MAC_TERM_EM_LDB_OBM_PUNT(0x2)";
            break;
        }
        case NPL_MAC_TERM_EM_LDB_UC_NO_DA:
        {
            return "NPL_MAC_TERM_EM_LDB_UC_NO_DA(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mac_termination_em_logical_db_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mac_termination_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MAC_TERM_UC_WITH_DA:
        {
            return "NPL_MAC_TERM_UC_WITH_DA(0x0)";
            break;
        }
        case NPL_MAC_TERM_UC_NO_DA:
        {
            return "NPL_MAC_TERM_UC_NO_DA(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mac_termination_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mcid_array_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MULTICAST_NUM_MCIDS_PER_ENTRY:
        {
            return "NPL_MULTICAST_NUM_MCIDS_PER_ENTRY(0x8)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mcid_array_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_meg_id_format_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MEG_ID_FORMAT_ICC:
        {
            return "NPL_MEG_ID_FORMAT_ICC(0x0)";
            break;
        }
        case NPL_MEG_ID_FORMAT_ICC_AND_CC:
        {
            return "NPL_MEG_ID_FORMAT_ICC_AND_CC(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_meg_id_format_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mirror_action_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MIRROR_DIRECT:
        {
            return "NPL_MIRROR_DIRECT(0x0)";
            break;
        }
        case NPL_MIRROR_OFFSET:
        {
            return "NPL_MIRROR_OFFSET(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mirror_action_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mp_table_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_DB_TRIGGER_MP_TABLE_TYPE_INJECT_CCM:
        {
            return "NPL_DB_TRIGGER_MP_TABLE_TYPE_INJECT_CCM(0x1)";
            break;
        }
        case NPL_DB_TRIGGER_MP_TABLE_TYPE_INJECT_DMM:
        {
            return "NPL_DB_TRIGGER_MP_TABLE_TYPE_INJECT_DMM(0x2)";
            break;
        }
        case NPL_DB_TRIGGER_MP_TABLE_TYPE_INJECT_LMM:
        {
            return "NPL_DB_TRIGGER_MP_TABLE_TYPE_INJECT_LMM(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mp_table_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mp_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ETH_MEP:
        {
            return "NPL_ETH_MEP(0x0)";
            break;
        }
        case NPL_ETH_MIP:
        {
            return "NPL_ETH_MIP(0x1)";
            break;
        }
        case NPL_BFD_MEP:
        {
            return "NPL_BFD_MEP(0x2)";
            break;
        }
        case NPL_MPLS_TP_MEP:
        {
            return "NPL_MPLS_TP_MEP(0x3)";
            break;
        }
        case NPL_MPLS_TP_MIP:
        {
            return "NPL_MPLS_TP_MIP(0x4)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mp_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mpls_forwarding_lookup_selector_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LSR_LOOKUP_SELECTOR_LABEL:
        {
            return "NPL_LSR_LOOKUP_SELECTOR_LABEL(0x0)";
            break;
        }
        case NPL_LSR_LOOKUP_SELECTOR_VRF_LABEL:
        {
            return "NPL_LSR_LOOKUP_SELECTOR_VRF_LABEL(0x1)";
            break;
        }
        case NPL_LSR_LOOKUP_SELECTOR_NPP_LABEL:
        {
            return "NPL_LSR_LOOKUP_SELECTOR_NPP_LABEL(0x2)";
            break;
        }
        case NPL_LSR_LOOKUP_SELECTOR_LP_LABEL:
        {
            return "NPL_LSR_LOOKUP_SELECTOR_LP_LABEL(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mpls_forwarding_lookup_selector_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mpls_next_header_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MPLS_NEXT_HEADER_MPLS:
        {
            return "NPL_MPLS_NEXT_HEADER_MPLS(0x0)";
            break;
        }
        case NPL_MPLS_NEXT_HEADER_ETHERNET:
        {
            return "NPL_MPLS_NEXT_HEADER_ETHERNET(0x1)";
            break;
        }
        case NPL_MPLS_NEXT_HEADER_IP:
        {
            return "NPL_MPLS_NEXT_HEADER_IP(0x2)";
            break;
        }
        case NPL_MPLS_NEXT_HEADER_IPV4:
        {
            return "NPL_MPLS_NEXT_HEADER_IPV4(0x3)";
            break;
        }
        case NPL_MPLS_NEXT_HEADER_IPV6:
        {
            return "NPL_MPLS_NEXT_HEADER_IPV6(0x4)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mpls_next_header_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mpls_next_protocol_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MPLS_NEXT_PROTOCOL_ETHERNET:
        {
            return "NPL_MPLS_NEXT_PROTOCOL_ETHERNET(0x0)";
            break;
        }
        case NPL_MPLS_NEXT_PROTOCOL_IPV4:
        {
            return "NPL_MPLS_NEXT_PROTOCOL_IPV4(0x1)";
            break;
        }
        case NPL_MPLS_NEXT_PROTOCOL_IPV6:
        {
            return "NPL_MPLS_NEXT_PROTOCOL_IPV6(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mpls_next_protocol_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mpls_qos_tag_selector_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MPLS_QOS_TAG_SELECT_QOS_GROUP:
        {
            return "NPL_MPLS_QOS_TAG_SELECT_QOS_GROUP(0x0)";
            break;
        }
        case NPL_MPLS_QOS_TAG_SELECT_LABEL_EXP:
        {
            return "NPL_MPLS_QOS_TAG_SELECT_LABEL_EXP(0x1)";
            break;
        }
        case NPL_MPLS_QOS_TAG_SELECT_ENCAP_QOS_TAG:
        {
            return "NPL_MPLS_QOS_TAG_SELECT_ENCAP_QOS_TAG(0x2)";
            break;
        }
        case NPL_MPLS_QOS_TAG_SELECT_FWD_QOS_TAG:
        {
            return "NPL_MPLS_QOS_TAG_SELECT_FWD_QOS_TAG(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mpls_qos_tag_selector_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_mpls_service_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MPLS_SERVICE_PWE:
        {
            return "NPL_MPLS_SERVICE_PWE(0x0)";
            break;
        }
        case NPL_MPLS_SERVICE_L3_MLDP_BUD:
        {
            return "NPL_MPLS_SERVICE_L3_MLDP_BUD(0x1)";
            break;
        }
        case NPL_MPLS_SERVICE_L3_MLDP_TAIL:
        {
            return "NPL_MPLS_SERVICE_L3_MLDP_TAIL(0x2)";
            break;
        }
        case NPL_MPLS_SERVICE_L3_VPN:
        {
            return "NPL_MPLS_SERVICE_L3_VPN(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_mpls_service_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_multicast_reserved_mcid_e enum_instance)
{
    switch(enum_instance) {
        case NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE:
        {
            return "NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE(0xffff)";
            break;
        }
        case NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_0_IFG_0:
        {
            return "NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_0_IFG_0(0xfffe)";
            break;
        }
        case NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_0_IFG_1:
        {
            return "NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_0_IFG_1(0xfffd)";
            break;
        }
        case NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_1_IFG_0:
        {
            return "NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_1_IFG_0(0xfffc)";
            break;
        }
        case NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_1_IFG_1:
        {
            return "NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_1_IFG_1(0xfffb)";
            break;
        }
        case NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_2_IFG_0:
        {
            return "NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_2_IFG_0(0xfffa)";
            break;
        }
        case NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_2_IFG_1:
        {
            return "NPL_MULTICAST_RESERVED_MCID_TO_NETWORK_SLICE_2_IFG_1(0xfff9)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_multicast_reserved_mcid_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_nh_ene_macro_code_e enum_instance)
{
    switch(enum_instance) {
        case NPL_NH_ENE_MACRO_ETH:
        {
            return "NPL_NH_ENE_MACRO_ETH(0x0)";
            break;
        }
        case NPL_NH_ENE_MACRO_ETH_VLAN:
        {
            return "NPL_NH_ENE_MACRO_ETH_VLAN(0x1)";
            break;
        }
        case NPL_NH_ENE_MACRO_ETH_VLAN_VLAN:
        {
            return "NPL_NH_ENE_MACRO_ETH_VLAN_VLAN(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_nh_ene_macro_code_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_nhlfe_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_NHLFE_TYPE_TE_HEADEND:
        {
            return "NPL_NHLFE_TYPE_TE_HEADEND(0x8)";
            break;
        }
        case NPL_NHLFE_TYPE_L2_ADJ_SID:
        {
            return "NPL_NHLFE_TYPE_L2_ADJ_SID(0xa)";
            break;
        }
        case NPL_NHLFE_TYPE_MIDPOINT_SWAP:
        {
            return "NPL_NHLFE_TYPE_MIDPOINT_SWAP(0x0)";
            break;
        }
        case NPL_NHLFE_TYPE_MIDPOINT_PHP:
        {
            return "NPL_NHLFE_TYPE_MIDPOINT_PHP(0x1)";
            break;
        }
        case NPL_NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_FULL:
        {
            return "NPL_NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_FULL(0x4)";
            break;
        }
        case NPL_NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_SWP:
        {
            return "NPL_NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_SWP(0x5)";
            break;
        }
        case NPL_NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_MP:
        {
            return "NPL_NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_MP(0x6)";
            break;
        }
        case NPL_NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_MP_SWP:
        {
            return "NPL_NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_MP_SWP(0x7)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_nhlfe_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_npl_log_level_e enum_instance)
{
    switch(enum_instance) {
        case NPL_NPL_LOGT:
        {
            return "NPL_NPL_LOGT(0x0)";
            break;
        }
        case NPL_NPL_LOGD:
        {
            return "NPL_NPL_LOGD(0x1)";
            break;
        }
        case NPL_NPL_LOGI:
        {
            return "NPL_NPL_LOGI(0x2)";
            break;
        }
        case NPL_NPL_LOGP:
        {
            return "NPL_NPL_LOGP(0x3)";
            break;
        }
        case NPL_NPL_LOGW:
        {
            return "NPL_NPL_LOGW(0x4)";
            break;
        }
        case NPL_NPL_LOGES:
        {
            return "NPL_NPL_LOGES(0x5)";
            break;
        }
        case NPL_NPL_LOGE:
        {
            return "NPL_NPL_LOGE(0x6)";
            break;
        }
        case NPL_NPL_LOGF:
        {
            return "NPL_NPL_LOGF(0x7)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_npl_log_level_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_npu_encap_l2_header_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_NPU_ENCAP_L2_HEADER_TYPE_AC:
        {
            return "NPL_NPU_ENCAP_L2_HEADER_TYPE_AC(0x0)";
            break;
        }
        case NPL_NPU_ENCAP_L2_HEADER_TYPE_PWE:
        {
            return "NPL_NPU_ENCAP_L2_HEADER_TYPE_PWE(0x1)";
            break;
        }
        case NPL_NPU_ENCAP_L2_HEADER_TYPE_PWE_WITH_TUNNEL_ID:
        {
            return "NPL_NPU_ENCAP_L2_HEADER_TYPE_PWE_WITH_TUNNEL_ID(0x2)";
            break;
        }
        case NPL_NPU_ENCAP_L2_HEADER_TYPE_SVL:
        {
            return "NPL_NPU_ENCAP_L2_HEADER_TYPE_SVL(0x5)";
            break;
        }
        case NPL_NPU_ENCAP_L2_HEADER_TYPE_VXLAN:
        {
            return "NPL_NPU_ENCAP_L2_HEADER_TYPE_VXLAN(0x6)";
            break;
        }
        case NPL_NPU_ENCAP_L2_IBM:
        {
            return "NPL_NPU_ENCAP_L2_IBM(0xe)";
            break;
        }
        case NPL_NPU_ENCAP_L2_MC_INGRESS_REPLICATION:
        {
            return "NPL_NPU_ENCAP_L2_MC_INGRESS_REPLICATION(0xf)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_npu_encap_l2_header_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_npu_encap_l3_header_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC:
        {
            return "NPL_NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC(0x1)";
            break;
        }
        case NPL_NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH:
        {
            return "NPL_NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH(0x3)";
            break;
        }
        case NPL_NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID:
        {
            return "NPL_NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID(0x8)";
            break;
        }
        case NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE:
        {
            return "NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE(0x9)";
            break;
        }
        case NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR:
        {
            return "NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE_SR(0xb)";
            break;
        }
        case NPL_NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE:
        {
            return "NPL_NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE(0xa)";
            break;
        }
        case NPL_NPU_ENCAP_L3_HEADER_TYPE_IPV4_TUNNEL:
        {
            return "NPL_NPU_ENCAP_L3_HEADER_TYPE_IPV4_TUNNEL(0x5)";
            break;
        }
        case NPL_NPU_ENCAP_L3_HEADER_TYPE_ILM_TUNNEL:
        {
            return "NPL_NPU_ENCAP_L3_HEADER_TYPE_ILM_TUNNEL(0x4)";
            break;
        }
        case NPL_NPU_ENCAP_L3_HEADER_TYPE_ILM_LABEL:
        {
            return "NPL_NPU_ENCAP_L3_HEADER_TYPE_ILM_LABEL(0x2)";
            break;
        }
        case NPL_NPU_ENCAP_L3_HEADER_TYPE_PWE_OR_MC_ACCOUNTING:
        {
            return "NPL_NPU_ENCAP_L3_HEADER_TYPE_PWE_OR_MC_ACCOUNTING(0xd)";
            break;
        }
        case NPL_NPU_ENCAP_L3_HEADER_TYPE_VXLAN_NH:
        {
            return "NPL_NPU_ENCAP_L3_HEADER_TYPE_VXLAN_NH(0x0)";
            break;
        }
        case NPL_NPU_ENCAP_L3_HEADER_TYPE_VXLAN_HOST:
        {
            return "NPL_NPU_ENCAP_L3_HEADER_TYPE_VXLAN_HOST(0x6)";
            break;
        }
        case NPL_NPU_ENCAP_L3_HEADER_TYPE_GRE:
        {
            return "NPL_NPU_ENCAP_L3_HEADER_TYPE_GRE(0x7)";
            break;
        }
        case NPL_NPU_ENCAP_L3_HEADER_TYPE_COLLAPSED_MC:
        {
            return "NPL_NPU_ENCAP_L3_HEADER_TYPE_COLLAPSED_MC(0xc)";
            break;
        }
        case NPL_NPU_ENCAP_L3_IBM:
        {
            return "NPL_NPU_ENCAP_L3_IBM(0xe)";
            break;
        }
        case NPL_NPU_ENCAP_L3_MC_INGRESS_REPLICATION:
        {
            return "NPL_NPU_ENCAP_L3_MC_INGRESS_REPLICATION(0xf)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_npu_encap_l3_header_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_npu_host_slice_e enum_instance)
{
    switch(enum_instance) {
        case NPL_NPU_HOST_SLICE:
        {
            return "NPL_NPU_HOST_SLICE(0x6)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_npu_host_slice_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_npu_mirror_or_redirect_encap_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_NPU_ENCAP_MIRROR_OR_REDIRECT:
        {
            return "NPL_NPU_ENCAP_MIRROR_OR_REDIRECT(0xe)";
            break;
        }
        case NPL_NPU_ENCAP_REMOTE_MIRROR:
        {
            return "NPL_NPU_ENCAP_REMOTE_MIRROR(0x5)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_npu_mirror_or_redirect_encap_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_npuh_compund_table_id_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ETH_TBL_ID:
        {
            return "NPL_ETH_TBL_ID(0x0)";
            break;
        }
        case NPL_BFD_TBL_ID:
        {
            return "NPL_BFD_TBL_ID(0x1)";
            break;
        }
        case NPL_PFC_TBL_ID:
        {
            return "NPL_PFC_TBL_ID(0x2)";
            break;
        }
        case NPL_PFC_CONG_TBL_ID:
        {
            return "NPL_PFC_CONG_TBL_ID(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_npuh_compund_table_id_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_npuh_eventq_id_e enum_instance)
{
    switch(enum_instance) {
        case NPL_NPUH_EVENTQ_PFC_ID:
        {
            return "NPL_NPUH_EVENTQ_PFC_ID(0x0)";
            break;
        }
        case NPL_NPUH_EVENTQ_BFD_ID:
        {
            return "NPL_NPUH_EVENTQ_BFD_ID(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_npuh_eventq_id_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_npuh_eventq_id_location_e enum_instance)
{
    switch(enum_instance) {
        case NPL_NPUH_EVENTQ_ID_WIDTH:
        {
            return "NPL_NPUH_EVENTQ_ID_WIDTH(0x2)";
            break;
        }
        case NPL_NPUH_EVENTQ_ID_SHIFT:
        {
            return "NPL_NPUH_EVENTQ_ID_SHIFT(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_npuh_eventq_id_location_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_oamp_event_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_OAMP_EVENT_NONE:
        {
            return "NPL_OAMP_EVENT_NONE(0x0)";
            break;
        }
        case NPL_OAMP_EVENT_CCM_FROM_MEP_IN_LOC:
        {
            return "NPL_OAMP_EVENT_CCM_FROM_MEP_IN_LOC(0x1)";
            break;
        }
        case NPL_OAMP_EVENT_RDI_STATE_CHANGE:
        {
            return "NPL_OAMP_EVENT_RDI_STATE_CHANGE(0x2)";
            break;
        }
        case NPL_OAMP_EVENT_BFD_FLAG_CHANGE:
        {
            return "NPL_OAMP_EVENT_BFD_FLAG_CHANGE(0x3)";
            break;
        }
        case NPL_OAMP_EVENT_BFD_STATE_CHANGE:
        {
            return "NPL_OAMP_EVENT_BFD_STATE_CHANGE(0x4)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_oamp_event_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_obm_encap_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_OBM_REDIRECT:
        {
            return "NPL_OBM_REDIRECT(0x0)";
            break;
        }
        case NPL_OBM_INJECT_DOWN:
        {
            return "NPL_OBM_INJECT_DOWN(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_obm_encap_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_oqse_logical_port_map_4p_e enum_instance)
{
    switch(enum_instance) {
        case NPL_OQSE_LOGICAL_PORT_MAP_TPSE_4P:
        {
            return "NPL_OQSE_LOGICAL_PORT_MAP_TPSE_4P(0x0)";
            break;
        }
        case NPL_OQSE_LOGICAL_PORT_MAP_LPSE_2P:
        {
            return "NPL_OQSE_LOGICAL_PORT_MAP_LPSE_2P(0x1)";
            break;
        }
        case NPL_OQSE_LOGICAL_PORT_MAP_LPSE_4P:
        {
            return "NPL_OQSE_LOGICAL_PORT_MAP_LPSE_4P(0x2)";
            break;
        }
        case NPL_OQSE_LOGICAL_PORT_MAP_IS_8P:
        {
            return "NPL_OQSE_LOGICAL_PORT_MAP_IS_8P(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_oqse_logical_port_map_4p_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_oqse_logical_port_map_8p_e enum_instance)
{
    switch(enum_instance) {
        case NPL_OQSE_LOGICAL_PORT_MAP_TPSE_8P:
        {
            return "NPL_OQSE_LOGICAL_PORT_MAP_TPSE_8P(0x3)";
            break;
        }
        case NPL_OQSE_LOGICAL_PORT_MAP_LPSE_8P:
        {
            return "NPL_OQSE_LOGICAL_PORT_MAP_LPSE_8P(0x7)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_oqse_logical_port_map_8p_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_oqse_topology_2p_e enum_instance)
{
    switch(enum_instance) {
        case NPL_OQSE_TOPOLOGY_SP_SP:
        {
            return "NPL_OQSE_TOPOLOGY_SP_SP(0x0)";
            break;
        }
        case NPL_OQSE_TOPOLOGY_SP_WFQ:
        {
            return "NPL_OQSE_TOPOLOGY_SP_WFQ(0x1)";
            break;
        }
        case NPL_OQSE_TOPOLOGY_WFQ_SP:
        {
            return "NPL_OQSE_TOPOLOGY_WFQ_SP(0x2)";
            break;
        }
        case NPL_OQSE_TOPOLOGY_WFQ_WFQ:
        {
            return "NPL_OQSE_TOPOLOGY_WFQ_WFQ(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_oqse_topology_2p_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_oqse_topology_4p_e enum_instance)
{
    switch(enum_instance) {
        case NPL_OQSE_TOPOLOGY_4SP:
        {
            return "NPL_OQSE_TOPOLOGY_4SP(0x0)";
            break;
        }
        case NPL_OQSE_TOPOLOGY_3SP_2WFQ:
        {
            return "NPL_OQSE_TOPOLOGY_3SP_2WFQ(0x1)";
            break;
        }
        case NPL_OQSE_TOPOLOGY_2SP_3WFQ:
        {
            return "NPL_OQSE_TOPOLOGY_2SP_3WFQ(0x2)";
            break;
        }
        case NPL_OQSE_TOPOLOGY_4WFQ:
        {
            return "NPL_OQSE_TOPOLOGY_4WFQ(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_oqse_topology_4p_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_oqse_topology_8p_e enum_instance)
{
    switch(enum_instance) {
        case NPL_OQSE_TOPOLOGY_8SP:
        {
            return "NPL_OQSE_TOPOLOGY_8SP(0x0)";
            break;
        }
        case NPL_OQSE_TOPOLOGY_7SP_2WFQ:
        {
            return "NPL_OQSE_TOPOLOGY_7SP_2WFQ(0x1)";
            break;
        }
        case NPL_OQSE_TOPOLOGY_6SP_3WFQ:
        {
            return "NPL_OQSE_TOPOLOGY_6SP_3WFQ(0x2)";
            break;
        }
        case NPL_OQSE_TOPOLOGY_5SP_4WFQ:
        {
            return "NPL_OQSE_TOPOLOGY_5SP_4WFQ(0x3)";
            break;
        }
        case NPL_OQSE_TOPOLOGY_4SP_5WFQ:
        {
            return "NPL_OQSE_TOPOLOGY_4SP_5WFQ(0x4)";
            break;
        }
        case NPL_OQSE_TOPOLOGY_3SP_6WFQ:
        {
            return "NPL_OQSE_TOPOLOGY_3SP_6WFQ(0x5)";
            break;
        }
        case NPL_OQSE_TOPOLOGY_2SP_7WFQ:
        {
            return "NPL_OQSE_TOPOLOGY_2SP_7WFQ(0x6)";
            break;
        }
        case NPL_OQSE_TOPOLOGY_8WFQ:
        {
            return "NPL_OQSE_TOPOLOGY_8WFQ(0x7)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_oqse_topology_8p_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_pd_rx_tm_destination_mask_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TM_DESTINATION_MASK_MCID:
        {
            return "NPL_TM_DESTINATION_MASK_MCID(0xf0000)";
            break;
        }
        case NPL_TM_DESTINATION_MASK_VOQ:
        {
            return "NPL_TM_DESTINATION_MASK_VOQ(0xe0000)";
            break;
        }
        case NPL_TM_DESTINATION_MASK_DSP:
        {
            return "NPL_TM_DESTINATION_MASK_DSP(0xd0000)";
            break;
        }
        case NPL_TM_DESTINATION_MASK_DOQ_AND_DS:
        {
            return "NPL_TM_DESTINATION_MASK_DOQ_AND_DS(0xd8000)";
            break;
        }
        case NPL_TM_DESTINATION_MASK_SLB_VOQ_CTXT:
        {
            return "NPL_TM_DESTINATION_MASK_SLB_VOQ_CTXT(0xd4000)";
            break;
        }
        case NPL_TM_DESTINATION_MASK_FABRIC_LBGID:
        {
            return "NPL_TM_DESTINATION_MASK_FABRIC_LBGID(0xda000)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_pd_rx_tm_destination_mask_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_per_pif_trap_mode_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PER_PIF_TRAP_MODE_DISABLED:
        {
            return "NPL_PER_PIF_TRAP_MODE_DISABLED(0x0)";
            break;
        }
        case NPL_PER_PIF_TRAP_MODE_ENABLED:
        {
            return "NPL_PER_PIF_TRAP_MODE_ENABLED(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_per_pif_trap_mode_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_plb_header_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PLB_HEADER_TYPE_SN_OR_TS1:
        {
            return "NPL_PLB_HEADER_TYPE_SN_OR_TS1(0x0)";
            break;
        }
        case NPL_PLB_HEADER_TYPE_TS3:
        {
            return "NPL_PLB_HEADER_TYPE_TS3(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_plb_header_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_plb_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PLB_TYPE_TS:
        {
            return "NPL_PLB_TYPE_TS(0x0)";
            break;
        }
        case NPL_PLB_TYPE_SN:
        {
            return "NPL_PLB_TYPE_SN(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_plb_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_port_mirror_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PORT_MIRROR_TYPE_UN_CONDITIONED:
        {
            return "NPL_PORT_MIRROR_TYPE_UN_CONDITIONED(0x0)";
            break;
        }
        case NPL_PORT_MIRROR_TYPE_CONDITIONED:
        {
            return "NPL_PORT_MIRROR_TYPE_CONDITIONED(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_port_mirror_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_proto_index_e enum_instance)
{
    switch(enum_instance) {
        case NPL_CURRENT_PROTO_INDEX:
        {
            return "NPL_CURRENT_PROTO_INDEX(0x0)";
            break;
        }
        case NPL_NEXT_PROTO_INDEX:
        {
            return "NPL_NEXT_PROTO_INDEX(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_proto_index_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_protocol_suffix_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PROTOCOL_TYPE_IPV4_SUFFIX:
        {
            return "NPL_PROTOCOL_TYPE_IPV4_SUFFIX(0x4)";
            break;
        }
        case NPL_PROTOCOL_TYPE_IPV6_SUFFIX:
        {
            return "NPL_PROTOCOL_TYPE_IPV6_SUFFIX(0x6)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_protocol_suffix_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_protocol_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PROTOCOL_TYPE_UNKNOWN:
        {
            return "NPL_PROTOCOL_TYPE_UNKNOWN(0x0)";
            break;
        }
        case NPL_PROTOCOL_TYPE_ETHERNET:
        {
            return "NPL_PROTOCOL_TYPE_ETHERNET(0x1)";
            break;
        }
        case NPL_PROTOCOL_TYPE_ETHERNET_VLAN:
        {
            return "NPL_PROTOCOL_TYPE_ETHERNET_VLAN(0x11)";
            break;
        }
        case NPL_PROTOCOL_TYPE_ICMP:
        {
            return "NPL_PROTOCOL_TYPE_ICMP(0x2)";
            break;
        }
        case NPL_PROTOCOL_TYPE_IPV4:
        {
            return "NPL_PROTOCOL_TYPE_IPV4(0x4)";
            break;
        }
        case NPL_PROTOCOL_TYPE_IPV4_L4:
        {
            return "NPL_PROTOCOL_TYPE_IPV4_L4(0x14)";
            break;
        }
        case NPL_PROTOCOL_TYPE_IPV6:
        {
            return "NPL_PROTOCOL_TYPE_IPV6(0x6)";
            break;
        }
        case NPL_PROTOCOL_TYPE_IPV6_L4:
        {
            return "NPL_PROTOCOL_TYPE_IPV6_L4(0x16)";
            break;
        }
        case NPL_PROTOCOL_TYPE_MPLS:
        {
            return "NPL_PROTOCOL_TYPE_MPLS(0x7)";
            break;
        }
        case NPL_PROTOCOL_TYPE_UDP:
        {
            return "NPL_PROTOCOL_TYPE_UDP(0xf)";
            break;
        }
        case NPL_PROTOCOL_TYPE_TCP:
        {
            return "NPL_PROTOCOL_TYPE_TCP(0xe)";
            break;
        }
        case NPL_PROTOCOL_TYPE_IGMP:
        {
            return "NPL_PROTOCOL_TYPE_IGMP(0xd)";
            break;
        }
        case NPL_PROTOCOL_TYPE_GRE:
        {
            return "NPL_PROTOCOL_TYPE_GRE(0x10)";
            break;
        }
        case NPL_PROTOCOL_TYPE_PTP:
        {
            return "NPL_PROTOCOL_TYPE_PTP(0x12)";
            break;
        }
        case NPL_PROTOCOL_TYPE_VXLAN:
        {
            return "NPL_PROTOCOL_TYPE_VXLAN(0x13)";
            break;
        }
        case NPL_PROTOCOL_TYPE_CFM:
        {
            return "NPL_PROTOCOL_TYPE_CFM(0x15)";
            break;
        }
        case NPL_PROTOCOL_TYPE_MACSEC:
        {
            return "NPL_PROTOCOL_TYPE_MACSEC(0x17)";
            break;
        }
        case NPL_PROTOCOL_TYPE_PFC:
        {
            return "NPL_PROTOCOL_TYPE_PFC(0x18)";
            break;
        }
        case NPL_PROTOCOL_TYPE_ARP:
        {
            return "NPL_PROTOCOL_TYPE_ARP(0x19)";
            break;
        }
        case NPL_PROTOCOL_TYPE_VLAN_0:
        {
            return "NPL_PROTOCOL_TYPE_VLAN_0(0x8)";
            break;
        }
        case NPL_PROTOCOL_TYPE_VLAN_1:
        {
            return "NPL_PROTOCOL_TYPE_VLAN_1(0x9)";
            break;
        }
        case NPL_PROTOCOL_TYPE_VLAN_2:
        {
            return "NPL_PROTOCOL_TYPE_VLAN_2(0xa)";
            break;
        }
        case NPL_PROTOCOL_TYPE_VLAN_3:
        {
            return "NPL_PROTOCOL_TYPE_VLAN_3(0xb)";
            break;
        }
        case NPL_PROTOCOL_TYPE_GTP:
        {
            return "NPL_PROTOCOL_TYPE_GTP(0xc)";
            break;
        }
        case NPL_PROTOCOL_TYPE_SVL:
        {
            return "NPL_PROTOCOL_TYPE_SVL(0x1d)";
            break;
        }
        case NPL_PROTOCOL_TYPE_PUNT:
        {
            return "NPL_PROTOCOL_TYPE_PUNT(0x1e)";
            break;
        }
        case NPL_PROTOCOL_TYPE_INJECT:
        {
            return "NPL_PROTOCOL_TYPE_INJECT(0x1f)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_protocol_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ptp_transparent_signaling_mode_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PTP_TRANSPARENT_NOP:
        {
            return "NPL_PTP_TRANSPARENT_NOP(0x0)";
            break;
        }
        case NPL_PTP_TRANSPARENT_NW_IPV4:
        {
            return "NPL_PTP_TRANSPARENT_NW_IPV4(0x3)";
            break;
        }
        case NPL_PTP_TRANSPARENT_NW_IPV6:
        {
            return "NPL_PTP_TRANSPARENT_NW_IPV6(0x7)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ptp_transparent_signaling_mode_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ptp_transport_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PTP_TRANSPORT_ETHERNET:
        {
            return "NPL_PTP_TRANSPORT_ETHERNET(0x0)";
            break;
        }
        case NPL_PTP_TRANSPORT_IPV4:
        {
            return "NPL_PTP_TRANSPORT_IPV4(0x1)";
            break;
        }
        case NPL_PTP_TRANSPORT_IPV6:
        {
            return "NPL_PTP_TRANSPORT_IPV6(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ptp_transport_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ptp_ts_cmd_op_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TS_CMD_OP_NOP:
        {
            return "NPL_TS_CMD_OP_NOP(0x0)";
            break;
        }
        case NPL_TS_CMD_UPDATE_CF:
        {
            return "NPL_TS_CMD_UPDATE_CF(0x1)";
            break;
        }
        case NPL_TS_CMD_UPDATE_CF_UPDATE_CS:
        {
            return "NPL_TS_CMD_UPDATE_CF_UPDATE_CS(0x2)";
            break;
        }
        case NPL_TS_CMD_UPDATE_CF_RESET_CS:
        {
            return "NPL_TS_CMD_UPDATE_CF_RESET_CS(0x3)";
            break;
        }
        case NPL_TS_CMD_STAMP_DEV_TIME:
        {
            return "NPL_TS_CMD_STAMP_DEV_TIME(0x5)";
            break;
        }
        case NPL_TS_CMD_STAMP_DEV_TIME_UPDATE_CS:
        {
            return "NPL_TS_CMD_STAMP_DEV_TIME_UPDATE_CS(0x6)";
            break;
        }
        case NPL_TS_CMD_STAMP_DEV_TIME_RESET_CS:
        {
            return "NPL_TS_CMD_STAMP_DEV_TIME_RESET_CS(0x7)";
            break;
        }
        case NPL_TS_CMD_STAMP_IN_SYS_TIME:
        {
            return "NPL_TS_CMD_STAMP_IN_SYS_TIME(0x8)";
            break;
        }
        case NPL_TS_CMD_RECORD:
        {
            return "NPL_TS_CMD_RECORD(0x9)";
            break;
        }
        case NPL_TS_CMD_RECORD_UPDATE_CS:
        {
            return "NPL_TS_CMD_RECORD_UPDATE_CS(0xa)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ptp_ts_cmd_op_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_punt_cud_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PUNT_CUD_TYPE_DCF:
        {
            return "NPL_PUNT_CUD_TYPE_DCF(0x0)";
            break;
        }
        case NPL_PUNT_CUD_TYPE_IBM:
        {
            return "NPL_PUNT_CUD_TYPE_IBM(0x1)";
            break;
        }
        case NPL_PUNT_CUD_TYPE_MC_IBM:
        {
            return "NPL_PUNT_CUD_TYPE_MC_IBM(0x2)";
            break;
        }
        case NPL_PUNT_CUD_TYPE_STD:
        {
            return "NPL_PUNT_CUD_TYPE_STD(0x6)";
            break;
        }
        case NPL_PUNT_CUD_TYPE_OBM:
        {
            return "NPL_PUNT_CUD_TYPE_OBM(0x4)";
            break;
        }
        case NPL_PUNT_CUD_TYPE_MC_LPTS:
        {
            return "NPL_PUNT_CUD_TYPE_MC_LPTS(0x8)";
            break;
        }
        case NPL_PUNT_CUD_TYPE_MC_ROUTABLE:
        {
            return "NPL_PUNT_CUD_TYPE_MC_ROUTABLE(0xc)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_punt_cud_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_punt_extension_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PUNT_EXT_TYPE_1:
        {
            return "NPL_PUNT_EXT_TYPE_1(0x0)";
            break;
        }
        case NPL_PUNT_EXT_TYPE_2:
        {
            return "NPL_PUNT_EXT_TYPE_2(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_punt_extension_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_punt_header_format_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PUNT_HEADER_FORMAT_TYPE_INTERNAL:
        {
            return "NPL_PUNT_HEADER_FORMAT_TYPE_INTERNAL(0x0)";
            break;
        }
        case NPL_PUNT_HEADER_FORMAT_TYPE_ERSPAN_II:
        {
            return "NPL_PUNT_HEADER_FORMAT_TYPE_ERSPAN_II(0x1)";
            break;
        }
        case NPL_PUNT_HEADER_FORMAT_TYPE_ERSPAN_III:
        {
            return "NPL_PUNT_HEADER_FORMAT_TYPE_ERSPAN_III(0x2)";
            break;
        }
        case NPL_PUNT_HEADER_FORMAT_TYPE_UDP:
        {
            return "NPL_PUNT_HEADER_FORMAT_TYPE_UDP(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_punt_header_format_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_punt_nw_encap_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PUNT_NW_NO_ENCAP_TYPE:
        {
            return "NPL_PUNT_NW_NO_ENCAP_TYPE(0x0)";
            break;
        }
        case NPL_PUNT_NW_ETH_ENCAP_TYPE:
        {
            return "NPL_PUNT_NW_ETH_ENCAP_TYPE(0x1)";
            break;
        }
        case NPL_PUNT_NW_ETH_NO_VLAN_ENCAP_TYPE:
        {
            return "NPL_PUNT_NW_ETH_NO_VLAN_ENCAP_TYPE(0x9)";
            break;
        }
        case NPL_PUNT_NW_IP_UDP_ENCAP_TYPE:
        {
            return "NPL_PUNT_NW_IP_UDP_ENCAP_TYPE(0x2)";
            break;
        }
        case NPL_PUNT_NW_IP_UDP_NO_VLAN_ENCAP_TYPE:
        {
            return "NPL_PUNT_NW_IP_UDP_NO_VLAN_ENCAP_TYPE(0xa)";
            break;
        }
        case NPL_PUNT_NW_IPV6_UDP_ENCAP_TYPE:
        {
            return "NPL_PUNT_NW_IPV6_UDP_ENCAP_TYPE(0x3)";
            break;
        }
        case NPL_PUNT_NW_IPV6_UDP_NO_VLAN_ENCAP_TYPE:
        {
            return "NPL_PUNT_NW_IPV6_UDP_NO_VLAN_ENCAP_TYPE(0xb)";
            break;
        }
        case NPL_PUNT_NW_IP_TUNNEL_ENCAP_TYPE:
        {
            return "NPL_PUNT_NW_IP_TUNNEL_ENCAP_TYPE(0x4)";
            break;
        }
        case NPL_PUNT_NW_IP_TUNNEL_NO_VLAN_ENCAP_TYPE:
        {
            return "NPL_PUNT_NW_IP_TUNNEL_NO_VLAN_ENCAP_TYPE(0xc)";
            break;
        }
        case NPL_PUNT_NW_IPV6_TUNNEL_ENCAP_TYPE:
        {
            return "NPL_PUNT_NW_IPV6_TUNNEL_ENCAP_TYPE(0x5)";
            break;
        }
        case NPL_PUNT_NW_IPV6_TUNNEL_NO_VLAN_ENCAP_TYPE:
        {
            return "NPL_PUNT_NW_IPV6_TUNNEL_NO_VLAN_ENCAP_TYPE(0xd)";
            break;
        }
        case NPL_PUNT_NW_PFC_ENCAP_TYPE:
        {
            return "NPL_PUNT_NW_PFC_ENCAP_TYPE(0x6)";
            break;
        }
        case NPL_PUNT_NW_NPU_HOST_ENCAP_TYPE:
        {
            return "NPL_PUNT_NW_NPU_HOST_ENCAP_TYPE(0xe)";
            break;
        }
        case NPL_PUNT_HOST_DMA_ENCAP_TYPE:
        {
            return "NPL_PUNT_HOST_DMA_ENCAP_TYPE(0xf)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_punt_nw_encap_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_punt_source_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PUNT_SRC_INBOUND_MIRROR:
        {
            return "NPL_PUNT_SRC_INBOUND_MIRROR(0x0)";
            break;
        }
        case NPL_PUNT_SRC_SNOOP:
        {
            return "NPL_PUNT_SRC_SNOOP(0x1)";
            break;
        }
        case NPL_PUNT_SRC_LPTS_FORWARDING:
        {
            return "NPL_PUNT_SRC_LPTS_FORWARDING(0x2)";
            break;
        }
        case NPL_PUNT_SRC_INGRESS_ACL:
        {
            return "NPL_PUNT_SRC_INGRESS_ACL(0x3)";
            break;
        }
        case NPL_PUNT_SRC_INGRESS_TRAP:
        {
            return "NPL_PUNT_SRC_INGRESS_TRAP(0x4)";
            break;
        }
        case NPL_PUNT_SRC_INGRESS_INCOMPLETE:
        {
            return "NPL_PUNT_SRC_INGRESS_INCOMPLETE(0x5)";
            break;
        }
        case NPL_PUNT_SRC_INGRESS_BFD:
        {
            return "NPL_PUNT_SRC_INGRESS_BFD(0x8)";
            break;
        }
        case NPL_PUNT_SRC_OUTBOUND_MIRROR:
        {
            return "NPL_PUNT_SRC_OUTBOUND_MIRROR(0xa)";
            break;
        }
        case NPL_PUNT_SRC_EGRESS_ACL:
        {
            return "NPL_PUNT_SRC_EGRESS_ACL(0xb)";
            break;
        }
        case NPL_PUNT_SRC_EGRESS_TRAP:
        {
            return "NPL_PUNT_SRC_EGRESS_TRAP(0xc)";
            break;
        }
        case NPL_PUNT_SRC_EGRESS_TM_DROP:
        {
            return "NPL_PUNT_SRC_EGRESS_TM_DROP(0xd)";
            break;
        }
        case NPL_PUNT_SRC_ERROR:
        {
            return "NPL_PUNT_SRC_ERROR(0x7)";
            break;
        }
        case NPL_PUNT_SRC_LC:
        {
            return "NPL_PUNT_SRC_LC(0xe)";
            break;
        }
        case NPL_PUNT_SRC_RSP:
        {
            return "NPL_PUNT_SRC_RSP(0xf)";
            break;
        }
        case NPL_PUNT_SRC_NPUH:
        {
            return "NPL_PUNT_SRC_NPUH(0x6)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_punt_source_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_q_or_meter_cntr_e enum_instance)
{
    switch(enum_instance) {
        case NPL_Q_CNTR:
        {
            return "NPL_Q_CNTR(0x0)";
            break;
        }
        case NPL_METER_CNTR:
        {
            return "NPL_METER_CNTR(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_q_or_meter_cntr_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_qos_first_macro_code_e enum_instance)
{
    switch(enum_instance) {
        case NPL_QOS_ENE_MACRO_NOP:
        {
            return "NPL_QOS_ENE_MACRO_NOP(0x0)";
            break;
        }
        case NPL_QOS_ENE_MACRO_L3_VPN:
        {
            return "NPL_QOS_ENE_MACRO_L3_VPN(0x1)";
            break;
        }
        case NPL_QOS_ENE_MACRO_EL:
        {
            return "NPL_QOS_ENE_MACRO_EL(0x2)";
            break;
        }
        case NPL_QOS_ENE_MACRO_L3_VPN_EL:
        {
            return "NPL_QOS_ENE_MACRO_L3_VPN_EL(0x3)";
            break;
        }
        case NPL_QOS_ENE_MACRO_L2_VPN:
        {
            return "NPL_QOS_ENE_MACRO_L2_VPN(0x4)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_qos_first_macro_code_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_qos_remark_mapping_key_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_QOS_REMARK_USE_QOS_GROUP:
        {
            return "NPL_QOS_REMARK_USE_QOS_GROUP(0x0)";
            break;
        }
        case NPL_QOS_REMARK_USE_QOS_TAG:
        {
            return "NPL_QOS_REMARK_USE_QOS_TAG(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_qos_remark_mapping_key_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_qos_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_QOS_TYPE_PIPE:
        {
            return "NPL_QOS_TYPE_PIPE(0x0)";
            break;
        }
        case NPL_QOS_TYPE_UNIFORM:
        {
            return "NPL_QOS_TYPE_UNIFORM(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_qos_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_rcy_tx_command_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RCY_REDIRECT_COMMAND_TX_ONLY_2:
        {
            return "NPL_RCY_REDIRECT_COMMAND_TX_ONLY_2(0x0)";
            break;
        }
        case NPL_RCY_REDIRECT_COMMAND_TX_ONLY:
        {
            return "NPL_RCY_REDIRECT_COMMAND_TX_ONLY(0x1)";
            break;
        }
        case NPL_RCY_REDIRECT_COMMAND_RCY_ONLY:
        {
            return "NPL_RCY_REDIRECT_COMMAND_RCY_ONLY(0x2)";
            break;
        }
        case NPL_RCY_REDIRECT_COMMAND_RCY_AND_TX:
        {
            return "NPL_RCY_REDIRECT_COMMAND_RCY_AND_TX(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_rcy_tx_command_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_redirect_code_e enum_instance)
{
    switch(enum_instance) {
        case NPL_REDIRECT_CODE_DEFAULT:
        {
            return "NPL_REDIRECT_CODE_DEFAULT(0x0)";
            break;
        }
        case NPL_REDIRECT_CODE_NO_SERVICE_MAPPING:
        {
            return "NPL_REDIRECT_CODE_NO_SERVICE_MAPPING(0xbf)";
            break;
        }
        case NPL_REDIRECT_CODE_AC_SAME_INTERFACE:
        {
            return "NPL_REDIRECT_CODE_AC_SAME_INTERFACE(0xbe)";
            break;
        }
        case NPL_REDIRECT_CODE_AC_DOWN_MEP:
        {
            return "NPL_REDIRECT_CODE_AC_DOWN_MEP(0xc0)";
            break;
        }
        case NPL_REDIRECT_CODE_AC_MIP:
        {
            return "NPL_REDIRECT_CODE_AC_MIP(0xc1)";
            break;
        }
        case NPL_REDIRECT_CODE_AC_UP_MEP:
        {
            return "NPL_REDIRECT_CODE_AC_UP_MEP(0xc2)";
            break;
        }
        case NPL_REDIRECT_CODE_DROP_NO_RECYCLE:
        {
            return "NPL_REDIRECT_CODE_DROP_NO_RECYCLE(0xc3)";
            break;
        }
        case NPL_REDIRECT_CODE_LPM_INCOMPLETE_0:
        {
            return "NPL_REDIRECT_CODE_LPM_INCOMPLETE_0(0xc4)";
            break;
        }
        case NPL_REDIRECT_CODE_LPM_INCOMPLETE_1:
        {
            return "NPL_REDIRECT_CODE_LPM_INCOMPLETE_1(0xc5)";
            break;
        }
        case NPL_REDIRECT_CODE_LPM_INCOMPLETE_2:
        {
            return "NPL_REDIRECT_CODE_LPM_INCOMPLETE_2(0xc6)";
            break;
        }
        case NPL_REDIRECT_CODE_LPM_INCOMPLETE_3:
        {
            return "NPL_REDIRECT_CODE_LPM_INCOMPLETE_3(0xc7)";
            break;
        }
        case NPL_REDIRECT_CODE_PFC_PILOT:
        {
            return "NPL_REDIRECT_CODE_PFC_PILOT(0xcc)";
            break;
        }
        case NPL_REDIRECT_CODE_PFC_MEASUREMENT:
        {
            return "NPL_REDIRECT_CODE_PFC_MEASUREMENT(0xcd)";
            break;
        }
        case NPL_REDIRECT_CODE_LPM_MC_LPTS:
        {
            return "NPL_REDIRECT_CODE_LPM_MC_LPTS(0xce)";
            break;
        }
        case NPL_REDIRECT_CODE_LPM_LPTS:
        {
            return "NPL_REDIRECT_CODE_LPM_LPTS(0xcf)";
            break;
        }
        case NPL_REDIRECT_CODE_L2_ACL_DROP:
        {
            return "NPL_REDIRECT_CODE_L2_ACL_DROP(0xca)";
            break;
        }
        case NPL_REDIRECT_CODE_L3_ACL_DROP:
        {
            return "NPL_REDIRECT_CODE_L3_ACL_DROP(0xcb)";
            break;
        }
        case NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT:
        {
            return "NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT(0xd0)";
            break;
        }
        case NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT1:
        {
            return "NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT1(0xd1)";
            break;
        }
        case NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT2:
        {
            return "NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT2(0xd2)";
            break;
        }
        case NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT3:
        {
            return "NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT3(0xd3)";
            break;
        }
        case NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT4:
        {
            return "NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT4(0xd4)";
            break;
        }
        case NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT5:
        {
            return "NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT5(0xd5)";
            break;
        }
        case NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT6:
        {
            return "NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT6(0xd6)";
            break;
        }
        case NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT7:
        {
            return "NPL_REDIRECT_CODE_L2_ACL_FORCE_PUNT7(0xd7)";
            break;
        }
        case NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT:
        {
            return "NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT(0xd8)";
            break;
        }
        case NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT1:
        {
            return "NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT1(0xd9)";
            break;
        }
        case NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT2:
        {
            return "NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT2(0xda)";
            break;
        }
        case NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT3:
        {
            return "NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT3(0xdb)";
            break;
        }
        case NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT4:
        {
            return "NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT4(0xdc)";
            break;
        }
        case NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT5:
        {
            return "NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT5(0xdd)";
            break;
        }
        case NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT6:
        {
            return "NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT6(0xde)";
            break;
        }
        case NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT7:
        {
            return "NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT7(0xdf)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_redirect_code_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_redirect_destination_e enum_instance)
{
    switch(enum_instance) {
        case NPL_REDIRECT_DESTINATION_DMA:
        {
            return "NPL_REDIRECT_DESTINATION_DMA(0x0)";
            break;
        }
        case NPL_REDIRECT_DESTINATION_NPU_HOST:
        {
            return "NPL_REDIRECT_DESTINATION_NPU_HOST(0x1)";
            break;
        }
        case NPL_REDIRECT_DESTINATION_DCF:
        {
            return "NPL_REDIRECT_DESTINATION_DCF(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_redirect_destination_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_redirect_is_drop_action_e enum_instance)
{
    switch(enum_instance) {
        case NPL_NOT_DROP_ACTION:
        {
            return "NPL_NOT_DROP_ACTION(0x0)";
            break;
        }
        case NPL_IS_DROP_ACTION:
        {
            return "NPL_IS_DROP_ACTION(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_redirect_is_drop_action_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_redirect_or_obm_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IS_REDIRECT:
        {
            return "NPL_IS_REDIRECT(0x0)";
            break;
        }
        case NPL_IS_OUTBOUND_MIRROR:
        {
            return "NPL_IS_OUTBOUND_MIRROR(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_redirect_or_obm_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_reserved_label_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RESERVED_LABEL_GAL:
        {
            return "NPL_RESERVED_LABEL_GAL(0xd)";
            break;
        }
        case NPL_RESERVED_LABEL_OAM:
        {
            return "NPL_RESERVED_LABEL_OAM(0xe)";
            break;
        }
        case NPL_RESERVED_LABEL_EXT:
        {
            return "NPL_RESERVED_LABEL_EXT(0xf)";
            break;
        }
        case NPL_RESERVED_LABEL_RA:
        {
            return "NPL_RESERVED_LABEL_RA(0x1)";
            break;
        }
        case NPL_RESERVED_LABEL_ELI:
        {
            return "NPL_RESERVED_LABEL_ELI(0x7)";
            break;
        }
        case NPL_RESERVED_LABEL_NULL_V4:
        {
            return "NPL_RESERVED_LABEL_NULL_V4(0x0)";
            break;
        }
        case NPL_RESERVED_LABEL_NULL_V6:
        {
            return "NPL_RESERVED_LABEL_NULL_V6(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_reserved_label_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_resolution_add_qos_mapping_mode_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED:
        {
            return "NPL_RESOLUTION_ADD_QOS_MAPPING_DISABLED(0x0)";
            break;
        }
        case NPL_RESOLUTION_ADD_QOS_MAPPING_ENALED:
        {
            return "NPL_RESOLUTION_ADD_QOS_MAPPING_ENALED(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_resolution_add_qos_mapping_mode_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_resolution_assoc_data_entry_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_NARROW:
        {
            return "NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_NARROW(0x0)";
            break;
        }
        case NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_WIDE:
        {
            return "NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_WIDE(0x1)";
            break;
        }
        case NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_NARROW_PROTECTION:
        {
            return "NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_NARROW_PROTECTION(0x2)";
            break;
        }
        case NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_WIDE_PROTECTION:
        {
            return "NPL_RESOLUTION_STAGE_ASSOC_DATA_ENTRY_TYPE_WIDE_PROTECTION(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_resolution_assoc_data_entry_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_resolution_dest_src_to_encap_mode_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS:
        {
            return "NPL_RESOLUTION_DEST_SRC_TO_ENCAP_BEFORE_PBTS(0x0)";
            break;
        }
        case NPL_RESOLUTION_DEST_SRC_TO_ENCAP_AFTER_PBTS:
        {
            return "NPL_RESOLUTION_DEST_SRC_TO_ENCAP_AFTER_PBTS(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_resolution_dest_src_to_encap_mode_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_resolution_dest_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_DESTINATION_TYPE_BVN:
        {
            return "NPL_DESTINATION_TYPE_BVN(0x0)";
            break;
        }
        case NPL_DESTINATION_TYPE_MC:
        {
            return "NPL_DESTINATION_TYPE_MC(0x1)";
            break;
        }
        case NPL_DESTINATION_TYPE_FLBG:
        {
            return "NPL_DESTINATION_TYPE_FLBG(0x2)";
            break;
        }
        case NPL_DESTINATION_TYPE_DSP:
        {
            return "NPL_DESTINATION_TYPE_DSP(0x3)";
            break;
        }
        case NPL_DESTINATION_TYPE_FEC:
        {
            return "NPL_DESTINATION_TYPE_FEC(0x4)";
            break;
        }
        case NPL_DESTINATION_TYPE_L2_DLP:
        {
            return "NPL_DESTINATION_TYPE_L2_DLP(0x5)";
            break;
        }
        case NPL_DESTINATION_TYPE_L2_DLPA_OR_ECMP:
        {
            return "NPL_DESTINATION_TYPE_L2_DLPA_OR_ECMP(0x6)";
            break;
        }
        case NPL_DESTINATION_TYPE_FRR:
        {
            return "NPL_DESTINATION_TYPE_FRR(0x7)";
            break;
        }
        case NPL_DESTINATION_TYPE_CE_PTR:
        {
            return "NPL_DESTINATION_TYPE_CE_PTR(0x8)";
            break;
        }
        case NPL_DESTINATION_TYPE_LEVEL2_ECMP:
        {
            return "NPL_DESTINATION_TYPE_LEVEL2_ECMP(0x9)";
            break;
        }
        case NPL_DESTINATION_TYPE_P_L3_NH:
        {
            return "NPL_DESTINATION_TYPE_P_L3_NH(0xa)";
            break;
        }
        case NPL_DESTINATION_TYPE_NPP:
        {
            return "NPL_DESTINATION_TYPE_NPP(0xb)";
            break;
        }
        case NPL_DESTINATION_TYPE_L3_NH:
        {
            return "NPL_DESTINATION_TYPE_L3_NH(0xc)";
            break;
        }
        case NPL_DESTINATION_TYPE_DSPA:
        {
            return "NPL_DESTINATION_TYPE_DSPA(0xd)";
            break;
        }
        case NPL_DESTINATION_TYPE_UNKNOWN:
        {
            return "NPL_DESTINATION_TYPE_UNKNOWN(0xe)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_resolution_dest_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_resolution_em_selector_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RESOLUTION_EM_SELECT_LB:
        {
            return "NPL_RESOLUTION_EM_SELECT_LB(0x0)";
            break;
        }
        case NPL_RESOLUTION_EM_SELECT_DEST_MAP:
        {
            return "NPL_RESOLUTION_EM_SELECT_DEST_MAP(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_resolution_em_selector_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_resolution_pbts_mode_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RESOLUTION_PBTS_DISABLED:
        {
            return "NPL_RESOLUTION_PBTS_DISABLED(0x0)";
            break;
        }
        case NPL_RESOLUTION_PBTS_ENABLED:
        {
            return "NPL_RESOLUTION_PBTS_ENABLED(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_resolution_pbts_mode_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_resolution_protection_selector_e enum_instance)
{
    switch(enum_instance) {
        case NPL_PROTECTION_SELECTOR_PROTECT:
        {
            return "NPL_PROTECTION_SELECTOR_PROTECT(0x0)";
            break;
        }
        case NPL_PROTECTION_SELECTOR_PRIMARY:
        {
            return "NPL_PROTECTION_SELECTOR_PRIMARY(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_resolution_protection_selector_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_resolution_state_assoc_data_entry_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RESOLUTION_ASSOC_DATA_ENTRY_NORMAL:
        {
            return "NPL_RESOLUTION_ASSOC_DATA_ENTRY_NORMAL(0x0)";
            break;
        }
        case NPL_RESOLUTION_ASSOC_DATA_ENTRY_PROTECTION:
        {
            return "NPL_RESOLUTION_ASSOC_DATA_ENTRY_PROTECTION(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_resolution_state_assoc_data_entry_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_resolution_table_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RESOLUTION_TABLE_FEC:
        {
            return "NPL_RESOLUTION_TABLE_FEC(0x0)";
            break;
        }
        case NPL_RESOLUTION_TABLE_STAGE0:
        {
            return "NPL_RESOLUTION_TABLE_STAGE0(0x1)";
            break;
        }
        case NPL_RESOLUTION_TABLE_STAGE1:
        {
            return "NPL_RESOLUTION_TABLE_STAGE1(0x2)";
            break;
        }
        case NPL_RESOLUTION_TABLE_STAGE2:
        {
            return "NPL_RESOLUTION_TABLE_STAGE2(0x3)";
            break;
        }
        case NPL_RESOLUTION_TABLE_STAGE3:
        {
            return "NPL_RESOLUTION_TABLE_STAGE3(0x4)";
            break;
        }
        case NPL_RESOLUTION_TABLE_LP_QUEUEING:
        {
            return "NPL_RESOLUTION_TABLE_LP_QUEUEING(0x5)";
            break;
        }
        case NPL_RESOLUTION_TABLE_PROCESSING_DONE:
        {
            return "NPL_RESOLUTION_TABLE_PROCESSING_DONE(0x7)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_resolution_table_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_rpf_mode_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RPF_MODE_NONE:
        {
            return "NPL_RPF_MODE_NONE(0x0)";
            break;
        }
        case NPL_RPF_MODE_STRICT:
        {
            return "NPL_RPF_MODE_STRICT(0x1)";
            break;
        }
        case NPL_RPF_MODE_LOOSE:
        {
            return "NPL_RPF_MODE_LOOSE(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_rpf_mode_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_rs_map_protocol_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IPV4_LB_HEADER_TYPE:
        {
            return "NPL_IPV4_LB_HEADER_TYPE(0x1)";
            break;
        }
        case NPL_IPV6_LB_HEADER_TYPE:
        {
            return "NPL_IPV6_LB_HEADER_TYPE(0x2)";
            break;
        }
        case NPL_ETHERNET_LB_HEADER_TYPE:
        {
            return "NPL_ETHERNET_LB_HEADER_TYPE(0x0)";
            break;
        }
        case NPL_MPLS_LB_HEADER_TYPE:
        {
            return "NPL_MPLS_LB_HEADER_TYPE(0x3)";
            break;
        }
        case NPL_NPL_HEADER_TYPE_UDP_OR_TCP:
        {
            return "NPL_NPL_HEADER_TYPE_UDP_OR_TCP(0x4)";
            break;
        }
        case NPL_NPL_HEADER_TYPE_VID:
        {
            return "NPL_NPL_HEADER_TYPE_VID(0x5)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_rs_map_protocol_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_rtf_profile_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RTF_PROFILE_0:
        {
            return "NPL_RTF_PROFILE_0(0x0)";
            break;
        }
        case NPL_RTF_PROFILE_1:
        {
            return "NPL_RTF_PROFILE_1(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_rtf_profile_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_rtf_res_profile_1_action_e enum_instance)
{
    switch(enum_instance) {
        case NPL_CHANGE_DEST_OVERIDE_METER_QOS_REMARK:
        {
            return "NPL_CHANGE_DEST_OVERIDE_METER_QOS_REMARK(0x0)";
            break;
        }
        case NPL_CHANGE_DEST_COUNTING:
        {
            return "NPL_CHANGE_DEST_COUNTING(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_rtf_res_profile_1_action_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_rtf_sec_action_e enum_instance)
{
    switch(enum_instance) {
        case NPL_NONE_ACL_ACTION:
        {
            return "NPL_NONE_ACL_ACTION(0x0)";
            break;
        }
        case NPL_CHANGE_DESTINATION:
        {
            return "NPL_CHANGE_DESTINATION(0x1)";
            break;
        }
        case NPL_DROP:
        {
            return "NPL_DROP(0x4)";
            break;
        }
        case NPL_FORCE_PUNT:
        {
            return "NPL_FORCE_PUNT(0x5)";
            break;
        }
        case NPL_PERMIT_COUNT_ENABLE:
        {
            return "NPL_PERMIT_COUNT_ENABLE(0x6)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_rtf_sec_action_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_rtf_stage_and_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RTF_NONE:
        {
            return "NPL_RTF_NONE(0x0)";
            break;
        }
        case NPL_RTF_OG:
        {
            return "NPL_RTF_OG(0x1)";
            break;
        }
        case NPL_RTF_PRE_FWD_L2:
        {
            return "NPL_RTF_PRE_FWD_L2(0x2)";
            break;
        }
        case NPL_RTF_PRE_FWD_L3:
        {
            return "NPL_RTF_PRE_FWD_L3(0x3)";
            break;
        }
        case NPL_RTF_POST_FWD_L2:
        {
            return "NPL_RTF_POST_FWD_L2(0x4)";
            break;
        }
        case NPL_RTF_POST_FWD_L3:
        {
            return "NPL_RTF_POST_FWD_L3(0x5)";
            break;
        }
        case NPL_RTF_RX_DONE_L2:
        {
            return "NPL_RTF_RX_DONE_L2(0x6)";
            break;
        }
        case NPL_RTF_RX_DONE_L3:
        {
            return "NPL_RTF_RX_DONE_L3(0x7)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_rtf_stage_and_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_rtf_stage_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RTF_PRE_FWD:
        {
            return "NPL_RTF_PRE_FWD(0x0)";
            break;
        }
        case NPL_RTF_POST_FWD:
        {
            return "NPL_RTF_POST_FWD(0x2)";
            break;
        }
        case NPL_RTF_RX_DONE:
        {
            return "NPL_RTF_RX_DONE(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_rtf_stage_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_rx_counter_compensation_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RX_COUNTER_COMPENSATION_NONE:
        {
            return "NPL_RX_COUNTER_COMPENSATION_NONE(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_rx_counter_compensation_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_rx_counters_set_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RX_COUNTERS_SET_TYPE_NO_SET:
        {
            return "NPL_RX_COUNTERS_SET_TYPE_NO_SET(0x0)";
            break;
        }
        case NPL_RX_COUNTERS_SET_TYPE_COLOR_AWARE:
        {
            return "NPL_RX_COUNTERS_SET_TYPE_COLOR_AWARE(0x1)";
            break;
        }
        case NPL_RX_COUNTERS_SET_TYPE_ADMISSION_AWARE:
        {
            return "NPL_RX_COUNTERS_SET_TYPE_ADMISSION_AWARE(0x2)";
            break;
        }
        case NPL_RX_COUNTERS_SET_TYPE_COLOR_AND_ADMISSION_AWARE:
        {
            return "NPL_RX_COUNTERS_SET_TYPE_COLOR_AND_ADMISSION_AWARE(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_rx_counters_set_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_scheduled_recycle_code_e enum_instance)
{
    switch(enum_instance) {
        case NPL_UNSCHEDULED_RECYCLE_CODE_NOP1:
        {
            return "NPL_UNSCHEDULED_RECYCLE_CODE_NOP1(0x0)";
            break;
        }
        case NPL_UNSCHEDULED_RECYCLE_CODE_NOP2:
        {
            return "NPL_UNSCHEDULED_RECYCLE_CODE_NOP2(0x1)";
            break;
        }
        case NPL_UNSCHEDULED_RECYCLE_CODE_REDIRECT:
        {
            return "NPL_UNSCHEDULED_RECYCLE_CODE_REDIRECT(0x2)";
            break;
        }
        case NPL_UNSCHEDULED_RECYCLE_CODE_MIRROR:
        {
            return "NPL_UNSCHEDULED_RECYCLE_CODE_MIRROR(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_scheduled_recycle_code_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_second_ene_macro_code_e enum_instance)
{
    switch(enum_instance) {
        case NPL_SECOND_ENE_NOP:
        {
            return "NPL_SECOND_ENE_NOP(0x0)";
            break;
        }
        case NPL_SECOND_ENE_1TO4:
        {
            return "NPL_SECOND_ENE_1TO4(0x1)";
            break;
        }
        case NPL_SECOND_ENE_INNER:
        {
            return "NPL_SECOND_ENE_INNER(0x2)";
            break;
        }
        case NPL_SECOND_ENE_1TO4_INNER:
        {
            return "NPL_SECOND_ENE_1TO4_INNER(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_second_ene_macro_code_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_service_mapping_logical_db_e enum_instance)
{
    switch(enum_instance) {
        case NPL_SM_LDB_AC_PORT:
        {
            return "NPL_SM_LDB_AC_PORT(0x0)";
            break;
        }
        case NPL_SM_LDB_AC_PORT_TAG:
        {
            return "NPL_SM_LDB_AC_PORT_TAG(0x4)";
            break;
        }
        case NPL_SM_LDB_AC_PORT_TAG_TAG_OR_DOUBLE_ACCESS:
        {
            return "NPL_SM_LDB_AC_PORT_TAG_TAG_OR_DOUBLE_ACCESS(0x8)";
            break;
        }
        case NPL_SM_LDB_PWE_TAG:
        {
            return "NPL_SM_LDB_PWE_TAG(0xc)";
            break;
        }
        case NPL_SM_LDB_MPLS_TERMINATION:
        {
            return "NPL_SM_LDB_MPLS_TERMINATION(0x5)";
            break;
        }
        case NPL_SM_LDB_VNI_RELAY_MAPPING:
        {
            return "NPL_SM_LDB_VNI_RELAY_MAPPING(0xe)";
            break;
        }
        case NPL_SM_LDB_SVID_RELAY_MAPPING:
        {
            return "NPL_SM_LDB_SVID_RELAY_MAPPING(0xf)";
            break;
        }
        case NPL_SM_LDB_IPV4_OVERLAY_MAPPING:
        {
            return "NPL_SM_LDB_IPV4_OVERLAY_MAPPING(0x6)";
            break;
        }
        case NPL_SM_LDB_INJECT_UP_RX_BASE:
        {
            return "NPL_SM_LDB_INJECT_UP_RX_BASE(0xb)";
            break;
        }
        case NPL_SM_LDB_INJECT_DOWN_REDIRECT_DATA:
        {
            return "NPL_SM_LDB_INJECT_DOWN_REDIRECT_DATA(0xa)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_service_mapping_logical_db_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_service_mapping_selector_e enum_instance)
{
    switch(enum_instance) {
        case NPL_SERVICE_MAPPING_SELECTOR_AC_PORT:
        {
            return "NPL_SERVICE_MAPPING_SELECTOR_AC_PORT(0x0)";
            break;
        }
        case NPL_SERVICE_MAPPING_SELECTOR_AC_PORT_TAG:
        {
            return "NPL_SERVICE_MAPPING_SELECTOR_AC_PORT_TAG(0x1)";
            break;
        }
        case NPL_SERVICE_MAPPING_SELECTOR_AC_PORT_TAG_TAG:
        {
            return "NPL_SERVICE_MAPPING_SELECTOR_AC_PORT_TAG_TAG(0x2)";
            break;
        }
        case NPL_SERVICE_MAPPING_SELECTOR_AC_DOUBLE_ACCESS:
        {
            return "NPL_SERVICE_MAPPING_SELECTOR_AC_DOUBLE_ACCESS(0x3)";
            break;
        }
        case NPL_SERVICE_MAPPING_SELECTOR_PWE_TAG:
        {
            return "NPL_SERVICE_MAPPING_SELECTOR_PWE_TAG(0x4)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_service_mapping_selector_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_sgacl_counter_offset_e enum_instance)
{
    switch(enum_instance) {
        case NPL_SGACL_COUNT_OFFSET_DROP:
        {
            return "NPL_SGACL_COUNT_OFFSET_DROP(0x1)";
            break;
        }
        case NPL_SGACL_COUNT_OFFSET_PERMIT:
        {
            return "NPL_SGACL_COUNT_OFFSET_PERMIT(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_sgacl_counter_offset_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_slice_mode_e enum_instance)
{
    switch(enum_instance) {
        case NPL_SLICE_MODE_FABRIC:
        {
            return "NPL_SLICE_MODE_FABRIC(0x0)";
            break;
        }
        case NPL_SLICE_MODE_NETWORK:
        {
            return "NPL_SLICE_MODE_NETWORK(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_slice_mode_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_snoop_code_e enum_instance)
{
    switch(enum_instance) {
        case NPL_SNOOP_CODE_BPDU:
        {
            return "NPL_SNOOP_CODE_BPDU(0x80)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_snoop_code_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_stage0_entry_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENTRY_TYPE_STAGE0_CE_PTR_L3_NH_VPN_INTER_AS_CE_PTR:
        {
            return "NPL_ENTRY_TYPE_STAGE0_CE_PTR_L3_NH_VPN_INTER_AS_CE_PTR(0x0)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE0_CE_PTR_L3_NH_VPN_INTER_AS_CE_PTR_WITH_COMMON_DATA:
        {
            return "NPL_ENTRY_TYPE_STAGE0_CE_PTR_L3_NH_VPN_INTER_AS_CE_PTR_WITH_COMMON_DATA(0x1)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE0_L3_NH_VPN_INTER_AS_CE_PTR_WITH_COMMON_DATA1:
        {
            return "NPL_ENTRY_TYPE_STAGE0_L3_NH_VPN_INTER_AS_CE_PTR_WITH_COMMON_DATA1(0x2)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE0_CE_PTR_P_L3_NH_VPN_INTER_AS_CE_PTR:
        {
            return "NPL_ENTRY_TYPE_STAGE0_CE_PTR_P_L3_NH_VPN_INTER_AS_CE_PTR(0x3)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE0_CE_PTR_P_L3_NH_VPN_INTER_AS_CE_PTR_WITH_COMMON_DATA:
        {
            return "NPL_ENTRY_TYPE_STAGE0_CE_PTR_P_L3_NH_VPN_INTER_AS_CE_PTR_WITH_COMMON_DATA(0x4)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE0_P_L3_NH_VPN_INTER_AS_CE_PTR_WITH_COMMON_DATA1:
        {
            return "NPL_ENTRY_TYPE_STAGE0_P_L3_NH_VPN_INTER_AS_CE_PTR_WITH_COMMON_DATA1(0x5)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE0_ECMP_DESTINATION:
        {
            return "NPL_ENTRY_TYPE_STAGE0_ECMP_DESTINATION(0x6)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE0_L2_DLP_DESTINATION_OVERLAY_NH:
        {
            return "NPL_ENTRY_TYPE_STAGE0_L2_DLP_DESTINATION_OVERLAY_NH(0x7)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE0_L2_DLP_DESTINATION:
        {
            return "NPL_ENTRY_TYPE_STAGE0_L2_DLP_DESTINATION(0x8)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE0_DESTINATION1:
        {
            return "NPL_ENTRY_TYPE_STAGE0_DESTINATION1(0x9)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE0_CE_PTR_L3_NH_IP_TUNNEL:
        {
            return "NPL_ENTRY_TYPE_STAGE0_CE_PTR_L3_NH_IP_TUNNEL(0xa)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE0_CE_PTR_LEVEL2_ECMP_IP_TUNNEL:
        {
            return "NPL_ENTRY_TYPE_STAGE0_CE_PTR_LEVEL2_ECMP_IP_TUNNEL(0xb)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE0_CE_PTR_DESTINATION_VPN_INTER_AS_CE_PTR:
        {
            return "NPL_ENTRY_TYPE_STAGE0_CE_PTR_DESTINATION_VPN_INTER_AS_CE_PTR(0xc)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE0_L2_DLP_DESTINATION_L2_DLP:
        {
            return "NPL_ENTRY_TYPE_STAGE0_L2_DLP_DESTINATION_L2_DLP(0xd)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_stage0_entry_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_stage1_entry_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENTRY_TYPE_STAGE1_LEVEL2_ECMP_DESTINATION:
        {
            return "NPL_ENTRY_TYPE_STAGE1_LEVEL2_ECMP_DESTINATION(0x0)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE1_DESTINATION1:
        {
            return "NPL_ENTRY_TYPE_STAGE1_DESTINATION1(0x1)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE1_P_L3_NH_L3_NH_TE_TUNNEL16B:
        {
            return "NPL_ENTRY_TYPE_STAGE1_P_L3_NH_L3_NH_TE_TUNNEL16B(0x2)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE1_LEVEL2_ECMP_L3_NH_TE_TUNNEL14B_OR_ASBR:
        {
            return "NPL_ENTRY_TYPE_STAGE1_LEVEL2_ECMP_L3_NH_TE_TUNNEL14B_OR_ASBR(0x3)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE1_L3_NH_TE_TUNNEL14B_OR_ASBR1:
        {
            return "NPL_ENTRY_TYPE_STAGE1_L3_NH_TE_TUNNEL14B_OR_ASBR1(0x4)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE1_L3_NH_TE_TUNNEL14B_OR_ASBR2:
        {
            return "NPL_ENTRY_TYPE_STAGE1_L3_NH_TE_TUNNEL14B_OR_ASBR2(0x5)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE1_P_L3_NH_DESTINATION_WITH_COMMON_DATA:
        {
            return "NPL_ENTRY_TYPE_STAGE1_P_L3_NH_DESTINATION_WITH_COMMON_DATA(0x6)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE1_L3_NH_TE_TUNNEL16B1:
        {
            return "NPL_ENTRY_TYPE_STAGE1_L3_NH_TE_TUNNEL16B1(0x7)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_stage1_entry_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_stage2_entry_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENTRY_TYPE_STAGE2_L3_NH_DESTINATION_L3_DLP:
        {
            return "NPL_ENTRY_TYPE_STAGE2_L3_NH_DESTINATION_L3_DLP(0x0)";
            break;
        }
        case NPL_ENTRY_TYPE_STAGE2_L3_NH_DESTINATION_L3_DLP_DLP_ATTR:
        {
            return "NPL_ENTRY_TYPE_STAGE2_L3_NH_DESTINATION_L3_DLP_DLP_ATTR(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_stage2_entry_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_stage3_entry_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_ENTRY_TYPE_STAGE3_DSPA_DESTINATION:
        {
            return "NPL_ENTRY_TYPE_STAGE3_DSPA_DESTINATION(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_stage3_entry_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_stamp_on_headers_e enum_instance)
{
    switch(enum_instance) {
        case NPL_STAMP_ON_PACKET_HEADER:
        {
            return "NPL_STAMP_ON_PACKET_HEADER(0x0)";
            break;
        }
        case NPL_STAMP_ON_ENCAP_HEADER:
        {
            return "NPL_STAMP_ON_ENCAP_HEADER(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_stamp_on_headers_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_svl_packet_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_SVL_PACKET_UNICAST:
        {
            return "NPL_SVL_PACKET_UNICAST(0xc)";
            break;
        }
        case NPL_SVL_PACKET_BUM_MC_COPY_ID:
        {
            return "NPL_SVL_PACKET_BUM_MC_COPY_ID(0xa)";
            break;
        }
        case NPL_SVL_PACKET_BUM_MCID:
        {
            return "NPL_SVL_PACKET_BUM_MCID(0xb)";
            break;
        }
        case NPL_SVL_PACKET_MIRROR:
        {
            return "NPL_SVL_PACKET_MIRROR(0xd)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_svl_packet_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_system_local_learn_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LEARN_TYPE_IGNORE:
        {
            return "NPL_LEARN_TYPE_IGNORE(0x0)";
            break;
        }
        case NPL_LEARN_TYPE_LOCAL:
        {
            return "NPL_LEARN_TYPE_LOCAL(0x1)";
            break;
        }
        case NPL_LEARN_TYPE_SYSTEM:
        {
            return "NPL_LEARN_TYPE_SYSTEM(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_system_local_learn_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_tag_swap_cmd_e enum_instance)
{
    switch(enum_instance) {
        case NPL_NO_TAG_SWAP:
        {
            return "NPL_NO_TAG_SWAP(0x0)";
            break;
        }
        case NPL_SWAP_TAG1:
        {
            return "NPL_SWAP_TAG1(0x1)";
            break;
        }
        case NPL_SWAP_TAG2:
        {
            return "NPL_SWAP_TAG2(0x2)";
            break;
        }
        case NPL_SWAP_TAG3:
        {
            return "NPL_SWAP_TAG3(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_tag_swap_cmd_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_term_acl_db_ids_t enum_instance)
{
    switch(enum_instance) {
        case NPL_TERM_ACL_DB_IPV6_SIP_COMPRESSION:
        {
            return "NPL_TERM_ACL_DB_IPV6_SIP_COMPRESSION(0x0)";
            break;
        }
        case NPL_TERM_ACL_DB_MAC_SEC_ACL:
        {
            return "NPL_TERM_ACL_DB_MAC_SEC_ACL(0x2)";
            break;
        }
        case NPL_TERM_ACL_DB_L2_LPTS_MAC:
        {
            return "NPL_TERM_ACL_DB_L2_LPTS_MAC(0x4)";
            break;
        }
        case NPL_TERM_ACL_DB_L2_LPTS_IPV4:
        {
            return "NPL_TERM_ACL_DB_L2_LPTS_IPV4(0x8)";
            break;
        }
        case NPL_TERM_ACL_DB_L2_LPTS_IPV6:
        {
            return "NPL_TERM_ACL_DB_L2_LPTS_IPV6(0xc)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_term_acl_db_ids_t");
    }
    return "";
}


std::string npl_enum_to_string(const npl_term_bucket_a_lu_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LU_A_MAC_SERVICE_MAPPING_TCAM_COMPOUND:
        {
            return "NPL_LU_A_MAC_SERVICE_MAPPING_TCAM_COMPOUND(0x1)";
            break;
        }
        case NPL_LU_A_MAC_SERVICE_MAPPING_0_EM_COMPOUND:
        {
            return "NPL_LU_A_MAC_SERVICE_MAPPING_0_EM_COMPOUND(0x2)";
            break;
        }
        case NPL_LU_A_MAC_SERVICE_MAPPING_1_EM_COMPOUND:
        {
            return "NPL_LU_A_MAC_SERVICE_MAPPING_1_EM_COMPOUND(0x3)";
            break;
        }
        case NPL_LU_A_MAC_RELAY:
        {
            return "NPL_LU_A_MAC_RELAY(0x4)";
            break;
        }
        case NPL_LU_A_MAC_TERMINATION_EM:
        {
            return "NPL_LU_A_MAC_TERMINATION_EM(0x5)";
            break;
        }
        case NPL_LU_A_TUNNEL1_COMPOUND:
        {
            return "NPL_LU_A_TUNNEL1_COMPOUND(0x6)";
            break;
        }
        case NPL_LU_A_MAC_TERMINATION_TCAM:
        {
            return "NPL_LU_A_MAC_TERMINATION_TCAM(0x7)";
            break;
        }
        case NPL_LU_A_TERM_NOP:
        {
            return "NPL_LU_A_TERM_NOP(0x0)";
            break;
        }
        case NPL_LU_A_MAC_VLAN_MAPPING_COMPOUND:
        {
            return "NPL_LU_A_MAC_VLAN_MAPPING_COMPOUND(0x8)";
            break;
        }
        case NPL_LU_A_MAC_VLAN_MAPPING_COMPOUND_MYMAC:
        {
            return "NPL_LU_A_MAC_VLAN_MAPPING_COMPOUND_MYMAC(0x9)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_term_bucket_a_lu_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_term_bucket_a_result_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RES_A_MAC_SERVICE_MAPPING_TCAM_LP:
        {
            return "NPL_RES_A_MAC_SERVICE_MAPPING_TCAM_LP(0x1)";
            break;
        }
        case NPL_RES_A_MAC_LINK_LP:
        {
            return "NPL_RES_A_MAC_LINK_LP(0x2)";
            break;
        }
        case NPL_RES_A_MAC_LINK_LP_COMPOUND:
        {
            return "NPL_RES_A_MAC_LINK_LP_COMPOUND(0x3)";
            break;
        }
        case NPL_RES_A_MAC_SERVICE_MAPPING_0_EM:
        {
            return "NPL_RES_A_MAC_SERVICE_MAPPING_0_EM(0x4)";
            break;
        }
        case NPL_RES_A_MAC_SERVICE_MAPPING_1_EM:
        {
            return "NPL_RES_A_MAC_SERVICE_MAPPING_1_EM(0x5)";
            break;
        }
        case NPL_RES_A_MAC_SERVICE_MAPPING_1_EM_COMPOUND:
        {
            return "NPL_RES_A_MAC_SERVICE_MAPPING_1_EM_COMPOUND(0x6)";
            break;
        }
        case NPL_RES_A_MAC_LP:
        {
            return "NPL_RES_A_MAC_LP(0x7)";
            break;
        }
        case NPL_RES_A_MAC_LP_COMPOUND:
        {
            return "NPL_RES_A_MAC_LP_COMPOUND(0x8)";
            break;
        }
        case NPL_RES_A_TUNNEL0_COMPOUND:
        {
            return "NPL_RES_A_TUNNEL0_COMPOUND(0x9)";
            break;
        }
        case NPL_RES_A_TERM_FRAGMENT_0_COMPOUND:
        {
            return "NPL_RES_A_TERM_FRAGMENT_0_COMPOUND(0xa)";
            break;
        }
        case NPL_RES_A_TERM_NOP:
        {
            return "NPL_RES_A_TERM_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_term_bucket_a_result_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_term_bucket_b_lu_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LU_B_MAC_TERMINATION_EM:
        {
            return "NPL_LU_B_MAC_TERMINATION_EM(0x1)";
            break;
        }
        case NPL_LU_B_TUNNEL0_COMPOUND:
        {
            return "NPL_LU_B_TUNNEL0_COMPOUND(0x2)";
            break;
        }
        case NPL_LU_B_MAC_SERVICE_MAPPING_TCAM_COMPOUND:
        {
            return "NPL_LU_B_MAC_SERVICE_MAPPING_TCAM_COMPOUND(0x3)";
            break;
        }
        case NPL_LU_B_MAC_SERVICE_MAPPING_TCAM_FROM_RELAY_COMPOUND:
        {
            return "NPL_LU_B_MAC_SERVICE_MAPPING_TCAM_FROM_RELAY_COMPOUND(0x4)";
            break;
        }
        case NPL_LU_B_MAC_SERVICE_MAPPING_1_EM_COMPOUND:
        {
            return "NPL_LU_B_MAC_SERVICE_MAPPING_1_EM_COMPOUND(0x5)";
            break;
        }
        case NPL_LU_B_TERM_NOP:
        {
            return "NPL_LU_B_TERM_NOP(0x0)";
            break;
        }
        case NPL_LU_B_CENTRAL_TCAM_T:
        {
            return "NPL_LU_B_CENTRAL_TCAM_T(0x6)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_term_bucket_b_lu_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_term_bucket_b_result_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RES_B_MAC_TERMINATION_TCAM:
        {
            return "NPL_RES_B_MAC_TERMINATION_TCAM(0x1)";
            break;
        }
        case NPL_RES_B_MAC_SERVICE_MAPPING_1_EM:
        {
            return "NPL_RES_B_MAC_SERVICE_MAPPING_1_EM(0x2)";
            break;
        }
        case NPL_RES_B_MAC_SERVICE_MAPPING_1_EM_COMPOUND:
        {
            return "NPL_RES_B_MAC_SERVICE_MAPPING_1_EM_COMPOUND(0x3)";
            break;
        }
        case NPL_RES_B_MAC_LP:
        {
            return "NPL_RES_B_MAC_LP(0x4)";
            break;
        }
        case NPL_RES_B_MAC_LP_COMPOUND:
        {
            return "NPL_RES_B_MAC_LP_COMPOUND(0x5)";
            break;
        }
        case NPL_RES_B_MAC_TERMINATION_EM:
        {
            return "NPL_RES_B_MAC_TERMINATION_EM(0x6)";
            break;
        }
        case NPL_RES_B_MAC_TERMINATION_EM_COMPOUND:
        {
            return "NPL_RES_B_MAC_TERMINATION_EM_COMPOUND(0x7)";
            break;
        }
        case NPL_RES_B_TUNNEL1_COMPOUND:
        {
            return "NPL_RES_B_TUNNEL1_COMPOUND(0x8)";
            break;
        }
        case NPL_RES_B_TERM_FRAGMENT_1_COMPOUND:
        {
            return "NPL_RES_B_TERM_FRAGMENT_1_COMPOUND(0x9)";
            break;
        }
        case NPL_RES_B_TERM_NOP:
        {
            return "NPL_RES_B_TERM_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_term_bucket_b_result_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_term_bucket_c_lu_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LU_C_MAC_LINK_LP:
        {
            return "NPL_LU_C_MAC_LINK_LP(0x1)";
            break;
        }
        case NPL_LU_C_MAC_TERMINATION_TCAM:
        {
            return "NPL_LU_C_MAC_TERMINATION_TCAM(0x2)";
            break;
        }
        case NPL_LU_C_MAC_SERVICE_MAPPING_0_EM_COMPOUND:
        {
            return "NPL_LU_C_MAC_SERVICE_MAPPING_0_EM_COMPOUND(0x3)";
            break;
        }
        case NPL_LU_C_MAC_LP:
        {
            return "NPL_LU_C_MAC_LP(0x4)";
            break;
        }
        case NPL_LU_C_TUNNEL1_COMPOUND:
        {
            return "NPL_LU_C_TUNNEL1_COMPOUND(0x5)";
            break;
        }
        case NPL_LU_C_TERM_FRAGMENT_IFG_COMPOUND:
        {
            return "NPL_LU_C_TERM_FRAGMENT_IFG_COMPOUND(0x6)";
            break;
        }
        case NPL_LU_C_TERM_NOP:
        {
            return "NPL_LU_C_TERM_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_term_bucket_c_lu_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_term_bucket_c_result_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RES_C_INGRESS_VLAN_MEMBERSHIP:
        {
            return "NPL_RES_C_INGRESS_VLAN_MEMBERSHIP(0x1)";
            break;
        }
        case NPL_RES_C_MAC_SERVICE_MAPPING_0_EM:
        {
            return "NPL_RES_C_MAC_SERVICE_MAPPING_0_EM(0x2)";
            break;
        }
        case NPL_RES_C_MAC_RELAY_COMPOUND:
        {
            return "NPL_RES_C_MAC_RELAY_COMPOUND(0x3)";
            break;
        }
        case NPL_RES_C_MAC_RELAY:
        {
            return "NPL_RES_C_MAC_RELAY(0x4)";
            break;
        }
        case NPL_RES_C_TUNNEL0_COMPOUND:
        {
            return "NPL_RES_C_TUNNEL0_COMPOUND(0x5)";
            break;
        }
        case NPL_RES_C_CENTRAL_TCAM_T:
        {
            return "NPL_RES_C_CENTRAL_TCAM_T(0x6)";
            break;
        }
        case NPL_RES_C_MAC_SERVICE_MAPPING_TCAM_COMPOUND:
        {
            return "NPL_RES_C_MAC_SERVICE_MAPPING_TCAM_COMPOUND(0x7)";
            break;
        }
        case NPL_RES_C_TERM_NOP:
        {
            return "NPL_RES_C_TERM_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_term_bucket_c_result_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_term_bucket_d_lu_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LU_D_MAC_LINK_RELAY:
        {
            return "NPL_LU_D_MAC_LINK_RELAY(0x1)";
            break;
        }
        case NPL_LU_D_INGRESS_VLAN_MEMBERSHIP:
        {
            return "NPL_LU_D_INGRESS_VLAN_MEMBERSHIP(0x2)";
            break;
        }
        case NPL_LU_D_MAC_RELAY:
        {
            return "NPL_LU_D_MAC_RELAY(0x3)";
            break;
        }
        case NPL_LU_D_TUNNEL0_COMPOUND:
        {
            return "NPL_LU_D_TUNNEL0_COMPOUND(0x4)";
            break;
        }
        case NPL_LU_D_TERM_NOP:
        {
            return "NPL_LU_D_TERM_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_term_bucket_d_lu_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_term_bucket_d_result_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RES_D_INGRESS_VLAN_MEMBERSHIP:
        {
            return "NPL_RES_D_INGRESS_VLAN_MEMBERSHIP(0x1)";
            break;
        }
        case NPL_RES_D_MAC_SERVICE_MAPPING_TCAM_RELAY:
        {
            return "NPL_RES_D_MAC_SERVICE_MAPPING_TCAM_RELAY(0x2)";
            break;
        }
        case NPL_RES_D_MAC_VLAN_MAPPING_COMPOUND:
        {
            return "NPL_RES_D_MAC_VLAN_MAPPING_COMPOUND(0x3)";
            break;
        }
        case NPL_RES_D_MAC_LINK_RELAY_COMPOUND:
        {
            return "NPL_RES_D_MAC_LINK_RELAY_COMPOUND(0x4)";
            break;
        }
        case NPL_RES_D_MAC_LINK_RELAY:
        {
            return "NPL_RES_D_MAC_LINK_RELAY(0x5)";
            break;
        }
        case NPL_RES_D_MAC_RELAY_COMPOUND:
        {
            return "NPL_RES_D_MAC_RELAY_COMPOUND(0x6)";
            break;
        }
        case NPL_RES_D_MAC_RELAY:
        {
            return "NPL_RES_D_MAC_RELAY(0x7)";
            break;
        }
        case NPL_RES_D_TUNNEL1_COMPOUND:
        {
            return "NPL_RES_D_TUNNEL1_COMPOUND(0x8)";
            break;
        }
        case NPL_RES_D_CENTRAL_TCAM_T:
        {
            return "NPL_RES_D_CENTRAL_TCAM_T(0x9)";
            break;
        }
        case NPL_RES_D_TERM_NOP:
        {
            return "NPL_RES_D_TERM_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_term_bucket_d_result_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_termination_logical_db_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TERMINATION_SIP_DIP_INDEX_LDB:
        {
            return "NPL_TERMINATION_SIP_DIP_INDEX_LDB(0x0)";
            break;
        }
        case NPL_TERMINATION_DIP_INDEX_LDB:
        {
            return "NPL_TERMINATION_DIP_INDEX_LDB(0x1)";
            break;
        }
        case NPL_TERMINATION_DIP_LDB:
        {
            return "NPL_TERMINATION_DIP_LDB(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_termination_logical_db_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_tm_header_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TM_HEADER_TYPE_UNICAST_OR_MUU_PLB:
        {
            return "NPL_TM_HEADER_TYPE_UNICAST_OR_MUU_PLB(0x0)";
            break;
        }
        case NPL_TM_HEADER_TYPE_UNICAST_FLB:
        {
            return "NPL_TM_HEADER_TYPE_UNICAST_FLB(0x1)";
            break;
        }
        case NPL_TM_HEADER_TYPE_MMM_PLB_OR_FLB:
        {
            return "NPL_TM_HEADER_TYPE_MMM_PLB_OR_FLB(0x2)";
            break;
        }
        case NPL_TM_HEADER_TYPE_MUM_PLB:
        {
            return "NPL_TM_HEADER_TYPE_MUM_PLB(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_tm_header_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_tm_header_type_uc_or_mmu_plb_key_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TM_HEADER_TYPE_UNICAST_OR_MUU_PLB_KEY:
        {
            return "NPL_TM_HEADER_TYPE_UNICAST_OR_MUU_PLB_KEY(0x6b0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_tm_header_type_uc_or_mmu_plb_key_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_transmit_bucket_a_lu_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LU_A_EGRESS_DIP_INDEX_COMPOUND:
        {
            return "NPL_LU_A_EGRESS_DIP_INDEX_COMPOUND(0x1)";
            break;
        }
        case NPL_LU_A_EGRESS_L3_DLP0_COMPOUND:
        {
            return "NPL_LU_A_EGRESS_L3_DLP0_COMPOUND(0x2)";
            break;
        }
        case NPL_LU_A_EGRESS_L3_DLP0_AND_DIRECT0_COMPOUND:
        {
            return "NPL_LU_A_EGRESS_L3_DLP0_AND_DIRECT0_COMPOUND(0x3)";
            break;
        }
        case NPL_LU_A_EGRESS_L3_DLP1_AND_DIRECT0_COMPOUND:
        {
            return "NPL_LU_A_EGRESS_L3_DLP1_AND_DIRECT0_COMPOUND(0x4)";
            break;
        }
        case NPL_LU_A_EGRESS_L3_DLP1_COMPOUND:
        {
            return "NPL_LU_A_EGRESS_L3_DLP1_COMPOUND(0x5)";
            break;
        }
        case NPL_LU_A_EGRESS_DIRECT1_COMPOUND:
        {
            return "NPL_LU_A_EGRESS_DIRECT1_COMPOUND(0x6)";
            break;
        }
        case NPL_LU_A_CENTRAL_TCAM_TX0:
        {
            return "NPL_LU_A_CENTRAL_TCAM_TX0(0x7)";
            break;
        }
        case NPL_LU_A_CENTRAL_TCAM_TX0_EXT:
        {
            return "NPL_LU_A_CENTRAL_TCAM_TX0_EXT(0x8)";
            break;
        }
        case NPL_LU_A_TRANS_NOP:
        {
            return "NPL_LU_A_TRANS_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_transmit_bucket_a_lu_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_transmit_bucket_a_result_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RES_A_EGRESS_L3_DLP0_COMPOUND:
        {
            return "NPL_RES_A_EGRESS_L3_DLP0_COMPOUND(0x1)";
            break;
        }
        case NPL_RES_A_EGRESS_L3_DLP1_COMPOUND:
        {
            return "NPL_RES_A_EGRESS_L3_DLP1_COMPOUND(0x2)";
            break;
        }
        case NPL_RES_A_EGRESS_DIRECT0_COMPOUND:
        {
            return "NPL_RES_A_EGRESS_DIRECT0_COMPOUND(0x3)";
            break;
        }
        case NPL_RES_A_EGRESS_DIRECT1_COMPOUND:
        {
            return "NPL_RES_A_EGRESS_DIRECT1_COMPOUND(0x4)";
            break;
        }
        case NPL_RES_A_TRANS_NOP:
        {
            return "NPL_RES_A_TRANS_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_transmit_bucket_a_result_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_transmit_bucket_b_lu_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LU_B_EGRESS_DIRECT0_COMPOUND:
        {
            return "NPL_LU_B_EGRESS_DIRECT0_COMPOUND(0x1)";
            break;
        }
        case NPL_LU_B_CENTRAL_TCAM_TX1:
        {
            return "NPL_LU_B_CENTRAL_TCAM_TX1(0x2)";
            break;
        }
        case NPL_LU_B_CENTRAL_TCAM_TX1_EXT:
        {
            return "NPL_LU_B_CENTRAL_TCAM_TX1_EXT(0x3)";
            break;
        }
        case NPL_LU_B_TRANS_NOP:
        {
            return "NPL_LU_B_TRANS_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_transmit_bucket_b_lu_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_transmit_bucket_b_result_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RES_B_EGRESS_LARGE_EM_COMPOUND:
        {
            return "NPL_RES_B_EGRESS_LARGE_EM_COMPOUND(0x1)";
            break;
        }
        case NPL_RES_B_EGRESS_DIP_INDEX_COMPOUND:
        {
            return "NPL_RES_B_EGRESS_DIP_INDEX_COMPOUND(0x2)";
            break;
        }
        case NPL_RES_B_EGRESS_SMALL_EM_COMPOUND:
        {
            return "NPL_RES_B_EGRESS_SMALL_EM_COMPOUND(0x3)";
            break;
        }
        case NPL_RES_B_EGRESS_DIRECT0_COMPOUND:
        {
            return "NPL_RES_B_EGRESS_DIRECT0_COMPOUND(0x4)";
            break;
        }
        case NPL_RES_B_EGRESS_DIRECT1_COMPOUND:
        {
            return "NPL_RES_B_EGRESS_DIRECT1_COMPOUND(0x5)";
            break;
        }
        case NPL_RES_B_CENTRAL_TCAM_TX1:
        {
            return "NPL_RES_B_CENTRAL_TCAM_TX1(0x6)";
            break;
        }
        case NPL_RES_B_TRANS_NOP:
        {
            return "NPL_RES_B_TRANS_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_transmit_bucket_b_result_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_transmit_bucket_c_lu_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LU_C_EGRESS_LARGE_EM_COMPOUND:
        {
            return "NPL_LU_C_EGRESS_LARGE_EM_COMPOUND(0x1)";
            break;
        }
        case NPL_LU_C_EGRESS_LARGE_EM_AND_DIP_INDEX_COMPOUND:
        {
            return "NPL_LU_C_EGRESS_LARGE_EM_AND_DIP_INDEX_COMPOUND(0x2)";
            break;
        }
        case NPL_LU_C_EGRESS_SMALL_EM_COMPOUND:
        {
            return "NPL_LU_C_EGRESS_SMALL_EM_COMPOUND(0x3)";
            break;
        }
        case NPL_LU_C_EGRESS_SMALL_EM_AND_DIP_INDEX_COMPOUND:
        {
            return "NPL_LU_C_EGRESS_SMALL_EM_AND_DIP_INDEX_COMPOUND(0x4)";
            break;
        }
        case NPL_LU_C_EGRESS_DIRECT0_COMPOUND:
        {
            return "NPL_LU_C_EGRESS_DIRECT0_COMPOUND(0x5)";
            break;
        }
        case NPL_LU_C_EGRESS_VLAN_MEMBERSHIP:
        {
            return "NPL_LU_C_EGRESS_VLAN_MEMBERSHIP(0x6)";
            break;
        }
        case NPL_LU_C_TRANS_NOP:
        {
            return "NPL_LU_C_TRANS_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_transmit_bucket_c_lu_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_transmit_bucket_c_result_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RES_C_EGRESS_LARGE_EM_COMPOUND:
        {
            return "NPL_RES_C_EGRESS_LARGE_EM_COMPOUND(0x1)";
            break;
        }
        case NPL_RES_C_CENTRAL_TCAM_TX0:
        {
            return "NPL_RES_C_CENTRAL_TCAM_TX0(0x2)";
            break;
        }
        case NPL_RES_C_CENTRAL_TCAM_TX1:
        {
            return "NPL_RES_C_CENTRAL_TCAM_TX1(0x3)";
            break;
        }
        case NPL_RES_C_EGRESS_VLAN_MEMBERSHIP:
        {
            return "NPL_RES_C_EGRESS_VLAN_MEMBERSHIP(0x4)";
            break;
        }
        case NPL_RES_C_TRANS_NOP:
        {
            return "NPL_RES_C_TRANS_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_transmit_bucket_c_result_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_transmit_bucket_d_lu_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_LU_D_EGRESS_LARGE_EM_COMPOUND:
        {
            return "NPL_LU_D_EGRESS_LARGE_EM_COMPOUND(0x1)";
            break;
        }
        case NPL_LU_D_EGRESS_LARGE_EM_AND_DIP_INDEX_COMPOUND:
        {
            return "NPL_LU_D_EGRESS_LARGE_EM_AND_DIP_INDEX_COMPOUND(0x2)";
            break;
        }
        case NPL_LU_D_EGRESS_DIP_INDEX_COMPOUND:
        {
            return "NPL_LU_D_EGRESS_DIP_INDEX_COMPOUND(0x3)";
            break;
        }
        case NPL_LU_D_EGRESS_SMALL_EM_COMPOUND:
        {
            return "NPL_LU_D_EGRESS_SMALL_EM_COMPOUND(0x4)";
            break;
        }
        case NPL_LU_D_EGRESS_SMALL_EM_AND_DIP_INDEX_COMPOUND:
        {
            return "NPL_LU_D_EGRESS_SMALL_EM_AND_DIP_INDEX_COMPOUND(0x5)";
            break;
        }
        case NPL_LU_D_EGRESS_L3_DLP0_COMPOUND:
        {
            return "NPL_LU_D_EGRESS_L3_DLP0_COMPOUND(0x6)";
            break;
        }
        case NPL_LU_D_EGRESS_L3_DLP1_COMPOUND:
        {
            return "NPL_LU_D_EGRESS_L3_DLP1_COMPOUND(0x7)";
            break;
        }
        case NPL_LU_D_EGRESS_L3_DLP0_AND_DIRECT0_COMPOUND:
        {
            return "NPL_LU_D_EGRESS_L3_DLP0_AND_DIRECT0_COMPOUND(0x8)";
            break;
        }
        case NPL_LU_D_EGRESS_L3_DLP1_AND_DIRECT0_COMPOUND:
        {
            return "NPL_LU_D_EGRESS_L3_DLP1_AND_DIRECT0_COMPOUND(0x9)";
            break;
        }
        case NPL_LU_D_EGRESS_DIRECT1_COMPOUND:
        {
            return "NPL_LU_D_EGRESS_DIRECT1_COMPOUND(0xa)";
            break;
        }
        case NPL_LU_D_EGRESS_VLAN_MEMBERSHIP:
        {
            return "NPL_LU_D_EGRESS_VLAN_MEMBERSHIP(0xb)";
            break;
        }
        case NPL_LU_D_TRANS_NOP:
        {
            return "NPL_LU_D_TRANS_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_transmit_bucket_d_lu_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_transmit_bucket_d_result_dest_e enum_instance)
{
    switch(enum_instance) {
        case NPL_RES_D_EGRESS_DIP_INDEX_COMPOUND:
        {
            return "NPL_RES_D_EGRESS_DIP_INDEX_COMPOUND(0x1)";
            break;
        }
        case NPL_RES_D_EGRESS_SMALL_EM_COMPOUND:
        {
            return "NPL_RES_D_EGRESS_SMALL_EM_COMPOUND(0x2)";
            break;
        }
        case NPL_RES_D_EGRESS_L3_DLP0_COMPOUND:
        {
            return "NPL_RES_D_EGRESS_L3_DLP0_COMPOUND(0x3)";
            break;
        }
        case NPL_RES_D_EGRESS_L3_DLP1_COMPOUND:
        {
            return "NPL_RES_D_EGRESS_L3_DLP1_COMPOUND(0x4)";
            break;
        }
        case NPL_RES_D_CENTRAL_TCAM_TX0:
        {
            return "NPL_RES_D_CENTRAL_TCAM_TX0(0x5)";
            break;
        }
        case NPL_RES_D_TRANS_NOP:
        {
            return "NPL_RES_D_TRANS_NOP(0x0)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_transmit_bucket_d_result_dest_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_transmit_l2_macros_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TRANSMIT_L2_FIRST_MACRO:
        {
            return "NPL_TRANSMIT_L2_FIRST_MACRO(0x0)";
            break;
        }
        case NPL_TRANSMIT_L2_SECOND_MACRO:
        {
            return "NPL_TRANSMIT_L2_SECOND_MACRO(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_transmit_l2_macros_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_trapped_nh_types_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TRAP_NH_IS_GLEAN:
        {
            return "NPL_TRAP_NH_IS_GLEAN(0x1)";
            break;
        }
        case NPL_TRAP_NH_IS_DROP:
        {
            return "NPL_TRAP_NH_IS_DROP(0x2)";
            break;
        }
        case NPL_TRAP_NH_IS_NULL:
        {
            return "NPL_TRAP_NH_IS_NULL(0x4)";
            break;
        }
        case NPL_TRAP_NH_IS_USER_TRAP1:
        {
            return "NPL_TRAP_NH_IS_USER_TRAP1(0x8)";
            break;
        }
        case NPL_TRAP_NH_IS_USER_TRAP2:
        {
            return "NPL_TRAP_NH_IS_USER_TRAP2(0x10)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_trapped_nh_types_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_trigger_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_DB_TRIGGER_TYPE_RMEP:
        {
            return "NPL_DB_TRIGGER_TYPE_RMEP(0x0)";
            break;
        }
        case NPL_DB_TRIGGER_TYPE_MP:
        {
            return "NPL_DB_TRIGGER_TYPE_MP(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_trigger_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_ttl_mode_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TTL_MODE_PIPE:
        {
            return "NPL_TTL_MODE_PIPE(0x0)";
            break;
        }
        case NPL_TTL_MODE_UNIFORM:
        {
            return "NPL_TTL_MODE_UNIFORM(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_ttl_mode_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_tunnel_temination_logical_db_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TUNNEL_TERMINATION_SIP_DIP_INDEX_LDB:
        {
            return "NPL_TUNNEL_TERMINATION_SIP_DIP_INDEX_LDB(0x0)";
            break;
        }
        case NPL_TUNNEL_TERMINATION_DIP_INDEX_LDB:
        {
            return "NPL_TUNNEL_TERMINATION_DIP_INDEX_LDB(0x2)";
            break;
        }
        case NPL_TUNNEL_TERMINATION_DIP_LDB:
        {
            return "NPL_TUNNEL_TERMINATION_DIP_LDB(0x3)";
            break;
        }
        case NPL_TUNNEL_TERMINATION_VNI_TO_RELAY_LDB:
        {
            return "NPL_TUNNEL_TERMINATION_VNI_TO_RELAY_LDB(0x8)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_tunnel_temination_logical_db_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_tunnel_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_IP_TUNNEL_IP_IN_IP:
        {
            return "NPL_IP_TUNNEL_IP_IN_IP(0x0)";
            break;
        }
        case NPL_IP_TUNNEL_GRE:
        {
            return "NPL_IP_TUNNEL_GRE(0x1)";
            break;
        }
        case NPL_IP_TUNNEL_GUE:
        {
            return "NPL_IP_TUNNEL_GUE(0x2)";
            break;
        }
        case NPL_IP_TUNNEL_VXLAN:
        {
            return "NPL_IP_TUNNEL_VXLAN(0x4)";
            break;
        }
        case NPL_IP_TUNNEL_NVGRE:
        {
            return "NPL_IP_TUNNEL_NVGRE(0x5)";
            break;
        }
        case NPL_IP_TUNNEL_PTP:
        {
            return "NPL_IP_TUNNEL_PTP(0xe)";
            break;
        }
        case NPL_IP_TUNNEL_NONE:
        {
            return "NPL_IP_TUNNEL_NONE(0xf)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_tunnel_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_tx_counter_compensation_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TX_COUNTER_COMPENSATION_FORWARDING_HEADER:
        {
            return "NPL_TX_COUNTER_COMPENSATION_FORWARDING_HEADER(0x0)";
            break;
        }
        case NPL_TX_COUNTER_COMPENSATION_FIRST_ENCAP:
        {
            return "NPL_TX_COUNTER_COMPENSATION_FIRST_ENCAP(0x1)";
            break;
        }
        case NPL_TX_COUNTER_COMPENSATION_SECOND_ENCAP:
        {
            return "NPL_TX_COUNTER_COMPENSATION_SECOND_ENCAP(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_tx_counter_compensation_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_tx_counters_set_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TX_COUNTERS_SET_TYPE_NO_SET:
        {
            return "NPL_TX_COUNTERS_SET_TYPE_NO_SET(0x0)";
            break;
        }
        case NPL_TX_COUNTERS_SET_TYPE_COLOR_AWARE:
        {
            return "NPL_TX_COUNTERS_SET_TYPE_COLOR_AWARE(0x1)";
            break;
        }
        case NPL_TX_COUNTERS_SET_TYPE_COLOR_AWARE_WITH_RED:
        {
            return "NPL_TX_COUNTERS_SET_TYPE_COLOR_AWARE_WITH_RED(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_tx_counters_set_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_tx_pre_edit_cmds_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TX_PRE_EDIT_CMD_NOP:
        {
            return "NPL_TX_PRE_EDIT_CMD_NOP(0x0)";
            break;
        }
        case NPL_TX_PRE_EDIT_CMD_DEL:
        {
            return "NPL_TX_PRE_EDIT_CMD_DEL(0x1)";
            break;
        }
        case NPL_TX_PRE_EDIT_CMD_CP:
        {
            return "NPL_TX_PRE_EDIT_CMD_CP(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_tx_pre_edit_cmds_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_tx_pre_edit_profile_cmds_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TX_PRE_EDIT_CMD_PROF:
        {
            return "NPL_TX_PRE_EDIT_CMD_PROF(0x2)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_tx_pre_edit_profile_cmds_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_tx_to_rx_rcy_data_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TX2RX_RCY_DATA_DEFAULT:
        {
            return "NPL_TX2RX_RCY_DATA_DEFAULT(0x40)";
            break;
        }
        case NPL_TX2RX_RCY_DATA_TX_REDIRECT_TO_DEST:
        {
            return "NPL_TX2RX_RCY_DATA_TX_REDIRECT_TO_DEST(0x8f)";
            break;
        }
        case NPL_TX2RX_SCHED_RCY_DATA_TX_REDIRECT_TO_DEST:
        {
            return "NPL_TX2RX_SCHED_RCY_DATA_TX_REDIRECT_TO_DEST(0x4f)";
            break;
        }
        case NPL_TX2RX_RCY_DATA_INJECT_DOWN_TO_DMA_PORT:
        {
            return "NPL_TX2RX_RCY_DATA_INJECT_DOWN_TO_DMA_PORT(0x8e)";
            break;
        }
        case NPL_TX2RX_RCY_DATA_INJECT_DOWN_TO_SCHEDULED_RCY_DMA_PORT:
        {
            return "NPL_TX2RX_RCY_DATA_INJECT_DOWN_TO_SCHEDULED_RCY_DMA_PORT(0x4e)";
            break;
        }
        case NPL_TX2RX_RCY_DATA_OBM_TO_INJECT_UP:
        {
            return "NPL_TX2RX_RCY_DATA_OBM_TO_INJECT_UP(0x9e)";
            break;
        }
        case NPL_TX2RX_SCHED_RCY_DATA_OBM_2_TO_INJECT_UP:
        {
            return "NPL_TX2RX_SCHED_RCY_DATA_OBM_2_TO_INJECT_UP(0x1e)";
            break;
        }
        case NPL_TX2RX_SCHED_RCY_DATA_OBM_TO_INJECT_UP:
        {
            return "NPL_TX2RX_SCHED_RCY_DATA_OBM_TO_INJECT_UP(0x5e)";
            break;
        }
        case NPL_TX2RX_SCHED_RCY_DATA_RCY_PORT_TO_INJECT_UP:
        {
            return "NPL_TX2RX_SCHED_RCY_DATA_RCY_PORT_TO_INJECT_UP(0x7e)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_tx_to_rx_rcy_data_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_txpp_pre_edit_command_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TXPP_PRE_EDIT_COMMAND_NOP:
        {
            return "NPL_TXPP_PRE_EDIT_COMMAND_NOP(0x0)";
            break;
        }
        case NPL_TXPP_PRE_EDIT_COMMAND_DELETE:
        {
            return "NPL_TXPP_PRE_EDIT_COMMAND_DELETE(0x1)";
            break;
        }
        case NPL_TXPP_PRE_EDIT_COMMAND_COPY:
        {
            return "NPL_TXPP_PRE_EDIT_COMMAND_COPY(0x2)";
            break;
        }
        case NPL_TXPP_PRE_EDIT_COMMAND_RESERVED:
        {
            return "NPL_TXPP_PRE_EDIT_COMMAND_RESERVED(0x3)";
            break;
        }
        case NPL_TXPP_PRE_EDIT_COMMAND_SF_0:
        {
            return "NPL_TXPP_PRE_EDIT_COMMAND_SF_0(0x4)";
            break;
        }
        case NPL_TXPP_PRE_EDIT_COMMAND_SF_1:
        {
            return "NPL_TXPP_PRE_EDIT_COMMAND_SF_1(0x5)";
            break;
        }
        case NPL_TXPP_PRE_EDIT_COMMAND_SF_2:
        {
            return "NPL_TXPP_PRE_EDIT_COMMAND_SF_2(0x6)";
            break;
        }
        case NPL_TXPP_PRE_EDIT_COMMAND_SF_3:
        {
            return "NPL_TXPP_PRE_EDIT_COMMAND_SF_3(0x7)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_txpp_pre_edit_command_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_txpp_ts_cmd_e enum_instance)
{
    switch(enum_instance) {
        case NPL_TXPP_TS_CMD_OP_NOP:
        {
            return "NPL_TXPP_TS_CMD_OP_NOP(0x0)";
            break;
        }
        case NPL_TXPP_TS_CMD_OP_UPDATE_CF:
        {
            return "NPL_TXPP_TS_CMD_OP_UPDATE_CF(0x1)";
            break;
        }
        case NPL_TXPP_TS_CMD_OP_TOD_STAMP:
        {
            return "NPL_TXPP_TS_CMD_OP_TOD_STAMP(0x5)";
            break;
        }
        case NPL_TXPP_TS_CMD_OP_IN_TIME_STAMP:
        {
            return "NPL_TXPP_TS_CMD_OP_IN_TIME_STAMP(0x8)";
            break;
        }
        case NPL_TXPP_TS_CMD_OP_TOD_RECORD:
        {
            return "NPL_TXPP_TS_CMD_OP_TOD_RECORD(0x9)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_txpp_ts_cmd_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_udc_db_access_type_ids_e enum_instance)
{
    switch(enum_instance) {
        case NPL_UDC_DB_ACCESS_COMMON_TERM:
        {
            return "NPL_UDC_DB_ACCESS_COMMON_TERM(0x0)";
            break;
        }
        case NPL_UDC_DB_ACCESS_HEADER_ACCESS_TERM:
        {
            return "NPL_UDC_DB_ACCESS_HEADER_ACCESS_TERM(0x1)";
            break;
        }
        case NPL_UDC_DB_ACCESS_COMMON_FWD:
        {
            return "NPL_UDC_DB_ACCESS_COMMON_FWD(0x2)";
            break;
        }
        case NPL_UDC_DB_ACCESS_HEADER_ACCESS_FWD:
        {
            return "NPL_UDC_DB_ACCESS_HEADER_ACCESS_FWD(0x3)";
            break;
        }
        case NPL_UDC_DB_ACCESS_COMMON_TRANS:
        {
            return "NPL_UDC_DB_ACCESS_COMMON_TRANS(0x4)";
            break;
        }
        case NPL_UDC_DB_ACCESS_HEADER_ACCESS_TRANS:
        {
            return "NPL_UDC_DB_ACCESS_HEADER_ACCESS_TRANS(0x5)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_udc_db_access_type_ids_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_udc_fi_macro_ids_e enum_instance)
{
    switch(enum_instance) {
        case NPL_UDC_FI_MACRO_ID_DB_ACCESS_COMMON_TERM:
        {
            return "NPL_UDC_FI_MACRO_ID_DB_ACCESS_COMMON_TERM(0x0)";
            break;
        }
        case NPL_UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_TERM:
        {
            return "NPL_UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_TERM(0x1)";
            break;
        }
        case NPL_UDC_FI_MACRO_ID_DB_ACCESS_COMMON_FWD:
        {
            return "NPL_UDC_FI_MACRO_ID_DB_ACCESS_COMMON_FWD(0x2)";
            break;
        }
        case NPL_UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_FWD:
        {
            return "NPL_UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_FWD(0x3)";
            break;
        }
        case NPL_UDC_FI_MACRO_ID_DB_ACCESS_COMMON_TRANS:
        {
            return "NPL_UDC_FI_MACRO_ID_DB_ACCESS_COMMON_TRANS(0x4)";
            break;
        }
        case NPL_UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_TRANS:
        {
            return "NPL_UDC_FI_MACRO_ID_DB_ACCESS_HEADER_ACCESS_TRANS(0x5)";
            break;
        }
        case NPL_UDC_FI_MACRO_ID_CATCH_RESERVED:
        {
            return "NPL_UDC_FI_MACRO_ID_CATCH_RESERVED(0x3e)";
            break;
        }
        case NPL_UDC_FI_MACRO_ID_UNDEF:
        {
            return "NPL_UDC_FI_MACRO_ID_UNDEF(0x3f)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_udc_fi_macro_ids_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_udf_enable_e enum_instance)
{
    switch(enum_instance) {
        case NPL_UDF_DISABLED:
        {
            return "NPL_UDF_DISABLED(0x0)";
            break;
        }
        case NPL_V4_UDF_ENABLE:
        {
            return "NPL_V4_UDF_ENABLE(0x1)";
            break;
        }
        case NPL_V6_UDF_ENABLE:
        {
            return "NPL_V6_UDF_ENABLE(0x2)";
            break;
        }
        case NPL_UDF_ENABLED:
        {
            return "NPL_UDF_ENABLED(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_udf_enable_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_udp_port_e enum_instance)
{
    switch(enum_instance) {
        case NPL_UDP_BFD_SINGLE_HOP_PORT:
        {
            return "NPL_UDP_BFD_SINGLE_HOP_PORT(0xec8)";
            break;
        }
        case NPL_UDP_BFD_ECHO_PORT:
        {
            return "NPL_UDP_BFD_ECHO_PORT(0xec9)";
            break;
        }
        case NPL_UDP_BFD_MULTI_HOP_PORT:
        {
            return "NPL_UDP_BFD_MULTI_HOP_PORT(0x12b0)";
            break;
        }
        case NPL_UDP_BFD_MICRO_HOP_PORT:
        {
            return "NPL_UDP_BFD_MICRO_HOP_PORT(0x1a80)";
            break;
        }
        case NPL_UDP_NVGRE_DST_PORT:
        {
            return "NPL_UDP_NVGRE_DST_PORT(0x2468)";
            break;
        }
        case NPL_UDP_VXLAN_DST_PORT:
        {
            return "NPL_UDP_VXLAN_DST_PORT(0x12b5)";
            break;
        }
        case NPL_UDP_MPLS_DST_PORT:
        {
            return "NPL_UDP_MPLS_DST_PORT(0x19eb)";
            break;
        }
        case NPL_UDP_IP_DST_PORT:
        {
            return "NPL_UDP_IP_DST_PORT(0x17c0)";
            break;
        }
        case NPL_UDP_BFD_CONTROL_SRC_PORT:
        {
            return "NPL_UDP_BFD_CONTROL_SRC_PORT(0xc000)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_udp_port_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_vlan_edit_command_main_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_VLAN_EDIT_COMMAND_MAIN_OTHER:
        {
            return "NPL_VLAN_EDIT_COMMAND_MAIN_OTHER(0x0)";
            break;
        }
        case NPL_VLAN_EDIT_COMMAND_MAIN_TRANSLATE_2_2:
        {
            return "NPL_VLAN_EDIT_COMMAND_MAIN_TRANSLATE_2_2(0x1)";
            break;
        }
        case NPL_VLAN_EDIT_COMMAND_MAIN_TRANSLATE_1_2:
        {
            return "NPL_VLAN_EDIT_COMMAND_MAIN_TRANSLATE_1_2(0x2)";
            break;
        }
        case NPL_VLAN_EDIT_COMMAND_MAIN_PUSH_2:
        {
            return "NPL_VLAN_EDIT_COMMAND_MAIN_PUSH_2(0x3)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_vlan_edit_command_main_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_vlan_edit_command_secondary_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_VLAN_EDIT_COMMAND_SECONDARY_NOP:
        {
            return "NPL_VLAN_EDIT_COMMAND_SECONDARY_NOP(0x0)";
            break;
        }
        case NPL_VLAN_EDIT_COMMAND_SECONDARY_REMARK:
        {
            return "NPL_VLAN_EDIT_COMMAND_SECONDARY_REMARK(0x1)";
            break;
        }
        case NPL_VLAN_EDIT_COMMAND_SECONDARY_POP_1:
        {
            return "NPL_VLAN_EDIT_COMMAND_SECONDARY_POP_1(0x2)";
            break;
        }
        case NPL_VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_1_1:
        {
            return "NPL_VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_1_1(0x3)";
            break;
        }
        case NPL_VLAN_EDIT_COMMAND_SECONDARY_PUSH_1:
        {
            return "NPL_VLAN_EDIT_COMMAND_SECONDARY_PUSH_1(0x4)";
            break;
        }
        case NPL_VLAN_EDIT_COMMAND_SECONDARY_POP_2:
        {
            return "NPL_VLAN_EDIT_COMMAND_SECONDARY_POP_2(0x5)";
            break;
        }
        case NPL_VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_2_1:
        {
            return "NPL_VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_2_1(0x6)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_vlan_edit_command_secondary_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_vlan_editing_type_e enum_instance)
{
    switch(enum_instance) {
        case NPL_VLAN_EDITING_NOP:
        {
            return "NPL_VLAN_EDITING_NOP(0x0)";
            break;
        }
        case NPL_VLAN_EDITING_REMARK:
        {
            return "NPL_VLAN_EDITING_REMARK(0x1)";
            break;
        }
        case NPL_VLAN_EDITING_POP_1:
        {
            return "NPL_VLAN_EDITING_POP_1(0x2)";
            break;
        }
        case NPL_VLAN_EDITING_POP_2:
        {
            return "NPL_VLAN_EDITING_POP_2(0x5)";
            break;
        }
        case NPL_VLAN_EDITING_PUSH_1:
        {
            return "NPL_VLAN_EDITING_PUSH_1(0x4)";
            break;
        }
        case NPL_VLAN_EDITING_PUSH_2:
        {
            return "NPL_VLAN_EDITING_PUSH_2(0x18)";
            break;
        }
        case NPL_VLAN_EDITING_TRANSLATE_1_1:
        {
            return "NPL_VLAN_EDITING_TRANSLATE_1_1(0x3)";
            break;
        }
        case NPL_VLAN_EDITING_TRANSLATE_2_1:
        {
            return "NPL_VLAN_EDITING_TRANSLATE_2_1(0x6)";
            break;
        }
        case NPL_VLAN_EDITING_TRANSLATE_1_2:
        {
            return "NPL_VLAN_EDITING_TRANSLATE_1_2(0x10)";
            break;
        }
        case NPL_VLAN_EDITING_TRANSLATE_2_2:
        {
            return "NPL_VLAN_EDITING_TRANSLATE_2_2(0x8)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_vlan_editing_type_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_voq_cgm_pd_counter_e enum_instance)
{
    switch(enum_instance) {
        case NPL_VOQ_CGM_PD_COUNTER_UC:
        {
            return "NPL_VOQ_CGM_PD_COUNTER_UC(0x0)";
            break;
        }
        case NPL_VOQ_CGM_PD_COUNTER_MC:
        {
            return "NPL_VOQ_CGM_PD_COUNTER_MC(0x1)";
            break;
        }
        case NPL_VOQ_CGM_PD_COUNTER_MS_UC:
        {
            return "NPL_VOQ_CGM_PD_COUNTER_MS_UC(0x2)";
            break;
        }
        case NPL_VOQ_CGM_PD_COUNTER_MS_MC:
        {
            return "NPL_VOQ_CGM_PD_COUNTER_MS_MC(0x3)";
            break;
        }
        case NPL_VOQ_CGM_PD_COUNTER_IGNORE:
        {
            return "NPL_VOQ_CGM_PD_COUNTER_IGNORE(0x4)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_voq_cgm_pd_counter_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_vpn_mode_e enum_instance)
{
    switch(enum_instance) {
        case NPL_VPN_MODE_PER_VRF:
        {
            return "NPL_VPN_MODE_PER_VRF(0x0)";
            break;
        }
        case NPL_VPN_MODE_PER_PREFIX:
        {
            return "NPL_VPN_MODE_PER_PREFIX(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_vpn_mode_e");
    }
    return "";
}


std::string npl_enum_to_string(const npl_vxlan_profile_e enum_instance)
{
    switch(enum_instance) {
        case NPL_L3_VXLAN_MAC_TERM_WITH_DA:
        {
            return "NPL_L3_VXLAN_MAC_TERM_WITH_DA(0x0)";
            break;
        }
        case NPL_L3_VXLAN_MAC_TERM_NO_DA:
        {
            return "NPL_L3_VXLAN_MAC_TERM_NO_DA(0x1)";
            break;
        }
        
        default:
        return std::string("UNKNOWN") + std::string("_npl_vxlan_profile_e");
    }
    return "";
}


