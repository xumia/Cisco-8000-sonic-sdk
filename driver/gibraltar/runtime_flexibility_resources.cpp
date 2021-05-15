
#include "common/defines.h"

#include "runtime_flexibility_resources.h"

namespace silicon_one {

// Table FEC:
//
//                  8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                padding(54)                                                |            Destination(20)            |  type(6)  |       Mpls_Head|VxLAN|Basic_Router; destination: CE_PTR|L2_DLP|L2_DLPA|LEVEL2_ECMP
//   |enc_typ|                                            padding(50)                                            |            Destination(20)            |  type(6)  | E     Basic_Router
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


la_status
configure_fec_type_decoding_table(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_fec_type_decoding_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_fec_type_decoding_table_t> table(device->m_tables.fec_type_decoding_table);


	npl_fec_type_decoding_table_key_t key;
	npl_fec_type_decoding_table_value_t value;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                padding(54)                                                |            Destination(20)            |  type(6)  |       Mpls_Head|VxLAN|Basic_Router; destination: CE_PTR|L2_DLP|L2_DLPA|LEVEL2_ECMP
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type fec_fec_destination_t {
//   fields {
//     padding     : 54;
//     destination : 20; // may be: ce_ptr or l2_dlp or l2_dlpa or level2_ecmp
//     type        : fec_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_FEC_FEC_DESTINATION;
	value.action = NPL_FEC_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 0;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = 0;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|                                            padding(50)                                            |            Destination(20)            |  type(6)  | E     Basic_Router
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type fec_destination1_t {
//   fields {
//     enc_type    : 4;
//     padding     : 50;
//     destination : 20; // may be: l3_nh
//     type        : fec_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_FEC_DESTINATION1;
	value.action = NPL_FEC_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 0;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = 0;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 76;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 29;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}

// Table Stage0:
//
//         32              24              16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          CE_PTR(16)           |VPN|       L3_NH(12)       |  type(6)  | E     Mpls_Head
//   |          CE_PTR(16)           |VPN|       L3_NH(12)       |  type(6)  | E   C Mpls_Head
//   |          CE_PTR(16)           |VPN|       L3_NH(12)       |  type(6)  | E   C Mpls_Head
//   |          CE_PTR(16)           |VPN|      P_L3_NH(12)      |  type(6)  | E     Mpls_Head
//   |          CE_PTR(16)           |VPN|      P_L3_NH(12)      |  type(6)  | E   C Mpls_Head
//   |          CE_PTR(16)           |VPN|      P_L3_NH(12)      |  type(6)  | E   C Mpls_Head
//   |    padding(10)    |            Destination(20)            |  type(6)  |       Basic_Router
//   |  Overlay_NH(10)   |            Destination(20)            |  type(6)  | E i   VxLAN; destination: L3_NH|LEVEL2_ECMP
//   |enc_typ|padding(6) |            Destination(20)            |  type(6)  | E i   AC; destination: BVN|DSP|DSPA
//   |enc_typ|padding(6) |            Destination(20)            |  type(6)  | E     Basic_Router
//   |pad|         IP_Tunnel(16)         |       L3_NH(12)       |  type(6)  | E     GRE
//   |p|         IP_Tunnel(16)         |     LEVEL2_ECMP(13)     |  type(6)  | E     GRE
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                  0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                      padding(28)                      |          CE_PTR(16)           |VPN|            Destination(20)            |  type(6)  |       Mpls_Head
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |enc_typ|           padding(17)           |            L2_DLP(18)             |            Destination(20)            |  type(6)  | E     AC; destination: BVN|DSP|DSPA
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


la_status
configure_stage0_type_decoding_table(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_stage0_type_decoding_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_stage0_type_decoding_table_t> table(device->m_tables.stage0_type_decoding_table);


	npl_stage0_type_decoding_table_key_t key;
	npl_stage0_type_decoding_table_value_t value;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          CE_PTR(16)           |VPN|       L3_NH(12)       |  type(6)  | E     Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage0_ce_ptr_l3_nh_vpn_inter_as_ce_ptr_t {
//   fields {
//     ce_ptr       : 16;
//     vpn_inter_as : 2;
//     l3_nh        : 12;
//     type         : stage0_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE0_CE_PTR_L3_NH_VPN_INTER_AS_CE_PTR;
	value.action = NPL_STAGE0_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 48;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 18;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 2;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 21;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 20;
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 17;
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          CE_PTR(16)           |VPN|       L3_NH(12)       |  type(6)  | E   C Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage0_ce_ptr_l3_nh_vpn_inter_as_ce_ptr_with_common_data_t {
//   fields {
//     ce_ptr       : 16;
//     vpn_inter_as : 2;
//     l3_nh        : 12;
//     type         : stage0_entry_type_e;
//   }
// }// common_data may be used: te_tunnel16b


	key.type = NPL_ENTRY_TYPE_STAGE0_CE_PTR_L3_NH_VPN_INTER_AS_CE_PTR_WITH_COMMON_DATA;
	value.action = NPL_STAGE0_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 48;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 18;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 2;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 21;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 20;
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 17;
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 112;
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 13;
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          CE_PTR(16)           |VPN|       L3_NH(12)       |  type(6)  | E   C Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage0_l3_nh_vpn_inter_as_ce_ptr_with_common_data1_t {
//   fields {
//     ce_ptr       : 16;
//     vpn_inter_as : 2;
//     l3_nh        : 12;
//     type         : stage0_entry_type_e;
//   }
// }// common_data may be used: te_tunnel16b


	key.type = NPL_ENTRY_TYPE_STAGE0_L3_NH_VPN_INTER_AS_CE_PTR_WITH_COMMON_DATA1;
	value.action = NPL_STAGE0_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 48;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 18;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 2;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 21;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 20;
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 17;
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 112;
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 13;
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          CE_PTR(16)           |VPN|      P_L3_NH(12)      |  type(6)  | E     Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage0_ce_ptr_p_l3_nh_vpn_inter_as_ce_ptr_t {
//   fields {
//     ce_ptr       : 16;
//     vpn_inter_as : 2;
//     p_l3_nh      : 12;
//     type         : stage0_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE0_CE_PTR_P_L3_NH_VPN_INTER_AS_CE_PTR;
	value.action = NPL_STAGE0_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 30;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 18;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 2;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 21;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 20;
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 17;
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          CE_PTR(16)           |VPN|      P_L3_NH(12)      |  type(6)  | E   C Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage0_ce_ptr_p_l3_nh_vpn_inter_as_ce_ptr_with_common_data_t {
//   fields {
//     ce_ptr       : 16;
//     vpn_inter_as : 2;
//     p_l3_nh      : 12;
//     type         : stage0_entry_type_e;
//   }
// }// common_data may be used: te_tunnel16b


	key.type = NPL_ENTRY_TYPE_STAGE0_CE_PTR_P_L3_NH_VPN_INTER_AS_CE_PTR_WITH_COMMON_DATA;
	value.action = NPL_STAGE0_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 30;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 18;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 2;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 21;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 20;
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 17;
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 112;
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 13;
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          CE_PTR(16)           |VPN|      P_L3_NH(12)      |  type(6)  | E   C Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage0_p_l3_nh_vpn_inter_as_ce_ptr_with_common_data1_t {
//   fields {
//     ce_ptr       : 16;
//     vpn_inter_as : 2;
//     p_l3_nh      : 12;
//     type         : stage0_entry_type_e;
//   }
// }// common_data may be used: te_tunnel16b


	key.type = NPL_ENTRY_TYPE_STAGE0_P_L3_NH_VPN_INTER_AS_CE_PTR_WITH_COMMON_DATA1;
	value.action = NPL_STAGE0_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 30;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 18;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 2;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 21;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 20;
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 17;
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 112;
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 13;
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    padding(10)    |            Destination(20)            |  type(6)  |       Basic_Router
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage0_ecmp_destination_t {
//   fields {
//     padding     : 10;
//     destination : 20; // may be: level2_ecmp
//     type        : stage0_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE0_ECMP_DESTINATION;
	value.action = NPL_STAGE0_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 0;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = 0;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Overlay_NH(10)   |            Destination(20)            |  type(6)  | E i   VxLAN; destination: L3_NH|LEVEL2_ECMP
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage0_l2_dlp_destination_overlay_nh_t {
//   fields {
//     overlay_nh  : 10;
//     destination : 20; // may be: l3_nh or level2_ecmp
//     type        : stage0_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE0_L2_DLP_DESTINATION_OVERLAY_NH;
	value.action = NPL_STAGE0_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 0;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L2_HEADER_TYPE_VXLAN;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits        = 18;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles   = 17;
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 26;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 10;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 14;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|padding(6) |            Destination(20)            |  type(6)  | E i   AC; destination: BVN|DSP|DSPA
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage0_l2_dlp_destination_t {
//   fields {
//     enc_type    : 4;
//     padding     : 6;
//     destination : 20; // may be: bvn or dsp or dspa
//     type        : stage0_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE0_L2_DLP_DESTINATION;
	value.action = NPL_STAGE0_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 0;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = 0;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits        = 18;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles   = 24;
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 32;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 29;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|padding(6) |            Destination(20)            |  type(6)  | E     Basic_Router
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage0_destination1_t {
//   fields {
//     enc_type    : 4;
//     padding     : 6;
//     destination : 20; // may be: l3_nh
//     type        : stage0_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE0_DESTINATION1;
	value.action = NPL_STAGE0_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 0;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = 0;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 32;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 29;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |pad|         IP_Tunnel(16)         |       L3_NH(12)       |  type(6)  | E     GRE
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage0_ce_ptr_l3_nh_ip_tunnel_t {
//   fields {
//     padding   : 2;
//     ip_tunnel : 16;
//     l3_nh     : 12;
//     type      : stage0_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE0_CE_PTR_L3_NH_IP_TUNNEL;
	value.action = NPL_STAGE0_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 48;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_GRE;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 18;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 18;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |p|         IP_Tunnel(16)         |     LEVEL2_ECMP(13)     |  type(6)  | E     GRE
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage0_ce_ptr_level2_ecmp_ip_tunnel_t {
//   fields {
//     padding     : 1;
//     ip_tunnel   : 16;
//     level2_ecmp : 13;
//     type        : stage0_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE0_CE_PTR_LEVEL2_ECMP_IP_TUNNEL;
	value.action = NPL_STAGE0_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 13;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 26;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_GRE;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 19;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 18;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      padding(28)                      |          CE_PTR(16)           |VPN|            Destination(20)            |  type(6)  |       Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage0_ce_ptr_destination_vpn_inter_as_ce_ptr_t {
//   fields {
//     padding      : 28;
//     ce_ptr       : 16;
//     vpn_inter_as : 2;
//     destination  : 20; // may be: level2_ecmp
//     type         : stage0_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE0_CE_PTR_DESTINATION_VPN_INTER_AS_CE_PTR;
	value.action = NPL_STAGE0_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 0;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = 0;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 26;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 2;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 21;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 28;
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 17;
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|           padding(17)           |            L2_DLP(18)             |            Destination(20)            |  type(6)  | E     AC; destination: BVN|DSP|DSPA
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage0_l2_dlp_destination_l2_dlp_t {
//   fields {
//     enc_type    : 4;
//     padding     : 17;
//     l2_dlp      : 18;
//     destination : 20; // may be: bvn or dsp or dspa
//     type        : stage0_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE0_L2_DLP_DESTINATION_L2_DLP;
	value.action = NPL_STAGE0_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 0;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = 0;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 61;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 29;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 26;
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 18;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 24;
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}

// Table Stage1:
//
//         32              24              16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |    padding(10)    |            Destination(20)            |  type(6)  |       GRE|VxLAN
//   |enc_typ|padding(6) |            Destination(20)            |  type(6)  | E     Basic_Router|Mpls_Head
//   |pad|       TE_Tunnel16b(16)        |       L3_NH(12)       |  type(6)  | E i   Mpls_Midpoint
//   |pad|   TE_Tunnel14b_or_ASBR(16)    |       L3_NH(12)       |  type(6)  | E     Mpls_Head
//   |pad|   TE_Tunnel14b_or_ASBR(16)    |       L3_NH(12)       |  type(6)  | E     Mpls_Head
//   |pad|   TE_Tunnel14b_or_ASBR(16)    |       L3_NH(12)       |  type(6)  | E     Mpls_Head
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                  0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                 padding(39)                                 |            Destination(20)            |  type(6)  |     C Mpls_Head|Mpls_Midpoint
//   |enc_typ|                     padding(27)                     |       TE_Tunnel16b(16)        |       L3_NH(12)       |  type(6)  | E     Mpls_Midpoint
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


la_status
configure_stage1_type_decoding_table(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_stage1_type_decoding_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_stage1_type_decoding_table_t> table(device->m_tables.stage1_type_decoding_table);


	npl_stage1_type_decoding_table_key_t key;
	npl_stage1_type_decoding_table_value_t value;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    padding(10)    |            Destination(20)            |  type(6)  |       GRE|VxLAN
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage1_level2_ecmp_destination_t {
//   fields {
//     padding     : 10;
//     destination : 20; // may be: l3_nh
//     type        : stage1_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE1_LEVEL2_ECMP_DESTINATION;
	value.action = NPL_STAGE1_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 0;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = 0;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|padding(6) |            Destination(20)            |  type(6)  | E     Basic_Router|Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage1_destination1_t {
//   fields {
//     enc_type    : 4;
//     padding     : 6;
//     destination : 20; // may be: l3_nh
//     type        : stage1_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE1_DESTINATION1;
	value.action = NPL_STAGE1_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 0;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = 0;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 32;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 29;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |pad|       TE_Tunnel16b(16)        |       L3_NH(12)       |  type(6)  | E i   Mpls_Midpoint
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage1_p_l3_nh_l3_nh_te_tunnel16b_t {
//   fields {
//     padding      : 2;
//     te_tunnel16b : 16;
//     l3_nh        : 12;
//     type         : stage1_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE1_P_L3_NH_L3_NH_TE_TUNNEL16B;
	value.action = NPL_STAGE1_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 48;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_ILM_TUNNEL;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits        = 12;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles   = 22;
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 18;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 13;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |pad|   TE_Tunnel14b_or_ASBR(16)    |       L3_NH(12)       |  type(6)  | E     Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage1_level2_ecmp_l3_nh_te_tunnel14b_or_asbr_t {
//   fields {
//     padding              : 2;
//     te_tunnel14b_or_asbr : 16;
//     l3_nh                : 12;
//     type                 : stage1_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE1_LEVEL2_ECMP_L3_NH_TE_TUNNEL14B_OR_ASBR;
	value.action = NPL_STAGE1_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 48;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 18;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 13;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |pad|   TE_Tunnel14b_or_ASBR(16)    |       L3_NH(12)       |  type(6)  | E     Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage1_l3_nh_te_tunnel14b_or_asbr1_t {
//   fields {
//     padding              : 2;
//     te_tunnel14b_or_asbr : 16;
//     l3_nh                : 12;
//     type                 : stage1_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE1_L3_NH_TE_TUNNEL14B_OR_ASBR1;
	value.action = NPL_STAGE1_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 48;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 18;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 13;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |pad|   TE_Tunnel14b_or_ASBR(16)    |       L3_NH(12)       |  type(6)  | E     Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage1_l3_nh_te_tunnel14b_or_asbr2_t {
//   fields {
//     padding              : 2;
//     te_tunnel14b_or_asbr : 16;
//     l3_nh                : 12;
//     type                 : stage1_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE1_L3_NH_TE_TUNNEL14B_OR_ASBR2;
	value.action = NPL_STAGE1_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 48;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 18;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 13;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                 padding(39)                                 |            Destination(20)            |  type(6)  |     C Mpls_Head|Mpls_Midpoint
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage1_p_l3_nh_destination_with_common_data_t {
//   fields {
//     padding     : 39;
//     destination : 20; // may be: l3_nh
//     type        : stage1_entry_type_e;
//   }
// }// common_data may be used: enc_type,te_tunnel14b_or_asbr


	key.type = NPL_ENTRY_TYPE_STAGE1_P_L3_NH_DESTINATION_WITH_COMMON_DATA;
	value.action = NPL_STAGE1_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 0;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = 0;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 124;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 29;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 108;
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 13;
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|                     padding(27)                     |       TE_Tunnel16b(16)        |       L3_NH(12)       |  type(6)  | E     Mpls_Midpoint
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage1_l3_nh_te_tunnel16b1_t {
//   fields {
//     enc_type     : 4;
//     padding      : 27;
//     te_tunnel16b : 16;
//     l3_nh        : 12;
//     type         : stage1_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE1_L3_NH_TE_TUNNEL16B1;
	value.action = NPL_STAGE1_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 48;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = 0;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 61;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 29;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 6;
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 12;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 22;
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 18;
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 13;
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}

// Table Stage2:
//
//         32              24              16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                  0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                        padding(30)                        |          L3_DLP(16)           |            Destination(20)            |  type(6)  |       Basic_Router|GRE|Mpls_Head|Mpls_Midpoint|VxLAN
//   |                padding(22)                |  dlp_attr(8)  |          L3_DLP(16)           |            Destination(20)            |  type(6)  |   i   Basic_Router|Mpls_Head|Mpls_Midpoint|VxLAN|GRE; destination: BVN|DSP|DSPA
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


la_status
configure_stage2_type_decoding_table(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_stage2_type_decoding_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_stage2_type_decoding_table_t> table(device->m_tables.stage2_type_decoding_table);


	npl_stage2_type_decoding_table_key_t key;
	npl_stage2_type_decoding_table_value_t value;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        padding(30)                        |          L3_DLP(16)           |            Destination(20)            |  type(6)  |       Basic_Router|GRE|Mpls_Head|Mpls_Midpoint|VxLAN
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage2_l3_nh_destination_l3_dlp_t {
//   fields {
//     padding     : 30;
//     l3_dlp      : 16;
//     destination : 20; // may be: glean
//     type        : stage2_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE2_L3_NH_DESTINATION_L3_DLP;
	value.action = NPL_STAGE2_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 0;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = 0;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 26;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 25;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                padding(22)                |  dlp_attr(8)  |          L3_DLP(16)           |            Destination(20)            |  type(6)  |   i   Basic_Router|Mpls_Head|Mpls_Midpoint|VxLAN|GRE; destination: BVN|DSP|DSPA
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage2_l3_nh_destination_l3_dlp_dlp_attr_t {
//   fields {
//     padding     : 22;
//     dlp_attr    : 8;
//     l3_dlp      : 16;
//     destination : 20; // may be: bvn or dsp or dspa
//     type        : stage2_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE2_L3_NH_DESTINATION_L3_DLP_DLP_ATTR;
	value.action = NPL_STAGE2_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 0;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = 0;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits        = 12;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles   = 22;
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 26;
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 16;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 25;
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 42;
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 8;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 10;
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}

// Table Stage3:
//
//         32              24              16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |    padding(10)    |            Destination(20)            |  type(6)  |       DSPA
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                  0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


la_status
configure_stage3_type_decoding_table(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_stage3_type_decoding_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_stage3_type_decoding_table_t> table(device->m_tables.stage3_type_decoding_table);


	npl_stage3_type_decoding_table_key_t key;
	npl_stage3_type_decoding_table_value_t value;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    padding(10)    |            Destination(20)            |  type(6)  |       DSPA
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage3_dspa_destination_t {
//   fields {
//     padding     : 10;
//     destination : 20; // may be: dsp
//     type        : stage3_entry_type_e;
//   }
// }


	key.type = NPL_ENTRY_TYPE_STAGE3_DSPA_DESTINATION;
	value.action = NPL_STAGE3_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.resolution_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.resolution_type_decoding_table_result.next_destination_type          = 0;
	value.payloads.resolution_type_decoding_table_result.next_destination_offset        = 6;
	value.payloads.resolution_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.resolution_type_decoding_table_result.encapsulation_type             = 0;
	value.payloads.resolution_type_decoding_table_result.dest_size_on_encap_data_in_bits         = 0;
	value.payloads.resolution_type_decoding_table_result.dest_offset_on_encap_data_in_nibbles    = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_0.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_0.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.offset_in_bits         = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.field_2.size_in_bits           = 0;
	value.payloads.resolution_type_decoding_table_result.field_2.destination_in_nibbles = 0; // don't care
	value.payloads.resolution_type_decoding_table_result.do_lp_queuing = 0;

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}


la_status
configure_decoding_tables(la_device_impl* device)
{
    la_status status;


    status = configure_fec_type_decoding_table(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    status = configure_stage0_type_decoding_table(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    status = configure_stage1_type_decoding_table(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    status = configure_stage2_type_decoding_table(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    status = configure_stage3_type_decoding_table(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
