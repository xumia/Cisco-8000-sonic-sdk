
#include "common/defines.h"

#include "runtime_flexibility_types.h"

namespace silicon_one {

// Table Native_FEC:
//
//                 48              40              32              24              16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                          padding(32)                          |            Destination(20)            |type(4)|     Mpls_Head|VxLAN|Basic_Router; destination: CE_PTR|L2_DLP|L2_DLPA|Stage2_ECMP
//   |enc_typ|                      padding(28)                      |            Destination(20)            |type(4)| E   Basic_Router
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


la_status
configure_native_fec_type_decoding_table(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_native_fec_type_decoding_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_native_fec_type_decoding_table_t> table(device->m_tables.native_fec_type_decoding_table);


	npl_native_fec_type_decoding_table_key_t key;
	npl_native_fec_type_decoding_table_value_t value;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          padding(32)                          |            Destination(20)            |type(4)|     Mpls_Head|VxLAN|Basic_Router; destination: CE_PTR|L2_DLP|L2_DLPA|Stage2_ECMP
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_fec_destination_t {
//   fields {
//     padding     : 32;
//     destination : 20; // may be: ce_ptr or l2_dlp or l2_dlpa or stage2_ecmp
//     type        : native_fec_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_FEC_ENTRY_TYPE_NATIVE_FEC_DESTINATION;
	value.action = NPL_NATIVE_FEC_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_fec_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.native_fec_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.native_fec_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.native_fec_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_fec_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_fec_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.native_fec_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.native_fec_type_decoding_table_result.field_0.offset_in_bits         = 0; // don't care
	value.payloads.native_fec_type_decoding_table_result.field_0.size_in_bits           = 0;
	value.payloads.native_fec_type_decoding_table_result.field_0.destination_in_nibbles = 0; // don't care
	value.payloads.native_fec_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.native_fec_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.native_fec_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.native_fec_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_fec_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|                      padding(28)                      |            Destination(20)            |type(4)| E   Basic_Router
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_fec_destination1_t {
//   fields {
//     enc_type    : 4;
//     padding     : 28;
//     destination : 20; // may be: stage3_nh
//     type        : native_fec_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_FEC_ENTRY_TYPE_NATIVE_FEC_DESTINATION1;
	value.action = NPL_NATIVE_FEC_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_fec_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.native_fec_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.native_fec_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.native_fec_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_fec_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_fec_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.native_fec_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.native_fec_type_decoding_table_result.field_0.offset_in_bits         = 52;
	value.payloads.native_fec_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.native_fec_type_decoding_table_result.field_0.destination_in_nibbles = 19;
	value.payloads.native_fec_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.native_fec_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.native_fec_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.native_fec_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_fec_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}

// Table Native_FRR:
//
//         48              40              32              24              16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |              padding(20)              |FRR_Protection(|            Destination(20)            |type(4)|     FRR_Protection_Placeholder
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


la_status
configure_native_frr_type_decoding_table(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_native_frr_type_decoding_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_native_frr_type_decoding_table_t> table(device->m_tables.native_frr_type_decoding_table);


	npl_native_frr_type_decoding_table_key_t key;
	npl_native_frr_type_decoding_table_value_t value;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              padding(20)              |FRR_Protection(|            Destination(20)            |type(4)|     FRR_Protection_Placeholder
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_frr_destination_frr_protection_t {
//   fields {
//     padding        : 20;
//     frr_protection : 8;
//     destination    : 20; // may be: dsp
//     type           : native_frr_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_FRR_ENTRY_TYPE_NATIVE_FRR_DESTINATION_FRR_PROTECTION;
	value.action = NPL_NATIVE_FRR_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_frr_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.native_frr_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.native_frr_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.native_frr_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_frr_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_frr_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.native_frr_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.native_frr_type_decoding_table_result.field_0.offset_in_bits         = 24;
	value.payloads.native_frr_type_decoding_table_result.field_0.size_in_bits           = 8;
	value.payloads.native_frr_type_decoding_table_result.field_0.destination_in_nibbles = 0;
	value.payloads.native_frr_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.native_frr_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.native_frr_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.native_frr_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_frr_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}

// Table Native_L2_LP:
//
//                 16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |            Destination(20)            |type(4)| E i AC; destination: BVN|DSP|DSPA
//   |            Destination(20)            |type(4)|   i Mpls_Head
//   |            Destination(20)            |type(4)| E i Mpls_Head; destination: Stage2_P_NH|Stage3_NH
//   |padding(5|VPN|     Stage2_ECMP(13)     |type(4)|   i Mpls_Head
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                 40              32              24              16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |enc_typ|    padding(10)    |  Overlay_NH(10)   |            Destination(20)            |type(4)| E i VxLAN; destination: Stage2_ECMP|Stage3_NH
//   |enc_typ|padding|         IP_Tunnel(16)         |            Destination(20)            |type(4)| E   GRE; destination: Stage2_ECMP|Stage3_NH
//   |enc_typ|padding|       TE_Tunnel16b(16)        |            Destination(20)            |type(4)| E i Mpls_Head; destination: Stage2_P_NH|Stage3_NH
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   40              32              24              16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |enc_typ|paddi|            CE_PTR(18)             |     Stage3_NH(12)     |type(4)| E   Mpls_Head
//   |enc_typ|paddi|            CE_PTR(18)             |    Stage2_P_NH(12)    |type(4)| E   Mpls_Head
//   |enc_typ|paddi|            L2_DLP(18)             |        DSP(12)        |type(4)| E   AC
//   |enc_typ|pad|            L2_DLP(18)             |        DSPA(13)         |type(4)| E   AC
//   |padding(6) |            CE_PTR(18)             |     Stage2_ECMP(13)     |type(4)|     Mpls_Head
//   |paddi|            L2_DLP(18)             |            BVN(16)            |type(4)| E   AC
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


la_status
configure_native_l2_lp_type_decoding_table(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_native_l2_lp_type_decoding_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_native_l2_lp_type_decoding_table_t> table(device->m_tables.native_l2_lp_type_decoding_table);


	npl_native_l2_lp_type_decoding_table_key_t key;
	npl_native_l2_lp_type_decoding_table_value_t value;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |            Destination(20)            |type(4)| E i AC; destination: BVN|DSP|DSPA
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_l2_lp_destination_t {
//   fields {
//     destination : 20; // may be: bvn or dsp or dspa
//     type        : native_l2_lp_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_DESTINATION;
	value.action = NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_add_type         = 1;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L2_HEADER_TYPE_AC;
	value.payloads.native_l2_lp_type_decoding_table_result.index_size_in_nibbles          = 5;
	value.payloads.native_l2_lp_type_decoding_table_result.index_destination_in_nibbles   = 14;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.offset_in_bits         = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.size_in_bits           = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.destination_in_nibbles = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |            Destination(20)            |type(4)|   i Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_l2_lp_destination1_t {
//   fields {
//     destination : 20; // may be: stage2_ecmp
//     type        : native_l2_lp_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_DESTINATION1;
	value.action = NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.index_size_in_nibbles          = 5;
	value.payloads.native_l2_lp_type_decoding_table_result.index_destination_in_nibbles   = 7;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.offset_in_bits         = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.size_in_bits           = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.destination_in_nibbles = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |            Destination(20)            |type(4)| E i Mpls_Head; destination: Stage2_P_NH|Stage3_NH
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_l2_lp_destination2_t {
//   fields {
//     destination : 20; // may be: stage2_p_nh or stage3_nh
//     type        : native_l2_lp_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_DESTINATION2;
	value.action = NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_add_type         = 1;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE;
	value.payloads.native_l2_lp_type_decoding_table_result.index_size_in_nibbles          = 5;
	value.payloads.native_l2_lp_type_decoding_table_result.index_destination_in_nibbles   = 7;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.offset_in_bits         = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.size_in_bits           = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.destination_in_nibbles = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |padding(5|VPN|     Stage2_ECMP(13)     |type(4)|   i Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_l2_lp_stage2_ecmp_vpn_inter_as_t {
//   fields {
//     padding      : 5;
//     vpn_inter_as : 2;
//     stage2_ecmp  : 13;
//     type         : native_l2_lp_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_STAGE2_ECMP_VPN_INTER_AS;
	value.action = NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_size          = 13;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_mask          = 13;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.index_size_in_nibbles          = 4;
	value.payloads.native_l2_lp_type_decoding_table_result.index_destination_in_nibbles   = 7;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.offset_in_bits         = 17;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.size_in_bits           = 2;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.destination_in_nibbles = 11;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|    padding(10)    |  Overlay_NH(10)   |            Destination(20)            |type(4)| E i VxLAN; destination: Stage2_ECMP|Stage3_NH
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_l2_lp_destination_overlay_nh_t {
//   fields {
//     enc_type    : 4;
//     padding     : 10;
//     overlay_nh  : 10;
//     destination : 20; // may be: stage2_ecmp or stage3_nh
//     type        : native_l2_lp_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_DESTINATION_OVERLAY_NH;
	value.action = NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.index_size_in_nibbles          = 5;
	value.payloads.native_l2_lp_type_decoding_table_result.index_destination_in_nibbles   = 7;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.offset_in_bits         = 44;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.destination_in_nibbles = 19;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.offset_in_bits         = 24;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.size_in_bits           = 10;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.destination_in_nibbles = 4;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|padding|         IP_Tunnel(16)         |            Destination(20)            |type(4)| E   GRE; destination: Stage2_ECMP|Stage3_NH
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_l2_lp_destination_ip_tunnel_t {
//   fields {
//     enc_type    : 4;
//     padding     : 4;
//     ip_tunnel   : 16;
//     destination : 20; // may be: stage2_ecmp or stage3_nh
//     type        : native_l2_lp_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_DESTINATION_IP_TUNNEL;
	value.action = NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.offset_in_bits         = 44;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.destination_in_nibbles = 19;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.offset_in_bits         = 24;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.size_in_bits           = 16;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.destination_in_nibbles = 8;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|padding|       TE_Tunnel16b(16)        |            Destination(20)            |type(4)| E i Mpls_Head; destination: Stage2_P_NH|Stage3_NH
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_l2_lp_destination_te_tunnel16b_t {
//   fields {
//     enc_type     : 4;
//     padding      : 4;
//     te_tunnel16b : 16;
//     destination  : 20; // may be: stage2_p_nh or stage3_nh
//     type         : native_l2_lp_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_DESTINATION_TE_TUNNEL16B;
	value.action = NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.index_size_in_nibbles          = 5;
	value.payloads.native_l2_lp_type_decoding_table_result.index_destination_in_nibbles   = 7;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.offset_in_bits         = 44;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.destination_in_nibbles = 19;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.offset_in_bits         = 24;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.size_in_bits           = 16;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.destination_in_nibbles = 3;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|paddi|            CE_PTR(18)             |     Stage3_NH(12)     |type(4)| E   Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_l2_lp_stage3_nh_ce_ptr_t {
//   fields {
//     enc_type  : 4;
//     padding   : 3;
//     ce_ptr    : 18;
//     stage3_nh : 12;
//     type      : native_l2_lp_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_STAGE3_NH_CE_PTR;
	value.action = NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_mask          = 24;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.offset_in_bits         = 37;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.destination_in_nibbles = 19;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.offset_in_bits         = 16;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.size_in_bits           = 18;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.destination_in_nibbles = 7;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|paddi|            CE_PTR(18)             |    Stage2_P_NH(12)    |type(4)| E   Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_l2_lp_stage2_p_nh_ce_ptr_t {
//   fields {
//     enc_type    : 4;
//     padding     : 3;
//     ce_ptr      : 18;
//     stage2_p_nh : 12;
//     type        : native_l2_lp_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_STAGE2_P_NH_CE_PTR;
	value.action = NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_mask          = 15;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.offset_in_bits         = 37;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.destination_in_nibbles = 19;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.offset_in_bits         = 16;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.size_in_bits           = 18;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.destination_in_nibbles = 7;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|paddi|            L2_DLP(18)             |        DSP(12)        |type(4)| E   AC
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_l2_lp_dsp_l2_dlp_t {
//   fields {
//     enc_type : 4;
//     padding  : 3;
//     l2_dlp   : 18;
//     dsp      : 12;
//     type     : native_l2_lp_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_DSP_L2_DLP;
	value.action = NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_mask          = 11;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.offset_in_bits         = 37;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.destination_in_nibbles = 19;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.offset_in_bits         = 16;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.size_in_bits           = 18;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.destination_in_nibbles = 14;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|pad|            L2_DLP(18)             |        DSPA(13)         |type(4)| E   AC
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_l2_lp_dspa_l2_dlp_t {
//   fields {
//     enc_type : 4;
//     padding  : 2;
//     l2_dlp   : 18;
//     dspa     : 13;
//     type     : native_l2_lp_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_DSPA_L2_DLP;
	value.action = NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_size          = 13;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_mask          = 14;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.offset_in_bits         = 37;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.destination_in_nibbles = 19;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.offset_in_bits         = 17;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.size_in_bits           = 18;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.destination_in_nibbles = 14;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |padding(6) |            CE_PTR(18)             |     Stage2_ECMP(13)     |type(4)|     Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_l2_lp_stage2_ecmp_ce_ptr_t {
//   fields {
//     padding     : 6;
//     ce_ptr      : 18;
//     stage2_ecmp : 13;
//     type        : native_l2_lp_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_STAGE2_ECMP_CE_PTR;
	value.action = NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_size          = 13;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_mask          = 13;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.offset_in_bits         = 17;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.size_in_bits           = 18;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.destination_in_nibbles = 7;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |paddi|            L2_DLP(18)             |            BVN(16)            |type(4)| E   AC
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_l2_lp_bvn_l2_dlp_t {
//   fields {
//     padding : 3;
//     l2_dlp  : 18;
//     bvn     : 16;
//     type    : native_l2_lp_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_L2_LP_ENTRY_TYPE_NATIVE_L2_LP_BVN_L2_DLP;
	value.action = NPL_NATIVE_L2_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_size          = 16;
	value.payloads.native_l2_lp_type_decoding_table_result.next_destination_mask          = 30;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_add_type         = 1;
	value.payloads.native_l2_lp_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L2_HEADER_TYPE_AC;
	value.payloads.native_l2_lp_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.offset_in_bits         = 20;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.size_in_bits           = 18;
	value.payloads.native_l2_lp_type_decoding_table_result.field_0.destination_in_nibbles = 14;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_l2_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}

// Table Native_LB:
//
//   48              40              32              24              16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                   padding(25)                   |            Destination(20)            |type(4)|     AC|VxLAN
//   |                   padding(25)                   |            Destination(20)            |type(4)|     GRE|Mpls_Head|Basic_Router; destination: CE_PTR|DPE|Stage2_ECMP
//   |enc_typ|               padding(21)               |            Destination(20)            |type(4)| E   Basic_Router
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


la_status
configure_native_lb_type_decoding_table(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_native_lb_type_decoding_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_native_lb_type_decoding_table_t> table(device->m_tables.native_lb_type_decoding_table);


	npl_native_lb_type_decoding_table_key_t key;
	npl_native_lb_type_decoding_table_value_t value;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   padding(25)                   |            Destination(20)            |type(4)|     AC|VxLAN
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_lb_destination_t {
//   fields {
//     padding     : 25;
//     destination : 20; // may be: l2_dlp
//     type        : native_lb_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_LB_ENTRY_TYPE_NATIVE_LB_DESTINATION;
	value.action = NPL_NATIVE_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_lb_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.native_lb_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.native_lb_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.native_lb_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_lb_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.native_lb_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.field_0.offset_in_bits         = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.field_0.size_in_bits           = 0;
	value.payloads.native_lb_type_decoding_table_result.field_0.destination_in_nibbles = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.native_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   padding(25)                   |            Destination(20)            |type(4)|     GRE|Mpls_Head|Basic_Router; destination: CE_PTR|DPE|Stage2_ECMP
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_lb_destination1_t {
//   fields {
//     padding     : 25;
//     destination : 20; // may be: ce_ptr or dpe or stage2_ecmp
//     type        : native_lb_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_LB_ENTRY_TYPE_NATIVE_LB_DESTINATION1;
	value.action = NPL_NATIVE_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_lb_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.native_lb_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.native_lb_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.native_lb_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_lb_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.native_lb_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.field_0.offset_in_bits         = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.field_0.size_in_bits           = 0;
	value.payloads.native_lb_type_decoding_table_result.field_0.destination_in_nibbles = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.native_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|               padding(21)               |            Destination(20)            |type(4)| E   Basic_Router
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type native_lb_destination2_t {
//   fields {
//     enc_type    : 4;
//     padding     : 21;
//     destination : 20; // may be: stage3_nh
//     type        : native_lb_entry_type_e;
//   }
// }


	key.type = NPL_NATIVE_LB_ENTRY_TYPE_NATIVE_LB_DESTINATION2;
	value.action = NPL_NATIVE_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.native_lb_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.native_lb_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.native_lb_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.native_lb_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.native_lb_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.native_lb_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.field_0.offset_in_bits         = 45;
	value.payloads.native_lb_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.native_lb_type_decoding_table_result.field_0.destination_in_nibbles = 19;
	value.payloads.native_lb_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.native_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.native_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.native_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}

// Table Path_LB:
//
//           24              16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          ASBR(15)           |  Stage3_NH_11b(11)  |type(| E   Mpls_Head
//   |          ASBR(15)           | Stage2_P_NH_11b(11) |type(| E   Mpls_Head
//   |     TE_Tunnel14b(14)      |     Stage3_NH(12)     |type(| E   Mpls_Head
//   |     TE_Tunnel14b(14)      |     Stage3_NH(12)     |type(| E   Mpls_Head
//   |     TE_Tunnel14b(14)      |    Stage2_P_NH(12)    |type(| E   Mpls_Head
//   |     TE_Tunnel14b(14)      |    Stage2_P_NH(12)    |type(| E   Mpls_Head
//   |enc_typ|pad|            Destination(20)            |type(| E   Mpls_Head|Basic_Router; destination: Stage2_P_NH|Stage3_NH
//   |padding(6) |            Destination(20)            |type(|     GRE|VxLAN
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


la_status
configure_path_lb_type_decoding_table(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_path_lb_type_decoding_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_path_lb_type_decoding_table_t> table(device->m_tables.path_lb_type_decoding_table);


	npl_path_lb_type_decoding_table_key_t key;
	npl_path_lb_type_decoding_table_value_t value;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          ASBR(15)           |  Stage3_NH_11b(11)  |type(| E   Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type path_lb_stage3_nh_11b_asbr_t {
//   fields {
//     asbr          : 15;
//     stage3_nh_11b : 11;
//     type          : path_lb_entry_type_e;
//   }
// }


	key.type = NPL_PATH_LB_ENTRY_TYPE_PATH_LB_STAGE3_NH_11B_ASBR;
	value.action = NPL_PATH_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.path_lb_type_decoding_table_result.next_destination_size          = 11;
	value.payloads.path_lb_type_decoding_table_result.next_destination_mask          = 24;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_add_type         = 1;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE;
	value.payloads.path_lb_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.path_lb_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_0.offset_in_bits         = 14;
	value.payloads.path_lb_type_decoding_table_result.field_0.size_in_bits           = 15;
	value.payloads.path_lb_type_decoding_table_result.field_0.destination_in_nibbles = 3;
	value.payloads.path_lb_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.path_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.path_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          ASBR(15)           | Stage2_P_NH_11b(11) |type(| E   Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type path_lb_stage2_p_nh_11b_asbr_t {
//   fields {
//     asbr            : 15;
//     stage2_p_nh_11b : 11;
//     type            : path_lb_entry_type_e;
//   }
// }


	key.type = NPL_PATH_LB_ENTRY_TYPE_PATH_LB_STAGE2_P_NH_11B_ASBR;
	value.action = NPL_PATH_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.path_lb_type_decoding_table_result.next_destination_size          = 11;
	value.payloads.path_lb_type_decoding_table_result.next_destination_mask          = 15;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_add_type         = 1;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE;
	value.payloads.path_lb_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.path_lb_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_0.offset_in_bits         = 14;
	value.payloads.path_lb_type_decoding_table_result.field_0.size_in_bits           = 15;
	value.payloads.path_lb_type_decoding_table_result.field_0.destination_in_nibbles = 3;
	value.payloads.path_lb_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.path_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.path_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     TE_Tunnel14b(14)      |     Stage3_NH(12)     |type(| E   Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type path_lb_stage3_nh_te_tunnel14b_t {
//   fields {
//     te_tunnel14b : 14;
//     stage3_nh    : 12;
//     type         : path_lb_entry_type_e;
//   }
// }


	key.type = NPL_PATH_LB_ENTRY_TYPE_PATH_LB_STAGE3_NH_TE_TUNNEL14B;
	value.action = NPL_PATH_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.path_lb_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.path_lb_type_decoding_table_result.next_destination_mask          = 24;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_add_type         = 1;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID;
	value.payloads.path_lb_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.path_lb_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_0.offset_in_bits         = 15;
	value.payloads.path_lb_type_decoding_table_result.field_0.size_in_bits           = 14;
	value.payloads.path_lb_type_decoding_table_result.field_0.destination_in_nibbles = 3;
	value.payloads.path_lb_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.path_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.path_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     TE_Tunnel14b(14)      |     Stage3_NH(12)     |type(| E   Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type path_lb_stage3_nh_te_tunnel14b1_t {
//   fields {
//     te_tunnel14b : 14;
//     stage3_nh    : 12;
//     type         : path_lb_entry_type_e;
//   }
// }


	key.type = NPL_PATH_LB_ENTRY_TYPE_PATH_LB_STAGE3_NH_TE_TUNNEL14B1;
	value.action = NPL_PATH_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.path_lb_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.path_lb_type_decoding_table_result.next_destination_mask          = 24;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_add_type         = 1;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE;
	value.payloads.path_lb_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.path_lb_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_0.offset_in_bits         = 15;
	value.payloads.path_lb_type_decoding_table_result.field_0.size_in_bits           = 14;
	value.payloads.path_lb_type_decoding_table_result.field_0.destination_in_nibbles = 3;
	value.payloads.path_lb_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.path_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.path_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     TE_Tunnel14b(14)      |    Stage2_P_NH(12)    |type(| E   Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type path_lb_stage2_p_nh_te_tunnel14b_t {
//   fields {
//     te_tunnel14b : 14;
//     stage2_p_nh  : 12;
//     type         : path_lb_entry_type_e;
//   }
// }


	key.type = NPL_PATH_LB_ENTRY_TYPE_PATH_LB_STAGE2_P_NH_TE_TUNNEL14B;
	value.action = NPL_PATH_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.path_lb_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.path_lb_type_decoding_table_result.next_destination_mask          = 15;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_add_type         = 1;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID;
	value.payloads.path_lb_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.path_lb_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_0.offset_in_bits         = 15;
	value.payloads.path_lb_type_decoding_table_result.field_0.size_in_bits           = 14;
	value.payloads.path_lb_type_decoding_table_result.field_0.destination_in_nibbles = 3;
	value.payloads.path_lb_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.path_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.path_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     TE_Tunnel14b(14)      |    Stage2_P_NH(12)    |type(| E   Mpls_Head
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type path_lb_stage2_p_nh_te_tunnel14b1_t {
//   fields {
//     te_tunnel14b : 14;
//     stage2_p_nh  : 12;
//     type         : path_lb_entry_type_e;
//   }
// }


	key.type = NPL_PATH_LB_ENTRY_TYPE_PATH_LB_STAGE2_P_NH_TE_TUNNEL14B1;
	value.action = NPL_PATH_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.path_lb_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.path_lb_type_decoding_table_result.next_destination_mask          = 15;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_add_type         = 1;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE;
	value.payloads.path_lb_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.path_lb_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_0.offset_in_bits         = 15;
	value.payloads.path_lb_type_decoding_table_result.field_0.size_in_bits           = 14;
	value.payloads.path_lb_type_decoding_table_result.field_0.destination_in_nibbles = 3;
	value.payloads.path_lb_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.path_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.path_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |enc_typ|pad|            Destination(20)            |type(| E   Mpls_Head|Basic_Router; destination: Stage2_P_NH|Stage3_NH
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type path_lb_destination_t {
//   fields {
//     enc_type    : 4;
//     padding     : 2;
//     destination : 20; // may be: stage2_p_nh or stage3_nh
//     type        : path_lb_entry_type_e;
//   }
// }


	key.type = NPL_PATH_LB_ENTRY_TYPE_PATH_LB_DESTINATION;
	value.action = NPL_PATH_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.path_lb_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.path_lb_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.path_lb_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_0.offset_in_bits         = 25;
	value.payloads.path_lb_type_decoding_table_result.field_0.size_in_bits           = 4;
	value.payloads.path_lb_type_decoding_table_result.field_0.destination_in_nibbles = 19;
	value.payloads.path_lb_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.path_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.path_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |padding(6) |            Destination(20)            |type(|     GRE|VxLAN
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type path_lb_destination1_t {
//   fields {
//     padding     : 6;
//     destination : 20; // may be: stage3_nh
//     type        : path_lb_entry_type_e;
//   }
// }


	key.type = NPL_PATH_LB_ENTRY_TYPE_PATH_LB_DESTINATION1;
	value.action = NPL_PATH_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.path_lb_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.path_lb_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.path_lb_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.path_lb_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_0.offset_in_bits         = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_0.size_in_bits           = 0;
	value.payloads.path_lb_type_decoding_table_result.field_0.destination_in_nibbles = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.path_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.path_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.path_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}

// Table Path_LP:
//
//         16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |padding(5|     Stage3_NH(12)     |type(|   i Mpls_Head|Mpls_Midpoint
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                 32              24              16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |p|       TE_Tunnel16b(16)        |            Destination(20)            |type(| E i Mpls_Midpoint
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     32              24              16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |             padding(19)             |     Stage3_NH(12)     |type(|     Mpls_Head|Mpls_Midpoint
//   |paddi|       TE_Tunnel16b(16)        |     Stage3_NH(12)     |type(| E   Mpls_Midpoint
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


la_status
configure_path_lp_type_decoding_table(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_path_lp_type_decoding_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_path_lp_type_decoding_table_t> table(device->m_tables.path_lp_type_decoding_table);


	npl_path_lp_type_decoding_table_key_t key;
	npl_path_lp_type_decoding_table_value_t value;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |padding(5|     Stage3_NH(12)     |type(|   i Mpls_Head|Mpls_Midpoint
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type path_lp_stage3_nh_t {
//   fields {
//     padding   : 5;
//     stage3_nh : 12;
//     type      : path_lp_entry_type_e;
//   }
// }


	key.type = NPL_PATH_LP_ENTRY_TYPE_PATH_LP_STAGE3_NH;
	value.action = NPL_PATH_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.path_lp_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.path_lp_type_decoding_table_result.next_destination_mask          = 24;
	value.payloads.path_lp_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.path_lp_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.path_lp_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.path_lp_type_decoding_table_result.index_size_in_nibbles          = 3;
	value.payloads.path_lp_type_decoding_table_result.index_destination_in_nibbles   = 12;
	value.payloads.path_lp_type_decoding_table_result.field_0.offset_in_bits         = 0; // don't care
	value.payloads.path_lp_type_decoding_table_result.field_0.size_in_bits           = 0;
	value.payloads.path_lp_type_decoding_table_result.field_0.destination_in_nibbles = 0; // don't care
	value.payloads.path_lp_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.path_lp_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.path_lp_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.path_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.path_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |p|       TE_Tunnel16b(16)        |            Destination(20)            |type(| E i Mpls_Midpoint
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type path_lp_destination_te_tunnel16b_t {
//   fields {
//     padding      : 1;
//     te_tunnel16b : 16;
//     destination  : 20; // may be: stage3_nh
//     type         : path_lp_entry_type_e;
//   }
// }


	key.type = NPL_PATH_LP_ENTRY_TYPE_PATH_LP_DESTINATION_TE_TUNNEL16B;
	value.action = NPL_PATH_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.path_lp_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.path_lp_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.path_lp_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.path_lp_type_decoding_table_result.encapsulation_add_type         = 1;
	value.payloads.path_lp_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_ILM_TUNNEL;
	value.payloads.path_lp_type_decoding_table_result.index_size_in_nibbles          = 3;
	value.payloads.path_lp_type_decoding_table_result.index_destination_in_nibbles   = 12;
	value.payloads.path_lp_type_decoding_table_result.field_0.offset_in_bits         = 23;
	value.payloads.path_lp_type_decoding_table_result.field_0.size_in_bits           = 16;
	value.payloads.path_lp_type_decoding_table_result.field_0.destination_in_nibbles = 3;
	value.payloads.path_lp_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.path_lp_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.path_lp_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.path_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.path_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             padding(19)             |     Stage3_NH(12)     |type(|     Mpls_Head|Mpls_Midpoint
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type path_lp_stage3_nh1_t {
//   fields {
//     padding   : 19;
//     stage3_nh : 12;
//     type      : path_lp_entry_type_e;
//   }
// }


	key.type = NPL_PATH_LP_ENTRY_TYPE_PATH_LP_STAGE3_NH1;
	value.action = NPL_PATH_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.path_lp_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.path_lp_type_decoding_table_result.next_destination_mask          = 24;
	value.payloads.path_lp_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.path_lp_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.path_lp_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.path_lp_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.path_lp_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.path_lp_type_decoding_table_result.field_0.offset_in_bits         = 3;
	value.payloads.path_lp_type_decoding_table_result.field_0.size_in_bits           = 12;
	value.payloads.path_lp_type_decoding_table_result.field_0.destination_in_nibbles = 12;
	value.payloads.path_lp_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.path_lp_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.path_lp_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.path_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.path_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |paddi|       TE_Tunnel16b(16)        |     Stage3_NH(12)     |type(| E   Mpls_Midpoint
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type path_lp_stage3_nh_te_tunnel16b_t {
//   fields {
//     padding      : 3;
//     te_tunnel16b : 16;
//     stage3_nh    : 12;
//     type         : path_lp_entry_type_e;
//   }
// }


	key.type = NPL_PATH_LP_ENTRY_TYPE_PATH_LP_STAGE3_NH_TE_TUNNEL16B;
	value.action = NPL_PATH_LP_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.path_lp_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.path_lp_type_decoding_table_result.next_destination_mask          = 24;
	value.payloads.path_lp_type_decoding_table_result.encapsulation_start            = 1;
	value.payloads.path_lp_type_decoding_table_result.encapsulation_add_type         = 1;
	value.payloads.path_lp_type_decoding_table_result.encapsulation_type             = NPL_NPU_ENCAP_L3_HEADER_TYPE_ILM_TUNNEL;
	value.payloads.path_lp_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.path_lp_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.path_lp_type_decoding_table_result.field_0.offset_in_bits         = 3;
	value.payloads.path_lp_type_decoding_table_result.field_0.size_in_bits           = 12;
	value.payloads.path_lp_type_decoding_table_result.field_0.destination_in_nibbles = 12;
	value.payloads.path_lp_type_decoding_table_result.field_1.offset_in_bits         = 15;
	value.payloads.path_lp_type_decoding_table_result.field_1.size_in_bits           = 16;
	value.payloads.path_lp_type_decoding_table_result.field_1.destination_in_nibbles = 3;
	value.payloads.path_lp_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.path_lp_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}

// Table Port_DSPA:
//
//                8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |pad|        DSP(12)        |t|     DSPA
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


la_status
configure_port_dspa_type_decoding_table(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_port_dspa_type_decoding_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_port_dspa_type_decoding_table_t> table(device->m_tables.port_dspa_type_decoding_table);


	npl_port_dspa_type_decoding_table_key_t key;
	npl_port_dspa_type_decoding_table_value_t value;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |pad|        DSP(12)        |t|     DSPA
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type port_dspa_dsp_t {
//   fields {
//     padding : 2;
//     dsp     : 12;
//     type    : port_dspa_entry_type_e;
//   }
// }


	key.type = NPL_PORT_DSPA_ENTRY_TYPE_PORT_DSPA_DSP;
	value.action = NPL_PORT_DSPA_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.port_dspa_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.port_dspa_type_decoding_table_result.next_destination_mask          = 11;
	value.payloads.port_dspa_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.port_dspa_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.port_dspa_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.port_dspa_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.port_dspa_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.port_dspa_type_decoding_table_result.field_0.offset_in_bits         = 0; // don't care
	value.payloads.port_dspa_type_decoding_table_result.field_0.size_in_bits           = 0;
	value.payloads.port_dspa_type_decoding_table_result.field_0.destination_in_nibbles = 0; // don't care
	value.payloads.port_dspa_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.port_dspa_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.port_dspa_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.port_dspa_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.port_dspa_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}

// Table Port_NPP_Protection:
//
//                 32              24              16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  padding(8)   |  Tunnel1_DLP(10)  |            Destination(20)            |typ|     NPP_Prot
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


la_status
configure_port_npp_protection_type_decoding_table(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_port_npp_protection_type_decoding_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_port_npp_protection_type_decoding_table_t> table(device->m_tables.port_npp_protection_type_decoding_table);


	npl_port_npp_protection_type_decoding_table_key_t key;
	npl_port_npp_protection_type_decoding_table_value_t value;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  padding(8)   |  Tunnel1_DLP(10)  |            Destination(20)            |typ|     NPP_Prot
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type port_npp_protection_destination_tunnel1_dlp_t {
//   fields {
//     padding     : 8;
//     tunnel1_dlp : 10;
//     destination : 20; // may be: dsp
//     type        : port_npp_protection_entry_type_e;
//   }
// }


	key.type = NPL_PORT_NPP_PROTECTION_ENTRY_TYPE_PORT_NPP_PROTECTION_DESTINATION_TUNNEL1_DLP;
	value.action = NPL_PORT_NPP_PROTECTION_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.port_npp_protection_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.port_npp_protection_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.port_npp_protection_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.port_npp_protection_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.port_npp_protection_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.port_npp_protection_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.port_npp_protection_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.port_npp_protection_type_decoding_table_result.field_0.offset_in_bits         = 22;
	value.payloads.port_npp_protection_type_decoding_table_result.field_0.size_in_bits           = 10;
	value.payloads.port_npp_protection_type_decoding_table_result.field_0.destination_in_nibbles = 0;
	value.payloads.port_npp_protection_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.port_npp_protection_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.port_npp_protection_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.port_npp_protection_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.port_npp_protection_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}

// Table Stage3_LB:
//
//                 32              24              16               8               0
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |dlp_attr(6)|          L3_DLP(16)           |            BVN(16)            |typ|   i Basic_Router|Mpls_Head|Mpls_Midpoint
//   |padding|dlp_attr(6)|          L3_DLP(16)           |        DSP(12)        |typ|   i Basic_Router|GRE|Mpls_Head|Mpls_Midpoint|VxLAN
//   |paddi|dlp_attr(6)|          L3_DLP(16)           |        DSPA(13)         |typ|   i Basic_Router|GRE|Mpls_Head|Mpls_Midpoint|VxLAN
//   |pad|          L3_DLP(16)           |            Destination(20)            |typ|     Basic_Router|GRE|Mpls_Head|Mpls_Midpoint|VxLAN
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


la_status
configure_stage3_lb_type_decoding_table(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_stage3_lb_type_decoding_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_stage3_lb_type_decoding_table_t> table(device->m_tables.stage3_lb_type_decoding_table);


	npl_stage3_lb_type_decoding_table_key_t key;
	npl_stage3_lb_type_decoding_table_value_t value;

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |dlp_attr(6)|          L3_DLP(16)           |            BVN(16)            |typ|   i Basic_Router|Mpls_Head|Mpls_Midpoint
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage3_lb_bvn_l3_dlp_dlp_attr_t {
//   fields {
//     dlp_attr : 6;
//     l3_dlp   : 16;
//     bvn      : 16;
//     type     : stage3_lb_entry_type_e;
//   }
// }


	key.type = NPL_STAGE3_LB_ENTRY_TYPE_STAGE3_LB_BVN_L3_DLP_DLP_ATTR;
	value.action = NPL_STAGE3_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.stage3_lb_type_decoding_table_result.next_destination_size          = 16;
	value.payloads.stage3_lb_type_decoding_table_result.next_destination_mask          = 30;
	value.payloads.stage3_lb_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.stage3_lb_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.stage3_lb_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.stage3_lb_type_decoding_table_result.index_size_in_nibbles          = 3;
	value.payloads.stage3_lb_type_decoding_table_result.index_destination_in_nibbles   = 12;
	value.payloads.stage3_lb_type_decoding_table_result.field_0.offset_in_bits         = 18;
	value.payloads.stage3_lb_type_decoding_table_result.field_0.size_in_bits           = 16;
	value.payloads.stage3_lb_type_decoding_table_result.field_0.destination_in_nibbles = 15;
	value.payloads.stage3_lb_type_decoding_table_result.field_1.offset_in_bits         = 34;
	value.payloads.stage3_lb_type_decoding_table_result.field_1.size_in_bits           = 6;
	value.payloads.stage3_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0;
	value.payloads.stage3_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.stage3_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |padding|dlp_attr(6)|          L3_DLP(16)           |        DSP(12)        |typ|   i Basic_Router|GRE|Mpls_Head|Mpls_Midpoint|VxLAN
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage3_lb_dsp_l3_dlp_dlp_attr_t {
//   fields {
//     padding  : 4;
//     dlp_attr : 6;
//     l3_dlp   : 16;
//     dsp      : 12;
//     type     : stage3_lb_entry_type_e;
//   }
// }


	key.type = NPL_STAGE3_LB_ENTRY_TYPE_STAGE3_LB_DSP_L3_DLP_DLP_ATTR;
	value.action = NPL_STAGE3_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.stage3_lb_type_decoding_table_result.next_destination_size          = 12;
	value.payloads.stage3_lb_type_decoding_table_result.next_destination_mask          = 11;
	value.payloads.stage3_lb_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.stage3_lb_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.stage3_lb_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.stage3_lb_type_decoding_table_result.index_size_in_nibbles          = 3;
	value.payloads.stage3_lb_type_decoding_table_result.index_destination_in_nibbles   = 12;
	value.payloads.stage3_lb_type_decoding_table_result.field_0.offset_in_bits         = 14;
	value.payloads.stage3_lb_type_decoding_table_result.field_0.size_in_bits           = 16;
	value.payloads.stage3_lb_type_decoding_table_result.field_0.destination_in_nibbles = 15;
	value.payloads.stage3_lb_type_decoding_table_result.field_1.offset_in_bits         = 30;
	value.payloads.stage3_lb_type_decoding_table_result.field_1.size_in_bits           = 6;
	value.payloads.stage3_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0;
	value.payloads.stage3_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.stage3_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |paddi|dlp_attr(6)|          L3_DLP(16)           |        DSPA(13)         |typ|   i Basic_Router|GRE|Mpls_Head|Mpls_Midpoint|VxLAN
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage3_lb_dspa_l3_dlp_dlp_attr_t {
//   fields {
//     padding  : 3;
//     dlp_attr : 6;
//     l3_dlp   : 16;
//     dspa     : 13;
//     type     : stage3_lb_entry_type_e;
//   }
// }


	key.type = NPL_STAGE3_LB_ENTRY_TYPE_STAGE3_LB_DSPA_L3_DLP_DLP_ATTR;
	value.action = NPL_STAGE3_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.stage3_lb_type_decoding_table_result.next_destination_size          = 13;
	value.payloads.stage3_lb_type_decoding_table_result.next_destination_mask          = 14;
	value.payloads.stage3_lb_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.stage3_lb_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.stage3_lb_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.stage3_lb_type_decoding_table_result.index_size_in_nibbles          = 3;
	value.payloads.stage3_lb_type_decoding_table_result.index_destination_in_nibbles   = 12;
	value.payloads.stage3_lb_type_decoding_table_result.field_0.offset_in_bits         = 15;
	value.payloads.stage3_lb_type_decoding_table_result.field_0.size_in_bits           = 16;
	value.payloads.stage3_lb_type_decoding_table_result.field_0.destination_in_nibbles = 15;
	value.payloads.stage3_lb_type_decoding_table_result.field_1.offset_in_bits         = 31;
	value.payloads.stage3_lb_type_decoding_table_result.field_1.size_in_bits           = 6;
	value.payloads.stage3_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0;
	value.payloads.stage3_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.stage3_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |pad|          L3_DLP(16)           |            Destination(20)            |typ|     Basic_Router|GRE|Mpls_Head|Mpls_Midpoint|VxLAN
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// header_type stage3_lb_destination_l3_dlp_t {
//   fields {
//     padding     : 2;
//     l3_dlp      : 16;
//     destination : 20; // may be: glean
//     type        : stage3_lb_entry_type_e;
//   }
// }


	key.type = NPL_STAGE3_LB_ENTRY_TYPE_STAGE3_LB_DESTINATION_L3_DLP;
	value.action = NPL_STAGE3_LB_TYPE_DECODING_TABLE_ACTION_WRITE;
	value.payloads.stage3_lb_type_decoding_table_result.next_destination_size          = 20;
	value.payloads.stage3_lb_type_decoding_table_result.next_destination_mask          = 0;
	value.payloads.stage3_lb_type_decoding_table_result.encapsulation_start            = 0;
	value.payloads.stage3_lb_type_decoding_table_result.encapsulation_add_type         = 0;
	value.payloads.stage3_lb_type_decoding_table_result.encapsulation_type             = 0; // don't care
	value.payloads.stage3_lb_type_decoding_table_result.index_size_in_nibbles          = 0;
	value.payloads.stage3_lb_type_decoding_table_result.index_destination_in_nibbles   = 0; // don't care
	value.payloads.stage3_lb_type_decoding_table_result.field_0.offset_in_bits         = 22;
	value.payloads.stage3_lb_type_decoding_table_result.field_0.size_in_bits           = 16;
	value.payloads.stage3_lb_type_decoding_table_result.field_0.destination_in_nibbles = 15;
	value.payloads.stage3_lb_type_decoding_table_result.field_1.offset_in_bits         = 0; // don't care
	value.payloads.stage3_lb_type_decoding_table_result.field_1.size_in_bits           = 0;
	value.payloads.stage3_lb_type_decoding_table_result.field_1.destination_in_nibbles = 0; // don't care
	value.payloads.stage3_lb_type_decoding_table_result.lb_key_overwrite               = 0;
	value.payloads.stage3_lb_type_decoding_table_result.lb_key_offset                  = 0; // don't care

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


    status = configure_native_fec_type_decoding_table(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    status = configure_native_frr_type_decoding_table(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    status = configure_native_l2_lp_type_decoding_table(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    status = configure_native_lb_type_decoding_table(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    status = configure_path_lb_type_decoding_table(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    status = configure_path_lp_type_decoding_table(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    status = configure_port_dspa_type_decoding_table(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    status = configure_port_npp_protection_type_decoding_table(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    status = configure_stage3_lb_type_decoding_table(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }


    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
