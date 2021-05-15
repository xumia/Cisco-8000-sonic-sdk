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

#ifndef __RA_ENUMS_H__
#define __RA_ENUMS_H__

namespace silicon_one
{

/// @brief Physical memories types.
enum resource_type_e { RESOURCE_TYPE_SRAM, RESOURCE_TYPE_TCAM, RESOURCE_TYPE_REGISTER, RESOURCE_TYPE_NUM };

/// @brief Database resource allocation.
enum allocation_e {
    ALLOCATION_SLICE,      ///< Per-slice resource.
    ALLOCATION_SLICE_PAIR, ///< Per-slice-pair resource.
    ALLOCATION_DEVICE,     ///< Global resource.
};

/// @brief Table location
enum location_e { LOCATION_EXTERNAL, LOCATION_INTERNAL };

/// @brief Translator type.
enum translation_type_e {
    TRANSLATION_TYPE_NONE,

    TRANSLATION_TYPE_EXACT,         ///< Translation to direct or exact match resources.
    TRANSLATION_TYPE_TERNARY,       ///< Translation to ternary resources (tcam+sram).
    TRANSLATION_TYPE_REG_TCAM,      ///< Translation to register tcam.
    TRANSLATION_TYPE_REG_SRAM,      ///< Translation to register sram.
    TRANSLATION_TYPE_MULTIVAL_REG,  ///< Translation to register sram, containing multiple values per line.
    TRANSLATION_TYPE_CEM_ARC,       ///< Translation to CEM ARC interface.
    TRANSLATION_TYPE_CTM,           ///< Translation to Central Tcam mapping.
    TRANSLATION_TYPE_LPM,           ///< Translation to LPM interface.
    TRANSLATION_TYPE_MULTIVAL_SRAM, ///< Translation to SRAM containing multiple values per line.
};

/// @brief List of all known database engines, internal and external.
/// The list should match NPL definitions.
enum database_block_e {
    DATABASE_BLOCK_UNKNOWN,

    DATABASE_BLOCK_INTERNAL_RXPP_FWD,
    DATABASE_BLOCK_INTERNAL_RXPP_TERM,
    DATABASE_BLOCK_INTERNAL_TXPP,
    DATABASE_BLOCK_INTERNAL_NPUH,
    DATABASE_BLOCK_LAST_INTERNAL = DATABASE_BLOCK_INTERNAL_NPUH,

    DATABASE_BLOCK_EXTERNAL_CDB_TOP,
    DATABASE_BLOCK_EXTERNAL_CDB_CORE,
    DATABASE_BLOCK_EXTERNAL_CDB_CORE_REDUCED,
    DATABASE_BLOCK_EXTERNAL_IDB_TOP,
    DATABASE_BLOCK_EXTERNAL_IDB_RES,
    DATABASE_BLOCK_EXTERNAL_SDB_MAC,
    DATABASE_BLOCK_EXTERNAL_SDB_ENC,
    DATABASE_BLOCK_EXTERNAL_RXPP_FWD,
    DATABASE_BLOCK_EXTERNAL_RXPP_TERM,
    DATABASE_BLOCK_EXTERNAL_RXPP_TERM_FI_ENG,
    DATABASE_BLOCK_EXTERNAL_FI_STAGE,
    DATABASE_BLOCK_EXTERNAL_TXPP,
    DATABASE_BLOCK_EXTERNAL_CLUSTER,
    DATABASE_BLOCK_EXTERNAL_NPUH_HOST,
    DATABASE_BLOCK_EXTERNAL_NPUH_FI_ENG,
    DATABASE_BLOCK_EXTERNAL_PDVOQ_SLICE,
    DATABASE_BLOCK_EXTERNAL_HMC_CGM,
    DATABASE_BLOCK_EXTERNAL_RX_PDR_2_SLICES,
    DATABASE_BLOCK_EXTERNAL_PDOQ,
    DATABASE_BLOCK_EXTERNAL_FILB_SLICE,
    DATABASE_BLOCK_EXTERNAL_RX_PDR_SHARED_DB,
    DATABASE_BLOCK_EXTERNAL_COUNTERS,
    DATABASE_BLOCK_EXTERNAL_COUNTERS_BANK_GROUP,
    DATABASE_BLOCK_EXTERNAL_RX_COUNTERS,
    DATABASE_BLOCK_EXTERNAL_TXPDR,
    DATABASE_BLOCK_EXTERNAL_RX_METER,
    DATABASE_BLOCK_EXTERNAL_RX_METER_BLOCK,
    DATABASE_BLOCK_EXTERNAL_REASSEMBLY,
    DATABASE_BLOCK_EXTERNAL_FRM,

    DATABASE_BLOCK_LAST = DATABASE_BLOCK_EXTERNAL_FRM,

    DATABASE_BLOCK_NUM
}; // enum engines_e

/// @brief List of HW databases, that share resources between logical tables.
enum database_e {
    DATABASE_NONE,

    // SRAM
    DATABASE_MAC_SERVICE_LP_SRAM,
    DATABASE_NATIVE_LP_SRAM,
    DATABASE_PATH_LP_SRAM,
    DATABASE_FI_MACRO_CONFIG_SRAM,
    DATABASE_LIGHT_FI_NPU_BASE_SRAM,
    DATABASE_LIGHT_FI_NPU_ENCAP_SRAM,
    DATABASE_LIGHT_FI_FABRIC_SRAM,
    DATABASE_LIGHT_FI_TM_SRAM,
    DATABASE_LIGHT_FI_STAGES_CFG_SRAM,
    DATABASE_MC_FE_LINKS_BMP_SRAM,

    // EM databases
    DATABASE_EGRESS_SMALL_EM,
    DATABASE_MAC_SERVICE_MAPPING_0_EM, // Service Mapping DB - port 0
    DATABASE_MAC_SERVICE_MAPPING_1_EM, // Service Mapping DB - port 1
    DATABASE_TUNNEL_0_EM,              // Tunnel DB - port 0
    DATABASE_TUNNEL_1_EM,              // Tunnel DB - port 1
    DATABASE_EGRESS_LARGE_EM,
    DATABASE_EGRESS_L3_DLP0_EM,
    DATABASE_MAC_TERMINATION_EM,
    DATABASE_RESOLUTION_NATIVE_LB_EM,
    DATABASE_RESOLUTION_PATH_LB_EM,
    DATABASE_RESOLUTION_PORT_DSPA_EM,
    DATABASE_RESOLUTION_PORT_NPP_LB_EM,
    DATABASE_TM_MC_EM,
    DATABASE_NPUH_ETH_MP_EM,

    // ARC
    DATABASE_CENTRAL_EM,

    // TCAM
    DATABASE_CENTRAL_TCAM,
    DATABASE_FI_CORE_TCAM,
    DATABASE_LIGHT_FI_NW0_TCAM,
    DATABASE_LIGHT_FI_NW1_TCAM,
    DATABASE_LIGHT_FI_NW2_TCAM,
    DATABASE_LIGHT_FI_NW3_TCAM,

    DATABASE_LAST = DATABASE_CENTRAL_TCAM,
    DATABASE_NUM
}; // enum database_e

} // namespace silicon_one

#endif // __RA_ENUMS_H__
