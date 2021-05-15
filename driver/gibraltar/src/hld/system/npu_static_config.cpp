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

#include "npu_static_config.h"

#include "lld/gibraltar_mem_structs.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "lld/pacific_mem_structs.h"
#include "lld/pacific_reg_structs.h"

#include "nplapi/npl_constants.h"
#include "nplapi/npl_enums.h"

#include "hw_tables/cem.h"
#include "hw_tables/em_common.h"

#include "api/types/la_system_types.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "hld_utils.h"
#include "la_device_impl.h"
#include "tm/tm_utils.h"

#include <random>

namespace silicon_one
{

///////////////////////////////////
/// ARC microcode
///////////////////////////////////

static const char DEFAULT_CEM_ARC_MICROCODE_ICCM_FILE[] = "res/firmware_cem_iccm.bin";
static const char DEFAULT_CEM_ARC_MICROCODE_DCCM_FILE[] = "res/firmware_cem_dccm.bin";

static const char CEM_ARC_MICROCODE_ICCM_ENVVAR[] = "CEM_ARC_MICROCODE_ICCM";
static const char CEM_ARC_MICROCODE_DCCM_ENVVAR[] = "CEM_ARC_MICROCODE_DCCM";

namespace rxpp_os_rate_limiter
{

union key {
    enum {
        SIZE = 1,
        NUM_KEYS = 16,
    };

    size_t flat;

    struct fields {
        size_t os_experienced_in_frag_rd : 1; // this is the lsb of the key
        size_t os_experienced_in_output_fifo : 1;
        size_t long_os_experienced_in_frag_rd : 1;
        size_t long_os_experienced_in_output_fifo : 1;
    } fields;

    size_t reg_num : 4;
};

} // namespace rxpp_rate_limiter

namespace txpp_misc
{

union macro_id_selection_fields_offset_key {
    enum {
        SIZE = 1,
        NUM_KEYS = 256,
    };

    size_t flat;

    struct fields {
        size_t first_enc_type : 4; // this is the lsb of the key
        size_t fwd_type : 4;
    } fields;

    size_t reg_num : 8;
};

union source_slice_to_light_fi_first_macro_key {
    enum {
        SIZE = 1,
        NUM_KEYS = 16,
    };

    size_t flat;

    struct fields {
        size_t second_packed_packet : 1; // this is the lsb of the key
        size_t source_slice_id : 3;
    } fields;

    size_t reg_num : 4;
};

union cud_encap_data_source_select_key {
    enum {
        SIZE = 1,
        NUM_KEYS = 4,
    };

    size_t flat;

    struct fields {
        size_t use_mapped_cud : 1; // this is the lsb of the key
        size_t use_narrow_cud : 1;
    } fields;

    size_t reg_num : 2;
};

union pre_edit_cmd_map_key {
    enum {
        SIZE = 1,
        NUM_KEYS = 32,
    };

    size_t flat;

    struct fields {
        size_t npu_header_type_en : 1; // this is the lsb of the key
        size_t mirror_en : 1;
        size_t orig_cmd_fwd_offset_recalc_en : 1;
        size_t orig_cmd_op_code : 2;
    } fields;

    size_t reg_num : 5;
};

enum pre_edit_op_code_e {
    PRE_EDIT_OP_CODE_NOP = 0,
    PRE_EDIT_OP_CODE_DELETE = 1,
    PRE_EDIT_OP_CODE_COPY = 2,
};

} // namespace txpp_misc

namespace cdb_cache_attributes
{

enum cdb_cache_ldb_profile_e {
    EM_LPM_LDB_NARROW = 0,
    EM_LPM_LDB_WIDE = 1,
    EM_ONLY_LDB_NARROW = 2,
    EM_ONLY_LDB_WIDE = 3,
};

enum cdb_cache_full_length_or_prefix_length_e {
    PREFIX_LENGTH_MATCH = 0,
    FULL_LENGTH = 1,
};

union cache_insert_ctrl_key {
    enum {
        SIZE = 1,
        NUM_KEYS = 256,
    };

    size_t flat;

    struct fields {
        size_t lpm_only_reply_full_length_or_em_lpm_reply_const_0 : 1; // this is the lsb of the key
        size_t lpm_only_reply_leaf_or_em_lpm_reply_hit : 1;
        size_t tcam_cache_is_full : 1;
        size_t em_cache_is_full : 1;
        size_t lpm_only_reply_const_1_or_em_lpm_reply_const_0 : 1;
        cdb_cache_ldb_profile_e cache_ldb_profile : 2;
        size_t is_from_hbm : 1;
    } fields;

    size_t reg_num : 8;
};

} // namespace cdb_cache_attributes

namespace macdb_sm_mapping
{
// EM config
union em_key {
    enum {
        SIZE = 1,
        NUM_KEYS = 32,
    };

    size_t flat;

    struct fields {
        size_t access_self : 1;
        size_t two_lookups_enable : 1;
        size_t access_lp : 1;
        size_t access_relay : 1;
        size_t access_mymac : 1;
    } fields;

    size_t reg_num : 5;
};

union em_result {
    enum {
        SIZE = 1,
        SIZE_IN_BITS = 4,
    };

    size_t flat;

    struct fields {
        size_t access_self : 1;
        size_t access_mymac : 1;
        size_t access_relay : 1;
        size_t access_lp : 1;
    } fields;
};

// TCAM config
union tcam_key {
    enum {
        SIZE = 1,
        NUM_KEYS = 8,
    };

    size_t flat;

    struct fields {
        size_t access_lp : 1;
        size_t access_relay : 1;
        size_t access_mymac : 1;
    } fields;

    size_t reg_num : 3;
};

union tcam_result {
    enum {
        SIZE = 1,
        SIZE_IN_BITS = 3,
    };

    size_t flat;

    struct fields {
        size_t access_mymac : 1;
        size_t access_lp : 1;
        size_t access_relay : 1;
    } fields;
};

} // namespace macdb_sm_mapping

namespace sna
{

union pp_local_id_table_data {
    enum {
        SIZE = 1,
        SIZE_IN_BITS = 9,
    };

    size_t flat;

    struct {
        size_t ifg : 1;
        size_t prio : 3;
        size_t pif : 5;
    } fields;
};

union map_tm_header_type_data {
    enum {
        SIZE = 1,
        SIZE_IN_BITS = 7,
    };

    size_t flat;

    struct {
        size_t outgoing_if_mode : 1;
        size_t offset_to_dest_slice : 6;
    } fields;
};

struct map_tm_header_type_entry {
    npl_tm_header_type_e header;
    map_tm_header_type_data data;
};

enum class sna_mode_e {
    SINGLE_CONNECTION = 0,
    SINGLE_CONN_EXCEPT_INJECT_AND_RECYCLE = 1,
    CONN_PER_PORT = 2,
    CONN_PER_PORT_AND_PRIORITY = 3,
};

} // namespace sna

/// @brief Structure to create vlan editing control command in for ingress_vlan_editing_control memory.
/// It was decided not to create NPL table, since the data is static and never used in NPL
namespace vlan_editing_control
{

// Copied from AV
enum ve_cmd {
    VE_CMD_NOP = 0,
    VE_CMD_REMARK = 1, // only pcp-dei update (same for both)
    VE_CMD_POP1 = 2,
    VE_CMD_POP2 = 5,
    VE_CMD_PUSH1 = 4,
    VE_CMD_PUSH2 = 11,
    VE_CMD_TRANSLATE_1_1 = 3,
    VE_CMD_TRANSLATE_2_1 = 6,
    VE_CMD_TRANSLATE_1_2 = 10,
    VE_CMD_TRANSLATE_2_2 = 9,
};

enum ve_selector_opcode {
    SELECT_NEW_FROM_IVE_COMMAND_TAG_1 = 0,
    SELECT_NEW_FROM_IVE_COMMAND_TAG_2 = 1,
    SELECT_FROM_TAG_1 = 2,
    SELECT_FROM_TAG_2 = 3,
    SELECT_NEW_PCP_DEI = 0,
    IGNORED_FIELD = 0
};

enum {
    DATA_SIZE = 2,
    DATA_SIZE_IN_BITS = 15,
    NUM_VE_CMDS = 12,
};

struct data {
    size_t vid1_select : 2;
    size_t vid2_select : 2;
    size_t pcp_dei1_select : 2;
    size_t pcp_dei2_select : 2;
    size_t tpid1_select : 2;
    size_t tpid2_select : 2;
    size_t delta : 3;
    size_t padding : 49;

    operator bit_vector()
    {
        return bit_vector(DATA_SIZE, (uint8_t*)this, DATA_SIZE_IN_BITS);
    }
};

union eve_drop_mapping_key {
    enum {
        SIZE = 1,
        NUM_KEYS = 64,
    };

    size_t flat;

    struct fields {
        size_t vlan2_exist : 1; // this is the lsb of the key
        size_t vlan1_exist : 1;
        size_t vlan_edit_cmd : 4;
    } fields;

    size_t reg_num : 6;
};

union eve_drop_mapping_val {
    enum {
        SIZE = 1,
        SIZE_IN_BITS = 2,
    };

    size_t flat;

    struct {
        uint64_t drop : 1; // Using 64b type so that shift operator will work for 64b bitmap
        uint64_t interrupt : 1;
    } fields;
};

} // namespace vlan_editing_control

/// @brief Leaba specific defines for NPU headers.
///
/// The below defines are generated in microcode and provided
/// to design (verilog). Current decision is to copy the values without generating matching include files for SDK.
namespace npu_headers_leaba_defines
{
enum {
    NPU_BASE_LEABA_DONT_OVERWRITE_WIDTH = 64,
    NPU_BASE_HEADER_LEABA_WIDTH = 28,
    NPU_HEADER_CONT_T_ANONYMOUS_UNION_ENCAP_OR_TERM_WIDTH = 108, // TODO: will need to change if using encap-data of 120
    NPU_HEADER_CONT_T_ANONYMOUS_UNION_ENCAP_OR_TERM_IVE_WIDTH = 28,
    NPU_HEADER_OFFSET_IN_BITS_TO_ENCAP_DATA = NPU_BASE_LEABA_DONT_OVERWRITE_WIDTH + NPU_BASE_HEADER_LEABA_WIDTH,
    NPU_HEADER_OFFSET_IN_BITS_TO_IVE_CMD
    = NPU_HEADER_OFFSET_IN_BITS_TO_ENCAP_DATA
      + (NPU_HEADER_CONT_T_ANONYMOUS_UNION_ENCAP_OR_TERM_WIDTH - NPU_HEADER_CONT_T_ANONYMOUS_UNION_ENCAP_OR_TERM_IVE_WIDTH),

    NPU_HEADER_OFFSET_IN_BITS_TO_ENC_TYPE = NPU_HEADER_OFFSET_IN_BITS_TO_ENCAP_DATA,
    NPU_HEADER_OFFSET_IN_BITS_TO_CUD_ID = NPU_HEADER_OFFSET_IN_BITS_TO_ENCAP_DATA + 28, // INGRESS_MC_ENCAP_HEADER_MC_WIDTH

    NPU_BASE_LEABA_DONT_OVERWRITE_BASE_TYPE_WIDTH = 4,
    NPU_BASE_LEABA_DONT_OVERWRITE_RECEIVE_TIME_WIDTH = 32,
    NPU_BASE_LEABA_DONT_OVERWRITE_METER_COLOR_WIDTH = 2,
    NPU_BASE_LEABA_DONT_OVERWRITE_L2_FLOOD_MC_PRUNING_WIDTH = 1,
    INGRESS_QOS_REMARK_ENCAP_QOS_TAG_WIDTH = 7,
    INGRESS_QOS_REMARK_QOS_GROUP_WIDTH = 7,
    NPU_HEADER_OFFSET_IN_BITS_TO_IVE_PCP_DEI = NPU_BASE_LEABA_DONT_OVERWRITE_BASE_TYPE_WIDTH
                                               + NPU_BASE_LEABA_DONT_OVERWRITE_RECEIVE_TIME_WIDTH
                                               + NPU_BASE_LEABA_DONT_OVERWRITE_METER_COLOR_WIDTH
                                               + NPU_BASE_LEABA_DONT_OVERWRITE_L2_FLOOD_MC_PRUNING_WIDTH
                                               + INGRESS_QOS_REMARK_ENCAP_QOS_TAG_WIDTH
                                               + INGRESS_QOS_REMARK_QOS_GROUP_WIDTH
                                               + 3,

    ENCAP_HEADER_OFFSET_IN_BITS_TO_IP_ENCAP_ENC_TYPE_2_NH = 40,   // Type(4)+l3-dlp(16)+nh-or-host-ptr(20)
    ENCAP_HEADER_OFFSET_IN_BITS_TO_IP_ENCAP_ENC_TYPE_2_HOST = 68, // Type(4)+l3-dlp(16)+host(48)
};
} // namespace npu_headers_leaba_defines

////////////////////////
/// npu_static_config
////////////////////////
npu_static_config::npu_static_config(const la_device_impl_wptr& la_device)
    : m_device(la_device),
      m_ll_device(la_device->get_ll_device_sptr()),
      m_tree(la_device->get_ll_device()->get_gibraltar_tree_scptr())
{
    for (la_slice_id_t slice_id = 0; slice_id < ASIC_MAX_SLICES_PER_DEVICE_NUM; slice_id++) {
        slice_config cfg;
        cfg.slice_mode = SLICE_WORK_MODE_DISABLED;
        m_slice_config.push_back(cfg);
    }

    for (la_slice_id_t slice_id : la_device->get_used_slices()) {
        slice_config& cfg = m_slice_config[slice_id];
        if (la_device->is_network_slice(slice_id)) {
            cfg.slice_mode = SLICE_WORK_MODE_NETWORK;
        } else { // assume its fabric
            cfg.slice_mode = SLICE_WORK_MODE_FABRIC;
        }
        cfg.sna_slice_mode = SNA_SLICE_MODE_DISABLE_CENTRAL_SNA;
    }
}

la_status

npu_static_config::configure_hw()
{
    log_debug(RA, "npu_static_config::configure_hw()");
    la_status status = LA_STATUS_SUCCESS;

    init_lists();

    for (la_slice_id_t slice_id : m_device->get_used_slices()) {
        configure_rxpp(slice_id);
        configure_txpp(slice_id);
        configure_npe_timeout_threshold(slice_id);
        for (la_ifg_id_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ++ifg_id) {
            configure_ifgb_packet_rate_shaper(slice_id, ifg_id);
        }
    }

    configure_cdb();
    configure_npuh();

    status = config_dbc_logical_db_mapping();
    return_on_error(status);

    status = write_lists();
    return_on_error(status);

    log_debug(RA, "npu_static_config::configure_hw() done");
    return LA_STATUS_SUCCESS;
}
//
la_status
npu_static_config::configure_dynamic_memories()
{
    log_debug(RA, "npu_static_config::configure_hw_post_soft_reset()");
    la_status status = LA_STATUS_SUCCESS;

    init_lists();

    for (size_t slice : m_device->get_used_slices()) {
        lld_memory_sptr tod_port_max_delay = m_tree->slice[slice]->npu->txpp->top->tod_port_max_delay_and_cong;
        m_mem_vals.push_back({tod_port_max_delay, bit_vector(0, tod_port_max_delay->get_desc()->width_bits)});

        // Set one-to-one delay measurement tc mapping.
        lld_memory_sptr delay_measurement_cmd = m_tree->slice[slice]->npu->txpp->top->delay_measurement_cmd;
        for (size_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            for (size_t pif = 0; pif < MAX_NUM_PIF_PER_IFG + NUM_INTERNAL_IFCS_PER_IFG; pif++) {
                for (size_t tc = 0; tc < NUM_OQ_PER_PIF; tc++) {
                    size_t line = ifg * NUM_OQ_PER_IFG + pif * NUM_OQ_PER_PIF + tc;
                    m_mem_line_vals.push_back({{delay_measurement_cmd, line}, tc});
                }
            }
        }
    }
    status = write_lists();
    return_on_error(status);

    log_debug(RA, "npu_static_config::configure_hw_post_soft_reset() done");
    return LA_STATUS_SUCCESS;
}

void
npu_static_config::configure_rxpp(la_slice_id_t slice_id)
{
    configure_rxpp_npe(slice_id);
    configure_rxpp_nppd_construction(slice_id);
    configure_rxpp_rate_limiter_and_packet_shaper_tune(slice_id);
    configure_rxpp_hw_fi(slice_id);
    configure_rxpp_cdb_cache(slice_id);
    configure_rxpp_fec_table_access(slice_id);
    configure_rxpp_res_lb_header_type_mapping(slice_id);
    configure_rxpp_lb(slice_id);
    configure_rxpp_sna(slice_id);
    configure_rxpp_spare_reg(slice_id);
    configure_rxpp_fec_mapping(slice_id);
    configure_flow_cache(slice_id);
}

void
npu_static_config::configure_rxpp_npe(la_slice_id_t slice_id)
{
    // term
    gibraltar::npe_ready_in_out_cfg_register term_ready_in_out;
    term_ready_in_out.fields.next_ready_to_valid_latency = 4;          // hard coded
    term_ready_in_out.fields.prev_slot_ready_to_slot_used_latency = 2; // hard coded

    for (auto& npe : m_tree->slice[slice_id]->npu->rxpp_term->npe) {
        m_reg_vals.push_back({npe->ready_in_out_cfg, term_ready_in_out});
    }
    // All the following configuration should arrive from microcode if change is needed
    //    for (const gibraltar_tree_slice_npu_rxpp_term_npe& npe : m_tree->slice[slice_id]->npu->rxpp_term->npe) {
    //        gibraltar::npe_general_cfg_register general_cfg;
    //        la_status status = m_ll_device->read_register(npe->general_cfg, general_cfg);
    //        if (status != LA_STATUS_SUCCESS) {
    //            return;
    //        }
    //
    //        general_cfg.fields.enable_counters_header_index_update = 0; // WA for a bug in HW. This will prevent automatic
    //                                                                    // counters_header_index update upon counter update in NPL
    //                                                                    and
    //                                                                    // will allow manual configuration needed for the WA
    //        general_cfg.fields.enable_snoop_priority_over_redirect = 0;
    //        m_reg_vals.push_back({npe->general_cfg, general_cfg});
    //    }

    // fwd
    gibraltar::npe_ready_in_out_cfg_register fwd_ready_in_out;
    fwd_ready_in_out.fields.next_ready_to_valid_latency = 14;         // hard coded
    fwd_ready_in_out.fields.prev_slot_ready_to_slot_used_latency = 5; // hard coded

    for (auto& npe : m_tree->slice[slice_id]->npu->rxpp_fwd->npe) {
        m_reg_vals.push_back({npe->ready_in_out_cfg, fwd_ready_in_out});
    }

    // All the following configuration should arrive from microcode if change is needed
    //    for (const gibraltar_tree_slice_npu_rxpp_fwd_npe& npe : m_tree->slice[slice_id]->npu->rxpp_fwd->npe) {
    //        gibraltar::npe_general_cfg_register general_cfg;
    //        la_status status = m_ll_device->read_register(npe->general_cfg, general_cfg);
    //        if (status != LA_STATUS_SUCCESS) {
    //            return;
    //        }
    //
    //        general_cfg.fields.enable_counters_header_index_update = 0; // WA for a bug in HW. This will prevent automatic
    //                                                                    // counters_header_index update upon counter update in NPL
    //                                                                    and
    //                                                                    // will allow manual configuration needed for the WA
    //        general_cfg.fields.enable_snoop_priority_over_redirect = 0;
    //        m_reg_vals.push_back({npe->general_cfg, general_cfg});
    //    }
}

void
npu_static_config::configure_rxpp_nppd_construction(la_slice_id_t slice_id)
{
    // TODO: Need to model table in NPL and remove from static configuration

    const slice_config& slice_cfg = m_slice_config[slice_id];

    // === NPU-Header size ===
    // Header width value is written in 8bytes resolution.
    size_t npu_header_width = (slice_cfg.slice_mode == SLICE_WORK_MODE_NETWORK) ? NPU_HEADER_WIDTH_IN_BYTES / 8 : 0;

    // term
    gibraltar::fi_stage_cfg_tx_header_width_register term_header_width;
    term_header_width.fields.cfg_tx_header_width_r = npu_header_width;
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_term->fi_stage->cfg_tx_header_width, term_header_width});

    // fwd
    gibraltar::rxpp_fwd_cfg_tx_header_width_register fwd_header_width;
    fwd_header_width.fields.cfg_tx_header_width_r = npu_header_width;
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->top->cfg_tx_header_width, fwd_header_width});

    // === PD construction ===
    // Assuming nppd structure at this point is as follows
    // {Packet-header-msbs (768b), extended-user-data (256b), user-data(832b)}
    // extended-user-data(256b) = {some-fields-used-by-rxpp (16b), soft-npu-header(64b), more-data(176b)}
    gibraltar::rxpp_fwd_pd_construction_congurations_register pd_construction;
    pd_construction.fields.soft_sms_header_offset
        = 2 * ((NPPD_USER_DATA_WIDTH_IN_BYTES + NPPD_EXTENDED_USER_DATA_WIDTH_IN_BYTES) - NPU_HEADER_HARD_WIDTH_IN_BYTES - 2);
    // Value is written in nibble resolution.
    pd_construction.fields.hard_sms_header_size = 2 * NPU_HEADER_HARD_WIDTH_IN_BYTES;
    // Do not mask error bit
    pd_construction.fields.mask_npe_err = 1;
    // Do not force fwd offset command to zero (i.e. fwd-offset-cmd should be assigned by NPL)
    pd_construction.fields.force_fwd_offset_cmd_to_zero = (slice_cfg.slice_mode == SLICE_WORK_MODE_NETWORK) ? 0 : 1;
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->top->pd_construction_congurations, pd_construction});
}

void
npu_static_config::configure_rxpp_rate_limiter_and_packet_shaper_tune(la_slice_id_t slice_id)
{
    // Configuring rxpp rate limiter.
    // key = {long_os_experienced_in_output_fifo, long_os_experienced_in_frag_rd, os_experienced_in_output_fifo,
    // os_experienced_in_frag_rd} //msb->lsb
    // NOTE: when long-os is set, the also the short will be set. i.e. keys of 4'b1000/4'b0100/4'b1100 are N/A
    lld_memory_sptr mem = m_tree->slice[slice_id]->npu->rxpp_term->top->input_packet_rate_limiter_configuration_set;
    for (size_t i = 0; i < rxpp_os_rate_limiter::key::NUM_KEYS; ++i) {
        gibraltar::rxpp_term_input_packet_rate_limiter_configuration_set_memory mem_entry;
        rxpp_os_rate_limiter::key key = {0};
        key.flat = i;

        if (key.fields.long_os_experienced_in_output_fifo) { // //Set to 1% PPS
            mem_entry.fields.enable_ifg0_rate_limit = 1;
            mem_entry.fields.enable_ifg1_rate_limit = 1;
            mem_entry.fields.rate_limiter_number_of_packets = 1;
            mem_entry.fields.rate_limiter_window_size = 100;
        } else if (key.fields.os_experienced_in_output_fifo) { // Set to 25% PPS
            mem_entry.fields.enable_ifg0_rate_limit = 1;
            mem_entry.fields.enable_ifg1_rate_limit = 1;
            mem_entry.fields.rate_limiter_number_of_packets = 1;
            mem_entry.fields.rate_limiter_window_size = 4;
        } else if (key.fields.os_experienced_in_frag_rd) { // Set to 33% PPS
            mem_entry.fields.enable_ifg0_rate_limit = 1;
            mem_entry.fields.enable_ifg1_rate_limit = 1;
            mem_entry.fields.rate_limiter_number_of_packets = 1;
            mem_entry.fields.rate_limiter_window_size = 3;
        } else { // no oversubscription -> set shaper to 95%
            // We disable ifg rate limit due to a HW bug in the shaper operation.
            // WA is that 95% PPS shaper will be done by IFGB packet-shaper instead of RxPP packet-shaper.
            mem_entry.fields.enable_ifg0_rate_limit = 0;
            mem_entry.fields.enable_ifg1_rate_limit = 0;
            mem_entry.fields.rate_limiter_number_of_packets = 95;
            mem_entry.fields.rate_limiter_window_size = 100;
        }

        m_mem_line_vals.push_back({{mem, i}, mem_entry});
    }
}

void
npu_static_config::configure_rxpp_hw_fi(la_slice_id_t slice_id)
{
    // TODO: Need to model table in NPL and remove from static configuration
    // NW Slices: configure from microcode/static tables
    // Fabric slices: Bypass

    // The Following configuration will bypass the hw_fi (packet parsing will be performed by cfg-fi only)
    // On init: set all macros to UNDEF - in this case HW-FI is bypassed
    gibraltar::fi_stage_hw_fi_end_of_pipe_last_macro_id_register end_of_pipe_last_macro_id;
    end_of_pipe_last_macro_id.fields.hw_fi_last_macro_id = NPL_FI_MACRO_ID_UNDEF;
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->rxpp_term->fi_stage->hw_fi_end_of_pipe_last_macro_id, end_of_pipe_last_macro_id});

    gibraltar::fi_stage_hw_fi_levels_macro_ids_register levels_macro_ids;
    levels_macro_ids.fields.hw_fi_eth_macro_id = NPL_FI_MACRO_ID_UNDEF;
    levels_macro_ids.fields.hw_fi_eth_last_macro_id = NPL_FI_MACRO_ID_UNDEF;
    levels_macro_ids.fields.hw_fi_vlan0_macro_id = NPL_FI_MACRO_ID_UNDEF;
    levels_macro_ids.fields.hw_fi_vlan0_last_macro_id = NPL_FI_MACRO_ID_UNDEF;
    levels_macro_ids.fields.hw_fi_vlan1_macro_id = NPL_FI_MACRO_ID_UNDEF;
    levels_macro_ids.fields.hw_fi_vlan1_last_macro_id = NPL_FI_MACRO_ID_UNDEF;
    levels_macro_ids.fields.hw_fi_vlan2_macro_id = NPL_FI_MACRO_ID_UNDEF;
    levels_macro_ids.fields.hw_fi_vlan2_last_macro_id = NPL_FI_MACRO_ID_UNDEF;
    levels_macro_ids.fields.hw_fi_ip_macro_id = NPL_FI_MACRO_ID_UNDEF;
    levels_macro_ids.fields.hw_fi_ip_last_macro_id = NPL_FI_MACRO_ID_UNDEF;
    levels_macro_ids.fields.hw_fi_udp_macro_id = NPL_FI_MACRO_ID_UNDEF;
    levels_macro_ids.fields.hw_fi_udp_last_macro_id = NPL_FI_MACRO_ID_UNDEF;
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_term->fi_stage->hw_fi_levels_macro_ids, levels_macro_ids});

    // The following is only to check CAM write
    lld_memory_sptr vlan1_core_cam = m_tree->slice[slice_id]->npu->rxpp_term->fi_stage->hw_fi_vlan1_core_ethertype_mapping_cam;
    gibraltar::fi_stage_hw_fi_vlan1_core_ethertype_mapping_cam_memory val;
    val.fields.hw_fi_vlan1_core_ethertype_mapping_cam_valid = 1;
    val.fields.hw_fi_vlan1_core_ethertype_mapping_cam_key = 0x8100;
    val.fields.hw_fi_vlan1_core_ethertype_mapping_cam_payload = (0 << 12 | NPL_FI_MACRO_ID_VLAN_1 << 5 | NPL_PROTOCOL_TYPE_VLAN_0);
    val.fields.hw_ecc = 0;
    m_mem_line_vals.push_back({{vlan1_core_cam, 3}, val});
}

void
npu_static_config::configure_rxpp_cdb_cache(la_slice_id_t slice_id)
{
    // === Hash seed ===
    const lld_register_desc_t* splitter_desc
        = m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->splitter_cache_hash_cfg_register->get_desc();
    // rc5 is generated twice longer than the provided key
    la_uint64_t splitter_key_width = splitter_desc->width_in_bits / 2;
    bit_vector splitter_hash_val = em::generate_pseudo_rc5(splitter_key_width, slice_id);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->splitter_cache_hash_cfg_register, splitter_hash_val});

    const lld_register_desc_t* lpm_desc
        = m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->lpm_cache_hash_cfg_register->get_desc();
    // rc5 is generated twice longer than the provided key
    la_uint64_t lpm_key_width = lpm_desc->width_in_bits / 2;
    bit_vector lpm_hash_val = em::generate_pseudo_rc5(lpm_key_width, slice_id);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->lpm_cache_hash_cfg_register, lpm_hash_val});

    // === Logical databases mapping ===
    // Old method - pacific like
    for (size_t i = 0; i < 32; ++i) {
        // Set key size according to lsb only [pacific like] (0->narrow, 1->wide)
        bit_vector cem_ldb_lsbs(i, 5);
        gibraltar::cdb_cache_splitter_cache_ldb_mapping_reg_register val = {.u8 = {0}};
        bit_vector ipv4_lpm_table_key_ldb(NPL_CENTRAL_EM_LDB_IPV4_VRF_DIP, NPL_CENTRAL_EM_LDB_IPV4_VRF_DIP_LEN);
        bit_vector ipv6_lpm_table_key_ldb(NPL_CENTRAL_EM_LDB_IPV6_VRF_DIP, NPL_CENTRAL_EM_LDB_IPV6_VRF_DIP_LEN);

        if (cem_ldb_lsbs.bit(0) == 0) { // Narrow
            val.fields.splitter_cache_ldb_to_key_size_index = 0;
            if (cem_ldb_lsbs.bits(NPL_CENTRAL_EM_LDB_IPV4_VRF_DIP_LEN - 1, 0) == ipv4_lpm_table_key_ldb) {
                val.fields.splitter_cache_ldb_to_cache_profile = cdb_cache_attributes::EM_LPM_LDB_NARROW;
            } else {
                val.fields.splitter_cache_ldb_to_cache_profile = cdb_cache_attributes::EM_ONLY_LDB_NARROW;
            }
        } else { // wide: (cem_ldb_lsbs.bit(0) == 1) //wide
            val.fields.splitter_cache_ldb_to_key_size_index = 1;
            if (cem_ldb_lsbs.bits(NPL_CENTRAL_EM_LDB_IPV6_VRF_DIP_LEN - 1, 0) == ipv6_lpm_table_key_ldb) {
                val.fields.splitter_cache_ldb_to_cache_profile = cdb_cache_attributes::EM_LPM_LDB_WIDE;
            } else {
                val.fields.splitter_cache_ldb_to_cache_profile = cdb_cache_attributes::EM_ONLY_LDB_WIDE;
            }
        }
        m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->splitter_cache_ldb_mapping_reg)[i], val});
    }
    // RPF
    // NOTE: only LPM lookups are relevant here (v4/v6)
    for (size_t i = 0; i < 32; ++i) {
        bit_vector cem_ldb_lsbs(i, 5);
        gibraltar::cdb_cache_lpm_cache_ldb_mapping_reg_register val = {.u8 = {0}};

        if (cem_ldb_lsbs.bit(0) == 0) { // Narrow
            val.fields.lpm_cache_ldb_to_key_size_index = 0;
            val.fields.lpm_cache_ldb_to_cache_profile = cdb_cache_attributes::EM_LPM_LDB_NARROW;
        } else { // wide: (cem_ldb_lsbs.bit(0) == 1) //wide
            val.fields.lpm_cache_ldb_to_key_size_index = 1;
            val.fields.lpm_cache_ldb_to_cache_profile = cdb_cache_attributes::EM_LPM_LDB_WIDE;
        }
        m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->lpm_cache_ldb_mapping_reg)[i], val});
    }

    // TODO: Use the below code (or similar), as part of the RA, instead of the above 'Logical databases mapping'
    //    microcode_parser::translator_desc_vec_t desc_vec = parser->get_translator_descriptors(_Trait::get_table_name());
    //    for (size_t i = 0; i < 32; ++i) {
    //        gibraltar::cdb_cache_splitter_cache_ldb_mapping_reg_register splitter_val = {.u8 = {0}};
    //        gibraltar::cdb_cache_lpm_cache_ldb_mapping_reg_register      rpf_val      = {.u8 = {0}};
    //
    //        bit_vector cem_ldb_lsbs(i, 5);
    //
    //
    //        // Set narrow/wide key width - according to CEM databases
    //        for (auto& desc : desc_vec) {
    //            if (desc.database_id != DATABASE_CENTRAL_EM) {
    //                continue;
    //            } else if (cem_ldb_lsbs.bits(desc.logical_table_id_width-1,0) == desc.logical_table_id) {
    //                if (desc.key_width > 46) { //wide for cdb cache
    //                    splitter_val.fields.splitter_cache_ldb_to_key_size_index = 1;
    //                    rpf_val.fields.lpm_cache_ldb_to_key_size_index = 1;
    //                    if (desc.npl_table_name == 'ipv6_vrf_dip_em_table'){
    //                        splitter_val.fields.splitter_cache_ldb_to_key_size_index = cdb_cache_attributes::EM_LPM_LDB_WIDE;
    //                        rpf_val.fields.lpm_cache_ldb_to_key_size_index = cdb_cache_attributes::EM_LPM_LDB_WIDE;
    //                    } else {
    //                        splitter_val.fields.splitter_cache_ldb_to_key_size_index = cdb_cache_attributes::EM_ONLY_LDB_WIDE;
    //                        rpf_val.fields.lpm_cache_ldb_to_key_size_index = cdb_cache_attributes::EM_ONLY_LDB_WIDE;
    //                    }
    //                } else { //narrow: key width is less or equal 46 bits
    //                    splitter_val.fields.splitter_cache_ldb_to_key_size_index = 0;
    //                    rpf_val.fields.lpm_cache_ldb_to_key_size_index = 0;
    //                    if (desc.npl_table_name == 'ipv4_vrf_dip_em_table'){
    //                        splitter_val.fields.splitter_cache_ldb_to_key_size_index = cdb_cache_attributes::EM_LPM_LDB_NARROW;
    //                        rpf_val.fields.lpm_cache_ldb_to_key_size_index = cdb_cache_attributes::EM_LPM_LDB_NARROW;
    //                    } else {
    //                        splitter_val.fields.splitter_cache_ldb_to_key_size_index = cdb_cache_attributes::EM_ONLY_LDB_NARROW;
    //                        rpf_val.fields.lpm_cache_ldb_to_key_size_index = cdb_cache_attributes::EM_ONLY_LDB_NARROW;
    //                    }
    //                }
    //                m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->splitter_cache_ldb_mapping_reg[i],
    //                splitter_val});
    //                m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->lpm_cache_ldb_mapping_reg[i],
    //                rpf_val});
    //                break;
    //            }
    //        }
    //    }

    // === Set is-leaf location ===
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->splitter_cache_leaf_indication_location_reg,
                          1}); // 1 because results lsbs are {..., leaf(1b), em-hit(1b)} //msb->lsb
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->lpm_cache_leaf_indication_location_reg,
                          0}); // 0 because results lsbs are {..., leaf(1b)} //msb->lsb

    // === Set is-hbm location ===
    // Assuming that LPM result is {spare, is-from_hbm(1b), is-default(1b), destination(19b)} //msb->lsb

    // Splitter Result after standartization (hbm-denied does not enter the cache - design truncate is)
    //    LPM-Only result = {lpm-result[63:0], padd(3b), is-default(1b), reply-format(2b), is-leaf(1b), em-hit(1b)} //msb->lsb
    //    EM+LPM result host format = {lpm-result[59:20], lpm-result[15:0], host(48b), mapped-dest-from-em(20b), padd(3b),
    //    is-default(1b), reply-format(2b), is-leaf(1b), em-hit(1b)} //msb->lsb
    //    EM+LPM result non-host format = {lpm-result[59:0], l3-dlp(16b),nh-ptr(16b), 12'h0, dest-from-em(20b), padd(3b),
    //    is-default(1b), reply-format(2b), is-leaf(1b), em-hit(1b)} //msb->lsb
    //    NOTE: for EM+LPM result, in case of destination-from-em, the lpm-result might be 'not-used', but the indication about
    //    'is-from-hbm' should be correct.
    //    // Nevertheless, hbm-denied in this case should not be raised. will need to set an indication on the em-payload that this
    //    is 'destination-from-em', and in npl check if this is the case, and if so - do not raise hbm-denied.
    gibraltar::cdb_cache_splitter_cache_from_hbm_location_reg_register splitter_is_from_hbm_location = {.u8 = {0}};
    splitter_is_from_hbm_location.fields.splitter_cache_from_hbm_location_em_and_lpm_reply = 8 + 20 + 48 + 16;
    splitter_is_from_hbm_location.fields.splitter_cache_from_hbm_location_lpm_reply = 8 + 19 + 1;
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->splitter_cache_from_hbm_location_reg, splitter_is_from_hbm_location});

    // RPF Result after standartization (hbm-denied does not enter the cache - design truncate is)
    //    Res = {lpm-result, is-leaf(1b)} //msb->lsb
    gibraltar::cdb_cache_lpm_cache_from_hbm_location_reg_register lpm_cache_from_hbm_location_reg = {.u8 = {0}};
    lpm_cache_from_hbm_location_reg.fields.lpm_cache_from_hbm_location_lpm_reply = 1 + 19 + 1;
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->lpm_cache_from_hbm_location_reg, lpm_cache_from_hbm_location_reg});

    // === Set reply format ===
    gibraltar::cdb_cache_splitter_cache_reply_format_reg_register splitter_cache_reply_format = {.u8 = {0}};
    splitter_cache_reply_format.fields.splitter_cache_format_bits_location = 2;
    splitter_cache_reply_format.fields.splitter_cache_lpm_reply_format = NPL_IP_EM_LPM_RESULT_TYPE_DESTINATION_FROM_LPM;
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->splitter_cache_reply_format_reg, splitter_cache_reply_format});

    // === Set cache insert logic ===
    // NOTE: lpm_only_reply is set (1) when one of the following:
    // 1. this is the rpf cache
    // 2. this is the splitter-cache, and reply-format is NPL_IP_EM_LPM_RESULT_TYPE_DESTINATION_FROM_LPM
    for (size_t i = 0; i < cdb_cache_attributes::cache_insert_ctrl_key::NUM_KEYS; ++i) {
        cdb_cache_attributes::cache_insert_ctrl_key key = {0};
        gibraltar::cdb_cache_splitter_cache_insert_controls_reg_register splitter_val = {{0}}; // default is not to insert cache
        gibraltar::cdb_cache_lpm_cache_insert_controls_reg_register rpf_val = {{0}};           // default is not to insert cache
        key.flat = i;

        // According to the key fields values, selected whether to insert to EM/Tcam cache and full/partial prefix length
        if ((key.fields.cache_ldb_profile == cdb_cache_attributes::EM_ONLY_LDB_WIDE)
            | (key.fields.cache_ldb_profile == cdb_cache_attributes::EM_ONLY_LDB_NARROW)) {
            // In case of EM only lookup, insert only to EM cache
            if (key.fields.lpm_only_reply_leaf_or_em_lpm_reply_hit) {
                splitter_val.fields.splitter_cache_insert_to_cache = !key.fields.em_cache_is_full;
                splitter_val.fields.splitter_cache_insert_to_tcam = 0;
                splitter_val.fields.splitter_cache_insert_length = cdb_cache_attributes::FULL_LENGTH;
            }
        } else { // cache_ldb_profile is EM_LPM_LDB_NARROW or EM_LPM_LDB_WIDE
            if (key.fields.lpm_only_reply_const_1_or_em_lpm_reply_const_0
                == 0) { // got EM reply (Host result, destination from EM..)
                if (key.fields.lpm_only_reply_leaf_or_em_lpm_reply_hit) {
                    if (key.fields.is_from_hbm) { // insert to Tcam with full prefix
                        splitter_val.fields.splitter_cache_insert_to_cache = !key.fields.tcam_cache_is_full;
                        splitter_val.fields.splitter_cache_insert_to_tcam = 1;
                        splitter_val.fields.splitter_cache_insert_length = cdb_cache_attributes::FULL_LENGTH;
                    } else { // insert to EM cache if em-hit and cache is not full
                        splitter_val.fields.splitter_cache_insert_to_cache = !key.fields.em_cache_is_full;
                        splitter_val.fields.splitter_cache_insert_to_tcam = 0;
                        splitter_val.fields.splitter_cache_insert_length = cdb_cache_attributes::FULL_LENGTH;
                    }
                }
            } else {                                                      // LPM only reply
                if (key.fields.lpm_only_reply_leaf_or_em_lpm_reply_hit) { // insert to Tcam cache if leaf and cache is not full (for
                                                                          // both 'from-hbm' or not)
                    splitter_val.fields.splitter_cache_insert_to_cache = !key.fields.tcam_cache_is_full;
                    splitter_val.fields.splitter_cache_insert_to_tcam = 1;
                    splitter_val.fields.splitter_cache_insert_length = cdb_cache_attributes::PREFIX_LENGTH_MATCH;
                    rpf_val.fields.lpm_cache_insert_to_cache = !key.fields.tcam_cache_is_full;
                    rpf_val.fields.lpm_cache_insert_to_tcam = 1;
                    rpf_val.fields.lpm_cache_insert_length = cdb_cache_attributes::PREFIX_LENGTH_MATCH;
                } else {                          // Node -> insert with full prefix to: Tcam is from HBM, EM otherwise
                    if (key.fields.is_from_hbm) { // insert to Tcam with full prefix
                        splitter_val.fields.splitter_cache_insert_to_cache = !key.fields.tcam_cache_is_full;
                        splitter_val.fields.splitter_cache_insert_to_tcam = 1;
                        splitter_val.fields.splitter_cache_insert_length = cdb_cache_attributes::FULL_LENGTH;
                        rpf_val.fields.lpm_cache_insert_to_cache = !key.fields.tcam_cache_is_full;
                        rpf_val.fields.lpm_cache_insert_to_tcam = 1;
                        rpf_val.fields.lpm_cache_insert_length = cdb_cache_attributes::FULL_LENGTH;
                    } else { // not from HBM -> insert to EM with full prefix
                        splitter_val.fields.splitter_cache_insert_to_cache = !key.fields.em_cache_is_full;
                        splitter_val.fields.splitter_cache_insert_to_tcam = 0;
                        splitter_val.fields.splitter_cache_insert_length = cdb_cache_attributes::FULL_LENGTH;
                        rpf_val.fields.lpm_cache_insert_to_cache = !key.fields.em_cache_is_full;
                        rpf_val.fields.lpm_cache_insert_to_tcam = 0;
                        rpf_val.fields.lpm_cache_insert_length = cdb_cache_attributes::FULL_LENGTH;
                    }
                }
                // Override: In case tcam cache is full, insert it to EM with full prefix (for both 'from-hbm' or not)
                if (key.fields.tcam_cache_is_full & !key.fields.em_cache_is_full) {
                    splitter_val.fields.splitter_cache_insert_to_cache = 1;
                    splitter_val.fields.splitter_cache_insert_to_tcam = 0;
                    splitter_val.fields.splitter_cache_insert_length = cdb_cache_attributes::FULL_LENGTH;
                    rpf_val.fields.lpm_cache_insert_to_cache = 1;
                    rpf_val.fields.lpm_cache_insert_to_tcam = 0;
                    rpf_val.fields.lpm_cache_insert_length = cdb_cache_attributes::FULL_LENGTH;
                }
            }
        }

        m_reg_vals.push_back(
            {(*m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->splitter_cache_insert_controls_reg)[key.reg_num], splitter_val});
        m_reg_vals.push_back(
            {(*m_tree->slice[slice_id]->npu->rxpp_fwd->cdb_cache->lpm_cache_insert_controls_reg)[key.reg_num], rpf_val});
    }
}

void
npu_static_config::configure_cdb_fwd_results_mapping_and_extraction()
{
    // TODO: Need to model table in NPL and remove from static configuration

    // ======= EM payload mapping =====
    // if format-result-to-standard is set, and em replied with host (identified by msb==1'd1),
    // EM result's bits [62:60] (which is the payload.dest[14:12] bits)  are mapped to new 6 msbs of the EM destination.
    // destination will be: mapped-value(6b), payload.dest[13:0])

    bit_vector dsp_mask(NPL_DESTINATION_MASK_DSP >> 14, 6);
    bit_vector dsp_mask_class_id((NPL_DESTINATION_MASK_DSP >> 14) | 1, 6);
    bit_vector dspa_mask(NPL_DESTINATION_MASK_DSPA >> 14, 6);
    bit_vector dspa_mask_class_id((NPL_DESTINATION_MASK_DSPA >> 14) | 1, 6);
    bit_vector l2_dlp_mask(NPL_DESTINATION_MASK_L2_DLP >> 14, 6);
    bit_vector l2_dlp_mask_class_id((NPL_DESTINATION_MASK_L2_DLP >> 14) | 1, 6);
    std::vector<bit_vector> db_splitter_lp_to_mask_vals({l2_dlp_mask,
                                                         l2_dlp_mask,
                                                         dsp_mask,
                                                         dspa_mask,
                                                         l2_dlp_mask_class_id,
                                                         l2_dlp_mask_class_id,
                                                         dsp_mask_class_id,
                                                         dspa_mask_class_id});
    for (size_t reg_idx = 0; reg_idx < m_tree->cdb->top->cdsp_em_payload_mapping->size(); ++reg_idx) {
        m_reg_vals.push_back({(*m_tree->cdb->top->cdsp_em_payload_mapping)[reg_idx], db_splitter_lp_to_mask_vals[reg_idx]});
    }

    // ======= Reply format payload mapping =====
    gibraltar::cdb_top_cdsp_reply_format_setting_register cdsp_reply_format_setting = {.u8 = {0}};
    cdsp_reply_format_setting.fields.format_result_to_standart = 1;
    cdsp_reply_format_setting.fields.em_reply_encoding = NPL_IP_EM_LPM_RESULT_TYPE_DESTINATION_FROM_EM;
    cdsp_reply_format_setting.fields.l3_dlp_reply_encoding = NPL_IP_EM_LPM_RESULT_TYPE_DESTINATION_FROM_EM;
    cdsp_reply_format_setting.fields.host_reply_encoding = NPL_IP_EM_LPM_RESULT_TYPE_HOST_MAC_AND_L3_DLP;
    cdsp_reply_format_setting.fields.lpm_reply_encoding = NPL_IP_EM_LPM_RESULT_TYPE_DESTINATION_FROM_LPM;
    m_reg_vals.push_back({m_tree->cdb->top->cdsp_reply_format_setting, cdsp_reply_format_setting});

    // ======= Is-Default extraction =====
    // Assuming that LPM result is {spare,  is-from_hbm(1b), is-default(1b), destination(19b), is-leaf(1b)} //msb->lsb
    gibraltar::cdb_top_cdsp_default_location_reg_register is_default_location = {.u8 = {0}};
    is_default_location.fields.default_location = 20;
    m_reg_vals.push_back({m_tree->cdb->top->cdsp_default_location_reg, is_default_location});
}

void
npu_static_config::configure_rxpp_fec_table_access(la_slice_id_t slice_id)
{
    // TODO: Need to model table in NPL and remove from static configuration

    bool enable_class_id_acls = false;
    m_device->get_bool_property(la_device_property_e::ENABLE_CLASS_ID_ACLS, enable_class_id_acls);
    if (enable_class_id_acls) {
        // Configuring FEC table access
        lld_memory_sptr mem = m_tree->slice[slice_id]->npu->rxpp_fwd->top->fec_table_access_map_reg;
        bit_vector access_fec_table_bv(0, 1);
        for (size_t line = 0; line < mem->get_desc()->entries; ++line) {
            m_mem_line_vals.push_back({{mem, line}, access_fec_table_bv});
        }
    } else {
        // Configuring FEC table access
        lld_memory_sptr mem = m_tree->slice[slice_id]->npu->rxpp_fwd->top->fec_table_access_map_reg;
        for (size_t line = 0; line < mem->get_desc()->entries; ++line) {
            bit_vector access_fec_table_bv((line == NPL_DESTINATION_FEC_PREFIX) ? 1 : 0, 1);
            m_mem_line_vals.push_back({{mem, line}, access_fec_table_bv});
        }
    }
}

void
npu_static_config::configure_rxpp_res_lb_header_type_mapping(la_slice_id_t slice_id)
{
    // TODO: Need to model table in NPL and remove from static configuration

    // res_lp_header_type_mapping
    for (size_t protocol_type = 0; protocol_type < 32; ++protocol_type) {
        gibraltar::rxpp_fwd_res_lb_header_type_mapping_reg_register val = {.u8 = {0}};

        val.fields.res_lb_key_current_header_type_to_profile_mapping = LB_FS_DEFAULT_PROFILE;

        switch (protocol_type) {
        case NPL_PROTOCOL_TYPE_ETHERNET:
            val.fields.res_lb_key_header_type_mapping = 0;
            val.fields.res_lb_key_next_header_type_mapping = 0;
            val.fields.res_lb_key_current_header_type_to_profile_mapping = 3;
            val.fields.res_lb_key_next_header_type_to_profile_mapping = 0;
            break;
        case NPL_PROTOCOL_TYPE_ETHERNET_VLAN:
            val.fields.res_lb_key_header_type_mapping = 0;
            val.fields.res_lb_key_next_header_type_mapping = 0;
            val.fields.res_lb_key_current_header_type_to_profile_mapping = 3;
            val.fields.res_lb_key_next_header_type_to_profile_mapping = 0;
            break;
        case NPL_PROTOCOL_TYPE_IPV4:
            val.fields.res_lb_key_header_type_mapping = 1;
            val.fields.res_lb_key_current_header_type_to_profile_mapping = LB_FS_IPV4_DOUBLE_SIP_DIP_PROFILE;
            break;
        case NPL_PROTOCOL_TYPE_IPV6:
            val.fields.res_lb_key_header_type_mapping = 2;
            val.fields.res_lb_key_current_header_type_to_profile_mapping = LB_FS_IPV6_EXTRA_PARTIAL_DIP_PROFILE;
            break;
        case NPL_PROTOCOL_TYPE_MPLS:
            val.fields.res_lb_key_header_type_mapping = 3;
            break;
        case NPL_PROTOCOL_TYPE_IPV4_L4:
            val.fields.res_lb_key_header_type_mapping = 1;
            val.fields.res_lb_key_current_header_type_to_profile_mapping = LB_FS_IPV4_DOUBLE_SIP_DIP_PROFILE;
            val.fields.res_lb_key_next_header_type_mapping = 4;
            break;
        case NPL_PROTOCOL_TYPE_IPV6_L4:
            val.fields.res_lb_key_header_type_mapping = 2;
            val.fields.res_lb_key_current_header_type_to_profile_mapping = LB_FS_IPV6_EXTRA_PARTIAL_DIP_PROFILE;
            val.fields.res_lb_key_next_header_type_mapping = 4;
            break;
        case NPL_PROTOCOL_TYPE_VLAN_0:
            val.fields.res_lb_key_header_type_mapping = 0;
            val.fields.res_lb_key_next_header_type_mapping = 5;
            val.fields.res_lb_key_current_header_type_to_profile_mapping = 3;
            val.fields.res_lb_key_next_header_type_to_profile_mapping = 1;
            break;
        case NPL_PROTOCOL_TYPE_VLAN_1:
            val.fields.res_lb_key_header_type_mapping = 0;
            val.fields.res_lb_key_next_header_type_mapping = 5;
            val.fields.res_lb_key_current_header_type_to_profile_mapping = 3;
            val.fields.res_lb_key_next_header_type_to_profile_mapping = 1;
            break;
        case NPL_PROTOCOL_TYPE_VLAN_2:
            val.fields.res_lb_key_header_type_mapping = 0;
            val.fields.res_lb_key_next_header_type_mapping = 5;
            val.fields.res_lb_key_current_header_type_to_profile_mapping = 3;
            val.fields.res_lb_key_next_header_type_to_profile_mapping = 1;
            break;
        case NPL_PROTOCOL_TYPE_VLAN_3:
            val.fields.res_lb_key_header_type_mapping = 0;
            val.fields.res_lb_key_next_header_type_mapping = 5;
            val.fields.res_lb_key_current_header_type_to_profile_mapping = 3;
            val.fields.res_lb_key_next_header_type_to_profile_mapping = 1;
            break;
        case NPL_PROTOCOL_TYPE_UDP:
            val.fields.res_lb_key_next_header_type_mapping = 4;
            break;
        case NPL_PROTOCOL_TYPE_TCP:
            val.fields.res_lb_key_next_header_type_mapping = 4;
            break;
        }

        m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->rxpp_fwd->top->res_lb_header_type_mapping_reg)[protocol_type], val});
    }
}

void
npu_static_config::configure_rxpp_lb(la_slice_id_t slice_id)
{
    // FS instruction
    for (size_t next_header_profile = 0; next_header_profile < 4; ++next_header_profile) {
        for (size_t curr_header_profile = 0; curr_header_profile < 4; ++curr_header_profile) {
            // Key is {next-header-profile, current-header-profile}.
            // Temp setting here all types to 'not-used'
            // Usage example: set some profiles to support IPV4_SYMMETRIC_SIP_DIP
            size_t reg_idx = (next_header_profile << 2) | curr_header_profile;

            // All values are 0
            gibraltar::rxpp_fwd_res_lb_profile_fs_insturctions_reg_register val = {.u8 = {0}};

            m_reg_vals.push_back(
                {(*m_tree->slice[slice_id]->npu->rxpp_fwd->top->res_lb_profile_fs_insturctions_reg)[reg_idx], val});
        }
    }

    // Set lb-key size to 16 (this should be the default)
    // NOTE: if need consistency, there is another configuration in the resolution block per LB level + group-id to reduce it to
    // 12b)

    // In AV, for the keys are left 0, while in LBR default value is ffff.

    // Mapping resolution key[5:0] to some controls
    // lsbs structure is: {5b - npl dependent, 1b - extended}
    // e.g. one can use 5 destination MSB as the 5b npl dependent above
    // lb_key_select (per DB):
    // 2'd1: select from memory (rxpp-hashing); 2'd2: select from engine-out.crc; 2'd3: (mem-out)^(npe-out.crc)
    //      LB-key[3] for Native-LB
    //      LB-key[2] for Path-LB
    //      LB-key[1] for NPP-LB
    //      LB-key[0] for DSP-LB
    for (size_t msbs = 0; msbs < 32; ++msbs) {
        for (size_t extended = 0; extended < 2; ++extended) {
            size_t reg_idx = (msbs << 1) | extended;
            gibraltar::rxpp_fwd_resolution_load_balancing_conf_register reg_val;
            // We take only soft_lb_key[0] (1 bit each lb_key, 0 - take it, 1 - don't)
            reg_val.fields.lb_key_mask = 0x0;
            reg_val.fields.lb_key_shift = 0;
            // {lb_key_select[3], lb_key_select[2], lb_key_select[1], lb_key_select[0]}
            // 0xFF -> all select from XOR of the barrel shited vector and hardwired logic (2'd1 for each)
            if (reg_idx == 0) {
                // only one bucket is used -> no soft LB header -> use only hardwired logic
                reg_val.fields.lb_key_select = 0x55;
            } else {
                reg_val.fields.lb_key_select = 0xFF;
            }
            m_reg_vals.push_back(
                {(*m_tree->slice[slice_id]->npu->rxpp_fwd->top->resolution_load_balancing_conf)[reg_idx], reg_val});
        }
    }
}

void
npu_static_config::configure_rxpp_sna(la_slice_id_t slice_id)
{
    const slice_config& slice_cfg = m_slice_config[slice_id];
    lld_memory_sptr pp_local_id_table = m_tree->slice[slice_id]->npu->rxpp_term->sna->pp_local_id_table;

    // On GB, there are different number of pifs per ifg (18/26)
    // Here we can configure according to the max (26)
    for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
        for (size_t prio = 0; prio < NUM_TC_CLASSES; prio++) {
            //            for (size_t pif = 0; pif < tm_utils::IFG_SYSTEM_PORT_SCHEDULERS; pif++) {
            for (size_t pif = 0; pif < 26; pif++) { // TODO: Change to param for GB number of ports per slice/ifg
                sna::pp_local_id_table_data val = {.flat = 0};
                val.fields.ifg = ifg;
                val.fields.pif = pif;
                // Network slices have reorder context per port/prio, fabric slices only per port.
                val.fields.prio = m_device->is_network_slice(slice_id) ? prio : 0;

                size_t addr = ((pif & 0b11111) << 4) | ((prio & 0b111) << 1) | (ifg & 0b1);
                m_mem_line_vals.push_back({{pp_local_id_table, addr}, val.flat});
            }
        }
    }

    // SNA-mode per Fabric-header-type.
    // All headers are mapped to port priority, since we don't support SN-plb.
    const lld_memory_desc_t* crf_fabric_slice_sna_mode_desc
        = m_tree->slice[slice_id]->npu->rxpp_term->sna->map_fabric_header_type_to_crf_fabric_slice_sna_mode->get_desc();
    for (size_t line = 0; line < crf_fabric_slice_sna_mode_desc->entries; ++line) {
        // Port priority option according to LBR
        // 0 - Port priority
        // 2 - SN-PLB
        // 3 - No reorder
        bit_vector sna_mode_pp_opt_bv(0, 2 /*width*/);

        m_mem_line_vals.push_back(
            {{m_tree->slice[slice_id]->npu->rxpp_term->sna->map_fabric_header_type_to_crf_fabric_slice_sna_mode, line},
             sna_mode_pp_opt_bv});
    }

    // Port-priority regs init
    // These are hard coded values: 0 for slices 0-2; 4096 for slices 3-5
    static const size_t per_slice_first_usable_reorder_context_id_in_slice[] = {0, 0, 0, 4096, 4096, 4096};

    gibraltar::slice_sna_per_slice_cfg_for_pp_sna_mode_register per_slice_cfg_for_pp_val;
    per_slice_cfg_for_pp_val.fields.max_valid_psn = 0xfffff; // Not in use
    per_slice_cfg_for_pp_val.fields.use_flow_sig_lsbs_as_reorder_context = 0;
    per_slice_cfg_for_pp_val.fields.first_usable_reorder_context_id_in_slice
        = per_slice_first_usable_reorder_context_id_in_slice[slice_id];

    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_term->sna->per_slice_cfg_for_pp_sna_mode, per_slice_cfg_for_pp_val});

    // Sna slice mode init / SNR Outgoing interface
    // TODO - talk to TM (Shira) to understand what need to be done
    gibraltar::slice_sna_per_slice_cfg_for_sna_modes_selection_register per_slice_cfg_for_sna_modes_val;
    per_slice_cfg_for_sna_modes_val.fields.constant_snr_outgoing_if = slice_id % 3;
    per_slice_cfg_for_sna_modes_val.fields.slice_mode = slice_cfg.sna_slice_mode;
    per_slice_cfg_for_sna_modes_val.fields.tor_slb_slice_snr_outgoing_if_mode = 0; // constant mode

    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->rxpp_term->sna->per_slice_cfg_for_sna_modes_selection, per_slice_cfg_for_sna_modes_val});

    // The following are not used
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_term->sna->per_slice_cfg_for_plb_sna_mode, 0});

    // per fabric-header.dest-slice (3b), holds snr-outgoing-interface
    // Valid only on CRF-Fabric-slices, when mode is 'Extracted'
    for (size_t slice : m_device->get_used_slices()) {
        bit_vector snr_outgoing_if_bv((slice % 3), 2);
        // In AV, this register is set only in FC vseq.

        m_mem_line_vals.push_back(
            {{m_tree->slice[slice_id]->npu->rxpp_term->sna->map_destination_slice_to_snr_outgoing_if, slice /*line*/},
             snr_outgoing_if_bv});
    }

    // TM-Header-attr
    std::vector<sna::map_tm_header_type_entry> map_tm_header_type_vec;

    sna::map_tm_header_type_entry e0 = {(npl_tm_header_type_e)0, {0}};
    e0.header = NPL_TM_HEADER_TYPE_UNICAST_OR_MUU_PLB;
    e0.data.fields.outgoing_if_mode = 1;
    e0.data.fields.offset_to_dest_slice = 20;
    map_tm_header_type_vec.push_back(e0);

    sna::map_tm_header_type_entry e1 = {(npl_tm_header_type_e)0, {0}};
    e1.header = NPL_TM_HEADER_TYPE_UNICAST_FLB;
    e1.data.fields.outgoing_if_mode = 0;
    e1.data.fields.offset_to_dest_slice = 0;
    map_tm_header_type_vec.push_back(e1);

    sna::map_tm_header_type_entry e2 = {(npl_tm_header_type_e)0, {0}};
    e2.header = NPL_TM_HEADER_TYPE_MMM_PLB_OR_FLB;
    e2.data.fields.outgoing_if_mode = 0;
    e2.data.fields.offset_to_dest_slice = 0;
    map_tm_header_type_vec.push_back(e2);

    sna::map_tm_header_type_entry e3 = {(npl_tm_header_type_e)0, {0}};
    e3.header = NPL_TM_HEADER_TYPE_MUM_PLB;
    e3.data.fields.outgoing_if_mode = 1;
    e3.data.fields.offset_to_dest_slice = 20;
    map_tm_header_type_vec.push_back(e3);

    for (const sna::map_tm_header_type_entry& curr : map_tm_header_type_vec) {
        bit_vector curr_bv(curr.data.flat, sna::map_tm_header_type_data::SIZE_IN_BITS);
        m_mem_line_vals.push_back(
            {{m_tree->slice[slice_id]->npu->rxpp_term->sna->map_tm_header_type, curr.header /*line*/}, curr_bv});
    }
}

void
npu_static_config::configure_rxpp_spare_reg(la_slice_id_t slice_id)
{
    la_device_revision_e revision = m_tree->get_revision();
    if (revision == la_device_revision_e::GIBRALTAR_A0) {
        return;
    }

    bit_vector rxpp_fwd_spare_reg_value;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->rxpp_fwd->top->spare_reg, rxpp_fwd_spare_reg_value);

    rxpp_fwd_spare_reg_value.set_bit(65, 1); // Disable RxPP CTCAM utilization improvement ECO.
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->top->spare_reg, rxpp_fwd_spare_reg_value});
}

void
npu_static_config::configure_rxpp_fec_mapping(la_slice_id_t slice_id)
{
    /*
     * FEC mapping:                key = LPM response = {is_fec, is_default, is_hbm_denied)
     *              mapped to      value = {type (2b), is_hbm_denied, is_default}
     *
     * Due to HW bug, the is_hbm_denied indication in the key is actually "is_leaf" instead. (so key is really is {is_fec,
     * is_default, is_leaf})
     *
     * The bug was fixed in Gibraltar A1.
     * The workaround for A0, is to make the key look like: {is_fec, is_hbm_denied, is_leaf}.
     * This can be done because "is_default" can be taken from a configurable location in the LPM response.
     * And then we will map this new key: {is_fec, is_hbm_denied, is_leaf} to {type = 2'b11, is_hbm_denied, is_default = 1'b0}
     */

    bool is_a0 = (m_tree->get_revision() == la_device_revision_e::GIBRALTAR_A0);

    // Step 1: Make mapping key::is_default take its value from LPM response::is_hbm_denied in A0, and from LPM response::is_default
    // in A1
    gibraltar::rxpp_fwd_lpm_fec_mapping_configurations_register fec_mapping_reg;
    la_status status
        = m_ll_device->read_register(m_tree->slice[slice_id]->npu->rxpp_fwd->top->lpm_fec_mapping_configurations, fec_mapping_reg);
    if (status != LA_STATUS_SUCCESS) {
        return;
    }

    if (is_a0) {
        fec_mapping_reg.fields.default_offset_on_lpm_result = 0; // HBM denied location in LPM response
    } else {
        fec_mapping_reg.fields.default_offset_on_lpm_result = 20; // Default location in LPM response
    }

    status
        = m_ll_device->write_register(m_tree->slice[slice_id]->npu->rxpp_fwd->top->lpm_fec_mapping_configurations, fec_mapping_reg);
    if (status != LA_STATUS_SUCCESS) {
        return;
    }
    // Step 2: Write the mapping
    for (size_t mapping_key = 0; mapping_key < 8; mapping_key++) {
        // disassemble key
        size_t is_hbm_denied;
        size_t is_default;
        size_t is_fec;

        if (is_a0) {
            is_hbm_denied = bit_utils::get_bit(mapping_key, 1);
            is_default = 0;
        } else {
            is_hbm_denied = bit_utils::get_bit(mapping_key, 0);
            is_default = bit_utils::get_bit(mapping_key, 1);
        }
        is_fec = bit_utils::get_bit(mapping_key, 2);

        // create value
        const size_t type = is_fec ? NPL_IP_LPM_RESULT_TYPE_DESTINATION_FROM_FEC : NPL_IP_LPM_RESULT_TYPE_DESTINATION_FROM_LPM;

        size_t mapping_value = 0;
        mapping_value = bit_utils::set_bits(mapping_value, 3, 2, type);
        mapping_value = bit_utils::set_bit(mapping_value, 1, is_hbm_denied);
        mapping_value = bit_utils::set_bit(mapping_value, 0, is_default);

        status = m_ll_device->write_register(
            (*m_tree->slice[slice_id]->npu->rxpp_fwd->top->lpm_fec_mapping_lsb_renponse_mapping_reg)[mapping_key], mapping_value);
        if (status != LA_STATUS_SUCCESS) {
            return;
        }
    }
}

void
npu_static_config::configure_npe_timeout_threshold(la_slice_id_t slice_id)
{
    size_t time_threshold = 1000000;
    for (auto& npe : m_tree->slice[slice_id]->npu->rxpp_term->npe) {
        gibraltar::npe_general_cfg_register cfg_reg;
        m_ll_device->read_register(npe->general_cfg, cfg_reg);
        cfg_reg.fields.packet_stack_timer_timeout = time_threshold;
        m_reg_vals.push_back({npe->general_cfg, cfg_reg});
    }
    for (auto& npe : m_tree->slice[slice_id]->npu->rxpp_fwd->npe) {
        gibraltar::npe_general_cfg_register cfg_reg;
        m_ll_device->read_register(npe->general_cfg, cfg_reg);
        cfg_reg.fields.packet_stack_timer_timeout = time_threshold;
        m_reg_vals.push_back({npe->general_cfg, cfg_reg});
    }
    for (auto& npe : m_tree->slice[slice_id]->npu->txpp->npe) {
        gibraltar::npe_general_cfg_register cfg_reg;
        m_ll_device->read_register(npe->general_cfg, cfg_reg);
        cfg_reg.fields.packet_stack_timer_timeout = time_threshold;
        m_reg_vals.push_back({npe->general_cfg, cfg_reg});
    }
}

void
npu_static_config::configure_flow_cache(la_slice_id_t slice_id)
{
    flc_set_rand_em_seed(slice_id);

    la_device_revision_e revision = m_tree->get_revision();
    constexpr size_t AGING_CYCLE_VALUE = 5 * 1000 * 1000; // defaults to 5M cycles
    if (revision == la_device_revision_e::GIBRALTAR_A0) {
        // Due to GB A0 bugs related to the delete mechanisms, enabling only aging deletes
        disable_flow_cache_delete_mechanisms(slice_id);
        flc_enable_or_disable_aging_deletes(slice_id, true /*enable*/, AGING_CYCLE_VALUE);
    } else {
        flc_set_default_delete_params(slice_id, AGING_CYCLE_VALUE);
        flc_enable_or_disable_random_deletes(slice_id, false /*enable*/, 1 /*del_percent*/);
    }
    // Enable verifier and set initial value to 3 times the aging cycle
    gibraltar::flc_db_verifier_update_rate_reg_register verifier_update_rate_reg;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->rxpp_term->flc_db->verifier_update_rate_reg, verifier_update_rate_reg);
    verifier_update_rate_reg.fields.verifier_update_rate = 3 * AGING_CYCLE_VALUE + 1000;
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_term->flc_db->verifier_update_rate_reg, verifier_update_rate_reg});
}

void
npu_static_config::flc_set_rand_em_seed(la_slice_id_t slice_id)
{
    std::mt19937_64 gen(1);
    std::uniform_int_distribution<uint64_t> dis;

    for (size_t i = 0; i < m_tree->slice[slice_id]->npu->rxpp_term->flc_db->flow_cache_per_bank_reg->size(); i++) {
        gibraltar::flc_db_flow_cache_per_bank_reg_register per_bank_reg;
        m_ll_device->read_register((*m_tree->slice[slice_id]->npu->rxpp_term->flc_db->flow_cache_per_bank_reg)[i], per_bank_reg);
        per_bank_reg.fields.flow_cache_hash_key_p0 = dis(gen);
        per_bank_reg.fields.flow_cache_hash_key_p1 = dis(gen);
        per_bank_reg.fields.flow_cache_hash_key_p2 = dis(gen);
        m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->rxpp_term->flc_db->flow_cache_per_bank_reg)[i], per_bank_reg});
    }
}

void
npu_static_config::disable_flow_cache_delete_mechanisms(la_slice_id_t slice_id)
{
    gibraltar::flc_queues_data_random_delete_register rand_delete_reg;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->data_random_delete, rand_delete_reg);
    //  disables random deletion
    rand_delete_reg.fields.data_random_delete_th = 0xffff;
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->data_random_delete, rand_delete_reg});

    gibraltar::flc_queues_data_aging_cycle_register aging_cycle_reg;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->data_aging_cycle, aging_cycle_reg);
    aging_cycle_reg.fields.data_activity_aging_cycle_value = 0;
    aging_cycle_reg.fields.data_aging_cycle_value = 0;
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->data_aging_cycle, aging_cycle_reg});

    gibraltar::flc_queues_disable_ser_packets_removal_reg_register ser_packets_removal_reg;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->disable_ser_packets_removal_reg,
                               ser_packets_removal_reg);
    ser_packets_removal_reg.fields.disable_ser_packets_removal = 1;
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->disable_ser_packets_removal_reg, ser_packets_removal_reg});
}

void
npu_static_config::flc_enable_or_disable_aging_deletes(la_slice_id_t slice_id, bool enable, uint32_t aging_cycle_value)
{
    gibraltar::flc_queues_data_aging_cycle_register aging_cycle_reg;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->data_aging_cycle, aging_cycle_reg);
    if (enable) {
        aging_cycle_reg.fields.data_aging_cycle_value = aging_cycle_value;
    } else {
        aging_cycle_reg.fields.data_aging_cycle_value = 0;
    }
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->data_aging_cycle, aging_cycle_reg});
}

void
npu_static_config::flc_enable_or_disable_random_deletes(la_slice_id_t slice_id, bool enable, uint32_t del_percent)
{
    gibraltar::flc_queues_data_random_delete_register rand_delete_reg;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->data_random_delete, rand_delete_reg);
    if (enable) {
        rand_delete_reg.fields.data_random_delete_th = (0xffff * (100 - del_percent)) / 100;
    } else {
        rand_delete_reg.fields.data_random_delete_th = 0xffff;
    }
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->data_random_delete, rand_delete_reg});
}

void
npu_static_config::flc_set_default_delete_params(la_slice_id_t slice_id, size_t aging_cycle_value)
{
    gibraltar::flc_queues_data_random_delete_register rand_delete_reg;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->data_random_delete, rand_delete_reg);
    // remove 1% of flows randomly
    rand_delete_reg.fields.data_random_delete_th = 64880;
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->data_random_delete, rand_delete_reg});

    gibraltar::flc_queues_data_aging_cycle_register aging_cycle_reg;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->data_aging_cycle, aging_cycle_reg);
    aging_cycle_reg.fields.data_activity_aging_cycle_value = 25;
    // should be > 12*NUM_INDICES*39 as per DV constraints
    aging_cycle_reg.fields.data_aging_cycle_value = aging_cycle_value;
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->data_aging_cycle, aging_cycle_reg});

    gibraltar::flc_queues_disable_ser_packets_removal_reg_register ser_packets_removal_reg;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->disable_ser_packets_removal_reg,
                               ser_packets_removal_reg);
    ser_packets_removal_reg.fields.disable_ser_packets_removal = 0;
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->rxpp_fwd->flc_queues->disable_ser_packets_removal_reg, ser_packets_removal_reg});
}

void
npu_static_config::configure_txpp(la_slice_id_t slice_id)
{

    bool svl_mode = false;
    m_device->get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);

    configure_txpp_npe(slice_id);
    configure_txpp_vlan_editing_control(slice_id);
    configure_txpp_eve_drop_control(slice_id);
    configure_txpp_misc(slice_id);
    configure_txpp_misc_slice_type(slice_id);
    configure_txpp_features_according_to_source_slice(slice_id);
    configure_txpp_macro_id_tcam_key_construction(slice_id);
    configure_txpp_cud_mapping(slice_id);
    configure_txpp_ibm(slice_id);
    //
    // SVL, SGT shares the space with pre-edit in appsoft header
    //
    // Due to NSIM bug this needs to be temporarily disabled
    if (svl_mode == false) {
        configure_txpp_pre_edit_command(slice_id);
    }
    configure_txpp_congestion_level_per_tm_header(slice_id);
    configure_txpp_performance_tune(slice_id);
    configure_txpp_spare_reg(slice_id);
}

void
npu_static_config::configure_txpp_npe(la_slice_id_t slice_id)
{
    // npe_ready_in_out
    gibraltar::npe_ready_in_out_cfg_register tx_ready_in_out;
    tx_ready_in_out.fields.next_ready_to_valid_latency = 4;          // hard coded
    tx_ready_in_out.fields.prev_slot_ready_to_slot_used_latency = 2; // hard coded

    for (auto& npe : m_tree->slice[slice_id]->npu->txpp->npe) {
        m_reg_vals.push_back({npe->ready_in_out_cfg, tx_ready_in_out});
    }
}

void
npu_static_config::configure_txpp_vlan_editing_control(la_slice_id_t slice_id)
{
    // Vlan edit enable per npu-header type
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->txpp->top->ingress_vlan_editing_en, 1 << NPL_FABRIC_HEADER_TYPE_NPU_WITH_IVE});
    // NOTE: The following may be not-used if first nibble of npu-header/fabric-header are not in the same namespace.
    //       in this case, there is an option to enable/disable feature per source-slice. see 'source_slice_feature_en_r' register
    m_reg_vals.push_back({(*m_tree->slice[slice_id]
                                ->npu->txpp->top->ingress_vlan_editing_new_npu_header_type_r)[NPL_FABRIC_HEADER_TYPE_NPU_WITH_IVE],
                          NPL_FABRIC_HEADER_TYPE_NPU_NO_IVE});

    // Offset to IVE-CMD and IVE-PCP-DEI
    static const size_t ive_cmd_offset_in_nibbles = npu_headers_leaba_defines::NPU_HEADER_OFFSET_IN_BITS_TO_IVE_CMD / 4;
    bit_vector ive_cmd_offset_val(ive_cmd_offset_in_nibbles, 7 /*width*/);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->header_type_npu_sms_ive_cmd_offset, ive_cmd_offset_val});

    static const size_t ive_pcp_dei_offset_in_nibbles = npu_headers_leaba_defines::NPU_HEADER_OFFSET_IN_BITS_TO_IVE_PCP_DEI / 4;
    bit_vector ive_pcp_dei_offset_val(ive_pcp_dei_offset_in_nibbles, 7 /*width*/);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->header_type_npu_sms_ive_pcp_dei_offset, ive_pcp_dei_offset_val});

    // Instructions per command
    std::vector<vlan_editing_control::data> ve_commands(vlan_editing_control::NUM_VE_CMDS);

    ve_commands[vlan_editing_control::VE_CMD_NOP] = vlan_editing_control::data({
        .vid1_select = vlan_editing_control::SELECT_FROM_TAG_1,
        .vid2_select = vlan_editing_control::SELECT_FROM_TAG_2,
        .pcp_dei1_select = vlan_editing_control::SELECT_FROM_TAG_1,
        .pcp_dei2_select = vlan_editing_control::SELECT_FROM_TAG_2,
        .tpid1_select = vlan_editing_control::SELECT_FROM_TAG_1,
        .tpid2_select = vlan_editing_control::SELECT_FROM_TAG_2,
        .delta = 0,
        .padding = 0,
    });

    ve_commands[vlan_editing_control::VE_CMD_POP1] = vlan_editing_control::data({
        .vid1_select = vlan_editing_control::SELECT_FROM_TAG_2,
        .vid2_select = vlan_editing_control::IGNORED_FIELD,
        .pcp_dei1_select = vlan_editing_control::SELECT_FROM_TAG_2,
        .pcp_dei2_select = vlan_editing_control::IGNORED_FIELD,
        .tpid1_select = vlan_editing_control::SELECT_FROM_TAG_2,
        .tpid2_select = vlan_editing_control::IGNORED_FIELD,
        .delta = 5,
        .padding = 0,
    });

    ve_commands[vlan_editing_control::VE_CMD_POP2] = vlan_editing_control::data({
        .vid1_select = vlan_editing_control::IGNORED_FIELD,
        .vid2_select = vlan_editing_control::IGNORED_FIELD,
        .pcp_dei1_select = vlan_editing_control::IGNORED_FIELD,
        .pcp_dei2_select = vlan_editing_control::IGNORED_FIELD,
        .tpid1_select = vlan_editing_control::IGNORED_FIELD,
        .tpid2_select = vlan_editing_control::IGNORED_FIELD,
        .delta = 6,
        .padding = 0,
    });

    ve_commands[vlan_editing_control::VE_CMD_PUSH1] = vlan_editing_control::data({
        .vid1_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_1,
        .vid2_select = vlan_editing_control::SELECT_FROM_TAG_1,
        .pcp_dei1_select = vlan_editing_control::SELECT_NEW_PCP_DEI,
        .pcp_dei2_select = vlan_editing_control::SELECT_FROM_TAG_1,
        .tpid1_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_1,
        .tpid2_select = vlan_editing_control::SELECT_FROM_TAG_1,
        .delta = 1,
        .padding = 0,
    });

    ve_commands[vlan_editing_control::VE_CMD_PUSH2] = vlan_editing_control::data({
        .vid1_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_1,
        .vid2_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_2,
        .pcp_dei1_select = vlan_editing_control::SELECT_NEW_PCP_DEI,
        .pcp_dei2_select = vlan_editing_control::SELECT_NEW_PCP_DEI,
        .tpid1_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_1,
        .tpid2_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_2,
        .delta = 2,
        .padding = 0,
    });

    ve_commands[vlan_editing_control::VE_CMD_REMARK] = vlan_editing_control::data({
        .vid1_select = vlan_editing_control::SELECT_FROM_TAG_1,
        .vid2_select = vlan_editing_control::SELECT_FROM_TAG_2,
        .pcp_dei1_select = vlan_editing_control::SELECT_NEW_PCP_DEI,
        .pcp_dei2_select = vlan_editing_control::SELECT_FROM_TAG_2,
        .tpid1_select = vlan_editing_control::SELECT_FROM_TAG_1,
        .tpid2_select = vlan_editing_control::SELECT_FROM_TAG_2,
        .delta = 0,
        .padding = 0,
    });

    ve_commands[vlan_editing_control::VE_CMD_TRANSLATE_1_1] = vlan_editing_control::data({
        .vid1_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_1,
        .vid2_select = vlan_editing_control::SELECT_FROM_TAG_2,
        .pcp_dei1_select = vlan_editing_control::SELECT_NEW_PCP_DEI,
        .pcp_dei2_select = vlan_editing_control::SELECT_FROM_TAG_2,
        .tpid1_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_1,
        .tpid2_select = vlan_editing_control::SELECT_FROM_TAG_2,
        .delta = 0,
        .padding = 0,
    });

    ve_commands[vlan_editing_control::VE_CMD_TRANSLATE_2_1] = vlan_editing_control::data({
        .vid1_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_1,
        .vid2_select = vlan_editing_control::IGNORED_FIELD,
        .pcp_dei1_select = vlan_editing_control::SELECT_NEW_PCP_DEI,
        .pcp_dei2_select = vlan_editing_control::IGNORED_FIELD,
        .tpid1_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_1,
        .tpid2_select = vlan_editing_control::IGNORED_FIELD,
        .delta = 5,
        .padding = 0,
    });

    ve_commands[vlan_editing_control::VE_CMD_TRANSLATE_1_2] = vlan_editing_control::data({
        .vid1_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_1,
        .vid2_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_2,
        .pcp_dei1_select = vlan_editing_control::SELECT_NEW_PCP_DEI,
        .pcp_dei2_select = vlan_editing_control::SELECT_NEW_PCP_DEI,
        .tpid1_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_1,
        .tpid2_select = vlan_editing_control::SELECT_FROM_TAG_1,
        .delta = 1,
        .padding = 0,
    });

    ve_commands[vlan_editing_control::VE_CMD_TRANSLATE_2_2] = vlan_editing_control::data({
        .vid1_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_1,
        .vid2_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_2,
        .pcp_dei1_select = vlan_editing_control::SELECT_NEW_PCP_DEI,
        .pcp_dei2_select = vlan_editing_control::SELECT_NEW_PCP_DEI,
        .tpid1_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_1,
        .tpid2_select = vlan_editing_control::SELECT_NEW_FROM_IVE_COMMAND_TAG_2,
        .delta = 0,
        .padding = 0,
    });

    for (size_t line = 0; line < vlan_editing_control::NUM_VE_CMDS; ++line) {
        m_mem_line_vals.push_back(
            {{m_tree->slice[slice_id]->npu->txpp->top->ingress_vlan_editing_control, line}, ve_commands[line]});
    }
}

void
npu_static_config::configure_txpp_eve_drop_control(la_slice_id_t slice_id)
{
    // The EveDropVlanEthType reg is programmed here for HW and for NSIM the same is
    // programmed via eve_drop_vlan_id_hw_table which is autogenerated from NPL.
    // Any new value addition/deletion of eth_type, the NPL code also has to be updated for NSIM.

    // Max 8 eth type can be programmed.
    uint16_t eth_type_value[] = {0x8100, 0x9100, 0x88a8};

    gibraltar::txpp_eve_drop_vlan_eth_type_reg_register eve_drop_valid_eth_type_reg;

    for (size_t entry_id = 0; entry_id < sizeof(eth_type_value) / sizeof(eth_type_value[0]); entry_id++) {
        eve_drop_valid_eth_type_reg.fields.eve_drop_vlan_eth_type_value = eth_type_value[entry_id];
        if (eth_type_value[entry_id] != 0) {
            eve_drop_valid_eth_type_reg.fields.eve_drop_vlan_eth_type_valid = 0x1;
        } else {
            eve_drop_valid_eth_type_reg.fields.eve_drop_vlan_eth_type_valid = 0x0;
        }
        m_reg_vals.push_back(
            {(*m_tree->slice[slice_id]->npu->txpp->top->eve_drop_vlan_eth_type_reg)[entry_id], eve_drop_valid_eth_type_reg});
    }
}

void
npu_static_config::configure_txpp_misc(la_slice_id_t slice_id)
{
    // Current layet bit index
    gibraltar::txpp_current_layer_bit_index_register current_layer_bit_index_val;
    current_layer_bit_index_val.fields.current_layer_bit_index_bmp = 0;
    if (m_device->m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        // need to set 1 for every 4 bits
        for (size_t field_idx = 0; field_idx < current_layer_bit_index_val.fields.CURRENT_LAYER_BIT_INDEX_BMP_WIDTH / 4;
             ++field_idx) {
            current_layer_bit_index_val.fields.current_layer_bit_index_bmp <<= 4;
            current_layer_bit_index_val.fields.current_layer_bit_index_bmp |= 0x1;
        }
    }
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->current_layer_bit_index, current_layer_bit_index_val});

    // Long termination enable - for npu-header of type 'with-ive'
    const slice_config& cfg = m_slice_config[slice_id];

    if (cfg.slice_mode == SLICE_WORK_MODE_NETWORK) {
        m_reg_vals.push_back(
            {m_tree->slice[slice_id]->npu->txpp->top->long_termination_en, 1 << NPL_FABRIC_HEADER_TYPE_NPU_WITH_IVE});
    } else {
        // fabric
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->long_termination_en, 0});
    }

    // TODO: The following should be device-config - per source slice - enable/disable features
    //    gibraltar::txpp_source_slice_feature_en_r_register source_slice_feature_en;
    //    gibraltar::txpp_congestion_level_tm_header_params_register congestion_level_tm_header_params;
    //
    //    gibraltar::txpp_mtu_check_pif_register mtu_check_pif;
}

void
npu_static_config::configure_txpp_features_according_to_source_slice(la_slice_id_t slice_id)
{
    // 1. Select first light-fi macro - according to source slice
    // Start from fabric-light-fi only if source-slice is fabric and this is not the second packed packet. otherwise start from
    // npu-base
    bit_vector source_slice2_first_lfi_mid_bmp(0, 48); // there are 16 values of 3 bits

    for (size_t i = 0; i < txpp_misc::source_slice_to_light_fi_first_macro_key::NUM_KEYS; ++i) {
        txpp_misc::source_slice_to_light_fi_first_macro_key key = {0};
        key.flat = i;
        // Check if source slice is fabric
        size_t source_slice_is_fabric = 0;
        if ((m_device->m_device_mode == device_mode_e::FABRIC_ELEMENT)
            | (m_slice_config[key.fields.source_slice_id].slice_mode == SLICE_WORK_MODE_FABRIC)) {
            source_slice_is_fabric = 1;
        }
        // Configure according to source slice mode
        bit_vector first_lfi_stage;
        if (source_slice_is_fabric & !key.fields.second_packed_packet) {
            first_lfi_stage = bit_vector(0, 3); // Fabric stage
        } else {
            first_lfi_stage = bit_vector(2, 3); // Npu-base stage
        }
        source_slice2_first_lfi_mid_bmp |= first_lfi_stage << (i * 3);
    }
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->txpp->top->source_slice2_first_lfi_mid_bmp_r, source_slice2_first_lfi_mid_bmp});

    // 2. Enable or disable features - according to source slice
    gibraltar::txpp_source_slice_feature_en_r_register source_slice_feature_en = {{0}};
    for (size_t source_slice_id : m_device->get_used_slices()) {
        // Check if source slice is network
        size_t source_slice_is_network = 1;
        if ((m_device->m_device_mode == device_mode_e::FABRIC_ELEMENT)
            | (m_slice_config[source_slice_id].slice_mode == SLICE_WORK_MODE_FABRIC)) {
            source_slice_is_network = 0;
        }
        // Configure according to source slice mode
        source_slice_feature_en.fields.ingress_vlan_edit_source_slice_en_bmp |= source_slice_is_network << source_slice_id;
        source_slice_feature_en.fields.long_termination_source_slice_en_bmp |= source_slice_is_network << source_slice_id;
        // TxPP Pre edit feature is disabled for now since HW NPL is performing the pre_edit functionality
        // even pre_edit_cmd_r register is not programmed. This needs to be modified. Until then pre_edit feature is
        // disabled.
        // source_slice_feature_en.fields.pre_txpp_edit_cmd_source_slice_en_bmp |= source_slice_is_network << source_slice_id;
        source_slice_feature_en.fields.unpacking_source_slice_en_bmp
            |= (!source_slice_is_network & (m_device->m_device_mode != device_mode_e::FABRIC_ELEMENT)) << source_slice_id;
        source_slice_feature_en.fields.cong_level_extract_source_slice_en_bmp
            |= (!source_slice_is_network & (m_device->m_device_mode != device_mode_e::FABRIC_ELEMENT)) << source_slice_id;
    }
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->source_slice_feature_en_r, source_slice_feature_en});
}

void
npu_static_config::configure_txpp_misc_slice_type(la_slice_id_t slice_id)
{
    const slice_config& cfg = m_slice_config[slice_id];
    for (size_t reg_idx = 0; reg_idx < m_tree->slice[slice_id]->npu->txpp->top->unpacking_en_size->size(); ++reg_idx) {
        gibraltar::txpp_unpacking_en_size_register val;
        val.fields.unpacking_en = 0;
        val.fields.unpacking_size_off = 0;
        if (cfg.slice_mode == SLICE_WORK_MODE_NETWORK) {
            if (reg_idx == NPL_FABRIC_HEADER_TYPE_SN_TS1_PLB_TWO_PACKETS) {
                val.fields.unpacking_en = 1;
                val.fields.unpacking_size_off = 7;
            } else if (reg_idx == NPL_FABRIC_HEADER_TYPE_TS3_PLB_TWO_PACKETS) {
                val.fields.unpacking_en = 1;
                val.fields.unpacking_size_off = 13;
            }
        }

        m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->txpp->top->unpacking_en_size)[reg_idx], val});
    }
}

void
npu_static_config::configure_txpp_macro_id_tcam_key_construction(la_slice_id_t slice_id)
{

    // Configure offsets to:
    // field-a: second encap type
    // field-b: another field from the npu-header if needed (currently not used)
    // NOTE: Currently  NPL_NPU_ENCAP_IP_HEADER_TYPE_HOST_MAC enc type (regardless of FWD Type)

    lld_memory_sptr mem = m_tree->slice[slice_id]->npu->txpp->top->npe_macro_selection_map;
    for (size_t i = 0; i < txpp_misc::macro_id_selection_fields_offset_key::NUM_KEYS; ++i) {
        gibraltar::txpp_npe_macro_selection_map_memory mem_entry;
        txpp_misc::macro_id_selection_fields_offset_key key = {0};
        key.flat = i;

        mem_entry.fields.field_b_offset = 0; // Currently not used

        // Q To Amir:
        // 1. why + 10 ? offset to enc-data inside the npu-header ?
        // 2. is the AV configure opposite ? NH/Host ? also - isn't it should be default as NH
        if (key.fields.first_enc_type
            == NPL_NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC) { // TODO: should be NPL_NPU_ENCAP_IP_HEADER_TYPE_HOST_MAC
            mem_entry.fields.field_a_offset = (npu_headers_leaba_defines::NPU_HEADER_OFFSET_IN_BITS_TO_ENCAP_DATA
                                               + npu_headers_leaba_defines::ENCAP_HEADER_OFFSET_IN_BITS_TO_IP_ENCAP_ENC_TYPE_2_HOST)
                                              / 4;
        } else if (key.fields.first_enc_type
                   == NPL_NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH) { // TODO: should be NPL_NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH
            mem_entry.fields.field_a_offset = (npu_headers_leaba_defines::NPU_HEADER_OFFSET_IN_BITS_TO_ENCAP_DATA
                                               + npu_headers_leaba_defines::ENCAP_HEADER_OFFSET_IN_BITS_TO_IP_ENCAP_ENC_TYPE_2_NH)
                                              / 4;
        } else {
            mem_entry.fields.field_a_offset = 0;
        }

        m_mem_line_vals.push_back({{mem, i}, mem_entry});
    }
}

void
npu_static_config::configure_txpp_cud_mapping(la_slice_id_t slice_id)
{
    // TODO: Need to model table in NPL and remove from static configuration

    bit_vector cud_encap_data_type_offset_val(npu_headers_leaba_defines::NPU_HEADER_OFFSET_IN_BITS_TO_ENC_TYPE / 4, 7);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->cud_encap_data_type_offset, cud_encap_data_type_offset_val});

    bit_vector cud_encap_data_cud_offset_val(npu_headers_leaba_defines::NPU_HEADER_OFFSET_IN_BITS_TO_CUD_ID / 4, 7);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->cud_encap_data_cud_offset, cud_encap_data_cud_offset_val});

    bit_vector cud_encap_data_offset_val(npu_headers_leaba_defines::NPU_HEADER_OFFSET_IN_BITS_TO_ENCAP_DATA / 4, 7);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->cud_encap_data_offset, cud_encap_data_offset_val});

    bit_vector cud_encap_data_type_mc_cud_value_val(NPL_NPU_ENCAP_L2_MC_INGRESS_REPLICATION, 4);
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->txpp->top->cud_encap_data_type_mc_cud_value, cud_encap_data_type_mc_cud_value_val});

    // Took from AV
    // 108 bits needs to be copied back to SMS
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->cud_mapping_enc_data_mask_width, 3});
}

void
npu_static_config::configure_txpp_ibm(la_slice_id_t slice_id)
{
    // This Register holds fields recognising In Bound Mirroring (IBM) commands from the received CUD.
    // It also holds enable switches to IBM related hardware.
    gibraltar::txpp_ibm_editing_enable_bmp_register val = {.u8 = {0}};
    bit_vector cud_ibm_offset_vec(0, 80);
    bit_vector mc_ibm_cud_offset(16, 5);
    bit_vector mc_copy_idb_cud_offset(18, 5);
    bit_vector uc_ibm_cud_offset(0, 5);
    bit_vector non_idm_cud_offset(
        24, 5); // bug WA: non-ibm will put large offset such that ibm-cmd will be 0 (which is assumed to be not used))

    if (m_device->m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        // CUD type of unicast IBM. Compared with the 4 msbs of the CUD.
        val.fields.cud_unicast_ibm = 0xd;

        // Enable vector for CUD mapping according to the IBM.
        // This field is a bitmap from an IBM command (5 bit) to IBM-CUD mapping enable (1 bit).
        // 0: Disable IBM-CUD mapping
        // 1: Enable IBM-CUD mapping
        // NOTE: ibm-command==0 shall not be used in GB due to pre-edit w/ibm bug
        val.fields.ibm_cmd_cud_map = 0xfffffffe;

        // Bitmap indicating whether the CUD contains a IBM command.
        // The 4 msbs of the CUD is passed to the bitmap, producing 1 bit.
        // 0: CUD does not contain IBM
        // 1: CUD contains IBM

        // 0-9'th bits on - this is for multicast (both types)
        // 13'th bit on - this is for unicast
        val.fields.cud_has_ibm_cmd_bmp = 0x23ff;

        /// The offset of the IBM within the CUD. Counted from the  LSB.
        /// Selection is done according to the CUD's 4 msbs.
        /// Each value in this vector is 5 bits long.

        // Copied this configuration for AV.
        // Position does not have a meaning, but the MSB bits should be set and shifted first.
        for (size_t pos = 0; pos < 8; ++pos) { // MC-Copy-ID + IBM
            cud_ibm_offset_vec |= (mc_copy_idb_cud_offset << pos * 5);
        }
        for (size_t pos = 8; pos < 10; ++pos) { // MCID + IBM
            cud_ibm_offset_vec |= (mc_ibm_cud_offset << pos * 5);
        }
        for (size_t pos = 10; pos < 13; ++pos) { // Non-IBM: Setting offset >= 24 such that IBM-Cmd will be equal to 0. this IBM
                                                 // command shall not be used (GB Bug WA in pre-edit)
            cud_ibm_offset_vec |= (non_idm_cud_offset << pos * 5);
        }
        for (size_t pos = 13; pos < 14; ++pos) { // Simple IBM
            cud_ibm_offset_vec |= (uc_ibm_cud_offset << pos * 5);
        }
        for (size_t pos = 14; pos < 16; ++pos) { // Non-IBM: Setting offset >= 24 such that IBM-Cmd will be equal to 0. this IBM
                                                 // command shall not be used (GB Bug WA in pre-edit)
            cud_ibm_offset_vec |= (non_idm_cud_offset << pos * 5);
        }
    }
    val.fields.set_cud_ibm_offset_vec((uint64_t*)cud_ibm_offset_vec.byte_array());
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->ibm_editing_enable_bmp, val});

    // Set MSB mc-cud mapping type for IBM. reigster is 5 bits - so shifting the 6bit prefix one bit to the right
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->cud_ibm_msb_value, CUD_MAP_PREFIX_6b >> 1});
}

void
npu_static_config::configure_txpp_pre_edit_command(la_slice_id_t slice_id)
{
    // TODO: Need to model table in NPL and remove from static configuration

    // The following is used for port expander only. for other cases will need to update the below

    // Pre edit enable
    gibraltar::txpp_pre_edit_en_r_register pre_edit_enable_reg = {{0}};
    // Enable only for npu-header-type with IVE
    pre_edit_enable_reg.fields.pre_edit_npu_header_type_en |= 1 << NPL_FABRIC_HEADER_TYPE_NPU_WITH_IVE;
    pre_edit_enable_reg.fields.pre_edit_ibm_en
        |= 1 << 0; // IBM-Command = 0 is actually 'non-ibm' (pre-edit with IBM GB WA). ibm-cmd of 0 should not be assigned by SDK!
    // NOTE: Other ibm-command should enable pre-edit according to requirements
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->pre_edit_en_r, pre_edit_enable_reg});

    // Pre edit header offset
    // The 32 stands for the offset in bytes to the command on the npu header.
    // If the npu header structure is changed, need to change this configuration.
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->pre_edit_header_offset_r, 32});

    // Below is a mapping of {incoming_pre_edit_cmd, ibm_en, hdr_type_en}
    // For incoming_pre_edit_cmd == DELETE, map command to delete regardless of ibm_en (because we want to remove the port-ext tag
    // before transmitting to host)
    // For incoming_pre_edit_cmd == COPY, map commnd to nop when ibm_en = 0 (because we don't want to change the IPv6 header before
    // transmitting to host)

    gibraltar::txpp_pre_edit_command_map_bmp_register pre_edit_command_map = {{0}};
    for (size_t i = 0; i < txpp_misc::pre_edit_cmd_map_key::NUM_KEYS; ++i) {
        txpp_misc::pre_edit_cmd_map_key key = {0};
        key.flat = i;

        if (!(key.fields.npu_header_type_en)) {
            pre_edit_command_map.fields.pre_edit_command_map = txpp_misc::PRE_EDIT_OP_CODE_NOP;
            pre_edit_command_map.fields.pre_edit_fwd_offset_recalc_en_map = 0;
        } else {
            if (key.fields.orig_cmd_op_code == txpp_misc::PRE_EDIT_OP_CODE_DELETE) {
                pre_edit_command_map.fields.pre_edit_command_map = key.fields.orig_cmd_op_code;                           // 1x1
                pre_edit_command_map.fields.pre_edit_fwd_offset_recalc_en_map = key.fields.orig_cmd_fwd_offset_recalc_en; // 1x1
            } else { // copy/nop
                if (!(key.fields.mirror_en)) {
                    pre_edit_command_map.fields.pre_edit_command_map = txpp_misc::PRE_EDIT_OP_CODE_NOP;
                    pre_edit_command_map.fields.pre_edit_fwd_offset_recalc_en_map = 0;
                } else {
                    pre_edit_command_map.fields.pre_edit_command_map = key.fields.orig_cmd_op_code;                           // 1x1
                    pre_edit_command_map.fields.pre_edit_fwd_offset_recalc_en_map = key.fields.orig_cmd_fwd_offset_recalc_en; // 1x1
                }
            }
        }
        m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->txpp->top->pre_edit_command_map_bmp)[i], pre_edit_command_map});
    }

    // NOTE: the pre edit can receive two formats of commands: full and profile.
    // In full command, there is no mapping. In AV only full command format was checked.
    // TODO: need NPL implementation for this table once profile is needed
    // lld_memory_sptr mem = m_tree->slice[slice_id]->npu->txpp->top->pre_txpp_edit_profile_mem;
}

void
npu_static_config::configure_txpp_congestion_level_per_tm_header(la_slice_id_t slice_id)
{
    // TODO: The below configuration need to be updated, once open line-card mode
    // Note that TM header structure and size need to be updated in order to support if..
    //      --> cong-level and cong-experiences should be new fields on the lsbs of the TM-Header..

    gibraltar::txpp_congestion_level_tm_header_params_register congestion_level_tm_header_params = {{0}};
    // Congestion level is found only on tm-header of type NPL_TM_HEADER_TYPE_UNICAST_OR_MUU_PLB
    congestion_level_tm_header_params.fields.cong_level_tm_cong_experienced_offset = 2; // Bit resolution. offset to 'vce' field
    congestion_level_tm_header_params.fields.cong_level_tm_cong_level_offset
        = 8 + 3 + 9 + 3 + 9; // Bit resolution. offset to congestion_level field in the tm-header
    congestion_level_tm_header_params.fields.cong_level_tm_cong_level_size
        = 4; // Size of the congestion level value in the TM header. Bit resolution.
    m_reg_vals.push_back(
        {(*m_tree->slice[slice_id]->npu->txpp->top->congestion_level_tm_header_params)[NPL_TM_HEADER_TYPE_UNICAST_OR_MUU_PLB],
         congestion_level_tm_header_params});
    // Following header types does not have congestion level, only if experienced.
    congestion_level_tm_header_params.fields.cong_level_tm_cong_experienced_offset = 2; // Bit resolution. offset to 'vce' field
    congestion_level_tm_header_params.fields.cong_level_tm_cong_level_offset
        = 0; // Bit resolution. offset to congestion_level fields
    congestion_level_tm_header_params.fields.cong_level_tm_cong_level_size
        = 0; // Size of the congestion level value in the TM header. Bit resolution.
    m_reg_vals.push_back(
        {(*m_tree->slice[slice_id]->npu->txpp->top->congestion_level_tm_header_params)[NPL_TM_HEADER_TYPE_UNICAST_FLB],
         congestion_level_tm_header_params});
    m_reg_vals.push_back(
        {(*m_tree->slice[slice_id]->npu->txpp->top->congestion_level_tm_header_params)[NPL_TM_HEADER_TYPE_MMM_PLB_OR_FLB],
         congestion_level_tm_header_params});
    m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->txpp->top->congestion_level_tm_header_params)[NPL_TM_HEADER_TYPE_MUM_PLB],
                          congestion_level_tm_header_params});
}

void
npu_static_config::configure_txpp_performance_tune(la_slice_id_t slice_id)
{
    // Configuring bit rate shaper and packet shaper to 99%
    gibraltar::txpp_sms0_packet_shaper_reg_register sms0_packet_shaper;
    sms0_packet_shaper.fields.sms0_packet_shaper_bubble_period = 100;
    sms0_packet_shaper.fields.sms0_packet_shaper_bubble_length
        = 0; // Should be 1 for 99% bit-rate. Disable by setting to 0 due to not fully understood behavior in HW
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->sms0_packet_shaper_reg, sms0_packet_shaper});

    gibraltar::txpp_sms1_packet_shaper_reg_register sms1_packet_shaper;
    sms1_packet_shaper.fields.sms1_packet_shaper_bubble_period = 100;
    sms1_packet_shaper.fields.sms1_packet_shaper_bubble_length
        = 0; // Should be 1 for 99% bit-rate. Disable by setting to 0 due to not fully understood behavior in HW
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->sms1_packet_shaper_reg, sms1_packet_shaper});

    // Configuring packet rate shaper and packet shaper to 99%
    gibraltar::txpp_logical_port_profile_mapping_per_em_reg_register logical_port_profiles_em_reg_val;
    m_ll_device->read_register((*m_tree->slice[slice_id]->npu->txpp->top->logical_port_profile_mapping_per_em_reg)[0],
                               logical_port_profiles_em_reg_val);
    logical_port_profiles_em_reg_val.fields.logical_port_profile_mapping_auto_bubble_req = 1;
    logical_port_profiles_em_reg_val.fields.logical_port_profile_mapping_bubble_req_threshold = 100;
    m_ll_device->write_register((*m_tree->slice[slice_id]->npu->txpp->top->logical_port_profile_mapping_per_em_reg)[0],
                                logical_port_profiles_em_reg_val);

    // ENE Arbitration fix
    for (auto& ene_cluster : m_tree->slice[slice_id]->npu->txpp->ene_cluster) {
        bit_vector cluster_spare_reg_value;
        m_ll_device->read_register(ene_cluster->spare_reg, cluster_spare_reg_value);
        cluster_spare_reg_value.set_bit(0, 1); // enable txpp ENC-cluster arbitration ECO
        m_reg_vals.push_back({ene_cluster->spare_reg, cluster_spare_reg_value});
    }
}

void
npu_static_config::configure_txpp_spare_reg(la_slice_id_t slice_id)
{
    la_device_revision_e revision = m_tree->get_revision();
    if (revision == la_device_revision_e::GIBRALTAR_A0) {
        return;
    }

    bit_vector txpp_spare_reg_value;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->txpp->top->spare_reg, txpp_spare_reg_value);

    txpp_spare_reg_value.set_bit(0, 0); // Disable TxPP CTCAM utilization improvement ECO.
    txpp_spare_reg_value.set_bit(1, 1); // Enable TxPP encap 4 bits HW shift ECO
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->top->spare_reg, txpp_spare_reg_value});
}

void
npu_static_config::configure_cdb()
{
    configure_cdb_fwd_results_mapping_and_extraction();
}

void
npu_static_config::configure_npuh()
{
    gibraltar::npe_ready_in_out_cfg_register npuh_ready_in_out;
    npuh_ready_in_out.fields.next_ready_to_valid_latency = 4;          // hard coded
    npuh_ready_in_out.fields.prev_slot_ready_to_slot_used_latency = 2; // hard coded

    m_reg_vals.push_back({m_tree->npuh->npe->ready_in_out_cfg, npuh_ready_in_out});

    fi_fis_cfg_max_fi_cycles_register max_fi_cycles;
    max_fi_cycles.fields.fis_cfg_max_fi_cycles_r = 15; // hard coded
    m_reg_vals.push_back({m_tree->npuh->fi->fis_cfg_max_fi_cycles, max_fi_cycles});
}

la_status
npu_static_config::configure_ifgb_packet_rate_shaper(la_slice_id_t slice_id, la_ifg_id_t ifg_id)
{
    gibraltar::ifgb_24p_rx_packet_shaper_cfg_register shaper_cfg_reg;
    la_status status = m_ll_device->read_register(m_tree->slice[slice_id]->ifg[ifg_id]->ifgb->rx_packet_shaper_cfg, shaper_cfg_reg);
    return_on_error(status);

    // Shaper must be disabled before config
    shaper_cfg_reg.fields.rx_packet_shaper_en = 0;
    status = m_ll_device->write_register(m_tree->slice[slice_id]->ifg[ifg_id]->ifgb->rx_packet_shaper_cfg, shaper_cfg_reg);
    return_on_error(status);

    shaper_cfg_reg.fields.rx_packet_shaper_en = 1;
    shaper_cfg_reg.fields.rx_packet_shaper_dec_val = 199;
    shaper_cfg_reg.fields.rx_packet_shaper_inc_val = 95;
    shaper_cfg_reg.fields.rx_packet_shaper_cnt_max = 4 * shaper_cfg_reg.fields.rx_packet_shaper_dec_val;
    status = m_ll_device->write_register(m_tree->slice[slice_id]->ifg[ifg_id]->ifgb->rx_packet_shaper_cfg, shaper_cfg_reg);

    return status;
}

la_status
npu_static_config::configure_cdb_arc()
{
    la_status status = LA_STATUS_SUCCESS;
    log_debug(RA, "npu_static_config::configure_cdb_arc()");

    std::string iccm_filename = find_resource_file(CEM_ARC_MICROCODE_ICCM_ENVVAR, DEFAULT_CEM_ARC_MICROCODE_ICCM_FILE);
    std::string dccm_filename = find_resource_file(CEM_ARC_MICROCODE_DCCM_ENVVAR, DEFAULT_CEM_ARC_MICROCODE_DCCM_FILE);

    cem em_db(m_ll_device);
    status = em_db.init_arc(iccm_filename, dccm_filename);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
npu_static_config::config_dbc_logical_db_mapping()
{
    // Configures which LU interfaces should be rate limited in case of a specific container gets full
    // Required so rate limiting is performed on the correct LU

    la_slice_id_vec_t nw_slices = get_slices(m_device, la_slice_mode_e::NETWORK);
    for (auto sid : nw_slices) {
        la_status status = LA_STATUS_SUCCESS;
        for (size_t i = 0; i < 32; i++) {
            uint64_t return_sm_result = bit_utils::get_bit(i, 0);
            uint64_t access_lp = bit_utils::get_bit(i, 2);
            uint64_t access_relay = bit_utils::get_bit(i, 3);
            uint64_t access_mymac = bit_utils::get_bit(i, 4);

            gibraltar::rxpp_term_macdb_sm_db0_mapping_reg_register db0_mapping_reg;
            status = m_ll_device->read_register((*m_tree->slice[sid]->npu->rxpp_term->top->macdb_sm_db0_mapping_reg)[i],
                                                db0_mapping_reg);
            return_on_error(status);
            // Result order is {lp-table, relay, mymac, SM}
            db0_mapping_reg.fields.macdb_sm_db0_mapping = 0;
            if (return_sm_result == 1) {
                db0_mapping_reg.fields.macdb_sm_db0_mapping |= 0b0001;
            }
            if (access_lp == 1) {
                db0_mapping_reg.fields.macdb_sm_db0_mapping |= 0b1000;
            }
            if (access_relay == 1) {
                db0_mapping_reg.fields.macdb_sm_db0_mapping |= 0b0100;
            }
            if (access_mymac == 1) {
                db0_mapping_reg.fields.macdb_sm_db0_mapping |= 0b0010;
            }
            m_reg_vals.push_back({(*m_tree->slice[sid]->npu->rxpp_term->top->macdb_sm_db0_mapping_reg)[i], db0_mapping_reg});

            gibraltar::rxpp_term_macdb_sm_db1_mapping_reg_register db1_mapping_reg;
            status = m_ll_device->read_register((*m_tree->slice[sid]->npu->rxpp_term->top->macdb_sm_db1_mapping_reg)[i],
                                                db1_mapping_reg);
            return_on_error(status);
            // Result order is {lp-table, relay, mymac, SM}
            db1_mapping_reg.fields.macdb_sm_db1_mapping = 0;
            if (return_sm_result == 1) {
                db1_mapping_reg.fields.macdb_sm_db1_mapping |= 0b0001;
            }
            if (access_lp == 1) {
                db1_mapping_reg.fields.macdb_sm_db1_mapping |= 0b1000;
            }
            if (access_relay == 1) {
                db1_mapping_reg.fields.macdb_sm_db1_mapping |= 0b0100;
            }
            if (access_mymac == 1) {
                db1_mapping_reg.fields.macdb_sm_db1_mapping |= 0b0010;
            }
            m_reg_vals.push_back({(*m_tree->slice[sid]->npu->rxpp_term->top->macdb_sm_db1_mapping_reg)[i], db1_mapping_reg});

            uint64_t return_vlan_mapping = bit_utils::get_bit(i, 0);
            // Result order is {mymac, link relay, link lp, vlan mapping}
            gibraltar::rxpp_term_macdb_vlan_mapping_db_mapping_reg_register db_mapping_reg;
            status = m_ll_device->read_register((*m_tree->slice[sid]->npu->rxpp_term->top->macdb_vlan_mapping_db_mapping_reg)[i],
                                                db_mapping_reg);
            return_on_error(status);
            db_mapping_reg.fields.macdb_vlan_mapping_db_mapping = 0;
            if (return_vlan_mapping == 1) {
                db_mapping_reg.fields.macdb_vlan_mapping_db_mapping |= 0b0001;
            }
            if (access_lp == 1) {
                db_mapping_reg.fields.macdb_vlan_mapping_db_mapping |= 0b0010;
            }
            if (access_relay == 1) {
                db_mapping_reg.fields.macdb_vlan_mapping_db_mapping |= 0b0100;
            }
            if (access_mymac == 1) {
                db_mapping_reg.fields.macdb_vlan_mapping_db_mapping |= 0b1000;
            }
            m_reg_vals.push_back(
                {(*m_tree->slice[sid]->npu->rxpp_term->top->macdb_vlan_mapping_db_mapping_reg)[i], db_mapping_reg});
        }

        for (size_t i = 0; i < 8; i++) {

            // Result order is {relay, lp-table, mymac, SM}
            uint64_t return_sm_result = bit_utils::get_bit(i, 0);
            uint64_t access_lp = bit_utils::get_bit(i, 2);

            gibraltar::rxpp_term_macdb_sm_tcam_mapping_reg_register tcam_mapping_reg;
            status = m_ll_device->read_register((*m_tree->slice[sid]->npu->rxpp_term->top->macdb_sm_tcam_mapping_reg)[i],
                                                tcam_mapping_reg);
            return_on_error(status);
            tcam_mapping_reg.fields.macdb_sm_tcam_mapping = 0b1010;
            if (return_sm_result == 1) {
                tcam_mapping_reg.fields.macdb_sm_tcam_mapping |= 0b0001;
            }
            if (access_lp == 1) {
                tcam_mapping_reg.fields.macdb_sm_tcam_mapping |= 0b0100;
            }
            m_reg_vals.push_back({(*m_tree->slice[sid]->npu->rxpp_term->top->macdb_sm_tcam_mapping_reg)[i], tcam_mapping_reg});
        }
    }
    return LA_STATUS_SUCCESS;
}

void
npu_static_config::init_lists()
{
    m_reg_vals.clear();
    m_mem_vals.clear();
    m_mem_line_vals.clear();
    m_tcam_line_vals.clear();
}

la_status
npu_static_config::write_lists()
{
    log_debug(RA, "npu_static_config::write()");
    la_status status = LA_STATUS_SUCCESS;

    if (!m_reg_vals.empty()) {
        status = lld_write_register_list(m_ll_device, m_reg_vals);
        return_on_error(status);
    }

    if (!m_mem_vals.empty()) {
        status = lld_write_memory_list(m_ll_device, m_mem_vals);
        return_on_error(status);
    }

    if (!m_mem_line_vals.empty()) {
        status = lld_write_memory_line_list(m_ll_device, m_mem_line_vals);
        return_on_error(status);
    }

    if (!m_tcam_line_vals.empty()) {
        status = lld_write_tcam_line_list(m_ll_device, m_tcam_line_vals);
        return_on_error(status);
    }

    log_debug(RA, "npu_static_config::write() done");
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
