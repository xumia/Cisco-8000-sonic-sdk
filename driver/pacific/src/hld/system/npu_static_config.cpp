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

#include "lld/ll_device.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"

#include "nplapi/npl_constants.h"
#include "nplapi/npl_enums.h"

#include "hw_tables/cem.h"
#include "hw_tables/em_common.h"

#include "api/types/la_system_types.h"
#include "common/defines.h"
#include "hld_utils.h"
#include "la_device_impl.h"
#include "tm/tm_utils.h"

namespace silicon_one
{

///////////////////////////////////
/// ARC microcode
///////////////////////////////////

static const char DEFAULT_CEM_ARC_MICROCODE_ICCM_FILE[] = "res/firmware_cem_iccm.bin";
static const char DEFAULT_CEM_ARC_MICROCODE_DCCM_FILE[] = "res/firmware_cem_dccm.bin";

static const char CEM_ARC_MICROCODE_ICCM_ENVVAR[] = "CEM_ARC_MICROCODE_ICCM";
static const char CEM_ARC_MICROCODE_DCCM_ENVVAR[] = "CEM_ARC_MICROCODE_DCCM";

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
    NPU_HEADER_CONT_T_ANONYMOUS_UNION_ENCAP_OR_TERM_WIDTH = 108,
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
      m_tree(la_device->get_ll_device()->get_pacific_tree_scptr())
{
    for (la_slice_id_t slice_id : m_device->get_used_slices()) {
        slice_config cfg;
        cfg.is_egress_tor = false;
        cfg.is_slb_enabled = false;
        if (m_device->is_network_slice(slice_id)) {
            cfg.slice_mode = SLICE_WORK_MODE_NETWORK;
        } else { // assume its fabric
            cfg.slice_mode = SLICE_WORK_MODE_FABRIC;
        }
        cfg.sna_slice_mode = SNA_SLICE_MODE_DISABLE_CENTRAL_SNA;

        m_slice_config.push_back(cfg);
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
    }

    for (la_slice_pair_id_t slice_pair_id : m_device->get_used_slice_pairs()) {
        configure_idb(slice_pair_id);
    }

    configure_sdb();
    configure_cdb();
    configure_npuh();

    status = configure_npuh_scanners();
    return_on_error(status);

    status = write_lists();
    return_on_error(status);

    log_debug(RA, "npu_static_config::configure_hw() done");
    return LA_STATUS_SUCCESS;
}

la_status
npu_static_config::configure_dynamic_memories()
{
    log_debug(RA, "npu_static_config::configure_hw_post_soft_reset()");
    la_status status = LA_STATUS_SUCCESS;

    init_lists();

    for (size_t slice : m_device->get_used_slices()) {
        lld_memory_scptr tod_port_max_delay = m_tree->slice[slice]->npu->txpp->txpp->tod_port_max_delay;
        m_mem_vals.push_back({tod_port_max_delay, bit_vector(0, tod_port_max_delay->get_desc()->width_bits)});

        lld_memory_scptr delay_measurement_cmd = m_tree->slice[slice]->npu->txpp->txpp->delay_measurement_cmd;
        m_mem_vals.push_back({delay_measurement_cmd, bit_vector(0, delay_measurement_cmd->get_desc()->width_bits)});
    }

    if (m_tree->get_revision() == la_device_revision_e::PACIFIC_A0) {
        // Pacific B0\B1 bug: the following memory can't be accessed.
        lld_memory_scptr em_group_rate_mem = m_tree->cdb->top->em_group_rate_mem;
        m_mem_vals.push_back({em_group_rate_mem, bit_vector(0, em_group_rate_mem->get_desc()->width_bits)});
    }
    if ((m_tree->get_revision() == la_device_revision_e::PACIFIC_A0)
        || (m_tree->get_revision() == la_device_revision_e::PACIFIC_B1)) {
        // Pacific B0 bug: the following three memories can't be accessed.
        lld_memory_scptr em_inst_rate_mem = m_tree->cdb->top->em_inst_rate_mem;
        m_mem_vals.push_back({em_inst_rate_mem, bit_vector(0, em_inst_rate_mem->get_desc()->width_bits)});

        lld_memory_scptr lpm_group_rate_mem = m_tree->cdb->top->lpm_group_rate_mem;
        m_mem_vals.push_back({lpm_group_rate_mem, bit_vector(0, lpm_group_rate_mem->get_desc()->width_bits)});

        lld_memory_scptr lpm_inst_rate_mem = m_tree->cdb->top->lpm_inst_rate_mem;
        m_mem_vals.push_back({lpm_inst_rate_mem, bit_vector(0, lpm_inst_rate_mem->get_desc()->width_bits)});
    }

    lld_memory_scptr cem_age_table = m_tree->cdb->top->cem_age_table;
    m_mem_vals.push_back({cem_age_table, bit_vector(0, cem_age_table->get_desc()->width_bits)});

    lld_memory_scptr rmep_last_time = m_tree->npuh->host->rmep_last_time;
    m_mem_vals.push_back({rmep_last_time, bit_vector(0, rmep_last_time->get_desc()->width_bits)});

    status = write_lists();
    return_on_error(status);

    log_debug(RA, "npu_static_config::configure_hw_post_soft_reset() done");
    return LA_STATUS_SUCCESS;
}

void
npu_static_config::configure_rxpp(la_slice_id_t slice_id)
{
    configure_rxpp_npe(slice_id);
    configure_rxpp_slice_mode(slice_id);
    configure_rxpp_npu_header(slice_id);
    configure_rxpp_fi(slice_id);
    configure_rxpp_cdb(slice_id);
    configure_rxpp_tunnel_termination_two_lookups(slice_id);
    configure_rxpp_db_connectivity(slice_id);
    configure_rxpp_res_lb_header_type_mapping(slice_id);
    configure_rxpp_lb(slice_id);
    configure_rxpp_sna(slice_id);
    configure_rxpp_sna_flow_signature(slice_id);
    configure_rxpp_pacific_B0_and_B1_changes(slice_id);

    lld_memory_scptr snoop_code_mem = m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->snoop_code_to_mirror_cmd0;
    bit_vector snoop_code_val(0, snoop_code_mem->get_desc()->width_bits);
    snoop_code_val.negate(); // all 1's
    m_mem_vals.push_back({snoop_code_mem, snoop_code_val});

    lld_memory_scptr mirror_code_mem = m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->mirror_code_to_mirror_cmd1;
    bit_vector mirror_code_val(0, mirror_code_mem->get_desc()->width_bits);
    mirror_code_val.negate(); // all 1's
    m_mem_vals.push_back({mirror_code_mem, mirror_code_val});

    lld_memory_scptr dcf_cmd_mem = m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->dcf_mirror_cmd_table;
    // The width of the memory is 6 bits.
    // [5] - valid
    // [4:0] - redirect code. All-1 is void code
    bit_vector dcf_cmd_val(0x1f, dcf_cmd_mem->get_desc()->width_bits);
    m_mem_vals.push_back({dcf_cmd_mem, dcf_cmd_val});

    // TODO: Dual homing - what is the destination
    // Set RxPP.FWD_destination to this destination if SNA->dual_homing is set
    /*
    m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->dual_homing_redirect_destination_cfg;
    rxpp_fwd_dual_homing_redirect_destination_cfg_register reg = { .u8 = {0} };
    reg.fields.dual_homing_redirect_destination;
    */
}

void
npu_static_config::configure_rxpp_npe(la_slice_id_t slice_id)
{
    // term
    npe_ready_in_out_cfg_register term_ready_in_out;
    term_ready_in_out.fields.next_ready_to_valid_latency = 4;          // hard coded
    term_ready_in_out.fields.prev_slot_ready_to_slot_used_latency = 2; // hard coded

    for (auto& npe : m_tree->slice[slice_id]->npu->rxpp_term->npe) {
        m_reg_vals.push_back({npe->ready_in_out_cfg, term_ready_in_out});
        npe_general_cfg_register general_cfg;
        la_status status = m_ll_device->read_register(npe->general_cfg, general_cfg);
        if (status != LA_STATUS_SUCCESS) {
            return;
        }

        general_cfg.fields.enable_counters_header_index_update = 0; // WA for a bug in HW. This will prevent automatic
                                                                    // counters_header_index update upon counter update in NPL and
                                                                    // will allow manual configuration needed for the WA
        general_cfg.fields.enable_snoop_priority_over_redirect = 0;
        general_cfg.fields.packet_stack_timer_timeout = 1000000000;
        m_reg_vals.push_back({npe->general_cfg, general_cfg});
    }

    // fwd
    npe_ready_in_out_cfg_register fwd_ready_in_out;
    fwd_ready_in_out.fields.next_ready_to_valid_latency = 14;         // hard coded
    fwd_ready_in_out.fields.prev_slot_ready_to_slot_used_latency = 5; // hard coded

    for (auto& npe : m_tree->slice[slice_id]->npu->rxpp_fwd->npe) {
        m_reg_vals.push_back({npe->ready_in_out_cfg, fwd_ready_in_out});
        npe_general_cfg_register general_cfg;
        la_status status = m_ll_device->read_register(npe->general_cfg, general_cfg);
        if (status != LA_STATUS_SUCCESS) {
            return;
        }

        general_cfg.fields.enable_counters_header_index_update = 0; // WA for a bug in HW. This will prevent automatic
                                                                    // counters_header_index update upon counter update in NPL and
                                                                    // will allow manual configuration needed for the WA
        general_cfg.fields.enable_lookup_if0_order_keeping = 1;
        general_cfg.fields.lookup_if0_order_keeping_priority_th = 5;
        general_cfg.fields.enable_lookup_if1_order_keeping = 1;
        general_cfg.fields.lookup_if1_order_keeping_priority_th = 5;
        general_cfg.fields.enable_snoop_priority_over_redirect = 0;
        general_cfg.fields.packet_stack_timer_timeout = 1000000000;
        m_reg_vals.push_back({npe->general_cfg, general_cfg});
    }
}

void
npu_static_config::configure_rxpp_slice_mode(la_slice_id_t slice_id)
{
    const slice_config& slice_cfg = m_slice_config[slice_id];

    rxpp_fwd_slice_work_mode_cfg_register slice_mode;
    slice_mode.fields.slice_work_mode = (slice_cfg.slice_mode == SLICE_WORK_MODE_NETWORK);
    slice_mode.fields.slb_work_mode = slice_cfg.is_slb_enabled;
    slice_mode.fields.flow_sig_on_npuh = slice_cfg.is_egress_tor;
    slice_mode.fields.flow_sig_on_lsb_of_npuh = 0;

    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->slice_work_mode_cfg, slice_mode});
}

void
npu_static_config::configure_rxpp_npu_header(la_slice_id_t slice_id)
{
    const slice_config& slice_cfg = m_slice_config[slice_id];

    // Header width value is written in 8bytes resolution.
    size_t npu_header_width = (slice_cfg.slice_mode == SLICE_WORK_MODE_NETWORK) ? NPU_HEADER_WIDTH_IN_BYTES / 8 : 0;

    // term
    fi_stage_cfg_tx_header_width_register term_header_width;
    term_header_width.fields.cfg_tx_header_width_r = npu_header_width;
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_term->fi_stage->cfg_tx_header_width, term_header_width});

    // fwd
    rxpp_fwd_cfg_tx_header_width_register fwd_header_width;
    fwd_header_width.fields.cfg_tx_header_width_r = npu_header_width;
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->cfg_tx_header_width, fwd_header_width});

    // PD construction.
    rxpp_fwd_pd_construction_congurations_register pd_construction;
    pd_construction.fields.soft_sms_header_offset = 96;
    // Value is written in nibble resolution.
    pd_construction.fields.hard_sms_header_size = NPU_SOFT_HEADER_WIDTH_IN_BYTES * 2;
    // Always 0
    pd_construction.fields.mask_npe_err = 1;
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->pd_construction_congurations, pd_construction});
}

void
npu_static_config::configure_rxpp_fi(la_slice_id_t slice_id)
{
    // Setting fi_max_cycles = 15
    fi_fis_cfg_max_fi_cycles_register max_fi_cycles;
    max_fi_cycles.fields.fis_cfg_max_fi_cycles_r = 15; // hard coded
    for (auto& fi_eng : m_tree->slice[slice_id]->npu->rxpp_term->fi_eng) {
        m_reg_vals.push_back({fi_eng->fis_cfg_max_fi_cycles, max_fi_cycles});
    }
}

void
npu_static_config::configure_rxpp_cdb(la_slice_id_t slice_id)
{
// 4k - DSP, 4k - DSPA, 8k - L2 DLP (Pwe/Vxlan/Host)
// In NPL control ip_process_vrf_dip_result  this setting is hard coded.
// Therefore, if we want to change, need to change NPL
#define L2_DLP_MASK_01ENCODING (NPL_DESTINATION_MASK_L2_DLP | (1 << 12))
    bit_vector dsp_mask(NPL_DESTINATION_MASK_DSP >> 12, 8);
    bit_vector dspa_mask(NPL_DESTINATION_MASK_DSPA >> 12, 8);
    bit_vector l2_dlp_mask(NPL_DESTINATION_MASK_L2_DLP >> 12, 8);
    bit_vector l2_dlp_mask2(L2_DLP_MASK_01ENCODING >> 12, 8);
    std::vector<bit_vector> db_splitter_lp_to_mask_vals({l2_dlp_mask, l2_dlp_mask2, dspa_mask, dsp_mask});
    for (size_t reg_idx = 0; reg_idx < m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->db_splitter_lp_to_mask_conf->size();
         ++reg_idx) {
        m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->db_splitter_lp_to_mask_conf)[reg_idx],
                              db_splitter_lp_to_mask_vals[reg_idx]});
    }
}

void
npu_static_config::configure_rxpp_tunnel_termination_two_lookups(la_slice_id_t slice_id)
{
    // Configuing Tunnel Termination
    // TODO: we do not support Tunnel Termination flow in SDK. Once supporting - need to review this setting again.
    // Checked: there is no NPL table.
    lld_memory_scptr mem = m_tree->slice[slice_id]->npu->rxpp_term->rxpp_term->tt0_two_lookups_map;
    for (size_t line = 0; line < mem->get_desc()->entries; ++line) {
        bit_vector two_lookups_enable_bv((line % 2), 1); // when lsb is 1, access both
        m_mem_line_vals.push_back({{mem, line}, two_lookups_enable_bv});
    }
}

void
npu_static_config::configure_rxpp_db_connectivity(la_slice_id_t slice_id)
{
    // Configuring macdb_sm_db0/1_mapping_reg
    // Map the 5 LSBs of the sm_db0 access key, to which DB responses are expected
    for (size_t i = 0; i < macdb_sm_mapping::em_key::NUM_KEYS; ++i) {
        macdb_sm_mapping::em_key key = {0};
        key.flat = i;

        macdb_sm_mapping::em_result res = {0};
        res.fields.access_self = key.fields.access_self;
        res.fields.access_mymac = key.fields.access_mymac;
        res.fields.access_relay = key.fields.access_relay;
        res.fields.access_lp = key.fields.access_lp;

        bit_vector res_bv(res.flat, macdb_sm_mapping::em_result::SIZE_IN_BITS);
        m_reg_vals.push_back(
            {(*m_tree->slice[slice_id]->npu->rxpp_term->rxpp_term->macdb_sm_db0_mapping_reg)[key.reg_num], res_bv});
        m_reg_vals.push_back(
            {(*m_tree->slice[slice_id]->npu->rxpp_term->rxpp_term->macdb_sm_db1_mapping_reg)[key.reg_num], res_bv});
    }

    // Configuring macdb_sm_tcam_mapping_reg
    // Map the 3 LSBs of the sm_tcam access key, to which DB responses are expected
    for (size_t i = 0; i < macdb_sm_mapping::tcam_key::NUM_KEYS; ++i) {
        macdb_sm_mapping::tcam_key key;
        key.flat = i;

        macdb_sm_mapping::tcam_result res = {0};
        res.fields.access_mymac = key.fields.access_mymac;
        res.fields.access_relay = key.fields.access_relay;
        res.fields.access_lp = key.fields.access_lp;

        bit_vector res_bv(res.flat, macdb_sm_mapping::tcam_result::SIZE_IN_BITS);
        m_reg_vals.push_back(
            {(*m_tree->slice[slice_id]->npu->rxpp_term->rxpp_term->macdb_sm_tcam_mapping_reg)[key.reg_num], res_bv});
    }

    // Configuring central TCAM
    // Map the 2 LSBs of the Central TCAM access key, to which DB responses are expected
    //{Don't care, 1'b1} -> {1'b0, 1'b1}  (when extended result return on interface 0)
    //{1'b1, 1'b0} -> {1'b1, 1'b0} (when non extended result returns on same interface)
    //{1'b0, 1'b0} -> {1'b0, 1'b0}

    for (size_t i = 0; i < m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->ctm_fwd_db_mapping_reg->size(); ++i) {
        m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->ctm_fwd_db_mapping_reg)[i], 0});
    }

    m_reg_vals.push_back({(m_tree->slice[slice_id]->npu->rxpp_term->rxpp_term->dbc_thresholds_reg), 0});
    m_reg_vals.push_back({(m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->dbc_thresholds_reg), 0});
}

void
npu_static_config::configure_rxpp_res_lb_header_type_mapping(la_slice_id_t slice_id)
{
    // res_lp_header_type_mapping
    // Checked: there is no NPL table.
    for (size_t protocol_type = 0; protocol_type < 32; ++protocol_type) {
        rxpp_fwd_res_lb_header_type_mapping_reg_register val = {.u8 = {0}};

        val.fields.res_lb_key_current_header_type_to_profile_mapping = LB_FS_DEFAULT_PROFILE;

        switch (protocol_type) {
        case NPL_PROTOCOL_TYPE_ETHERNET:
            val.fields.res_lb_key_header_type_mapping = 0;
            break;
        case NPL_PROTOCOL_TYPE_ETHERNET_VLAN:
            val.fields.res_lb_key_header_type_mapping = 0;
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
            val.fields.res_lb_key_next_header_type_mapping = 5;
            break;
        case NPL_PROTOCOL_TYPE_VLAN_1:
            val.fields.res_lb_key_next_header_type_mapping = 5;
            break;
        case NPL_PROTOCOL_TYPE_VLAN_2:
            val.fields.res_lb_key_next_header_type_mapping = 5;
            break;
        case NPL_PROTOCOL_TYPE_VLAN_3:
            val.fields.res_lb_key_next_header_type_mapping = 5;
            break;
        case NPL_PROTOCOL_TYPE_UDP:
            val.fields.res_lb_key_next_header_type_mapping = 4;
            break;
        case NPL_PROTOCOL_TYPE_TCP:
            val.fields.res_lb_key_next_header_type_mapping = 4;
            break;
        }

        m_reg_vals.push_back(
            {(*m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->res_lb_header_type_mapping_reg)[protocol_type], val});
    }
}

void
npu_static_config::configure_rxpp_lb(la_slice_id_t slice_id)
{
    // LB-KEY const values
    rxpp_fwd_res_lb_key_const_config_reg_register key_const_config_val;
    key_const_config_val.fields.res_lb_key_crc_0_init_key = 0xffff;
    key_const_config_val.fields.res_lb_key_crc_1_init_key = 0xffff;
    key_const_config_val.fields.res_lb_key_crc_2_init_key = 0xffff;
    key_const_config_val.fields.res_lb_key_crc_3_init_key = 0xffff;
    key_const_config_val.fields.res_lb_key_crc_4_init_key = 0xffff;
    key_const_config_val.fields.res_lb_key_crc_5_init_key = 0xffff;
    key_const_config_val.fields.res_lb_key_hash_shift = 1;
    key_const_config_val.fields.res_lb_key_key_0_const_add = 0xabcd;
    key_const_config_val.fields.res_lb_key_key_1_const_add = 0xabcd;
    key_const_config_val.fields.res_lb_key_key_2_const_add = 0xabcd;
    key_const_config_val.fields.res_lb_key_key_3_const_add = 0xabcd;

    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->res_lb_key_const_config_reg, key_const_config_val});

    // FS instruction
    for (size_t next_header_profile = 0; next_header_profile < 4; ++next_header_profile) {
        for (size_t curr_header_profile = 0; curr_header_profile < 4; ++curr_header_profile) {
            // Key is {next-header-profile, current-header-profile}.
            // Setting here all types to 'not-used'
            // In AV, some profiles (3, 7, 15) are set to support CURRENT_HEADER_LB_PROFILE_IPV4_SYMMETRIC_SIP_DIP which is not in
            // use.
            size_t reg_idx = (next_header_profile << 2) | curr_header_profile;

            // All values are 0
            rxpp_fwd_res_lb_profile_fs_insturctions_reg_register val = {.u8 = {0}};

            m_reg_vals.push_back(
                {(*m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->res_lb_profile_fs_insturctions_reg)[reg_idx], val});
        }
    }

    // Set lb-key size to 16 (assuming enable-consistenct is reset)
    rxpp_fwd_resolution_load_balancing_field_size_conf_register field_size_conf_val;
    field_size_conf_val.fields.field_size_is_16b = 1;

    // In AV, for the keys are left 0, while in LBR default value is ffff.
    field_size_conf_val.fields.lb_key_crc_0_init_key = 0xffff;
    field_size_conf_val.fields.lb_key_crc_1_init_key = 0xffff;
    field_size_conf_val.fields.lb_key_crc_2_init_key = 0xffff;
    field_size_conf_val.fields.lb_key_crc_3_init_key = 0xffff;
    field_size_conf_val.fields.lb_key_crc_4_init_key = 0xffff;
    field_size_conf_val.fields.lb_key_crc_5_init_key = 0xffff;

    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->resolution_load_balancing_field_size_conf, field_size_conf_val});

    // Mapping 2 destination MSB to which DB responses are expected (enc_data/destination_data).
    for (size_t reg_idx = 0; reg_idx < m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->res_acc2_db_mapping_reg->size();
         ++reg_idx) {

        rxpp_fwd_res_acc2_db_mapping_reg_register reg_val;
        // TODO: Etgar's take is 0x1 - check with Igor.
        // Currently setting 0x0 to match AV
        reg_val.fields.res_acc2_db_mapping = 0x0;

        m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->res_acc2_db_mapping_reg)[reg_idx], reg_val});
    }

    // Mapping 5 destination MSB + extended to which DB responses are expected (enc_data/destination_data).
    // Map all of them to both responses (11)
    for (size_t msbs = 0; msbs < 32; ++msbs) {
        for (size_t extended = 0; extended < 2; ++extended) {
            size_t reg_idx = (msbs << 1) | extended;

            rxpp_fwd_res_acc0_db_mapping_reg_register reg_val;
            // In AV, "don't care" profiles are not set.
            reg_val.fields.res_acc0_db_mapping = 0x3;

            m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->res_acc0_db_mapping_reg)[reg_idx], reg_val});
        }
    }

    // Mapping - 5 destination MSB + extended how to calculate hash function per DB.
    // key_select (per DB).
    //  all get (11) - XOR of the barrel shited vector and hardwired logic.
    //      LB-key[3] for Native-LB
    //      LB-key[2] for Path-LB
    //      LB-key[1] for NPP-LB
    //      LB-key[0] for DSP-LB
    // control - to which DB responses are expected (enc_data/destination_data).
    //  all mapped to both responses (11)
    for (size_t msbs = 0; msbs < 32; ++msbs) {
        for (size_t extended = 0; extended < 2; ++extended) {
            size_t reg_idx = (msbs << 1) | extended;

            rxpp_fwd_resolution_load_balancing_conf_register reg_val;
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

            reg_val.fields.control = 0x3;

            m_reg_vals.push_back(
                {(*m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->resolution_load_balancing_conf)[reg_idx], reg_val});
        }
    }
}

void
npu_static_config::configure_rxpp_sna(la_slice_id_t slice_id)
{
    const slice_config& slice_cfg = m_slice_config[slice_id];
    lld_memory_scptr pp_local_id_table = m_tree->slice[slice_id]->npu->sna->pp_local_id_table;
    const lld_memory_desc_t* pp_local_id_table_desc = pp_local_id_table->get_desc();
    la_device_revision_e revision = m_tree->get_revision();

    if ((revision == la_device_revision_e::PACIFIC_B0) || (revision == la_device_revision_e::PACIFIC_B1)) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            for (size_t prio = 0; prio < NUM_TC_CLASSES; prio++) {
                for (size_t pif = 0; pif < tm_utils::IFG_SYSTEM_PORT_SCHEDULERS; pif++) {
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
    } else {
        // Re-order bug workaround
        // Due to bug in re-order the following workaround is required.
        // When the bug fixed the table data is sna::pp_local_id_table_data.
        // There is another bug related to priority.
        // Checked: there is no NPL table.
        for (size_t line = 0; line < pp_local_id_table_desc->entries; ++line) {
            m_mem_line_vals.push_back({{pp_local_id_table, line}, line % 2});
        }
    }

    // SNA-mode per Fabric-header-type.
    // All headers are mapped to port priority, since we don't support SN-plb.
    const lld_memory_desc_t* crf_fabric_slice_sna_mode_desc
        = m_tree->slice[slice_id]->npu->sna->map_fabric_header_type_to_crf_fabric_slice_sna_mode->get_desc();
    for (size_t line = 0; line < crf_fabric_slice_sna_mode_desc->entries; ++line) {
        // Port priority option according to LBR
        // 0 - Port priority
        // 2 - SN-PLB
        // 3 - No reorder
        bit_vector sna_mode_pp_opt_bv(0, 2 /*width*/);

        m_mem_line_vals.push_back(
            {{m_tree->slice[slice_id]->npu->sna->map_fabric_header_type_to_crf_fabric_slice_sna_mode, line}, sna_mode_pp_opt_bv});
    }

    // Port-priority regs init
    // These are hard coded values: 0 for slices 0-2; 4096 for slices 3-5
    static const size_t per_slice_first_usable_reorder_context_id_in_slice[] = {0, 0, 0, 4096, 4096, 4096};

    slice_sna_per_slice_cfg_for_pp_sna_mode_register per_slice_cfg_for_pp_val;
    per_slice_cfg_for_pp_val.fields.max_valid_psn = 0xfffff;                  // Not in use
    per_slice_cfg_for_pp_val.fields.use_flow_sig_lsbs_as_reorder_context = 0; // Due to bug in IFG
    per_slice_cfg_for_pp_val.fields.first_usable_reorder_context_id_in_slice
        = per_slice_first_usable_reorder_context_id_in_slice[slice_id];

    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->sna->per_slice_cfg_for_pp_sna_mode, per_slice_cfg_for_pp_val});

    // Sna slice mode init / SNR Outgoing interface
    // TODO - talk to TM (Shira) to understand what need to be done
    slice_sna_per_slice_cfg_for_sna_modes_selection_register per_slice_cfg_for_sna_modes_val;
    per_slice_cfg_for_sna_modes_val.fields.constant_snr_outgoing_if = slice_id % 3;
    per_slice_cfg_for_sna_modes_val.fields.slice_mode = slice_cfg.sna_slice_mode;
    per_slice_cfg_for_sna_modes_val.fields.tor_slb_slice_snr_outgoing_if_mode = 0; // constant mode

    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->sna->per_slice_cfg_for_sna_modes_selection, per_slice_cfg_for_sna_modes_val});

    slice_sna_per_slice_cfg_for_plb_sna_mode_register per_slice_cfg_for_plb_sna_mode_val;
    // In AV, this register is set only in FC vseq.
    per_slice_cfg_for_plb_sna_mode_val.fields.fabric_header_offset_to_source_identifier_field_in_nibbles = 8;
    per_slice_cfg_for_plb_sna_mode_val.fields.fabric_header_offset_to_psn_field_in_nibbles = 11;

    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->sna->per_slice_cfg_for_plb_sna_mode, per_slice_cfg_for_plb_sna_mode_val});

    // per fabric-header.dest-slice (3b), holds snr-outgoing-interface
    // Valid only on CRF-Fabric-slices, when mode is 'Extracted'
    for (size_t slice : m_device->get_used_slices()) {
        bit_vector snr_outgoing_if_bv((slice % 3), 2);
        // In AV, this register is set only in FC vseq.

        m_mem_line_vals.push_back(
            {{m_tree->slice[slice_id]->npu->sna->map_destination_slice_to_snr_outgoing_if, slice /*line*/}, snr_outgoing_if_bv});
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
        // In AV, this register is set only in FC vseq.
        bit_vector curr_bv(curr.data.flat, sna::map_tm_header_type_data::SIZE_IN_BITS);

        m_mem_line_vals.push_back({{m_tree->slice[slice_id]->npu->sna->map_tm_header_type, curr.header /*line*/}, curr_bv});
    }
}

void
npu_static_config::configure_rxpp_sna_flow_signature(la_slice_id_t slice_id)
{
    // SNA: Flow-signature Init
    // TODO: Talked to Aviran. He wants this table to be exposed to SDK (not to user).
    // The idea is initially set the signature to 5-tuples, but later he would want to tweak it.
    // Currently creating just default value.
    // In AV, the value is set to 0x100004421010001ffffff
    bit_vector key(0, 40);
    bit_vector mask(0, 40);
    bit_vector payload(0, 152);

    m_tcam_line_vals.push_back(
        {{m_tree->slice[slice_id]->npu->sna->fls_calculation_program_selection_reg_tcam, 0 /*line*/}, {key, mask}});

    m_mem_line_vals.push_back(
        {{m_tree->slice[slice_id]->npu->sna->fls_calculation_program_selection_reg_tcam_mem, 0 /*line*/}, payload});

    slice_sna_program_selection_field_select_instraction_register val;
    val.fields.program_selection_fs_instraction = 0;
    for (size_t idx = 0; idx < m_tree->slice[slice_id]->npu->sna->program_selection_field_select_instraction->size(); ++idx) {
        m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->sna->program_selection_field_select_instraction)[idx], val});
    }
}

void
npu_static_config::configure_rxpp_pacific_B0_and_B1_changes(la_slice_id_t slice_id)
{
    la_device_revision_e revision = m_tree->get_revision();
    if ((revision != la_device_revision_e::PACIFIC_B0) && (revision != la_device_revision_e::PACIFIC_B1)) {
        return;
    }

    bit_vector rxpp_fwd_spare_reg_value;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->spare_reg, rxpp_fwd_spare_reg_value);
    if ((slice_id % 2 == 1) && m_device->is_network_slice(slice_id)) {
        rxpp_fwd_spare_reg_value.set_bit(64, 1); // Enable RxPP counters stamping ECO only for odd slices.
    } else {
        rxpp_fwd_spare_reg_value.set_bit(64, 0);
    }

    rxpp_fwd_spare_reg_value.set_bit(0, 1); // enable arbitration ECO.
    if (revision == la_device_revision_e::PACIFIC_B1) {
        rxpp_fwd_spare_reg_value.set_bit(65, 1); // Disable RxPP CTCAM utilization improvement ECO.
    }
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->spare_reg, rxpp_fwd_spare_reg_value});

    rxpp_fwd_fwd2out_ic_rate_limiting_config_reg_register rate_limiting_reg;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->fwd2out_ic_rate_limiting_config_reg,
                               rate_limiting_reg);
    rate_limiting_reg.fields.fwd2out_ic_rate_limiting_enabled_when_phase_empty = 1; // enable rate limiting
    rate_limiting_reg.fields.fwd2out_ic_rate_limiting_threshold = 2;
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->rxpp_fwd->rxpp_fwd->fwd2out_ic_rate_limiting_config_reg, rate_limiting_reg});

    bit_vector rxpp_term_spare_reg_value;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->rxpp_term->rxpp_term->spare_reg, rxpp_term_spare_reg_value);
    if (m_device->is_network_slice(slice_id)) {
        rxpp_term_spare_reg_value.set_bits(79, 68, 120); // set period to 120
        // For network slices, we set the packet shaper to 95%
        rxpp_term_spare_reg_value.set_bits(67, 64, 6);   // set bubble length to 6
    } else {                                             // fabric slice
        rxpp_term_spare_reg_value.set_bits(79, 68, 101); // set period to 101
        // For fabric slices, we set the packet shaper to 99%
        rxpp_term_spare_reg_value.set_bits(67, 64, 1); // set bubble length to 1
    }
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->rxpp_term->rxpp_term->spare_reg, rxpp_term_spare_reg_value});
}

void
npu_static_config::configure_txpp(la_slice_id_t slice_id)
{
    configure_txpp_npe(slice_id);
    configure_txpp_db_connectivity(slice_id);
    configure_txpp_vlan_editing_control(slice_id);
    configure_txpp_header_type_and_size(slice_id);
    configure_txpp_misc(slice_id);
    configure_txpp_misc_slice_type(slice_id);
    configure_txpp_ptp(slice_id);
    configure_txpp_second_encap_type_offset(slice_id);
    configure_txpp_cud_mapping(slice_id);
    configure_txpp_ibm(slice_id);
    configure_txpp_dlp_profile_table(slice_id);
    configure_txpp_spare_reg(slice_id);
}

void
npu_static_config::configure_txpp_npe(la_slice_id_t slice_id)
{
    // npe_ready_in_out
    npe_ready_in_out_cfg_register tx_ready_in_out;
    tx_ready_in_out.fields.next_ready_to_valid_latency = 4;          // hard coded
    tx_ready_in_out.fields.prev_slot_ready_to_slot_used_latency = 2; // hard coded

    for (auto& npe : m_tree->slice[slice_id]->npu->txpp->npe) {
        m_reg_vals.push_back({npe->ready_in_out_cfg, tx_ready_in_out});
        npe_general_cfg_register general_cfg;
        la_status status = m_ll_device->read_register(npe->general_cfg, general_cfg);
        if (status != LA_STATUS_SUCCESS) {
            return;
        }

        general_cfg.fields.packet_stack_timer_timeout = 1000000000;
        general_cfg.fields.enable_lookup_if0_order_keeping = 1;
        general_cfg.fields.lookup_if0_order_keeping_priority_th = 5;
        general_cfg.fields.enable_snoop_priority_over_redirect = 0;
        m_reg_vals.push_back({npe->general_cfg, general_cfg});
    }
}

void
npu_static_config::configure_txpp_db_connectivity(la_slice_id_t slice_id)
{
    // Where possible, disabling (by writing 0 to) all Databases rate limiters to avoid cases of phase starvation.
    // Option is available only for the following databases: DLP0, DLP1, Large-EM, Small-EM.
    // [Option is not available for the following databases: Direct-0, Direct-1, Dip-index]

    // {2'b11, 2'b10, 2'b01, 2'b00}; //Per each index: {access-dip-index, return-result}
    // bit_vector encdb_large_enc_em_logical_db_result_mapping_val(0xe4 /*11 10 01 00*/, 8 /*width = 2x4*/);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->encdb_large_enc_em_logical_db_result_mapping, 0});

    // {2'b11, 2'b10, 2'b01, 2'b00}; //Per each index: {access-dip-index, return-result}
    // bit_vector encdb_small_enc_em_logical_db_result_mapping_val(0xe4 /*11 10 01 00*/, 8 /*width = 2x4*/);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->encdb_small_enc_em_logical_db_result_mapping, 0});

    // {2'b11, 2'b01}; //Per each index: {access-direct-0/1, return-result (always set)}
    // bit_vector encdb_l3_dlp0_logical_db_result_mapping_val(0xd /*11 01*/, 4 /*width = 2x2*/);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->encdb_l3_dlp0_logical_db_result_mapping, 0});

    // {2'b11, 2'b01}; //Per each index: {access-direct-0/1, return-result (always set)}
    // bit_vector encdb_l3_dlp1_logical_db_result_mapping_val(0xd /*11 01*/, 4 /*width = 2x2*/);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->encdb_l3_dlp1_logical_db_result_mapping, 0});

    // CTM
    //{Don't care, 1'b1} -> {1'b0, 1'b1}  (when extended result return on interface 0)
    //{1'b1, 1'b0} -> {1'b1, 1'b0} (when non extended result returns on same interface)
    //{1'b0, 1'b0} -> {1'b0, 1'b0}
    //
    // {2'b01, 2'b10, 2'b01, 2'b00}
    bit_vector ctm_egr_logical_db_result_mapping_val(0x64 /*01 10 01 00*/, 8 /*width = 2x4*/);
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->txpp->txpp->ctm_egr_logical_db_result_mapping, ctm_egr_logical_db_result_mapping_val});

    m_reg_vals.push_back({(m_tree->slice[slice_id]->npu->txpp->txpp->dbc_threshold_free_entries_therslod), 0});
    m_reg_vals.push_back({(m_tree->slice[slice_id]->npu->txpp->txpp->ctm_egr_logical_db_result_mapping), 0});
}

void
npu_static_config::configure_txpp_vlan_editing_control(la_slice_id_t slice_id)
{
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
            {{m_tree->slice[slice_id]->npu->txpp->txpp->ingress_vlan_editing_control, line}, ve_commands[line]});
    }
}

void
npu_static_config::configure_txpp_header_type_and_size(la_slice_id_t slice_id)
{
    // Configure both registers (with IVE and without IVE) to different values.
    bit_vector npu_header_type_val_with_ive(NPL_FABRIC_HEADER_TYPE_NPU_WITH_IVE, 4 /*width*/);
    bit_vector npu_header_type_val_without_ive(NPL_FABRIC_HEADER_TYPE_NPU_NO_IVE, 4 /*width*/);

    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->npu_header_type_with_ive, npu_header_type_val_with_ive});
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->npu_header_type_without_ive, npu_header_type_val_without_ive});

    // 0: 16B; 1: 24B; 2: 32B; 3:40B;
    bit_vector header_size_val(3, 2);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->header_type_npu_sms_size, header_size_val});

    // From VLAN editing config
    // npu-header fields
    static const size_t ive_cmd_offset_in_nibbles = npu_headers_leaba_defines::NPU_HEADER_OFFSET_IN_BITS_TO_IVE_CMD / 4;
    bit_vector ive_cmd_offset_val(ive_cmd_offset_in_nibbles, 7 /*width*/);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->header_type_npu_sms_ive_cmd_offset, ive_cmd_offset_val});

    static const size_t ive_pcp_dei_offset_in_nibbles = npu_headers_leaba_defines::NPU_HEADER_OFFSET_IN_BITS_TO_IVE_PCP_DEI / 4;
    bit_vector ive_pcp_dei_offset_val(ive_pcp_dei_offset_in_nibbles, 7 /*width*/);
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->txpp->txpp->header_type_npu_sms_ive_pcp_dei_offset, ive_pcp_dei_offset_val});
}

void
npu_static_config::configure_txpp_misc(la_slice_id_t slice_id)
{
    // Maximal number of words from txpp's first sms2txpp interface allowed in the TxPP per interface.
    bit_vector if_word_mem_alloc_val(512, 10);
    // both register arrays have the same size.
    size_t if_word_mem_alloc_reg_size = m_tree->slice[slice_id]->npu->txpp->txpp->ifg0_ifc_word_mem_alloc->size();
    for (size_t reg_idx = 0; reg_idx < if_word_mem_alloc_reg_size; ++reg_idx) {
        m_reg_vals.push_back(
            {(*m_tree->slice[slice_id]->npu->txpp->txpp->ifg0_ifc_word_mem_alloc)[reg_idx], if_word_mem_alloc_val});
        m_reg_vals.push_back(
            {(*m_tree->slice[slice_id]->npu->txpp->txpp->ifg1_ifc_word_mem_alloc)[reg_idx], if_word_mem_alloc_val});
    }

    bit_vector input_ready_to_valid_latency_val(0x45, 8);
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->txpp->txpp->npe_input_ready_to_valid_latency, input_ready_to_valid_latency_val});

    bit_vector input_used_to_pop_latency_val(5, 4);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->npe_input_used_to_pop_latency, input_used_to_pop_latency_val});

    bit_vector output_grant_to_valid_latency_val(10, 4);
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->txpp->txpp->npe_output_grant_to_valid_latency, output_grant_to_valid_latency_val});

    bit_vector non_sop_in_fifo_threshold_val(5, 4);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->non_sop_in_fifo_threshold, non_sop_in_fifo_threshold_val});

    // All below registers are set 0:FE / 1:LC or SA
    ///////////////
    bit_vector fe_device_zero
        = (m_device->m_device_mode == device_mode_e::FABRIC_ELEMENT) ? bit_vector(0x0, 1) : bit_vector(0x1, 1);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->light_fi_npu_sms_msb_align, fe_device_zero});

    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->fwd_term_sms_hdr_rotate_hdr_en, fe_device_zero});
    ///////////////

    bit_vector post_ene_ipv4_delta_offset_correction_val(0, 8);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->post_ene_ipv4_delta_offset_correction,
                          post_ene_ipv4_delta_offset_correction_val});

    txpp_current_layer_bit_index_register current_layer_bit_index_val;
    current_layer_bit_index_val.fields.current_layer_bit_index_bmp = 0;

    if (m_device->m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        // need to set 1 for every 4 bits
        for (size_t field_idx = 0; field_idx < current_layer_bit_index_val.fields.CURRENT_LAYER_BIT_INDEX_BMP_WIDTH / 4;
             ++field_idx) {
            current_layer_bit_index_val.fields.current_layer_bit_index_bmp <<= 4;
            current_layer_bit_index_val.fields.current_layer_bit_index_bmp |= 0x1;
        }
    }

    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->current_layer_bit_index, current_layer_bit_index_val});

    // Change ISSU configuration such that indication will not be taken from NPU-Header, but from configuration
    bit_vector issu_cfg = bit_vector(0x1, 1);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->issu_use_cfg_value, issu_cfg});
    // Set ISSU Value for both incoming and npe
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->incoming_frag_issu, 0});
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->npe_issu, 0});

    const slice_config& cfg = m_slice_config[slice_id];

    if (cfg.slice_mode == SLICE_WORK_MODE_NETWORK) {
        // same as default
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->long_termination_disable, 0});
    } else {
        // fabric
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->long_termination_disable, 1});
    }
}

void
npu_static_config::configure_txpp_misc_slice_type(la_slice_id_t slice_id)
{
    const slice_config& cfg = m_slice_config[slice_id];

    // All below registers are set 1:network / 0:fabric
    ///////////////
    bit_vector network_slice_one = (cfg.slice_mode == SLICE_WORK_MODE_NETWORK) ? bit_vector(1, 1) : bit_vector(0, 1);

    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->egress_slice, network_slice_one});
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->fwd_qos_mapping_enable, network_slice_one});
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->encap_qos_mapping_enable, network_slice_one});
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->copy_cud_npe_mid_sms_hdr_on_rotated_hdr, network_slice_one});
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->stamp_cud_on_eve, network_slice_one});

    // Setting only the enable bit. The bitmap will be set via calc_checksum_enable_table NPL table.
    txpp_eve_stage_en_signals_register eve_stage_en_signals_val = {.u8 = {0}};
    eve_stage_en_signals_val.fields.eve_en_r = (cfg.slice_mode == SLICE_WORK_MODE_NETWORK) ? 1 : 0;
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->eve_stage_en_signals, eve_stage_en_signals_val});
    /////////////////

    // All below registers are set 0:network / 1:fabric
    ///////////////
    bit_vector fabric_slice_one = (cfg.slice_mode == SLICE_WORK_MODE_NETWORK) ? bit_vector(0, 1) : bit_vector(1, 1);

    for (size_t reg_idx = 0; reg_idx < m_tree->slice[slice_id]->npu->txpp->txpp->fabric_mode->size(); ++reg_idx) {
        m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->txpp->txpp->fabric_mode)[reg_idx], fabric_slice_one});
    }

    for (auto& ene_cluster : m_tree->slice[slice_id]->npu->txpp->cluster) {
        m_reg_vals.push_back({ene_cluster->fabric_mode, fabric_slice_one});
    }
    ////////////////

    for (size_t reg_idx = 0; reg_idx < m_tree->slice[slice_id]->npu->txpp->txpp->unpacking_en_size->size(); ++reg_idx) {
        txpp_unpacking_en_size_register val;
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

        m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->txpp->txpp->unpacking_en_size)[reg_idx], val});
    }
}

void
npu_static_config::configure_txpp_ptp(la_slice_id_t slice_id)
{
    // Negative offset between start of UDP CheckSum and start of PTP CorrectionField:
    // 2 (UDP CS) + 8 (PTP header before CF). 128 - 8 - 2 = 118
    // If we want to stamp time on OriginTime field, value should be: 128 - 34 - 2 = 92
    bit_vector tod_device_time_udp_cs_offset_val(118, 7);

    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->txpp->txpp->tod_device_time_udp_cs_offset, tod_device_time_udp_cs_offset_val});
}

void
npu_static_config::configure_txpp_second_encap_type_offset(la_slice_id_t slice_id)
{
    // txpp_first_enc_type_to_second_enc_type_offset NPL table (reg: npe_mid_res_sec_enc_type_off_sel) selects,
    // which one of the registers npe_mid_res_sec_enc_type_off[0/1] to use. If table value is set to 1, register [0] is used.
    // Default value is 0.
    // Therefore, default option should be set to register [1] and special option should be set to register [0]
    // The content of register 0 is used

    // Special option
    // Setting in nibbles
    txpp_npe_mid_res_sec_enc_type_off_register off0_val;
    off0_val.fields.npe_mid_res_sec_enc_type_off_r
        = npu_headers_leaba_defines::ENCAP_HEADER_OFFSET_IN_BITS_TO_IP_ENCAP_ENC_TYPE_2_HOST / 4;

    m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->txpp->txpp->npe_mid_res_sec_enc_type_off)[0], off0_val});

    // Default option
    // Setting in nibbles
    txpp_npe_mid_res_sec_enc_type_off_register off1_val;
    off1_val.fields.npe_mid_res_sec_enc_type_off_r
        = npu_headers_leaba_defines::ENCAP_HEADER_OFFSET_IN_BITS_TO_IP_ENCAP_ENC_TYPE_2_NH / 4;

    m_reg_vals.push_back({(*m_tree->slice[slice_id]->npu->txpp->txpp->npe_mid_res_sec_enc_type_off)[1], off1_val});
}

void
npu_static_config::configure_txpp_cud_mapping(la_slice_id_t slice_id)
{
    // case of ingress-replication

    bit_vector cud_encap_data_type_offset_val(npu_headers_leaba_defines::NPU_HEADER_OFFSET_IN_BITS_TO_ENC_TYPE / 4, 7);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->cud_encap_data_type_offset, cud_encap_data_type_offset_val});

    bit_vector cud_encap_data_cud_offset_val(npu_headers_leaba_defines::NPU_HEADER_OFFSET_IN_BITS_TO_CUD_ID / 4, 7);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->cud_encap_data_cud_offset, cud_encap_data_cud_offset_val});

    bit_vector cud_encap_data_offset_val(npu_headers_leaba_defines::NPU_HEADER_OFFSET_IN_BITS_TO_ENCAP_DATA / 4, 7);
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->cud_encap_data_offset, cud_encap_data_offset_val});

    bit_vector cud_encap_data_type_mc_cud_value_val(NPL_NPU_ENCAP_L2_MC_INGRESS_REPLICATION, 4);
    m_reg_vals.push_back(
        {m_tree->slice[slice_id]->npu->txpp->txpp->cud_encap_data_type_mc_cud_value, cud_encap_data_type_mc_cud_value_val});

    txpp_cud_mc_copy_id_range_register cud_mc_copy_id_range_val;
    cud_mc_copy_id_range_val.fields.cud_mc_copy_id_range_mask = 0x1f;
    cud_mc_copy_id_range_val.fields.cud_mc_copy_id_range_value = NPL_CFG_MC_COPY_ID_MAP_RANGE;
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->cud_mc_copy_id_range, cud_mc_copy_id_range_val});
}

void
npu_static_config::configure_txpp_ibm(la_slice_id_t slice_id)
{
    // This Register holds fields recognising In Bound Mirroring (IBM) commands from the received CUD.
    // It also holds enable switches to IBM related hardware.
    txpp_ibm_editing_enable_bmp_register val = {.u8 = {0}};

    if (m_device->m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        // CUD type of unicast IBM. Compared with the 4 msbs of the CUD.
        val.fields.cud_unicast_ibm = 0xd;

        // Enable vector for CUD mapping according to the IBM.
        // This field is a bitmap from an IBM command (5 bit) to IBM-CUD mapping enable (1 bit).
        // 0: Disable IBM-CUD mapping
        // 1: Enable IBM-CUD mapping
        val.fields.ibm_cmd_cud_map = 0xffffffff;

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
        for (size_t pos = 8; pos < 10; ++pos) {
            val.fields.cud_ibm_offset_vec_p0 <<= 5;
            val.fields.cud_ibm_offset_vec_p0 |= 16;
        }

        for (size_t pos = 0; pos < 8; ++pos) {
            val.fields.cud_ibm_offset_vec_p0 <<= 5;
            val.fields.cud_ibm_offset_vec_p0 |= 18;
        }
    }

    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->ibm_editing_enable_bmp, val});
}

void
npu_static_config::configure_txpp_dlp_profile_table(la_slice_id_t slice_id)
{
    lld_memory_scptr mem = m_tree->slice[slice_id]->npu->txpp->txpp->logical_port_prof_table;
    bit_vector zero_val(0, mem->get_desc()->width_bits);
    m_mem_vals.push_back({mem, zero_val});
}

void
npu_static_config::configure_txpp_spare_reg(la_slice_id_t slice_id)
{
    // The following configs are relevant to B0.

    bit_vector txpp_spare_reg_value;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->txpp->txpp->spare_reg, txpp_spare_reg_value);

    size_t bubble_length;
    if (m_device->is_network_slice(slice_id)) {
        bubble_length = 5;
    } else {
        bubble_length = 1;
    }

    txpp_spare_reg_value.set_bits(79, 68, 100);           // set period to 100
    txpp_spare_reg_value.set_bits(67, 64, bubble_length); // set bubble length to 1
    txpp_spare_reg_value.set_bit(127, 0);                 // enable txpp phase-like db-access.

    la_device_revision_e revision = m_tree->get_revision();
    if (revision == la_device_revision_e::PACIFIC_B1) {
        txpp_spare_reg_value.set_bit(0, 0); // Disable TxPP CTCAM utilization improvement ECO.
    }
    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->txpp->txpp->spare_reg, txpp_spare_reg_value});

    for (auto& ene_cluster : m_tree->slice[slice_id]->npu->txpp->cluster) {
        bit_vector cluster_spare_reg_value;
        m_ll_device->read_register(ene_cluster->spare_reg, cluster_spare_reg_value);
        cluster_spare_reg_value.set_bit(0, 1); // enable txpp ENC-cluster arbitration ECO
        m_reg_vals.push_back({ene_cluster->spare_reg, cluster_spare_reg_value});
    }
}

void
npu_static_config::configure_sdb()
{
    // Setting mask for service-mapping-1 double access.
    // The mask depends on key format. On packets with VLAN-VLAN, mask suppose to hide second VLAN.
    // If key format is changed, the mask should be changed as well.

    // config sm1 mask for double-access:
    // mask PxVxV to PxV i.e.
    // mask {0(6), vlan2(12), vlan1(12), lp(16), ldb(4)} to {0(6), 0(12), vlan1(12), lp(16), ldb(4)}
    // Need to keep 32 lsb on.
    bit_vector sm1_mask(0xffffffff);
    for (size_t idx = 0; idx < m_tree->sdb->mac->per_slice_sm1_mask_cfg->size(); ++idx) {
        m_reg_vals.push_back({(*m_tree->sdb->mac->per_slice_sm1_mask_cfg)[idx], sm1_mask});
    }

    m_reg_vals.push_back({(m_tree->sdb->mac->bubble_logic_counter_cfg), 5});
}

void
npu_static_config::configure_cdb()
{
    // CEM access rate counters.
    cdb_top_cem_access_rate_counters_register cem_ar_reg_val;
    // min valid value is 256*2
    cem_ar_reg_val.fields.em_group_rate_counter_refresh_period = 10000;
    // min valid value 16*2
    cem_ar_reg_val.fields.em_inst_rate_counter_refresh_period = 10000;
    // TODO update after testing
    cem_ar_reg_val.fields.em_inst_uneven_load_threshold = 8000;

    m_reg_vals.push_back({m_tree->cdb->top->cem_access_rate_counters, cem_ar_reg_val});

    // LPM access rate counters.
    cdb_top_lpm_access_rate_counters_register lpm_ar_reg_val;
    // min valid value is 128*2
    lpm_ar_reg_val.fields.lpm_group_rate_counter_refresh_period = 10000;
    // min valid value is 16*2
    lpm_ar_reg_val.fields.lpm_inst_rate_counter_refresh_period = 10000;
    // TODO update after testing
    lpm_ar_reg_val.fields.lpm_inst_uneven_load_threshold = 8000;

    m_reg_vals.push_back({m_tree->cdb->top->lpm_access_rate_counters, lpm_ar_reg_val});

    bit_vector slb_enable(1, 1);
    m_reg_vals.push_back({m_tree->cdb->top->slb_or_pld_logic, slb_enable});

    cdb_top_select_rxpp_number_per_each_slice_sna_register rxpp_per_slice_sna_val;
    rxpp_per_slice_sna_val.fields.selected_rxpp_to_slice_sna0 = 3;
    rxpp_per_slice_sna_val.fields.selected_rxpp_to_slice_sna1 = 4;
    rxpp_per_slice_sna_val.fields.selected_rxpp_to_slice_sna2 = 5;
    rxpp_per_slice_sna_val.fields.selected_slice_sna_to_rxpp0 = 3;
    rxpp_per_slice_sna_val.fields.selected_slice_sna_to_rxpp1 = 3;
    rxpp_per_slice_sna_val.fields.selected_slice_sna_to_rxpp2 = 3;
    rxpp_per_slice_sna_val.fields.selected_slice_sna_to_rxpp3 = 0;
    rxpp_per_slice_sna_val.fields.selected_slice_sna_to_rxpp4 = 1;
    rxpp_per_slice_sna_val.fields.selected_slice_sna_to_rxpp5 = 2;

    m_reg_vals.push_back({m_tree->cdb->top->select_rxpp_number_per_each_slice_sna, rxpp_per_slice_sna_val});

    la_device_revision_e revision = m_tree->get_revision();
    if (revision == la_device_revision_e::PACIFIC_A0) {
        m_reg_vals.push_back({(m_tree->cdb->top->hbm_lkp_threshold), 92});
        m_reg_vals.push_back({(m_tree->cdb->top->max_hbm_req_per_slice_if), 37});
    } else if ((revision == la_device_revision_e::PACIFIC_B0) || (revision == la_device_revision_e::PACIFIC_B1)) {
        // These changes are relevant for both A0/B0 and B0/B0 modes.
        m_reg_vals.push_back({(m_tree->cdb->top->hbm_lkp_threshold), 110});
        m_reg_vals.push_back({(m_tree->cdb->top->max_hbm_req_per_slice_if), 28});
    }

    // Splitter and LPM cache
    la_uint64_t splitter_scan_period;
    la_uint64_t lpm_scan_period;
    la_uint64_t activity_threshold;
    la_uint64_t activity_offset;
    la_uint64_t age_threshold;
    if (revision == la_device_revision_e::PACIFIC_B0) {
        // Min scan type: 1*2K =~2u ; Max total_scan time =~ (value+20)*2K [ns] =~ 80u
        splitter_scan_period = 15;
        lpm_scan_period = 20;
        // Assuming (R*.value) is 1000: setting this reg to 0, will use timestamp resolution of ~1u. Value of 0 is used for 1u
        // resolution
        activity_offset = 0;
        // Assuming resolution is ~1u, value of 0 means entry. will be aged if not seen for last ~1u (HW logic is GREATER-THAN).
        // Value of 63 is used for 'no-activity-deletes'
        activity_threshold = 1;
        // Assuming resolution is ~128u, value of 2 means entry will be aged if not seen for last ~384u (HW logic is
        // GREATER-THAN).
        // Value of 3 is used for 'no-aging-deletes'
        age_threshold = 2;
    } else if (revision == la_device_revision_e::PACIFIC_B1) {
        splitter_scan_period = 0;
        lpm_scan_period = 0;
        activity_offset = 0;
        activity_threshold = 0;
        // Assuming resolution is ~128u, value of 2 means entry will be aged if not seen for last ~128u.
        age_threshold = 0;
    } else {
        splitter_scan_period = 1000; // total_scan = value*2K [ns] = 2u (100 is 200u -> 25 is 50u)
        lpm_scan_period = 1000;      // total_scan = value*2K [ns] = 2u (100 is 200u -> 25 is 50u)
        activity_offset = 3;
        activity_threshold = 62; // Default is 4. use 63 for 'no-activity-delete'
        age_threshold = 2;
    }
    for (la_slice_id_t slice_id : m_device->get_used_slices()) {
        const lld_register_desc_t* splitter_desc
            = m_tree->slice[slice_id]->npu->cdb_cache->splitter_cache_hash_cfg_register->get_desc();
        // rc5 is generated twice longer than the provided key
        la_uint64_t splitter_key_width = splitter_desc->width_in_bits / 2;
        bit_vector splitter_hash_val = em::generate_pseudo_rc5(splitter_key_width, slice_id);
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->splitter_cache_hash_cfg_register, splitter_hash_val});

        const lld_register_desc_t* lpm_desc = m_tree->slice[slice_id]->npu->cdb_cache->lpm_cache_hash_cfg_register->get_desc();
        // rc5 is generated twice longer than the provided key
        la_uint64_t lpm_key_width = lpm_desc->width_in_bits / 2;
        bit_vector lpm_hash_val = em::generate_pseudo_rc5(lpm_key_width, slice_id);
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->lpm_cache_hash_cfg_register, lpm_hash_val});

        // Cache configurations
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->splitter_cache_scan_period_register, splitter_scan_period});
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->lpm_cache_scan_period_register, lpm_scan_period});

        // Number of clocks the insert machine will stall between attempts to insert new data to cache.
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->splitter_cache_insert_period_register, 1});
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->lpm_cache_insert_period_register, 1});

        // candidates_shift_period == R*. This value is used also for the age/activity counter (ECO).
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->splitter_cache_candidates_shift_period_register, 1000});
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->lpm_cache_candidates_shift_period_register, 1000});

        // Assuming (R*.value) is 1000: setting this reg to 0, will use timestamp resolution of ~1u.
        // Value of 7 is used for 128u resolution
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->splitter_cache_age_offset_register, 7});
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->lpm_cache_age_offset_register, 7});

        // Assuming resolution is ~128u, value of 2 means entry will be aged if not seen for last ~384u (HW logic is GREATER-THAN).
        // Value of 3 is used for 'no-aging-deletes'
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->splitter_cache_age_threshold_register, age_threshold});
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->lpm_cache_age_threshold_register, age_threshold});

        // Assuming (R*.value) is 1000: setting this reg to 0, will use timestamp resolution of ~1u.
        // Value of 3 is used for 8u resolution
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->splitter_cache_activity_offset_register, activity_offset});
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->lpm_cache_activity_offset_register, activity_offset});

        m_reg_vals.push_back(
            {m_tree->slice[slice_id]->npu->cdb_cache->splitter_cache_activity_threshold_register, activity_threshold});
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->lpm_cache_activity_threshold_register, activity_threshold});

        // Disabled by default.
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->splitter_cache_random_delete_on_hit_entry_register, 0});
        m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->lpm_cache_random_delete_on_hit_entry_register, 0});

        configure_cdb_cache_spare_reg(slice_id);
    }
}

void
npu_static_config::configure_cdb_cache_spare_reg(la_slice_id_t slice_id)
{
    // The following configs are relevant only for B0.

    bit_vector spare_reg_value;
    m_ll_device->read_register(m_tree->slice[slice_id]->npu->cdb_cache->spare_reg, spare_reg_value);
    spare_reg_value.set_bit(2, 0); // enable cdb cache age and activity resolution eco.
    spare_reg_value.set_bit(1, 1); // enable LPM cache.
    la_device_revision_e revision = m_tree->get_revision();

    bool is_ip_cache_hbm_mode = false;
    if ((revision == la_device_revision_e::PACIFIC_B0) || (revision == la_device_revision_e::PACIFIC_B1)) {
        is_ip_cache_hbm_mode = true;
    }
    spare_reg_value.set_bit(0, is_ip_cache_hbm_mode ? 0 : 1); /* 0 = HBM mode, 1 = leaf/node mode */
    if (revision == la_device_revision_e::PACIFIC_B1) {
        spare_reg_value.set_bit(3, 0); // Do not disable duplicate ECO (i.e. enable the fix)
        spare_reg_value.set_bit(4, 0); // Do not disable EM-Bypass ECO (i.e. enable the fix)
    }

    m_reg_vals.push_back({m_tree->slice[slice_id]->npu->cdb_cache->spare_reg, spare_reg_value});
}

void
npu_static_config::configure_idb(la_slice_pair_id_t slice_pair_id)
{
    // when set, service-relay-table is 16K, and link-relay-table is 0K
    // when reset, service-relay-table is 12K, and link-relay-table is 4k
    idb_top_disable_link_relay_cfg_register disable_link_relay_cfg_val;
    disable_link_relay_cfg_val.fields.slice0_disable_link_relay_table = 1;
    disable_link_relay_cfg_val.fields.slice1_disable_link_relay_table = 1;

    m_reg_vals.push_back({m_tree->slice_pair[slice_pair_id]->idb->top->disable_link_relay_cfg, disable_link_relay_cfg_val});

    static const size_t threshold = 5;
    idb_top_bubble_logic_counter_cfg_register bubble_logic_counter_cfg_reg;
    bubble_logic_counter_cfg_reg.fields.dip_index_input_cbr_num_of_clks_before_forced_bubble = threshold;
    bubble_logic_counter_cfg_reg.fields.direct0_input_cbr_num_of_clks_before_forced_bubble = threshold;
    bubble_logic_counter_cfg_reg.fields.direct1_input_cbr_num_of_clks_before_forced_bubble = threshold;
    bubble_logic_counter_cfg_reg.fields.dlp1_input_cbr_num_of_clks_before_forced_bubble = threshold;
    bubble_logic_counter_cfg_reg.fields.link_relay_input_cbr_num_of_clks_before_forced_bubble = threshold;
    bubble_logic_counter_cfg_reg.fields.mymac_em_input_cbr_num_of_clks_before_forced_bubble = threshold;
    bubble_logic_counter_cfg_reg.fields.mymac_em_vm_cbr_num_of_clks_before_forced_bubble = threshold;
    bubble_logic_counter_cfg_reg.fields.service_relay_input_cbr_num_of_clks_before_forced_bubble = threshold;
    bubble_logic_counter_cfg_reg.fields.small_em_input_cbr_num_of_clks_before_forced_bubble = threshold;
    m_reg_vals.push_back({m_tree->slice_pair[slice_pair_id]->idb->top->bubble_logic_counter_cfg, bubble_logic_counter_cfg_reg});

    idb_res_npp_data_register npp_data_val;
    // Number of NPPs in 1K resolution. Max-valid-value is 16.
    npp_data_val.fields.num_of_npps_in_1k_resolution = 16;
    // destination[13:10] is masked with this value before checking if it's an NPP
    npp_data_val.fields.npp_mask = 0x1f;
    // 0:DSP-Range are directly mapped to DSP max-valid value is cfg_num_of_npps_in_1k_resolution.
    // Value in 1K resolution
    npp_data_val.fields.dsp_range = 8;
    // 6 msbs of the DSP according to the device's destination-encoding
    npp_data_val.fields.dsp_prefix = NPL_DESTINATION_MASK_DSP >> 14;
    // DSP-Range:DSPA-Range are directly mapped to DSPA max-valid value is cfg_num_of_npps_in_1k_resolution.
    // Value in 1K resolution
    npp_data_val.fields.dspa_range = 16;
    // 6 msbs of the DSPA according to the device's destination-encoding
    npp_data_val.fields.dspa_prefix = NPL_DESTINATION_MASK_DSPA >> 14;

    m_reg_vals.push_back({m_tree->slice_pair[slice_pair_id]->idb->res->npp_data, npp_data_val});

    configure_idb_spare_reg(slice_pair_id);
}

void
npu_static_config::configure_idb_spare_reg(la_slice_pair_id_t slice_pair_id)
{
    // The following configs are relevant only for B0.

    bit_vector spare_reg_value;
    m_ll_device->read_register(m_tree->slice_pair[slice_pair_id]->idb->res->spare_reg, spare_reg_value);
    spare_reg_value.set_bit(65, 0); // enable resolution arbitration SP ECO
    m_reg_vals.push_back({m_tree->slice_pair[slice_pair_id]->idb->res->spare_reg, spare_reg_value});
}

void
npu_static_config::configure_npuh()
{
    npe_ready_in_out_cfg_register npuh_ready_in_out;
    npuh_ready_in_out.fields.next_ready_to_valid_latency = 4;          // hard coded
    npuh_ready_in_out.fields.prev_slot_ready_to_slot_used_latency = 2; // hard coded

    m_reg_vals.push_back({m_tree->npuh->npe->ready_in_out_cfg, npuh_ready_in_out});

    npe_general_cfg_register general_cfg;
    la_status status = m_ll_device->read_register(m_tree->npuh->npe->general_cfg, general_cfg);
    if (status != LA_STATUS_SUCCESS) {
        return;
    }

    general_cfg.fields.packet_stack_timer_timeout = 1000000000;
    m_reg_vals.push_back({m_tree->npuh->npe->general_cfg, general_cfg});

    fi_fis_cfg_max_fi_cycles_register max_fi_cycles;
    max_fi_cycles.fields.fis_cfg_max_fi_cycles_r = 15; // hard coded
    m_reg_vals.push_back({m_tree->npuh->fi->fis_cfg_max_fi_cycles, max_fi_cycles});
}

la_status
npu_static_config::configure_npuh_scanners()
{
    log_debug(RA, "npu_static_config::configure_npuh_scanners()");
    la_status status = LA_STATUS_SUCCESS;

    // Clocks are define intervals for scanners. Setting to max value.
    std::vector<lld_register_scptr> npuh_timers;
    npuh_timers.push_back(m_tree->npuh->host->sat_timer);
    npuh_timers.push_back(m_tree->npuh->host->rmep_timer);
    npuh_timers.push_back(m_tree->npuh->host->mp_lm_timer);
    npuh_timers.push_back(m_tree->npuh->host->mp_dm_timer);
    npuh_timers.push_back(m_tree->npuh->host->mp_ccm_timer);

    // Setting only 32 lsb - ignoring the rest.
    bit_vector scanner_max_interval(0xffffffff);

    for (lld_register_scptr timer_reg : npuh_timers) {
        status = m_ll_device->read_modify_write_register(*timer_reg, 31, 0, scanner_max_interval);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
npu_static_config::configure_cdb_arc()
{
    la_status status = LA_STATUS_SUCCESS;
    log_debug(RA, "npu_static_config::configure_cdb_arc()");
    log_debug(SIM, "command::arc_configuration_started");

    // Configuring aging
    cdb_top_aging_regs_register aging_reg_val;
    aging_reg_val.fields.aging_cycle = 30;    // dummy
    aging_reg_val.fields.aging_interval = 30; // dummy
    aging_reg_val.fields.aging_enable = 0;    // TODO: enable afer testing

    status = m_ll_device->write_register(m_tree->cdb->top->aging_regs, aging_reg_val);
    return_on_error(status);

    std::string iccm_filename = find_resource_file(CEM_ARC_MICROCODE_ICCM_ENVVAR, DEFAULT_CEM_ARC_MICROCODE_ICCM_FILE);
    std::string dccm_filename = find_resource_file(CEM_ARC_MICROCODE_DCCM_ENVVAR, DEFAULT_CEM_ARC_MICROCODE_DCCM_FILE);

    cem em_db(m_ll_device);
    status = em_db.init_arc(iccm_filename, dccm_filename);
    return_on_error(status);

    log_debug(SIM, "command::arc_configuration_done");
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
