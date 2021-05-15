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

#ifndef __FABRIC_INIT_HANDLER_H__
#define __FABRIC_INIT_HANDLER_H__

#include "hld_types.h"
#include "hld_types_fwd.h"
#include "lld/lld_utils.h"

namespace silicon_one
{

class fabric_init_handler
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS
    fabric_init_handler() = default; // Needed for cereal

public:
    explicit fabric_init_handler(const la_device_impl_wptr& device);
    ~fabric_init_handler();

    la_status configure_phase_topology_pre_soft_reset();
    la_status configure_phase_topology_dynamic_memories();
    la_status configure_phase_topology_post_soft_reset();
    la_status create_fabric_mc_voq_set(la_voq_set_wptr& voq_set);

    // Post soft-reset helper function - public because it's used by soft-reset sequence
    la_status configure_post_soft_reset_pdvoq();

    // Enable PFC-specific changes if PFC used on this device
    la_status set_pfc();

    enum {
        FIRST_POSSIBLE_FABRIC_SLICE_IN_LC = 3,
    };

private:
    enum {
        /// VOQ congestion management profile indices.
        /// The specific numbers are arbitrary, to match the HW init.
        MS_VOQ_UCH_CGM_PROFILE_INDEX = 10,
        MS_VOQ_UCL_CGM_PROFILE_INDEX = 11,
        MS_VOQ_MC_CGM_PROFILE_INDEX = 12,

        NUM_OF_PGS = 8, ///< Number of Priority Groups

        NUM_FBM_FABRIC_SLICE_VALID_BUFFERS = 4, ///< Number of valid FBM buffers fabric slices
    };

    static constexpr uint64_t MS_VOQ_CGM_PROFILES[]
        = {MS_VOQ_UCH_CGM_PROFILE_INDEX, MS_VOQ_UCL_CGM_PROFILE_INDEX, MS_VOQ_MC_CGM_PROFILE_INDEX};

    ///@brief Register helper structs
    union tpse_oqpg_map_tm_port_u {
        struct fields_s {
            uint64_t oq0 : 3;
            uint64_t oq1 : 3;
            uint64_t oq2 : 3;
            uint64_t oq3 : 3;
            uint64_t oq4 : 2;
            uint64_t oq5 : 2;
            uint64_t oq6 : 1;
        } fields;

        uint64_t flat;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(tpse_oqpg_map_tm_port_u)
    CEREAL_SUPPORT_PRIVATE_CLASS(tpse_oqpg_map_tm_port_u::fields_s)

    // Pre soft reset helper functions
    la_status configure_ms_voqs();
    la_status configure_ms_voq_cgm_profiles();
    la_status configure_drop_voq_cgm_profiles();
    la_status configure_drop_voq_cgm_profile_buffers_consumption_lut_for_enq(size_t vog_cgm_profile_id);
    la_status configure_drop_voq_cgm_profile_buff_region_thresholds(size_t vog_cgm_profile_id);
    la_status configure_ms_voq_cgm_profile_buff_region_thresholds();
    la_status configure_ms_voq_cgm_profile_pkt_enq_time_region_thresholds();
    la_status configure_ms_voq_cgm_profile_pkt_region_thresholds();
    la_status configure_ms_voq_cgm_profile_buffers_consumption_lut_for_enq();
    la_status configure_ms_voq_cgm_profile_pd_consumption_lut_for_enq();
    la_status configure_ms_voq_cgm_profile_dram_cgm_profile();
    la_status configure_ms_voq_cgm_profile_slice_cgm_profile();
    la_status configure_csms();
    la_status configure_mc_voqs();
    la_status attach_mc_voqs_to_fabric_schedulers();
    la_status configure_pre_soft_reset_pdvoq();
    la_status prepare_pdvoq_static_mapping(lld_memory_line_value_list_t& mem_line_val_list, lld_memory_scptr static_mapping);
    la_status configure_pdvoq_voq_properties();
    la_status configure_pdvoq_mc_voq_properties();
    la_status configure_pdvoq_ms_voq_properties();
    la_status configure_pdoq();
    la_status prepare_pdoq_oqg_to_link_map(lld_memory_line_value_list_t& mem_line_val_list, la_slice_id_t sid);
    la_status prepare_pdoq_ifse_general_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t sid);
    la_status prepare_pdoq_tpse_oqpg_mapping_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t sid);
    la_status prepare_pdoq_oqpg_cir_token_bucket_cfg(lld_memory_line_value_list_t& mem_line_val_list, la_slice_id_t sid);
    la_status prepare_pdoq_oq_pir_token_bucket_cfg(lld_memory_line_value_list_t& mem_line_val_list, la_slice_id_t sid);
    la_status prepare_pdoq_tpse_wfq_cfg(lld_memory_line_value_list_t& mem_line_val_list, la_slice_id_t sid);
    la_status configure_rx_cgm();
    la_status configure_pre_soft_reorder_block();
    la_status prepare_pp_reorder_em_fbm_config_reg(lld_register_value_list_t& reg_val_list, la_slice_id_t sid);
    la_status prepare_nw_reorder_block_em_fbm_config_reg(lld_register_value_list_t& reg_val_list, la_slice_id_t sid);
    la_status configure_filb();
    la_status prepare_filb_static_fabric_reachability(lld_memory_value_list_t& mem_val_list, la_slice_id_t rx_slice);
    la_status prepare_filb_lfsr_cfg_reg(lld_register_value_list_t& reg_val_list, la_slice_id_t rx_slice);
    la_status configure_sch();
    la_status prepare_sch_ifse_general_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t sid);
    la_status prepare_sch_tpse_general_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t sid);
    la_status configure_tx_cgm();
    la_status prepare_tx_cgm_cgm_reject_mask(lld_register_value_list_t& reg_val_list, la_slice_id_t sid);
    la_status prepare_tx_cgm_fabric_link_uch_th_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t sid);
    la_status prepare_tx_cgm_fabric_link_ucl_th_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t sid);
    la_status prepare_tx_cgm_fabric_link_mc_th_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t sid);
    la_status configure_tx_pdr();
    la_status configure_mc_bitmap_base_voq_lookup_table();
    la_status prepare_tx_pdr_fabric_link_map(lld_memory_line_value_list_t& mem_line_val_list, la_slice_id_t sid);

    // Dynamic memories helper functions
    la_status configure_dynamic_memories_reorder_block();

    // Post soft reset helper functions
    la_status configure_ics();
    la_status configure_ics_ms_voq();
    la_status prepare_pdvoq_voq2context(lld_memory_line_value_list_t& mem_line_val_list, lld_memory_scptr voq2context);
    la_status prepare_pdvoq_voqcgm_profile(lld_memory_line_value_list_t& mem_line_val_list, lld_memory_scptr voqcgm_profile);
    la_status prepare_pdvoq_contextfbm_bmp(lld_memory_line_value_list_t& mem_line_val_list, lld_memory_scptr contextfbm_bmp);
    la_status prepare_pdvoq_context_allocate(lld_memory_line_value_list_t& mem_line_val_list,
                                             lld_memory_scptr context_allocate_grant_set,
                                             lld_memory_scptr context_allocate_set_master,
                                             lld_memory_scptr context_allocate_set_slave);
    la_status prepare_pdvoq_cmap_th_reg_network(lld_register_value_list_t& reg_val_list, lld_register_scptr cmap_th_reg);
    la_status prepare_pdvoq_cmap_th_reg_fabric(lld_register_value_list_t& reg_val_list, lld_register_scptr cmap_th_reg);
    la_status prepare_pp_reorder_pp_exact_match_fbm(lld_memory_value_list_t& mem_val_list,
                                                    lld_memory_line_value_list_t& mem_line_val_list,
                                                    la_slice_id_t sid);
    la_status prepare_nw_reorder_block_nw_exact_match_fbm(lld_memory_value_list_t& mem_val_list,
                                                          lld_memory_line_value_list_t& mem_line_val_list,
                                                          la_slice_id_t sid);
    la_status prepare_reorder_block_exact_match_fbm_entries(lld_memory_value_list_t& mem_val_list,
                                                            lld_memory_line_value_list_t& mem_line_val_list,
                                                            const lld_memory_array_container& exact_match_fbm);
    la_status configure_post_soft_dmc_frm();

    la_status configure_scmid_to_mcid_table_default();

    size_t get_voq_cgm_index_for_cs_fabric_context(npl_cs_fabric_context_e cs_fabric_context);

    // Containing device
    la_device_impl_wptr m_device;

    la_voq_set_wptr m_mc_voq_set;

    la_vsc_gid_vec_t m_base_mc_vsc_vec;
};

} // namespace silicon_one

#endif // __FABRIC_INIT_HANDLER_H__
