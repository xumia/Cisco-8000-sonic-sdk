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

#ifndef __RA_NPU_STATIC_CONFIG_GB_H__
#define __RA_NPU_STATIC_CONFIG_GB_H__

#include "api/types/la_common_types.h"
#include "api/types/la_system_types.h"
#include "hld_types.h"
#include "system/la_device_impl.h"

#include "common/la_status.h"
#include "lld/lld_utils.h"

#include <array>
#include <vector>

namespace silicon_one
{

class ll_device;
class gibraltar_tree;

/// @brief Device static configuration
///
class npu_static_config
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    enum {
        NPPD_WIDTH_IN_BYTES = 232,                   // 1856b
        NPPD_PACKET_HEADER_WIDTH_IN_BYTES = 128,     // 1024b
        NPPD_USER_DATA_WIDTH_IN_BYTES = 104,         // 832b
        NPPD_EXTENDED_USER_DATA_WIDTH_IN_BYTES = 32, // 256b
        NPU_HEADER_MAX_WIDTH_IN_BYTES = 64,
        NPU_HEADER_HARD_WIDTH_IN_BYTES = 32,
        NPU_HEADER_SOFT_WIDTH_IN_BYTES = 8,
        NPU_HEADER_WIDTH_IN_BYTES = NPU_HEADER_HARD_WIDTH_IN_BYTES + NPU_HEADER_SOFT_WIDTH_IN_BYTES,
    };

    enum slice_work_mode_e {
        SLICE_WORK_MODE_FABRIC = 0,
        SLICE_WORK_MODE_NETWORK,
        SLICE_WORK_MODE_DISABLED,
    };

    enum sna_slice_mode_e {
        SNA_SLICE_MODE_DISABLE_CENTRAL_SNA = 0, // No Central SNA in GB
    };

    enum fs_profiles_e {
        LB_FS_DEFAULT_PROFILE = 0,
        LB_FS_IPV4_DOUBLE_SIP_DIP_PROFILE = 1,
        LB_FS_IPV6_EXTRA_PARTIAL_DIP_PROFILE = 2,
        LB_FS_ETH_EXTRA_PARTIAL_SA_DA_PROFILE = 3,
        LB_FS_ETH_VLAN_EXTRA_PARTIAL_SA_PROFILE = 7,
    };

    struct slice_config {
        slice_work_mode_e slice_mode;    ///< Fabric or Network.
        sna_slice_mode_e sna_slice_mode; ///< Sequence-number assignment slice mode.
    };

public:
    // C'tor
    explicit npu_static_config(const la_device_impl_wptr& la_device);

    /// @brief Writes config memories configuration to all NPU blocks.
    ///
    /// @retval status code.
    la_status configure_hw();

    /// @brief Writes dynamic memories configuration to all NPU blocks.
    ///
    /// @retval status code.
    la_status configure_dynamic_memories();

    /// @brief Configure CDB ARC.
    ///
    /// @retval status code.
    la_status configure_cdb_arc();

private:
    // RXPP
    ////////////////////////
    void configure_rxpp(la_slice_id_t slice_id);
    void configure_rxpp_npe(la_slice_id_t slice_id);
    void configure_rxpp_nppd_construction(la_slice_id_t slice_id);
    void configure_rxpp_rate_limiter_and_packet_shaper_tune(la_slice_id_t slice_id);
    // Format identifier
    void configure_rxpp_hw_fi(la_slice_id_t slice_id);
    // Database access configuration
    void configure_rxpp_fec_table_access(la_slice_id_t slice_id);
    // Load balancing
    void configure_rxpp_res_lb_header_type_mapping(la_slice_id_t slice_id);
    void configure_rxpp_lb(la_slice_id_t slice_id);
    // FEC mapping init
    void configure_rxpp_fec_mapping(la_slice_id_t slice_id);
    // SNA
    ////////////////////////
    void configure_rxpp_sna(la_slice_id_t slice_id);

    // Gibraltar A1 changes
    void configure_rxpp_spare_reg(la_slice_id_t slice_id);

    //
    // cdb cache
    void configure_rxpp_cdb_cache(la_slice_id_t slice_id);
    //
    // flow cache
    void configure_flow_cache(la_slice_id_t slice_id);
    //
    //    // CDB
    //    ////////////////////////
    void configure_cdb();
    void configure_cdb_fwd_results_mapping_and_extraction();
    //
    //    // IDB
    //    ////////////////////////
    void configure_idb_service_mapping_data_extraction(la_slice_pair_id_t slice_pair_id);
    //    // TXPP
    //    ////////////////////////
    void configure_txpp(la_slice_id_t slice_id);
    //
    void configure_txpp_npe(la_slice_id_t slice_id);
    void configure_txpp_vlan_editing_control(la_slice_id_t slice_id);
    void configure_txpp_eve_drop_control(la_slice_id_t slice_id);
    void configure_txpp_misc(la_slice_id_t slice_id);
    void configure_txpp_misc_slice_type(la_slice_id_t slice_id);
    void configure_txpp_features_according_to_source_slice(la_slice_id_t slice_id);
    void configure_txpp_macro_id_tcam_key_construction(la_slice_id_t slice_id);
    void configure_txpp_cud_mapping(la_slice_id_t slice_id);
    void configure_txpp_ibm(la_slice_id_t slice_id);
    void configure_txpp_pre_edit_command(la_slice_id_t slice_id);
    void configure_txpp_congestion_level_per_tm_header(la_slice_id_t slice_id);
    void configure_txpp_performance_tune(la_slice_id_t slice_id);
    // Gibraltar A1 changes
    void configure_txpp_spare_reg(la_slice_id_t slice_id);

    // NPUH
    ////////////////////////
    void configure_npuh();

    la_status configure_ifgb_packet_rate_shaper(la_slice_id_t slice_id, la_ifg_id_t ifg_id);

    void configure_npe_timeout_threshold(la_slice_id_t slice_id);

    void flc_set_rand_em_seed(la_slice_id_t slice_id);
    void flc_set_default_delete_params(la_slice_id_t slice_id, size_t aging_cycle_value);
    void disable_flow_cache_delete_mechanisms(la_slice_id_t slice_id);
    void flc_enable_or_disable_aging_deletes(la_slice_id_t slice_id, bool enable, uint32_t aging_cycle_value);
    void flc_enable_or_disable_random_deletes(la_slice_id_t slice_id, bool enable, uint32_t del_percent);

    void init_lists();
    la_status write_lists();

    la_status config_dbc_logical_db_mapping();

private:
    // Low level device access
    la_device_impl_wptr m_device;
    ll_device_sptr m_ll_device;
    gibraltar_tree_wcptr m_tree;

    // Slice configuration
    std::vector<slice_config> m_slice_config;

    // Data to write
    lld_register_value_list_t m_reg_vals;
    lld_memory_value_list_t m_mem_vals;
    lld_memory_line_value_list_t m_mem_line_vals;
    tcam_line_value_list_t m_tcam_line_vals;

    npu_static_config() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif // __RA_NPU_STATIC_CONFIG_GB_H__
