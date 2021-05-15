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

#ifndef __RA_NPU_STATIC_CONFIG_H__
#define __RA_NPU_STATIC_CONFIG_H__

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
class pacific_tree;

/// @brief Device static configuration
///
class npu_static_config
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    enum {
        NPU_HEADER_WIDTH_IN_BYTES = 40,
        NPU_SOFT_HEADER_WIDTH_IN_BYTES = 32,
    };

    enum slice_work_mode_e {
        SLICE_WORK_MODE_FABRIC = 0,
        SLICE_WORK_MODE_NETWORK,
    };

    enum sna_slice_mode_e {
        SNA_SLICE_MODE_DISABLE_CENTRAL_SNA = 0,
        SNA_SLICE_MODE_CRF_FABRIC_SLICE = 1,
        SNA_SLICE_MODE_TOR_SLB_SLICE = 2,
    };

    enum fs_profiles_e {
        LB_FS_DEFAULT_PROFILE = 0,
        LB_FS_IPV4_DOUBLE_SIP_DIP_PROFILE = 1,
        LB_FS_IPV6_EXTRA_PARTIAL_DIP_PROFILE = 2,
    };

    struct slice_config {
        slice_work_mode_e slice_mode;    ///< Fabric or Network.
        sna_slice_mode_e sna_slice_mode; ///< Sequence-number assignment slice mode.
        bool is_slb_enabled;             ///< Network slice with SLB enabled.
        bool is_egress_tor;              ///< Egress TOR slice.
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
    void configure_rxpp_slice_mode(la_slice_id_t slice_id);
    void configure_rxpp_npu_header(la_slice_id_t slice_id);
    void configure_rxpp_fi(la_slice_id_t slice_id);
    // Database access configuration
    void configure_rxpp_cdb(la_slice_id_t slice_id);
    void configure_rxpp_tunnel_termination_two_lookups(la_slice_id_t slice_id);
    void configure_rxpp_db_connectivity(la_slice_id_t slice_id);
    // Load balancing
    void configure_rxpp_res_lb_header_type_mapping(la_slice_id_t slice_id);
    void configure_rxpp_lb(la_slice_id_t slice_id);

    // SNA
    ////////////////////////
    void configure_rxpp_sna(la_slice_id_t slice_id);
    void configure_rxpp_sna_flow_signature(la_slice_id_t slice_id);

    // Pacific B0 changes
    void configure_rxpp_pacific_B0_and_B1_changes(la_slice_id_t slice_id);

    // SDB
    ////////////////////////
    void configure_sdb();

    // CDB
    ////////////////////////
    void configure_cdb();
    void configure_cdb_cache_spare_reg(la_slice_id_t slice_id);

    // IDB
    ////////////////////////
    void configure_idb(la_slice_pair_id_t slice_pair_id);
    void configure_idb_spare_reg(la_slice_pair_id_t slice_pair_id);

    // TXPP
    ////////////////////////
    void configure_txpp(la_slice_id_t slice_id);

    void configure_txpp_npe(la_slice_id_t slice_id);
    void configure_txpp_db_connectivity(la_slice_id_t slice_id);
    void configure_txpp_vlan_editing_control(la_slice_id_t slice_id);
    void configure_txpp_header_type_and_size(la_slice_id_t slice_id);
    void configure_txpp_misc(la_slice_id_t slice_id);
    void configure_txpp_misc_slice_type(la_slice_id_t slice_id);
    void configure_txpp_ptp(la_slice_id_t slice_id);
    void configure_txpp_second_encap_type_offset(la_slice_id_t slice_id);
    void configure_txpp_cud_mapping(la_slice_id_t slice_id);
    void configure_txpp_ibm(la_slice_id_t slice_id);

    // TODO: this workaround till we decide how to init default values.
    // This table is accessed twice on macro. Second time on uninitialized entry.
    void configure_txpp_dlp_profile_table(la_slice_id_t slice_id);

    // Pacific B0 changes
    void configure_txpp_spare_reg(la_slice_id_t slice_id);

    // NPUH
    ////////////////////////
    void configure_npuh();

    // Scanners
    ////////////////////////
    la_status configure_npuh_scanners();

    void init_lists();
    la_status write_lists();

private:
    // Low level device access
    la_device_impl_wptr m_device;
    ll_device_sptr m_ll_device;
    pacific_tree_wcptr m_tree;

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

#endif // __RA_NPU_STATIC_CONFIG_H__
