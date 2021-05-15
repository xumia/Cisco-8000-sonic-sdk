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

#ifndef __RA_RESOURCE_MANAGER_H__
#define __RA_RESOURCE_MANAGER_H__

#include "../../src/hw_tables/ctm/ctm_common.h"
#include "api/types/la_acl_types.h"
#include "api/types/la_system_types.h"
#include "hw_tables/cem.h"
#include "hw_tables/hw_tables_fwd.h"
#include "hw_tables/logical_em.h"
#include "hw_tables/lpm_settings.h"
#include "hw_tables/physical_locations.h"
#include "nplapi/npl_enums.h"
#include "ra/ra_types.h"
#include "ra/ra_types_fwd.h"

namespace silicon_one
{
class ll_device;
class lld_register;

/// @brief Resource manager for special and EM tables.
///
/// This object defines the HW resources used by:
/// 1. Exact match tables.
/// 2. Configurable-size tables. (npl_lp_attributes, LPM, MAC table etc).
///
/// It provides the table initialization flow with HW resource information for each table.
///
/// Settings for configurable tables should be performed before the table initialization flow is run.
/// Hardware EM tables are updated after table initialization flow is complete, once all logical EM-s using a single HW EM are
/// known.

class resource_manager
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    enum resolution_lp_db {
        RESOLUTION_LP_DB_NATIVE, // native_l2_and_lp_db
        RESOLUTION_LP_DB_PATH,   // path_lp
        RESOLUTION_LP_DB_LAST = RESOLUTION_LP_DB_PATH,
    };

    // C'tor
    resource_manager(const ll_device_sptr& ldevice);

    // D'tor
    ~resource_manager();

    // forbid copy
    resource_manager(const resource_manager&) = delete;
    resource_manager& operator=(const resource_manager&) = delete;

    /// @brief Set device mode.
    ///
    /// @param[in]      is_fabric       Is device FE.
    void set_device_mode(bool is_fabric);

    /// @brief Initialize CTM.
    ///
    void init_ctm(bool is_linecard_mode, size_t number_of_slices);

    /// @brief Enable HBM usage for LPM.
    ///
    /// Assumed that the device is HBM enabled.
    ///
    /// @param[in]  val     Enable/disable HBM LPM usage.
    void enable_lpm_hbm(bool val);

    /// @brief Set max number of bucket in LPM L2 SRAM.
    ///
    /// This is used for testing only.
    ///
    /// @param[in]  val     Number of buckets.
    ///
    /// @return #la_status.
    la_status set_lpm_max_number_of_l2_sram_buckets(size_t val);

    /// @brief Set number of banksets of each LPM core's TCAM.
    ///
    /// @param[in] val      Number of banksets.
    void set_lpm_tcam_num_banksets(size_t val);

    /// @brief Set number of rows in each LPM TCAM bank.
    ///
    /// This is used for testing only.
    ///
    /// @param[in] val      Number of rows in bank.
    void set_lpm_tcam_bank_size(size_t val);

    /// @brief Set LPM's rebalance interval.
    ///
    /// @param[in]  val     Rebalance interval (number of actions between rebalance runs).
    void set_lpm_rebalance_interval(size_t val);

    /// @brief Set LPM's start balancing threshold.
    ///
    /// @param[in]  val     Rebalance start threshold (Percentage of deviation between least/most utilized cores).
    void set_lpm_rebalance_start_fairness_threshold(double val);

    /// @brief Set LPM's end balancing threshold.
    ///
    /// @param[in]  val     Rebalance end threshold (Percentage of deviation between least/most utilized cores).
    void set_lpm_rebalance_end_fairness_threshold(double val);

    /// @brief Set load of a single width key on LPM TCAM.
    ///
    /// @param[in]  val      Weighted load of a single width key on LPM TCAM.
    void set_lpm_tcam_single_width_key_weight(size_t val);

    /// @brief Set load of a double width key on LPM TCAM.
    ///
    /// @param[in]  val      Weighted load of a double width key on LPM TCAM.
    void set_lpm_tcam_double_width_key_weight(size_t val);

    /// @brief Set load of a quad width key on LPM TCAM.
    ///
    /// @param[in]  val      Weighted load of a quad width key on LPM TCAM.
    void set_lpm_tcam_quad_width_key_weight(size_t val);

    /// @brief Get initialized configuration object for Native/Path LP tables.
    ///
    /// @retval     pointer to the initialized configuration object.
    const resolution_lp_config_scptr& get_resolution_lp_config(resolution_lp_db db) const;

    /// @brief Get initialized configuration object for Service LP attributes table.
    ///
    /// @retval     pointer to the initialized configuration object.
    const service_lp_attribute_config_scptr& get_service_lp_attribute_config() const;

    /// @brief Get initialized configuration object for Service Mapping tables.
    ///
    /// @retval     pointer to the initialized configuration object.
    const service_mapping_config_scptr& get_service_mapping_config() const;

    /// @brief Get initialized configuration object for Large Encapsulation DB tables.
    ///
    /// @retval     pointer to the initialized configuration object.
    const large_enc_db_config_scptr& get_large_enc_db_config() const;

    /// @brief Get initialized configuration object for CEM DB tables.
    ///
    /// @retval     pointer to the initialized configuration object.
    const cem_config_scptr& get_cem_config() const;

    /// @brief Get initialized configuration object for LPM.
    ///
    /// @retval     pointer to the initialized configuration object.
    const lpm_config_scptr& get_lpm_config() const;

    /// @retval     pointer to the configuration mgr object.
    const ctm_mgr_sptr& get_ctm_mgr();
    bool get_table_map(size_t npl_table_id, ctm::group_desc::group_ifs_e& interface_out, size_t& logical_id_out);

    /// @brief Get logical_lpm object.
    ///
    /// @retval     pointer to logical_lpm object.
    const logical_lpm_sptr& get_lpm();

    /// @brief Get cem object.
    ///
    /// @retval     pointer to cem object.
    const cem_sptr& get_cem();

    /// @brief Get EM DB object for a given slice or slice pair.
    ///
    /// @param[in]    type                      which db
    /// @param[in]    slice_or_slice_pair_id    Slice or slice pair id.
    ///
    /// @retval       pointer to logical_em object EM DB for given slice or slice pair.
    logical_em_wptr get_em_db(la_resource_descriptor::type_e type, size_t slice_or_slice_pair_id);

    /// @brief Set EM DB object for a given slice or slice pair in resource manager.
    ///
    /// @param[in]    type                      which db
    /// @param[in]    em_db                     pointer to logical_em for large_enc_em_db.
    /// @param[in]    slice_or_slice_pair_id    Slice pair id.
    ///
    /// @retval       status code.
    la_status set_em_db(la_resource_descriptor::type_e type, const logical_em_wptr& em_db, size_t slice_or_slice_pair_id);

    /// @brief Get MC_EMDB object.
    ///
    /// @retval       pointer to logical_em object for mc_emdb.
    const logical_em_wptr& get_mc_emdb();

    /// @brief Set MC_EMDB object in resource manager.
    ///
    /// @param[in]    mc_emdb            pointer to logical_em for mc_emdb.
    ///
    /// @retval       status code.
    la_status set_mc_emdb(const logical_em_wptr& mc_emdb);

    /// @brief Callback to allow polling LPM-HBM stats.
    void lpm_hbm_collect_stats();

    /// @brief Callback to allow performing LPM-HBM caching.
    void lpm_hbm_do_caching();

    /// @brief Callback to clear and unmask L2 ECC error registers.
    ///
    /// In Pacific, false ECC error notification is raised when writing to LPM.
    /// This function is part of the WA to fix it.
    ///
    /// @note This is called periodically by the poller thread.
    void lpm_unmask_and_clear_l2_ecc_interrupt_registers();

    /// @brief Configure LPM in HBM after soft-reset
    la_status lpm_hbm_config();

    /// @brief Update CEM utilization data by reading core usage
    /// from ARC
    ///
    /// @note This is called periodically by the poller thread.
    void update_cem_size();

    /// @brief If an entry was deleted then there is a possibility to evacuate CAM entry to SRAM.
    /// Each call check the next relevant CAM entry and try to evacuate it
    ///
    /// @note This is called periodically by the poller thread on Pacific.
    void cem_cam_evacuation();

private:
    static constexpr size_t UNINITIALIZED_VALUE = std::numeric_limits<size_t>::max();

    friend ra_translator_creator;

    /// @brief Initialize HW resources before NPL tables initialization.
    ///
    /// @retval     status code.
    la_status pre_table_init();

    /// @brief Initialize HW resources after NPL tables initialization.
    ///
    /// @retval     status code.
    la_status post_table_init();

    /// @brief Register new NPL table in Exact Match core.
    ///
    /// @param[in]  em                      Physical EM.
    /// @param[in]  key_width_idx           EM key option to be used by the provided table.
    /// @param[in]  logical_table_id_columns_values      consts of
    /// the NPL table to be placed on the given EM key.
    ///
    /// @retval     status code.
    la_status register_em_table(const physical_em& em,
                                size_t key_width_idx,
                                const logical_table_id_columns_values_t& logical_table_id_columns_values);

    /// @brief Register Exact Batch banks.
    ///
    /// @param[in]  em                      Physical EM.
    ///
    /// @retval     status code.
    la_status register_em_banks(const physical_em& em);

    /// @brief Update parameters that have changed.
    ///
    /// @param[in]  settings         Lpm const parameters.
    void update_lpm_settings(lpm_settings& settings) const;

private:
    resource_manager() = default;

    // Low Level device
    ll_device_sptr m_ll_device;

    // Device mode
    bool m_is_fabric_device;

    // Configuration options
    bool m_hbm_lpm_enabled;
    size_t m_lpm_max_number_of_l2_sram_buckets;
    size_t m_lpm_rebalance_interval;
    double m_lpm_rebalance_start_fairness_threshold;
    double m_lpm_rebalance_end_fairness_threshold;
    size_t m_lpm_tcam_single_width_key_weight; ///< Wait of a single width Key for the purpose of LPM rebalance.
    size_t m_lpm_tcam_double_width_key_weight; ///< Wait of a double width Key for the purpose of LPM rebalance.
    size_t m_lpm_tcam_quad_width_key_weight;   ///< Wait of a quad width Key for the purpose of LPM rebalance.
    size_t m_lpm_tcam_num_banksets;
    size_t m_lpm_tcam_bank_size;

    // Special Table configuration

    resolution_lp_config_scptr m_resolution_lp_config[RESOLUTION_LP_DB_LAST + 1];
    service_lp_attribute_config_scptr m_service_lp_attribute_config;
    service_mapping_config_scptr m_service_mapping_config;
    large_enc_db_config_scptr m_large_enc_db_config;
    cem_config_scptr m_cem_config;
    lpm_config_scptr m_lpm_config;

    // ctm mgr
    ctm_mgr_sptr m_ctm_mgr;
    ra_ternary_table_mapping_sptr m_table_mapping;

    // Logical LPM singelton
    logical_lpm_sptr m_lpm;

    // CEM singleton
    cem_sptr m_cem;

    // LARGE_ENCAP_EM
    vector_alloc<logical_em_wptr> m_large_enc_em_db;

    // SMALL_ENCAP_EM
    vector_alloc<logical_em_wptr> m_small_enc_em_db;

    // Egress encap DBs for AKPG
    vector_alloc<logical_em_wptr> m_egress_enc_em0_db;
    vector_alloc<logical_em_wptr> m_egress_enc_em1_db;
    vector_alloc<logical_em_wptr> m_egress_enc_em2_db;
    vector_alloc<logical_em_wptr> m_egress_enc_em3_db;
    vector_alloc<logical_em_wptr> m_egress_enc_em4_db;
    vector_alloc<logical_em_wptr> m_egress_enc_em5_db;

    // L3_DLP0_EM
    vector_alloc<logical_em_wptr> m_l3_dlp0_em_db;

    // TUNNEL_0_EM
    vector_alloc<logical_em_wptr> m_tunnel_0_em_db;
    vector_alloc<logical_em_wptr> m_tunnel_1_em_db;

    // MC_EMDB
    logical_em_wptr m_mc_emdb;
};

} // namespace silicon_one

#endif // __RA_RESOURCE_MANAGER_H__
