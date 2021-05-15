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

#include "ra/resource_manager.h"
#include "ra_ternary_table_mapping.h"
#include "special_tables/cem_config.h"
#include "special_tables/ctm_mgr_tcam.h"
#include "special_tables/lpm_config.h"
#include "special_tables/resolution_lp_sram.h"
#include "special_tables/service_lp_attribute_config.h"

#include "hw_tables/cem.h"
#include "hw_tables/logical_em.h"
#include "hw_tables/logical_lpm.h"
#include "hw_tables/lpm_settings.h"

#include "em_utils.h"
#include "engine_block_mapper.h"

#include "common/defines.h"
#include "common/logger.h"
#include "lld/ll_device.h"

#include "nplapi/npl_constants.h"
#include "nplapi/npl_enums.h"
#include "nplapi/npl_tables_enum.h"

#include "common/gen_utils.h"

#include "api/types/la_acl_types.h"
#include "api/types/la_system_types.h"
#include "ra/ra_types_fwd.h"

namespace silicon_one
{

//******************************
// AUX functions
//******************************
cem_config_sptr
create_cem_config(const ll_device_sptr ldevice)
{
    cem_config_sptr config = std::make_shared<cem_config>(ldevice);

    // IPV4
    config->add_table(NPL_TABLES_IPV4_VRF_DIP_EM_TABLE,
                      NPL_CENTRAL_EM_LDB_IPV4_VRF_DIP,
                      NPL_CENTRAL_EM_LDB_IPV4_VRF_DIP_LEN,
                      cem_config::CEM_KEY_WIDTH_OPT_46);

    config->add_table(NPL_TABLES_IPV4_OG_PCL_EM_TABLE,
                      NPL_CENTRAL_EM_LDB_IPV4_VRF_DIP,
                      NPL_CENTRAL_EM_LDB_IPV4_VRF_DIP_LEN,
                      cem_config::CEM_KEY_WIDTH_OPT_46);

    config->add_table(NPL_TABLES_IPV4_VRF_S_G_TABLE,
                      NPL_CENTRAL_EM_LDB_IPV4_VRF_S_G,
                      NPL_CENTRAL_EM_LDB_IPV4_VRF_S_G_LEN,
                      cem_config::CEM_KEY_WIDTH_OPT_142);

    // IPV6
    config->add_table(NPL_TABLES_IPV6_VRF_DIP_EM_TABLE,
                      NPL_CENTRAL_EM_LDB_IPV6_VRF_DIP,
                      NPL_CENTRAL_EM_LDB_IPV6_VRF_DIP_LEN,
                      cem_config::CEM_KEY_WIDTH_OPT_142);

    config->add_table(NPL_TABLES_IPV6_OG_PCL_EM_TABLE,
                      NPL_CENTRAL_EM_LDB_IPV6_VRF_DIP,
                      NPL_CENTRAL_EM_LDB_IPV6_VRF_DIP_LEN,
                      cem_config::CEM_KEY_WIDTH_OPT_142);

    config->add_table(NPL_TABLES_IPV6_VRF_S_G_TABLE,
                      NPL_CENTRAL_EM_LDB_IPV6_VRF_S_G,
                      NPL_CENTRAL_EM_LDB_IPV6_VRF_S_G_LEN,
                      cem_config::CEM_KEY_WIDTH_OPT_142);

    // Forwarding
    config->add_table(NPL_TABLES_MAC_FORWARDING_TABLE,
                      NPL_CENTRAL_EM_LDB_MAC_RELAY_DA,
                      NPL_CENTRAL_EM_LDB_MAC_RELAY_DA_LEN,
                      cem_config::CEM_KEY_WIDTH_OPT_78);

    config->add_table(NPL_TABLES_MAC_FORWARDING_W_METADATA_TABLE,
                      NPL_CENTRAL_EM_LDB_MAC_RELAY_DA_W_MD,
                      NPL_CENTRAL_EM_LDB_MAC_RELAY_DA_W_MD_LEN,
                      cem_config::CEM_KEY_WIDTH_OPT_78);

    config->add_table(NPL_TABLES_MPLS_FORWARDING_TABLE,
                      NPL_CENTRAL_EM_LDB_MPLS_FWD,
                      NPL_CENTRAL_EM_LDB_MPLS_FWD_LEN,
                      cem_config::CEM_KEY_WIDTH_OPT_46);

    return config;
}

//******************************
// resource_manager
//******************************
constexpr size_t MAX_L2_SRAM_BUCKETS = 4096;

resource_manager::resource_manager(const ll_device_sptr& ldevice)
    : m_ll_device(ldevice),
      m_is_fabric_device(false),
      m_hbm_lpm_enabled(false),
      m_lpm_max_number_of_l2_sram_buckets(UNINITIALIZED_VALUE),
      m_lpm_tcam_single_width_key_weight(UNINITIALIZED_VALUE),
      m_lpm_tcam_double_width_key_weight(UNINITIALIZED_VALUE),
      m_lpm_tcam_quad_width_key_weight(UNINITIALIZED_VALUE),
      m_lpm_tcam_num_banksets(1),
      m_lpm_tcam_bank_size(UNINITIALIZED_VALUE)
{
    dassert_crit(ldevice);

    m_cem_config = create_cem_config(ldevice);

    m_lpm_config = std::make_shared<const lpm_config>();

    m_ctm_mgr = nullptr;
    m_lpm = nullptr;
    m_cem = nullptr;
    m_large_enc_em_db.resize(engine_block_mapper::NUM_SLICE_PAIRS_PER_DEVICE);
    m_small_enc_em_db.resize(engine_block_mapper::NUM_SLICE_PAIRS_PER_DEVICE);
    m_l3_dlp0_em_db.resize(engine_block_mapper::NUM_SLICE_PAIRS_PER_DEVICE);
    m_tunnel_0_em_db.resize(engine_block_mapper::ASIC_MAX_SLICES_PER_DEVICE_NUM);
    m_mc_emdb = nullptr;
}

resource_manager::~resource_manager()
{
}

void
resource_manager::set_device_mode(bool is_fabric)
{
    m_is_fabric_device = is_fabric;
}

void
resource_manager::init_ctm(bool is_linecard_mode, size_t number_of_slices)
{
    m_ctm_mgr = std::make_shared<ctm_mgr_tcam>(m_ll_device,
                                               is_linecard_mode,
                                               m_lpm_tcam_num_banksets,
                                               engine_block_mapper(m_ll_device->get_gibraltar_tree_scptr()),
                                               ctm::NUM_SLICES);

    m_table_mapping = std::make_shared<ra_ternary_table_mapping>(m_ll_device);
    m_table_mapping->update_mapping();
}

bool
resource_manager::get_table_map(size_t npl_table_id, ctm::group_desc::group_ifs_e& interface_out, size_t& logical_id_out)
{
    ra_ternary_table_mapping::table_to_group_desc table_map;
    bool is_valid = m_table_mapping->get_table_mapping(npl_table_id, table_map);
    if (is_valid) {
        interface_out = table_map.m_interface;
        logical_id_out = table_map.logical_id;
    }
    return is_valid;
}
void
resource_manager::enable_lpm_hbm(bool val)
{
    m_hbm_lpm_enabled = val;
}

la_status
resource_manager::set_lpm_max_number_of_l2_sram_buckets(size_t val)
{
    if ((val == 0) || (val > MAX_L2_SRAM_BUCKETS)) {
        return LA_STATUS_EOUTOFRANGE;
    }
    m_lpm_max_number_of_l2_sram_buckets = val;
    return LA_STATUS_SUCCESS;
}

void
resource_manager::set_lpm_tcam_num_banksets(size_t val)
{
    m_lpm_tcam_num_banksets = val;
}

void
resource_manager::set_lpm_tcam_bank_size(size_t val)
{
    m_lpm_tcam_bank_size = val;
}

void
resource_manager::set_lpm_rebalance_interval(size_t val)
{
    m_lpm_rebalance_interval = val;
    if (m_lpm != nullptr) {
        m_lpm->set_rebalance_interval(val);
    }
}

void
resource_manager::set_lpm_rebalance_start_fairness_threshold(double val)
{
    m_lpm_rebalance_start_fairness_threshold = val;
    if (m_lpm != nullptr) {
        m_lpm->set_rebalance_start_fairness_threshold(m_lpm_rebalance_start_fairness_threshold);
    }
}

void
resource_manager::set_lpm_rebalance_end_fairness_threshold(double val)
{
    m_lpm_rebalance_end_fairness_threshold = val;
    if (m_lpm != nullptr) {
        m_lpm->set_rebalance_end_fairness_threshold(m_lpm_rebalance_end_fairness_threshold);
    }
}

void
resource_manager::set_lpm_tcam_single_width_key_weight(size_t val)
{
    m_lpm_tcam_single_width_key_weight = val;
}

void
resource_manager::set_lpm_tcam_double_width_key_weight(size_t val)
{
    m_lpm_tcam_double_width_key_weight = val;
}

void
resource_manager::set_lpm_tcam_quad_width_key_weight(size_t val)
{
    m_lpm_tcam_quad_width_key_weight = val;
}

const service_lp_attribute_config_scptr&
resource_manager::get_service_lp_attribute_config() const
{
    return m_service_lp_attribute_config;
}

const service_mapping_config_scptr&
resource_manager::get_service_mapping_config() const
{
    return m_service_mapping_config;
}

const large_enc_db_config_scptr&
resource_manager::get_large_enc_db_config() const
{
    return m_large_enc_db_config;
}

const cem_config_scptr&
resource_manager::get_cem_config() const
{
    return m_cem_config;
}

const lpm_config_scptr&
resource_manager::get_lpm_config() const
{
    return m_lpm_config;
}

const ctm_mgr_sptr&
resource_manager::get_ctm_mgr()
{
    return m_ctm_mgr;
}

const logical_lpm_sptr&
resource_manager::get_lpm()
{
    return m_lpm;
}

const cem_sptr&
resource_manager::get_cem()
{
    return m_cem;
}

logical_em_wptr
resource_manager::get_em_db(la_resource_descriptor::type_e type, size_t slice_or_slice_pair_id)
{
    vector_alloc<logical_em_wptr>* em_db_vector = nullptr;

    switch (type) {
    case la_resource_descriptor::type_e::EGRESS_LARGE_ENCAP_EM:
        em_db_vector = &m_large_enc_em_db;
        break;
    case la_resource_descriptor::type_e::EGRESS_SMALL_ENCAP_EM:
        em_db_vector = &m_small_enc_em_db;
        break;
    case la_resource_descriptor::type_e::EGRESS_L3_DLP0_EM:
        em_db_vector = &m_l3_dlp0_em_db;
        break;
    case la_resource_descriptor::type_e::TUNNEL_0_EM:
        em_db_vector = &m_tunnel_0_em_db;
        break;
    // The following EM DBs are only used for AKPG
    case la_resource_descriptor::type_e::EGRESS_ENC_EM0:
    case la_resource_descriptor::type_e::EGRESS_ENC_EM1:
    case la_resource_descriptor::type_e::EGRESS_ENC_EM2:
    case la_resource_descriptor::type_e::EGRESS_ENC_EM3:
    case la_resource_descriptor::type_e::EGRESS_ENC_EM4:
    case la_resource_descriptor::type_e::EGRESS_ENC_EM5:
    case la_resource_descriptor::type_e::TUNNEL_1_EM:
    default:
        dassert_crit(false);
        return nullptr;
    }

    if (slice_or_slice_pair_id >= em_db_vector->size()) {
        return nullptr;
    }

    return (*em_db_vector)[slice_or_slice_pair_id];
}

la_status
resource_manager::set_em_db(la_resource_descriptor::type_e type, const logical_em_wptr& em_db, size_t slice_or_slice_pair_id)
{
    vector_alloc<logical_em_wptr>* em_db_vector = nullptr;

    switch (type) {
    case la_resource_descriptor::type_e::EGRESS_LARGE_ENCAP_EM:
        em_db_vector = &m_large_enc_em_db;
        break;
    case la_resource_descriptor::type_e::EGRESS_SMALL_ENCAP_EM:
        em_db_vector = &m_small_enc_em_db;
        break;
    case la_resource_descriptor::type_e::EGRESS_L3_DLP0_EM:
        em_db_vector = &m_l3_dlp0_em_db;
        break;
    case la_resource_descriptor::type_e::TUNNEL_0_EM:
        em_db_vector = &m_tunnel_0_em_db;
        break;
    // The following EM DBs are only used for AKPG
    case la_resource_descriptor::type_e::EGRESS_ENC_EM0:
    case la_resource_descriptor::type_e::EGRESS_ENC_EM1:
    case la_resource_descriptor::type_e::EGRESS_ENC_EM2:
    case la_resource_descriptor::type_e::EGRESS_ENC_EM3:
    case la_resource_descriptor::type_e::EGRESS_ENC_EM4:
    case la_resource_descriptor::type_e::EGRESS_ENC_EM5:
    case la_resource_descriptor::type_e::TUNNEL_1_EM:
    default:
        dassert_crit(false);
        return LA_STATUS_EINVAL;
    }

    if (slice_or_slice_pair_id >= em_db_vector->size()) {
        return LA_STATUS_EINVAL;
    }

    (*em_db_vector)[slice_or_slice_pair_id] = em_db;

    return LA_STATUS_SUCCESS;
}

const logical_em_wptr&
resource_manager::get_mc_emdb()
{
    return m_mc_emdb;
}

la_status
resource_manager::set_mc_emdb(const logical_em_wptr& mc_emdb)
{
    m_mc_emdb = mc_emdb;

    return LA_STATUS_SUCCESS;
}

void
resource_manager::update_lpm_settings(lpm_settings& settings) const
{
    if (m_hbm_lpm_enabled) {
        settings.l2_buckets_per_sram_row = 1;
        settings.l2_max_number_of_hbm_buckets = 12 * 1024;
    }

    settings.tcam_num_banksets = m_lpm_tcam_num_banksets;

    if (m_lpm_max_number_of_l2_sram_buckets != UNINITIALIZED_VALUE) {
        settings.l2_max_number_of_sram_buckets = m_lpm_max_number_of_l2_sram_buckets;
    }

    if (m_lpm_tcam_bank_size != UNINITIALIZED_VALUE) {
        settings.tcam_bank_size = m_lpm_tcam_bank_size;
    }

    if (m_lpm_tcam_single_width_key_weight != UNINITIALIZED_VALUE) {
        settings.tcam_single_width_key_weight = m_lpm_tcam_single_width_key_weight;
    }

    if (m_lpm_tcam_double_width_key_weight != UNINITIALIZED_VALUE) {
        settings.tcam_double_width_key_weight = m_lpm_tcam_double_width_key_weight;
    }

    if (m_lpm_tcam_quad_width_key_weight != UNINITIALIZED_VALUE) {
        settings.tcam_quad_width_key_weight = m_lpm_tcam_quad_width_key_weight;
    }
}

la_status
resource_manager::pre_table_init()
{
    la_status status;
    if (m_is_fabric_device) {
        m_lpm = create_logical_lpm(m_ll_device);
    } else {
        lpm_settings settings = create_lpm_settings(m_ll_device);
        update_lpm_settings(settings);

        m_lpm = create_logical_lpm(m_ll_device, settings);
        m_lpm->set_rebalance_interval(m_lpm_rebalance_interval);
    }

    m_cem = std::make_shared<cem>(m_ll_device);

    log_debug(RA, "resource_manager::pre_table_init Update CEM configuration");
    status = m_cem_config->configure_hw(m_ll_device);
    return_on_error(status);

    log_debug(RA, "resource_manager::pre_table_init Update LPM configuration");
    status = m_lpm_config->configure_hw(m_ll_device, m_hbm_lpm_enabled, m_lpm_tcam_num_banksets);
    return_on_error(status);

    log_debug(RA, "resource_manager::pre_table_init Update CTM configuration");
    status = m_ctm_mgr->configure_hw();
    return_on_error(status);

    log_debug(RA, "resource_manager::pre_table_init Done");
    return LA_STATUS_SUCCESS;
}

la_status
resource_manager::post_table_init()
{
    return LA_STATUS_SUCCESS;
}

la_status
resource_manager::register_em_table(const physical_em& em,
                                    size_t key_width_idx,
                                    const logical_table_id_columns_values_t& logical_table_id_columns_values)
{
    size_t table_logical_id = 0, table_logical_id_width = 0;
    // logical ID of EM table should always be in the lsb bits of the key
    auto it = logical_table_id_columns_values.find(0);
    if (it != logical_table_id_columns_values.end()) {
        table_logical_id = it->second.get_value();
        table_logical_id_width = it->second.get_width();
    }

    // Register per-core settings.
    for (const lld_register_scptr& config_reg : em.config_regs) {
        const lld_register_desc_t* desc = config_reg->get_desc();
        bit_vector per_em_reg_value(0, desc->width_in_bits);

        la_status status = m_ll_device->read_register(config_reg, per_em_reg_value);
        return_on_error(status);

        em_utils::add_table_to_per_em_reg(
            table_logical_id, table_logical_id_width, em.key_widths.size(), key_width_idx, per_em_reg_value);

        log_debug(RA,
                  "resource_manager::register_em update per_em_reg %s with logical_id: %zd, logical_id_width: %zd",
                  desc->name.c_str(),
                  table_logical_id,
                  table_logical_id_width);
        status = m_ll_device->write_register(config_reg, per_em_reg_value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

void
resource_manager::lpm_hbm_collect_stats()
{
    m_lpm->lpm_hbm_collect_stats();
}

void
resource_manager::lpm_hbm_do_caching()
{
    m_lpm->lpm_hbm_do_caching();
}

void
resource_manager::lpm_unmask_and_clear_l2_ecc_interrupt_registers()
{
    m_lpm->unmask_and_clear_l2_ecc_interrupt_registers();
}

la_status
resource_manager::lpm_hbm_config()
{
    return m_lpm_config->configure_hbm(m_ll_device);
}

void
resource_manager::update_cem_size()
{
    m_cem->update_size();
}

void
resource_manager::cem_cam_evacuation()
{
    m_cem->evacuate();
}

la_status
resource_manager::register_em_banks(const physical_em& em)
{
    // Register per-bank settings.
    for (const physical_em::bank& bank : em.banks) {
        const lld_register_desc_t* desc = bank.config_reg->get_desc();
        bit_vector per_bank_reg_value(0, desc->width_in_bits);

        la_status status = m_ll_device->read_register(*bank.config_reg, per_bank_reg_value);
        return_on_error(status);

        size_t rc5_width = bank.rc5.get_width();
        // rc5 starts from bit #1
        per_bank_reg_value.set_bits(rc5_width, 1, bank.rc5);
        per_bank_reg_value.set_bit(0, bank.is_active);

        log_debug(RA,
                  "resource_manager::register_em update per_bank_reg %s with RC5: %s",
                  desc->name.c_str(),
                  bank.rc5.to_string().c_str());
        status = m_ll_device->write_register(*bank.config_reg, per_bank_reg_value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

const resolution_lp_config_scptr&
resource_manager::get_resolution_lp_config(resolution_lp_db db) const
{
    return m_resolution_lp_config[db];
}

} // namespace silicon_one
