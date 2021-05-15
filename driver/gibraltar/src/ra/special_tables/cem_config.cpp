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

#include "cem_config.h"
#include "em_utils.h"

#include "common/defines.h"
#include "common/logger.h"

#include "hw_tables/em_common.h"

#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"

#include "lld/ll_device.h"

#include "nplapi/npl_constants.h"

namespace silicon_one
{

//**************************************
// cem_config
//**************************************
cem_config::cem_config(const ll_device_sptr& ldevice)
    : m_cem_parameters(cem::cem_parameters::get_params(ldevice->get_device_revision()))
{
}

la_status
cem_config::configure_hw(const ll_device_sptr& ldevice) const
{
    la_status status = LA_STATUS_SUCCESS;
    gibraltar_tree_scptr tree = ldevice->get_gibraltar_tree_scptr();

    // Update key width per table
    size_t keys_num = em_utils::get_num_keys(DATABASE_CENTRAL_EM);
    size_t key_width_reg_field = em_utils::get_key_option_register_field_width(keys_num);
    bit_vector key_width_reg(0, key_width_reg_field * em_utils::MAX_TABLES_PER_EM);

    for (const table_record& tbl : m_tables) {
        em_utils::add_table_to_per_em_reg(tbl.logical_id, tbl.logical_id_width, keys_num, tbl.key_width_option, key_width_reg);
    }

    // Update group-core map
    // TODO-pacific: Testing implementation: 256 groups - 16 cores. Each 16 consecutive groups are mapped to the same core.
    // TODO-GB: not sure if the /16 is correct. There are more banks, so maybe need to distribute the groups on 28 banks, and not
    // only 16.
    log_debug(RA, "cem_config::configure_hw setting group-core mapping");
    for (size_t group_idx = 0; group_idx < tree->cdb->top->cem_group_map_table->size(); ++group_idx) {
        gibraltar::cdb_top_cem_group_map_table_register core_map = {.u8 = {0}};
        core_map.fields.group_to_em_map = group_idx / 16;
        status = ldevice->write_register((*tree->cdb->top->cem_group_map_table)[group_idx], core_map);
        return_on_error(status);
    }

    log_debug(RA, "cem_config::configure_hw setting learn mode");
    gibraltar::cdb_top_learn_manager_ldb_cfg_register learn_mgr_cfg_val = {.u8 = {0}};
    learn_mgr_cfg_val.fields.mact_ldb = NPL_CENTRAL_EM_LDB_MAC_RELAY_DA;
    learn_mgr_cfg_val.fields.mact_ldb_width = NPL_CENTRAL_EM_LDB_MAC_RELAY_DA_LEN;
    status = ldevice->write_register(tree->cdb->top->learn_manager_ldb_cfg, learn_mgr_cfg_val);
    return_on_error(status);

    // NOTE: default learning mode is set to SYSTEM learn
    //
    gibraltar::cdb_top_learn_manager_cfg_max_learn_type_register learn_mgr_type_val = {.u8 = {0}};
    learn_mgr_type_val.fields.local_learning = 0;
    learn_mgr_type_val.fields.system_learning = 1;
    status = ldevice->write_register(tree->cdb->top->learn_manager_cfg_max_learn_type, learn_mgr_type_val);
    return_on_error(status);

    // Initialize age refresh values for age_value 1-5, 7
    // all will be mapped to EM_REFRESH_AGE
    // STATIC values (0 and 6) are not remapped to EM_REFRESH_AGE
    for (size_t age_value_idx = 0; age_value_idx < tree->cdb->top->age_refresh_value_reg->size(); ++age_value_idx) {
        gibraltar::cdb_top_age_refresh_value_reg_register refresh_value = {.u8 = {0}};
        if (age_value_idx == cem_config::EM_NO_AGING_AGE) {
            // map static MAC age_value to EM_NO_AGING_AGE
            refresh_value.fields.age_refresh_value = cem_config::EM_NO_AGING_AGE;
        } else if (age_value_idx == 0) {
            // No re-map for deleted/un-initialized entries
            refresh_value.fields.age_refresh_value = 0;
        } else {
            refresh_value.fields.age_refresh_value = cem_config::EM_REFRESH_AGE;
        }
        status = ldevice->write_register((*tree->cdb->top->age_refresh_value_reg)[age_value_idx], refresh_value);
        return_on_error(status);
    }

    log_debug(RA, "cem_config::configure_hw register tables to CDB_TOP");
    status = ldevice->write_register(tree->cdb->top->em_key_width, key_width_reg);
    return_on_error(status);

    log_debug(RA, "cem_config::configure_hw set top active banks");
    for (size_t core_idx = 0; core_idx < tree->cdb->top->active_banks->size(); ++core_idx) {
        status = ldevice->write_register((*tree->cdb->top->active_banks)[core_idx], m_cem_parameters.banks_configuration);
        return_on_error(status);
    }

    // Update full cores
    for (auto& core : tree->cdb->core) {
        log_debug(RA, "cem_config::configure_hw configure full core");
        status = write_cdb_core_config(ldevice, core, key_width_reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

void
cem_config::add_table(size_t table_id, size_t logical_id, size_t logical_id_width, size_t key_width_option)
{
    table_record table_rec;

    table_rec.table_id = table_id;
    table_rec.logical_id = logical_id;
    table_rec.logical_id_width = logical_id_width;
    table_rec.key_width_option = key_width_option;

    m_tables.push_back(table_rec);
}

bit_vector
cem_config::get_active_banks() const
{
    return m_cem_parameters.banks_configuration;
}

la_status
cem_config::set_rc5_seed(const ll_device_sptr& ldevice, const lld_register_array_sptr& em_hash_reg) const
{
    size_t cem_primary_key_width = em_utils::get_primary_key_width(DATABASE_CENTRAL_EM);

    for (size_t bank_idx = 0; bank_idx < m_cem_parameters.num_banks; ++bank_idx) {
        bit_vector rc5_seed = em::generate_pseudo_rc5(cem_primary_key_width, bank_idx);
        la_status status = ldevice->write_register((*em_hash_reg)[bank_idx], rc5_seed);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

template <class CDB_CORE>
la_status
cem_config::write_cdb_core_config(const ll_device_sptr& ldevice, const CDB_CORE& core, const bit_vector& key_width_reg) const
{
    // Update key_width register
    la_status status = ldevice->write_register(core->em_key_width, key_width_reg);
    return_on_error(status);

    // EM configuration:
    // CEM banks are accessed by HW (learn module) and ARC.
    // Access priority is granted to HW, means that ARC cannot access the data if banks is busy with HW.
    // Therefore, ARC can access banks only if HW does not access on the same cycle (aka bubble).
    // If HW access does not have bubbles, these are automatically generated according to bubble_threshold parameter.
    // bubble_req_threshold - number of cycles, after which a bubble will be generated to allow ARC access.
    // auto_bubble_req_en - if on, bubble will be generated every 'threshold' cycles, regardless whether bubbles occured in between.
    //                      if off, bubble will be generated after at most 'threshold' cycles.
    //
    // EM configuration register structure:
    // bits [16:1]  - bubble_req_threshold
    // bit [0]      - auto_bubble_req_en
    gibraltar::cdb_core_em_configurations_register em_config_reg;
    em_config_reg.fields.auto_bubble_req_en = 0;
    em_config_reg.fields.bubble_req_threshold = 15;
    status = ldevice->write_register(core->em_configurations, em_config_reg);
    return_on_error(status);

    bit_vector per_em_config_reg(0, m_cem_parameters.num_banks * 2);
    // Per em configuration register structure:
    // bits[15:0]   - active banks
    // bits[31:16]  - use primitive polynoms
    //
    // Don't use primitive polynoms for EM calculation. See hw_tables/crc_divisors.h for details.
    per_em_config_reg.set_bits(m_cem_parameters.num_banks - 1, 0, m_cem_parameters.banks_configuration);

    // Two LPM/CEM cores per CDB core
    //
    // Core0
    // write per_em config
    status = ldevice->write_register((*core->per_em_configurations)[0], per_em_config_reg);
    return_on_error(status);

    // update hash register
    status = set_rc5_seed(ldevice, core->hash_key_em0);
    return_on_error(status);

    // Core1
    // write per_em config
    status = ldevice->write_register((*core->per_em_configurations)[1], per_em_config_reg);
    return_on_error(status);

    // update hash register
    status = set_rc5_seed(ldevice, core->hash_key_em1);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
