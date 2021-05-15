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

#include "common/dassert.h"
#include <array>
#include <list>
#include <vector>

#include <unistd.h>

#include "api_tracer.h"
#include "la_device_impl.h"

#include "avago_serdes_device_handler.h"
#include "system/device_model_types.h"
#include "system/device_port_handler_pacific.h"
#include "system/dummy_serdes_device_handler_base.h"

#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "lld/interrupt_types.h"
#include "lld/ll_device.h"
#include "lld/lld_utils.h"
#include "lld/pacific_mem_structs.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"

#include "cpu2jtag/cpu2jtag.h"
#include "hld_utils.h"
#include "la_hbm_handler_impl.h"
#include "la_strings.h"
#include "npu_static_config.h"
#include "pacific_pvt_handler.h"
#include "pvt_handler.h"
#include "qos/la_meter_set_impl.h"
#include "system/ifg_handler.h"
#include "system/ifg_handler_pacific.h"
#include "system/la_mac_port_base.h"
#include "system/la_ptp_handler_pacific.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/tm_utils.h"

#include <chrono>
#include <thread>

#include <iostream>

namespace silicon_one
{

static const char SERDES_FILE_NAME[] = "res/serdes.0x109e_208d_0a4.rom";
static const char HBM_FILE_NAME[] = "res/hbm.0x055f_2002.rom";
static const char HBM_FILE_ENVVAR[] = "HBM_FIRMWARE";
static const char HBM_MBIST_FILE_NAME[] = "res/hbm.0x055f_2012.rom";
static const char HBM_MBIST_FILE_ENVVAR[] = "HBM_MBIST_FIRMWARE";
static const char SBUS_MASTER_FILE_NAME[] = "res/sbus_master.0x1024_2001.rom";

enum {
    SERDES_REV = 0x109e,
    SERDES_BUILD = 0x208d,
    SBUS_MASTER_REV = 0x1024,
    SBUS_MASTER_BUILD = 0x2001,
    HBM_REV = 0x55f,
    HBM_BUILD = 0x2002,
    HBM_MBIST_BUILD = 0x2012,

    KIBI = 1024,
    MEBI = 1024 * 1024,
    GIBI = 1024 * 1024 * 1024,
    BYTE_THRESHOLD_RESOLUTION = 256,
};

static void
push_back_ones(lld_register_value_list_t& reg_val_list, lld_register_scptr reg)
{
    reg_val_list.push_back({reg, bit_vector::ones(reg->get_desc()->width_in_bits)});
}

static void
push_back_ones(lld_memory_value_list_t& mem_val_list, lld_memory_scptr mem)
{
    mem_val_list.push_back({mem, bit_vector::ones(mem->get_desc()->width_bits)});
}

la_status
la_device_impl::initialize(init_phase_e phase)
{
    start_api_call("phase=", phase);

    using std::chrono::high_resolution_clock;
    auto t0 = high_resolution_clock::now();

    init_phase_e init_phase = m_init_phase;

    switch (phase) {
    case init_phase_e::DEVICE: {
        if (m_init_phase != init_phase_e::CREATED) {
            return LA_STATUS_EINVAL;
        }

        la_status status = initialize_phase_device();
        return_on_error(status);

        init_phase = init_phase_e::DEVICE;
        break;
    }

    case init_phase_e::TOPOLOGY: {
        if (m_init_phase != init_phase_e::DEVICE) {
            return LA_STATUS_EINVAL;
        }

        la_status status = verify_topology_configuration();
        return_on_error(status);

        status = initialize_device_mode();
        return_on_error(status);

        device_mode_optimized_storage_initialization();

        if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
            // Until this point, reconnect metadata was accumulated, but not written to the device.
            // This is the first time a fresh reconnect metadata is written to the device.
            la_status rc = initialize_reconnect_handler();
            return_on_error(rc);

            status = initialize_fe_mode();
            return_on_error(status);
        }

        // Create translator_creator.
        translator_creator_sptr creator;
        status = create_flow(creator);
        return_on_error(status);

        status = initialize_phase_topology(creator);

        return_on_error(status);

        init_phase = init_phase_e::TOPOLOGY;
        break;
    }

    default:
        return LA_STATUS_EINVAL;
    }

    la_status status = m_reconnect_handler->update_init_phase(init_phase);
    return_on_error(status);

    m_init_phase = init_phase;

    log_debug(API, "Initialization phase %s completed successfully", silicon_one::to_string(phase).c_str());

    auto t1 = high_resolution_clock::now();
    auto delta_time = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);

    std::cout << "BOOT TIME OPT: " << __func__ << " phase: " << silicon_one::to_string(phase) << " execution time "
              << delta_time.count() << " ms" << std::endl;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::clear_meter_block_memories()
{
    const size_t num_of_blocks = 4;
    const size_t num_of_tables = 3;

    lld_memory_value_list_t mem_val_list;
    // Write to all tables that hold multiple entries in a single line. Using
    // these tables require RMW operation and reading an uninitialized memory
    // might result with ECC error.
    for (size_t block_index = 0; block_index < num_of_blocks; block_index++) {
        for (size_t table_index = 0; table_index < num_of_tables; table_index++) {
            lld_memory_scptr m;

            m = (*m_pacific_tree->rx_meter->block[block_index]->meters_table)[table_index];
            mem_val_list.push_back({m, bit_vector(0, m->get_desc()->width_bits)});

            m = (*m_pacific_tree->rx_meter->block[block_index]->meters_state_table)[table_index];
            mem_val_list.push_back({m, bit_vector(0, m->get_desc()->width_bits)});

            // TOOD - there's a general fix for clearing all config memory - remove when applied
            m = (*m_pacific_tree->rx_meter->block[block_index]->meters_attribute_table)[table_index];
            mem_val_list.push_back({m, bit_vector(0, m->get_desc()->width_bits)});

            // TOOD - there's a general fix for clearing all config memory - remove when applied
            m = (*m_pacific_tree->rx_meter->block[block_index]->meter_shaper_configuration_table)[table_index];
            mem_val_list.push_back({m, bit_vector(0, m->get_desc()->width_bits)});
        }
    }

    /* Write everything at once */
    la_status status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_phase_device_core()
{
    // Reset core and ARCs
    la_status retval = m_ll_device->reset();
    if (retval) {
        return retval;
    }

    // Reset all access engines
    retval = m_ll_device->reset_access_engines();
    if (retval) {
        return retval;
    }

    // Initialize device ID register
    csms_device_config_reg_register dev_id_reg_val = {.u8 = {0}};
    dev_id_reg_val.fields.device_id = m_ll_device->get_device_id();
    retval = m_ll_device->write_register(*m_pacific_tree->csms->device_config_reg, dev_id_reg_val);
    if (retval) {
        return retval;
    }

    retval = init_txpp_time_offsets();
    if (retval) {
        return retval;
    }

    retval = init_sbif_interrupts();

    return retval;
}

la_status
la_device_impl::initialize_hbm_max_pool()
{
    // Configure HBM max DRAM buffer to (967232 = 1M - 32*1024) instead of its initial value (of 1024*1024)
    hmc_cgm_initial_config_values_register total_size;
    total_size.fields.total_buffers_max_size = 967232;

    la_status status = m_ll_device->write_register(*m_pacific_tree->hmc_cgm->initial_config_values, total_size);
    return status;
}

la_status
la_device_impl::initialize_fw_filepath()
{
    m_hbm_fw_info.filepath = find_resource_file(HBM_FILE_ENVVAR, m_hbm_fw_info.filename.c_str());
    m_hbm_mbist_fw_info.filepath = find_resource_file(HBM_MBIST_FILE_ENVVAR, m_hbm_mbist_fw_info.filename.c_str());

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_reconnect_handler()
{
    la_status rc;

    rc = m_reconnect_handler->initialize();
    if (rc) {
        return rc;
    }

    rc = m_reconnect_handler->update_device_id(m_ll_device->get_device_id());
    if (rc) {
        return rc;
    }

    for (size_t prop = (size_t)la_device_property_e::FIRST_BOOLEAN_PROPERTY;
         !rc && prop <= (size_t)la_device_property_e::LAST_BOOLEAN_PROPERTY;
         ++prop) {
        rc = m_reconnect_handler->update_device_property((la_device_property_e)prop, m_device_properties[prop].bool_val);
    }
    for (size_t prop = (size_t)la_device_property_e::FIRST_INTEGER_PROPERTY;
         !rc && prop <= (size_t)la_device_property_e::LAST_INTEGER_PROPERTY;
         ++prop) {
        rc = m_reconnect_handler->update_device_property((la_device_property_e)prop, m_device_properties[prop].int_val);
    }

    return rc;
}

la_status
la_device_impl::initialize_serdes()
{
    start_profiling("Initialize serdes");

    if (is_simulated_or_emulated_device()) {
        return LA_STATUS_SUCCESS;
    }

    bool reconnect = m_reconnect_handler->is_reconnect_in_progress();

    if (m_serdes_device_handler == nullptr) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    return m_serdes_device_handler->init(reconnect);
}

la_status
la_device_impl::initialize_phase_device()
{
    start_profiling("Initialize phase device");

    dassert_crit(m_init_phase == init_phase_e::CREATED);
    la_status stat = initialize_first(m_reconnect_handler->is_reconnect_in_progress());
    return_on_error(stat);

    m_device_port_handler = std::make_shared<device_port_handler_pacific>(shared_from_this());

    bool dummy = false;
    get_bool_property(la_device_property_e::ENABLE_DUMMY_SERDES_HANDLER, dummy);
    if (is_emulated_device() || dummy) {
        m_serdes_device_handler = std::make_shared<dummy_serdes_device_handler_base>(shared_from_this());
    } else {
        m_serdes_device_handler = std::make_shared<avago_serdes_device_handler>(shared_from_this());
    }

    m_device_port_handler->initialize();

    m_hbm_fw_info.revision = HBM_REV;
    m_hbm_fw_info.build_id = HBM_BUILD;
    m_hbm_fw_info.filename = HBM_FILE_NAME;
    m_hbm_mbist_fw_info.revision = HBM_REV; // The revision is similar to the regular HBM FW
    m_hbm_mbist_fw_info.build_id = HBM_MBIST_BUILD;
    m_hbm_mbist_fw_info.filename = HBM_MBIST_FILE_NAME;

    la_status status = initialize_fw_filepath();
    return_on_error(status);

    if (!m_reconnect_handler->is_reconnect_in_progress()) {
        // This is the first time we write to device
        status = initialize_phase_device_core();
        return_on_error(status);

        if (!m_init_performance_helper->is_optimization_enabled()) {
            status = do_diagnostics_test(test_feature_e::MEM_BIST);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "Device diagnostics failed, consider replacing it.");
                // Currently, the HW is not stable and we don't want to prevent people from using such HW.
                // TODO: return failure.
                // return status;
            }
        }
    }

    // Write burst can be safely enabled when the device is not under traffic.
    // TODO: enable write burst for the entire init sequence.
    m_ll_device->set_write_burst(true);

    status = init_config_memories();
    m_ll_device->set_write_burst(false);

    return_on_error(status);

    if (!m_reconnect_handler->is_reconnect_in_progress()) {
        status = initialize_phase_device_core();
        return_on_error(status);

        status = disable_tcam_parity_scanners();
        return_on_error(status);

        // Direct PIF 18 to packet-DMA
        status = init_packet_dma();
        return_on_error(status);

        status = init_hbm();
        return_on_error(status);
    }

    status = initialize_serdes();
    return_on_error(status);

    status = m_cpu2jtag_handler->enable(m_device_frequency_int_khz, m_tck_frequency_mhz);
    return_on_error(status);

    int refclk = get_refclk_from_fuse(m_fuse_userbits);
    atomic_init(&m_device_properties[(int)la_device_property_e::EFUSE_REFCLK_SETTINGS].int_val, refclk);

    if (refclk & 0x10) {
        int refclk_per_ifg = 0;
        for (int i = 0; i < 4; i++) {
            if ((refclk >> i) & 0x1) {
                refclk_per_ifg |= 0x7 << (3 * i);
            }
        }

        atomic_init(&m_device_properties[(int)la_device_property_e::DEV_REFCLK_SEL].int_val, refclk_per_ifg);
    }

    // Initialize temperature and voltage poller
    status = m_pvt_handler->initialize();
    return_on_error(status);

    // HBM max pool should be initialized on DEVICE phase as the user API to configure each HBM pool
    // must be called before phase TOPOLOGY and uses this initialization for calculation.
    status = initialize_hbm_max_pool();
    return_on_error(status);

    bool enable_lpm_ip_cache;
    status = get_bool_property(la_device_property_e::ENABLE_LPM_IP_CACHE, enable_lpm_ip_cache);
    return_on_error(status);
    set_bool_property_lpm_cache_enabled(enable_lpm_ip_cache);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_config_memories()
{
    start_profiling("Init config memories");
    log_debug(SIM, "command::init_config_memories_started");
    // Most memories are initialized to zero.
    // Some memories are initialized to non-zero values.
    std::map<lld_memory_scptr, bit_vector, lld_memory_scptr_ops> mem_init_values;

    // vsc_map_cfg
    bit_vector vsc_map_cfg_val(0, m_pacific_tree->slice[0]->ifg[0]->sch->vsc_map_cfg->get_desc()->width_total_bits);
    vsc_map_cfg_val.negate();
    for (la_slice_id_t i : get_used_slices()) {
        for (const auto& ifg : m_pacific_tree->slice[i]->ifg) {
            if (i < FIRST_HW_FABRIC_SLICE) {
                mem_init_values[ifg->sch->vsc_map_cfg] = vsc_map_cfg_val;
            } else {
                mem_init_values[ifg->fabric_sch->vsc_map_cfg] = vsc_map_cfg_val;
            }
        }
    }

    // sch_oqse_cfg
    static_assert((size_t)sch_oqse_cfg_memory::SIZE_IN_BITS == (size_t)sch_fab_oqse_cfg_memory::SIZE_IN_BITS,
                  "sch_oqse_cfg_memory SIZE does not match");
    sch_oqse_cfg_memory sch_oqse_cfg = {.u8 = {0}};
    sch_oqse_cfg.fields.oqse_wfq_weight0 = 1;
    sch_oqse_cfg.fields.oqse_wfq_weight1 = 1;
    sch_oqse_cfg.fields.oqse_wfq_weight2 = 1;
    sch_oqse_cfg.fields.oqse_wfq_weight3 = 1;
    sch_oqse_cfg.fields.oqse_wfq_weight4 = 1;
    sch_oqse_cfg.fields.oqse_wfq_weight5 = 1;
    sch_oqse_cfg.fields.oqse_wfq_weight6 = 1;
    sch_oqse_cfg.fields.oqse_wfq_weight7 = 1;
    for (la_slice_id_t i : get_used_slices()) {
        for (const auto& ifg : m_pacific_tree->slice[i]->ifg) {
            if (i < FIRST_HW_FABRIC_SLICE) {
                mem_init_values[ifg->sch->oqse_cfg] = sch_oqse_cfg;
            } else {
                mem_init_values[ifg->fabric_sch->oqse_cfg] = sch_oqse_cfg;
            }
        }
    }

    // sch_tpse_wfq_cfg
    static_assert((size_t)sch_tpse_wfq_cfg_memory::SIZE_IN_BITS == (size_t)sch_fab_tpse_wfq_cfg_memory::SIZE_IN_BITS,
                  "sch_tpse_wfq_cfg_memory SIZE does not match");
    sch_tpse_wfq_cfg_memory sch_tpse_wfq_cfg = {.u8 = {0}};
    sch_tpse_wfq_cfg.fields.tpse_wfq_weight0 = 1;
    sch_tpse_wfq_cfg.fields.tpse_wfq_weight1 = 1;
    sch_tpse_wfq_cfg.fields.tpse_wfq_weight2 = 1;
    sch_tpse_wfq_cfg.fields.tpse_wfq_weight3 = 1;
    sch_tpse_wfq_cfg.fields.tpse_wfq_weight4 = 1;
    sch_tpse_wfq_cfg.fields.tpse_wfq_weight5 = 1;
    sch_tpse_wfq_cfg.fields.tpse_wfq_weight6 = 1;
    sch_tpse_wfq_cfg.fields.tpse_wfq_weight7 = 1;
    for (la_slice_id_t i : get_used_slices()) {
        for (const auto& ifg : m_pacific_tree->slice[i]->ifg) {
            if (i < FIRST_HW_FABRIC_SLICE) {
                mem_init_values[ifg->sch->tpse_wfq_cfg] = sch_tpse_wfq_cfg;
            } else {
                mem_init_values[ifg->fabric_sch->tpse_wfq_cfg] = sch_tpse_wfq_cfg;
            }
        }
    }

    // pdoq_tpse_wfq_cfg
    pdoq_tpse_wfq_cfg_memory pdoq_tpse_wfq_cfg = {.u8 = {0}};
    pdoq_tpse_wfq_cfg.fields.tpse_wfq_weight0 = 1;
    pdoq_tpse_wfq_cfg.fields.tpse_wfq_weight1 = 1;
    pdoq_tpse_wfq_cfg.fields.tpse_wfq_weight2 = 1;
    pdoq_tpse_wfq_cfg.fields.tpse_wfq_weight3 = 1;
    pdoq_tpse_wfq_cfg.fields.tpse_wfq_weight4 = 1;
    pdoq_tpse_wfq_cfg.fields.tpse_wfq_weight5 = 1;
    pdoq_tpse_wfq_cfg.fields.tpse_wfq_weight6 = 1;
    pdoq_tpse_wfq_cfg.fields.tpse_wfq_weight7 = 1;
    for (la_slice_id_t i : get_used_slices()) {
        const auto& pdoq_tpse_wfq_cfg_arr(m_pacific_tree->slice[i]->pdoq->top->tpse_wfq_cfg);
        for (size_t i = 0; i < pdoq_tpse_wfq_cfg_arr->size(); i++) {
            mem_init_values[(*pdoq_tpse_wfq_cfg_arr)[i]] = pdoq_tpse_wfq_cfg;
        }
    }

    // pdoq_uc_mc_wfq_cfg
    pdoq_uc_mc_wfq_cfg_memory pdoq_uc_mc_wfq_cfg = {.u8 = {0}};
    pdoq_uc_mc_wfq_cfg.fields.uc_wfq_weight = 1;
    pdoq_uc_mc_wfq_cfg.fields.mc_wfq_weight = 1;
    for (la_slice_id_t i : get_used_slices()) {
        const auto& pdoq_uc_mc_wfq_cfg_arr(m_pacific_tree->slice[i]->pdoq->top->uc_mc_wfq_cfg);
        for (size_t i = 0; i < pdoq_uc_mc_wfq_cfg_arr->size(); i++) {
            mem_init_values[(*pdoq_uc_mc_wfq_cfg_arr)[i]] = pdoq_uc_mc_wfq_cfg;
        }
    }

    // Iterate through all CONFIG memories, fill with either all-ones or all-zeros.
    // This includes TCAMs, which must be filled with zeros (valid TCAM values) then marked as invalid.
    for (lld_block_scptr block : m_pacific_tree->get_leaf_blocks()) {
        if (block == m_pacific_tree->sbif) {
            continue;
        }
        for (lld_memory_scptr mem : block->get_memories()) {
            const lld_memory_desc_t* desc = mem->get_desc();
            if (desc->type == lld_memory_type_e::CONFIG) {
                la_status rc = init_config_memory(mem, mem_init_values);
                return_on_error(rc);
            }
        }
    }

    log_debug(SIM, "command::init_config_memories_done");
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_config_memory(lld_memory_scptr mem,
                                   const std::map<lld_memory_scptr, bit_vector, handle_ops<lld_memory_scptr> >& mem_init_values)
{
    const lld_memory_desc_t* desc = mem->get_desc();
    bit_vector val(0, desc->width_total_bits);
    auto it = mem_init_values.find(mem);
    if (it != mem_init_values.end()) {
        val = it->second;
    }

    la_status rc = m_ll_device->fill_memory(*mem, 0, desc->entries, val);
    return_on_error(rc);

    // TCAMs must be marked as "invalid".
    // Otherwise, they contain "zero" which is a valid meaningful value.
    if (desc->subtype == lld_memory_subtype_e::X_Y_TCAM || desc->subtype == lld_memory_subtype_e::REG_TCAM) {
        size_t max_tcam_line = (desc->subtype == lld_memory_subtype_e::X_Y_TCAM ? desc->entries / 2 : desc->entries);
        for (size_t tcam_line = 0; tcam_line < max_tcam_line; ++tcam_line) {
            rc = m_ll_device->invalidate_tcam(*mem, tcam_line);
            return_on_error(rc);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::disable_tcam_parity_scanners()
{
    // tcam_scan_period_cfg register has a fixed address in all LBRs.
    la_entry_addr_t tcam_scan_period_cfg_addr = m_pacific_tree->cdb->core[0]->tcam_scan_period_cfg->get_desc()->addr;
    lld_register_value_list_t reg_val_list;

    // Shutdown all TCAM scanners by setting scan period to 0
    for (lld_block_scptr b : m_pacific_tree->get_leaf_blocks()) {
        lld_register_scptr tcam_scan = b->get_register(tcam_scan_period_cfg_addr);
        if (tcam_scan) {
            reg_val_list.push_back({tcam_scan, 0});
        }
    }

    la_status rc = lld_write_register_list(m_ll_device, reg_val_list);

    return rc;
}

la_status
la_device_impl::init_packet_dma()
{
    // re-init packet DMA engine by placing it in the reset state and
    // taking it out of reset so the kernel driver is in sync with the ASIC
    //
    // this is to resolve the punt/inject issue where kernel driver is
    // reloaded but the ASIC DMA engine is not reset

    bool using_leaba_nic;
    la_status status = get_bool_property(la_device_property_e::USING_LEABA_NIC, using_leaba_nic);
    return_on_error(status);

    lld_register_value_list_t reg_val_list;

    // Clear interrupt registers
    push_back_ones(reg_val_list, m_pacific_tree->sbif->dma_err_interrupt_reg);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->dma_done_interrupt_reg);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->dma_drop_fc_interrupt_reg);

    // toggle packet-DMA reset bits, wait for 10ms till reset is executed
    sbif_reset_reg_register reset_reg;
    status = m_ll_device->read_register(*m_pacific_tree->sbif->reset_reg, reset_reg);
    return_on_error(status);

    reset_reg.fields.packet_dma_rstn = 0;
    reg_val_list.push_back({(m_pacific_tree->sbif->reset_reg), reset_reg});
    status = lld_write_register_list(m_ll_device, reg_val_list);

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    reg_val_list.clear();

    if (using_leaba_nic) {
        status = reset_network_interfaces();
        return_on_error(status);
    }

    status = m_ll_device->read_register(*m_pacific_tree->sbif->reset_reg, reset_reg);
    return_on_error(status);

    reset_reg.fields.packet_dma_rstn = 1;
    reg_val_list.push_back({(m_pacific_tree->sbif->reset_reg), reset_reg});

    status = lld_write_register_list(m_ll_device, reg_val_list);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    return status;
}

la_status
la_device_impl::init_hbm()
{
    auto handler = std::make_shared<la_hbm_handler_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(handler, oid);
    return_on_error(status);

    status = handler->initialize(oid);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    status = handler->activate();
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_hbm_handler = handler;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_sbif_interrupts()
{
    lld_register_value_list_t reg_val_list;

    // Disable root-level master interrupts
    reg_val_list.push_back({(m_pacific_tree->sbif->arc3_master_interrupt_reg_mask), 0});
    reg_val_list.push_back({(m_pacific_tree->sbif->arc2_master_interrupt_reg_mask), 0});
    reg_val_list.push_back({(m_pacific_tree->sbif->arc1_master_interrupt_reg_mask), 0});
    reg_val_list.push_back({(m_pacific_tree->sbif->arc0_master_interrupt_reg_mask), 0});
    reg_val_list.push_back({(m_pacific_tree->sbif->msi_master_interrupt_reg_mask), 0});
    reg_val_list.push_back({(m_pacific_tree->sbif->pin_master_interrupt_reg_mask), 0});

    // msi_blocks_interrupt_summary_reg0 is not fully modeled yet.
    // Write '1' only to bits that are already modeled in pacific_interrupt_tree.py
    // TODO: eventually, when everything is modeled, should wright all-ones.
    sbif_msi_blocks_interrupt_summary_reg0_mask_register mask0 = {{0}};
    mask0.fields.msi_cdb_top_interrupt_summary_mask = 1;
    mask0.fields.msi_counters_interrupt_summary_mask = 1;
    mask0.fields.msi_dram_control_interrupt_summary_mask = 1;
    mask0.fields.msi_egr_interrupt_summary_mask = 1;
    mask0.fields.msi_fdll_interrupt_summary_mask = 1;
    mask0.fields.msi_fllb_interrupt_summary_mask = 1;
    mask0.fields.msi_ics_interrupt_summary_mask = 1;
    mask0.fields.msi_idb_interrupt_summary_mask = (1 << 3) - 1;  // 3-bits field - all ones
    mask0.fields.msi_ifg_interrupt_summary_mask = (1 << 12) - 1; // 12-bits field - all ones
    mask0.fields.msi_nw_reorder_interrupt_summary_mask = 1;
    mask0.fields.msi_pp_reorder_interrupt_summary_mask = 0;
    mask0.fields.msi_pdoq_interrupt_summary_mask = 1;
    mask0.fields.msi_pdvoq_interrupt_summary_mask = 1;
    mask0.fields.msi_reassembly_interrupt_summary_mask = 1;
    mask0.fields.msi_rx_cgm_interrupt_summary_mask = 1;
    mask0.fields.msi_rx_meter_interrupt_summary_mask = 1;
    mask0.fields.msi_rx_pdr_interrupt_summary_mask = 1;
    mask0.fields.msi_sch_interrupt_summary_mask = 1;

    const lld_register_scptr mask0_regs[] = {m_pacific_tree->sbif->arc0_blocks_interrupt_summary_reg0_mask,
                                             m_pacific_tree->sbif->arc1_blocks_interrupt_summary_reg0_mask,
                                             m_pacific_tree->sbif->arc2_blocks_interrupt_summary_reg0_mask,
                                             m_pacific_tree->sbif->arc3_blocks_interrupt_summary_reg0_mask,
                                             m_pacific_tree->sbif->msi_blocks_interrupt_summary_reg0_mask,
                                             m_pacific_tree->sbif->pin_blocks_interrupt_summary_reg0_mask};

    for (lld_register_scptr reg : mask0_regs) {
        reg_val_list.push_back({reg, mask0});
    }

    // msi_blocks_interrupt_summary_reg1 is fully modeled - write all-ones to enable it.
    const lld_register_scptr mask1_regs[] = {m_pacific_tree->sbif->arc0_blocks_interrupt_summary_reg1_mask,
                                             m_pacific_tree->sbif->arc1_blocks_interrupt_summary_reg1_mask,
                                             m_pacific_tree->sbif->arc2_blocks_interrupt_summary_reg1_mask,
                                             m_pacific_tree->sbif->arc3_blocks_interrupt_summary_reg1_mask,
                                             m_pacific_tree->sbif->msi_blocks_interrupt_summary_reg1_mask,
                                             m_pacific_tree->sbif->pin_blocks_interrupt_summary_reg1_mask};

    for (lld_register_scptr reg : mask1_regs) {
        push_back_ones(reg_val_list, reg);
    }

    la_status status = lld_write_register_list(m_ll_device, reg_val_list);

    return status;
}

la_status
la_device_impl::verify_topology_configuration()
{
    for (la_slice_id_t sid : get_used_slices()) {
        if (m_slice_mode[sid] == la_slice_mode_e::INVALID) {
            log_err(HLD, "Slice mode of slice %d is undefined", sid);
            return LA_STATUS_ENOTINITIALIZED;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_em_per_bank_reg()
{
    // Initialize all exact match per bank registers.
    // Currently, the values taken from designer but probably will be changed.
    lld_register_value_list_t reg_val_list;

    la_uint64_t exact_match_seed = 0x1757DF59C01ULL;

    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_NON_FABRIC)) {
        for (size_t exact_match = 0; exact_match < m_pacific_tree->slice[slice]->pp_reorder->pp_exact_match_per_bank_reg->size();
             exact_match++) {
            reg_val_list.push_back(
                {(*m_pacific_tree->slice[slice]->pp_reorder->pp_exact_match_per_bank_reg)[exact_match], exact_match_seed});
            exact_match_seed += 2;
        }
    }

    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_FABRIC)) {
        for (size_t block = 0; block < array_size(m_pacific_tree->slice[slice]->nw_reorder_block); block++) {
            exact_match_seed = 0x1757DF59DB5ULL;
            exact_match_seed
                += (slice - 3) * 2 * m_pacific_tree->slice[slice]->nw_reorder_block[block]->nw_exact_match_per_bank_reg->size();
            for (size_t exact_match = 0;
                 exact_match < m_pacific_tree->slice[slice]->nw_reorder_block[block]->nw_exact_match_per_bank_reg->size();
                 exact_match++) {
                reg_val_list.push_back(
                    {(*m_pacific_tree->slice[slice]->nw_reorder_block[block]->nw_exact_match_per_bank_reg)[exact_match],
                     exact_match_seed});
                exact_match_seed += 2;
            }
        }
    }

    // FDLL EMDB
    reg_val_list.push_back({(*m_pacific_tree->fdll[0]->emdb_per_bank_reg)[0], bit_vector("0x1FFD72A23")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[0]->emdb_per_bank_reg)[1], bit_vector("0x13FE68197")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[0]->emdb_per_bank_reg)[2], bit_vector("0x1C277EE61")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[0]->emdb_per_bank_reg)[3], bit_vector("0x14EC91FB1")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[0]->emdb_per_bank_reg)[4], bit_vector("0xF1DBAD15")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[0]->emdb_per_bank_reg)[5], bit_vector("0x1643BF5A3")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[0]->emdb_per_bank_reg)[6], bit_vector("0x1FBE88691")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[0]->emdb_per_bank_reg)[7], bit_vector("0x36AAC869")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[1]->emdb_per_bank_reg)[0], bit_vector("0x15BC5009B")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[1]->emdb_per_bank_reg)[1], bit_vector("0x18B510C43")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[1]->emdb_per_bank_reg)[2], bit_vector("0x1A6DE3DFD")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[1]->emdb_per_bank_reg)[3], bit_vector("0x1619F38B9")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[1]->emdb_per_bank_reg)[4], bit_vector("0x1A7A8C6E9")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[1]->emdb_per_bank_reg)[5], bit_vector("0x1B9222F93")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[1]->emdb_per_bank_reg)[6], bit_vector("0x6D87CEAB")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[1]->emdb_per_bank_reg)[7], bit_vector("0xDC797721")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[2]->emdb_per_bank_reg)[0], bit_vector("0xAD971051")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[2]->emdb_per_bank_reg)[1], bit_vector("0x27D4821")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[2]->emdb_per_bank_reg)[2], bit_vector("0x1B432DFCB")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[2]->emdb_per_bank_reg)[3], bit_vector("0x142A900B5")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[2]->emdb_per_bank_reg)[4], bit_vector("0x15C06B3B7")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[2]->emdb_per_bank_reg)[5], bit_vector("0x110B5738B")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[2]->emdb_per_bank_reg)[6], bit_vector("0x4C99D329")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[2]->emdb_per_bank_reg)[7], bit_vector("0x579F567F")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[3]->emdb_per_bank_reg)[0], bit_vector("0x1B7372C55")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[3]->emdb_per_bank_reg)[1], bit_vector("0x14DF29C31")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[3]->emdb_per_bank_reg)[2], bit_vector("0x16521627")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[3]->emdb_per_bank_reg)[3], bit_vector("0x13A126F21")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[3]->emdb_per_bank_reg)[4], bit_vector("0x15D9858F")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[3]->emdb_per_bank_reg)[5], bit_vector("0x39D2578B")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[3]->emdb_per_bank_reg)[6], bit_vector("0xBA21AADD")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[3]->emdb_per_bank_reg)[7], bit_vector("0x1078906BF")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[4]->emdb_per_bank_reg)[0], bit_vector("0xB51BA479")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[4]->emdb_per_bank_reg)[1], bit_vector("0x90AB6733")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[4]->emdb_per_bank_reg)[2], bit_vector("0x133C56213")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[4]->emdb_per_bank_reg)[3], bit_vector("0x109FD2F91")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[4]->emdb_per_bank_reg)[4], bit_vector("0x152C53535")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[4]->emdb_per_bank_reg)[5], bit_vector("0x15B963A8B")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[4]->emdb_per_bank_reg)[6], bit_vector("0x1AB398ACB")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[4]->emdb_per_bank_reg)[7], bit_vector("0x1575C758D")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[5]->emdb_per_bank_reg)[0], bit_vector("0xC224D2F3")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[5]->emdb_per_bank_reg)[1], bit_vector("0x4D801B83")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[5]->emdb_per_bank_reg)[2], bit_vector("0x1E4894EC3")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[5]->emdb_per_bank_reg)[3], bit_vector("0x8B67FEE7")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[5]->emdb_per_bank_reg)[4], bit_vector("0x305F32B5")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[5]->emdb_per_bank_reg)[5], bit_vector("0x1482C2903")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[5]->emdb_per_bank_reg)[6], bit_vector("0x186122E39")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[5]->emdb_per_bank_reg)[7], bit_vector("0x36D7C865")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[6]->emdb_per_bank_reg)[0], bit_vector("0x1DE9E0F71")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[6]->emdb_per_bank_reg)[1], bit_vector("0x13BB584CF")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[6]->emdb_per_bank_reg)[2], bit_vector("0xD9C4A6ED")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[6]->emdb_per_bank_reg)[3], bit_vector("0x8DEB28A3")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[6]->emdb_per_bank_reg)[4], bit_vector("0x111455799")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[6]->emdb_per_bank_reg)[5], bit_vector("0xE7317BA1")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[6]->emdb_per_bank_reg)[6], bit_vector("0x17CAE194F")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[6]->emdb_per_bank_reg)[7], bit_vector("0x1609ADBCF")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[7]->emdb_per_bank_reg)[0], bit_vector("0x1A84C2231")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[7]->emdb_per_bank_reg)[1], bit_vector("0x14A3680D7")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[7]->emdb_per_bank_reg)[2], bit_vector("0x763C2571")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[7]->emdb_per_bank_reg)[3], bit_vector("0x190E9CF")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[7]->emdb_per_bank_reg)[4], bit_vector("0x10038C6D1")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[7]->emdb_per_bank_reg)[5], bit_vector("0xE64772B1")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[7]->emdb_per_bank_reg)[6], bit_vector("0x3E3C1175")});
    reg_val_list.push_back({(*m_pacific_tree->fdll[7]->emdb_per_bank_reg)[7], bit_vector("0x16A39B7E9")});

    // PDOQ EMDB
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[0]->emdb_per_bank_reg)[0], bit_vector("0xE30418A5")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[0]->emdb_per_bank_reg)[1], bit_vector("0x1806F3B91")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[0]->emdb_per_bank_reg)[2], bit_vector("0x36CB6D5")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[0]->emdb_per_bank_reg)[3], bit_vector("0x108405539")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[1]->emdb_per_bank_reg)[0], bit_vector("0xF50D038F")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[1]->emdb_per_bank_reg)[1], bit_vector("0x17D66C2A3")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[1]->emdb_per_bank_reg)[2], bit_vector("0x246F7903")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[1]->emdb_per_bank_reg)[3], bit_vector("0x629F9B79")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[2]->emdb_per_bank_reg)[0], bit_vector("0x15EEAA7CB")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[2]->emdb_per_bank_reg)[1], bit_vector("0xA60A2917")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[2]->emdb_per_bank_reg)[2], bit_vector("0xF711933D")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[2]->emdb_per_bank_reg)[3], bit_vector("0x122A400AD")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[3]->emdb_per_bank_reg)[0], bit_vector("0x8BF51FA5")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[3]->emdb_per_bank_reg)[1], bit_vector("0x1A4F87C37")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[3]->emdb_per_bank_reg)[2], bit_vector("0xE53C9CC3")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[3]->emdb_per_bank_reg)[3], bit_vector("0x1D22AB859")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[4]->emdb_per_bank_reg)[0], bit_vector("0x14425ECF")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[4]->emdb_per_bank_reg)[1], bit_vector("0x162B70A63")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[4]->emdb_per_bank_reg)[2], bit_vector("0x1A8F4F0D9")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[4]->emdb_per_bank_reg)[3], bit_vector("0x1A860D3E5")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[5]->emdb_per_bank_reg)[0], bit_vector("0x1307D8D73")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[5]->emdb_per_bank_reg)[1], bit_vector("0xFEFB7A6B")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[5]->emdb_per_bank_reg)[2], bit_vector("0x234A0A1F")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[5]->emdb_per_bank_reg)[3], bit_vector("0x1DA5635B")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[6]->emdb_per_bank_reg)[0], bit_vector("0x138FB38AD")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[6]->emdb_per_bank_reg)[1], bit_vector("0x3355A7B")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[6]->emdb_per_bank_reg)[2], bit_vector("0x1046AEC1D")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[6]->emdb_per_bank_reg)[3], bit_vector("0x102BF8951")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[7]->emdb_per_bank_reg)[0], bit_vector("0x27015F63")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[7]->emdb_per_bank_reg)[1], bit_vector("0x1DF6DBA23")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[7]->emdb_per_bank_reg)[2], bit_vector("0xD15FCEA3")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[7]->emdb_per_bank_reg)[3], bit_vector("0x997C250B")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[8]->emdb_per_bank_reg)[0], bit_vector("0x93CD188B")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[8]->emdb_per_bank_reg)[1], bit_vector("0x9EF76BB")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[8]->emdb_per_bank_reg)[2], bit_vector("0x67CF8DC5")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[8]->emdb_per_bank_reg)[3], bit_vector("0x117CE6521")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[9]->emdb_per_bank_reg)[0], bit_vector("0xF31D857F")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[9]->emdb_per_bank_reg)[1], bit_vector("0x1F59B00B5")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[9]->emdb_per_bank_reg)[2], bit_vector("0xF413EB89")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[9]->emdb_per_bank_reg)[3], bit_vector("0x11A73493")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[10]->emdb_per_bank_reg)[0], bit_vector("0xEA79B1B5")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[10]->emdb_per_bank_reg)[1], bit_vector("0x6945BDBD")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[10]->emdb_per_bank_reg)[2], bit_vector("0x1BCF9569F")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[10]->emdb_per_bank_reg)[3], bit_vector("0x67DBE867")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[11]->emdb_per_bank_reg)[0], bit_vector("0x17F08C42B")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[11]->emdb_per_bank_reg)[1], bit_vector("0xB15C34BD")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[11]->emdb_per_bank_reg)[2], bit_vector("0x1C78331DF")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[11]->emdb_per_bank_reg)[3], bit_vector("0x1D8BCDC35")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[12]->emdb_per_bank_reg)[0], bit_vector("0x1F3B6A7CD")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[12]->emdb_per_bank_reg)[1], bit_vector("0xD8AAC82F")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[12]->emdb_per_bank_reg)[2], bit_vector("0x125F1BA77")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[12]->emdb_per_bank_reg)[3], bit_vector("0x1AD209CDD")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[13]->emdb_per_bank_reg)[0], bit_vector("0x1CBA80E61")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[13]->emdb_per_bank_reg)[1], bit_vector("0xD93FB02F")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[13]->emdb_per_bank_reg)[2], bit_vector("0x105E97A17")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[13]->emdb_per_bank_reg)[3], bit_vector("0x79F4302D")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[14]->emdb_per_bank_reg)[0], bit_vector("0x85C13999")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[14]->emdb_per_bank_reg)[1], bit_vector("0x134840D89")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[14]->emdb_per_bank_reg)[2], bit_vector("0x7BFAA58B")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[14]->emdb_per_bank_reg)[3], bit_vector("0x12CF542C5")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[15]->emdb_per_bank_reg)[0], bit_vector("0x768C8C15")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[15]->emdb_per_bank_reg)[1], bit_vector("0x1EBDB65AD")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[15]->emdb_per_bank_reg)[2], bit_vector("0xED78857")});
    reg_val_list.push_back({(*m_pacific_tree->pdoq->empd[15]->emdb_per_bank_reg)[3], bit_vector("0x1E1DC0571")});

    // PDVOQ EMDB - same as PDOQ
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[0]->emdb_per_bank_reg)[0], bit_vector("0xE30418A5")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[0]->emdb_per_bank_reg)[1], bit_vector("0x1806F3B91")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[0]->emdb_per_bank_reg)[2], bit_vector("0x36CB6D5")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[0]->emdb_per_bank_reg)[3], bit_vector("0x108405539")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[1]->emdb_per_bank_reg)[0], bit_vector("0xF50D038F")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[1]->emdb_per_bank_reg)[1], bit_vector("0x17D66C2A3")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[1]->emdb_per_bank_reg)[2], bit_vector("0x246F7903")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[1]->emdb_per_bank_reg)[3], bit_vector("0x629F9B79")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[2]->emdb_per_bank_reg)[0], bit_vector("0x15EEAA7CB")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[2]->emdb_per_bank_reg)[1], bit_vector("0xA60A2917")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[2]->emdb_per_bank_reg)[2], bit_vector("0xF711933D")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[2]->emdb_per_bank_reg)[3], bit_vector("0x122A400AD")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[3]->emdb_per_bank_reg)[0], bit_vector("0x8BF51FA5")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[3]->emdb_per_bank_reg)[1], bit_vector("0x1A4F87C37")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[3]->emdb_per_bank_reg)[2], bit_vector("0xE53C9CC3")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[3]->emdb_per_bank_reg)[3], bit_vector("0x1D22AB859")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[4]->emdb_per_bank_reg)[0], bit_vector("0x14425ECF")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[4]->emdb_per_bank_reg)[1], bit_vector("0x162B70A63")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[4]->emdb_per_bank_reg)[2], bit_vector("0x1A8F4F0D9")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[4]->emdb_per_bank_reg)[3], bit_vector("0x1A860D3E5")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[5]->emdb_per_bank_reg)[0], bit_vector("0x1307D8D73")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[5]->emdb_per_bank_reg)[1], bit_vector("0xFEFB7A6B")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[5]->emdb_per_bank_reg)[2], bit_vector("0x234A0A1F")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[5]->emdb_per_bank_reg)[3], bit_vector("0x1DA5635B")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[6]->emdb_per_bank_reg)[0], bit_vector("0x138FB38AD")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[6]->emdb_per_bank_reg)[1], bit_vector("0x3355A7B")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[6]->emdb_per_bank_reg)[2], bit_vector("0x1046AEC1D")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[6]->emdb_per_bank_reg)[3], bit_vector("0x102BF8951")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[7]->emdb_per_bank_reg)[0], bit_vector("0x27015F63")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[7]->emdb_per_bank_reg)[1], bit_vector("0x1DF6DBA23")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[7]->emdb_per_bank_reg)[2], bit_vector("0xD15FCEA3")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[7]->emdb_per_bank_reg)[3], bit_vector("0x997C250B")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[8]->emdb_per_bank_reg)[0], bit_vector("0x93CD188B")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[8]->emdb_per_bank_reg)[1], bit_vector("0x9EF76BB")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[8]->emdb_per_bank_reg)[2], bit_vector("0x67CF8DC5")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[8]->emdb_per_bank_reg)[3], bit_vector("0x117CE6521")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[9]->emdb_per_bank_reg)[0], bit_vector("0xF31D857F")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[9]->emdb_per_bank_reg)[1], bit_vector("0x1F59B00B5")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[9]->emdb_per_bank_reg)[2], bit_vector("0xF413EB89")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[9]->emdb_per_bank_reg)[3], bit_vector("0x11A73493")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[10]->emdb_per_bank_reg)[0], bit_vector("0xEA79B1B5")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[10]->emdb_per_bank_reg)[1], bit_vector("0x6945BDBD")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[10]->emdb_per_bank_reg)[2], bit_vector("0x1BCF9569F")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[10]->emdb_per_bank_reg)[3], bit_vector("0x67DBE867")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[11]->emdb_per_bank_reg)[0], bit_vector("0x17F08C42B")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[11]->emdb_per_bank_reg)[1], bit_vector("0xB15C34BD")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[11]->emdb_per_bank_reg)[2], bit_vector("0x1C78331DF")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[11]->emdb_per_bank_reg)[3], bit_vector("0x1D8BCDC35")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[12]->emdb_per_bank_reg)[0], bit_vector("0x1F3B6A7CD")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[12]->emdb_per_bank_reg)[1], bit_vector("0xD8AAC82F")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[12]->emdb_per_bank_reg)[2], bit_vector("0x125F1BA77")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[12]->emdb_per_bank_reg)[3], bit_vector("0x1AD209CDD")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[13]->emdb_per_bank_reg)[0], bit_vector("0x1CBA80E61")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[13]->emdb_per_bank_reg)[1], bit_vector("0xD93FB02F")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[13]->emdb_per_bank_reg)[2], bit_vector("0x105E97A17")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[13]->emdb_per_bank_reg)[3], bit_vector("0x79F4302D")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[14]->emdb_per_bank_reg)[0], bit_vector("0x85C13999")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[14]->emdb_per_bank_reg)[1], bit_vector("0x134840D89")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[14]->emdb_per_bank_reg)[2], bit_vector("0x7BFAA58B")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[14]->emdb_per_bank_reg)[3], bit_vector("0x12CF542C5")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[15]->emdb_per_bank_reg)[0], bit_vector("0x768C8C15")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[15]->emdb_per_bank_reg)[1], bit_vector("0x1EBDB65AD")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[15]->emdb_per_bank_reg)[2], bit_vector("0xED78857")});
    reg_val_list.push_back({(*m_pacific_tree->pdvoq->empd[15]->emdb_per_bank_reg)[3], bit_vector("0x1E1DC0571")});

    la_status status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_txpp_time_offsets()
{
    // values in clock cycles. No need to adjust when changing clock frequency
    constexpr float TOD_GEN_REGS_VALS[] = {21, 13, 3, 10, 26, 35};
    constexpr float TOD_GEN_REGS_OFFSET = 150;
    // values in ns measured for CALCULATED_VALUES_DEVICE_FREQUENCY. Need to adjust according to actual clock frequency
    constexpr float DEVICE_TIME_OFFSET_CFG_VALS[] = {0xa2 - 3, 0x95 - 3, 0x69 - 3, 0x74 - 3, 0x35 - 3, 0x28 - 3};
    float device_freq_adjust = (float)CALCULATED_VALUES_DEVICE_FREQUENCY / m_device_frequency_int_khz;

    for (la_slice_id_t slice_id : get_used_slices()) {
        la_status status;
        txpp_tod_gen_regs_register tod_gen_regs;

        status = m_ll_device->read_register(*m_pacific_tree->slice[slice_id]->npu->txpp->txpp->tod_gen_regs, tod_gen_regs);
        return_on_error(status);
        tod_gen_regs.fields.tod_gen_load_cmd_delay = TOD_GEN_REGS_VALS[slice_id] + TOD_GEN_REGS_OFFSET;
        status = m_ll_device->write_register(*m_pacific_tree->slice[slice_id]->npu->txpp->txpp->tod_gen_regs, tod_gen_regs);
        return_on_error(status);
        status = m_ll_device->write_register(*m_pacific_tree->slice[slice_id]->npu->txpp->txpp->device_time_offset_cfg,
                                             round(DEVICE_TIME_OFFSET_CFG_VALS[slice_id] * device_freq_adjust));
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm()
{
    la_status status = init_tm_ics();
    return_on_error(status);

    status = init_tm_filb();
    return_on_error(status);

    status = init_tm_pdoq_top();
    return_on_error(status);

    status = init_tm_pdoq_fdoq();
    return_on_error(status);

    status = init_tm_pdvoq();
    return_on_error(status);

    status = init_tm_reorder();
    return_on_error(status);

    status = init_tm_rxcgm();
    return_on_error(status);

    status = init_tm_rxpdr();
    return_on_error(status);

    status = init_tm_rxpdr_mc_db();
    return_on_error(status);

    status = init_tm_txcgm();
    return_on_error(status);

    status = init_tm_txpdr();
    return_on_error(status);

    status = init_tm_ts_ms();
    return_on_error(status);

    status = init_tm_ts_mon();
    return_on_error(status);

    status = init_tm_reassembly();
    return_on_error(status);

    status = init_tm_other();
    return_on_error(status);

    status = init_other();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_ics()
{
    lld_register_value_list_t reg_val_list;

    la_status status;

    // Initialize various ICS block registers to constant values according to designer's tune output.
    for (size_t i : get_used_slices()) {
        const auto& slice = m_pacific_tree->slice[i];

        // Set static-go threshold: If slow credit arrives and Qsize in bytes is greater than this threshold - send credit request
        // with static-go
        const uint64_t static_go_th = 512 * UNITS_IN_KIBI; // Given by the design team.
        for (size_t j = 0; j < m_pacific_tree->slice[0]->ics->queue_size_static_go_th_reg->size(); j++) {
            if ((m_device_mode == device_mode_e::LINECARD) && is_network_slice(i)) {
                reg_val_list.push_back({(*slice->ics->queue_size_static_go_th_reg)[j], static_go_th});
            } else {
                reg_val_list.push_back({(*slice->ics->queue_size_static_go_th_reg)[j], 0x7FFFFF});
            }
        }

        // Enable static-go on Enq-request
        ics_slice_enq_conf_static_go_reg_register enq_conf_static_go;
        if ((m_device_mode == device_mode_e::LINECARD) && is_network_slice(i)) {
            status = m_ll_device->read_register(*slice->ics->enq_conf_static_go_reg, enq_conf_static_go);
            return_on_error(status);
            enq_conf_static_go.fields.en_static_go_on_enq_qsize = 1;
            reg_val_list.push_back({(slice->ics->enq_conf_static_go_reg), enq_conf_static_go});
        }

        for (size_t j = 0; j < m_pacific_tree->slice[0]->ics->clear_queue_blocking_th_reg->size(); j++) {
            reg_val_list.push_back({(*slice->ics->clear_queue_blocking_th_reg)[j], 0x2400});
        }

        int credit_in_bytes;
        status = get_int_property(la_device_property_e::CREDIT_SIZE_IN_BYTES, credit_in_bytes);
        return_on_error(status);

        ics_slice_read_pipe_param_reg_register read_pipe_param_reg = {.u8 = {0}};

        read_pipe_param_reg.fields.retransmit_win_size = 0x7FF;
        read_pipe_param_reg.fields.max_negative_cb = 0x3000;
        read_pipe_param_reg.fields.pre_pkt_cb_th = credit_in_bytes - 1;
        reg_val_list.push_back({(slice->ics->read_pipe_param_reg), read_pipe_param_reg});

        reg_val_list.push_back({(slice->ics->weighted_round_robin), 0x1911});
        reg_val_list.push_back({(slice->ics->deq_rpt_pipe_param_reg), 0xF423F});
        reg_val_list.push_back({(slice->ics->compensation_per_ifg), 0xFFFFF00000});

        ics_slice_eligible_th_reg_register ics_slice_eligible_th;
        status = m_ll_device->read_register(*slice->ics->eligible_th_reg, ics_slice_eligible_th);
        return_on_error(status);

        ics_slice_eligible_th.fields.eir_slice_blocking_th = 512 * UNITS_IN_KIBI; // Given by the design team.
        ics_slice_eligible_th.fields.cir_slice_blocking_th = 512 * UNITS_IN_KIBI; // Given by the design team.

        if ((m_device_mode == device_mode_e::LINECARD) && is_network_slice(i)) {
            ics_slice_eligible_th.fields.speculative_qsize_th = 1;
        } else {
            // SA, LC fabric, FE
            ics_slice_eligible_th.fields.speculative_qsize_th = 1;
            ics_slice_eligible_th.fields.eir_slice_blocking_th = 0;
            ics_slice_eligible_th.fields.cir_slice_blocking_th = 0;
        }

        reg_val_list.push_back({(slice->ics->eligible_th_reg), ics_slice_eligible_th});

        reg_val_list.push_back(
            {(slice->ics->almost_full_cfg), bit_vector("0x2484215882540090046024501049492402852900404040410101010040420")});

        ics_slice_credits_conf_reg_register credits_reg;

        credits_reg.fields.static_go_profile = 0x0;
        credits_reg.fields.crdt_in_bytes = credit_in_bytes;
        switch (credit_in_bytes) {
        case 1024:
            credits_reg.fields.crdt_size_log2 = 0xA;
            break;

        case 2048:
            credits_reg.fields.crdt_size_log2 = 0xB;
            break;

        default:
            return LA_STATUS_EUNKNOWN;
        }
        credits_reg.fields.init_extra_credits = 0x0;
        credits_reg.fields.stop_credits_th = 0x0;
        credits_reg.fields.return_credits_th = credit_in_bytes - 1;
        credits_reg.fields.static_go_stop_credits_th = 0x01000;
        credits_reg.fields.static_go_return_credits_th = 0x01400;
        credits_reg.fields.enq_priority_th = 0x10;
        credits_reg.fields.return_crdt_on_off = 0x0;
        credits_reg.fields.max_qb_threshold = 0x00186A0;
        credits_reg.fields.random_credits_allocated = 0x0F;
        credits_reg.fields.return_crdt_queue_blocking = 0x1;
        credits_reg.fields.return_eir_crdt_slice_blocking = 0x1;
        credits_reg.fields.return_cir_crdt_slice_blocking = 0x1;
        credits_reg.fields.return_crdt_list_full_blocking = 0x1;

        reg_val_list.push_back({(slice->ics->credits_conf_reg), credits_reg});

        ics_slice_general_conf_reg_register ics_gen_conf;
        ics_gen_conf.fields.network_slice1_fabric_slice0 = 1;
        ics_gen_conf.fields.scrubber_step = 0;
        ics_gen_conf.fields.scrubber_req_type = 0;
        ics_gen_conf.fields.slb_req_type = 3;
        ics_gen_conf.fields.slb_link_voqs_offset = 3;
        ics_gen_conf.fields.level_to_stop_pdvoq = 0x080;
        ics_gen_conf.fields.rand_crdt_req_limit = 0x10;
        ics_gen_conf.fields.ignore_credits = 0;
        ics_gen_conf.fields.pause_checkin_machine = 1; // Before soft-reset set to 1, after soft reset set to 0.
        ics_gen_conf.fields.evict_to_dram_with_credits = 1;
        ics_gen_conf.fields.evict_to_dram_while_eligible = 1;
        ics_gen_conf.fields.evict_to_dram_while_dequeue = 1;
        ics_gen_conf.fields.evict_to_dram_ignore_shapers = 0;
        ics_gen_conf.fields.retransmit_on_ib_fifo_full = 0;
        reg_val_list.push_back({(slice->ics->general_conf_reg), ics_gen_conf});

        reg_val_list.push_back({(slice->ics->scrubber_th_reg), 4});
        reg_val_list.push_back({(slice->ics->context_msb_reg), 0});
    }

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_filb()
{
    // Initialize registers and memories
    lld_register_value_list_t reg_val_list;

    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_NON_FABRIC)) {
        for (size_t j = 0; j < m_pacific_tree->slice[0]->filb->serdes2link->size(); j++) {
            size_t link_id = (j / 2) % 19;
            reg_val_list.push_back({(*m_pacific_tree->slice[slice]->filb->serdes2link)[j], link_id});
        }

        reg_val_list.push_back(
            {(m_pacific_tree->slice[slice]->filb->general_conf_reg), bit_vector("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE")});

        // Send to delete on slices 3-5
        reg_val_list.push_back({(m_pacific_tree->slice[slice]->filb->filb_delete_xbar), (slice + 3)});

        if ((m_device_mode == device_mode_e::LINECARD) && is_network_slice(slice)) {
            // Packet packing occurs only in LC mode from Network slices
            reg_val_list.push_back({(m_pacific_tree->slice[slice]->filb->packing_reg), bit_vector("0xFFD7064")});
        }
    }

    for (la_slice_id_t slice : get_slice_id_manager()->get_slices_by_fabric_type(fabric_slices_type_e::HW_NON_FABRIC)) {
        reg_val_list.push_back({(m_pacific_tree->slice[slice]->filb->slb_reg), bit_vector("0xE07038180A05012C0")});
    }

    la_status status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_pdoq_fdoq()
{
    lld_register_value_list_t reg_val_list;

    reg_val_list.push_back({(m_pacific_tree->pdoq_shared_mem->dram_packing_configuration), 0x8});
    for (la_slice_id_t slice : get_used_slices()) {
        reg_val_list.push_back({(*m_pacific_tree->pdoq_shared_mem->slice_mode_configuration)[slice], m_tm_slice_mode[slice]});

        pdoq_fdoq_fdoq_general_configuration_register fdoq_general_cfg;
        // In TX-Network slice, indicate which are RX-fabric slices, to allow dual PD unpacking
        if (is_network_slice(slice)) {
            bit_vector unpack_pd_enable(0, ASIC_MAX_SLICES_PER_DEVICE_NUM);
            for (la_slice_id_t rx_sid : get_used_slices()) {
                if (m_slice_mode[rx_sid] == la_slice_mode_e::CARRIER_FABRIC) {
                    unpack_pd_enable.set_bit(rx_sid, 1);
                }
            }
            fdoq_general_cfg.fields.unpack_pd_enable = unpack_pd_enable.get_value();
        } else {
            fdoq_general_cfg.fields.unpack_pd_enable = 0;
        }
        fdoq_general_cfg.fields.slice_mode = m_tm_slice_mode[slice];
        fdoq_general_cfg.fields.mlp_en = 0;
        fdoq_general_cfg.fields.fabric_fast_link_enable = 0;
        fdoq_general_cfg.fields.txpp_fc_enable = 0;
        fdoq_general_cfg.fields.delete_sp_disable = 1;

        reg_val_list.push_back({(m_pacific_tree->slice[slice]->pdoq->fdoq->fdoq_general_configuration), fdoq_general_cfg});
        reg_val_list.push_back({(m_pacific_tree->slice[slice]->pdoq->fdoq->fdoq_pdif_fifo_alm_full_th), 4});

        // Disable initiation of IFG Tx buffer credit counter, will be enabled as part of port creation.
        reg_val_list.push_back({(m_pacific_tree->slice[slice]->pdoq->fdoq->ifg_credit_init), bit_vector("0xFFFFFFFFFF")});

        // Set the partial mirror packet size to 256B (bit number 31 to 40)
        reg_val_list.push_back(
            {(m_pacific_tree->slice[slice]->pdoq->fdoq->partial_mirror_configuration), bit_vector("0x10000000000")});

        reg_val_list.push_back({(*m_pacific_tree->pdoq_shared_mem->internal_fifo_alm_full)[slice], 0xC0311});

        for (la_ifg_id_t ifg = 0; ifg < m_pacific_tree->slice[slice]->pdoq->fdoq->fodq_total_ifg_thresholds->size(); ifg++) {
            reg_val_list.push_back({(*m_pacific_tree->slice[slice]->pdoq->fdoq->fodq_total_ifg_thresholds)[ifg], 0x320001F4});
        }

        if ((m_revision == la_device_revision_e::PACIFIC_B0) || (m_revision == la_device_revision_e::PACIFIC_B1)) {
            // Bits 0-15: port reset, should be 1
            // Bits 16-19 & 30-33: packet shaper, should be 0 (disabled)
            reg_val_list.push_back({(m_pacific_tree->slice[slice]->pdoq->fdoq->spare_reg), 0xFFFF});
        }
    }

    la_status status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    // Thresholds for the following speeds: 800, 400, 100, 50, 40, 25, 10, not used
    // PD threshold, 11bit LSB. Values: {300, 120, 32, 20, 16, 10, 4, 0}
    // Bytes threshold, 25bit. Values: {81920, 30720, 30720, 20480, 10000, 10000, 10000, 0}
    constexpr la_uint64_t PDS_PD_IF_FIFO_THRESHOLD[] = {0x12C, 0x078, 0x20, 0x14, 0x10, 0xA, 0x4, 0x0};
    constexpr la_uint64_t BYTES_IF_FIFO_THRESHOLD[] = {80 * KIBI, 30 * KIBI, 30 * KIBI, 20 * KIBI, 0x2710, 0x2710, 0x2710, 0x0};

    // These profiles are being used by the profile-id configured in pd_if_fifos_thresholds_profile.
    // Mapping profile->memory_line is configured by la_ifg_scheduler_impl::s_pdif_fifo_threshold_profile_id.
    pdoq_fdoq_pd_if_fifos_thresholds_memory pd_if_fifos_thresholds;
    for (size_t sid : get_used_slices()) {
        const auto& slice = m_pacific_tree->slice[sid];
        for (size_t i = 0; i < array_size(PDS_PD_IF_FIFO_THRESHOLD); i++) {
            pd_if_fifos_thresholds.fields.pdif_pds_th = PDS_PD_IF_FIFO_THRESHOLD[i];
            pd_if_fifos_thresholds.fields.pdif_bytes_th = BYTES_IF_FIFO_THRESHOLD[i];
            status = m_ll_device->write_memory(*slice->pdoq->fdoq->pd_if_fifos_thresholds, i, pd_if_fifos_thresholds);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_pdoq_top()
{
    lld_register_value_list_t reg_val_list;
    lld_memory_value_list_t mem_val_list;
    la_status status;

    // Initialize various ICS block registers to constant values according to designer's tune output.
    for (la_slice_id_t slice_i : get_used_slices()) {
        const auto& slice_pdoq_top = m_pacific_tree->slice[slice_i]->pdoq->top;

        pdoq_dqc_general_configuration_register dqc_general_cfg;
        dqc_general_cfg.fields.slice_mode = m_tm_slice_mode[slice_i];
        dqc_general_cfg.fields.retransmit_delay = 0x3FC;
        dqc_general_cfg.fields.all_credit_elig = 0;
        dqc_general_cfg.fields.slow_read_request_th = 7;
        dqc_general_cfg.fields.delete_pdif_th = DELETE_FIFO_SIZE - DELETE_FIFO_GUARD_BUFFER;
        dqc_general_cfg.fields.lc_compensation_map = 0;

        reg_val_list.push_back({(slice_pdoq_top->dqc_general_configuration), dqc_general_cfg});
        reg_val_list.push_back({(slice_pdoq_top->fabric_link_configuration), 0x22E});

        // oq_crbal_th_configuration configures profiles that are indirected by pacific_tree.slice[slice_id]->pdoq->top->oq_profile.
        pdoq_oq_crbal_th_configuration_register oq_crbal_th_configuration;
        oq_crbal_th_configuration.fields.max_credit_balance = 0x0c0c0c0c0c0c0c0c0;
        oq_crbal_th_configuration.fields.max_empty_credit_balance = 0x0c0c0c0c0c0c0c0c0;
        oq_crbal_th_configuration.fields.max_negative_credit_balance = 0x04040404040404040;
        oq_crbal_th_configuration.fields.max_empty_lfsr_mask = 0;
        reg_val_list.push_back({(slice_pdoq_top->oq_crbal_th_configuration), oq_crbal_th_configuration});

        pdoq_dqc_eligible_arbiter_register dqc_eligible_arbiter;
        status = m_ll_device->read_register(*slice_pdoq_top->dqc_eligible_arbiter, dqc_eligible_arbiter);
        return_on_error(status);
        dqc_eligible_arbiter.fields.elig_arb_delete_sp_pd_th = 128;
        dqc_eligible_arbiter.fields.elig_arb_delete_sp_buffer_th = 256;
        reg_val_list.push_back({(slice_pdoq_top->dqc_eligible_arbiter), dqc_eligible_arbiter});

        pdoq_pdoq_credit_value_register pdoq_credit_value_reg;
        status = m_ll_device->read_register(*slice_pdoq_top->pdoq_credit_value, pdoq_credit_value_reg);
        return_on_error(status);
        pdoq_credit_value_reg.fields.credit_value = tm_utils::TX_SCH_TOKEN_SIZE;
        reg_val_list.push_back({(slice_pdoq_top->pdoq_credit_value), pdoq_credit_value_reg});

        const lld_register_desc_t* ifse_cir_shaper_max_bucket_configuration_desc
            = slice_pdoq_top->ifse_cir_shaper_max_bucket_configuration->get_desc();

        size_t max_bucket_size
            = is_fabric_slice(slice_i) ? tm_utils::MAX_FABRIC_TRANSMIT_BUCKET_SIZE : tm_utils::MAX_TRANSMIT_BUCKET_SIZE;
        for (size_t port = 0; port < ifse_cir_shaper_max_bucket_configuration_desc->instances; port++) {
            reg_val_list.push_back({(*slice_pdoq_top->ifse_cir_shaper_max_bucket_configuration)[port], max_bucket_size});
            reg_val_list.push_back({(*slice_pdoq_top->ifse_cir_shaper_rate_configuration)[port], 0});
            reg_val_list.push_back({(*slice_pdoq_top->ifse_pir_shaper_max_bucket_configuration)[port], max_bucket_size});
            reg_val_list.push_back({(*slice_pdoq_top->ifse_pir_shaper_configuration)[port], 0});
        }

        lld_memory_scptr oq_profile = slice_pdoq_top->oq_profile;
        mem_val_list.push_back({oq_profile, bit_vector(2, oq_profile->get_desc()->width_bits)});
    }

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_pdvoq()
{
    // TODO: Remove most of the initialization here, MUST be part of VOQ CGM profile.
    // Note: Most of those LBR tables has NPL table and MUST be configured using VOQ CGM API.
    // TODO: Remove this hack!
    lld_register_value_list_t reg_val_list;
    lld_memory_value_list_t mem_val_list;
    lld_memory_line_value_list_t mem_line_val_list;
    la_status status;

    enum {
        PROFILE_BUFF_REGION_THRESHOLD_WIDTH = 14,
        PROFILE_BUFF_REGION_THRESHOLD_COUNT = 7,
    };

    int profile_buff_region_thresholds_values[] = {1500, 1510, 1520, 1530, 1540, 1550, 1560};
    bit_vector profile_buff_region_thresholds_value;
    for (size_t i = 0; i < PROFILE_BUFF_REGION_THRESHOLD_COUNT; i++) {
        size_t lsb = i * PROFILE_BUFF_REGION_THRESHOLD_WIDTH;
        size_t msb = lsb + PROFILE_BUFF_REGION_THRESHOLD_WIDTH - 1;
        profile_buff_region_thresholds_value.set_bits(msb, lsb, profile_buff_region_thresholds_values[i]);
    }

    for (size_t empd = 0; empd < array_size(m_pacific_tree->pdvoq->empd); empd++) {
        reg_val_list.push_back({(m_pacific_tree->pdvoq->empd[empd]->almost_full), 0x720235});
    }

    for (la_slice_id_t slice : get_used_slices()) {
        lld_memory_scptr static_mapping = nullptr;

        // The next 5 memories has NPL
        lld_memory_scptr pd_consumption_lut_for_enq = nullptr;
        lld_memory_scptr profile_buff_region_thresholds = nullptr;
        lld_memory_scptr profile_pkt_enq_time_region_thresholds = nullptr;
        lld_memory_scptr profile_pkt_region_thresholds = nullptr;
        lld_memory_scptr dram_cgm_profile = nullptr;

        // TODO: The following memory requires NPL table and proper configuration. It also requires extending the API.
        // The current configuration is default and should work properly on standalone.
        lld_memory_scptr voq_properties = nullptr;

        if (slice < FIRST_HW_FABRIC_SLICE) {
            reg_val_list.push_back({(m_pacific_tree->slice[slice]->pdvoq->almost_full_conf), 0x135179088428AULL});

            // TODO: remove the following, should be part of VOQ CGM profile
            pd_consumption_lut_for_enq = m_pacific_tree->slice[slice]->pdvoq->pd_consumption_lut_for_enq;
            profile_buff_region_thresholds = m_pacific_tree->slice[slice]->pdvoq->profile_buff_region_thresholds;
            profile_pkt_enq_time_region_thresholds = m_pacific_tree->slice[slice]->pdvoq->profile_pkt_enq_time_region_thresholds;
            profile_pkt_region_thresholds = m_pacific_tree->slice[slice]->pdvoq->profile_pkt_region_thresholds;
            dram_cgm_profile = m_pacific_tree->slice[slice]->pdvoq->dram_cgm_profile;

            voq_properties = m_pacific_tree->slice[slice]->pdvoq->voq_properties;

            static_mapping = m_pacific_tree->slice[slice]->pdvoq->static_mapping;
        } else {
            reg_val_list.push_back({(m_pacific_tree->slice[slice]->fabric_pdvoq->almost_full_conf), 0x134F79088428A});
            reg_val_list.push_back(
                {(m_pacific_tree->slice[slice]->fabric_pdvoq->cmap_th_reg), bit_vector("0xFFFFFFFFFFFF5FFFD03E83E8")});

            // TODO: remove the following, should be part of VOQ CGM profile
            pd_consumption_lut_for_enq = m_pacific_tree->slice[slice]->fabric_pdvoq->pd_consumption_lut_for_enq;
            profile_buff_region_thresholds = m_pacific_tree->slice[slice]->fabric_pdvoq->profile_buff_region_thresholds;
            profile_pkt_enq_time_region_thresholds
                = m_pacific_tree->slice[slice]->fabric_pdvoq->profile_pkt_enq_time_region_thresholds;
            profile_pkt_region_thresholds = m_pacific_tree->slice[slice]->fabric_pdvoq->profile_pkt_region_thresholds;
            dram_cgm_profile = m_pacific_tree->slice[slice]->fabric_pdvoq->dram_cgm_profile;

            voq_properties = m_pacific_tree->slice[slice]->fabric_pdvoq->voq_properties;

            static_mapping = m_pacific_tree->slice[slice]->fabric_pdvoq->static_mapping;
        }

        reg_val_list.push_back(
            {(*m_pacific_tree->pdvoq_shared_mma->voq_counter_range)[slice * NUM_VOQ_SLICE_COUNTER_REGIONS], 0x9FFF0000});

        pdvoq_shared_mma_cgm_thresholds_register cgm_thresholds;
        status = m_ll_device->read_register(*m_pacific_tree->pdvoq_shared_mma->cgm_thresholds, cgm_thresholds);
        return_on_error(status);

        if (m_device_mode == device_mode_e::STANDALONE) {
            cgm_thresholds.fields.uc_th = 64 * KIBI;
            cgm_thresholds.fields.mc_th = 6 * KIBI;
        }

        if (m_device_mode == device_mode_e::LINECARD) {
            cgm_thresholds.fields.uc_th = 48 * KIBI;
            cgm_thresholds.fields.mc_th = 6 * KIBI;
            cgm_thresholds.fields.ms_uc_th = 12 * KIBI;
            cgm_thresholds.fields.ms_mc_th = 5 * KIBI;
        }

        // FE config stays at the default

        reg_val_list.push_back({(m_pacific_tree->pdvoq_shared_mma->cgm_thresholds), cgm_thresholds});

        // Initialize to 0 the first 7 traffic class and to 0xFFFFFFFF the 8th traffic class.
        mem_val_list.push_back({pd_consumption_lut_for_enq, 0});

        for (size_t mem_line = 7; mem_line < pd_consumption_lut_for_enq->get_desc()->entries; mem_line += 8) {
            mem_line_val_list.push_back({{pd_consumption_lut_for_enq, mem_line}, bit_vector("0xFFFFFFFF")});
        }

        mem_val_list.push_back({profile_buff_region_thresholds, profile_buff_region_thresholds_value});
        mem_val_list.push_back({profile_pkt_enq_time_region_thresholds, bit_vector("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")});
        mem_val_list.push_back({profile_pkt_region_thresholds, bit_vector("0x3CF0EA636B0D483138B542968")});
        mem_val_list.push_back({dram_cgm_profile, 0});

        // Carrier-fabric slice is configured in fabric init.
        if (m_slice_mode[slice] != la_slice_mode_e::CARRIER_FABRIC) {
            mem_val_list.push_back({voq_properties, bit_vector("0x60606060606060606060606060606060")});
        }

        // Mark the last context as static context so it won't be reused - will not return to the pool
        mem_line_val_list.push_back({{static_mapping, static_mapping->get_desc()->entries - 1}, bit_vector("0x8000000000000000")});
    }

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    status = lld_write_memory_line_list(m_ll_device, mem_line_val_list);
    return_on_error(status);

    status = configure_overhead_accounting(NPU_HEADER_SIZE - ETHERNET_OVERHEAD);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_reorder()
{
    lld_register_value_list_t reg_val_list;
    lld_memory_value_list_t mem_val_list;

    la_status status = LA_STATUS_SUCCESS;

    // Port profiles for various port speeds - defines max queue size
    // The first three are for 50G port and below
    // Next are for 100G, 200G, 400G, 800G and unlimited
    constexpr la_uint_t PROFILE_CONFIG_TABLE_VALUES_REV_A0[] = {0x32, 0x32, 0x32, 0x64, 0xAF, 0x2BC, 0x4e2, 0x7FF};
    constexpr la_uint_t PROFILE_CONFIG_TABLE_VALUES_REV_B0_B1[] = {0xaf, 0xaf, 0xaf, 0xaf, 0x15e, 0x15e, 0x4e2, 0x4e2};

    nw_reorder_slice_configuration_register slice_cfg;
    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_NON_FABRIC)) {
        slice_cfg.fields.slice_my_slice_number = slice + 3;
        slice_cfg.fields.slice_ifg0_max_source_port_number = 19;
        slice_cfg.fields.slice_reorder_block_num_offset = slice * 2;
        slice_cfg.fields.slice_mode = m_tm_slice_mode[slice + 3];
        slice_cfg.fields.slice_reorder_block_sel_mode = 3;
        slice_cfg.fields.slice_outgoing_slice_setting_enable = 1;
        slice_cfg.fields.slice_outgoing_slice_set_value = slice;
        slice_cfg.fields.slice_pp_reorder_min_connection_number = 4096;
        slice_cfg.fields.slice_backpressure_mode = 0;
        slice_cfg.fields.slice_reorder_full_prevention_enable = 1;
        slice_cfg.fields.slice_reorder_full_prevention_rate_limiting = 1;

        reg_val_list.push_back({(*m_pacific_tree->nw_reorder->slice_configuration)[slice], slice_cfg});
    }

    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_NON_FABRIC)) {
        pp_reorder_slice_slice_configuration_register slice_cfg;
        slice_cfg.fields.slice_my_slice_number = slice;
        slice_cfg.fields.slice_ifg0_max_source_port_number = 19;
        slice_cfg.fields.slice_reorder_block_num_offset = 0;
        slice_cfg.fields.slice_mode = m_tm_slice_mode[slice];
        slice_cfg.fields.slice_reorder_block_sel_mode = 3;
        slice_cfg.fields.reorder_full_prevention_enable = 1;
        slice_cfg.fields.reorder_full_prevention_rate_limiting = 1;

        reg_val_list.push_back({(m_pacific_tree->slice[slice]->pp_reorder->slice_configuration), slice_cfg});

        for (size_t block = 0; block < 2; block++) {
            pp_reorder_slice_block_general_configurations_register general_cfg;
            general_cfg.fields.block_reorder_block_number = 0;
            general_cfg.fields.block_rd_fifo_thr_to_receive_strict_prio = 0x3FF;
            general_cfg.fields.block_enable_masking_pd_for_assured_read_rd = 1;
            general_cfg.fields.block_pp_reorder_min_connection_number = 0;
            general_cfg.fields.block_num_of_reorder_blocks = 1;
            general_cfg.fields.block_my_slice_number = slice;
            general_cfg.fields.block_slice_mode = m_tm_slice_mode[slice];
            general_cfg.fields.slice_packet_loss_detection_using_skew_enable = 0;

            reg_val_list.push_back({(*m_pacific_tree->slice[slice]->pp_reorder->block_general_configurations)[block], general_cfg});

            pp_reorder_slice_block_skew_configurations_register skew_cfg;
            skew_cfg.fields.block_skew_measurement_addition = 3;

            reg_val_list.push_back({(*m_pacific_tree->slice[slice]->pp_reorder->block_skew_configurations)[block], skew_cfg});

            lld_memory_scptr connection_profile_table
                = (*m_pacific_tree->slice[slice]->pp_reorder->connection_profile_table)[block];
            mem_val_list.push_back({connection_profile_table, bit_vector(6, connection_profile_table->get_desc()->width_bits)});

            for (size_t mem_line = 0; mem_line < array_size(PROFILE_CONFIG_TABLE_VALUES_REV_A0); mem_line++) {
                la_uint_t val;
                if ((m_revision == la_device_revision_e::PACIFIC_B0) || (m_revision == la_device_revision_e::PACIFIC_B1)) {
                    val = PROFILE_CONFIG_TABLE_VALUES_REV_B0_B1[mem_line];
                } else {
                    val = PROFILE_CONFIG_TABLE_VALUES_REV_A0[mem_line];
                }
                status = m_ll_device->write_memory(
                    *(*m_pacific_tree->slice[slice]->pp_reorder->profile_config_table)[block], mem_line, val);
                return_on_error(status);
            }
        }
    }

    size_t read_trig = 1;
    size_t block_num = 0;

    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_FABRIC)) {
        for (size_t block = 0; block < array_size(m_pacific_tree->slice[slice]->nw_reorder_block); block++) {
            nw_reorder_block_block_assured_read_configuration_register assured_read;
            assured_read.fields.block_assured_read_counter_threshold = 17;
            assured_read.fields.block_assured_read_trig_value = read_trig;
            read_trig *= 2;
            assured_read.fields.block_assured_read_seq_num_addition = 17;

            reg_val_list.push_back(
                {(m_pacific_tree->slice[slice]->nw_reorder_block[block]->block_assured_read_configuration), assured_read});

            nw_reorder_block_block_general_configurations_register general_cfg;
            general_cfg.fields.block_num_of_reorder_blocks = 1;
            general_cfg.fields.my_slice_number = slice;
            general_cfg.fields.block_reorder_block_number = block_num;
            general_cfg.fields.slice_mode = m_tm_slice_mode[slice];
            general_cfg.fields.block_pp_reorder_min_connection_number = 4096;
            general_cfg.fields.reset_done_fifo_full_thr = 14;
            general_cfg.fields.packet_loss_detection_using_skew_enable = 0;
            general_cfg.fields.disable_assured_read_in_slb = 0;

            reg_val_list.push_back(
                {(m_pacific_tree->slice[slice]->nw_reorder_block[block]->block_general_configurations), general_cfg});

            nw_reorder_block_block_skew_configurations_register skew_cfg;
            skew_cfg.fields.block_t_value = 0x3F;
            skew_cfg.fields.block_w_value = 0x3F;
            skew_cfg.fields.block_lower_skew_counter_threshold = 0;
            skew_cfg.fields.block_skew_measurement_addition = 3;

            reg_val_list.push_back({(m_pacific_tree->slice[slice]->nw_reorder_block[block]->block_skew_configurations), skew_cfg});

            nw_reorder_block_block_reset_configuration_register reset_cfg;
            reset_cfg.fields.block_full_scan_reset_enable = 0;
            reset_cfg.fields.block_reset_done_value = 1 << block_num;

            reg_val_list.push_back({(m_pacific_tree->slice[slice]->nw_reorder_block[block]->block_reset_configuration), reset_cfg});

            lld_memory_scptr connection_profile_table
                = m_pacific_tree->slice[slice]->nw_reorder_block[block]->connection_profile_table;
            mem_val_list.push_back({connection_profile_table, bit_vector(6, connection_profile_table->get_desc()->width_bits)});

            for (size_t mem_line = 0; mem_line < array_size(PROFILE_CONFIG_TABLE_VALUES_REV_A0); mem_line++) {
                la_uint_t val;
                if ((m_revision == la_device_revision_e::PACIFIC_B0) || (m_revision == la_device_revision_e::PACIFIC_B1)) {
                    val = PROFILE_CONFIG_TABLE_VALUES_REV_B0_B1[mem_line];
                } else {
                    val = PROFILE_CONFIG_TABLE_VALUES_REV_A0[mem_line];
                }
                status = m_ll_device->write_memory(
                    *m_pacific_tree->slice[slice]->nw_reorder_block[block]->profile_config_table, mem_line, val);
                return_on_error(status);
            }

            block_num++;
        }
    }

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_rxcgm()
{
    la_status status;
    lld_memory_value_list_t mem_val_list;

    for (la_slice_id_t slice : get_used_slices()) {
        lld_memory_scptr ctc_group_profile_lut = (*m_pacific_tree->rx_cgm->ctc_group_profile_lut)[slice];
        lld_memory_scptr ctc_profile_lut = (*m_pacific_tree->rx_cgm->ctc_profile_lut)[slice];

        if (m_device_mode == device_mode_e::STANDALONE) {
            mem_val_list.push_back({ctc_group_profile_lut, bit_vector(0x6A665000, ctc_group_profile_lut->get_desc()->width_bits)});
            mem_val_list.push_back({ctc_profile_lut, bit_vector(0x54CE4000, ctc_profile_lut->get_desc()->width_bits)});
        } else {
            // LC or FE
            mem_val_list.push_back({ctc_group_profile_lut, bit_vector(0x80006000, ctc_group_profile_lut->get_desc()->width_bits)});
            mem_val_list.push_back({ctc_profile_lut, bit_vector(0x6a665000, ctc_profile_lut->get_desc()->width_bits)});
        }

        lld_memory_scptr source_if_to_port_map = (*m_pacific_tree->rx_cgm->source_if_to_port_map)[slice];
        for (size_t mem_line = 0; mem_line < source_if_to_port_map->get_desc()->entries; mem_line++) {
            size_t port = (mem_line < 20 ? mem_line : mem_line - 20) & 0x1F;
            size_t ifg = mem_line < 20 ? 0 : 1;
            status = m_ll_device->write_memory(*source_if_to_port_map, mem_line, port | (ifg << 5));
            return_on_error(status);
        }

        lld_memory_scptr sq_group_profile_lut = (*m_pacific_tree->rx_cgm->sq_group_profile_lut)[slice];
        for (size_t mem_line = 0; mem_line < sq_group_profile_lut->get_desc()->entries; mem_line++) {
            bit_vector value;

            if (m_device_mode == device_mode_e::STANDALONE) {
                if (mem_line == 0) {
                    value = bit_vector("0x8000299a0a66");
                } else {
                    // mem_line > 0
                    value = bit_vector("0x14000699a1a66");
                }
            } else {
                // LC or FE
                if (mem_line == 0) {
                    value = bit_vector("0xF00050001400");
                } else {
                    // mem_line > 0
                    value = bit_vector("0x28000D4CC3551");
                }
            }

            status = m_ll_device->write_memory(*sq_group_profile_lut, mem_line, value);
            return_on_error(status);
        }

        lld_memory_scptr tc_to_cgm_tc_lut = (*m_pacific_tree->rx_cgm->tc_to_cgm_tc_lut)[slice];
        for (size_t tc = 0; tc < tc_to_cgm_tc_lut->get_desc()->entries; tc++) {
            size_t val = tc % 4 + (tc / 4) * 0xC;
            status = m_ll_device->write_memory(*tc_to_cgm_tc_lut, tc, val);
            return_on_error(status);
        }

        lld_memory_scptr sq_map_table = (*m_pacific_tree->rx_cgm->sq_map_table)[slice];
        for (size_t line = 0; line < sq_map_table->get_desc()->entries; line++) {
            la_uint_t val = 2; // Map mode, port
            val |= (line < 40) ? (line << 5) : 0;
            status = m_ll_device->write_memory(*sq_map_table, line, val);
            return_on_error(status);
        }
    }

    status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    for (la_slice_id_t slice : get_used_slices()) {
        lld_memory_scptr sq_profile_lut = (*m_pacific_tree->rx_cgm->sq_profile_lut)[slice];
        status = m_ll_device->write_memory(*sq_profile_lut, 0, bit_vector("0x400014CC04CD"));
        return_on_error(status);
        status = m_ll_device->write_memory(*sq_profile_lut, 1, bit_vector("0x80002998099A"));
        return_on_error(status);
        status = m_ll_device->write_memory(*sq_profile_lut, 2, bit_vector("0x20000A6602668"));
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_txcgm()
{
    la_status status = LA_STATUS_SUCCESS;
    lld_register_value_list_t reg_val_list;
    lld_memory_value_list_t mem_val_list;
    lld_memory_line_value_list_t mem_line_val_list;

    bool is_lc_type_2_4_t;
    status = get_bool_property(la_device_property_e::LC_TYPE_2_4_T, is_lc_type_2_4_t);
    return_on_error(status);

    reg_val_list.push_back(
        {(m_pacific_tree->tx_cgm_top->buffer_pool_histogram_cfg), bit_vector("0x320096003E8019000960032000C80000")});

    // total_sch_uc_buffers_th
    txcgm_top_total_sch_uc_buffers_th_register total_sch_uc_buffers_th;
    status = m_ll_device->read_register(*m_pacific_tree->tx_cgm_top->total_sch_uc_buffers_th, total_sch_uc_buffers_th);
    return_on_error(status);

    if (m_device_mode == device_mode_e::STANDALONE) {
        total_sch_uc_buffers_th.fields.total_sch_uc_buffers_fc_th
            = (m_revision == la_device_revision_e::PACIFIC_B1) ? 18 * KIBI : 8 * KIBI;
        total_sch_uc_buffers_th.fields.total_sch_uc_buffers_drop_th = 100 * KIBI;
        total_sch_uc_buffers_th.fields.remote_sch_uc_buffers_drop_th = 100 * KIBI;
        total_sch_uc_buffers_th.fields.remote_sch_uc_buffers_fcn_th = 100 * KIBI;
    } else if (m_device_mode == device_mode_e::LINECARD) {
        if (is_lc_type_2_4_t) {
            total_sch_uc_buffers_th.fields.total_sch_uc_buffers_fc_th
                = (m_revision == la_device_revision_e::PACIFIC_B1) ? 24 * KIBI : 14 * KIBI;
        } else { // LC type is 3.6T
            total_sch_uc_buffers_th.fields.total_sch_uc_buffers_fc_th
                = (m_revision == la_device_revision_e::PACIFIC_B1) ? 25 * KIBI : 15 * KIBI;
        }
        total_sch_uc_buffers_th.fields.total_sch_uc_buffers_drop_th
            = bit_utils::ones(total_sch_uc_buffers_th.fields.TOTAL_SCH_UC_BUFFERS_DROP_TH_WIDTH);
        total_sch_uc_buffers_th.fields.remote_sch_uc_buffers_drop_th = 100 * KIBI;
        total_sch_uc_buffers_th.fields.remote_sch_uc_buffers_fcn_th = 100 * KIBI;
    } else {
        // FE
        total_sch_uc_buffers_th.fields.total_sch_uc_buffers_fc_th
            = bit_utils::ones(total_sch_uc_buffers_th.fields.TOTAL_SCH_UC_BUFFERS_FC_TH_WIDTH);
        total_sch_uc_buffers_th.fields.total_sch_uc_buffers_drop_th = 64 * KIBI;
        total_sch_uc_buffers_th.fields.remote_sch_uc_buffers_drop_th
            = bit_utils::ones(total_sch_uc_buffers_th.fields.REMOTE_SCH_UC_BUFFERS_DROP_TH_WIDTH);
        total_sch_uc_buffers_th.fields.remote_sch_uc_buffers_fcn_th = 48 * KIBI;
    }

    reg_val_list.push_back({(m_pacific_tree->tx_cgm_top->total_sch_uc_buffers_th), total_sch_uc_buffers_th});

    // total_sch_uc_pd_th
    txcgm_top_total_sch_uc_pd_th_register total_sch_uc_pd_th;
    status = m_ll_device->read_register(*m_pacific_tree->tx_cgm_top->total_sch_uc_pd_th, total_sch_uc_pd_th);
    return_on_error(status);

    if (m_device_mode == device_mode_e::STANDALONE) {
        total_sch_uc_pd_th.fields.total_sch_uc_pds_drop_th
            = bit_utils::ones(total_sch_uc_pd_th.fields.TOTAL_SCH_UC_PDS_DROP_TH_WIDTH);
    } else if (m_device_mode == device_mode_e::LINECARD) {
        total_sch_uc_pd_th.fields.total_sch_uc_pds_fc_th = 10 * KIBI;
        total_sch_uc_pd_th.fields.total_sch_uc_pds_drop_th = 20 * KIBI;
    } else {
        // FE
        total_sch_uc_pd_th.fields.total_sch_uc_pds_fc_th = bit_utils::ones(total_sch_uc_pd_th.fields.TOTAL_SCH_UC_PDS_FC_TH_WIDTH);
        total_sch_uc_pd_th.fields.total_sch_uc_pds_drop_th = 16 * KIBI;
    }

    reg_val_list.push_back({(m_pacific_tree->tx_cgm_top->total_sch_uc_pd_th), total_sch_uc_pd_th});

    // total_mc_pd_th
    txcgm_top_total_mc_pd_th_register total_mc_pd_th;
    status = m_ll_device->read_register(*m_pacific_tree->tx_cgm_top->total_mc_pd_th, total_mc_pd_th);
    return_on_error(status);

    if (m_device_mode == device_mode_e::STANDALONE) {
        total_mc_pd_th.fields.total_mc_pds_drop_th = 17 * KIBI;
        total_mc_pd_th.fields.total_mc_pds_status_th0 = 9 * KIBI;
        total_mc_pd_th.fields.total_mc_pds_status_th1 = 13 * KIBI;
        total_mc_pd_th.fields.total_mc_pds_status_th2 = 15 * KIBI;
    } else if (m_device_mode == device_mode_e::LINECARD) {
        total_mc_pd_th.fields.total_mc_pds_drop_th = 13 * KIBI;
        total_mc_pd_th.fields.total_mc_pds_status_th0 = 7 * KIBI;
        total_mc_pd_th.fields.total_mc_pds_status_th1 = 10 * KIBI;
        total_mc_pd_th.fields.total_mc_pds_status_th2 = 11.5 * KIBI;
    } else {
        // FE
        total_mc_pd_th.fields.total_mc_pds_drop_th = 11 * KIBI;
    }
    reg_val_list.push_back({(m_pacific_tree->tx_cgm_top->total_mc_pd_th), total_mc_pd_th});

    // total_ms_pd_th
    txcgm_top_total_ms_pd_th_register total_ms_pd_th;
    status = m_ll_device->read_register(*m_pacific_tree->tx_cgm_top->total_ms_pd_th, total_ms_pd_th);
    return_on_error(status);

    if (m_device_mode == device_mode_e::STANDALONE) {
        total_ms_pd_th.fields.total_ms_voq_pds_fc_th = 32000;
        total_ms_pd_th.fields.total_ms_voq_ms_oq_pds_fc_th = 32000;
        total_ms_pd_th.fields.total_ms_voq_ms_oq_nwk_oq_pds_fc_th = 32000;
        total_ms_pd_th.fields.total_ms_voq_pds_drop_th = 100000;
        total_ms_pd_th.fields.total_ms_voq_ms_oq_pds_drop_th = 100000;
        total_ms_pd_th.fields.total_ms_voq_ms_oq_nwk_oq_pds_drop_th = 100000;
    } else if (m_device_mode == device_mode_e::LINECARD) {
        total_ms_pd_th.fields.total_ms_voq_pds_fc_th = 8 * KIBI;
        total_ms_pd_th.fields.total_ms_voq_ms_oq_pds_fc_th = 8 * KIBI;
        if (is_lc_type_2_4_t) {
            total_ms_pd_th.fields.total_ms_voq_ms_oq_nwk_oq_pds_fc_th = 12 * KIBI;
        } else { // LC type is 3.6T
            total_ms_pd_th.fields.total_ms_voq_ms_oq_nwk_oq_pds_fc_th = 15 * KIBI;
        }
        total_ms_pd_th.fields.total_ms_voq_pds_drop_th = bit_utils::ones(total_ms_pd_th.fields.TOTAL_MS_VOQ_PDS_DROP_TH_WIDTH);
        total_ms_pd_th.fields.total_ms_voq_ms_oq_pds_drop_th = 20 * KIBI;
        total_ms_pd_th.fields.total_ms_voq_ms_oq_nwk_oq_pds_drop_th
            = bit_utils::ones(total_ms_pd_th.fields.TOTAL_MS_VOQ_MS_OQ_NWK_OQ_PDS_DROP_TH_WIDTH);
    } else {
        // FE
        total_ms_pd_th.fields.total_ms_voq_pds_fc_th = 8 * KIBI;
        total_ms_pd_th.fields.total_ms_voq_ms_oq_pds_fc_th = 8 * KIBI;
        total_ms_pd_th.fields.total_ms_voq_ms_oq_nwk_oq_pds_fc_th = 12 * KIBI;
        total_ms_pd_th.fields.total_ms_voq_pds_drop_th = bit_utils::ones(total_ms_pd_th.fields.TOTAL_MS_VOQ_PDS_DROP_TH_WIDTH);
        total_ms_pd_th.fields.total_ms_voq_ms_oq_pds_drop_th
            = bit_utils::ones(total_ms_pd_th.fields.TOTAL_MS_VOQ_MS_OQ_PDS_DROP_TH_WIDTH);
        total_ms_pd_th.fields.total_ms_voq_ms_oq_nwk_oq_pds_drop_th
            = bit_utils::ones(total_ms_pd_th.fields.TOTAL_MS_VOQ_MS_OQ_NWK_OQ_PDS_DROP_TH_WIDTH);
    }

    reg_val_list.push_back({(m_pacific_tree->tx_cgm_top->total_ms_pd_th), total_ms_pd_th});

    // total_fab_pd_th
    if (m_device_mode == device_mode_e::LINECARD) {
        txcgm_top_total_fab_pd_th_register total_fab_pd_th;

        status = m_ll_device->read_register(*m_pacific_tree->tx_cgm_top->total_fab_pd_th, total_fab_pd_th);
        return_on_error(status);

        total_fab_pd_th.fields.total_fab_pds_fcn_th = bit_utils::ones(total_fab_pd_th.fields.TOTAL_FAB_PDS_FCN_TH_WIDTH);

        reg_val_list.push_back({(m_pacific_tree->tx_cgm_top->total_fab_pd_th), total_fab_pd_th});
    }

    lld_memory_scptr top_source_link_map = m_pacific_tree->tx_cgm_top->source_link_map;
    for (size_t line = 0; line < top_source_link_map->get_desc()->entries; line++) {
        la_uint_t val
            = ((line % 20) == 19)
                  ? 18
                  : ((line % 20) == 18) ? 0 : ((line % 2) == 1) ? 0 : (line < 19) ? line / 2 : (line < 39) ? (line / 2) - 1 : 0;
        mem_line_val_list.push_back({{top_source_link_map, line}, val});
    }

    // Initialize various block thresholds
    for (la_slice_id_t slice : get_used_slices()) {
        txcgm_general_configuration_register txcgm_general_cfg;
        txcgm_general_cfg.fields.slice_mode = m_tm_slice_mode[slice];
        txcgm_general_cfg.fields.drop_all_pds = 0;
        txcgm_general_cfg.fields.pd_color_map = 0xE4;
        txcgm_general_cfg.fields.drop_color_uc_enable = 0;
        txcgm_general_cfg.fields.drop_color_mc_enable = 0;
        if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
            // Only in FE mode: Port counting only on UCH/UCL (5,6) Qs
            uint64_t enable_uc_oqg_accounting = 0;
            bit_utils::set_bit(&enable_uc_oqg_accounting, NPL_FABRIC_OQ_TYPE_PLB_UC_LOW, true);
            bit_utils::set_bit(&enable_uc_oqg_accounting, NPL_FABRIC_OQ_TYPE_PLB_UC_HIGH, true);
            txcgm_general_cfg.fields.enable_uc_oqg_accounting = enable_uc_oqg_accounting;
        } else {
            txcgm_general_cfg.fields.enable_uc_oqg_accounting = 0xFF;
        }

        txcgm_general_cfg.fields.packet_rate_limiter = 0;
        txcgm_general_cfg.fields.disable_ucdv_res = 0;
        txcgm_general_cfg.fields.disable_ucdv_fe_mode = 0;
        reg_val_list.push_back({(m_pacific_tree->slice[slice]->tx->cgm->general_configuration), txcgm_general_cfg});

        if (slice >= 3) {
            for (la_ifg_id_t ifg = 0; ifg < 2; ifg++) {
                reg_val_list.push_back({(*m_pacific_tree->slice[slice]->tx->cgm->fabric_link_mc_th_configuration)[ifg],
                                        bit_vector("0x3FFFF001E00050000F00014")});
                reg_val_list.push_back({(*m_pacific_tree->slice[slice]->tx->cgm->fabric_link_uch_th_configuration)[ifg],
                                        bit_vector("0x1E00050000F00014")});
                reg_val_list.push_back({(*m_pacific_tree->slice[slice]->tx->cgm->fabric_link_ucl_th_configuration)[ifg],
                                        bit_vector("0x1E00050000F00014")});
            }
        }

        lld_memory_scptr counter_set_map = m_pacific_tree->slice[slice]->tx->cgm->counter_set_map;

        // Initialize to point to 0. Counters 1-3 will allocated.
        for (size_t line = 0; line < counter_set_map->get_desc()->entries; line++) {
            mem_line_val_list.push_back({{counter_set_map, line}, 0});
        }

        txcgm_delete_flow_control_register delete_flow_control_reg;
        status = m_ll_device->read_register(*m_pacific_tree->slice[slice]->tx->cgm->delete_flow_control, delete_flow_control_reg);
        return_on_error(status);

        // delete pd size is 128, divide it into quarters
        delete_flow_control_reg.fields.delete_lb_fc_pd_th0 = 32;
        delete_flow_control_reg.fields.delete_lb_fc_pd_th1 = 64;
        delete_flow_control_reg.fields.delete_lb_fc_pd_th2 = 96;

        // delete buffer size is 256, divide it into quarters
        delete_flow_control_reg.fields.delete_lb_fc_buffer_th0 = 64;
        delete_flow_control_reg.fields.delete_lb_fc_buffer_th1 = 128;
        delete_flow_control_reg.fields.delete_lb_fc_buffer_th2 = 192;

        if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
            delete_flow_control_reg.fields.delete_fc_pd_th = 10000;
            delete_flow_control_reg.fields.delete_fc_buffer_th = 40000;
        }

        reg_val_list.push_back({(m_pacific_tree->slice[slice]->tx->cgm->delete_flow_control), delete_flow_control_reg});

        status = prepare_tx_cgm_uc_ifg_profile(mem_val_list, slice);
        return_on_error(status);

        std::map<la_mac_port::port_speed_e, uint64_t> fc_bytes_th_arr;
        status = prepare_tx_cgm_uc_oq_profile(mem_val_list, mem_line_val_list, slice, is_lc_type_2_4_t, fc_bytes_th_arr);
        return_on_error(status);

        status = prepare_tx_cgm_uc_oqg_profile(mem_val_list, mem_line_val_list, slice, is_lc_type_2_4_t, fc_bytes_th_arr);
        return_on_error(status);

        status = prepare_tx_cgm_mc_oq_profile(mem_val_list, mem_line_val_list, slice);
        return_on_error(status);

        status = prepare_tx_cgm_mc_byte_pd_drop_resolutions(mem_val_list, mem_line_val_list, slice);
        return_on_error(status);

        // The profile mapping re-initialized in interface scheduler initialization according to port speed.
        lld_memory_scptr uc_oq_profile_map = m_pacific_tree->slice[slice]->tx->cgm->uc_oq_profile_map;
        mem_val_list.push_back({uc_oq_profile_map, 0});

        lld_memory_scptr mc_oq_profile_map = m_pacific_tree->slice[slice]->tx->cgm->mc_oq_profile_map;
        mem_val_list.push_back({mc_oq_profile_map, 0});

        lld_memory_scptr uc_oqg_profile_map = m_pacific_tree->slice[slice]->tx->cgm->uc_oqg_profile_map;
        mem_val_list.push_back({uc_oqg_profile_map, 0});

        // By default, all OQs are disabled and will be dropped. The bit is cleared on creation.
        lld_memory_scptr oq_drop_bitmap = m_pacific_tree->slice[slice]->tx->cgm->oq_drop_bitmap;
        mem_val_list.push_back({oq_drop_bitmap, 0xFF});

        lld_memory_scptr fabric_link_map = m_pacific_tree->slice[slice]->tx->cgm->fabric_link_map;
        for (size_t line = 0; line < fabric_link_map->get_desc()->entries; line++) {
            la_uint_t val;
            if (is_network_slice(slice)) {
                val = (line == 19) ? 9
                                   : (((line % 20) == 9) || (line == 38) || (line == 39))
                                         ? 0x12
                                         : ((line % 2) == 1) ? 0 : (line < 19) ? line / 2 : (line < 39) ? (line / 2) - 1 : 0;
            } else if (m_slice_mode[slice] == la_slice_mode_e::CARRIER_FABRIC) {
                val = (line < 9) ? line
                                 : ((line % 20) == 9)
                                       ? 0x12
                                       : ((line > 9) && (line < 20)) ? 0 : ((line >= 20) && (line < 29)) ? (line - 20 + 9) : 0;

            } else {
                return LA_STATUS_ENOTIMPLEMENTED;
            }

            mem_line_val_list.push_back({{fabric_link_map, line}, val});
        }

        lld_memory_scptr mc_oq_pd_drop_resolution = m_pacific_tree->slice[slice]->tx->cgm->mc_oq_pd_drop_resolution;
        mem_val_list.push_back({mc_oq_pd_drop_resolution, 0});
    }

    // Write all at once
    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    status = lld_write_memory_line_list(m_ll_device, mem_line_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::prepare_tx_cgm_uc_ifg_profile(lld_memory_value_list_t& mem_val_list, la_slice_id_t slice)
{
    // Initialize the profiles
    txcgm_uc_ifg_profile_memory uc_ifg_profile;

    uc_ifg_profile.fields.flow_control_bytes_th = bit_utils::ones(uc_ifg_profile.fields.FLOW_CONTROL_BYTES_TH_WIDTH);
    uc_ifg_profile.fields.flow_control_buffers_th = bit_utils::ones(uc_ifg_profile.fields.FLOW_CONTROL_BUFFERS_TH_WIDTH);
    uc_ifg_profile.fields.flow_control_pds_th = bit_utils::ones(uc_ifg_profile.fields.FLOW_CONTROL_PDS_TH_WIDTH);

    mem_val_list.push_back({(m_pacific_tree->slice[slice]->tx->cgm->uc_ifg_profile), uc_ifg_profile});

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::prepare_tx_cgm_uc_oq_profile(lld_memory_value_list_t& mem_val_list,
                                             lld_memory_line_value_list_t& mem_line_val_list,
                                             la_slice_id_t slice,
                                             bool is_lc_type_2_4_t,
                                             std::map<la_mac_port::port_speed_e, uint64_t>& out_fc_bytes_th_arr)
{
    // Initialize the profiles
    txcgm_uc_oq_profile_memory uc_oq_profile;

    uc_oq_profile.fields.flow_control_buffers_th = bit_utils::ones(uc_oq_profile.fields.FLOW_CONTROL_BUFFERS_TH_WIDTH);
    uc_oq_profile.fields.flow_control_pds_th = bit_utils::ones(uc_oq_profile.fields.FLOW_CONTROL_PDS_TH_WIDTH);
    uc_oq_profile.fields.fcn_bytes_th = bit_utils::ones(uc_oq_profile.fields.FCN_BYTES_TH_WIDTH);
    uc_oq_profile.fields.drop_bytes_th = bit_utils::ones(uc_oq_profile.fields.DROP_BYTES_TH_WIDTH);

    if (is_network_slice(slice)) {
        // SA or LC network slice
        uc_oq_profile.fields.drop_buffers_th = bit_utils::ones(uc_oq_profile.fields.DROP_BUFFERS_TH_WIDTH);
        uc_oq_profile.fields.drop_pds_th = bit_utils::ones(uc_oq_profile.fields.DROP_PDS_TH_WIDTH);
        uc_oq_profile.fields.fcn_buffers_th = bit_utils::ones(uc_oq_profile.fields.FCN_BUFFERS_TH_WIDTH);
        uc_oq_profile.fields.fcn_pds_th = bit_utils::ones(uc_oq_profile.fields.FCN_PDS_TH_WIDTH);
        uc_oq_profile.fields.pd_counter_type = 0;
    }

    if ((m_device_mode == device_mode_e::LINECARD) && (m_slice_mode[slice] == la_slice_mode_e::CARRIER_FABRIC)) {
        uc_oq_profile.fields.flow_control_bytes_th = bit_utils::ones(uc_oq_profile.fields.FLOW_CONTROL_BYTES_TH_WIDTH);
        uc_oq_profile.fields.drop_buffers_th = 800;
        uc_oq_profile.fields.drop_pds_th = 800;
        uc_oq_profile.fields.fcn_buffers_th = bit_utils::ones(uc_oq_profile.fields.FCN_BUFFERS_TH_WIDTH);
        uc_oq_profile.fields.fcn_pds_th = bit_utils::ones(uc_oq_profile.fields.FCN_PDS_TH_WIDTH);
        uc_oq_profile.fields.pd_counter_type = 2;
    }

    if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        uc_oq_profile.fields.flow_control_bytes_th = bit_utils::ones(uc_oq_profile.fields.FLOW_CONTROL_BYTES_TH_WIDTH);
        uc_oq_profile.fields.drop_buffers_th = 2000;
        uc_oq_profile.fields.drop_pds_th = bit_utils::ones(uc_oq_profile.fields.DROP_PDS_TH_WIDTH);
        uc_oq_profile.fields.fcn_buffers_th = 341;
        uc_oq_profile.fields.fcn_pds_th = 341;
        uc_oq_profile.fields.pd_counter_type = 0;
    }

    lld_memory_scptr uc_oq_profile_ptr = m_pacific_tree->slice[slice]->tx->cgm->uc_oq_profile;

    if (is_network_slice(slice)) {
        // SA or LC network slice
        double flow_control_bytes_per_1gig;
        if (m_device_mode == device_mode_e::STANDALONE) {
            flow_control_bytes_per_1gig = (double)48 * KIBI / 100; // 48 KB for 100G port
        } else {
            // LC network slice
            flow_control_bytes_per_1gig = (double)230 * KIBI / 100; // 230 KB for 100G port
        }

        // UC OQ profiles - we use 8 profiles. First set all to drop, then configure specific.
        mem_val_list.push_back({uc_oq_profile_ptr, bit_vector("0x3FFFFFFFFFFFF0000000000003FFFFFFFFFFFF")});

        for (la_mac_port::port_speed_e i : m_device_port_handler->get_supported_speeds()) {
            la_mac_port::port_speed_e port_speed = (i < la_mac_port::port_speed_e::E_50G) ? la_mac_port::port_speed_e::E_50G : i;
            uint64_t fc_bytes_th = flow_control_bytes_per_1gig * la_2_port_speed(port_speed) / BYTE_THRESHOLD_RESOLUTION;
            uc_oq_profile.fields.flow_control_bytes_th = fc_bytes_th;
            out_fc_bytes_th_arr[i] = fc_bytes_th;
            uc_oq_profile.fields.drop_bytes_th = bit_utils::ones(uc_oq_profile.fields.DROP_BYTES_TH_WIDTH);

            // Configure the speed in reverse to the profile index. So #0 is 800G, ..., #7 is 10G, etc.
            la_uint_t oq_profile_id = la_interface_scheduler_impl::TX_CGM_PROFILE_MAP.at(i);
            mem_line_val_list.push_back({{uc_oq_profile_ptr, oq_profile_id}, uc_oq_profile});

            // Configure an additional OQ profile per port speed for use with PFC.
            oq_profile_id = la_interface_scheduler_impl::TX_CGM_PROFILE_MAP_PFC.at(i);
            mem_line_val_list.push_back({{uc_oq_profile_ptr, oq_profile_id}, uc_oq_profile});
        }
    } else {
        // LC fabric slice or FE
        mem_val_list.push_back({uc_oq_profile_ptr, uc_oq_profile});
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::prepare_tx_cgm_uc_oqg_profile(lld_memory_value_list_t& mem_val_list,
                                              lld_memory_line_value_list_t& mem_line_val_list,
                                              la_slice_id_t slice,
                                              bool is_lc_type_2_4_t,
                                              const std::map<la_mac_port::port_speed_e, uint64_t>& fc_bytes_th_arr)
{
    // Initialize the profiles
    txcgm_uc_oqg_profile_memory uc_oqg_profile;
    uc_oqg_profile.fields.flow_control_buffers_th = bit_utils::ones(uc_oqg_profile.fields.FLOW_CONTROL_BUFFERS_TH_WIDTH);
    uc_oqg_profile.fields.flow_control_pds_th = bit_utils::ones(uc_oqg_profile.fields.FLOW_CONTROL_PDS_TH_WIDTH);
    uc_oqg_profile.fields.drop_pds_th = bit_utils::ones(uc_oqg_profile.fields.DROP_PDS_TH_WIDTH);
    uc_oqg_profile.fields.drop_bytes_th = bit_utils::ones(uc_oqg_profile.fields.DROP_BYTES_TH_WIDTH);

    if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        uc_oqg_profile.fields.drop_buffers_th = 2000;
        uc_oqg_profile.fields.fcn_bytes_th = bit_utils::ones(uc_oqg_profile.fields.FCN_BYTES_TH_WIDTH);
        uc_oqg_profile.fields.fcn_buffers_th = 341;
        uc_oqg_profile.fields.fcn_pds_th = 341;
    } else {
        uc_oqg_profile.fields.drop_buffers_th = bit_utils::ones(uc_oqg_profile.fields.DROP_BUFFERS_TH_WIDTH);
        uc_oqg_profile.fields.fcn_bytes_th = bit_utils::ones(uc_oqg_profile.fields.FCN_BYTES_TH_WIDTH);
        uc_oqg_profile.fields.fcn_buffers_th = bit_utils::ones(uc_oqg_profile.fields.FCN_BUFFERS_TH_WIDTH);
        uc_oqg_profile.fields.fcn_pds_th = bit_utils::ones(uc_oqg_profile.fields.FCN_PDS_TH_WIDTH);
    }

    lld_memory_scptr uc_oqg_profile_ptr = m_pacific_tree->slice[slice]->tx->cgm->uc_oqg_profile;

    if (is_network_slice(slice)) {
        // SA and LC network
        for (auto const& entry : fc_bytes_th_arr) {
            uc_oqg_profile.fields.drop_bytes_th = bit_utils::ones(uc_oqg_profile.fields.DROP_BUFFERS_TH_WIDTH);
            uc_oqg_profile.fields.flow_control_bytes_th
                = (m_revision == la_device_revision_e::PACIFIC_B1) ? 4 * entry.second : 2 * entry.second;

            // Configure the speed in reverse to the profile index. So #0 is 800G, ..., #7 is 10G, etc.
            la_uint_t uc_oqg_profile_id = la_interface_scheduler_impl::TX_CGM_PROFILE_MAP.at(entry.first);
            mem_line_val_list.push_back({{uc_oqg_profile_ptr, uc_oqg_profile_id}, uc_oqg_profile});
        }
    } else if ((m_device_mode == device_mode_e::LINECARD) && (m_slice_mode[slice] == la_slice_mode_e::CARRIER_FABRIC)) {
        // LC fabric
        mem_val_list.push_back({uc_oqg_profile_ptr, bit_vector("0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")});
    } else {
        // FE
        uc_oqg_profile.fields.drop_bytes_th = bit_utils::ones(uc_oqg_profile.fields.DROP_BYTES_TH_WIDTH);
        uc_oqg_profile.fields.flow_control_bytes_th = bit_utils::ones(uc_oqg_profile.fields.FLOW_CONTROL_BYTES_TH_WIDTH);
        mem_val_list.push_back({uc_oqg_profile_ptr, uc_oqg_profile});
    }

    return LA_STATUS_SUCCESS;
}

/* MC OQ profile settings for standalone - port speeds 10G, 25G, 40G, 50G */
static void
populate_mc_oq_profile_standalone_10G(txcgm_mc_oq_profile_memory& mc_oq_profile)
{
    mc_oq_profile.fields.qsize_byte_range_th0 = 0.7 * 0.075 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th1 = 0.075 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th2 = 0.7 * 0.15 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th3 = 0.15 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th4 = 0.7 * 0.35 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th5 = 0.35 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th6 = 1 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_pd_range_th0 = 0.7 * 50;
    mc_oq_profile.fields.qsize_pd_range_th1 = 50;
    mc_oq_profile.fields.qsize_pd_range_th2 = 0.7 * 100;
    mc_oq_profile.fields.qsize_pd_range_th3 = 100;
    mc_oq_profile.fields.qsize_pd_range_th4 = 0.7 * 200;
    mc_oq_profile.fields.qsize_pd_range_th5 = 200;
    mc_oq_profile.fields.qsize_pd_range_th6 = 1200;
    mc_oq_profile.fields.fcn_bytes_th = 0x3FFFF;
    mc_oq_profile.fields.fcn_pds_th = 0x7FFF;
    mc_oq_profile.fields.pd_counter_type = 1;
}

/* MC OQ profile settings for standalone - port speeds 100G, 200G */
static void
populate_mc_oq_profile_standalone_100G(txcgm_mc_oq_profile_memory& mc_oq_profile)
{
    mc_oq_profile.fields.qsize_byte_range_th0 = 0.7 * 0.15 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th1 = 0.15 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th2 = 0.7 * 0.3 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th3 = 0.3 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th4 = 0.7 * 0.7 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th5 = 0.7 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th6 = 2 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_pd_range_th0 = 0.7 * 100;
    mc_oq_profile.fields.qsize_pd_range_th1 = 100;
    mc_oq_profile.fields.qsize_pd_range_th2 = 0.7 * 200;
    mc_oq_profile.fields.qsize_pd_range_th3 = 200;
    mc_oq_profile.fields.qsize_pd_range_th4 = 0.7 * 400;
    mc_oq_profile.fields.qsize_pd_range_th5 = 400;
    mc_oq_profile.fields.qsize_pd_range_th6 = 1600;
    mc_oq_profile.fields.fcn_bytes_th = 0x3FFFF;
    mc_oq_profile.fields.fcn_pds_th = 0x7FFF;
    mc_oq_profile.fields.pd_counter_type = 1;
}

/* MC OQ profile settings for standalone - port speeds 400G, 800G */
static void
populate_mc_oq_profile_standalone_400G(txcgm_mc_oq_profile_memory& mc_oq_profile)
{
    mc_oq_profile.fields.qsize_byte_range_th0 = 0.7 * 0.6 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th1 = 0.6 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th2 = 0.7 * 1.2 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th3 = 1.2 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th4 = 0.7 * 2.8 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th5 = 2.8 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th6 = 8 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_pd_range_th0 = 0.7 * 400;
    mc_oq_profile.fields.qsize_pd_range_th1 = 400;
    mc_oq_profile.fields.qsize_pd_range_th2 = 0.7 * 800;
    mc_oq_profile.fields.qsize_pd_range_th3 = 800;
    mc_oq_profile.fields.qsize_pd_range_th4 = 0.7 * 1200;
    mc_oq_profile.fields.qsize_pd_range_th5 = 1200;
    mc_oq_profile.fields.qsize_pd_range_th6 = 1600;
    mc_oq_profile.fields.fcn_bytes_th = 0x3FFFF;
    mc_oq_profile.fields.fcn_pds_th = 0x7FFF;
    mc_oq_profile.fields.pd_counter_type = 1;
}

/* MC OQ profile settings for network slices in linecard - port speeds 10G, 25G, 40G, 50G */
static void
populate_mc_oq_profile_linecard_10G(txcgm_mc_oq_profile_memory& mc_oq_profile)
{
    mc_oq_profile.fields.qsize_byte_range_th0 = 0.7 * 0.075 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th1 = 0.075 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th2 = 0.7 * 0.15 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th3 = 0.15 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th4 = 0.7 * 0.35 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th5 = 0.35 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th6 = 1 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_pd_range_th0 = 0.7 * 100;
    mc_oq_profile.fields.qsize_pd_range_th1 = 100;
    mc_oq_profile.fields.qsize_pd_range_th2 = 0.7 * 200;
    mc_oq_profile.fields.qsize_pd_range_th3 = 200;
    mc_oq_profile.fields.qsize_pd_range_th4 = 0.7 * 400;
    mc_oq_profile.fields.qsize_pd_range_th5 = 400;
    mc_oq_profile.fields.qsize_pd_range_th6 = 1000;
    mc_oq_profile.fields.fcn_bytes_th = 0x3FFFF;
    mc_oq_profile.fields.fcn_pds_th = 0x7FFF;
    mc_oq_profile.fields.pd_counter_type = 1;
}

/* MC OQ profile settings for network slices in linecard - port speeds 100G, 200G */
static void
populate_mc_oq_profile_linecard_100G(txcgm_mc_oq_profile_memory& mc_oq_profile)
{
    mc_oq_profile.fields.qsize_byte_range_th0 = 0.7 * 0.15 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th1 = 0.15 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th2 = 0.7 * 0.3 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th3 = 0.3 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th4 = 0.7 * 0.7 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th5 = 0.7 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th6 = 2 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_pd_range_th0 = 0.7 * 200;
    mc_oq_profile.fields.qsize_pd_range_th1 = 200;
    mc_oq_profile.fields.qsize_pd_range_th2 = 0.7 * 400;
    mc_oq_profile.fields.qsize_pd_range_th3 = 400;
    mc_oq_profile.fields.qsize_pd_range_th4 = 0.7 * 750;
    mc_oq_profile.fields.qsize_pd_range_th5 = 750;
    mc_oq_profile.fields.qsize_pd_range_th6 = 1200;
    mc_oq_profile.fields.fcn_bytes_th = 0x3FFFF;
    mc_oq_profile.fields.fcn_pds_th = 0x7FFF;
    mc_oq_profile.fields.pd_counter_type = 1;
}

/* MC OQ profile settings for network slices in linecard - port speeds 400G, 800G */
static void
populate_mc_oq_profile_linecard_400G(txcgm_mc_oq_profile_memory& mc_oq_profile)
{
    mc_oq_profile.fields.qsize_byte_range_th0 = 0.7 * 0.6 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th1 = 0.6 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th2 = 0.7 * 1.2 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th3 = 1.2 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th4 = 0.7 * 2.8 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th5 = 2.8 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_byte_range_th6 = 8 * 1024 * 1024 / 256;
    mc_oq_profile.fields.qsize_pd_range_th0 = 0.7 * 400;
    mc_oq_profile.fields.qsize_pd_range_th1 = 400;
    mc_oq_profile.fields.qsize_pd_range_th2 = 0.7 * 800;
    mc_oq_profile.fields.qsize_pd_range_th3 = 800;
    mc_oq_profile.fields.qsize_pd_range_th4 = 0.7 * 1000;
    mc_oq_profile.fields.qsize_pd_range_th5 = 1000;
    mc_oq_profile.fields.qsize_pd_range_th6 = 1200;
    mc_oq_profile.fields.fcn_bytes_th = 0x3FFFF;
    mc_oq_profile.fields.fcn_pds_th = 0x7FFF;
    mc_oq_profile.fields.pd_counter_type = 1;
}

/* MC OQ profile settings for fabric-element - all port speeds */
static void
populate_mc_oq_profile_fabric(txcgm_mc_oq_profile_memory& mc_oq_profile)
{
    mc_oq_profile.fields.qsize_byte_range_th0 = 1;
    mc_oq_profile.fields.qsize_byte_range_th1 = 2;
    mc_oq_profile.fields.qsize_byte_range_th2 = 3;
    mc_oq_profile.fields.qsize_byte_range_th3 = 4;
    mc_oq_profile.fields.qsize_byte_range_th4 = 5;
    mc_oq_profile.fields.qsize_byte_range_th5 = 6;
    mc_oq_profile.fields.qsize_byte_range_th6 = 150 * KIBI / BYTE_THRESHOLD_RESOLUTION;
    mc_oq_profile.fields.qsize_pd_range_th0 = 1;
    mc_oq_profile.fields.qsize_pd_range_th1 = 2;
    mc_oq_profile.fields.qsize_pd_range_th2 = 3;
    mc_oq_profile.fields.qsize_pd_range_th3 = 4;
    mc_oq_profile.fields.qsize_pd_range_th4 = 5;
    mc_oq_profile.fields.qsize_pd_range_th5 = 6;
    mc_oq_profile.fields.qsize_pd_range_th6 = 400;
    mc_oq_profile.fields.fcn_bytes_th = 75 * KIBI / BYTE_THRESHOLD_RESOLUTION;
    mc_oq_profile.fields.fcn_pds_th = 200;
    mc_oq_profile.fields.pd_counter_type = 1;
}

la_status
la_device_impl::prepare_tx_cgm_mc_oq_profile_per_speed(lld_memory_value_list_t& mem_val_list,
                                                       lld_memory_line_value_list_t& mem_line_val_list,
                                                       la_slice_id_t slice,
                                                       size_t profile)
{
    const std::vector<la_mac_port::port_speed_e> supported_speeds = m_device_port_handler->get_supported_speeds();
    size_t num_of_speeds = supported_speeds.size();
    la_mac_port::port_speed_e speed = supported_speeds.at(profile % num_of_speeds);
    dassert_crit(std::find(supported_speeds.begin(), supported_speeds.end(), speed) != supported_speeds.end());

    dassert_crit((m_device_mode == device_mode_e::STANDALONE) || (m_device_mode == device_mode_e::LINECARD));

    txcgm_mc_oq_profile_memory mc_oq_profile;
    if (m_device_mode == device_mode_e::STANDALONE) {
        if ((speed == la_mac_port::port_speed_e::E_800G) || (speed == la_mac_port::port_speed_e::E_400G)) {
            populate_mc_oq_profile_standalone_400G(mc_oq_profile);
        } else if ((speed == la_mac_port::port_speed_e::E_200G) || (speed == la_mac_port::port_speed_e::E_100G)) {
            populate_mc_oq_profile_standalone_100G(mc_oq_profile);
        } else {
            populate_mc_oq_profile_standalone_10G(mc_oq_profile);
        }
    } else { // LINECARD
        if ((speed == la_mac_port::port_speed_e::E_800G) || (speed == la_mac_port::port_speed_e::E_400G)) {
            populate_mc_oq_profile_linecard_400G(mc_oq_profile);
        } else if ((speed == la_mac_port::port_speed_e::E_200G) || (speed == la_mac_port::port_speed_e::E_100G)) {
            populate_mc_oq_profile_linecard_100G(mc_oq_profile);
        } else {
            populate_mc_oq_profile_linecard_10G(mc_oq_profile);
        }
    }

    lld_memory_scptr mc_oq_profile_ptr = m_pacific_tree->slice[slice]->tx->cgm->mc_oq_profile;
    size_t oq_profile_id;
    if (profile < num_of_speeds) {
        oq_profile_id = la_interface_scheduler_impl::TX_CGM_PROFILE_MAP.at(speed);
    } else {
        oq_profile_id = la_interface_scheduler_impl::TX_CGM_PROFILE_MAP_PFC.at(speed);
    }
    mem_line_val_list.push_back({{mc_oq_profile_ptr, oq_profile_id}, mc_oq_profile});

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::prepare_tx_cgm_mc_oq_profile(lld_memory_value_list_t& mem_val_list,
                                             lld_memory_line_value_list_t& mem_line_val_list,
                                             la_slice_id_t slice)
{
    lld_memory_scptr mc_oq_profile_ptr = m_pacific_tree->slice[slice]->tx->cgm->mc_oq_profile;

    if ((m_device_mode == device_mode_e::LINECARD) && (m_slice_mode[slice] == la_slice_mode_e::CARRIER_FABRIC)) {
        // LC fabric slice config is irrelevant. Use HW init values for alignment.
        bit_vector lcf_settings("0x107D0FA0007000C0014002000300040004036B00BB80271007D00177003E8007D00");
        mem_val_list.push_back({mc_oq_profile_ptr, lcf_settings});

        return LA_STATUS_SUCCESS;

    } else if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        // Fabric element settings are same for all speeds
        txcgm_mc_oq_profile_memory mc_oq_profile;
        populate_mc_oq_profile_fabric(mc_oq_profile);
        mem_val_list.push_back({mc_oq_profile_ptr, mc_oq_profile});

        return LA_STATUS_SUCCESS;
    }

    size_t profile;
    size_t num_of_speeds = (size_t)m_device_port_handler->get_supported_speeds().size();
    size_t num_of_profiles = is_network_slice(slice) ? num_of_speeds * 2 : num_of_speeds;
    for (profile = 0; profile < num_of_profiles; profile++) {
        la_status status = prepare_tx_cgm_mc_oq_profile_per_speed(mem_val_list, mem_line_val_list, slice, profile);
        return_on_error(status);
    }

    // Default values of all the rest of the lines
    for (; profile < mc_oq_profile_ptr->get_desc()->entries; profile++) {
        mem_line_val_list.push_back(
            {{mc_oq_profile_ptr, profile}, bit_vector("0x000107D0FA000007000C00140020003000400040007000180005000100003000080001")});
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::prepare_tx_cgm_mc_byte_pd_drop_resolutions(lld_memory_value_list_t& mem_val_list,
                                                           lld_memory_line_value_list_t& mem_line_val_list,
                                                           la_slice_id_t slice)
{
    // Static config of MC drop resolution
    static constexpr uint64_t MC_OQ_BYTE_DROP_GREEN[] = {0x80, 0xc0, 0xf0, 0xff};
    static constexpr uint64_t MC_OQ_BYTE_DROP_YELLOW[] = {0x80, 0xe0, 0xf8, 0xff};
    static constexpr uint64_t MC_OQ_PD_DROP_GREEN[] = {0x80, 0xc0, 0xf0, 0xfc};
    static constexpr uint64_t MC_OQ_PD_DROP_YELLOW[] = {0x80, 0xe0, 0xf8, 0xfe};

    // Initialize the MC drop resolution tables.
    // Setting each profile to drop in the last region is enough.
    //
    // In order to sync with the init_dump config, configure the following:
    // - In FE
    //      * In profiles 0..15  drop only in the last region. These are all the profiles.
    // - In SA, LC
    //      * In profiles 0..8  drop according to static tables above.
    //      * In profiles 9..15 drop in all regions.

    size_t first_all_drop_profile;

    if ((m_device_mode == device_mode_e::FABRIC_ELEMENT) || is_network_slice(slice)) {
        first_all_drop_profile = 16;
    } else {
        first_all_drop_profile = 8;
    }

    static_assert((size_t)txcgm_mc_oq_byte_drop_resolution_memory::fields::DROP_GREEN_WIDTH
                      == (size_t)txcgm_mc_oq_byte_drop_resolution_memory::fields::DROP_YELLOW_WIDTH,
                  "txcgm_mc_oq_byte_drop_resolution_memory DROP_GREEN_WIDTH and DROP_YELLOW_WIDTH do not match");

    constexpr size_t NUM_DROP_REGIONS = txcgm_mc_oq_byte_drop_resolution_memory::fields::DROP_GREEN_WIDTH;
    constexpr size_t GLOBAL_MC_BUFFERS_STATUS_WIDTH = 2;
    constexpr size_t MC_OQ_PROFILE_WIDTH = txcgm_mc_oq_profile_map_memory::fields::MC_PROFILE_WIDTH;
    constexpr size_t LAST_DROP_REGION_INDEX = NUM_DROP_REGIONS - 1;

    auto pd_drop_mem = m_pacific_tree->slice[slice]->tx->cgm->mc_oq_pd_drop_resolution;
    auto byte_drop_mem = m_pacific_tree->slice[slice]->tx->cgm->mc_oq_byte_drop_resolution;

    txcgm_mc_oq_byte_drop_resolution_memory mc_oq_byte_drop_resolution;
    txcgm_mc_oq_pd_drop_resolution_memory mc_oq_pd_drop_resolution;

    for (size_t global_mc_buffers_status = 0; global_mc_buffers_status < (1 << GLOBAL_MC_BUFFERS_STATUS_WIDTH);
         global_mc_buffers_status++) {
        if (is_network_slice(slice)) {
            // Configure profiles according to static tables
            mc_oq_byte_drop_resolution.fields.drop_green = MC_OQ_BYTE_DROP_GREEN[global_mc_buffers_status];
            mc_oq_byte_drop_resolution.fields.drop_yellow = MC_OQ_BYTE_DROP_YELLOW[global_mc_buffers_status];
            mc_oq_pd_drop_resolution.fields.drop_green = MC_OQ_PD_DROP_GREEN[global_mc_buffers_status];
            mc_oq_pd_drop_resolution.fields.drop_yellow = MC_OQ_PD_DROP_YELLOW[global_mc_buffers_status];
        } else {
            mc_oq_byte_drop_resolution.fields.drop_green = (1 << LAST_DROP_REGION_INDEX);
            mc_oq_byte_drop_resolution.fields.drop_yellow = (1 << LAST_DROP_REGION_INDEX);
            mc_oq_pd_drop_resolution.fields.drop_green = (1 << LAST_DROP_REGION_INDEX);
            mc_oq_pd_drop_resolution.fields.drop_yellow = (1 << LAST_DROP_REGION_INDEX);
        }

        for (size_t mc_oq_profile = 0; mc_oq_profile < first_all_drop_profile; mc_oq_profile++) {
            if ((global_mc_buffers_status == 3) && (mc_oq_profile == 8)) {
                // mc_oq_byte_drop_resolution is declared outside this scope, hence, the change will affect profiles[8..15]
                mc_oq_byte_drop_resolution.fields.drop_green = 0xfc;
                mc_oq_byte_drop_resolution.fields.drop_yellow = 0xfe;
            }
            size_t mem_line = (global_mc_buffers_status << MC_OQ_PROFILE_WIDTH) | mc_oq_profile;
            mem_line_val_list.push_back({{byte_drop_mem, mem_line}, mc_oq_byte_drop_resolution});
            mem_line_val_list.push_back({{pd_drop_mem, mem_line}, mc_oq_pd_drop_resolution});
        }

        // Configure profiles that drop in all region
        mc_oq_byte_drop_resolution.fields.drop_green = bit_utils::ones(NUM_DROP_REGIONS);
        mc_oq_byte_drop_resolution.fields.drop_yellow = bit_utils::ones(NUM_DROP_REGIONS);
        mc_oq_pd_drop_resolution.fields.drop_green = bit_utils::ones(NUM_DROP_REGIONS);
        mc_oq_pd_drop_resolution.fields.drop_yellow = bit_utils::ones(NUM_DROP_REGIONS);

        for (size_t mc_oq_profile = first_all_drop_profile; mc_oq_profile < (1 << MC_OQ_PROFILE_WIDTH); mc_oq_profile++) {
            size_t mem_line = (global_mc_buffers_status << MC_OQ_PROFILE_WIDTH) | mc_oq_profile;
            mem_line_val_list.push_back({{byte_drop_mem, mem_line}, mc_oq_byte_drop_resolution});
            mem_line_val_list.push_back({{pd_drop_mem, mem_line}, mc_oq_pd_drop_resolution});
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_rxpdr()
{
    la_status status = LA_STATUS_SUCCESS;
    lld_register_value_list_t reg_val_list;
    lld_memory_value_list_t mem_val_list;
    lld_memory_line_value_list_t mem_line_val_list;

    rx_pdr_counters_thresholds_reg2_register reg2;
    rx_pdr_counters_thresholds_reg3_register reg3;
    rx_pdr_counters_thresholds_reg4_register reg4;

    if (m_revision == la_device_revision_e::PACIFIC_B1) {
        reg2.fields.counter_a_drop_thr0 = 40 * KIBI;
        reg2.fields.counter_a_drop_thr1 = 53 * KIBI;
    } else {
        reg2.fields.counter_a_drop_thr0 = 35 * KIBI;
        reg2.fields.counter_a_drop_thr1 = 48 * KIBI;
    }

    reg3.fields.counter_sum_b_e_g_a_ingress_mc_drop_thr = 77 * KIBI;
    reg3.fields.counter_b_drop_thr0 = 10 * KIBI;
    reg3.fields.counter_b_drop_thr1 = 10 * KIBI;

    reg4.fields.counter_sum_b_e_txcgm_drop_thr0 = 5 * KIBI;
    reg4.fields.counter_sum_b_e_txcgm_drop_thr1 = 7.5 * KIBI;
    reg4.fields.counter_sum_b_e_txcgm_drop_thr2 = 9 * KIBI;

    if (m_device_mode == device_mode_e::STANDALONE) {
        reg2.fields.counter_sum_b_e_g_a_ingress_uc_drop_thr
            = bit_utils::ones(reg2.fields.COUNTER_SUM_B_E_G_A_INGRESS_UC_DROP_THR_WIDTH); // bug in IBM
        reg2.fields.counter_sum_b_e_g_ibm_drop_thr
            = bit_utils::ones(reg2.fields.COUNTER_SUM_B_E_G_IBM_DROP_THR_WIDTH); // bug in IBM
        reg2.fields.counter_sum_b_e_g_a_ibm_drop_thr
            = bit_utils::ones(reg2.fields.COUNTER_SUM_B_E_G_A_IBM_DROP_THR_WIDTH);                      // bug in IBM
        reg2.fields.counter_g_ibm_drop_thr = bit_utils::ones(reg2.fields.COUNTER_G_IBM_DROP_THR_WIDTH); // bug in IBM
        reg3.fields.counter_sum_b_e_g_a_ingress_mc_drop_thr
            = bit_utils::ones(reg3.fields.COUNTER_SUM_B_E_G_A_INGRESS_MC_DROP_THR_WIDTH); // bug in IBM
        reg3.fields.counter_sum_b_e_g_ingress_mc_drop_thr
            = bit_utils::ones(reg3.fields.COUNTER_SUM_B_E_G_INGRESS_MC_DROP_THR_WIDTH); // bug in IBM
        reg4.fields.counter_e_drop_thr0 = 0x02800;
        reg4.fields.counter_e_drop_thr1 = 0x02c00;
        reg4.fields.counter_sum_b_e_g_plb_mc_drop_thr = 0x05000;
        reg4.fields.counter_sum_b_e_g_a_plb_mc_drop_thr = bit_utils::ones(reg4.fields.COUNTER_SUM_B_E_G_A_PLB_MC_DROP_THR_WIDTH);
    } else if (m_device_mode == device_mode_e::LINECARD) {
        reg2.fields.counter_sum_b_e_g_a_ingress_uc_drop_thr
            = bit_utils::ones(reg2.fields.COUNTER_SUM_B_E_G_A_INGRESS_UC_DROP_THR_WIDTH); // bug in IBM
        reg2.fields.counter_sum_b_e_g_ibm_drop_thr
            = bit_utils::ones(reg2.fields.COUNTER_SUM_B_E_G_IBM_DROP_THR_WIDTH); // bug in IBM
        reg2.fields.counter_sum_b_e_g_a_ibm_drop_thr
            = bit_utils::ones(reg2.fields.COUNTER_SUM_B_E_G_A_IBM_DROP_THR_WIDTH);                      // bug in IBM
        reg2.fields.counter_g_ibm_drop_thr = bit_utils::ones(reg2.fields.COUNTER_G_IBM_DROP_THR_WIDTH); // bug in IBM
        reg3.fields.counter_sum_b_e_g_a_ingress_mc_drop_thr = 0x13000;
        reg3.fields.counter_sum_b_e_g_ingress_mc_drop_thr = 0x05000;
        reg4.fields.counter_e_drop_thr0 = bit_utils::ones(reg4.fields.COUNTER_E_DROP_THR0_WIDTH);
        reg4.fields.counter_e_drop_thr1 = bit_utils::ones(reg4.fields.COUNTER_E_DROP_THR1_WIDTH);
        reg4.fields.counter_sum_b_e_g_plb_mc_drop_thr = bit_utils::ones(reg4.fields.COUNTER_SUM_B_E_G_PLB_MC_DROP_THR_WIDTH);
        reg4.fields.counter_sum_b_e_g_a_plb_mc_drop_thr = bit_utils::ones(reg4.fields.COUNTER_SUM_B_E_G_A_PLB_MC_DROP_THR_WIDTH);
    } else if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        reg2.fields.counter_sum_b_e_g_a_ibm_drop_thr = 77 * KIBI;
        reg2.fields.counter_sum_b_e_g_a_ingress_uc_drop_thr = 75 * KIBI;
        reg2.fields.counter_sum_b_e_g_ibm_drop_thr = bit_utils::ones(reg2.fields.COUNTER_SUM_B_E_G_IBM_DROP_THR_WIDTH);
        reg2.fields.counter_g_ibm_drop_thr = 5 * KIBI;
        reg3.fields.counter_sum_b_e_g_a_ingress_mc_drop_thr = 0x13000;
        reg3.fields.counter_sum_b_e_g_ingress_mc_drop_thr = 0x05000;
        reg4.fields.counter_e_drop_thr0 = bit_utils::ones(reg4.fields.COUNTER_E_DROP_THR0_WIDTH);
        reg4.fields.counter_e_drop_thr1 = bit_utils::ones(reg4.fields.COUNTER_E_DROP_THR1_WIDTH);
        reg4.fields.counter_sum_b_e_g_plb_mc_drop_thr = bit_utils::ones(reg4.fields.COUNTER_SUM_B_E_G_PLB_MC_DROP_THR_WIDTH);
        reg4.fields.counter_sum_b_e_g_a_plb_mc_drop_thr = bit_utils::ones(reg4.fields.COUNTER_SUM_B_E_G_A_PLB_MC_DROP_THR_WIDTH);
    } else {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    reg_val_list.push_back({(m_pacific_tree->rx_pdr->counters_thresholds_reg2), reg2});
    reg_val_list.push_back({(m_pacific_tree->rx_pdr->counters_thresholds_reg3), reg3});
    reg_val_list.push_back({(m_pacific_tree->rx_pdr->counters_thresholds_reg4), reg4});

    la_uint64_t rxpdr_device_mode;
    status = populate_rxpdr_device_mode(rxpdr_device_mode);
    return_on_error(status);

    reg_val_list.push_back({(m_pacific_tree->rx_pdr->global_configuration), rxpdr_device_mode});

    for (la_slice_id_t slice : get_used_slices()) {
        rx_pdr_2_slices_slice_global_configuration_register global_cfg;
        global_cfg.fields.slice_drop_voq_number = 0xFFFF;
        global_cfg.fields.slice_plb_mode = 1; ///< 0 - SN PLB 1 - TS PLB
        global_cfg.fields.slice_device_type
            = rxpdr_device_mode; ///< Indicates the mode of the device: 2'h0 - LC 2'h1 - TR 2'h2 - SA 2'h3 - FE
        global_cfg.fields.slice_disable_cache = 0;
        if (m_device_mode == device_mode_e::STANDALONE) {
            global_cfg.fields.slice_rxrqs_arb_mode = 0;
        } else if ((m_device_mode == device_mode_e::LINECARD) || (m_device_mode == device_mode_e::FABRIC_ELEMENT)) {
            global_cfg.fields.slice_rxrqs_arb_mode = 1;
        } else {
            return LA_STATUS_ENOTIMPLEMENTED;
        }

        global_cfg.fields.slice_rxrqs_arb_wrr0_cl0_weight = 0x1F;

        if (m_device_mode == device_mode_e::STANDALONE) {
            global_cfg.fields.slice_rxrqs_arb_wrr0_cl1_weight = 0x1F;
        } else if ((m_device_mode == device_mode_e::LINECARD) || (m_device_mode == device_mode_e::FABRIC_ELEMENT)) {
            global_cfg.fields.slice_rxrqs_arb_wrr0_cl1_weight = 0x1;
        } else {
            return LA_STATUS_ENOTIMPLEMENTED;
        }

        global_cfg.fields.slice_rxrqs_arb_wrr0_cl2_weight = 0x1F;
        global_cfg.fields.slice_mode = m_tm_slice_mode[slice];

        if (is_network_slice(slice)) {
            global_cfg.fields.slice_rxrq_selection_mode = 0;
        } else if (m_slice_mode[slice] == la_slice_mode_e::CARRIER_FABRIC) {
            global_cfg.fields.slice_rxrq_selection_mode = 1;
        } else {
            return LA_STATUS_ENOTIMPLEMENTED;
        }

        global_cfg.fields.slice_mc_cache_reset_counter_val = 0x1FFF;
        global_cfg.fields.slice_mc_cache_reset_trig = 0;
        global_cfg.fields.slice_uc_pipe_out_fifo_alm_full_thr = 24;
        global_cfg.fields.slice_uc_pipe_out_fifo_mask_thr = 24;
        global_cfg.fields.slice_mc_pipe_out_fifo_alm_full_thr = 30;
        global_cfg.fields.slice_mc_pipe_out_fifo_mask_thr = 30;
        global_cfg.fields.slice56_fabric_links_en = 0; // This is relevant only for FLB (not PLB)
        global_cfg.fields.slice_out_arb_mode = 0;
        global_cfg.fields.slice_out_arb_wrr_uc_weight = 0x1F;
        global_cfg.fields.slice_out_arb_wrr_mc_weight = 0x1F;
        global_cfg.fields.slice_req_fifo_alm_full_thr = 4;
        global_cfg.fields.slice_rxpdr2_rxcgm_cbt_alm_full_thr = 5;

        reg_val_list.push_back(
            {(*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->slice_global_configuration)[slice % 2], global_cfg});

        lld_memory_scptr fb_link_to_link_bundle_table
            = (*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->fb_link_to_link_bundle_table)[slice % 2];
        mem_val_list.push_back({fb_link_to_link_bundle_table, INVALID_BUNDLE});

        lld_memory_scptr fe_rlb_uc_tx_fb_link_to_oq_map
            = (*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->fe_rlb_uc_tx_fb_link_to_oq_map)[slice % 2];
        for (size_t line = 0; line < fe_rlb_uc_tx_fb_link_to_oq_map->get_desc()->entries; line++) {
            la_uint_t val = ((line % 9) << 3) + (((line / 9) % 2) * 160);
            mem_line_val_list.push_back({{fe_rlb_uc_tx_fb_link_to_oq_map, line}, val});
        }

        lld_memory_scptr source_if2_port_map_table
            = (*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->source_if2_port_map_table)[slice % 2];
        for (size_t line = 0; line < source_if2_port_map_table->get_desc()->entries; line++) {
            la_uint_t val
                = ((line % 20) == 19)
                      ? 0x12
                      : ((line % 2) == 1) ? 0 : (line < 18) ? line / 2 : (line == 18) ? 0 : (line < 38) ? (line / 2) - 1 : 0;
            mem_line_val_list.push_back({{source_if2_port_map_table, line}, val});
        }

        lld_memory_scptr tc_to_prio_map = (*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->tc_to_prio_map)[slice % 2];
        for (size_t line = 0; line < tc_to_prio_map->get_desc()->entries; line++) {
            la_uint_t val = (line < 4) ? 0 : 1;
            mem_line_val_list.push_back({{tc_to_prio_map, line}, val});
        }

        const la_uint_t ms_voq_fabric_context_offset_array[] = {0, 0x72, 0xE4, 0x156};
        lld_memory_scptr ms_voq_fabric_context_offset
            = (*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->ms_voq_fabric_context_offset)[slice % 2];
        for (size_t line = 0; line < ms_voq_fabric_context_offset->get_desc()->entries; line++) {
            la_uint_t val = line < array_size(ms_voq_fabric_context_offset_array) ? ms_voq_fabric_context_offset_array[line] : 0;
            mem_line_val_list.push_back({{ms_voq_fabric_context_offset, line}, val});
        }

        const la_uint_t oq_fabric_context_offset_array[] = {6, 5, 0, 0};
        lld_memory_scptr oq_fabric_context_offset
            = (*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->oq_fabric_context_offset)[slice % 2];
        for (size_t line = 0; line < oq_fabric_context_offset->get_desc()->entries; line++) {
            la_uint_t val = line < array_size(oq_fabric_context_offset_array) ? oq_fabric_context_offset_array[line] : 0;
            mem_line_val_list.push_back({{oq_fabric_context_offset, line}, val});
        }

        // Except for the following, all other out_color_and_tc_to_thr_map_table values are initialized to 0.
        mem_line_val_list.push_back(
            {{(*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->out_color_and_tc_to_thr_map_table)[slice % 2], 7}, 0x7});
        mem_line_val_list.push_back(
            {{(*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->out_color_and_tc_to_thr_map_table)[slice % 2], 15}, 0x7});
        mem_line_val_list.push_back(
            {{(*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->out_color_and_tc_to_thr_map_table)[slice % 2], 23}, 0x7});
        mem_line_val_list.push_back(
            {{(*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->out_color_and_tc_to_thr_map_table)[slice % 2], 31}, 0x7});

        mem_line_val_list.push_back(
            {{(*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->source_if_is_recycle_map_table)[slice % 2], 19}, 0x1});
        mem_line_val_list.push_back(
            {{(*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->source_if_is_recycle_map_table)[slice % 2], 39}, 0x1});

        lld_memory_scptr dest_slice_voq_map_table
            = (*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->dest_slice_voq_map_table)[slice % 2];
        for (size_t dest_slice : get_used_slices()) {
            mem_line_val_list.push_back({{dest_slice_voq_map_table, dest_slice}, dest_slice * 19});
        }

        lld_memory_scptr is_flb = (*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->mc_tc_is_flb_map)[slice % 2];
        for (size_t line = 0; line < is_flb->get_desc()->entries; line++) {
            mem_line_val_list.push_back({{(*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->mc_tc_is_flb_map)[slice % 2], line}, 0});
        }
    }

    for (la_slice_pair_id_t slice_pair : get_used_slice_pairs()) {
        lld_memory_scptr fe_broadcast_bmp = m_pacific_tree->slice_pair[slice_pair]->rx_pdr->fe_broadcast_bmp;
        mem_val_list.push_back({fe_broadcast_bmp, bit_vector("0xFFFFFFFFFFFFFFFFFFFFFFFFFFF")});

        for (size_t fifo = 0; fifo < 4 /* num of rxpdr FIFOs */; fifo++) {
            rx_pdr_2_slices_rxrqs_configurations_register reg;
            reg.fields.slice0_rxrq_fifo_size = 0x80;
            reg.fields.slice0_rxrq_start_addr = 0x80 * fifo;
            reg.fields.slice1_rxrq_fifo_size = 0x80;
            reg.fields.slice1_rxrq_start_addr = 0x80 * fifo;
            reg_val_list.push_back({(*m_pacific_tree->slice_pair[slice_pair]->rx_pdr->rxrqs_configurations)[fifo], reg});
        }
    }

    for (la_slice_id_t slice : get_used_slices()) {
        // fe_configurations_reg2
        rx_pdr_2_slices_fe_configurations_reg2_register fe_configurations_reg2;

        status = m_ll_device->read_register(*(*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->fe_configurations_reg2)[slice % 2],
                                            fe_configurations_reg2);
        return_on_error(status);

        if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
            fe_configurations_reg2.fields.slice_rep_res_mc_backpressure_en = 1;
        } else {
            fe_configurations_reg2.fields.slice_rep_res_mc_backpressure_en = 0;
        }

        reg_val_list.push_back(
            {(*m_pacific_tree->slice_pair[slice / 2]->rx_pdr->fe_configurations_reg2)[slice % 2], fe_configurations_reg2});
    }

    // rx_pdr->counters_thresholds_reg1
    rx_pdr_counters_thresholds_reg1_register counters_thresholds_reg1;
    la_status read_status = m_ll_device->read_register(*m_pacific_tree->rx_pdr->counters_thresholds_reg1, counters_thresholds_reg1);
    return_on_error(read_status);

    counters_thresholds_reg1.fields.voq_cgm_counter_a_thr0 = 28 * KIBI;
    counters_thresholds_reg1.fields.voq_cgm_counter_a_thr1 = 30 * KIBI;
    counters_thresholds_reg1.fields.voq_cgm_counter_a_thr2 = 32 * KIBI;

    reg_val_list.push_back({(m_pacific_tree->rx_pdr->counters_thresholds_reg1), counters_thresholds_reg1});

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    status = lld_write_memory_line_list(m_ll_device, mem_line_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::populate_rxpdr_device_mode(la_uint64_t& rxpdr_device_mode)
{
    switch (m_device_mode) {
    case device_mode_e::STANDALONE:
        rxpdr_device_mode = 2;
        return LA_STATUS_SUCCESS;

    case device_mode_e::LINECARD:
        rxpdr_device_mode = 0;
        return LA_STATUS_SUCCESS;

    case device_mode_e::FABRIC_ELEMENT:
        rxpdr_device_mode = 3;
        return LA_STATUS_SUCCESS;

    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }
}

la_status
la_device_impl::init_tm_rxpdr_mc_db()
{
    la_status status = LA_STATUS_SUCCESS;
    lld_register_value_list_t reg_val_list;

    for (size_t i = 0; i < array_size(m_pacific_tree->rx_pdr_mc_db); i++) {

        // global_configuration
        rx_pdr_shared_db_global_configuration_register gc_reg;

        la_uint64_t rxpdr_device_mode;
        status = populate_rxpdr_device_mode(rxpdr_device_mode);
        return_on_error(status);

        gc_reg.fields.device_type = rxpdr_device_mode;

        reg_val_list.push_back({(m_pacific_tree->rx_pdr_mc_db[i]->global_configuration), gc_reg});
    }

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_txpdr()
{
    la_status status = LA_STATUS_SUCCESS;
    lld_register_value_list_t reg_val_list;
    lld_memory_line_value_list_t mem_line_val_list;

    for (la_slice_id_t slice : get_used_slices()) {
        reg_val_list.push_back({(m_pacific_tree->slice[slice]->tx->pdr->relicator_key_mappings), slice});

        // This is relevant for all, except LC on a fabric slice
        if (((m_device_mode == device_mode_e::LINECARD) && (m_slice_mode[slice] == la_slice_mode_e::CARRIER_FABRIC)) == false) {
            constexpr size_t TXRQ_FIFO_SIZE_CFG_ARR_SIZE = 4;
            std::array<size_t, TXRQ_FIFO_SIZE_CFG_ARR_SIZE> txrq_fifo_size_arr;

            switch (m_device_mode) {
            case device_mode_e::STANDALONE: {
                // standalone mode does not use unscheduled traffic so it
                // can share the 1k FIFO between lp and hp scheduled traffic.
                txrq_fifo_size_arr = {{512, 512, 0, 0}};
                break;
            }
            case device_mode_e::LINECARD: {
                // linecard mode requires both scheduled and unscheduled
                // traffic, the fifo is split between hp and lp for each.
                txrq_fifo_size_arr = {{256, 256, 256, 256}};
                break;
            }
            case device_mode_e::FABRIC_ELEMENT: {
                // fabric element requires only unscheduled lp traffic.
                // the full fifo can be used.
                txrq_fifo_size_arr = {{0, 0, 0, 1000}};
                break;
            }
            default:
                return LA_STATUS_ENOTIMPLEMENTED;
            }

            txpdr_txrq_fifo_size_cfg_register txrq_fifo_size_cfg;
            size_t start_addr = 0;

            for (size_t i = 0; i < TXRQ_FIFO_SIZE_CFG_ARR_SIZE; i++) {
                txrq_fifo_size_cfg.fields.txrq_fifo_size = txrq_fifo_size_arr[i];
                txrq_fifo_size_cfg.fields.txrq_fifo_start_addr = start_addr;

                reg_val_list.push_back({(*m_pacific_tree->slice[slice]->tx->pdr->txrq_fifo_size_cfg)[i], txrq_fifo_size_cfg});

                start_addr += txrq_fifo_size_arr[i];
            }
        }

        txpdr_txrq_thresholds_register txrq_thresholds;

        if (m_device_mode == device_mode_e::LINECARD) {
            // flow control thresholds are set to half the fifo size
            // linecard mode sets lower thresholds due to smaller FIFO sizes
            txrq_thresholds.fields.sch_hp_fc_th = 128;
            txrq_thresholds.fields.sch_lp_fc_th = 128;
            // drop thresholds are set just below the fifo size
            txrq_thresholds.fields.sch_hp_drop_th = 250;
            txrq_thresholds.fields.sch_lp_drop_th = 250;
            txrq_thresholds.fields.unsch_hp_drop_th = 250;
            txrq_thresholds.fields.unsch_lp_drop_th = 250;

            // set the byte thresholds to half the size available
            txrq_thresholds.fields.sch_hp_byte_fc_th = 0x0080000;     // 512 KiB
            txrq_thresholds.fields.sch_lp_byte_fc_th = 0x0080000;     // 512 KiB
            txrq_thresholds.fields.unsch_hp_byte_drop_th = 0x0080000; // 512 KiB
            txrq_thresholds.fields.unsch_lp_byte_drop_th = 0x0080000; // 512 KiB

        } else { // STANDALONE and FABRIC_ELEMENT
            // flow control thresholds are set to half the fifo size
            txrq_thresholds.fields.sch_hp_fc_th = 256;
            txrq_thresholds.fields.sch_lp_fc_th = 256;
            // drop thresholds are set just below the fifo size
            txrq_thresholds.fields.sch_hp_drop_th = 500;
            txrq_thresholds.fields.sch_lp_drop_th = 500;
            // unscheduled traffic is not used for standalone
            txrq_thresholds.fields.unsch_hp_drop_th = 990;
            txrq_thresholds.fields.unsch_lp_drop_th = 990;

            // set the size thresholds to the maximum size
            // Note, standalone does not use the unscheduled thresholds and
            // fabric element does not use the scheduled thresholds so both
            // can be set to the same value.
            txrq_thresholds.fields.sch_hp_byte_fc_th = 0x0100000;     // 1 MiB
            txrq_thresholds.fields.sch_lp_byte_fc_th = 0x0100000;     // 1 MiB
            txrq_thresholds.fields.unsch_hp_byte_drop_th = 0x0100000; // 1 MiB
            txrq_thresholds.fields.unsch_lp_byte_drop_th = 0x0100000; // 1 MiB
        }

        reg_val_list.push_back({(m_pacific_tree->slice[slice]->tx->pdr->txrq_thresholds), txrq_thresholds});

        reg_val_list.push_back({(m_pacific_tree->slice[slice]->tx->pdr->relicator_key_mappings), slice});
        reg_val_list.push_back({(m_pacific_tree->slice[slice]->tx->pdr->slice_mode_configuration), m_tm_slice_mode[slice]});
        if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
            reg_val_list.push_back({(m_pacific_tree->slice[slice]->tx->pdr->txrq_mappings), 0});
        } else if (m_device_mode == device_mode_e::LINECARD) {
            if (is_network_slice(slice)) {
                // For a fab->net MC packets, before replication in TXPDR, takes the TC in the PD and maps to the H/L MC queue
                reg_val_list.push_back({(m_pacific_tree->slice[slice]->tx->pdr->txrq_mappings), 0x100});
            } else {
                // Fabric slice
                reg_val_list.push_back({(m_pacific_tree->slice[slice]->tx->pdr->txrq_mappings), 0x1e0});
            }
        }

        lld_memory_scptr tc_profile_map = m_pacific_tree->slice[slice]->tx->pdr->tc_profile_map;
        for (size_t line = 0; line < tc_profile_map->get_desc()->entries; line++) {
            mem_line_val_list.push_back({{tc_profile_map, line}, line % 8});
        }
    }

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_line_list(m_ll_device, mem_line_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_ts_ms()
{
    const la_uint_t ts_ms_source_link_map[] = {0, 0,  1, 0,  2, 0,  3, 0,  4, 0,  5, 0,  6, 0,  7, 0,  8, 0, 0,  18, 9,
                                               0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15, 0, 16, 0, 17, 0, 0, 18, 0};

    la_status status = LA_STATUS_SUCCESS;
    lld_register_value_list_t reg_val_list;
    lld_memory_line_value_list_t mem_line_val_list;

    bit_vector source_slice_mode(0, ASIC_MAX_SLICES_PER_DEVICE_NUM);
    for (size_t rx_slice : get_used_slices()) {
        if (is_network_slice(rx_slice)) {
            source_slice_mode.set_bit(rx_slice, true);
        } else {
            source_slice_mode.set_bit(rx_slice, false);
        }
    }

    for (la_slice_id_t slice : get_used_slices()) {
        tsms_general_configuration_register tsms_cfg;

        tsms_cfg.fields.slice_mode = m_tm_slice_mode[slice];
        tsms_cfg.fields.source_slice_mode = source_slice_mode.get_value();

        if (m_tm_slice_mode[slice] == (la_uint_t)tm_slice_mode_e::LC_CRF_TS_NETWORK) {
            tsms_cfg.fields.enable_cgm_plb_count = 1;
        } else {
            tsms_cfg.fields.enable_cgm_plb_count = 0;
        }

        if (m_slice_mode[slice] == la_slice_mode_e::CARRIER_FABRIC) {
            tsms_cfg.fields.enable_nwk_blocking = 0;
            tsms_cfg.fields.enable_fab_blocking = 1;
        } else {
            tsms_cfg.fields.enable_nwk_blocking = 1;
            tsms_cfg.fields.enable_fab_blocking = 0;
        }

        reg_val_list.push_back({(m_pacific_tree->slice[slice]->ts_ms->general_configuration), tsms_cfg});

        status = prepare_tm_ts_ms_tsms_th_configuration(reg_val_list, slice);
        return_on_error(status);

        status = prepare_tm_ts_ms_rate_meter_cfg(reg_val_list, slice);
        return_on_error(status);

        status = prepare_tm_ts_ms_rlb_fifo_start_addr(mem_line_val_list, slice);
        return_on_error(status);

        // System fixes: fix FTE offset in TSMS
        if (m_device_mode != device_mode_e::STANDALONE) {
            const int negative_fte_offset_1200_mhz = 48;

            // Adjust required fte_offset to actual device frequency
            int required_negative_fte_offset = ceil((float)negative_fte_offset_1200_mhz * (1.2 / m_device_frequency_float_ghz));

            // Calculate two's complement in hex for the register configuration
            uint64_t fte_offset = 0xFFFFFF;
            fte_offset = fte_offset - required_negative_fte_offset + 1;

            reg_val_list.push_back({(m_pacific_tree->slice[slice]->ts_ms->fte_offset_configuration), fte_offset});
        }

        status = prepare_tm_ts_ms_tsmon_valid_slice_configuration(reg_val_list, slice);
        return_on_error(status);

        if (m_device_mode == device_mode_e::STANDALONE) {
            // Configure device in stand-alone mode. // TODO: calculate the values
            reg_val_list.push_back({(m_pacific_tree->slice[slice]->ts_ms->xbar_flow_control_cfg), bit_vector("0x80025812C7")});
        }

        status = prepare_tm_ts_ms_keepalive_gen_cfg(reg_val_list, slice);
        return_on_error(status);

        lld_memory_scptr link_to_oqg_map = m_pacific_tree->slice[slice]->ts_ms->link_to_oqg_map;
        for (size_t line = 0; line < link_to_oqg_map->get_desc()->entries; line++) {
            la_uint_t val = line < 9 ? line : (line - 9) + 20;
            status = m_ll_device->write_memory(*link_to_oqg_map, line, val);
            return_on_error(status);
        }

        lld_memory_scptr source_link_map = m_pacific_tree->slice[slice]->ts_ms->source_link_map;
        for (size_t line = 0; line < source_link_map->get_desc()->entries; line++) {
            la_uint_t val = line < array_size(ts_ms_source_link_map) ? ts_ms_source_link_map[line] : 0;
            status = m_ll_device->write_memory(*source_link_map, line, val);
            return_on_error(status);
        }
    }

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_line_list(m_ll_device, mem_line_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::prepare_tm_ts_ms_tsms_th_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t tx_slice)
{
    for (la_slice_id_t rx_slice : get_used_slices()) {

        tsms_tsms_fifo_th_configuration_register fifo_reg;
        tsms_tsms_delete_fifo_th_configuration_register delete_fifo_reg;

        la_status status = populate_tm_ts_ms_tsms_th_configuration_reg(tx_slice, rx_slice, fifo_reg, delete_fifo_reg);
        return_on_error(status);

        reg_val_list.push_back({(*m_pacific_tree->slice[tx_slice]->ts_ms->tsms_fifo_th_configuration)[rx_slice], fifo_reg});
        reg_val_list.push_back(
            {(*m_pacific_tree->slice[tx_slice]->ts_ms->tsms_delete_fifo_th_configuration)[rx_slice], delete_fifo_reg});
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::populate_tm_ts_ms_tsms_th_configuration_reg(la_slice_id_t tx_slice,
                                                            la_slice_id_t rx_slice,
                                                            tsms_tsms_fifo_th_configuration_register& fifo_reg,
                                                            tsms_tsms_delete_fifo_th_configuration_register& delete_fifo_reg)
{
    bool is_sa = (m_device_mode == device_mode_e::STANDALONE);
    bool is_lc_net2net = ((m_device_mode == device_mode_e::LINECARD) && is_network_slice(rx_slice) && is_network_slice(tx_slice));
    bool is_lc_net2fab = ((m_device_mode == device_mode_e::LINECARD) && is_network_slice(rx_slice)
                          && (m_slice_mode[tx_slice] == la_slice_mode_e::CARRIER_FABRIC));
    bool is_lc_fab2net = ((m_device_mode == device_mode_e::LINECARD) && (m_slice_mode[rx_slice] == la_slice_mode_e::CARRIER_FABRIC)
                          && is_network_slice(tx_slice));
    bool is_lc_fab2fab = ((m_device_mode == device_mode_e::LINECARD) & (m_slice_mode[rx_slice] == la_slice_mode_e::CARRIER_FABRIC)
                          && (m_slice_mode[tx_slice] == la_slice_mode_e::CARRIER_FABRIC));
    bool is_fe = (m_device_mode == device_mode_e::FABRIC_ELEMENT);

    if (is_sa || is_lc_net2net) {
        fifo_reg.fields.rlb_fifo_enable = 1;
        fifo_reg.fields.rlb_uch_fifo_size = 0;
        fifo_reg.fields.rlb_ucl_fifo_size = 0;
        fifo_reg.fields.rlb_mc_fifo_size = 0;
        fifo_reg.fields.rlb_fifo_alm_full_th = 60;
        fifo_reg.fields.flb_fifo_size = 384;
        fifo_reg.fields.flb_fifo_start_addr = 0;
        fifo_reg.fields.flb_fifo_alm_full_th = 60;

        delete_fifo_reg.fields.delete_fifo_size = 512;
        delete_fifo_reg.fields.delete_fifo_start_addr = fifo_reg.fields.flb_fifo_size;
        delete_fifo_reg.fields.delete_fifo_lb_th = 32;
        delete_fifo_reg.fields.delete_fifo_sp_th = 48;

        return LA_STATUS_SUCCESS;
    }

    if (is_lc_net2fab) {
        fifo_reg.fields.rlb_fifo_enable = 1;
        fifo_reg.fields.rlb_uch_fifo_size = 256;
        fifo_reg.fields.rlb_ucl_fifo_size = 0;
        fifo_reg.fields.rlb_mc_fifo_size = 0;
        fifo_reg.fields.rlb_fifo_alm_full_th = 60;
        fifo_reg.fields.flb_fifo_size = 128;
        fifo_reg.fields.flb_fifo_start_addr = fifo_reg.fields.rlb_uch_fifo_size;
        fifo_reg.fields.flb_fifo_alm_full_th = 60;

        delete_fifo_reg.fields.delete_fifo_size = 512;
        delete_fifo_reg.fields.delete_fifo_start_addr = fifo_reg.fields.rlb_uch_fifo_size + fifo_reg.fields.flb_fifo_size;
        delete_fifo_reg.fields.delete_fifo_lb_th = 32;
        delete_fifo_reg.fields.delete_fifo_sp_th = 48;

        return LA_STATUS_SUCCESS;
    }

    if (is_lc_fab2net || is_fe) {
        // Defines which fifo exist and their size - there is a fifo between each RX fabric port on each of the 3 fabric
        // contexes.
        // The HW is prepared for the maximum possible of 19 = (9 + 9 + 1 [borrowed]) links in RX fabric slice, so there are 57
        // possible fifos between each RX and TX slice.

        size_t num_fabric_ports_in_slice;
        bool is_borrower_slice_en = is_borrower_slice(rx_slice);
        if (is_borrower_slice_en) {
            num_fabric_ports_in_slice = NUM_FABRIC_PORTS_IN_NORMAL_IFG + NUM_FABRIC_PORTS_IN_ENHANCED_IFG;
        } else {
            num_fabric_ports_in_slice = NUM_FABRIC_PORTS_IN_NORMAL_IFG + NUM_FABRIC_PORTS_IN_NORMAL_IFG;
        }
        la_uint64_t link_bitmask = bit_utils::ones(num_fabric_ports_in_slice);

        bit_vector fifo_bitmask(0, MAX_FABRIC_PORTS_IN_SLICE * NUM_PLB_FABRIC_CONTEXTS);
        for (size_t fabric_context = 0; fabric_context < NUM_PLB_FABRIC_CONTEXTS; fabric_context++) {
            // Enable UC_L and MC. Disable UC_H by skipping it
            if (fabric_context != NPL_FABRIC_CONTEXT_PLB_UC_H) {
                size_t lsb = fabric_context * MAX_FABRIC_PORTS_IN_SLICE;
                size_t msb = lsb + MAX_FABRIC_PORTS_IN_SLICE - 1;
                fifo_bitmask.set_bits(msb, lsb, link_bitmask);
            }
        }

        fifo_reg.fields.rlb_fifo_enable = fifo_bitmask.get_value();
        fifo_reg.fields.rlb_uch_fifo_size = 0;
        fifo_reg.fields.rlb_ucl_fifo_size = 32;
        fifo_reg.fields.rlb_mc_fifo_size = 16;
        fifo_reg.fields.rlb_fifo_alm_full_th = 0;
        fifo_reg.fields.flb_fifo_size = 4;
        fifo_reg.fields.flb_fifo_start_addr = is_borrower_slice_en ? 912 : 864;
        fifo_reg.fields.flb_fifo_alm_full_th = 20;

        delete_fifo_reg.fields.delete_fifo_size = 28;
        delete_fifo_reg.fields.delete_fifo_start_addr = is_borrower_slice_en ? 916 : 868;
        delete_fifo_reg.fields.delete_fifo_lb_th = 14;
        delete_fifo_reg.fields.delete_fifo_sp_th = 21;

        return LA_STATUS_SUCCESS;
    }

    if (is_lc_fab2fab) {
        fifo_reg.fields.rlb_fifo_enable = 0;
        fifo_reg.fields.rlb_uch_fifo_size = 0;
        fifo_reg.fields.rlb_ucl_fifo_size = 0;
        fifo_reg.fields.rlb_mc_fifo_size = 0;
        fifo_reg.fields.rlb_fifo_alm_full_th = 0;
        fifo_reg.fields.flb_fifo_size = 384;
        fifo_reg.fields.flb_fifo_start_addr = 0;
        fifo_reg.fields.flb_fifo_alm_full_th = 60;

        delete_fifo_reg.fields.delete_fifo_size = 512;
        delete_fifo_reg.fields.delete_fifo_start_addr = fifo_reg.fields.flb_fifo_size;
        delete_fifo_reg.fields.delete_fifo_lb_th = 32;
        delete_fifo_reg.fields.delete_fifo_sp_th = 48;

        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::prepare_tm_ts_ms_rate_meter_cfg(lld_register_value_list_t& reg_val_list, la_slice_id_t tx_slice)
{
    tsms_rate_meter_cfg_register reg;

    la_status status = m_ll_device->read_register(*m_pacific_tree->slice[tx_slice]->ts_ms->rate_meter_cfg, reg);
    return_on_error(status);

    reg.fields.meter_en = 0;

    constexpr uint64_t MAX_BUCKET = 4;
    constexpr float NUM_OF_TOKENS = 2;
    constexpr float DESIRED_RATE
        = 1600; // Total BW of network slice is 1800 Gbps. We want to limit incoming fabric MC traffic to max of 1600 Gbps.

    float bytes_per_clock = DESIRED_RATE / 8.0 /* bits per byte */ / m_device_frequency_float_ghz;
    float clocks_interval_between_tokens = 128.0 /* token size in bytes */ * NUM_OF_TOKENS / bytes_per_clock;
    uint64_t meter_rate_interval = floor(clocks_interval_between_tokens * 16 /* value is in units of 1/16 clocks */);

    reg.fields.slice_meter_rate = meter_rate_interval;
    reg.fields.slice_meter_max_bucket = MAX_BUCKET;
    reg.fields.slice_meter_token_value = (uint64_t)NUM_OF_TOKENS;
    reg.fields.mc_shaper_rate = meter_rate_interval;
    reg.fields.mc_shaper_max_bucket = MAX_BUCKET;

    reg_val_list.push_back({(m_pacific_tree->slice[tx_slice]->ts_ms->rate_meter_cfg), reg});

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::prepare_tm_ts_ms_rlb_fifo_start_addr(lld_memory_line_value_list_t& mem_line_val_list, la_slice_id_t tx_slice)
{
    if ((m_tm_slice_mode[tx_slice] == (la_uint_t)tm_slice_mode_e::LC_CRF_TS_NETWORK)
        || (m_tm_slice_mode[tx_slice] == (la_uint_t)tm_slice_mode_e::FABRIC_TS)) {
        // Defines start address of each PLB TSMS fifo. First 19 entries are for UCH, second 19 are for UCL, third 19 are for
        // MC.
        // For example, assuming UCH, UCL and MC fifo sizes are 16, then
        // UCH addr: fifo 0  -> 0    UCL addr: fifo 0  -> 16 + 0     MC addr: fifo 0  -> 32 + 0
        //           fifo 1  -> 48             fifo 1  -> 16 + 48             fifo 1  -> 32 + 48
        //                ...                           ...                         ...
        //           fifo 17 -> 816            fifo 17 -> 16 + 816            fifo 17 -> 32 + 816
        //           fifo 18 -> 864            fifo 18 -> 16 + 864            fifo 18 -> 32 + 864
        // The delta between each line above is start_addr_step_size, the delta between columns is the column's fifo size.

        size_t start_addr_step_size = (TSMS_RLB_UCH_FIFO_SIZE + TSMS_RLB_UCL_FIFO_SIZE + TSMS_RLB_MC_FIFO_SIZE);

        for (size_t fabric_context = 0; fabric_context < NUM_PLB_FABRIC_CONTEXTS; fabric_context++) {

            size_t start_addr_offset;

            switch (fabric_context) {
            case NPL_FABRIC_CONTEXT_PLB_UC_H:
                start_addr_offset = 0;
                break;

            case NPL_FABRIC_CONTEXT_PLB_UC_L:
                start_addr_offset = 0;
                break;

            case NPL_FABRIC_CONTEXT_PLB_MC:
                start_addr_offset = TSMS_RLB_UCH_FIFO_SIZE + TSMS_RLB_UCL_FIFO_SIZE;
                break;

            default:
                return LA_STATUS_EUNKNOWN;
            }

            for (size_t fabric_port_num = 0; fabric_port_num < MAX_FABRIC_PORTS_IN_SLICE; fabric_port_num++) {

                size_t fifo_index = fabric_context * MAX_FABRIC_PORTS_IN_SLICE + fabric_port_num;
                size_t start_addr = start_addr_step_size * fabric_port_num + start_addr_offset;

                mem_line_val_list.push_back(
                    {{(m_pacific_tree->slice[tx_slice]->ts_ms->rlb_fifo_start_addr), fifo_index}, start_addr});
            }
        }
    } else {
        // TODO - ask AlexK why only the first fifo is zeroed and not all.
        mem_line_val_list.push_back({{(m_pacific_tree->slice[tx_slice]->ts_ms->rlb_fifo_start_addr), 0}, 0});
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::prepare_tm_ts_ms_tsmon_valid_slice_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t tx_slice)
{
    // Defines for a TX slice, from which RX slice it should do merge-sort.

    lld_register_scptr tsmon_valid_slice_configuration = m_pacific_tree->slice[tx_slice]->ts_ms->tsmon_valid_slice_configuration;
    // In a SA device there no merge-sorting
    if (m_device_mode == device_mode_e::STANDALONE) {
        // No merge-sorting
        reg_val_list.push_back({tsmon_valid_slice_configuration, 0});

        return LA_STATUS_SUCCESS;
    }

    // In a LC device, TX network slices do merge-sort from RX fabric.
    if (m_device_mode == device_mode_e::LINECARD) {
        switch (m_slice_mode[tx_slice]) {
        case la_slice_mode_e::UDC:
        case la_slice_mode_e::NETWORK: {
            bit_vector ms_en(0, ASIC_MAX_SLICES_PER_DEVICE_NUM);

            for (la_slice_id_t rx_slice : get_used_slices()) {
                if (m_slice_mode[rx_slice] == la_slice_mode_e::CARRIER_FABRIC) {
                    ms_en.set_bit(rx_slice, true);
                } else {
                    ms_en.set_bit(rx_slice, false);
                }
            }

            reg_val_list.push_back({tsmon_valid_slice_configuration, ms_en});

            return LA_STATUS_SUCCESS;
        }

        case la_slice_mode_e::CARRIER_FABRIC: {
            // No merge-sorting
            reg_val_list.push_back({tsmon_valid_slice_configuration, 0});

            return LA_STATUS_SUCCESS;
        }

        default:
            return LA_STATUS_ENOTIMPLEMENTED;
        }
    }

    // In FE only down-facing slices do merge-sort.
    if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        la_clos_direction_e tx_slice_direction = m_slice_clos_direction[tx_slice];

        if (tx_slice_direction == la_clos_direction_e::DOWN) {
            bit_vector ms_en(0, ASIC_MAX_SLICES_PER_DEVICE_NUM);

            for (la_slice_id_t rx_slice : get_used_slices()) {
                ms_en.set_bit(rx_slice, true);
            }

            reg_val_list.push_back({tsmon_valid_slice_configuration, ms_en});

            return LA_STATUS_SUCCESS;

        } else { // up
            // TODO - what behavior is for up?
            return LA_STATUS_ENOTIMPLEMENTED;
        }
    }

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_device_impl::prepare_tm_ts_ms_keepalive_gen_cfg(lld_register_value_list_t& reg_val_list, la_slice_id_t tx_slice)
{
    if (m_slice_mode[tx_slice] != la_slice_mode_e::CARRIER_FABRIC) {
        return LA_STATUS_SUCCESS;
    }

    tsms_keepalive_gen_cfg_register keepalive_gen_cfg;

    keepalive_gen_cfg.fields.keepalive_gen_enable = 0;  // default
    keepalive_gen_cfg.fields.keepalive_gen_profile = 0; // default
    keepalive_gen_cfg.fields.keepalive_gen_rate0 = 1000;
    keepalive_gen_cfg.fields.keepalive_gen_rate1 = 200;      // default
    keepalive_gen_cfg.fields.keepalive_gen_packet_size = 64; // default
    keepalive_gen_cfg.fields.keepalive_gen_oq_offset = 6;    // default
    keepalive_gen_cfg.fields.keepalive_gen_constant = 0;     // default

    reg_val_list.push_back({(m_pacific_tree->slice[tx_slice]->ts_ms->keepalive_gen_cfg), keepalive_gen_cfg});

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_ts_mon()
{
    la_status status = LA_STATUS_SUCCESS;
    lld_register_value_list_t reg_val_list;
    lld_memory_line_value_list_t mem_line_val_list;

    for (la_slice_id_t slice : get_used_slices()) {
        status = prepare_ts_mon_monitor_configuration(reg_val_list, slice);
        return_on_error(status);

        lld_memory_scptr source_link_map = (*m_pacific_tree->ts_mon->source_link_map)[slice];

        for (size_t line = 0; line < source_link_map->get_desc()->entries; line++) {
            la_uint_t val
                = ((line % 20) == 19)
                      ? 18
                      : ((line % 20) == 18) ? 0 : ((line % 2) == 1) ? 0 : (line < 19) ? line / 2 : (line < 39) ? (line / 2) - 1 : 0;
            mem_line_val_list.push_back({{source_link_map, line}, val});
        }

        reg_val_list.push_back({(*m_pacific_tree->ts_mon->slice_mode_configuration)[slice], m_tm_slice_mode[slice]});
    }

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_line_list(m_ll_device, mem_line_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::prepare_ts_mon_monitor_configuration(lld_register_value_list_t& reg_val_list, la_slice_id_t slice)
{
    if (is_network_slice(slice)) {
        return LA_STATUS_SUCCESS;
    }

    ts_mon_ucl_monitor_configuration_register ucl_reg;
    ts_mon_uch_monitor_configuration_register uch_reg;
    ts_mon_mc_monitor_configuration_register mc_reg;

    // UCL
    ucl_reg.fields.ucl_fte_offset = 0;             // dump
    ucl_reg.fields.ucl_min_time_between_ts = 6000; // dump

    // UCH
    uch_reg.fields.uch_fte_offset = 0;             // dump
    uch_reg.fields.uch_min_time_between_ts = 6000; // dump

    // MC
    mc_reg.fields.mc_fte_offset = 0; // dump
    mc_reg.fields.mc_min_time_between_ts = (m_slice_mode[slice] == la_slice_mode_e::NETWORK) ? 24000 : 10000;

    if (m_device_mode == device_mode_e::LINECARD) {
        ucl_reg.fields.ucl_fte_allowed_distance = 480000;
        ucl_reg.fields.ucl_skew_allowed_distance = 480000;

        uch_reg.fields.uch_fte_allowed_distance = 480000;
        uch_reg.fields.uch_skew_allowed_distance = 480000;

        mc_reg.fields.mc_fte_allowed_distance = 480000;
        mc_reg.fields.mc_skew_allowed_distance = 480000;
    }

    if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        ucl_reg.fields.ucl_fte_allowed_distance = 320000;
        ucl_reg.fields.ucl_skew_allowed_distance = 320000;

        uch_reg.fields.uch_fte_allowed_distance = 320000;
        uch_reg.fields.uch_skew_allowed_distance = 320000;

        mc_reg.fields.mc_fte_allowed_distance = 320000;
        mc_reg.fields.mc_skew_allowed_distance = 320000;
    }

    reg_val_list.push_back({(*m_pacific_tree->ts_mon->ucl_monitor_configuration)[slice], ucl_reg});
    reg_val_list.push_back({(*m_pacific_tree->ts_mon->uch_monitor_configuration)[slice], uch_reg});
    reg_val_list.push_back({(*m_pacific_tree->ts_mon->mc_monitor_configuration)[slice], mc_reg});

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_reassembly()
{
    for (la_slice_id_t slice : get_used_slices()) {
        reassembly_reassembly_conf_reg1_register conf_reg;

        la_status status = m_ll_device->read_register(*(*m_pacific_tree->reassembly->reassembly_conf_reg1)[slice], conf_reg);
        return_on_error(status);

        conf_reg.fields.in_fifo_ifg_pause_threshold = 16;
        conf_reg.fields.in_fifo_rxpp_pause_threshold = 32;
        conf_reg.fields.out_pd_fifo_full_threshold = 58;
        conf_reg.fields.out_pd_control_fifo_full_threshold = 58;

        status = m_ll_device->write_register(*(*m_pacific_tree->reassembly->reassembly_conf_reg1)[slice], conf_reg);
        return_on_error(status);
    }

    if (m_revision == la_device_revision_e::PACIFIC_B1) {
        bit_vector spare_reg;
        la_status status = m_ll_device->read_register(*m_pacific_tree->reassembly->spare_reg, spare_reg);
        return_on_error(status);
        spare_reg.set_bits(2, 0, 0);  // RX-Meter - same meter bank used by 2 slices, zero for odd slices.
        spare_reg.set_bits(11, 6, 0); // Header compensation of HBM evicted packets - in B1 reassembly block overrides sch
                                      // compensation field on the pd, so we enable it per slice.
        status = m_ll_device->write_register(*m_pacific_tree->reassembly->spare_reg, spare_reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_other()
{
    lld_register_value_list_t reg_val_list;
    lld_memory_line_value_list_t mem_line_val_list;
    la_status status;

    if (m_device_mode == device_mode_e::LINECARD) {
        // Configure fabric rate limit
        constexpr size_t FRL_LINK_MAP_0 = 0;
        constexpr size_t FRL_LINK_MAP_1 = 1;
        constexpr size_t FRL_LINK_MAP_2 = 2;
        constexpr size_t FRL_LINK_MAP_3 = 3;

        bool is_lc_type_2_4_t;
        status = get_bool_property(la_device_property_e::LC_TYPE_2_4_T, is_lc_type_2_4_t);
        return_on_error(status);

        int credit_in_bytes;
        status = get_int_property(la_device_property_e::CREDIT_SIZE_IN_BYTES, credit_in_bytes);
        return_on_error(status);

        const int TM_CREDIT_VAL = credit_in_bytes * 128;

        uint64_t frl_rates[FRL_LINK_MAP_3 + 1];
        if (is_lc_type_2_4_t) {
            frl_rates[0] = (TM_CREDIT_VAL * (m_device_frequency_int_khz / 1000)) / 2800000;
            frl_rates[1] = (TM_CREDIT_VAL * (m_device_frequency_int_khz / 1000)) / 2300000;
            frl_rates[2] = (TM_CREDIT_VAL * (m_device_frequency_int_khz / 1000)) / 2100000;
            frl_rates[3] = (TM_CREDIT_VAL * (m_device_frequency_int_khz / 1000)) / 1800000;
        } else { // LC type is 3.6T
            frl_rates[0] = (TM_CREDIT_VAL * (m_device_frequency_int_khz / 1000)) / 4000000;
            frl_rates[1] = (TM_CREDIT_VAL * (m_device_frequency_int_khz / 1000)) / 3500000;
            frl_rates[2] = (TM_CREDIT_VAL * (m_device_frequency_int_khz / 1000)) / 3300000;
            frl_rates[3] = (TM_CREDIT_VAL * (m_device_frequency_int_khz / 1000)) / 3000000;
        }

        bit_vector links_map("0x5555555555555555555555555500"); // This is the original initialization
        // Now configure 2 links (2 bits per link) for each of the first 3 FRL_LINK_MAP values
        for (size_t i = FRL_LINK_MAP_0; i < FRL_LINK_MAP_3; i++) {
            for (size_t j = 0; j < 2; j++) { // Configure 2 links per map value
                links_map.set_bits((i * 4) + 1, i * 4, i);
                links_map.set_bits((i * 4) + 3, (i * 4) + 2, i);
            }
        }

        // Now go over all the rest of 56 fabric links and configure wach link (2 bits) to FRL_LINK_MAP_3
        // As we onfigured 2 links for each of the 3 previous map values, the start link is == (FRL_LINK_MAP_3 * 2)
        for (size_t i = FRL_LINK_MAP_3 * 2; i < MAX_FABRIC_PORTS_IN_LINECARD_DEVICE; i++) {
            links_map.set_bits((i * 2) + 1, i * 2, FRL_LINK_MAP_3);
        }
        reg_val_list.push_back({(m_pacific_tree->sch_top->frl_congested_links_mapping), links_map});

        sch_top_frl_rate_mapping_register frl_rate_mapping_reg;

        // Set eligible links mapping
        frl_rate_mapping_reg.fields.eligible_links_map = 0x055555554; // from dump
        frl_rate_mapping_reg.fields.set_eligible_links_map(FRL_LINK_MAP_3, FRL_LINK_MAP_3);
        frl_rate_mapping_reg.fields.set_eligible_links_map(FRL_LINK_MAP_2, FRL_LINK_MAP_2);
        frl_rate_mapping_reg.fields.set_eligible_links_map(FRL_LINK_MAP_1, FRL_LINK_MAP_1);
        frl_rate_mapping_reg.fields.set_eligible_links_map(FRL_LINK_MAP_0, FRL_LINK_MAP_0);

        // Set frl map link rate
        frl_rate_mapping_reg.fields.num_links_to_rate_map = 0; // initalize to zero
        frl_rate_mapping_reg.fields.set_num_links_to_rate_map(FRL_LINK_MAP_3, frl_rates[3]);
        frl_rate_mapping_reg.fields.set_num_links_to_rate_map(FRL_LINK_MAP_2, frl_rates[2]);
        frl_rate_mapping_reg.fields.set_num_links_to_rate_map(FRL_LINK_MAP_1, frl_rates[1]);
        frl_rate_mapping_reg.fields.set_num_links_to_rate_map(FRL_LINK_MAP_0, frl_rates[0]);

        frl_rate_mapping_reg.fields.fabric_rate_limiter_enable = 1;           // from dump
        frl_rate_mapping_reg.fields.num_links_to_max_bucket_map = 0x0183060c; // from dump
        frl_rate_mapping_reg.fields.network_sch_bitmap = 0x3f;                // from dump
        reg_val_list.push_back({(m_pacific_tree->sch_top->frl_rate_mapping), frl_rate_mapping_reg});
    } else {
        reg_val_list.push_back({(m_pacific_tree->sch_top->frl_rate_mapping), bit_vector("0x7E00000180000000000003600000000")});
    }

    reg_val_list.push_back({(m_pacific_tree->hmc_cgm->quant_thresholds),
                            bit_vector("0x700068006000580050004800400070006800600058005000480040003C0"
                                       "07000D0018002C00500090010001C00300050008000C0010001")});

    // Initialize various block registers to constant values according to designer's tune output.
    // This is essentially ASIC_MAX_SLICES_PER_DEVICE_NUM
    for (size_t i = 0; i < 5; i++) {
        // Put FFLB block to bypass mode
        reg_val_list.push_back({(m_pacific_tree->slice[i]->fllb->enable_config), 0x2});
    }
    reg_val_list.push_back({(m_pacific_tree->slice[5]->fabric_fllb->enable_config), 0x2});

    // When FLLB is in bypass mode it is better to always also disable aging
    for (size_t i : get_used_slices()) {
        const lld_register_scptr fllb_aging_config
            = (i < 5) ? m_pacific_tree->slice[i]->fllb->aging_config : m_pacific_tree->slice[i]->fabric_fllb->aging_config;

        fllb_aging_config_register aging_config_val;

        status = m_ll_device->read_register(*fllb_aging_config, aging_config_val);
        return_on_error(status);

        aging_config_val.fields.disable_aging = 1;
        reg_val_list.push_back({(fllb_aging_config), aging_config_val});
    }

    lld_memory_scptr hmc_cgm_profile_table = m_pacific_tree->hmc_cgm->profile_global;

    for (size_t mem_line = 0; mem_line < hmc_cgm_profile_table->get_desc()->entries; mem_line++) {
        mem_line_val_list.push_back({{hmc_cgm_profile_table, mem_line},
                                     mem_line < 16
                                         ? bit_vector("0xFFFEFFEFFF3FF7FFAFFCFFE3FF001C000300005000080000C000100001040000000000")
                                         : bit_vector("0xFFFEFFEFFF3FF7FFAFFCFFE3FF001C000300005000080000C000100001040000000001")});
    }

    mem_line_val_list.push_back({{(m_pacific_tree->reassembly->debug_pd_field_value_cfg), 0}, 0});
    mem_line_val_list.push_back({{(m_pacific_tree->reassembly->debug_pd_field_mask_cfg), 0}, 0});

    for (la_slice_id_t slice : get_used_slices()) {
        lld_memory_scptr source_port_map_table = (*m_pacific_tree->reassembly->source_port_map_table)[slice];
        for (size_t line = 0; line < source_port_map_table->get_desc()->entries; line++) {
            la_uint_t value = ((slice == 0) || (slice == 3) || (slice == 4)) ? (line < 32 ? line + 20 : line - 32)
                                                                             : (line < 32 ? line : (line - 32) + 20);
            mem_line_val_list.push_back({{source_port_map_table, line}, value});
        }
    }

    // Fix for VOQ return to SMS from HBM once congestion is over.
    if (m_revision == la_device_revision_e::PACIFIC_B1) {
        bit_vector spare_reg;
        status = m_ll_device->read_register(*m_pacific_tree->hmc_cgm->spare_reg, spare_reg);
        return_on_error(status);
        spare_reg.set_bits(4, 0, 8);
        reg_val_list.push_back({(m_pacific_tree->hmc_cgm->spare_reg), spare_reg});
    }

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_line_list(m_ll_device, mem_line_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_other()
{
    la_status status = LA_STATUS_SUCCESS;
    lld_register_value_list_t reg_val_list;
    lld_memory_value_list_t mem_val_list;
    if (m_device_mode == device_mode_e::STANDALONE) {
        // TXRQ message duplication configuration. Range is 0-96.
        csms_txrq_req_dup_reg_register reg;
        reg.fields.txrq_min_vsc_range = SA_MC_VSC_RANGE_START;
        reg.fields.txrq_max_vsc_range = SA_MC_VSC_RANGE_END;
        for (size_t i = 0; i < m_pacific_tree->csms->txrq_req_dup_reg->size(); i++) {
            reg_val_list.push_back({(*m_pacific_tree->csms->txrq_req_dup_reg)[i], reg});
        }

        // Set the fabric MC VSC range so it is not overlapping with SA MC range.
        csms_fmc_req_dup_reg_register fmc_req_dup_reg;
        fmc_req_dup_reg.fields.fmc_min_vsc_range = FABRIC_MC_VSC_IN_SA;
        fmc_req_dup_reg.fields.fmc_max_vsc_range = FABRIC_MC_VSC_IN_SA;
        fmc_req_dup_reg.fields.fmc_dup_bitmap = 0;
        reg_val_list.push_back({(m_pacific_tree->csms->fmc_req_dup_reg), fmc_req_dup_reg});
    }

    for (la_slice_id_t slice = 0; slice < m_pacific_tree->csms->dst_dev_map_mem->size(); slice++) {
        lld_memory_scptr dst_dev_map_mem = (*m_pacific_tree->csms->dst_dev_map_mem)[slice];
        mem_val_list.push_back({dst_dev_map_mem, 0});
    }

    counters_rx_lm_constant_config_register counters_rx_lm_reg;
    counters_rx_lm_reg.fields.max_rx_lm_grant_round_trip_time = 42;
    reg_val_list.push_back({(m_pacific_tree->counters->top->rx_lm_constant_config), counters_rx_lm_reg});

    for (la_slice_id_t slice : get_used_slices()) {
        lld_memory_scptr counters_bank_config = (*m_pacific_tree->counters->top->counters_bank_config)[slice];
        mem_val_list.push_back({counters_bank_config, bit_vector(8, counters_bank_config->get_desc()->width_bits)});
    }

    const uint64_t DISABLE_MAX_COUNTER_THRESHOLD
        = bit_utils::ones(counters_bank_group_4k_bank_interrupt_config_register::fields::MAX_COUNTER_INTERRUPT_THRESHOLD_WIDTH);
    bool is_narrow_counters_mode = m_device_properties[(int)la_device_property_e::ENABLE_NARROW_COUNTERS].bool_val;
    uint64_t threshold = is_narrow_counters_mode
                             ? static_cast<uint64_t>(m_device_properties[(int)la_device_property_e::MAX_COUNTER_THRESHOLD].int_val)
                             : DISABLE_MAX_COUNTER_THRESHOLD;

    counters_bank_group_bank_interrupt_config_register counters_bank_group_reg;
    counters_bank_group_reg.fields.max_counter_interrupt_threshold = threshold;
    for (size_t i = 0; i < array_size(m_pacific_tree->counters->bank_4k); i++) {
        for (size_t j = 0; j < m_pacific_tree->counters->bank_4k[0]->bank_interrupt_config->size(); j++) {
            reg_val_list.push_back({(*m_pacific_tree->counters->bank_4k[i]->bank_interrupt_config)[j], counters_bank_group_reg});
        }
    }

    for (size_t i = 0; i < array_size(m_pacific_tree->counters->bank_6k); i++) {
        for (size_t j = 0; j < m_pacific_tree->counters->bank_6k[0]->bank_interrupt_config->size(); j++) {
            reg_val_list.push_back({(*m_pacific_tree->counters->bank_6k[i]->bank_interrupt_config)[j], counters_bank_group_reg});
        }
    }

    csms_rlb_mc_cg_msg_reg_register rlb_mc_cg_msg;
    rlb_mc_cg_msg.fields.rlb_mc_cg_timer_val = 1 * KIBI;
    reg_val_list.push_back({(m_pacific_tree->csms->rlb_mc_cg_msg_reg), rlb_mc_cg_msg});

    // LPM CPU bubble: Set the bubble length being sent towards the CBRs whenever cif tries to write to a memory in the core
    // The following will make a bubble of up to 512 clks (disabled earlier once bubble is gotten)
    if (m_revision == la_device_revision_e::PACIFIC_B1) {
        bit_vector spare_reg;
        la_uint64_t val1 = 0x8; // 4'b1000
        la_uint64_t val2 = 0x2; // 2'b10
        for (size_t i = 0; i < array_size(m_pacific_tree->cdb->core); i++) {
            status = m_ll_device->read_register(*m_pacific_tree->cdb->core[i]->spare_reg, spare_reg);
            return_on_error(status);
            spare_reg.set_bit(0, 1); // Enable
            spare_reg.set_bits(67, 64, val1);
            spare_reg.set_bits(69, 68, val2);
            reg_val_list.push_back({(m_pacific_tree->cdb->core[i]->spare_reg), spare_reg});
        }
        for (size_t i = 0; i < array_size(m_pacific_tree->cdb->core_reduced); i++) {
            status = m_ll_device->read_register(*m_pacific_tree->cdb->core_reduced[i]->spare_reg, spare_reg);
            return_on_error(status);
            spare_reg.set_bit(0, 1); // Enable
            spare_reg.set_bits(67, 64, val1);
            spare_reg.set_bits(69, 68, val2);
            reg_val_list.push_back({(m_pacific_tree->cdb->core_reduced[i]->spare_reg), spare_reg});
        }
    }

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_credit_size()
{
    la_status status = LA_STATUS_SUCCESS;
    int current_credit_in_bytes;
    status = get_int_property(la_device_property_e::CREDIT_SIZE_IN_BYTES, current_credit_in_bytes);
    return_on_error(status);
    if (current_credit_in_bytes != INVALID_CREDIT_SIZE) {
        // if a user configured this property to a desired value than it shouldn't change
        return LA_STATUS_SUCCESS;
    }

    // initialize default value per device mode
    int default_credit_in_bytes = (m_device_mode == device_mode_e::LINECARD) ? 2048 : 1024;
    status = set_int_property(la_device_property_e::CREDIT_SIZE_IN_BYTES, default_credit_in_bytes);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_topology()
{
    la_status status = LA_STATUS_SUCCESS;

    for (la_slice_id_t slice : get_used_slices()) {
        switch (m_device_mode) {
        case device_mode_e::STANDALONE:
            m_tm_slice_mode[slice] = (la_uint_t)tm_slice_mode_e::STANDALONE;
            break;

        case device_mode_e::FABRIC_ELEMENT:
            m_tm_slice_mode[slice] = (la_uint_t)tm_slice_mode_e::FABRIC_TS;
            break;

        case device_mode_e::LINECARD:
            if (is_network_slice(slice)) {
                m_tm_slice_mode[slice] = (la_uint_t)tm_slice_mode_e::LC_CRF_TS_NETWORK;
                break;
            }

            if (m_slice_mode[slice] == la_slice_mode_e::CARRIER_FABRIC) {
                m_tm_slice_mode[slice] = (la_uint_t)tm_slice_mode_e::LC_CRF_TS_FABRIC;
                break;
            }

            return LA_STATUS_ENOTIMPLEMENTED;

        default:
            return LA_STATUS_ENOTIMPLEMENTED;
        }
    }

    status = init_em_per_bank_reg();
    return_on_error(status);

    for (la_slice_id_t sid : get_used_slices()) {
        for (la_ifg_id_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ifg_id++) {
            status = m_ifg_handlers[sid][ifg_id]->initialize_topology();
            return_on_error(status);
        }
    }

    status = init_tm();
    return_on_error(status);

    // Initialize per-slice settings
    for (la_slice_id_t slice : get_used_slices()) {
        la_status status = init_topology_tm(slice);
        return_on_error(status);
    }

    status = init_load_balancing_keys();
    return_on_error(status);

    status = init_interrupts();

    return status;
}

la_status
la_device_impl::init_meters()
{
    lld_register_value_list_t reg_val_list;
    lld_memory_value_list_t mem_val_list;
    lld_memory_line_value_list_t mem_line_val_list;

    // The global rate limiters should not interfere with traffic so configure high to practically disable them.
    // Shaper calculation is limited to a consecutive set of 5 bits, so: 0.96875 = 2^(-1) + 2^(-2) + ... + 2^(-5).
    // So max practical rate compensated to the multipliers limitation is: 900 Gbps / 0.96875 = 929 Gbps
    // Max token size = ceil(929 [Gbps] / 8 [bits per byte] / 1.2 [GHz] / 4 [bytes per clock]) = 25
    // 2 (twice the highest to practically disable) * 25 = 50
    // Device frequency in this case (as we use twice the highest number) is negligible
    constexpr size_t GLOBAL_METERS_TOKEN_SIZE = 50;

    // 1100 [Gbps] = 900G [physical rate] + 100G [recycle] + 100G [host]
    constexpr size_t IFG_FULL_RATE = 1100;

    // 8 = 1/8 [token/clock] * 64 [bytes/token]
    constexpr size_t TOKEN_BYTES_PER_CLOCK = 8;
    // 4 = 1/8 [token/clock] * 32 [bytes/token]
    constexpr size_t RATE_LIMITERS_TOKEN_BYTES_PER_CLOCK = 4;

    float num_exact_meter_64byte_tokens
        = ceil((float)IFG_FULL_RATE / 8.0 /* bits per Byte */ / m_device_frequency_float_ghz / (float)TOKEN_BYTES_PER_CLOCK);
    m_meter_shaper_rate = num_exact_meter_64byte_tokens * (float)TOKEN_BYTES_PER_CLOCK * m_device_frequency_float_ghz;
    // The calculation below would work if tokens given to rate limiter is not 2 times what is should
    // be(GLOBAL_METERS_TOKEN_SIZE. Retaining the commented code just in case we switch to halving the current value of token
    // size for rate limiters
    // float num_rate_limiters_32byte_tokens = ceil((float)IFG_FULL_RATE / 8.0 /* bits per Byte */ / m_device_frequency_float_ghz
    //                                             / (float)RATE_LIMITERS_TOKEN_BYTES_PER_CLOCK);
    float num_rate_limiters_32byte_tokens = GLOBAL_METERS_TOKEN_SIZE;
    m_rate_limiters_shaper_rate
        = num_rate_limiters_32byte_tokens * (float)RATE_LIMITERS_TOKEN_BYTES_PER_CLOCK * m_device_frequency_float_ghz;
    for (la_slice_id_t slice : get_used_slices()) {

        la_uint_t sm = m_tm_slice_mode[slice];

        // Set slice mode and enable metering
        rx_meter_global_conf_reg_register rx_meter_smr;
        rx_meter_smr.fields.slice_bypass_rx_meter = (m_slice_mode[slice] == la_slice_mode_e::NETWORK) ? 0 : 1;
        rx_meter_smr.fields.slice_mode = sm;
        reg_val_list.push_back({(*m_pacific_tree->rx_meter->top->global_conf_reg)[slice], rx_meter_smr});

        // Set meter-bank <-> slice mapping.
        // Enabling all meters on all slices.
        rx_meter_exact_meter_configuration_register exact_meter_configuration;
        if (is_network_slice(slice)) {
            exact_meter_configuration.fields.slice_exact_block_en = 0b11 << (slice * NUM_IFGS_PER_SLICE);
        } else { // fabric
            exact_meter_configuration.fields.slice_exact_block_en = 0;
        }
        reg_val_list.push_back({(*m_pacific_tree->rx_meter->top->exact_meter_configuration)[slice], exact_meter_configuration});

        rx_meter_statistical_meter_configuration_register stat_meter_conf_reg;
        stat_meter_conf_reg.fields.slice_statistic_mode = 0;    // set threshold to 512, lowest possible.
        stat_meter_conf_reg.fields.slice_coef_mode = slice * 3; // Keep the default value, each slice should have a different value.
        // The following fields belong to distributed meters which is not support, so we keep the default value for them.
        stat_meter_conf_reg.fields.slice_marked_packet_weight = 3;
        stat_meter_conf_reg.fields.slice_un_marked_packet_weight = 0;
        stat_meter_conf_reg.fields.slice_marked_packet_threshold = 0;
        reg_val_list.push_back({(*m_pacific_tree->rx_meter->top->statistical_meter_configuration)[slice], stat_meter_conf_reg});

        // Prepare a variable with full ratio to be used at several places inside the loop
        tm_utils::token_bucket_ratio_cfg_t ratio_cfg = tm_utils::calc_rate_ratio(m_meter_shaper_rate, LA_RATE_UNLIMITED);

        for (la_ifg_id_t i = 0; i < NUM_IFGS_PER_SLICE; i++) {
            la_ifg_id_t ifg = get_slice_id_manager()->slice_ifg_2_global_ifg(slice, i);

            // Per block token size
            size_t block_index = ifg / la_meter_set_impl::NUM_SHAPER_PER_EXACT_METERS_BLOCK;
            size_t meter_index = ifg % la_meter_set_impl::NUM_SHAPER_PER_EXACT_METERS_BLOCK;
            rx_meter_block_meter_block_configuration_register bc;
            bc.fields.block_token_size = (uint64_t)num_exact_meter_64byte_tokens;
            bc.fields.block_shaper_fifo_pause_thr = 12; // Use default value to avoid read-modify-write
            reg_val_list.push_back({(*m_pacific_tree->rx_meter->block[block_index]->meter_block_configuration)[meter_index], bc});

            // Configure rate-limiters

            // PER IFG

            rx_meter_global_rate_limiter_block_configuration_register ifg_token;
            ifg_token.fields.global_rate_limiter_block_token_size = GLOBAL_METERS_TOKEN_SIZE;
            ifg_token.fields.global_rate_limiter_block_shaper_fifo_pause_thr = 8; // Use default value to avoid read-modify-write
            reg_val_list.push_back({(*m_pacific_tree->rx_meter->top->global_rate_limiter_block_configuration)[ifg], ifg_token});

            // Profile
            rx_meter_global_rate_limiters_attribute_table_memory ifg_attr;
            ifg_attr.fields.global_rate_limiters_profile = 0;
            mem_val_list.push_back({(*m_pacific_tree->rx_meter->top->global_rate_limiters_attribute_table)[ifg], ifg_attr});

            // Rate limit per type
            rx_meter_global_rate_limiter_shaper_configuration_table_memory ifg_limiter;
            ifg_limiter.fields.global_rate_limiter_shaper_configuration_cir_weight = ratio_cfg.flat;
            mem_val_list.push_back(
                {(*m_pacific_tree->rx_meter->top->global_rate_limiter_shaper_configuration_table)[ifg], ifg_limiter});

            // PER Profile update CIR burst Size
            rx_meter_global_rate_limiters_profile_table_memory ifg_profile;
            ifg_profile.fields.global_rate_limiters_profile_cbs = 100;
            mem_val_list.push_back({(*m_pacific_tree->rx_meter->top->global_rate_limiters_profile_table)[ifg], ifg_profile});

            // PER Type Update token bucket "commited_bucket" to max bucket
            rx_meter_global_rate_limiters_table_memory ifg_bucket;
            ifg_bucket.fields.global_rate_limiters_commited_bucket = 102400;
            mem_val_list.push_back({(*m_pacific_tree->rx_meter->top->global_rate_limiters_table)[ifg], ifg_bucket});

            // PER Type Update "commited-above-zero" to 1
            rx_meter_global_rate_limiters_state_table_memory ifg_state;
            ifg_state.fields.global_rate_limiters_state_commited_above_zero = 1;
            mem_val_list.push_back({(*m_pacific_tree->rx_meter->top->global_rate_limiters_state_table)[ifg], ifg_state});

            // PER PORT

            // Token size
            rx_meter_rate_limiter_block_configuration_register port_config;
            port_config.fields.rate_limiter_block_token_size = GLOBAL_METERS_TOKEN_SIZE;
            port_config.fields.rate_limiter_block_shaper_fifo_pause_thr = 8; // Use default value to avoid read-modify-write
            reg_val_list.push_back({(*m_pacific_tree->rx_meter->top->rate_limiter_block_configuration)[ifg], port_config});

            // Profile
            rx_meter_rate_limiters_attribute_table_memory port_attr;
            port_attr.fields.rate_limiters_profile = 0;
            mem_val_list.push_back({(*m_pacific_tree->rx_meter->top->rate_limiters_attribute_table)[ifg], port_attr});

            // Rate limit per type
            rx_meter_rate_limiter_shaper_configuration_table_memory port_limiter;
            port_limiter.fields.rate_limiter_shaper_configuration_cir_weight = ratio_cfg.flat;
            mem_val_list.push_back({(*m_pacific_tree->rx_meter->top->rate_limiter_shaper_configuration_table)[ifg], port_limiter});

            // PER Profile update CIR burst Size
            rx_meter_rate_limiters_profile_table_memory port_profile;
            port_profile.fields.rate_limiters_profile_cbs = 100;
            mem_val_list.push_back({(*m_pacific_tree->rx_meter->top->rate_limiters_profile_table)[ifg], port_profile});

            // PER Type Update token bucket "commited_bucket" to max bucket
            rx_meter_rate_limiters_table_memory port_bucket;
            port_bucket.fields.rate_limiters_commited_bucket = 102400;
            mem_val_list.push_back({(*m_pacific_tree->rx_meter->top->rate_limiters_table)[ifg], port_bucket});

            // PER Type Update "commited-above-zero" to 1
            rx_meter_rate_limiters_state_table_memory port_state;
            port_state.fields.rate_limiters_state_commited_above_zero = 1;
            mem_val_list.push_back({(*m_pacific_tree->rx_meter->top->rate_limiters_state_table)[ifg], port_state});
        }

        rx_meter_if_source_port_config_memory if_port_config;

        // Port -> IFG mapping + compensation
        for (size_t port_num = 0; port_num < (2 * tm_utils::IFG_SYSTEM_PORT_SCHEDULERS); port_num++) {
            if_port_config.fields.slice_ifg = (port_num < tm_utils::IFG_SYSTEM_PORT_SCHEDULERS) ? 0 : 1;
            if_port_config.fields.slice_header_bytes_dec = 9; // +40B NPU header, -4B FCS = 36B
                                                              // Units are DWORDS => 9
            if_port_config.fields.slice_local_port_num = port_num % tm_utils::IFG_SYSTEM_PORT_SCHEDULERS;

            mem_line_val_list.push_back(
                {{(*m_pacific_tree->rx_meter->top->if_source_port_config)[slice], port_num}, if_port_config});
        }
    }

    for (size_t stat_bank = 0; stat_bank < NUM_STATISTICAL_METER_BANKS; stat_bank++) {
        rx_meter_meter_block_configuration_register stat_meter_block_conf = {.u8 = {0}};
        stat_meter_block_conf.fields.block_shaper_fifo_pause_thr = 9; // Keep default value.
        stat_meter_block_conf.fields.block_statistic_mode = 0;        // set threshold to 512, lowest possible.
        // The following fields belong to distributed meters which is not support, so we keep the default value for them:
        stat_meter_block_conf.fields.block_scrubber_window = 0xff;
        stat_meter_block_conf.fields.block_disable_scrubber = 1;
        stat_meter_block_conf.fields.block_packet_count_for_stat_update
            = get_meter_cir_eir_factor(la_meter_set::type_e::STATISTICAL);
        stat_meter_block_conf.fields.block_token_size_resolution = 0;
        reg_val_list.push_back({(*m_pacific_tree->rx_meter->top->meter_block_configuration)[stat_bank], stat_meter_block_conf});
    }

    if (m_revision == la_device_revision_e::PACIFIC_B1) {
        // statistical meter ECO in pacific B1 allows lower PPS
        bit_vector spare_reg;
        la_status status = m_ll_device->read_register(m_pacific_tree->rx_meter->top->spare_reg, spare_reg);
        return_on_error(status);
        // stat_meter_block_conf.fields.block_statistic_mode is configured so that threshold is 512
        // spare_reg[0] <-- 1 (enable ECO)
        spare_reg.set_bit(0, true);
        // spare_reg[14:1] <-- threshold - 1
        constexpr la_uint64_t ECO_Lmax = 512;
        constexpr la_uint64_t threshold = ECO_Lmax - 1;
        spare_reg.set_bits(14, 1, threshold);
        reg_val_list.push_back({(m_pacific_tree->rx_meter->top->spare_reg), spare_reg});
    }

    // Commit all changes
    la_status status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    status = lld_write_memory_line_list(m_ll_device, mem_line_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_topology_tm(la_slice_id_t slice)
{
    la_status status = LA_STATUS_SUCCESS;
    lld_register_value_list_t reg_val_list;
    la_uint_t sm = m_tm_slice_mode[slice];

    reassembly_slice_mode_reg_register reassembly_smr;
    reassembly_smr.fields.slice_mode = sm;
    reg_val_list.push_back({(*m_pacific_tree->reassembly->slice_mode_reg)[slice], reassembly_smr});

    rx_cgm_slice_mode_reg_register rx_cgm_smr;
    rx_cgm_smr.fields.cgm_slice_mode = sm;
    reg_val_list.push_back({(*m_pacific_tree->rx_cgm->slice_mode_reg)[slice], rx_cgm_smr});

    filb_slice_slice_mode_reg_register filb_smr;
    filb_smr.fields.slice_mode = sm;
    lld_register_scptr filb_slice_mode_reg = is_multi_device_aware_slice(slice)
                                                 ? m_pacific_tree->slice[slice]->filb->slice_mode_reg
                                                 : m_pacific_tree->slice[slice]->fabric_filb->slice_mode_reg;
    reg_val_list.push_back({filb_slice_mode_reg, filb_smr});

    // Slices 0-4 are regular; slice 5 is different.
    fllb_slice_mode_config_register fllb_smr;
    fllb_smr.fields.slice_mode = sm;
    lld_register_scptr fllb_slice_mode_reg = (slice != 0x5) ? m_pacific_tree->slice[slice]->fllb->slice_mode_config
                                                            : m_pacific_tree->slice[slice]->fabric_fllb->slice_mode_config;
    reg_val_list.push_back({fllb_slice_mode_reg, fllb_smr});

    ics_slice_slice_mode_reg_register ics_smr;
    ics_smr.fields.ics_mode = sm;
    reg_val_list.push_back({(m_pacific_tree->slice[slice]->ics->slice_mode_reg), ics_smr});

    pdvoq_slice_slice_mode_reg_register pdvoq_smr;
    // Due to a bug, in FE mode configure the pdvoq slice as SLICE_MODE_CRF_FAB_TS to solve the write fail count from the rqm.v
    pdvoq_smr.fields.slice_mode
        = (m_device_mode == device_mode_e::FABRIC_ELEMENT) ? (uint64_t)tm_slice_mode_e::LC_CRF_TS_FABRIC : sm;
    lld_register_scptr pdvoq_slice_mode_reg = is_multi_device_aware_slice(slice)
                                                  ? m_pacific_tree->slice[slice]->pdvoq->slice_mode_reg
                                                  : m_pacific_tree->slice[slice]->fabric_pdvoq->slice_mode_reg;
    reg_val_list.push_back({pdvoq_slice_mode_reg, pdvoq_smr});

    rx_counters_gen_config_register rx_counter_smr;
    rx_counter_smr.fields.slice_mode = sm;
    rx_counter_smr.fields.lm_index_aging_th = 0x1000;
    reg_val_list.push_back({(*m_pacific_tree->rx_counters->gen_config)[slice], rx_counter_smr});

    // Commit all changes
    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_time_soft_reset(la_uint_t reset_val)
{
    log_debug(HLD, "la_device_impl::init_time_soft_reset(%d)", reset_val);

    std::vector<lld_register_scptr> soft_reset_vec;

    for (size_t i = 0; i < array_size(m_pacific_tree->counters->bank_4k); i++) {
        soft_reset_vec.push_back(m_pacific_tree->counters->bank_4k[i]->soft_reset_configuration);
    }

    for (size_t i = 0; i < array_size(m_pacific_tree->counters->bank_6k); i++) {
        soft_reset_vec.push_back(m_pacific_tree->counters->bank_6k[i]->soft_reset_configuration);
    }

    for (size_t i = 0; i < array_size(m_pacific_tree->pdoq->empd); i++) {
        soft_reset_vec.push_back(m_pacific_tree->pdoq->empd[i]->soft_reset_configuration);
    }

    for (size_t i = 0; i < array_size(m_pacific_tree->pdvoq->empd); i++) {
        soft_reset_vec.push_back(m_pacific_tree->pdvoq->empd[i]->soft_reset_configuration);
    }

    for (size_t i = 0; i < array_size(m_pacific_tree->fdll); i++) {
        soft_reset_vec.push_back(m_pacific_tree->fdll[i]->soft_reset_configuration);
    }

    for (size_t i : get_used_slices()) {
        const auto& slice = m_pacific_tree->slice[i];

        // PP reorder block exists only on slices 0-2, on the other slices we have nw_reorder block
        if (i < 3) {
            soft_reset_vec.push_back(slice->pp_reorder->soft_reset_configuration);
        } else {
            for (size_t j = 0; j < 2; j++) {
                soft_reset_vec.push_back(slice->nw_reorder_block[j]->soft_reset_configuration);
            }
        }

        if (i < FIRST_HW_FABRIC_SLICE) {
            soft_reset_vec.push_back(slice->filb->soft_reset_configuration);
            soft_reset_vec.push_back(slice->pdvoq->soft_reset_configuration);
        } else {
            soft_reset_vec.push_back(slice->fabric_filb->soft_reset_configuration);
            soft_reset_vec.push_back(slice->fabric_pdvoq->soft_reset_configuration);
        }
        if (i < 5) {
            soft_reset_vec.push_back(slice->fllb->soft_reset_configuration);
        } else {
            soft_reset_vec.push_back(slice->fabric_fllb->soft_reset_configuration);
        }

        soft_reset_vec.push_back(slice->ics->soft_reset_configuration);
        soft_reset_vec.push_back(slice->pdoq->fdoq->soft_reset_configuration);
        soft_reset_vec.push_back(slice->pdoq->top->soft_reset_configuration);
        soft_reset_vec.push_back(slice->ts_ms->soft_reset_configuration);
        soft_reset_vec.push_back(slice->tx->cgm->soft_reset_configuration);
        soft_reset_vec.push_back(slice->tx->pdr->soft_reset_configuration);

        for (const auto& ifg : slice->ifg) {
            soft_reset_vec.push_back(ifg->ifgb->soft_reset_configuration);
            soft_reset_vec.push_back(ifg->mac_pool2->soft_reset_configuration);
            for (const auto& mac_pool8 : ifg->mac_pool8) {
                soft_reset_vec.push_back(mac_pool8->soft_reset_configuration);
            }
            if (i < FIRST_HW_FABRIC_SLICE) {
                soft_reset_vec.push_back(ifg->sch->soft_reset_configuration);
            } else {
                soft_reset_vec.push_back(ifg->fabric_sch->soft_reset_configuration);
            }
        }
    }

    for (size_t i = 0; i < array_size(m_pacific_tree->sms_quad); i++) {
        soft_reset_vec.push_back(m_pacific_tree->sms_quad[i]->soft_reset_configuration);
    }

    for (size_t i = 0; i < array_size(m_pacific_tree->rx_meter->block); i++) {
        soft_reset_vec.push_back(m_pacific_tree->rx_meter->block[i]->soft_reset_configuration);
    }

    for (size_t i = 0; i < array_size(m_pacific_tree->slice_pair); i++) {
        soft_reset_vec.push_back(m_pacific_tree->slice_pair[i]->rx_pdr->soft_reset_configuration);
    }

    for (size_t i = 0; i < array_size(m_pacific_tree->rx_pdr_mc_db); i++) {
        soft_reset_vec.push_back(m_pacific_tree->rx_pdr_mc_db[i]->soft_reset_configuration);
    }

    soft_reset_vec.push_back(m_pacific_tree->counters->top->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->csms->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->dics->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->dmc->frm->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->dmc->fte->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->dmc->pier->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->dvoq->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->fdll_shared_mem->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->hmc_cgm->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->ics_top->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->nw_reorder->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->pdoq_shared_mem->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->pdvoq_shared_mma->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->reassembly->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->rx_cgm->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->rx_counters->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->rx_meter->top->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->rx_pdr->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->sch_top->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->sms_main->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->ts_mon->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->tx_cgm_top->soft_reset_configuration);

    // NPU
    for (size_t sid : get_used_slices()) {
        const auto& slice = m_pacific_tree->slice[sid];
        for (size_t j = 0; j < array_size(m_pacific_tree->slice[0]->npu->rxpp_term->npe); j++) {
            soft_reset_vec.push_back(slice->npu->rxpp_term->npe[j]->soft_reset_configuration);
        }

        for (size_t j = 0; j < array_size(m_pacific_tree->slice[0]->npu->rxpp_fwd->npe); j++) {
            soft_reset_vec.push_back(slice->npu->rxpp_fwd->npe[j]->soft_reset_configuration);
        }

        for (size_t j = 0; j < array_size(m_pacific_tree->slice[0]->npu->rxpp_term->fi_eng); j++) {
            soft_reset_vec.push_back(slice->npu->rxpp_term->fi_eng[j]->soft_reset_configuration);
        }

        soft_reset_vec.push_back(slice->npu->rxpp_term->fi_stage->soft_reset_configuration);

        soft_reset_vec.push_back(slice->npu->rxpp_term->rxpp_term->soft_reset_configuration);
        soft_reset_vec.push_back(slice->npu->rxpp_fwd->rxpp_fwd->soft_reset_configuration);

        soft_reset_vec.push_back(slice->npu->cdb_cache->soft_reset_configuration);

        for (size_t j = 0; j < array_size(m_pacific_tree->slice[0]->npu->txpp->npe); j++) {
            soft_reset_vec.push_back(slice->npu->txpp->npe[j]->soft_reset_configuration);
        }

        for (size_t j = 0; j < array_size(m_pacific_tree->slice[0]->npu->txpp->cluster); j++) {
            soft_reset_vec.push_back(slice->npu->txpp->cluster[j]->soft_reset_configuration);
        }

        soft_reset_vec.push_back(slice->npu->sna->soft_reset_configuration);
        soft_reset_vec.push_back(slice->npu->txpp->txpp->soft_reset_configuration);
    }

    for (size_t i = 0; i < array_size(m_pacific_tree->slice_pair); i++) {
        soft_reset_vec.push_back(m_pacific_tree->slice_pair[i]->idb->top->soft_reset_configuration);
        soft_reset_vec.push_back(m_pacific_tree->slice_pair[i]->idb->res->soft_reset_configuration);
    }

    soft_reset_vec.push_back(m_pacific_tree->sdb->mac->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->sdb->enc->soft_reset_configuration);

    soft_reset_vec.push_back(m_pacific_tree->cdb->top->soft_reset_configuration);

    for (size_t i = 0; i < array_size(m_pacific_tree->cdb->core); i++) {
        soft_reset_vec.push_back(m_pacific_tree->cdb->core[i]->soft_reset_configuration);
    }

    for (size_t i = 0; i < array_size(m_pacific_tree->cdb->core_reduced); i++) {
        soft_reset_vec.push_back(m_pacific_tree->cdb->core_reduced[i]->soft_reset_configuration);
    }

    soft_reset_vec.push_back(m_pacific_tree->npuh->npe->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->npuh->fi->soft_reset_configuration);
    soft_reset_vec.push_back(m_pacific_tree->npuh->host->soft_reset_configuration);

    lld_register_value_list_t reg_val_list;
    for (auto lld_reg : soft_reset_vec) {
        reg_val_list.push_back({lld_reg, reset_val});
    }

    la_status stat = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(stat);

    log_debug(HLD, "la_device_impl::init_time_soft_reset() done");
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::poll_init_done()
{
    log_debug(HLD, "la_device_impl::poll_init_done()");
    la_status status = LA_STATUS_SUCCESS;

    // The code block below replaces future interface of polling on access engine.
    // Once LLD interface will be ready, this block should be removed
    size_t addr0 = m_pacific_tree->slice_pair[0]->idb->top->init_done_status_register->get_absolute_address();
    size_t addr1 = m_pacific_tree->slice[0]->ifg[0]->sch->oqse_shaper_init->get_absolute_address();
    bit_vector expected_val(1, 16);
    bit_vector mask(1, 16);
    log_debug(
        HLD, "command::poll_no_response %016zx 2 %s %s 200", addr0, expected_val.to_string().c_str(), mask.to_string().c_str());
    log_debug(
        HLD, "command::poll_no_response %016zx 2 %s %s 200", addr1, expected_val.to_string().c_str(), mask.to_string().c_str());
    /////////////////////////////////////////////////

    std::vector<lld_register_scptr> init_done_regs;
    init_done_regs.push_back(m_pacific_tree->slice[0]->ifg[0]->sch->oqse_shaper_init);
    init_done_regs.push_back(m_pacific_tree->slice_pair[0]->idb->top->init_done_status_register);
    init_done_regs.push_back(m_pacific_tree->sdb->mac->init_done_status_register);
    init_done_regs.push_back(m_pacific_tree->cdb->top->init_done_status_register);

    for (lld_register_scptr init_done_reg : init_done_regs) {
        bit_vector done_bv(0);
        while (!done_bv.bit(0)) {
            status = m_ll_device->read_register(*init_done_reg, done_bv);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_dynamic_memories()
{
    lld_memory_value_list_t mem_val_list;
    lld_memory_line_value_list_t mem_line_val_list;

    // Initialize dynamic memories on each slice
    for (size_t slice : get_used_slices()) {
        lld_memory_scptr contextfbm_bmp;
        lld_memory_scptr voqcgm_profile;
        lld_memory_scptr voq2context;
        lld_memory_scptr pdvoq_context2voq;

        if (slice < FIRST_HW_FABRIC_SLICE) {
            contextfbm_bmp = (m_pacific_tree->slice[slice]->pdvoq->contextfbm_bmp);
            voqcgm_profile = (m_pacific_tree->slice[slice]->pdvoq->voqcgm_profile);
            voq2context = (m_pacific_tree->slice[slice]->pdvoq->voq2context);
            pdvoq_context2voq = (m_pacific_tree->slice[slice]->pdvoq->context2voq);
        } else {
            contextfbm_bmp = (m_pacific_tree->slice[slice]->fabric_pdvoq->contextfbm_bmp);
            voqcgm_profile = (m_pacific_tree->slice[slice]->fabric_pdvoq->voqcgm_profile);
            voq2context = (m_pacific_tree->slice[slice]->fabric_pdvoq->voq2context);
            pdvoq_context2voq = (m_pacific_tree->slice[slice]->fabric_pdvoq->context2voq);
        }

        // Initialize context free bitmap to all free. In the HW-Network slices mark last context as not free.
        mem_val_list.push_back({contextfbm_bmp, bit_vector("0xFFFFFFFFFFFFFFFF")});
        if (slice < FIRST_HW_FABRIC_SLICE) {
            mem_line_val_list.push_back(
                {{contextfbm_bmp, contextfbm_bmp->get_desc()->entries - 1}, bit_vector("0x7FFFFFFFFFFFFFFF")});
        }

        lld_memory_scptr ics_context2voq = (m_pacific_tree->slice[slice]->ics->context2voq);
        // The HW scrubber mechanism in some corner case will send credit request to unused VOQ context.
        // Today it is resulted in 2b ECC error.
        // Initiate this memory to 0 (except last entry), such that requests will be sent to VOQ 0 (which is MC VOQ, getting
        // additional credit to it at some rare case will not affect the BW as eventually MC traffic is unscheduled anyway).
        mem_val_list.push_back({ics_context2voq, 0});
        mem_line_val_list.push_back({{ics_context2voq, ics_context2voq->get_desc()->entries - 1}, 0xFFFF});

        mem_line_val_list.push_back({{voqcgm_profile, voqcgm_profile->get_desc()->entries - 1}, 0});

        mem_val_list.push_back({voq2context, 0});
        mem_val_list.push_back({pdvoq_context2voq, 0});

        mem_val_list.push_back({m_pacific_tree->slice[slice]->ics->queue_profile, 0});
        mem_val_list.push_back({m_pacific_tree->slice[slice]->ics->queue_list, 3 /* Local-FLB-HP */});

        // Initialize dynamic memories on each IFG
        for (size_t ifg = 0; ifg < array_size(m_pacific_tree->slice[slice]->ifg); ifg++) {
            if (slice < FIRST_HW_FABRIC_SLICE) {
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->sch->vscc_cir_link_list, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->sch->vscc_eir_link_list, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->sch->oqse_cir_link_list, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->sch->oqse_cir_token_bucket, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->sch->oqse_cir_token_bucket_empty, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->sch->oqse_cir_token_bucket_link_list, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->sch->oqse_eir_link_list, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->sch->oqse_eir_token_bucket, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->sch->oqse_eir_token_bucket_empty, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->sch->oqse_eir_token_bucket_link_list, 0});
            } else {
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->fabric_sch->vscc_cir_link_list, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->fabric_sch->vscc_eir_link_list, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->fabric_sch->oqse_cir_link_list, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->fabric_sch->oqse_cir_token_bucket, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->fabric_sch->oqse_cir_token_bucket_empty, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->fabric_sch->oqse_cir_token_bucket_link_list, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->fabric_sch->oqse_eir_link_list, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->fabric_sch->oqse_eir_token_bucket, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->fabric_sch->oqse_eir_token_bucket_empty, 0});
                mem_val_list.push_back({m_pacific_tree->slice[slice]->ifg[ifg]->fabric_sch->oqse_eir_token_bucket_link_list, 0});
            }
        }
    }

    // Write only to 4 slices since the last two are having reduced blocks without this memory
    for (size_t slice : get_slice_id_manager()->get_slices_by_fabric_type(fabric_slices_type_e::HW_NON_FABRIC)) {
        lld_memory_scptr fabric_reachability_mem = (m_pacific_tree->slice[slice]->filb->fabric_reachability);
        mem_val_list.push_back({fabric_reachability_mem, 0});
    }

    push_back_ones(mem_val_list, m_pacific_tree->ics_top->dram_context_pool);

    // Initialize meter top/block memories
    for (const auto& rx_meter_block : m_pacific_tree->rx_meter->block) {
        for (size_t i = 0; i < rx_meter_block->meter_shaper_linked_list_table->get_desc()->instances; ++i) {
            mem_val_list.push_back({(*rx_meter_block->meter_shaper_linked_list_table)[i], 0});
        }
    }

    auto& meter_top = m_pacific_tree->rx_meter->top;
    for (size_t i = 0; i < meter_top->meter_shaper_linked_list_table->get_desc()->instances; ++i) {
        mem_val_list.push_back({(*meter_top->meter_shaper_linked_list_table)[i], 0});
    }

    for (size_t i = 0; i < meter_top->meters_token_table->get_desc()->instances; ++i) {
        mem_val_list.push_back({(*meter_top->meters_token_table)[i], 1});
    }

    // Initialize shared_sram banks. During init, shared_srams can be written to as a normal memory, with CIF write.
    // During traffic, they can only be written to through redirection (implemented in LPM).
    const auto& cdb = m_pacific_tree->cdb;
    for (size_t i = 0; i < array_size(cdb->core); ++i) {
        for (size_t j = 0; j < cdb->core[0]->srams_group0->get_desc()->instances; ++j) {
            mem_val_list.push_back({(*cdb->core[i]->srams_group0)[j], 0});
            mem_val_list.push_back({(*cdb->core[i]->srams_group1)[j], 0});
            mem_val_list.push_back({(*cdb->core_reduced[i]->srams_group0)[j], 0});
            mem_val_list.push_back({(*cdb->core_reduced[i]->srams_group1)[j], 0});
        }
    }

    for (size_t i : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_NON_FABRIC)) {
        for (size_t j = 0; j < m_pacific_tree->slice[i]->pp_reorder->pp_exact_match_verifier->get_desc()->instances; ++j) {
            mem_val_list.push_back({(*m_pacific_tree->slice[i]->pp_reorder->pp_exact_match_verifier)[j], 0});
        }
    }

    mem_val_list.push_back({m_pacific_tree->dics->dramcontext2smscontext, 0});

    la_status status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    status = lld_write_memory_line_list(m_ll_device, mem_line_val_list);
    return_on_error(status);

    // Remove DRAM context 0 from operation
    ics_top_dram_pool_fbm_conf_register dram_pool_fbm_conf_reg;
    status = m_ll_device->read_register(*m_pacific_tree->ics_top->dram_pool_fbm_conf, dram_pool_fbm_conf_reg);
    return_on_error(status);

    dram_pool_fbm_conf_reg.fields.dram_pool_fbm_total_free_buf = 4095;
    status = m_ll_device->write_register(*m_pacific_tree->ics_top->dram_pool_fbm_conf, dram_pool_fbm_conf_reg);
    return_on_error(status);

    ics_top_dram_context_pool_memory dram_context_pool_memory;
    status = m_ll_device->read_memory(*m_pacific_tree->ics_top->dram_context_pool, 0, dram_context_pool_memory);
    return_on_error(status);

    dram_context_pool_memory.fields.dram_context_pool_bmp = 0xfffffffffffffffe;
    status = m_ll_device->write_memory(*m_pacific_tree->ics_top->dram_context_pool, 0, dram_context_pool_memory);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround()
{
    la_status status = apply_topology_post_soft_reset_workaround_ics();
    return_on_error(status);

    status = apply_topology_post_soft_reset_workaround_dics();
    return_on_error(status);

    status = apply_topology_post_soft_reset_workaround_dvoq();
    return_on_error(status);

    status = apply_topology_post_soft_reset_workaround_ifgb();
    return_on_error(status);

    status = apply_topology_post_soft_reset_workaround_reorder();
    return_on_error(status);

    status = apply_topology_post_soft_reset_workaround_tx_cgm();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround_ics()
{
    la_status status = LA_STATUS_SUCCESS;
    lld_register_value_list_t reg_val_list;
    lld_memory_value_list_t mem_val_list;

    ics_slice_general_conf_reg_register ics_gen_conf;
    ics_slice_internal_fifo_alm_full_register ics_internal_alm_full;
    ics_slice_packing_configuration_register ics_packing_cfg;
    ics_slice_dram_list_param_reg_register ics_dram_list;

    ics_internal_alm_full.fields.dram_delete_fifo_alm_full = 3;
    ics_internal_alm_full.fields.dram_pack_fifo_alm_full = 3;

    for (size_t rx_slice : get_used_slices()) {
        for (size_t tx_slice : get_used_slices()) {
            if (m_device_mode != device_mode_e::FABRIC_ELEMENT) {
                // SA and LC
                if ((is_network_slice(rx_slice)) && (is_network_slice(tx_slice))) {
                    // RX network -> TX network
                    reg_val_list.push_back({(*m_pacific_tree->slice[rx_slice]->ics->delete_credits)[tx_slice], 0x40});
                } else if ((m_slice_mode[rx_slice] == la_slice_mode_e::CARRIER_FABRIC) && is_network_slice(tx_slice)) {
                    // RX fabric -> TX network
                    reg_val_list.push_back({(*m_pacific_tree->slice[rx_slice]->ics->delete_credits)[tx_slice], 0x1c});
                } else if (m_slice_mode[tx_slice] == la_slice_mode_e::CARRIER_FABRIC) {
                    // RX any -> TX fabric
                    if ((m_revision == la_device_revision_e::PACIFIC_B0) || (m_revision == la_device_revision_e::PACIFIC_B1)) {
                        reg_val_list.push_back({(*m_pacific_tree->slice[rx_slice]->ics->delete_credits)[tx_slice], 0x40});
                    } else {
                        reg_val_list.push_back({(*m_pacific_tree->slice[rx_slice]->ics->delete_credits)[tx_slice], 0});
                    }
                } else {
                    return LA_STATUS_ENOTIMPLEMENTED;
                }
            } else {
                // FE
                reg_val_list.push_back({(*m_pacific_tree->slice[rx_slice]->ics->delete_credits)[tx_slice], 0x1c});
            }
        }

        // The trigger must be post setting the delete credits
        reg_val_list.push_back({(m_pacific_tree->slice[rx_slice]->ics->delete_credits_trig), 0x0});
        reg_val_list.push_back({(m_pacific_tree->slice[rx_slice]->ics->delete_credits_trig), 0x1});
        reg_val_list.push_back({(m_pacific_tree->slice[rx_slice]->ics->delete_credits_trig), 0x0});

        // Post soft reset need to access ICS general configuration and set to 0 PauseCheckinMachine field
        status = m_ll_device->read_register(*m_pacific_tree->slice[rx_slice]->ics->general_conf_reg, ics_gen_conf);
        return_on_error(status);
        ics_gen_conf.fields.pause_checkin_machine = 0;

        if (is_network_slice(rx_slice)) {
            // The scrubber is relevant only for the Network slices
            ics_gen_conf.fields.scrubber_step = 500000;
        }

        reg_val_list.push_back({(m_pacific_tree->slice[rx_slice]->ics->general_conf_reg), ics_gen_conf});

        lld_memory_scptr aged_out_queue = (m_pacific_tree->slice[rx_slice]->ics->aged_out_queue);
        mem_val_list.push_back({aged_out_queue, bit_vector(0, aged_out_queue->get_desc()->width_bits)});

        if (is_network_slice(rx_slice)) {
            // The scrubber is relevant only for the Network slices
            // This field (scrubber aging trigger) MUST be written after writing the general config register
            reg_val_list.push_back({(m_pacific_tree->slice[rx_slice]->ics->scrb_aging_trig_reg), 1});
        }

        lld_memory_scptr scrubber_mem = (m_pacific_tree->slice[rx_slice]->ics->scrubber_mem);
        mem_val_list.push_back({scrubber_mem, bit_vector(4, scrubber_mem->get_desc()->width_bits)});

        // ICS internal_fifo_alm_full
        reg_val_list.push_back({(m_pacific_tree->slice[rx_slice]->ics->internal_fifo_alm_full), ics_internal_alm_full});

        // Read-modify-write ICS packing_configuration
        status = m_ll_device->read_register(*m_pacific_tree->slice[rx_slice]->ics->packing_configuration, ics_packing_cfg);
        return_on_error(status);
        ics_packing_cfg.fields.dram_buffer_size = 4;
        ics_packing_cfg.fields.dram_burst_size = 13;
        ics_packing_cfg.fields.max_pds_in_pack = 16;
        ics_packing_cfg.fields.header_size = 8;
        reg_val_list.push_back({(m_pacific_tree->slice[rx_slice]->ics->packing_configuration), ics_packing_cfg});

        // Read-modify-write ICS dram_list_param_reg
        status = m_ll_device->read_register(*m_pacific_tree->slice[rx_slice]->ics->dram_list_param_reg, ics_dram_list);
        return_on_error(status);
        ics_dram_list.fields.dram_eligible_th_norm = 6144;
        ics_dram_list.fields.dram_eligible_th_empty
            = ((m_revision == la_device_revision_e::PACIFIC_B1) && is_network_slice(rx_slice)) ? 8191 : 6144;
        ics_dram_list.fields.num_of_reads_per_dram_buffer
            = ((m_revision == la_device_revision_e::PACIFIC_B1) && is_network_slice(rx_slice)) ? 128 : 32;
        ics_dram_list.fields.max_parallel_dram_contexts = 14;
        ics_dram_list.fields.qsize_limit_to_read_it_all = 200000;

        reg_val_list.push_back({(m_pacific_tree->slice[rx_slice]->ics->dram_list_param_reg), ics_dram_list});
    }

    bool does_hbm_exist;
    status = hbm_exists(does_hbm_exist);
    return_on_error(status);

    bool is_pacific_b1_sa_lc = ((m_revision == la_device_revision_e::PACIFIC_B1)
                                && ((m_device_mode == device_mode_e::STANDALONE) || (m_device_mode == device_mode_e::LINECARD)));

    if (does_hbm_exist && m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        // ICS Top - Read-modify-write or just simply write
        ics_top_dram_write_meter_register dram_write_meter_reg;
        ics_top_dram_write_eligible_meter_register dram_write_eligible_meter_reg;
        ics_top_dram_discard_meter_register dram_discard_meter_reg;

        // Generally we would like to limit the write meter to half of the total BW, to allow similar read BW.
        // DRAM pf type X-DIE has total BW of 3.6 Tbps, but currently the write limit will be 1.75 Tbps (instead of 1.8).
        // DRAM of type B-DIE has total BW of 2.2 Tbps so write meter limit will be 1.1 Tbps.
        // There is a single HBM with two interfaces. So pick any (1st) to get the info.
        la_uint_t hbm_model_id = m_hbm_handler->m_device_model_id;
        constexpr float METER_RATE = 1.0;
        float desired_hbm_write_rate;
        float desired_hbm_eviction_rate;
        switch (hbm_model_id) {
        case HBM_MODEL_X_DIE:
            desired_hbm_write_rate = is_pacific_b1_sa_lc ? 1300 : 1600;    // Gbps
            desired_hbm_eviction_rate = is_pacific_b1_sa_lc ? 1100 : 1200; // Gbps
            break;
        case HBM_MODEL_B_DIE:
            desired_hbm_write_rate = 1100;    // Gbps
            desired_hbm_eviction_rate = 1050; // Gbps
            break;
        default:
            log_warning(HLD, "Unsupported HBM model ID = 0x%x.", hbm_model_id);
            return LA_STATUS_EUNKNOWN;
        }

        status = m_ll_device->read_register(*m_pacific_tree->ics_top->dram_write_meter, dram_write_meter_reg);
        return_on_error(status);
        status = m_ll_device->read_register(*m_pacific_tree->ics_top->dram_write_eligible_meter, dram_write_eligible_meter_reg);
        return_on_error(status);
        status = m_ll_device->read_register(*m_pacific_tree->ics_top->dram_discard_meter, dram_discard_meter_reg);
        return_on_error(status);
        dram_write_meter_reg.fields.dram_write_meter_rate = (uint64_t)METER_RATE;
        dram_write_meter_reg.fields.dram_write_meter_inc_value
            = floor(desired_hbm_eviction_rate * METER_RATE / m_device_frequency_float_ghz / 8.0);
        dram_write_meter_reg.fields.dram_write_meter_max_bucket = 1 * MEBI;    // 1 MB
        dram_write_meter_reg.fields.dram_write_meter_max_bucket_th = MEBI / 2; // 0.5 MB

        dram_write_eligible_meter_reg.fields.dram_write_elig_meter_rate = (uint64_t)METER_RATE;
        dram_write_eligible_meter_reg.fields.dram_write_elig_meter_inc_value
            = floor(desired_hbm_write_rate * METER_RATE / m_device_frequency_float_ghz / 8.0);
        dram_write_eligible_meter_reg.fields.dram_write_elig_meter_max_bucket
            = is_pacific_b1_sa_lc ? 12 * MEBI /*12 MB*/ : 1 * GIBI /*1 GB*/;
        dram_write_eligible_meter_reg.fields.dram_write_elig_meter_max_bucket_th
            = is_pacific_b1_sa_lc ? 3 * MEBI /*3 MB*/ : 256 * MEBI /*256 MB*/;

        dram_discard_meter_reg.fields.dram_discard_meter_max_bucket_th = 256 * MEBI; // 256 MB
        dram_discard_meter_reg.fields.dram_discard_meter_max_bucket = 1 * GIBI;      // 1 GB
        dram_discard_meter_reg.fields.dram_discard_meter_rate = 1;
        dram_discard_meter_reg.fields.dram_discard_meter_inc_value = 0xFFFF;

        reg_val_list.push_back({(m_pacific_tree->ics_top->dram_write_meter), dram_write_meter_reg});
        reg_val_list.push_back({(m_pacific_tree->ics_top->dram_write_eligible_meter), dram_write_eligible_meter_reg});
        reg_val_list.push_back({(m_pacific_tree->ics_top->dram_discard_meter), dram_discard_meter_reg});

        // Setting the debug register for ICS top to 1 will cause both meters (DRAM write meter, DRAM write eligible meter)
        // to operate independently of each other.
        reg_val_list.push_back({(m_pacific_tree->ics_top->debug_reg), 1});
    }

    // Note: scrubber_mem is burst-accessed by internal ics scrubber, which has a higher priority than CPU access.
    // As a result, CPU access may fail with the default CIF timeout. Here we increase the CIF timeout.
    ics_slice_memory_access_timeout_register timeout_reg;
    for (size_t sid : get_used_slices()) {
        const auto& slice = m_pacific_tree->slice[sid];
        status = m_ll_device->read_register(*slice->ics->memory_access_timeout, timeout_reg);
        return_on_error(status);

        timeout_reg.fields.timeout_counter_thr = 0xf000;
        status = m_ll_device->write_register(*slice->ics->memory_access_timeout, timeout_reg);
        return_on_error(status);
    }

    // Note: here we first must write the memory and only after that the registers.
    //       One of the registers is scrb_aging_trig_reg which should be set to 1 after properly initializing the memories.
    status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    ics_slice_slice_mode_reg_register ics_slice_mode;
    ics_slice_ms_q_conf_register ics_slice_ms_q_conf;

    for (size_t slice_num : get_used_slices()) {
        // Configure UCH to 32 entries and UCL to 0 for Fabric Element and Line Card fabric slice
        // There is a bug where the ics.ms_q_conf can't be configured in non-standalone mode
        // so the workaround is to temporary change slice mode to standalone
        if (m_slice_mode[slice_num] == la_slice_mode_e::CARRIER_FABRIC) {
            status = m_ll_device->read_register(*m_pacific_tree->slice[slice_num]->ics->slice_mode_reg, ics_slice_mode);
            return_on_error(status);
            status = m_ll_device->write_register(*m_pacific_tree->slice[slice_num]->ics->slice_mode_reg,
                                                 (la_uint_t)tm_slice_mode_e::STANDALONE);
            return_on_error(status);
            ics_slice_ms_q_conf.fields.ms_q_uch_crdts = 0;
            ics_slice_ms_q_conf.fields.ms_q_ucl_crdts = 32;
            ics_slice_ms_q_conf.fields.ms_q_mc_crdts = 16;
            status = m_ll_device->write_register(*m_pacific_tree->slice[slice_num]->ics->ms_q_conf, ics_slice_ms_q_conf);
            return_on_error(status);
            status = m_ll_device->write_register(*m_pacific_tree->slice[slice_num]->ics->slice_mode_reg, ics_slice_mode);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround_dics()
{
    la_status status = LA_STATUS_SUCCESS;
    lld_register_value_list_t reg_val_list;

    // DICS
    dics_eligible_th_reg_register dics_eligible_th_reg;
    dics_credits_conf_reg_register dics_credits_conf_reg;

    status = m_ll_device->read_register(*m_pacific_tree->dics->eligible_th_reg, dics_eligible_th_reg);
    return_on_error(status);
    status = m_ll_device->read_register(*m_pacific_tree->dics->credits_conf_reg, dics_credits_conf_reg);
    return_on_error(status);

    dics_eligible_th_reg.fields.eir_slice_blocking_th = 0x4800;
    dics_eligible_th_reg.fields.cir_slice_blocking_th = 0x4800;
    dics_eligible_th_reg.fields.eir_slice_pds_blocking_th = 5;
    dics_eligible_th_reg.fields.cir_slice_pds_blocking_th = 5;
    dics_eligible_th_reg.fields.speculative_en
        = ((m_revision == la_device_revision_e::PACIFIC_B1)
           && ((m_device_mode == device_mode_e::STANDALONE) || (m_device_mode == device_mode_e::LINECARD)))
              ? 1
              : 0;

    dics_credits_conf_reg.fields.stop_crdt_on_off = 0; // only when force dram is done
    dics_credits_conf_reg.fields.max_qb_threshold = 0x100000;

    int credit_in_bytes;
    status = get_int_property(la_device_property_e::CREDIT_SIZE_IN_BYTES, credit_in_bytes);
    return_on_error(status);

    dics_credits_conf_reg.fields.crdt_in_bytes = credit_in_bytes;

    switch (credit_in_bytes) {
    case 1024:
        dics_credits_conf_reg.fields.crdt_size_log2 = 10;
        break;

    case 2048:
        dics_credits_conf_reg.fields.crdt_size_log2 = 11;
        break;

    default:
        return LA_STATUS_EUNKNOWN;
    }

    reg_val_list.push_back({(m_pacific_tree->dics->eligible_th_reg), dics_eligible_th_reg});
    reg_val_list.push_back({(m_pacific_tree->dics->credits_conf_reg), dics_credits_conf_reg});

    dics_accept_queue_blocking_th_reg_register dics_accept_queue_blocking_th_reg;
    dics_clear_queue_blocking_th_reg_register dics_clear_queue_blocking_th_reg;
    dics_set_queue_blocking_th_reg_register dics_set_queue_blocking_th_reg;

    dics_accept_queue_blocking_th_reg.fields.accept_queue_blocking_th = 50000;
    dics_clear_queue_blocking_th_reg.fields.clear_queue_blocking_th = 25000;
    dics_set_queue_blocking_th_reg.fields.set_queue_blocking_th = 15000000;

    for (size_t i = 0; i < NUM_VOQ_CGM_PROFILES_PER_DEVICE; i++) {
        reg_val_list.push_back({(*m_pacific_tree->dics->accept_queue_blocking_th_reg)[i], dics_accept_queue_blocking_th_reg});
        reg_val_list.push_back({(*m_pacific_tree->dics->clear_queue_blocking_th_reg)[i], dics_clear_queue_blocking_th_reg});
        reg_val_list.push_back({(*m_pacific_tree->dics->set_queue_blocking_th_reg)[i], dics_set_queue_blocking_th_reg});
    }

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround_dvoq()
{
    la_status status = LA_STATUS_SUCCESS;
    lld_register_value_list_t reg_val_list;

    // DVOQ
    dvoq_used_bytes_config_register_register dvoq_used_bytes_config_reg;
    dvoq_used_bytes_config_reg.fields.size_when_half = 6144;
    dvoq_used_bytes_config_reg.fields.size_when_full = 8192;
    reg_val_list.push_back({(m_pacific_tree->dvoq->used_bytes_config_register), dvoq_used_bytes_config_reg});

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround_ifgb()
{
    lld_register_value_list_t reg_val_list;

    uint64_t shaper_burst;
    uint64_t shaper_period;
    uint64_t odd_ifg_diff;
    if ((m_revision == la_device_revision_e::PACIFIC_B0) || (m_revision == la_device_revision_e::PACIFIC_B1)) {
        shaper_burst = tm_utils::MAX_IFG_RX_SHAPER_BURST_PACIFIC_B0_B1;
        shaper_period = tm_utils::MAX_IFG_RX_SHAPER_PERIOD_PACIFIC_B0_B1;
        odd_ifg_diff = tm_utils::MAX_IFG_RX_SHAPER_ODD_IFG_DIFF_PACIFIC_B0_B1;
    } else { // PACIFIC::A0
        shaper_burst = tm_utils::MAX_IFG_RX_SHAPER_BURST_PACIFIC_A0;
        shaper_period = tm_utils::MAX_IFG_RX_SHAPER_PERIOD_PACIFIC_A0;
        odd_ifg_diff = tm_utils::MAX_IFG_RX_SHAPER_ODD_IFG_DIFF_PACIFIC_A0;
    }
    ifgb_rx_shaper_cfg_register even_rx_shaper_reg;
    ifgb_rx_shaper_cfg_register odd_rx_shaper_reg;
    even_rx_shaper_reg.fields.rx_shaper_burst = shaper_burst;
    even_rx_shaper_reg.fields.rx_shaper_period = shaper_period;
    odd_rx_shaper_reg.fields.rx_shaper_burst = shaper_burst + odd_ifg_diff;
    odd_rx_shaper_reg.fields.rx_shaper_period = shaper_period + odd_ifg_diff;

    for (la_slice_id_t sid : get_used_slices()) {
        for (la_ifg_id_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ifg_id++) {
            if (ifg_id & 1) {
                reg_val_list.push_back({(m_pacific_tree->slice[sid]->ifg[ifg_id]->ifgb->rx_shaper_cfg), odd_rx_shaper_reg});
            } else {
                reg_val_list.push_back({(m_pacific_tree->slice[sid]->ifg[ifg_id]->ifgb->rx_shaper_cfg), even_rx_shaper_reg});
            }

            if (m_revision == la_device_revision_e::PACIFIC_B1) {
                bit_vector spare_reg;
                la_status status = m_ll_device->read_register(*m_pacific_tree->slice[sid]->ifg[ifg_id]->ifgb->spare_reg, spare_reg);
                return_on_error(status);
                spare_reg.set_bit(0, 1); // Padding short packets.
                spare_reg.set_bit(1, 1); // Egress NPU drop.
                reg_val_list.push_back({(m_pacific_tree->slice[sid]->ifg[ifg_id]->ifgb->spare_reg), spare_reg});
                return_on_error(status);
            }
        }
    }

    la_status status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround_reorder()
{
    if ((m_revision == la_device_revision_e::PACIFIC_B0) || (m_revision == la_device_revision_e::PACIFIC_B1)) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = LA_STATUS_SUCCESS;
    lld_register_value_list_t reg_val_list;
    lld_memory_value_list_t mem_val_list;

    // Remove re-order exact match bins
    // Due to HW bug in Re-order exact match we remove 2 bins out of 6. The bins are organized in two banks
    // so we mark two bins in the second bank as in-use and write invalid data.
    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_NON_FABRIC)) {
        // Remove banks
        // Total 8 banks, we need to modify 4 of them (the odd ones)
        for (size_t bank = 0; bank < 4; bank++) {
            size_t cfg_bank = bank * 2 + 1;
            lld_memory_scptr exact_match_valid = (*m_pacific_tree->slice[slice]->pp_reorder->pp_exact_match_valid)[cfg_bank];
            // Mark two bins as in use
            mem_val_list.push_back({exact_match_valid, bit_vector(3, exact_match_valid->get_desc()->width_bits)});

            lld_memory_scptr exact_match_verifier = (*m_pacific_tree->slice[slice]->pp_reorder->pp_exact_match_verifier)[cfg_bank];
            // Write invalid data.
            mem_val_list.push_back({exact_match_verifier, 0});
        }
    }

    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_FABRIC)) {
        for (size_t block = 0; block < array_size(m_pacific_tree->slice[slice]->nw_reorder_block); block++) {
            // Remove banks
            // Total 4 banks, we need to modify 2 of them (the odd ones)
            for (size_t bank = 0; bank < 2; bank++) {
                size_t cfg_bank = bank * 2 + 1;
                lld_memory_scptr exact_match_valid
                    = (*m_pacific_tree->slice[slice]->nw_reorder_block[block]->nw_exact_match_valid)[cfg_bank];
                // Mark two bins as in use
                mem_val_list.push_back({exact_match_valid, bit_vector(31, exact_match_valid->get_desc()->width_bits)});

                lld_memory_scptr exact_match_verifier
                    = (*m_pacific_tree->slice[slice]->nw_reorder_block[block]->nw_exact_match_verifier)[cfg_bank];
                // Write invalid data.
                mem_val_list.push_back({exact_match_verifier, 0});
            }
        }
    }

    status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround_tx_cgm()
{
    la_status status = LA_STATUS_SUCCESS;
    lld_memory_value_list_t mem_val_list;

    for (la_slice_id_t slice : get_used_slices()) {
        lld_memory_scptr uc_oq_state = (m_pacific_tree->slice[slice]->tx->cgm->uc_oq_state);
        lld_memory_scptr mc_qsize_byte = (m_pacific_tree->slice[slice]->tx->cgm->mc_qsize_byte);
        lld_memory_scptr mc_qsize_pd = (m_pacific_tree->slice[slice]->tx->cgm->mc_qsize_pd);

        mem_val_list.push_back({uc_oq_state, bit_vector(0, uc_oq_state->get_desc()->width_bits)});
        mem_val_list.push_back({mc_qsize_byte, bit_vector(0, mc_qsize_byte->get_desc()->width_bits)});
        mem_val_list.push_back({mc_qsize_pd, bit_vector(0, mc_qsize_pd->get_desc()->width_bits)});
    }

    status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_init_workarounds()
{
    log_debug(HLD, "la_device_impl::apply_init_workarounds()");
    la_status status = LA_STATUS_SUCCESS;

    // EM with XOR memory requires 1 line initializing after srstn release
    //      Priority: Low
    //      Date added: 25/07/2017
    //      Block: Exact match with XOR memory
    //      Description:
    //          EM with XOR memory tries to init the XOR memory before the inner init process of the XOR memory is done.
    //          The behavior causes single specific line inside the XOR memory, to be initialized with unknown value, while it
    //          should be initialized to 0.
    //      Workaround:
    //      1. Take block out of soft reset
    //      2. Write 0 to the miss-initialized line.
    //
    //      The line is deterministic per EM module, and will always be the same:
    //      i. For the  large encapsulation data base, there are two types of EM with XOR memory:
    //              address to write for the 4k EM = {2'b10, 11'd2043};
    //              address to write for the 8k EM = {2'b10, 12'd4086};

    // LargeEncDB 2-port XOR memory is implemented as following:
    // - EM verifier is constructed from 2 banks (2k each for small/ 4k each for large) + XOR bank (same size).
    // - banks are exposed in LBR (verifier size is 4k entries for small / 8k entries for large).
    // - XOR bank is hidden and is used to enable 2-port access.
    //
    // The problem is that normal SDK API fails on OUT-OF-RANGE
    // Have to use raw API

    const size_t large_enc_bank_4k_line = 2043 | (2 << 11); // writing to bank #3
    const size_t large_enc_bank_8k_line = 4086 | (2 << 12); // writing to bank #3

    std::vector<lld_memory_array_sptr> large_enc_banks;
    large_enc_banks.push_back(m_pacific_tree->sdb->enc->large_enc_db0_verifier);
    large_enc_banks.push_back(m_pacific_tree->sdb->enc->large_enc_db1_verifier);
    large_enc_banks.push_back(m_pacific_tree->sdb->enc->large_enc_db2_verifier);
    large_enc_banks.push_back(m_pacific_tree->sdb->enc->large_enc_db3_verifier);

    std::vector<size_t> large_enc_lines;
    large_enc_lines.push_back(large_enc_bank_4k_line);
    large_enc_lines.push_back(large_enc_bank_8k_line);
    large_enc_lines.push_back(large_enc_bank_8k_line);
    large_enc_lines.push_back(large_enc_bank_4k_line);

    for (size_t arr_idx = 0; arr_idx < large_enc_banks.size(); ++arr_idx) {
        lld_memory_array_sptr banks = large_enc_banks[arr_idx];
        la_block_id_t block_id = banks->get_block_id();
        for (size_t idx = 0; idx < banks->size(); ++idx) {
            const lld_memory_desc_t* desc = (*banks)[idx]->get_desc();

            la_entry_addr_t mem_address = desc->addr + large_enc_lines[arr_idx];
            la_entry_width_t width = desc->width_total_bits;
            bit_vector zero_bv(0, width);

            status = m_ll_device->write_memory_raw(block_id, mem_address, width, zero_bv);
            return_on_error(status);
        }
    }

    //      ii. For the Shared-db verifier in the RXPDR there is one type of EM with XOR memory:
    //              address to write =  {1'b1, 14'h7f8};
    const size_t rxpdr_line = 0x7f8 | (1 << 14); // writing to bank #3
    std::vector<lld_memory_array_sptr> rxpdr_banks;
    rxpdr_banks.push_back(m_pacific_tree->rx_pdr_mc_db[0]->shared_db_verifier);
    rxpdr_banks.push_back(m_pacific_tree->rx_pdr_mc_db[1]->shared_db_verifier);

    for (const lld_memory_array_sptr rxpdr_em : rxpdr_banks) {
        la_block_id_t block_id = rxpdr_em->get_block_id();
        for (size_t idx = 0; idx < rxpdr_em->size(); ++idx) {
            const lld_memory_desc_t* desc = (*rxpdr_em)[idx]->get_desc();

            la_entry_addr_t mem_address = desc->addr + rxpdr_line;
            la_entry_width_t width = desc->width_total_bits;
            bit_vector zero_bv(0, width);

            status = m_ll_device->write_memory_raw(block_id, mem_address, width, zero_bv);
            return_on_error(status);
        }
    }

    //      iii. For the l3_dlp0 verifier in the IDB there is one type of EM with XOR memory:
    //              address to write =  {{2'b10},{11'd2044}};
    const size_t l3_dlp0_line = 2044 | (2 << 11); // writing to bank #3
    std::vector<lld_memory_array_sptr> idb_banks;
    idb_banks.push_back(m_pacific_tree->slice_pair[0]->idb->top->l3_dlp0_table_verifier);
    idb_banks.push_back(m_pacific_tree->slice_pair[1]->idb->top->l3_dlp0_table_verifier);
    idb_banks.push_back(m_pacific_tree->slice_pair[2]->idb->top->l3_dlp0_table_verifier);

    for (lld_memory_array_sptr idb_em : idb_banks) {
        la_block_id_t block_id = idb_em->get_block_id();
        for (size_t idx = 0; idx < idb_em->size(); ++idx) {
            const lld_memory_desc_t* desc = (*idb_em)[idx]->get_desc();

            la_entry_addr_t mem_address = desc->addr + l3_dlp0_line;
            la_entry_width_t width = desc->width_total_bits;
            bit_vector zero_bv(0, width);

            status = m_ll_device->write_memory_raw(block_id, mem_address, width, zero_bv);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_dmc()
{
    la_status status;

    status = init_dmc_frm();
    return_on_error(status);

    status = init_dmc_fte();
    return_on_error(status);

    status = init_dmc_pier();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_dmc_frm()
{
    lld_register_value_list_t reg_val_list;

    // device_config_reg
    frm_device_config_reg_register device_config_reg = {.u8 = {0}};

    switch (m_device_mode) {
    case device_mode_e::STANDALONE:
        device_config_reg.fields.device_type = (uint64_t)frm_device_config_mode_e::SA;
        break;

    case device_mode_e::LINECARD:
        device_config_reg.fields.device_type = (uint64_t)frm_device_config_mode_e::LC;
        break;

    case device_mode_e::FABRIC_ELEMENT:
        if (m_fe_mode == fe_mode_e::FE2) {
            device_config_reg.fields.device_type = (uint64_t)frm_device_config_mode_e::FE2;
            break;
        }

        if (m_fe_mode == fe_mode_e::FE13) {
            device_config_reg.fields.device_type = (uint64_t)frm_device_config_mode_e::FE13;
            break;
        }

        return LA_STATUS_ENOTIMPLEMENTED;

    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (m_device_mode == device_mode_e::LINECARD) {
        if (m_slice_mode[3] == la_slice_mode_e::CARRIER_FABRIC) {
            device_config_reg.fields.slice3_config = 1;
        }

        if (m_slice_mode[4] == la_slice_mode_e::CARRIER_FABRIC) {
            device_config_reg.fields.slice4_config = 1;
        }
    }

    device_config_reg.fields.device_id = get_id();

    bool lc_56_fabric_port_mode;
    la_status status = get_bool_property(la_device_property_e::LC_56_FABRIC_PORT_MODE, lc_56_fabric_port_mode);
    return_on_error(status);

    if (lc_56_fabric_port_mode == true) {
        device_config_reg.fields.ifg6_extra_link_enable = 1;
        device_config_reg.fields.ifg11_extra_link_enable = 1;
    }

    // Indicate slice CLOS direction
    if ((m_device_mode == device_mode_e::FABRIC_ELEMENT) && (m_fe_mode == fe_mode_e::FE13)) {
        bit_vector slice_clos_up_bitmask(0, ASIC_MAX_SLICES_PER_DEVICE_NUM);

        for (la_slice_id_t sid : get_used_slices()) {
            bool is_up_slice = (m_slice_clos_direction[sid] == la_clos_direction_e::UP);
            slice_clos_up_bitmask.set_bit(sid, is_up_slice);
        }

        device_config_reg.fields.fe13_config = slice_clos_up_bitmask.get_value();
    }

    reg_val_list.push_back({(m_pacific_tree->dmc->frm->device_config_reg), device_config_reg});

    // Mask non-fabric ports
    bit_vector fabric_port_mask(0, NUM_FABRIC_PORTS_IN_DEVICE);

    for (la_slice_id_t sid : get_used_slices()) {
        if (m_slice_mode[sid] == la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }

        size_t num_fabric_ports_in_slice = NUM_FABRIC_PORTS_IN_DEVICE / ASIC_MAX_SLICES_PER_DEVICE_NUM;
        size_t first_port = sid * num_fabric_ports_in_slice;
        size_t last_port = (sid + 1) * num_fabric_ports_in_slice - 1;

        la_uint64_t network_slice_ports_bitmask = bit_utils::get_lsb_mask(num_fabric_ports_in_slice);

        fabric_port_mask.set_bits(last_port, first_port, network_slice_ports_bitmask);
    }

    if (lc_56_fabric_port_mode == true) {
        fabric_port_mask.set_bit(8 /*fabric port num*/, 0 /*indicate fabric port*/);
        fabric_port_mask.set_bit(53 /*fabric port num*/, 0 /*indicate fabric port*/);
    }

    reg_val_list.push_back({(m_pacific_tree->dmc->frm->fabric_link_mask_reg), fabric_port_mask});

    if (m_device_mode != device_mode_e::STANDALONE) {
        // No need to configure these in SA mode

        if (m_device_mode == device_mode_e::LINECARD) {
            // congestion_score_fc
            frm_congestion_score_fc_reg_register congestion_score_fc_reg;

            congestion_score_fc_reg.fields.congestion_score_fc_en = 0;
            congestion_score_fc_reg.fields.congestion_score_fc_thr = 131;

            reg_val_list.push_back({(m_pacific_tree->dmc->frm->congestion_score_fc_reg), congestion_score_fc_reg});

            // plb_uc_context_fc_en_reg
            reg_val_list.push_back({(m_pacific_tree->dmc->frm->plb_uc_context_fc_en_reg), 1});
        }

        // dcf_data_config_reg
        frm_dcf_data_config_reg_register dcf_data_config_reg;

        if (m_device_mode == device_mode_e::LINECARD) {
            dcf_data_config_reg.fields.dcf_data_en = 0;
            dcf_data_config_reg.fields.dcf_data_device_oversub_thr = 0;
        } else {
            // FE
            dcf_data_config_reg.fields.dcf_data_en = 1;
            dcf_data_config_reg.fields.dcf_data_device_oversub_thr = 10;
        }

        reg_val_list.push_back({(m_pacific_tree->dmc->frm->dcf_data_config_reg), dcf_data_config_reg});
    }

    // Write all registers
    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_dmc_fte()
{
    // initialize PTP handler
    auto ptp_handler = std::make_shared<la_ptp_handler_pacific>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(ptp_handler, oid);
    return_on_error(status);

    status = ptp_handler->initialize(oid);
    return_on_error(status);

    m_ptp_handler = ptp_handler;

    // Rest of FTE initialization
    lld_register_value_list_t reg_val_list;

    // device_config_reg
    fte_device_config_reg_register device_config_reg = {.u8 = {0}};
    device_config_reg.fields.device_id = get_id();

    switch (m_device_mode) {
    case device_mode_e::STANDALONE:
        device_config_reg.fields.device_type = (uint64_t)fte_device_config_mode_e::SA;
        break;

    case device_mode_e::LINECARD:
        device_config_reg.fields.device_type = (uint64_t)fte_device_config_mode_e::LC;
        break;

    case device_mode_e::FABRIC_ELEMENT:
        if (m_fe_mode == fe_mode_e::FE2) {
            device_config_reg.fields.device_type = (uint64_t)fte_device_config_mode_e::FE2;
            break;
        }

        if (m_fe_mode == fe_mode_e::FE13) {
            device_config_reg.fields.device_type = (uint64_t)fte_device_config_mode_e::FE13;
            break;
        }

        return LA_STATUS_ENOTIMPLEMENTED;

    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (m_device_mode == device_mode_e::LINECARD) {
        if (m_slice_mode[3] == la_slice_mode_e::CARRIER_FABRIC) {
            device_config_reg.fields.slice3_config = 1;
        }

        if (m_slice_mode[4] == la_slice_mode_e::CARRIER_FABRIC) {
            device_config_reg.fields.slice4_config = 1;
        }
    }
    bool lc_56_fabric_port_mode;
    status = get_bool_property(la_device_property_e::LC_56_FABRIC_PORT_MODE, lc_56_fabric_port_mode);
    return_on_error(status);

    if (lc_56_fabric_port_mode == true) {
        device_config_reg.fields.extra_fabric_link8 = 1;
        device_config_reg.fields.extra_fabric_link53 = 1;
    }

    // Indicate slice CLOS direction
    if ((m_device_mode == device_mode_e::FABRIC_ELEMENT) && (m_fe_mode == fe_mode_e::FE13)) {
        bit_vector slice_clos_up_bitmask(0, ASIC_MAX_SLICES_PER_DEVICE_NUM);

        for (la_slice_id_t sid : get_used_slices()) {
            bool is_up_slice = (m_slice_clos_direction[sid] == la_clos_direction_e::UP);
            slice_clos_up_bitmask.set_bit(sid, is_up_slice);
        }

        device_config_reg.fields.fe13_config = slice_clos_up_bitmask.get_value();
    }

    reg_val_list.push_back({(m_pacific_tree->dmc->fte->device_config_reg), device_config_reg});

    // Fabric time clock values configuration in nanosecond
    float clock_interval = (1.0 / m_device_frequency_float_ghz);
    uint64_t ns_whole = floor(clock_interval);
    float fraction = clock_interval - (float)ns_whole;
    // Get CLOCK_INC_FRAC_VALUE_WIDTH bits after binary point
    uint64_t ns_frac = floor(fraction * pow(2.0, fte_clock_inc_reg_register::fields::CLOCK_INC_FRAC_VALUE_WIDTH));
    uint64_t compensate;
    switch (m_device_frequency_int_khz) {
    case 1000000:
        compensate = 0;
        break;
    case 1200000:
        compensate = 3;
        break;
    case 1050000:
        compensate = 1;
        break;
    case 1100000:
        compensate = 11;
        break;
    default:
        compensate = 0;
    }

    fte_clock_inc_reg_register clock_inc_reg;
    clock_inc_reg.fields.clock_inc_ns_value = ns_whole;
    clock_inc_reg.fields.clock_inc_frac_value = ns_frac;
    clock_inc_reg.fields.clock_frac_comp_period = compensate;
    reg_val_list.push_back({m_pacific_tree->dmc->fte->clock_inc_reg, clock_inc_reg});

    fte_device_time_unit_reg_register device_time_unit_reg;
    device_time_unit_reg.fields.device_time_clock_inc_ns_value = ns_whole;
    device_time_unit_reg.fields.device_time_clock_inc_frac_value = ns_frac;
    device_time_unit_reg.fields.device_time_clock_frac_comp_period = compensate;
    reg_val_list.push_back({m_pacific_tree->dmc->fte->device_time_unit_reg, device_time_unit_reg});

    fte_device_time_new_unit_reg_register device_time_new_unit_reg;
    device_time_new_unit_reg.fields.device_time_clock_new_inc_ns_value = ns_whole;
    device_time_new_unit_reg.fields.device_time_clock_new_inc_frac_value = ns_frac;
    device_time_new_unit_reg.fields.device_time_clock_new_frac_comp_period = compensate;
    reg_val_list.push_back({m_pacific_tree->dmc->fte->device_time_new_unit_reg, device_time_new_unit_reg});

    // Time sync message rate
    fte_sync_gen_timer_reg_register sync_gen_timer_reg;
    sync_gen_timer_reg.fields.sync_gen_timer = 4;
    reg_val_list.push_back({m_pacific_tree->dmc->fte->sync_gen_timer_reg, sync_gen_timer_reg});

    fte_device_time_sync_reg_register device_time_sync_reg;
    status = m_ll_device->read_register(*m_pacific_tree->dmc->fte->device_time_sync_reg, device_time_sync_reg);
    return_on_error(status);
    device_time_sync_reg.fields.device_time_load_pad_delay = 3;
    reg_val_list.push_back({m_pacific_tree->dmc->fte->device_time_sync_reg, device_time_sync_reg});

    // 0 all fields
    reg_val_list.push_back({m_pacific_tree->dmc->fte->new_time_load_reg, 0});

    // Time difference thresholds for time sync
    fte_time_diff_threshold_reg_register time_diff_threshold_reg;
    status = m_ll_device->read_register(*m_pacific_tree->dmc->fte->time_diff_threshold_reg, time_diff_threshold_reg);
    return_on_error(status);

    if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        time_diff_threshold_reg.fields.time_diff_far_thr = 0x200;
    } else if (m_device_mode == device_mode_e::LINECARD) {
        time_diff_threshold_reg.fields.time_diff_adj_thr = 0x23;
    }

    reg_val_list.push_back({m_pacific_tree->dmc->fte->time_diff_threshold_reg, time_diff_threshold_reg});

    // enable_reg
    fte_enable_reg_register enable_reg;

    enable_reg.fields.peer_delay_req_gen_en = 0;          // default
    enable_reg.fields.peer_delay_req_gen_link_idx = 0x7f; // default
    enable_reg.fields.sync_packet_gen_en = 1;

    reg_val_list.push_back({(m_pacific_tree->dmc->fte->enable_reg), enable_reg});

    // leaky bucket
    fte_leaky_bucket_reg_register leaky_bucket_reg;
    status = m_ll_device->read_register(*m_pacific_tree->dmc->fte->leaky_bucket_reg, leaky_bucket_reg);
    return_on_error(status);

    leaky_bucket_reg.fields.leaky_in_sync_inc_val = 1;
    reg_val_list.push_back({(m_pacific_tree->dmc->fte->leaky_bucket_reg), leaky_bucket_reg});

    // Write all registers
    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_dmc_pier()
{
    lld_register_value_list_t reg_val_list;

    // fe_device_mode_reg
    pier_fe_device_mode_reg_register fe_device_mode_reg;

    if (m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        fe_device_mode_reg.fields.fe_device_mode = 1;
    } else {
        // LC, SA, ...
        fe_device_mode_reg.fields.fe_device_mode = 0;
    }

    reg_val_list.push_back({(m_pacific_tree->dmc->pier->fe_device_mode_reg), fe_device_mode_reg});

    bool lc_56_fabric_port_mode;
    la_status status = get_bool_property(la_device_property_e::LC_56_FABRIC_PORT_MODE, lc_56_fabric_port_mode);
    return_on_error(status);

    if (lc_56_fabric_port_mode == true) {
        pier_oob_extra_links_reg_register oob_extra_links_reg;

        oob_extra_links_reg.fields.oob_extra_link_ifg6 = 1;
        oob_extra_links_reg.fields.oob_extra_link_ifg11 = 1;

        reg_val_list.push_back({(m_pacific_tree->dmc->pier->oob_extra_links_reg), oob_extra_links_reg});
    }

    pier_oob_inb_ratio_reg_register oob_inb_ratio_reg;

    if (m_device_mode == device_mode_e::STANDALONE) {
        oob_inb_ratio_reg.fields.oob_inb_inj_ratio = 2;
        oob_inb_ratio_reg.fields.oob_inb_ext_ratio = 2;
    } else if (m_device_mode == device_mode_e::LINECARD) {
        oob_inb_ratio_reg.fields.oob_inb_inj_ratio = 0;
        oob_inb_ratio_reg.fields.oob_inb_ext_ratio = 2;
    } else {
        // FE
        oob_inb_ratio_reg.fields.oob_inb_inj_ratio = 0;
        oob_inb_ratio_reg.fields.oob_inb_ext_ratio = 1;
    }

    reg_val_list.push_back({(m_pacific_tree->dmc->pier->oob_inb_ratio_reg), oob_inb_ratio_reg});

    // Map IFG0->packet-DMA and IFG1->NPU-host on all slices
    reg_val_list.push_back({(m_pacific_tree->dmc->pier->inb_ifg_extract_map_reg), 0x444444});

    // Write all registers
    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// Clear the CRC errors in the recycle buffers
la_status
la_device_impl::clear_rcy_path()
{
    for (la_slice_id_t slice : get_used_slices()) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            //    set_ifgb_rx_debug_buffer_capture_source(slice_id, ifg_id, 19)  #SLICE, IFG, PIF
            //    set_ifgb_rx_debug_buffer_capture_enable(slice_id, ifg_id, "CAPTURE_AND_BLOCK")  #SLICE, IFG, PIF
            ifgb_rx_dbg_cfg_register rx_dbg_cfg_reg;
            la_status status
                = m_ll_device->read_register(*m_pacific_tree->slice[slice]->ifg[ifg]->ifgb->rx_dbg_cfg, rx_dbg_cfg_reg);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "%s: read_register rx_dbg_cfg_reg failed, %s", __func__, la_status2str(status).c_str());
                return status;
            }

            rx_dbg_cfg_reg.fields.dbg_buf_capture_en = 2; // CAPTURE_AND_BLOCK
            rx_dbg_cfg_reg.fields.dbg_buf_capture_source = RECYCLE_PIF_ID;

            status = m_ll_device->write_register(*m_pacific_tree->slice[slice]->ifg[ifg]->ifgb->rx_dbg_cfg, rx_dbg_cfg_reg);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "%s: write_register rx_dbg_cfg_reg failed, %s", __func__, la_status2str(status).c_str());
                return status;
            }

            //    #WRITE TO TX BUFFER
            //    txpp_dbg_buf_pkt = write_packet_to_tx_debug_buffer(slice_id, ifg_id, 19, 152, 0)
            //    #SLICE,IFG,PIF,LENGTH,START_ADDR
            size_t length = 152;
            size_t start_addr = 0;
            size_t end_addr = 1;
            ifgb_tx_debug_buff1_register buff1_reg;
            status = m_ll_device->read_register(*m_pacific_tree->slice[slice]->ifg[ifg]->ifgb->tx_debug_buff1, buff1_reg);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "%s: read_register buff1_reg failed, %s", __func__, la_status2str(status).c_str());
                return status;
            }

            buff1_reg.fields.tx_debug_buff_credit_inf_init = 0;
            buff1_reg.fields.tx_debug_buff_end_addr = end_addr;

            status = m_ll_device->write_register(*m_pacific_tree->slice[slice]->ifg[ifg]->ifgb->tx_debug_buff1, buff1_reg);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "%s: write_register buff1_reg failed, %s", __func__, la_status2str(status).c_str());
                return status;
            }

            size_t t_length = length;
            size_t wr_addr = start_addr;
            while (t_length > 0) {
                size_t sop = (t_length == length) ? 1 : 0;
                size_t eop = (t_length <= 128) ? 1 : 0;
                size_t word_size = (t_length <= 128) ? t_length : 128;
                bit_vector mem_entry(0, 1063);

                mem_entry.set_bits(1024 + 0, 1024 + 0, sop);
                mem_entry.set_bits(1024 + 1, 1024 + 1, eop);
                mem_entry.set_bits(1024 + 9, 1024 + 2, word_size);
                mem_entry.set_bits(1024 + 15, 1024 + 11, RECYCLE_PIF_ID);
                status = m_ll_device->write_memory(*m_pacific_tree->slice[slice]->ifg[ifg]->ifgb->tx_debug_mem, wr_addr, mem_entry);
                if (status != LA_STATUS_SUCCESS) {
                    log_err(HLD, "%s: write_memory failed, %s", __func__, la_status2str(status).c_str());
                    return status;
                }

                wr_addr++;
                t_length = t_length - word_size;
            }

            //    set_ifgb_tx_debug_buffer_num_of_iterations(slice_id, ifg_id, 680)   #SLICE,IFG,NUM_OF_ITERATIONS
            ifgb_tx_debug_buff0_register buff0_reg;
            status = m_ll_device->read_register(*m_pacific_tree->slice[slice]->ifg[ifg]->ifgb->tx_debug_buff0, buff0_reg);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "%s: read_register buff0_reg failed, %s", __func__, la_status2str(status).c_str());
                return status;
            }

            buff0_reg.fields.tx_debug_buff_iter = 680;

            status = m_ll_device->write_register(*m_pacific_tree->slice[slice]->ifg[ifg]->ifgb->tx_debug_buff0, buff0_reg);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "%s: write_register buff0_reg failed, %s", __func__, la_status2str(status).c_str());
                return status;
            }

            //    set_ifgb_tx_debug_buffer_enable(slice_id,ifg_id,1)                   #SLICE,IFG,ENABLE

            buff0_reg.fields.tx_debug_buff_en = 1;

            status = m_ll_device->write_register(*m_pacific_tree->slice[slice]->ifg[ifg]->ifgb->tx_debug_buff0, buff0_reg);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "%s: write_register buff0_reg failed, %s", __func__, la_status2str(status).c_str());
                return status;
            }

            //    set_ifgb_tx_debug_buffer_start(slice_id,ifg_id)                      #SLICE,IFG
            buff0_reg.fields.tx_debug_buff_start = 1;

            status = m_ll_device->write_register(*m_pacific_tree->slice[slice]->ifg[ifg]->ifgb->tx_debug_buff0, buff0_reg);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "%s: write_register buff0_reg failed, %s", __func__, la_status2str(status).c_str());
                return status;
            }

            buff0_reg.fields.tx_debug_buff_start = 0;

            status = m_ll_device->write_register(*m_pacific_tree->slice[slice]->ifg[ifg]->ifgb->tx_debug_buff0, buff0_reg);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "%s: write_register buff0_reg failed, %s", __func__, la_status2str(status).c_str());
                return status;
            }
            //    #rxpp_dbg_buf_pkt = read_packet_from_rx_debug_buffer(slice_id,ifg_id,128)
            //    time.sleep(1)
        }
    }

    usleep(1000); // milisecond
    for (la_slice_id_t slice : get_used_slices()) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            //    set_ifgb_rx_debug_buffer_capture_enable(slice_id, ifg_id, "DISABLE")  #SLICE, IFG, PIF
            ifgb_rx_dbg_cfg_register rx_dbg_cfg_reg;
            la_status status
                = m_ll_device->read_register(*m_pacific_tree->slice[slice]->ifg[ifg]->ifgb->rx_dbg_cfg, rx_dbg_cfg_reg);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "%s: read_register rx_dbg_cfg_reg failed, %s", __func__, la_status2str(status).c_str());
                return status;
            }

            rx_dbg_cfg_reg.fields.dbg_buf_capture_en = 0; // DISABLE

            status = m_ll_device->write_register(*m_pacific_tree->slice[slice]->ifg[ifg]->ifgb->rx_dbg_cfg, rx_dbg_cfg_reg);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "%s: write_register rx_dbg_cfg_reg failed, %s", __func__, la_status2str(status).c_str());
                return status;
            }
            //    set_ifgb_tx_debug_buffer_enable(slice_id,ifg_id,0)                   #SLICE,IFG,ENABLE

            ifgb_tx_debug_buff0_register buff0_reg;
            status = m_ll_device->read_register(*m_pacific_tree->slice[slice]->ifg[ifg]->ifgb->tx_debug_buff0, buff0_reg);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "%s: read_register buff0_reg failed, %s", __func__, la_status2str(status).c_str());
                return status;
            }

            buff0_reg.fields.tx_debug_buff_en = 0;

            status = m_ll_device->write_register(*m_pacific_tree->slice[slice]->ifg[ifg]->ifgb->tx_debug_buff0, buff0_reg);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "%s: write_register buff0_reg failed, %s", __func__, la_status2str(status).c_str());
                return status;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_sms_main()
{
    lld_register_value_list_t reg_val_list;

    sms_main_sms_cgm_thr_reg_register sms_cgm_thr_reg_register;
    sms_cgm_thr_reg_register.fields.sms_cgm_thr = 1000;
    sms_cgm_thr_reg_register.fields.sms_hbm_cgm_thr = 0;

    // sms_is_fabric_slice_reg
    bit_vector fabric_slices(0, ASIC_MAX_SLICES_PER_DEVICE_NUM);

    for (la_slice_id_t sid : get_used_slices()) {
        if (m_slice_mode[sid] == la_slice_mode_e::CARRIER_FABRIC) {
            fabric_slices.set_bit(sid, true);
        }
    }

    reg_val_list.push_back({(m_pacific_tree->sms_main->sms_is_fabric_slice_reg), fabric_slices});
    reg_val_list.push_back({(m_pacific_tree->sms_main->sms_cgm_thr_reg), sms_cgm_thr_reg_register});

    /////////////////////////////////////////////////////////////////////////////////////////////////////
    //  SMS cache workaround provided by design team. Disables the SMS cache.
    //
    for (size_t i = 0; i < array_size(m_pacific_tree->sms_quad); i++) {
        for (size_t j = 0; j < m_pacific_tree->sms_quad[i]->cif2_sms_cache_cfg_size_reg->size(); j++) {
            reg_val_list.push_back({(*m_pacific_tree->sms_quad[i]->cif2_sms_cache_cfg_size_reg)[j], 0});
        }
    }

    reg_val_list.push_back({(m_pacific_tree->sms_main->sms_fbm_mma_almost_full_reg), 16});
    /////////////////////////////////////////////////////////////////////////////////////////////////////

    // Hotfix by design team - sms fifo for dram slice: This fix avoids MMU write path stuck
    reg_val_list.push_back({(*m_pacific_tree->sms_quad[1]->cif2_sms_fdoq_cfg_alm_full_reg)[2], 128});
    reg_val_list.push_back({(*m_pacific_tree->sms_quad[1]->cif2_sms_fdoq_cfg_alm_full_reg)[3], 128});

    // Write all registers
    la_status status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

static void
add_cif_node_masks(const interrupt_tree::node_scptr& node, lld_register_value_list_t& reg_val_list)
{
    if (node->mask) {
        bit_vector bv(0, node->mask->get_desc()->width_in_bits);
        for (const auto& bit : node->bits) {
            if (bit->is_masked) {
                bv.set_bit(bit->bit_i, true);
            }
        }

        // CSS node's mask is active high
        // CIF node's mask is active low
        if (!node->is_mask_active_low) {
            bv = ~bv;
        }
        reg_val_list.push_back({node->mask, bv});
    } else if (node->status->get_desc()->addr == lld_register::MEM_PROTECT_INTERRUPT) {
        // mem_protect interrupt masks of a CIF block are always active low
        for (lld_register_scptr mask : node->mem_protect.masks) {
            if (mask) {
                reg_val_list.push_back({mask, 0});
            }
        }
    }
}

void
la_device_impl::set_default_cif_masks(lld_register_value_list_t& reg_val_list)
{
    la_block_id_t sbif_block_id = m_pacific_tree->sbif->get_block_id();

    // Enable all CIF interrupt masks.
    // Skip SBIF, it is initialized separately.
    auto node_cb = ([&](const interrupt_tree::node_scptr& node, size_t unused) {
        if (node->status->get_block_id() != sbif_block_id) {
            add_cif_node_masks(node, reg_val_list);
        }
        return UINT64_MAX; // continue traversing down the tree to all sub nodes
    });

    auto bit_cb = ([](const interrupt_tree::bit_scptr&, size_t) {});

    // Traverse the interrupt tree, populate 'reg_val_list'
    m_notification->get_interrupt_tree()->traverse(node_cb, bit_cb);
}

void
la_device_impl::override_masks_ts_ms(lld_register_value_list_t& reg_val_list)
{
    if (m_device_mode != device_mode_e::LINECARD) {
        // mask only in LC mode
        return;
    }

    tsms_general_interrupt_register_mask_register tsms_general_mask = {{0}};
    tsms_general_mask.fields.uch_ms_time_error_mask = 1;

    // mask ts_ms.general_interrupt_register on slices 3,4,5 only
    for (la_slice_id_t sid : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_FABRIC)) {
        reg_val_list.push_back({m_pacific_tree->slice[sid]->ts_ms->general_interrupt_register_mask, tsms_general_mask});
    }
}

void
la_device_impl::override_masks_hbm(lld_register_value_list_t& reg_val_list)
{
    bool does_hbm_exist = false;
    la_status rc = hbm_exists(does_hbm_exist);

    if (!rc && does_hbm_exist && m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        // HBM exists and used, do not override HBM interrupt masks
        return;
    }

    // HBM does not exist, mask off the 'cattrip' bit, which is known to be constantly pending.
    hbm_general_interrupt_register_mask_register hbm_mask = {{0}};
    hbm_mask.fields.cattrip_interrupt_mask = 1; // Catastrophic temperature indication from HBM die

    reg_val_list.push_back({m_pacific_tree->hbm->hi->general_interrupt_register_mask, hbm_mask});
    reg_val_list.push_back({m_pacific_tree->hbm->lo->general_interrupt_register_mask, hbm_mask});
}

void
la_device_impl::override_masks_mem_protect(lld_register_value_list_t& reg_val_list)
{
    // Disable 'Parity' mem_protect interrupt for all TCAMs.
    cdb_cache_parity_err_interrupt_register_mask_register cdb_cache_mask = {{0}};
    cdb_cache_mask.fields.splitter_cache_tcam_parity_err_interrupt_mask = 1;
    cdb_cache_mask.fields.lpm_cache_tcam_parity_err_interrupt_mask = 1;

    rxpp_term_parity_err_interrupt_register_mask_register rxpp_term_mask = {{0}};
    rxpp_term_mask.fields.mymac_tcam_parity_err_interrupt_mask = 1;
    rxpp_term_mask.fields.sm_tcam_parity_err_interrupt_mask = 1;

    fi_parity_err_interrupt_register_mask_register fi_mask = {{0}};
    fi_mask.fields.fi_core_tcam_parity_err_interrupt_mask = 1;

    npe_parity_err_interrupt_register_mask_register npe_mask = {{0}};
    npe_mask.fields.lookup_keys_selection_tcam_parity_err_interrupt_mask = 1;
    npe_mask.fields.resolution_keys_selection_tcam_parity_err_interrupt_mask = 1;
    npe_mask.fields.lookup_core_tcam_parity_err_interrupt_mask = 1;
    npe_mask.fields.traps_tcam_parity_err_interrupt_mask = 1;

    reg_val_list.push_back({m_pacific_tree->npuh->fi->parity_err_interrupt_register_mask, fi_mask});

    for (size_t slice_id : get_used_slices()) {
        const auto& slice = m_pacific_tree->slice[slice_id];
        reg_val_list.push_back({slice->npu->cdb_cache->parity_err_interrupt_register_mask, cdb_cache_mask});
        reg_val_list.push_back({slice->npu->rxpp_term->rxpp_term->parity_err_interrupt_register_mask, rxpp_term_mask});

        for (const auto& fi_eng : slice->npu->rxpp_term->fi_eng) {
            reg_val_list.push_back({fi_eng->parity_err_interrupt_register_mask, fi_mask});
        }
        for (const auto& npe : slice->npu->rxpp_fwd->npe) {
            reg_val_list.push_back({npe->parity_err_interrupt_register_mask, npe_mask});
        }
        for (const auto& npe : slice->npu->rxpp_term->npe) {
            reg_val_list.push_back({npe->parity_err_interrupt_register_mask, npe_mask});
        }
        for (const auto& npe : slice->npu->txpp->npe) {
            reg_val_list.push_back({npe->parity_err_interrupt_register_mask, npe_mask});
        }
    }

    cdb_top_parity_err_interrupt_register_mask_register cdb_top_mask = {{0}};
    cdb_top_mask.fields.clpm_group_map_tcam0_parity_err_interrupt_mask = 1;
    cdb_top_mask.fields.clpm_group_map_tcam1_parity_err_interrupt_mask = 1;
    cdb_top_mask.fields.clpm_group_map_tcam2_parity_err_interrupt_mask = 1;
    cdb_top_mask.fields.clpm_group_map_tcam3_parity_err_interrupt_mask = 1;
    cdb_top_mask.fields.clpm_group_map_tcam4_parity_err_interrupt_mask = 1;
    cdb_top_mask.fields.clpm_group_map_tcam5_parity_err_interrupt_mask = 1;
    cdb_top_mask.fields.clpm_group_map_tcam6_parity_err_interrupt_mask = 1;
    cdb_top_mask.fields.clpm_group_map_tcam7_parity_err_interrupt_mask = 1;
    cdb_top_mask.fields.clpm_group_map_tcam8_parity_err_interrupt_mask = 1;
    cdb_top_mask.fields.clpm_group_map_tcam9_parity_err_interrupt_mask = 1;
    cdb_top_mask.fields.clpm_group_map_tcam10_parity_err_interrupt_mask = 1;
    cdb_top_mask.fields.clpm_group_map_tcam11_parity_err_interrupt_mask = 1;
    reg_val_list.push_back({m_pacific_tree->cdb->top->parity_err_interrupt_register_mask, cdb_top_mask});

    // All bits in core->parity_err_interrupt_register_mask correspond to TCAM memories
    for (const auto& core : m_pacific_tree->cdb->core) {
        push_back_ones(reg_val_list, core->parity_err_interrupt_register_mask);
    }
    for (const auto& core : m_pacific_tree->cdb->core_reduced) {
        push_back_ones(reg_val_list, core->parity_err_interrupt_register_mask);
    }

    npe_parity_err_interrupt_register_mask_register npuh_npe_mask = {{0}};
    npuh_npe_mask.fields.lookup_keys_selection_tcam_parity_err_interrupt_mask = 1;
    npuh_npe_mask.fields.resolution_keys_selection_tcam_parity_err_interrupt_mask = 1;
    npuh_npe_mask.fields.lookup_core_tcam_parity_err_interrupt_mask = 1;
    npuh_npe_mask.fields.traps_tcam_parity_err_interrupt_mask = 1;
    reg_val_list.push_back({m_pacific_tree->npuh->npe->parity_err_interrupt_register_mask, npuh_npe_mask});

    filb_slice_ecc_1b_err_interrupt_register_mask_register filb_mask = {{0}};
    filb_mask.fields.slb_fc_timer_ecc_1b_err_interrupt_mask = 1;
    for (la_slice_id_t i : get_used_slices()) {
        if (i < FIRST_HW_FABRIC_SLICE) {
            reg_val_list.push_back({m_pacific_tree->slice[i]->filb->ecc_1b_err_interrupt_register_mask, filb_mask});
            reg_val_list.push_back({m_pacific_tree->slice[i]->filb->ecc_2b_err_interrupt_register_mask, filb_mask});
        } else {
            // slb_fc_timer memory does not exist in fabric_flb - nothing to mask
        }
    }

    // disable ECC1b/2b for slice[]->ifg[]->ifgb->tx_desc_mem[] and slice[]->ifg[]->ifgb->rcy_data_mem[]
    // due to a known HW issue in init FSMs connectivity.
    ifgb_ecc_1b_err_interrupt_register_mask_register ifgb_ecc_mask = {{0}};
    ifgb_ecc_mask.fields.tx_desc_mem00_ecc_1b_err_interrupt_mask = 1;
    ifgb_ecc_mask.fields.tx_desc_mem01_ecc_1b_err_interrupt_mask = 1;
    ifgb_ecc_mask.fields.tx_desc_mem1_ecc_1b_err_interrupt_mask = 1;
    ifgb_ecc_mask.fields.rcy_data_mem0_ecc_1b_err_interrupt_mask = 1;
    ifgb_ecc_mask.fields.rcy_data_mem1_ecc_1b_err_interrupt_mask = 1;
    ifgb_ecc_mask.fields.rcy_data_mem2_ecc_1b_err_interrupt_mask = 1;
    ifgb_ecc_mask.fields.rcy_data_mem3_ecc_1b_err_interrupt_mask = 1;
    ifgb_ecc_mask.fields.rcy_data_mem4_ecc_1b_err_interrupt_mask = 1;
    ifgb_ecc_mask.fields.rcy_data_mem5_ecc_1b_err_interrupt_mask = 1;

    for (size_t sid : get_used_slices()) {
        const auto& slice = m_pacific_tree->slice[sid];
        for (const auto& ifg : slice->ifg) {
            reg_val_list.push_back({ifg->ifgb->ecc_1b_err_interrupt_register_mask, ifgb_ecc_mask});
            reg_val_list.push_back({ifg->ifgb->ecc_2b_err_interrupt_register_mask, ifgb_ecc_mask});
        }
    }
}

void
la_device_impl::override_masks_npuh(lld_register_value_list_t& reg_val_list)
{
    npu_host_em_response_interrupt_mask_register mask{{0}};
    // This interrupt is asserted when the EM is accessed through the CPU/ARC to perform actions (read/write/delete, etc.).
    // This will happen for sw-based PFC updating the queue congestion table.
    // JWB: FIXME mask.fields.eth_mp_em_resp_mask = 1;
    mask.fields.eth_mp_em_resp_mask = 0;
    reg_val_list.push_back({m_pacific_tree->npuh->host->em_response_interrupt_mask, mask});
}

void
la_device_impl::clear_sbif_interrupts(lld_register_value_list_t& reg_val_list)
{
    // blocks reg0
    push_back_ones(reg_val_list, m_pacific_tree->sbif->arc0_blocks_interrupt_summary_reg0);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->arc1_blocks_interrupt_summary_reg0);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->arc2_blocks_interrupt_summary_reg0);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->arc3_blocks_interrupt_summary_reg0);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->msi_blocks_interrupt_summary_reg0);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->pin_blocks_interrupt_summary_reg0);

    // blocks reg1
    push_back_ones(reg_val_list, m_pacific_tree->sbif->arc0_blocks_interrupt_summary_reg1);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->arc1_blocks_interrupt_summary_reg1);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->arc2_blocks_interrupt_summary_reg1);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->arc3_blocks_interrupt_summary_reg1);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->msi_blocks_interrupt_summary_reg1);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->pin_blocks_interrupt_summary_reg1);

    // master
    push_back_ones(reg_val_list, m_pacific_tree->sbif->arc3_master_interrupt_reg);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->arc2_master_interrupt_reg);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->arc1_master_interrupt_reg);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->arc0_master_interrupt_reg);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->msi_master_interrupt_reg);
    push_back_ones(reg_val_list, m_pacific_tree->sbif->pin_master_interrupt_reg);
}

la_status
la_device_impl::init_interrupts()
{
    lld_register_value_list_t reg_val_list;

    // Set masks for all CIF interruts, including mem_protect (SER) masks
    set_default_cif_masks(reg_val_list);

    // Additional masks, not loaded from JSON.
    override_masks_ts_ms(reg_val_list);
    override_masks_hbm(reg_val_list);
    override_masks_mem_protect(reg_val_list);
    override_masks_npuh(reg_val_list);

    // Combine multiple writes to same register using OR logic
    lld_unordered_merge_register_value_list(reg_val_list);

    // Since some CIF interrupts are masked, we need to clear SBIF too, so that
    // summary bits that correspond to pending but masked CIF interrupts will be cleared.
    clear_sbif_interrupts(reg_val_list);

    la_status rc = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(rc);

    // Final touch - unmask CIF interrupts at MSI root level.
    // If PROCESS_INTERRUPTS is 'true', we expect to start receiving MSI interrupts after this line.
    rc = configure_device_bool_property(la_device_property_e::PROCESS_INTERRUPTS);

    return rc;
}

void
la_device_impl::initialize_device_properties()
{
    initialize_device_bool_properties();
    initialize_device_int_properties();
    initialize_device_string_properties();
}

void
la_device_impl::initialize_device_bool_properties()
{
    la_device_property_e unsupported_device_properties[] = {
        la_device_property_e::ENABLE_INFO_PHY,
    };
    for (int i = 0; i < (int)(sizeof(unsupported_device_properties) / sizeof(la_device_property_e)); i++) {
        atomic_init(&m_device_properties[(int)unsupported_device_properties[i]].supported, false);
    }

    atomic_init(&m_device_properties[(int)la_device_property_e::LC_56_FABRIC_PORT_MODE].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::LC_FORCE_FORWARD_THROUGH_FABRIC_MODE].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::LC_ADVERTISE_DEVICE_ON_FABRIC_MODE].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::LC_TYPE_2_4_T].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_NSIM_ACCURATE_SCALE_MODEL].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_HBM].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION_CACHING_MODE].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::DISABLE_ELECTRICAL_IDLE_DETECTION].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::TEST_MODE_PACIFIC_A0_ALLOW_RCY_ON_ALL_SLICES].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::PROCESS_INTERRUPTS].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::POLL_MSI].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::RTL_SIMULATION_WORKAROUNDS].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::EMULATED_DEVICE].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::GB_INITIALIZE_CONFIG_MEMORIES].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::GB_INITIALIZE_OTHER].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::GB_A1_DISABLE_FIXES].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::GB_A2_DISABLE_FIXES].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::USING_LEABA_NIC].bool_val, true);

    // Forwarding caches are enabled only on Pacific B0 and B1 due to multiple cache correctness issues on Pacific A0.
    bool en_lpm_ip_cache = ((m_revision == la_device_revision_e::PACIFIC_B0) || (m_revision == la_device_revision_e::PACIFIC_B1));
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_LPM_IP_CACHE].bool_val, en_lpm_ip_cache);

    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_MBIST_REPAIR].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::IGNORE_MBIST_ERRORS].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_NARROW_COUNTERS].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_MPLS_SR_ACCOUNTING].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_CLASS_ID_ACLS].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_PACIFIC_B0_IFG_CHANGES].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_PACIFIC_OOB_INTERLEAVING].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::INSTANTIATE_REMOTE_SYSTEM_PORTS].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::HBM_MOVE_TO_READ_ON_EMPTY].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::HBM_MOVE_TO_WRITE_ON_EMPTY].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SERDES_NRZ_FAST_TUNE].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_NETWORK_SERDES_PAM4_FAST_TUNE].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_FABRIC_SERDES_PAM4_FAST_TUNE].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_FABRIC_FEC_RS_KP4].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::DISABLE_SERDES_POST_ANLT_TUNE].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SERDES_PRE_ICAL_PRIOR_ANLT].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::SERDES_DFE_EID].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SERDES_TX_SLIP].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SERDES_TX_REFRESH].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_IGNORE_LONG_TUNE].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_ENABLE_25G_DFETAP_CHECK].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_ENABLE_SER_CHECK].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_MAC_PORT_DEGRADED_SER_NOTIFICATIONS].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SERDES_LOW_POWER].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::RECONNECT_IGNORE_IN_FLIGHT].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::IGNORE_SBUS_MASTER_MBIST_FAILURE].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SENSOR_POLL].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::SLEEP_IN_SET_MAX_BURST].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_ECN_QUEUING].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SERDES_LDO_VOLTAGE_REGULATOR].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SRM_OVERRIDE_PLL_KP_KF].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::IGNORE_COMPONENT_INIT_FAILURES].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::PACIFIC_PFC_HBM_ENABLED].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_POWER_SAVING_MODE].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::FORCE_DISABLE_HBM].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::HBM_SKIP_TRAINING].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_DUMMY_SERDES_HANDLER].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::DESTINATION_SYSTEM_PORT_IN_IBM_METADATA].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_BOOT_OPTIMIZATION].bool_val, false);
}

void
la_device_impl::initialize_device_int_properties()
{
    la_device_property_e unsupported_device_properties[] = {
        la_device_property_e::OOB_INJ_CREDITS,
        la_device_property_e::MATILDA_MODEL_TYPE,
        la_device_property_e::ENABLE_SERDES_LDO_VOLTAGE_REGULATOR,
        la_device_property_e::SERDES_RXA_POWER_SEQUENCE_MODE,
        la_device_property_e::SERDES_CL136_PRESET_TYPE,
        la_device_property_e::NUM_MULTIPORT_PHY,
    };
    for (int i = 0; i < (int)(sizeof(unsupported_device_properties) / sizeof(la_device_property_e)); i++) {
        atomic_init(&m_device_properties[(int)unsupported_device_properties[i]].supported, false);
    }

    atomic_init(&m_device_properties[(int)la_device_property_e::HBM_FREQUENCY].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::STATISTICAL_METER_MULTIPLIER].int_val, 1);
    atomic_init(&m_device_properties[(int)la_device_property_e::POLL_INTERVAL_MILLISECONDS].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::POLL_FAST_INTERVAL_MILLISECONDS].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::RESTORE_INTERRUPT_MASKS_INTERVAL_MILLISECONDS].int_val, 1000);
    atomic_init(&m_device_properties[(int)la_device_property_e::POLL_NON_WIRED_INTERRUPTS_INTERVAL_MILLISECONDS].int_val, 1000);
    atomic_init(&m_device_properties[(int)la_device_property_e::MSI_DAMPENING_INTERVAL_MILLISECONDS].int_val, 100);
    atomic_init(&m_device_properties[(int)la_device_property_e::MSI_DAMPENING_THRESHOLD].int_val, 10);
    atomic_init(&m_device_properties[(int)la_device_property_e::SENSOR_POLL_INTERVAL_MILLISECONDS].int_val, 100);
    atomic_init(&m_device_properties[(int)la_device_property_e::TEMPERATURE_SENSOR_POLL_FAILURE_TIMEOUT_MILLISECONDS].int_val,
                3000);
    atomic_init(&m_device_properties[(int)la_device_property_e::MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY].int_val,
                (int)DEFAULT_MIN_LINKS_THRESHOLD);
    atomic_init(&m_device_properties[(int)la_device_property_e::SERDES_FW_REVISION].int_val, (int)SERDES_REV);
    atomic_init(&m_device_properties[(int)la_device_property_e::SERDES_FW_BUILD].int_val, (int)SERDES_BUILD);
    atomic_init(&m_device_properties[(int)la_device_property_e::SBUS_MASTER_FW_REVISION].int_val, (int)SBUS_MASTER_REV);
    atomic_init(&m_device_properties[(int)la_device_property_e::SBUS_MASTER_FW_BUILD].int_val, (int)SBUS_MASTER_BUILD);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_TUNE_TIMEOUT].int_val, 45);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_PAM4_MAX_TUNE_RETRY].int_val, 3);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_PAM4_MIN_EYE_HEIGHT].int_val, 16);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_NRZ_MIN_EYE_HEIGHT].int_val, 5);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_10G_NRZ_MIN_EYE_HEIGHT].int_val, 5);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_CDR_LOCK_AFTER_TUNE_TIMEOUT].int_val, 10);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_PCS_LOCK_TIME].int_val, 1000);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_SAVE_STATE_SERDES_DEBUG_SNAPSHOTS].int_val, 1);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_SAVE_STATE_SM_STATE_TRANSITION_CAPTURES].int_val, 30);
    atomic_init(&m_device_properties[(int)la_device_property_e::NETWORK_MAC_PORT_TUNE_AND_PCS_LOCK_ITER].int_val, 1);
    atomic_init(&m_device_properties[(int)la_device_property_e::FABRIC_MAC_PORT_TUNE_AND_PCS_LOCK_ITER].int_val, 1);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_AUTO_NEGOTIATION_TIMEOUT].int_val, 500);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_LINK_TRAINING_TIMEOUT].int_val, 6);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_NRZ_LINK_TRAINING_TIMEOUT].int_val, 6000);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_PAM4_LINK_TRAINING_TIMEOUT].int_val, 6000);
    atomic_init(&m_device_properties[(int)la_device_property_e::SERDES_RXA_POWER_SEQUENCE_MODE].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::SERDES_CL136_PRESET_TYPE].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::LPM_REBALANCE_INTERVAL].int_val, 1000);
    atomic_init(&m_device_properties[(int)la_device_property_e::LPM_REBALANCE_START_FAIRNESS_THRESHOLD_PERCENT].int_val, 80);
    atomic_init(&m_device_properties[(int)la_device_property_e::LPM_REBALANCE_END_FAIRNESS_THRESHOLD_PERCENT].int_val, 90);
    atomic_init(&m_device_properties[(int)la_device_property_e::LPM_TCAM_SINGLE_WIDTH_KEY_WEIGHT].int_val, 1);
    atomic_init(&m_device_properties[(int)la_device_property_e::LPM_TCAM_DOUBLE_WIDTH_KEY_WEIGHT].int_val, 2);
    atomic_init(&m_device_properties[(int)la_device_property_e::LPM_TCAM_QUAD_WIDTH_KEY_WEIGHT].int_val, 4);
    atomic_init(&m_device_properties[(int)la_device_property_e::LPM_L2_MAX_SRAM_BUCKETS].int_val, 4096);
    atomic_init(&m_device_properties[(int)la_device_property_e::LPM_TCAM_NUM_BANKSETS].int_val, 1);
    atomic_init(&m_device_properties[(int)la_device_property_e::LPM_TCAM_BANK_SIZE].int_val, 512);
    atomic_init(&m_device_properties[(int)la_device_property_e::HBM_READ_CYCLES].int_val, 512);
    atomic_init(&m_device_properties[(int)la_device_property_e::HBM_WRITE_CYCLES].int_val, 512);
    atomic_init(&m_device_properties[(int)la_device_property_e::HBM_MIN_MOVE_TO_READ].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::HBM_LPM_FAVOR_MODE].int_val, 2); // FAVOR_LPM_MIN_WRITE
    atomic_init(&m_device_properties[(int)la_device_property_e::HBM_PHY_T_RDLAT_OFFSET].int_val, 7);
    atomic_init(&m_device_properties[(int)la_device_property_e::LPTS_MAX_ENTRY_COUNTERS].int_val,
                (int)DEFAULT_LPTS_MAX_ENTRY_COUNTERS);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAX_NUM_PCL_GIDS].int_val, (int)DEFAULT_NUM_PCL_GIDS);
    atomic_init(&m_device_properties[(int)la_device_property_e::DEVICE_FREQUENCY].int_val, (int)DEFAULT_DEVICE_FREQUENCY);
    atomic_init(&m_device_properties[(int)la_device_property_e::TCK_FREQUENCY].int_val, (int)DEFAULT_TCK_FREQUENCY);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAX_COUNTER_THRESHOLD].int_val, (int)DEFAULT_MAX_COUNTER_THRESHOLD);
    atomic_init(&m_device_properties[(int)la_device_property_e::AAPL_IFG_DELAY_BEFORE_EXEC].int_val, 6000);
    atomic_init(&m_device_properties[(int)la_device_property_e::AAPL_HBM_DELAY_BEFORE_EXEC].int_val, 500);
    atomic_init(&m_device_properties[(int)la_device_property_e::AAPL_IFG_DELAY_BEFORE_POLL].int_val, 10);
    atomic_init(&m_device_properties[(int)la_device_property_e::AAPL_HBM_DELAY_BEFORE_POLL].int_val, 10);
    atomic_init(&m_device_properties[(int)la_device_property_e::AAPL_IFG_DELAY_IN_POLL].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::AAPL_IFG_POLL_TIMEOUT].int_val, 100);
    atomic_init(&m_device_properties[(int)la_device_property_e::RESET_INTERRUPT_COUNTERS_INTERVAL_SECONDS].int_val,
                (int)DEFAULT_RESET_INTERRUPT_COUNTERS_INTERVAL_SECONDS);
    atomic_init(&m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_CONFIG_ECC_1B].int_val,
                (int)interrupt_default_threshold_e::MEM_CONFIG_ECC_1B);
    atomic_init(&m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_CONFIG_ECC_2B].int_val,
                (int)interrupt_default_threshold_e::MEM_CONFIG_ECC_2B);
    atomic_init(&m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_CONFIG_PARITY].int_val,
                (int)interrupt_default_threshold_e::MEM_CONFIG_PARITY);
    atomic_init(&m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_VOLATILE_ECC_1B].int_val,
                (int)interrupt_default_threshold_e::MEM_VOLATILE_ECC_1B);
    atomic_init(&m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_VOLATILE_ECC_2B].int_val,
                (int)interrupt_default_threshold_e::MEM_VOLATILE_ECC_2B);
    atomic_init(&m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_MEM_VOLATILE_PARITY].int_val,
                (int)interrupt_default_threshold_e::MEM_VOLATILE_PARITY);
    atomic_init(&m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_LPM_SRAM_ECC_1B].int_val,
                (int)interrupt_default_threshold_e::LPM_SRAM_ECC_1B);
    atomic_init(&m_device_properties[(int)la_device_property_e::INTERRUPT_THRESHOLD_LPM_SRAM_ECC_2B].int_val,
                (int)interrupt_default_threshold_e::LPM_SRAM_ECC_2B);
    atomic_init(&m_device_properties[(int)la_device_property_e::LINKUP_TIME_BEFORE_SERDES_REFRESH].int_val, 120);
    atomic_init(&m_device_properties[(int)la_device_property_e::MATILDA_MODEL_TYPE].int_val,
                (int)matilda_model_e::GIBRALTAR_REGULAR);
    atomic_init(&m_device_properties[(int)la_device_property_e::EFUSE_REFCLK_SETTINGS].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::DEV_REFCLK_SEL].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAX_NUMBER_OF_PERIODIC_SAVE_STATE_FILES].int_val, 10);
    atomic_init(&m_device_properties[(int)la_device_property_e::PACIFIC_PFC_PILOT_PROBABILITY].int_val, 25);
    atomic_init(&m_device_properties[(int)la_device_property_e::PACIFIC_PFC_MEASUREMENT_PROBABILITY].int_val, 8);
    atomic_init(&m_device_properties[(int)la_device_property_e::MULTICAST_MCID_SCALE_THRESHOLD].int_val,
                (int)la_device_impl::MAX_MC_LOCAL_MCID);
    atomic_init(&m_device_properties[(int)la_device_property_e::CREDIT_SIZE_IN_BYTES].int_val, INVALID_CREDIT_SIZE);
    atomic_init(&m_device_properties[(int)la_device_property_e::METER_BUCKET_REFILL_POLLING_DELAY].int_val, 20000);
}

void
la_device_impl::initialize_device_string_properties()
{
    m_device_properties[(int)la_device_property_e::SERDES_FW_FILE_NAME].string_val = SERDES_FILE_NAME;
    m_device_properties[(int)la_device_property_e::SBUS_MASTER_FW_FILE_NAME].string_val = SBUS_MASTER_FILE_NAME;
}

la_status
la_device_impl::init_load_balancing_keys()
{
    lld_register_value_list_t reg_val_list;

    // configure lb vector profile 1 to read the sip + dip again
    rxpp_fwd_res_lb_profile_fs_insturctions_reg_register second_sip_dip;
    la_status status = m_ll_device->read_register( // slice 0 is just an arbitrary slice
        *(*m_pacific_tree->slice[0]
               ->npu->rxpp_fwd->rxpp_fwd->res_lb_profile_fs_insturctions_reg)[npu_static_config::LB_FS_IPV4_DOUBLE_SIP_DIP_PROFILE],
        second_sip_dip);
    return_on_error(status, HLD, ERROR, "%s: read_register second_sip_dip failed, %s", __func__, la_status2str(status).c_str());

    // fs[0-1]_instruction refers to the desired part to be fetched from the packet:
    // [11:6] - offset in Bytes, [5:0] - size in bits
    // fs[0-1]_instruction are applied in 'resolution_compound_utils.npl' -> apply_field_select()
    second_sip_dip.fields.res_lb_key_fs0_instruction
        = 0x320; // SIP:	0x320 = (001100 100000) -> offset = 12 [Bytes], size = 32 [bits]
    second_sip_dip.fields.res_lb_key_fs1_instruction
        = 0x420; // DIP:	0x420 = (010000 100000) -> offset = 16 [Bytes], size = 32 [bits]

    // configure lb vector profile 2 to take ipv6 partial dip
    rxpp_fwd_res_lb_profile_fs_insturctions_reg_register fs_instruction_ipv6_partial_dip;
    status = m_ll_device->read_register( // slice 0 is just an arbitrary slice
        *(*m_pacific_tree->slice[0]
               ->npu->rxpp_fwd->rxpp_fwd
               ->res_lb_profile_fs_insturctions_reg)[npu_static_config::LB_FS_IPV6_EXTRA_PARTIAL_DIP_PROFILE],
        fs_instruction_ipv6_partial_dip);
    return_on_error(status,
                    HLD,
                    ERROR,
                    "%s: read_register fs_instruction_ipv6_partial_dip failed, %s",
                    __func__,
                    la_status2str(status).c_str());

    // fs[0-1]_instruction refers to the desired part to be fetched from the packet:
    // [11:6] - offset in Bytes, [5:0] - size in bits
    // fs[0-1]_instruction are applied in 'resolution_compound_utils.npl' -> apply_field_select()
    fs_instruction_ipv6_partial_dip.fields.res_lb_key_fs0_instruction
        = 0x760; // IPV6_DIP[87:56]:	0x760 = (011101 100000) -> offset = 29 [Bytes], size = 32 [bits]

    // Write the modified registers to all slices
    for (la_slice_id_t slice : get_used_slices()) {
        reg_val_list.push_back({(*m_pacific_tree->slice[slice]
                                      ->npu->rxpp_fwd->rxpp_fwd
                                      ->res_lb_profile_fs_insturctions_reg)[npu_static_config::LB_FS_IPV4_DOUBLE_SIP_DIP_PROFILE],
                                second_sip_dip});
        reg_val_list.push_back(
            {(*m_pacific_tree->slice[slice]
                   ->npu->rxpp_fwd->rxpp_fwd
                   ->res_lb_profile_fs_insturctions_reg)[npu_static_config::LB_FS_IPV6_EXTRA_PARTIAL_DIP_PROFILE],
             fs_instruction_ipv6_partial_dip});
    }

    // Commit the changes
    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// Overwrite P4 static and NPE / NPU tables initialization
// Can be used across devices / device revisions to avoid separate microcode
la_status
la_device_impl::post_topology_p4_overrides()
{
    la_status status = post_topology_p4_overrides_network();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::post_topology_p4_overrides_network()
{
    // Support for B1 devices
    if (m_revision != la_device_revision_e::PACIFIC_B1) {
        return LA_STATUS_SUCCESS;
    }

    const auto& tables(m_tables.is_pacific_b1_static_table);
    npl_is_pacific_b1_static_table_key_t key;
    npl_is_pacific_b1_static_table_value_t value;
    value.action = NPL_IS_PACIFIC_B1_STATIC_TABLE_ACTION_WRITE;
    value.payloads.is_pacific_b1.val = NPL_TRUE_VALUE;
    auto status = per_slice_tables_set(m_slice_mode, tables, {la_slice_mode_e::NETWORK}, key, value);
    return_on_error(status);

    for (LA_UNUSED auto slice_id : get_slices(shared_from_this(), la_slice_mode_e::NETWORK)) {

        la_status status = set_pac_b1_padding(slice_id);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_pac_b1_padding(la_slice_id_t slice_id)
{
    const auto& table(m_tables.pad_mtu_inj_check_static_table[slice_id]);

    size_t entries_num = table->size();
    std::vector<npl_pad_mtu_inj_check_static_table_entry_t*> entries(entries_num, nullptr);
    table->get_entries(&entries[0], entries_num);
    for (auto entry : entries) {
        auto line = entry->line();
        auto key = entry->key();
        auto mask = entry->mask();
        auto value = entry->value();
        if ((key.l3_tx_local_vars_fwd_pkt_size == 0) && (mask.l3_tx_local_vars_fwd_pkt_size == 0x3FC0)) {
            // Erase the entry for padding macro
            la_status status = table->erase(line);
            return_on_error_log(status,
                                HLD,
                                ERROR,
                                "%ld , %lx, %lx, %lx\n",
                                line,
                                key.l3_tx_local_vars_fwd_pkt_size,
                                mask.l3_tx_local_vars_fwd_pkt_size,
                                value.payloads.pad_mtu_inj_next_macro_action.macro_id);
        }
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
