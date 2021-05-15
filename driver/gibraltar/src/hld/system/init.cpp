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
#include <algorithm>
#include <array>
#include <cmath>
#include <list>
#include <unistd.h>
#include <vector>

#include "api_tracer.h"
#include "la_device_impl.h"

#include "../../../shared/src/lld/ll_filtered_device_impl.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/la_profile.h"
#include "common/la_profile_database.h"
#include "common/logger.h"
#include "lld/device_reg_structs.h"
#include "lld/gibraltar_mem_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/interrupt_types.h"
#include "lld/ll_device.h"
#include "lld/lld_utils.h"
#include "system/device_model_types.h"

#include "cpu2jtag/cpu2jtag.h"
#include "gibraltar_pvt_handler.h"
#include "hld_utils.h"
#include "la_hbm_handler_impl.h"
#include "la_strings.h"
#include "npu_static_config.h"
#include "pvt_handler.h"
#include "qos/la_meter_set_impl.h"
#include "srm_serdes_device_handler.h"
#include "system/device_configurator_base.h"
#include "system/device_port_handler_gibraltar.h"
#include "system/dummy_serdes_device_handler_base.h"
#include "system/ifg_handler.h"
#include "system/la_mac_port_base.h"
#include "system/la_ptp_handler_gibraltar.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/tm_utils.h"

#include <chrono>
#include <thread>

namespace silicon_one
{

static const char SERDES_FILE_NAME[] = "res/srm_app_fw_image_0_33_1_1688.txt";
static const char HBM_FILE_NAME[] = "res/hbm.0x055f_2002.rom";
static const char HBM_FILE_ENVVAR[] = "HBM_FIRMWARE";
static const char HBM_MBIST_FILE_NAME[] = "res/hbm.0x055f_2012.rom";
static const char HBM_MBIST_FILE_ENVVAR[] = "HBM_MBIST_FIRMWARE";
static const char SBUS_MASTER_FILE_NAME[] = "res/sbus_master.0x1024_2001.rom";

enum {
    SERDES_REV = 33,
    SERDES_BUILD = 1688,
    SBUS_MASTER_REV = 0x1021,
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
la_device_impl::disable_npe_powered_down_blocks()
{
    la_status status;
    la_slice_id_vec_t fabric_slices;
    ll_filtered_device_impl* filtered_ll_dev = dynamic_cast<ll_filtered_device_impl*>(m_ll_device.get());
    for (la_slice_id_t slice : get_used_slices()) {
        if (m_slice_mode[slice] == la_slice_mode_e::CARRIER_FABRIC || m_slice_mode[slice] == la_slice_mode_e::DC_FABRIC) {
            fabric_slices.push_back(slice);
        }
    }
    for (la_slice_id_t slice : fabric_slices) {
        status = filtered_ll_dev->disable_block(m_gb_tree->slice[slice]->npu->rxpp_term->npe[1]->get_block_id());
        return_on_error(status);
        status = filtered_ll_dev->disable_block(m_gb_tree->slice[slice]->npu->rxpp_term->npe[2]->get_block_id());
        return_on_error(status);
        status = filtered_ll_dev->disable_block(m_gb_tree->slice[slice]->npu->rxpp_fwd->npe[1]->get_block_id());
        return_on_error(status);
        status = filtered_ll_dev->disable_block(m_gb_tree->slice[slice]->npu->rxpp_fwd->npe[2]->get_block_id());
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::disable_idb_res_and_encdb_powered_down_blocks()
{
    la_status status;
    ll_filtered_device_impl* filtered_ll_dev = dynamic_cast<ll_filtered_device_impl*>(m_ll_device.get());

    la_slice_id_vec_t used_slices = get_used_slices();

    for (la_slice_pair_id_t pair_idx : get_used_slice_pairs()) {
        // get first and second slice of slice_pair
        auto pair_idx_first_slice = pair_idx * 2;
        auto pair_idx_second_slice = pair_idx * 2 + 1;

        // check if slices in slice_pair are valid
        if (contains(used_slices, pair_idx_first_slice) && contains(used_slices, pair_idx_second_slice)) {
            // check if slices in slice_pair are FABRIC
            bool is_pair_idx_first_slice_fabric = m_slice_mode[pair_idx_first_slice] == la_slice_mode_e::CARRIER_FABRIC
                                                  || m_slice_mode[pair_idx_first_slice] == la_slice_mode_e::DC_FABRIC;

            bool is_pair_idx_second_slice_fabric = m_slice_mode[pair_idx_second_slice] == la_slice_mode_e::CARRIER_FABRIC
                                                   || m_slice_mode[pair_idx_second_slice] == la_slice_mode_e::DC_FABRIC;

            // if both slices are valid and fabric, disable_block idb_res and idb_encdb
            if (is_pair_idx_first_slice_fabric && is_pair_idx_second_slice_fabric) {
                status = filtered_ll_dev->disable_block(m_gb_tree->slice_pair[pair_idx]->idb->res->get_block_id());
                return_on_error(status);

                status = filtered_ll_dev->disable_block(m_gb_tree->slice_pair[pair_idx]->idb->encdb->get_block_id());
                return_on_error(status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::disable_hbm_powered_down_blocks()
{
    std::vector<la_block_id_t> powered_down_blocks;
    // filter out blocks
    for (auto block_itr : m_gb_tree->hbm->get_leaf_blocks()) {
        powered_down_blocks.push_back(block_itr->get_block_id());
    }

    for (auto block_itr : m_gb_tree->mmu->get_leaf_blocks()) {
        powered_down_blocks.push_back(block_itr->get_block_id());
    }

    ll_filtered_device_impl* ll_dev = dynamic_cast<ll_filtered_device_impl*>(m_ll_device.get());
    for (la_block_id_t b_id : powered_down_blocks) {
        la_status stat = ll_dev->disable_block(b_id);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize(init_phase_e phase)
{
    bool does_hbm_exists = false;
    la_status status;

    start_api_call("phase=", phase);

    init_phase_e init_phase = m_init_phase;

    status = hbm_exists(does_hbm_exists);
    return_on_error(status);

    bool power_saving_mode = false;
    get_bool_property(la_device_property_e::ENABLE_POWER_SAVING_MODE, power_saving_mode);

    if (m_reconnect_handler->is_reconnect_in_progress() && power_saving_mode) {
        disable_npe_powered_down_blocks();
        disable_idb_res_and_encdb_powered_down_blocks();
        if (!does_hbm_exists) {
            disable_hbm_powered_down_blocks();
        }
    }

    switch (phase) {
    case init_phase_e::DEVICE: {
        if (m_init_phase != init_phase_e::CREATED) {
            return LA_STATUS_EINVAL;
        }
        status = initialize_phase_device();
        return_on_error(status);

        init_phase = init_phase_e::DEVICE;
        break;
    }

    case init_phase_e::TOPOLOGY: {
        start_profiling("Init phase topology");
        if (m_init_phase != init_phase_e::DEVICE) {
            return LA_STATUS_EINVAL;
        }

        log_debug(HLD, "%s: TOPOLOGY - start", __func__);

        status = verify_topology_configuration();
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

        if (m_device_mode != device_mode_e::STANDALONE) {
            status = set_fabric_protocols_version();
            return_on_error(status);
        }

        // Create translator_creator.
        log_debug(HLD, "%s: create_flow", __func__);
        translator_creator_sptr creator;

        bool gb_initialization_other = false;
        get_bool_property(la_device_property_e::GB_INITIALIZE_OTHER, gb_initialization_other);
        if (gb_initialization_other) {
            status = create_flow(creator);
            return_on_error(status);
        }

        log_debug(HLD, "%s: initialize_phase_topology", __func__);
        status = initialize_phase_topology(creator);
        return_on_error(status);

        if (!does_hbm_exists) {
            if (power_saving_mode) {
                la_status rc = turn_off_hbm_and_mmu_blocks();
                log_on_error(rc, HLD, ERROR, "Failed to disable HBM blocks.");
            }
        }

        init_phase = init_phase_e::TOPOLOGY;
        log_debug(HLD, "%s: TOPOLOGY - done", __func__);
        break;
    }

    default:
        return LA_STATUS_EINVAL;
    }

    status = m_reconnect_handler->update_init_phase(init_phase);
    return_on_error(status);

    m_init_phase = init_phase;

    log_debug(API, "Initialization phase %s completed successfully", silicon_one::to_string(phase).c_str());

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_phase_device_core()
{
    log_debug(HLD, "%s: reset", __func__);

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
    gibraltar::csms_device_config_reg_register dev_id_reg_val = {.u8 = {0}};
    dev_id_reg_val.fields.device_id = m_ll_device->get_device_id();
    retval = m_ll_device->write_register(m_gb_tree->csms->device_config_reg, dev_id_reg_val);
    if (retval) {
        return retval;
    }

    retval = init_txpp_time_offsets();
    if (retval) {
        return retval;
    }

    retval = init_sbif_interrupts();
    return_on_error(retval);

    log_debug(HLD, "%s: done", __func__);

    return retval;
}

la_status
la_device_impl::initialize_fw_filepath()
{
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

    return m_serdes_device_handler->init(reconnect);
}

la_status
la_device_impl::read_core_hard_rstn(bool& core_hard_rstn)
{
    bool tmp = m_ll_device->get_shadow_read_enabled();
    m_ll_device->set_shadow_read_enabled(false);

    gibraltar::sbif_reset_reg_register reset_val{{0}};
    la_status rc = m_ll_device->read_register(m_gb_tree->sbif->reset_reg, reset_val);

    m_ll_device->set_shadow_read_enabled(tmp);
    return_on_error(rc);

    core_hard_rstn = reset_val.fields.core_hard_rstn;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::initialize_phase_device()
{
    start_profiling("Initialize phase device");

    dassert_crit(m_init_phase == init_phase_e::CREATED);
    la_status stat = initialize_first(m_reconnect_handler->is_reconnect_in_progress());
    return_on_error(stat);

    log_debug(HLD, "%s: entered", __func__);

    stat = m_init_performance_helper->reset();
    return_on_error(stat);

    m_device_port_handler = std::make_shared<device_port_handler_gibraltar>(shared_from_this());

    bool dummy = false;
    get_bool_property(la_device_property_e::ENABLE_DUMMY_SERDES_HANDLER, dummy);
    if (is_emulated_device() || dummy) {
        m_serdes_device_handler = std::make_shared<dummy_serdes_device_handler_base>(shared_from_this());
    } else {
        m_serdes_device_handler = std::make_shared<srm_serdes_device_handler>(shared_from_this());
    }

    bool a2_fixes_disabled;
    auto rev = m_ll_device->get_device_revision();
    get_bool_property(la_device_property_e::GB_A2_DISABLE_FIXES, a2_fixes_disabled);
    if (rev == la_device_revision_e::GIBRALTAR_A2) {
        la_status status = gb_rev_a2_apply_fixes(!a2_fixes_disabled);
        return_on_error(status);
    }

    m_device_port_handler->initialize();

    la_status retval = initialize_fw_filepath();
    return_on_error(retval);

    if (!m_reconnect_handler->is_reconnect_in_progress()) {
        bool core_hard_rstn;
        retval = read_core_hard_rstn(core_hard_rstn);
        return_on_error(retval);

        if (core_hard_rstn && rev == la_device_revision_e::GIBRALTAR_A0 && !is_emulated_device()) {
            log_err(HLD, "%s: cannot initialize a GIBRALTAR_A0 device that is already out-of-reset", __func__);
            return LA_STATUS_EINVAL;
        }
        // For emulated Gibraltar, or physical GIBRALTAR_A1 and higher, go on.

        // This is the first time we access the device. MBIST is a no-op on emulator.
        // Do not need to run MEM_BIST diagnostics when boot optimization is enabled.
        if (!m_init_performance_helper->is_optimization_enabled()) {
            retval = diagnostics_test(test_feature_e::MEM_BIST);
            return_on_error(retval);
        } else {
            log_debug(HLD, "%s : diagnostics_test skipped for cold boot optimization. Optimization ENABLED.", __func__);
        }

        retval = initialize_phase_device_core();
        return_on_error(retval);
    }

    log_debug(HLD, "%s: initialize CONFIG memories", __func__);

    // Write burst can be safely enabled when the device is not under traffic.
    // TODO: enable write burst for the entire init sequence.
    m_ll_device->set_write_burst(true);

    bool gb_initialization_config_memories = false;
    get_bool_property(la_device_property_e::GB_INITIALIZE_CONFIG_MEMORIES, gb_initialization_config_memories);
    if (gb_initialization_config_memories) {
        retval = init_config_memories();
    }

    retval = turn_off_registers_for_matilda();
    return_on_error(retval);

    m_ll_device->set_write_burst(false);
    return_on_error(retval);

    if (!m_reconnect_handler->is_reconnect_in_progress()) {
        retval = initialize_phase_device_core();
        return_on_error(retval);

        retval = disable_tcam_parity_scanners();
        return_on_error(retval);

        // Direct PIF 18 to packet-DMA
        retval = init_packet_dma();
        return_on_error(retval);

        // cpu2jtag is needed for HBM and for PVT
        retval = m_cpu2jtag_handler->enable(m_device_frequency_int_khz, m_tck_frequency_mhz);
        return_on_error(retval);

        retval = init_hbm();
        return_on_error(retval);
    }

    retval = initialize_serdes();
    return_on_error(retval);

    retval = m_pvt_handler->initialize();
    return_on_error(retval);

    log_debug(HLD, "%s: done", __func__);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_config_memories()
{
    start_profiling("Init config memories");
    log_debug(SIM, "command::init_config_memories_started");
    log_debug(HLD, "%s: start", __func__);

    if (is_emulated_device()) {
        // memories are zero-initialized on emulated device
        log_debug(HLD, "%s: skip on emulated device", __func__);
    } else {
        for (auto& block : m_gb_tree->get_leaf_blocks()) {
            log_debug(HLD, "%s: block=%s", __func__, block->get_name().c_str());

            const lld_block::block_indices_struct& block_indices = block->get_block_indices();
            bool should_skip = device_configurator_base::skip_this_block_matilda(block_indices, get_used_slices());
            for (lld_memory_scptr mem : block->get_memories()) {

                if (mem->get_desc()->type == lld_memory_type_e::CONFIG) {
                    log_debug(HLD, "%s: mem=%s", __func__, mem->get_name().c_str());
                    la_status rc = init_config_memory(mem, should_skip);
                    return_on_error(rc);
                }
            }
        }
    }

    log_debug(HLD, "%s: done", __func__);
    log_debug(SIM, "command::init_config_memories_done");

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_config_memory(lld_memory_scptr mem, bool should_skip_fill)
{
    const lld_memory_desc_t* desc = mem->get_desc();
    bool is_tcam = (desc->subtype == lld_memory_subtype_e::KEY_MASK_TCAM || desc->subtype == lld_memory_subtype_e::REG_TCAM);
    if (!should_skip_fill) {
        bit_vector val(0, desc->width_total_bits);
        la_status rc = m_ll_device->fill_memory(*mem, 0, desc->entries, val);
        return_on_error(rc);
    }
    // TCAMs must be marked as "invalid".
    // Otherwise, they contain "zero" which is a valid meaningful value.
    if (is_tcam) {
        size_t max_tcam_line = (desc->subtype == lld_memory_subtype_e::KEY_MASK_TCAM ? desc->entries / 2 : desc->entries);
        for (size_t tcam_line = 0; tcam_line < max_tcam_line; ++tcam_line) {
            la_status rc = m_ll_device->invalidate_tcam(*mem, tcam_line);
            return_on_error(rc);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::disable_tcam_parity_scanners()
{
    // tcam_scan_period_cfg register has a fixed address in all LBRs
    la_entry_addr_t tcam_scan_period_cfg_addr = m_gb_tree->cdb->core[0]->tcam_scan_period_cfg->get_desc()->addr;
    lld_register_value_list_t reg_val_list;

    // Shutdown all TCAM scanners by setting scan period to 0
    for (auto& b : m_gb_tree->get_leaf_blocks()) {
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
    push_back_ones(reg_val_list, m_gb_tree->sbif->packet_dma_err_interrupt_reg);
    push_back_ones(reg_val_list, m_gb_tree->sbif->packet_dma_done_interrupt_reg);
    push_back_ones(reg_val_list, m_gb_tree->sbif->ext_dma_drop_fc_interrupt_reg);

    // toggle packet-DMA reset bits, wait for 10ms till reset is executed
    gibraltar::sbif_reset_reg_register reset_reg;
    status = m_ll_device->read_register(m_gb_tree->sbif->reset_reg, reset_reg);
    return_on_error(status);

    reset_reg.fields.packet_dma_inj_ctxt_rstn = 0;
    reset_reg.fields.packet_dma_rstn = 0;
    reg_val_list.push_back({(m_gb_tree->sbif->reset_reg), reset_reg});
    status = lld_write_register_list(m_ll_device, reg_val_list);

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    reg_val_list.clear();

    if (using_leaba_nic) {
        status = reset_network_interfaces();
        return_on_error(status);
    }

    status = m_ll_device->read_register(m_gb_tree->sbif->reset_reg, reset_reg);
    return_on_error(status);

    reset_reg.fields.packet_dma_inj_ctxt_rstn = 0xfff;
    reset_reg.fields.packet_dma_rstn = 1;
    reg_val_list.push_back({(m_gb_tree->sbif->reset_reg), reset_reg});

    status = lld_write_register_list(m_ll_device, reg_val_list);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    return status;
}

la_status
la_device_impl::init_hbm()
{
    auto hbm_handler = std::make_shared<la_hbm_handler_impl>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(hbm_handler, oid);
    return_on_error(status);

    status = hbm_handler->initialize(oid);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    status = hbm_handler->activate();
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    m_hbm_handler = hbm_handler;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_sbif_interrupts()
{
    lld_register_value_list_t reg_val_list;
    const auto& sbif = m_gb_tree->sbif;

    // On GB, all interrupt masks are active low, 0 == enabled

    // Disable all root-level master interrupts - write all-ones
    // If there is a pending "outgoing" interrupt, it will be cleared as a result.
    push_back_ones(reg_val_list, sbif->arc3_master_interrupt_reg_mask);
    push_back_ones(reg_val_list, sbif->arc2_master_interrupt_reg_mask);
    push_back_ones(reg_val_list, sbif->arc1_master_interrupt_reg_mask);
    push_back_ones(reg_val_list, sbif->arc0_master_interrupt_reg_mask);
    push_back_ones(reg_val_list, sbif->msi_master_interrupt_reg_mask);
    push_back_ones(reg_val_list, sbif->pin_master_interrupt_reg_mask);

    // Enable all summary interrupt registers - write 0
    reg_val_list.push_back({sbif->arc0_blocks_interrupt_summary_reg0_mask, 0});
    reg_val_list.push_back({sbif->arc1_blocks_interrupt_summary_reg0_mask, 0});
    reg_val_list.push_back({sbif->arc2_blocks_interrupt_summary_reg0_mask, 0});
    reg_val_list.push_back({sbif->arc3_blocks_interrupt_summary_reg0_mask, 0});
    reg_val_list.push_back({sbif->msi_blocks_interrupt_summary_reg0_mask, 0});
    reg_val_list.push_back({sbif->pin_blocks_interrupt_summary_reg0_mask, 0});

    reg_val_list.push_back({sbif->arc0_blocks_interrupt_summary_reg1_mask, 0});
    reg_val_list.push_back({sbif->arc1_blocks_interrupt_summary_reg1_mask, 0});
    reg_val_list.push_back({sbif->arc2_blocks_interrupt_summary_reg1_mask, 0});
    reg_val_list.push_back({sbif->arc3_blocks_interrupt_summary_reg1_mask, 0});
    reg_val_list.push_back({sbif->msi_blocks_interrupt_summary_reg1_mask, 0});
    reg_val_list.push_back({sbif->pin_blocks_interrupt_summary_reg1_mask, 0});

    reg_val_list.push_back({sbif->arc0_blocks_interrupt_summary_reg2_mask, 0});
    reg_val_list.push_back({sbif->arc1_blocks_interrupt_summary_reg2_mask, 0});
    reg_val_list.push_back({sbif->arc2_blocks_interrupt_summary_reg2_mask, 0});
    reg_val_list.push_back({sbif->arc3_blocks_interrupt_summary_reg2_mask, 0});
    reg_val_list.push_back({sbif->msi_blocks_interrupt_summary_reg2_mask, get_rxpp_term_interrupt_summary_mask()});
    reg_val_list.push_back({sbif->pin_blocks_interrupt_summary_reg2_mask, 0});

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

template <class REGISTER_TYPE, class BLOCK_ARRAY>
void
prepare_tm_em_per_bank_reg(const BLOCK_ARRAY& block_array, lld_register_value_list_t& reg_val_list)
{
    // Configre the TM EM hashes. They should be unique between banks in a block, but can be identical between blocks.
    // The hash configuration of a bank within a block is a single register in a register array.
    // The hash values themselves are just random.

    constexpr la_uint64_t HASH_VALUES[] = {0x0601AC88665F05ULL,
                                           0x2BC3FCF4B2CA26ULL,
                                           0xE03AD689DF088FULL,
                                           0x476622A1171719ULL,
                                           0x0525C8093BF07BULL,
                                           0xDA27D42F456F6FULL,
                                           0x2E7142BFE92EBAULL,
                                           0x09FEE7A29835A6ULL};

    for (auto& block : block_array) {
        size_t reg_array_size = block->emdb_per_bank_reg->size();

        dassert_crit(reg_array_size < array_size(HASH_VALUES));

        la_uint64_t mask = bit_utils::get_lsb_mask(REGISTER_TYPE::fields::EMDB_HASH_KEY_WIDTH);
        for (size_t idx = 0; idx < reg_array_size; idx++) {
            REGISTER_TYPE reg = {.u8 = {0}};
            reg.fields.emdb_active_banks = 1;
            reg.fields.emdb_hash_key = HASH_VALUES[idx] & mask;
            reg.fields.emdb_use_primitive_crc = 0; // match Pacific for now

            reg_val_list.push_back({(*block->emdb_per_bank_reg)[idx], reg});
        }
    }
}

la_status
la_device_impl::init_em_per_bank_reg()
{
    // Initialize all exact match per bank registers.
    // Currently, the values taken from designer but probably will be changed.
    lld_register_value_list_t reg_val_list;

    la_uint64_t exact_match_seed = 0x1757DF59C01ULL;

    for (la_slice_id_t slice : get_used_slices()) {
        if (m_slice_id_manager->is_fabric_type_slice(slice, fabric_slices_type_e::LINECARD_NON_FABRIC)) {
            for (size_t exact_match = 0; exact_match < m_gb_tree->slice[slice]->pp_reorder->pp_exact_match_per_bank_reg->size();
                 exact_match++) {
                reg_val_list.push_back(
                    {(*m_gb_tree->slice[slice]->pp_reorder->pp_exact_match_per_bank_reg)[exact_match], exact_match_seed});
                exact_match_seed += 2;
            }
        } else {
            for (size_t block = 0; block < array_size(m_gb_tree->slice[slice]->nw_reorder_block); block++) {
                exact_match_seed = 0x1757DF59DB5ULL;
                exact_match_seed
                    += (slice - 3) * 2 * m_gb_tree->slice[slice]->nw_reorder_block[block]->nw_exact_match_per_bank_reg->size();
                for (size_t exact_match = 0;
                     exact_match < m_gb_tree->slice[slice]->nw_reorder_block[block]->nw_exact_match_per_bank_reg->size();
                     exact_match++) {
                    reg_val_list.push_back(
                        {(*m_gb_tree->slice[slice]->nw_reorder_block[block]->nw_exact_match_per_bank_reg)[exact_match],
                         exact_match_seed});
                    exact_match_seed += 2;
                }
            }
        }
    }

    prepare_tm_em_per_bank_reg<gibraltar::fdll_emdb_per_bank_reg_register>(m_gb_tree->fdll, reg_val_list);
    prepare_tm_em_per_bank_reg<gibraltar::pdoq_empd_emdb_per_bank_reg_register>(m_gb_tree->pdoq->empd, reg_val_list);
    prepare_tm_em_per_bank_reg<gibraltar::pdvoq_empd_emdb_per_bank_reg_register>(m_gb_tree->pdvoq->empd, reg_val_list);

    la_status status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_txpp_time_offsets()
{
    // values are frequency independent
    constexpr float TOD_GEN_REGS_VALS[] = {
        5, // slice 0
        1, // slice 1
        8, // slice 2
        9, // slice 3
        2, // slice 4
        6  // slice 5
    };
    // values in ns measured for CALCULATED_VALUES_DEVICE_FREQUENCY. Need to adjust according to actual clock frequency
    constexpr float DEVICE_TIME_OFFSET_CFG_VALS[] = {
        233, // slice 0
        221, // slice 1
        147, // slice 2
        147, // slice 3
        221, // slice 4
        233  // slice 5
    };
    float device_freq_adjust = float(1) / m_device_frequency_float_ghz;

    for (la_slice_id_t slice_id : get_used_slices()) {
        la_status status;
        txpp_tod_gen_regs_register tod_gen_regs;

        status = m_ll_device->read_register(m_gb_tree->slice[slice_id]->npu->txpp->top->tod_gen_regs, tod_gen_regs);
        return_on_error(status);
        tod_gen_regs.fields.tod_gen_load_cmd_delay = TOD_GEN_REGS_VALS[slice_id];
        status = m_ll_device->write_register(m_gb_tree->slice[slice_id]->npu->txpp->top->tod_gen_regs, tod_gen_regs);
        return_on_error(status);
        status = m_ll_device->write_register(m_gb_tree->slice[slice_id]->npu->txpp->top->device_time_offset_cfg,
                                             round(DEVICE_TIME_OFFSET_CFG_VALS[slice_id] * device_freq_adjust));
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_counters_bank_interrupt_config()
{
    lld_register_value_list_t reg_val_list;
    const uint64_t DISABLE_MAX_COUNTER_THRESHOLD = bit_utils::ones(
        gibraltar::counters_bank_group_6k_bank_interrupt_config_register::fields::MAX_COUNTER_INTERRUPT_THRESHOLD_WIDTH);
    bool is_narrow_counters_mode = m_device_properties[(int)la_device_property_e::ENABLE_NARROW_COUNTERS].bool_val;
    uint64_t threshold = is_narrow_counters_mode
                             ? static_cast<uint64_t>(m_device_properties[(int)la_device_property_e::MAX_COUNTER_THRESHOLD].int_val)
                             : DISABLE_MAX_COUNTER_THRESHOLD;

    gibraltar::counters_bank_group_bank_interrupt_config_register counters_bank_group_reg;
    counters_bank_group_reg.fields.max_counter_interrupt_threshold = threshold;
    for (size_t bank = 0; bank < array_size(m_gb_tree->counters->bank_8k); bank++) {
        for (size_t index = 0; index < m_gb_tree->counters->bank_8k[0]->bank_interrupt_config->size(); index++) {
            reg_val_list.push_back({(*m_gb_tree->counters->bank_8k[bank]->bank_interrupt_config)[index], counters_bank_group_reg});
        }
    }

    for (size_t bank = 0; bank < array_size(m_gb_tree->counters->bank_6k); bank++) {
        for (size_t index = 0; index < m_gb_tree->counters->bank_6k[0]->bank_interrupt_config->size(); index++) {
            reg_val_list.push_back({(*m_gb_tree->counters->bank_6k[bank]->bank_interrupt_config)[index], counters_bank_group_reg});
        }
    }
    la_status status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_tm_pdoq_fdoq()
{
    lld_register_value_list_t reg_val_list;

    for (la_slice_id_t slice : get_used_slices()) {
        // Set the partial mirror packet size to 256B (bit number 31 to 40)
        reg_val_list.push_back({(m_gb_tree->slice[slice]->pdoq->fdoq->partial_mirror_configuration), bit_vector("0x10000000000")});
    }

    la_status status = lld_write_register_list(m_ll_device, reg_val_list);
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
            if (m_slice_mode[slice] == la_slice_mode_e::NETWORK) {
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

    status = init_counters_bank_interrupt_config();
    return_on_error(status);

    status = init_tm_pdoq_fdoq();
    return_on_error(status);

    // Initialize per-slice settings
    /*
    for (la_slice_id_t slice :m_device->get_used_slices()) {
        la_status status = init_topology_tm(slice);
        return_on_error(status);
    }
    */

    status = init_load_balancing_keys();
    return_on_error(status);

    status = init_interrupts();

    return status;
}

la_status
la_device_impl::init_meters()
{
    lld_memory_value_list_t mem_val_list;

    // TODO: remove depracated value once LBRs are fixed and accepted.
    // 1400 [Gbps] = 1200G [physical rate] + 100G [recycle] + 100G [host]
    // constexpr size_t IFG_FULL_RATE = 1400;

    // 8 = 1/8 [token/clock] * 64 [bytes/token]
    constexpr size_t TOKEN_BYTES_PER_CLOCK = 8;
    // 4 = 1/8 [token/clock] * 32 [bytes/token]
    constexpr size_t RATE_LIMITERS_TOKEN_BYTES_PER_CLOCK = 4;

    gibraltar::rx_meter_block_meter_block_configuration_register bcr;

    la_status status;
    status = m_ll_device->read_register((*m_gb_tree->rx_meter->block[0]->meter_block_configuration)[0], bcr);

    // TODO: Keeping this in WIP commit, to be removed when LBRs are fixed and accepted.
    // float num_exact_meter_64byte_tokens
    //    = ceil((float)IFG_FULL_RATE / 8.0 /* bits per Byte */ / m_device_frequency_float_ghz / (float)TOKEN_BYTES_PER_CLOCK);

    m_meter_shaper_rate = bcr.fields.block_token_size * (float)TOKEN_BYTES_PER_CLOCK * m_device_frequency_float_ghz;

    // The calculation below would work if tokens given to rate limiter is not 2 times what is should
    // be(GLOBAL_METERS_TOKEN_SIZE. Retaining the commented code just in case we switch to halving the current value of token
    // size for rate limiters
    // float num_rate_limiters_32byte_tokens = ceil((float)IFG_FULL_RATE / 8.0 /* bits per Byte */ / m_device_frequency_float_ghz
    //                                             / (float)RATE_LIMITERS_TOKEN_BYTES_PER_CLOCK);

    gibraltar::rx_meter_global_rate_limiter_block_configuration_register global_rate_limiter_bcr;

    status = m_ll_device->read_register((*m_gb_tree->rx_meter->top->global_rate_limiter_block_configuration)[0],
                                        global_rate_limiter_bcr);

    float num_rate_limiters_32byte_tokens = global_rate_limiter_bcr.fields.global_rate_limiter_block_token_size;

    m_rate_limiters_shaper_rate
        = num_rate_limiters_32byte_tokens * (float)RATE_LIMITERS_TOKEN_BYTES_PER_CLOCK * m_device_frequency_float_ghz;

    // Prepare a variable with full ratio to be used inside the loop
    tm_utils::token_bucket_ratio_cfg_t ratio_cfg = tm_utils::calc_rate_ratio(m_meter_shaper_rate, LA_RATE_UNLIMITED);

    for (la_slice_ifg slice_ifg : get_used_ifgs()) {
        la_ifg_id_t ifg = m_slice_id_manager->slice_ifg_2_global_ifg(slice_ifg);
        // Rate limit per type
        rx_meter_rate_limiter_shaper_configuration_table_memory port_limiter;
        port_limiter.fields.rate_limiter_shaper_configuration_cir_weight = ratio_cfg.flat;
        mem_val_list.push_back({(*m_gb_tree->rx_meter->top->rate_limiter_shaper_configuration_table)[ifg], port_limiter});
    }
    status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_time_soft_reset(la_uint_t reset_val)
{
    log_debug(HLD, "%s: reset_val=%d", __func__, reset_val);

    std::vector<lld_register_scptr> soft_reset_vec;

    for (const auto& bank_8k : m_gb_tree->counters->bank_8k) {
        soft_reset_vec.push_back((bank_8k->soft_reset_configuration));
    }

    for (const auto& bank_6k : m_gb_tree->counters->bank_6k) {
        soft_reset_vec.push_back((bank_6k->soft_reset_configuration));
    }

    for (const auto& pdoq_empd : m_gb_tree->pdoq->empd) {
        soft_reset_vec.push_back((pdoq_empd->soft_reset_configuration));
    }

    for (const auto& pdvoq_empd : m_gb_tree->pdvoq->empd) {
        soft_reset_vec.push_back((pdvoq_empd->soft_reset_configuration));
    }

    for (const auto& fdll : m_gb_tree->fdll) {
        soft_reset_vec.push_back((fdll->soft_reset_configuration));
    }

    for (size_t i : get_used_slices()) {
        const auto& slice = m_gb_tree->slice[i];

        // PP reorder block exists only on slices 0-2, on the other slices we have nw_reorder block
        if (i < 3) {
            soft_reset_vec.push_back((slice->pp_reorder->soft_reset_configuration));
        } else {
            for (const auto& nw_reorder_block : slice->nw_reorder_block) {
                soft_reset_vec.push_back((nw_reorder_block->soft_reset_configuration));
            }
        }

        soft_reset_vec.push_back((slice->filb->soft_reset_configuration));
        soft_reset_vec.push_back((slice->pdvoq->soft_reset_configuration));

        if (i < 5) {
            soft_reset_vec.push_back((slice->fllb->soft_reset_configuration));
        } else {
            soft_reset_vec.push_back((slice->fabric_fllb->soft_reset_configuration));
        }

        soft_reset_vec.push_back((slice->ics->soft_reset_configuration));
        soft_reset_vec.push_back((slice->pdoq->fdoq->soft_reset_configuration));
        soft_reset_vec.push_back((slice->pdoq->top->soft_reset_configuration));
        soft_reset_vec.push_back((slice->ts_ms->soft_reset_configuration));
        soft_reset_vec.push_back((slice->tx->cgm->soft_reset_configuration));
        soft_reset_vec.push_back((slice->tx->pdr->soft_reset_configuration));

        for (const auto& ifg : slice->ifg) {
            soft_reset_vec.push_back((ifg->ifgb->soft_reset_configuration));

            for (const auto& mac_pool8 : ifg->mac_pool8) {
                if (mac_pool8->is_valid()) {
                    soft_reset_vec.push_back((mac_pool8->soft_reset_configuration));
                }
            }

            soft_reset_vec.push_back((ifg->sch->soft_reset_configuration));
        }
    }

    for (const auto& sms_quad : m_gb_tree->sms_quad) {
        soft_reset_vec.push_back((sms_quad->soft_reset_configuration));
    }

    for (const auto& rx_meter_block : m_gb_tree->rx_meter->block) {
        soft_reset_vec.push_back((rx_meter_block->soft_reset_configuration));
    }

    for (size_t i : get_used_slice_pairs()) {
        const auto& slice_pair = m_gb_tree->slice_pair[i];
        soft_reset_vec.push_back((slice_pair->rx_pdr->soft_reset_configuration));
    }

    for (const auto& rx_pdr_mc_db : m_gb_tree->rx_pdr_mc_db) {
        soft_reset_vec.push_back((rx_pdr_mc_db->soft_reset_configuration));
    }

    soft_reset_vec.push_back((m_gb_tree->counters->top->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->csms->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->dics->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->dmc->frm->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->dmc->fte->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->dmc->pier->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->dvoq->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->fdll_shared_mem->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->dram_cgm->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->ics_top->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->nw_reorder->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->pdoq_shared_mem->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->pdvoq_shared_mma->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->reassembly->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->rx_cgm->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->rx_counters->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->rx_meter->top->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->rx_pdr->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->sch_top->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->sms_main->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->ts_mon->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->tx_cgm_top->soft_reset_configuration));

    // NPU
    for (size_t i : get_used_slices()) {
        const auto& slice = m_gb_tree->slice[i];
        for (const auto& term_npe : slice->npu->rxpp_term->npe) {
            soft_reset_vec.push_back((term_npe->soft_reset_configuration));
        }

        for (const auto& fwd_npe : slice->npu->rxpp_fwd->npe) {
            soft_reset_vec.push_back((fwd_npe->soft_reset_configuration));
        }

        for (const auto& fi_eng : slice->npu->rxpp_term->fi_eng) {
            soft_reset_vec.push_back((fi_eng->soft_reset_configuration));
        }

        soft_reset_vec.push_back((slice->npu->rxpp_term->flc_db->soft_reset_configuration));
        soft_reset_vec.push_back((slice->npu->rxpp_fwd->flc_queues->soft_reset_configuration));
        soft_reset_vec.push_back((slice->npu->rxpp_term->fi_stage->soft_reset_configuration));
        soft_reset_vec.push_back((slice->npu->rxpp_term->top->soft_reset_configuration));
        soft_reset_vec.push_back((slice->npu->rxpp_fwd->top->soft_reset_configuration));
        soft_reset_vec.push_back((slice->npu->rxpp_fwd->cdb_cache->soft_reset_configuration));

        for (const auto& txpp_npe : slice->npu->txpp->npe) {
            soft_reset_vec.push_back((txpp_npe->soft_reset_configuration));
        }

        for (const auto& ene_cluster : slice->npu->txpp->ene_cluster) {
            soft_reset_vec.push_back((ene_cluster->soft_reset_configuration));
        }

        soft_reset_vec.push_back((slice->npu->rxpp_term->sna->soft_reset_configuration));
        soft_reset_vec.push_back((slice->npu->txpp->top->soft_reset_configuration));
    }

    for (size_t i : get_used_slice_pairs()) {
        const auto& slice_pair = m_gb_tree->slice_pair[i];
        soft_reset_vec.push_back((slice_pair->idb->macdb->soft_reset_configuration));
        soft_reset_vec.push_back((slice_pair->idb->encdb->soft_reset_configuration));
        soft_reset_vec.push_back((slice_pair->idb->res->soft_reset_configuration));
    }

    soft_reset_vec.push_back((m_gb_tree->cdb->top->soft_reset_configuration));

    for (const auto& cdb_core : m_gb_tree->cdb->core) {
        soft_reset_vec.push_back((cdb_core->soft_reset_configuration));
    }

    soft_reset_vec.push_back((m_gb_tree->npuh->npe->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->npuh->fi->soft_reset_configuration));
    soft_reset_vec.push_back((m_gb_tree->npuh->host->soft_reset_configuration));

    lld_register_value_list_t reg_val_list;

    for (auto lld_reg : soft_reset_vec) {
        if (!lld_reg->is_valid()) {
            log_err(HLD, "%s: invalid register %s", __func__, lld_reg->get_name().c_str());
            continue;
        }

        reg_val_list.push_back({lld_reg, reset_val});
    }

    la_status stat = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(stat);

    log_debug(HLD, "%s: done", __func__);

    return LA_STATUS_SUCCESS;
}

enum { POLL_INIT_DONE_MAX = 100 };

la_status
la_device_impl::poll_init_done()
{
    log_debug(HLD, "%s", __func__);
    la_slice_id_t rep_sid = get_used_slice_pairs()[0];
    struct {
        lld_register_scptr reg;
        bit_vector expected;
    } init_done_regs[] = {
        // Poll till idb.res.init_done becomes non-zero.
        {m_gb_tree->slice_pair[rep_sid]->idb->res->init_done_status_register, bit_vector(1, 16)},

        // Poll till dvoq.init_active becomes zero.
        {m_gb_tree->dvoq->init_active, bit_vector(0, 16)},
    };

    for (auto el : init_done_regs) {
        auto mask = bit_vector::ones(el.reg->get_desc()->width_in_bits);
        mask.resize(16);
        log_debug(SIM,
                  "command::poll_no_response %016zx 2 %s %s 200",
                  el.reg->get_absolute_address(),
                  el.expected.to_string().c_str(),
                  mask.to_string().c_str());
    }

    if (!is_simulated_device()) {
        for (auto el : init_done_regs) {
            for (size_t i = 0;; ++i) {
                if (i == POLL_INIT_DONE_MAX) {
                    log_err(HLD, "%s: exceeded max retries=%ld", __func__, i);
                    return LA_STATUS_ENOTINITIALIZED;
                }
                bit_vector val;
                la_status rc = m_ll_device->read_register(*el.reg, val);
                return_on_error(rc);
                if (val.get_value() == el.expected.get_value()) {
                    break;
                }
            }
        }
    }

    log_debug(HLD, "%s: done", __func__);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_dynamic_memories()
{

    lld_memory_value_list_t mem_val_list;

    for (la_slice_id_t sid : get_used_slices()) {
        const auto& slice = m_gb_tree->slice[sid];
        for (const auto& ifg : slice->ifg) {
            mem_val_list.push_back({ifg->sch->vscc_cir_link_list, 0});
            mem_val_list.push_back({ifg->sch->vscc_eir_link_list, 0});
        }

        for (const auto& mem : slice->filb->get_memories()) {
            if (mem->get_desc()->is_volatile()) {
                mem_val_list.push_back({mem, 0});
            }
        }
        const auto& memories = (slice->fllb->is_valid() ? slice->fllb->get_memories() : slice->fabric_fllb->get_memories());
        for (const auto mem : memories) {
            if (mem->get_desc()->is_volatile()) {
                mem_val_list.push_back({mem, 0});
            }
        }
    }

    // Initialize shared_sram banks. During init, shared_srams can be written to as a normal memory, with CIF write.
    // During traffic, they can only be written to through redirection (implemented in LPM).
    // NOTE: CEM memory changed in GB, have to use GB tree in order to initialize them properly
    const auto& cdb = m_gb_tree->cdb;
    for (size_t i = 0; i < array_size(cdb->core); ++i) {
        for (size_t j = 0; j < cdb->core[0]->srams_group0->get_desc()->instances; ++j) {
            mem_val_list.push_back({(*cdb->core[i]->srams_group0)[j], 0});
            mem_val_list.push_back({(*cdb->core[i]->srams_group1)[j], 0});
        }
    }

    la_status status = lld_write_memory_list(m_ll_device, mem_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_pre_2nd_soft_reset_workaround()
{
    la_status status = apply_topology_pre_2nd_soft_reset_workaround_ics();
    return_on_error(status);

    status = apply_topology_pre_2nd_soft_reset_workaround_pdvoq();
    return_on_error(status);

    status = apply_topology_pre_2nd_soft_reset_workaround_reorder();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_pre_2nd_soft_reset_workaround_ics()
{
    lld_register_value_list_t reg_val_list;
    la_status status;

    status = apply_topology_soft_reset_workaround_ics_dram_pool_fbm_conf(reg_val_list, 0 /*dram_pool_fbm_rstn_cfg*/);
    return_on_error(status);

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_pre_2nd_soft_reset_workaround_reorder()
{
    lld_register_value_list_t reg_val_list;
    la_status status;

    status = apply_topology_soft_reset_workaround_nw_reorder_em_fbm_cfg(reg_val_list, 0 /*em_fbm_cfg*/);
    return_on_error(status);

    status = apply_topology_soft_reset_workaround_pp_reorder_em_fbm_cfg(reg_val_list, 0 /*em_fbm_cfg*/);
    return_on_error(status);

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_pre_2nd_soft_reset_workaround_pdvoq()
{
    lld_register_value_list_t reg_val_list;
    la_status status;

    status = apply_topology_soft_reset_workaround_pdvoq_fbm_rstn_cfg(reg_val_list, 0 /*fbm_rstn_cfg*/);
    return_on_error(status);

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround()
{
    la_status status = apply_topology_post_soft_reset_workaround_ics();
    return_on_error(status);

    status = apply_topology_post_soft_reset_workaround_pdvoq();
    return_on_error(status);

    status = apply_topology_post_soft_reset_workaround_reorder();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_soft_reset_workaround_ics_dram_pool_fbm_conf(lld_register_value_list_t& reg_val_list,
                                                                            uint64_t dram_pool_fbm_rstn_cfg)
{
    gibraltar::ics_top_dram_pool_fbm_conf_register fbm_conf;

    la_status status = m_ll_device->read_register(m_gb_tree->ics_top->dram_pool_fbm_conf, fbm_conf);
    return_on_error(status);

    fbm_conf.fields.dram_pool_fbm_rstn_cfg = dram_pool_fbm_rstn_cfg;

    reg_val_list.push_back({(m_gb_tree->ics_top->dram_pool_fbm_conf), fbm_conf});

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround_ics_memory_access_timeout(lld_register_value_list_t& reg_val_list)
{
    // scrubber_mem is burst-accessed by internal ics scrubber, which has a higher priority than CPU access.
    // As a result, CPU access may fail with the default CIF timeout. Here we increase the CIF timeout.
    for (la_slice_id_t sid : get_used_slices()) {
        const auto& slice = m_gb_tree->slice[sid];
        gibraltar::ics_slice_memory_access_timeout_register timeout_reg;

        la_status status = m_ll_device->read_register(slice->ics->memory_access_timeout, timeout_reg);
        return_on_error(status);

        timeout_reg.fields.timeout_counter_thr = 0xf000;

        reg_val_list.push_back({(slice->ics->memory_access_timeout), timeout_reg});
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_soft_reset_workaround_pp_reorder_em_fbm_cfg(lld_register_value_list_t& reg_val_list,
                                                                           uint64_t em_fbm_cfg)
{
    for (la_slice_id_t sid : get_used_slices()) {
        if (m_slice_mode[sid] != la_slice_mode_e::CARRIER_FABRIC || !m_gb_tree->slice[sid]->pp_reorder->is_valid()) {
            continue;
        }
        for (size_t i = 0; i < m_gb_tree->slice[sid]->pp_reorder->em_fbm_config_reg->size(); i++) {
            gibraltar::pp_reorder_slice_em_fbm_config_reg_register pp_em_fbm_config_reg;
            la_status status
                = m_ll_device->read_register((*m_gb_tree->slice[sid]->pp_reorder->em_fbm_config_reg)[i], pp_em_fbm_config_reg);
            return_on_error(status);

            pp_em_fbm_config_reg.fields.em_fbm_init = em_fbm_cfg;

            reg_val_list.push_back({(*m_gb_tree->slice[sid]->pp_reorder->em_fbm_config_reg)[i], pp_em_fbm_config_reg});
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_soft_reset_workaround_nw_reorder_em_fbm_cfg(lld_register_value_list_t& reg_val_list,
                                                                           uint64_t em_fbm_cfg)
{
    for (la_slice_id_t sid : get_used_slices()) {
        if (m_slice_mode[sid] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }
        for (const auto& nw_reorder_block : m_gb_tree->slice[sid]->nw_reorder_block) {
            if (!nw_reorder_block->is_valid()) {
                continue;
            }
            for (size_t i = 0; i < nw_reorder_block->em_fbm_config_reg->size(); i++) {
                gibraltar::nw_reorder_block_em_fbm_config_reg_register nw_em_fbm_config_reg;
                la_status status = m_ll_device->read_register((*nw_reorder_block->em_fbm_config_reg)[i], nw_em_fbm_config_reg);
                return_on_error(status);

                nw_em_fbm_config_reg.fields.em_fbm_init = em_fbm_cfg;

                reg_val_list.push_back({(*nw_reorder_block->em_fbm_config_reg)[i], nw_em_fbm_config_reg});
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_soft_reset_workaround_pdvoq_fbm_rstn_cfg(lld_register_value_list_t& reg_val_list,
                                                                        uint64_t fbm_rstn_cfg)
{

    for (size_t i : get_used_slices()) {
        const auto& slice = m_gb_tree->slice[i];
        gibraltar::pdvoq_slice_general_conf_register fbm_conf;

        la_status status = m_ll_device->read_register(slice->pdvoq->general_conf, fbm_conf);
        return_on_error(status);

        fbm_conf.fields.fbm_rstn_cfg = fbm_rstn_cfg;

        reg_val_list.push_back({(slice->pdvoq->general_conf), fbm_conf});
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround_ics()
{
    lld_register_value_list_t reg_val_list;
    la_status status;

    status = apply_topology_soft_reset_workaround_ics_dram_pool_fbm_conf(reg_val_list, 1 /*dram_pool_fbm_rstn_cfg*/);
    return_on_error(status);

    status = apply_topology_post_soft_reset_workaround_ics_memory_access_timeout(reg_val_list);
    return_on_error(status);

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround_pdvoq()
{
    lld_register_value_list_t reg_val_list;
    la_status status;

    status = apply_topology_soft_reset_workaround_pdvoq_fbm_rstn_cfg(reg_val_list, 1 /*fbm_rstn_cfg*/);
    return_on_error(status);

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround_dics()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround_dvoq()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround_ifgb()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround_reorder()
{
    lld_register_value_list_t reg_val_list;
    la_status status;

    status = apply_topology_soft_reset_workaround_nw_reorder_em_fbm_cfg(reg_val_list, 1 /*em_fbm_cfg*/);
    return_on_error(status);

    status = apply_topology_soft_reset_workaround_pp_reorder_em_fbm_cfg(reg_val_list, 1 /*em_fbm_cfg*/);
    return_on_error(status);

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_topology_post_soft_reset_workaround_tx_cgm()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::apply_init_workarounds()
{
    log_debug(HLD, "la_device_impl::apply_init_workarounds()");
    // For GB no workarounds are needed so far.
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
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_dmc_fte()
{
    enum {
        DEVICE_TIME_PPS_INTERVALS = 10000,
        DEVICE_TIME_PPS_WIDTH = 1000,
        DEVICE_TIME_LOAD_PAD_DELAY = 3,
        FTE_NEW_TIME_lOAD_DELAY = 88,
        FTE_DEVICE_TIME_OFFSET = 88,
    };

    // initialize PTP handler
    auto ptp_handler = std::make_shared<la_ptp_handler_gibraltar>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(ptp_handler, oid);
    return_on_error(status);

    status = ptp_handler->initialize(oid);
    return_on_error(status);

    m_ptp_handler = ptp_handler;

    // Rest of FTE initialization
    lld_register_value_list_t reg_val_list;

    // if we use m_device_frequency_float_ghz, we lose precision and get the wrong values
    double period_ns = (1.0 / (double)m_device_frequency_int_khz) * 1000000.0;
    uint64_t period_ns_whole = floor(period_ns);
    double period_ns_fractional = period_ns - period_ns_whole;

    la_uint_t device_time_bit_width = gibraltar::fte_device_time_unit_reg_register::fields::DEVICE_TIME_CLOCK_INC_FRAC_VALUE_WIDTH;
    double period_subns = period_ns_fractional * pow(2.0, device_time_bit_width);
    uint64_t period_subns_whole = floor(period_subns);
    float period_subns_fractional = period_subns - period_subns_whole;

    // compute numerator and denominator
    uint64_t clock_compensation_period = m_device_frequency_float_ghz * 100;
    uint64_t clock_compensation_value = period_subns_fractional * clock_compensation_period;

    // find GCD to reduce fraction
    uint64_t gcd = std::__gcd(clock_compensation_value, clock_compensation_period);

    la_uint_t max_compensation_value
        = ((la_uint_t)0x01 << gibraltar::fte_device_time_unit_reg_register::fields::DEVICE_TIME_CLOCK_FRAC_COMP_VAL_WIDTH) - 1;

    clock_compensation_period = clock_compensation_period / gcd;
    clock_compensation_value = clock_compensation_value / gcd;

    // check numerator and denominator for max values
    if (clock_compensation_period > max_compensation_value || clock_compensation_value > max_compensation_value) {
        log_warning(HLD,
                    "Could not calculate time unit clock compensation values, setting to 0. "
                    "clock_inc_ns_value=%lu clock_inc_frac_value=%lu comp_period=%lu comp_val=%lu",
                    period_ns_whole,
                    period_subns_whole,
                    clock_compensation_period,
                    clock_compensation_value);
        clock_compensation_value = 0;
        clock_compensation_period = 0;
    }

    gibraltar::fte_device_time_new_unit_reg_register device_time_new_unit_reg;
    device_time_new_unit_reg.fields.device_time_clock_new_inc_ns_value = period_ns_whole;
    device_time_new_unit_reg.fields.device_time_clock_new_inc_frac_value = period_subns_whole;
    device_time_new_unit_reg.fields.device_time_clock_new_frac_comp_period = clock_compensation_period;
    device_time_new_unit_reg.fields.device_time_clock_new_frac_comp_val = clock_compensation_value;
    reg_val_list.push_back({m_gb_tree->dmc->fte->device_time_new_unit_reg, device_time_new_unit_reg});

    gibraltar::fte_clock_inc_reg_register clock_inc_reg;
    clock_inc_reg.fields.clock_inc_ns_value = period_ns_whole;
    clock_inc_reg.fields.clock_inc_frac_value = period_subns_whole;
    clock_inc_reg.fields.clock_frac_comp_period = clock_compensation_period;
    clock_inc_reg.fields.clock_frac_comp_val = clock_compensation_value;
    reg_val_list.push_back({m_gb_tree->dmc->fte->clock_inc_reg, clock_inc_reg});

    gibraltar::fte_device_time_unit_reg_register device_time_unit_reg;
    device_time_unit_reg.fields.device_time_clock_inc_ns_value = period_ns_whole;
    device_time_unit_reg.fields.device_time_clock_inc_frac_value = period_subns_whole;
    device_time_unit_reg.fields.device_time_clock_frac_comp_period = clock_compensation_period;
    device_time_unit_reg.fields.device_time_clock_frac_comp_val = clock_compensation_value;
    reg_val_list.push_back({m_gb_tree->dmc->fte->device_time_unit_reg, device_time_unit_reg});

    gibraltar::fte_device_time_pps_reg_register dev_time_pps_reg;
    dev_time_pps_reg.fields.device_time_pps_en = 1;
    dev_time_pps_reg.fields.device_time_pps_interval = DEVICE_TIME_PPS_INTERVALS;
    dev_time_pps_reg.fields.device_time_pps_width = DEVICE_TIME_PPS_WIDTH;
    reg_val_list.push_back({m_gb_tree->dmc->fte->device_time_pps_reg, dev_time_pps_reg});

    fte_device_time_sync_reg_register device_time_sync_reg;
    status = m_ll_device->read_register(m_gb_tree->dmc->fte->device_time_sync_reg, device_time_sync_reg);
    return_on_error(status);
    device_time_sync_reg.fields.device_time_load_pad_delay = DEVICE_TIME_LOAD_PAD_DELAY;
    reg_val_list.push_back({m_gb_tree->dmc->fte->device_time_sync_reg, device_time_sync_reg});

    gibraltar::fte_new_time_load_reg_register new_time_load_reg{{0}};
    new_time_load_reg.fields.new_time_load_delay = FTE_NEW_TIME_lOAD_DELAY;
    reg_val_list.push_back({m_gb_tree->dmc->fte->new_time_load_reg, new_time_load_reg});

    float device_freq_adjust = float(1) / m_device_frequency_float_ghz;
    reg_val_list.push_back({m_gb_tree->dmc->fte->device_time_offset_cfg, round(FTE_DEVICE_TIME_OFFSET * device_freq_adjust)});

    // Write all registers
    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_dmc_pier()
{
    lld_register_value_list_t reg_val_list;

    bool lc_56_fabric_port_mode;
    la_status status = get_bool_property(la_device_property_e::LC_56_FABRIC_PORT_MODE, lc_56_fabric_port_mode);
    return_on_error(status);

    // Map IFG0->packet-DMA and IFG1->NPU-host on all slices
    reg_val_list.push_back({(m_gb_tree->dmc->pier->inb_ifg_extract_map_reg), 0x444444});

    // Write all registers
    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// Clear the CRC errors in the recycle buffers
la_status
la_device_impl::clear_rcy_path()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::init_sms_main()
{
    return LA_STATUS_SUCCESS;
}

void
set_cif_interrupt_mask(const interrupt_tree::node_scptr& node,
                       std::map<lld_register_scptr, uint64_t, lld_register_scptr_ops>& reg_val_map)
{
    // On GB, all masks are active low, 0 == enabled.
    if (node->mask) {
        reg_val_map[node->mask] = 0;
        for (const auto& bit : node->bits) {
            if (bit->is_masked) {
                reg_val_map[node->mask] |= 1 << (bit->bit_i);
            }
        }
    } else if (node->status->get_desc()->addr == lld_register::MEM_PROTECT_INTERRUPT) {
        for (lld_register_scptr mask : node->mem_protect.masks) {
            if (mask) {
                reg_val_map[mask] = 0;
            }
        }
    }
}

// CIF block IDs are below 'sbif'.
// Non-CIF block IDs include sbif, top-regfile, sim-access
static inline bool
is_cif_block_id(la_block_id_t block_id)
{
    return (block_id < gibraltar_tree::lld_block_id_e::LLD_BLOCK_ID_SBIF);
}

la_status
la_device_impl::set_default_cif_masks()
{
    // On GB, the initial values of CIF interrupt masks in HW is "0==enabled".
    //        the default values in LBRs are "1's == disabled"
    //        the initial value of mem-protect masks in HW and the default in LBR's is "1's==disabled".

    // Interrupt registers are up to 32bit wide.
    std::map<lld_register_scptr, uint64_t, lld_register_scptr_ops> reg_val_map;

    // Disable all CIF interrupts.
    for (const auto block : m_gb_tree->get_leaf_blocks()) {
        if (is_cif_block_id(block->get_block_id())) {
            for (const auto r : block->get_registers()) {
                if (r->get_desc()->type == lld_register_type_e::INTERRUPT_MASK) {
                    reg_val_map[r] = (1 << r->get_desc()->width_in_bits) - 1;
                }
            }
        }
    }

    // Enable all modeled CIF interrupts, respect the "bit::is_masked" field.
    auto node_cb = ([&](const interrupt_tree::node_scptr& node, size_t unused) {
        if (is_cif_block_id(node->status->get_block_id())) {
            set_cif_interrupt_mask(node, reg_val_map);
        }
        return UINT64_MAX; // continue traversing down the tree to all sub nodes
    });

    auto bit_cb = ([](const interrupt_tree::bit_scptr&, size_t) {});

    // Traverse the interrupt tree, this covers only modeled interrupts.
    m_notification->get_interrupt_tree()->traverse(node_cb, bit_cb);

    for (const auto& reg_val : reg_val_map) {
        la_status rc = m_ll_device->write_register(*reg_val.first, reg_val.second);
        return_on_error(rc);
    }

    return LA_STATUS_SUCCESS;
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
    for (la_slice_id_t i : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_FABRIC)) {
        reg_val_list.push_back({m_gb_tree->slice[i]->ts_ms->general_interrupt_register_mask, tsms_general_mask});
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

    // HBM does not exist, mask off hbm_db interrupts and mem-protect errors.
    for (const auto& hbm_db : m_gb_tree->hbm->db) {
        for (const auto reg : hbm_db->get_registers()) {
            if (reg->get_desc()->type == lld_register_type_e::INTERRUPT_MASK) {
                push_back_ones(reg_val_list, reg);
            }
        }
        push_back_ones(reg_val_list, hbm_db->ecc_1b_err_interrupt_register_mask);
        push_back_ones(reg_val_list, hbm_db->ecc_2b_err_interrupt_register_mask);
    }
}

void
la_device_impl::override_masks_tcam_parity(lld_register_value_list_t& reg_val_list)
{
    // Disable 'Parity' mem_protect interrupt for all TCAMs.

    bit_vector rxpp_term_mask = bit_vector::ones(rxpp_term_parity_err_interrupt_register_mask_register::SIZE_IN_BITS);

    gibraltar::npe_parity_err_interrupt_register_mask_register npe_mask{{0}};
    npe_mask.fields.lookup_keys_selection_tcam_parity_err_interrupt_mask = 1;
    npe_mask.fields.resolution_keys_selection_tcam_low_parity_err_interrupt_mask = 1;
    npe_mask.fields.resolution_keys_selection_tcam_high_parity_err_interrupt_mask = 1;
    npe_mask.fields.lookup_core_tcam_parity_err_interrupt_mask = 1;
    npe_mask.fields.traps_tcam_parity_err_interrupt_mask = 1;

    bit_vector cdb_cache_mask = bit_vector::ones(cdb_cache_parity_err_interrupt_register_mask_register::SIZE_IN_BITS);

    gibraltar::fi_parity_err_interrupt_register_mask_register fi_mask{{0}};
    fi_mask.fields.fi_core_tcam_parity_err_interrupt_mask = 1;

    gibraltar::flc_db_parity_err_interrupt_register_mask_register flc_db_mask{{0}};
    flc_db_mask.fields.header_types_array_tcam_parity_err_interrupt_mask = 1;

    bit_vector cdb_core_mask = bit_vector::ones(cdb_core_parity_err_interrupt_register_mask_register::SIZE_IN_BITS);

    gibraltar::cdb_top_parity_err_interrupt_register_mask_register cdb_top_mask{
        .fields = {.cem_iccm_parity_err_interrupt_mask = 0,
                   .clpm_group_map_tcam0_parity_err_interrupt_mask = 1,
                   .clpm_group_map_tcam1_parity_err_interrupt_mask = 1,
                   .clpm_group_map_tcam2_parity_err_interrupt_mask = 1,
                   .clpm_group_map_tcam3_parity_err_interrupt_mask = 1,
                   .clpm_group_map_tcam4_parity_err_interrupt_mask = 1,
                   .clpm_group_map_tcam5_parity_err_interrupt_mask = 1,
                   .clpm_group_map_tcam6_parity_err_interrupt_mask = 1,
                   .clpm_group_map_tcam7_parity_err_interrupt_mask = 1,
                   .clpm_group_map_tcam8_parity_err_interrupt_mask = 1,
                   .clpm_group_map_tcam9_parity_err_interrupt_mask = 1,
                   .clpm_group_map_tcam10_parity_err_interrupt_mask = 1,
                   .clpm_group_map_tcam11_parity_err_interrupt_mask = 1},
    };

    reg_val_list.push_back({m_gb_tree->cdb->top->parity_err_interrupt_register_mask, cdb_top_mask});
    reg_val_list.push_back({m_gb_tree->npuh->fi->parity_err_interrupt_register_mask, fi_mask});
    reg_val_list.push_back({m_gb_tree->npuh->npe->parity_err_interrupt_register_mask, npe_mask});

    for (la_slice_id_t sid : get_used_slices()) {
        const auto& slice = m_gb_tree->slice[sid];
        // rxpp_fwd
        reg_val_list.push_back({slice->npu->rxpp_fwd->cdb_cache->parity_err_interrupt_register_mask, cdb_cache_mask});
        for (const auto& npe : slice->npu->rxpp_fwd->npe) {
            reg_val_list.push_back({npe->parity_err_interrupt_register_mask, npe_mask});
        }

        // rxpp_term
        for (const auto& fi_eng : slice->npu->rxpp_term->fi_eng) {
            reg_val_list.push_back({fi_eng->parity_err_interrupt_register_mask, fi_mask});
        }
        reg_val_list.push_back({slice->npu->rxpp_term->flc_db->parity_err_interrupt_register_mask, flc_db_mask});
        for (const auto& npe : slice->npu->rxpp_term->npe) {
            reg_val_list.push_back({npe->parity_err_interrupt_register_mask, npe_mask});
        }
        reg_val_list.push_back({slice->npu->rxpp_term->top->parity_err_interrupt_register_mask, rxpp_term_mask});

        // txpp
        for (const auto& npe : slice->npu->txpp->npe) {
            reg_val_list.push_back({npe->parity_err_interrupt_register_mask, npe_mask});
        }
    }

    for (const auto& core : m_gb_tree->cdb->core) {
        reg_val_list.push_back({core->parity_err_interrupt_register_mask, cdb_core_mask});
    }
}

void
la_device_impl::override_masks_mem_protect(lld_register_value_list_t& reg_val_list)
{
}

void
la_device_impl::clear_sbif_interrupts(lld_register_value_list_t& reg_val_list)
{
    // blocks reg0
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc0_blocks_interrupt_summary_reg0);
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc1_blocks_interrupt_summary_reg0);
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc2_blocks_interrupt_summary_reg0);
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc3_blocks_interrupt_summary_reg0);
    push_back_ones(reg_val_list, m_gb_tree->sbif->msi_blocks_interrupt_summary_reg0);
    push_back_ones(reg_val_list, m_gb_tree->sbif->pin_blocks_interrupt_summary_reg0);

    // blocks reg1
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc0_blocks_interrupt_summary_reg1);
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc1_blocks_interrupt_summary_reg1);
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc2_blocks_interrupt_summary_reg1);
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc3_blocks_interrupt_summary_reg1);
    push_back_ones(reg_val_list, m_gb_tree->sbif->msi_blocks_interrupt_summary_reg1);
    push_back_ones(reg_val_list, m_gb_tree->sbif->pin_blocks_interrupt_summary_reg1);

    // blocks reg2
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc0_blocks_interrupt_summary_reg2);
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc1_blocks_interrupt_summary_reg2);
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc2_blocks_interrupt_summary_reg2);
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc3_blocks_interrupt_summary_reg2);
    push_back_ones(reg_val_list, m_gb_tree->sbif->msi_blocks_interrupt_summary_reg2);
    push_back_ones(reg_val_list, m_gb_tree->sbif->pin_blocks_interrupt_summary_reg2);

    // master
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc3_master_interrupt_reg);
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc2_master_interrupt_reg);
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc1_master_interrupt_reg);
    push_back_ones(reg_val_list, m_gb_tree->sbif->arc0_master_interrupt_reg);
    push_back_ones(reg_val_list, m_gb_tree->sbif->msi_master_interrupt_reg);
    push_back_ones(reg_val_list, m_gb_tree->sbif->pin_master_interrupt_reg);
}

la_status
la_device_impl::init_interrupts()
{
    // Mask-off all not-modeled CIF interrupts.
    // Set masks for all modeled CIF interrupts, including mem_protect (SER) masks.
    la_status rc = set_default_cif_masks();
    return_on_error(rc);

    lld_register_value_list_t reg_val_list;

    // Override some selected interrupt masks.
    override_masks_ts_ms(reg_val_list);
    override_masks_hbm(reg_val_list);
    override_masks_tcam_parity(reg_val_list);
    override_masks_mem_protect(reg_val_list);

    // Combine multiple writes to same register using OR logic
    lld_unordered_merge_register_value_list(reg_val_list);

    // Since some CIF interrupts are masked, we need to clear SBIF too, so that
    // summary bits that correspond to pending but masked CIF interrupts will be cleared.
    clear_sbif_interrupts(reg_val_list);

    rc = lld_write_register_list(m_ll_device, reg_val_list);
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
    atomic_init(&m_device_properties[(int)la_device_property_e::GB_INITIALIZE_CONFIG_MEMORIES].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::GB_INITIALIZE_OTHER].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::GB_A1_DISABLE_FIXES].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::GB_A2_DISABLE_FIXES].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::USING_LEABA_NIC].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_LPM_IP_CACHE].bool_val, true);

    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_MBIST_REPAIR].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::IGNORE_MBIST_ERRORS].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_NARROW_COUNTERS].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_MPLS_SR_ACCOUNTING].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_PBTS].bool_val, false);
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
    atomic_init(&m_device_properties[(int)la_device_property_e::DISABLE_SERDES_POST_ANLT_TUNE].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SERDES_PRE_ICAL_PRIOR_ANLT].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::SERDES_DFE_EID].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SERDES_TX_REFRESH].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SERDES_TX_SLIP].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_IGNORE_LONG_TUNE].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_ENABLE_25G_DFETAP_CHECK].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_ENABLE_SER_CHECK].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SERDES_LOW_POWER].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_MAC_PORT_DEGRADED_SER_NOTIFICATIONS].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::RECONNECT_IGNORE_IN_FLIGHT].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::IGNORE_SBUS_MASTER_MBIST_FAILURE].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SENSOR_POLL].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_FE_PER_DEVICE_MIN_LINKS].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::SLEEP_IN_SET_MAX_BURST].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::STATISTICAL_METER_COUNTING].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_ECN_QUEUING].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SERDES_LDO_VOLTAGE_REGULATOR].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_SRM_OVERRIDE_PLL_KP_KF].bool_val, true);
    atomic_init(&m_device_properties[(int)la_device_property_e::IGNORE_COMPONENT_INIT_FAILURES].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::PACIFIC_PFC_HBM_ENABLED].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_POWER_SAVING_MODE].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::FORCE_DISABLE_HBM].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::HBM_SKIP_TRAINING].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_DUMMY_SERDES_HANDLER].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::DESTINATION_SYSTEM_PORT_IN_IBM_METADATA].bool_val, false);
    atomic_init(&m_device_properties[(int)la_device_property_e::ENABLE_BOOT_OPTIMIZATION].bool_val, true);
}

void
la_device_impl::initialize_device_int_properties()
{

    la_device_property_e unsupported_device_properties[] = {
        la_device_property_e::STATISTICAL_METER_MULTIPLIER,
        la_device_property_e::TEMPERATURE_SENSOR_POLL_FAILURE_TIMEOUT_MILLISECONDS,
        la_device_property_e::AAPL_IFG_DELAY_BEFORE_EXEC,
        la_device_property_e::AAPL_HBM_DELAY_BEFORE_EXEC,
        la_device_property_e::AAPL_IFG_DELAY_BEFORE_POLL,
        la_device_property_e::AAPL_HBM_DELAY_BEFORE_POLL,
        la_device_property_e::AAPL_IFG_DELAY_IN_POLL,
        la_device_property_e::AAPL_IFG_POLL_TIMEOUT,
        la_device_property_e::LPTS_MAX_ENTRY_COUNTERS,
        la_device_property_e::MAC_PORT_SAVE_STATE_SERDES_DEBUG_SNAPSHOTS,
        la_device_property_e::LINKUP_TIME_BEFORE_SERDES_REFRESH,
        la_device_property_e::ENABLE_SERDES_TX_REFRESH,
        la_device_property_e::DEV_REFCLK_SEL,
        la_device_property_e::EFUSE_REFCLK_SETTINGS,
        la_device_property_e::LC_56_FABRIC_PORT_MODE,
        la_device_property_e::PACIFIC_PFC_PILOT_PROBABILITY,
        la_device_property_e::PACIFIC_PFC_MEASUREMENT_PROBABILITY,
        la_device_property_e::NUM_MULTIPORT_PHY,
    };
    for (int i = 0; i < (int)(sizeof(unsupported_device_properties) / sizeof(la_device_property_e)); i++) {
        atomic_init(&m_device_properties[(int)unsupported_device_properties[i]].supported, false);
    }
    atomic_init(&m_device_properties[(int)la_device_property_e::HBM_FREQUENCY].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::POLL_INTERVAL_MILLISECONDS].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::POLL_FAST_INTERVAL_MILLISECONDS].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::RESTORE_INTERRUPT_MASKS_INTERVAL_MILLISECONDS].int_val, 1000);
    atomic_init(&m_device_properties[(int)la_device_property_e::POLL_NON_WIRED_INTERRUPTS_INTERVAL_MILLISECONDS].int_val, 1000);
    atomic_init(&m_device_properties[(int)la_device_property_e::MSI_DAMPENING_INTERVAL_MILLISECONDS].int_val, 100);
    atomic_init(&m_device_properties[(int)la_device_property_e::MSI_DAMPENING_THRESHOLD].int_val, 10);
    atomic_init(&m_device_properties[(int)la_device_property_e::SENSOR_POLL_INTERVAL_MILLISECONDS].int_val, 100);
    atomic_init(&m_device_properties[(int)la_device_property_e::MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY].int_val,
                (int)DEFAULT_MIN_LINKS_THRESHOLD);
    atomic_init(&m_device_properties[(int)la_device_property_e::SERDES_FW_REVISION].int_val, (int)SERDES_REV);
    atomic_init(&m_device_properties[(int)la_device_property_e::SERDES_FW_BUILD].int_val, (int)SERDES_BUILD);
    atomic_init(&m_device_properties[(int)la_device_property_e::SBUS_MASTER_FW_REVISION].int_val, (int)SBUS_MASTER_REV);
    atomic_init(&m_device_properties[(int)la_device_property_e::SBUS_MASTER_FW_BUILD].int_val, (int)SBUS_MASTER_BUILD);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_TUNE_TIMEOUT].int_val, 30);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_PAM4_MAX_TUNE_RETRY].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_PAM4_MIN_EYE_HEIGHT].int_val, 16);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_NRZ_MIN_EYE_HEIGHT].int_val, 5);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_10G_NRZ_MIN_EYE_HEIGHT].int_val, 5);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_CDR_LOCK_AFTER_TUNE_TIMEOUT].int_val, 10);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_PCS_LOCK_TIME].int_val, 1000);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_SAVE_STATE_SERDES_DEBUG_SNAPSHOTS].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_SAVE_STATE_SM_STATE_TRANSITION_CAPTURES].int_val, 30);
    atomic_init(&m_device_properties[(int)la_device_property_e::NETWORK_MAC_PORT_TUNE_AND_PCS_LOCK_ITER].int_val, 1);
    atomic_init(&m_device_properties[(int)la_device_property_e::FABRIC_MAC_PORT_TUNE_AND_PCS_LOCK_ITER].int_val, 1);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_AUTO_NEGOTIATION_TIMEOUT].int_val, 500);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_LINK_TRAINING_TIMEOUT].int_val, 3);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_NRZ_LINK_TRAINING_TIMEOUT].int_val, 1000);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAC_PORT_PAM4_LINK_TRAINING_TIMEOUT].int_val, 3000);
    atomic_init(&m_device_properties[(int)la_device_property_e::SERDES_RXA_POWER_SEQUENCE_MODE].int_val, 1);
    atomic_init(&m_device_properties[(int)la_device_property_e::SERDES_CL136_PRESET_TYPE].int_val, 1);
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
    atomic_init(&m_device_properties[(int)la_device_property_e::SGACL_MAX_CELL_COUNTERS].int_val,
                (int)DEFAULT_SGACL_MAX_CELL_COUNTERS);
    atomic_init(&m_device_properties[(int)la_device_property_e::DEVICE_FREQUENCY].int_val, (int)DEFAULT_DEVICE_FREQUENCY);
    atomic_init(&m_device_properties[(int)la_device_property_e::MATILDA_MODEL_TYPE].int_val,
                (int)matilda_model_e::GIBRALTAR_REGULAR);
    atomic_init(&m_device_properties[(int)la_device_property_e::TCK_FREQUENCY].int_val, (int)DEFAULT_TCK_FREQUENCY);
    atomic_init(&m_device_properties[(int)la_device_property_e::MAX_COUNTER_THRESHOLD].int_val, (int)DEFAULT_MAX_COUNTER_THRESHOLD);
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
    atomic_init(&m_device_properties[(int)la_device_property_e::MAX_NUMBER_OF_PERIODIC_SAVE_STATE_FILES].int_val, 10);
    atomic_init(&m_device_properties[(int)la_device_property_e::MULTICAST_MCID_SCALE_THRESHOLD].int_val,
                (int)la_device_impl::MAX_MC_LOCAL_MCID);
    atomic_init(&m_device_properties[(int)la_device_property_e::LINKUP_TIME_BEFORE_SERDES_REFRESH].int_val, 0);
    atomic_init(&m_device_properties[(int)la_device_property_e::OOB_INJ_CREDITS].int_val, 1);
    atomic_init(&m_device_properties[(int)la_device_property_e::CREDIT_SIZE_IN_BYTES].int_val, 2048);
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
    // slice 0 is just an arbitrary slice
    la_slice_id_t rep_sid = first_active_slice_id();
    lld_register_value_list_t reg_val_list;
    // configure lb vector profile 1 to read the sip + dip again
    gibraltar::rxpp_fwd_res_lb_profile_fs_insturctions_reg_register second_sip_dip;
    la_status status = m_ll_device->read_register(
        (*m_gb_tree->slice[rep_sid]
              ->npu->rxpp_fwd->top->res_lb_profile_fs_insturctions_reg)[npu_static_config::LB_FS_IPV4_DOUBLE_SIP_DIP_PROFILE],
        second_sip_dip);

    // fs[0-1]_instruction refers to the desired part to be fetched from the packet:
    // [11:6] - offset in Bytes, [5:0] - size in bits
    // fs[0-1]_instruction are applied in 'resolution_compound_utils.npl' -> apply_field_select()
    second_sip_dip.fields.res_lb_key_fs0_instruction
        = 0x320; //	SIP:	0x320 = (001100 100000) -> offset = 12 [Bytes], size = 32 [bits]
    second_sip_dip.fields.res_lb_key_fs1_instruction
        = 0x420; //	DIP:	0x420 = (010000 100000) -> offset = 16 [Bytes], size = 32 [bits]

    // configure lb vector profile 2 to take ipv6 partial dip
    gibraltar::rxpp_fwd_res_lb_profile_fs_insturctions_reg_register fs_instruction_ipv6_partial_dip;
    status = m_ll_device->read_register( // slice 0 is just an arbitrary slice
        (*m_gb_tree->slice[rep_sid]
              ->npu->rxpp_fwd->top->res_lb_profile_fs_insturctions_reg)[npu_static_config::LB_FS_IPV6_EXTRA_PARTIAL_DIP_PROFILE],
        fs_instruction_ipv6_partial_dip);

    // fs[0-1]_instruction refers to the desired part to be fetched from the packet:
    // [11:6] - offset in Bytes, [5:0] - size in bits
    // fs[0-1]_instruction are applied in 'resolution_compound_utils.npl' -> apply_field_select()
    fs_instruction_ipv6_partial_dip.fields.res_lb_key_fs0_instruction
        = 0x760; // IPV6_DIP[87:56]:	0x760 = (011101 100000) -> offset = 29 [Bytes], size = 32 [bits]

    // configure lb vector profile 3 to take ethernet partial sa and da
    gibraltar::rxpp_fwd_res_lb_profile_fs_insturctions_reg_register fs_instruction_eth_partial_sa_da;
    status = m_ll_device->read_register( // slice 0 is just an arbitrary slice
        (*m_gb_tree->slice[rep_sid]
              ->npu->rxpp_fwd->top->res_lb_profile_fs_insturctions_reg)[npu_static_config::LB_FS_ETH_EXTRA_PARTIAL_SA_DA_PROFILE],
        fs_instruction_eth_partial_sa_da);

    // fs[0-1]_instruction refers to the desired part to be fetched from the packet:
    // [11:6] - offset in Bytes, [5:0] - size in bits
    // fs[0-1]_instruction are applied in 'resolution_compound_utils.npl' -> apply_field_select()
    fs_instruction_eth_partial_sa_da.fields.res_lb_key_fs0_instruction
        = 0x220; // SA[47:16]:    0x220 = (001000 100000) -> offset = 8 [Bytes], size = 32 [bits]
    fs_instruction_eth_partial_sa_da.fields.res_lb_key_fs1_instruction
        = 0xa0; // DA[47:16]: 0xa0 = (000010 100000) -> offset = 2 [Bytes], size = 32 [bits]

    // configure lb vector profile 7 to take ethernet partial sa
    gibraltar::rxpp_fwd_res_lb_profile_fs_insturctions_reg_register fs_instruction_eth_vlan_partial_sa;
    status = m_ll_device->read_register( // slice 0 is just an arbitrary slice
        (*m_gb_tree->slice[rep_sid]
              ->npu->rxpp_fwd->top->res_lb_profile_fs_insturctions_reg)[npu_static_config::LB_FS_ETH_VLAN_EXTRA_PARTIAL_SA_PROFILE],
        fs_instruction_eth_vlan_partial_sa);
    fs_instruction_eth_vlan_partial_sa.fields.res_lb_key_fs0_instruction
        = 0x1e0; // SA[39:8]:	0x1e0 = (000111 100000) -> offset = 7 [Bytes], size = 32 [bits]

    // Write the modified registers to all slices
    for (la_slice_id_t slice : get_used_slices()) {
        reg_val_list.push_back(
            {(*m_gb_tree->slice[slice]
                   ->npu->rxpp_fwd->top->res_lb_profile_fs_insturctions_reg)[npu_static_config::LB_FS_IPV4_DOUBLE_SIP_DIP_PROFILE],
             second_sip_dip});
        reg_val_list.push_back(
            {(*m_gb_tree->slice[slice]
                   ->npu->rxpp_fwd->top
                   ->res_lb_profile_fs_insturctions_reg)[npu_static_config::LB_FS_IPV6_EXTRA_PARTIAL_DIP_PROFILE],
             fs_instruction_ipv6_partial_dip});
        reg_val_list.push_back(
            {(*m_gb_tree->slice[slice]
                   ->npu->rxpp_fwd->top
                   ->res_lb_profile_fs_insturctions_reg)[npu_static_config::LB_FS_ETH_EXTRA_PARTIAL_SA_DA_PROFILE],
             fs_instruction_eth_partial_sa_da});
        reg_val_list.push_back(
            {(*m_gb_tree->slice[slice]
                   ->npu->rxpp_fwd->top
                   ->res_lb_profile_fs_insturctions_reg)[npu_static_config::LB_FS_ETH_VLAN_EXTRA_PARTIAL_SA_PROFILE],
             fs_instruction_eth_vlan_partial_sa});
    }

    // Commit the changes
    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::turn_off_registers_for_matilda()
{

    std::vector<lld_register_sptr> power_down_regs;
    std::vector<la_block_id_t> powered_down_blocks;
    bool write_to_device = m_ll_device->get_write_to_device();
    m_ll_device->set_write_to_device(true);

    // m_ll_device->reset();
    // m_ll_device->reset_access_engines();
    // should enable the burst mode here, write to register without waiting for response.
    // void * out_val=nullptr;
    // la_status stat = m_ll_device->read_register(m_gb_tree->sbif->acc_eng_global_cfg_reg, 3 );
    // return_on_error(stat);
    // int * data =static_cast<int *>(out_val);
    // *(data+0)=1;//val.burst_write_mode = 1;
    // la_status stat = m_ll_device->write_register(m_gb_tree->sbif->acc_eng_global_cfg_reg,3, data);
    // return_on_error(stat);

    // for (la_slice_id_t sid: m_slice_id_manager->get_all_possible_slices())
    for (la_slice_id_t sid = 0; sid < m_slice_id_manager->num_slices_per_device(); sid++) {
        // disable only the invalid slices
        if (m_slice_id_manager->is_slice_valid(sid) == LA_STATUS_SUCCESS) {

            continue;
        }
        log_info(HLD, "-------------------------------%s---- turning off slice %d", __func__, sid);
        // set the slice mode to disabled
        m_slice_mode[sid] = la_slice_mode_e::DISABLED;
        // RxPP Term
        power_down_regs.push_back(m_gb_tree->slice[sid]->npu->rxpp_term->flc_db->power_down_configuration);
        power_down_regs.push_back(m_gb_tree->slice[sid]->npu->rxpp_term->fi_stage->power_down_configuration);
        power_down_regs.push_back(m_gb_tree->slice[sid]->npu->rxpp_term->sna->power_down_configuration);

        for (size_t i = 0; i < 3; i++) {
            power_down_regs.push_back(m_gb_tree->slice[sid]->npu->rxpp_term->npe[i]->power_down_configuration);
        }
        for (size_t i = 0; i < 8; i++) {
            power_down_regs.push_back(m_gb_tree->slice[sid]->npu->rxpp_term->fi_eng[i]->power_down_configuration);
        }

        // RxPP Fwd
        power_down_regs.push_back(m_gb_tree->slice[sid]->npu->rxpp_fwd->cdb_cache->power_down_configuration);
        power_down_regs.push_back(m_gb_tree->slice[sid]->npu->rxpp_fwd->flc_queues->power_down_configuration);

        for (size_t i = 0; i < 3; i++) {
            power_down_regs.push_back(m_gb_tree->slice[sid]->npu->rxpp_fwd->npe[i]->power_down_configuration);
        }

        // TxPP

        for (size_t i = 0; i < 2; i++) {
            power_down_regs.push_back(m_gb_tree->slice[sid]->npu->txpp->npe[i]->power_down_configuration);
        }

        for (size_t i = 0; i < 2; i++) {
            power_down_regs.push_back(m_gb_tree->slice[sid]->npu->txpp->ene_cluster[i]->power_down_configuration);
        }
        // top registers
        power_down_regs.push_back(m_gb_tree->slice[sid]->npu->txpp->top->power_down_configuration);
        power_down_regs.push_back(m_gb_tree->slice[sid]->npu->rxpp_fwd->top->power_down_configuration);
        power_down_regs.push_back(m_gb_tree->slice[sid]->npu->rxpp_term->top->power_down_configuration);

        for (auto block_itr : m_gb_tree->slice[sid]->npu->rxpp_term->get_leaf_blocks()) {
            powered_down_blocks.push_back(block_itr->get_block_id());
        }
        for (auto block_itr : m_gb_tree->slice[sid]->npu->rxpp_fwd->get_leaf_blocks()) {
            powered_down_blocks.push_back(block_itr->get_block_id());
        }
        for (auto block_itr : m_gb_tree->slice[sid]->npu->txpp->get_leaf_blocks()) {
            powered_down_blocks.push_back(block_itr->get_block_id());
        }

        //  GB IFGs
        for (size_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ifg_id++) {
            power_down_regs.push_back(m_gb_tree->slice[sid]->ifg[ifg_id]->ifgb->power_down_configuration);
            for (auto block_itr : m_gb_tree->slice[sid]->ifg[ifg_id]->ifgb->get_leaf_blocks()) {
                powered_down_blocks.push_back(block_itr->get_block_id());
            }
            size_t serdes_count = m_ifg_handlers[sid][ifg_id]->get_serdes_count();
            if (serdes_count == 16) {
                for (size_t m = 0; m < 2; m++) {
                    power_down_regs.push_back(m_gb_tree->slice[sid]->ifg[ifg_id]->mac_pool8[m]->power_down_configuration);
                    for (auto block_itr : m_gb_tree->slice[sid]->ifg[ifg_id]->mac_pool8[m]->get_leaf_blocks()) {
                        powered_down_blocks.push_back(block_itr->get_block_id());
                    }
                }
            } else { // serdes_count==24
                for (size_t m = 0; m < 3; m++) {
                    power_down_regs.push_back(m_gb_tree->slice[sid]->ifg[ifg_id]->mac_pool8[m]->power_down_configuration);
                    for (auto block_itr : m_gb_tree->slice[sid]->ifg[ifg_id]->mac_pool8[m]->get_leaf_blocks()) {
                        powered_down_blocks.push_back(block_itr->get_block_id());
                    }
                }
            }
        }
    }
    for (la_slice_id_t sid = 0; sid < m_slice_id_manager->num_slice_pairs_per_device(); sid++) {
        // disable only the invalid slice pairs
        if (m_slice_id_manager->is_slice_pair_valid(sid) == LA_STATUS_SUCCESS) {
            continue;
        }
        for (auto block_itr : m_gb_tree->slice_pair[sid]->rx_pdr->get_leaf_blocks()) {
            powered_down_blocks.push_back(block_itr->get_block_id());
        }
    }

    m_ll_device->set_write_burst(true);
    for (lld_register_sptr reg_ptr : power_down_regs) {
        // log_err(HLD, "------- powering down register.");
        la_status stat = m_ll_device->write_register(reg_ptr, 1);
        return_on_error(stat);
    }
    m_ll_device->set_write_burst(false);
    m_ll_device->set_write_to_device(write_to_device);

    ll_filtered_device_impl* ll_dev = dynamic_cast<ll_filtered_device_impl*>(m_ll_device.get());
    for (la_block_id_t b_id : powered_down_blocks) {
        la_status stat = ll_dev->disable_block(b_id);
        return_on_error(stat);
    }
    return LA_STATUS_SUCCESS;
}

uint64_t
la_device_impl::get_rxpp_term_interrupt_summary_mask() const
{
    bit_vector mask = bit_vector::ones(m_slice_id_manager->num_slices_per_device()); // rxpp_term interrupt summary is 6 bits lsb
    for (la_slice_id_t slice : get_used_slices()) {
        mask.set_bit(slice, 0);
    }

    return mask.get_value();
}

la_status
la_device_impl::turn_off_hbm_and_mmu_blocks()
{
    std::vector<la_block_id_t> powered_down_blocks;

    bool write_to_device = m_ll_device->get_write_to_device();
    if (!write_to_device) {
        log_debug(HLD, "%s : Write to device is disabled. MMU and HBM blocks off for power saving", __func__);
        return LA_STATUS_SUCCESS;
    }

    m_ll_device->set_write_burst(true);

    // Power down MMU blocks
    gibraltar::mmu_power_down_configuration_register mmu_reg_val = {{0}};
    mmu_reg_val.fields.power_down = 0x1;
    la_status status = m_ll_device->write_register(m_gb_tree->mmu->power_down_configuration, mmu_reg_val);
    return_on_error(status);

    gibraltar::mmu_buff_power_down_configuration_register mmu_buff_reg_val = {{0}};
    mmu_buff_reg_val.fields.power_down = 0x1;
    status = m_ll_device->write_register(m_gb_tree->mmu_buff->power_down_configuration, mmu_buff_reg_val);
    return_on_error(status);

    // Power down HBM blocks
    gibraltar::hbm_power_down_configuration_register hbm_reg_val = {{0}};
    hbm_reg_val.fields.power_down = 0x1;
    status = m_ll_device->write_register(m_gb_tree->hbm->db[0]->power_down_configuration, hbm_reg_val);
    return_on_error(status);
    status = m_ll_device->write_register(m_gb_tree->hbm->db[1]->power_down_configuration, hbm_reg_val);
    return_on_error(status);

    for (int i = 0; i < 8; i++) {
        gibraltar::hbm_chnl_4x_tall_power_down_configuration_register hbm_chnl_val;
        hbm_chnl_val.fields.power_down = 0x1;
        status = m_ll_device->write_register(m_gb_tree->hbm->chnl[i]->power_down_configuration, hbm_chnl_val);
        return_on_error(status);
    }

    m_ll_device->set_write_burst(false);

    disable_hbm_powered_down_blocks();

    log_debug(HLD, "%s : MMU and HBM blocks off for power saving", __func__);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::rxpp_use_single_npe_on_fabric_slices()
{
    la_slice_id_vec_t fabric_slices;
    for (la_slice_id_t slice : get_used_slices()) {
        if (m_slice_mode[slice] == la_slice_mode_e::CARRIER_FABRIC || m_slice_mode[slice] == la_slice_mode_e::DC_FABRIC) {
            fabric_slices.push_back(slice);
        }
    }

    if (fabric_slices.empty()) {
        return LA_STATUS_SUCCESS;
    }

    gibraltar::rxpp_term_power_down_configuration_register rxpp_term_power_down_cfg_reg_val = {{0}};
    gibraltar::rxpp_fwd_power_down_configuration_register rxpp_fwd_power_down_cfg_reg_val = {{0}};
    gibraltar::rxpp_term_issu_states_register issu_states_reg_val = {{0}};

    // Configure engines not to process packets
    issu_states_reg_val.fields.rxpp_input_issu_state = 0x1;
    issu_states_reg_val.fields.term0_input_issu_state = 0x1;
    issu_states_reg_val.fields.term0_output_issu_state = 0x1;
    issu_states_reg_val.fields.fwd0_input_issu_state = 0x1;
    for (la_slice_id_t slice : fabric_slices) {
        la_status status
            = m_ll_device->write_register(m_gb_tree->slice[slice]->npu->rxpp_term->top->issu_states, issu_states_reg_val);
        return_on_error(status);
    }

    bool write_to_device = m_ll_device->get_write_to_device();
    if (!write_to_device) {
        log_info(HLD, "Write to device is disabled. Using single NPE(0) for termination and forwarding on fabric slices");
        return LA_STATUS_SUCCESS;
    }

    m_ll_device->set_write_burst(true);

    // Power off non-used engines
    rxpp_term_power_down_cfg_reg_val.fields.power_down = 0x1;
    rxpp_fwd_power_down_cfg_reg_val.fields.power_down = 0x1;

    for (la_slice_id_t slice : fabric_slices) {
        la_status status = m_ll_device->write_register(m_gb_tree->slice[slice]->npu->rxpp_term->npe[1]->power_down_configuration,
                                                       rxpp_term_power_down_cfg_reg_val);
        return_on_error(status);
        status = m_ll_device->write_register(m_gb_tree->slice[slice]->npu->rxpp_term->npe[2]->power_down_configuration,
                                             rxpp_term_power_down_cfg_reg_val);
        return_on_error(status);

        status = m_ll_device->write_register(m_gb_tree->slice[slice]->npu->rxpp_fwd->npe[1]->power_down_configuration,
                                             rxpp_fwd_power_down_cfg_reg_val);
        return_on_error(status);
        status = m_ll_device->write_register(m_gb_tree->slice[slice]->npu->rxpp_fwd->npe[2]->power_down_configuration,
                                             rxpp_fwd_power_down_cfg_reg_val);
        return_on_error(status);
    }

    disable_npe_powered_down_blocks();

    m_ll_device->set_write_burst(false);

    log_info(HLD, "Using single NPE(0) for termination and forwarding on fabric slices");

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::turn_off_idb_res_and_encdb_blocks()
{
    la_status status;

    bool write_to_device = m_ll_device->get_write_to_device();
    if (!write_to_device) {
        log_debug(HLD, "%s : Write to device is disabled. IDB_RES and IDB_ENCDB blocks off for power saving.", __func__);
        return LA_STATUS_SUCCESS;
    }

    m_ll_device->set_write_burst(true);

    // Power down IDB_RES and IDB_ENCDB block
    gibraltar::res_power_down_configuration_register res_power_down_cfg_reg_val = {{0}};
    gibraltar::idb_encdb_power_down_configuration_register idb_encdb_power_down_cfg_reg_val = {{0}};

    res_power_down_cfg_reg_val.fields.power_down = 0x1;
    idb_encdb_power_down_cfg_reg_val.fields.power_down = 0x1;

    la_slice_id_vec_t used_slices = get_used_slices();

    for (la_slice_pair_id_t pair_idx : get_used_slice_pairs()) {
        // get first and second slice of slice_pair
        auto pair_idx_first_slice = pair_idx * 2;
        auto pair_idx_second_slice = pair_idx * 2 + 1;

        // check if slices in slice_pair are valid
        if (contains(used_slices, pair_idx_first_slice) && contains(used_slices, pair_idx_second_slice)) {
            // check if slices in slice_pair are FABRIC
            bool is_pair_idx_first_slice_fabric = m_slice_mode[pair_idx_first_slice] == la_slice_mode_e::CARRIER_FABRIC
                                                  || m_slice_mode[pair_idx_first_slice] == la_slice_mode_e::DC_FABRIC;

            bool is_pair_idx_second_slice_fabric = m_slice_mode[pair_idx_second_slice] == la_slice_mode_e::CARRIER_FABRIC
                                                   || m_slice_mode[pair_idx_second_slice] == la_slice_mode_e::DC_FABRIC;

            // if both slices are valid and fabric, power_down idb_res and idb_encdb
            if (is_pair_idx_first_slice_fabric && is_pair_idx_second_slice_fabric) {
                status = m_ll_device->write_register(m_gb_tree->slice_pair[pair_idx]->idb->res->power_down_configuration,
                                                     res_power_down_cfg_reg_val);
                return_on_error(status);

                status = m_ll_device->write_register(m_gb_tree->slice_pair[pair_idx]->idb->encdb->power_down_configuration,
                                                     idb_encdb_power_down_cfg_reg_val);
                return_on_error(status);
            }
        }
    }

    m_ll_device->set_write_burst(false);

    disable_idb_res_and_encdb_powered_down_blocks();

    log_debug(HLD, "%s: IDB_RES and IDB_ENCDB blocks off for power saving.", __func__);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
