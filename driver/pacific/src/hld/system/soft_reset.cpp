// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include <array>
#include <cstring>
#include <ctime>
#include <map>
#include <vector>

#include "api/types/la_limit_types.h"
#include "api_tracer.h"
#include "common/bit_vector.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "hw_tables/cem.h"
#include "hw_tables/hw_tables_fwd.h"
#include "la_device_impl.h"
#include "lld/ll_device.h"
#include "lld/lld_block.h"
#include "lld/lld_memory.h"
#include "lld/lld_register.h"
#include "lld/lld_strings.h"
#include "lld/lld_utils.h"
#include "lld/pacific_mem_structs.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"
#include "npu/la_bfd_session_base.h"
#include "ra/resource_manager.h"
#include "system/fabric_init_handler.h"
#include "system/la_fabric_port_impl.h"
#include "system/la_hbm_handler_impl.h"
#include "system/la_pci_port_base.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_output_queue_scheduler_impl.h"
#include "tm/tm_utils.h"

namespace silicon_one
{

// Hold a list of memory-line values for a single memory block
typedef std::vector<std::pair<lld_memory_scptr, std::vector<bit_vector> > > memory_lines_t;

// State of packet-DMA
struct packet_dma_state_t {
    std::vector<la_pci_port_base*> pci_ports; // PCI ports state
};

// Hold the rstn register state in mac-pools of a single IFG
struct ifg_mac_pool_state {
    std::array<mac_pool8_rstn_reg_register, 2> mp8;
    mac_pool2_rstn_reg_register mp2;
    bool mac_pool2_already_restored;
    ifg_mac_pool_state() : mac_pool2_already_restored(false)
    {
    }
};

// Hold the rstn register state in mac-pools of a single device
struct device_mac_pool_state {
    std::array<ifg_mac_pool_state, NUM_IFGS_PER_DEVICE> ifg;
};

// Hold fabric protocol state
struct fabric_protocol_state_t {
    std::vector<frm_fabric_routing_table_memory> frt_lines;
    std::vector<frm_rev_fabric_routing_table_memory> rev_frt_lines;
    std::vector<la_fabric_port_impl*> keepalive_list;
    std::array<uint64_t, ASIC_MAX_SLICES_PER_DEVICE_NUM> orig_ka;
    bool frp_enabled;
};

// Return true iff the name of the given block contains one of the strings in 'filter_vec' (partial match).
static bool
filter_block_by_name(lld_block_scptr block, std::vector<std::string> filter_vec)
{
    auto name = block->get_name();

    for (auto filter : filter_vec) {
        if (name.find(filter) != std::string::npos) {
            return true;
        }
    }

    return false;
}

// De-assert the given block iff the block is already asserted.
// Returns the previous state (asserted or not) of the block.
static la_status
deassert_soft_reset_single(ll_device_sptr ll_dev,
                           lld_block_scptr block,
                           lld_reg_mem_line_value_list_t& write_list,
                           bool& out_is_active)
{
    auto srstn_reg = block->get_register(lld_register::RSTN);
    if (srstn_reg == nullptr) {
        out_is_active = false;

        return LA_STATUS_SUCCESS;
    }

    bit_vector regval_bv;
    la_status status = ll_dev->read_register(srstn_reg, regval_bv);
    return_on_error(status);

    if (regval_bv.get_value() == 1) {
        out_is_active = true;
        write_list.push_back({lld_reg_mem_line(srstn_reg), 0});

        return LA_STATUS_SUCCESS;
    }

    out_is_active = false;

    return LA_STATUS_SUCCESS;
}

static la_status
deassert_soft_reset(ll_device_sptr ll_dev, const std::vector<lld_block_scptr>& blocks, std::vector<bool>& out_is_active)
{
    lld_reg_mem_line_value_list_t write_list;

    out_is_active.resize(blocks.size());

    for (size_t i = 0; i < blocks.size(); i++) {
        bool is_active = false;
        la_status status = deassert_soft_reset_single(ll_dev, blocks[i], write_list, is_active);
        return_on_error(status);
        out_is_active[i] = is_active;
    }

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

// Assert the given block.
static void
assert_soft_reset_single(lld_block_scptr block, lld_reg_mem_line_value_list_t& write_list)
{
    auto srstn_reg = block->get_register(lld_register::RSTN);
    write_list.push_back({lld_reg_mem_line(srstn_reg), 1});
}

static la_status
assert_soft_reset(ll_device_sptr ll_dev, const std::vector<lld_block_scptr> blocks, const std::vector<bool> is_active)
{
    lld_reg_mem_line_value_list_t write_list;

    for (size_t i = 0; i < blocks.size(); i++) {
        if (!is_active[i]) {
            continue;
        }

        assert_soft_reset_single(blocks[i], write_list);
    }

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

// Deassert the mac-pools in the given IFG.
// Returns the previous rstn state of the mac-pools.
static la_status
deassert_mac_pool(ll_device_sptr ll_dev,
                  la_slice_id_t slice,
                  la_ifg_id_t ifg,
                  ifg_mac_pool_state& out_mac_pool_state,
                  lld_register_value_list_t& reg_val_list)
{
    auto pt = ll_dev->get_pacific_tree();
    uint64_t regval = 0;

    // Deassert MAC pool 8
    for (size_t mp = 0; mp < 2; mp++) {
        mac_pool8_rstn_reg_register r8;
        la_status status = ll_dev->read_register(pt->slice[slice]->ifg[ifg]->mac_pool8[mp]->rstn_reg, r8);
        return_on_error(status);

        // Store the current state
        out_mac_pool_state.mp8[mp] = r8;

        // Write the new state to the Tx ports
        r8.fields.tx_mac_rstn0 = regval;
        r8.fields.tx_mac_rstn1 = regval;
        r8.fields.tx_mac_rstn2 = regval;
        r8.fields.tx_mac_rstn3 = regval;
        r8.fields.tx_mac_rstn4 = regval;
        r8.fields.tx_mac_rstn5 = regval;
        r8.fields.tx_mac_rstn6 = regval;
        r8.fields.tx_mac_rstn7 = regval;
        reg_val_list.push_back({(pt->slice[slice]->ifg[ifg]->mac_pool8[mp]->rstn_reg), r8});

        // Write the new state to the Rx ports
        r8.fields.rx_mac_rstn0 = regval;
        r8.fields.rx_mac_rstn1 = regval;
        r8.fields.rx_mac_rstn2 = regval;
        r8.fields.rx_mac_rstn3 = regval;
        r8.fields.rx_mac_rstn4 = regval;
        r8.fields.rx_mac_rstn5 = regval;
        r8.fields.rx_mac_rstn6 = regval;
        r8.fields.rx_mac_rstn7 = regval;
        reg_val_list.push_back({(pt->slice[slice]->ifg[ifg]->mac_pool8[mp]->rstn_reg), r8});
    }

    // Deassert MAC pool 2
    mac_pool2_rstn_reg_register r2;
    la_status status = ll_dev->read_register(pt->slice[slice]->ifg[ifg]->mac_pool2->rstn_reg, r2);
    return_on_error(status);

    // Store the current state
    out_mac_pool_state.mp2 = r2;

    // Write the new state to the Tx ports
    r2.fields.tx_mac_rstn0 = regval;
    r2.fields.tx_mac_rstn1 = regval;
    reg_val_list.push_back({(pt->slice[slice]->ifg[ifg]->mac_pool2->rstn_reg), r2});

    // Write the new state to the Rx ports
    r2.fields.rx_mac_rstn0 = regval;
    r2.fields.rx_mac_rstn1 = regval;
    reg_val_list.push_back({(pt->slice[slice]->ifg[ifg]->mac_pool2->rstn_reg), r2});

    return LA_STATUS_SUCCESS;
}

// Restore the mac-pools in the given IFG.
// Restore the mac-pools in the given IFG.
static la_status
restore_mac_pool8(ll_device_sptr ll_dev,
                  la_slice_id_t slice,
                  la_ifg_id_t ifg,
                  size_t mp,
                  const ifg_mac_pool_state& mac_pool_state,
                  lld_register_value_list_t& reg_val_list)
{
    auto pt = ll_dev->get_pacific_tree();
    mac_pool8_rstn_reg_register r8;
    la_status status = ll_dev->read_register(pt->slice[slice]->ifg[ifg]->mac_pool8[mp]->rstn_reg, r8);
    return_on_error(status);

    // Write the old state to the Rx ports
    r8.fields.rx_mac_rstn0 = mac_pool_state.mp8[mp].fields.rx_mac_rstn0;
    r8.fields.rx_mac_rstn1 = mac_pool_state.mp8[mp].fields.rx_mac_rstn1;
    r8.fields.rx_mac_rstn2 = mac_pool_state.mp8[mp].fields.rx_mac_rstn2;
    r8.fields.rx_mac_rstn3 = mac_pool_state.mp8[mp].fields.rx_mac_rstn3;
    r8.fields.rx_mac_rstn4 = mac_pool_state.mp8[mp].fields.rx_mac_rstn4;
    r8.fields.rx_mac_rstn5 = mac_pool_state.mp8[mp].fields.rx_mac_rstn5;
    r8.fields.rx_mac_rstn6 = mac_pool_state.mp8[mp].fields.rx_mac_rstn6;
    r8.fields.rx_mac_rstn7 = mac_pool_state.mp8[mp].fields.rx_mac_rstn7;
    reg_val_list.push_back({(pt->slice[slice]->ifg[ifg]->mac_pool8[mp]->rstn_reg), r8});

    // Write the old state to the Tx ports
    r8.fields.tx_mac_rstn0 = mac_pool_state.mp8[mp].fields.tx_mac_rstn0;
    r8.fields.tx_mac_rstn1 = mac_pool_state.mp8[mp].fields.tx_mac_rstn1;
    r8.fields.tx_mac_rstn2 = mac_pool_state.mp8[mp].fields.tx_mac_rstn2;
    r8.fields.tx_mac_rstn3 = mac_pool_state.mp8[mp].fields.tx_mac_rstn3;
    r8.fields.tx_mac_rstn4 = mac_pool_state.mp8[mp].fields.tx_mac_rstn4;
    r8.fields.tx_mac_rstn5 = mac_pool_state.mp8[mp].fields.tx_mac_rstn5;
    r8.fields.tx_mac_rstn6 = mac_pool_state.mp8[mp].fields.tx_mac_rstn6;
    r8.fields.tx_mac_rstn7 = mac_pool_state.mp8[mp].fields.tx_mac_rstn7;
    reg_val_list.push_back({(pt->slice[slice]->ifg[ifg]->mac_pool8[mp]->rstn_reg), r8});

    return LA_STATUS_SUCCESS;
}

static la_status
restore_mac_pool2(ll_device_sptr ll_dev,
                  la_slice_id_t slice,
                  la_ifg_id_t ifg,
                  const ifg_mac_pool_state& mac_pool_state,
                  lld_register_value_list_t& reg_val_list)
{
    auto pt = ll_dev->get_pacific_tree();
    mac_pool2_rstn_reg_register r2;
    la_status status = ll_dev->read_register(pt->slice[slice]->ifg[ifg]->mac_pool2->rstn_reg, r2);
    return_on_error(status);

    // Write the old state to the Rx ports
    r2.fields.rx_mac_rstn0 = mac_pool_state.mp2.fields.rx_mac_rstn0;
    r2.fields.rx_mac_rstn1 = mac_pool_state.mp2.fields.rx_mac_rstn1;
    reg_val_list.push_back({(pt->slice[slice]->ifg[ifg]->mac_pool2->rstn_reg), r2});

    // Write the old state to the Tx ports
    r2.fields.tx_mac_rstn0 = mac_pool_state.mp2.fields.tx_mac_rstn0;
    r2.fields.tx_mac_rstn1 = mac_pool_state.mp2.fields.tx_mac_rstn1;
    reg_val_list.push_back({(pt->slice[slice]->ifg[ifg]->mac_pool2->rstn_reg), r2});

    return LA_STATUS_SUCCESS;
}

static la_status
stop_packet_dma(const la_device_impl* la_dev, ll_device_sptr ll_dev, packet_dma_state_t& packet_dma_state)
{
    // Stop PCI ports
    std::vector<la_object*> pci_ports = la_dev->get_objects(la_object::object_type_e::PCI_PORT);
    for (la_object* obj : pci_ports) {
        la_pci_port_base* pp = static_cast<la_pci_port_base*>(static_cast<la_pci_port*>(obj));
        if (pp->is_active()) {
            la_status status = pp->stop();
            return_on_error(status);

            packet_dma_state.pci_ports.push_back(pp);
        }
    }

    return LA_STATUS_SUCCESS;
}

static la_status
start_packet_dma(const la_device_impl* la_dev, ll_device_sptr ll_dev, const packet_dma_state_t& packet_dma_state)
{
    // Start PCI ports
    for (auto pp : packet_dma_state.pci_ports) {
        la_status status = pp->activate();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

// On enter - put all ports in reset mode.
static la_status
stop_mac_pools(const la_device_impl* la_dev, device_mac_pool_state& mac_pool_state, packet_dma_state_t& packet_dma_state)
{
    lld_register_value_list_t reg_val_list;
    auto ll_dev = la_dev->get_ll_device_sptr();

    // Stop packet-DMA traffic
    la_status status = stop_packet_dma(la_dev, ll_dev, packet_dma_state);
    return_on_error(status);

    for (la_slice_id_t slice : la_dev->get_used_slices()) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            size_t ifg_index = la_dev->get_slice_id_manager()->slice_ifg_2_global_ifg(slice, ifg);

            // Stop Network traffic
            status = deassert_mac_pool(ll_dev, slice, ifg, mac_pool_state.ifg[ifg_index], reg_val_list);
            return_on_error(status);
        }
    }

    return lld_write_register_list(ll_dev, reg_val_list);
}

// Stop or start IFGBs
static la_status
start_stop_ifg_buffers(ll_device_sptr ll_dev, const slice_manager_smart_ptr& sid_mgr, bool start)
{
    auto pt = ll_dev->get_pacific_tree();
    uint64_t val = start ? 1 : 0;
    lld_register_value_list_t reg_val_list;

    for (la_slice_id_t slice : sid_mgr->get_used_slices_internal()) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            reg_val_list.push_back({(pt->slice[slice]->ifg[ifg]->ifgb->soft_reset_configuration), val});
        }
    }

    return lld_write_register_list(ll_dev, reg_val_list);
}

// Check if need to restore MAC pool 2
static bool
should_restore_pool2(la_slice_id_t slice,
                     la_ifg_id_t ifg,
                     la_slice_mode_e req_slice_mode,
                     la_slice_mode_e curr_slice_mode,
                     bool is_lc_56_fabric_port_mode,
                     bool mac_pool2_already_restored)
{
    if (!is_lc_56_fabric_port_mode) {
        return (req_slice_mode == curr_slice_mode);
    }

    if ((req_slice_mode == la_slice_mode_e::NETWORK) && (curr_slice_mode == la_slice_mode_e::NETWORK)) {
        return !mac_pool2_already_restored;
    }

    if ((req_slice_mode == la_slice_mode_e::NETWORK) && (curr_slice_mode == la_slice_mode_e::CARRIER_FABRIC)) {
        return false;
    }

    if ((req_slice_mode == la_slice_mode_e::CARRIER_FABRIC) && (curr_slice_mode == la_slice_mode_e::CARRIER_FABRIC)) {
        return true;
    }

    // ((req_slice_mode == la_slice_mode_e::CARRIER_FABRIC) && (curr_slice_mode == la_slice_mode_e::NETWORK))
    return (((slice == 0) && (ifg == 0)) || ((slice == 2) && (ifg == 1)));
}

// On exit - take ports out of reset mode
static la_status
start_mac_pools(const la_device_impl* la_dev,
                device_mac_pool_state& mac_pool_state,
                packet_dma_state_t& packet_dma_state,
                la_slice_mode_e req_slice_mode)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    lld_register_value_list_t reg_val_list;
    bool is_lc_56_fabric_port_mode;
    la_status status = la_dev->get_bool_property(la_device_property_e::LC_56_FABRIC_PORT_MODE, is_lc_56_fabric_port_mode);
    return_on_error(status);

    for (la_slice_id_t slice : la_dev->get_used_slices()) {
        la_slice_mode_e curr_slice_mode;
        status = la_dev->get_slice_mode(slice, curr_slice_mode);
        return_on_error(status);

        bool restore_pool8 = (req_slice_mode == curr_slice_mode);

        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            size_t ifg_index = la_dev->get_slice_id_manager()->slice_ifg_2_global_ifg(slice, ifg);
            ifg_mac_pool_state& imps = mac_pool_state.ifg[ifg_index];
            bool restore_pool2 = should_restore_pool2(
                slice, ifg, req_slice_mode, curr_slice_mode, is_lc_56_fabric_port_mode, imps.mac_pool2_already_restored);

            // Restore network traffic

            // Assert MAC pool 8
            if (restore_pool8) {
                for (size_t mp = 0; mp < 2; mp++) {
                    status = restore_mac_pool8(ll_dev, slice, ifg, mp, imps, reg_val_list);
                    return_on_error(status);
                }
            }

            // Assert MAC pool 2
            if (restore_pool2) {
                status = restore_mac_pool2(ll_dev, slice, ifg, imps, reg_val_list);
                return_on_error(status);
                imps.mac_pool2_already_restored = true;
            }
        }
    }

    status = lld_write_register_list(ll_dev, reg_val_list);
    return_on_error(status);

    if (req_slice_mode == la_slice_mode_e::CARRIER_FABRIC) {
        return LA_STATUS_SUCCESS;
    }

    // Network slices - restore packet-DMA traffic
    return start_packet_dma(la_dev, ll_dev, packet_dma_state);
}

// Read CEM CAM into shadow
static la_status
read_cem_cam(ll_device_sptr ll_dev)
{
    auto pt = ll_dev->get_pacific_tree();

    bool shadow_enabled = ll_dev->get_shadow_read_enabled();
    ll_dev->set_shadow_read_enabled(false);
    size_t num_of_cores = array_size(pt->cdb->core);
    for (size_t core = 0; core < num_of_cores; core++) {
        size_t num_of_cams_in_core = pt->cdb->core[core]->em_cam->get_desc()->instances;
        for (size_t cam = 0; cam < num_of_cams_in_core; cam++) {
            lld_memory_scptr core_mem = (*pt->cdb->core[core]->em_cam)[cam];
            lld_memory_scptr reduced_core_mem = (*pt->cdb->core_reduced[core]->em_cam)[cam];
            size_t num_of_lines_in_cam = reduced_core_mem->get_desc()->entries;
            for (size_t line = 0; line < num_of_lines_in_cam; line++) {
                bit_vector bv1;
                la_status status = ll_dev->read_memory(core_mem, line, bv1);
                return_on_error(status);

                bit_vector bv2;
                status = ll_dev->read_memory(reduced_core_mem, line, bv2);
                return_on_error(status);
            }
        }
    }

    ll_dev->set_shadow_read_enabled(shadow_enabled);

    return LA_STATUS_SUCCESS;
}

// Return true iff the given memory need to be restored after soft reset
static bool
need_to_restore_em_cam(const lld_memory_desc_t* desc)
{
    static const char* config_marked_as_dynamic[] = {
        "LLD_MEMORY_RXPP_TERM_TUNNEL_TERMINATION", "LLD_MEMORY_SDB_", "LLD_MEMORY_IDB_",
    };

    if (desc->type == lld_memory_type_e::CONFIG) {
        return true;
    }

    log_debug(SOFT_RESET,
              "%s: name=%s addr=%x width_bits=%u width_total=%u width_total_bits=%u "
              "entries=%u instances=%u wrapper=%s type=%s subtype=%s protection=%s readable=%d writable=%d",
              __func__,
              desc->name.c_str(),
              desc->addr,
              desc->width_bits,
              desc->width_total,
              desc->width_total_bits,
              desc->entries,
              desc->instances,
              desc->wrapper.c_str(),
              to_string(desc->type).c_str(),
              to_string(desc->subtype).c_str(),
              to_string(desc->protection).c_str(),
              desc->readable,
              desc->writable);

    for (size_t i = 0; i < array_size(config_marked_as_dynamic); i++) {
        if (strncmp(desc->name.c_str(), config_marked_as_dynamic[i], strlen(config_marked_as_dynamic[i])) == 0) {
            return true;
        }
    }

    return false;
}

// Restore the given memory
static la_status
restore_em_cam(ll_device_sptr ll_dev, lld_memory_scptr mem)
{
    // auto desc = mem->get_desc();
    // log_debug(SOFT_RESET,
    //              "%s: mem %s(%s) type is %s. number of entries: %0d",
    //              __func__, mem->get_name().c_str(), desc->name.c_str(), desc->wrapper, desc->entries);

    // TODO replace with bulk read/write when implemented
    for (size_t line = 0; line < mem->get_desc()->entries; line++) {
        la_status status = ll_dev->refresh_memory(*mem, line);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

static la_status
save_frt(la_device_impl* la_dev, fabric_protocol_state_t& fps)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();

    auto& frt = pt->dmc->frm->fabric_routing_table;
    auto& rev_frt = pt->dmc->frm->rev_fabric_routing_table;
    size_t frt_entries_nr = frt->get_desc()->entries;
    size_t rev_frt_entries_nr = rev_frt->get_desc()->entries;

    fps.frt_lines.clear();
    fps.frt_lines.reserve(frt_entries_nr);
    fps.rev_frt_lines.clear();
    fps.rev_frt_lines.reserve(rev_frt_entries_nr);
    // FRT
    for (size_t idx = 0; idx < frt_entries_nr; idx++) {
        frm_fabric_routing_table_memory line;
        la_status status = ll_dev->read_memory(frt, idx, line);
        return_on_error(status);
        fps.frt_lines.push_back(line);
    }
    // Reverse FRT
    for (size_t idx = 0; idx < rev_frt_entries_nr; idx++) {
        frm_rev_fabric_routing_table_memory line;
        la_status status = ll_dev->read_memory(rev_frt, idx, line);
        return_on_error(status);
        fps.rev_frt_lines.push_back(line);
    }
    return LA_STATUS_SUCCESS;
}

static la_status
restore_frt(la_device_impl* la_dev, fabric_protocol_state_t& frp)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();

    auto& frt = pt->dmc->frm->fabric_routing_table;
    auto& rev_frt = pt->dmc->frm->rev_fabric_routing_table;
    size_t frt_entries_nr = frt->get_desc()->entries;
    size_t rev_frt_entries_nr = rev_frt->get_desc()->entries;

    lld_memory_line_value_list_t write_list;

    // FRT
    for (size_t idx = 0; idx < frt_entries_nr; idx++) {
        bit_vector line = frp.frt_lines[idx];
        // Bit 0 has to be reverse of the same bit in RFRT
        // in order for the updates to be replicated to other
        // blocks. This a HW requirement.
        // It will be automatically set to the value from RFRT
        // by the HW, when the scan is triggered.
        bool bit0 = line.bit(0);
        line.set_bit(0, !bit0);
        write_list.push_back({{frt, idx}, line});
    }
    // Reverse FRT
    for (size_t idx = 0; idx < rev_frt_entries_nr; idx++) {
        write_list.push_back({{rev_frt, idx}, frp.rev_frt_lines[idx]});
    }

    la_status status = lld_write_memory_line_list(ll_dev, write_list);
    return_on_error(status);

    // Trigger scan so that writting above will take effect.
    status = la_dev->trigger_frt_scan();

    return status;
}

// Clear fabric routing table
static la_status
clear_frt(la_device_impl* la_dev)
{
    log_info(SOFT_RESET, "Clearing fabric routing table ...");
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();
    lld_memory_line_value_list_t mem_line_val_list;

    // FRT
    size_t entries_nr = pt->dmc->frm->fabric_routing_table->get_desc()->entries;
    for (size_t line = 0; line < entries_nr; line++) {
        mem_line_val_list.push_back({{pt->dmc->frm->fabric_routing_table, line}, 0});
    }

    // Reverse FRT
    entries_nr = pt->dmc->frm->rev_fabric_routing_table->get_desc()->entries;
    for (size_t line = 0; line < entries_nr; line++) {
        mem_line_val_list.push_back({{pt->dmc->frm->rev_fabric_routing_table, line}, 0});
    }

    la_status status = lld_write_memory_line_list(ll_dev, mem_line_val_list);
    return_on_error(status);

    // Allow the FRT to be reconstructed
    for (size_t _sleep = 0; _sleep < 64ull; _sleep++) {
        __builtin_ia32_pause();
    }

    log_info(SOFT_RESET, "Done.");

    return LA_STATUS_SUCCESS;
}

// Restore or clear the data in EM memories
static la_status
restore_em_cam_data(ll_device_sptr ll_dev)
{
    auto pt = ll_dev->get_pacific_tree();
    auto blocks = pt->get_leaf_blocks();
    la_status status = LA_STATUS_EUNKNOWN;

    for (auto block : blocks) {
        auto memories = block->get_memories();
        for (auto mem : memories) {
            auto desc = mem->get_desc();

            if (desc->subtype != lld_memory_subtype_e::REG_CAM) {
                continue;
            }

            if (need_to_restore_em_cam(desc)) {
                status = restore_em_cam(ll_dev, mem);
                return_on_error(status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

// Deassert soft-reset in DMC
static la_status
dmc_deassert_soft_reset(ll_device_sptr ll_dev, std::vector<lld_block_scptr>& blocks, std::vector<bool>& out_is_active)
{
    auto pt = ll_dev->get_pacific_tree();

    blocks = {pt->dmc->frm, pt->dmc->fte, pt->dmc->pier, pt->dmc->mrb, pt->csms};

    return deassert_soft_reset(ll_dev, blocks, out_is_active);
}

// Deassert soft-reset in SMS module
static la_status
sms_deassert_soft_reset(ll_device_sptr ll_dev, std::vector<lld_block_scptr>& blocks, std::vector<bool>& out_is_active)
{
    auto pt = ll_dev->get_pacific_tree();

    lld_reg_mem_line_value_list_t write_list;
    blocks = {pt->sms_quad[0], pt->sms_quad[1], pt->sms_quad[2], pt->sms_quad[3], pt->sms_main};

    return deassert_soft_reset(ll_dev, blocks, out_is_active);
}

// Pause/resume ICS module according to the given argument
static la_status
ics_pause_resume(ll_device_sptr ll_dev, const slice_manager_smart_ptr& sid_mgr, bool pause)
{
    auto pt = ll_dev->get_pacific_tree();
    lld_reg_mem_line_value_list_t write_list;

    for (la_slice_id_t slice : sid_mgr->get_used_slices_internal()) {
        ics_slice_general_conf_reg_register reg;

        la_status status = ll_dev->read_register(pt->slice[slice]->ics->general_conf_reg, reg);
        return_on_error(status);

        reg.fields.pause_checkin_machine = pause ? 1 : 0;

        write_list.push_back({lld_reg_mem_line((pt->slice[slice]->ics->general_conf_reg)), reg});
        write_list.push_back({lld_reg_mem_line((pt->slice[slice]->ics->delete_credits_trig)), pause ? 0 : 1});
    }

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

// Return a list of all the blocks of the control
static void
get_control_blocks(const pacific_tree* pt, std::vector<lld_block_scptr>& out_blocks)
{
    std::vector<std::string> block_names{
        "reassembly",
        "rx_meter",
        "counters",
        "fllb",
        "reorder",
        "pdr",
        "cgm",
        "ts_mon",
        "pdvoq",
        "ics",
        "filb",
        "ts_ms",
        "pdoq",
        "dics",
        "dvoq",
        "fdll",
        "sch",
    };

    auto blocks = pt->get_leaf_blocks();
    for (auto block : blocks) {
        if (!filter_block_by_name(block, block_names)) {
            continue;
        }

        out_blocks.push_back(block);
    }
}

// Perform soft-reset sequence on REORDER module
static la_status
reorder_soft_reset_all(ll_device_sptr ll_dev, const slice_manager_smart_ptr& sid_mgr)
{
    auto pt = ll_dev->get_pacific_tree();
    lld_reg_mem_line_value_list_t write_list;

    for (la_slice_id_t slice : sid_mgr->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_NON_FABRIC)) {
        write_list.push_back({lld_reg_mem_line((pt->slice[slice]->pp_reorder->soft_reset_configuration)), 0});
        write_list.push_back({lld_reg_mem_line((pt->slice[slice]->pp_reorder->soft_reset_configuration)), 1});
    }

    for (la_slice_id_t slice : sid_mgr->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_FABRIC)) {
        size_t blocks_nr = array_size(pt->slice[slice]->nw_reorder_block);
        for (size_t block = 0; block < blocks_nr; block++) {
            write_list.push_back({lld_reg_mem_line((pt->slice[slice]->nw_reorder_block[block]->soft_reset_configuration)), 0});
            write_list.push_back({lld_reg_mem_line((pt->slice[slice]->nw_reorder_block[block]->soft_reset_configuration)), 1});
        }
    }

    write_list.push_back({lld_reg_mem_line((pt->nw_reorder->soft_reset_configuration)), 0});
    write_list.push_back({lld_reg_mem_line((pt->nw_reorder->soft_reset_configuration)), 1});

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

// Clear 'aged-out' marking for all contexts
static la_status
ics_set_aging(ll_device_sptr ll_dev, const slice_manager_smart_ptr& sid_mgr)
{
    auto pt = ll_dev->get_pacific_tree();

    for (la_slice_id_t slice : sid_mgr->get_used_slices_internal()) {
        size_t entries_nr = pt->slice[slice]->ics->aged_out_queue->get_desc()->entries;
        la_status status = ll_dev->fill_memory(*pt->slice[slice]->ics->aged_out_queue,
                                               0, // mem_first_entry
                                               entries_nr,
                                               0); // in_bv
        return_on_error(status);

        status = ll_dev->write_register(pt->slice[slice]->ics->scrb_aging_trig_reg, 1);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

// Return the number of credits for a given port
static la_status
get_pdoq_num_credits(ll_device_sptr ll_dev, la_slice_id_t slice, la_ifg_id_t ifg, unsigned port, size_t& out_num_credits)
{
    auto pt = ll_dev->get_pacific_tree();
    unsigned num_credits = 0;

    if (port < 16) {
        ifgb_tx_fif_cfg_register reg;
        la_status status = ll_dev->read_register((*pt->slice[slice]->ifg[ifg]->ifgb->tx_fif_cfg)[port], reg);
        return_on_error(status);

        num_credits = reg.fields.tx_f_end_addr - reg.fields.tx_f_start_addr + 1;
    } else if (port == 16) {
        ifgb_tx_fif_cfg16_register reg;
        la_status status = ll_dev->read_register(pt->slice[slice]->ifg[ifg]->ifgb->tx_fif_cfg16, reg);
        return_on_error(status);

        num_credits = reg.fields.tx_f16_end_addr - reg.fields.tx_f16_start_addr + 1;
    } else if (port == 17) {
        ifgb_tx_fif_cfg17_register reg;
        la_status status = ll_dev->read_register(pt->slice[slice]->ifg[ifg]->ifgb->tx_fif_cfg17, reg);
        return_on_error(status);

        num_credits = reg.fields.tx_f17_end_addr - reg.fields.tx_f17_start_addr + 1;
    } else if (port == 18) {
        ifgb_tx_fif_cfg18_register reg;
        la_status status = ll_dev->read_register(pt->slice[slice]->ifg[ifg]->ifgb->tx_fif_cfg18, reg);
        return_on_error(status);

        num_credits = reg.fields.tx_f18_end_addr - reg.fields.tx_f18_start_addr + 1;
    } else if (port == 19) {
        num_credits = 152;
    }

    // Round down credits
    if (num_credits == 77) {
        num_credits = 76;
    }

    if (num_credits == 154) {
        num_credits = 152;
    }

    static const unsigned valid_num_credits[] = {76, 152, 616};

    bool is_valid = false;
    for (size_t i = 0; i < array_size(valid_num_credits); i++) {
        if (num_credits == valid_num_credits[i]) {
            is_valid = true;
            break;
        }
    }

    if (!is_valid) {
        log_err(SOFT_RESET, "ERROR: num_credits %0d in slice %0d, ifg %0d, port %0d is illegal", num_credits, slice, ifg, port);
        num_credits = 0;
    }

    out_num_credits = num_credits;

    return LA_STATUS_SUCCESS;
}

// Check whether the given port is active or not
static la_status
is_active_ifg_port(ll_device_sptr ll_dev, la_slice_id_t slice, la_ifg_id_t ifg, unsigned port, bool& out_is_active)
{
    auto pt = ll_dev->get_pacific_tree();

    auto m = (*pt->slice[slice]->pdoq->fdoq->fdoq_ifg_calendar)[ifg];
    size_t entries_nr = m->get_desc()->entries;
    for (size_t i = 0; i < entries_nr; i++) {
        pdoq_fdoq_fdoq_ifg_calendar_memory e;
        la_status status = ll_dev->read_memory(m, i, e);
        return_on_error(status);

        if (e.fields.fdoq_ifg_calendar_data == port) {
            out_is_active = true;
            return LA_STATUS_SUCCESS;
        }
    }

    pdoq_fdoq_fdoq_general_configuration_register reg;
    la_status status = ll_dev->read_register(pt->slice[slice]->pdoq->fdoq->fdoq_general_configuration, reg);
    return_on_error(status);

    out_is_active = ((reg.fields.mlp_en & (1 << ifg)) != 0) && ((port == 0) || (port == 8));

    return LA_STATUS_SUCCESS;
}

// Reset credits of all ports in the device
static la_status
pdoq_reset_credits(ll_device_sptr ll_dev, const slice_manager_smart_ptr& sid_mgr)
{
    lld_reg_mem_line_value_list_t write_list;
    auto pt = ll_dev->get_pacific_tree();

    for (la_slice_id_t slice : sid_mgr->get_used_slices_internal()) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            for (unsigned port = 0; port < tm_utils::IFG_SYSTEM_PORT_SCHEDULERS; port++) {

                size_t num_credits = 0;
                bool is_active = false;
                la_status status = is_active_ifg_port(ll_dev, slice, ifg, port, is_active);
                return_on_error(status);

                if (is_active) {
                    status = get_pdoq_num_credits(ll_dev, slice, ifg, port, num_credits);
                    return_on_error(status);
                }

                pdoq_fdoq_ifg_credit_init_register reg;
                status = ll_dev->read_register(pt->slice[slice]->pdoq->fdoq->ifg_credit_init, reg);
                return_on_error(status);

                reg.fields.ifg_credit_init_enable
                    = (ifg == 0) ? (1 << port) : (1ull << (tm_utils::IFG_SYSTEM_PORT_SCHEDULERS + port));
                reg.fields.ifg_credit_init_value = num_credits;
                write_list.push_back({lld_reg_mem_line((pt->slice[slice]->pdoq->fdoq->ifg_credit_init)), reg});
            }
        }
    }

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

// Clear TXCGM memories
static la_status
txcgm_reset_mem(ll_device_sptr ll_dev, const slice_manager_smart_ptr& sid_mgr)
{
    auto pt = ll_dev->get_pacific_tree();

    for (la_slice_id_t slice : sid_mgr->get_used_slices_internal()) {
        lld_memory_scptr uc_oq_state_mem = pt->slice[slice]->tx->cgm->uc_oq_state;
        size_t entries_nr = uc_oq_state_mem->get_desc()->entries;
        la_status status = ll_dev->fill_memory(*uc_oq_state_mem, 0, entries_nr, 0);
        return_on_error(status);

        lld_memory_scptr mc_qsize_byte_mem = pt->slice[slice]->tx->cgm->mc_qsize_byte;
        entries_nr = mc_qsize_byte_mem->get_desc()->entries;
        status = ll_dev->fill_memory(*mc_qsize_byte_mem, 0, entries_nr, 0);
        return_on_error(status);

        lld_memory_scptr mc_qsize_pd_mem = pt->slice[slice]->tx->cgm->mc_qsize_pd;
        entries_nr = mc_qsize_pd_mem->get_desc()->entries;
        status = ll_dev->fill_memory(*mc_qsize_pd_mem, 0, entries_nr, 0);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

// Reset FE link bundles
la_status
reset_fe_link_bundles(la_device_impl* la_dev)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();
    lld_reg_mem_line_value_list_t write_list;

    if (la_dev->m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        return LA_STATUS_SUCCESS;
    }

    for (la_slice_id_t slice : la_dev->get_used_slices()) {
        auto m = (*pt->slice_pair[slice / 2]->rx_pdr->fe_uc_link_bundle_desc_table)[slice % 2];
        size_t lines_nr = m->get_desc()->entries;

        for (size_t l = 0; l < lines_nr; l++) {
            rx_pdr_2_slices_fe_uc_link_bundle_desc_table_memory bundle_desc;
            la_status status = ll_dev->read_memory(m, l, bundle_desc);
            return_on_error(status);
            bundle_desc.fields.slice_bundle_link0_bc = 0;
            bundle_desc.fields.slice_bundle_link1_bc = 0;
            bundle_desc.fields.slice_bundle_link2_bc = 0;
            bundle_desc.fields.slice_bundle_link3_bc = 0;
            write_list.push_back({lld_reg_mem_line(m, l), bundle_desc});
        }
    }

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

// Change ICS slice mode to non-fabric
// There is a bug where the ics can't be configured in non-standalone mode
// so the workaround is to temporary change slice mode to standalone
static la_status
ics_slice_mode_wa_enter(la_device_impl* la_dev, std::array<uint64_t, ASIC_MAX_SLICES_PER_DEVICE_NUM>& out_orig_ics_slice_modes)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();
    lld_reg_mem_line_value_list_t write_list;

    for (size_t slice_num = 0; slice_num < array_size(pt->slice); slice_num++) {
        ics_slice_slice_mode_reg_register ics_slice_mode;
        la_status status = ll_dev->read_register(pt->slice[slice_num]->ics->slice_mode_reg, ics_slice_mode);
        return_on_error(status);
        out_orig_ics_slice_modes[slice_num] = ics_slice_mode.fields.ics_mode;
        ics_slice_mode.fields.ics_mode = (uint64_t)la_device_impl::tm_slice_mode_e::STANDALONE;
        status = ll_dev->write_register(pt->slice[slice_num]->ics->slice_mode_reg, ics_slice_mode);
        return_on_error(status);
    }

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

// Restore ICS slice mode
static la_status
ics_slice_mode_wa_leave(la_device_impl* la_dev, const std::array<uint64_t, ASIC_MAX_SLICES_PER_DEVICE_NUM>& orig_ics_slice_modes)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();
    lld_reg_mem_line_value_list_t write_list;

    for (size_t slice_num = 0; slice_num < array_size(pt->slice); slice_num++) {
        la_uint_t sm = orig_ics_slice_modes[slice_num];
        ics_slice_slice_mode_reg_register ics_slice_mode;
        ics_slice_mode.fields.ics_mode = sm;
        la_status status = ll_dev->write_register(pt->slice[slice_num]->ics->slice_mode_reg, ics_slice_mode);
        return_on_error(status);
    }

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

// Reset the MS VOQ credit count
static la_status
reset_ms_voq_credit_count(la_device_impl* la_dev)
{
    la_slice_id_t rep_sid = la_dev->first_active_slice_id();
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();
    lld_reg_mem_line_value_list_t write_list;

    // This cfg is the same for all tsms fifo in LC (dest slices 0,1,2 source slices 3,4,5) and in FE (all to all).
    // We use dest slice 0 and source slice 3, which works for both.

    la_slice_id_t first_linecard_fab_slice
        = la_dev->get_slice_id_manager()->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_FABRIC)[0];
    tsms_tsms_fifo_th_configuration_register fifo_reg;
    la_status status
        = ll_dev->read_register((*pt->slice[rep_sid]->ts_ms->tsms_fifo_th_configuration)[first_linecard_fab_slice], fifo_reg);
    return_on_error(status);

    for (size_t slice_num = 0; slice_num < array_size(pt->slice); slice_num++) {
        if (la_dev->m_slice_mode[slice_num] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }

        ics_slice_ms_q_conf_register ics_slice_ms_q_conf;

        status = ll_dev->read_register(pt->slice[slice_num]->ics->ms_q_conf, ics_slice_ms_q_conf);
        return_on_error(status);
        ics_slice_ms_q_conf.fields.ms_q_uch_crdts = fifo_reg.fields.rlb_uch_fifo_size;
        ics_slice_ms_q_conf.fields.ms_q_ucl_crdts = fifo_reg.fields.rlb_ucl_fifo_size;
        ics_slice_ms_q_conf.fields.ms_q_mc_crdts = fifo_reg.fields.rlb_mc_fifo_size;
        write_list.push_back({lld_reg_mem_line((pt->slice[slice_num]->ics->ms_q_conf)), ics_slice_ms_q_conf});
    }

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

// Configure reorder for fabric slices
static la_status
reorder_soft_reset_fe_lc(la_device_impl* la_dev, fabric_init_handler* fih)
{
    la_status status = LA_STATUS_EUNKNOWN;
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();

    // Reset
    for (la_slice_id_t slice : la_dev->get_slice_id_manager()->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_FABRIC)) {
        size_t blocks_nr = array_size(pt->slice[slice]->nw_reorder_block);
        for (size_t block = 0; block < blocks_nr; block++) {
            status = ll_dev->write_register(pt->slice[slice]->nw_reorder_block[block]->soft_reset_configuration, 1);
            return_on_error(status);
        }
    }

    status = ll_dev->write_register(pt->nw_reorder->soft_reset_configuration, 1);
    return_on_error(status);

    // Configure memories
    status = fih->configure_phase_topology_dynamic_memories();
    return_on_error(status);

    // Reset
    status = ll_dev->write_register(pt->nw_reorder->soft_reset_configuration, 0);
    return_on_error(status);
    status = ll_dev->write_register(pt->nw_reorder->soft_reset_configuration, 1);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// Perform soft-reset sequence on control modules
static la_status
control_deassert_soft_reset(la_device_impl* la_dev,
                            std::array<uint64_t, ASIC_MAX_SLICES_PER_DEVICE_NUM>& orig_ics_slice_modes,
                            std::vector<lld_block_scptr>& blocks,
                            std::vector<bool>& out_is_active)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();

    log_debug(SOFT_RESET, "    ics_pause_resume ...");
    la_status status = ics_pause_resume(ll_dev, la_dev->get_slice_id_manager(), true /*pause*/);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    log_debug(SOFT_RESET, "    ics_slice_mode_wa_enter...");
    orig_ics_slice_modes.fill((uint64_t)la_device_impl::tm_slice_mode_e::STANDALONE);
    status = ics_slice_mode_wa_enter(la_dev, orig_ics_slice_modes);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    log_debug(SOFT_RESET, "    deassert_control_blocks ...");
    get_control_blocks(pt, blocks);
    status = deassert_soft_reset(ll_dev, blocks, out_is_active);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    return LA_STATUS_SUCCESS;
}

// Perform soft-reset sequence on control modules
static la_status
control_assert_soft_reset(la_device_impl* la_dev,
                          fabric_init_handler* fih,
                          const std::array<uint64_t, ASIC_MAX_SLICES_PER_DEVICE_NUM>& orig_ics_slice_modes,
                          const std::vector<lld_block_scptr>& blocks,
                          const std::vector<bool>& is_active)
{
    auto ll_dev = la_dev->get_ll_device_sptr();

    log_debug(SOFT_RESET, "    assert_control_blocks ...");
    la_status status = assert_soft_reset(ll_dev, blocks, is_active);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    if (la_dev->m_device_mode != device_mode_e::STANDALONE) {
        log_debug(SOFT_RESET, "    configure reorder memories ...");
        status = reorder_soft_reset_fe_lc(la_dev, fih);
        return_on_error(status);
        log_debug(SOFT_RESET, "    done");
    }
    auto sid_mgr = la_dev->get_slice_id_manager();

    status = reorder_soft_reset_all(ll_dev, sid_mgr);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    status = ics_pause_resume(ll_dev, sid_mgr, false /*pause*/);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    status = ics_set_aging(ll_dev, sid_mgr);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    status = pdoq_reset_credits(ll_dev, sid_mgr);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    status = fih->configure_post_soft_reset_pdvoq();
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    status = reset_ms_voq_credit_count(la_dev);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    status = ics_slice_mode_wa_leave(la_dev, orig_ics_slice_modes);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    status = txcgm_reset_mem(ll_dev, la_dev->get_slice_id_manager());
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    status = reset_fe_link_bundles(la_dev);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    // Commit all writes
    return LA_STATUS_SUCCESS;
}

// Return a list of all the NPU block
static void
get_npu_blocks(const pacific_tree* pt, std::vector<lld_block_scptr>& out_blocks)
{
    std::vector<std::string> block_names{
        "npu", "idb", "sdb", "cdb",
    };

    auto blocks = pt->get_leaf_blocks();
    for (auto block : blocks) {
        if (!filter_block_by_name(block, block_names)) {
            continue;
        }

        out_blocks.push_back(block);
    }
}

// Put all NPU sub-blocks in assert state
template <class T>
static void
assert_npu_sub_blocks(const std::vector<lld_block_scptr> npu_blocks,
                      const std::vector<bool> is_active,
                      const T sub_strings,
                      lld_reg_mem_line_value_list_t& write_list)
{
    for (size_t i = 0; i < npu_blocks.size(); i++) {
        if (!is_active[i]) {
            continue;
        }

        auto name = npu_blocks[i]->get_name();
        bool is_match = true;
        for (auto str : sub_strings) {
            if (name.find(str) == std::string::npos) {
                is_match = false;
                break;
            }
        }

        if (is_match) {
            assert_soft_reset_single(npu_blocks[i], write_list);
        }
    }
}

// Perform soft reset to the NPU
static la_status
npu_deassert_soft_reset(la_device_impl* la_dev, std::vector<lld_block_scptr>& npu_blocks, std::vector<bool>& out_is_active)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();

    get_npu_blocks(pt, npu_blocks);

    // Deassert all NPU blocks
    return deassert_soft_reset(ll_dev, npu_blocks, out_is_active);
}

static la_status
npu_assert_soft_reset(la_device_impl* la_dev, const std::vector<lld_block_scptr>& npu_blocks, const std::vector<bool>& is_active)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    lld_reg_mem_line_value_list_t write_list;

    // Assert the NPU blocks in a specific order
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "npe"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "fi_eng"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "sna"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "fi_stage"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "rxpp_term.rxpp_term"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "rxpp_fwd.rxpp_fwd"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "cdb_cache"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "txpp.cluster"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "txpp.txpp"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 1>({{"idb.top"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 1>({{"idb.res"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 1>({{"sdb.enc"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 1>({{"sdb.mac"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 1>({{"cdb.top"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 1>({{"cdb.core"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 1>({{"npuh.npe"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 1>({{"npuh.fi"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 1>({{"npuh.host"}}), write_list);

    // Commit all writes
    la_status status = lld_write_memory_line_or_register_list(ll_dev, write_list);
    return_on_error(status);

    status = la_dev->init_npe2dbc_thread_ready_indication();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// Return a list of all HBM blocks
static void
get_mmu_hbm_blocks(const pacific_tree* pt, std::vector<lld_block_scptr>& out_blocks)
{
    std::vector<std::string> block_names{
        "hbm", "mmu",
    };

    auto blocks = pt->get_leaf_blocks();
    for (auto block : blocks) {
        if (!filter_block_by_name(block, block_names)) {
            continue;
        }

        out_blocks.push_back(block);
    }
}

static la_status
mmu_hbm_deassert_soft_reset(la_device_impl* la_dev, std::vector<lld_block_scptr>& blocks, std::vector<bool>& out_is_active)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();

    get_mmu_hbm_blocks(pt, blocks);

    log_info(SOFT_RESET, "    Deassert soft-reset in MMU HBM blocks ...");
    la_status status = deassert_soft_reset(ll_dev, blocks, out_is_active);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    return LA_STATUS_SUCCESS;
}

static la_status
mmu_hbm_assert_soft_reset(la_device_impl* la_dev, const std::vector<lld_block_scptr>& blocks, const std::vector<bool>& is_active)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    log_info(SOFT_RESET, "    Aassert soft-reset in MMU HBM blocks ...");
    la_status status = assert_soft_reset(ll_dev, blocks, is_active);
    return_on_error(status);

    log_info(SOFT_RESET, "    Done.");
    log_info(SOFT_RESET, "    Resetting HBM handler ...");
    status = la_dev->m_hbm_handler->soft_reset();
    return_on_error(status);

    log_info(SOFT_RESET, "    Done.");

    /// Reconfigure LPM in HBM
    bool lpm_in_hbm;
    status = la_dev->get_bool_property(la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION, lpm_in_hbm);
    return_on_error(status);

    if (!lpm_in_hbm) {
        return LA_STATUS_SUCCESS;
    }

    log_info(SOFT_RESET, "    Reconfiguring LPM HBM ...");
    status = la_dev->m_resource_manager->lpm_hbm_config();
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    return LA_STATUS_SUCCESS;
}

// Workaround to a bug in EM memory used by the reorder. Need to set
// some memory cells after they were cleared by the reorder soft reset.
la_status
la_device_impl::exact_match_wa()
{
    auto ll_dev = m_ll_device;
    auto pt = m_pacific_tree;
    lld_reg_mem_line_value_list_t write_list;
    la_device_revision_e revision = pt->get_revision();

    if ((revision == la_device_revision_e::PACIFIC_B0) || (revision == la_device_revision_e::PACIFIC_B1)) {
        return LA_STATUS_SUCCESS;
    }

    // #1 connection
    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_NON_FABRIC)) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            auto m = (*pt->slice[slice]->pp_reorder->connection_profile_table)[ifg];
            size_t lines_nr = m->get_desc()->entries;
            for (size_t line = 0; line < lines_nr; line++) {
                write_list.push_back({lld_reg_mem_line(m, line), 6});
            }
        }
    }
    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_FABRIC)) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            auto m = pt->slice[slice]->nw_reorder_block[ifg]->connection_profile_table;
            size_t lines_nr = m->get_desc()->entries;
            for (size_t line = 0; line < lines_nr; line++) {
                write_list.push_back({lld_reg_mem_line(m, line), 6});
            }
        }
    }

    // Init dynamic memory
    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_NON_FABRIC)) {
        for (size_t block = 0; block < pt->slice[slice]->pp_reorder->pp_exact_match_verifier->get_desc()->instances; ++block) {
            size_t lines_nr = (*pt->slice[slice]->pp_reorder->pp_exact_match_verifier)[block]->get_desc()->entries;
            for (size_t line = 0; line < lines_nr; line++) {
                write_list.push_back({lld_reg_mem_line((*pt->slice[slice]->pp_reorder->pp_exact_match_verifier)[block], line), 0});
            }
        }
    }

    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_FABRIC)) {
        for (size_t block = 0; block < array_size(pt->slice[slice]->nw_reorder_block); block++) {
            for (size_t bank = 0; bank < /*banks_nr*/ 4; bank++) {
                size_t lines_nr = (*pt->slice[slice]->nw_reorder_block[block]->nw_exact_match_verifier)[bank]->get_desc()->entries;
                for (size_t line = 0; line < lines_nr; line++) {
                    write_list.push_back(
                        {lld_reg_mem_line((*pt->slice[slice]->nw_reorder_block[block]->nw_exact_match_verifier)[bank], line), 0});
                }
            }
        }
    }

    // Remove banks
    la_status status = apply_topology_post_soft_reset_workaround_reorder();
    return_on_error(status);

    // Set back-pressure from reorder
    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_NON_FABRIC)) {
        pp_reorder_slice_slice_configuration_register r;
        la_status status = ll_dev->read_register(pt->slice[slice]->pp_reorder->slice_configuration, r);
        return_on_error(status);

        r.fields.reorder_full_prevention_enable = 1;
        r.fields.reorder_full_prevention_rate_limiting = 1;
        write_list.push_back({lld_reg_mem_line((pt->slice[slice]->pp_reorder->slice_configuration)), r});
    }

    // Set reorder-drop-threshold (1250 instead of 1400 - to enable drop before back-pressure towards rxpp)
    size_t reorder_drop_threshold = 1250;
    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_NON_FABRIC)) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            write_list.push_back(
                {lld_reg_mem_line((*pt->slice[slice]->pp_reorder->profile_config_table)[ifg], 6), reorder_drop_threshold});
        }
    }

    for (la_slice_id_t slice : m_slice_id_manager->get_slices_by_fabric_type(fabric_slices_type_e::LINECARD_FABRIC)) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            write_list.push_back(
                {lld_reg_mem_line((pt->slice[slice]->nw_reorder_block[ifg]->profile_config_table), 6), reorder_drop_threshold});
        }
    }

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

// Hold memory lines of active OQs
using oq_active_list_t = std::vector<std::tuple<la_slice_id_t, size_t, uint64_t> >;

// Disable all active OQs
static la_status
oq_drop(ll_device_sptr ll_dev, const slice_manager_smart_ptr& sid_mgr, oq_active_list_t& oq_active_list)
{
    auto pt = ll_dev->get_pacific_tree();
    lld_memory_line_value_list_t mem_line_val_list;

    for (la_slice_id_t slice : sid_mgr->get_used_slices_internal()) {
        auto& m(pt->slice[slice]->tx->cgm->oq_drop_bitmap);
        for (size_t line = 0; line < m->get_desc()->entries; line++) {
            txcgm_oq_drop_bitmap_memory todbm;
            la_status status = ll_dev->read_memory(m, line, todbm);
            return_on_error(status);

            if (todbm.fields.oq_drop_bitmap_data != 0xff) {
                uint64_t data = todbm.fields.oq_drop_bitmap_data;
                oq_active_list.push_back(std::make_tuple(slice, line, data));
                todbm.fields.oq_drop_bitmap_data = 0xff;
                mem_line_val_list.push_back({{m, line}, todbm});
            }
        }
    }

    return lld_write_memory_line_list(ll_dev, mem_line_val_list);
}

// Re-enable all OQs that were disabled
static la_status
oq_restore(la_device_impl* la_dev, oq_active_list_t& oq_active_list, la_slice_mode_e req_slice_mode)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();
    lld_memory_line_value_list_t mem_line_val_list;

    for (auto slice_line : oq_active_list) {
        la_slice_id_t slice;
        size_t line;
        uint64_t oq_drop_bitmap_data;
        std::tie(slice, line, oq_drop_bitmap_data) = slice_line;
        la_slice_mode_e curr_slice_mode;
        la_status status = la_dev->get_slice_mode(slice, curr_slice_mode);
        return_on_error(status);

        if (req_slice_mode != curr_slice_mode) {
            continue;
        }

        auto& m(pt->slice[slice]->tx->cgm->oq_drop_bitmap);
        txcgm_oq_drop_bitmap_memory todbm;
        todbm.fields.oq_drop_bitmap_data = oq_drop_bitmap_data;
        mem_line_val_list.push_back({{m, line}, todbm});
    }

    return lld_write_memory_line_list(ll_dev, mem_line_val_list);
}

// Set all the schedulers to static-go, i.e. - make them grant credits without being asked
static la_status
set_sched_static_go(la_device_impl* la_dev, bit_vector& reachable_devices_bv)
{
    for (auto o : la_dev->get_objects(la_object::object_type_e::SYSTEM_PORT)) {
        auto sp = static_cast<la_system_port_base*>(o);
        if (sp->get_port_type() == la_system_port_base::port_type_e::REMOTE) {
            continue;
        }

        log_debug(SOFT_RESET, "        %s:  %s", __func__, sp->to_string().c_str());
        auto sps = sp->get_scheduler();
        for (la_oq_id_t oq = 0; oq < tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH; oq++) {
            log_debug(SOFT_RESET, "            oq=%u", oq);
            la_output_queue_scheduler* oqs = nullptr;
            la_status status = sps->get_output_queue_scheduler(oq, oqs);
            return_on_error(status);
            log_debug(SOFT_RESET, "                sps=%s", sps->to_string().c_str());
            auto oqsi = static_cast<la_output_queue_scheduler_impl*>(oqs);
            status = oqsi->set_static_go(reachable_devices_bv);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

// Restart peer-discovery
static la_status
restart_peer_discovery_lc(la_device_impl* la_dev, const fabric_protocol_state_t& fabric_protocol_state)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();

    fte_enable_reg_register reg;
    reg.fields.peer_delay_req_gen_link_idx = 0x7f; // Enable all active links
    reg.fields.sync_packet_gen_en = 1;

    reg.fields.peer_delay_req_gen_en = 0;
    la_status status = ll_dev->write_register(pt->dmc->fte->enable_reg, reg);
    return_on_error(status);

    reg.fields.peer_delay_req_gen_en = 1;
    status = ll_dev->write_register(pt->dmc->fte->enable_reg, reg);
    return_on_error(status);

    reg.fields.peer_delay_req_gen_en = 0;
    status = ll_dev->write_register(pt->dmc->fte->enable_reg, reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// Restart peer-discovery
static la_status
restart_peer_discovery_fe(la_device_impl* la_dev, const fabric_protocol_state_t& fabric_protocol_state)
{
    constexpr size_t MAX_RETRIES = 9;
    la_status status;
    std::vector<la_fabric_port_impl*> need_to_activate = fabric_protocol_state.keepalive_list;
    std::vector<la_fabric_port_impl*> failed_to_activate;

    for (size_t retries = 0; retries < MAX_RETRIES; retries++) {
        for (auto fp : need_to_activate) {
            status = fp->activate(la_fabric_port::link_protocol_e::PEER_DISCOVERY);
            if (status == LA_STATUS_SUCCESS) {
                continue;
            }

            if (status != LA_STATUS_EAGAIN) {
                return_on_error(status);
            }

            failed_to_activate.push_back(fp);
        }

        if (failed_to_activate.empty()) {
            break;
        }

        need_to_activate = failed_to_activate;
        failed_to_activate.clear();
        log_info(SOFT_RESET, "%s: sleeping", __func__);
        for (size_t _sleep = 0; _sleep < (64ull << retries); _sleep++) {
            __builtin_ia32_pause();
        }
    }

    if (!failed_to_activate.empty()) {
        log_err(SOFT_RESET, "%s: device=%d peer-discovery failed", __func__, la_dev->get_id());
        for (auto fp : failed_to_activate) {
            log_err(SOFT_RESET, "\t%s", fp->to_string().c_str());
        }

        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

static la_status
wait_for_time_sync(la_device_impl* la_dev, const fabric_protocol_state_t& fabric_protocol_state)
{
    constexpr size_t MAX_RETRIES = 9;
    bool is_fabric_time_synced;

    for (size_t retries = 0; retries < MAX_RETRIES; retries++) {
        la_status status = la_dev->get_fabric_time_sync_status(is_fabric_time_synced);
        return_on_error(status);
        if (is_fabric_time_synced) {
            break;
        }

        log_info(SOFT_RESET, "%s: sleeping", __func__);
        for (size_t _sleep = 0; _sleep < (64ull << retries); _sleep++) {
            __builtin_ia32_pause();
        }
    }

    if (!is_fabric_time_synced) {
        log_err(SOFT_RESET, "%s: device=%d time sync failed", __func__, la_dev->get_id());

        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

static la_status
restart_keepalive_lc(la_device_impl* la_dev, const fabric_protocol_state_t& fabric_protocol_state)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();

    for (la_slice_id_t slice : la_dev->get_used_slices()) {
        tsms_keepalive_gen_cfg_register reg;
        la_status status = ll_dev->read_register(pt->slice[slice]->ts_ms->keepalive_gen_cfg, reg);
        return_on_error(status);
        reg.fields.keepalive_gen_enable = fabric_protocol_state.orig_ka[slice];
        status = ll_dev->write_register(pt->slice[slice]->ts_ms->keepalive_gen_cfg, reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

static la_status
restart_keepalive_fe(la_device_impl* la_dev, const fabric_protocol_state_t& fabric_protocol_state)
{
    constexpr size_t MAX_RETRIES = 9;
    la_status status;
    std::vector<la_fabric_port_impl*> need_to_activate = fabric_protocol_state.keepalive_list;
    std::vector<la_fabric_port_impl*> failed_to_activate;

    for (size_t retries = 0; retries < MAX_RETRIES; retries++) {
        for (auto fp : need_to_activate) {
            status = fp->activate(la_fabric_port::link_protocol_e::LINK_KEEPALIVE);
            if (status == LA_STATUS_SUCCESS) {
                continue;
            }

            if (status != LA_STATUS_EAGAIN) {
                return_on_error(status);
            }

            failed_to_activate.push_back(fp);
        }

        if (failed_to_activate.empty()) {
            break;
        }

        need_to_activate = failed_to_activate;
        failed_to_activate.clear();
        log_info(SOFT_RESET, "%s: sleeping", __func__);
        for (size_t _sleep = 0; _sleep < (64ull << retries); _sleep++) {
            __builtin_ia32_pause();
        }
    }

    if (!failed_to_activate.empty()) {
        log_err(SOFT_RESET, "%s: device=%d keepalive failed", __func__, la_dev->get_id());
        for (auto fp : failed_to_activate) {
            log_err(SOFT_RESET, "\t%s", fp->to_string().c_str());
        }

        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

// Restart fabric protocols on FE
static la_status
do_restart_fabric_protocols_fe(la_device_impl* la_dev, const fabric_protocol_state_t& fabric_protocol_state)
{
    la_status status;
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();

    // Peer discovery
    log_info(SOFT_RESET, "    Restarting peer discovery ...");
    status = restart_peer_discovery_fe(la_dev, fabric_protocol_state);
    // Don't abort on failure. TODO return abort after adding transactions to rollback device status on failure
    if (status != LA_STATUS_SUCCESS) {
        log_err(SOFT_RESET, "    restart_peer_discovery_fe failed");
    } else {
        log_info(SOFT_RESET, "    Done.");
    }

    // Fabric time engine
    log_info(SOFT_RESET, "    Enabling fabric time engine ...");
    fte_enable_reg_register enable_reg;
    status = ll_dev->read_register(pt->dmc->fte->enable_reg, enable_reg);
    return_on_error(status);
    enable_reg.fields.sync_packet_gen_en = 1;
    status = ll_dev->write_register(pt->dmc->fte->enable_reg, enable_reg);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    // Wait for time sync
    log_info(SOFT_RESET, "    Waiting for time sync ...");
    status = wait_for_time_sync(la_dev, fabric_protocol_state);
    return_on_error(status);
    // Don't abort on failure. TODO return abort after adding transactions to rollback device status on failure
    if (status != LA_STATUS_SUCCESS) {
        log_err(SOFT_RESET, "    wait_for_time_sync failed");
    } else {
        log_info(SOFT_RESET, "    Done.");
    }

    // Keepalive
    log_info(SOFT_RESET, "    Restarting keepalive ...");
    status = restart_keepalive_fe(la_dev, fabric_protocol_state);
    // Don't abort on failure. TODO return abort after adding transactions to rollback device status on failure
    if (status != LA_STATUS_SUCCESS) {
        log_err(SOFT_RESET, "    restart_keepalive_fe failed");
    } else {
        log_info(SOFT_RESET, "    Done.");
    }

    // Fabric routing table manager
    log_info(SOFT_RESET, "    Enabling fabric routing table manager ...");
    status = la_dev->trigger_frt_scan();
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    // Fabric routing protocol
    if (fabric_protocol_state.frp_enabled) {
        log_info(SOFT_RESET, "    Enabling fabric routing protocol ...");
        frm_frp_enable_reg_register frp_reg;
        frp_reg.fields.frp_packet_gen_en = 1;
        status = ll_dev->write_register(pt->dmc->frm->frp_enable_reg, frp_reg);
        return_on_error(status);
        log_info(SOFT_RESET, "    Done.");
    }

    // Re-connect the FE
    log_info(SOFT_RESET, "    Reconnecting FE ...");
    status = la_dev->set_fe_fabric_reachability_enabled(true);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    return LA_STATUS_SUCCESS;
}

static la_status
clear_link_down_status(la_device_impl* la_dev)
{
    la_status status;
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();

    frm_fabric_link_down_transition_reg_register reg;

    status = ll_dev->read_register(pt->dmc->frm->fabric_link_down_transition_reg, reg);
    return_on_error(status);
    reg.fields.fabric_link_down_transition_p0 = 0;
    reg.fields.fabric_link_down_transition_p1 = 0;
    status = ll_dev->write_register(pt->dmc->frm->fabric_link_down_transition_reg, reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// Restart fabric protocols on LC
static la_status
do_restart_fabric_protocols_lc(la_device_impl* la_dev, fabric_protocol_state_t& fabric_protocol_state)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();

    // Keepalive
    log_info(SOFT_RESET, "    Restarting keepalive ...");
    la_status status = restart_keepalive_lc(la_dev, fabric_protocol_state);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    log_info(SOFT_RESET, "    Clearing link down status ...");
    status = clear_link_down_status(la_dev);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    // Peer discovery
    log_info(SOFT_RESET, "    Restarting peer discovery and enabling fabric time engine...");
    status = restart_peer_discovery_lc(la_dev, fabric_protocol_state);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    // Fabric routing protocol
    if (fabric_protocol_state.frp_enabled) {
        log_info(SOFT_RESET, "    Enabling fabric routing protocol ...");
        frm_frp_enable_reg_register frp_reg;
        frp_reg.fields.frp_packet_gen_en = 1;
        status = ll_dev->write_register(pt->dmc->frm->frp_enable_reg, frp_reg);
        return_on_error(status);
        log_info(SOFT_RESET, "    Done.");
    } else {
        // Restore saved fabric routing table
        log_info(SOFT_RESET, "    Restoring FRT...");
        status = restore_frt(la_dev, fabric_protocol_state);
        return_on_error(status);
        log_info(SOFT_RESET, "    Done.");
    }

    // Reconnecting LC
    log_info(SOFT_RESET, "    Reconnecting LC ...");
    frm_device_config_reg_register reg;
    status = ll_dev->read_register(pt->dmc->frm->device_config_reg, reg);
    return_on_error(status);
    reg.fields.device_id = la_dev->get_id();
    status = ll_dev->write_register(pt->dmc->frm->device_config_reg, reg);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    return LA_STATUS_SUCCESS;
}

// Restart fabric protocols. Return only after device stabilizes
static la_status
restart_fabric_protocols(la_device_impl* la_dev, fabric_protocol_state_t& fabric_protocol_state)
{
    if (la_dev->m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        return do_restart_fabric_protocols_fe(la_dev, fabric_protocol_state);
    }

    return do_restart_fabric_protocols_lc(la_dev, fabric_protocol_state);
}

// Get the fabric multicast eligibility vector
static la_status
get_is_fmc_elig_is_zero(ll_device_sptr ll_dev, bool& out_fmc_elig_is_zero)
{
    auto pt = ll_dev->get_pacific_tree();
    frm_fmc_elig_reg_register fmc_elig_reg;
    la_status status = ll_dev->read_register(pt->dmc->frm->fmc_elig_reg, fmc_elig_reg);
    return_on_error(status);
    out_fmc_elig_is_zero = ((fmc_elig_reg.fields.fmc_elig_p0 == 0) && (fmc_elig_reg.fields.fmc_elig_p1 == 0));

    return LA_STATUS_SUCCESS;
}

// Stop fabric protocols
static la_status
stop_fabric_protocols(la_device_impl* la_dev, fabric_protocol_state_t& fabric_protocol_state)
{
    la_status status;
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto pt = ll_dev->get_pacific_tree();

    if (la_dev->m_device_mode == device_mode_e::FABRIC_ELEMENT) {
        // Isolate the FE
        log_info(SOFT_RESET, "    Isolating FE ...");
        status = la_dev->set_fe_fabric_reachability_enabled(false);
        return_on_error(status);
        log_info(SOFT_RESET, "    Done.");
    } else {
        // Isolate the LC
        log_info(SOFT_RESET, "    Isolating LC ...");
        frm_device_config_reg_register reg;
        la_status status = ll_dev->read_register(pt->dmc->frm->device_config_reg, reg);
        return_on_error(status);
        reg.fields.device_id = la_device_impl::MAX_DEVICES; // Non-existent device
        status = ll_dev->write_register(pt->dmc->frm->device_config_reg, reg);
        return_on_error(status);
        log_info(SOFT_RESET, "    Done.");
    }

    for (la_slice_id_t slice : la_dev->get_used_slices()) {
        tsms_keepalive_gen_cfg_register reg;
        status = ll_dev->read_register(pt->slice[slice]->ts_ms->keepalive_gen_cfg, reg);
        return_on_error(status);
        fabric_protocol_state.orig_ka[slice] = reg.fields.keepalive_gen_enable;
    }

    log_info(SOFT_RESET, "    Disabling keepalive and peer discovery ...");
    auto fabric_ports = la_dev->get_objects(la_object::object_type_e::FABRIC_PORT);
    for (auto o : fabric_ports) {
        auto fp = static_cast<la_fabric_port_impl*>(o);

        la_fabric_port::port_status ps;
        if (fp->get_status(ps) != LA_STATUS_SUCCESS) {
            log_warning(SOFT_RESET,
                        "%s:  %s get_status failed %s - skipping",
                        __func__,
                        fp->to_string().c_str(),
                        to_string(status).c_str());
            continue;
        }

        if (!ps.fabric_link_up) {
            continue;
        }

        log_debug(SOFT_RESET, "%s:  %s", __func__, fp->to_string().c_str());

        // Keepalive
        bool is_keepalive;
        status = fp->get_link_keepalive_activated(is_keepalive);
        return_on_error(status);
        if (is_keepalive) {
            fabric_protocol_state.keepalive_list.push_back(fp);
            status = fp->deactivate(la_fabric_port::link_protocol_e::LINK_KEEPALIVE);
            return_on_error(status);
        }

        // Peer delay
        status = fp->deactivate(la_fabric_port::link_protocol_e::PEER_DISCOVERY);
        return_on_error(status);
    }
    log_info(SOFT_RESET, "    Done.");

    // Fabric routing protocol
    frm_frp_enable_reg_register frp_reg;
    status = ll_dev->read_register(pt->dmc->frm->frp_enable_reg, frp_reg);
    return_on_error(status);
    fabric_protocol_state.frp_enabled = (frp_reg.fields.frp_packet_gen_en == 1);
    if (fabric_protocol_state.frp_enabled) {
        log_info(SOFT_RESET, "    Disabling fabric routing protocol ...");
        frp_reg.fields.frp_packet_gen_en = 0;
        status = ll_dev->write_register(pt->dmc->frm->frp_enable_reg, frp_reg);
        return_on_error(status);
        log_info(SOFT_RESET, "    Done.");
    }

    if (!fabric_protocol_state.frp_enabled) {
        // Save FRT because DMC reset will erase it.
        log_info(SOFT_RESET, "    Saving FRT ...");
        status = save_frt(la_dev, fabric_protocol_state);
        return_on_error(status);
        log_info(SOFT_RESET, "    Done.");
    }

    // Fabric time engine
    log_info(SOFT_RESET, "    Disabling fabric time engine ...");
    fte_enable_reg_register enable_reg;
    status = ll_dev->read_register(pt->dmc->fte->enable_reg, enable_reg);
    return_on_error(status);
    enable_reg.fields.sync_packet_gen_en = 0;
    status = ll_dev->write_register(pt->dmc->fte->enable_reg, enable_reg);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    return LA_STATUS_SUCCESS;
}

static la_status
toggle_bfd_timer(ll_device_sptr ll_dev)
{
    auto pt = ll_dev->get_pacific_tree();
    la_status status;

    {
        npu_host_mp_ccm_timer_register reg;
        status = ll_dev->read_register(pt->npuh->host->mp_ccm_timer, reg);
        return_on_error(status);

        reg.fields.mp_ccm_timer_enable = 0;
        status = ll_dev->write_register(pt->npuh->host->mp_ccm_timer, reg);
        return_on_error(status);

        reg.fields.mp_ccm_timer_enable = 1;
        status = ll_dev->write_register(pt->npuh->host->mp_ccm_timer, reg);
        return_on_error(status);
    }
    {
        npu_host_rmep_timer_register reg;
        status = ll_dev->read_register(pt->npuh->host->rmep_timer, reg);
        return_on_error(status);

        reg.fields.rmep_timer_enable = 0;
        status = ll_dev->write_register(pt->npuh->host->rmep_timer, reg);
        return_on_error(status);

        reg.fields.rmep_timer_enable = 1;
        status = ll_dev->write_register(pt->npuh->host->rmep_timer, reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

static la_status
reset_components(la_device_impl* la_dev, fabric_init_handler* fih)
{
    auto ll_dev = la_dev->get_ll_device_sptr();

    log_info(SOFT_RESET, "    Deassert SMS ...");
    std::vector<lld_block_scptr> sms_blocks;
    std::vector<bool> sms_is_already_asserted;
    la_status status = sms_deassert_soft_reset(ll_dev, sms_blocks, sms_is_already_asserted);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    log_info(SOFT_RESET, "    Reset control ...");
    std::vector<lld_block_scptr> control_blocks;
    std::vector<bool> control_is_already_asserted;
    std::array<uint64_t, ASIC_MAX_SLICES_PER_DEVICE_NUM> orig_ics_slice_modes;
    status = control_deassert_soft_reset(la_dev, orig_ics_slice_modes, control_blocks, control_is_already_asserted);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    log_info(SOFT_RESET, "    Deassert DMC ...");
    std::vector<lld_block_scptr> dmc_blocks;
    std::vector<bool> dmc_is_already_asserted;
    status = dmc_deassert_soft_reset(ll_dev, dmc_blocks, dmc_is_already_asserted);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    log_info(SOFT_RESET, "    Deassert NPU ...");
    std::vector<lld_block_scptr> npu_blocks;
    std::vector<bool> npu_is_already_asserted;
    status = npu_deassert_soft_reset(la_dev, npu_blocks, npu_is_already_asserted);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    bool hbm_enabled = false;
    std::vector<lld_block_scptr> hbm_blocks;
    std::vector<bool> hbm_is_already_asserted;
    status = la_dev->hbm_exists(hbm_enabled);
    return_on_error(status);
    if (hbm_enabled) {
        log_info(SOFT_RESET, "    Deassert MMU HBM ...");
        status = mmu_hbm_deassert_soft_reset(la_dev, hbm_blocks, hbm_is_already_asserted);
        return_on_error(status);
        log_info(SOFT_RESET, "    Done.");
    }

    // Assert soft reset for components
    log_info(SOFT_RESET, "    Assert SMS ...");
    status = assert_soft_reset(ll_dev, sms_blocks, sms_is_already_asserted);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    log_info(SOFT_RESET, "    Assert control ...");
    status = control_assert_soft_reset(la_dev, fih, orig_ics_slice_modes, control_blocks, control_is_already_asserted);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    log_info(SOFT_RESET, "    Assert DMC ...");
    status = assert_soft_reset(ll_dev, dmc_blocks, dmc_is_already_asserted);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    log_info(SOFT_RESET, "    Assert NPU ...");
    status = npu_assert_soft_reset(la_dev, npu_blocks, npu_is_already_asserted);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    if (hbm_enabled) {
        log_info(SOFT_RESET, "    Assert MMU HBM ...");
        status = mmu_hbm_assert_soft_reset(la_dev, hbm_blocks, hbm_is_already_asserted);
        return_on_error(status);
        log_info(SOFT_RESET, "    Done.");
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::reset_bfd_session_timeout()
{
    la_status status;
    std::vector<la_bfd_session_base_wptr> armed_sessions;

    // Go through all sessions and disarm them.
    for (auto bfd_session_base : m_bfd_sessions) {
        if (bfd_session_base == nullptr) {
            continue;
        }
        if (bfd_session_base->is_armed()) {
            status = bfd_session_base->do_disarm_detection_timer();
            return_on_error(status);
            armed_sessions.push_back(bfd_session_base);
        }
    }

    // Clean out any current expired sessions from the eventq.
    poll_npu_host_event_queue();

    // Reenable session which were previously armed. The actual arming of the session
    // will be delayed for 1 detection period.
    for (const auto& bfd_session : armed_sessions) {
        if (bfd_session == nullptr) {
            continue;
        }

        status = bfd_session->do_arm_detection_timer();
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::soft_reset()
{
    start_api_call("");

    log_info(SOFT_RESET, "Soft reset starting ...");

    la_status status = LA_STATUS_EUNKNOWN;
    cem_wptr _cem;
    bit_vector reachable_devices_bv;
    fabric_protocol_state_t fabric_protocol_state;
    device_mac_pool_state mac_pool_state;
    packet_dma_state_t packet_dma_state;
    oq_active_list_t oq_active_list;
    bool is_fmc_elig_zero = true;

    // Sample remote devices reachability
    if (m_device_mode == device_mode_e::LINECARD) {
        la_status status = get_reachable_devices(reachable_devices_bv);
        return_on_error(status);
    }

    if (m_device_mode != device_mode_e::STANDALONE) {
        // Store fabric multicast eligibility status
        status = get_is_fmc_elig_is_zero(m_ll_device, is_fmc_elig_zero);
        return_on_error(status);
    }
    log_info(SOFT_RESET, "Done.");

    // Stop fabric protocols
    if (m_device_mode != device_mode_e::STANDALONE) {
        log_info(SOFT_RESET, "Stopping fabric protocols ...");
        status = stop_fabric_protocols(this, fabric_protocol_state);
        return_on_error(status);
        log_info(SOFT_RESET, "Done.");
    }

    // Stop network traffic
    log_info(SOFT_RESET, "Disabling OQs ...");
    status = oq_drop(m_ll_device, m_slice_id_manager, oq_active_list);
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    log_info(SOFT_RESET, "Stopping MAC pools ...");
    status = stop_mac_pools(this, mac_pool_state, packet_dma_state);
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    log_info(SOFT_RESET, "Stopping IFG buffers ...");
    status = start_stop_ifg_buffers(m_ll_device, get_slice_id_manager(), false /*start*/);
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    // Bring ARC to waiting state
    log_info(SOFT_RESET, "Suspending ARC ...");
    _cem = m_resource_manager->get_cem();
    if (_cem != nullptr) {
        status = _cem->set_soft_reset_mode(true);
        return_on_error(status);
    }
    log_info(SOFT_RESET, "Done.");

    // Bring CEM CAM to shadow
    log_info(SOFT_RESET, "Reading CEM CAM ...");
    status = read_cem_cam(m_ll_device);
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    // Reset components
    log_info(SOFT_RESET, "Reset components ...");
    status = reset_components(this, m_fabric_init_handler.get());
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    // Restore EM CAM data
    log_info(SOFT_RESET, "Restoring EM CAM data ...");
    status = restore_em_cam_data(m_ll_device);
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    // EM WA
    log_info(SOFT_RESET, "Exact match workaround ...");
    status = exact_match_wa();
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    // Make sure all the memories are clear
    log_info(SOFT_RESET, "Poll init  ...");
    status = poll_init_done();
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    // Resume ARC
    log_info(SOFT_RESET, "Resuming ARC ...");
    _cem = m_resource_manager->get_cem();
    if (_cem != nullptr) {
        status = _cem->set_soft_reset_mode(false);
        return_on_error(status);
    }
    log_info(SOFT_RESET, "Done.");

    // Resume network traffic
    log_info(SOFT_RESET, "Restarting IFG buffers...");
    status = start_stop_ifg_buffers(m_ll_device, get_slice_id_manager(), true /*start*/);
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    // Resume fabric protocols
    if (m_device_mode != device_mode_e::STANDALONE) {
        log_info(SOFT_RESET, "Restarting MAC pools for fabric ports...");
        status = start_mac_pools(this, mac_pool_state, packet_dma_state, la_slice_mode_e::CARRIER_FABRIC);
        return_on_error(status);
        log_info(SOFT_RESET, "Done.");

        log_info(SOFT_RESET, "Enabling OQs on fabric slices...");
        status = oq_restore(this, oq_active_list, la_slice_mode_e::CARRIER_FABRIC);
        return_on_error(status);
        log_info(SOFT_RESET, "Done.");

        log_info(SOFT_RESET, "Restaring fabric protocols ...");
        status = restart_fabric_protocols(this, fabric_protocol_state);
        return_on_error(status);
        log_info(SOFT_RESET, "Done.");
    }

    // Resume network traffic
    log_info(SOFT_RESET, "Restarting MAC pools for network ports...");
    status = start_mac_pools(this, mac_pool_state, packet_dma_state, la_slice_mode_e::NETWORK);
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    // Enable OQs
    log_info(SOFT_RESET, "Enabling OQs on network slices...");
    status = oq_restore(this, oq_active_list, la_slice_mode_e::NETWORK);
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    if (m_device_mode != device_mode_e::STANDALONE && fabric_protocol_state.frp_enabled) {
        // Clear fabric routing table
        log_info(SOFT_RESET, "Clearing FRT...");
        status = clear_frt(this);
        return_on_error(status);
        log_info(SOFT_RESET, "Done.");
    }

    if (m_device_mode == device_mode_e::LINECARD) {
        // Make all schedulers grant credits even if not requested
        log_info(SOFT_RESET, "Setting static go ...");
        status = set_sched_static_go(this, reachable_devices_bv);
        return_on_error(status);
        log_info(SOFT_RESET, "Done.");
    }

    // Clear interrupts
    log_info(SOFT_RESET, "Clear all pending interrupts ...");
    m_notification->get_interrupt_tree()->clear();
    log_info(SOFT_RESET, "Done.");

    if (m_device_mode != device_mode_e::STANDALONE) {
        // Clear the link-down reason
        log_info(SOFT_RESET, "Clear link-down reason ...");
        for (la_slice_id_t slice : get_used_slices()) {
            // Reading the register clears it
            ts_mon_link_status_reg_register tsmon_link;
            status = m_ll_device->read_register((*m_pacific_tree->ts_mon->link_status_reg)[slice], tsmon_link);
            return_on_error(status);
        }
        log_info(SOFT_RESET, "Done.");
    }

    if ((m_device_mode != device_mode_e::STANDALONE) && !is_fmc_elig_zero) {
        // Verify fabric multicast eligibility status
        bool new_is_fmc_elig_zero;
        status = get_is_fmc_elig_is_zero(m_ll_device, new_is_fmc_elig_zero);
        return_on_error(status);
        if (new_is_fmc_elig_zero) {
            log_err(SOFT_RESET, "Fabric MC eligibility vector is clear");
            return LA_STATUS_EAGAIN;
        }
    }

    // Restore IFGB shaper
    log_info(SOFT_RESET, "Restore IFGB shaper ...");
    status = apply_topology_post_soft_reset_workaround_ifgb();
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    // Toggle BFD timer
    log_info(SOFT_RESET, "Toggle BFD timer ...");
    status = toggle_bfd_timer(m_ll_device);
    return_on_error(status);
    status = reset_bfd_session_timeout();
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    log_info(SOFT_RESET, "Soft reset Done.");

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
