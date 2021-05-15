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
#include "common/bit_utils.h"
#include "common/bit_vector.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "hw_tables/cem.h"
#include "hw_tables/hw_tables_fwd.h"
#include "la_device_impl.h"
#include "lld/gibraltar_mem_structs.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "lld/lld_block.h"
#include "lld/lld_memory.h"
#include "lld/lld_register.h"
#include "lld/lld_strings.h"
#include "lld/lld_utils.h"
#include "npu/la_bfd_session_base.h"
#include "ra/resource_manager.h"
#include "system/ifg_handler.h"
#include "system/la_fabric_port_impl.h"
#include "system/la_hbm_handler_impl.h"
#include "system/la_pci_port_base.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_output_queue_scheduler_impl.h"
#include "tm/tm_utils.h"

namespace silicon_one
{

using namespace gibraltar;

// Hold a list of memory-line values for a single memory block
typedef std::vector<std::pair<lld_memory_scptr, std::vector<bit_vector> > > memory_lines_t;

// State of packet-DMA
struct packet_dma_state_t {
    std::vector<la_pci_port_base*> pci_ports; // PCI ports state
};

// Hold the rstn register state in mac-pools and ifg shaper cfg of a single IFG
struct ifg_state {
    std::array<mac_pool8_rstn_reg_register, 3> mac_pools;
    ifgb_24p_rx_shaper_cfg_register ifg_shaper;
};

// Hold the rstn register state in mac-pools and ifg shaper cfg of a single device
struct device_ifg_state {
    ifg_state& get_ifg_state(la_slice_id_t slice, la_slice_id_t ifg)
    {
        return ifgs[slice * NUM_IFGS_PER_SLICE + ifg];
    }

private:
    std::array<ifg_state, NUM_IFGS_PER_DEVICE> ifgs;
};

// Hold fabric protocol state
struct fabric_protocol_state_t {
    std::vector<frm_fabric_routing_table_memory> frt_lines;
    std::vector<frm_low_rev_fabric_routing_table_memory> low_rev_frt_lines;
    std::vector<frm_high_rev_fabric_routing_table_memory> high_rev_frt_lines;
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
    la_status status = ll_dev->read_register(*srstn_reg, regval_bv);
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

static size_t
get_num_mac_pools(const la_device_impl* la_dev, la_slice_id_t slice, la_ifg_id_t ifg)
{
    size_t num_mac_pools = la_dev->m_ifg_handlers[slice][ifg]->get_serdes_count() / la_mac_port_base::NUM_SERDESES_IN_MAC_POOL8;
    return num_mac_pools;
}

// Deassert the mac-pools in the given IFG.
// Returns the previous rstn state of the mac-pools.
static la_status
deassert_mac_pools(const la_device_impl* la_dev,
                   la_slice_id_t slice,
                   la_ifg_id_t ifg,
                   ifg_state& out_ifg_state,
                   lld_register_value_list_t& reg_val_list)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto gbt = ll_dev->get_gibraltar_tree();
    uint64_t regval = 0;

    // Deassert MAC pool 8
    size_t num_mac_pools = get_num_mac_pools(la_dev, slice, ifg);
    for (size_t mp = 0; mp < num_mac_pools; mp++) {

        mac_pool8_rstn_reg_register r8;
        la_status status = ll_dev->read_register(gbt->slice[slice]->ifg[ifg]->mac_pool8[mp]->rstn_reg, r8);
        return_on_error(status);

        // Store the current state
        out_ifg_state.mac_pools[mp] = r8;

        // Write the new state to the Tx ports
        r8.fields.tx_mac_rstn0 = regval;
        r8.fields.tx_mac_rstn1 = regval;
        r8.fields.tx_mac_rstn2 = regval;
        r8.fields.tx_mac_rstn3 = regval;
        r8.fields.tx_mac_rstn4 = regval;
        r8.fields.tx_mac_rstn5 = regval;
        r8.fields.tx_mac_rstn6 = regval;
        r8.fields.tx_mac_rstn7 = regval;
        reg_val_list.push_back({(gbt->slice[slice]->ifg[ifg]->mac_pool8[mp]->rstn_reg), r8});

        // Write the new state to the Rx ports
        r8.fields.rx_mac_rstn0 = regval;
        r8.fields.rx_mac_rstn1 = regval;
        r8.fields.rx_mac_rstn2 = regval;
        r8.fields.rx_mac_rstn3 = regval;
        r8.fields.rx_mac_rstn4 = regval;
        r8.fields.rx_mac_rstn5 = regval;
        r8.fields.rx_mac_rstn6 = regval;
        r8.fields.rx_mac_rstn7 = regval;
        reg_val_list.push_back({(gbt->slice[slice]->ifg[ifg]->mac_pool8[mp]->rstn_reg), r8});
    }

    return LA_STATUS_SUCCESS;
}

// Restore the mac-pools in the given IFG.
static la_status
restore_mac_pools(const la_device_impl* la_dev,
                  la_slice_id_t slice,
                  la_ifg_id_t ifg,
                  ifg_state& ifg_state,
                  lld_register_value_list_t& reg_val_list)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto gbt = ll_dev->get_gibraltar_tree();

    size_t num_mac_pools = get_num_mac_pools(la_dev, slice, ifg);
    for (size_t mp = 0; mp < num_mac_pools; mp++) {

        mac_pool8_rstn_reg_register r8;
        la_status status = ll_dev->read_register(gbt->slice[slice]->ifg[ifg]->mac_pool8[mp]->rstn_reg, r8);
        return_on_error(status);

        // Write the old state to the Rx ports
        r8.fields.rx_mac_rstn0 = ifg_state.mac_pools[mp].fields.rx_mac_rstn0;
        r8.fields.rx_mac_rstn1 = ifg_state.mac_pools[mp].fields.rx_mac_rstn1;
        r8.fields.rx_mac_rstn2 = ifg_state.mac_pools[mp].fields.rx_mac_rstn2;
        r8.fields.rx_mac_rstn3 = ifg_state.mac_pools[mp].fields.rx_mac_rstn3;
        r8.fields.rx_mac_rstn4 = ifg_state.mac_pools[mp].fields.rx_mac_rstn4;
        r8.fields.rx_mac_rstn5 = ifg_state.mac_pools[mp].fields.rx_mac_rstn5;
        r8.fields.rx_mac_rstn6 = ifg_state.mac_pools[mp].fields.rx_mac_rstn6;
        r8.fields.rx_mac_rstn7 = ifg_state.mac_pools[mp].fields.rx_mac_rstn7;
        reg_val_list.push_back({(gbt->slice[slice]->ifg[ifg]->mac_pool8[mp]->rstn_reg), r8});

        // Write the old state to the Tx ports
        r8.fields.tx_mac_rstn0 = ifg_state.mac_pools[mp].fields.tx_mac_rstn0;
        r8.fields.tx_mac_rstn1 = ifg_state.mac_pools[mp].fields.tx_mac_rstn1;
        r8.fields.tx_mac_rstn2 = ifg_state.mac_pools[mp].fields.tx_mac_rstn2;
        r8.fields.tx_mac_rstn3 = ifg_state.mac_pools[mp].fields.tx_mac_rstn3;
        r8.fields.tx_mac_rstn4 = ifg_state.mac_pools[mp].fields.tx_mac_rstn4;
        r8.fields.tx_mac_rstn5 = ifg_state.mac_pools[mp].fields.tx_mac_rstn5;
        r8.fields.tx_mac_rstn6 = ifg_state.mac_pools[mp].fields.tx_mac_rstn6;
        r8.fields.tx_mac_rstn7 = ifg_state.mac_pools[mp].fields.tx_mac_rstn7;
        reg_val_list.push_back({(gbt->slice[slice]->ifg[ifg]->mac_pool8[mp]->rstn_reg), r8});
    }

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
stop_mac_pools(const la_device_impl* la_dev, device_ifg_state& dev_state, packet_dma_state_t& packet_dma_state)
{
    lld_register_value_list_t reg_val_list;
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto gbt = ll_dev->get_gibraltar_tree();

    // Stop packet-DMA traffic
    la_status status = stop_packet_dma(la_dev, ll_dev, packet_dma_state);
    return_on_error(status);
    for (la_slice_id_t slice : la_dev->get_used_slices()) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            ifg_state& out_ifg_state = dev_state.get_ifg_state(slice, ifg);
            la_status status = ll_dev->read_register(gbt->slice[slice]->ifg[ifg]->ifgb->rx_shaper_cfg, out_ifg_state.ifg_shaper);
            return_on_error(status);
            // Stop Network traffic
            status = deassert_mac_pools(la_dev, slice, ifg, out_ifg_state, reg_val_list);
            return_on_error(status);
        }
    }

    return lld_write_register_list(ll_dev, reg_val_list);
}

static la_status
start_stop_oob_extract_logic(const la_device_impl* la_dev, const slice_manager_smart_ptr& sid_mgr, bool start)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto gbt = ll_dev->get_gibraltar_tree();
    uint64_t val = start ? 1 : 0;
    lld_register_value_list_t reg_val_list;
    ifgb_24p_rx_rstn_reg_register rx_rstn_reg;
    la_status status;

    for (la_slice_id_t slice : sid_mgr->get_used_slices_internal()) {
        if (la_dev->is_network_slice(slice)) {
            continue;
        }
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            status = ll_dev->read_register(gbt->slice[slice]->ifg[ifg]->ifgb->rx_rstn_reg, rx_rstn_reg);
            return_on_error(status);
            rx_rstn_reg.fields.rx_oobe_rstn = val;
            reg_val_list.push_back({(gbt->slice[slice]->ifg[ifg]->ifgb->rx_rstn_reg), rx_rstn_reg});
        }
    }

    return lld_write_register_list(ll_dev, reg_val_list);
}

// Stop or start IFGBs
static la_status
start_stop_ifg_buffers(ll_device_sptr ll_dev, const slice_manager_smart_ptr& sid_mgr, bool start)
{
    auto gbt = ll_dev->get_gibraltar_tree();
    uint64_t val = start ? 1 : 0;
    lld_register_value_list_t reg_val_list;

    for (la_slice_id_t slice : sid_mgr->get_used_slices_internal()) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            reg_val_list.push_back({(gbt->slice[slice]->ifg[ifg]->ifgb->soft_reset_configuration), val});
        }
    }

    return lld_write_register_list(ll_dev, reg_val_list);
}

// On exit - take ports out of reset mode
static la_status
start_mac_pools(const la_device_impl* la_dev,
                device_ifg_state& dev_state,
                packet_dma_state_t& packet_dma_state,
                la_slice_mode_e req_slice_mode)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto gbt = ll_dev->get_gibraltar_tree();
    lld_register_value_list_t reg_val_list;
    la_status status;

    for (la_slice_id_t slice : la_dev->get_used_slices()) {
        la_slice_mode_e curr_slice_mode;
        status = la_dev->get_slice_mode(slice, curr_slice_mode);
        return_on_error(status);

        bool restore_pool = (req_slice_mode == curr_slice_mode);
        if (restore_pool) {
            for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
                ifg_state& out_ifg_state = dev_state.get_ifg_state(slice, ifg);
                status = restore_mac_pools(la_dev, slice, ifg, out_ifg_state, reg_val_list);
                return_on_error(status);
                reg_val_list.push_back({(gbt->slice[slice]->ifg[ifg]->ifgb->rx_shaper_cfg), out_ifg_state.ifg_shaper});
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

static la_status
save_frt(la_device_impl* la_dev, fabric_protocol_state_t& fps)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto gbt = ll_dev->get_gibraltar_tree();

    auto& frt = gbt->dmc->frm->fabric_routing_table;
    auto& low_rev_frt = gbt->dmc->frm->low_rev_fabric_routing_table;
    auto& high_rev_frt = gbt->dmc->frm->high_rev_fabric_routing_table;
    size_t frt_entries_nr = frt->get_desc()->entries;
    size_t low_rev_frt_entries_nr = low_rev_frt->get_desc()->entries;
    size_t high_rev_frt_entries_nr = high_rev_frt->get_desc()->entries;

    fps.frt_lines.clear();
    fps.frt_lines.reserve(frt_entries_nr);
    fps.low_rev_frt_lines.clear();
    fps.low_rev_frt_lines.reserve(low_rev_frt_entries_nr);
    fps.high_rev_frt_lines.clear();
    fps.high_rev_frt_lines.reserve(high_rev_frt_entries_nr);
    // FRT
    for (size_t idx = 0; idx < frt_entries_nr; idx++) {
        frm_fabric_routing_table_memory line;
        la_status status = ll_dev->read_memory(frt, idx, line);
        return_on_error(status);
        fps.frt_lines.push_back(line);
    }
    // Reverse FRT
    for (size_t idx = 0; idx < low_rev_frt_entries_nr; idx++) {
        frm_low_rev_fabric_routing_table_memory line;
        la_status status = ll_dev->read_memory(low_rev_frt, idx, line);
        return_on_error(status);
        fps.low_rev_frt_lines.push_back(line);
    }
    for (size_t idx = 0; idx < high_rev_frt_entries_nr; idx++) {
        frm_high_rev_fabric_routing_table_memory line;
        la_status status = ll_dev->read_memory(high_rev_frt, idx, line);
        return_on_error(status);
        fps.high_rev_frt_lines.push_back(line);
    }
    return LA_STATUS_SUCCESS;
}

static la_status
restore_frt(la_device_impl* la_dev, fabric_protocol_state_t& frp)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto gbt = ll_dev->get_gibraltar_tree();

    auto& frt = gbt->dmc->frm->fabric_routing_table;
    auto& low_rev_frt = gbt->dmc->frm->low_rev_fabric_routing_table;
    auto& high_rev_frt = gbt->dmc->frm->high_rev_fabric_routing_table;
    size_t frt_entries_nr = frt->get_desc()->entries;
    size_t low_rev_frt_entries_nr = low_rev_frt->get_desc()->entries;
    size_t high_rev_frt_entries_nr = high_rev_frt->get_desc()->entries;

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
    for (size_t idx = 0; idx < low_rev_frt_entries_nr; idx++) {
        write_list.push_back({{low_rev_frt, idx}, frp.low_rev_frt_lines[idx]});
    }
    for (size_t idx = 0; idx < high_rev_frt_entries_nr; idx++) {
        write_list.push_back({{high_rev_frt, idx}, frp.high_rev_frt_lines[idx]});
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
    auto gbt = ll_dev->get_gibraltar_tree();
    lld_memory_line_value_list_t mem_line_val_list;

    // FRT
    size_t entries_nr = gbt->dmc->frm->fabric_routing_table->get_desc()->entries;
    for (size_t line = 0; line < entries_nr; line++) {
        mem_line_val_list.push_back({{gbt->dmc->frm->fabric_routing_table, line}, 0});
    }

    // Reverse FRT
    entries_nr = gbt->dmc->frm->low_rev_fabric_routing_table->get_desc()->entries;
    for (size_t line = 0; line < entries_nr; line++) {
        mem_line_val_list.push_back({{gbt->dmc->frm->low_rev_fabric_routing_table, line}, 0});
    }
    entries_nr = gbt->dmc->frm->high_rev_fabric_routing_table->get_desc()->entries;
    for (size_t line = 0; line < entries_nr; line++) {
        mem_line_val_list.push_back({{gbt->dmc->frm->high_rev_fabric_routing_table, line}, 0});
    }

    la_status status = lld_write_memory_line_list(ll_dev, mem_line_val_list);
    return_on_error(status);

    // Allow the FRT to be reconstructed
    for (size_t _sleep = 0; _sleep < 64ull; _sleep++) {
        SPINLOCK_NOP;
    }

    log_info(SOFT_RESET, "Done.");

    return LA_STATUS_SUCCESS;
}

// Reset EM CAM memories in selected blocks
static la_status
reset_em_cam_data(ll_device_sptr ll_dev)
{
    auto gbt = ll_dev->get_gibraltar_tree();
    auto blocks = gbt->get_leaf_blocks();
    la_status status = LA_STATUS_EUNKNOWN;

    std::vector<std::string> block_names{"pp_reorder",
                                         "nw_reorder_block",
                                         "fllb", // Yes "fllb", not "filb"
                                         "fdll",
                                         "pdvoq",
                                         "pdoq",
                                         "rxpp_term.flc_db"};

    for (auto block : blocks) {
        if (filter_block_by_name(block, block_names)) {
            for (auto mem : block->get_memories()) {
                auto desc = mem->get_desc();
                if (desc->subtype == lld_memory_subtype_e::REG_CAM) {
                    status = ll_dev->fill_memory(*mem, 0, desc->entries, 0);
                    return_on_error(status);
                }
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

// Deassert soft-reset in DMC
static la_status
dmc_deassert_soft_reset(ll_device_sptr ll_dev, std::vector<lld_block_scptr>& blocks, std::vector<bool>& out_is_active)
{
    auto gbt = ll_dev->get_gibraltar_tree();

    blocks = {gbt->dmc->frm, gbt->dmc->fte, gbt->dmc->pier, gbt->dmc->mrb, gbt->csms};

    return deassert_soft_reset(ll_dev, blocks, out_is_active);
}

// Deassert soft-reset in SMS module
static la_status
sms_deassert_soft_reset(ll_device_sptr ll_dev, std::vector<lld_block_scptr>& blocks, std::vector<bool>& out_is_active)
{
    auto gbt = ll_dev->get_gibraltar_tree();

    lld_reg_mem_line_value_list_t write_list;
    blocks = {gbt->sms_quad[0], gbt->sms_quad[1], gbt->sms_quad[2], gbt->sms_quad[3], gbt->sms_main};

    return deassert_soft_reset(ll_dev, blocks, out_is_active);
}

// Pause/resume ICS module according to the given argument
static la_status
ics_pause_resume(ll_device_sptr ll_dev, bool pause, const slice_manager_smart_ptr& sid_mgr)
{
    auto gbt = ll_dev->get_gibraltar_tree();
    lld_reg_mem_line_value_list_t write_list;

    for (la_slice_id_t slice : sid_mgr->get_used_slices_internal()) {
        ics_slice_general_conf_reg_register reg;

        la_status status = ll_dev->read_register(gbt->slice[slice]->ics->general_conf_reg, reg);
        return_on_error(status);

        reg.fields.pause_checkin_machine = pause ? 1 : 0;

        write_list.push_back({lld_reg_mem_line((gbt->slice[slice]->ics->general_conf_reg)), reg});
        write_list.push_back({lld_reg_mem_line((gbt->slice[slice]->ics->delete_credits_trig)), pause ? 0 : 1});
    }

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

// Return a list of all the blocks of the control
static void
get_control_blocks(const gibraltar_tree* gbt, std::vector<lld_block_scptr>& out_blocks)
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

    auto blocks = gbt->get_leaf_blocks();
    for (auto block : blocks) {
        if (!filter_block_by_name(block, block_names)) {
            continue;
        }

        out_blocks.push_back(block);
    }
}

// Clear 'aged-out' marking for all contexts
static la_status
ics_set_aging(ll_device_sptr ll_dev, const slice_manager_smart_ptr& sid_mgr)
{
    auto gbt = ll_dev->get_gibraltar_tree();

    for (la_slice_id_t slice : sid_mgr->get_used_slices_internal()) {
        size_t entries_nr = gbt->slice[slice]->ics->aged_out_queue->get_desc()->entries;
        la_status status = ll_dev->fill_memory(*gbt->slice[slice]->ics->aged_out_queue,
                                               0, // mem_first_entry
                                               entries_nr,
                                               0); // in_bv
        return_on_error(status);

        status = ll_dev->write_register(gbt->slice[slice]->ics->scrb_aging_trig_reg, 1);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

// Return the number of credits for a given port
static la_status
get_pdoq_num_credits(ll_device_sptr ll_dev, la_slice_id_t slice, la_ifg_id_t ifg, unsigned port, size_t& out_num_credits)
{
    auto gbt = ll_dev->get_gibraltar_tree();
    unsigned num_credits = 0;

    constexpr la_uint_t TX_DATA_WIDTH = 32;  // bytes
    constexpr la_uint_t RCY_DATA_WIDTH = 16; // bytes

    if (port < 24) {
        ifgb_24p_tx_fif_cfg_register reg;
        la_status status = ll_dev->read_register((*gbt->slice[slice]->ifg[ifg]->ifgb->tx_fif_cfg)[port], reg);
        return_on_error(status);

        num_credits = (reg.fields.tx_f_end_addr - reg.fields.tx_f_start_addr + 1) * TX_DATA_WIDTH - 8; // -8 is design limitation
    } else if (port == 24) {
        ifgb_24p_tx_fif_cfg24_register reg;
        la_status status = ll_dev->read_register(gbt->slice[slice]->ifg[ifg]->ifgb->tx_fif_cfg24, reg);
        return_on_error(status);

        num_credits
            = (reg.fields.tx_f24_end_addr - reg.fields.tx_f24_start_addr + 1) * TX_DATA_WIDTH - 8; // -8 is design limitation
    } else if (port == 25) {
        ifgb_24p_rcy_fif_cfg_register reg;
        la_status status = ll_dev->read_register(gbt->slice[slice]->ifg[ifg]->ifgb->rcy_fif_cfg, reg);
        return_on_error(status);

        num_credits = (reg.fields.rcy_fif_sched_end_addr - reg.fields.rcy_fif_sched_start_addr + 1) * RCY_DATA_WIDTH;
    }

    out_num_credits = num_credits;

    return LA_STATUS_SUCCESS;
}

// Check whether the given port is active or not
static la_status
is_active_ifg_port(ll_device_sptr ll_dev, la_slice_id_t slice, la_ifg_id_t ifg, unsigned port, bool& out_is_active)
{
    auto gbt = ll_dev->get_gibraltar_tree();

    auto m = (*gbt->slice[slice]->pdoq->fdoq->fdoq_ifg_calendar)[ifg];
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

    out_is_active = 0;

    return LA_STATUS_SUCCESS;
}

// Reset credits of all ports in the device
static la_status
pdoq_reset_credits(ll_device_sptr ll_dev, const slice_manager_smart_ptr& sid_mgr)
{
    lld_reg_mem_line_value_list_t write_list;
    auto gbt = ll_dev->get_gibraltar_tree();

    for (la_slice_id_t slice : sid_mgr->get_used_slices_internal()) {
        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            for (unsigned port = 0; port < tm_utils::TM_IFG_SYSTEM_PORT_SCHEDULERS; port++) {

                size_t num_credits = 0;
                bool is_active = false;
                la_status status = is_active_ifg_port(ll_dev, slice, ifg, port, is_active);
                return_on_error(status);

                if (is_active) {
                    status = get_pdoq_num_credits(ll_dev, slice, ifg, port, num_credits);
                    return_on_error(status);
                }

                pdoq_fdoq_ifg_credit_init_register reg;
                status = ll_dev->read_register(gbt->slice[slice]->pdoq->fdoq->ifg_credit_init, reg);
                return_on_error(status);

                pdoq_fdoq_fdoq_general_configuration_register data;
                status = ll_dev->read_register(gbt->slice[slice]->pdoq->fdoq->fdoq_general_configuration, data);
                return_on_error(status);

                // NOTE: MLP mode 3 (1200G - all 3 mac pools) is not yet supported in SDK API.
                enum {
                    MLP_MASTER = (uint)la_mac_port::mlp_mode_e::MLP_MASTER,
                    MLP_SLAVE = (uint)la_mac_port::mlp_mode_e::MLP_SLAVE,
                    MLP_1200 = 3
                };

                la_uint_t port_in_slice = ifg * tm_utils::TM_IFG_SYSTEM_PORT_SCHEDULERS + port;
                uint64_t mlp_mode = bit_utils::get_bits(data.fields.mlp_mode, ifg * 2 + 1, ifg * 2);
                if ((mlp_mode == MLP_MASTER && port == 0) || (mlp_mode == MLP_SLAVE && port == 8)) {
                    reg.fields.ifg_credit_init_enable = bit_utils::set_bit(
                        reg.fields.ifg_credit_init_enable, port_in_slice + la_mac_port_base::NUM_SERDESES_IN_MAC_POOL8, 1);
                } else if (mlp_mode == MLP_1200 && port == 0) {
                    reg.fields.ifg_credit_init_enable = bit_utils::set_bit(
                        reg.fields.ifg_credit_init_enable, port_in_slice + la_mac_port_base::NUM_SERDESES_IN_MAC_POOL8 * 2, 1);
                } else {
                    reg.fields.ifg_credit_init_enable = bit_utils::set_bit(reg.fields.ifg_credit_init_enable, port_in_slice, 1);
                }

                reg.fields.ifg_credit_init_value = num_credits;
                write_list.push_back({lld_reg_mem_line((gbt->slice[slice]->pdoq->fdoq->ifg_credit_init)), reg});
            }
        }
    }

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

// Clear TXCGM memories
static la_status
txcgm_reset_mem(ll_device_sptr ll_dev, const slice_manager_smart_ptr& sid_mgr)
{
    auto gbt = ll_dev->get_gibraltar_tree();

    for (la_slice_id_t slice : sid_mgr->get_used_slices_internal()) {
        lld_memory_scptr uc_oq_state_mem = gbt->slice[slice]->tx->cgm->uc_oq_state;
        size_t entries_nr = uc_oq_state_mem->get_desc()->entries;
        la_status status = ll_dev->fill_memory(*uc_oq_state_mem, 0, entries_nr, 0);
        return_on_error(status);

        lld_memory_scptr mc_qsize_byte_mem = gbt->slice[slice]->tx->cgm->mc_qsize_byte;
        entries_nr = mc_qsize_byte_mem->get_desc()->entries;
        status = ll_dev->fill_memory(*mc_qsize_byte_mem, 0, entries_nr, 0);
        return_on_error(status);

        lld_memory_scptr mc_qsize_pd_mem = gbt->slice[slice]->tx->cgm->mc_qsize_pd;
        entries_nr = mc_qsize_pd_mem->get_desc()->entries;
        status = ll_dev->fill_memory(*mc_qsize_pd_mem, 0, entries_nr, 0);
        return_on_error(status);

        lld_memory_scptr uc_oqg_state_mem = gbt->slice[slice]->tx->cgm->uc_oqg_state;
        entries_nr = uc_oqg_state_mem->get_desc()->entries;
        status = ll_dev->fill_memory(*uc_oqg_state_mem, 0, entries_nr, 0);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

// Reset FE link bundles
static la_status
reset_fe_link_bundles(la_device_impl* la_dev)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto gbt = ll_dev->get_gibraltar_tree();
    lld_reg_mem_line_value_list_t write_list;

    if (la_dev->m_device_mode != device_mode_e::FABRIC_ELEMENT) {
        return LA_STATUS_SUCCESS;
    }

    for (la_slice_id_t slice : la_dev->get_used_slices()) {
        auto m = (*gbt->slice_pair[slice / 2]->rx_pdr->fe_uc_link_bundle_desc_table)[slice % 2];
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
    auto gbt = ll_dev->get_gibraltar_tree();
    lld_reg_mem_line_value_list_t write_list;

    ////////arrrg - that looks really bad for the mathilda, what to do here? ASIC_MAX_SLICES_PER_DEVICE_NUM
    for (size_t slice_num = 0; slice_num < array_size(gbt->slice); slice_num++) {
        ics_slice_slice_mode_reg_register ics_slice_mode;
        la_status status = ll_dev->read_register(gbt->slice[slice_num]->ics->slice_mode_reg, ics_slice_mode);
        return_on_error(status);
        out_orig_ics_slice_modes[slice_num] = ics_slice_mode.fields.ics_mode;
        ics_slice_mode.fields.ics_mode = (uint64_t)la_device_impl::tm_slice_mode_e::STANDALONE;
        status = ll_dev->write_register(gbt->slice[slice_num]->ics->slice_mode_reg, ics_slice_mode);
        return_on_error(status);
    }

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

// Restore ICS slice mode
static la_status
ics_slice_mode_wa_leave(la_device_impl* la_dev, const std::array<uint64_t, ASIC_MAX_SLICES_PER_DEVICE_NUM>& orig_ics_slice_modes)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto gbt = ll_dev->get_gibraltar_tree();
    lld_reg_mem_line_value_list_t write_list;

    for (size_t slice_num = 0; slice_num < array_size(gbt->slice); slice_num++) {
        la_uint_t sm = orig_ics_slice_modes[slice_num];
        ics_slice_slice_mode_reg_register ics_slice_mode;
        ics_slice_mode.fields.ics_mode = sm;
        la_status status = ll_dev->write_register(gbt->slice[slice_num]->ics->slice_mode_reg, ics_slice_mode);
        return_on_error(status);
    }

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

static la_status
reset_shapers_token_bucket(ll_device_sptr ll_dev)
{
    auto gbt = ll_dev->get_gibraltar_tree();

    lld_register_value_list_t write_list;

    for (auto& slice : gbt->slice) {
        for (int ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            write_list.push_back({(slice->ifg[ifg]->sch->lpse_cir_shaper_init), 1});
            write_list.push_back({(slice->ifg[ifg]->sch->tpse_cir_shaper_init), 1});
            write_list.push_back({(slice->ifg[ifg]->sch->lpse_eir_shaper_init), 1});
            write_list.push_back({(slice->ifg[ifg]->sch->tpse_pir_shaper_init), 1});
            write_list.push_back({(*slice->pdoq->top->tpse_cir_shaper_init)[ifg], 1});
            write_list.push_back({(*slice->pdoq->top->tpse_pir_shaper_init)[ifg], 1});
        }
    }

    return lld_write_register_list(ll_dev, write_list);
}

static la_status
reset_dram_cgm(ll_device_sptr ll_dev)
{
    auto gbt = ll_dev->get_gibraltar_tree();

    dram_cgm_time_control_cfg_register reg;
    la_status status = ll_dev->read_register(gbt->dram_cgm->time_control_cfg, reg);
    return_on_error(status);

    lld_register_value_list_t write_list;

    reg.fields.count_enable = 0;
    write_list.push_back({(gbt->dram_cgm->time_control_cfg), reg});
    reg.fields.count_enable = 1;
    write_list.push_back({(gbt->dram_cgm->time_control_cfg), reg});

    return lld_write_register_list(ll_dev, write_list);
}

// This function is copy/pasted from fabric_init_handler AS IS
static la_status
prepare_pdvoq_context_allocate(lld_memory_line_value_list_t& mem_line_val_list,
                               lld_memory_scptr context_allocate_grant_set,
                               lld_memory_scptr context_allocate_set_master,
                               lld_memory_scptr context_allocate_set_slave)
{
    // Indicate that the MS-VOQs dont need credits. They can send a packet as soon as they get it.
    // This assumes that the line width and data of context_allocate_grant_set, context_allocate_set_master,
    // context_allocate_set_slave are the same.

    size_t grant_set_line_width = context_allocate_grant_set->get_desc()->width_bits;
    dassert_crit(grant_set_line_width == context_allocate_set_master->get_desc()->width_bits);
    dassert_crit(grant_set_line_width == context_allocate_set_slave->get_desc()->width_bits);

    size_t line_width = grant_set_line_width;

    size_t num_of_lines_to_write = div_round_up(MAX_NUM_OF_MSVOQS_PER_SLICE, line_width);
    size_t num_of_bits_to_set = MAX_NUM_OF_MSVOQS_PER_SLICE;

    for (size_t mem_line = 0; mem_line < num_of_lines_to_write; mem_line++) {
        // Create a vector with num_of_bits_to_set_in_line LSB bits set, and the rest reset.
        size_t num_of_bits_to_set_in_line = std::min(num_of_bits_to_set, line_width);
        bit_vector line_data = bit_vector::ones_range(num_of_bits_to_set_in_line - 1 /*msb*/, 0 /*lsb*/, line_width /*width*/);

        mem_line_val_list.push_back({{(context_allocate_grant_set), mem_line}, line_data});
        mem_line_val_list.push_back({{(context_allocate_set_master), mem_line}, line_data});
        mem_line_val_list.push_back({{(context_allocate_set_slave), mem_line}, line_data});
        num_of_bits_to_set -= line_width;
    }

    return LA_STATUS_SUCCESS;
}

static la_status
configure_pdvoq_context_allocate(la_device_impl* la_dev)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto gbt = ll_dev->get_gibraltar_tree();

    lld_memory_line_value_list_t write_list;

    for (size_t slice : la_dev->get_used_slices()) {
        if (la_dev->m_slice_mode[slice] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }
        prepare_pdvoq_context_allocate(write_list,
                                       gbt->slice[slice]->pdvoq->context_allocate_grant_set,
                                       gbt->slice[slice]->pdvoq->context_allocate_set_master,
                                       gbt->slice[slice]->pdvoq->context_allocate_set_slave);
    }

    return lld_write_memory_line_list(ll_dev, write_list);
}

// Reset the MS VOQ credit count
static la_status
reset_ms_voq_credit_count(la_device_impl* la_dev)
{
    la_slice_id_t rep_sid = la_dev->first_active_slice_id();
    la_slice_id_t fab_slice = la_dev->get_slice_id_manager()->first_possible_fabric_slice_in_lc();
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto gbt = ll_dev->get_gibraltar_tree();
    lld_reg_mem_line_value_list_t write_list;

    // This cfg is the same for all tsms fifo in LC (dest slices 0,1,2 source slices 3,4,5) and in FE (all to all).
    // We use dest slice 0 and source slice 3, which works for both.
    tsms_tsms_fifo_th_configuration_register fifo_reg;
    la_status status = ll_dev->read_register((*gbt->slice[rep_sid]->ts_ms->tsms_fifo_th_configuration)[fab_slice], fifo_reg);
    return_on_error(status);

    for (size_t slice_num = 0; slice_num < array_size(gbt->slice); slice_num++) {
        if (la_dev->m_slice_mode[slice_num] != la_slice_mode_e::CARRIER_FABRIC) {
            continue;
        }

        ics_slice_ms_q_conf_register ics_slice_ms_q_conf;

        status = ll_dev->read_register(gbt->slice[slice_num]->ics->ms_q_conf, ics_slice_ms_q_conf);
        return_on_error(status);
        ics_slice_ms_q_conf.fields.ms_q_uch_crdts = fifo_reg.fields.rlb_uch_fifo_size;
        ics_slice_ms_q_conf.fields.ms_q_ucl_crdts = fifo_reg.fields.rlb_ucl_fifo_size;
        ics_slice_ms_q_conf.fields.ms_q_mc_crdts = fifo_reg.fields.rlb_mc_fifo_size;
        write_list.push_back({lld_reg_mem_line((gbt->slice[slice_num]->ics->ms_q_conf)), ics_slice_ms_q_conf});
    }

    return lld_write_memory_line_or_register_list(ll_dev, write_list);
}

// Configure reorder for fabric slices
static la_status
reorder_soft_reset_fe_lc(la_device_impl* la_dev)
{
    la_status status = LA_STATUS_EUNKNOWN;
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto gbt = ll_dev->get_gibraltar_tree();

    bit_vector zeros(0, 64);
    bit_vector ones = bit_vector::ones(64);

    // First 4 entries in nw_exact_match_fbm are set to all ones, the rest are set to zeros
    constexpr size_t INITIAL_ONES_COUNT = 4;

    for (la_slice_id_t slice : la_dev->get_slice_id_manager()->get_slices_by_fabric_type(fabric_slices_type_e::HW_FABRIC)) {
        for (auto& reorder_block : gbt->slice[slice]->nw_reorder_block) {
            for (size_t fbm = 0; fbm < reorder_block->nw_exact_match_fbm->size(); fbm++) {
                lld_memory_scptr fbm_mem = (*reorder_block->nw_exact_match_fbm)[fbm];
                size_t total = fbm_mem->get_desc()->entries;
                status = ll_dev->fill_memory(*fbm_mem, 0, INITIAL_ONES_COUNT, ones);
                return_on_error(status);
                status = ll_dev->fill_memory(*fbm_mem, INITIAL_ONES_COUNT, total - INITIAL_ONES_COUNT, zeros);
                return_on_error(status);
            }
        }
    }
    for (la_slice_id_t slice : la_dev->get_slice_id_manager()->get_slices_by_fabric_type(fabric_slices_type_e::HW_FABRIC)) {
        for (auto& reorder_block : gbt->slice[slice]->nw_reorder_block) {
            nw_reorder_block_soft_reset_configuration_register reg;
            reg.fields.soft_rstn = 0;
            status = ll_dev->write_register(reorder_block->soft_reset_configuration, reg);
            return_on_error(status);
            reg.fields.soft_rstn = 1;
            status = ll_dev->write_register(reorder_block->soft_reset_configuration, reg);
        }
    }

    // Trigger reset
    nw_reorder_soft_reset_configuration_register reg;
    reg.fields.soft_rstn = 0;
    status = ll_dev->write_register(gbt->nw_reorder->soft_reset_configuration, reg);
    return_on_error(status);
    reg.fields.soft_rstn = 1;
    status = ll_dev->write_register(gbt->nw_reorder->soft_reset_configuration, reg);
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
    auto gbt = ll_dev->get_gibraltar_tree();

    log_debug(SOFT_RESET, "    ics_pause_resume ...");
    la_status status = ics_pause_resume(ll_dev, true /*pause*/, la_dev->get_slice_id_manager());
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    log_debug(SOFT_RESET, "    ics_slice_mode_wa_enter...");
    orig_ics_slice_modes.fill((uint64_t)la_device_impl::tm_slice_mode_e::STANDALONE);
    status = ics_slice_mode_wa_enter(la_dev, orig_ics_slice_modes);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    log_debug(SOFT_RESET, "    deassert_control_blocks ...");
    get_control_blocks(gbt, blocks);
    status = deassert_soft_reset(ll_dev, blocks, out_is_active);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    return LA_STATUS_SUCCESS;
}

// Perform soft-reset sequence on control modules
static la_status
control_assert_soft_reset(la_device_impl* la_dev,
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
        status = reorder_soft_reset_fe_lc(la_dev);
        return_on_error(status);
        log_debug(SOFT_RESET, "    done");
    }
    auto sid_mgr = la_dev->get_slice_id_manager();

    status = ics_pause_resume(ll_dev, false /*pause*/, sid_mgr);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    status = ics_set_aging(ll_dev, sid_mgr);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    status = pdoq_reset_credits(ll_dev, sid_mgr);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    status = reset_shapers_token_bucket(ll_dev);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    status = reset_dram_cgm(ll_dev);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    if (la_dev->m_device_mode != device_mode_e::STANDALONE) {
        status = configure_pdvoq_context_allocate(la_dev);
        return_on_error(status);
        log_debug(SOFT_RESET, "    done");
    }

    status = reset_ms_voq_credit_count(la_dev);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    status = ics_slice_mode_wa_leave(la_dev, orig_ics_slice_modes);
    return_on_error(status);
    log_debug(SOFT_RESET, "    done");

    status = txcgm_reset_mem(ll_dev, sid_mgr);
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
get_npu_blocks(const gibraltar_tree* gbt, std::vector<lld_block_scptr>& out_blocks)
{
    std::vector<std::string> block_names{
        "npu", "idb", "cdb",
    };

    auto blocks = gbt->get_leaf_blocks();
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
    auto gbt = ll_dev->get_gibraltar_tree();

    get_npu_blocks(gbt, npu_blocks);

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
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "flc"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "fi_stage"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "rxpp_term.top"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "rxpp_fwd.top"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "cdb_cache"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "txpp.ene_cluster"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 3>({{"npu", "slice", "txpp.top"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 1>({{"idb.macdb"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 1>({{"idb.encdb"}}), write_list);
    assert_npu_sub_blocks(npu_blocks, is_active, std::array<const char*, 1>({{"idb.res"}}), write_list);
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

static la_status
mmu_hbm_soft_reset(la_device_impl* la_dev)
{
    log_info(SOFT_RESET, "    Resetting HBM handler ...");
    la_status status = la_dev->m_hbm_handler->soft_reset();
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

// Hold memory lines of active OQs
using oq_active_list_t = std::vector<std::tuple<la_slice_id_t, size_t, uint64_t> >;

// Disable all active OQs
static la_status
oq_drop(ll_device_sptr ll_dev, oq_active_list_t& oq_active_list, const slice_manager_smart_ptr& sid_mgr)
{
    auto gbt = ll_dev->get_gibraltar_tree();
    lld_memory_line_value_list_t mem_line_val_list;

    for (la_slice_id_t slice : sid_mgr->get_used_slices_internal()) {
        auto& m(gbt->slice[slice]->tx->cgm->oq_drop_bitmap);
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
    auto gbt = ll_dev->get_gibraltar_tree();
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

        auto& m(gbt->slice[slice]->tx->cgm->oq_drop_bitmap);
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
    auto gbt = ll_dev->get_gibraltar_tree();

    fte_enable_reg_register reg;
    la_status status = ll_dev->read_register(gbt->dmc->fte->enable_reg, reg);

    // Enable all active links
    reg.fields.peer_delay_req_gen_link_idx = bit_utils::ones(fte_enable_reg_register::fields::PEER_DELAY_REQ_GEN_LINK_IDX_WIDTH);
    reg.fields.peer_delay_req_gen_en = 0;
    status = ll_dev->write_register(gbt->dmc->fte->enable_reg, reg);
    return_on_error(status);

    reg.fields.peer_delay_req_gen_en = 1;
    status = ll_dev->write_register(gbt->dmc->fte->enable_reg, reg);
    return_on_error(status);

    reg.fields.sync_packet_gen_en = 1;
    status = ll_dev->write_register(gbt->dmc->fte->enable_reg, reg);
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
            SPINLOCK_NOP;
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
            SPINLOCK_NOP;
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
    auto gbt = ll_dev->get_gibraltar_tree();

    for (la_slice_id_t slice : la_dev->get_used_slices()) {
        tsms_keepalive_gen_cfg_register reg;
        la_status status = ll_dev->read_register(gbt->slice[slice]->ts_ms->keepalive_gen_cfg, reg);
        return_on_error(status);
        reg.fields.keepalive_gen_enable = fabric_protocol_state.orig_ka[slice];
        status = ll_dev->write_register(gbt->slice[slice]->ts_ms->keepalive_gen_cfg, reg);
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
            SPINLOCK_NOP;
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
    auto gbt = ll_dev->get_gibraltar_tree();

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
    status = ll_dev->read_register(gbt->dmc->fte->enable_reg, enable_reg);
    return_on_error(status);
    enable_reg.fields.sync_packet_gen_en = 1;
    status = ll_dev->write_register(gbt->dmc->fte->enable_reg, enable_reg);
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
        status = ll_dev->write_register(gbt->dmc->frm->frp_enable_reg, frp_reg);
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
    auto gbt = ll_dev->get_gibraltar_tree();

    frm_fabric_link_down_transition_reg_register reg;

    status = ll_dev->read_register(gbt->dmc->frm->fabric_link_down_transition_reg, reg);
    return_on_error(status);
    reg.fields.fabric_link_down_transition_p0 = 0;
    reg.fields.fabric_link_down_transition_p1 = 0;
    status = ll_dev->write_register(gbt->dmc->frm->fabric_link_down_transition_reg, reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// Restart fabric protocols on LC
static la_status
do_restart_fabric_protocols_lc(la_device_impl* la_dev, fabric_protocol_state_t& fabric_protocol_state)
{
    auto ll_dev = la_dev->get_ll_device_sptr();
    auto gbt = ll_dev->get_gibraltar_tree();

    // Keepalive
    log_info(SOFT_RESET, "    Restarting keepalive ...");
    la_status status = restart_keepalive_lc(la_dev, fabric_protocol_state);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    log_info(SOFT_RESET, "    Clearing link down status ...");
    status = clear_link_down_status(la_dev);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    // Reconnecting LC
    log_info(SOFT_RESET, "    Reconnecting LC ...");
    frm_device_config_reg_register reg;
    status = ll_dev->read_register(gbt->dmc->frm->device_config_reg, reg);
    reg.fields.device_type = (uint64_t)frm_device_config_mode_e::LC;
    status = ll_dev->write_register(gbt->dmc->frm->device_config_reg, reg);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    // Peer discovery
    log_info(SOFT_RESET, "    Restarting peer discovery and enabling fabric time engine...");
    status = restart_peer_discovery_lc(la_dev, fabric_protocol_state);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    // Enable reachable bitmap updates
    log_info(SOFT_RESET, "    Enabling reachable bitmap updates ...");
    frm_debug_frtm_debug_reg_register frtm_reg;
    status = ll_dev->read_register(gbt->dmc->frm->debug_frtm_debug_reg, frtm_reg);
    return_on_error(status);
    frtm_reg.fields.debug_frtm_disable_reachable_bitmap_updates = 0;
    status = ll_dev->write_register(gbt->dmc->frm->debug_frtm_debug_reg, frtm_reg);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    // Fabric routing protocol
    if (fabric_protocol_state.frp_enabled) {
        log_info(SOFT_RESET, "    Enabling fabric routing protocol ...");
        frm_frp_enable_reg_register frp_reg;
        frp_reg.fields.frp_packet_gen_en = 1;
        status = ll_dev->write_register(gbt->dmc->frm->frp_enable_reg, frp_reg);
        return_on_error(status);
        log_info(SOFT_RESET, "    Done.");
    } else {
        // Restore saved fabric routing table
        log_info(SOFT_RESET, "    Restoring FRT...");
        status = restore_frt(la_dev, fabric_protocol_state);
        return_on_error(status);
        log_info(SOFT_RESET, "    Done.");
    }

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
    auto gbt = ll_dev->get_gibraltar_tree();
    frm_fmc_elig_reg_register fmc_elig_reg;
    la_status status = ll_dev->read_register(gbt->dmc->frm->fmc_elig_reg, fmc_elig_reg);
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
    auto gbt = ll_dev->get_gibraltar_tree();

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
        la_status status = ll_dev->read_register(gbt->dmc->frm->device_config_reg, reg);
        return_on_error(status);
        reg.fields.device_type = (uint64_t)frm_device_config_mode_e::FE2;
        status = ll_dev->write_register(gbt->dmc->frm->device_config_reg, reg);
        return_on_error(status);
        log_info(SOFT_RESET, "    Done.");
    }

    frm_debug_frtm_debug_reg_register frtm_reg;
    status = ll_dev->read_register(gbt->dmc->frm->debug_frtm_debug_reg, frtm_reg);
    return_on_error(status);
    frtm_reg.fields.debug_frtm_disable_reachable_bitmap_updates = 1;
    status = ll_dev->write_register(gbt->dmc->frm->debug_frtm_debug_reg, frtm_reg);
    return_on_error(status);
    frm_frp_reachable_bitmap12_reg_register reach_reg;
    reach_reg.fields = {};
    ll_dev->write_register(gbt->dmc->frm->frp_reachable_bitmap12_reg, reach_reg);
    return_on_error(status);

    for (la_slice_id_t slice : la_dev->get_used_slices()) {
        tsms_keepalive_gen_cfg_register reg;
        status = ll_dev->read_register(gbt->slice[slice]->ts_ms->keepalive_gen_cfg, reg);
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
    status = ll_dev->read_register(gbt->dmc->frm->frp_enable_reg, frp_reg);
    return_on_error(status);
    fabric_protocol_state.frp_enabled = (frp_reg.fields.frp_packet_gen_en == 1);
    if (fabric_protocol_state.frp_enabled) {
        log_info(SOFT_RESET, "    Disabling fabric routing protocol ...");
        frp_reg.fields.frp_packet_gen_en = 0;
        status = ll_dev->write_register(gbt->dmc->frm->frp_enable_reg, frp_reg);
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
    status = ll_dev->read_register(gbt->dmc->fte->enable_reg, enable_reg);
    return_on_error(status);
    enable_reg.fields.sync_packet_gen_en = 0;
    status = ll_dev->write_register(gbt->dmc->fte->enable_reg, enable_reg);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    return LA_STATUS_SUCCESS;
}

static la_status
toggle_bfd_timer(ll_device_sptr ll_dev)
{
    auto gbt = ll_dev->get_gibraltar_tree();
    la_status status;

    {
        npu_host_mp_ccm_timer_register reg;
        status = ll_dev->read_register(gbt->npuh->host->mp_ccm_timer, reg);
        return_on_error(status);

        reg.fields.mp_ccm_timer_enable = 0;
        status = ll_dev->write_register(gbt->npuh->host->mp_ccm_timer, reg);
        return_on_error(status);

        reg.fields.mp_ccm_timer_enable = 1;
        status = ll_dev->write_register(gbt->npuh->host->mp_ccm_timer, reg);
        return_on_error(status);
    }
    {
        npu_host_rmep_timer_register reg;
        status = ll_dev->read_register(gbt->npuh->host->rmep_timer, reg);
        return_on_error(status);

        reg.fields.rmep_timer_enable = 0;
        status = ll_dev->write_register(gbt->npuh->host->rmep_timer, reg);
        return_on_error(status);

        reg.fields.rmep_timer_enable = 1;
        status = ll_dev->write_register(gbt->npuh->host->rmep_timer, reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

static la_status
ifg_dmc_credits_fix(ll_device_sptr ll_dev, size_t val)
{
    auto gbt = ll_dev->get_gibraltar_tree();

    pier_oob_inj_credit_init_reg_register reg;
    ll_dev->read_register(gbt->dmc->pier->oob_inj_credit_init_reg, reg);

    lld_register_value_list_t write_list;

    for (size_t i = 0; i < NUM_FABRIC_PORTS_IN_DEVICE; i++) {
        reg.fields.oob_inj_credit_init_en = 1;
        reg.fields.oob_inj_credit_init_val = val;
        reg.fields.oob_inj_credit_init_link = i;
        write_list.push_back({gbt->dmc->pier->oob_inj_credit_init_reg, reg});
        reg.fields.oob_inj_credit_init_en = 0;
        write_list.push_back({gbt->dmc->pier->oob_inj_credit_init_reg, reg});
    }

    return lld_write_register_list(ll_dev, write_list);
}

static la_status
reset_components(la_device_impl* la_dev)
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
    status = la_dev->hbm_exists(hbm_enabled);
    return_on_error(status);
    if (hbm_enabled) {
        // In python code from validation HBM deassert is last and assert is first,
        // so they are combined in lb_hbm_handler_impl::soft_reset()
        log_info(SOFT_RESET, "    Resetting MMU HBM ...");
        status = mmu_hbm_soft_reset(la_dev);
        return_on_error(status);
        log_info(SOFT_RESET, "    Done.");
    }

    // Assert soft reset for components
    log_info(SOFT_RESET, "    Assert SMS ...");
    status = assert_soft_reset(ll_dev, sms_blocks, sms_is_already_asserted);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    log_info(SOFT_RESET, "    Assert control ...");
    status = control_assert_soft_reset(la_dev, orig_ics_slice_modes, control_blocks, control_is_already_asserted);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    log_info(SOFT_RESET, "    Assert DMC ...");
    status = assert_soft_reset(ll_dev, dmc_blocks, dmc_is_already_asserted);
    return_on_error(status);

    if (la_dev->m_device_mode != device_mode_e::STANDALONE) {
        status = ifg_dmc_credits_fix(ll_dev, 0);
        return_on_error(status);
    }

    log_info(SOFT_RESET, "    Done.");

    log_info(SOFT_RESET, "    Assert NPU ...");
    status = npu_assert_soft_reset(la_dev, npu_blocks, npu_is_already_asserted);
    return_on_error(status);
    log_info(SOFT_RESET, "    Done.");

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::reset_bfd_session_timeout()
{
    la_status status;
    std::vector<la_bfd_session_base_wptr> armed_sessions;

    // Go through all sessions and disarm them.
    for (const auto& bfd_session_base : m_bfd_sessions) {
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
    device_ifg_state ifg_state;
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
    status = oq_drop(m_ll_device, oq_active_list, get_slice_id_manager());
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    log_info(SOFT_RESET, "Stopping MAC pools ...");
    status = stop_mac_pools(this, ifg_state, packet_dma_state);
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    log_info(SOFT_RESET, "Stopping oobe logic ...");
    status = start_stop_oob_extract_logic(this, get_slice_id_manager(), false /*start*/);
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

    // Reset CEM CAM
    log_info(SOFT_RESET, "Resetting CEM CAM ...");
    status = reset_em_cam_data(m_ll_device);
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    // Reset components
    log_info(SOFT_RESET, "Reset components ...");
    status = reset_components(this);
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

    log_info(SOFT_RESET, "Restartng oobe logic ...");
    status = start_stop_oob_extract_logic(this, get_slice_id_manager(), true /*start*/);
    return_on_error(status);
    log_info(SOFT_RESET, "Done.");

    // Resume fabric protocols
    if (m_device_mode != device_mode_e::STANDALONE) {
        log_info(SOFT_RESET, "Restarting MAC pools for fabric ports...");
        status = start_mac_pools(this, ifg_state, packet_dma_state, la_slice_mode_e::CARRIER_FABRIC);
        return_on_error(status);
        log_info(SOFT_RESET, "Done.");

        if (m_device_mode == device_mode_e::LINECARD) {
            status = ifg_dmc_credits_fix(m_ll_device, m_device_properties[(int)la_device_property_e::OOB_INJ_CREDITS].int_val);
            return_on_error(status);
        }

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
    status = start_mac_pools(this, ifg_state, packet_dma_state, la_slice_mode_e::NETWORK);
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
            status = m_ll_device->read_register((*m_gb_tree->ts_mon->link_status_reg)[slice], tsmon_link);
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
