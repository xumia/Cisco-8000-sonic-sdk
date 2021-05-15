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

#include "access_engine.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "ll_device_impl.h"
#include "lld/device_tree.h"

using namespace silicon_one;

bool
access_engine::pacific_b0_lpm_bubble_errata_workaround_eligible(la_block_id_t block_id, la_entry_addr_t addr) const
{
    if (m_ll_device->get_device_revision() != la_device_revision_e::PACIFIC_B0) {
        log_debug(AE, "Only Pacific B0 is eligible for LPM memory workaround");
        return false;
    }

    const lld_block_scptr block = m_ll_device->get_pacific_tree()->get_block(block_id);

    if (!block) {
        return false;
    }

    std::string block_name = block->get_name();

    // This covers both cdb->core and cdb->core_reduced
    if (block_name.find("cdb.core") != 0) {
        log_debug(AE, "Block %s uneligible for LPM memory workaround", block_name.c_str());
        return false;
    }

    log_debug(AE, "Memory/register in block %s eligible for lpm bubble workaround", block_name.c_str());
    return true;
}

access_engine::state_e
access_engine::pacific_b0_lpm_bubble_errata_perform_workaround()
{
    static constexpr size_t NUM_SLICES_PER_DEVICE_WALKAROUND = 6;
    constexpr uint64_t LPM_BUBBLE_ERRATA_BUBBLE = 15;
    constexpr uint64_t LPM_BUBBLE_ERRATA_PERIOD = 16;

    std::array<bit_vector, NUM_SLICES_PER_DEVICE_WALKAROUND> original_rxpp_values;

    dassert_crit(m_ll_device->get_device_revision() != la_device_revision_e::PACIFIC_B0,
                 "LPM bubble workaround only relevant for Pacific B0.");
    dassert_crit(m_state == state_e::FAIL);

    log_debug(AE, "ae[%d]: access engine stuck, slow down the device to unstuck it", m_engine_id);

    access_engine_uptr ae = m_ll_device->reserve_access_engine();
    dassert_crit(ae->m_engine_id != m_engine_id, "Reserved access engine is already in use");

    // Crank down the device's shapers to reduce traffic rate, creating bubbles that will the LPM memory to be updated.
    for (la_slice_id_t i = 0; i < NUM_SLICES_PER_DEVICE_WALKAROUND; i++) {
        m_ll_device->read_rxpp_traffic_shaper(ae.get(), i, original_rxpp_values[i]);

        bit_vector new_rxpp_val = original_rxpp_values[i];
        new_rxpp_val.set_bits(67, 64, LPM_BUBBLE_ERRATA_BUBBLE);
        new_rxpp_val.set_bits(79, 68, LPM_BUBBLE_ERRATA_PERIOD);

        m_ll_device->write_rxpp_traffic_shaper(ae.get(), i, new_rxpp_val);
    }

    restart_failed_command();
    wait_completion();

    // Restore the device to original speed.
    for (la_slice_id_t i = 0; i < NUM_SLICES_PER_DEVICE_WALKAROUND; i++) {
        m_ll_device->write_rxpp_traffic_shaper(ae.get(), i, original_rxpp_values[i]);
    }

    m_ll_device->release_access_engine(std::move(ae));

    if (m_state == state_e::READY) {
        log_debug(AE, "ae[%d]: Access engine fixed", m_engine_id);
    } else {
        log_err(AE, "ae[%d]: Access engine slowdown didn't work, state = %d", m_engine_id, (int)m_state);
    }

    return m_state;
}

bool
access_engine::gibraltar_lp_profile_mapping_verifier_workaround_eligible(la_block_id_t block_id, la_entry_addr_t addr) const
{
    la_device_revision_e revision = m_ll_device->get_device_revision();
    if (revision < la_device_revision_e::GIBRALTAR_A0 || revision > la_device_revision_e::GIBRALTAR_A2) {
        log_debug(AE, "%s: not a Gibraltar A0 or A1 device.", __func__);
        return false;
    }

    const gibraltar_tree* gb = m_ll_device->get_gibraltar_tree();
    const lld_block_scptr block = gb->get_block(block_id);

    switch (block_id) {
    case gibraltar_tree::lld_block_id_e::LLD_BLOCK_ID_TXPP0:
    case gibraltar_tree::lld_block_id_e::LLD_BLOCK_ID_TXPP1:
    case gibraltar_tree::lld_block_id_e::LLD_BLOCK_ID_TXPP2:
    case gibraltar_tree::lld_block_id_e::LLD_BLOCK_ID_TXPP3:
    case gibraltar_tree::lld_block_id_e::LLD_BLOCK_ID_TXPP4:
    case gibraltar_tree::lld_block_id_e::LLD_BLOCK_ID_TXPP5:
        break;
    default:
        log_debug(AE, "%s: uneligible block %s", __func__, block->get_name().c_str());
        return false;
    }

    lld_memory_scptr memory = block->get_memory(addr);
    if (!memory) {
        log_debug(AE, "%s: no memory found for address %x in block %s", __func__, addr, block->get_name().c_str());
        return false;
    }

    const la_entry_addr_t mem_addr = memory->get_desc()->addr;
    const la_entry_addr_t min_mem_addr
        = (*gb->slice[0]->npu->txpp->top->logical_port_profile_mapping_verifier)[0]->get_desc()->addr;
    const la_entry_addr_t max_mem_addr
        = (*gb->slice[0]->npu->txpp->top->logical_port_profile_mapping_verifier)[3]->get_desc()->addr;
    if (mem_addr < min_mem_addr || mem_addr > max_mem_addr) {
        log_debug(AE, "%s: memory %s is uneligible", __func__, memory->get_name().c_str());
        return false;
    }

    log_debug(AE, "%s: memory is eligible", memory->get_name().c_str());
    return true;
}

access_engine::state_e
access_engine::gibraltar_lp_profile_mapping_verifier_perform_workaround()
{
    do {
        go();
        wait_completion();
    } while (m_state == state_e::FAIL
             && gibraltar_lp_profile_mapping_verifier_workaround_eligible(m_error_block_id, m_error_address));

    return m_state;
}
