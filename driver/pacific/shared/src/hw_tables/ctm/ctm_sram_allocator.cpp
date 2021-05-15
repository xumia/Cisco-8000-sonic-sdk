// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "ctm_sram_allocator.h"
#include "common/logger.h"
#include "ctm_common_tcam.h"

namespace silicon_one
{
using namespace ctm;

ctm_sram_allocator::ctm_sram_allocator(size_t number_of_rings,
                                       size_t number_of_tcams_per_ring,
                                       size_t number_of_srams,
                                       size_t number_of_channels)
    : m_rings_containers(number_of_rings)
{
    for (ring_srams_container& ring_container : m_rings_containers) {

        ring_container.channel_to_num_srams = vector_alloc<num_srams>(number_of_channels, num_srams::NUM_SRAMS_INVAL);

        ring_container.channel_to_free_sram_pair_list.resize(number_of_channels);

        ring_container.sram_descriptors.resize(number_of_srams);
        for (size_t sram_idx = 0; sram_idx < number_of_srams; sram_idx++) {
            sram_block_desc& sram_desc = ring_container.sram_descriptors[sram_idx];
            sram_desc.sram_result_desc.result_channel = CHANNEL_INVAL;

            sram_desc.tcam_idx_per_half[(size_t)ctm_sram_half::FIRST_HALF] = MEM_IDX_INVAL;
            sram_desc.tcam_idx_per_half[(size_t)ctm_sram_half::SECOND_HALF] = MEM_IDX_INVAL;

            ring_container.free_sram_blocks.push_back(sram_idx);
        }

        ring_container.tcam_to_srams
            = vector_alloc<ctm_sram_pair>(number_of_tcams_per_ring, {.msb_sram_idx = MEM_IDX_INVAL, .lsb_sram_idx = MEM_IDX_INVAL});
    }
}

la_status
ctm_sram_allocator::allocate_srams(size_t ring_idx, size_t tcam_idx, size_t result_channel)
{
    ring_srams_container& ring = m_rings_containers[ring_idx];
    dassert_crit(result_channel < ring.channel_to_free_sram_pair_list.size());

    num_srams num_of_srams = ring.channel_to_num_srams[result_channel];
    // Before SRAM allocation, result channel's payload width has to be set.
    dassert_crit(num_of_srams != num_srams::NUM_SRAMS_INVAL);

    size_t number_of_srams_to_allocate = num_of_srams == num_srams::ONE_SRAM ? 1 : 2;

    ctm_sram_pair allocated_sram_pair;

    // Check if there is already a free pair to allocate
    if (ring.channel_to_free_sram_pair_list[result_channel].size() > 0) {
        // Allocation can't fail from here
        allocated_sram_pair = do_allocation_from_free_res_channel_list(ring, tcam_idx, result_channel, num_of_srams);

    } else if (ring.free_sram_blocks.size() >= number_of_srams_to_allocate) { // Allocate from free SRAM blocks
        // Allocation can't fail from here
        allocated_sram_pair = do_allocation_from_free_blocks_list(ring, tcam_idx, result_channel, num_of_srams);

    } else {
        return LA_STATUS_ERESOURCE;
    }

    dassert_crit(ring.tcam_to_srams[tcam_idx].lsb_sram_idx == MEM_IDX_INVAL);
    ring.tcam_to_srams[tcam_idx] = allocated_sram_pair;
    log_debug(RA,
              "ctm_sram_allocator allocated SRAMs on ring %zu MSB %zu LSB %zu half %d for TCAM %zu result channel %zu",
              ring_idx,
              allocated_sram_pair.msb_sram_idx,
              allocated_sram_pair.lsb_sram_idx,
              (int)allocated_sram_pair.sram_half,
              tcam_idx,
              result_channel);
    return LA_STATUS_SUCCESS;
}

bool
ctm_sram_allocator::can_allocate_srams(size_t ring_idx, size_t result_channel) const
{
    const ring_srams_container& ring = m_rings_containers[ring_idx];
    dassert_crit(ring.channel_to_num_srams[result_channel] != num_srams::NUM_SRAMS_INVAL);
    dassert_crit(result_channel < ring.channel_to_free_sram_pair_list.size());

    size_t number_of_srams_to_allocate = ring.channel_to_num_srams[result_channel] == num_srams::ONE_SRAM ? 1 : 2;

    if (ring.channel_to_free_sram_pair_list[result_channel].size() > 0) {
        return true;
    } else if (ring.free_sram_blocks.size() >= number_of_srams_to_allocate) {
        return true;
    }
    return false;
}

void
ctm_sram_allocator::free_srams(size_t ring_idx, size_t tcam_idx)
{

    ring_srams_container& ring = m_rings_containers[ring_idx];

    ctm_sram_pair& sram_pair = ring.tcam_to_srams[tcam_idx];

    dassert_crit(sram_pair.lsb_sram_idx != MEM_IDX_INVAL);

    sram_block_desc& lsb_sram_desc = ring.sram_descriptors[sram_pair.lsb_sram_idx];

    size_t result_channel = lsb_sram_desc.sram_result_desc.result_channel;
    dassert_crit(result_channel != CHANNEL_INVAL);

    mark_sram_half_as_free(ring, sram_pair.lsb_sram_idx, sram_pair.sram_half);

    if (sram_pair.msb_sram_idx != MEM_IDX_INVAL) {
        mark_sram_half_as_free(ring, sram_pair.msb_sram_idx, sram_pair.sram_half);
        dassert_crit(is_sram_block_free(ring, sram_pair.lsb_sram_idx) == is_sram_block_free(ring, sram_pair.msb_sram_idx));
    }

    // If both SRAM halves of the block are free after marking the current half as free we remove the already free half from it's
    // corresponding list and push it to the free blocks list.
    // Else, If there is only one free half (the one we just marked as free) we push the pair into its corresponding list.
    if (is_sram_block_free(ring, sram_pair.lsb_sram_idx)) {

        ctm_sram_pair sram_pair_to_remove = sram_pair;
        sram_pair_to_remove.sram_half
            = (sram_pair.sram_half == ctm_sram_half::FIRST_HALF) ? ctm_sram_half::SECOND_HALF : ctm_sram_half::FIRST_HALF;
        dassert_crit(contains(ring.channel_to_free_sram_pair_list[result_channel], sram_pair_to_remove));
        ring.channel_to_free_sram_pair_list[result_channel].remove(sram_pair_to_remove);
        ring.free_sram_blocks.push_back(sram_pair.lsb_sram_idx);
        if (sram_pair.msb_sram_idx != MEM_IDX_INVAL) {
            ring.free_sram_blocks.push_back(sram_pair.msb_sram_idx);
        }
    } else {
        dassert_crit(!contains(ring.channel_to_free_sram_pair_list[result_channel], sram_pair));
        // Once we push the SRAM pair to its free list, we don't need to push it again when checking the MSB.
        ring.channel_to_free_sram_pair_list[result_channel].push_back(sram_pair);
    }
    log_debug(RA,
              "ctm_sram_allocator freed SRAMs on ring %zu MSB %zu LSB %zu half %d for TCAM %zu",
              ring_idx,
              sram_pair.msb_sram_idx,
              sram_pair.lsb_sram_idx,
              (int)sram_pair.sram_half,
              tcam_idx);
    ring.tcam_to_srams[tcam_idx] = {.msb_sram_idx = MEM_IDX_INVAL, .lsb_sram_idx = MEM_IDX_INVAL};
}

ctm_sram_pair
ctm_sram_allocator::do_allocation_from_free_blocks_list(ring_srams_container& ring,
                                                        size_t tcam_idx,
                                                        size_t result_channel,
                                                        num_srams num_of_srams)
{
    ctm_sram_pair out_sram_pair = {.msb_sram_idx = MEM_IDX_INVAL, .lsb_sram_idx = MEM_IDX_INVAL};
    ctm_sram_pair remaining_sram_pair = {.msb_sram_idx = MEM_IDX_INVAL, .lsb_sram_idx = MEM_IDX_INVAL};

    size_t lsb_sram_idx = ring.free_sram_blocks.front();
    remaining_sram_pair.lsb_sram_idx = lsb_sram_idx;
    out_sram_pair.lsb_sram_idx = lsb_sram_idx;
    ring.free_sram_blocks.pop_front();

    if (num_of_srams == num_srams::TWO_SRAMS) {
        size_t msb_sram_idx = ring.free_sram_blocks.front();
        ring.free_sram_blocks.pop_front();
        remaining_sram_pair.msb_sram_idx = msb_sram_idx;
        out_sram_pair.msb_sram_idx = msb_sram_idx;
    }

    out_sram_pair.sram_half = ctm_sram_half::FIRST_HALF;
    remaining_sram_pair.sram_half = ctm_sram_half::SECOND_HALF;

    ring.channel_to_free_sram_pair_list[result_channel].push_back(remaining_sram_pair);

    mark_sram_half_desc_as_allcoated(
        ring, tcam_idx, out_sram_pair.lsb_sram_idx, ctm_sram_half::FIRST_HALF, result_channel, false /* is_msb */);

    if (num_of_srams == num_srams::TWO_SRAMS) {
        mark_sram_half_desc_as_allcoated(
            ring, tcam_idx, out_sram_pair.msb_sram_idx, ctm_sram_half::FIRST_HALF, result_channel, true /* is_msb */);
    }

    return out_sram_pair;
}

ctm_sram_pair
ctm_sram_allocator::do_allocation_from_free_res_channel_list(ring_srams_container& ring,
                                                             size_t tcam_idx,
                                                             size_t result_channel,
                                                             num_srams num_of_srams)
{
    ctm_sram_pair out_sram_pair = {.msb_sram_idx = MEM_IDX_INVAL, .lsb_sram_idx = MEM_IDX_INVAL};
    out_sram_pair = ring.channel_to_free_sram_pair_list[result_channel].front();

    ring.channel_to_free_sram_pair_list[result_channel].pop_front();
    dassert_crit(out_sram_pair.lsb_sram_idx != MEM_IDX_INVAL);

    mark_sram_half_desc_as_allcoated(
        ring, tcam_idx, out_sram_pair.lsb_sram_idx, out_sram_pair.sram_half, result_channel, false /* is_msb */);

    if (num_of_srams == num_srams::TWO_SRAMS) {
        dassert_crit(out_sram_pair.msb_sram_idx != MEM_IDX_INVAL);
        mark_sram_half_desc_as_allcoated(
            ring, tcam_idx, out_sram_pair.msb_sram_idx, out_sram_pair.sram_half, result_channel, true /* is_msb */);
    }

    return out_sram_pair;
}

void
ctm_sram_allocator::mark_sram_half_as_free(ring_srams_container& ring, size_t sram_idx, ctm_sram_half sram_half)
{

    dassert_crit(!is_sram_half_free(ring, sram_idx, sram_half));
    sram_block_desc& sram_desc = ring.sram_descriptors[sram_idx];

    sram_desc.tcam_idx_per_half[(size_t)sram_half] = MEM_IDX_INVAL;

    if (is_sram_block_free(ring, sram_idx)) {
        sram_desc.sram_result_desc.result_channel = CHANNEL_INVAL;
    }
}

void
ctm_sram_allocator::mark_sram_half_desc_as_allcoated(ring_srams_container& ring,
                                                     size_t tcam_idx,
                                                     size_t sram_idx,
                                                     ctm_sram_half sram_half,
                                                     size_t result_channel,
                                                     bool is_msb)
{
    sram_block_desc& sram_desc = ring.sram_descriptors[sram_idx];
    dassert_crit(sram_desc.sram_result_desc.result_channel == result_channel
                 || sram_desc.sram_result_desc.result_channel == CHANNEL_INVAL);

    if (sram_desc.sram_result_desc.result_channel == CHANNEL_INVAL) {
        sram_desc.sram_result_desc.result_channel = result_channel;
        sram_desc.sram_result_desc.is_msb = is_msb;
    }

    dassert_crit(sram_desc.sram_result_desc.is_msb == is_msb);
    dassert_crit(ring.sram_descriptors[sram_idx].tcam_idx_per_half[(size_t)sram_half] == MEM_IDX_INVAL);

    ring.sram_descriptors[sram_idx].tcam_idx_per_half[(size_t)sram_half] = tcam_idx;
}

sram_desc
ctm_sram_allocator::get_sram_result_desc(size_t ring_idx, size_t sram_idx) const
{
    const sram_block_desc& internal_sram_desc = m_rings_containers[ring_idx].sram_descriptors[sram_idx];
    return internal_sram_desc.sram_result_desc;
}

ctm_sram_pair
ctm_sram_allocator::get_srams_by_tcam(size_t ring_idx, size_t tcam_idx) const
{
    return m_rings_containers[ring_idx].tcam_to_srams[tcam_idx];
}

size_t
ctm_sram_allocator::get_tcam_by_sram_half(size_t ring_idx, size_t sram_idx, ctm_sram_half sram_half) const
{
    return m_rings_containers[ring_idx].sram_descriptors[sram_idx].tcam_idx_per_half[(size_t)sram_half];
}

bool
ctm_sram_allocator::is_sram_half_free(ring_srams_container& ring, size_t sram_idx, ctm_sram_half sram_half) const
{
    return ring.sram_descriptors[sram_idx].tcam_idx_per_half[(size_t)sram_half] == MEM_IDX_INVAL;
}

bool
ctm_sram_allocator::is_sram_block_free(ring_srams_container& ring, size_t sram_idx) const
{
    return is_sram_half_free(ring, sram_idx, ctm_sram_half::FIRST_HALF)
           && is_sram_half_free(ring, sram_idx, ctm_sram_half::SECOND_HALF);
}

void
ctm_sram_allocator::set_result_channel_payload_width(size_t ring_idx, size_t result_channel, num_srams number_of_payload_srams)
{
    ring_srams_container& ring = m_rings_containers[ring_idx];
    dassert_crit(ring.channel_to_num_srams[result_channel] == num_srams::NUM_SRAMS_INVAL
                 || ring.channel_to_num_srams[result_channel] == number_of_payload_srams);
    ring.channel_to_num_srams[result_channel] = number_of_payload_srams;
}

vector_alloc<size_t>
ctm_sram_allocator::get_tcams_with_partially_allocated_block(size_t ring_idx, size_t result_channel)
{

    ring_srams_container& ring = m_rings_containers[ring_idx];
    dassert_crit(result_channel < ring.channel_to_free_sram_pair_list.size());
    vector_alloc<size_t> ret_vector;

    for (const ctm_sram_pair& sram_pair : ring.channel_to_free_sram_pair_list[result_channel]) {
        // We iterate over all free SRAMs pairs that belongs to the result channel, and return their occupied matching pair, which
        // uppon freeing will free the whole SRAM blocks.
        dassert_crit(sram_pair.lsb_sram_idx != MEM_IDX_INVAL);
        ctm_sram_half free_sram_half = sram_pair.sram_half;
        ctm_sram_half occupied_half
            = (free_sram_half == ctm_sram_half::FIRST_HALF) ? ctm_sram_half::SECOND_HALF : ctm_sram_half::FIRST_HALF;
        size_t occupied_tcam_with_paritally_allocated_block
            = get_tcam_by_sram_half(ring_idx, sram_pair.lsb_sram_idx, occupied_half);
        dassert_crit(occupied_tcam_with_paritally_allocated_block != MEM_IDX_INVAL);
        ret_vector.push_back(occupied_tcam_with_paritally_allocated_block);
    }

    return ret_vector;
}

} // namespace silicon_one
