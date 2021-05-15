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

#ifndef __CTM_SRAM_ALLOCATOR_H__
#define __CTM_SRAM_ALLOCATOR_H__

#include "common/cereal_utils.h"
#include "common/la_status.h"
#include "ctm_common_tcam.h"

#include <stddef.h>
#include <vector>

namespace silicon_one
{
using namespace ctm;

enum class ctm_sram_half {
    FIRST_HALF,
    SECOND_HALF,
};

/// @brief SRAM msb and lsb pair, and the SRAM half where they both located.
struct ctm_sram_pair {
    size_t msb_sram_idx;
    size_t lsb_sram_idx;
    ctm_sram_half sram_half;

    bool operator==(const ctm_sram_pair& rhs) const
    {
        return std::tie(sram_half, lsb_sram_idx, msb_sram_idx) == std::tie(rhs.sram_half, rhs.lsb_sram_idx, rhs.msb_sram_idx);
    }
};

class ctm_sram_allocator
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Creates a new CTM srams allocator.
    ///
    /// @param[in]  number_of_rings               Number of rings.
    /// @param[in]  number_of_tcams_per_ring      Number of TCAMs per ring.
    /// @param[in]  number_of_srams_per_ring      Number of sram pairs per ring.
    /// @param[in]  number_of_channels            Number of result channels.
    ///
    ctm_sram_allocator(size_t number_of_rings,
                       size_t number_of_tcams_per_ring,
                       size_t number_of_srams_per_ring,
                       size_t number_of_channels);

    /// @brief Default c'tor - allowed only for serialization purposes.
    ctm_sram_allocator() = default;

    /// @brief Allocates a new SRAM pair to a given result channel, pair may contain only single SRAM.
    ///
    /// @param[in]  ring_idx                 Ring index to allocate SRAM in.
    /// @param[in]  tcam_idx                 TCAM index to allocate SRAM to.
    /// @param[in]  result_channel           Result channel to allocate a SRAM to.
    ///
    /// @retval     status code.
    la_status allocate_srams(size_t ring_idx, size_t tcam_idx, size_t result_channel);

    /// @brief Return whether SRAM can be allcoated to a given result_channel.
    ///
    /// @param[in]  ring_idx                 Ring index where SRAM is required.
    /// @param[in]  result_channel           Result channel.
    ///
    /// @retval     true/false whether SRAM can be allcoated.
    bool can_allocate_srams(size_t ring_idx, size_t result_channel) const;

    /// @brief Frees a given SRAM pair, pair may contain only single SRAM.
    ///
    /// @param[in]  ring_idx              Ring index to free SRAM in.
    /// @param[in]  tcam_idx              TCAM idx which to free its SRAMs
    ///
    void free_srams(size_t ring_idx, size_t tcam_idx);

    /// @brief Return the SRAM result descriptor.
    ///
    /// @param[in]  ring_idx                 Ring index of the SRAM.
    /// @param[in]  sram_idx                 SRAM index.
    ///
    /// @retval     sram_desc
    sram_desc get_sram_result_desc(size_t ring_idx, size_t sram_idx) const;

    /// @brief Return SRAM pair of a given TCAM.
    ///
    /// @param[in]  ring_idx                 Ring index of the SRAM.
    /// @param[in]  tcam_idx                 TCAM index.
    ///
    /// @retval     ctm_sram_pair
    ctm_sram_pair get_srams_by_tcam(size_t ring_idx, size_t tcam_idx) const;

    /// @brief Return TCAM idnex of a given SRAM half.
    ///
    /// @param[in]  ring_idx                 Ring index of the SRAM.
    /// @param[in]  sram_idx                 SRAM index.
    /// @param[in]  sram_half                Whether the SRAM half is low or high entries.
    ///
    /// @retval     tcam_idx
    size_t get_tcam_by_sram_half(size_t ring_idx, size_t sram_idx, ctm_sram_half sram_half) const;

    /// @brief Sets the number of SRAMs for a given ring and result channel.
    ///
    /// @param[in]  ring_idx                    Ring index.
    /// @param[in]  result_channel              Result channel.
    /// @param[in]  number_of_payload_srams     Number of payload SRAMs to set.
    ///
    void set_result_channel_payload_width(size_t ring_idx, size_t result_channel, num_srams number_of_payload_srams);

    /// @brief Returns TCAMs that in a given ring with a given result channel, their SRAM is part of partially allocated block.
    ///
    /// @param[in]  ring_idx                    Ring index.
    /// @param[in]  result_channel              Result channel.
    ///
    /// @retval TCAM indices vector of TCAMs with partially allocated block
    vector_alloc<size_t> get_tcams_with_partially_allocated_block(size_t ring_idx, size_t result_channel);

private:
    using sram_pair_list = list_alloc<ctm_sram_pair>;

    struct sram_block_desc {
        sram_desc sram_result_desc;  ///< SRAM's result descriptor which contains result channel and MSB/LSB.
        size_t tcam_idx_per_half[2]; ///< Map between SRAM half to TCAM index.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(sram_block_desc);

    struct ring_srams_container {
        list_alloc<int>
            free_sram_blocks; ///< List of free SRAM blocks, where a block is a SRAM of size 1k which can be used as two halves.
        vector_alloc<sram_pair_list> channel_to_free_sram_pair_list; ///< Vector of free pairs list per channel.
        vector_alloc<num_srams> channel_to_num_srams;                ///< Map between result channel to its payload width.
        vector_alloc<sram_block_desc> sram_descriptors; ///< Vector of size number_of_srams which conatins the SRAM descriptors.
        vector_alloc<ctm_sram_pair> tcam_to_srams;      ///< Map between TCAM to its sram pair.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(ring_srams_container);

    /// @brief Allocate SRAM pair from free SRAM block list of given ring.
    ///
    /// @param[in]  ring                    Ring's srams container to allocate from.
    /// @param[in]  tcam_idx                 TCAM index which the SRAM belongs to.
    /// @param[in]  result_channel          Result channel to allocate the SRAM to.
    /// @param[in]  num_of_srams            Whether to allocate one or two SRAMs.
    ///
    ctm_sram_pair do_allocation_from_free_blocks_list(ring_srams_container& ring,
                                                      size_t tcam_idx,
                                                      size_t result_channel,
                                                      num_srams num_of_srams);

    /// @brief Allocate SRAM pair from free SRAM pairs with result channel list.
    ///
    /// @param[in]  ring                    Ring's srams container to allocate from.
    /// @param[in]  tcam_idx                TCAM index which the SRAM belongs to.
    /// @param[in]  result_channel          Result channel to allocate the SRAM to.
    /// @param[in]  num_of_srams            Whether to allocate one or two SRAMs.
    ///
    ctm_sram_pair do_allocation_from_free_res_channel_list(ring_srams_container& ring,
                                                           size_t tcam_idx,
                                                           size_t result_channel,
                                                           num_srams num_of_srams);

    /// @brief Mark SRAM's half descriptor as allocated.
    ///
    /// @param[in]  ring_idx                 Ring index of the SRAM.
    /// @param[in]  tcam_idx                 TCAM index which the SRAM belongs to.
    /// @param[in]  sram_idx                 SRAM index to mark as allocated.
    /// @param[in]  sram_half                SRAM half to mark as allocated.
    /// @param[in]  result_channel           Result channel of the SRAM.
    /// @param[in]  is_msb                   Whether the SRAM is MSB or LSB.
    ///
    void mark_sram_half_desc_as_allcoated(ring_srams_container& ring,
                                          size_t tcam_idx,
                                          size_t sram_idx,
                                          ctm_sram_half sram_half,
                                          size_t result_channel,
                                          bool is_msb);

    /// @brief Mark SRAM's half descriptor as free.
    ///
    /// @param[in]  ring                     Ring container of the SRAM.
    /// @param[in]  sram_idx                 SRAM index to mark as free.
    /// @param[in]  sram_half                SRAM half to mark as free.
    ///
    void mark_sram_half_as_free(ring_srams_container& ring, size_t sram_idx, ctm_sram_half sram_half);

    /// @brief Returns whether a SRAM half is free or not.
    ///
    /// @param[in]  ring                     Ring container of the SRAM.
    /// @param[in]  sram_idx                 SRAM index.
    /// @param[in]  sram_half                SRAM half.
    ///
    /// @retval     bool                     Whether the SRAM half is free or not.
    bool is_sram_half_free(ring_srams_container& ring, size_t sram_idx, ctm_sram_half sram_half) const;

    /// @brief Returns whether a SRAM block is free or not.
    ///
    /// @param[in]  ring                     Ring container of the SRAM.
    /// @param[in]  sram_idx                 SRAM index.
    ///
    /// @retval     bool                     Whether the SRAM block is free or not.
    bool is_sram_block_free(ring_srams_container& ring, size_t sram_idx) const;

    // Members
    vector_alloc<ring_srams_container>
        m_rings_containers; ///< Vector of size number_of_rings, which contains each ring's SRAM management data.
};

} // namespace silicon_one

#endif
