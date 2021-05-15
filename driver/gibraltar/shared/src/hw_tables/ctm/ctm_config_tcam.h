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

#ifndef __CTM_CONFIG_TCAM_H__
#define __CTM_CONFIG_TCAM_H__

#include "common/la_status.h"
#include "ctm_common_tcam.h"
#include "ctm_config.h"
#include "ctm_config_group.h"
#include "ctm_sram_allocator.h"
#include "lld/lld_fwd.h"

#include <boost/variant.hpp>
#include <map>
#include <stddef.h>
#include <vector>

namespace silicon_one
{

/// @brief Static configuration of CDB Central Tcam.
///
class ctm_config_tcam : public ctm_config
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    struct ctm_tcam_location {
        bool is_valid;       ///< DB is configured on this TCAM for the specific key size
        size_t ring_idx;     ///< CDB ring index.
        size_t subring_idx;  ///< Subring index.
        size_t lsb_tcam_idx; ///< Index of TCAM containing key's LSB
        size_t msb_tcam_idx; ///< Index of TCAM containing key's MSB (relevant for tables with key > 160bits)
        size_t sram_lsb_idx; ///< Index of SRAM to 320 key table.
        size_t sram_msb_idx; ///< Index of SRAM to 320 key table.
        size_t sram_offset;  ///< SRAM offset in lines.
    };

    // C'tor
    ctm_config_tcam(const ll_device_sptr& ldevice, bool is_linecard_mode, size_t lpm_tcam_num_banksets, size_t number_of_slices);

    // D'tor
    virtual ~ctm_config_tcam() = default;
    /// @brief Returns location for given narrow bank
    ///
    /// @param[in]  ring_idx           Ring ID.
    /// @param[in]  subring_idx        Subring ID.
    /// @param[in]  mem_idx            TCAM bank ID.
    ///
    /// @retval location
    ctm_config_tcam::ctm_tcam_location get_tcam_160_key_hw_location(size_t ring_idx, size_t subring_idx, size_t tcam_idx) const;

    /// @brief Returns location for given wide TCAM location indentified by its MSB TCAM.
    ///
    /// @param[in]  ring_idx           Ring ID.
    /// @param[in]  subring_idx        Subring ID.
    /// @param[in]  mem_idx            MSB TCAM bank ID.
    ///
    /// @retval location
    ctm_config_tcam::ctm_tcam_location get_tcam_320_key_hw_location(size_t ring_idx, size_t subring_idx, size_t tcam_idx) const;

    /// @brief Returns whether a TCAM is part of legal existing pair.
    ///
    /// @param[in]   ring_idx      Ring idx of the TCAM.
    /// @param[in]   subring_idx   Subring idx of the TCAM.
    /// @param[in]   tcam_idx      TCAM index.
    ///
    /// @retval      true/false whether the TCAM is part of existing pair.
    bool is_tcam_part_of_pair(size_t ring_idx, size_t subring_idx, size_t tcam_idx) const;

    /// @brief Returns whether a given TCAM index is MSB.
    ///
    /// @param[in]  tcam_idx            TCAM index.
    ///
    /// @retval     true/false whether a given TCAM index is MSB.
    virtual bool is_msb_tcam(const size_t tcam_idx) const = 0;

    /// @brief Returns LSB TCAM index corresponding to the given TCAM index.
    ///        This function returns the given tcam_idx if it's already a LSB index.
    ///
    /// @param[in]  tcam_idx            TCAM index.
    ///
    /// @retval     LSB TCAM index
    size_t get_lsb_tcam(const size_t tcam_idx) const;

    /// @brief Returns MSB TCAM index corresponding to the given TCAM index.
    ///        This function returns the given tcam_idx if it's already a MSB index.
    ///
    /// @param[in]  tcam_idx            TCAM index.
    ///
    /// @retval     MSB TCAM index
    size_t get_msb_tcam(const size_t tcam_idx) const;

    /// @brief Returns LSB/MSB TCAM index corresponding to the given TCAM index.
    ///        This function returns the given tcam_idx if it's already a MSB index.
    ///
    /// @param[in]  tcam_idx            TCAM index.
    ///
    /// @retval     MSB/LSB TCAM index
    size_t get_paired_tcam(const size_t tcam_idx) const;

    /// @brief Returns 320b keys TCAM offset.
    ///
    /// @retval     offset between LSB and MSB TCAMs
    virtual size_t get_key_320_tcam_offset() const = 0;

    /// @brief  Returns the number of subrings per ring.
    ///
    /// @retval Number of subrings
    virtual size_t get_number_of_subrings() const = 0;

    /// @brief Returns the eligible TCAMs for a given group - in case of wide group, the MSB TCAMs are returned.
    ///
    /// @param[in]  desc    Group descriptor of the group to return its TCAMs.
    ///
    /// @retval     Vector of tcam_desc containing the eligible TCAMs
    const std::vector<tcam_desc>& get_eligible_tcams_for_group(const group_desc& desc) const;

    /// @brief Returns the eligible LSB TCAMs for a given WIDE group.
    ///
    /// @param[in]  desc    Group descriptor of the wide group to return its LSB TCAMs.
    ///
    /// @retval     Vector of tcam_desc containing the eligible LSB TCAMs
    const std::vector<tcam_desc>& get_eligible_lsb_tcams_for_wide_group(const group_desc& desc) const;

    /// @brief Returns the groups associated with a given TCAM.
    ///
    /// @param[in]  desc    TCAM descriptor.
    ///
    /// @retval     Vector of group_desc containing groups associated with the TCAM.
    std::vector<group_desc> get_groups_by_tcam(const tcam_desc& tcam) const;

    /// @brief Allocates TCAM for a given group, in case of wide group - both MSB and LSB are allocated.
    ///
    /// @param[in]   group      Group descriptor.
    /// @param[out]  out_tcam   Allocated TCAM's descriptor, in case of wide group, LSB TCAM is returned.
    ///
    /// @retval      status
    la_status allocate_tcam_for_group(const group_desc& group, tcam_desc& out_tcam);

    /// @brief Allocates a given TCAM for a given narrow group.
    ///
    /// @param[in]   group      Group descriptor.
    /// @param[out]  tcam       TCAM descriptor to allocate for group.
    ///
    /// @retval      status
    la_status allocate_specific_tcam_for_narrow_group(const group_desc& group, const tcam_desc& tcam);

    /// @brief Returns the maximum scale of a group independently to the other groups sharing the same resources.
    ///
    /// @param[in]   group      Group descriptor.
    ///
    /// @retval      max group scale.
    size_t get_max_group_scale(const ctm::group_desc& group) const override;

    /// @brief Returns the maximum scale of any narrow group, that occupies just one ring.
    ///        independently to the other groups sharing the same resources, or the default entries.
    ///
    /// @retval      max group scale.
    size_t get_max_narrow_scale_per_ring() const;

    /// @brief Returns the maximum scale of any wide group, that occupies just one ring.
    ///        independently to the other groups sharing the same resources, or the default entries.
    ///
    /// @retval      max group scale.
    size_t get_max_wide_scale_per_ring() const;

    /// @brief Returns the corresponding MSB group of a given wide group.
    ///
    /// @param[in]   wide_group      Wide group descriptor.
    ///
    /// @retval      group_desc of the corresponding MSB group.
    group_desc get_msb_narrow_group_from_wide_group(const group_desc& wide_group) const;

    /// @brief Returns the corresponding LSB group of a given wide group.
    ///
    /// @param[in]   wide_group      Wide group descriptor.
    ///
    /// @retval      group_desc of the corresponding LSB group.
    group_desc get_lsb_narrow_group_from_wide_group(const group_desc& wide_group) const;

    /// @brief Returns the corresponding wide group of a given LSB/MSB group.
    ///
    /// @param[in]   narrow_group      Narrow LSB/MSB group descriptor.
    ///
    /// @retval      group_desc of the corresponding wide group.
    group_desc get_wide_group_from_narrow_group(const group_desc& narrow_group) const;

    /// @brief Frees a given TCAM.
    ///
    /// @param[in]   tcam      TCAM descriptor to free.
    ///
    /// @retval  la_status
    la_status free_tcam(const tcam_desc& tcam);

    /// @brief Return map between priority to TCAM containers were upon freeing a container, it's promised that a new TCAM can be
    /// allocated to the given group.
    /// @param[in]   group      Group to calculate priorites for.
    ///
    /// @retval  la_status
    priority_to_tcams_map get_tcams_to_relocate_for_group(const group_desc& group) const;

    /// @brief Returns whether a TCAM belongs to LPM.
    ///
    /// @param[in]   ring_idx      Ring idx of the TCAM.
    /// @param[in]   subring_idx   Subring idx of the TCAM.
    /// @param[in]   tcam_idx      TCAM index.
    ///
    /// @retval      true/false whether the TCAM belongs to LPM.
    bool is_lpm_tcam(size_t ring_idx, size_t subring_idx, size_t tcam_idx) const;

    /// @brief Returns all the groups that are competing on the same TCAM resources with a given group.
    ///
    /// @param[in]   group      Group to return its competing groups.
    ///
    /// @retval      true/false whether the TCAM belongs to LPM.
    groups_container get_competing_groups(const group_desc& group) const;

    /// @brief Returns all the TCAM spaces that this group can allocate TCAMs from.
    ///
    /// @param[in]   group      Group for which to get the TCAM spaces.
    ///
    /// @retval      a list of unique TCAM space ids.
    vector_alloc<size_t> get_spaces_for_group(const group_desc& group) const;

protected:
    enum hw_constants_e {
        INVALID_ABS_INPUT_INTERFACE_VALUE
        = 31, ///< TCAM absoulute input interface invalid value, absoulute input represented by 5 bits, all 1s meand invalid.
        INVALID_ABS_OUTPUT_INTERFACE_VALUE
        = 63, ///< TCAM absoulute output interface invalid value, absoulute output represented by 6 bits, all 1s meand invalid.
        TCAM_LDB_ACCESS_FULL_MASK = 0xffff, ///< TCAM LDB access register's for mask.
        CHANNEL_INVAL_REG_VALUE = 7,        ///< Invalid value for key, hit and result channels.
        MEM_IDX_INVAL_REG_VALUE = 12,       ///< Invalid index for TCAM/SRAM.
    };

    using ctm_config_group_sptr = std::shared_ptr<ctm_config_group>;
    using groups_vec = vector_alloc<ctm_config_group_sptr>;

    // For serialization purposes
    ctm_config_tcam() = default;

private:
    struct ctm_config_tcam_desc {
        ctm_config_group_sptr narrow_group;
        ctm_config_group_sptr wide_group;
    };

    CEREAL_SUPPORT_PRIVATE_CLASS(ctm_config_tcam_desc)

    using tcams_vec = vector_alloc<ctm_config_tcam_desc>;
    using subrings_tcam_vec = vector_alloc<tcams_vec>;
    using rings_tcams_vec = vector_alloc<subrings_tcam_vec>;

    ///@brief Allocation priorities, order between priorities is important.
    enum class allocation_priority_e {
        INVAL_PRIORITY,
        ANY_TCAM,
        LPM_BLOCKED_PAIR,
        POSSIBLE_PAIR,
        NEW_PAIR,
        HIGHEST_PRIORITY = NEW_PAIR,
    };

    enum class free_priority_e {
        LOWEST_PRIORITY,
        ANY_TCAM = LOWEST_PRIORITY,
        TCAM_FREES_SRAM_BLOCK,
        TCAM_ISNT_PART_OF_PAIR,
        OLD_TCAM_NOT_IN_PLACE,
        TCAM_IN_PLACE_FOR_NEW_GROUP,
        HIGHEST_PRIORITY = TCAM_IN_PLACE_FOR_NEW_GROUP,
    };

    enum class wide_single_tcam_free_priority_e {
        LOWEST_PRIORITY,
        TCAM_FREES_SRAM_BLOCK = LOWEST_PRIORITY,
        TCAM_COMPLEMENT_FREE,
        TCAM_COMPLEMENT_FIT,
        HIGHEST_PRIORITY = TCAM_COMPLEMENT_FIT,
    };

    static_assert((size_t)free_priority_e::HIGHEST_PRIORITY < sizeof(size_t) * 8, "Free priorities are being used as bits indices");

    /// @brief Returns whether a TCAM can be inserted to wide group.
    ///
    /// @param[in]   ring_idx      Ring idx of the TCAM.
    /// @param[in]   subring_idx   Subring idx of the TCAM.
    /// @param[in]   tcam_idx      TCAM index.
    ///
    /// @retval      true/false whether the TCAM can be inserted to wide_group.
    bool can_insert_tcam_to_wide_group(size_t ring_idx, size_t subring_idx, size_t tcam_idx) const;

    /// @brief Calculate free priority of TCAM in favor of given group.
    ///
    /// @param[in]   destined_group     Group to calculate priority for.
    /// @param[in]   tcam               TCAM to calculate priority for.
    ///
    /// @retval  la_status
    size_t calculate_tcam_free_priority_for_narrow_group(const group_desc& destined_group, const tcam_desc& tcam) const;

    /// @brief Calculate free priority of single TCAM in favor of given  widegroup.
    ///
    /// @param[in]   destined_group     Group to calculate priority for.
    /// @param[in]   tcam               TCAM to calculate priority for.
    ///
    /// @retval  la_status
    size_t calculate_single_tcam_free_priority_for_wide_group(const group_desc& destined_group, const tcam_desc& tcam) const;

    priority_to_tcams_map get_tcams_to_relocate_for_narrow_group(const group_desc& group) const;
    priority_to_tcams_map get_tcams_to_relocate_for_wide_group(const group_desc& group) const;

protected:
    constexpr static group_desc::group_ifs_e DBM_INTERFACE = group_desc::GROUP_IFS_FW0_NARROW;

    /// @brief  Creates map of input interfaces to core key channels
    void map_input_interfaces();

    /// @brief  Creates map of core result channels to output interfaces
    void map_output_interfaces();

    /// @brief  Run map initialization
    void map_init();

    /// @brief  Initializes the SRAM allocator.
    void init_sram_allocator();

    /// @brief  Confgure CDB top HW.
    virtual la_status configure_cdb_top() const = 0;

    /// @brief Returns the relative result channel of a group, in case of DBM returns 0.
    ///
    /// @param[in]   ring_idx      Ring of the result channel.
    /// @param[in]   group_desc    Group desc to return its result channel.
    ///
    /// @retval      result channel of the given group.
    size_t get_group_result_channel(size_t ring_idx, const group_desc& group) const;

    /// @brief Adds TCAM to a given group.
    ///
    /// @param[in]   group_desc    Group to add the TCAM to.
    /// @param[in]   ring_idx      Ring idx of the TCAM.
    /// @param[in]   subring_idx   Subring idx of the TCAM.
    /// @param[in]   tcam_idx      TCAM index.
    ///
    void add_tcam_to_group(const group_desc& group, size_t ring_idx, size_t subring_idx, size_t tcam_idx);

    /// @brief Returns whether a TCAM is free or not.
    ///
    /// @param[in]   ring_idx      Ring idx of the TCAM.
    /// @param[in]   subring_idx   Subring idx of the TCAM.
    /// @param[in]   tcam_idx      TCAM index.
    ///
    /// @retval      true/false whether the TCAM is free.
    bool is_tcam_free(size_t ring_idx, size_t subring_idx, size_t tcam_idx) const;

    /// @brief Returns a vector of rings which the group is mapped to.
    ///
    /// @param[in]   group_desc    Group desc to return its rings.
    ///
    /// @retval      vector of integer representing the eligible rings indices.
    vector_alloc<size_t> get_eligible_rings_for_group(const group_desc& group) const;

    /// @brief Find the highest priority TCAM in a specific ring to allocate for a narrow group.
    ///
    /// @param[in]    ring_idx        Ring idx to search in.
    /// @param[in]    subring_idx     Subring idx to search in.
    /// @param[in]    group_desc      Group desc to find TCAM for.
    /// @param[out]   out_tcam_idx    The TCAM founded.
    /// @param[out]   out_priority    The priority founded.
    ///
    /// @retval      la_status
    la_status find_best_tcam_to_allocate_in_ring_for_narrow_group(size_t ring_idx,
                                                                  size_t subring_idx,
                                                                  const group_desc& group,
                                                                  size_t& out_tcam_idx,
                                                                  allocation_priority_e& out_priority);

    /// @brief Find the highest priority TCAM in a specific ring to allocate for a wide group.
    ///
    /// @param[in]    ring_idx          Ring idx to search in.
    /// @param[in]    subring_idx       Subring idx to search in.
    /// @param[in]    group_desc        Group desc to find TCAM for.
    /// @param[out]   out_msb_tcam_idx  MSB TCAM to allocate, can be set to IDX_INVAL in case that only LSB TCAM allocation is
    /// sufficient or in case of fail.
    /// @param[out]   out_lsb_tcam_idx  LSB TCAM to allocate, can be set to IDX_INVAL in case that only MSB TCAM allocation is
    /// sufficient
    /// @param[out]   out_priority      The priority founded.
    ///
    /// @retval      la_status
    la_status find_best_tcam_to_allocate_in_ring_for_wide_group(size_t ring_idx,
                                                                size_t subring_idx,
                                                                const group_desc& group,
                                                                size_t& out_msb_tcam_idx,
                                                                size_t& out_lsb_tcam_idx,
                                                                allocation_priority_e& out_priority);

    /// @brief Find the highest priority TCAM in all rings to allocate for a narrow group.
    ///
    /// @param[in]    group_desc      Group desc to find TCAM for.
    /// @param[out]   out_tcam_desc   The TCAM founded.
    ///
    /// @retval      la_status
    la_status find_best_tcam_to_allocate_for_narrow_group(const group_desc& group, tcam_desc& out_tcam_desc);

    /// @brief Find the highest priority TCAM in all rings to allocate for a wide group.
    ///
    /// @param[in]    group_desc          Group desc to find TCAM for.
    /// @param[out]   out_msb_tcam_desc   MSB TCAM to allocate if needed.
    /// @param[out]   out_lsb_tcam_desc   LSB TCAM to allocate if needed.
    ///
    /// @retval      la_status
    la_status find_best_tcam_to_allocate_for_wide_group(const group_desc& group,
                                                        tcam_desc& out_msb_tcam_desc,
                                                        tcam_desc& out_lsb_tcam_desc);

    /// @brief Find in a ring a TCAM to allocate that creates a new pair.
    ///
    /// @param[in]    ring_idx        Ring idx to search in.
    /// @param[in]    subring_idx     Subring idx to search in.
    /// @param[in]    group_desc      Group desc to find TCAM for.
    /// @param[out]   out_tcam_idx    The TCAM index founded.
    ///
    /// @retval      la_status
    la_status find_create_pair_tcam_to_allocate(size_t ring_idx,
                                                size_t subring_idx,
                                                const group_desc& group,
                                                size_t& out_tcam_idx) const;

    /// @brief Find in a ring a TCAM to allocate that is part of free pair slots.
    ///
    /// @param[in]    ring_idx        Ring idx to search in.
    /// @param[in]    subring_idx     Subring idx to search in.
    /// @param[in]    group_desc      Group desc to find TCAM for.
    /// @param[out]   out_tcam_idx    The TCAM index founded.
    ///
    /// @retval      la_status
    la_status find_free_pair_tcam_to_allocate(size_t ring_idx,
                                              size_t subring_idx,
                                              const group_desc& group,
                                              size_t& out_tcam_idx) const;

    /// @brief Find in a ring a TCAM to allocate that can't be paired because of LPM.
    ///
    /// @param[in]    ring_idx        Ring idx to search in.
    /// @param[in]    subring_idx     Subring idx to search in.
    /// @param[in]    group_desc      Group desc to find TCAM for.
    /// @param[out]   out_tcam_idx    The TCAM index founded.
    ///
    /// @retval      la_status
    la_status find_lpm_blocked_pair_tcam_to_allocate(size_t ring_idx,
                                                     size_t subring_idx,
                                                     const group_desc& group,
                                                     size_t& out_tcam_idx) const;

    /// @brief Find in a ring any TCAM to allocate.
    ///
    /// @param[in]    ring_idx        Ring idx to search in.
    /// @param[in]    subring_idx     Subring idx to search in.
    /// @param[in]    group_desc      Group desc to find TCAM for.
    /// @param[out]   out_tcam_idx    The TCAM index founded.
    ///
    /// @retval      la_status
    la_status find_any_tcam_to_allocate(size_t ring_idx, size_t subring_idx, const group_desc& group, size_t& out_tcam_idx) const;

    /// @brief Returns whether an allcoation of TCAM to a group will create a pair.
    ///
    /// @param[in]    ring_idx          Ring idx of the TCAM.
    /// @param[in]    subring_idx       Subring idx of the TCAM.
    /// @param[in]    tcam_idx          TCAM index.
    /// @param[in]    group_desc        Group candidate for the allcoation.
    ///
    /// @retval      true/false whether the allocation will create pair.
    bool will_allocation_create_pair(size_t ring_idx, size_t subring_idx, size_t tcam_idx, const group_desc& group) const;

    /// @brief Returns whether interface in LSB and MSB location are composing a legal pair.
    ///
    /// @param[in]    msb_ifs           MSB interface.
    /// @param[in]    lsb_ifs           LSB interface.
    ///
    /// @retval      true/false whether interfaces composing a legal pair.
    bool is_ifs_eligible_tcam_pair(group_desc::group_ifs_e msb_ifs, group_desc::group_ifs_e lsb_ifs) const;

    /// @brief Returns the group descriptor of a given TCAM.
    ///
    /// @param[in]    ring_idx          Ring idx of the TCAM.
    /// @param[in]    subring_idx       Subring idx of the TCAM.
    /// @param[in]    tcam_idx          TCAM index.
    ///
    /// @retval      group_desc
    group_desc get_tcam_narrow_group_desc(size_t ring_idx, size_t subring_idx, size_t tcam_idx) const;

    /// @brief Returns whether interface is MSB interface (FW0 or TX0).
    ///
    /// @param[in]    interface           Interface to check.
    ///
    /// @retval      true/false whether interfaces is MSB.
    bool is_msb_ifs(group_desc::group_ifs_e interface) const;

    /// @brief Returns the wide interface corresponding to a given narrow interface.
    ///
    /// @param[in]    interface           Interface to check.
    ///
    /// @retval      wide interface of the corresponding narrow interface.
    group_desc::group_ifs_e get_wide_ifs(group_desc::group_ifs_e interface) const;

    /// @brief Returns the key channel of a given group.
    ///
    /// @param[in]    group_desc           Group to return its key channel
    ///
    /// @retval      key channel of a given group.
    size_t get_group_key_channel(const group_desc& group) const;

    /// @brief Returns the number of payload SRAMs of a given group.
    ///
    /// @param[in]    group_desc           Group to return its number of SRAMs
    ///
    /// @retval      num_srams
    num_srams get_ifs_payload_srams_number(group_desc::group_ifs_e group) const;

    /// @brief Returns whether there is an input mapping between slice and interface to a given ring
    ///
    /// @param[in]    ring_idx           Ring index to check the mapping for.
    /// @param[in]    slice_idx           Slice index.
    /// @param[in]    interface_idx       Interface index.
    ///
    /// @retval      num_srams
    bool is_group_connected_to_ring_input(size_t ring_idx, const group_desc& group) const;

    /// @brief Returns whether TCAM can be mapped to a group.
    ///
    /// @param[in]    ring_idx           Ring index to check the mapping for.
    /// @param[in]    tcam_idx           TCAM index.
    /// @param[in]    group_desc         Group to check for.
    ///
    /// @retval       bool
    bool is_tcam_eligible_for_group(size_t ring_idx, size_t tcam_idx, const group_desc& group) const;

    /// @brief Allocated TCAM for a wide group.
    ///
    /// @param[in]     group_desc         Wide group to allocate for.
    /// @param[out]    out_tcam           TCAM allocated in case of success.
    ///
    /// @retval       la_status
    la_status allocate_tcam_for_wide_group(const group_desc& group, tcam_desc& out_tcam);

    /// @brief Allocated TCAM for a narrow group.
    ///
    /// @param[in]     group_desc         Narrow group to allocate for.
    /// @param[out]    out_tcam           TCAM allocated in case of success.
    ///
    /// @retval       la_status
    la_status allocate_tcam_for_narrow_group(const group_desc& group, tcam_desc& out_tcam);

    /// @brief do allocation of TCAM for a narrow group.
    ///
    /// @param[in]     group         Narrow group to allocate for.
    /// @param[out]    tcam          TCAM to allocate for group.
    ///
    /// @retval       la_status
    void do_allocate_tcam_for_narrow_group(const group_desc& group, const tcam_desc& tcam);

    /// @brief Convert ring and subring indices to SRAM allocator index
    ///
    /// @param[in]     ring_idx         Ring index.
    /// @param[in]     subring_idx         Subring index.
    ///
    /// @retval       SRAM allocator index.
    size_t cdb_ring_to_sram_allcoator_ring(size_t ring_idx, size_t subring_idx) const;

    /// @brief Configure TCAM in HW.
    ///
    /// @param[in]     ring_idx         Ring index of the TCAM to configure.
    /// @param[in]     subring_idx      Subring index of the TCAM to configure.
    /// @param[in]     tcam_idx         TCAM index.
    /// @param[in]     channel_idx      Channel index to configure.
    /// @param[in]     configure_sram   true/false whether to configure SRAMs, should be false in case there is no payload for the
    /// TCAM.
    ///
    virtual void configure_tcam(size_t ring_idx, size_t subring_idx, size_t tcam_idx, size_t channel, bool configure_sram) = 0;

    /// @brief Invalidate TCAM in HW.
    ///
    /// @param[in]     tcam             TCAM to invalidate.
    /// @param[in]     srams            SRAM pair to invalidate.
    /// @param[in]     result_channel   Result channel to remove SRAM from.
    ///
    virtual void invalidate_tcam(const tcam_desc& tcam, const ctm_sram_pair& srams, size_t result_channel) = 0;

    /// @brief Creates a TCAM container from a single TCAM.
    ///
    /// @param[in]     tcam        TCAM to create container from.
    ///
    /// @retval       tcam_container
    tcams_container create_tcams_container(const tcam_desc& tcam) const;

    /// @brief Creates a TCAM container from a two TCAMs.
    ///
    /// @param[in]     first_tcam    First TCAM to create container from.
    /// @param[in]     tcam          Second TCAM to create container from.
    ///
    /// @retval       tcam_container
    tcams_container create_tcams_container(const tcam_desc& first_tcam, const tcam_desc& second_tcam) const;

    // Members
    std::array<std::array<ctm::slice_interface_input_desc, ctm::NUM_CHANNELS_PER_CORE>, ctm::NUM_RINGS> m_ctm_slice_ifs_mapping_in;

    std::array<std::array<ctm::slice_interface_out_desc, ctm::NUM_INTERFACES_PER_SLICE>, ctm::NUM_SLICES>
        m_ctm_slice_ifs_mapping_out;

    // Map from internal core channel to external interface
    size_t m_key_channel_to_abs_input_interface[ctm::NUM_RINGS][ctm::NUM_CHANNELS_PER_CORE];

    // Map from interface to an internal channel
    size_t m_output_interface_to_abs_result_channel[ctm::NUM_SLICES][ctm::NUM_INTERFACES_PER_SLICE];

    // For configuring DB mergers
    uint8_t m_dbm[ctm::NUM_DB_MERGERS];

    std::unique_ptr<ctm_sram_allocator> m_sram_allocator;

    vector_alloc<groups_vec> m_slice_groups;

    rings_tcams_vec m_rings_tcams;

    // Configuration members
    vector_alloc<size_t> m_lpm_tcams_ring0;
    vector_alloc<size_t> m_lpm_tcams_ring1;

    size_t m_lpm_tcam_num_banksets;

    bool m_is_stand_alone;

    static const std::array<std::array<ctm::slice_interface_input_desc, ctm::NUM_CHANNELS_PER_CORE>, ctm::NUM_RINGS>
        s_ctm_slice_ifs_mapping_stand_alone_in;
    static const std::array<std::array<ctm::slice_interface_input_desc, ctm::NUM_CHANNELS_PER_CORE>, ctm::NUM_RINGS>
        s_ctm_slice_ifs_mapping_line_card_in;
    static const std::array<std::array<ctm::slice_interface_out_desc, ctm::NUM_INTERFACES_PER_SLICE>, ctm::NUM_SLICES>
        s_ctm_slice_ifs_mapping_stand_alone_out;
    static const std::array<std::array<ctm::slice_interface_out_desc, ctm::NUM_INTERFACES_PER_SLICE>, ctm::NUM_SLICES>
        s_ctm_slice_ifs_mapping_line_card_out;
};

} // namespace silicon_one

#endif // __CTM_CONFIG_TCAM_H__
