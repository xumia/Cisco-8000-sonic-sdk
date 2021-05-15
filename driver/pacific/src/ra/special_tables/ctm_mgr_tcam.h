// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __CTM_MGR_TCAM_H__
#define __CTM_MGR_TCAM_H__

#include "api/types/la_acl_types.h"
#include "common/allocator_wrapper.h"
#include "common/bit_vector.h"
#include "common/gen_utils.h"
#include "ctm/ctm_common_tcam.h"
#include "ctm/ctm_config_tcam.h"
#include "ctm_mgr.h"
#include "ctm_tcam_line_mgr.h"
#include "engine_block_mapper.h"
#include "hw_tables/memory_tcam.h"
#include "hw_tables/physical_locations.h"
#include "hw_tables/tcam_types.h"

namespace silicon_one
{

class ll_device;

/// @brief Implementation of #silicon_one::
class ctm_mgr_tcam : public ctm_mgr
{
    /////For Serialization Purposes/////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    ctm_mgr_tcam() = default;
    ////////////////////////////////////
public:
    /// @brief C'tor
    ///
    /// @param[in]  ldevice             Pointer to low level device.
    /// @param[in]  is_linecard_mode
    /// @param[in]  lpm_tcam_num_banksets
    /// @param[in]  block_mapper             Pointer to low level device.
    ctm_mgr_tcam(const ll_device_sptr& ldevice,
                 bool is_linecard_mode,
                 size_t lpm_tcam_num_banksets,
                 engine_block_mapper block_mapper,
                 size_t number_of_slices);

    // D'tor
    ~ctm_mgr_tcam() = default;

    la_status configure_hw() const override;

    /// TCAM MGR API
    la_status write(table_desc table_id,
                    size_t line_idx,
                    const bit_vector& key,
                    const bit_vector& mask,
                    const bit_vector& value) override;
    la_status write_bulk(table_desc table_id,
                         size_t first_line_idx,
                         size_t bulk_size,
                         const vector_alloc<tcam_entry_desc>& entries) override;
    la_status move(table_desc table_id, size_t src_line_idx, size_t dest_line) override;
    la_status update(table_desc table_id, size_t line_idx, const bit_vector& value) override;
    la_status invalidate(table_desc table_id, size_t line_idx) override;
    la_status read(table_desc table_id,
                   size_t line_idx,
                   bit_vector& out_key,
                   bit_vector& out_mask,
                   bit_vector& out_value,
                   bool& out_valid) override;
    la_status set_default_value(table_desc table_id,
                                const bit_vector& key,
                                const bit_vector& mask,
                                const bit_vector& value) override;
    size_t get_table_size(const table_desc& table_id) const override;

    size_t get_table_usage(const table_desc& table) const override;

    ///@brief Calclute the maximum entries that can be inserted successfully in a table in the current system state.
    ///
    ///@param[in] table table for which to check the maximum scale.
    ///@retval   number of lines that can be successfully inserted.
    size_t get_max_available_space(const table_desc& table) override;

private:
    struct line_desc {
        size_t line;
        tcam_desc tcam_id;

        line_desc() : line(ctm::IDX_INVAL), tcam_id(){};
        line_desc(const size_t line_init, const tcam_desc& tcam_id_init) : line(line_init), tcam_id(tcam_id_init){};
        line_desc operator=(const line_desc& ref);
        bool operator!=(const line_desc& ref) const;
        bool operator<(const line_desc& ref) const;
        bool operator>(const line_desc& ref) const;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(line_desc)

    struct remaining_stack_space_s {
        // We allow for negative values, for easier math and they do exist logically to represent how much space is lacking.
        int total_space;
        int wide_space;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(remaining_stack_space_s)

    enum {
        NUM_OF_STACKS = 2,    // number of possible tcam stacks.
        FIRST_STACK_IDX = 0,  // idx of first stack.
        SECOND_STACK_IDX = 1, // idx of second stack.
    };

    struct group_data_for_reallocation_s {
        group_data_for_reallocation_s() : narrow_groups(NUM_OF_STACKS), num_of_narrow_tcams_to_clear_per_stack(NUM_OF_STACKS)
        {
        }
        std::vector<group_desc> narrow_groups;
        group_desc wide_group;
        vector_alloc<size_t> num_of_narrow_tcams_to_clear_per_stack;
        size_t num_of_wide_tcams_to_clear;
        size_t number_of_tcam_stacks;
        bool is_tcam_paired;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(group_data_for_reallocation_s)

    struct tcams_per_space_s {
        size_t wide_tcams = 0;        // Linear scale one tcam. Width 2 tcams.
        size_t narrow_only_tcams = 0; // Linear scale 1 tcam. Width 1 tcam. Basicaly theese tcams have lpm on the other side.
    };

    CEREAL_SUPPORT_PRIVATE_CLASS(tcams_per_space_s)

    using line_position = size_t;
    using lines_map = map_alloc<line_position, line_desc>;
    using line_iterator = lines_map::iterator;
    using memory_map = map_alloc<tcam_desc, memory_tcam>;
    using ctm_config_tcam_sptr = std::shared_ptr<ctm_config_tcam>;
    using table_to_lines_mapping_map = map_alloc<table_desc, lines_map>;

    ctm_config_tcam_sptr m_ctm_config_tcam;

    map_alloc<tcam_desc, ctm_tcam_line_mgr> m_line_mgr; // line mgr per TCAM bank
    memory_map m_mem_tcam_160;                          // memory tcam per TCAM bank (key size 160)
    memory_map m_mem_tcam_320;                          // memory tcam per TCAM bank (key size 320)
    map_alloc<group_desc, size_t> m_group_size;
    table_to_lines_mapping_map m_entries; // for each table map of the allocated entries.

    vector_alloc<group_desc> m_groups_that_cant_reallocate;
    vector_alloc<tcam_desc> m_reserved_tcams;

    map_alloc<group_desc, vector_alloc<tcam_desc> > m_tcam_already_freed_from_group; // this is transient data used to protect
                                                                                     // during tcam re/allocation from infinite
                                                                                     // loops. It keeps a map of group->tcams that
                                                                                     // were taken from this group.

    /// @brief Get initialized configuration object for CTM.
    ///
    /// @retval     pointer to the initialized configuration object.
    const ctm_config_sptr get_ctm_config() const override;

private:
    /// @brief Assigns absolute TCAM lines from a relative line.
    ///
    /// @param[in]  table               The relavent table.
    /// @param[in]  first_line_idx      The first relative line from which to assign.
    /// @param[in]  number_of_lines     The number of lines needed to be assigned.
    /// @return     #la_status
    la_status allocate_lines(table_desc table, line_position first_line_idx, size_t number_of_lines);

    la_status make_space_for_group(group_desc group, size_t number_of_lines);

    /// @brief Tries to bring more free space on the lsb and msb side of a wide group by doing group relocation.
    ///
    /// @param[in]  wide_group          Wide group for which we are making more space.
    /// @param[in]  number_of_lines     Number of lines needed to be free.
    /// @param[out] out_free_space_lsb  Number of free lines on the lsb side.
    /// @param[out] out_free_space_msb  Number of free lines on the msb side.
    void relocate_narrow_groups_for_wide_group(const group_desc& wide_group,
                                               size_t number_of_lines,
                                               size_t& out_free_space_lsb,
                                               size_t& out_free_space_msb);

    /// @brief Tries to bring more free space on the lsb and msb side of a wide group by doing narrow tcam allocation.
    ///        For each side, if the allocation is successfull group relocation will be done as well.
    ///
    /// @param[in]  wide_group          Wide group for which we are making more space.
    /// @param[in]  number_of_lines     Number of lines needed to be free.
    /// @param[in]  free_space_lsb      Number of free lines on the lsb side.
    /// @param[in]  free_space_msb      Number of free lines on the msb side.
    ///
    /// @return  #la_status
    la_status allocate_narrow_tcams_for_wide_group(const group_desc& wide_group,
                                                   size_t number_of_lines,
                                                   size_t free_space_lsb,
                                                   size_t free_space_msb);

    // Releases absolute TCAM line mapping.
    la_status release_line(table_desc table_id, size_t line_idx);

    ///@brief Get number of free lines in a vector of tcams.
    ///
    ///@param[in]  tcams                    A container of tcams on which to check for a free line.
    ///@param[in]  needed_number_of_lines   The maximum number of free lines to search for.
    ///@return     number of free lines
    size_t get_free_space_in_tcams(const tcams_container& tcams);

    ///@brief Find the first free line in a container of tcams.
    ///
    ///@param[in]  tcams                 A container of tcams on which to search for a free line.
    ///@param[in]  out_in_tcam_it        A tcam container iterator pointing to the first tcam from which to search
    ///@param[in]  out_in_first_line     First line index in tcam from which to search.
    ///@param[out] out_in_tcam_it        A tcam container iterator pointing to the tcam on which the line was found, end()
    /// otherwise.
    ///@param[out] out_in_first_line     Free line index in the tcam that was found, undefined otherwise.
    ///@return     #la_status
    la_status find_free_line_in_tcams(const tcams_container& tcams,
                                      tcams_container::const_iterator& out_in_tcam_it,
                                      size_t& out_in_first_line);

    size_t get_free_space_in_group(group_desc group);
    size_t get_free_space_in_group(group_desc group, const tcams_container& tcams_to_avoid);
    size_t get_number_of_lines_in_group(const group_desc& group) const override;
    line_desc find_free_wide_line_in_tcam(const line_desc& start_line, const line_desc& end_line);
    la_status make_free_wide_lines(group_desc& group, size_t number_of_lines);
    la_status make_free_wide_lines(group_desc& group, size_t number_of_lines, const tcams_container& tcams_to_avoid);
    la_status map_physical_to_logical_address(line_desc line, table_desc& table_out, size_t& logical_index);

    set_alloc<group_desc> get_indirect_compeeting_groups(const group_desc& subject_group,
                                                         groups_container& subject_compeeting_groups);

    void count_the_need_for_one_TCAM_space_wide_competition(groups_container& competing_groups,
                                                            map_alloc<group_desc, vector_alloc<size_t> >& group_to_spaces_map,
                                                            map_alloc<group_desc, size_t>& out_group_to_unused_space_map,
                                                            map_alloc<size_t, tcams_per_space_s>& out_available_tcams_per_space);
    void count_the_need_for_two_TCAM_spaces_wide_competition(vector_alloc<size_t>& spaces_for_subject_group,
                                                             groups_container& competing_groups,
                                                             map_alloc<group_desc, vector_alloc<size_t> >& group_to_spaces_map,
                                                             map_alloc<group_desc, size_t>& out_group_to_unused_space_map,
                                                             map_alloc<size_t, tcams_per_space_s>& out_available_tcams_per_space);
    void count_the_need_for_one_TCAM_space_narrow_competition(const group_desc& subject_group,
                                                              groups_container& competing_groups,
                                                              map_alloc<group_desc, vector_alloc<size_t> >& group_to_spaces_map,
                                                              map_alloc<group_desc, size_t>& out_group_to_unused_space_map,
                                                              map_alloc<size_t, tcams_per_space_s>& out_available_tcams_per_space);
    void count_the_need_for_two_TCAM_spaces_narrow_competition(const group_desc& subject_group,
                                                               vector_alloc<size_t>& spaces_for_subject_group,
                                                               groups_container& competing_groups,
                                                               map_alloc<group_desc, vector_alloc<size_t> >& group_to_spaces_map,
                                                               map_alloc<group_desc, size_t>& out_group_to_unused_space_map,
                                                               map_alloc<size_t, tcams_per_space_s>& out_available_tcams_per_space);

    void get_available_space_after_compeeting_groups_needs(const group_desc& subject_group,
                                                           map_alloc<group_desc, size_t>& out_group_to_unused_space_map,
                                                           map_alloc<size_t, tcams_per_space_s>& out_available_tcams_per_space);
    size_t calculate_max_available_space_wide(const group_desc& subject_group,
                                              map_alloc<size_t, tcams_per_space_s>& available_tcams_per_space);
    size_t calculate_max_available_space_narrow(const group_desc& subject_group,
                                                const map_alloc<group_desc, size_t>& group_to_unused_space_map,
                                                const map_alloc<size_t, tcams_per_space_s>& available_tcams_per_space);

    ///@brief Will try to relocate lines from tables to try and make additional free lines on a set of provided tcams.
    ///
    ///@param[in]  destination_tcams            Theese are the tcams that need the free lines.
    ///@param[in]  number_of_lines_to_relocate  The number of lines needed to be relocated.
    ///@return     Number of lines relocated
    size_t relocate_groups(const tcams_container& destination_tcams, size_t number_of_lines_to_relocate);

    ///@brief try to allocate new tcams for the group.
    ///
    ///@param[in]  group                 The group to add tcams to.
    ///@param[in]  number_of_tcams       The number of tcams to allocate.
    ///@param[in]  must_alocate_all      If must_alocate_all then return success only if all the tcams were allocated.
    ///                                  If not, return success if at least one tcam was allocated.
    ///@return     #la_status
    la_status allocate_new_tcams_for_group(const group_desc& group, size_t number_of_tcams, bool must_allocate_all);
    la_status allocate_tcam_for_group(const group_desc& group, tcam_desc& out_tcam);
    la_status try_free_tcams(const group_desc& group_to_make_space_for);
    la_status can_tcams_be_cleared_for_reallocation(const tcams_container& tcams);
    remaining_stack_space_s get_free_space_after_clear(const group_desc& narrow_group_on_stack,
                                                       const group_desc& wide_group_on_stack,
                                                       size_t num_of_narrow_tcams_to_clear,
                                                       size_t num_of_wide_tcams_to_clear);
    group_data_for_reallocation_s get_tcams_info_for_reallocation(const tcams_container& tcams_to_free);

    ///@brief try to free tcams for group by calling recursive reallocation.
    ///
    ///@param[in]  group_to_make_space_for       The group to free tcams for.
    ///
    ///@return     #la_status
    la_status recursive_reallocation(const group_desc& group_to_make_space_for);
    la_status try_recursive_reallocation_to_free_wide_tcams(const tcams_container& tcam_pair_to_free);
    la_status try_recursive_reallocation_to_free_narrow_tcams_for_wide_group(const tcams_container& tcam_pair_to_free,
                                                                             const group_desc& group_to_make_space_for);
    la_status try_recursive_reallocation_to_free_narrow_tcams_for_narrow_group(const tcams_container& tcam_pair_to_free);

    ///@brief Clear and free tcams.
    la_status free_tcams(const tcams_container& tcams_to_free);

    ///@brief Clear tcams of all content, by pushing it to the left and right, until the tcam is empty.
    la_status clear_tcams(const tcams_container& tcams_to_free);
    bool are_tcams_on_the_same_narrow_group(const tcams_container& tcams);
    la_status allocate_line_in_range(table_desc table,
                                     line_desc prev_line_desc,
                                     line_desc next_line_desc,
                                     const tcams_container& tcams_to_avoid,
                                     line_desc& abs_line);

    /// @brief Find and allocate free TCAM lines on left side between first and last line.
    ///
    /// @param[in]  table               The relavent table.
    /// @param[in]  entries             The entries map of the table.
    /// @param[in]  first_line          The first line from which to search.
    /// @param[in]  last_line           The last line upto which to search.
    /// @param[in]  lines_to_allocate   The maximum number of lines needed to be allocated.
    /// @param[out] new_lines           The descriptors of the allocated lines.
    /// @return     #la_status
    la_status find_and_allocate_lines_in_range_left(table_desc table,
                                                    lines_map& entries,
                                                    line_iterator& first_line,
                                                    line_iterator& last_line,
                                                    size_t& lines_to_allocate,
                                                    const tcams_container& tcams_to_avoid,
                                                    vector_alloc<line_desc>& new_lines);
    /// @brief Find and allocate free TCAM lines on right side between first and last line.
    ///
    /// @param[in]  table               The relavent table.
    /// @param[in]  entries             The entries map of the table.
    /// @param[in]  first_line          The first line from which to search.
    /// @param[in]  last_line           The last line upto which to search.
    /// @param[in]  lines_to_allocate   The maximum number of lines needed to be allocated.
    /// @param[out] new_lines           The descriptors of the allocated lines.
    /// @return     #la_status
    la_status find_and_allocate_lines_in_range_right(table_desc table,
                                                     lines_map& entries,
                                                     line_iterator& first_line,
                                                     line_iterator& last_line,
                                                     size_t& lines_to_allocate,
                                                     const tcams_container& tcams_to_avoid,
                                                     vector_alloc<line_desc>& new_lines);

    /// @brief Find and allocate free TCAM lines from first_line_idx.
    ///
    /// @param[in]  table               The relavent table.
    /// @param[in]  first_line_idx      The first line from which to search.
    /// @param[in]  number_of_lines     The maximum number of lines needed to be allocated.
    /// @param[in]  allocate_for_write  If the allocation called for writing  - true, if for moving - false.
    /// @param[in]  tcams_to_avoid      Tcams to avoid allocating lines in.
    /// @param[out] new_lines_out       The descriptors of the allocated lines.
    /// @return     #la_status
    la_status find_and_allocate_lines(table_desc table,
                                      line_position first_line_idx,
                                      size_t number_of_lines,
                                      bool allocate_for_write,
                                      const tcams_container& tcams_to_avoid,
                                      vector_alloc<line_desc>& new_lines_out);
    la_status find_and_allocate_lines_for_write(table_desc table,
                                                line_position first_line_idx,
                                                size_t number_of_lines,
                                                vector_alloc<line_desc>& new_lines_out);
    la_status find_and_allocate_lines_for_move(table_desc table,
                                               line_position first_line_idx,
                                               size_t number_of_lines,
                                               const tcams_container& tcams_to_avoid,
                                               vector_alloc<line_desc>& new_lines_out);

    la_status move_lines(line_iterator to_move, line_iterator new_abs_line, line_desc empty_abs_line, bool direction);
    size_t find_allocated_lines_in_tcam(const table_desc& table,
                                        const tcam_desc& tcam,
                                        line_position& out_first_line_to_move,
                                        size_t needed_number_of_lines);

    void initialize_tcam_table_mapping();
    void initialize_group_table_mapping();
    void initialize_table_sizes();
    void create_mem_tcam(const tcam_desc& tcam);
    void create_line_mgr_for_tcam(const tcam_desc& tcam);

    la_status move_one_line(table_desc table, size_t src_line_idx, size_t dest_line_idx);

    la_status push_lines_left(const table_desc& table,
                              line_iterator stop_line,
                              line_iterator next_to_move,
                              vector_alloc<line_desc>& free_lines);
    la_status push_lines_right(const table_desc& table,
                               line_iterator stop_line,
                               line_iterator next_to_move,
                               vector_alloc<line_desc>& free_lines);

    la_status move_one_line(const table_desc& table, line_desc& src_line, line_desc& dest_line);

    void filter_tcams(const tcams_container& tcams, const tcams_container& tcams_to_remove, tcams_container& out_tcams);
    void filter_tcams_to_free(tcams_container_vec& in_out_tcams_pairs, const group_desc& group_to_make_space_for);
    void filter_tcams_pairs(tcams_container_vec& in_out_tcams_pairs, const vector_alloc<group_desc>& groups_to_filter);
    void filter_tcams_pairs(tcams_container_vec& in_out_tcams_pairs, const vector_alloc<tcam_desc>& tcams_to_remove);
    bool does_tcams_contain_a_group_from_list(const tcams_container& tcams, const vector_alloc<group_desc>& groups);

    // Append CTM TCAM/SRAM to the existing memories of the section
    void append_ctm_tcam(tcam_section& section, size_t ring_idx, size_t subring_idx, size_t tcam_idx);
    void append_ctm_sram(tcam_section& section, size_t ring_idx, size_t subring_idx, size_t sram_idx, size_t offset);
    memory_tcam& get_memory_tcam(const tcam_desc& tcam_id, const table_desc& table);

    const tcams_container& get_eligible_tcams_for_table(const table_desc& desc) const;
    const tcams_container& get_eligible_lsb_tcams_for_wide_table(const table_desc& desc) const;
    table_vec get_tables_by_tcam(const tcam_desc& tcam) const;
    group_desc get_narrow_group_on_tcam(const tcam_desc& tcam) const;
    group_desc get_wide_group_on_tcams(const tcams_container& tcams) const;
    group_desc get_sibling_groups(const group_desc& narrow_group) const;
    groups_container get_narrow_groups(const group_desc& wide_group) const;
    bool is_subgroup(const group_desc& wide_group, const group_desc& narrow_group) const;
    size_t get_number_of_tcams_needed_to_fit_lines(const size_t number_of_lines) const;
    tcam_desc get_paired_tcam(const tcam_desc& tcam);

    void insert_to_sorted_line_vector(vector_alloc<line_desc>& line_vector, line_desc& line);
};

} // namespace silicon_one

#endif // __CTM_MGR_TCAM_H__
