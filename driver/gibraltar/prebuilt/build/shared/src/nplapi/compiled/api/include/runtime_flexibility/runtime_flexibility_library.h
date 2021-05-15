// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef RUNTIME_FLEXIBILITY_LIBRARY_H
#define RUNTIME_FLEXIBILITY_LIBRARY_H
#include "runtime_flexibility_types.h"

typedef void (*callback_print)(std::string /*print comment*/, size_t /*library id*/);
// Helper structs

enum udk_placement_bucket_type_e {
    UDK_PLACEMENT_BUCKET_TYPE_PACKET_AND_PD = 0,
    UDK_PLACEMENT_BUCKET_TYPE_PACKET_ONLY = 1,
    UDK_PLACEMENT_BUCKET_TYPE_CALCULATED_ONLY = 2
};

class runtime_flexibility_library
{

#ifdef CEREAL_SUPPORT_PRIVATE_MEMBERS
    CEREAL_SUPPORT_PRIVATE_MEMBERS
#endif

public:
    struct udk_component_internal {
        mutable udk_component component;
        mutable size_t index;
        mutable std::vector<int> component_index_in_place_udk_vec_per_table;
        mutable uint16_t component_fragment_offset = 0;
        mutable uint8_t number_of_tables_used_in = 0;
        mutable bool fragmented_component_parent_skip_placement = false;
        mutable bool fragmented_component_child = false;
        uint16_t lsb_penalty;
        bool may_share_channel(const udk_component_internal& rhs_component) const;
        bool is_intersecting(const udk_component_internal& rhs_component) const;
        udk_component_internal()
        {
            component = udk_component();
            index = 0;
            lsb_penalty = 0;
        }
        udk_component_internal(const udk_component& _component, size_t _index)
        {
            component = _component;
            index = _index;
            lsb_penalty = get_lsb_penalty(_component);
        }
        udk_component_internal(const udk_component_internal& _internal_component)
        {
            component = _internal_component.component;
            index = _internal_component.index;
            component_index_in_place_udk_vec_per_table
                = std::vector<int>(_internal_component.component_index_in_place_udk_vec_per_table);
            number_of_tables_used_in = _internal_component.number_of_tables_used_in;
            fragmented_component_parent_skip_placement = _internal_component.fragmented_component_parent_skip_placement;
            fragmented_component_child = _internal_component.fragmented_component_child;
            component_fragment_offset = _internal_component.component_fragment_offset;
            lsb_penalty = _internal_component.lsb_penalty;
        }
        udk_component_internal& operator=(const udk_component_internal& _internal_component)
        {
            component = _internal_component.component;
            index = _internal_component.index;
            component_index_in_place_udk_vec_per_table = _internal_component.component_index_in_place_udk_vec_per_table;
            number_of_tables_used_in = _internal_component.number_of_tables_used_in;
            fragmented_component_parent_skip_placement = _internal_component.fragmented_component_parent_skip_placement;
            fragmented_component_child = _internal_component.fragmented_component_child;
            component_fragment_offset = _internal_component.component_fragment_offset;
            lsb_penalty = _internal_component.lsb_penalty;
            return *this;
        }
        std::vector<std::pair<std::vector<size_t>, std::vector<size_t>>> get_split_set_of_tables();
        void fragment_internal_component_split_list_init(std::vector<std::pair<uint16_t, uint16_t>>& split_combinations_vec);
        void fragment_internal_component_vec_gen(size_t fragments_start_index,
                                                 std::pair<uint16_t, uint16_t>& comb,
                                                 std::vector<udk_component_internal>& fragments_vec);
        uint16_t get_msb_penalty() const;
        uint16_t get_width_with_lsb_penalty() const;
        uint16_t get_offset_to_lsb_with_penalty() const;
        static uint16_t get_lsb_penalty(const udk_component& _component)
        {
            // offset_to_lsb = offset_in_bits + m_width_in_bits
            if (_component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PACKET
                || _component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PD) {
                return (8 - (_component.offset_in_bits + _component.m_width_in_bits) % 8) % 8;
            }
            return 0;
        }
    };

    struct udk_components_group {
        std::vector<udk_component_internal> components; // ordered from msb to lsb
        uint16_t msb_offset = 0;
        uint16_t offset_to_lsb_with_penalty = 0;
        uint16_t get_msb_penalty() const;
        void add_component_on_lsb(udk_component_internal& component);
        int get_additional_width_to_place_if_adjacent(const udk_component_internal& other_component);
        uint16_t get_group_width();
        udk_components_group()
        {
        }
        udk_components_group(const udk_components_group& _group)
            : components(_group.components),
              msb_offset(_group.msb_offset),
              offset_to_lsb_with_penalty(_group.offset_to_lsb_with_penalty)
        // copy c'tor
        {
        }
    };

    struct udk_placement_bucket {
        int available_width = 0;
        int used_width = 0;
        field_select_info field_select;
        udk_placement_bucket_type_e bucket_type = UDK_PLACEMENT_BUCKET_TYPE_PACKET_AND_PD;
        std::vector<udk_component_internal> placed_fields;
        std::vector<udk_components_group> placed_component_groups;
        size_t max_msb_penalty = 0;
        std::map<size_t /*table index*/, uint8_t /*key part index*/> tables_in;
        size_t bucket_index = 0;
        udk_placement_bucket(size_t _available_width,
                             field_select_info _field_select,
                             udk_placement_bucket_type_e _bucket_type,
                             size_t _bucket_index)
            : available_width(static_cast<int>(_available_width)),
              used_width(0),
              field_select(_field_select),
              bucket_type(_bucket_type),
              bucket_index(_bucket_index)
        {
        }
        udk_placement_bucket()
        {
        }
        int restructure_component_groups();

        void split_components_into_groups(std::vector<udk_component_internal>& sorted_placed_fields);
    };

    struct key_part {
        size_t max_width;
        size_t used_width;
        std::vector<size_t> udk_placement_buckets_indices;
        std::vector<udk_placement_bucket> udk_placement_buckets; // for debug puproses only
        std::vector<udk_component_internal> range_compression_components;
        size_t number_of_buckets_supporting_udf;
        size_t number_of_constant_bits;
        size_t max_number_of_buckets;
        int get_available_width() const
        {
            int range_compression_nibble_allignment = 0;
            if (range_compression_components.size() > 0 && ((used_width + number_of_constant_bits) % 4 > 0)) {
                range_compression_nibble_allignment += 4 - ((used_width + number_of_constant_bits) % 4);
            }
            return static_cast<int>(max_width - used_width - number_of_constant_bits - range_compression_nibble_allignment);
        }
        bool additional_buckets_available() const
        {
            return udk_placement_buckets_indices.size() < max_number_of_buckets;
        }
        key_part(const size_t _max_width, const size_t _num_of_constant_bits, const size_t _max_number_of_buckets)
            : max_width(_max_width),
              used_width(0),
              number_of_buckets_supporting_udf(0),
              number_of_constant_bits(_num_of_constant_bits),
              max_number_of_buckets(_max_number_of_buckets)
        {
        }
        key_part()
        {
        }
    };

    struct udk_component_pointer {
        size_t original_index = 0;
        size_t offset_to_add = 0;
        size_t width = 0;
        udk_component_pointer(){};
        udk_component_pointer(size_t _original_index, size_t _offset_to_add, size_t _width)
            : original_index(_original_index), offset_to_add(_offset_to_add), width(_width){};
    };
    runtime_flexibility_library(callback_print cback_print_func,
                                bool is_placing_for_nsim,
                                size_t library_id,
                                bool is_placing_for_hw = true);
    void set_callback_print(callback_print cback_print_func);
    place_udk_res place_udk(const udk_resources& resources /*generated input*/,
                            const std::vector<udk_table_id_and_components>& udk_components /*runtime input*/,
                            std::vector<microcode_write>& placement_output /*output*/,
                            std::vector<udk_translation_info>& trans_info /*output*/);
    ~runtime_flexibility_library()
    {
    }
    key_part get_last_udk_placement(size_t table_index, size_t key_part_idx) const;

    std::string get_last_udk_placement_str() const;
    void set_is_placing_for_nsim(bool is_placing_for_nsim);
    void set_is_placing_for_hw(bool is_placing_for_hw);
    const std::vector<std::string>& get_udk_data_output_str();
    void set_verbose(bool verbose);
    void set_components_fragmentization(bool enable_fragment);
    void set_log_level(size_t log_level);
    size_t get_log_level();
    bool check_log_level(size_t log_level);

private:
    // Default c'tor - disallowed, used only for serialization purposes.
    runtime_flexibility_library();
    place_udk_res nsim_place_udk(const udk_resources& resources,
                                 const std::vector<udk_table_id_and_components>& udk_components,
                                 std::vector<microcode_write>& microcode_writes,
                                 std::vector<udk_translation_info>& trans_info /*output*/);
    place_udk_res hw_place_udk(const udk_resources& resources /*generated input*/,
                               const std::vector<udk_table_id_and_components>& udk_components /*runtime input*/,
                               std::vector<microcode_write>& microcode_writes /*output*/,
                               std::vector<udk_translation_info>& trans_info /*output*/);
    place_udk_res place_udk_init_vars(const udk_resources& resources,
                                      const std::vector<udk_table_id_and_components>& udk_table_id_and_components);
    bool recursive_place_udk(size_t component_index);
    bool recursive_place_udk_component_and_bucket(size_t bucket_index,
                                                  size_t component_index,
                                                  bool& succeed_in_placement_skip_fragmentation);
    bool place_bucket_in_udk_tables(size_t bucket_index, size_t component_index);
    bool place_udk_component_in_bucket(size_t bucket_index, const udk_component_internal& component);
    bool place_range_compression_udk_component_in_table(size_t component_index, size_t table_index, uint8_t key_part_index);
    bool revert_last_udk_placement(size_t bucket_index);
    int revert_last_udk_placement_in_bucket(size_t bucket_index);
    bool generate_place_udk_outputs(const udk_resources& resources,
                                    const std::vector<udk_table_id_and_components>& udk_table_id_and_components,
                                    std::vector<microcode_write>& placement_output /*output*/,
                                    std::vector<udk_translation_info>& trans_info /*output*/
                                    );
    bool generate_udk_microcode_writes(const udk_resources& resources, std::vector<microcode_write>& placement_output);
    bool generate_key_construction_lines_microcode_changes(const udk_resources& resources,
                                                           std::vector<microcode_write>& placement_output);
    bool generate_field_selects_at_key_construction_level_microcode_changes(const udk_resources& resources,
                                                                            std::vector<microcode_write>& placement_output);
    bool generate_scoper_channels_microcode_changes(const udk_resources& resources, std::vector<microcode_write>& placement_output);
    void create_microcode_writes_as_string(std::vector<microcode_write>& placement_output); // general function
    bool generate_udk_translation_info(const udk_resources& resources, std::vector<udk_translation_info>& trans_info);
    bool generate_udk_translation_info_for_nsim(const udk_resources& resources,
                                                const std::vector<udk_table_id_and_components>& udk_tables_components,
                                                std::vector<udk_translation_info>& trans_info);
    void sort_fields_in_udk_buckets_post_placement();
    bool possible_to_place_width_in_udk_bucket(size_t width_to_place, udk_placement_bucket& bucket);
    bool possible_to_place_width_in_remaining_udk_buckets(udk_component_internal& internal_component);
    int calculate_width_to_place(const udk_component_internal& internal_component, size_t bucket_index);
    bool do_component_tables_match_bucket_tables(const udk_component_internal& internal_component, size_t bucket_index) const;
    void merge_intersecting_udk_components_in_a_single_key(size_t table_index,
                                                           size_t processed_component_index,
                                                           size_t original_component_index);
    void dump_udk_table_components(const std::vector<udk_table_id_and_components>& udk_table_id_and_components);
    bool verify_udk_table_components_are_legal(const std::vector<udk_table_id_and_components>& udk_table_id_and_components,
                                               const udk_resources& resource);
    void merge_intersecting_udk_components_calculated_fields_in_a_single_key(size_t table_index,
                                                                             size_t processed_component_index,
                                                                             size_t original_component_index);
    void clean_place_udk_outputs(std::vector<microcode_write>& placement_output /*output*/,
                                 std::vector<udk_translation_info>& trans_info /*output*/);

private:
    callback_print m_callback_print;
    bool m_is_placing_for_nsim;
    bool m_is_placing_for_hw;
    size_t m_library_id;
    std::vector<std::vector<key_part>> m_tables_key_parts;
    std::vector<udk_component_internal> m_udk_components;
    std::vector<udk_placement_bucket> m_udk_placement_buckets;
    std::vector<udk_table_id_and_components> m_udk_tables_components;
    std::vector<udk_table_id_and_components> m_processed_udk_tables_components;
    std::vector<std::vector<std::vector<udk_component_pointer>>> m_processed_component_index_to_original_indices_and_offset;
    std::vector<std::string> m_udk_data_str_outputs; // for debug purposes only

    bool m_verbose;
    bool m_components_fragmentization_enable = true;
    size_t m_log_level = 0;
};

#endif // RUNTIME_FLEXIBILITY_LIBRARY_H
