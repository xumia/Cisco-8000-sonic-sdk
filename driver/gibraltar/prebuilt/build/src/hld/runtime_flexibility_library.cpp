// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "runtime_flexibility_library.h"
#include <algorithm>
#include <set>
#include "common/bit_vector.h"
using silicon_one::bit_vector;
using silicon_one::bit_vector64_t;
using silicon_one::bit_vector128_t;
using silicon_one::bit_vector192_t;
using silicon_one::bit_vector384_t;

// sorting methods:
struct field_select_less {
    bool operator()(const field_select_info& a, const field_select_info& b) const
    {
        if (a.fs_allocated_width == b.fs_allocated_width) {
            return a.fs_index < b.fs_index;
        }
        return a.fs_allocated_width > b.fs_allocated_width;
    }
};

struct udk_component_less {
    bool operator()(const runtime_flexibility_library::udk_component_internal& a,
                    const runtime_flexibility_library::udk_component_internal& b) const
    {
        if (a.component.m_udk_type != b.component.m_udk_type) {
            return a.component.m_udk_type > b.component.m_udk_type; // udk_component_type enum is set with prioritized values
        } else if (a.number_of_tables_used_in != b.number_of_tables_used_in) // less tables used first - for less recursive calls
        {
            return a.number_of_tables_used_in < b.number_of_tables_used_in;
        }
        for (size_t table_id = 0; table_id < a.component_index_in_place_udk_vec_per_table.size();
             table_id++) // make components with same table colors together
        {
            if ((a.component_index_in_place_udk_vec_per_table[table_id] == -1)
                != (b.component_index_in_place_udk_vec_per_table[table_id] == -1)) {
                return a.component_index_in_place_udk_vec_per_table[table_id] != -1;
            }
        }
        // handle the larger components first
        if (a.component.get_width_on_key_in_bits() >= 32 || b.component.get_width_on_key_in_bits() >= 32) {
            if (a.component.get_width_on_key_in_bits() != b.component.get_width_on_key_in_bits()) {
                return a.component.get_width_on_key_in_bits() > b.component.get_width_on_key_in_bits();
            }
        }
        if (a.component.offset_in_bits != b.component.offset_in_bits) {
            return a.component.offset_in_bits < b.component.offset_in_bits;
        } // prioritizing offset makes components merge easier

        if (a.component.get_width_on_key_in_bits() != b.component.get_width_on_key_in_bits()) {
            return a.component.get_width_on_key_in_bits() > b.component.get_width_on_key_in_bits();
        }
        for (size_t table_id = 0; table_id < a.component_index_in_place_udk_vec_per_table.size();
             table_id++) // make components with same table colors together
        {
            if (a.component_index_in_place_udk_vec_per_table[table_id] != b.component_index_in_place_udk_vec_per_table[table_id]) {
                return a.component_index_in_place_udk_vec_per_table[table_id]
                       > b.component_index_in_place_udk_vec_per_table[table_id];
            }
        }
        return false;
    }
};

struct udk_component_merge_less {
    bool operator()(const runtime_flexibility_library::udk_component_internal& a,
                    const runtime_flexibility_library::udk_component_internal& b) const
    {
        auto& lhs_component = a.component;
        auto& rhs_component = b.component;
        if (lhs_component.m_udk_type
            != rhs_component.m_udk_type) { // no need to merge calculated fields or range compression components
            return lhs_component.m_udk_type > rhs_component.m_udk_type;
        }
        if (lhs_component.get_width_on_key_in_bits() != rhs_component.get_width_on_key_in_bits()) {
            return lhs_component.get_width_on_key_in_bits() > rhs_component.get_width_on_key_in_bits();
        }
        if (lhs_component.offset_in_bits != rhs_component.offset_in_bits) {
            return lhs_component.offset_in_bits < rhs_component.offset_in_bits;
        }
        auto& lhs_data = lhs_component.m_data;
        auto& rhs_data = rhs_component.m_data;
        auto& lhs_udf = lhs_data.udf_from_packet_instance;
        auto& rhs_udf = rhs_data.udf_from_packet_instance;
        switch (lhs_component.m_udk_type) {
        case UDK_COMPONENT_TYPE_UDF_FROM_PACKET: {
            if (lhs_udf.protocol_layer != rhs_udf.protocol_layer) {
                return lhs_udf.protocol_layer > rhs_udf.protocol_layer;
            }
            if (lhs_udf.header != rhs_udf.header) {
                return lhs_udf.header > rhs_udf.header;
            }
            if (lhs_udf.is_relative != rhs_udf.is_relative) {
                return lhs_udf.is_relative;
            }
            return false;
        }
        case UDK_COMPONENT_TYPE_CALCULATED_FIELD: {
            if (lhs_data.m_calculated_field_instance.field_id != rhs_data.m_calculated_field_instance.field_id) {
                return lhs_data.m_calculated_field_instance.field_id > rhs_data.m_calculated_field_instance.field_id;
            }
            return false;
            break;
        }
        case UDK_COMPONENT_TYPE_RANGE_COMPRESSION_RESULT:
            break;
        default: {
            return false;
        }
        }
        for (size_t table_index = 0; table_index < a.component_index_in_place_udk_vec_per_table.size();
             table_index++) { // joint to calculated and range compression result components
            if (a.component_index_in_place_udk_vec_per_table[table_index]
                != b.component_index_in_place_udk_vec_per_table[table_index]) {
                return a.component_index_in_place_udk_vec_per_table[table_index]
                       > b.component_index_in_place_udk_vec_per_table[table_index];
            }
        }
        return false;
    }
};

struct udk_components_group_less {
    bool operator()(const runtime_flexibility_library::udk_components_group& a,
                    const runtime_flexibility_library::udk_components_group& b) const
    {
        if (a.get_msb_penalty() != b.get_msb_penalty()) {
            return a.get_msb_penalty() < b.get_msb_penalty();
        } else if (a.msb_offset != b.msb_offset) {
            return a.msb_offset < b.msb_offset;
        }
        return false;
    }
};

uint16_t
runtime_flexibility_library::udk_component_internal::get_msb_penalty() const
{
    uint16_t penalty = component.offset_in_bits % 8;
    if (component.get_width_in_bits() % 16 > 0 && component.get_width_in_bits() % 16 <= 8) {
        penalty += 8; // width penalty
    }
    return penalty;
}

uint16_t
runtime_flexibility_library::udk_component_internal::get_width_with_lsb_penalty() const
{
    return component.get_width_in_bits() + lsb_penalty;
}

uint16_t
runtime_flexibility_library::udk_component_internal::get_offset_to_lsb_with_penalty() const
{
    return component.offset_in_bits + get_width_with_lsb_penalty();
}

bool
runtime_flexibility_library::udk_component_internal::is_intersecting(
    const runtime_flexibility_library::udk_component_internal& rhs_component) const
{
    for (size_t table_index = 0; table_index < this->component_index_in_place_udk_vec_per_table.size(); table_index++) {
        if ((this->component_index_in_place_udk_vec_per_table[table_index] >= 0)
            != (rhs_component.component_index_in_place_udk_vec_per_table[table_index] >= 0)) // they are in different tables
        {
            return false;
        }
    }
    return component.is_intersecting(rhs_component.component);
}

bool
runtime_flexibility_library::udk_component_internal::may_share_channel(
    const runtime_flexibility_library::udk_component_internal& rhs_component) const
{ // this method assumes no intersection between the components
    if (rhs_component.component.m_udk_type != component.m_udk_type) {
        return false;
    }
    if (component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PACKET) {
        if (component.m_data.udf_from_packet_instance.protocol_layer
                != rhs_component.component.m_data.udf_from_packet_instance.protocol_layer
            || component.m_data.udf_from_packet_instance.header != rhs_component.component.m_data.udf_from_packet_instance.header
            || component.m_data.udf_from_packet_instance.is_relative
                   != rhs_component.component.m_data.udf_from_packet_instance.is_relative) {
            return false;
        }
    }
    uint16_t lhs_offset_to_lsb_with_penalty = component.offset_in_bits + get_width_with_lsb_penalty();
    uint16_t rhs_offset_to_lsb_with_penalty = rhs_component.component.offset_in_bits + rhs_component.get_width_with_lsb_penalty();
    int current_diff = rhs_component.component.offset_in_bits - lhs_offset_to_lsb_with_penalty;
    if (-7 <= current_diff && current_diff <= 7) // other is right to us
    {
        return true;
    }
    current_diff = component.offset_in_bits - rhs_offset_to_lsb_with_penalty;
    if (-7 <= current_diff && current_diff <= 7) // other is left to us
    {
        return true;
    }
    return false;
}

void
default_print(std::string comment, size_t library_id)
{
    printf("%zu: %s\n", library_id, comment.c_str());
}

runtime_flexibility_library::runtime_flexibility_library(callback_print cback_print_func,
                                                         bool is_placing_for_nsim,
                                                         size_t library_id,
                                                         bool is_placing_for_hw)
    : m_callback_print(cback_print_func),
      m_is_placing_for_nsim(is_placing_for_nsim),
      m_is_placing_for_hw(is_placing_for_hw),
      m_library_id(library_id),
      m_verbose(false)
{
    if (cback_print_func == nullptr) {
        m_callback_print = &default_print;
    }
}

runtime_flexibility_library::runtime_flexibility_library()
{
    m_callback_print = &default_print;
}

void
runtime_flexibility_library::set_callback_print(callback_print cback_print_func)
{
    if (cback_print_func != nullptr) {
        m_callback_print = cback_print_func;
    }
}

bool
runtime_flexibility_library::place_range_compression_udk_component_in_table(size_t component_index,
                                                                            size_t table_index,
                                                                            uint8_t key_part_index)
{
    auto& current_component = m_udk_components[component_index];
    if (m_tables_key_parts[table_index][key_part_index].get_available_width()
        < current_component.component.get_width_on_key_in_bits()) {
        return false;
    }
    m_tables_key_parts[table_index][key_part_index].used_width += current_component.component.get_width_on_key_in_bits();
    m_tables_key_parts[table_index][key_part_index].range_compression_components.push_back(current_component);
    return true;
}

int
runtime_flexibility_library::calculate_width_to_place(const udk_component_internal& internal_component, size_t bucket_index)
{
    auto& bucket = m_udk_placement_buckets[bucket_index];
    int width_to_place = internal_component.get_width_with_lsb_penalty();
    if (!bucket.placed_fields.empty() && (internal_component.component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PD
                                          || internal_component.component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PACKET)) {
        bucket.placed_fields.push_back(internal_component);
        width_to_place = bucket.restructure_component_groups();
        bucket.placed_fields.pop_back();
        bucket.restructure_component_groups();
    }
    return width_to_place;
}

bool
runtime_flexibility_library::do_component_tables_match_bucket_tables(const udk_component_internal& internal_component,
                                                                     size_t bucket_index) const
{
    auto& bucket = m_udk_placement_buckets[bucket_index];
    if (bucket.placed_fields.size() > 0) {
        for (size_t i = 0; i < internal_component.component_index_in_place_udk_vec_per_table.size(); i++) {
            if ((internal_component.component_index_in_place_udk_vec_per_table[i] == -1) != (bucket.tables_in.count(i) == 0)
                && bucket.placed_fields.size() > 0) { // component in table XOR bucket in table
                if (m_verbose) {
                    m_callback_print("unable to place component " + std::to_string(internal_component.index) + " in bucket index "
                                         + std::to_string(bucket_index)
                                         + " - bucket containes components with different color",
                                     m_library_id);
                }
                return false;
            }
        }
    }
    return true;
}

bool
runtime_flexibility_library::place_udk_component_in_bucket(size_t bucket_index, const udk_component_internal& internal_component)
{
    udk_placement_bucket& bucket = m_udk_placement_buckets[bucket_index];
    if (bucket.bucket_type != UDK_PLACEMENT_BUCKET_TYPE_PACKET_AND_PD
        && internal_component.component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PD) {
        return false;
    }
    if (bucket.bucket_type != UDK_PLACEMENT_BUCKET_TYPE_CALCULATED_ONLY
        && internal_component.component.m_udk_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD) {
        return false;
    }
    if (!bucket.placed_fields.empty()
        && bucket.placed_fields.back().component.m_udk_type != internal_component.component.m_udk_type) {
        if (m_verbose) {
            m_callback_print("unable to place component " + std::to_string(internal_component.index) + " in bucket "
                                 + std::to_string(bucket_index)
                                 + "- currently not supporting more than one component type in a bucket",
                             m_library_id);
        }
        return false;
    }
    int width_to_place = calculate_width_to_place(internal_component, bucket_index);
    // checks
    if (bucket.bucket_type == UDK_PLACEMENT_BUCKET_TYPE_PACKET_AND_PD
        || bucket.bucket_type == UDK_PLACEMENT_BUCKET_TYPE_PACKET_ONLY) {
        if (!do_component_tables_match_bucket_tables(internal_component, bucket_index)) {
            return false;
        }
        if (possible_to_place_width_in_udk_bucket(width_to_place, bucket)) {
            bucket.placed_fields.push_back(internal_component);
            int additional_width_used = bucket.restructure_component_groups();
            if (width_to_place != additional_width_used) {
                if (m_verbose) {
                    m_callback_print("width calculated " + std::to_string(width_to_place) + " is different than accual width added "
                                         + std::to_string(additional_width_used)
                                         + " in component index "
                                         + std::to_string(internal_component.index)
                                         + " in bucket index "
                                         + std::to_string(bucket_index),
                                     m_library_id);
                }
                return false;
            }
            for (auto& table_bucket_is_placed_in : bucket.tables_in) { // bucket already assigned to tables
                m_tables_key_parts[table_bucket_is_placed_in.first /*table index*/]
                                  [table_bucket_is_placed_in.second /*key part index*/]
                                      .used_width
                    += additional_width_used;
            }
            return true;
        } else {
            if (m_verbose) {
                m_callback_print("Unable to place component " + std::to_string(internal_component.index) + " with width "
                                     + std::to_string(width_to_place)
                                     + " in bucket "
                                     + std::to_string(bucket.bucket_index),
                                 m_library_id);
            }
            return false;
        }
    } else if (bucket.bucket_type == UDK_PLACEMENT_BUCKET_TYPE_CALCULATED_ONLY && bucket.placed_fields.size() == 0
               && internal_component.component.m_udk_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD) {
        bucket.placed_fields.push_back(internal_component);
        bucket.available_width -= width_to_place;
        bucket.used_width += width_to_place;
        return true;
    }
    if (m_verbose
        && !(internal_component.component.m_udk_type != UDK_COMPONENT_TYPE_CALCULATED_FIELD
             && bucket.bucket_type == UDK_PLACEMENT_BUCKET_TYPE_CALCULATED_ONLY)) {
        m_callback_print("Unable to place component index " + std::to_string(internal_component.index) + " type "
                             + std::to_string(internal_component.component.m_udk_type)
                             + " width "
                             + std::to_string(internal_component.component.get_width_in_bits())
                             + " to bucket type "
                             + std::to_string(bucket.bucket_type)
                             + " of field select index "
                             + std::to_string(bucket.field_select.fs_index),
                         m_library_id);
    }
    return false;
}

int
runtime_flexibility_library::revert_last_udk_placement_in_bucket(size_t bucket_index)
{
    udk_placement_bucket& bucket = m_udk_placement_buckets[bucket_index];
    if (bucket.placed_fields.size() == 0 || bucket.used_width == 0) {
        if (m_verbose) {
            m_callback_print("trying to revert placement in bucket index " + std::to_string(bucket_index)
                                 + " which is empty. error!",
                             m_library_id);
        }
        return 0;
    }
    bucket.placed_fields.pop_back();
    return bucket.restructure_component_groups();
}

bool
runtime_flexibility_library::revert_last_udk_placement(size_t bucket_index)
{
    int width_change_due_to_revert = revert_last_udk_placement_in_bucket(bucket_index);
    udk_placement_bucket& bucket = m_udk_placement_buckets[bucket_index];
    for (auto bucket_table : bucket.tables_in) {
        m_tables_key_parts[bucket_table.first][bucket_table.second].used_width += width_change_due_to_revert;
        if (bucket.placed_fields.size() == 0) // remove bucket from table
        {
            m_tables_key_parts[bucket_table.first][bucket_table.second].udk_placement_buckets_indices.pop_back();
            m_tables_key_parts[bucket_table.first][bucket_table.second].number_of_buckets_supporting_udf--;
        }
    }
    if (bucket.placed_fields.size() == 0) { // remove tables from bucket
        bucket.tables_in.clear();
    }
    return true;
}

place_udk_res
runtime_flexibility_library::place_udk(
    const udk_resources& resources /*generated input*/,
    const std::vector<udk_table_id_and_components>& udk_table_id_and_components /*runtime input*/,
    std::vector<microcode_write>& placement_output /*output*/,
    std::vector<udk_translation_info>& trans_info /*output*/)
{
    if (udk_table_id_and_components.size() > UDK_MAX_TABLES_PER_PLACEMENT) {
        // init: clearing placement_output & trans_info
        clean_place_udk_outputs(placement_output, trans_info);
    }

    if (m_verbose) {
        // dumps udk table components inputs
        dump_udk_table_components(udk_table_id_and_components);
    }

    if (!verify_udk_table_components_are_legal(udk_table_id_and_components, resources)) {
        // verify udk table components inputs types is defined
        return PLACE_UDK_RES_EWRONG_ARGS;
    }

    if (udk_table_id_and_components.size() > UDK_MAX_TABLES_PER_PLACEMENT) {
        if (m_verbose) {
            m_callback_print("place_udk command limit constrains: \n"
                             "Tables per placement:"
                                 + std::to_string(udk_table_id_and_components.size())
                                 + ", max tables per placement:"
                                 + std::to_string(UDK_MAX_TABLES_PER_PLACEMENT),
                             m_library_id);
        }
        return PLACE_UDK_RES_EWRONG_ARGS;
    }
    for (auto& udk_components_per_table : udk_table_id_and_components) {
        if (udk_components_per_table.udk_components.size() > MAX_NUMBER_OF_UDK_COMPONENTS) {
            if (m_verbose) {
                m_callback_print("place_udk command limit constrains: \n"
                                 "Table id:"
                                     + std::to_string(udk_components_per_table.udk_table_id)
                                     + ", num of udk components "
                                     + std::to_string(udk_components_per_table.udk_components.size())
                                     + ", limit of udk components per table: "
                                     + std::to_string(MAX_NUMBER_OF_UDK_COMPONENTS),
                                 m_library_id);
            }
            return PLACE_UDK_RES_EWRONG_ARGS;
        }
    }
    place_udk_res result = PLACE_UDK_RES_OK;

    if (m_is_placing_for_hw) {
        result = hw_place_udk(resources, udk_table_id_and_components, placement_output, trans_info);
        if (m_verbose) {
            std::string result_str = (result == PLACE_UDK_RES_OK) ? "hw place udk passed!" : "hw place udk failed!";
            result_str += (m_is_placing_for_nsim && (result == PLACE_UDK_RES_OK)) ? ", continue to place udk with nsim" : "";
            m_callback_print(result_str, m_library_id);
        }
        if (m_verbose && check_log_level(3)) {
            m_callback_print("generating hw place_udk translation info:", m_library_id);
            for (auto& trans_info_itr : trans_info) {
                std::string key_info = trans_info_itr.get_key_info("key_check");
                m_callback_print(key_info, m_library_id);
            }
        }
    }

    if (m_is_placing_for_nsim && (result == PLACE_UDK_RES_OK)) {
        result = nsim_place_udk(resources, udk_table_id_and_components, placement_output, trans_info);
    }

    m_udk_tables_components.clear();           // to prevent mem leaks
    m_processed_udk_tables_components.clear(); // to prevent mem leaks

    return result;
}

void
runtime_flexibility_library::dump_udk_table_components(const std::vector<udk_table_id_and_components>& udk_table_id_and_components)
{
    m_callback_print("Place_udk input components:"
                     "\nNum of udk tables requested: "
                         + std::to_string(udk_table_id_and_components.size()),
                     m_library_id);

    for (auto& table : udk_table_id_and_components) {
        m_callback_print("\nTable id:" + std::to_string(table.udk_table_id), m_library_id);

        uint8_t component_index = 0;
        for (auto& udk_component : table.udk_components) {
            m_callback_print("Component " + std::to_string(component_index + 1) + "/" + std::to_string(table.udk_components.size())
                                 + " "
                                 + udk_component.generate_udk_component_to_string(),
                             m_library_id);

            component_index++;
        }
    }
}

bool
runtime_flexibility_library::verify_udk_table_components_are_legal(
    const std::vector<udk_table_id_and_components>& udk_table_id_and_components,
    const udk_resources& resources)
{
    if (m_verbose == true && check_log_level(1)) {
        m_callback_print("verify udk input components:", m_library_id);
    }

    std::string verify_error_message = "";
    for (size_t table_index = 0; table_index < udk_table_id_and_components.size(); table_index++) {
        auto& table = udk_table_id_and_components[table_index];
        for (size_t component_index = 0; component_index < table.udk_components.size(); component_index++) {
            auto& udk_component = table.udk_components[component_index];
            std::string component_msg_prefix = "\nTable id:" + std::to_string(table.udk_table_id) + " Component "
                                               + std::to_string(component_index + 1) + "/"
                                               + std::to_string(table.udk_components.size());
            // unknown type
            if (udk_component.m_udk_type != UDK_COMPONENT_TYPE_UDF_FROM_PACKET
                && udk_component.m_udk_type != UDK_COMPONENT_TYPE_UDF_FROM_PD
                && udk_component.m_udk_type != UDK_COMPONENT_TYPE_CALCULATED_FIELD
                && udk_component.m_udk_type != UDK_COMPONENT_TYPE_RANGE_COMPRESSION_RESULT) {
                verify_error_message
                    += component_msg_prefix + " component type:" + std::to_string(udk_component.m_udk_type) + " is unknown!";
                continue;
            }
            // verify calculated field id is known
            if (udk_component.m_udk_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD) {
                if (resources.tables_properties.at(table.udk_table_id)
                        .table_calculated_fields.count(udk_component.m_data.m_calculated_field_instance.field_id)
                    == 0) {
                    verify_error_message += component_msg_prefix + " component calculated field id :"
                                            + std::to_string(udk_component.m_data.m_calculated_field_instance.field_id)
                                            + " wasn't found";
                }
                continue;
            }
            if (udk_component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PD
                || udk_component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PACKET) {
                std::string udf_from_pd_packet_error = "";
                if (udk_component.get_width_in_bits() == 0) {
                    udf_from_pd_packet_error += ", illegal width:" + std::to_string(udk_component.get_width_in_bits());
                }
                if (udk_component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PACKET) {
                    if ((udk_component.m_data.udf_from_packet_instance.header < -1)
                        || (udk_component.m_data.udf_from_packet_instance.header > 6)) {
                        udf_from_pd_packet_error
                            += ", illegal header:" + std::to_string(udk_component.m_data.udf_from_packet_instance.header);
                    }
                    if (udk_component.m_data.udf_from_packet_instance.protocol_layer != INT8_MAX
                        && ((udk_component.m_data.udf_from_packet_instance.protocol_layer < -1)
                            || (udk_component.m_data.udf_from_packet_instance.protocol_layer > 2))) {
                        udf_from_pd_packet_error += ", illegal protocol_layer:"
                                                    + std::to_string(udk_component.m_data.udf_from_packet_instance.protocol_layer);
                    }
                }
                if (!udf_from_pd_packet_error.empty()) {
                    verify_error_message += component_msg_prefix + udf_from_pd_packet_error;
                }
                continue;
            }
        }
    }
    if (!verify_error_message.empty()) {
        m_callback_print("illegal udk input components! " + verify_error_message, m_library_id);
        return false;
    }
    return true;
}

void
runtime_flexibility_library::clean_place_udk_outputs(std::vector<microcode_write>& placement_output /*output*/,
                                                     std::vector<udk_translation_info>& trans_info /*output*/)
{
    placement_output.clear();
    for (auto& line : trans_info) {
        line.clean();
    }
}

void
runtime_flexibility_library::merge_intersecting_udk_components_in_a_single_key(size_t table_index,
                                                                               size_t processed_component_index,
                                                                               size_t original_component_index)
{
    auto& component_to_merge_to = m_processed_udk_tables_components[table_index].udk_components[processed_component_index];
    auto& component_to_merge = m_udk_tables_components[table_index].udk_components[original_component_index];
    // calculating lsbs
    uint16_t original_lsb = component_to_merge_to.offset_in_bits + component_to_merge_to.m_width_in_bits;
    uint16_t optional_new_lsb = component_to_merge.offset_in_bits + component_to_merge.m_width_in_bits;
    // updating offset
    if (component_to_merge.offset_in_bits < component_to_merge_to.offset_in_bits) {
        component_to_merge_to.offset_in_bits = component_to_merge.offset_in_bits;
    }
    uint16_t updated_lsb = original_lsb > optional_new_lsb ? original_lsb : optional_new_lsb;
    component_to_merge_to.m_width_in_bits = updated_lsb - component_to_merge_to.offset_in_bits;
    uint16_t lsb_offset_diff = updated_lsb - original_lsb;
    // calculating offset pointer for map
    uint16_t lsb_offset_diff_in_component_to_merge = updated_lsb - optional_new_lsb;
    // updating data structures
    if (lsb_offset_diff) {
        for (auto& component_index_to_update :
             m_processed_component_index_to_original_indices_and_offset[table_index][processed_component_index]) {
            component_index_to_update.offset_to_add += lsb_offset_diff;
        }
    }
    m_processed_component_index_to_original_indices_and_offset[table_index][processed_component_index].emplace_back(
        original_component_index, lsb_offset_diff_in_component_to_merge, component_to_merge.m_width_in_bits);
}

void
runtime_flexibility_library::merge_intersecting_udk_components_calculated_fields_in_a_single_key(size_t table_index,
                                                                                                 size_t processed_component_index,
                                                                                                 size_t original_component_index)
{
    auto& component_to_merge = m_udk_tables_components[table_index].udk_components[original_component_index];
    m_processed_component_index_to_original_indices_and_offset[table_index][processed_component_index].emplace_back(
        original_component_index, 0, component_to_merge.m_width_in_bits);
}

place_udk_res
runtime_flexibility_library::place_udk_init_vars(const udk_resources& resources,
                                                 const std::vector<udk_table_id_and_components>& udk_tables_components)
{
    m_udk_tables_components = udk_tables_components;
    m_processed_udk_tables_components = udk_tables_components;
    m_udk_placement_buckets.clear();
    m_processed_component_index_to_original_indices_and_offset
        = std::vector<std::vector<std::vector<udk_component_pointer>>>(udk_tables_components.size());
    std::vector<field_select_info> field_selects = resources.field_selects;
    std::sort(field_selects.begin(), field_selects.end(), field_select_less());
    size_t sum_of_all_fss_for_udf = 0;
    for (auto& field_select : field_selects) {
        bool bucket_supports_pd = false;
        if (field_select.first_channel + ((field_select.fs_allocated_width + 8) / CHANNEL_WIDTH)
                <= resources.first_lsb_channel_with_no_pd_support
            || field_select.first_channel >= resources.first_bypass_channel_with_pd_support) {
            bucket_supports_pd = true;
        }
        m_udk_placement_buckets.emplace_back(field_select.fs_allocated_width,
                                             field_select,
                                             bucket_supports_pd ? UDK_PLACEMENT_BUCKET_TYPE_PACKET_AND_PD
                                                                : UDK_PLACEMENT_BUCKET_TYPE_PACKET_ONLY,
                                             m_udk_placement_buckets.size());
        sum_of_all_fss_for_udf += field_select.fs_allocated_width;
        if (m_verbose) {
            m_callback_print("Using fs id " + std::to_string(field_select.fs_index) + ", allocated width:"
                                 + std::to_string(field_select.fs_allocated_width),
                             m_library_id);
        }
    }
    for (size_t table_index = 0; table_index < m_udk_tables_components.size(); table_index++) {
        auto& table_components = m_udk_tables_components[table_index];
        m_processed_udk_tables_components[table_index].udk_components.clear();
        for (size_t component_index = 0; component_index < m_udk_tables_components[table_index].udk_components.size();
             component_index++) {
            auto& current_table_component = table_components.udk_components[component_index];
            bool is_merged = false;
            for (size_t other_comp_index = 0;
                 other_comp_index < m_processed_udk_tables_components[table_index].udk_components.size();
                 other_comp_index++) {
                if (current_table_component.is_intersecting(
                        m_processed_udk_tables_components[table_index].udk_components[other_comp_index])) {
                    if (current_table_component.m_udk_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD) {
                        m_callback_print("Table id " + std::to_string(table_components.udk_table_id) + +" component desc: "
                                             + std::string(current_table_component.m_description)
                                             + " calculated field merge",
                                         m_library_id);
                        merge_intersecting_udk_components_calculated_fields_in_a_single_key(
                            table_index, other_comp_index, component_index);
                        is_merged = true;
                        break;
                    }

                    merge_intersecting_udk_components_in_a_single_key(table_index, other_comp_index, component_index);
                    is_merged = true;
                    break;
                }
            }
            if (!is_merged) {
                m_processed_udk_tables_components[table_index].udk_components.emplace_back(current_table_component);
                m_processed_component_index_to_original_indices_and_offset[table_index].emplace_back();
                m_processed_component_index_to_original_indices_and_offset[table_index].back().emplace_back(
                    component_index, 0, current_table_component.m_width_in_bits);
            }
        }
    }

    std::set<udk_component_internal, udk_component_merge_less> merged_components;
    for (size_t table_index = 0; table_index < m_processed_udk_tables_components.size(); table_index++) {
        auto& table_components = m_processed_udk_tables_components[table_index];
        if (resources.tables_properties.count(table_components.udk_table_id) == 0) {
            if (m_verbose) {
                m_callback_print("Table id " + std::to_string(table_components.udk_table_id) + " not found in resources",
                                 m_library_id);
            }
            return PLACE_UDK_RES_EWRONG_ARGS;
        }
        auto& table_properties = resources.tables_properties.at(table_components.udk_table_id);
        for (size_t component_index = 0; component_index < table_components.udk_components.size(); component_index++) {
            auto& current_table_component = table_components.udk_components[component_index];
            udk_component_internal current_component(current_table_component, component_index);
            if (current_table_component.m_udk_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD) {
                calculated_field_id_t field_id = current_table_component.m_data.m_calculated_field_instance.field_id;
                if (table_properties.table_calculated_fields.count(field_id) == 0) {
                    if (m_verbose) {
                        m_callback_print("field id " + std::to_string(field_id) + " not found in table "
                                             + std::to_string(table_components.udk_table_id),
                                         m_library_id);
                    }
                    return PLACE_UDK_RES_EWRONG_ARGS;
                }
                current_component.component.m_width_in_bits = table_properties.table_calculated_fields.at(field_id).field_width;
                current_component.component.m_data.m_calculated_field_instance.key_part_index
                    = table_properties.table_calculated_fields.at(field_id).key_part_index;
            }
            current_component.component_index_in_place_udk_vec_per_table
                = std::vector<int>(m_processed_udk_tables_components.size(), -1);
            current_component.component_index_in_place_udk_vec_per_table[table_index] = static_cast<int>(component_index);
            current_component.number_of_tables_used_in++;
            if (merged_components.count(current_component) == 0) {
                merged_components.insert(current_component);
            } else {
                auto component_in_set = merged_components.find(current_component);
                component_in_set->component_index_in_place_udk_vec_per_table[table_index] = static_cast<int>(component_index);
                component_in_set->number_of_tables_used_in++;
            }
        }
    }

    m_udk_components.clear();
    // now we can take all components from merged_components and move them to another container std::vector<internal_components>
    m_udk_components.assign(merged_components.begin(), merged_components.end());
    // need to also sort this container by number of tables each component is being used in
    std::sort(m_udk_components.begin(),
              m_udk_components.end(),
              udk_component_less()); // move calculated fields to front, big elements also
    udk_component_internal current_component = m_udk_components.back();
    for (auto comp : m_udk_components) {
        if (current_component.index != comp.index) {
            if (current_component.is_intersecting(comp)) { // calling the wrapper method - will return false if tables don't match
                if (m_verbose) {
                    m_callback_print("component with index " + std::to_string(current_component.index)
                                         + " overlaps component with index "
                                         + std::to_string(comp.index),
                                     m_library_id);
                }
                return PLACE_UDK_RES_EWRONG_ARGS;
            }
        }
        std::string tmp = "";
        for (auto ind : comp.component_index_in_place_udk_vec_per_table) {
            tmp += std::to_string(ind) + " ";
        }
        if (m_verbose) {
            m_callback_print("component type " + std::to_string(comp.component.m_udk_type)
                                 + " component_index_in_place_udk_vec_per_table: "
                                 + tmp,
                             m_library_id);
        }
        current_component = comp;
    }
    if (m_verbose) {
        m_callback_print("components to place: ", m_library_id);
        for (auto& comp : m_udk_components) {
            if (comp.index == (size_t)(-1)) {
                break;
            }
            std::string tables_str = "";
            for (auto idx : comp.component_index_in_place_udk_vec_per_table) {
                tables_str += std::to_string(idx) + " ";
            }

            m_callback_print("component indices: " + tables_str + "component size "
                                 + std::to_string(comp.component.get_width_in_bits()),
                             m_library_id);
        }
    }
    m_tables_key_parts.clear();
    for (size_t table_index = 0; table_index < m_processed_udk_tables_components.size(); table_index++) {
        uint16_t table_id = m_processed_udk_tables_components[table_index].udk_table_id;
        m_tables_key_parts.emplace_back();
        auto& table_properties = resources.tables_properties.at(table_id);
        uint8_t num_of_key_parts = (uint8_t)(table_properties.m_key_sizes_per_key_part.size());
        for (uint8_t i = 0; i < num_of_key_parts; i++) {
            m_tables_key_parts.back().emplace_back(table_properties.m_key_sizes_per_key_part[i],
                                                   table_properties.m_constant_bits_per_key_part[i],
                                                   table_properties.max_number_of_field_selects_for_each_key_part[i]);
        }
        size_t udf_components_width
            = 0;                    // making sure that udf_key_part of components does not excceed field select width available
        size_t total_key_width = 0; // also make sure that total key width will not excceed maximum key width allowed for hw
        for (auto& internal_component : m_processed_udk_tables_components[table_index].udk_components) {
            if (internal_component.m_udk_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD) {
                total_key_width
                    += table_properties.table_calculated_fields.at(internal_component.m_data.m_calculated_field_instance.field_id)
                           .field_width;
            } else {
                if (internal_component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PACKET
                    || internal_component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PD) {
                    udf_components_width
                        += internal_component
                               .get_width_on_key_in_bits(); // important not to add lsb penalty as fields can be merged
                }
                total_key_width += internal_component.get_width_on_key_in_bits();
            }
        }
        size_t max_key_width = 0;
        for (uint8_t i = 0; i < num_of_key_parts; i++) {
            max_key_width += m_tables_key_parts.back()[i].get_available_width();
        }
        if (max_key_width < total_key_width) {
            if (m_verbose) {
                m_callback_print("key width " + std::to_string(total_key_width) + " for table id " + std::to_string(table_id)
                                     + " is greater than max fields width "
                                     + std::to_string(max_key_width)
                                     + " available for place udk, failure!\n",
                                 m_library_id);
            }
            return PLACE_UDK_RES_ENO_PLACEMENT;
        }
        if (sum_of_all_fss_for_udf < udf_components_width) {
            if (m_verbose) {
                m_callback_print("udf components width " + std::to_string(udf_components_width)
                                     + " is greater than max udf fields width "
                                     + std::to_string(sum_of_all_fss_for_udf)
                                     + " available for place udk, failure!\n",
                                 m_library_id);
            }
            return PLACE_UDK_RES_ENO_PLACEMENT;
        }
    }
    return PLACE_UDK_RES_OK;
}

place_udk_res
runtime_flexibility_library::hw_place_udk(
    const udk_resources& resources /*generated input*/,
    const std::vector<udk_table_id_and_components>& udk_table_id_and_components /*runtime input*/,
    std::vector<microcode_write>& microcode_writes /*output*/,
    std::vector<udk_translation_info>& trans_info /*output*/)
{
    if (m_verbose) {
        m_callback_print("we have " + std::to_string(udk_table_id_and_components.size()) + " tables to place", m_library_id);
    }
    // init_vars
    if (m_verbose) {
        for (auto table_prop : resources.tables_properties) {
            m_callback_print("table id " + std::to_string(table_prop.first), m_library_id);
            for (size_t key_part_idx = 0; key_part_idx < table_prop.second.m_constant_bits_per_key_part.size(); key_part_idx++) {
                m_callback_print("key_part index " + std::to_string(key_part_idx) + " constant bits "
                                     + std::to_string(table_prop.second.m_constant_bits_per_key_part[key_part_idx])
                                     + " key part size: "
                                     + std::to_string(table_prop.second.m_key_sizes_per_key_part[key_part_idx]),
                                 m_library_id);
            }
        }
    }

    place_udk_res result = place_udk_init_vars(resources, udk_table_id_and_components);
    if (result != PLACE_UDK_RES_OK) {
        return result;
    }
    bool res = recursive_place_udk(0);
    if (!res) {
        if (m_verbose) {
            m_callback_print("unable to place udk, returning no placement result", m_library_id);
        }
        return PLACE_UDK_RES_ENO_PLACEMENT;
    }
    if (!generate_place_udk_outputs(resources, udk_table_id_and_components, microcode_writes, trans_info)) {
        return PLACE_UDK_RES_EWRONG_ARGS;
    }
    if (m_verbose) {
        m_callback_print("Place udk ok, placement: \n" + get_last_udk_placement_str(), m_library_id);
    }
    return PLACE_UDK_RES_OK;
}

bool
runtime_flexibility_library::generate_place_udk_outputs(const udk_resources& resources,
                                                        const std::vector<udk_table_id_and_components>& udk_table_id_and_components,
                                                        std::vector<microcode_write>& placement_output /*output*/,
                                                        std::vector<udk_translation_info>& trans_info /*output*/)
{
    sort_fields_in_udk_buckets_post_placement();
    bool result = true;
    if (!generate_udk_microcode_writes(resources, placement_output)) {
        m_callback_print("generate_mc_writes_failed", m_library_id);
        result = false;
    }
    result &= generate_udk_translation_info(resources, trans_info);
    return result;
}

bool
runtime_flexibility_library::generate_udk_microcode_writes(const udk_resources& resources,
                                                           std::vector<microcode_write>& placement_output)
{
    m_udk_data_str_outputs.clear();
    if (!generate_key_construction_lines_microcode_changes(resources, placement_output)) {
        return false;
    }
    if (!generate_field_selects_at_key_construction_level_microcode_changes(resources, placement_output)) {
        return false;
    }
    if (!generate_scoper_channels_microcode_changes(resources, placement_output)) {
        return false;
    }
    create_microcode_writes_as_string(placement_output);
    return true;
}

void
runtime_flexibility_library::create_microcode_writes_as_string(std::vector<microcode_write>& placement_output)
{
    for (auto& output_write : placement_output) {
        bit_vector bv(0, output_write.width);
        memcpy(bv.byte_array(), output_write.data, output_write.get_width_in_bytes());
        m_udk_data_str_outputs.push_back(bv.to_string());
    }
}
const std::vector<std::string>&
runtime_flexibility_library::get_udk_data_output_str()
{
    return m_udk_data_str_outputs;
}
bool
runtime_flexibility_library::generate_key_construction_lines_microcode_changes(const udk_resources& resources,
                                                                               std::vector<microcode_write>& placement_output)
{
    for (size_t table_index = 0; table_index < m_processed_udk_tables_components.size(); table_index++) {
        auto& udk_table = m_processed_udk_tables_components[table_index];
        if (resources.tables_properties.count(udk_table.udk_table_id) == 0) {
            m_callback_print("unable to create key_construction_lines, table id " + std::to_string(udk_table.udk_table_id)
                                 + " is not available in current udk resources",
                             m_library_id);
            return false;
        }
        if (m_tables_key_parts[table_index].size()
            > resources.tables_properties.at(udk_table.udk_table_id).m_key_sizes_per_key_part.size()) {
            m_callback_print("unable to create key_construction_lines, not enough key parts provided in resources", m_library_id);
            return false;
        }
        for (size_t key_part_idx = 0; key_part_idx < m_tables_key_parts[table_index].size(); key_part_idx++) {
            auto& uc_ptr
                = resources.tables_properties.at(udk_table.udk_table_id).lookup_keys_construction_table_pointers.at(key_part_idx);
            microcode_write uc_write(uc_ptr.block_name, uc_ptr.table_name);
            uc_write.array_index = uc_ptr.array_index;
            size_t num_of_field_selects = resources.tables_properties.at(udk_table.udk_table_id)
                                              .max_number_of_field_selects_for_each_key_part[key_part_idx];
            bit_vector bv(0, num_of_field_selects * resources.field_select_index_width_in_bits);
            for (auto& line : uc_ptr.table_lines) {
                uc_write.line = (size_t)(line.line_num); // having different lines for two key_parts
                size_t fs_idx = 0;

                for (auto bucket_index : m_tables_key_parts[table_index][key_part_idx].udk_placement_buckets_indices) {
                    auto& bucket = m_udk_placement_buckets[bucket_index];
                    if (bucket.placed_fields.size() > 0) {
                        size_t fs_index = bucket.field_select.fs_index;
                        if (bucket.placed_fields[0].component.m_udk_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD) {
                            auto fs_index_itr = line.calculated_field_id_to_fs_index.find(
                                bucket.placed_fields[0].component.m_data.m_calculated_field_instance.field_id);
                            auto fs_index_perrow_itr = line.calculated_field_id_to_fs_index_per_row.find(
                                bucket.placed_fields[0].component.m_data.m_calculated_field_instance.field_id);
                            if (fs_index_itr == line.calculated_field_id_to_fs_index.end()
                                && fs_index_perrow_itr == line.calculated_field_id_to_fs_index_per_row.end()) {

                                m_callback_print(
                                    "unable to find calculated_field_id_to_fs_index, field id: "
                                        + std::to_string(
                                              bucket.placed_fields[0].component.m_data.m_calculated_field_instance.field_id),
                                    m_library_id);

                                if (m_verbose) {
                                    std::string map_debug_print = "calculated_field_id_to_fs_index Map";
                                    for (auto& itr : line.calculated_field_id_to_fs_index) {
                                        map_debug_print += "\n field id:" + std::to_string(itr.first)
                                                           + ",fs index: " + std::to_string(itr.second);
                                    }
                                    m_callback_print("debug details: \n component:"
                                                         + bucket.placed_fields[0].component.generate_udk_component_to_string()
                                                         + ",\n"
                                                         + map_debug_print,
                                                     m_library_id);
                                }
                                return false;
                            }
                            if (fs_index_itr != line.calculated_field_id_to_fs_index.end()) {
                                fs_index = (size_t)line.calculated_field_id_to_fs_index.at(
                                    bucket.placed_fields[0].component.m_data.m_calculated_field_instance.field_id);
                            } else { // fs_index_perrow_itr
                                fs_index = (size_t)line.calculated_field_id_to_fs_index_per_row.at(
                                    bucket.placed_fields[0].component.m_data.m_calculated_field_instance.field_id);
                            }
                        }
                        bv.set_bits((fs_idx + 1) * resources.field_select_index_width_in_bits - 1,
                                    fs_idx * resources.field_select_index_width_in_bits,
                                    fs_index);
                        fs_idx++;
                    }
                }
                for (; fs_idx < resources.tables_properties.at(udk_table.udk_table_id)
                                    .max_number_of_field_selects_for_each_key_part[key_part_idx];
                     fs_idx++) {
                    bv.set_bits((fs_idx + 1) * resources.field_select_index_width_in_bits - 1,
                                fs_idx * resources.field_select_index_width_in_bits,
                                resources.field_select_not_used_value);
                }
                uc_write.offset = resources.offset_of_field_selects_in_key_construction_microcode_line;
                uc_write.width = num_of_field_selects * resources.field_select_index_width_in_bits;
                memcpy(uc_write.data, bv.byte_array(), uc_write.get_width_in_bytes());

                placement_output.push_back(uc_write);
            }
        }
    }
    return true;
}
bool
runtime_flexibility_library::generate_field_selects_at_key_construction_level_microcode_changes(
    const udk_resources& resources,
    std::vector<microcode_write>& placement_output)
{
    microcode_write uc_write(resources.lookup_keys_construction_macro_table_pointer.block_name,
                             resources.lookup_keys_construction_macro_table_pointer.table_name);
    for (auto& table_key_parts : m_tables_key_parts) {
        for (auto& key_part : table_key_parts) {
            for (auto bucket_index : key_part.udk_placement_buckets_indices) {
                auto bucket = m_udk_placement_buckets[bucket_index];
                if (bucket.used_width > 0 && !(bucket.placed_fields.empty())
                    && (bucket.placed_fields[0].component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PACKET
                        || bucket.placed_fields[0].component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PD)) {
                    // we need to make uc change only for UDF
                    uc_write.width = bucket.field_select.num_of_bits_in_ucode;
                    uc_write.offset = bucket.field_select.offset_in_ucode;
                    bit_vector bv(bucket.used_width - 1, bucket.field_select.num_of_bits_in_ucode);
                    memcpy(uc_write.data, bv.byte_array(), uc_write.get_width_in_bytes());
                    uc_write.line = resources.macro_id;
                    placement_output.push_back(uc_write);
                }
            }
        }
    }
    // no need to modify offset
    return true;
}
void
transform_component_to_channel_data(bit_vector& bv, const udk_component& field, const udk_resources& resources)
{
    if (field.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PACKET) {
        bv.set_bits_from_msb(0, 2, 0x1 /*signals field from packet-header*/);
        bv.set_bits(10,
                    8,
                    (uint64_t)(field.m_data.udf_from_packet_instance.header == -1
                                   ? 7
                                   : field.m_data.udf_from_packet_instance.header)); // transform -1 to 7 value
        size_t base_offset_info_layer = field.m_data.udf_from_packet_instance.is_relative ? 5 : 1;
        if (field.m_data.udf_from_packet_instance.protocol_layer == INT8_MAX) {
            base_offset_info_layer = 0;
        } else {
            base_offset_info_layer += field.m_data.udf_from_packet_instance.protocol_layer;
        }
        bv.set_bits(13, 11, base_offset_info_layer);
    } else if (field.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PD) {
        bv.set_bits_from_msb(0, 8, 0x0); // 2'd0 (offset), 6'd0 (n/a)
    }
    bv.set_bits(7,
                0,
                (field.offset_in_bits + field.get_width_in_bits()
                 + runtime_flexibility_library::udk_component_internal::get_lsb_penalty(field))
                        / 8
                    - CHANNEL_WIDTH / 8); // lsb_offset - channel_size
}
bool
runtime_flexibility_library::generate_scoper_channels_microcode_changes(const udk_resources& resources,
                                                                        std::vector<microcode_write>& placement_output)
{
    microcode_write uc_write(resources.scoper_macro_table_pointer.block_name, resources.scoper_macro_table_pointer.table_name);
    uc_write.line = resources.macro_id;
    uc_write.width = UCODE_WIDTH_PER_CHANNEL_IN_SCOPER_MACRO_TABLE;
    bit_vector bv(0, uc_write.width);
    for (auto& table_key_parts : m_tables_key_parts) {
        for (auto& key_part : table_key_parts) {
            for (auto bucket_index : key_part.udk_placement_buckets_indices) {
                uint64_t last_channel_offset_to_lsb = UINT64_MAX;
                auto& bucket = m_udk_placement_buckets[bucket_index];
                size_t current_channel = bucket.field_select.first_channel;
                for (size_t field_index = 0; field_index < bucket.placed_fields.size(); field_index++) {
                    auto& field = bucket.placed_fields[field_index];
                    if (field.component.m_udk_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD) { // no changes neede if calculated
                                                                                             // field, range compression result is
                                                                                             // not in bucket level
                        break;
                    }
                    transform_component_to_channel_data(bv, field.component, resources);
                    size_t placed_width = 0;
                    if (field_index > 0 && field.may_share_channel(bucket.placed_fields[field_index - 1])) {
                        uint16_t offset_to_lsb_in_bytes = (field.get_offset_to_lsb_with_penalty() / 8);
                        if (last_channel_offset_to_lsb == offset_to_lsb_in_bytes) // offsets match over a whole channel
                        {
                            placed_width += CHANNEL_WIDTH;
                        } else if (last_channel_offset_to_lsb - 1 == offset_to_lsb_in_bytes) // offsets match over one byte
                        {
                            placed_width += CHANNEL_WIDTH / 2;
                        }
                        uint16_t additionalOffsetValue = (uint16_t)(bv.bits(7, 0).get_value() - placed_width / 8);
                        int16_t additionalOffsetAsInt = additionalOffsetValue; // to check negativity
                        if (additionalOffsetAsInt < 0) {
                            // need to give wrap-around offset instead of offset < 0
                            additionalOffsetValue += 256; // need to add 2K bits
                            if (m_verbose) {
                                m_callback_print("original offset was negative (in bytes: " + std::to_string(additionalOffsetAsInt)
                                                     + ")",
                                                 m_library_id);
                            }
                        }

                        bv.set_bits(7, 0, additionalOffsetValue);
                    }
                    for (; placed_width < field.get_width_with_lsb_penalty(); placed_width += CHANNEL_WIDTH, current_channel++) {
                        memcpy(uc_write.data, bv.byte_array(), (CHANNEL_WIDTH / 8));
                        uc_write.offset = UCODE_WIDTH_PER_CHANNEL_IN_SCOPER_MACRO_TABLE * current_channel;
                        placement_output.push_back(uc_write);
                        uint16_t additionalOffsetValue = (uint16_t)(bv.bits(7, 0).get_value() - CHANNEL_WIDTH / 8);
                        int16_t additionalOffsetAsInt = additionalOffsetValue; // to check negativity
                        if (additionalOffsetAsInt < 0) {
                            // need to give wrap-around offset instead of offset < 0
                            additionalOffsetValue += 256; // need to add 2K bits
                            if (m_verbose) {
                                m_callback_print("original offset was negative (in bytes: " + std::to_string(additionalOffsetAsInt)
                                                     + ")",
                                                 m_library_id);
                            }
                        }
                        bv.set_bits(7, 0, additionalOffsetValue);
                    }
                    last_channel_offset_to_lsb = bv.bits(7, 0).get_value() + CHANNEL_WIDTH / 4;
                }
            }
        }
    }
    return true;
}

bool
runtime_flexibility_library::generate_udk_translation_info(const udk_resources& resources,
                                                           std::vector<udk_translation_info>& trans_info)
{

    if (trans_info.size() < m_udk_tables_components.size()) {
        if (m_verbose) {
            m_callback_print("translation info provided size " + std::to_string(trans_info.size())
                                 + " is smaller than number of tables to place "
                                 + std::to_string(m_udk_tables_components.size()),
                             m_library_id);
        }
        return false;
    }

    for (size_t table_idx = 0; table_idx < m_tables_key_parts.size(); table_idx++) {
        auto& table_key_parts = m_tables_key_parts[table_idx];
        size_t base_offset = 0;
        size_t offset_on_key = 0;
        uint16_t table_id = m_udk_tables_components[table_idx].udk_table_id;
        for (int key_part_idx = static_cast<int>(table_key_parts.size() - 1); key_part_idx >= 0;
             key_part_idx--) { // key parts are set from msb to lsb
            trans_info[table_idx].constant_bits_per_key_part.emplace_back(
                (uint16_t)offset_on_key,
                (uint16_t)resources.tables_properties.at(table_id).m_constant_bits_per_key_part[key_part_idx]);
            offset_on_key += resources.tables_properties.at(table_id).m_constant_bits_per_key_part[key_part_idx];
            for (auto bucket_index : table_key_parts[key_part_idx].udk_placement_buckets_indices) {
                auto& bucket = m_udk_placement_buckets[bucket_index];
                size_t current_sequence_width = 0;
                // size_t current_sequence_msb_offset_on_source = 0;
                for (size_t field_index = 0; field_index < bucket.placed_fields.size(); field_index++) {
                    auto& placed_field = bucket.placed_fields[field_index];
                    size_t component_width = placed_field.component.get_width_in_bits();
                    // TODO avamar - fix (lsb padding bits can be calculated as negative
                    // size_t lsb_padding_bits = placed_field.lsb_penalty; // adding the lsb padding bits between fields
                    // if (current_sequence_width != 0) {
                    // lsb_padding_bits = placed_field.component.offset_in_bits - current_sequence_msb_offset_on_source; TODO - fix
                    // this
                    //}
                    // offset_on_key += lsb_padding_bits;
                    // current_sequence_width += lsb_padding_bits;
                    for (size_t processed_index = 0;
                         processed_index < m_processed_component_index_to_original_indices_and_offset
                                               [table_idx][placed_field.component_index_in_place_udk_vec_per_table[table_idx]]
                                                   .size();
                         processed_index++) {
                        auto& original_component = m_processed_component_index_to_original_indices_and_offset
                            [table_idx][placed_field.component_index_in_place_udk_vec_per_table[table_idx]][processed_index];
                        auto& description
                            = m_udk_tables_components[table_idx].udk_components[original_component.original_index].m_description;
                        size_t width_to_use = original_component.width;
                        uint16_t component_fragment_offset = 0;
                        if (placed_field.component.m_udk_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD) {
                            width_to_use = component_width;
                        }
                        uint16_t component_fragment_lsb_offset
                            = (uint16_t)width_to_use - (component_fragment_offset + placed_field.component.get_width_in_bits());
                        if (placed_field.fragmented_component_child) {
                            component_fragment_offset = placed_field.component_fragment_offset;
                            component_fragment_lsb_offset
                                = (uint16_t)width_to_use - (component_fragment_offset + placed_field.component.get_width_in_bits());
                            width_to_use = placed_field.component.get_width_in_bits();
                        }

                        trans_info[table_idx].placement_info[original_component.original_index].add_placement_info(
                            (int16_t)(offset_on_key + original_component.offset_to_add),
                            width_to_use,
                            (uint16_t)processed_index,
                            (component_fragment_offset),
                            description);
                        if (m_verbose) {
                            m_callback_print("translation info DEBUG, original component:"
                                             ", original_index:"
                                                 + std::to_string(original_component.original_index)
                                                 + ", offset_to_add:"
                                                 + std::to_string(original_component.offset_to_add)
                                                 + ", width:"
                                                 + std::to_string(original_component.width),
                                             m_library_id);
                            m_callback_print(
                                "translation info DEBUG, placement_info_t:"
                                ", offset_on_key:"
                                    + std::to_string(offset_on_key)
                                    + ", width_to_use:"
                                    + std::to_string(width_to_use)
                                    + ", processed_index:"
                                    + std::to_string(processed_index)
                                    + ", component_fragment_offset(msb offset):"
                                    + std::to_string(component_fragment_offset)
                                    + ", component_fragment_offset(lsb offset):"
                                    + std::to_string(component_fragment_lsb_offset)
                                    + ", minimal_offset: "
                                    + std::to_string(
                                          trans_info[table_idx].placement_info[original_component.original_index].minimal_offset)
                                    + ", total_width: "
                                    + std::to_string(
                                          trans_info[table_idx].placement_info[original_component.original_index].total_width)
                                    + ", description:"
                                    + description,
                                m_library_id);
                        }
                    }
                    offset_on_key += component_width;
                    current_sequence_width += component_width;
                    // current_sequence_msb_offset_on_source = placed_field.component.offset_in_bits + component_width;
                    if (field_index < (bucket.placed_fields.size() - 1)
                        && !placed_field.may_share_channel(bucket.placed_fields[field_index + 1])) {
                        if (current_sequence_width % CHANNEL_WIDTH
                            > 0) { // if we got here it means the next field is starting a new sequence
                            offset_on_key += (CHANNEL_WIDTH - (current_sequence_width % CHANNEL_WIDTH))
                                             % CHANNEL_WIDTH; // adding complementing bits to channel width
                            if (m_verbose) {
                                m_callback_print("placed field index " + std::to_string(placed_field.index)
                                                     + " is not complementing channel width but not placed last in bucket (last "
                                                       "placed field index: "
                                                     + std::to_string(bucket.placed_fields.back().index)
                                                     + "), number of components in bucket "
                                                     + std::to_string(bucket.placed_fields.size())
                                                     + " adding penalty width",
                                                 m_library_id);
                            }
                        }
                        current_sequence_width = 0;
                    }
                }
            }
            if (offset_on_key % 4 > 0) { // if there are any range compression results - nibble align them
                offset_on_key += (4 - offset_on_key % 4);
            }
            for (auto& range_compression_component : table_key_parts[key_part_idx].range_compression_components) {
                size_t component_width = range_compression_component.component.get_width_in_bits();
                trans_info[table_idx].placement_info[range_compression_component.index].add_placement_info(
                    (int16_t)offset_on_key, component_width, SIZE_MAX, 0, range_compression_component.component.m_description);
                offset_on_key
                    += range_compression_component.component.get_width_on_key_in_bits(); // offset_on_key is nibble aligned
            }
            base_offset += resources.tables_properties.at(table_id).m_key_sizes_per_key_part[key_part_idx];
            // trans_info.physical_key_width = offset; TODO should have this value once SDK will replace table json
            trans_info[table_idx].physical_key_width
                += resources.tables_properties.at(table_id).m_key_sizes_per_key_part[key_part_idx]; // needed to be offset- current
            // bypass for SDK support until they
            // will remove physical table size
            // json
            offset_on_key = base_offset;
        }
        trans_info[table_idx].number_of_components
            = m_udk_tables_components[table_idx].udk_components.size(); // getting number of components per table
    }
    return true;
}

void
runtime_flexibility_library::sort_fields_in_udk_buckets_post_placement()
{
    for (auto& bucket_it : m_udk_placement_buckets) {
        if (!bucket_it.placed_fields.empty()
            && bucket_it.bucket_type != UDK_PLACEMENT_BUCKET_TYPE_CALCULATED_ONLY) { // putting group with highest msb penalty last
            std::sort(
                bucket_it.placed_component_groups.begin(), bucket_it.placed_component_groups.end(), udk_components_group_less());
            bucket_it.placed_fields.clear();
            for (auto& group : bucket_it.placed_component_groups) {
                bucket_it.placed_fields.insert(bucket_it.placed_fields.end(), group.components.rbegin(), group.components.rend());
            }
        }
    }
}

bool
do_all_bucket_tables_match_component(runtime_flexibility_library::udk_placement_bucket& bucket,
                                     runtime_flexibility_library::udk_component_internal& current_component)
{
    for (auto table_bucket : bucket.tables_in) {
        if (table_bucket.first >= current_component.component_index_in_place_udk_vec_per_table.size()
            || current_component.component_index_in_place_udk_vec_per_table[table_bucket.first] == -1) {
            return false;
        }
    }
    return true;
}

void get_subsets(std::vector<size_t>& input_set, size_t index, std::vector<std::vector<size_t>>& all_subsets);
void
get_subsets(std::vector<size_t>& input_set, size_t index, std::vector<std::vector<size_t>>& all_subsets)
{
    static std::vector<size_t> current_subset;
    if (index == input_set.size()) {
        all_subsets.push_back(current_subset);
        return;
    }
    current_subset.push_back(input_set[index]); // using first with element
    get_subsets(input_set, index + 1, all_subsets);
    current_subset.pop_back();
    get_subsets(input_set, index + 1, all_subsets); // then without element
}

// get_split_set: generates available pairs of subsets from one set of unique positive numbers, if numbers are not unique - result
// may include multiple copies of same pairs

std::vector<std::pair<std::vector<size_t>, std::vector<size_t>>> runtime_flexibility_library::udk_component_internal::
    get_split_set_of_tables() // TODO should we put this method inside udk_component_internal?
{
    std::vector<size_t> all_tables;
    for (size_t table_index = 0; table_index < component_index_in_place_udk_vec_per_table.size(); table_index++) {
        if (component_index_in_place_udk_vec_per_table[table_index] >= 0) {
            all_tables.push_back(table_index);
        }
    }
    std::vector<std::pair<std::vector<size_t>, std::vector<size_t>>> result;
    if (all_tables.size() > 1) // breaking condition
    {
        std::vector<std::vector<size_t>> all_subsets;
        get_subsets(all_tables, 0, all_subsets); // recursive method generates all subsets
        for (size_t sset_idx = 1; sset_idx < (all_subsets.size()) / 2;
             sset_idx++) { // no need for first pair as it containes original input set and empty one
            result.emplace_back(all_subsets[sset_idx], all_subsets[all_subsets.size() - sset_idx - 1]);
        }
    }
    return result;
}

void
runtime_flexibility_library::udk_component_internal::fragment_internal_component_split_list_init(
    std::vector<std::pair<uint16_t, uint16_t>>& split_combinations_vec)
{

    fragmented_component_parent_skip_placement = true;
    // creates the fragments combinations

    if (component.get_width_in_bits() > COMPONENT_FRAGMENT_MIN_WIDTH_IN_BITS) {
        // notice we need to go over half of the fragment combinations
        // the other half is equal but in different order
        uint16_t num_of_fragments = component.get_width_in_bits() / COMPONENT_FRAGMENT_MIN_WIDTH_IN_BITS;
        for (uint16_t counter = 1; counter <= num_of_fragments / 2; counter++) {
            uint16_t fragment_size = counter * COMPONENT_FRAGMENT_MIN_WIDTH_IN_BITS;
            uint16_t component_size = component.get_width_in_bits() - fragment_size;
            split_combinations_vec.insert(split_combinations_vec.begin(), std::make_pair(component_size, fragment_size));
        }
    }
}

void
runtime_flexibility_library::udk_component_internal::fragment_internal_component_vec_gen(
    size_t fragments_start_index,
    std::pair<uint16_t, uint16_t>& comb,
    std::vector<udk_component_internal>& fragments_vec)
{

    fragments_vec[0].fragmented_component_child = true;
    fragments_vec[0].fragmented_component_parent_skip_placement = false;
    fragments_vec[0].component_fragment_offset = component_fragment_offset;

    fragments_vec[1].fragmented_component_child = true;
    fragments_vec[1].fragmented_component_parent_skip_placement = false;
    fragments_vec[1].component_fragment_offset = component_fragment_offset + comb.first;

    fragments_vec[0].component.m_width_in_bits = comb.first;
    fragments_vec[1].component.offset_in_bits += comb.first;
    fragments_vec[1].component.m_width_in_bits = comb.second;

    // tocheck - fragmented components description cannot be changed (desc size is limited to save memory allocation)
    fragments_vec[0].index = fragments_start_index;
    fragments_vec[1].index = fragments_start_index + 1;
    fragments_vec[0].lsb_penalty = 0; // the 2nd fragment is taking the lsb part (and penalty)
}

bool
runtime_flexibility_library::recursive_place_udk(size_t component_index)
{
    if (m_udk_components.size() <= component_index) { // place_udk_done
        if (m_verbose) {
            m_callback_print("place udk done, " + std::to_string(component_index) + " components placed", m_library_id);
            if (m_verbose && check_log_level(1)) { // todo avamar - need to assign different log level
                m_callback_print(get_last_udk_placement_str(), m_library_id);
            }
        }
        return true;
    }
    udk_component_internal& current_component = m_udk_components[component_index];
    bool succeed_in_placement_skip_fragmentation = false;
    if (current_component.component.m_udk_type != UDK_COMPONENT_TYPE_UDF_FROM_PACKET
        && current_component.component.m_udk_type != UDK_COMPONENT_TYPE_UDF_FROM_PD) {
        uint8_t key_part_idx = current_component.component.m_udk_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD
                                   ? current_component.component.m_data.m_calculated_field_instance.key_part_index
                                   : 0; // for range compression result - we only use key part 0 currently
        size_t table_index;
        for (table_index = 0; table_index < current_component.component_index_in_place_udk_vec_per_table.size(); table_index++) {
            if (current_component.component_index_in_place_udk_vec_per_table[table_index] < 0) {
                continue;
            }
            if (table_index >= m_tables_key_parts.size() || key_part_idx >= m_tables_key_parts[table_index].size()) {
                if (m_verbose) {
                    m_callback_print("unable to place calculated field with wrong table/key_part index "
                                         + std::to_string(key_part_idx),
                                     m_library_id);
                }
                return false;
            }
            break;
        }
        if (table_index >= current_component.component_index_in_place_udk_vec_per_table.size()) {
            if (m_verbose) {
                m_callback_print("Unable to place non-udf component in table, no table index is defined for component",
                                 m_library_id);
                return false;
            }
        }
        if (current_component.component.m_udk_type == UDK_COMPONENT_TYPE_RANGE_COMPRESSION_RESULT) {
            if (place_range_compression_udk_component_in_table(component_index, table_index, key_part_idx) == true) {
                // not used for range compression for now
                succeed_in_placement_skip_fragmentation = true;
                if (recursive_place_udk(component_index + 1) == true) {
                    return true;
                }
                // recursive place udk failed - revert last placement
                m_tables_key_parts[table_index][key_part_idx].range_compression_components.pop_back();
                m_tables_key_parts[table_index][key_part_idx].used_width
                    -= current_component.component.get_width_on_key_in_bits(); // revert last placement
            }
            return false;
        }
        // Handling calculated field
        m_udk_placement_buckets.emplace_back(
            128, field_select_info(), UDK_PLACEMENT_BUCKET_TYPE_CALCULATED_ONLY, m_udk_placement_buckets.size());
        // calculated fields to be placed at reverse order - first available bucket
        if (recursive_place_udk_component_and_bucket(
                m_udk_placement_buckets.size() - 1, component_index, succeed_in_placement_skip_fragmentation)
            == false) { // placement failed
            m_udk_placement_buckets.pop_back();
            return false;
        }
        return true;
    }
    // Handling UDF
    for (size_t bucket_index = 0; bucket_index < m_udk_placement_buckets.size(); bucket_index++) {
        if (!do_all_bucket_tables_match_component(m_udk_placement_buckets.at(bucket_index), m_udk_components[component_index])) {
            continue;
        }
        if (recursive_place_udk_component_and_bucket(bucket_index, component_index, succeed_in_placement_skip_fragmentation)
            == true) { // placement OK
            return true;
        }
    }
    if (m_verbose) { // if we got here it means no suitable bucket or failed using all the suitable buckets
        m_callback_print("printing current placement, next fragmentation & splitting components using multiples tables ",
                         m_library_id);
        if ((m_verbose) && check_log_level(1)) { // todo avamar -> for now, to decrease the massive log size
            m_callback_print(get_last_udk_placement_str(), m_library_id);
        }
    }

    if (m_udk_components.at(component_index).number_of_tables_used_in > 1) {
        if (m_verbose && check_log_level(2)) { // split all current color components
                                               // todo avamar - need to assign different log level
            m_callback_print("splitting component index " + std::to_string(m_udk_components[component_index].index), m_library_id);
        }
        // TODO current solution has double branches - need to avoid rechecking already done branches
        udk_component_internal tmp_copy_of_current_component = m_udk_components[component_index];
        auto tables_sets = m_udk_components[component_index].get_split_set_of_tables();
        for (auto& split_option : tables_sets) {
            udk_component_internal current_component_copy_to_split = m_udk_components[component_index];
            for (auto table_index : split_option.first) {
                current_component_copy_to_split.component_index_in_place_udk_vec_per_table[table_index] = -1;
                if (m_verbose && check_log_level(2)) { // todo avamar - need to assign different log level
                    m_callback_print("First component will remain in table index " + std::to_string(table_index), m_library_id);
                }
            }
            for (auto table_index : split_option.second) {
                m_udk_components[component_index].component_index_in_place_udk_vec_per_table[table_index] = -1;
                if (m_verbose && check_log_level(2)) { // todo avamar - need to assign different log level
                    m_callback_print("Second component will remain in table index " + std::to_string(table_index), m_library_id);
                }
            }
            current_component_copy_to_split.number_of_tables_used_in = (uint8_t)split_option.second.size();
            m_udk_components[component_index].number_of_tables_used_in = (uint8_t)split_option.first.size();
            m_udk_components.push_back(current_component_copy_to_split); // TODO do we need to remove double branches
            if (recursive_place_udk(component_index) == true) {
                return true;
            }
            // reverting last split
            m_udk_components[component_index] = tmp_copy_of_current_component;
            m_udk_components.pop_back();
        }
    }

    // adding split component mechanism
    if ((m_components_fragmentization_enable == true) && (succeed_in_placement_skip_fragmentation == false)
        && (m_udk_components[component_index].fragmented_component_parent_skip_placement == false)
        && ((m_udk_components[component_index].component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PD)
            || (m_udk_components[component_index].component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PACKET))
        // check if component can fit in the remaining unallocated fs
        && (possible_to_place_width_in_remaining_udk_buckets(m_udk_components[component_index]))) {
        if ((m_verbose) && check_log_level(1)) { // todo avamar - need to assign different log level
            m_callback_print("udk component splitting into parts - init", m_library_id);
        }

        std::vector<std::pair<uint16_t, uint16_t>> split_combinations_vec;
        std::vector<udk_component_internal> udk_new_internal_component_vec(2, m_udk_components[component_index]);
        m_udk_components[component_index].fragment_internal_component_split_list_init(split_combinations_vec);

        for (size_t split_comb_index = 0; split_comb_index < split_combinations_vec.size(); split_comb_index++) {

            m_udk_components[component_index].fragment_internal_component_vec_gen(
                m_udk_components.size(), split_combinations_vec[split_comb_index], udk_new_internal_component_vec);
            if (m_verbose && check_log_level(2)) { // todo avamar - need to assign different log level
                m_callback_print("udk component split succeed,"
                                 "current component index:"
                                     + std::to_string(m_udk_components[component_index].index)
                                     + ",current component width:"
                                     + std::to_string(m_udk_components[component_index].component.m_width_in_bits)
                                     + ",current component offset:"
                                     + std::to_string(m_udk_components[component_index].component.offset_in_bits)
                                     + ",current component component_fragment_offset:"
                                     + std::to_string(m_udk_components[component_index].component_fragment_offset),
                                 m_library_id);
                m_callback_print(" combination:" + std::to_string(split_comb_index) + ",fragment 0 index :"
                                     + std::to_string(udk_new_internal_component_vec[0].index)
                                     + ",fragment 0 width :"
                                     + std::to_string(udk_new_internal_component_vec[0].component.m_width_in_bits)
                                     + ",fragment 0 offset:"
                                     + std::to_string(udk_new_internal_component_vec[0].component.offset_in_bits)
                                     + ",fragment 0 component_fragment_offset:"
                                     + std::to_string(udk_new_internal_component_vec[0].component_fragment_offset)
                                     + ", child"
                                     + std::to_string(udk_new_internal_component_vec[0].fragmented_component_child)
                                     + ", desc:"
                                     + std::string(udk_new_internal_component_vec[0].component.m_description),
                                 m_library_id);
                m_callback_print(+",fragment 1 index :" + std::to_string(udk_new_internal_component_vec[1].index)
                                     + ",fragment 1 width :"
                                     + std::to_string(udk_new_internal_component_vec[1].component.m_width_in_bits)
                                     + ",fragment 1 offset:"
                                     + std::to_string(udk_new_internal_component_vec[1].component.offset_in_bits)
                                     + ",fragment 1 component_fragment_offset:"
                                     + std::to_string(udk_new_internal_component_vec[1].component_fragment_offset)
                                     + ", child"
                                     + std::to_string(udk_new_internal_component_vec[1].fragmented_component_child)
                                     + ", desc:"
                                     + std::string(udk_new_internal_component_vec[1].component.m_description),
                                 m_library_id);
            }
            // only try to replace if split was done (insert combinations from end to start,
            m_udk_components.insert(m_udk_components.begin() + component_index + 1,
                                    udk_new_internal_component_vec.begin(),
                                    udk_new_internal_component_vec.end());

            if (recursive_place_udk(component_index + 1) == true) {
                return true;
            } // fragment placement failed, delete all child fragments
            if (m_verbose) {
                m_callback_print("udk component split placement failed, tries another combination", m_library_id);
            }
            for (size_t fragment_index = 0; fragment_index < 2; fragment_index++) {
                if (m_verbose && check_log_level(2)) { // todo avamar - need to assign different log level
                    m_callback_print("erasing:" + m_udk_components[component_index + 1].component.generate_udk_component_to_string()
                                         + "is child:"
                                         + std::to_string(m_udk_components[component_index + 1].fragmented_component_child),
                                     m_library_id);
                }
                if (m_udk_components[component_index + 1].fragmented_component_child) {
                    m_udk_components.erase(m_udk_components.begin() + component_index
                                           + 1); // verify component child & delete fragment
                }
            }
        }
        // went over all possible split combinations options, split failed to place
        m_udk_components[component_index].fragmented_component_parent_skip_placement = false;
    }

    return false;
}

bool
runtime_flexibility_library::recursive_place_udk_component_and_bucket(size_t bucket_index,
                                                                      size_t component_index,
                                                                      bool& succeed_in_placement_skip_fragmentation)
{
    auto& current_component = m_udk_components[component_index];
    if (place_udk_component_in_bucket(bucket_index, current_component)
        == true) { // now place bucket assign bucket to tables key parts if not assigned
        if (m_verbose) {
            m_callback_print("placed component index " + std::to_string(m_udk_components[component_index].index) + " type "
                                 + std::to_string(current_component.component.m_udk_type)
                                 + " width "
                                 + std::to_string(current_component.component.get_width_in_bits())
                                 + " to bucket type "
                                 + std::to_string(m_udk_placement_buckets[bucket_index].bucket_type)
                                 + " of field select index "
                                 + std::to_string(m_udk_placement_buckets[bucket_index].field_select.fs_index),
                             m_library_id);
        }
        if (m_udk_placement_buckets[bucket_index].tables_in.size() == 0) { // need to assign bucket to table
            if (place_bucket_in_udk_tables(bucket_index, component_index)
                == false) { // this assigns at each table, at first key_part available for each (for udf)
                            // for calculated field, it assigned the keypart defined at the npl
                if (m_verbose) {
                    m_callback_print("revert last udk placement in bucket #" + std::to_string(bucket_index), m_library_id);
                }
                revert_last_udk_placement(bucket_index);

                return false;
            }
            succeed_in_placement_skip_fragmentation = true;
            if (recursive_place_udk(component_index + 1) == true) {
                return true;
            }
            if (m_udk_components[component_index].component.m_udk_type != UDK_COMPONENT_TYPE_CALCULATED_FIELD) {
                // basic fix -> no support to assign calculated field at different key part than assign at npl
                for (auto& table_in : m_udk_placement_buckets[bucket_index]
                                          .tables_in) { // trying to switch key parts for tables with more than one key part
                    size_t table_index = table_in.first;
                    size_t current_table_key_part_index = table_in.second + 1;
                    if (m_tables_key_parts[table_index].size()
                        <= current_table_key_part_index) { // no more key parts for current table
                        continue;
                    }
                    key_part& current_table_key_part = m_tables_key_parts[table_index][current_table_key_part_index];
                    bool current_key_part_ok = false;
                    for (; current_table_key_part_index < m_tables_key_parts[table_index].size(); current_table_key_part_index++) {
                        current_table_key_part = m_tables_key_parts[table_index][current_table_key_part_index];
                        if (current_table_key_part.additional_buckets_available()
                            && m_udk_placement_buckets[bucket_index].used_width <= current_table_key_part.get_available_width()) {
                            current_key_part_ok = true; // found OK key part
                            break;
                        }
                    }
                    if (!current_key_part_ok) {
                        continue; // no more OK key parts for current table - try next table
                    }
                    auto& previous_table_key_part = m_tables_key_parts[table_index][table_in.second];
                    previous_table_key_part.udk_placement_buckets_indices.pop_back();
                    previous_table_key_part.used_width -= m_udk_placement_buckets[bucket_index].used_width;
                    previous_table_key_part.number_of_buckets_supporting_udf--;
                    current_table_key_part.used_width += m_udk_placement_buckets[bucket_index].used_width;
                    current_table_key_part.udk_placement_buckets_indices.push_back(bucket_index);
                    current_table_key_part.number_of_buckets_supporting_udf++;
                    m_udk_placement_buckets[bucket_index].tables_in[table_index] = (uint8_t)current_table_key_part_index;
                    succeed_in_placement_skip_fragmentation = true;
                    if (recursive_place_udk(component_index + 1) == true) {
                        return true;
                    }
                }
            }
        } else { // bucket already assigned to table
            succeed_in_placement_skip_fragmentation = true;
            if (recursive_place_udk(component_index + 1) == true) {
                return true;
            }
        }
        if (!revert_last_udk_placement(bucket_index)) {
            m_callback_print("unable to perform revert", m_library_id);
        }

    } // currently we don't support split of large fields over several buckets, TBD
    return false;
}

bool
runtime_flexibility_library::place_bucket_in_udk_tables(size_t bucket_index, size_t component_index)
{
    udk_component_internal& current_component = m_udk_components[component_index];
    udk_component& component = current_component.component;
    udk_placement_bucket& bucket = m_udk_placement_buckets[bucket_index];
    for (size_t table_index = 0; table_index < m_processed_udk_tables_components.size(); table_index++) {
        if (current_component.component_index_in_place_udk_vec_per_table[table_index] < 0) {
            continue;
        }
        uint8_t key_part_idx = 0;
        auto& current_table = m_tables_key_parts[table_index];
        if (component.m_udk_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD) {
            key_part_idx = component.m_data.m_calculated_field_instance.key_part_index;
            if (key_part_idx >= current_table.size()) {
                if (m_verbose) {
                    m_callback_print("provided wrong key part index " + std::to_string(key_part_idx) + " for calculated field id "
                                         + std::to_string(component.m_data.m_calculated_field_instance.field_id),
                                     m_verbose);
                }
                return false;
            }
        } else // component is UDF
        {
            for (key_part_idx = 0; key_part_idx < current_table.size(); key_part_idx++) {
                auto& current_table_key_part = current_table[key_part_idx];
                if (current_table_key_part.get_available_width() < bucket.used_width) {
                    if (m_verbose) {
                        m_callback_print("key part " + std::to_string(key_part_idx) + " of table index "
                                             + std::to_string(table_index)
                                             + " has no available width for current component index "
                                             + std::to_string(component_index)
                                             + " available key part width "
                                             + std::to_string(current_table_key_part.get_available_width())
                                             + " < component width "
                                             + std::to_string(current_component.component.get_width_in_bits()),
                                         m_library_id);
                    }
                    continue; // try next key part
                }
                if (!current_table_key_part.additional_buckets_available()) {
                    if (m_verbose) {
                        m_callback_print("key part " + std::to_string(key_part_idx) + " of table index "
                                             + std::to_string(table_index)
                                             + " has no buckets left",
                                         m_library_id);
                    }         // not enough buckets - might have more available at next key part
                    continue; // try next key part
                }
                break; // key part ok
            }
            if (key_part_idx >= current_table.size()) {
                if (m_verbose) {
                    m_callback_print("table index " + std::to_string(table_index) + " has no place for bucket "
                                         + std::to_string(bucket.bucket_index),
                                     m_library_id);
                }
                return false; // cannot accept new bucket - returning false
            }
        }
        auto& current_table_key_part = current_table[key_part_idx];
        current_table_key_part.used_width += bucket.used_width;
        current_table_key_part.udk_placement_buckets_indices.push_back(bucket_index);
        bucket.tables_in.emplace(table_index, key_part_idx);
        if (current_component.component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PACKET
            || current_component.component.m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PD) {
            current_table_key_part.number_of_buckets_supporting_udf++;
        }
        if (m_verbose) {
            m_callback_print("assigned bucket index " + std::to_string(bucket.bucket_index) + " to table index "
                                 + std::to_string(table_index)
                                 + " key part "
                                 + std::to_string(key_part_idx),
                             m_library_id);
        }
    }
    return true;
}

std::string
runtime_flexibility_library::get_last_udk_placement_str() const
{
    std::string out_str = "";
    static std::vector<std::string> bucket_types{"UDK_PLACEMENT_BUCKET_TYPE_PACKET_AND_PD",
                                                 "UDK_PLACEMENT_BUCKET_TYPE_PACKET_ONLY",
                                                 "UDK_PLACEMENT_BUCKET_TYPE_CALCULATED_ONLY"};
    for (size_t table_idx = 0; table_idx < m_tables_key_parts.size(); table_idx++) {
        out_str += "table_idx " + std::to_string(table_idx) + ": \n";
        auto& key_parts = m_tables_key_parts[table_idx];
        for (size_t j = 0; j < key_parts.size(); j++) {
            out_str += "\tkey_part " + std::to_string(j) + ": \n";
            out_str += "\t\tused width " + std::to_string(key_parts[j].used_width) + "\n";
            out_str += "\t\t#constant bits " + std::to_string(key_parts[j].number_of_constant_bits) + "\n";
            for (auto& range_compression_comp : key_parts[j].range_compression_components) {
                out_str += "\t\trange compression result with width "
                           + std::to_string(range_compression_comp.component.get_width_in_bits()) + "\n";
            }
            for (auto bucket_index : key_parts[j].udk_placement_buckets_indices) {
                auto& bucket = m_udk_placement_buckets[bucket_index];
                out_str += "\t\tudk_placement_bucket #" + std::to_string(bucket.bucket_index)
                           + " type: " + bucket_types.at((size_t)bucket.bucket_type) + ":\n";
                out_str += "\t\t\tfield_select index: " + std::to_string(bucket.field_select.fs_index)
                           + " width: " + std::to_string(bucket.field_select.fs_allocated_width)
                           + " used width: " + std::to_string(bucket.used_width)
                           + " available width: " + std::to_string(bucket.available_width) + "\n";
                out_str += "\t\t\tcomponents placed: \n";
                for (auto& internal_component : bucket.placed_fields) {
                    out_str += "\t\t\t\t";
                    std::string description(internal_component.component.m_description);
                    if (!description.empty()) {
                        out_str += "component: " + description + ", ";
                    }
                    out_str += "component offset : " + std::to_string(internal_component.component.offset_in_bits)
                               + ", width: " + std::to_string(internal_component.component.get_width_in_bits()) + "\n";
                }
            }
        }
    }
    return out_str;
}
void
runtime_flexibility_library::set_is_placing_for_nsim(bool is_placing_for_nsim)
{
    m_is_placing_for_nsim = is_placing_for_nsim;
}

void
runtime_flexibility_library::set_is_placing_for_hw(bool is_placing_for_hw)
{
    m_is_placing_for_hw = is_placing_for_hw;
}

runtime_flexibility_library::key_part
runtime_flexibility_library::get_last_udk_placement(size_t table_index, size_t key_part_idx) const
{
    if (table_index < m_tables_key_parts.size() && key_part_idx < m_tables_key_parts[table_index].size()) {
        key_part result = m_tables_key_parts[table_index][key_part_idx];
        for (size_t bucket_id : m_tables_key_parts[table_index][key_part_idx].udk_placement_buckets_indices) {
            result.udk_placement_buckets.push_back(m_udk_placement_buckets[bucket_id]);
        }
        return result;
    }
    return key_part(0, 0, 0);
}

place_udk_res
runtime_flexibility_library::nsim_place_udk(const udk_resources& resources,
                                            const std::vector<udk_table_id_and_components>& udk_tables_components,
                                            std::vector<microcode_write>& microcode_writes,
                                            std::vector<udk_translation_info>& trans_info /*output*/)
{
    place_udk_command command(resources.macro_id, udk_tables_components);

    if (command.number_of_udk_tables == UINT8_MAX) {
        if (m_verbose) {
            m_callback_print("nsim place_udk - wrong key_size option", m_library_id);
        }
        return PLACE_UDK_RES_EWRONG_ARGS;
    }
    size_t command_len = command.get_command_len();
    microcode_writes.emplace_back(std::string("SIM_ACCESS"), std::string("PLACE_UDK_COMMAND"));
    memcpy(microcode_writes.back().data, &command, command_len);
    microcode_writes.back().width = command_len;
    microcode_writes.back().block = std::string("SIM_ACCESS");
    microcode_writes.back().name = std::string("PLACE_UDK_COMMAND");
    microcode_writes.back().line = 0;
    microcode_writes.back().array_index = 0;
    microcode_writes.back().offset = 0;

    m_udk_tables_components = udk_tables_components;
    if (m_verbose) {
        m_callback_print("nsim place_udk - udk library placement extracted ok", m_library_id);
    }

    if (!m_is_placing_for_hw) {
        // only create dummy translation info for nsim-only tests
        // HW flow have already generated the full translation info
        if (!generate_udk_translation_info_for_nsim(resources, m_udk_tables_components, trans_info)) {
            return PLACE_UDK_RES_EWRONG_ARGS;
        }
    }
    return PLACE_UDK_RES_OK;
}

bool
runtime_flexibility_library::generate_udk_translation_info_for_nsim(
    const udk_resources& resources,
    const std::vector<udk_table_id_and_components>& udk_tables_components,
    std::vector<udk_translation_info>& trans_info)
{

    if (trans_info.size() < m_udk_tables_components.size()) {
        if (m_verbose) {
            m_callback_print("translation info provided size " + std::to_string(trans_info.size())
                                 + " is smaller than number of tables to place "
                                 + std::to_string(m_udk_tables_components.size()),
                             m_library_id);
        }
        return false;
    }

    for (uint16_t table_idx = 0; table_idx < m_udk_tables_components.size(); table_idx++) {
        int16_t offset = 0;
        auto& tables_components = m_udk_tables_components[table_idx];
        uint16_t table_id = tables_components.udk_table_id;
        for (size_t component_idx = 0; component_idx < tables_components.udk_components.size();
             component_idx++) // components are placed by order they were provided
        {
            auto& component = tables_components.udk_components[component_idx];
            uint16_t width = component.get_width_in_bits();
            if (component.m_udk_type == UDK_COMPONENT_TYPE_RANGE_COMPRESSION_RESULT && (offset % 4) > 0) {
                offset += (4 - offset % 4); // making sure range compression result lsb is nibble aligned
                width = 16;                 // For simulation only setting width to be always 16
            }
            if (component.m_udk_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD) {
                if (table_idx < resources.tables_properties.size()
                    && resources.tables_properties.at(table_id).table_calculated_fields.count(
                           component.m_data.m_calculated_field_instance.field_id)
                           > 0)
                    width = resources.tables_properties.at(table_id)
                                .table_calculated_fields.at(component.m_data.m_calculated_field_instance.field_id)
                                .field_width;
            }
            trans_info[table_idx].placement_info[component_idx].add_placement_info(
                offset, width, SIZE_MAX, 0, component.m_description);
            offset += width;
        }
        trans_info[table_idx].number_of_components = tables_components.udk_components.size();
        trans_info[table_idx].physical_key_width = offset; // not sure it even matters here...
    }
    return true;
}

void
runtime_flexibility_library::set_verbose(bool verbose)
{
    m_verbose = verbose;
}

void
runtime_flexibility_library::set_components_fragmentization(bool enable_fragment)
{
    m_components_fragmentization_enable = enable_fragment;
}

void
runtime_flexibility_library::set_log_level(size_t log_level)
{
    m_log_level = log_level;
    if (m_log_level > 0) {
        set_verbose(true);
    }
}

size_t
runtime_flexibility_library::get_log_level()
{
    return m_log_level;
}

bool
runtime_flexibility_library::check_log_level(size_t log_level)
{
    return (m_log_level >= log_level);
}

bool
runtime_flexibility_library::possible_to_place_width_in_udk_bucket(size_t width_to_place, udk_placement_bucket& bucket)
{
    if (bucket.available_width < (int)width_to_place) {
        if (m_verbose) {
            m_callback_print("Unable to place component with width " + std::to_string(width_to_place)
                                 + ", not enough place in bucket: "
                                 + std::to_string(bucket.available_width)
                                 + " bits available",
                             m_library_id);
        }
        return false;
    }
    for (auto& table : bucket.tables_in) {
        if (m_tables_key_parts.size() <= table.first || m_tables_key_parts[table.first].size() <= table.second) {
            if (m_verbose) {
                m_callback_print("Wrong table id or key part!", m_library_id);
            }
            return false;
        }
        if (m_tables_key_parts[table.first][table.second].get_available_width() < (int)width_to_place) {
            if (m_verbose) {
                m_callback_print("Unable to place component with width " + std::to_string(width_to_place) + " in table id "
                                     + std::to_string(table.first)
                                     + " key part "
                                     + std::to_string(table.second)
                                     + " not enough place: "
                                     + std::to_string(m_tables_key_parts[table.first][table.second].get_available_width())
                                     + " bits available",
                                 m_library_id);
            }
            return false;
        }
    }
    return true;
}

bool
runtime_flexibility_library::possible_to_place_width_in_remaining_udk_buckets(udk_component_internal& internal_component)
{
    int total_availble_width = 0;
    for (auto& bucket : m_udk_placement_buckets) {
        // checks
        if (bucket.bucket_type == UDK_PLACEMENT_BUCKET_TYPE_PACKET_AND_PD
            || bucket.bucket_type == UDK_PLACEMENT_BUCKET_TYPE_PACKET_ONLY) {
            if (do_component_tables_match_bucket_tables(internal_component, bucket.bucket_index)) {
                total_availble_width += bucket.available_width;
                if (m_verbose && (check_log_level(3)))
                    m_callback_print("bucket available width counter "
                                     "bucket index:"
                                         + std::to_string(bucket.bucket_index)
                                         + ",bucket available width:"
                                         + std::to_string(bucket.available_width)
                                         + ", total availble width: "
                                         + std::to_string(total_availble_width)
                                         + " bits available",
                                     m_library_id);
            }
        }
    }
    if (total_availble_width < (int)internal_component.get_width_with_lsb_penalty()) {
        if (m_verbose && (check_log_level(1))) {
            m_callback_print("Unable to place component with width "
                                 + std::to_string(internal_component.get_width_with_lsb_penalty())
                                 + ", not enough place in all remaining buckets: "
                                 + std::to_string(total_availble_width)
                                 + " bits available",
                             m_library_id);
        }
        return false;
    }
    if (m_verbose && (check_log_level(3))) {
        m_callback_print("We are able to place component with width "
                             + std::to_string(internal_component.get_width_with_lsb_penalty())
                             + ", not enough place in all remaining buckets: "
                             + std::to_string(total_availble_width)
                             + " bits available",
                         m_library_id);
    }
    return true;
}

int
runtime_flexibility_library::udk_placement_bucket::restructure_component_groups()
{
    size_t width_before_restructure = used_width;
    placed_component_groups.clear();
    if (placed_fields.empty()) {
        available_width += used_width;
        used_width = 0;
        max_msb_penalty = 0;
        return (-(int)width_before_restructure);
    } else if (placed_fields.back().component.m_udk_type == UDK_COMPONENT_TYPE_RANGE_COMPRESSION_RESULT
               || placed_fields.back().component.m_udk_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD) {
        return 0;
    }
    std::vector<udk_component_internal> sorted_placed_fields(placed_fields.begin(), placed_fields.end());
    std::sort(sorted_placed_fields.begin(), sorted_placed_fields.end(), [](udk_component_internal& a, udk_component_internal& b) {
        return a.component.offset_in_bits < b.component.offset_in_bits;
    });
    split_components_into_groups(sorted_placed_fields);
    max_msb_penalty = 0;
    used_width = 0;
    for (auto group : placed_component_groups) {
        uint16_t group_msb_penalty = group.get_msb_penalty();
        used_width += group.get_group_width();
        used_width += group_msb_penalty;
        if (max_msb_penalty < group_msb_penalty) {
            max_msb_penalty = group_msb_penalty;
        }
    }
    used_width -= static_cast<int>(max_msb_penalty);
    available_width -= static_cast<int>(used_width - width_before_restructure);
    return static_cast<int>(used_width - width_before_restructure);
}

void
runtime_flexibility_library::udk_placement_bucket::split_components_into_groups(
    std::vector<udk_component_internal>& sorted_placed_components)
{
    for (auto& current_component : sorted_placed_components) {
        if (placed_component_groups.empty()
            || !placed_component_groups.back().components.back().may_share_channel(current_component)) {
            placed_component_groups.emplace_back();
        }
        placed_component_groups.back().add_component_on_lsb(current_component);
    }
}

uint16_t
runtime_flexibility_library::udk_components_group::get_msb_penalty() const
{
    uint16_t effective_width_including_msb_penalty = ((offset_to_lsb_with_penalty - msb_offset + 15) / 16) * 16;
    int effective_msb_with_penalty = offset_to_lsb_with_penalty - effective_width_including_msb_penalty;
    return msb_offset - effective_msb_with_penalty;
}
void
runtime_flexibility_library::udk_components_group::add_component_on_lsb(udk_component_internal& component)
{
    components.push_back(component);
    if (components.size() == 1) {
        msb_offset = component.component.offset_in_bits;
    }
    offset_to_lsb_with_penalty = component.get_offset_to_lsb_with_penalty();
}

int
runtime_flexibility_library::udk_components_group::get_additional_width_to_place_if_adjacent(
    const udk_component_internal& other_component)
{
    if (components.empty()) {
        return other_component.get_width_with_lsb_penalty();
    }
    uint16_t current_offset_to_lsb = offset_to_lsb_with_penalty;
    if (components.back().may_share_channel(other_component)) {
        return other_component.get_offset_to_lsb_with_penalty() - current_offset_to_lsb;
    }
    return -1;
}

uint16_t
runtime_flexibility_library::udk_components_group::get_group_width()
{
    return offset_to_lsb_with_penalty - msb_offset;
}
