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

#include "runtime_flexibility_types.h"
#include "common/bit_vector.h"
using silicon_one::bit_vector;
using silicon_one::bit_vector64_t;
using silicon_one::bit_vector128_t;
using silicon_one::bit_vector192_t;
using silicon_one::bit_vector384_t;
#include <algorithm>
#include <map>
field_select_info::field_select_info()
{
    memset(this, 0, sizeof(*this));
}

field_select_info::field_select_info(size_t _fs_index, size_t _fs_allocated_width, size_t _first_channel)
{
    fs_index = _fs_index;
    fs_allocated_width = _fs_allocated_width;
    first_channel = _first_channel;
}

field_select_info::field_select_info(size_t _fs_index,
                                     size_t _fs_allocated_width,
                                     size_t _offset_in_ucode,
                                     size_t _num_of_bits_in_ucode,
                                     size_t _first_channel)
    : fs_index(_fs_index),
      fs_allocated_width(_fs_allocated_width),
      offset_in_ucode(_offset_in_ucode),
      num_of_bits_in_ucode(_num_of_bits_in_ucode),
      first_channel(_first_channel)
{
}

typedef uint8_t calculated_field_id_t;

table_line_info_t::table_line_info_t(int _line_num) : line_num(_line_num)
{
}
table_line_info_t::table_line_info_t() : line_num(-1)
{
}

microcode_pointers::microcode_pointers() : block_name(""), table_name(""), array_index(-1)
{
}
microcode_pointers::microcode_pointers(std::string _block_name, std::string _table_name) : microcode_pointers()
{
    block_name = _block_name;
    table_name = _table_name;
}
microcode_pointers::microcode_pointers(const microcode_pointers& uc_pointers)
    : block_name(uc_pointers.block_name), table_name(uc_pointers.table_name)
{
    for (auto& line : uc_pointers.table_lines) {
        table_lines.emplace_back(line);
    }
    array_index = uc_pointers.array_index;
}

udk_resources::udk_resources()
{
    macro_id = 0;

    field_selects = std::vector<field_select_info>();
    tables_properties = std::map<uint16_t, udk_table_properties>();
}

udk_resources::udk_resources(uint16_t _macro_id) : udk_resources()
{
    macro_id = _macro_id;
}

size_t
microcode_write::get_width_in_bytes()
{
    return (width + 7) / 8;
}
microcode_write::microcode_write()
{
}
microcode_write::microcode_write(std::string _block_name, std::string _table_name) : block(_block_name), name(_table_name)
{
}

uint16_t
udk_component::get_width_in_bits() const
{
    return m_width_in_bits;
}
uint16_t
udk_component::get_width_on_key_in_bits() const
{
    if (m_udk_type == UDK_COMPONENT_TYPE_RANGE_COMPRESSION_RESULT) {
        return ((m_width_in_bits + 3) / 4) * 4; // returning nibble aligned bits
    }
    return get_width_in_bits();
}

bool
udk_component::is_intersecting(const udk_component& rhs_component) const
{
    {
        if (rhs_component.m_udk_type != m_udk_type) {
            return false;
        }
        if (m_udk_type == UDK_COMPONENT_TYPE_RANGE_COMPRESSION_RESULT) {
            return false;
        }
        if (m_udk_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD) {
            return false;
        }
        if (m_udk_type == UDK_COMPONENT_TYPE_UDF_FROM_PACKET) {
            if (m_data.udf_from_packet_instance.protocol_layer != rhs_component.m_data.udf_from_packet_instance.protocol_layer
                || m_data.udf_from_packet_instance.header != rhs_component.m_data.udf_from_packet_instance.header
                || m_data.udf_from_packet_instance.is_relative != rhs_component.m_data.udf_from_packet_instance.is_relative) {
                return false;
            }
        }
        if (offset_in_bits <= rhs_component.offset_in_bits && rhs_component.offset_in_bits < offset_in_bits + m_width_in_bits) {
            return true;
        }
        if (offset_in_bits >= rhs_component.offset_in_bits
            && rhs_component.offset_in_bits + rhs_component.get_width_in_bits() > offset_in_bits) {
            return true;
        }
        return false;
    }
    return false;
}

void
udk_component::set_description(std::string description)
{
    uint8_t max_size
        = MAX_COMPONENT_DESCRIPTION_SIZE > description.size() ? (uint8_t)description.size() : MAX_COMPONENT_DESCRIPTION_SIZE;
    memset(m_description, 0, MAX_COMPONENT_DESCRIPTION_SIZE);
    memcpy(m_description, description.c_str(), max_size);
}

std::string
udk_component::generate_udk_component_to_string() const
{
    std::string componentInfo;
    componentInfo = "udk type: " + std::to_string(m_udk_type);
    switch (m_udk_type) {
    case UDK_COMPONENT_TYPE_UDF_FROM_PACKET:
        componentInfo += " UDF_FROM_PACKET ,udf_from_packet_desc:"
                         ",protocol_layer:"
                         + std::to_string(m_data.udf_from_packet_instance.protocol_layer)
                         + ",is_relative:" + std::to_string(m_data.udf_from_packet_instance.is_relative)
                         + ",header:" + std::to_string(m_data.udf_from_packet_instance.header) + ",width_in_bits: "
                         + std::to_string(m_width_in_bits) + ",offset_in_bits: " + std::to_string(offset_in_bits);
        break;
    case UDK_COMPONENT_TYPE_UDF_FROM_PD:
        componentInfo += " UDF_FROM_PD "
                         ",width_in_bits: "
                         + std::to_string(m_width_in_bits) + ",offset_in_bits: " + std::to_string(offset_in_bits);
        break;
    case UDK_COMPONENT_TYPE_CALCULATED_FIELD:
        componentInfo += " CALCULATED_FIELD ,calculated_field_instance: "
                         ",field_id:"
                         + std::to_string(m_data.m_calculated_field_instance.field_id);
        break;
    case UDK_COMPONENT_TYPE_RANGE_COMPRESSION_RESULT:
        componentInfo += " RANGE_COMPRESSION_RESULT "
                         ",width_in_bits: "
                         + std::to_string(m_width_in_bits);
        break;
    default:
        componentInfo += " Unknown Type";
        break;
    }
    componentInfo += ",description:" + std::string(m_description);
    return componentInfo;
}

udk_component::udk_component()
{
    memset(this, 0, sizeof(*this));
}
udk_component::udk_component(int8_t protocol_layer,
                             int8_t header,
                             int8_t width_in_bytes,
                             int8_t offset_in_bytes,
                             bool is_relative,
                             std::string description)
    : udk_component()
{
    m_udk_type = UDK_COMPONENT_TYPE_UDF_FROM_PACKET;
    m_data.udf_from_packet_instance.protocol_layer = protocol_layer;
    m_data.udf_from_packet_instance.header = header;
    m_width_in_bits = width_in_bytes * 8;
    offset_in_bits = offset_in_bytes * 8;
    m_data.udf_from_packet_instance.is_relative = is_relative;
    memcpy(m_description,
           description.c_str(),
           MAX_COMPONENT_DESCRIPTION_SIZE < description.size() ? MAX_COMPONENT_DESCRIPTION_SIZE : description.size());
}
udk_component::udk_component(udk_component_type component_type, uint32_t value, std::string description) : udk_component()
{
    if (component_type == UDK_COMPONENT_TYPE_RANGE_COMPRESSION_RESULT) {
        m_width_in_bits = value;
    } else if (component_type == UDK_COMPONENT_TYPE_CALCULATED_FIELD) {
        m_data.m_calculated_field_instance.field_id = value;
        m_width_in_bits = 0;
    } else if (component_type == UDK_COMPONENT_TYPE_UDF_FROM_PD) {
        m_width_in_bits = value >> OFFSET_ON_PD_ENUM_WIDTH;
        offset_in_bits = value & ((1 << OFFSET_ON_PD_ENUM_WIDTH) - 1);
    }
    m_udk_type = component_type;
    memcpy(m_description,
           description.c_str(),
           MAX_COMPONENT_DESCRIPTION_SIZE < description.size() ? MAX_COMPONENT_DESCRIPTION_SIZE : description.size());
}

udk_component::udk_component(const udk_component& _component)
{
    m_udk_type = _component.m_udk_type;
    m_data = _component.m_data;
    m_width_in_bits = _component.get_width_in_bits();
    offset_in_bits = _component.offset_in_bits;
    memcpy(m_description, _component.m_description, MAX_COMPONENT_DESCRIPTION_SIZE);
}

udk_table_id_and_components::udk_table_id_and_components()
{
    udk_table_id = UINT16_MAX;
}
udk_table_id_and_components::udk_table_id_and_components(uint16_t _udk_table_id, const std::vector<udk_component>& _udk_components)
{
    udk_table_id = _udk_table_id;
    udk_components = _udk_components;
}

place_udk_info_per_table::place_udk_info_per_table(const udk_table_id_and_components& udk_table_id_and_components)
{
    udk_table_id = udk_table_id_and_components.udk_table_id;
    number_of_udk_components = (uint8_t)(udk_table_id_and_components.udk_components.size());
}
place_udk_info_per_table::place_udk_info_per_table()
{
    udk_table_id = UINT16_MAX;
    number_of_udk_components = UINT8_MAX;
}
place_udk_command::place_udk_command()
{
}
place_udk_command::place_udk_command(uint16_t _macro_id,
                                     const std::vector<udk_table_id_and_components>& udk_table_id_and_components_vec)
    : place_udk_command()
{
    std::vector<udk_component> udk_components;
    uint8_t table_idx = 0;
    for (; table_idx < udk_table_id_and_components_vec.size(); table_idx++) {
        auto& components = udk_table_id_and_components_vec[table_idx];
        place_udk_tables_info[table_idx] = place_udk_info_per_table(components);
        udk_components.insert(udk_components.end(), components.udk_components.begin(), components.udk_components.end());
    }

    // notice MAX_NUMBER_OF_UDK_COMPONENTS == 32 , UDK_MAX_TABLES_PER_PLACEMENT == 15
    // while sizeof(udk_component) == 17
    // which means full utilization will result in 8160 > (UDK_MAX_DATA_SIZE == 4096)
    //
    number_of_udk_components = (uint16_t)udk_components.size();
    if (get_command_len() < UDK_MAX_DATA_SIZE) {
        macro_id = _macro_id;
        number_of_udk_tables = table_idx;
        memcpy(values, udk_components.data(), number_of_udk_components * sizeof(udk_component));
    } else { // otherwise - return empty command
        number_of_udk_tables = UINT8_MAX;
    }
}
size_t
place_udk_command::get_command_len() const
{
    return sizeof(place_udk_command) - UDK_MAX_DATA_SIZE + number_of_udk_components * sizeof(udk_component);
}

udk_translation_info::udk_translation_info()
{
}
int16_t
udk_translation_info::get_udk_component_offset_on_key_in_bits(size_t component_index)
{
    if (component_index >= number_of_components) {
        return UINT8_MAX;
    }
    return placement_info[component_index].minimal_offset;
}
size_t
udk_translation_info::get_udk_component_width_in_bits(size_t component_index)
{
    if (component_index >= number_of_components) {
        return UINT8_MAX;
    }
    return placement_info[component_index].total_width;
}

struct placement_info_less { // This is used for key parsing
    bool operator()(const udk_translation_info::placement_info_t& a, const udk_translation_info::placement_info_t& b) const
    {
        if (a.minimal_offset != b.minimal_offset) {
            return a.minimal_offset > b.minimal_offset;
        } else if (a.total_width != b.total_width) {
            return a.total_width > b.total_width;
        }
        int res = strcmp(a.description, b.description);
        return res > 0;
    }
};
struct fragment_info_less { // This is used for key parsing
    bool operator()(const udk_translation_info::placement_info_t::fragment_info_t& a,
                    const udk_translation_info::placement_info_t::fragment_info_t& b) const
    {

        if (a.width == 0 || b.width == 0) {
            if (a.width == 0) {
                return false;
            }
            if (b.width == 0) {
                return true;
            }
        }
        if (a.offset_in_component != b.offset_in_component) {
            return a.offset_in_component > b.offset_in_component;
        } else if (a.processed_index != b.processed_index) {
            return a.processed_index > b.processed_index;
        } else if (a.width != b.width) {
            return a.width > b.width;
        } else {
            // shouldn't reach the condition below, since fragments should have different offsets
            return false;
        }
    }
};

std::string
udk_translation_info::get_key_info(const std::string& key)
{
    bit_vector key_bv(key);
    std::map<placement_info_t, std::string /*comment*/, placement_info_less> sorted_comments;
    for (size_t component_index = 0; component_index < number_of_components; component_index++) {
        std::string current_comment = "";
        std::string fragment_offset_on_component_str = "";
        for (size_t fragment_index = 0; fragment_index < placement_info[component_index].fragments_vec.size(); fragment_index++) {
            uint16_t msb = placement_info[component_index].fragments_vec[fragment_index].offset
                           + placement_info[component_index].fragments_vec[fragment_index].width - 1;

            if (placement_info[component_index].fragments_vec.size() > 1) {
                fragment_offset_on_component_str
                    = " fragment offset on component: "
                      + std::to_string(placement_info[component_index].fragments_vec[fragment_index].offset_in_component);
            }
            if (!current_comment.empty()) {
                current_comment += "\n";
            }
            current_comment += "bits " + std::to_string(placement_info[component_index].fragments_vec[fragment_index].offset)
                               + " to " + std::to_string(msb) + " value: "
                               + key_bv.bits(msb, placement_info[component_index].fragments_vec[fragment_index].offset).to_string()
                               + " component with index: " + std::to_string(component_index) + fragment_offset_on_component_str
                               + " description: " + std::string(placement_info[component_index].description);
        }
        sorted_comments[placement_info[component_index]] = current_comment;
    }

    std::string result = "key value: " + key + "\n";
    uint16_t processed_index = 0;
    for (auto& constant_info : constant_bits_per_key_part) {
        uint16_t msb = constant_info.second - 1 + constant_info.first;
        placement_info_t const_info;
        const_info.add_placement_info(msb, 0, processed_index, 0, "");
        std::string current_comment = "bits " + std::to_string(constant_info.first) + " to " + std::to_string(msb)
                                      + " value: " + key_bv.bits(msb, constant_info.first).to_string() + " constant key part\n";
        sorted_comments[const_info] = current_comment;
        processed_index++;
    }
    for (auto it = sorted_comments.begin(); it != sorted_comments.end(); it++) {
        result += it->second + "\n";
    }
    return result;
}

udk_translation_info::placement_info_t::placement_info_t()
{
    memset(this, 0, sizeof(*this));
}

void
udk_translation_info::placement_info_t::add_placement_info(int16_t _offset,
                                                           size_t _width,
                                                           size_t _processed_index,
                                                           uint16_t _offset_in_component,
                                                           const char _description[MAX_COMPONENT_DESCRIPTION_SIZE])
{
    if (fragments_vec.size() == 0) {
        minimal_offset = _offset;
        total_width = 0;
    }
    fragments_vec.emplace_back(
        fragment_info_t(_offset, (uint16_t)_width, (uint16_t)_processed_index, (int16_t)_offset_in_component));
    minimal_offset = std::min((int16_t)_offset, (int16_t)minimal_offset);
    total_width += (uint16_t)_width;
    memcpy(description, _description, MAX_COMPONENT_DESCRIPTION_SIZE);
    if (_width != 0 && _processed_index != UINT16_MAX) { // to avoid irrelevant cases
        std::sort(fragments_vec.begin(), fragments_vec.end(), fragment_info_less());
    }
}

udk_translation_info::placement_info_t::fragment_info_t::fragment_info_t()
    : offset(INT16_MAX), width(0), processed_index(UINT16_MAX), offset_in_component(0)
{
}

udk_translation_info::placement_info_t::fragment_info_t::fragment_info_t(
    const udk_translation_info::placement_info_t::fragment_info_t& _fragment_info)
    : offset(_fragment_info.offset),
      width(_fragment_info.width),
      processed_index(_fragment_info.processed_index),
      offset_in_component(_fragment_info.offset_in_component)
{
}

udk_translation_info::placement_info_t::fragment_info_t::fragment_info_t(int16_t _offset,
                                                                         uint16_t _width,
                                                                         uint16_t _processed_index,
                                                                         int16_t _offset_in_component)
    : offset(_offset), width(_width), processed_index(_processed_index), offset_in_component(_offset_in_component)
{
}

void
udk_translation_info::clean()
{
    number_of_components = 0;
    physical_key_width = 0;
    constant_bits_per_key_part.clear();
    placement_info_t new_placement_info = placement_info_t();

    for (auto& placement_info_obj : placement_info) {
        placement_info_obj = new_placement_info;
    }
}
