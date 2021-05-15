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

#ifndef RUNTIME_FLEXIBILITY_TYPES_H
#define RUNTIME_FLEXIBILITY_TYPES_H
#define MAX_NUMBER_OF_UDK_COMPONENTS 32
// this file contains some commented lines for future use
#include <string>
#include <vector>
#include <map>
#include <stdint.h>
#include <cstring>
#define UDK_MAX_DATA_SIZE 4096
#define UDK_MAX_TABLES_PER_PLACEMENT 15
#define CHANNEL_WIDTH 16
#define UCODE_WIDTH_PER_CHANNEL_IN_SCOPER_MACRO_TABLE 16
#define OFFSET_ON_PD_ENUM_WIDTH 12
#define COMPONENT_FRAGMENT_MIN_WIDTH_IN_BITS 8

#ifdef __GNUC__
#define ATTR_UNUSED __attribute__((unused))
#else
#define ATTR_UNUSED
#endif

typedef uint8_t udk_key_size_t;
static const udk_key_size_t UDK_KEY_SIZE_160 = 0;
static const udk_key_size_t UDK_KEY_SIZE_320 = 1;
static const udk_key_size_t UDK_KEY_SIZE_NUM_SIZES = 2;
static const udk_key_size_t UDK_KEY_SIZE_FIRST = UDK_KEY_SIZE_160;
static const udk_key_size_t UDK_KEY_SIZE_ERROR = UDK_KEY_SIZE_NUM_SIZES;
static std::map<udk_key_size_t, int8_t> udk_key_size_to_key_parts
    = {{UDK_KEY_SIZE_160, 1}, {UDK_KEY_SIZE_320, 2}, {UDK_KEY_SIZE_NUM_SIZES, -1}};

static std::map<int8_t, udk_key_size_t> num_key_parts_to_udk_type
    = {{1, UDK_KEY_SIZE_160}, {2, UDK_KEY_SIZE_320}, {-1, UDK_KEY_SIZE_NUM_SIZES}};

static int get_num_of_key_parts(udk_key_size_t key_size) ATTR_UNUSED;
static int
get_num_of_key_parts(udk_key_size_t key_size)
{
    if (udk_key_size_to_key_parts.count(key_size) == 0) {
        return -1;
    }
    return udk_key_size_to_key_parts[key_size];
}

static udk_key_size_t
get_key_size_type(int8_t num_key_parts)
{
    if (num_key_parts_to_udk_type.count(num_key_parts) == 0) {
        return UDK_KEY_SIZE_NUM_SIZES;
    }
    return num_key_parts_to_udk_type[num_key_parts];
}
struct field_select_info {
    size_t fs_index;
    size_t fs_allocated_width;
    size_t offset_in_ucode;
    size_t num_of_bits_in_ucode;
    size_t first_channel;
    field_select_info();
    field_select_info(size_t _fs_index, size_t _fs_allocated_width, size_t _first_channel);
    field_select_info(size_t _fs_index,
                      size_t _fs_allocated_width,
                      size_t _offset_in_ucode,
                      size_t _num_of_bits_in_ucode,
                      size_t _first_channel);
};

typedef uint8_t calculated_field_id_t;

struct table_line_info_t {
    int line_num;
    std::map<calculated_field_id_t, uint16_t> calculated_field_id_to_fs_index;
    std::map<calculated_field_id_t, uint16_t> calculated_field_id_to_fs_index_per_row;
    table_line_info_t();
    explicit table_line_info_t(int _line_num);
};
struct microcode_pointers {
    std::string block_name;
    std::string table_name;
    int8_t array_index;
    std::vector<table_line_info_t> table_lines;

    microcode_pointers();
    microcode_pointers(std::string _block_name, std::string _table_name);
    microcode_pointers(const microcode_pointers& uc_pointers);
};
struct calculated_field_info_t {
    uint16_t field_width;
    uint8_t key_part_index;
    calculated_field_info_t()
    {
        field_width = -1;
        key_part_index = -1;
    }
    explicit calculated_field_info_t(uint16_t _field_width) : field_width(_field_width), key_part_index(-1)
    {
    }
    calculated_field_info_t(uint16_t _field_width, uint8_t _key_part_index)
        : field_width(_field_width), key_part_index(_key_part_index)
    {
    }
};
struct udk_table_properties {
    std::vector<uint32_t> max_number_of_field_selects_for_each_key_part; // might not be common for all key_parts
    std::vector<uint32_t> m_key_sizes_per_key_part;
    std::vector<uint32_t> m_constant_bits_per_key_part; // inlinePayloadSize in key_construction.cpp
    std::vector<microcode_pointers> lookup_keys_construction_table_pointers;
    std::map<calculated_field_id_t, calculated_field_info_t> table_calculated_fields;
    udk_table_properties()
    {
    }
};

struct udk_resources {
    uint16_t macro_id;
    std::vector<field_select_info> field_selects;
    std::map<uint16_t /*table id*/, udk_table_properties> tables_properties;
    // key_construction_lines
    microcode_pointers scoper_macro_table_pointer;
    microcode_pointers lookup_keys_construction_macro_table_pointer;
    size_t field_select_index_width_in_bits;
    size_t field_select_not_used_value;
    size_t offset_of_field_selects_in_key_construction_microcode_line;
    uint16_t first_lsb_channel_with_no_pd_support;
    uint16_t first_bypass_channel_with_pd_support;
    udk_resources();
    explicit udk_resources(uint16_t _macro_id);
};

typedef uint8_t udk_component_type;
static const udk_component_type UDK_COMPONENT_TYPE_UDF_FROM_PACKET = 1;
static const udk_component_type UDK_COMPONENT_TYPE_UDF_FROM_PD = 2;
static const udk_component_type UDK_COMPONENT_TYPE_CALCULATED_FIELD = 3;
static const udk_component_type UDK_COMPONENT_TYPE_RANGE_COMPRESSION_RESULT = 4;

struct microcode_write {
    std::string block;
    std::string name;
    int8_t array_index = 0;
    size_t line = 0;
    size_t offset = 0;
    size_t width = 0;
    uint8_t data[UDK_MAX_DATA_SIZE] = {0};
    // uint8_t data[sizeof(place_udk_command)] = {0}; TODO - define max on place_udk_command
    size_t get_width_in_bytes();
    microcode_write();
    microcode_write(std::string _block_name, std::string _table_name);
};

enum place_udk_res {
    PLACE_UDK_RES_OK,
    PLACE_UDK_RES_ENO_PLACEMENT,
    PLACE_UDK_RES_EWRONG_ARGS,
    PLACE_UDK_RES_EWRONG_KEY_SIZE,
    PLACE_UDK_RES_ENOTIMPLEMENTED,
    PLACE_UDK_RES_EUNKNOWN
};

#pragma pack(push, 1)
static const uint8_t MAX_COMPONENT_DESCRIPTION_SIZE = 32;
struct udk_component {
    struct udf_from_packet_desc {
        int8_t protocol_layer;
        int8_t header;
        bool is_relative;
    };
    udk_component_type m_udk_type;
    union data_u {
        udf_from_packet_desc udf_from_packet_instance;
        struct calculated_field {
            calculated_field_id_t field_id;
            uint16_t field_select_index;
            uint8_t key_part_index;
        } m_calculated_field_instance;
    } m_data;
    uint16_t m_width_in_bits;
    int16_t offset_in_bits = 0;
    char m_description[MAX_COMPONENT_DESCRIPTION_SIZE];
    udk_component();
    udk_component(int8_t protocol_layer,
                  int8_t header,
                  int8_t width_in_bytes,
                  int8_t offset_in_bytes,
                  bool is_relative,
                  std::string comment = ""); // c'tor of udk component from packet
    udk_component(udk_component_type component_type, uint32_t value, std::string comment = ""); // c'tor of all other types
    udk_component(const udk_component& _component);                                             // copy c'tor
    uint16_t get_width_in_bits() const;
    uint16_t get_width_on_key_in_bits() const;
    bool is_intersecting(const udk_component& _component) const;
    void set_description(std::string comment);
    std::string generate_udk_component_to_string() const;
};

struct udk_table_id_and_components {
    uint16_t udk_table_id;
    std::vector<udk_component> udk_components;
    udk_table_id_and_components();
    udk_table_id_and_components(uint16_t _udk_table_id, const std::vector<udk_component>& _udk_components);
};

struct place_udk_info_per_table {
    uint16_t udk_table_id;
    uint8_t number_of_udk_components;
    explicit place_udk_info_per_table(const udk_table_id_and_components& table_components);
    place_udk_info_per_table();
};

struct place_udk_command {
    uint16_t macro_id = 0;
    uint8_t number_of_udk_tables = 0;
    uint16_t number_of_udk_components = 0;
    place_udk_info_per_table place_udk_tables_info[UDK_MAX_TABLES_PER_PLACEMENT] = {place_udk_info_per_table()};
    uint8_t values[UDK_MAX_DATA_SIZE] = {0};
    place_udk_command();
    place_udk_command(uint16_t _macro_id, const std::vector<udk_table_id_and_components>& udk_tables_components);
    size_t get_command_len() const;
};
#pragma pack(pop)

struct udk_translation_info {
    struct placement_info_t {
        struct fragment_info_t {
            int16_t offset;
            uint16_t width;
            uint16_t processed_index;
            int16_t offset_in_component;
            fragment_info_t();
            fragment_info_t(const fragment_info_t& _fragment_info);
            fragment_info_t(int16_t offset, uint16_t width, uint16_t processed_index, int16_t offset_in_component);
        };
        std::vector<fragment_info_t> fragments_vec;
        char description[MAX_COMPONENT_DESCRIPTION_SIZE];
        int16_t minimal_offset = INT16_MAX; // the base offset of all fragments
        uint16_t total_width = 0;           // the full width of all fragments
        placement_info_t();
        void add_placement_info(int16_t _offset,
                                size_t _width,
                                size_t _processed_index,
                                uint16_t offset_in_component,
                                const char _description[MAX_COMPONENT_DESCRIPTION_SIZE]);
    };
    placement_info_t placement_info[MAX_NUMBER_OF_UDK_COMPONENTS];
    size_t number_of_components = 0;
    size_t physical_key_width = 0;
    std::vector<std::pair<uint16_t /*offset*/, uint16_t /*width*/>> constant_bits_per_key_part;
    udk_translation_info();
    int16_t get_udk_component_offset_on_key_in_bits(size_t component_index);
    size_t get_udk_component_width_in_bits(size_t component_index);
    std::string get_key_info(const std::string& key);
    void clean();
};

#endif // RUNTIME_FLEXIBILITY_TYPES_H
