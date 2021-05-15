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

#include <memory>

#include "common/defines.h"
#include "common/file_utils.h"
#include "state_writer.h"
#include "system/la_device_impl.h"

using namespace std;

namespace silicon_one
{
state_writer::state_writer(ll_device_sptr m_ll_device, la_device::save_state_options options)
    : m_ll_device(m_ll_device), m_options(options), m_lld_block(m_ll_device->get_device_tree())
{
    m_root_json = json_object();
}

state_writer::~state_writer()
{
    if (m_root_json != nullptr) {
        json_decref(m_root_json);
    }
}

json_t*
state_writer::acquire_json_tree()
{
    json_t* root = m_root_json;
    m_root_json = nullptr;
    return (root);
}

bool
state_writer::should_include(lld_register_scptr reg) const
{
    if (m_options.include_all) {
        return true;
    }

    auto reg_desc = reg->get_desc();

    if (m_options.include_config && reg_desc->type == lld_register_type_e::CONFIG) {
        return true;
    }

    if (m_options.include_volatile && reg_desc->is_volatile()) {
        return true;
    }

    if (m_options.include_counters && reg_desc->include_counter) {
        return true;
    }

    if (m_options.include_status && reg_desc->include_status) {
        return true;
    }

    return false;
}

bool
state_writer::should_include(lld_memory_scptr mem) const
{
    if (m_options.include_all) {
        return true;
    }

    auto mem_desc = mem->get_desc();
    if (m_options.include_volatile && mem_desc->is_volatile()) {
        return true;
    }

    auto mem_type = mem_desc->type;
    if (m_options.include_config && (mem_type == lld_memory_type_e::CONFIG)) {
        return true;
    }

    return false;
}

la_status
state_writer::get_register_value(lld_register_scptr reg, bit_vector& out_value) const
{
    if (m_options.reset_on_read) {
        return (m_ll_device->read_register((*reg), out_value));
    } else {
        return (m_ll_device->peek_register((*reg), out_value));
    }
}

void
state_writer::build_tree_json()
{
    std::string key_str;
    if (m_ll_device->is_gibraltar()) {
        key_str = "gibraltar_tree";
    } else if (m_ll_device->get_device_revision() == la_device_revision_e::ASIC4_A0) {
        key_str = "asic4_tree";
    } else if (m_ll_device->is_asic5()) {
        key_str = "asic5_tree";
    } else {
        key_str = "pacific_tree";
    }
    json_t* m_root_value = json_object();
    json_object_set_new(m_root_json, key_str.c_str(), m_root_value);
    lld_block_to_json(m_lld_block, m_root_value);
}

void
state_writer::lld_block_to_json(lld_block_scptr block, json_t* json_block)
{
    if (block->is_valid()) {
        leaf_lld_block_to_json(block, json_block);
    } else {
        complex_lld_block_to_json(block, json_block);
    }
}

void
state_writer::leaf_lld_block_to_json(lld_block_scptr block, json_t* json)
{
    json_object_set_new(json, "block_id", json_integer(block->get_block_id()));
    lld_block::lld_register_vec_t registers_vec = block->get_registers();
    for (auto reg : registers_vec) {
        if (!should_include(reg)) {
            continue;
        }

        std::string key_str = reg->get_short_name();
        json_object_set_new(json, key_str.c_str(), json_string("INVALID"));
        m_map.emplace(reg, json);
    }

    lld_block::lld_memory_vec_t memories_vec = block->get_memories();
    for (auto mem : memories_vec) {
        if (!should_include(mem)) {
            continue;
        }

        json_object_set_new(json, mem->get_short_name().c_str(), json_string("INVALID"));
        m_map.emplace(mem, json);
    }
}

void
state_writer::complex_lld_block_to_json(lld_block_scptr block, json_t* json)
{
    lld_block::lld_block_vec_t sub_blocks_vec = block->get_blocks();
    size_t num_blocks = sub_blocks_vec.size();
    std::string current_block_name = "";
    std::string next_block_name = "";
    int index = -1;
    json_t* json_sub_block = nullptr;
    for (size_t i = 0; i < num_blocks; i++) {
        lld_block_scptr sub_block = sub_blocks_vec[i];
        std::string current_block_name = sub_block->get_template_name();
        if (current_block_name == "") {
            continue;
        }

        if (i < num_blocks - 1) {
            next_block_name = sub_blocks_vec[i + 1]->get_template_name();
            if (current_block_name == next_block_name) {
                index = (index > 0) ? index : 0;
            }
        }

        std::string current_block_json_name;
        if (index > -1) {
            // TODO: Use JSON lists
            current_block_json_name = current_block_name + "[" + std::to_string(index) + "]";
            index++;
        } else {
            current_block_json_name = current_block_name;
        }

        json_sub_block = json_object();
        lld_block_to_json(sub_block, json_sub_block);
        if (json_sub_block != nullptr) {
            json_object_set_new(json, current_block_json_name.c_str(), json_sub_block);
        }

        if (current_block_name != next_block_name) {
            index = -1;
        }
    }
}

json_t*
state_writer::get_register_subfields_json(const lld_register_desc_t* desc, const bit_vector& value)
{
    json_t* json_sub_block = json_object();
    la_entry_addr_t addr = desc->addr;
    json_object_set_new(json_sub_block, "address", json_integer(addr));
    for (auto field : desc->fields) {
        // export requested types of fields
        if (m_options.include_all                                                                   // all fields
            || (m_options.include_status && (field.type == lld_storage_field_type_e::STATUS))       // status fields only
            || (m_options.include_config && (field.type == lld_storage_field_type_e::CONFIG))       // config fields only
            || (m_options.include_counters && (field.type == lld_storage_field_type_e::COUNTER))) { // counter fields only
            json_object_set_new(
                json_sub_block, field.name.c_str(), json_integer(value.bits_from_lsb(field.lsb, field.width_in_bits).get_value()));
        }
    }
    return json_sub_block;
}

la_status
state_writer::fill_json_with_real_storage_values()
{
    la_status status;
    bit_vector value;

    for (auto it : m_map) {
        if (it.first->is_register()) {
            lld_register_scptr reg = std::static_pointer_cast<const lld_register>(it.first);
            const lld_register_desc_t* desc = reg->get_desc();
            status = get_register_value(reg, value);
            return_on_error(status);
            std::string key_str = reg->get_short_name();
            json_object_set_new(it.second, key_str.c_str(), json_string(value.to_string().c_str()));
            if (m_options.verbose_subfields) {
                json_object_set_new(it.second, key_str.c_str(), get_register_subfields_json(desc, value));
            }
        } else {
            lld_memory_scptr mem(static_pointer_cast<const lld_memory>(it.first));
            json_t* json_memory = json_array();
            for (size_t line = 0; line < mem->get_desc()->entries; line++) {
                status = m_ll_device->read_memory(*mem, line, value);
                return_on_error(status);
                std::string data = value.to_string();
                json_array_append_new(json_memory, json_string(data.c_str()));
            }
            std::string key_str = mem->get_short_name();
            json_object_set_new(it.second, key_str.c_str(), json_memory);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
state_writer::write(std::string fname)
{
    la_status stat = file_utils::write_json_to_file(m_root_json, fname);
    return stat;
}

la_status
state_writer::fill()
{
    build_tree_json();
    return (fill_json_with_real_storage_values());
}

la_status
state_writer::fill(json_t*& in_root, std::string in_str)
{
    json_object_set_new(m_root_json, in_str.c_str(), in_root);
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
