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

#include "init_configurator.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "system/la_device_impl.h"

#include "common/logger.h"

#include <jansson.h>
#include <sstream>
#include <stdlib.h>

static const char DEFAULT_INIT_CONFIGURATION_FILE[] = "res/gibraltar_init_configuration.json";
static const char DEFAULT_BASE_OUTPUT_DIR[] = "out/noopt-debug";

static const char INIT_CONFIGURATION_FILE_ENVVAR[] = "INIT_CONFIGURATION_FILE";
static const char BASE_OUTPUT_DIR_ENVVAR[] = "BASE_OUTPUT_DIR";

namespace silicon_one
{

//*****************************
// init_configurator
//*****************************
la_device_impl*
init_configurator::get_device() const
{
    return m_device;
}

json_t*
init_configurator::read_object(json_t* data, const char* tag)
{
    json_t* ret = json_object_get(data, tag);
    if (ret == nullptr) {
        log_err(HLD, "Could not read tag: %s", tag);
    }

    return ret;
}

init_configurator::init_configurator(la_device_impl* device)
    : m_device(device), m_gibraltar_tree(device->get_ll_device()->get_gibraltar_tree()), m_root(nullptr)
{
    dassert_crit(m_gibraltar_tree != nullptr);
}

la_status
init_configurator::initialize()
{
    dassert_crit(m_root == nullptr);

    const char* init_configuration_filename_env = getenv(INIT_CONFIGURATION_FILE_ENVVAR);
    const char* base_outdir_env = getenv(BASE_OUTPUT_DIR_ENVVAR);

    std::stringstream ss;
    if (init_configuration_filename_env) {
        ss << init_configuration_filename_env;
    } else if (base_outdir_env) {
        ss << base_outdir_env << "/" << DEFAULT_INIT_CONFIGURATION_FILE;
    } else {
        ss << DEFAULT_BASE_OUTPUT_DIR << "/" << DEFAULT_INIT_CONFIGURATION_FILE;
    }

    std::string init_configuration_filename = ss.str();

    log_info(HLD, "Loading init_configuration from %s.", init_configuration_filename.c_str());

    json_error_t error;

    m_root = json_load_file(init_configuration_filename.c_str(), 0, &error);
    if (!m_root) {
        log_err(HLD, "Loading init_configuration failed. Could not open file %s.", init_configuration_filename.c_str());
        return LA_STATUS_SUCCESS;
    }

    log_debug(HLD, "Done loading init_configuration");

    return LA_STATUS_SUCCESS;
}

la_status
init_configurator::destroy()
{
    if (!m_root) {
        return LA_STATUS_SUCCESS;
    }

    dassert_crit(m_root != nullptr);
    json_decref(m_root);
    m_root = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
init_configurator::configure_device(init_step_e init_step)
{
    if (!m_root) {
        return LA_STATUS_SUCCESS;
    }

    std::string init_step_string = to_tag_string(init_step);

    log_debug(HLD, "Start initializing init_step %s", init_step_string.c_str());

    la_status status = configure_device_in_init_step(init_step_string);

    log_debug(HLD, "Finish initializing init_step %s", init_step_string.c_str());

    return status;
}

la_status
init_configurator::configure_device_in_init_step(const std::string init_step_string)
{
    dassert_crit(m_root != nullptr);

    json_t* device_multiple_modes_config = json_object_get(m_root, init_step_string.c_str());
    if (!device_multiple_modes_config) {
        log_err(HLD, "No %s configuration found.", init_step_string.c_str());
        return LA_STATUS_ENOTFOUND;
    }

    std::string device_mode_string = to_tag_string(m_device->m_device_mode);

    json_t* device_mode_config = json_object_get(device_multiple_modes_config, device_mode_string.c_str());
    if (!device_mode_config) {
        log_err(HLD, "No %s configuration found.", device_mode_string.c_str());
        return LA_STATUS_ENOTFOUND;
    }

    la_status status = configure_device_mode(device_mode_config);

    return status;
}

la_status
init_configurator::configure_device_mode(json_t* device_mode_config)
{
    const char* block_name;
    json_t* block_data;

    json_object_foreach(device_mode_config, block_name, block_data)
    {
        la_status status = configure_block(block_name, block_data);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
init_configurator::configure_block(const char* block_name, json_t* block_data)
{
    log_debug(HLD, "Start initializing block %s", block_name);

    json_t* block_id_json = read_object(block_data, "block_id");
    la_block_id_t block_id = json_integer_value(block_id_json);

    lld_block_scptr block = m_gibraltar_tree->get_block(block_id);
    if (!block) {
        log_err(HLD, "Block %s with block_id %u not found.", block_name, block_id);
        return LA_STATUS_ENOTFOUND;
    }

    la_status status;

    status = configure_block_registers(block, block_data);
    return_on_error(status);

    status = configure_block_memories(block, block_data);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
init_configurator::configure_block_registers(lld_block_scptr block, json_t* block_data)
{
    log_debug(HLD, "Start initializing block %s registers", block->get_name().c_str());

    json_t* register_arr = json_object_get(block_data, "regs");

    if (!register_arr) {
        log_debug(HLD, "No registers to configure");
    }

    lld_register_value_list_t reg_val_list;

    for (size_t i = 0; i < json_array_size(register_arr); i++) {
        json_t* register_data = json_array_get(register_arr, i);

        configure_register(block, register_data, reg_val_list);
    }

    la_status status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status, HLD, ERROR, "Failed to write registers for block %s.", block->get_name().c_str());

    return LA_STATUS_SUCCESS;
}

void
init_configurator::configure_register(lld_block_scptr block, json_t* register_data, lld_register_value_list_t& reg_val_list)
{
    json_t* addr_json = read_object(register_data, "addr");
    json_t* val_json = read_object(register_data, "val");

    dassert_crit(addr_json);
    dassert_crit(val_json);

    la_entry_addr_t addr = json_integer_value(addr_json);
    std::string val = json_string_value(val_json);

    lld_register_scptr reg = block->get_register(addr);

    dassert_crit(reg);

    reg_val_list.push_back({reg, bit_vector(val)});
}

la_status
init_configurator::configure_block_memories(lld_block_scptr block, json_t* block_data)
{
    log_debug(HLD, "Start initializing block %s memories", block->get_name().c_str());

    json_t* mems_json = json_object_get(block_data, "mems");
    if (!mems_json) {
        log_debug(HLD, "No memories to configure");
    }

    const char* memory_name;
    json_t* memory_data;

    json_object_foreach(mems_json, memory_name, memory_data)
    {
        la_status status = configure_memory(block, memory_name, memory_data);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
init_configurator::configure_memory(lld_block_scptr block, const char* memory_name, json_t* memory_data)
{
    log_debug(HLD, "Start initializing block %s memory %s", block->get_name().c_str(), memory_name);

    json_t* is_const_config_json = read_object(memory_data, "is_const_config");
    la_uint8_t is_const_config = json_integer_value(is_const_config_json);

    if (is_const_config == 1) {
        json_t* memory_const_data = read_object(memory_data, "const_config");

        la_status status = configure_memory_const(block, memory_const_data);
        return_on_error(status);
    } else {
        lld_memory_scptr memory = nullptr;
        lld_memory_line_value_list_t mem_line_value_list;
        json_t* memory_line_arr = read_object(memory_data, "var_config");

        for (size_t i = 0; i < json_array_size(memory_line_arr); i++) {
            json_t* memory_line_data = json_array_get(memory_line_arr, i);
            la_status status = configure_memory_line(block, memory, memory_line_data, mem_line_value_list);
            return_on_error(status);
        }
        la_status status = lld_write_memory_line_list(m_device->m_ll_device, mem_line_value_list);
        return_on_error(status, HLD, ERROR, "Failed to write memories for block %s.", block->get_name().c_str());
    }

    return LA_STATUS_SUCCESS;
}

la_status
init_configurator::configure_memory_const(lld_block_scptr block, json_t* memory_const_data)
{
    json_t* addr_json = read_object(memory_const_data, "addr");
    json_t* val_json = read_object(memory_const_data, "val");

    dassert_crit(addr_json);
    dassert_crit(val_json);

    la_entry_addr_t addr = json_integer_value(addr_json);
    std::string val = json_string_value(val_json);

    lld_memory_scptr memory = block->get_memory(addr);
    dassert_crit(memory);

    lld_memory_value_list_t mem_value_list;
    mem_value_list.push_back({memory, bit_vector(val)});

    la_status status = lld_write_memory_list(m_device->m_ll_device, mem_value_list);
    return_on_error(status,
                    HLD,
                    ERROR,
                    "Failed to write const value in memory %s for block %s.",
                    memory->get_name().c_str(),
                    block->get_name().c_str());

    return LA_STATUS_SUCCESS;
}

la_status
init_configurator::configure_memory_line(lld_block_scptr block,
                                         lld_memory_scptr& memory,
                                         json_t* memory_line_data,
                                         lld_memory_line_value_list_t& mem_line_value_list)
{
    json_t* addr_json = read_object(memory_line_data, "addr");
    json_t* val_json = read_object(memory_line_data, "val");

    dassert_crit(addr_json);
    dassert_crit(val_json);

    la_entry_addr_t addr = json_integer_value(addr_json);
    std::string val = json_string_value(val_json);

    if (!memory) {
        memory = block->get_memory(addr);
        dassert_crit(memory);
    }

    lld_memory_desc_t const* mem_desc = memory->get_desc();

    // verify that the address is actually a part of the found memory's space
    if (addr >= (mem_desc->addr + mem_desc->entries)) {
        log_err(HLD, "Got invalid addr %u. Memory base addr %u with %u entries", addr, mem_desc->addr, mem_desc->entries);

        return LA_STATUS_ENOTFOUND;
    }

    size_t mem_line = addr - mem_desc->addr;

    mem_line_value_list.push_back({{memory, mem_line}, bit_vector(val)});

    return LA_STATUS_SUCCESS;
}

std::string
init_configurator::to_tag_string(init_step_e init_step)
{
    static const char* strs[]
        = {[(int)init_step_e::PRE_SOFT_RESET] = "pre_soft_reset", [(int)init_step_e::POST_SOFT_RESET] = "post_soft_reset"};

    if ((size_t)init_step < array_size(strs)) {
        return std::string(strs[(size_t)init_step]);
    }

    dassert_crit(!"Unknown init step");
    return std::string("Unknown init step");
}

std::string
init_configurator::to_tag_string(device_mode_e device_mode)
{
    dassert_crit(device_mode != device_mode_e::INVALID);

    static const char* strs[] = {[(int)device_mode_e::INVALID] = "INVALID",
                                 [(int)device_mode_e::STANDALONE] = "init_mode_sa",
                                 [(int)device_mode_e::LINECARD] = "init_mode_lc",
                                 [(int)device_mode_e::FABRIC_ELEMENT] = "init_mode_fe"};

    if ((size_t)device_mode < array_size(strs)) {
        return std::string(strs[(size_t)device_mode]);
    }

    dassert_crit(!"Unknown device mode");
    return std::string("Unknown device mode");
}

} // namespace silicon_one
