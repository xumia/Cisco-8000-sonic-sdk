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

#include "ra_device_simulator.h"
#include "common/logger.h"

#include "lld/ll_device.h"
#include "lld/pacific_tree.h"

#include "lld/socket_connection/lld_conn_lib.h"

#include <cstdarg>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>

#include <errno.h>

namespace silicon_one
{

//////////////////////////////////
// Logging function to override logger
//////////////////////////////////
static const char* RA_CMD_FILE_MEMS = "./sdk_cmd_file.mems_initialization.txt";
static const char* RA_CMD_FILE_INIT = "./sdk_cmd_file.rest_of_init.txt";
static const char* RA_CMD_FILE_FLOW = "./sdk_cmd_file.flow.txt";

static const char* RA_CMD_MEMS_INIT_DONE = "init_config_memories_done";
static const char* RA_CMD_ARC_CONFIG_STARTED = "arc_configuration_started";
static const char* RA_CMD_ARC_CONFIG_DONE = "arc_configuration_finished";

FILE* s_ra_log_file = nullptr;
lld_conn_h s_ra_log_socket_h = nullptr;
simulator_options current_sim_options;
bool should_use_socket = false;

static std::mutex log_file_lock;

void
ra_log_printf(const char* format, ...)
{
    std::lock_guard<std::mutex> lock(log_file_lock);
    if (s_ra_log_file) {
        va_list args;
        va_start(args, format);

        vfprintf(s_ra_log_file, format, args);
        va_end(args);
    }
}

void
write_message(const char* message)
{
    ra_log_printf("%s\n", message);
}

void
write_message_to_log_file(const char* message)
{
    if (strcmp(message, RA_CMD_MEMS_INIT_DONE) == 0) {
        write_message(message);
        set_logger_file(RA_CMD_FILE_INIT);
        should_use_socket = current_sim_options.use_socket_in_rest_of_init;
        return;
    }
    if (!current_sim_options.use_socket_in_load_arc_microcode) {
        if (strcmp(message, RA_CMD_ARC_CONFIG_STARTED) == 0) {
            should_use_socket = false;
        } else if (strcmp(message, RA_CMD_ARC_CONFIG_DONE) == 0) {
            should_use_socket = current_sim_options.use_socket_in_rest_of_init;
        }
    }

    write_message(message);
}

bool
set_logger_file(const char* file_path)
{
    std::lock_guard<std::mutex> lock(log_file_lock);
    if (s_ra_log_file != nullptr) {
        fflush(s_ra_log_file);
        fclose(s_ra_log_file);
    }

    s_ra_log_file = fopen(file_path, "w");
    if (!s_ra_log_file) {
        fprintf(stderr, "%s: failed opening %s, errno=%d\n", __func__, file_path, errno);
        return false;
    }
    return true;
}

char*
ra_format_message(char* str)
{
    static std::regex line_regex("^(-D-[A-Z]+-[0-9]+- )");
    static std::regex command_regex("^(command::)");

    std::cmatch line_match;
    if (!std::regex_search(str, line_match, line_regex)) {
        return nullptr;
    }

    std::cmatch command_match;
    if (!std::regex_search(line_match[1].second, command_match, command_regex)) {
        size_t start_pos = (size_t)(line_match[1].second - str) - 2;
        str[start_pos] = '#';
        return str + start_pos;
    }

    return str + (size_t)(command_match[1].second - str);
}

void
ra_device_simulator_print(la_device_id_t device_id,
                          la_logger_component_e component,
                          la_logger_level_e sevirity,
                          const char* message)
{
    enum { MESSAGE_BUFFER = 1024 };

    char ra_message[MESSAGE_BUFFER] = {0};
    strncpy(ra_message, message, MESSAGE_BUFFER);

    char* message_to_send = ra_format_message(ra_message);
    if (!message_to_send) {
        // No changes are done - print the message to stdout
        printf("%s\n", message);
        return;
    }

    write_message_to_log_file(message_to_send);
    if (current_sim_options.use_socket && should_use_socket) {
        lld_conn_send_message(s_ra_log_socket_h, message_to_send, strlen(message_to_send));
    }
}

bool
ra_logger_on(la_device_id_t device_id, const char* file_path)
{
    if (!set_logger_file(file_path)) {
        return false;
    }

    logger& linst = logger::instance();
    linst.set_log_function(ra_device_simulator_print);
    linst.set_logging_level(device_id, silicon_one::la_logger_component_e::SIM, silicon_one::la_logger_level_e::DEBUG);
    linst.set_logging_level(device_id, silicon_one::la_logger_component_e::RA, silicon_one::la_logger_level_e::DEBUG);
    linst.set_logging_level(device_id, silicon_one::la_logger_component_e::TABLES, silicon_one::la_logger_level_e::DEBUG);
    linst.set_logging_level(device_id, silicon_one::la_logger_component_e::HLD, silicon_one::la_logger_level_e::DEBUG);

    if (current_sim_options.use_socket) {
        s_ra_log_socket_h = lld_client_connect("localhost", current_sim_options.port, current_sim_options.port + 1);
        if (s_ra_log_socket_h == nullptr) {
            return false;
        }
    }

    return true;
}

void
ra_logger_off(la_device_id_t device_id)
{
    {
        std::lock_guard<std::mutex> lock(log_file_lock);
        if (s_ra_log_file != nullptr) {
            fflush(s_ra_log_file);
            fclose(s_ra_log_file);
            s_ra_log_file = nullptr;
        }
    }

    logger& linst = logger::instance();
    linst.set_log_default_function();
    linst.set_logging_level(device_id, silicon_one::la_logger_component_e::SIM, silicon_one::la_logger_level_e::INFO);
    linst.set_logging_level(device_id, silicon_one::la_logger_component_e::RA, silicon_one::la_logger_level_e::INFO);
    linst.set_logging_level(device_id, silicon_one::la_logger_component_e::TABLES, silicon_one::la_logger_level_e::INFO);
    linst.set_logging_level(device_id, silicon_one::la_logger_component_e::HLD, silicon_one::la_logger_level_e::INFO);

    if (current_sim_options.use_socket && s_ra_log_socket_h != nullptr) {
        lld_conn_destroy(s_ra_log_socket_h);
        s_ra_log_socket_h = nullptr;
        should_use_socket = false;
    }
}

//////////////////////////////////
// Helper utilities
//////////////////////////////////

size_t
construct_absolute_address(size_t block_id, size_t addr)
{
    static const size_t RELATIVE_ADDRESS_WIDTH = 32;
    return addr + (block_id << RELATIVE_ADDRESS_WIDTH);
}

la_block_id_t
address_get_block_id(size_t addr)
{
    return addr >> 32;
}

la_entry_addr_t
address_get_entry_address(size_t addr)
{
    static const size_t ADDR_MASK = ((size_t)1 << 32) - 1;
    return addr & ADDR_MASK;
}

std::string
bytes_to_str(const uint8_t* bytes, size_t bytes_len)
{
    std::stringstream ss;

    for (int i = bytes_len - 1; i >= 0; --i) {
        char buf[3];
        sprintf(buf, "%02x", bytes[i]);
        ss << buf;
    }

    return ss.str();
}

//////////////////////////////////
// ra_device_simulator
//////////////////////////////////

ra_device_simulator::ra_device_simulator(const std::vector<size_t>& block_filter_vec)
{
    if (!block_filter_vec.empty()) {
        m_block_filter.insert(block_filter_vec.begin(), block_filter_vec.end());
    }
}

bool
ra_device_simulator::initialize(la_device_id_t device_id, simulator_options& sim_options)
{
    m_device_id = device_id;
    current_sim_options = sim_options;

    bool ret = ra_logger_on(device_id, RA_CMD_FILE_MEMS);
    should_use_socket = sim_options.use_socket_in_mems_init;
    return ret;
}

ra_device_simulator::~ra_device_simulator()
{
    ra_logger_off(m_device_id);
}

la_device_revision_e
ra_device_simulator::get_device_revision() const
{
    // TODO
    return la_device_revision_e::PACIFIC_A0;
}

la_status
ra_device_simulator::write_register(la_block_id_t block_id,
                                    la_entry_addr_t reg_address,
                                    la_entry_width_t reg_width,
                                    size_t count,
                                    const void* in_val)
{
    if (count != 1) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    const uint8_t* val_uint8 = (const uint8_t*)in_val;

    std::string cmd = "write_reg";
    lld_register_scptr reg = m_pacific_tree->get_register(block_id, reg_address);
    if (reg) {
        // If register does not exist, means that we're writing
        // ouside LBR address space.
        // Let the command pass thru, but no information can be
        // retrieved from our datastructures.
        reg->write_shadow(reg_width, in_val);

        // need to write frontdoor for each reg which is of type 'External', unless backdoor access is implemented (which is not by
        // default for Externals..)
        const lld_register_desc_t* desc = reg->get_desc();
        std::string reg_name(desc->name);
        lld_register_type_e reg_type = desc->type;
        if (reg_type == lld_register_type_e::EXTERNAL) {
            // Workaround till we have backdoor for the following registers
            if (reg_name == "LLD_REGISTER_CDB_CORE_LPM_RD_MOD_WR" || reg_name == "LLD_REGISTER_CDB_CORE_REDUCED_LPM_RD_MOD_WR") {
                cmd = "write_frontdoor";
            }
        }
    }

    send_write_rtl_command(cmd.c_str(), block_id, reg_address, val_uint8, reg_width);

    return LA_STATUS_SUCCESS;
}

la_status
ra_device_simulator::write_memory(la_block_id_t block_id,
                                  la_entry_addr_t mem_address,
                                  la_entry_width_t mem_width,
                                  size_t mem_entries,
                                  const void* in_val)
{
    lld_memory_scptr mem = m_pacific_tree->get_memory(block_id, mem_address);
    if (mem) {
        // If memory does not exist, means that we're writing
        // outside LBR address space.
        // Let the command pass thru, but no information can be
        // retrieved from our datastructures.
        const lld_memory_desc_t* desc = mem->get_desc();
        size_t line = mem_address - desc->addr;
        mem->write_shadow(line, mem_entries, in_val);
    }

    const uint8_t* val = (const uint8_t*)in_val;
    for (size_t i = 0; i < mem_entries; ++i, val += mem_width) {
        send_write_rtl_command("write_mem", block_id, mem_address + i, val, mem_width);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ra_device_simulator::read_register(la_block_id_t block_id,
                                   la_entry_addr_t reg_address,
                                   la_entry_width_t reg_width,
                                   size_t count,
                                   void* out_val)
{
    if (count != 1) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    bool ret = send_read_rtl_command("read_reg", block_id, reg_address, (uint8_t*)out_val, reg_width);

    if (!ret) {
        ra_log_printf("# -> no socket connected or address not found\n");
        return handle_special_registers(block_id, reg_address, reg_width, out_val);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ra_device_simulator::read_memory(la_block_id_t block_id,
                                 la_entry_addr_t mem_address,
                                 la_entry_width_t mem_width,
                                 size_t mem_entries,
                                 void* out_val)
{
    if (mem_entries != 1) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    bool ret = send_read_rtl_command("read_mem", block_id, mem_address, (uint8_t*)out_val, mem_width);

    if (!ret) {
        ra_log_printf("# -> no socket connected or address not found\n");
        return handle_special_memories(block_id, mem_address, mem_width, out_val);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ra_device_simulator::add_property(std::string key, std::string value)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

bool
ra_device_simulator::send_write_rtl_command(const char* cmd, size_t block_id, size_t addr, const uint8_t* val, size_t val_size)
{
    if (!m_block_filter.empty() && m_block_filter.find(block_id) == m_block_filter.end()) {
        return false;
    }

    addr = construct_absolute_address(block_id, addr);
    std::string str = bytes_to_str(val, val_size);

    log_debug(SIM, "command::%s %016zx %zd %s", cmd, addr, val_size, str.c_str());
    return true;
}

bool
ra_device_simulator::send_read_rtl_command(const char* cmd, size_t block_id, size_t addr, uint8_t* out_val, size_t val_size)
{
    if (!m_block_filter.empty() && m_block_filter.find(block_id) == m_block_filter.end()) {
        return false;
    }

    addr = construct_absolute_address(block_id, addr);
    log_debug(SIM, "command::%s %016zx %zd", cmd, addr, val_size);

    if (current_sim_options.use_socket && should_use_socket) {
        uint8_t message[512];
        size_t nbytes = lld_conn_recv_message(s_ra_log_socket_h, message, sizeof(message));
        // First byte of the message is the status
        // 0 - success
        // 1 - timeout
        // 2 - address not found
        uint8_t status = message[0];
        if (status != 0) {
            return false;
        }
        memcpy(out_val, message + 1, nbytes - 1);
        std::string str = bytes_to_str(out_val, nbytes - 1);
        ra_log_printf("# -> received read %016zx %zd %s\n", addr, nbytes - 1, str.c_str());
        return true;
    }
    return false;
}

la_status
ra_device_simulator::handle_special_registers(la_block_id_t block_id,
                                              la_entry_addr_t reg_address,
                                              la_entry_width_t reg_width,
                                              void* out_val)
{
    // LONG LIST OF SPECIAL CASES
    std::map<lld_register_scptr, size_t, lld_register_scptr_ops> reg_val_map{
        // Hard reset
        {m_pacific_tree->slice_pair[0]->idb->top->init_done_status_register, 0x1},
        {m_pacific_tree->sdb->mac->init_done_status_register, 0x1},
        {m_pacific_tree->cdb->top->init_done_status_register, 0x1},
        {m_pacific_tree->rx_pdr->status_register, 0x1},
        {m_pacific_tree->slice_pair[0]->rx_pdr->status_register, 0x1},
        {m_pacific_tree->slice[0]->ifg[0]->sch->oqse_shaper_init, 0x1},
        // CDB ARC status
        {(*m_pacific_tree->cdb->top->access_reg)[36], 0x0},
        {m_pacific_tree->cdb->top->valid_reg, 0x0},
        {m_pacific_tree->cdb->top->arc_mem_start, 0x0},
        // Counters
        {m_pacific_tree->counters->top->cpu_read, 0x400000}};

    for (auto curr : reg_val_map) {
        lld_register_scptr reg = curr.first;
        const lld_register_desc_t* desc = reg->get_desc();
        size_t val = curr.second;
        if (block_id == reg->get_block_id() && reg_address == desc->addr) {
            size_t width = std::min((size_t)reg_width, sizeof(size_t));
            memcpy(out_val, &val, width);

            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
ra_device_simulator::handle_special_memories(la_block_id_t block_id,
                                             la_entry_addr_t mem_address,
                                             la_entry_width_t mem_width,
                                             void* out_val)
{
    lld_memory_scptr mem = m_pacific_tree->get_memory(block_id, mem_address);
    if (mem) {
        // If memory does not exist, means that we're reading
        // outside LBR address space.
        // Let the command pass thru, but no information can be
        // retrieved from our datastructures.
        const lld_memory_desc_t* desc = mem->get_desc();
        size_t line = mem_address - desc->addr;
        mem->read_shadow(line, 1, out_val);
    }

    return LA_STATUS_SUCCESS;
}

bit_vector
read_reg_shadow(lld_register_scptr item)
{
    static const size_t MAX_SIZE = 256;

    const lld_register_desc_t* desc = item->get_desc();

    uint8_t buff[MAX_SIZE];
    item->read_shadow(MAX_SIZE, buff);
    bit_vector bv(desc->width, buff, desc->width_in_bits);

    return bv;
}

bit_vector
read_mem_shadow(lld_memory_scptr item, size_t line)
{
    static const size_t MAX_SIZE = 512;

    const lld_memory_desc_t* desc = item->get_desc();

    uint8_t buff[MAX_SIZE];
    item->read_shadow(line, 1, buff);
    bit_vector bv(desc->width_total, buff, desc->width_total_bits);

    return bv;
}

bool
ra_device_simulator::init_device_done() const
{
    // Infore RTL that init device is done (may be use for save-restore)
    log_debug(SIM, "command::init_device_done");
    should_use_socket = true;
    return set_logger_file(RA_CMD_FILE_FLOW);
}

std::string
ra_device_simulator::check_address(size_t address, const std::string& val, bool is_mem) const
{
    la_block_id_t block_id = address_get_block_id(address);
    la_entry_addr_t entry_addr = address_get_entry_address(address);

    bit_vector sim_val;
    if (is_mem) {
        lld_memory_scptr mem = m_pacific_tree->get_memory(block_id, entry_addr);
        if (!mem) {
            // If memory does not exist, means that we're
            // writing ouside LBR address space.
            // Let the command pass thru, but no information can
            // be retrieved from our datastructures.
            return val;
        }
        const lld_memory_desc_t* desc = mem->get_desc();
        size_t mem_line = entry_addr - desc->addr;
        sim_val = read_mem_shadow(mem, mem_line);
    } else {
        lld_register_scptr reg = m_pacific_tree->get_register(block_id, entry_addr);
        if (!reg) {
            // If register does not exist, means that we're
            // writing ouside LBR address space.
            // Let the command pass thru, but no information can
            // be retrieved from our datastructures.
            return val;
        }
        sim_val = read_reg_shadow(reg);
    }

    // bit_vector exp_val(val, sim_val.get_width());

    return sim_val.to_string();
}

la_status
ra_device_simulator::open_device(int& device_fd, int& interrupt_fd, size_t& interrupt_width_bytes)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

void
ra_device_simulator::close_device(int device_fd, int interrupt_fd)
{
}

} // namespace silicon_one
