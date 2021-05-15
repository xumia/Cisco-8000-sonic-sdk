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

#ifndef __SOCKET_COMMAND_H__
#define __SOCKET_COMMAND_H__

#include <string.h>
#include <stdint.h>
#include <vector>
#include <iomanip>
#include <string>
#include <sstream>
#include <iostream>
#include <cinttypes>
#include <assert.h>
#include <cstddef>
#include "utils/list_macros.h"
#include "rpc_socket_command.h"

#include <chrono>

//
// Useful aliases for keeping track of durations
//
using HiResClock = std::chrono::high_resolution_clock;
using FloatSec = std::chrono::duration<float>;

#ifdef __GNUC__
#define PACKED(class_to_pack) class_to_pack __attribute__((__packed__))
#else
#define PACKED(class_to_pack) __pragma(pack(push, 1)) class_to_pack __pragma(pack(pop))
#endif
namespace dsim
{

struct ext_asic_specific_t {
    uint32_t ext_dma_pd_base_lsb_reg_0;
    uint32_t ext_dma_pd_base_msb_reg_0;
    uint32_t ext_dma_wr_pd_ptr_reg_0;
    uint32_t ext_dma_rd_pd_ptr_reg_0;
    uint32_t ext_dma_pd_length_reg_0;
    uint32_t ext_dma_data_base_lsb_reg_0;
    uint32_t ext_dma_data_base_msb_reg_0;
    uint32_t ext_dma_wr_data_ptr_reg_0;
    uint32_t ext_dma_rd_data_ptr_reg_0;
    uint32_t ext_dma_data_length_reg_0;
    uint32_t ext_dma_cfg_reg_0;
};

struct inj_asic_specific_t {
    uint32_t inj_dma_pd_base_lsb_reg_0;
    uint32_t inj_dma_pd_base_msb_reg_0;
    uint32_t inj_dma_wr_pd_ptr_reg_0;
    uint32_t inj_dma_rd_pd_ptr_reg_0;
    uint32_t inj_dma_pd_length_reg_0;
    uint32_t inj_dma_cfg_reg_0;
};

//
// We serialize all the register addresses and names between the client and server.
// This is the amount of space we reserve for that serialized data.
//
#define MAX_PACKET_DMA_REG_ADDRESSES_SERIALIZED_DATA 128
#define MAX_PACKET_DMA_REG_NAMES_SERIALIZED_DATA 600

struct packet_dma_info_t {
    uint8_t reg_addresses[MAX_PACKET_DMA_REG_ADDRESSES_SERIALIZED_DATA];
    uint8_t reg_names[MAX_PACKET_DMA_REG_NAMES_SERIALIZED_DATA];
    uint32_t sbif_block_id;
};

// Size in bytes of the cpu_read & cpu_read_result registers
// Used for counter read protocol between DSIM server/client.
#define COUNTER_CPU_READ_RESULT_CONCATENATED_SIZE (32)

//
// Currently enough for 96 banks * 10 bytes (asic3). To keep the client
// to server API simple we always send this size, regardless of the platform.
//
#define COUNTER_CPU_READ_MAX_COUNTERS_SIZE (960)

#define DEVICE_INFO_STR_MAX 32
#define DEVICE_INFO_REG_STR_MAX 64

/// Client id is intended to be a unique identifier, assigned by the device simulator.  The client uses this
/// when communicating with the server.
typedef uint32_t client_id_t;

/// Seqno is intended to be a monotonically increasing sequence number, used to ensure the client and server
/// are in sync about the current message.
typedef uint64_t client_seqno_t;

struct device_info {
    char device_name[DEVICE_INFO_STR_MAX];
    char device_revision[DEVICE_INFO_STR_MAX];
    char reg_cpu_read_name[DEVICE_INFO_REG_STR_MAX];
    char reg_cpu_read_result_name[DEVICE_INFO_REG_STR_MAX];
    char max_counters_table_name[DEVICE_INFO_REG_STR_MAX];
    client_id_t client_id;
    uint32_t sim_access_block_id;
    uint32_t sim_access_mem_address_place_udk;
    uint32_t sim_access_nsim_command_mem;
    uint64_t counters_cpu_read_address;
    uint32_t counters_cpu_read_width;
    uint64_t counters_cpu_counter_read_result_address;
    uint32_t counters_cpu_counter_read_result_width;
    uint64_t counters_max_counters_address_begin;
    uint64_t counters_max_counters_address_end;
    uint16_t counters_max_counters_address_entry_width_in_bytes;
    //
    // Padding to avoid any alignment issues if the client and server are compiled differently.
    //
    uint16_t pad;
    struct packet_dma_info_t packet_dma_info;
    size_t num_of_commands_to_dump_on_crash;

    device_info()
    {
        memset(this, 0, sizeof(device_info));
    }
};

// Maximum size of the socket command buffer (1Mb)
#define SOCKET_COMMAND_BUFFER_LEN (1 * 1024 * 1024)
#define SOCKET_COMMAND_BUFFER_HEADER_LEN sizeof(socket_command_header)

// VERSION_HANDSHAKE must stay value 7 for forward/backward compatibility reasons.

// clang-format off
#define SOCKET_COMMAND_ENUMS(list_macro)                          \
    list_macro(WRITE_MEMORY,                                 0),  \
    list_macro(READ_MEMORY,                                  1),  \
    list_macro(WRITE_REGISTER,                               2),  \
    list_macro(READ_REGISTER,                                3),  \
    list_macro(INJECT_PACKET,                                4),  \
    list_macro(EXTRACT_PACKETS,                              5),  \
    list_macro(DEVICE_INFO_SYNC,                             6),  \
    list_macro(VERSION_HANDSHAKE,                            7),  \
    list_macro(LOG_MESSAGE,                                  8),  \
    list_macro(ADD_PROPERTY,                                 9),  \
    list_macro(WRITE_MEMORY_BY_NAME,                         10), \
    list_macro(READ_MEMORY_BY_NAME,                          11), \
    list_macro(WRITE_REGISTER_BY_NAME,                       12), \
    list_macro(READ_REGISTER_BY_NAME,                        13), \
    list_macro(RESET_STATE,                                  14), \
    list_macro(DUMP_DEBUG_INFO,                              20), \
    list_macro(FLUSH,                                        21), \
    list_macro(PING,                                         22), \
    list_macro(DESTROY_SIMULATOR,                            23), \
    list_macro(SET_LOG_FILE,                                 24), \
    list_macro(SET_LOG_LEVEL,                                25), \
    list_macro(PACKET_DMA_ENABLE,                            26), \
    list_macro(INJECT_PACKET_DESC,                           27), \
    list_macro(STEP_PACKET,                                  28), \
    list_macro(STEP_MACRO,                                   29), \
    list_macro(STEP,                                         30), \
    list_macro(TRIGGER_LRC_FIFO,                             31), \
    list_macro(GET_PACKET,                                   32), \
    list_macro(GET_PACKETS,                                  33), \
    list_macro(INJECT_DB_TRIGGER,                            35), \
    list_macro(GET_CONNECTION_HANDLE,                        39), \
    list_macro(GET_DEVICE_NAME,                              40), \
    list_macro(SET_EXPOSE_NPU_HOST,                          43), \
    list_macro(GET_AND_CLEAR_EVENT_QUEUE,                    44), \
    list_macro(SET_SLICE_CONTEXT,                            45), \
    list_macro(CLEAR_ALL_DEVICE_STATE,                       48), \
    list_macro(GET_ENTRY,                                    49), \
    list_macro(GET_EVENT_QUEUE_READ_PTR,                     50), \
    list_macro(GET_EVENT_QUEUE_WRITE_PTR,                    51), \
    list_macro(GET_LPM_ENTRY,                                52), \
    list_macro(GET_NUM_LOG_MESSAGES,                         53), \
    list_macro(GET_NUM_PACKET_WAITING_TO_BE_INJECTED,        54), \
    list_macro(GET_PORT_CONFIG,                              55), \
    list_macro(GET_TERNARY_ENTRY,                            56), \
    list_macro(IS_PORT_UP,                                   57), \
    list_macro(SET_MODULE_FILE_LOG_LEVEL,                    63), \
    list_macro(SET_MODULE_STDOUT_LOG_LEVEL,                  64), \
    list_macro(SET_OVERSUBSCRIBED_INTERFACES_DETECTION_MODE, 66), \
    list_macro(GET_AND_CLEAR_OUTPUT_PACKETS,                 69), \
    list_macro(GET_TABLE_ID_BY_NAME,                         72),

// clang-format on

// Available commands, this must be 4 bytes long for forward/backward compatibility reasons.
enum class socket_command_type_e : uint32_t { SOCKET_COMMAND_ENUMS(LIST_MACRO_FIXED_ENUM_VALUE) };

//
// Convert socket_command_type_e to a string
//
static inline const std::string
to_string(const socket_command_type_e cmd)
{
    static std::vector<std::string> names = {SOCKET_COMMAND_ENUMS(LIST_MACRO_FIXED_ENUM_STRING)};
    if ((size_t)cmd >= names.size()) {
        return std::string("invalid socket_command_type_e:") + std::to_string(static_cast<int>(cmd));
    }
    return names[static_cast<int>(cmd)];
}

union socket_command_flags_u {
    struct {
        bool expecting_reply : 1; ///< Command conditionally sends a response, and the client expects a reply
        uint8_t padding : 7;
    };
    uint8_t all_flags;

    void append_flags(std::string& out)
    {
        std::stringstream stream;
        stream << "0x" << std::hex << all_flags;

        out += stream.str();

        if (all_flags != 0) {
            out += "(";
        }

        if (expecting_reply) {
            out += "EXPECTING_REPLY";
        }

        if (all_flags != 0) {
            out += ")";
        }
    }
};

// expecting_reply = false
struct write_memory_socket_command {
    uint32_t block_id;
    uint32_t memory_address;
    uint16_t memory_addr_width;
    uint16_t entry_count;
    uint8_t payload[1];

private:
    write_memory_socket_command(write_memory_socket_command const&) = delete;
    write_memory_socket_command& operator=(write_memory_socket_command const&) = delete;
};

constexpr size_t WRITE_MEMORY_SOCKET_COMMAND_SIZE = offsetof(write_memory_socket_command, payload);

// Version handshake has this shape because it is is used to communicate
// between different versions of npsuite that may have a different protocol
// version.  We need to enable upgrade/downgrade of a running SDK + NSIM instance,
// so this command needs to stay the same shape as it has since npsuite release 1.67.
#define VERSION_HANDSHAKE_SOCKET_COMMAND_REQUIRED_PADDING 12
#define VERSION_HANDSHAKE_SOCKET_COMMAND_BUFFER_LEN 2048
PACKED(struct version_handshake_socket_command {
    socket_command_type_e cmd;
    uint8_t padding[VERSION_HANDSHAKE_SOCKET_COMMAND_REQUIRED_PADDING];
    uint8_t data[VERSION_HANDSHAKE_SOCKET_COMMAND_BUFFER_LEN];
});
typedef enum version_handshake_result_e { VERSION_HANDSHAKE_MISMATCH = 0, VERSION_HANDSHAKE_OK } version_handshake_result_e;

// expecting_reply = true
struct read_memory_socket_command {
    uint32_t block_id;
    uint32_t memory_address;
    uint16_t memory_addr_width;
    uint16_t entry_count;
};

// expecting_reply = sometimes
struct write_register_socket_command {
    uint32_t block_id;
    uint32_t reg_address;
    uint16_t reg_addr_width;
    uint16_t entry_count;
    uint8_t payload[1];

private:
    write_register_socket_command(write_register_socket_command const&) = delete;
    write_register_socket_command& operator=(write_register_socket_command const&) = delete;
};

constexpr size_t WRITE_REGISTER_SOCKET_COMMAND_SIZE = offsetof(write_register_socket_command, payload);

// expecting_reply = true
struct read_register_socket_command {
    uint32_t block_id;
    uint32_t reg_address;
    uint16_t reg_addr_width;
    uint16_t entry_count;
};

// expecting_reply = false
struct inject_packet_socket_command {
    uint32_t ctx_id;
    uint16_t packet_size;
};

// expecting_reply = true
struct extract_packets_socket_command {
    uint32_t ctx_id;
    uint32_t bytes_available;
    uint16_t packets_available;
};

// expecting_reply = false
struct log_message_socket_command {
    uint32_t log_level;
    uint8_t log_message[1];

private:
    log_message_socket_command(log_message_socket_command const&) = delete;
    log_message_socket_command& operator=(log_message_socket_command const&) = delete;
};

constexpr size_t LOG_MESSAGE_SOCKET_COMMAND_SIZE = offsetof(log_message_socket_command, log_message);

///////////////////////////////////////////////////////////////////////////////
// write memory by name
///////////////////////////////////////////////////////////////////////////////

// expecting_reply = false
struct write_memory_by_name_socket_command {
    uint32_t mem_index;
    uint32_t mem_address;
    uint16_t mem_width;
    uint16_t entry_count;
    uint16_t mem_name_len;
    uint8_t payload[1];

private:
    write_memory_by_name_socket_command(write_memory_by_name_socket_command const&) = delete;
    write_memory_by_name_socket_command& operator=(write_memory_by_name_socket_command const&) = delete;
};

constexpr size_t WRITE_MEMORY_BY_NAME_SOCKET_COMMAND_SIZE = offsetof(write_memory_by_name_socket_command, payload);

///////////////////////////////////////////////////////////////////////////////
// read memory by name
///////////////////////////////////////////////////////////////////////////////

struct read_memory_by_name_socket_command {
    uint32_t mem_index;
    uint32_t mem_address;
    uint16_t mem_width;
    uint16_t entry_count;
    uint16_t mem_name_len;
    uint8_t mem_name[1];

private:
    read_memory_by_name_socket_command(read_memory_by_name_socket_command const&) = delete;
    read_memory_by_name_socket_command& operator=(read_memory_by_name_socket_command const&) = delete;
};

constexpr size_t READ_MEMORY_BY_NAME_SOCKET_COMMAND_SIZE = offsetof(read_memory_by_name_socket_command, mem_name);

///////////////////////////////////////////////////////////////////////////////
// write register by name
///////////////////////////////////////////////////////////////////////////////

// expecting_reply = maybe
// reg_name_len bytes of payload is the register name,
// followed by the register value.
struct write_register_by_name_socket_command {
    uint32_t reg_index;
    uint16_t reg_width;
    uint16_t entry_count;
    uint16_t reg_name_len;
    uint8_t payload[1];

private:
    write_register_by_name_socket_command(write_register_by_name_socket_command const&) = delete;
    write_register_by_name_socket_command& operator=(write_register_by_name_socket_command const&) = delete;
};

constexpr size_t WRITE_REGISTER_BY_NAME_SOCKET_COMMAND_SIZE = offsetof(write_register_by_name_socket_command, payload);

///////////////////////////////////////////////////////////////////////////////
// read register by name
///////////////////////////////////////////////////////////////////////////////

// expecting_reply = true
struct read_register_by_name_socket_command {
    uint32_t reg_index;
    uint16_t reg_width;
    uint16_t entry_count;
    uint16_t reg_name_len;
    uint8_t reg_name[1];

private:
    read_register_by_name_socket_command(read_register_by_name_socket_command const&) = delete;
    read_register_by_name_socket_command& operator=(read_register_by_name_socket_command const&) = delete;
};

constexpr size_t READ_REGISTER_BY_NAME_SOCKET_COMMAND_SIZE = offsetof(read_register_by_name_socket_command, reg_name);

constexpr size_t SOCKET_COMMAND_AS_STRING_REASONABLE_LEN = 16 * 1024;

// seqno and client_id are not used until it has been exchanged during
// device info sync, so device info sync set them
// to 0 when sent.
struct socket_command_header {
    // This field must be 32 bits and must be the first element of
    //   the structure to ensure forwards/backwards compatibility
    socket_command_type_e cmd;    // 32 bits
    client_seqno_t seqno;         // 64 bits
    client_id_t client_id;        // 32 bits
    socket_command_flags_u flags; // 8 bits
    uint8_t payload[1];

    void append_command_name(std::string& out) const
    {
        static std::vector<std::string> command_names = {SOCKET_COMMAND_ENUMS(LIST_MACRO_FIXED_ENUM_STRING)};

        uint8_t cmd_val = static_cast<uint8_t>(cmd);
        if (cmd_val >= command_names.size()) {
            out += "Unknown socket command: " + std::to_string(cmd_val);
        } else {
            out += command_names[cmd_val];
        }
    }

    void append_decoded_write_memory_socket_command(std::string& out) const
    {
        const write_memory_socket_command* wmsc = reinterpret_cast<const write_memory_socket_command*>(payload);
        std::stringstream stream;
        out += ", block id = ";
        out += std::to_string(wmsc->block_id);
        out += ", memory address = 0x";
        stream << std::hex << wmsc->memory_address;
        out += stream.str();
        out += ", memory address width = ";
        out += std::to_string(wmsc->memory_addr_width);
        out += ", entry count = ";
        out += std::to_string(wmsc->entry_count);
    }

    void append_decoded_read_memory_socket_command(std::string& out) const
    {
        const read_memory_socket_command* wmsc = reinterpret_cast<const read_memory_socket_command*>(payload);
        std::stringstream stream;
        out += ", block id = ";
        out += std::to_string(wmsc->block_id);
        out += ", memory address = 0x";
        stream << std::hex << wmsc->memory_address;
        out += stream.str();
        out += ", memory address width = ";
        out += std::to_string(wmsc->memory_addr_width);
        out += ", entry count = ";
        out += std::to_string(wmsc->entry_count);
    }

    void append_decoded_write_register_socket_command(std::string& out) const
    {
        const write_register_socket_command* wrsc = reinterpret_cast<const write_register_socket_command*>(payload);
        std::stringstream stream;
        out += ", block id = ";
        out += std::to_string(wrsc->block_id);
        out += ", register address = 0x";
        stream << std::hex << wrsc->reg_address;
        out += stream.str();
        out += ", register address width = ";
        out += std::to_string(wrsc->reg_addr_width);
        out += ", entry count = ";
        out += std::to_string(wrsc->entry_count);
    }

    void append_decoded_read_register_socket_command(std::string& out) const
    {
        const read_register_socket_command* rrsc = reinterpret_cast<const read_register_socket_command*>(payload);
        std::stringstream stream;
        out += ", block id = ";
        out += std::to_string(rrsc->block_id);
        out += ", register address = 0x";
        stream << std::hex << rrsc->reg_address;
        out += stream.str();
        out += ", register address width = ";
        out += std::to_string(rrsc->reg_addr_width);
        out += ", entry count = ";
        out += std::to_string(rrsc->entry_count);
    }

    void append_decoded_inject_packet_socket_command(std::string& out) const
    {
        const inject_packet_socket_command* ipsc = reinterpret_cast<const inject_packet_socket_command*>(payload);
        out += ", packet size = ";
        out += std::to_string(ipsc->packet_size);
    }

    void append_decoded_extract_packet_socket_command(std::string& out) const
    {
        const extract_packets_socket_command* epsc = reinterpret_cast<const extract_packets_socket_command*>(payload);
        out += ", ctx id = ";
        out += std::to_string(epsc->ctx_id);
        out += ", bytes available = ";
        out += std::to_string(epsc->bytes_available);
        out += ", packets available = ";
        out += std::to_string(epsc->packets_available);
    }

    void append_decoded_log_message_socket_command(std::string& out) const
    {
        const log_message_socket_command* lmsc = reinterpret_cast<const log_message_socket_command*>(payload);
        out += ", log level = ";
        out += std::to_string(lmsc->log_level);
    }

    void append_decoded_write_memory_by_name_socket_command(std::string& out) const
    {
        const write_memory_by_name_socket_command* wmbnsc = reinterpret_cast<const write_memory_by_name_socket_command*>(payload);
        out += ", memory index = ";
        out += std::to_string(wmbnsc->mem_index);
        out += ", memory address = ";
        out += std::to_string(wmbnsc->mem_address);
        out += ", memory width = ";
        out += std::to_string(wmbnsc->mem_width);
        out += ", entry count = ";
        out += std::to_string(wmbnsc->entry_count);
        out += ", memory name len = ";
        out += std::to_string(wmbnsc->mem_name_len);
        out += ", memory name = ";
        out += std::string(reinterpret_cast<const char*>(wmbnsc->payload), static_cast<size_t>(wmbnsc->mem_name_len));
    }

    void append_decoded_read_memory_by_name_socket_command(std::string& out) const
    {
        const read_memory_by_name_socket_command* rmbnsc = reinterpret_cast<const read_memory_by_name_socket_command*>(payload);
        out += ", memory index = ";
        out += std::to_string(rmbnsc->mem_index);
        out += ", memory address = ";
        out += std::to_string(rmbnsc->mem_address);
        out += ", memory width = ";
        out += std::to_string(rmbnsc->mem_width);
        out += ", entry count = ";
        out += std::to_string(rmbnsc->entry_count);
        out += ", memory name len = ";
        out += std::to_string(rmbnsc->mem_name_len);
        out += ", memory name = ";
        out += std::string(reinterpret_cast<const char*>(rmbnsc->mem_name), static_cast<size_t>(rmbnsc->mem_name_len));
    }

    void append_decoded_write_register_by_name_socket_command(std::string& out) const
    {
        const write_register_by_name_socket_command* wrbnsc
            = reinterpret_cast<const write_register_by_name_socket_command*>(payload);
        out += ", register index = ";
        out += std::to_string(wrbnsc->reg_index);
        out += ", register width = ";
        out += std::to_string(wrbnsc->reg_width);
        out += ", entry count = ";
        out += std::to_string(wrbnsc->entry_count);
        out += ", register name len = ";
        out += std::to_string(wrbnsc->reg_name_len);
        out += ", register name = ";
        out += std::string(reinterpret_cast<const char*>(wrbnsc->payload), static_cast<size_t>(wrbnsc->reg_name_len));
    }

    void append_decoded_read_register_by_name_socket_command(std::string& out) const
    {
        const read_register_by_name_socket_command* rrbnsc = reinterpret_cast<const read_register_by_name_socket_command*>(payload);
        out += ", register index = ";
        out += std::to_string(rrbnsc->reg_index);
        out += ", register width = ";
        out += std::to_string(rrbnsc->reg_width);
        out += ", entry count = ";
        out += std::to_string(rrbnsc->entry_count);
        out += ", register name len = ";
        out += std::to_string(rrbnsc->reg_name_len);
        out += ", register name = ";
        out += std::string(reinterpret_cast<const char*>(rrbnsc->reg_name), static_cast<size_t>(rrbnsc->reg_name_len));
    }

    // clang-format off
    // NB: We might want to actually dump the content of the paydeletes.
    void append_decoded_command(std::string& out) const
    {
        switch (cmd) {
        case socket_command_type_e::WRITE_MEMORY:
            append_decoded_write_memory_socket_command(out);
            break;
        case socket_command_type_e::READ_MEMORY:
            append_decoded_read_memory_socket_command(out);
            break;
        case socket_command_type_e::WRITE_REGISTER:
            append_decoded_write_register_socket_command(out);
            break;
        case socket_command_type_e::READ_REGISTER:
            append_decoded_read_register_socket_command(out);
            break;
        case socket_command_type_e::INJECT_PACKET:
            append_decoded_inject_packet_socket_command(out);
            break;
        case socket_command_type_e::EXTRACT_PACKETS:
            append_decoded_extract_packet_socket_command(out);
            break;
        case socket_command_type_e::DEVICE_INFO_SYNC:
            break;
        case socket_command_type_e::VERSION_HANDSHAKE:
            break;
        case socket_command_type_e::LOG_MESSAGE:
            append_decoded_log_message_socket_command(out);
            break;
        case socket_command_type_e::ADD_PROPERTY:
            break;
        case socket_command_type_e::WRITE_MEMORY_BY_NAME:
            append_decoded_write_memory_by_name_socket_command(out);
            break;
        case socket_command_type_e::READ_MEMORY_BY_NAME:
            append_decoded_read_memory_by_name_socket_command(out);
            break;
        case socket_command_type_e::WRITE_REGISTER_BY_NAME:
            append_decoded_write_register_by_name_socket_command(out);
            break;
        case socket_command_type_e::READ_REGISTER_BY_NAME:
            append_decoded_read_register_by_name_socket_command(out);
            break;
        case socket_command_type_e::RESET_STATE:                                  // fallthrough
        case socket_command_type_e::DUMP_DEBUG_INFO:                              // fallthrough
        case socket_command_type_e::FLUSH:                                        // fallthrough
        case socket_command_type_e::PING:                                         // fallthrough
        case socket_command_type_e::DESTROY_SIMULATOR:                            // fallthrough
        case socket_command_type_e::SET_LOG_FILE:                                 // fallthrough
        case socket_command_type_e::SET_LOG_LEVEL:                                // fallthrough
        case socket_command_type_e::PACKET_DMA_ENABLE:                            // fallthrough
        case socket_command_type_e::INJECT_PACKET_DESC:                           // fallthrough
        case socket_command_type_e::STEP_PACKET:                                  // fallthrough
        case socket_command_type_e::STEP_MACRO:                                   // fallthrough
        case socket_command_type_e::STEP:                                         // fallthrough
        case socket_command_type_e::TRIGGER_LRC_FIFO:                             // fallthrough
        case socket_command_type_e::GET_PACKET:                                   // fallthrough
        case socket_command_type_e::GET_PACKETS:                                  // fallthrough
        case socket_command_type_e::GET_AND_CLEAR_OUTPUT_PACKETS:                 // fallthrough
        case socket_command_type_e::INJECT_DB_TRIGGER:                            // fallthrough
        case socket_command_type_e::GET_CONNECTION_HANDLE:                        // fallthrough
        case socket_command_type_e::GET_DEVICE_NAME:                              // fallthrough
        case socket_command_type_e::SET_EXPOSE_NPU_HOST:                          // fallthrough
        case socket_command_type_e::GET_AND_CLEAR_EVENT_QUEUE:                    // fallthrough
        case socket_command_type_e::SET_SLICE_CONTEXT:                            // fallthrough
        case socket_command_type_e::SET_MODULE_FILE_LOG_LEVEL:                    // fallthrough
        case socket_command_type_e::SET_MODULE_STDOUT_LOG_LEVEL:                  // fallthrough
        case socket_command_type_e::CLEAR_ALL_DEVICE_STATE:                       // fallthrough
        case socket_command_type_e::GET_NUM_PACKET_WAITING_TO_BE_INJECTED:        // fallthrough
        case socket_command_type_e::GET_NUM_LOG_MESSAGES:                         // fallthrough
        case socket_command_type_e::GET_ENTRY:                                    // fallthrough
        case socket_command_type_e::GET_LPM_ENTRY:                                // fallthrough
        case socket_command_type_e::GET_TERNARY_ENTRY:                            // fallthrough
        case socket_command_type_e::SET_OVERSUBSCRIBED_INTERFACES_DETECTION_MODE: // fallthrough
        case socket_command_type_e::IS_PORT_UP:                                   // fallthrough
        case socket_command_type_e::GET_PORT_CONFIG:                              // fallthrough
        case socket_command_type_e::GET_EVENT_QUEUE_WRITE_PTR:                    // fallthrough
        case socket_command_type_e::GET_EVENT_QUEUE_READ_PTR:                     // fallthrough
        case socket_command_type_e::GET_TABLE_ID_BY_NAME:                         // fallthrough
            break;
        default:
            out += "Unknown socket command: " + std::to_string(static_cast<uint32_t>(cmd));
            break;
        }
    }
    // clang-format on

    // If you plan to dump a lot of these to string, it might be faster to not allocate
    // a bunch of smaller strings
    void to_string(std::string& out) const
    {
        out = "socket_command(cmd = ";
        append_command_name(out);
        out += ", client_id = ";
        out += std::to_string(client_id);
        out += ", seqno = ";
        out += std::to_string(seqno);
        append_decoded_command(out);
        out += ")";
    }

    std::string to_string() const
    {
        std::string out;
        out.resize(SOCKET_COMMAND_AS_STRING_REASONABLE_LEN);
        this->to_string(out);
        return out;
    }

private:
    socket_command_header(socket_command_header const&) = delete;
    socket_command_header& operator=(socket_command_header const&) = delete;
};

constexpr size_t SOCKET_COMMAND_HEADER_SIZE = offsetof(socket_command_header, payload);

struct transaction_info_t {
    std::string connection_details;
    std::vector<uint8_t> cmd;

    transaction_info_t(const std::string& _connection_details, const socket_command_header* _cmd_hdr, uint32_t _cmd_len)
        : cmd(reinterpret_cast<const uint8_t*>(_cmd_hdr), reinterpret_cast<const uint8_t*>(_cmd_hdr) + _cmd_len)
    {
        connection_details = _connection_details;
        assert(_cmd_len >= SOCKET_COMMAND_HEADER_SIZE && "Command length provided is larger than maximum");
    }

    const socket_command_header* cmd_hdr() const
    {
        return reinterpret_cast<const socket_command_header*>(&cmd[0]);
    }

    uint32_t cmd_len() const
    {
        return static_cast<uint32_t>(cmd.size());
    }

    transaction_info_t(const transaction_info_t& ti) = delete;

    transaction_info_t(transaction_info_t&& ti) noexcept
        : connection_details(std::move(ti.connection_details)), cmd(std::move(ti.cmd))
    {
    }
};

} // namespace dsim

#endif // __SOCKET_COMMAND_H__
