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

#include "device_simulator/dsim_client/dsim_client.h"
#include "device_simulator/dsim_client/dsim_socket_client.h"
#include "device_simulator/socket_command.h"
#include "device_simulator/dsim_common/nsim_command.h"
#include "utils/logger/logger.h"
#include "npsuite/version.h"
#include "utils/rpc_serialize.h"
#include "utils/nsim_bv_serializers.h"
#include "nsim/nsim_data_interface_serializers.h"    // for nsim_packet_info_t, nsim_db_trigger_info_t
#include "nsim/nsim_control_interface_serializers.h" // for nsim_source_location_info_t
#include "nsim/nsim_port_config_serializers.h"
#include "dsim_client_msg_util.h"

#include <memory>
#include <map>
#include <csignal>
#include <iterator>
#include <algorithm> // std::count
#include <sstream>
#include <functional>              // for _1, _2
using namespace std::placeholders; // for _1, _2, _3...

#if defined(_WIN32) || defined(_WIN64)

#include <Windows.h>

void
sleep(unsigned seconds)
{
    Sleep(seconds * 1000);
}

#else
#include <unistd.h>
#endif

using namespace npsuite;
namespace dsim
{

//
// (copy of LbrDefinitions to avoid needing lbr headers)
//
// Parse either:
//    "<BLOCK_INSTANCE_NAME>.<MEMORY_NAME>.<SUBFIELD_NAME>" and get the "<SUBFIELD_NAME>" (if present)
//    "<BLOCK_INSTANCE_NAME>.<REGISTER_NAME>.<SUBFIELD_NAME>" and get the "<SUBFIELD_NAME>" (if present)
//
std::vector<std::string>
SplitString(const std::string& str, const std::string& delimiter)
{
    std::vector<std::string> splitted;
    size_t startPos = 0;
    std::string tmpStr = str;
    while ((startPos = tmpStr.find(delimiter)) != str.npos) {
        if (tmpStr.substr(0, startPos).empty() == false) {
            splitted.push_back(tmpStr.substr(0, startPos));
        }
        tmpStr = tmpStr.substr(startPos + delimiter.length());
    }
    splitted.push_back(tmpStr);
    return splitted;
}

static bool
parse_memory_or_register_type_string(const std::string& memory_type_in,
                                     std::string& block_name_out,
                                     std::string& mem_name_out,
                                     std::string& subfield_out)
{
    const char splitchar = '.';
    const std::string splitstr(sizeof(splitchar), splitchar);
    const auto fields = SplitString(memory_type_in, splitstr);
    const auto nseps = std::count(memory_type_in.begin(), memory_type_in.end(), splitchar);

    if (nseps == 2) {
        block_name_out = fields[0];
        mem_name_out = fields[1];
        subfield_out = fields[2];
        return true;
    }

    if (nseps == 1) {
        block_name_out = fields[0];
        mem_name_out = fields[1];
        subfield_out = "";
        return true;
    }

    return false;
}

//
// Given "<BLOCK_INSTANCE_NAME>.<MEMORY_NAME>.<SUBFIELD_NAME>" get the "<SUBFIELD_NAME>" (if present)
//
static bool
parse_memory_type_string(const std::string& memory_type_in,
                         std::string& block_name_out,
                         std::string& mem_name_out,
                         std::string& subfield_out)
{
    return parse_memory_or_register_type_string(memory_type_in, block_name_out, mem_name_out, subfield_out);
}

//
// Given "<BLOCK_INSTANCE_NAME>.<REGISTER_NAME>.<SUBFIELD_NAME>" get the "<SUBFIELD_NAME>" (if present)
//
static bool
parse_register_type_string(const std::string& memory_type_in,
                           std::string& block_name_out,
                           std::string& mem_name_out,
                           std::string& subfield_out)
{
    return parse_memory_or_register_type_string(memory_type_in, block_name_out, mem_name_out, subfield_out);
}

void
dsim_client::dump_debug_info(bool log, bool dump_stats)
{
    //
    // Make sure we flush everything to avoid garbled output.
    //
    std::cout.flush();
    std::cerr.flush();
    fflush(stderr);
    fflush(stdout);

    if (log && ES_LOGGING_ENABLED(m_logger, APP)) {
        if (m_socket_client == nullptr) {
            ESLOG_INSTANCE(m_logger, APP, "Dumping transaction information for DSIM client (no socket):");
        } else {
            ESLOG_INSTANCE(
                m_logger, APP, "Dumping transaction information for DSIM client: " + m_socket_client->get_connection_details());
        }
    } else {
        if (m_socket_client == nullptr) {
            fprintf(stderr, "Dumping transaction information for DSIM client (no socket):\n");
        } else {
            fprintf(
                stderr, "Dumping transaction information for DSIM client: %s\n", m_socket_client->get_connection_details().c_str());
        }
    }

    std::string tmp_string;
    tmp_string.resize(SOCKET_COMMAND_AS_STRING_REASONABLE_LEN);

    if (log) {
        std::lock_guard<std::mutex> guard(m_last_n_commands_mutex);

        for (auto& ti : m_last_n_commands) {
            ti.cmd_hdr()->to_string(tmp_string);
            if (log && ES_LOGGING_ENABLED(m_logger, APP)) {
                ESLOG_INSTANCE(m_logger,
                               APP,
                               string_format("Sent from DSIM client: %s - %s", ti.connection_details.c_str(), tmp_string.c_str()));
            } else {
                fprintf(stderr, "Sent from DSIM client: %s - %s\n", ti.connection_details.c_str(), tmp_string.c_str());
            }
        }
    }

    if (dump_stats) {
        auto prefix = "DSIM client: ";
        if (m_socket_client) {
            m_socket_client->dump_per_socket_stats(prefix);
        }
        socket_connection_common::dump_global_socket_stats(prefix);
    }
}

void
dsim_client::handle_signal(int signal)
{
    if (signal != SIGINT) {
        // If the signal is SIGUSR2, we want the values to go to the log instead of stderr
        dump_debug_info(signal == SIGUSR2, signal == SIGUSR2 /* dump stats */);
    }
}

void
dsim_client::save_transaction_info(const std::string& connection_details, const socket_command_header* cmd_hdr, uint32_t cmd_len)
{
    std::lock_guard<std::mutex> guard(m_last_n_commands_mutex);
    if (m_last_n_commands.size() == m_num_of_commands_to_dump_on_crash) {
        m_last_n_commands.pop_front();
    }
    m_last_n_commands.push_back({connection_details, cmd_hdr, cmd_len});
}

std::string
dsim_client::get_release_version()
{
    return NPSUITE_VERSION;
}

bool
dsim_client::initialize(const char* socket_addr, size_t port, const char* sdk_version)
{
    int num_retries = sdk_version != nullptr ? m_num_connection_retries : 0;
    bool connected = false;
    bool tried_to_connect = false;
    size_t received_bytes = 0;
    size_t expected_reply_length = 0;
    uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE;
    std::string full_version_string;

    auto debug_prefix = "DSIM client connecting to socket: " + std::string(socket_addr) + ":" + std::to_string(port) + " ";
    ESLOG_INSTANCE(m_logger, NSIM_DEBUG, debug_prefix);

    if (m_socket_client != nullptr) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, debug_prefix + "failed: we appear to already be initialized")
        return false;
    }

    //
    // Apply any NSIM socket environment settings found
    //
    config();

    full_version_string = get_release_version();
    full_version_string += "/";
    if (sdk_version != nullptr) {
        full_version_string += sdk_version;
    }
    buffer_size += static_cast<uint32_t>(full_version_string.length() + 1); // +1 For NULL terminator

    assert(buffer_size <= SOCKET_COMMAND_BUFFER_LEN);

    socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(m_socket_command_buffer);
    do {
        if (tried_to_connect == true) {
            ESLOG_INSTANCE(
                m_logger, NSIM_DEBUG, debug_prefix + "failed, retrying in " + std::to_string(m_timeout_between_retries) + "s");
            sleep(m_timeout_between_retries);
        } else {
            tried_to_connect = true;
        }
        m_socket_client = new socket_client(socket_addr, m_logger);
        connected = m_socket_client->init_connection(port);
        if (!connected) {
            ESLOG_INSTANCE(m_logger,
                           NSIM_DEBUG,
                           debug_prefix + "failed to init connection, retrying in " + std::to_string(m_timeout_between_retries)
                               + "s");
            sleep(m_timeout_between_retries);
            delete m_socket_client;
            m_socket_client = nullptr;
            continue;
        }

        //
        // NOTE tests check for the presence of "INIT"
        //
        Logger::setThreadPrefix("INIT (" + m_socket_client->get_connection_details() + ")");

        // Perform NPsuite version handshake
        version_handshake_socket_command* ver_hs_cmd = reinterpret_cast<version_handshake_socket_command*>(m_socket_command_buffer);
        memset(ver_hs_cmd, 0, sizeof(version_handshake_socket_command));
        ver_hs_cmd->cmd = socket_command_type_e::VERSION_HANDSHAKE;
        memcpy(ver_hs_cmd->data, full_version_string.c_str(), full_version_string.length());

        if (!send(buffer_size, cmd_hdr)) {
            ELOG_INSTANCE(m_logger, NSIM_DEBUG, debug_prefix + "failed to send VERSION_HANDSHAKE command");
            sleep(m_timeout_between_retries);
            delete m_socket_client;
            m_socket_client = nullptr;
            connected = false;
            continue;
        }

        // Do we need to do this?
        if (m_num_of_commands_to_dump_on_crash > 0) {
            // Create the "alternate" version handshake command for use in the
            // transaction record
            memset(cmd_hdr, 0, buffer_size);
            cmd_hdr->cmd = socket_command_type_e::VERSION_HANDSHAKE;
            cmd_hdr->flags.expecting_reply = true;
            memcpy(cmd_hdr->payload, full_version_string.c_str(), full_version_string.length());
            save_transaction_info(m_socket_client->get_connection_details(), cmd_hdr, buffer_size);
        }

        version_handshake_result_e validation_result = VERSION_HANDSHAKE_MISMATCH;
        expected_reply_length = sizeof(version_handshake_result_e);
        received_bytes
            = m_socket_client->receive(&validation_result, expected_reply_length, "DSIM client VERSION_HANDSHAKE receive: ");
        if (received_bytes != expected_reply_length) {
            ELOG_INSTANCE(
                m_logger,
                NSIM_DEBUG,
                debug_prefix
                    + "failed: DSIM client VERSION_HANDSHAKE command failed: received bytes different than needed expected "
                    + std::to_string(expected_reply_length)
                    + " received "
                    + std::to_string(received_bytes));
            handle_receive_error(received_bytes, cmd_hdr->cmd);
            sleep(m_timeout_between_retries);
            delete m_socket_client;
            m_socket_client = nullptr;
            connected = false;
            continue;
        }
        handle_receive_success(received_bytes, cmd_hdr->cmd);

        if (validation_result == VERSION_HANDSHAKE_MISMATCH) {
            ESLOG_INSTANCE(m_logger,
                           NSIM_DEBUG,
                           debug_prefix
                               + "failed: DSIM client VERSION_HANDSHAKE DSIM client vs server versions mismatch detected!");
            sleep(m_timeout_between_retries);
            delete m_socket_client;
            m_socket_client = nullptr;
            connected = false;
            continue;
        } else if (validation_result != VERSION_HANDSHAKE_OK) {
            ELOG_INSTANCE(
                m_logger, NSIM_DEBUG, debug_prefix + "failed: DSIM client VERSION_HANDSHAKE command failed: UNKNOWN RESPONSE!");
            sleep(m_timeout_between_retries);
            delete m_socket_client;
            m_socket_client = nullptr;
            connected = false;
            continue;
        }

    } while (num_retries-- > 0 && !connected);

    if (!connected) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, debug_prefix + "failed: out of retries");
        return false;
    }

    ESLOG_INSTANCE(m_logger, NSIM_DEBUG, debug_prefix + "success");

    // Device info sync
    buffer_size = SOCKET_COMMAND_HEADER_SIZE;
    memset(cmd_hdr, 0, buffer_size);
    cmd_hdr->cmd = socket_command_type_e::DEVICE_INFO_SYNC;
    cmd_hdr->flags.expecting_reply = true;

    if (!send_and_save(buffer_size, cmd_hdr)) {
        delete m_socket_client;
        m_socket_client = nullptr;
        return false;
    }

    // receive reply
    expected_reply_length = sizeof(m_dev_info);
    received_bytes = m_socket_client->receive(&m_dev_info, expected_reply_length, "DSIM client version receive: ");
    // check reply
    if (received_bytes != expected_reply_length) {
        delete m_socket_client;
        m_socket_client = nullptr;
        ELOG_INSTANCE(m_logger,
                      NSIM_DEBUG,
                      debug_prefix + "failed: DSIM client DEVICE_INFO_SYNC command : received bytes different than needed expected "
                          + std::to_string(expected_reply_length)
                          + " received "
                          + std::to_string(received_bytes));
        handle_receive_error(received_bytes, cmd_hdr->cmd);
        return false;
    }
    handle_receive_success(received_bytes, cmd_hdr->cmd);

    //
    // Deserialize the packet DMA info
    //
    std::string s1((const char*)m_dev_info.packet_dma_info.reg_addresses, (size_t)sizeof(m_dev_info.packet_dma_info.reg_addresses));
    std::istringstream stream_reg_addresses(s1);

    std::string s2((const char*)m_dev_info.packet_dma_info.reg_names, (size_t)sizeof(m_dev_info.packet_dma_info.reg_names));
    std::istringstream stream_reg_names(s2);

    m_packet_dma_extract.initialize(m_logger, m_socket_client, m_dev_info, stream_reg_addresses, stream_reg_names);
    m_packet_dma_inject.initialize(m_logger, m_socket_client, m_dev_info, stream_reg_addresses, stream_reg_names);

    m_counters_cpu_read_bv.resize(m_dev_info.counters_cpu_read_width);
    m_cpu_counter_read_result_bv.resize(m_dev_info.counters_cpu_counter_read_result_width);

    m_num_of_commands_to_dump_on_crash = m_dev_info.num_of_commands_to_dump_on_crash;
    if (m_num_of_commands_to_dump_on_crash > 0) {
        m_signal_callback_id = SignalHandler::GetInstance().AddCallback(this, &dsim_client::handle_signal);
    }

    m_client_id = m_dev_info.client_id;
    m_next_seqno = 1;

    //
    // Get some register names that we will intercept via "read register by name" to find cached data.
    //
    m_reg_cpu_read_name = std::string(m_dev_info.reg_cpu_read_name);
    m_reg_cpu_read_result = std::string(m_dev_info.reg_cpu_read_result_name);
    m_max_counters_table_name = std::string(m_dev_info.max_counters_table_name);

    return true;
}

//
// Apply any NSIM socket environment settings found
//
void
dsim_client::config(void)
{
    std::string str_val;
    if (socket_connection_common::GetEnvVar("NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT", str_val)) {
        try {
            m_nsim_client_flush_frequency_byte_count = std::stoi(str_val);
        } catch (const std::invalid_argument& e) {
            m_nsim_client_flush_frequency_byte_count = 0;
            ELOG_INSTANCE(m_logger,
                          NSIM_DEBUG,
                          "DSIM client NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT set to invalid value (disabled): "
                              + std::string(e.what()));
        } catch (const std::out_of_range& e) {
            m_nsim_client_flush_frequency_byte_count = 0;
            ELOG_INSTANCE(m_logger,
                          NSIM_DEBUG,
                          "DSIM client NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT out of range (disabled): " + std::string(e.what()));
        }
    }
}

//
// A wrapper for socket_connection send that does extra work upon fail/pass.
//
bool
dsim_client::send(uint64_t len_in_bytes, socket_command_header* cmd_hdr, bool save)
{
    if (!m_socket_client) {
        FLOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client attempting to send on uninitialized socket: " + to_string(cmd_hdr->cmd));
        assert(false && "DSIM client attempting to send on uninitialized socket");
    }

    if (cmd_hdr->cmd != socket_command_type_e::VERSION_HANDSHAKE) {
        cmd_hdr->seqno = m_next_seqno++;
    }

    auto ret = m_socket_client->send(static_cast<size_t>(len_in_bytes), (void*)cmd_hdr, "DSIM client send: ");
    if (ret) {
        handle_send_success(len_in_bytes, cmd_hdr, save);
    } else {
        handle_send_error(len_in_bytes, cmd_hdr);
    }

    return ret;
}

//
// A wrapper for socket_connection send that does extra work upon fail/pass.
// Additionally saves the message to the transaction history.
//
bool
dsim_client::send_and_save(uint64_t len_in_bytes, socket_command_header* cmd_hdr)
{
    handle_pre_send(len_in_bytes, cmd_hdr);

    return send(len_in_bytes, cmd_hdr, true /* save */);
}

//
// Perform common actions prior to sending a command.
//
void
dsim_client::handle_pre_send(uint64_t len_in_bytes, const socket_command_header* cmd_hdr)
{
    //
    // Check to see if this new command will push us over the flush limit.
    // We need to do this pre send as opposed to post send as a number of
    // send commands will expect a reply and injecting a flush would break
    // the protocol.
    //
    if (m_nsim_client_flush_frequency_byte_count <= 0) {
        return;
    }

    //
    // Don't count flush messages towards the messages sent without a response count
    // or we will end up in a recursive loop.
    //
    // Also don't count initial messages where flush would interfere with the protocol.
    //
    if ((cmd_hdr->cmd == socket_command_type_e::FLUSH) || (cmd_hdr->cmd == socket_command_type_e::DEVICE_INFO_SYNC)
        || (cmd_hdr->cmd == socket_command_type_e::VERSION_HANDSHAKE)) {
        return;
    }

    //
    // If we have sent "n" messages without a response, force a flush. This hopefully
    // avoids any TCP issues w.r.t overflow of prequeue bufferes on the server side.
    //
    if (m_socket_client) {
        auto stats = &m_socket_client->m_nsim_per_socket_stats[cmd_hdr->cmd];
        if (stats->tx_bytes_no_flush + len_in_bytes >= m_nsim_client_flush_frequency_byte_count) {
            stats->tx_bytes_no_flush = 0;
            flush();
        }
    }
}

//
// Perform common actions post a successful send of a message to the DSIM server
//
void
dsim_client::handle_send_success(uint64_t len_in_bytes, const socket_command_header* cmd_hdr, bool save)
{
    //
    // Save DSIM client statistics
    //
    if (m_socket_client) {
        //
        // Save per socket statistics
        //
        auto stats = &m_socket_client->m_nsim_per_socket_stats[cmd_hdr->cmd];
        stats->tx_cmds++;
        stats->tx_bytes += len_in_bytes;
        stats->tx_bytes_no_flush += len_in_bytes;

        //
        // Save global socket statistics
        //
        socket_connection_common::m_nsim_global_socket_stats.tx_cmds++;
        socket_connection_common::m_nsim_global_socket_stats.tx_bytes += len_in_bytes;

        if (save) {
            if (m_num_of_commands_to_dump_on_crash > 0) {
                save_transaction_info(m_socket_client->get_connection_details(), cmd_hdr, static_cast<uint32_t>(len_in_bytes));
            }
        }
    }
}

//
// Perform common actions post a failed send of a message to the DSIM server
//
void
dsim_client::handle_send_error(uint64_t len_in_bytes, const socket_command_header* cmd_hdr)
{
    //
    // Save DSIM client statistics
    //
    if (m_socket_client) {
        //
        // Save per socket statistics
        //
        auto stats = &m_socket_client->m_nsim_per_socket_stats[cmd_hdr->cmd];
        stats->tx_error++;
        stats->tx_bytes += len_in_bytes;

        //
        // Save global socket statistics
        //
        socket_connection_common::m_nsim_global_socket_stats.tx_error++;
        socket_connection_common::m_nsim_global_socket_stats.tx_bytes += len_in_bytes;
    }

    //
    // Used to dampen errors, just in case we get a flood of them
    //
    if (last_handle_send_error_time_set) {
        auto now = HiResClock::now();
        FloatSec elapsed = std::chrono::duration_cast<FloatSec>(now - last_handle_send_error_time);
        if (elapsed.count() < handle_send_error_frequency_in_seconds) {
            if (m_socket_client) {
                m_send_error_count++;
                if (m_send_error_count >= m_send_error_count_limit_per_epoch) {
                    if (m_send_error_count == m_send_error_count_limit_per_epoch) {
                        ELOG_INSTANCE(m_logger,
                                      NSIM_DEBUG,
                                      "DSIM client " + to_string(cmd_hdr->cmd)
                                          + " send error (too many errors, stopping reporting): "
                                          + m_socket_client->get_connection_details());
                    }
                } else {
                    ELOG_INSTANCE(m_logger,
                                  NSIM_DEBUG,
                                  "DSIM client " + to_string(cmd_hdr->cmd)
                                      + " send error (not showing full details due to error dampening): "
                                      + m_socket_client->get_connection_details());
                }
            } else {
                ELOG_INSTANCE(m_logger,
                              NSIM_DEBUG,
                              "DSIM client " + to_string(cmd_hdr->cmd)
                                  + " send error (not showing full details due to error dampening), no socket");
            }
            return;
        }
    }

    m_send_error_count = 0;

    if (m_socket_client) {
        ELOG_INSTANCE(m_logger,
                      NSIM_DEBUG,
                      "DSIM client " + to_string(cmd_hdr->cmd) + " send error: " + m_socket_client->get_connection_details());
    } else {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client " + to_string(cmd_hdr->cmd) + " send error, no socket")
    }

    last_handle_send_error_time = HiResClock::now();
    last_handle_send_error_time_set = true;

    dump_debug_info(true /* log */, true /* dump stats */);
}

//
// Perform common actions post a successful send of a message to the DSIM server
//
void
dsim_client::handle_receive_success(uint64_t len_in_bytes, const socket_command_type_e cmd)
{
    //
    // Save DSIM client statistics
    //
    if (m_socket_client) {
        //
        // Save per socket statistics
        //
        auto stats = &m_socket_client->m_nsim_per_socket_stats[cmd];
        stats->rx_cmds++;
        stats->rx_bytes += len_in_bytes;

        //
        // We received something, so we know the DSIM server is alive. Reset the count.
        //
        stats->tx_bytes_no_flush = 0;

        //
        // Save global socket statistics
        //
        socket_connection_common::m_nsim_global_socket_stats.rx_cmds++;
        socket_connection_common::m_nsim_global_socket_stats.rx_bytes += len_in_bytes;
    }
}

//
// Used by the client to try to indicate to the server that it has encountered a read error.
//
void
dsim_client::handle_receive_error(uint64_t len_in_bytes, const socket_command_type_e cmd)
{
    //
    // Save DSIM client statistics
    //
    if (m_socket_client) {
        //
        // Save per socket statistics
        //
        auto stats = &m_socket_client->m_nsim_per_socket_stats[cmd];
        stats->rx_error++;
        stats->rx_bytes += len_in_bytes;

        //
        // Save global socket statistics
        //
        socket_connection_common::m_nsim_global_socket_stats.rx_error++;
        socket_connection_common::m_nsim_global_socket_stats.rx_bytes += len_in_bytes;
    }

    //
    // Used to dampen errors, just in case we get a flood of them
    //
    if (last_handle_receive_error_time_set) {
        auto now = HiResClock::now();
        FloatSec elapsed = std::chrono::duration_cast<FloatSec>(now - last_handle_receive_error_time);
        if (elapsed.count() < handle_receive_error_frequency_in_seconds) {
            if (m_socket_client) {
                m_receive_error_count++;
                if (m_receive_error_count >= m_receive_error_count_limit_per_epoch) {
                    if (m_receive_error_count == m_receive_error_count_limit_per_epoch) {
                        ELOG_INSTANCE(m_logger,
                                      NSIM_DEBUG,
                                      "DSIM client " + to_string(cmd) + " receive error (too many errors, stopping reporting): "
                                          + m_socket_client->get_connection_details());
                    }
                } else {
                    ELOG_INSTANCE(m_logger,
                                  NSIM_DEBUG,
                                  "DSIM client " + to_string(cmd)
                                      + " receive error (not showing full details due to error dampening): "
                                      + m_socket_client->get_connection_details());
                }
            } else {
                ELOG_INSTANCE(m_logger,
                              NSIM_DEBUG,
                              "DSIM client " + to_string(cmd)
                                  + " receive error (not showing full details due to error dampening), no socket");
            }
            return;
        }
    }

    m_receive_error_count = 0;

    if (m_socket_client) {
        ELOG_INSTANCE(
            m_logger, NSIM_DEBUG, "DSIM client " + to_string(cmd) + " receive error: " + m_socket_client->get_connection_details());
    } else {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client " + to_string(cmd) + " receive error, no socket")
    }

    last_handle_receive_error_time = HiResClock::now();
    last_handle_receive_error_time_set = true;

    (void)write_rpc_and_wait_for_status(socket_command_type_e::DUMP_DEBUG_INFO);

    dump_debug_info(true /* log */, true /* dump stats */);
}

dsim_status_e
dsim_client::reset_state(void)
{
    api_lock lock(m_lock);

    if (!m_socket_client || m_socket_client->is_socket_closed()) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client RESET_STATE: client is not initialized and not connected");
        return DSIM_STATUS_ENOTINITIALIZED;
    }

    //
    // Reset packet DMA
    //
    m_packet_dma_inject.reset_state();
    m_packet_dma_extract.reset_state();

    //
    // Reset counters
    //
    m_counters_cpu_read_bv.reset();
    m_cpu_counter_read_result_bv.reset();
    m_counters_max_counter_data.resize(0);

    return write_rpc_and_wait_for_status(socket_command_type_e::RESET_STATE);
}

//
// Flush the DSIM client to server connection. This works by waiting for a response to the flush from the DSIM server. This then
// indicates that the server has finished processing all preceeding messages.
//
dsim_status_e
dsim_client::flush(void)
{
    api_lock lock(m_lock);
    return write_rpc_and_wait_for_status(socket_command_type_e::FLUSH);
}

//
// Dump stats and recent messages to stderr
//
dsim_status_e
dsim_client::dump_debug_info(void)
{
    api_lock lock(m_lock);
    dump_debug_info(true /* log */, true /* dump stats */);
    return write_rpc_and_wait_for_status(socket_command_type_e::DUMP_DEBUG_INFO);
}

dsim_client::dsim_client(int num_connection_retries, int timeout_between_retries) : dsim_client()
{
    set_num_of_connection_retries(num_connection_retries);
    set_timeout_between_retries(timeout_between_retries);
}

dsim_client::dsim_client()
    : m_socket_client(nullptr),
      m_logger(nullptr),
      m_num_connection_retries(0),
      m_timeout_between_retries(1),
      m_num_of_commands_to_dump_on_crash(10),
      m_client_id(0),
      m_next_seqno(0)
{
    m_logger = new npsuite::Logger(
        "" /* log directory */, true /* log prefix enabled */, "client_log.txt" /* log file name */, LOG_FILE_COMPRESSION_DISABLED);
    m_logger->SetStdOutLogLevelForAll(npsuite::NPSUITE_LOG_LEVEL_ESSENTIAL);
    m_logger->SetFileLogLevelForAll(npsuite::NPSUITE_LOG_LEVEL_PROGRESS);
}

/// @brief Get number of connection retries to the server
///
/// @retval Number of connection retries
int
dsim_client::get_num_of_connection_retries()
{
    return m_num_connection_retries;
}

/// @brief Set number of connection retries to the server
///
/// @param[in] num_connection_retries   Number of connection retries
void
dsim_client::set_num_of_connection_retries(int num_connection_retries)
{
    m_num_connection_retries = num_connection_retries;
}

/// @brief Get timeout between retries in seconds
///
/// @retval timeout between retries in seconds
int
dsim_client::get_timeout_between_retries()
{
    return m_timeout_between_retries;
}

/// @brief Set timeout between retries in seconds
///
/// @param[in] timeout_in_sec   timeout between retries in seconds
void
dsim_client::set_timeout_between_retries(int timeout_in_sec)
{
    m_timeout_between_retries = timeout_in_sec;
}

dsim_client::~dsim_client()
{
    if (m_signal_callback_id != SignalHandler::NoCallbackId) {
        SignalHandler::GetInstance().RemoveCallback(m_signal_callback_id);
    }

    if (m_socket_client) {
        if (!m_socket_client->is_socket_closed()) {
            m_socket_client->close_socket();
            ESLOG_INSTANCE(m_logger, APP, "Client disconnected: " + m_socket_client->get_connection_details());
        }
        delete m_socket_client;
    }

    delete m_logger;
}

dsim_status_e
dsim_client::read_register(uint32_t block_id, uint32_t reg_address, uint16_t reg_width, size_t count, void* out_val)
{
    api_lock lock(m_lock);

    if (m_socket_client == nullptr || m_socket_client->is_socket_closed()) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client READ_REGISTER: client is not initialized and not connected");
        return DSIM_STATUS_ENOTINITIALIZED;
    }

    if (calculate_key(block_id, reg_address) == m_dev_info.counters_cpu_read_address) {
        memcpy(out_val, m_counters_cpu_read_bv.byte_array(), m_counters_cpu_read_bv.get_width_in_bytes());
        return DSIM_STATUS_SUCCESS;
    }

    if (calculate_key(block_id, reg_address) == m_dev_info.counters_cpu_counter_read_result_address) {
        memcpy(out_val, m_cpu_counter_read_result_bv.byte_array(), m_cpu_counter_read_result_bv.get_width_in_bytes());
        return DSIM_STATUS_SUCCESS;
    }

    auto status = m_packet_dma_inject.read_register(block_id, reg_address, reg_width, count, out_val);
    if (status != DSIM_STATUS_ENOTFOUND) {
        return status;
    }

    status = m_packet_dma_extract.read_register(
        m_client_id, m_next_seqno, block_id, reg_address, reg_width, count, out_val, m_socket_command_buffer);
    if (status != DSIM_STATUS_ENOTFOUND) {
        return status;
    }

    uint16_t entry_count = (uint16_t)count;
    size_t expected_reply_length = reg_width * entry_count;
    uint32_t send_size = SOCKET_COMMAND_HEADER_SIZE + sizeof(read_register_socket_command);

    if (send_size > SOCKET_COMMAND_BUFFER_LEN) {
        ELOG_INSTANCE(
            m_logger,
            NSIM_DEBUG,
            string_format("DSIM client READ_REGISTER: Cannot store payload of %u bytes into buffer of max size %u.  block_id: %u, "
                          "address: %u, width: %u, count: %u",
                          send_size,
                          SOCKET_COMMAND_BUFFER_LEN,
                          block_id,
                          reg_address,
                          reg_width,
                          count));
        return DSIM_STATUS_ESIZE;
    }
    socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(m_socket_command_buffer);
    memset(cmd_hdr, 0, send_size);

    cmd_hdr->cmd = socket_command_type_e::READ_REGISTER;
    cmd_hdr->client_id = m_client_id;
    cmd_hdr->flags.expecting_reply = true;
    read_register_socket_command* rrsc = reinterpret_cast<read_register_socket_command*>(cmd_hdr->payload);
    rrsc->block_id = block_id;
    rrsc->reg_address = reg_address;
    rrsc->reg_addr_width = reg_width;
    rrsc->entry_count = entry_count;

    if (!send_and_save(send_size, cmd_hdr)) {
        return DSIM_STATUS_EUNKNOWN;
    }

    size_t received_bytes = m_socket_client->receive(out_val, expected_reply_length, "DSIM client READ_REGISTER receive: ");
    dsim_status_e ret = DSIM_STATUS_SUCCESS;
    // check reply
    if (received_bytes != expected_reply_length) {
        // the server should send error code in case the read operation failed
        ELOG_INSTANCE(m_logger,
                      NSIM_DEBUG,
                      "DSIM client READ_REGISTER: received bytes different than needed expected "
                          + std::to_string(expected_reply_length)
                          + " received "
                          + std::to_string(received_bytes));
        if (received_bytes != sizeof(size_t)) {
            handle_receive_error(received_bytes, cmd_hdr->cmd);
            return DSIM_STATUS_EUNKNOWN;
        }

        ret = *(dsim_status_e*)out_val;
    }
    handle_receive_success(received_bytes, cmd_hdr->cmd);

    ILOG_INSTANCE(
        m_logger, NSIM_DEBUG, "client received: status " + std::to_string(ret) + ", bytes: " + std::to_string(received_bytes));
    return ret;
}

dsim_status_e
dsim_client::read_register_by_name(const std::string& mem_reg_name,
                                   size_t reg_index,
                                   uint16_t reg_width,
                                   size_t count,
                                   void* out_val)
{
    api_lock lock(m_lock);

    if (m_socket_client == nullptr || m_socket_client->is_socket_closed()) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client READ_REGISTER_BY_NAME: client is not initialized and not connected");
        return DSIM_STATUS_ENOTINITIALIZED;
    }

    //
    // Was this a read to a register that may have some cached data?
    //
    {
        std::string block_name;
        std::string reg_name;
        std::string subfield;
        if (!parse_register_type_string(mem_reg_name, block_name, reg_name, subfield)) {
            ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client READ_REGISTER_BY_NAME: invalid register name format: " + mem_reg_name);
            return DSIM_STATUS_EUNKNOWN;
        }

        auto full_reg_name = block_name + "." + reg_name;

        if (block_name == "counters") {
            if (subfield == "") {
                if (full_reg_name == m_reg_cpu_read_name) {
                    memcpy(out_val, m_counters_cpu_read_bv.byte_array(), m_counters_cpu_read_bv.get_width_in_bytes());
                    return DSIM_STATUS_SUCCESS;
                }
                if (full_reg_name == m_reg_cpu_read_result) {
                    memcpy(out_val, m_cpu_counter_read_result_bv.byte_array(), m_cpu_counter_read_result_bv.get_width_in_bytes());
                    return DSIM_STATUS_SUCCESS;
                }
            }
        }

        auto status = m_packet_dma_inject.read_register_by_name(full_reg_name, reg_index, reg_width, count, out_val);
        if (status != DSIM_STATUS_ENOTFOUND) {
            if (subfield != "") {
                ELOG_INSTANCE(m_logger,
                              NSIM_DEBUG,
                              "DSIM client READ_REGISTER_BY_NAME: subfield support not implemented for " + mem_reg_name);
                return DSIM_STATUS_ENOTIMPLEMENTED;
            }
            return status;
        }

        status = m_packet_dma_extract.read_register_by_name(
            m_client_id, m_next_seqno, full_reg_name, reg_index, reg_width, count, out_val, m_socket_command_buffer);
        if (status != DSIM_STATUS_ENOTFOUND) {
            if (subfield != "") {
                ELOG_INSTANCE(m_logger,
                              NSIM_DEBUG,
                              "DSIM client READ_REGISTER_BY_NAME: subfield support not implemented for " + mem_reg_name);
                return DSIM_STATUS_ENOTIMPLEMENTED;
            }
            return status;
        }
    }

    //
    // Do we need to support cached memory for read-by-name?
    //
    uint16_t name_len = static_cast<uint16_t>(mem_reg_name.length());
    uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE + READ_REGISTER_BY_NAME_SOCKET_COMMAND_SIZE + name_len;
    if (buffer_size > SOCKET_COMMAND_BUFFER_LEN) {
        ELOG_INSTANCE(
            m_logger,
            NSIM_DEBUG,
            string_format("DSIM client READ_REGISTER_BY_NAME: Cannot store payload of %u bytes into buffer of max size %u.  "
                          "register: %s, index: %u, width: %u, count: %u",
                          buffer_size,
                          SOCKET_COMMAND_BUFFER_LEN,
                          mem_reg_name.c_str(),
                          reg_index,
                          reg_width,
                          count));
        return DSIM_STATUS_ESIZE;
    }

    socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(m_socket_command_buffer);
    memset(cmd_hdr, 0, buffer_size);
    cmd_hdr->cmd = socket_command_type_e::READ_REGISTER_BY_NAME;
    cmd_hdr->client_id = m_client_id;
    cmd_hdr->flags.expecting_reply = true;

    read_register_by_name_socket_command* rrbnsc = reinterpret_cast<read_register_by_name_socket_command*>(cmd_hdr->payload);
    rrbnsc->reg_index = static_cast<uint32_t>(reg_index);
    rrbnsc->reg_width = reg_width;
    rrbnsc->entry_count = static_cast<uint16_t>(count);
    rrbnsc->reg_name_len = name_len;
    std::copy(mem_reg_name.begin(), mem_reg_name.end(), rrbnsc->reg_name);

    if (!send_and_save(buffer_size, cmd_hdr)) {
        return DSIM_STATUS_EUNKNOWN;
    }

    // receive reply
    size_t expected_reply_length = reg_width * count;
    size_t received_bytes = m_socket_client->receive(out_val, expected_reply_length, "DSIM client READ_REGISTER_BY_NAME receive: ");
    dsim_status_e ret = DSIM_STATUS_SUCCESS;
    // check reply
    if (received_bytes != expected_reply_length) {
        // the server should send error code in case the read operation failed
        ELOG_INSTANCE(m_logger,
                      NSIM_DEBUG,
                      "DSIM client READ_REGISTER_BY_NAME: received bytes different than needed expected "
                          + std::to_string(expected_reply_length)
                          + " received "
                          + std::to_string(received_bytes));
        if (received_bytes != sizeof(size_t)) {
            handle_receive_error(received_bytes, cmd_hdr->cmd);
            return DSIM_STATUS_EUNKNOWN;
        }

        if (!received_bytes) {
            handle_receive_error(received_bytes, cmd_hdr->cmd);
            return DSIM_STATUS_EUNKNOWN;
        }

        ret = *(dsim_status_e*)out_val;
    }

    if (ret == DSIM_STATUS_SUCCESS) {
        handle_receive_success(received_bytes, cmd_hdr->cmd);
    }

    ILOG_INSTANCE(
        m_logger,
        NSIM_DEBUG,
        "read_register_by_name: client received: status " + std::to_string(ret) + ", bytes: " + std::to_string(received_bytes));
    return ret;
}

//
// Update the local counter register cache with either single concatenated counter or max counter data.
//
dsim_status_e
dsim_client::recv_single_or_max_counter_data(void)
{
    //
    // Local heap storage large enough to store max counter data (too large for the stack).
    // We have to pre-allocate this as we do not know how much data we will get back; well,
    // we could but we'd have to look at the subfield to determine if the counter target
    // was single or max. This seems simpler and safer.
    //
    static thread_local std::vector<uint8_t> tmp_recv_data;
    tmp_recv_data.resize(COUNTER_CPU_READ_MAX_COUNTERS_SIZE);
    uint8_t* in = &tmp_recv_data[0];
    size_t received_bytes = m_socket_client->receive(in, COUNTER_CPU_READ_MAX_COUNTERS_SIZE, "DSIM client counters receive: ");

    if (received_bytes == COUNTER_CPU_READ_MAX_COUNTERS_SIZE) {
        //
        // We have received max counter table data. Copy the data into our class.
        //
        m_counters_max_counter_data.reserve(COUNTER_CPU_READ_MAX_COUNTERS_SIZE);
        m_counters_max_counter_data.resize(0);
        std::copy(in, in + received_bytes, std::back_inserter(m_counters_max_counter_data));

        ILOG_INSTANCE(m_logger, NSIM_COUNTER, "Received max counter data from server");
    } else {
        //
        // We have single concatenated counter data. Copy the data into our class.
        //
        size_t cpu_read_size = m_counters_cpu_read_bv.get_width_in_bytes();
        size_t cpu_read_res_size = m_cpu_counter_read_result_bv.get_width_in_bytes();
        size_t expected_reply_length = cpu_read_size + cpu_read_res_size;

        if (received_bytes != expected_reply_length) {
            ELOG_INSTANCE(m_logger,
                          NSIM_DEBUG,
                          "DSIM client read single counter: received bytes different than needed expected "
                              + std::to_string(expected_reply_length)
                              + " received "
                              + std::to_string(received_bytes));
            handle_receive_error(received_bytes, socket_command_type_e::WRITE_REGISTER);
            return DSIM_STATUS_EUNKNOWN;
        }

        memcpy(m_counters_cpu_read_bv.byte_array(), in, cpu_read_size);
        memcpy(m_cpu_counter_read_result_bv.byte_array(), in + cpu_read_size, cpu_read_res_size);

        ILOG_INSTANCE(m_logger, NSIM_COUNTER, "Received single counter data from server");
    }

    handle_receive_success(received_bytes, socket_command_type_e::WRITE_REGISTER);

    return DSIM_STATUS_SUCCESS;
}

dsim_status_e
dsim_client::write_register(uint32_t block_id, uint32_t reg_address, uint16_t reg_width, size_t count, const void* in_val)
{
    api_lock lock(m_lock);

    if (m_socket_client == nullptr || m_socket_client->is_socket_closed()) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client WRITE_REGISTER: client is not initialized and not connected");
        return DSIM_STATUS_ENOTINITIALIZED;
    }

    auto status = m_packet_dma_inject.write_register(
        m_client_id, m_next_seqno, block_id, reg_address, reg_width, count, in_val, m_socket_command_buffer);
    // Return status only if internal Packet DMA error, otherwise continue and update DSIM register
    if (status != DSIM_STATUS_ENOTFOUND && status != DSIM_STATUS_SUCCESS) {
        return status;
    }

    status = m_packet_dma_extract.write_register(block_id, reg_address, reg_width, count, in_val);
    // Return status only if internal Packet DMA error, otherwise continue and update DSIM register
    if (status != DSIM_STATUS_ENOTFOUND && status != DSIM_STATUS_SUCCESS) {
        return status;
    }

    if (count == 0) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client wrong buffer size, socket command creation failed");
        return DSIM_STATUS_ESIZE;
    }

    // prepare command
    bool expecting_reply = (m_dev_info.counters_cpu_read_address == calculate_key(block_id, reg_address));

    uint16_t entry_count = (uint16_t)count;
    uint32_t payload_size = static_cast<uint32_t>(reg_width * count);
    uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE + WRITE_REGISTER_SOCKET_COMMAND_SIZE + payload_size;
    if (buffer_size > SOCKET_COMMAND_BUFFER_LEN) {
        ELOG_INSTANCE(
            m_logger,
            NSIM_DEBUG,
            string_format("DSIM client WRITE_REGISTER: Cannot store payload of %u bytes into buffer of max size %u.  block_id: %u, "
                          "address: %u, width: %u, count: %u",
                          buffer_size,
                          SOCKET_COMMAND_BUFFER_LEN,
                          block_id,
                          reg_address,
                          reg_width,
                          count));
        return DSIM_STATUS_ESIZE;
    }
    socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(m_socket_command_buffer);

    memset(cmd_hdr, 0, buffer_size);

    write_register_socket_command* wrsc = reinterpret_cast<write_register_socket_command*>(cmd_hdr->payload);
    cmd_hdr->cmd = socket_command_type_e::WRITE_REGISTER;
    cmd_hdr->client_id = m_client_id;
    cmd_hdr->flags.expecting_reply = expecting_reply;
    wrsc->block_id = block_id;
    wrsc->reg_address = reg_address;
    wrsc->reg_addr_width = reg_width;
    wrsc->entry_count = entry_count;
    memcpy(wrsc->payload, in_val, payload_size);

    if (!send_and_save(buffer_size, cmd_hdr)) {
        return DSIM_STATUS_EUNKNOWN;
    }

    if (expecting_reply) {
        // Update the local counter register cache.
        return recv_single_or_max_counter_data();
    }

    return DSIM_STATUS_SUCCESS;
}

dsim_status_e
dsim_client::write_register_by_name(const std::string& name, size_t reg_index, uint16_t reg_width, size_t count, const void* in_val)
{
    api_lock lock(m_lock);

    if (m_socket_client == nullptr || m_socket_client->is_socket_closed()) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client WRITE_REGISTER_BY_NAME: client is not initialized and not connected");
        return DSIM_STATUS_ENOTINITIALIZED;
    }

    std::string block_name;
    std::string reg_name;
    std::string subfield;
    if (!parse_register_type_string(name, block_name, reg_name, subfield)) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client WRITE_REGISTER_BY_NAME: invalid register name format: " + name);
        return DSIM_STATUS_EUNKNOWN;
    }

    //
    // No subfield support yet for reg names
    //
    auto full_reg_name = block_name + "." + reg_name;
    auto status = m_packet_dma_inject.write_register_by_name(
        m_client_id, m_next_seqno, full_reg_name, reg_index, reg_width, count, in_val, m_socket_command_buffer);
    if (status != DSIM_STATUS_ENOTFOUND) {
        if (subfield != "") {
            ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client WRITE_REGISTER_BY_NAME: subfield support not implemented for " + name);
            return DSIM_STATUS_ENOTIMPLEMENTED;
        }
        return status;
    }

    status = m_packet_dma_extract.write_register_by_name(full_reg_name, reg_index, reg_width, count, in_val);
    if (status != DSIM_STATUS_ENOTFOUND) {
        if (subfield != "") {
            ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client WRITE_REGISTER_BY_NAME: subfield support not implemented for " + name);
            return DSIM_STATUS_ENOTIMPLEMENTED;
        }
        return status;
    }

    // prepare command
    bool expecting_reply = (full_reg_name == m_reg_cpu_read_name);
    uint32_t name_len = static_cast<uint32_t>(name.length());
    uint32_t payload_len = reg_width * static_cast<uint16_t>(count);
    uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE + WRITE_REGISTER_BY_NAME_SOCKET_COMMAND_SIZE + name_len + payload_len;
    if (buffer_size > SOCKET_COMMAND_BUFFER_LEN) {
        ELOG_INSTANCE(
            m_logger,
            NSIM_DEBUG,
            string_format("DSIM client WRITE_REGISTER_BY_NAME: Cannot store payload of %u bytes into buffer of max size %u.  "
                          "register: %s, index: %u, width: %u, count: %u",
                          buffer_size,
                          SOCKET_COMMAND_BUFFER_LEN,
                          name.c_str(),
                          reg_index,
                          reg_width,
                          count));
        return DSIM_STATUS_ESIZE;
    }

    socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(m_socket_command_buffer);
    memset(cmd_hdr, 0, buffer_size);
    cmd_hdr->cmd = socket_command_type_e::WRITE_REGISTER_BY_NAME;
    cmd_hdr->client_id = m_client_id;
    cmd_hdr->flags.expecting_reply = expecting_reply;

    write_register_by_name_socket_command* wrbnsc = reinterpret_cast<write_register_by_name_socket_command*>(cmd_hdr->payload);
    wrbnsc->reg_index = static_cast<uint32_t>(reg_index);
    wrbnsc->reg_width = reg_width;
    wrbnsc->entry_count = static_cast<uint16_t>(count);
    wrbnsc->reg_name_len = name_len;
    std::copy(name.begin(), name.end(), wrbnsc->payload);
    memcpy(wrbnsc->payload + name_len, in_val, payload_len);

    if (!send_and_save(buffer_size, cmd_hdr)) {
        return DSIM_STATUS_EUNKNOWN;
    }

    //
    // Was this a write to a register that has trigger the return of some cached data?
    //
    if (expecting_reply) {
        // Update the local counter register cache.
        return recv_single_or_max_counter_data();
    }

    return DSIM_STATUS_SUCCESS;
}

dsim_status_e
dsim_client::read_memory(uint32_t block_id, uint32_t mem_address, uint16_t mem_width, size_t mem_entries, void* out_val)
{
    api_lock lock(m_lock);

    if (m_socket_client == nullptr || m_socket_client->is_socket_closed()) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client READ_MEMORY: client is not initialized and not connected");
        return DSIM_STATUS_ENOTINITIALIZED;
    }

    auto key = calculate_key(block_id, mem_address);

    //
    // Requesting a read from the max counters table? Use cached data if available.
    //
    if (read_max_counters_cache(key, mem_width, mem_entries, out_val) == DSIM_STATUS_SUCCESS) {
        return DSIM_STATUS_SUCCESS;
    }

    if (mem_entries == 0) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client READ_MEMORY: wrong buffer size, socket command creation failed");
        return DSIM_STATUS_ESIZE;
    }
    uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE + sizeof(read_memory_socket_command);
    if (buffer_size > SOCKET_COMMAND_BUFFER_LEN) {
        ELOG_INSTANCE(
            m_logger,
            NSIM_DEBUG,
            string_format("DSIM client READ_MEMORY: Cannot store payload of %u bytes into buffer of max size %u.  block_id: %u, "
                          "mem_address: %u, mem_width: %u, entry_count: %u",
                          buffer_size,
                          SOCKET_COMMAND_BUFFER_LEN,
                          block_id,
                          mem_address,
                          mem_width,
                          mem_entries));
        return DSIM_STATUS_ESIZE;
    }

    socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(m_socket_command_buffer);

    memset(cmd_hdr, 0, buffer_size);

    read_memory_socket_command* rmsc = reinterpret_cast<read_memory_socket_command*>(cmd_hdr->payload);
    cmd_hdr->cmd = socket_command_type_e::READ_MEMORY;
    cmd_hdr->client_id = m_client_id;
    cmd_hdr->flags.expecting_reply = true;
    rmsc->block_id = block_id;
    rmsc->memory_address = mem_address;
    rmsc->memory_addr_width = mem_width;
    rmsc->entry_count = static_cast<uint16_t>(mem_entries);

    if (!send_and_save(buffer_size, cmd_hdr)) {
        return DSIM_STATUS_EUNKNOWN;
    }

    // receive reply
    size_t expected_reply_length = mem_width * mem_entries;
    size_t received_bytes = m_socket_client->receive(out_val, expected_reply_length, "DSIM client READ_MEMORY receive: ");
    dsim_status_e ret = DSIM_STATUS_SUCCESS;
    // check reply
    if (received_bytes != expected_reply_length) {
        // the server should send error code in case the read operation failed
        ELOG_INSTANCE(m_logger,
                      NSIM_DEBUG,
                      "DSIM client READ_MEMORY: received bytes different than needed expected "
                          + std::to_string(expected_reply_length)
                          + " received "
                          + std::to_string(received_bytes));
        if (received_bytes != sizeof(size_t)) {
            handle_receive_error(received_bytes, cmd_hdr->cmd);
            return DSIM_STATUS_EUNKNOWN;
        }

        ret = *(dsim_status_e*)out_val;
    }

    if (ret == DSIM_STATUS_SUCCESS) {
        handle_receive_success(received_bytes, cmd_hdr->cmd);
    }

    return ret;
}

dsim_status_e
dsim_client::write_memory(uint32_t block_id, uint32_t mem_address, uint16_t mem_width, size_t mem_entries, const void* in_val)
{
    if (m_sdk_re_initializing) {
        return DSIM_STATUS_SUCCESS;
    }

    if (m_socket_client == nullptr || m_socket_client->is_socket_closed()) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client WRITE_MEMORY: client is not initialized and not connected");
        return DSIM_STATUS_ENOTINITIALIZED;
    }

    if (mem_entries == 0) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client WRITE_MEMORY: wrong buffer size, socket command creation failed");
        return DSIM_STATUS_ESIZE;
    }

    uint16_t entry_count = (uint16_t)mem_entries;
    uint32_t payload_size = mem_width * entry_count;
    uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE + WRITE_MEMORY_SOCKET_COMMAND_SIZE + payload_size;
    if (buffer_size > SOCKET_COMMAND_BUFFER_LEN) {
        ELOG_INSTANCE(
            m_logger,
            NSIM_DEBUG,
            string_format("DSIM client WRITE_MEMORY: Cannot store payload of %u bytes into buffer of max size %u.  block_id: %u, "
                          "mem_address: %u, mem_width: %u, entry_count: %u",
                          buffer_size,
                          SOCKET_COMMAND_BUFFER_LEN,
                          block_id,
                          mem_address,
                          mem_width,
                          entry_count));
        return DSIM_STATUS_ESIZE;
    }
    socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(m_socket_command_buffer);

    memset(cmd_hdr, 0, buffer_size);

    write_memory_socket_command* wmsc = reinterpret_cast<write_memory_socket_command*>(cmd_hdr->payload);
    cmd_hdr->cmd = socket_command_type_e::WRITE_MEMORY;
    cmd_hdr->client_id = m_client_id;
    cmd_hdr->flags.expecting_reply = false;
    wmsc->block_id = block_id;
    wmsc->memory_address = mem_address;
    wmsc->memory_addr_width = mem_width;
    wmsc->entry_count = entry_count;
    memcpy(wmsc->payload, in_val, payload_size);

    if (!send_and_save(buffer_size, cmd_hdr)) {
        return DSIM_STATUS_EUNKNOWN;
    }

    return DSIM_STATUS_SUCCESS;
}

dsim_status_e
dsim_client::read_modify_write_memory(uint32_t block_id,
                                      uint32_t mem_entry,
                                      uint16_t mem_width,
                                      uint16_t data_offset,
                                      uint16_t data_width,
                                      size_t mem_entries,
                                      const void* in_val)
{
    api_lock lock(m_lock);

    if (m_socket_client == nullptr || m_socket_client->is_socket_closed()) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client read_modify_write_memory: client is not initialized and not connected");
        return DSIM_STATUS_ENOTINITIALIZED;
    }

    assert(mem_entries == 1 && "Multi-entries are not supported yet.");
    bit_vector mask;
    mask.resize(data_width, UINT64_MAX);
    mask <<= data_offset;
    mask.resize(mem_width * 8);
    size_t expected_reply_length = mem_entries * mem_width;
    std::unique_ptr<uint8_t[]> buff{new uint8_t[expected_reply_length]};

    dsim_status_e status = read_memory(block_id, mem_entry, mem_width, (uint16_t)mem_entries, static_cast<void*>(buff.get()));

    if (status != DSIM_STATUS_SUCCESS) {
        ELOG_INSTANCE(m_logger,
                      NSIM_DEBUG,
                      "DSIM client read_modify_write_memory: failed during read_memory() stage with status "
                          + std::to_string(status));
        return status;
    }

    bit_vector value{expected_reply_length, buff.get(), expected_reply_length * 8};
    value = (value & ~mask)
            | (bit_vector{expected_reply_length, static_cast<const uint8_t*>(in_val), expected_reply_length * 8} & mask);

    status = write_memory(block_id, mem_entry, mem_width, (uint16_t)mem_entries, static_cast<void*>(value.byte_array()));

    if (status != DSIM_STATUS_SUCCESS) {
        ELOG_INSTANCE(m_logger,
                      NSIM_DEBUG,
                      "DSIM client read_modify_write_memory: failed during write_memory() stage with status "
                          + std::to_string(status));
    }

    return status;
}

dsim_status_e
dsim_client::add_property(std::string key, std::string value)
{
    if (m_socket_client == nullptr || m_socket_client->is_socket_closed()) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client add_property: client is not initialized and not connected");
        return DSIM_STATUS_ENOTINITIALIZED;
    }

    if (key == "SDK_RE_INITIALIZING") {
        try {
            m_sdk_re_initializing = std::stoi(value) ? true : false;
            ILOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client add_property: " + key + " => " + value);
            return DSIM_STATUS_SUCCESS;
        } catch (...) {
            ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client add_property: " + key + ": invalid value " + value);
            return DSIM_STATUS_EINVAL;
        }
    }

    // prepare command
    std::string key_value_string(std::to_string(key.length()) + ":" + std::to_string(value.length()) + ":" + key + value);
    uint32_t key_value_string_len = static_cast<uint32_t>(key_value_string.length() + 1); // +1 to get the \0 at the end
    uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE + key_value_string_len;
    if (buffer_size > SOCKET_COMMAND_BUFFER_LEN) {
        ELOG_INSTANCE(
            m_logger,
            NSIM_DEBUG,
            string_format(
                "DSIM client add_property: Cannot store payload of %u bytes into buffer of max size %u.  key: %s, value: %s",
                buffer_size,
                SOCKET_COMMAND_BUFFER_LEN,
                key.c_str(),
                value.c_str()));
        return DSIM_STATUS_ESIZE;
    }

    socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(m_socket_command_buffer);
    memset(cmd_hdr, 0, buffer_size);
    cmd_hdr->cmd = socket_command_type_e::ADD_PROPERTY;
    cmd_hdr->client_id = m_client_id;
    cmd_hdr->flags.expecting_reply = false;

    memcpy(reinterpret_cast<char*>(cmd_hdr->payload), key_value_string.c_str(), key_value_string_len);

    if (!send_and_save(buffer_size, cmd_hdr)) {
        return DSIM_STATUS_EUNKNOWN;
    }

    return DSIM_STATUS_SUCCESS;
}

void
dsim_client::set_log_file(const char* log_file_path, bool logPrefixEnabled)
{
    set_log_file(log_file_path, logPrefixEnabled, MAX_LOG_DISABLED, MAX_LOG_DISABLED, LOG_FILE_COMPRESSION_DISABLED);
}

void
dsim_client::set_log_file(const char* log_file_path, bool logPrefixEnabled, size_t maxLogSize, size_t maxLogFiles, bool compress)
{
    std::string logger_path_as_string = log_file_path;
    size_t found = logger_path_as_string.find_last_of("/\\");
    std::string file;
    std::string folder;
    if (found == std::string::npos) {
        file = logger_path_as_string;
        folder = ".";
    } else {
        file = logger_path_as_string.substr(found + 1);
        folder = logger_path_as_string.substr(0, found);
    }

    m_logger->SetLogFilePath(folder, logPrefixEnabled, file, maxLogSize, maxLogFiles, compress);
}

void
dsim_client::set_log_level(nsim::nsim_log_module_e level)
{
    m_logger->SetStdOutLogLevelForAll(NPSUITE_LOG_LEVEL_FATAL);
    m_logger->SetFileLogLevelForAll(NPSUITE_LOG_LEVEL_FATAL);

    if (level == nsim::nsim_log_module_e::NSIM_LOG_NONE) {
        return;
    }

    m_logger->SetStdOutLogLevelForAll(NPSUITE_LOG_LEVEL_ESSENTIAL);
    m_logger->SetFileLogLevelForAll(NPSUITE_LOG_LEVEL_ESSENTIAL);

    m_logger->SetModuleFileLogLevel(NSIM_TABLE, NPSUITE_LOG_LEVEL_INFO);

    if (level == nsim::nsim_log_module_e::NSIM_LOG_TABLE) {
        return;
    }

    m_logger->SetModuleFileLogLevel(USER, NPSUITE_LOG_LEVEL_INFO);

    if (level == nsim::nsim_log_module_e::NSIM_LOG_USER) {
        return;
    }

    // if we got here we want full debug info.
    m_logger->SetFileLogLevelForAll(NPSUITE_LOG_LEVEL_TRACE);
}

void
dsim_client::set_module_file_log_level(nsim::nsim_log_module_e module, npsuite::npsuite_log_level_e level)
{
    switch (module) {
    case nsim::NSIM_LOG_NONE:
        break;
    case nsim::NSIM_LOG_TABLE:
        m_logger->SetModuleFileLogLevel(NSIM_TABLE, static_cast<npsuite::npsuite_log_level_e>(level));
        break;
    case nsim::NSIM_LOG_FULL:
        m_logger->SetFileLogLevelForAll(static_cast<npsuite::npsuite_log_level_e>(level));
        break;
    default:
        ELOG_INSTANCE(
            m_logger, NSIM_DEBUG, "DSIM client can't change individual file log level for " + std::to_string(module) + " module.");
        break;
    }
}

void
dsim_client::set_module_stdout_log_level(nsim::nsim_log_module_e module, npsuite::npsuite_log_level_e level)
{
    switch (module) {
    case nsim::NSIM_LOG_NONE:
        break;
    case nsim::NSIM_LOG_TABLE:
        m_logger->SetModuleStdOutLogLevel(NSIM_TABLE, static_cast<npsuite::npsuite_log_level_e>(level));
        break;
    case nsim::NSIM_LOG_FULL:
        m_logger->SetStdOutLogLevelForAll(static_cast<npsuite::npsuite_log_level_e>(level));
        break;
    default:
        ELOG_INSTANCE(m_logger,
                      NSIM_DEBUG,
                      "DSIM client can't change individual stdout log level for " + std::to_string(module) + " module.");
        break;
    }
}

void
dsim_client::set_log_file(const char* log_file_path)
{
    set_log_file(log_file_path, true, 0, 0, LOG_FILE_COMPRESSION_DISABLED);
}

std::string
dsim_client::get_device_name() const
{
    return m_dev_info.device_name;
}

std::string
dsim_client::get_device_revision() const
{
    return m_dev_info.device_revision;
}

uint32_t
dsim_client::get_sim_access_block_id() const
{
    return m_dev_info.sim_access_block_id;
}

uint32_t
dsim_client::get_sim_access_mem_address_place_udk() const
{
    return m_dev_info.sim_access_mem_address_place_udk;
}

uint32_t
dsim_client::get_sim_access_nsim_command_mem_address() const
{
    return m_dev_info.sim_access_nsim_command_mem;
}

void
dsim_client::nsim_log_message(npsuite::npsuite_log_level_e loglevel, std::string user_prefix_identifier, std::string message)
{
    api_lock lock(m_lock);

    if (m_socket_client == nullptr || m_socket_client->is_socket_closed()) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client LOG_MESSAGE: client is not initialized and not connected");
        return;
    }

    std::string packed_message(user_prefix_identifier + "@" + message);
    uint32_t packed_message_len = static_cast<uint32_t>(packed_message.length() + 1); // +1 to get the \0 at the end
    uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE + LOG_MESSAGE_SOCKET_COMMAND_SIZE + packed_message_len;
    if (buffer_size > SOCKET_COMMAND_BUFFER_LEN) {
        WLOG_INSTANCE(
            m_logger,
            NSIM_DEBUG,
            string_format(
                "nsim_log_message: Cannot store payload of %u bytes into buffer of max size %u. Message will be truncated...",
                buffer_size,
                SOCKET_COMMAND_BUFFER_LEN));
        packed_message_len -= (buffer_size - SOCKET_COMMAND_BUFFER_LEN);
        buffer_size -= (buffer_size - SOCKET_COMMAND_BUFFER_LEN);
    }

    socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(m_socket_command_buffer);
    memset(cmd_hdr, 0, buffer_size);
    cmd_hdr->cmd = socket_command_type_e::LOG_MESSAGE;
    cmd_hdr->client_id = m_client_id;
    cmd_hdr->flags.expecting_reply = false;

    log_message_socket_command* lmsc = reinterpret_cast<log_message_socket_command*>(cmd_hdr->payload);
    lmsc->log_level = static_cast<uint32_t>(loglevel);
    memcpy(reinterpret_cast<char*>(lmsc->log_message), packed_message.c_str(), packed_message_len);

    if (!send_and_save(buffer_size, cmd_hdr)) {
        return;
    }
}

void
log_user_message(void* opaque, int nsim_log_level, std::string user_prefix_identifier, std::string message)
{
    dsim_client* client = static_cast<dsim_client*>(opaque);
    if (client != nullptr) {
        client->nsim_log_message((npsuite::npsuite_log_level_e)nsim_log_level, user_prefix_identifier, message);
    }
}

dsim_status_e
dsim_client::read_memory_by_name(const std::string& mem_block_name,
                                 size_t mem_index,
                                 uint32_t mem_address,
                                 uint16_t mem_width,
                                 size_t mem_entries,
                                 void* out_val)
{
    api_lock lock(m_lock);

    if (m_socket_client == nullptr || m_socket_client->is_socket_closed()) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client READ_MEMORY_BY_NAME: client is not initialized and not connected");
        return DSIM_STATUS_ENOTINITIALIZED;
    }

    //
    // Was this a read to memory that may have some cached data?
    //
    {
        std::string block_name;
        std::string mem_name;
        std::string subfield;
        if (parse_memory_type_string(mem_block_name, block_name, mem_name, subfield)) {
            if ((block_name == "counters") && (subfield == "")) {
                auto full_mem_name = block_name + "." + mem_name;
                if (full_mem_name == m_max_counters_table_name) {
                    uint64_t address = m_dev_info.counters_max_counters_address_begin
                                       + m_dev_info.counters_max_counters_address_entry_width_in_bytes * mem_address;
                    if (read_max_counters_cache(address, mem_width, mem_entries, out_val) == DSIM_STATUS_SUCCESS) {
                        return DSIM_STATUS_SUCCESS;
                    }
                }
            }
        }
    }

    uint32_t name_len = static_cast<uint32_t>(mem_block_name.length());
    uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE + READ_MEMORY_BY_NAME_SOCKET_COMMAND_SIZE + name_len;
    if (buffer_size > SOCKET_COMMAND_BUFFER_LEN) {
        ELOG_INSTANCE(
            m_logger,
            NSIM_DEBUG,
            string_format("DSIM client READ_MEMORY_BY_NAME: Cannot store payload of %u bytes into buffer of max size %u.  memory: "
                          "%s, mem_address: %u, mem_index %u, mem_width: %u, entry_count: %u",
                          buffer_size,
                          SOCKET_COMMAND_BUFFER_LEN,
                          mem_block_name.c_str(),
                          mem_address,
                          mem_index,
                          mem_width,
                          mem_entries));
        return DSIM_STATUS_ESIZE;
    }

    socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(m_socket_command_buffer);
    memset(cmd_hdr, 0, buffer_size);
    cmd_hdr->cmd = socket_command_type_e::READ_MEMORY_BY_NAME;
    cmd_hdr->client_id = m_client_id;
    cmd_hdr->flags.expecting_reply = true;

    read_memory_by_name_socket_command* rmbnsc = reinterpret_cast<read_memory_by_name_socket_command*>(cmd_hdr->payload);
    rmbnsc->mem_index = static_cast<uint32_t>(mem_index);
    rmbnsc->mem_address = mem_address;
    rmbnsc->mem_width = mem_width;
    rmbnsc->entry_count = static_cast<uint16_t>(mem_entries);
    rmbnsc->mem_name_len = name_len;
    std::copy(mem_block_name.begin(), mem_block_name.end(), rmbnsc->mem_name);

    if (!send_and_save(buffer_size, cmd_hdr)) {
        return DSIM_STATUS_EUNKNOWN;
    }

    // receive reply
    size_t expected_reply_length = mem_width * mem_entries;
    size_t received_bytes = m_socket_client->receive(out_val, expected_reply_length, "DSIM client READ_MEMORY_BY_NAME receive: ");
    dsim_status_e ret = DSIM_STATUS_SUCCESS;
    // check reply
    if (received_bytes != expected_reply_length) {
        // the server should send error code in case the read operation failed
        ELOG_INSTANCE(m_logger,
                      NSIM_DEBUG,
                      "DSIM client READ_MEMORY_BY_NAME: received bytes different than needed expected "
                          + std::to_string(expected_reply_length)
                          + " received "
                          + std::to_string(received_bytes));
        if (received_bytes != sizeof(size_t)) {
            handle_receive_error(received_bytes, cmd_hdr->cmd);
            return DSIM_STATUS_EUNKNOWN;
        }

        ret = *(dsim_status_e*)out_val;
    }

    if (ret == DSIM_STATUS_SUCCESS) {
        handle_receive_success(received_bytes, cmd_hdr->cmd);
    }

    return ret;
}

dsim_status_e
dsim_client::write_memory_by_name(const std::string& mem_name,
                                  size_t mem_index,
                                  uint32_t mem_entry,
                                  uint16_t mem_width,
                                  size_t mem_entries,
                                  const void* in_val)
{
    if (m_socket_client == nullptr || m_socket_client->is_socket_closed()) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client WRITE_MEMORY_BY_NAME: client is not initialized and not connected");
        return DSIM_STATUS_ENOTINITIALIZED;
    }

    uint32_t name_len = static_cast<uint32_t>(mem_name.length());
    uint32_t payload_len = static_cast<uint32_t>(mem_width * mem_entries);
    uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE + sizeof(write_memory_by_name_socket_command) + name_len + payload_len;
    if (buffer_size > SOCKET_COMMAND_BUFFER_LEN) {
        ELOG_INSTANCE(
            m_logger,
            NSIM_DEBUG,
            string_format("DSIM client WRITE_MEMORY_BY_NAME: Cannot store payload of %u bytes into buffer of max size %u.  memory: "
                          "%s, mem_index %u, mem_width: %u, entry_count: %u",
                          buffer_size,
                          SOCKET_COMMAND_BUFFER_LEN,
                          mem_name.c_str(),
                          mem_index,
                          mem_width,
                          mem_entries));
        return DSIM_STATUS_ESIZE;
    }

    socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(m_socket_command_buffer);
    memset(cmd_hdr, 0, buffer_size);
    cmd_hdr->cmd = socket_command_type_e::WRITE_MEMORY_BY_NAME;
    cmd_hdr->client_id = m_client_id;
    cmd_hdr->flags.expecting_reply = false;

    write_memory_by_name_socket_command* wmbnsc = reinterpret_cast<write_memory_by_name_socket_command*>(cmd_hdr->payload);
    wmbnsc->mem_index = static_cast<uint32_t>(mem_index);
    wmbnsc->mem_address = mem_entry;
    wmbnsc->mem_width = mem_width;
    wmbnsc->entry_count = static_cast<uint16_t>(mem_entries);
    wmbnsc->mem_name_len = name_len;
    std::copy(mem_name.begin(), mem_name.end(), wmbnsc->payload);
    memcpy(wmbnsc->payload + name_len, in_val, payload_len);

    if (!send_and_save(buffer_size, cmd_hdr)) {
        return DSIM_STATUS_EUNKNOWN;
    }

    return DSIM_STATUS_SUCCESS;
}

dsim_status_e
dsim_client::read_max_counters_cache(uint64_t mem_address, uint16_t mem_width, size_t mem_entries, void* out_val)
{
    if ((mem_address >= m_dev_info.counters_max_counters_address_begin)
        && (mem_address < m_dev_info.counters_max_counters_address_end)) {
        uint64_t offset = mem_address - m_dev_info.counters_max_counters_address_begin;
        uint64_t table_size = m_dev_info.counters_max_counters_address_end - m_dev_info.counters_max_counters_address_begin;
        uint64_t mem_width_in_bytes = mem_width;

        if (offset + mem_width_in_bytes * mem_entries > table_size) {
            ELOG_INSTANCE(m_logger,
                          NSIM_DEBUG,
                          "DSIM client address overflow " + std::to_string(mem_address) + " while reading "
                              + std::to_string(mem_width_in_bytes * mem_entries)
                              + " bytes"
                              + ", offset = "
                              + std::to_string(offset)
                              + ", table_size = "
                              + std::to_string(table_size)
                              + ", cache size = "
                              + std::to_string(m_counters_max_counter_data.size())
                              + ", mem_width = "
                              + std::to_string(mem_width_in_bytes)
                              + ", mem_entries = "
                              + std::to_string(mem_entries)
                              + ", begin = "
                              + std::to_string(m_dev_info.counters_max_counters_address_begin)
                              + ", end = "
                              + std::to_string(m_dev_info.counters_max_counters_address_end));
            return DSIM_STATUS_EUNKNOWN;
        }

        if (offset + mem_width_in_bytes * mem_entries <= static_cast<uint64_t>(m_counters_max_counter_data.size())) {
            auto base = m_counters_max_counter_data.begin() + static_cast<size_t>(offset);
            std::copy(base, base + static_cast<size_t>(mem_width_in_bytes * mem_entries), static_cast<uint8_t*>(out_val));
            return DSIM_STATUS_SUCCESS;
        }

        //
        // Fall through to non cached read.
        //
        DLOG_INSTANCE(m_logger,
                      NSIM_COUNTER,
                      "cached data overflow " + std::to_string(mem_address) + " while reading "
                          + std::to_string(mem_width_in_bytes * mem_entries)
                          + " bytes"
                          + ", offset = "
                          + std::to_string(offset)
                          + ", table_size = "
                          + std::to_string(table_size)
                          + ", cache size = "
                          + std::to_string(m_counters_max_counter_data.size())
                          + ", mem_width = "
                          + std::to_string(mem_width_in_bytes)
                          + ", mem_entries = "
                          + std::to_string(mem_entries)
                          + ", begin = "
                          + std::to_string(m_dev_info.counters_max_counters_address_begin)
                          + ", end = "
                          + std::to_string(m_dev_info.counters_max_counters_address_end));
    }
    return DSIM_STATUS_ENOTFOUND;
}

//
// Test the client connection and wait for a response
//
dsim_status_e
dsim_client::rpc_ping(void)
{
    if (!m_socket_client) {
        return DSIM_STATUS_EUNKNOWN;
    }

    api_lock lock(m_lock);
    return write_rpc_and_wait_for_status(socket_command_type_e::PING);
}

//
// Teardown the server.
//
dsim_status_e
dsim_client::rpc_destroy_simulator(void)
{
    api_lock lock(m_lock);
    return write_rpc_and_wait_for_status(socket_command_type_e::DESTROY_SIMULATOR);
}

//
// Set the DSIM server log file path
//
dsim_status_e
dsim_client::rpc_set_server_log_file(const std::string& log_file_path, bool logPrefixEnabled)
{
    api_lock lock(m_lock);
    return write_rpc_and_wait_for_status(socket_command_type_e::SET_LOG_FILE, log_file_path, logPrefixEnabled);
}

//
// Set the DSIM server log level
//
// Sets log level to INFO for the specified module, and the module
// acsts as a threshold, meaning the ones "above" the specified one
// will only log errors and fatals (default) and the ones "below"
// will be set to log level INFO.
//
// Set NSIM_LOG_NONE to log only errors and fatals for all modules.
//
dsim_status_e
dsim_client::rpc_set_server_log_level(nsim::nsim_log_module_e level)
{
    api_lock lock(m_lock);
    return write_rpc_and_wait_for_status(socket_command_type_e::SET_LOG_LEVEL, level);
}

//
// Enable packet DMA
//
dsim_status_e
dsim_client::rpc_packet_dma_enable(bool value)
{
    api_lock lock(m_lock);
    return write_rpc_and_wait_for_status(socket_command_type_e::PACKET_DMA_ENABLE, value);
}

//
// Inject the given packet descriptor information
//
dsim_status_e
dsim_client::rpc_inject_packet_desc(const struct nsim::nsim_packet_info_t& packet,
                                    const std::map<std::string, std::string>& initial_values)
{
    api_lock lock(m_lock);
    return write_rpc_and_wait_for_status(socket_command_type_e::INJECT_PACKET_DESC, packet, initial_values);
}

dsim_status_e
dsim_client::rpc_inject_packet(const std::string& packet,
                               size_t slice_id,
                               size_t ifg,
                               size_t pif,
                               const std::map<std::string, std::string>& initial_values)
{
    api_lock lock(m_lock);
    struct nsim_packet_info_t out;

    out.m_packet_data = bit_vector(packet, packet.size() * 4);
    out.m_slice_id = slice_id;
    out.m_ifg = ifg;
    out.m_pif = pif;
    out.m_should_dump_state = false;

    return rpc_inject_packet_desc(out, initial_values);
}

//
// Simulate one packet.
// Evaluates the current packet execution, stopping one step before the packet finishes.
// Invoking #step() after #step_macro() will load the next macro.
//
dsim_status_e
dsim_client::rpc_step_packet(void)
{
    api_lock lock(m_lock);
    return write_rpc_and_wait_for_status(socket_command_type_e::STEP_PACKET);
}

//
// Step the simulation one macro forward.
// Evaluates the current macro, stopping one step before end of the macro.
// Invoking #step() after #step_macro() will load the next macro.
//
dsim_status_e
dsim_client::rpc_step_macro(void)
{
    api_lock lock(m_lock);
    return write_rpc_and_wait_for_status(socket_command_type_e::STEP_MACRO);
}

//
// Invoking #step() after #step_macro() will load the next macro.
// Evaluates the next statement to be executed, and advances the current statement location.
//
dsim_status_e
dsim_client::rpc_step(void)
{
    api_lock lock(m_lock);
    return write_rpc_and_wait_for_status(socket_command_type_e::STEP);
}

//
// Sets lrc_fifo trigger to run before next packet
//
dsim_status_e
dsim_client::rpc_trigger_lrc_fifo(void)
{
    api_lock lock(m_lock);
    return write_rpc_and_wait_for_status(socket_command_type_e::TRIGGER_LRC_FIFO);
}

//
// Get a single packet from the server. This will also clear out any other waiting packets.
//
dsim_status_e
dsim_client::rpc_get_packet(struct nsim::nsim_packet_info_t& out)
{
    api_lock lock(m_lock);
    uint32_t num_of_packets = 1;
    auto cmd = socket_command_type_e::GET_PACKET;
    auto response = write_rpc(cmd, num_of_packets);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        std::list<struct nsim::nsim_packet_info_t> tmp;
        response = read_rpc(cmd, result, tmp);
        if (response == DSIM_STATUS_SUCCESS) {
            if (!tmp.empty()) {
                out = tmp.front();
            }
        } else {
            response = result;
        }
    }
    return response;
}

//
// Get all packets from the server
//
dsim_status_e
dsim_client::rpc_get_packets(std::list<struct nsim::nsim_packet_info_t>& out)
{
    api_lock lock(m_lock);
    auto cmd = socket_command_type_e::GET_PACKETS;
    auto response = write_rpc(cmd);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        response = read_rpc(cmd, result, out);
        if (response != DSIM_STATUS_SUCCESS) {
            response = result;
        }
    }
    return response;
}

//
// Get all packets from the server
//
std::list<struct nsim::nsim_packet_info_t>
dsim_client::rpc_get_and_clear_output_packets(size_t timeout_in_milliseconds, size_t num_of_packets)
{
    api_lock lock(m_lock);
    std::list<struct nsim::nsim_packet_info_t> out;
    uint32_t timeout_in_milliseconds_out = static_cast<uint32_t>(timeout_in_milliseconds);
    uint32_t num_of_packets_out = static_cast<uint32_t>(num_of_packets);

    auto cmd = socket_command_type_e::GET_AND_CLEAR_OUTPUT_PACKETS;
    auto response = write_rpc(cmd, timeout_in_milliseconds_out, num_of_packets_out);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        response = read_rpc(cmd, result, out);
        if (response != DSIM_STATUS_SUCCESS) {
            response = result;
        }
    }
    return out;
}

//
// Push trigger info
//
dsim_status_e
dsim_client::rpc_inject_db_trigger(const struct nsim_db_trigger_info_t& trigger)
{
    api_lock lock(m_lock);
    return write_rpc_and_wait_for_status(socket_command_type_e::INJECT_DB_TRIGGER, trigger);
}

//
// Retrieve the connection handle of the server
//
dsim_status_e
dsim_client::rpc_get_connection_handle(std::string& out)
{
    api_lock lock(m_lock);
    auto cmd = socket_command_type_e::GET_CONNECTION_HANDLE;
    auto response = write_rpc(cmd);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        response = read_rpc(cmd, result, out);
        if (response != DSIM_STATUS_SUCCESS) {
            response = result;
        }
    }
    return response;
}

//
// Retrieve the device name from the server
//
std::string
dsim_client::rpc_get_device_name(void)
{
    std::string out;
    api_lock lock(m_lock);
    auto cmd = socket_command_type_e::GET_DEVICE_NAME;
    auto response = write_rpc(cmd);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        (void)read_rpc(cmd, result, out);
    }
    return out;
}

//
// Expose the NPU to the host.
//
dsim_status_e
dsim_client::rpc_set_expose_npu_host(void)
{
    api_lock lock(m_lock);
    return write_rpc_and_wait_for_status(socket_command_type_e::SET_EXPOSE_NPU_HOST);
}

//
// Set the slice context
//
dsim_status_e
dsim_client::rpc_set_slice_context(size_t slice_id, size_t context_id)
{
    api_lock lock(m_lock);
    uint32_t slice_id_out = static_cast<uint32_t>(slice_id);
    uint32_t context_id_out = static_cast<uint32_t>(context_id);
    return write_rpc_and_wait_for_status(socket_command_type_e::SET_SLICE_CONTEXT, slice_id_out, context_id_out);
}

//
// Get and clear the event queue, returning the events.
//
std::list<bit_vector>
dsim_client::rpc_get_and_clear_event_queue(void)
{
    api_lock lock(m_lock);
    std::list<bit_vector> out;
    auto cmd = socket_command_type_e::GET_AND_CLEAR_EVENT_QUEUE;
    auto response = write_rpc(cmd);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        read_rpc(cmd, result, out);
    }
    return out;
}

//
// Set the given modules log level
//
dsim_status_e
dsim_client::rpc_set_module_file_log_level(nsim::nsim_log_module_e module, npsuite::npsuite_log_level_e level)
{
    api_lock lock(m_lock);
    uint32_t module_out = static_cast<uint32_t>(module);
    uint32_t level_out = static_cast<uint32_t>(level);
    return write_rpc_and_wait_for_status(socket_command_type_e::SET_MODULE_FILE_LOG_LEVEL, module_out, level_out);
}

// Set the given module's stdout log level
//
//
dsim_status_e
dsim_client::rpc_set_module_stdout_log_level(nsim::nsim_log_module_e module, npsuite::npsuite_log_level_e level)
{
    api_lock lock(m_lock);
    uint32_t module_out = static_cast<uint32_t>(module);
    uint32_t level_out = static_cast<uint32_t>(level);
    return write_rpc_and_wait_for_status(socket_command_type_e::SET_MODULE_STDOUT_LOG_LEVEL, module_out, level_out);
}

//
// Clear all table device state
//
dsim_status_e
dsim_client::rpc_clear_all_device_state()
{
    api_lock lock(m_lock);
    return write_rpc_and_wait_for_status(socket_command_type_e::CLEAR_ALL_DEVICE_STATE);
}

//
// Get the number of packets waiting to be injected
//
size_t
dsim_client::rpc_get_num_packet_waiting_to_be_injected(void)
{
    api_lock lock(m_lock);
    size_t out{};
    auto cmd = socket_command_type_e::GET_NUM_PACKET_WAITING_TO_BE_INJECTED;
    auto response = write_rpc(cmd);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        uint32_t tmp{};
        read_rpc(cmd, result, tmp);
        out = static_cast<size_t>(tmp);
    }
    return out;
}

//
// Get the nplc log message count
//
size_t
dsim_client::rpc_get_num_log_messages(/* npsuite::npsuite_log_level_e */ int level)
{
    api_lock lock(m_lock);
    size_t out{};
    uint32_t level_out = static_cast<uint32_t>(level);

    auto cmd = socket_command_type_e::GET_NUM_LOG_MESSAGES;
    auto response = write_rpc(cmd, level_out);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        uint32_t tmp{};
        read_rpc(cmd, result, tmp);
        out = static_cast<size_t>(tmp);
    }
    return out;
}

//
// Table lookup
//
dsim_status_e
dsim_client::rpc_get_entry(const std::string& table_name, size_t index, const nsim::bit_vector& key, nsim::bit_vector& out_payload)
{
    api_lock lock(m_lock);
    uint32_t index_out = static_cast<uint32_t>(index);

    auto cmd = socket_command_type_e::GET_ENTRY;
    auto response = write_rpc(cmd, table_name, index_out, key);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        response = read_rpc(cmd, result, out_payload);
        if (response != DSIM_STATUS_SUCCESS) {
            response = result;
        }
    }
    return response;
}

//
// Longest prefix match table lookup
//
dsim_status_e
dsim_client::rpc_get_lpm_entry(const std::string& table_name,
                               size_t index,
                               const nsim::bit_vector& key,
                               size_t length,
                               nsim::bit_vector& out_payload)
{
    api_lock lock(m_lock);
    uint32_t index_out = static_cast<uint32_t>(index);
    uint32_t length_out = static_cast<uint32_t>(length);

    auto cmd = socket_command_type_e::GET_LPM_ENTRY;
    auto response = write_rpc(cmd, table_name, index_out, key, length_out);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        response = read_rpc(cmd, result, out_payload);
        if (response != DSIM_STATUS_SUCCESS) {
            response = result;
        }
    }
    return response;
}

//
// Ternary table lookup
//
dsim_status_e
dsim_client::rpc_get_ternary_entry(const std::string& table_name,
                                   size_t index,
                                   size_t line,
                                   nsim::bit_vector& out_key,
                                   nsim::bit_vector& out_mask,
                                   nsim::bit_vector& out_payload)
{
    api_lock lock(m_lock);
    uint32_t index_out = static_cast<uint32_t>(index);
    uint32_t line_out = static_cast<uint32_t>(line);

    auto cmd = socket_command_type_e::GET_TERNARY_ENTRY;
    auto response = write_rpc(cmd, table_name, index_out, line_out);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        response = read_rpc(cmd, result, out_key, out_mask, out_payload);
        if (response != DSIM_STATUS_SUCCESS) {
            response = result;
        }
    }
    return response;
}

//
// Set oversubscribed interfaces mode
//
dsim_status_e
dsim_client::rpc_set_oversubscribed_interfaces_detection_mode(nsim::oversubscribed_interfaces_detection_mode_e mode)
{
    api_lock lock(m_lock);
    uint32_t mode_out = static_cast<uint32_t>(mode);
    return write_rpc_and_wait_for_status(socket_command_type_e::SET_OVERSUBSCRIBED_INTERFACES_DETECTION_MODE, mode_out);
}

//
// Is the given port up
//
bool
dsim_client::rpc_is_port_up(size_t slice_id, size_t ifg, size_t pif)
{
    api_lock lock(m_lock);
    bool out{};
    uint32_t slice_id_out = static_cast<uint32_t>(slice_id);
    uint32_t ifg_out = static_cast<uint32_t>(ifg);
    uint32_t pif_out = static_cast<uint32_t>(pif);

    auto cmd = socket_command_type_e::IS_PORT_UP;
    auto response = write_rpc(cmd, slice_id_out, ifg_out, pif_out);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        read_rpc(cmd, result, out);
    }
    return out;
}

//
// Get all the port config for the given slice, ifg and pif
//
nsim_port_pif_config_t
dsim_client::rpc_get_port_config(size_t slice_id, size_t ifg, size_t pif)
{
    api_lock lock(m_lock);
    nsim_port_pif_config_t out;
    uint32_t slice_id_out = static_cast<uint32_t>(slice_id);
    uint32_t ifg_out = static_cast<uint32_t>(ifg);
    uint32_t pif_out = static_cast<uint32_t>(pif);

    auto cmd = socket_command_type_e::GET_PORT_CONFIG;
    auto response = write_rpc(cmd, slice_id_out, ifg_out, pif_out);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        read_rpc(cmd, result, out);
    }
    return out;
}

//
// Get the event queue write pointer
//
nsim::bit_vector
dsim_client::rpc_get_event_queue_write_ptr(void)
{
    api_lock lock(m_lock);
    nsim::bit_vector out;
    auto cmd = socket_command_type_e::GET_EVENT_QUEUE_WRITE_PTR;
    auto response = write_rpc(cmd);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        read_rpc(cmd, result, out);
    }
    return out;
}

//
// Get the event queue read pointer
//
nsim::bit_vector
dsim_client::rpc_get_event_queue_read_ptr(void)
{
    api_lock lock(m_lock);
    nsim::bit_vector out;
    auto cmd = socket_command_type_e::GET_EVENT_QUEUE_READ_PTR;
    auto response = write_rpc(cmd);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        read_rpc(cmd, result, out);
    }
    return out;
}

//
// Get the table ID from the given name
//
uint32_t
dsim_client::rpc_get_table_id_by_name(const std::string& name)
{
    api_lock lock(m_lock);
    uint32_t table_id{};
    auto cmd = socket_command_type_e::GET_TABLE_ID_BY_NAME;
    auto response = write_rpc(cmd, name);
    if (response == DSIM_STATUS_SUCCESS) {
        dsim_status_e result;
        read_rpc(cmd, result, table_id);
    }
    return table_id;
}

//
// Register a callback to be invoked when the logger logs a message.
//
npsuite::register_log_message_client_handle_t
dsim_client::register_log_message_callback(npsuite::npsuite_log_level_e level, npsuite::npsuite_logger_message_callback_t callback)
{
    assert(m_logger && "No logger, cannot register callback");
    return m_logger->register_log_message_callback(level, callback);
}

//
// Register a callback to be invoked when the logger logs a message.
//
npsuite::register_log_message_client_handle_t
dsim_client::register_log_message_callback(npsuite::npsuite_logger_message_callback_t callback)
{
    return register_log_message_callback(npsuite::NPSUITE_LOG_LEVEL_FATAL /* no filtering */, callback);
}

//
// Deregister a previous callback to be invoked when NSIM logs messages.
//
void
dsim_client::unregister_log_message_callback(const npsuite::register_log_message_client_handle_t& client_handle)
{
    assert(m_logger && "No logger, cannot unregister callback");
    m_logger->unregister_log_message_callback(client_handle);
}

} // namespace dsim
