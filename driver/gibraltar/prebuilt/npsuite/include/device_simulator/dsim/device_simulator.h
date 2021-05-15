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

#ifndef __DSIM_H__
#define __DSIM_H__

#include "device_simulator/dsim_config_interface.h"
#include "device_simulator/socket_command.h"
#include "device_simulator/dsim_common/socket_connection.h"
#include "device_simulator/dsim_common/nsim_command.h"
#include "device_simulator/packet_dma_inject.h"
#include "device_simulator/packet_dma_extract.h"
#include "nsim/nsim.h"
#include "utils/nsim_bv.h"
#include "utils/signal_handler.h"

#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <set>
#include <deque>
#if !defined(_WIN32) && !defined(_WIN64)
#include <pthread.h>
#endif
#include <assert.h>
#include <unordered_map>
#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif
struct place_udk_command;
namespace npsuite
{
class Logger;
}

namespace nsim
{
class nsim_core;
class register_container;
class memory_container;
class device_register;
class nsim_register_counter_listener;
class nsim_register_override_listener;
class nsim_register_arc_register_listener;
class nsim_register_ext_dma;
class nsim_register_inj_dma;
} // namespace nsim

namespace ref_model
{
class microcode_table_t;
}

namespace dsim
{
class dsim_socket_server;

/// @brief Callback for the user to check if the version of the npsuite/sdk match
///
/// @param[in] npsuite_version      NPSuite release version string
/// @param[in] sdk_version          SDK release version string
/// @param[in] opaque               User opaque data to be passed when triggering the callback
///
/// @retval VERSION_HANDSHAKE_MISMATCH   In case versions mismatch is detected
/// @retval VERSION_HANDSHAKE_OK         In case versions match
typedef bool (*version_handshake_cb_t)(const std::string /* npsuite_version */,
                                       const std::string /* sdk_version */,
                                       void* /* opaque */);

bool default_version_handshake_callback(const std::string npsuite_version, const std::string sdk_version, void* opaque_data);

class ServerKeepaliveThread;

/// @brief Server side implementation of server-client device simulation flow.
///
/// The simulator receives commands thru the provided socket and executes them on NSIM simulator.
/// device_simulator object should be running at a separate thread, since it's blocking thread execution while
/// listening.
class device_simulator : private dsim_config_interface
{
public:
    // D'tor
    ~device_simulator();

    // device_simulator API
    /// @brief Getting a string connection handle
    /// Returns a string connection handle structured  "$device_path/socket/$host:$port"
    std::string get_connection_handle() const;
    /// @brief Returns port
    size_t get_port() const;
    /// @brief Returns logger pointer
    npsuite::Logger* get_logger();
    /// @brief Returns nsim pointer
    nsim::nsim_core* get_nsim();
    /// @brief Creates device simulator and a thread that waits to commands.
    /// Returns pointer to created device simulator.
    /// After this operation, clients may connect to the socket.
    ///
    /// @param[in]  source_path     NPL code path.
    /// @param[in]  leaba_defined_path   leaba defined folder path.
    /// @param[in]  host   host path.
    /// @param[in]  port   port number, 0 for random port number to be chosen.
    /// @param[in]  path   device path.
    /// @param[in]  additional_params   additional parameters map[feature_type, feature_value]

    ///
    /// @retval     nullptr                     Operation failed.
    /// @retval     device_simulator ptr        Operation attempt successful, its local port to be used by client to connect,
    /// nsim can be used also.
    static device_simulator* create_and_run_simulator_server(const std::string& source_path,
                                                             const std::string& leaba_defined_path,
                                                             const char* host,
                                                             unsigned short port,
                                                             std::string path,
                                                             std::map<std::string, std::string> additional_params
                                                             = std::map<std::string, std::string>());

    /// @brief Creates device simulator and a thread that waits to commands.
    /// Returns pointer to created device simulator.
    /// After this operation, clients may connect to the socket.
    ///
    /// @param[in]  source_path     NPL code path.
    /// @param[in]  leaba_defined_path   leaba defined folder path.
    /// @param[in]  host   host path.
    /// @param[in]  port   port number, 0 for random port number to be chosen.
    /// @param[in]  path   device path.
    /// @param[in]  additional_params   additional parameters map[feature_type, feature_value]
    /// @param[in]  cb_pair             Callback + opaque_data for version validation handshaking
    ///
    /// @retval     nullptr                     Operation failed.
    /// @retval     device_simulator ptr        Operation attempt successful, its local port to be used by client to connect,
    /// nsim can be used also.
    static device_simulator* create_and_run_simulator_server(const std::string& source_path,
                                                             const std::string& leaba_defined_path,
                                                             const char* host,
                                                             unsigned short port,
                                                             std::string path,
                                                             std::map<std::string, std::string> additional_params,
                                                             std::pair<version_handshake_cb_t, void*>* cb_pair);

    static device_simulator* create_and_run_simulator_server_default(const std::string& source_path,
                                                                     const std::string& leaba_defined_path,
                                                                     const char* host,
                                                                     unsigned short port,
                                                                     std::string path,
                                                                     std::map<std::string, std::string> additional_params
                                                                     = std::map<std::string, std::string>());

    /// @brief Sets log level to INFO for the specified module, and the module
    /// acsts as a threshold, meaning the ones "above" the specified one
    /// will only log errors and fatals (default) and the ones "below"
    /// will be set to log level INFO.
    ///
    /// Set NSIM_LOG_NONE to log only errors and fatals for all modules.
    /// Set NSIM_LOG_FULL to log everything for all modules.
    ///
    /// @param[in]  module     log module to be set
    void set_log_level(nsim::nsim_log_module_e module);
    /// @brief sets log file
    /// @param[in]  log_file_path     path to log file
    /// @param[in]  logPrefixEnabled  Enable log prefix if true
    void set_log_file(const char* log_file_path, bool logPrefixEnabled);

    /// @brief Registers a callback to be triggered on version handshaking command
    /// Everytime a client tries to connect it send its own version and the version of the SDK
    /// to the DSIM server for handshaking validation, basically, DSIM client and server versions must match
    ///
    /// @param[in] ver_handshake_cb     User callback routine to be triggered and perform the validation
    /// @param[in] opaque_data          User defined opaque data to be sent when triggering the callback
    ///
    /// @retval ID >= 0         Index in the container where the cb has been added
    /// @retval ID < 0          Error, probably already registered.
    bool register_version_handshake_callback(version_handshake_cb_t ver_handshake_cb, void* opaque_data);

    /// @brief Unregisters a callback for handshaking validation
    ///
    /// @param[in] cb_id     ID of the callback to remove from the container
    ///
    /// @retval true        Success
    /// @retval false       Did not find a cb with that ID in the container
    bool unregister_version_handshake_callback(version_handshake_cb_t ver_handshake_cb, void* opaque_data);

    /// @brief Checks if the client version matches the server version
    ///
    /// @param[in] version_string     client version string in form <NPSUITE_VER>/<SDK_VER>
    ///
    /// @retval true        If the versions match or fail_on_versions_match is false and there is a mismatch (permissive mode)
    /// @retval false       Versions do not match (enforcing mode)
    bool version_validation(const std::string& npsuite_version, const std::string& sdk_version);

    ///
    /// @brief Dump local statistics about messages received from the client.
    ///
    void dump_debug_info(bool log);

    ///
    /// @brief Check if the simulator command server is still running.
    ///
    /// @retval true        Server is running
    /// @retval false       Server has stopped
    bool is_running(void);

private:
    // C'tor
    device_simulator(nsim::nsim_core* nsim,
                     const char* host,
                     unsigned short port,
                     std::string device_path,
                     npsuite::Logger* logger);
    //
    // Handle for all socket connections
    //
    std::mutex m_socket_server_mutex;
    class dsim_socket_server* m_socket_server{};

    bool run();
    bool initialize(std::map<std::string, std::string>& additional_params);
    bool initialize_keepalive_handler(std::map<std::string, std::string>& additional_params);
    bool initialize_device_registers();
    bool initialize_device_memories();
    bool initialize_additional_parameters(std::map<std::string, std::string>& additional_params);
    // Making these three functions public makes it very difficult to make the case
    // analysis of running threads and what to clean up during shutdown.  Moving
    // them private to avoid that situation.
    static device_simulator* create_simulator_server(const std::string& source_path,
                                                     const std::string& leaba_defined_path,
                                                     const char* host,
                                                     unsigned short port,
                                                     std::string path,
                                                     std::map<std::string, std::string> additional_params
                                                     = std::map<std::string, std::string>());
    static void run_dsim_server(device_simulator* server);
    static void run_simulator_server(device_simulator* server);

    dsim_status_e write_register(uint32_t block_id,
                                 uint32_t reg_address,
                                 uint16_t reg_width,
                                 size_t count,
                                 const void* in_val) override;

    dsim_status_e write_register_by_name(const std::string& name,
                                         size_t reg_index,
                                         uint16_t reg_width,
                                         size_t count,
                                         const void* in_val) override;

    dsim_status_e read_register(uint32_t block_id, uint32_t reg_address, uint16_t reg_width, size_t count, void* out_val) override;

    dsim_status_e read_register_by_name(const std::string& name,
                                        size_t reg_index,
                                        uint16_t reg_width,
                                        size_t count,
                                        void* out_val) override;

    dsim_status_e write_memory(uint32_t block_id,
                               uint32_t mem_address,
                               uint16_t entry_width,
                               size_t number_of_entries,
                               const void* in_val) override;

    dsim_status_e read_memory(uint32_t block_id,
                              uint32_t mem_address,
                              uint16_t entry_width,
                              size_t number_of_entries,
                              void* out_val) override;

    dsim_status_e add_property(std::string key, std::string value) override;

    dsim_status_e read_memory_by_name(const std::string& mem_name,
                                      size_t mem_index,
                                      uint32_t mem_entry,
                                      uint16_t entry_width,
                                      size_t number_of_entries,
                                      void* out_val) override;

    dsim_status_e write_memory_by_name(const std::string& mem_name,
                                       size_t mem_index,
                                       uint32_t mem_entry,
                                       uint16_t entry_width,
                                       size_t number_of_entries,
                                       const void* in_val) override;

    dsim_status_e handle_nsim_write_request(const nsim::nsim_command::command& cmd);

    dsim_status_e handle_nsim_place_udk_write_request(const place_udk_command* cmd);

    dsim_status_e handle_nsim_read_request(const nsim::nsim_command::command& cmd);

    void handle_reset_state_command(socket_command_header* cmd_hdr, std::unique_ptr<dsim::socket_connection_common>& sc);
    void handle_dump_debug_info_command(socket_command_header* cmd_hdr, std::unique_ptr<dsim::socket_connection_common>& sc);
    void handle_flush_command(socket_command_header* cmd_hdr, std::unique_ptr<dsim::socket_connection_common>& sc);

    void handle_ping_command(socket_command_header* cmd_hdr,
                             std::unique_ptr<dsim::socket_connection_common>& sc,
                             size_t received_bytes);

    void handle_destroy_simulator_command(socket_command_header* cmd_hdr,
                                          std::unique_ptr<dsim::socket_connection_common>& sc,
                                          size_t received_bytes);

    void handle_set_log_file_command(socket_command_header* cmd_hdr,
                                     std::unique_ptr<dsim::socket_connection_common>& sc,
                                     size_t received_bytes);

    void handle_set_log_level_command(socket_command_header* cmd_hdr,
                                      std::unique_ptr<dsim::socket_connection_common>& sc,
                                      size_t received_bytes);

    void handle_packet_dma_enable_command(socket_command_header* cmd_hdr,
                                          std::unique_ptr<dsim::socket_connection_common>& sc,
                                          size_t received_bytes);

    void handle_inject_packet_desc_command(socket_command_header* cmd_hdr,
                                           std::unique_ptr<dsim::socket_connection_common>& sc,
                                           size_t received_bytes);

    void handle_step_packet_command(socket_command_header* cmd_hdr,
                                    std::unique_ptr<dsim::socket_connection_common>& sc,
                                    size_t received_bytes);

    void handle_step_macro_command(socket_command_header* cmd_hdr,
                                   std::unique_ptr<dsim::socket_connection_common>& sc,
                                   size_t received_bytes);

    void handle_step_command(socket_command_header* cmd_hdr,
                             std::unique_ptr<dsim::socket_connection_common>& sc,
                             size_t received_bytes);

    void handle_trigger_lrc_fifo_command(socket_command_header* cmd_hdr,
                                         std::unique_ptr<dsim::socket_connection_common>& sc,
                                         size_t received_bytes);

    void handle_get_packet_command(socket_command_header* cmd_hdr,
                                   std::unique_ptr<dsim::socket_connection_common>& sc,
                                   size_t received_bytes);

    void handle_get_packets_command(socket_command_header* cmd_hdr,
                                    std::unique_ptr<dsim::socket_connection_common>& sc,
                                    size_t received_bytes);

    void handle_get_num_packets_command(socket_command_header* cmd_hdr,
                                        std::unique_ptr<dsim::socket_connection_common>& sc,
                                        size_t received_bytes);

    void handle_inject_db_trigger_command(socket_command_header* cmd_hdr,
                                          std::unique_ptr<dsim::socket_connection_common>& sc,
                                          size_t received_bytes);

    void handle_get_connection_handle_command(socket_command_header* cmd_hdr,
                                              std::unique_ptr<dsim::socket_connection_common>& sc,
                                              size_t received_bytes);

    void handle_get_device_name_command(socket_command_header* cmd_hdr,
                                        std::unique_ptr<dsim::socket_connection_common>& sc,
                                        size_t received_bytes);

    void handle_set_expose_npu_host_command(socket_command_header* cmd_hdr,
                                            std::unique_ptr<dsim::socket_connection_common>& sc,
                                            size_t received_bytes);

    void handle_set_slice_context_command(socket_command_header* cmd_hdr,
                                          std::unique_ptr<dsim::socket_connection_common>& sc,
                                          size_t received_bytes);

    void handle_get_and_clear_event_queue_command(socket_command_header* cmd_hdr,
                                                  std::unique_ptr<dsim::socket_connection_common>& sc,
                                                  size_t received_bytes);

    void handle_set_module_file_log_level_command(socket_command_header* cmd_hdr,
                                                  std::unique_ptr<dsim::socket_connection_common>& sc,
                                                  size_t received_bytes);

    void handle_set_module_stdout_log_level_command(socket_command_header* cmd_hdr,
                                                    std::unique_ptr<dsim::socket_connection_common>& sc,
                                                    size_t received_bytes);

    void handle_clear_all_device_state_command(socket_command_header* cmd_hdr,
                                               std::unique_ptr<dsim::socket_connection_common>& sc,
                                               size_t received_bytes);

    void handle_get_num_packet_waiting_to_be_injected_command(socket_command_header* cmd_hdr,
                                                              std::unique_ptr<dsim::socket_connection_common>& sc,
                                                              size_t received_bytes);

    void handle_get_num_log_messages_command(socket_command_header* cmd_hdr,
                                             std::unique_ptr<dsim::socket_connection_common>& sc,
                                             size_t received_bytes);

    void handle_get_entry_command(socket_command_header* cmd_hdr,
                                  std::unique_ptr<dsim::socket_connection_common>& sc,
                                  size_t received_bytes);

    void handle_get_lpm_entry_command(socket_command_header* cmd_hdr,
                                      std::unique_ptr<dsim::socket_connection_common>& sc,
                                      size_t received_bytes);

    void handle_get_ternary_entry_command(socket_command_header* cmd_hdr,
                                          std::unique_ptr<dsim::socket_connection_common>& sc,
                                          size_t received_bytes);

    void handle_set_oversubscribed_interfaces_detection_mode_command(socket_command_header* cmd_hdr,
                                                                     std::unique_ptr<dsim::socket_connection_common>& sc,
                                                                     size_t received_bytes);

    void handle_is_port_up_command(socket_command_header* cmd_hdr,
                                   std::unique_ptr<dsim::socket_connection_common>& sc,
                                   size_t received_bytes);

    void handle_get_port_config_command(socket_command_header* cmd_hdr,
                                        std::unique_ptr<dsim::socket_connection_common>& sc,
                                        size_t received_bytes);

    void handle_get_event_queue_write_ptr_command(socket_command_header* cmd_hdr,
                                                  std::unique_ptr<dsim::socket_connection_common>& sc,
                                                  size_t received_bytes);

    void handle_get_event_queue_read_ptr_command(socket_command_header* cmd_hdr,
                                                 std::unique_ptr<dsim::socket_connection_common>& sc,
                                                 size_t received_bytes);

    void handle_get_field_descriptor_command(socket_command_header* cmd_hdr,
                                             std::unique_ptr<dsim::socket_connection_common>& sc,
                                             size_t received_bytes);

    void handle_get_table_id_by_name_command(socket_command_header* cmd_hdr,
                                             std::unique_ptr<dsim::socket_connection_common>& sc,
                                             size_t received_bytes);

    bool extract_command_buffer(const nsim::nsim_command::command& cmd);
    uint64_t get_full_reg_address_by_name(std::string reg_name);

    //
    // If we have previously performed a write to a register that generated cached
    // data in the form of single or max counter data, then return a pointer to that
    // data along with the size.
    //
    void read_single_or_max_counter_data(size_t* send_size, void** send_what);
    void handle_signal(int);

    void update_client_info(std::unique_ptr<socket_connection_common>& sc,
                            const socket_command_header* cmd_hdr,
                            uint32_t client_id,
                            uint32_t cmd_len);
    void cleanup_client(std::unique_ptr<socket_connection_common>& sc, bool log_error = false);
    void cleanup_client_on_error(std::unique_ptr<socket_connection_common>& sc);

    //
    // This class+thread monitors keepalive events (DSIM client messages or ping). Upon a configured period of quiesence it
    // will exit the server. This avoids the server winding up as a zombie process if the client exits uncleanly, crashes etc...
    //
private:
    std::mutex server_keepalive_thread_mutex;
    class ServerKeepaliveThread* server_keepalive_thread{};

public:
    void client_keepalive_event(void);

private:
    typedef struct dsim_client_info_ {
        std::deque<transaction_info_t> prev_commands;
        uint64_t next_seqno = 0;
        uint32_t client_id = 0;
    } dsim_client_info_t;

    // nsim simulator
    nsim::nsim_core* m_nsim;
    std::string m_device_path;
    std::string m_host;
    size_t m_port;
    std::string m_connection_details;
    std::atomic<bool> m_shutdown_simulator;
    size_t m_max_number_of_connections;
    // I really want a semaphore here.  Future/promises are more
    // heavy weight than I need (no need to pass information).  However,
    // I need to lock a thread and unlock it explicitly when another thread
    // does something.  Using futures because std::semaphore is not in C++11
    std::promise<bool> m_run_has_ran;

    uint16_t m_npu_host_port;
    bool m_packet_dma_data_reordered;

    /// logger
    npsuite::Logger* m_logger;
    std::thread* m_running_thread;
    bool server_is_running{}; // Set to true if m_running_thread is running

    int32_t m_nsim_timer_resolution_miliseconds;
    // temp variables
    nsim::bit_vector m_key_bv;
    nsim::bit_vector m_value_bv;
    nsim::bit_vector m_mask_bv;
    uint32_t m_ternary_line;
    uint16_t m_lpm_key_len;
    // place_udk members
    uint16_t m_place_udk_macro_id;
    std::vector<udk_table_id_and_components> m_place_udk_tables_info;

    uint32_t m_sbif_block_id;

    uint32_t m_sim_access_block_id;
    uint32_t m_sim_access_mem_address_place_udk;
    uint32_t m_sim_access_nsim_command_mem;

    nsim::nsim_register_override_listener* m_register_override_listener;
    nsim::nsim_register_counter_listener* m_register_counter_listener;
    nsim::nsim_register_arc_register_listener* m_register_arc_register_listener;
    nsim::nsim_register_ext_dma* m_register_ext_dma{};
    nsim::nsim_register_inj_dma* m_register_inj_dma{};

    nsim::register_container* m_register_container;
    nsim::memory_container* m_memory_container;

    std::vector<std::pair<version_handshake_cb_t, void* /* opaque_data */>> m_ver_handshake_cbs;
    bool m_fail_on_versions_mismatch;

    size_t m_num_of_commands_to_dump_on_crash;
    npsuite::SignalHandler::CallbackId_t m_signal_callback_id = npsuite::SignalHandler::NoCallbackId;

    uint32_t m_next_client_id;

    std::unordered_map<int, dsim_client_info_t> m_dsim_clients;
    void dump_debug_info(std::unordered_map<int, dsim_client_info_t>::iterator& it, bool log);
    bool dump_debug_info(std::unique_ptr<socket_connection_common>& sc, bool log_error);
    void handle_write_memory_socket_command(socket_command_header* cmd_hdr);
    void handle_read_memory_socket_command(socket_command_header* cmd_hdr,
                                           std::unique_ptr<dsim::socket_connection_common>& sc,
                                           uint8_t* send_reply_buffer);
    void handle_write_memory_by_name_socket_command(socket_command_header* cmd_hdr);
    void handle_read_memory_by_name_socket_command(socket_command_header* cmd_hdr,
                                                   std::unique_ptr<dsim::socket_connection_common>& sc,
                                                   uint8_t* send_reply_buffer);
    void handle_write_register_by_name_socket_command(socket_command_header* cmd_hdr,
                                                      std::unique_ptr<dsim::socket_connection_common>& sc);
    void handle_read_register_by_name_socket_command(socket_command_header* cmd_hdr,
                                                     std::unique_ptr<dsim::socket_connection_common>& sc,
                                                     uint8_t* send_reply_buffer);
    void handle_write_register_socket_command(socket_command_header* cmd_hdr, std::unique_ptr<dsim::socket_connection_common>& sc);
    void handle_read_register_socket_command(socket_command_header* cmd_hdr,
                                             std::unique_ptr<dsim::socket_connection_common>& sc,
                                             uint8_t* send_reply_buffer);
    void handle_inject_packet_socket_command(socket_command_header* cmd_hdr,
                                             std::unique_ptr<dsim::socket_connection_common>& sc,
                                             nsim_packet_info_t& packet_info,
                                             uint8_t* packet_data);
    void handle_extract_packets_socket_command(socket_command_header* cmd_hdr,
                                               std::unique_ptr<dsim::socket_connection_common>& sc,
                                               uint8_t* packet_data);
    void handle_device_info_sync_socket_command(socket_command_header* cmd_hdr,
                                                std::unique_ptr<dsim::socket_connection_common>& sc,
                                                size_t received_bytes);
    void handle_version_handshake_socket_command(socket_command_header* cmd_hdr,
                                                 std::unique_ptr<dsim::socket_connection_common>& sc);
    void handle_log_message_socket_command(socket_command_header* cmd_hdr);
    void handle_add_property_socket_command(socket_command_header* cmd_hdr);

    //
    // Internal socket send wrapper. cmd_hdr here is only used for debugging.
    //
    bool send(std::unique_ptr<socket_connection_common>& sc,
              uint64_t len_in_bytes,
              void* buf,
              const socket_command_header* cmd_hdr,
              bool close_connection_on_error = true);

    //
    // Internal socket send wrapper. cmd here is only used for debugging.
    //
    bool send(std::unique_ptr<socket_connection_common>& sc,
              uint64_t len_in_bytes,
              void* buf,
              const socket_command_type_e cmd,
              bool close_connection_on_error = true);

    //
    // Perform common actions post a successful send of a message to the DSIM server
    //
    void handle_send_success(std::unique_ptr<socket_connection_common>& sc,
                             uint64_t len_in_bytes,
                             const socket_command_type_e cmd,
                             bool save = false);
    void handle_send_success(std::unique_ptr<socket_connection_common>& sc,
                             uint64_t len_in_bytes,
                             const socket_command_header* cmd_hdr,
                             bool save = false);

    //
    // Perform common actions post a failed send of a message to the DSIM server
    //
    void handle_send_error(std::unique_ptr<socket_connection_common>& sc, uint64_t len_in_bytes, const socket_command_type_e cmd);
    void handle_send_error(std::unique_ptr<socket_connection_common>& sc,
                           uint64_t len_in_bytes,
                           const socket_command_header* cmd_hdr);

    //
    // Perform common actions post a successful receive of a message from the DSIM server
    //
    void handle_receive_success(std::unique_ptr<socket_connection_common>& sc,
                                uint64_t len_in_bytes,
                                const socket_command_header* cmd_hdr);

    //
    // Something went wrong receiving from the client
    //
    void handle_receive_error(std::unique_ptr<socket_connection_common>& sc,
                              uint64_t len_in_bytes,
                              const socket_command_header* cmd_hdr);

    //
    // Used to dampen errors, just in case we get a flood of them
    //
    static const int handle_send_error_frequency_in_seconds = 60;
    std::chrono::time_point<HiResClock> last_handle_send_error_time;
    bool last_handle_send_error_time_set;

    //
    // Serialize data and send to the DSIM client
    //
    dsim_status_e write_rpc(const socket_command_type_e cmd, std::unique_ptr<dsim::socket_connection_common>& sc);
    dsim_status_e write_rpc(const socket_command_type_e cmd,
                            const dsim_rpc_version_t version,
                            std::unique_ptr<dsim::socket_connection_common>& sc);
    template <typename T, typename... Rest>
    dsim_status_e write_rpc_internal(const dsim_rpc_version_t version,
                                     const bool has_payload,
                                     const socket_command_type_e cmd,
                                     std::unique_ptr<dsim::socket_connection_common>& sc,
                                     const T t,
                                     Rest... rest);
    template <typename T, typename... Rest>
    dsim_status_e write_rpc(const socket_command_type_e cmd,
                            std::unique_ptr<dsim::socket_connection_common>& sc,
                            const T t,
                            Rest... rest);
    template <typename T, typename... Rest>
    dsim_status_e write_rpc(const socket_command_type_e cmd,
                            const dsim_rpc_version_t version,
                            std::unique_ptr<dsim::socket_connection_common>& sc,
                            const T t,
                            Rest... rest);

    //
    // Deserialize data from the DSIM client.
    //
    dsim_status_e read_rpc(socket_command_header* cmd_hdr, size_t received_bytes);
    dsim_status_e read_rpc(socket_command_header* cmd_hdr, dsim_rpc_version_t& version, size_t received_bytes);
    template <typename T, typename... Rest>
    dsim_status_e read_rpc_internal(dsim_rpc_version_t& version,
                                    const bool has_payload,
                                    socket_command_header* cmd_hdr,
                                    size_t received_bytes,
                                    T& t,
                                    Rest&... rest);
    template <typename T, typename... Rest>
    dsim_status_e read_rpc(socket_command_header* cmd_hdr, size_t received_bytes, T& t, Rest&... rest);
    template <typename T, typename... Rest>
    dsim_status_e read_rpc(socket_command_header* cmd_hdr, dsim_rpc_version_t& version, size_t received_bytes, T& t, Rest&... rest);
};

extern "C" {
/// @brief Creates device simulator and a thread that waits to process commands.
/// Returns pointer to created device simulator.
/// After this operation, clients may connect to the socket.
///
/// @param[in]  source_path         NPL code path.
/// @param[in]  leaba_defined_path  leaba defined folder path.
/// @param[in]  host                host path.
/// @param[in]  port                port number, 0 for random port number to be chosen.
/// @param[in]  path                device path.
/// @param[in]  additional_params   additional parameters map[feature_type, feature_value]

///
/// @retval     nullptr                 Operation failed.
/// @retval     device_simulator ptr    Operation attempt successful, its local port to be used by client to connect,
/// nsim can be used also.
device_simulator* create_and_run_simulator_server(const std::string& source_path,
                                                  const std::string& leaba_defined_path,
                                                  const char* host,
                                                  unsigned short port,
                                                  std::string path,
                                                  std::pair<version_handshake_cb_t, void*> cb_pair,
                                                  std::map<std::string, std::string> additional_params
                                                  = std::map<std::string, std::string>());

device_simulator* create_and_run_simulator_server_default(const std::string& source_path,
                                                          const std::string& leaba_defined_path,
                                                          const char* host,
                                                          unsigned short port,
                                                          std::string path,
                                                          std::map<std::string, std::string> additional_params
                                                          = std::map<std::string, std::string>());

//
// NOTE cannot return C++ types within extern C code, hence some of the void returns below:
//
// NOTE Keep in sync with the below
//
void destroy_simulator(device_simulator* server);
void set_log_level(device_simulator*, nsim::nsim_log_module_e module);
void get_device_name(device_simulator*, std::string& out);
void get_connection_handle(device_simulator*, std::string& out);
bool inject_packet(device_simulator*, const nsim_packet_info_t& packet_info, const nsim::nsim_name_value_map_t& initial_values);
bool step_packet(device_simulator*);
bool step_macro(device_simulator*);
bool step(device_simulator*);
void trigger_lrc_fifo(device_simulator*);
void packet_dma_enable(device_simulator*, bool);
void set_log_file(device_simulator*, const char* p, bool logPrefixEnabled);
bool inject_db_trigger(device_simulator*, const nsim_db_trigger_info_t& trigger_info);
void get_and_clear_output_packets(device_simulator*, std::list<nsim_packet_info_t>& out);
bool set_expose_npu_host(device_simulator*);
bool set_slice_context(device_simulator*, size_t slice_id, size_t context_id);
bool get_and_clear_event_queue(device_simulator*, std::list<nsim::bit_vector>& out);
}

//
// NOTE Keep in sync with the above
//
typedef dsim::device_simulator* (*c_api_create_and_run_simulator_server_t)(const std::string& source_path,
                                                                           const std::string& leaba_defined_path,
                                                                           const char* host,
                                                                           unsigned short port,
                                                                           std::string path,
                                                                           std::map<std::string, std::string> additional_params);

typedef void (*c_api_destroy_simulator_t)(dsim::device_simulator*);
typedef void (*c_api_set_log_level_t)(dsim::device_simulator*, nsim::nsim_log_module_e module);
typedef void (*c_api_get_device_name_t)(dsim::device_simulator*, std::string& out);
typedef void (*c_api_get_connection_handle_t)(dsim::device_simulator*, std::string& out);
typedef bool (*c_api_inject_packet_t)(dsim::device_simulator*,
                                      const nsim_packet_info_t& packet_info,
                                      const nsim::nsim_name_value_map_t& initial_values);
typedef bool (*c_api_step_packet_t)(dsim::device_simulator*);
typedef bool (*c_api_step_macro_t)(dsim::device_simulator*);
typedef bool (*c_api_step_t)(dsim::device_simulator*);
typedef void (*c_api_trigger_lrc_fifo_t)(dsim::device_simulator*);
typedef void (*c_api_packet_dma_enable_t)(dsim::device_simulator*, bool);
typedef void (*c_api_set_log_file_t)(dsim::device_simulator*, const char* p, bool logPrefixEnabled);
typedef bool (*c_api_inject_db_trigger_t)(dsim::device_simulator*, const nsim_db_trigger_info_t& trigger_info);
typedef void (*c_api_get_and_clear_output_packets_t)(dsim::device_simulator*, std::list<nsim_packet_info_t>& out);
typedef bool (*c_api_set_expose_npu_host_t)(dsim::device_simulator*);
typedef bool (*c_api_set_slice_context_t)(dsim::device_simulator*, size_t slice_id, size_t context_id);
typedef bool (*c_api_get_and_clear_event_queue_t)(dsim::device_simulator*, std::list<nsim::bit_vector>& out);

struct device_simulator_apis {
    c_api_create_and_run_simulator_server_t m_create_and_run_simulator_server{};
    c_api_destroy_simulator_t m_destroy_simulator{};
    c_api_set_log_level_t m_set_log_level{};
    c_api_get_device_name_t m_get_device_name{};
    c_api_get_connection_handle_t m_get_connection_handle{};
    c_api_inject_packet_t m_inject_packet{};
    c_api_step_packet_t m_step_packet{};
    c_api_step_macro_t m_step_macro{};
    c_api_step_t m_step{};
    c_api_trigger_lrc_fifo_t m_trigger_lrc_fifo{};
    c_api_packet_dma_enable_t m_packet_dma_enable{};
    c_api_get_and_clear_output_packets_t m_get_and_clear_output_packets;
    c_api_set_log_file_t m_set_log_file{};
    c_api_inject_db_trigger_t m_inject_db_trigger{};
    c_api_set_expose_npu_host_t m_set_expose_npu_host{};
    c_api_set_slice_context_t m_set_slice_context{};
    c_api_get_and_clear_event_queue_t m_get_and_clear_event_queue{};
};

} // namespace dsim

#endif // __NSIM_DEVICE_SIMULATOR_H__
