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

#ifndef __DSIM_CLIENT_H__
#define __DSIM_CLIENT_H__

#include "device_simulator/dsim_config_interface.h"
#include "device_simulator/packet_dma_inject.h"
#include "device_simulator/packet_dma_extract.h"
#include "device_simulator/socket_command.h"
#include "nsim/nsim_log_interface.h"
#include "device_simulator/dsim_rpc_interface.h"
#include "nsim/nsim_data_interface.h"    // for nsim_packet_info_t, nsim_db_trigger_info_t
#include "nsim/nsim_control_interface.h" // for nsim_source_location_info_t
#include "nsim/nsim_log_interface.h"
#include "utils/nsim_bv.h"
#include "utils/signal_handler.h"

#include <mutex>
#include <string>
#include <set>
#include <deque>
#include <list>
#include <memory>

namespace npsuite
{
class Logger;
}
namespace dsim
{
class socket_client;

/// @brief Log message function. Should be used as callback in modules which do not have direct access to nsim.
///
/// @param[in] opaque                   NSIM object pointer
/// @param[in] nsim_log_level           Integer version of the npsuite::npsuite_log_level_e
/// @param[in] user_prefix_identifier   User prefix identifier for custom print of the logger module name
/// @param[in] message                  User string message
void log_user_message(void* opaque, int nsim_log_level, std::string user_prefix_identifier, std::string message);

/// @brief Client side of server-client device simulation flow.
///
/// The client is instantiated on HLD side and sends commands for execution through a socket.
class dsim_client : public dsim_config_interface, public nsim::nsim_log_interface, public dsim_rpc_interface
{
public:
    /// C'tor
    dsim_client();
    dsim_client(int num_connection_retries, int timeout_between_retries);
    ~dsim_client() override;
    /// @brief intializes client including socket
    ///
    /// @param[in]  socket_addr   Address of socket
    /// @param[in]  port          Port for connection
    /// @param[in]  sdk_version   String describing the client's version
    ///
    /// @retval     false         Operation failed.
    /// @retval     true          Operation failed.
    bool initialize(const char* socket_addr, size_t port, const char* sdk_version = nullptr);

    /// @brief Reset state for the client and server. If more than one client exists, then
    /// local client state will need to be reset on each client.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e reset_state(void);

    /// @brief Flush the DSIM client to server connection. This works by waiting
    /// for a response to the flush from the DSIM server. This then indicates
    /// that the server has finished processing all preceeding messages.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e flush(void);

    /// @brief Dump stats and recent messages to stderr.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e dump_debug_info(void);

    /// @brief get npsuite release version
    ///
    /// @return release version string
    std::string get_release_version();

    /// @brief Get number of connection retries to the server
    ///
    /// @retval Number of connection retries
    int get_num_of_connection_retries();

    /// @brief Set number of connection retries to the server
    ///
    /// @param[in] num_connection_retries   Number of connection retries
    void set_num_of_connection_retries(int num_connection_retries);

    /// @brief Get timeout between retries in seconds
    ///
    /// @retval timeout between retries in seconds
    int get_timeout_between_retries();

    /// @brief Set timeout between retries in seconds
    ///
    /// @param[in] timeout_in_sec   timeout between retries in seconds
    void set_timeout_between_retries(int timeout_in_sec);

    /// @brief Sets log level to INFO for the specified module, and the module
    /// acsts as a threshold, meaning the ones "above" the specified one
    /// will only log errors and fatals (default) and the ones "below"
    /// will be set to log level INFO.
    ///
    /// Set NSIM_LOG_NONE to log only errors and fatals for all modules.
    /// Set NSIM_LOG_FULL to log everything for all modules.
    ///
    /// @param[in]  module     log module to be set
    void set_log_level(nsim::nsim_log_module_e module) override;
    /// @brief Sets the log level to file for specified module.
    /// If NSIM_LOG_FULL is passed as the module, the specified level is set for all modules.
    /// If NSIM_LOG_NONE is passed as the module, nothing is done.
    ///
    /// @param[in] module   module
    ///
    /// @param[in] level    log level
    void set_module_file_log_level(nsim::nsim_log_module_e module, npsuite::npsuite_log_level_e level) override;
    /// @brief Sets the log level to standard output for specified module.
    /// If NSIM_LOG_FULL is passed as the module, the specified level is set for all modules.
    /// If NSIM_LOG_NONE is passed as the module, nothing is done.
    ///
    /// @param[in] module   module
    ///
    /// @param[in] level    log level
    void set_module_stdout_log_level(nsim::nsim_log_module_e module, npsuite::npsuite_log_level_e level) override;
    /// @brief Initializes the logger
    ///
    /// @param[in]  log_file_path   path to the log file
    void set_log_file(const char* log_file_path) override;

    /// @brief Initializes the logger
    ///
    /// @param[in]  log_file_path   path to the log file
    ///
    /// @param[in]  logPrefixEnabled  enables time prefix of log
    void set_log_file(const char* log_file_path, bool logPrefixEnabled) override;

    /// @brief Initializes the logger
    ///
    /// @param[in]  log_file_path     path to the log file
    ///
    /// @param[in]  logPrefixEnabled  enables time prefix of log
    ///
    /// @param[in]  maxLogSize        sets the maximum log file size
    ///
    /// @param[in]  maxLogFiles       sets the maximum number of log files (log will be distributed over this many files)
    ///
    /// @param[in]  compress          enable log file compression if true
    void set_log_file(const char* log_file_path,
                      bool logPrefixEnabled,
                      size_t maxLogSize,
                      size_t maxLogFiles,
                      bool compress) override;

    /// @brief Print user log INFO message
    ///
    /// @param[in]  loglevel                    Message loglevel
    /// @param[in]  user_prefix_identifier      User prefix identifier, will appear before the message
    /// @param[in]  message                     String message
    void nsim_log_message(npsuite::npsuite_log_level_e loglevel, std::string user_prefix_identifier, std::string message) override;

    /// @brief Register a callback to be invoked when NSIM logs messages. Logs of a higher level than "log_level" are
    /// filtered.
    ///
    /// @param[in]  log_level                   Message loglevel for filtering
    /// @param[in]  callback                    Client function to call upon NSIM logging a message
    ///
    /// @retval Handle returned to uniquely identify this callback registration
    npsuite::register_log_message_client_handle_t register_log_message_callback(
        npsuite::npsuite_log_level_e log_level,
        npsuite::npsuite_logger_message_callback_t callback);

    /// @brief Register a callback to be invoked when NSIM logs messages. No filtering of logs occurs here.
    ///
    /// @param[in]  callback                    Client function to call upon NSIM logging a message
    ///
    /// @retval Handle returned to uniquely identify this callback registration
    npsuite::register_log_message_client_handle_t register_log_message_callback(
        npsuite::npsuite_logger_message_callback_t callback);

    /// @brief Deregister a previous log message callback. If the client is not registered this is a no-op.
    ///
    /// @param[in]  client_handle               Handle to uniquely identify this callback registration
    void unregister_log_message_callback(const npsuite::register_log_message_client_handle_t& client_handle);

    /// @brief Write register callback.
    ///
    /// @param[in]  block_id               Block ID of the register.
    /// @param[in]  reg_address            Register address in the block.
    /// @param[in]  reg_width              Width in byte resolution.
    /// @param[in]  count                  Number of consecutive entries to be read.
    /// @param[out] in_val                 Value to be written to the register.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e write_register(uint32_t block_id,
                                 uint32_t reg_address,
                                 uint16_t reg_width,
                                 size_t count,
                                 const void* in_val) override;

    /// @brief Write register by name callback.
    ///
    /// @param[in]  reg_name               Register name
    /// @param[in]  reg_index              Register index
    /// @param[in]  reg_address            Register address in the block.
    /// @param[in]  reg_width              Width in byte resolution.
    /// @param[in]  count                  Number of consecutive entries to be read.
    /// @param[out] in_val                 Value to be written to the register.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e write_register_by_name(const std::string& name,
                                         size_t reg_index,
                                         uint16_t reg_width,
                                         size_t count,
                                         const void* in_val) override;

    /// @brief Read register callback.
    ///
    /// @param[in]  block_id               Block ID of the register.
    /// @param[in]  reg_address            Register address in the block.
    /// @param[in]  reg_width              Width in byte resolution.
    /// @param[in]  count                  Number of consecutive entries to be read.
    /// @param[out] out_val                Return value destination buffer.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e read_register(uint32_t block_id, uint32_t reg_address, uint16_t reg_width, size_t count, void* out_val) override;

    /// @brief Read register by name callback.
    ///
    /// @param[in]  reg_name               Register name
    /// @param[in]  reg_index              Register index
    /// @param[in]  reg_address            Register address in the block.
    /// @param[in]  reg_width              Width in byte resolution.
    /// @param[in]  count                  Number of consecutive entries to be read.
    /// @param[out] out_val                Return value destination buffer.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e read_register_by_name(const std::string& name,
                                        size_t reg_index,
                                        uint16_t reg_width,
                                        size_t count,
                                        void* out_val) override;

    /// @brief Write memory callback.
    ///
    /// @param[in]  block_id               Block ID of the memory.
    /// @param[in]  mem_address            Memory address in the block.
    /// @param[in]  mem_width              Memory entry width in byte resolution.
    /// @param[in]  mem_entries            Number of consecutive entries to be read.
    /// @param[out] in_val                 Value to be written.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e write_memory(uint32_t block_id,
                               uint32_t mem_address,
                               uint16_t mem_width,
                               size_t mem_entries,
                               const void* in_val) override;
    /// @brief Read memory callback.
    ///
    /// @param[in]  block_id               Block ID of the memory.
    /// @param[in]  mem_address            Memory address in the block.
    /// @param[in]  mem_width              Memory entry width in byte resolution.
    /// @param[in]  mem_entries            Number of consecutive entries to be read.
    /// @param[out] out_val                Return value destination buffer.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e read_memory(uint32_t block_id,
                              uint32_t mem_address,
                              uint16_t mem_width,
                              size_t mem_entries,
                              void* out_val) override;

    /// @brief Read memory by name callback.
    ///
    /// @param[in]  mem_name               Name of the block ID of the memory.
    /// @param[in]  mem_index              Memory array index
    /// @param[in]  mem_entry              Memory address in the block.
    /// @param[in]  mem_width              Memory entry width in byte resolution.
    /// @param[in]  mem_entries            Number of consecutive entries to be read.
    /// @param[out] out_val                Return value destination buffer.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e read_memory_by_name(const std::string& mem_name,
                                      size_t mem_index,
                                      uint32_t mem_entry,
                                      uint16_t mem_width,
                                      size_t mem_entries,
                                      void* out_val) override;

    /// @brief Write memory by name callback.
    ///
    /// @param[in]  mem_name               Name of the block ID of the memory.
    /// @param[in]  mem_index              Memory array index
    /// @param[in]  mem_entry              Memory address in the block.
    /// @param[in]  mem_width              Memory entry width in byte resolution.
    /// @param[in]  mem_entries            Number of consecutive entries to be read.
    /// @param[out] in_val                 Value to be written.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EINVAL    One of the parameters is invalid.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e write_memory_by_name(const std::string& mem_name,
                                       size_t mem_index,
                                       uint32_t mem_entry,
                                       uint16_t mem_width,
                                       size_t mem_entries,
                                       const void* in_val) override;

    dsim_status_e read_modify_write_memory(uint32_t block_id,
                                           uint32_t mem_address,
                                           uint16_t mem_width,
                                           uint16_t data_offset,
                                           uint16_t data_width,
                                           size_t mem_entries,
                                           const void* in_val);

    /// @brief Add a generic key/value property
    dsim_status_e add_property(std::string key, std::string value) override;

    /// @brief Get the name of device client is connected to
    std::string get_device_name() const;

    /// @brief Get the device revision of the device client is connected to
    std::string get_device_revision() const;

    /// @brief Get SIM_ACCESS block id
    uint32_t get_sim_access_block_id() const;

    /// @brief Get Place UDK address
    uint32_t get_sim_access_mem_address_place_udk() const;

    /// @brief Get nsim command mem address
    uint32_t get_sim_access_nsim_command_mem_address() const;

    /// @brief Used for dumping debug info on crashes
    ///
    /// @param[in] log             If true, uses logging infra if enabled to
    ///                            emit the debug information.  Otherwise the
    ///                            debug information is sent to stderr
    void dump_debug_info(bool log, bool dump_stats = false);

    dsim_status_e read_max_counters_cache(uint64_t mem_address, uint16_t mem_width, size_t mem_entries, void* out_val);

    /// @brief Test the client connection and wait for a response
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_ping(void) override;

    /// @brief Teardown the server.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_destroy_simulator(void) override;

    /// @brief Set the DSIM server log file path
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_set_server_log_file(const std::string& log_file_path, bool logPrefixEnabled) override;

    /// @brief Set the DSIM server log level
    ///
    /// Sets log level to INFO for the specified module, and the module
    /// acsts as a threshold, meaning the ones "above" the specified one
    /// will only log errors and fatals (default) and the ones "below"
    /// will be set to log level INFO.
    ///
    /// Set NSIM_LOG_NONE to log only errors and fatals for all modules.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_set_server_log_level(nsim::nsim_log_module_e) override;

    /// @brief Enable packet DMA
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_packet_dma_enable(bool) override;

    /// @brief Inject the given packet descriptor information
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_inject_packet_desc(const struct nsim::nsim_packet_info_t& packet,
                                         const std::map<std::string, std::string>& initial_state) override;

    /// @brief Inject the given packet
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_inject_packet(const std::string& packet,
                                    size_t slice_id,
                                    size_t ifg,
                                    size_t pif,
                                    const std::map<std::string, std::string>& initial_values) override;

    /// @brief Simulate one packet.
    ///
    /// Evaluates the current packet execution, stopping one step before the packet finishes.
    /// Invoking #step() after #step_macro() will load the next macro.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_step_packet(void) override;

    /// @brief Step the simulation one macro forward.
    /// Evaluates the current macro, stopping one step before end of the macro.
    /// Invoking #step() after #step_macro() will load the next macro.
    //
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_step_macro(void) override;

    /// @brief Invoking #step() after #step_macro() will load the next macro.
    /// Evaluates the next statement to be executed, and advances the current statement location.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_step(void) override;

    /// @brief Sets lrc_fifo trigger to run before next packet
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_trigger_lrc_fifo(void) override;

    /// Get a single packet from the server. This will also clear out any other waiting packets.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_get_packet(struct nsim::nsim_packet_info_t&) override;

    /// @brief Get all packets from the server
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_get_packets(std::list<struct nsim::nsim_packet_info_t>&) override;
    std::list<struct nsim::nsim_packet_info_t> rpc_get_and_clear_output_packets(size_t timeout_in_milliseconds,
                                                                                size_t num_of_packets) override;

    /// @brief Push trigger info
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_inject_db_trigger(const struct nsim_db_trigger_info_t& trigger) override;

    /// @brief Retrieve the connection handle of the server
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_get_connection_handle(std::string&) override;

    /// @brief Retrieve the device name
    ///
    /// @retval     The device name
    std::string rpc_get_device_name(void) override;

    /// @brief Expose the NPU to the host
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_set_expose_npu_host(void) override;

    /// @brief Set the slice contest
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_set_slice_context(size_t slice_id, size_t context_id) override;

    /// @brief Get and clear the event queue, returning a list of events
    ///
    /// @retval     List of events (as bit vectors)
    std::list<nsim::bit_vector> rpc_get_and_clear_event_queue(void) override;

    /// @brief Set the given module's log level
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_set_module_file_log_level(nsim::nsim_log_module_e module, npsuite::npsuite_log_level_e level) override;

    /// @brief Set the given module's stdout log level
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_set_module_stdout_log_level(nsim::nsim_log_module_e module, npsuite::npsuite_log_level_e level) override;

    /// @brief Clear all table device state
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_clear_all_device_state() override;

    /// @brief Get the number of packets waiting to be injected
    ///
    /// @retval     Number of packets waiting to be injected
    size_t rpc_get_num_packet_waiting_to_be_injected(void) override;

    /// @brief Get the nplc log message count
    ///
    /// @retval     Number of log messages corresponding to the given level
    size_t rpc_get_num_log_messages(/* npsuite::npsuite_log_level_e */ int level) override;

    /// @brief Table lookup
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_get_entry(const std::string& table_name,
                                size_t index,
                                const nsim::bit_vector& key,
                                nsim::bit_vector& out_payload) override;

    /// @brief Longest prefix table query
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_get_lpm_entry(const std::string& table_name,
                                    size_t index,
                                    const nsim::bit_vector& key,
                                    size_t length,
                                    nsim::bit_vector& out_payload) override;

    /// @brief Ternary table lookup
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_get_ternary_entry(const std::string& table_name,
                                        size_t index,
                                        size_t line,
                                        nsim::bit_vector& out_key,
                                        nsim::bit_vector& out_mask,
                                        nsim::bit_vector& out_payload) override;

    /// @brief Set oversubscribed interfaces mode
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    dsim_status_e rpc_set_oversubscribed_interfaces_detection_mode(nsim::oversubscribed_interfaces_detection_mode_e) override;

    /// @brief Is the given port up
    ///
    /// @retval     True/up, False/down
    bool rpc_is_port_up(size_t slice_id, size_t ifg, size_t pif) override;

    /// @brief Get all the port config for the given slice, ifg and pif
    ///
    /// @retval     Return mac lane port config for given slice/ifg/pif
    nsim_port_pif_config_t rpc_get_port_config(size_t slice_id, size_t ifg, size_t pif) override;

    /// @brief Get the event queue write pointer
    ///
    /// @retval     Bit vector of write pointer
    nsim::bit_vector rpc_get_event_queue_write_ptr(void) override;

    /// @brief Get the event queue read pointer
    ///
    /// @retval     Bit vector of read pointer
    nsim::bit_vector rpc_get_event_queue_read_ptr(void) override;

    /// @brief Get the table name ID
    ///
    /// @retval     Table ID
    uint32_t rpc_get_table_id_by_name(const std::string& name) override;

private:
    void handle_signal(int);
    void save_transaction_info(const std::string& connection_details, const socket_command_header* cmd_hdr, uint32_t cmd_len);

    //
    // A wrapper for socket_connection send that does extra work upon fail/pass.
    //
    bool send(uint64_t len_in_bytes, socket_command_header* cmd_hdr, bool save = false);

    //
    // A wrapper for socket_connection send that does extra work upon fail/pass.
    // Additionally saves the message to the transaction history.
    //
    bool send_and_save(uint64_t len_in_bytes, socket_command_header* cmd_hdr);

    //
    // Perform common actions post a successful send of a message to the DSIM server
    //
    void handle_send_success(uint64_t len_in_bytes, const socket_command_header* cmd_hdr, bool save = false);

    //
    // Perform common actions prior to sending a command.
    //
    void handle_pre_send(uint64_t len_in_bytes, const socket_command_header* cmd_hdr);

    //
    // Perform common actions post a failed send of a message to the DSIM server
    //
    void handle_send_error(uint64_t len_in_bytes, const socket_command_header* cmd_hdr);

    //
    // Perform common actions post a successful receive of a message from the DSIM server
    //
    void handle_receive_success(uint64_t len_in_bytes, const socket_command_type_e);

    //
    // Used by the client to try to indicate to the server that it has encountered a read error.
    //
    void handle_receive_error(uint64_t len_in_bytes, const socket_command_type_e);

    //
    // Used to dampen errors, just in case we get a flood of them
    //
    static const int handle_receive_error_frequency_in_seconds = 60;
    std::chrono::time_point<HiResClock> last_handle_receive_error_time;
    bool last_handle_receive_error_time_set;

    static const int handle_send_error_frequency_in_seconds = 60;
    std::chrono::time_point<HiResClock> last_handle_send_error_time;
    bool last_handle_send_error_time_set;

    //
    // Further dampening, if too many errors occur within the above time period,
    // stop flooding error messages.
    //
    static const int m_send_error_count_limit_per_epoch = 100;
    size_t m_send_error_count{};
    static const int m_receive_error_count_limit_per_epoch = 100;
    size_t m_receive_error_count{};

    //
    // To avoid TCP buffer overflow on either end, it is likely prudent for us
    // to dampen the amount of data we send to the client in one burst. This
    // byte counter is increased per sent message and is reset by any received message.
    // Should we hit the m_nsim_client_flush_frequency_byte_count limit then we will
    // send a manual flush and wait for the response.
    //
    // Can be overriden by env variable "NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT"
    //
    // Example timings:
    //
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT                    0: Ran 15 tests in 51.926s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT              5000000: Ran 15 tests in 52.779s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT              4000000: Ran 15 tests in 53.259s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT              3000000: Ran 15 tests in 53.795s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT              2000000: Ran 15 tests in 54.462s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT              1000000: Ran 15 tests in 54.485s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT               900000: Ran 15 tests in 54.731s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT               800000: Ran 15 tests in 54.625s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT               700000: Ran 15 tests in 55.135s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT               600000: Ran 15 tests in 56.203s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT               500000: Ran 15 tests in 56.524s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT               400000: Ran 15 tests in 56.199s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT               300000: Ran 15 tests in 57.089s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT               200000: Ran 15 tests in 58.641s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT               100000: Ran 15 tests in 62.440s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT                50000: Ran 15 tests in 66.087s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT                20000: Ran 15 tests in 73.901s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT                10000: Ran 15 tests in 72.845s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT                 5000: Ran 15 tests in 70.437s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT                 1000: Ran 15 tests in 84.879s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT                  500: Ran 15 tests in 102.390s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT                  100: Ran 15 tests in 230.378s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT                   50: Ran 15 tests in 306.636s
    // NSIM_CLIENT_FLUSH_FREQUENCY_BYTE_COUNT                    1: Ran 15 tests in 303.318s
    //
    // Disabled for now, but kept around in case we hit packet drops again.
    //
    static const uint64_t m_nsim_client_flush_frequency_byte_count_default = 0LLU;
    uint64_t m_nsim_client_flush_frequency_byte_count = m_nsim_client_flush_frequency_byte_count_default;

    //
    // Flush needs special handling as we send it post existing message construction but
    // prior to send() (to avoid sequence number issues). So we have our own buffer to avoid
    // overwriting the existing command.
    //
    uint8_t m_socket_flush_command_buffer[SOCKET_COMMAND_BUFFER_HEADER_LEN];

    //
    // Serialize data and send to the DSIM server
    //
    dsim_status_e write_rpc(const socket_command_type_e cmd);
    dsim_status_e write_rpc(const socket_command_type_e cmd, dsim_rpc_version_t version);
    dsim_status_e write_rpc_and_wait_for_status(const socket_command_type_e cmd);
    template <typename T, typename... Rest>
    dsim_status_e write_rpc_internal(const dsim_rpc_version_t version,
                                     const bool has_payload,
                                     const socket_command_type_e cmd,
                                     const T t,
                                     Rest... rest);
    template <typename T, typename... Rest>
    dsim_status_e write_rpc(const socket_command_type_e cmd, const dsim_rpc_version_t version, const T t, Rest... rest);
    template <typename T, typename... Rest>
    dsim_status_e write_rpc(const socket_command_type_e cmd, const T t, Rest... rest);
    template <typename T, typename... Rest>
    dsim_status_e write_rpc_and_wait_for_status(const socket_command_type_e cmd, const T t, Rest... rest);

    //
    // Deserialize data from the DSIM server.
    //
    dsim_status_e read_rpc(const socket_command_type_e cmd);
    dsim_status_e read_rpc(const socket_command_type_e cmd, dsim_rpc_version_t& version, uint8_t* buf, size_t received_bytes);
    dsim_status_e read_status(const socket_command_type_e cmd);
    template <typename T, typename... Rest>
    dsim_status_e read_rpc_internal(dsim_rpc_version_t& version,
                                    const bool has_payload,
                                    const socket_command_type_e cmd,
                                    uint8_t* buf,
                                    size_t received_bytes,
                                    T& t,
                                    Rest&... rest);
    template <typename T, typename... Rest>
    dsim_status_e read_rpc_internal(dsim_rpc_version_t& version,
                                    const bool has_payload,
                                    const socket_command_type_e cmd,
                                    T& t,
                                    Rest&... rest);
    template <typename T, typename... Rest>
    dsim_status_e read_rpc(const socket_command_type_e cmd, T& t, Rest&... rest);
    template <typename T, typename... Rest>
    dsim_status_e read_rpc(const socket_command_type_e cmd, uint8_t* buf, size_t received_bytes, T& t, Rest&... rest);
    template <typename T, typename... Rest>
    dsim_status_e read_rpc(const socket_command_type_e cmd,
                           dsim_rpc_version_t& version,
                           uint8_t* buf,
                           size_t received_bytes,
                           T& t,
                           Rest&... rest);

private:
    //
    // Apply any configuration
    //
    void config(void);

    uint8_t m_socket_command_buffer[SOCKET_COMMAND_BUFFER_LEN];

    packet_dma_inject m_packet_dma_inject;
    packet_dma_extract m_packet_dma_extract;
    socket_client* m_socket_client;
    npsuite::Logger* m_logger;

    // Local cpu_read register cache
    nsim::bit_vector m_counters_cpu_read_bv;

    // Local counter value register cache
    nsim::bit_vector m_cpu_counter_read_result_bv;

    // Basic device information to which we connected to
    struct device_info m_dev_info;

    using api_lock = std::lock_guard<std::recursive_mutex>;
    std::recursive_mutex m_lock;

    int m_num_connection_retries;
    int m_timeout_between_retries;

    size_t m_num_of_commands_to_dump_on_crash;
    std::deque<transaction_info_t> m_last_n_commands;
    std::mutex m_last_n_commands_mutex;
    npsuite::SignalHandler::CallbackId_t m_signal_callback_id = npsuite::SignalHandler::NoCallbackId;

    //
    // Max counter table cache.
    //
    std::vector<uint8_t> m_counters_max_counter_data;

    //
    // Registers we intercept by name and can return cached data from.
    //
    std::string m_reg_cpu_read_name;
    std::string m_reg_cpu_read_result;
    std::string m_max_counters_table_name;

    //
    // Retrieve either single or max counter data from the socket. We use
    // the size to determine which.
    //
    dsim_status_e recv_single_or_max_counter_data(void);

    // Client ID assigned the client instance by the device simulator
    client_id_t m_client_id;

    // Next sequence number for message sent to server from client
    client_seqno_t m_next_seqno;

    // Disable all write of memory. The assumption is that we have just applied a snapshot and can
    // safely ignore these writes for a speedup during SDK test restart.
    //
    // TODO the same for registers; Omer says to leave for now
    bool m_sdk_re_initializing{};

public:
};

} // namespace dsim

#endif //  __DSIM_CLIENT_H__
