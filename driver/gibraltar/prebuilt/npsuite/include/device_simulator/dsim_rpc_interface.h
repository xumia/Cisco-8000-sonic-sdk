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

#ifndef __DSIM_RPC_INTERFACE_h__
#define __DSIM_RPC_INTERFACE_h__
#include <stdint.h>
#include <stddef.h>
#include <string>
#include <map>
#include "nsim/nsim_log_interface.h"
#include "nsim/nsim_data_interface.h"    // for nsim_packet_info_t, nsim_db_trigger_info_t, nsim_packet_statistics_t
#include "nsim/nsim_control_interface.h" // for nsim_source_location_info_t

namespace dsim
{
class dsim_rpc_interface
{
public:
    virtual ~dsim_rpc_interface()
    {
    }

    /// @brief Test the client connection and wait for a response
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_ping(void) = 0;

    /// @brief Teardown the server.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_destroy_simulator(void) = 0;

    /// @brief Set the DSIM server log file path
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_set_server_log_file(const std::string& log_file_path, bool logPrefixEnabled) = 0;

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
    virtual dsim_status_e rpc_set_server_log_level(nsim::nsim_log_module_e) = 0;

    /// @brief Enable packet DMA
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_packet_dma_enable(bool) = 0;

    /// @brief Inject the given packet descriptor information
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_inject_packet_desc(const struct nsim::nsim_packet_info_t& packet,
                                                 const std::map<std::string, std::string>& initial_values)
        = 0;

    /// @brief Inject the given packet
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_inject_packet(const std::string& packet,
                                            size_t slice_id,
                                            size_t ifg,
                                            size_t pif,
                                            const std::map<std::string, std::string>& initial_values)
        = 0;

    /// @brief Simulate one packet.
    ///
    /// Evaluates the current packet execution, stopping one step before the packet finishes.
    /// Invoking #step() after #step_macro() will load the next macro.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_step_packet(void) = 0;

    /// @brief Step the simulation one macro forward.
    /// Evaluates the current macro, stopping one step before end of the macro.
    /// Invoking #step() after #step_macro() will load the next macro.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_step_macro(void) = 0;

    /// @brief Invoking #step() after #step_macro() will load the next macro.
    /// Evaluates the next statement to be executed, and advances the current statement location.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_step(void) = 0;

    /// @brief Sets lrc_fifo trigger to run before next packet
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_trigger_lrc_fifo(void) = 0;

    /// Get a single packet from the server. This will also clear out any other waiting packets.
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_get_packet(struct nsim::nsim_packet_info_t&) = 0;

    /// @brief Get all packets from the server
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_get_packets(std::list<struct nsim::nsim_packet_info_t>&) = 0;
    virtual std::list<struct nsim::nsim_packet_info_t> rpc_get_and_clear_output_packets(size_t timeout_in_milliseconds,
                                                                                        size_t num_of_packets)
        = 0;

    /// @brief Push trigger info
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_inject_db_trigger(const struct nsim_db_trigger_info_t& trigger) = 0;

    /// @brief Retrieve the connection handle of the server
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_get_connection_handle(std::string&) = 0;

    /// @brief Retrieve the device name
    ///
    /// @retval     The device name
    virtual std::string rpc_get_device_name(void) = 0;

    /////////////////////////////////////////////////////////////////////////////////////////
    // APIs after this point are not currently used by the SDK but are used by npsuite tests
    /////////////////////////////////////////////////////////////////////////////////////////

    /// @brief Expose the NPU to the host
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_set_expose_npu_host(void) = 0;

    /// @brief Set the slice contest
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_set_slice_context(size_t slice_id, size_t context_id) = 0;

    /// @brief Get and clear the event queue, returning a list of events
    ///
    /// @retval     List of events (as bit vectors)
    virtual std::list<nsim::bit_vector> rpc_get_and_clear_event_queue(void) = 0;

    /// @brief Set the given module's log level
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_set_module_file_log_level(nsim::nsim_log_module_e module, npsuite::npsuite_log_level_e level) = 0;

    /// @brief Set the given module's stdout log level
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_set_module_stdout_log_level(nsim::nsim_log_module_e module, npsuite::npsuite_log_level_e level) = 0;

    /// @brief Clear all table device state
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_clear_all_device_state() = 0;

    /// @brief Get the number of packets waiting to be injected
    ///
    /// @retval     Number of packets waiting to be injected
    virtual size_t rpc_get_num_packet_waiting_to_be_injected(void) = 0;

    /// @brief Get the nplc log message count
    ///
    /// @retval     Number of log messages corresponding to the given level
    virtual size_t rpc_get_num_log_messages(/* npsuite::npsuite_log_level_e */ int level) = 0;

    /// @brief Table lookup
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_get_entry(const std::string& table_name,
                                        size_t index,
                                        const nsim::bit_vector& key,
                                        nsim::bit_vector& out_payload)
        = 0;

    /// @brief Longest prefix table query
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_get_lpm_entry(const std::string& table_name,
                                            size_t index,
                                            const nsim::bit_vector& key,
                                            size_t length,
                                            nsim::bit_vector& out_payload)
        = 0;

    /// @brief Ternary table lookup
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_get_ternary_entry(const std::string& table_name,
                                                size_t index,
                                                size_t line,
                                                nsim::bit_vector& out_key,
                                                nsim::bit_vector& out_mask,
                                                nsim::bit_vector& out_payload)
        = 0;

    /// @brief Set oversubscribed interfaces mode
    ///
    /// @retval     DSIM_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     DSIM_STATUS_EUNKNOWN  An unknown error occurred.
    virtual dsim_status_e rpc_set_oversubscribed_interfaces_detection_mode(nsim::oversubscribed_interfaces_detection_mode_e) = 0;

    /// @brief Is the given port up
    ///
    /// @retval     True/up, False/down
    virtual bool rpc_is_port_up(size_t slice_id, size_t ifg, size_t pif) = 0;

    /// @brief Get all the port config for the given slice, ifg and pif
    ///
    /// @retval     Return mac lane port config for given slice/ifg/pif
    virtual nsim_port_pif_config_t rpc_get_port_config(size_t slice_id, size_t ifg, size_t pif) = 0;

    /// @brief Get the event queue write pointer
    ///
    /// @retval     Bit vector of write pointer
    virtual nsim::bit_vector rpc_get_event_queue_write_ptr(void) = 0;

    /// @brief Get the event queue read pointer
    ///
    /// @retval     Bit vector of read pointer
    virtual nsim::bit_vector rpc_get_event_queue_read_ptr(void) = 0;

    /// @brief Get the table name ID
    ///
    /// @retval     Table ID
    virtual uint32_t rpc_get_table_id_by_name(const std::string& name) = 0;
};
} // namespace dsim
#endif //__DSIM_RPC_INTERFACE_h__
