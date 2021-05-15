// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __NSIM_PROVIDER_H__
#define __NSIM_PROVIDER_H__

#include "device_simulator/dsim/device_simulator.h"   // Needed for C API
#include "device_simulator/dsim_client/dsim_client.h" // Needed for RPC API
#include "nsim/nsim_control_interface.h"              // for nsim_source_location_info_t
#include "nsim/nsim_data_interface.h"                 // for nsim_db_trigger_info_t
#include "nsim/nsim_log_interface.h"                  // for nsim_log_module_e

namespace nsim
{
class nsim_core;
}
namespace dsim
{
class device_simulator;
struct device_simulator_apis;
}

#include "common/cereal_utils.h"
#include "nsim_provider/nsim_provider_types_fwd.h"
#include "sim_provider/sim_provider.h"

namespace silicon_one
{

class nsim_provider : public sim_provider
{
public:
    /// @brief Simulator constructor.
    nsim_provider(const std::string& silicon_one_path,
                  const std::string& source_path,
                  const std::string& leaba_path,
                  const std::map<std::string, std::string> additional_params,
                  const std::string& host,
                  int port);

    // D'tor
    ~nsim_provider();

    //
    // If ENABLE_NSIM_LOG is set, sync that to the server
    //
    bool set_log_level_from_env(void);

    // sim_provider API
    //
    /// @brief Inject packet into simulation.
    /// Packets are simulated in the order in which they were injected.
    ///
    /// @param[in]  packet_desc         Packet descriptor.
    /// @param[in]  initial_values      Set of (name, value) pairs to be updated prior to Format Identification.
    ///
    /// @return true if packet injected successfully, false otherwise.
    bool inject_packet(const sim_packet_info_desc& packet_desc, const sim_initial_metadata_map_t& initial_values = {}) override;

    /// @brief Step injected packet through the simulator until the packet/s handling is finished.
    ///
    /// @retval Return status.
    bool step_packet() override;

    /// @brief Step Learn Notification packet through the simulator until the packet/s handling is finished.
    ///
    /// @retval Return status.
    bool step_learn_notify_packet();

    /// @brief Step until the end of the macro
    ///
    /// @retval Return status.
    bool step_macro(void);

    /// @brief Single step
    ///
    /// @retval Return status.
    bool step(void);

    /// @brief Sets lrc_fifo trigger to run before next packet
    ///
    /// @retval true if successful
    bool trigger_lrc_fifo(void);

    /// @brief Inject packet into simulation.
    /// Packets are simulated in the order in which they were injected.
    ///
    /// @param[in]  struct           Trigger info struct.
    ///
    /// @return true if trigger injected successfully, false otherwise.
    bool inject_db_trigger(const nsim_db_trigger_info_t& trigger_info);
    bool inject_db_trigger(size_t line_id, size_t trigger_type, size_t mp_type);

    /// @brief Read one egress packet from the simulator
    ///
    /// @retval Egress packet
    sim_packet_info_desc get_packet() override;

    /// @brief Read all egress packets from the simulator
    ///
    /// @retval Vector of all egress packets
    sim_packet_info_desc_vec_t get_packets() override;

    /// @brief Get connection handle.
    ///
    /// @retval Path to the device.
    const std::string get_connection_handle();

    /// @brief Return device path for the simulated device.
    ///
    /// @retval Path to the simulated device.
    const char* get_device_path();

    /// @brief Return device name for the simulated device.
    ///
    /// @retval Device name
    const std::string get_device_name(void);

    /// @brief Enables NSIM logging.
    ///
    /// @param[in]  enabled      logging is enabled for all messages or set only for Error/Fatal messages.
    ///
    /// @retval true if successful
    bool set_logging(bool enabled);

    /// @brief Set NSIM logging level
    ///
    /// @param[in]  level        log level to set.
    ///
    /// @retval true if successful
    bool set_log_level(nsim::nsim_log_module_e level);

    /// @brief Enable or disable Packet DMA support
    ///
    /// @param[in]  enable              Parameter, true or false
    ///                                 indicating if the packet DMA should be enabled
    /// @retval true if successful
    bool packet_dma_enable(bool);

    /// @brief sets log file
    /// @param[in]  log_file_path     path to log file
    /// @param[in]  logPrefixEnabled  Enable log prefix if true
    ///
    /// @retval true if successful
    bool set_log_file(const char* p, bool logPrefixEnabled);

    /// @brief Expose the NPU to the host.
    ///
    /// @retval true if successful
    bool set_expose_npu_host(void);

    /// @brief Set the slice context
    ///
    /// @param[in]  slice_id    ID of slice for which context will be set
    /// @param[in]  context_id  ID for context to set for slice
    ///
    /// @retval true if successful
    bool set_slice_context(size_t slice_id, size_t context_id);

    /// @brief Get and clear the event queue, returning the events.
    ///
    /// @param[out]  out  Output for event queue
    ///
    /// @retval true if successful
    bool get_and_clear_event_queue(std::list<nsim::bit_vector>& out);

    /// @brief Deletes the simulator
    void destroy_simulator();

    // Get a debug string describing this class
    std::string to_string(void) const;

private:
    nsim_provider()
    {
    } // For serialization purposes only.
    // forbid copy
    nsim_provider(const nsim_provider&);
    nsim_provider& operator=(const nsim_provider&);

    //
    // Find NPSUITE_ROOT etc...
    //
    void get_config(std::map<std::string, std::string>& additional_params);

    //
    // Debugging enabled within nsim_provider.cpp and logging enabled in nsim.py
    // Usually set by the "ENABLE_NSIM_LOG" environment variable. Expected values
    // are "0" and "1" although some tests like to set "full" or "true".
    //
    bool m_logging_enabled{};

    //
    // Set by the "ENABLE_NSIM_DEBUG=1".
    //
    bool m_debug_enabled{};

    //
    // Set if "NSIM_RPC_ENABLE=1". If "NSIM_RPC_ENABLE=0" then we use the C API.
    //
    bool m_use_rpc_api{};

    //
    // This ignores the timeout checks for the DSIM server, just in case it is very
    // very slow e.g. something like valgrind. To enable, set NSIM_DISABLE_WRAPPER_TIMEOUT=1
    //
    bool m_disable_wrapper_timeout{};

    std::string m_npsuite_root;
    std::string m_source_path;
    std::string m_leaba_defined;
    std::string m_nsim_archive;
    std::string m_device_path;
    std::map<std::string, std::string> m_additional_params;
    std::string m_hostname;
    int m_port{};
    bool m_exiting{};

    /////////////////////////////////////////////////////////////////////////////////////
    // RPC API fields
    /////////////////////////////////////////////////////////////////////////////////////

    //
    // Bring up the RPC connection
    //
    void rpc_api_connect(void);
    //
    // Tear down the RPC connection
    //
    void rpc_api_disconnect(void);
    //
    // Make sure the RPC works
    //
    void rpc_api_test_connection(void);
    //
    // Start nsim.py on the server side via RPC
    //
    std::vector<std::string> rpc_api_get_server_args(const std::string& server_port_file);
    //
    // Start the DSIM server on the server side via RPC
    //
    void rpc_api_create_server(std::vector<std::string>& args, const std::string& server_port_file);

    //
    // Handle to the DSIM client
    //
    dsim::dsim_client* m_client{};

    /////////////////////////////////////////////////////////////////////////////////////
    // C API fields
    /////////////////////////////////////////////////////////////////////////////////////

    std::string m_dl_libdsim_path; // Path to libdsim.so
    void* m_libdsym_handle{};
    dsim::device_simulator* m_server{}; // Handle to our dsim server class
    void c_api_create_server(void);     // Locate our libdsim.so
    void c_api_find_symbols(void);

    /////////////////////////////////////////////////////////////////////////////////////
    // C API symbols that are resolved via dlsym() if we are loading libdsim.so
    /////////////////////////////////////////////////////////////////////////////////////

    struct dsim::device_simulator_apis dsim_apis {
    };

    /////////////////////////////////////////////////////////////////////////////////////
    // Common API callbacks used to provide either a python RPC or C backend api.
    /////////////////////////////////////////////////////////////////////////////////////

    void rpc_api_init(void);
    void c_api_init(void);

    void rpc_api_populate(void);
    void c_api_populate(void);

    void c_api_destructor(void);
    void rpc_api_destructor(void);

    bool c_api_set_log_file(const char* p, bool logPrefixEnabled);
    bool rpc_api_set_log_file(const char* p, bool logPrefixEnabled);

    bool c_api_set_log_level(nsim::nsim_log_module_e module);
    bool rpc_api_set_log_level(nsim::nsim_log_module_e module);

    bool c_api_packet_dma_enable(bool value);
    bool rpc_api_packet_dma_enable(bool value);

    bool c_api_inject_packet(const sim_packet_info_desc& packet_desc, const sim_initial_metadata_map_t& initial_values);
    bool rpc_api_inject_packet(const sim_packet_info_desc& packet_desc, const sim_initial_metadata_map_t& initial_values);

    bool c_api_step_packet(void);
    bool rpc_api_step_packet(void);

    bool c_api_step_macro(void);
    bool rpc_api_step_macro(void);

    bool c_api_step(void);
    bool rpc_api_step(void);

    sim_packet_info_desc c_api_get_packet(void);
    sim_packet_info_desc rpc_api_get_packet(void);

    sim_packet_info_desc_vec_t c_api_get_packets(void);
    sim_packet_info_desc_vec_t rpc_api_get_packets(void);

    bool c_api_trigger_lrc_fifo(void);
    bool rpc_api_trigger_lrc_fifo(void);

    bool c_api_inject_db_trigger(const nsim_db_trigger_info_t& trigger_info);
    bool rpc_api_inject_db_trigger(const nsim_db_trigger_info_t& trigger_info);

    const std::string rpc_api_get_connection_handle(void);
    const std::string c_api_get_connection_handle(void);

    const std::string rpc_api_get_device_name(void);
    const std::string c_api_get_device_name(void);

    bool rpc_api_set_expose_npu_host(void);
    bool c_api_set_expose_npu_host(void);

    bool rpc_api_set_slice_context(size_t slice_id, size_t context_id);
    bool c_api_set_slice_context(size_t slice_id, size_t context_id);

    bool rpc_api_get_and_clear_event_queue(std::list<nsim::bit_vector>& out);
    bool c_api_get_and_clear_event_queue(std::list<nsim::bit_vector>& out);

    struct backend_api {
        std::function<void(void)> destructor;
        std::function<bool(const char*, bool logPrefixEnabled)> set_log_file;
        std::function<bool(nsim::nsim_log_module_e module)> set_log_level;
        std::function<bool(bool)> packet_dma_enable;
        std::function<bool(const sim_packet_info_desc&, const sim_initial_metadata_map_t&)> inject_packet;
        std::function<bool(void)> step_packet;
        std::function<bool(void)> step_macro;
        std::function<bool(void)> step;
        std::function<bool(void)> trigger_lrc_fifo;
        std::function<sim_packet_info_desc(void)> get_packet;
        std::function<sim_packet_info_desc_vec_t(void)> get_packets;
        std::function<bool(const nsim_db_trigger_info_t&)> inject_db_trigger;
        std::function<const std::string(void)> get_connection_handle;
        std::function<const std::string(void)> get_device_name;
        std::function<bool(void)> set_expose_npu_host;
        std::function<bool(size_t, size_t)> set_slice_context;
        std::function<bool(std::list<nsim::bit_vector>& out)> get_and_clear_event_queue;
    } api;

    bool is_true_env_value(const char* value) const;
    bool is_false_env_value(const char* value) const;
};

} // namespace silicon_one

#endif // __NSIM_PROVIDER_H__
