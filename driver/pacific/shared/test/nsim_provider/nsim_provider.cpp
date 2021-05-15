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

//
// The NSIM provider allows a client to have local or remote access to libdsim.
//
// - Remote access is provided via RPC TCP/IP socket connection
// - Local access is via dlopen of "libdsim.so".
//
// The same APIs are provided to the client in either case.
//
// To enable RPC, do this before running any tests:
//
//     export NSIM_RPC_ENABLE=1
//
// To enable local connection only and 0loading of libdsim.so, do this before running any tests:
//
//     export NSIM_RPC_ENABLE=0
//
// When dsim is running remotely, it is also possible to have a keepalive to
// avoid the server process being left running if the client crashes. To enable
// this, (to disable set to <= 0) do:
//
//     export NSIM_SET_KEEPALIVE_TIMEOUT_IN_SEC=360
//
// Upon keepalive expiry it is possible to make dsim dump stack versus exit
// quietly. The stack dump can be useful for debugging. To enable this:
//
//     export NSIM_SET_KEEPALIVE_TIMEOUT_ABORT=1
//
// To enable logs on the dsim server:
//
//     export ENABLE_NSIM_LOG=1
//
// To enbable local debugs of this library:
//
//     export NSIM_RPC_DEBUG_ENABLE=1
//
// Design:
//
// +--------------------------------------------------------------------------+
// | Process 1                                                                |
// | +------------------------+                                               |
// | |      An SDK test       |-----> read/write mem/regs ------+             |
// | +------------------------+                                 |             |
// |             |                                              |             |
// |             v                                              v             |
// |       inject_packet()                         +------------------------+ |
// |             |                                 |       Dsim client      | |
// |             |                                 +------------------------+ |
// |             |                                 +------------------------+ |
// |             |                                 |     libdsim_dlient     | |
// |             |                                 +------------------------+ |
// | +------------------------+                                 |             |
// | |     uut_provider.py    |                                 |             |
// | +------------------------+                                 |             |
// | +------------------------+                                 |             |
// | |     libnsim_provider   |                                 |             |
// | +------------------------+                                 |             |
// | +------------------------+                                 v             |
// | |    nsim_provider.cpp   | <----------------------------------------------- YOU ARE HERE
// | +------------------------+                                 |             |
// |             |                                              |             |
// |             +--------------->--------------+               |             |
// |             |                              |               |             |
// |       NSIM_RPC_ENABLE=1           NSIM_RPC_ENABLE=0        |             |
// |             |                              |               |             |
// |             |                              v               |             |
// |             |                  +-------------------------+ |             |
// |             |                  | nsim_provider_c_api.cpp | |             |
// |             v                  +-------------------------+ |             |
// | +---------------------------+              |               |             |
// | | nsim_provider_rpc_api.cpp |              |               |             |
// | +---------------------------+              |               |             |
// |        |           |              dlopen("libdsim.so")     |             |
// |        |           |                       |               |             |
// | inject_packet()    |                inject_packet()        |             |
// |        |           |                       |               |             |
// |        v           v                       v               |             |
// | +-------------+    |                 +------------+        |             |
// | | DSIM client |  fork()              |   libdsim  |<-------+             |
// | +-------------+    |                 +------------+                      |
// |        |           |                                                     |
// |        |           |                                                     |
// | inject_packet()    |                                                     |
// |        |           |                                                     |
// |        v           v                                                     |
// +--------------------------------------------------------------------------+
//          ^           |
//          :           |
// RPC server socket    |
//          :           |
//          v           v
// +-----------------------+
// | Process 2 DSIM server |
// |                       |
// | +-------------------+ |
// | |     libdsim       | |
// | +-------------------+ |
// +-----------------------+
//

#include "nsim_provider_local.h"
#include <strings.h>

namespace silicon_one
{

//
// Prefer the C API by default as it is faster and uses a single process.
//
static bool NSIM_USE_RPC_API_DEFAULT = false;

//
// Global debug for all classes
//
bool g_debug_enabled = false;

#ifdef ENABLE_NSIM_PROV_DEBUGGING
//
// List of providers that have not been shutdown.
//
std::recursive_mutex g_providers_mutex;
std::list<nsim_provider*> g_providers;
#endif

//
// Start DSIM either locally or remotely.
//
nsim_provider::nsim_provider(const std::string& device_path,
                             const std::string& source_path,
                             const std::string& leaba_path,
                             const std::map<std::string, std::string> additional_params,
                             const std::string& host,
                             int port)
{
    NSIM_PROV_TRACE();

    m_device_path = device_path;
    m_source_path = source_path;
    m_leaba_defined = leaba_path;

    //
    // Save the requested hostname and port. Port is usually 0 for the SDK, so we must
    // safely allocate a free port for the DSIM server. This is done within the DSIM
    // server wrapper itself.
    //
    m_hostname = host;
    if (m_hostname == "") {
        m_hostname = "localhost";
    }
    m_port = port;

    m_additional_params = additional_params;

    //
    // Find NPSUITE_ROOT etc...
    //
    get_config(m_additional_params);

    NSIM_PROV_DEBUG("Initialize");

    //
    // Populate callback vectors with either the C or RPC API backend
    //
    if (m_use_rpc_api) {
        rpc_api_init();
    } else {
        c_api_init();
    }

    //
    // If ENABLE_NSIM_LOG is set, sync that to the server
    //
    set_log_level_from_env();

#ifdef ENABLE_NSIM_PROV_DEBUGGING
    //
    // Keep track of this object just in case the SDK does not.
    //
    std::lock_guard<std::recursive_mutex> guard(g_providers_mutex);
    g_providers.push_back(this);

    //
    // Add a cleanup hook so we can catch cases where the SDK does not release our object.
    // Failure to do this can lead to the RPC server hanging around in a zombie fashion.
    //
    if (!atexit_added) {
        atexit_added = true;
        std::atexit(exiting);
    }
#endif

    NSIM_PROV_DEBUG("Initialized");
}

nsim_provider::~nsim_provider()
{
    NSIM_PROV_TRACE();
    NSIM_PROV_DEBUG("Destructor called");

#ifdef ENABLE_NSIM_PROV_DEBUGGING
    //
    // Remove this object from the global list of providers.
    //
    std::lock_guard<std::recursive_mutex> guard(g_providers_mutex);
    auto found = std::find(g_providers.begin(), g_providers.end(), this);
    if (found == g_providers.end()) {
        assert(false && "Provider object not found");
    }
    g_providers.erase(found);
#endif

    api.destructor();

    NSIM_PROV_DEBUG("Destructor completed");
}

//
// Deletes the simulator
//
void
nsim_provider::destroy_simulator()
{
    NSIM_PROV_TRACE();
    delete this;
}

//
// Find NPSUITE_ROOT etc...
//
void
nsim_provider::get_config(std::map<std::string, std::string>& additional_params)
{
    NSIM_PROV_TRACE();

    auto NSIM_RPC_DEBUG_ENABLE = getenv("NSIM_RPC_DEBUG_ENABLE");
    if (NSIM_RPC_DEBUG_ENABLE != nullptr) {
        try {
            m_debug_enabled = std::stoi(std::string(NSIM_RPC_DEBUG_ENABLE));
            g_debug_enabled = m_debug_enabled;
            NSIM_PROV_DEBUG("Set NSIM_RPC_DEBUG_ENABLE = \"" << m_debug_enabled << "\" (from env)");
        } catch (const std::invalid_argument& e) {
            NSIM_PROV_ERROR("NSIM_RPC_DEBUG_ENABLE set to invalid value");
        } catch (const std::out_of_range& e) {
            NSIM_PROV_ERROR("NSIM_RPC_DEBUG_ENABLE out of range");
        }
    }

    //
    // Enable DSIM logging
    //
    NSIM_PROV_TRACE();
    auto ENABLE_NSIM_LOG = getenv("ENABLE_NSIM_LOG");
    if (ENABLE_NSIM_LOG != nullptr) {
        try {
            //
            // SAI seems to think "full" and "true" are valid...
            //
            if (!strcasecmp(ENABLE_NSIM_LOG, "full")) {
                m_logging_enabled = true;
            } else if (!strcasecmp(ENABLE_NSIM_LOG, "true")) {
                m_logging_enabled = true;
            } else if (!strcasecmp(ENABLE_NSIM_LOG, "false")) {
                m_logging_enabled = false;
            } else {
                m_logging_enabled = std::stoi(std::string(ENABLE_NSIM_LOG));
            }
            NSIM_PROV_DEBUG("Set ENABLE_NSIM_LOG = \"" << m_logging_enabled << "\" (from env)");
        } catch (const std::invalid_argument& e) {
            NSIM_PROV_ERROR("ENABLE_NSIM_LOG set to invalid value");
        } catch (const std::out_of_range& e) {
            NSIM_PROV_ERROR("ENABLE_NSIM_LOG out of range");
        }
    }

    if (m_debug_enabled) {
        m_logging_enabled = true;
    }

    //
    // Enable RPC?
    //
    m_use_rpc_api = NSIM_USE_RPC_API_DEFAULT;

    NSIM_PROV_TRACE();
    auto NSIM_RPC_ENABLE = getenv("NSIM_RPC_ENABLE");
    if (NSIM_RPC_ENABLE != nullptr) {
        try {
            //
            // SAI seems to think "full" and "true" are valid...
            //
            if (!strcasecmp(NSIM_RPC_ENABLE, "full")) {
                m_use_rpc_api = true;
            } else if (!strcasecmp(NSIM_RPC_ENABLE, "true")) {
                m_use_rpc_api = true;
            } else if (!strcasecmp(NSIM_RPC_ENABLE, "false")) {
                m_use_rpc_api = false;
            } else {
                m_use_rpc_api = std::stoi(std::string(NSIM_RPC_ENABLE));
            }
            NSIM_PROV_DEBUG("Set NSIM_RPC_ENABLE = \"" << m_use_rpc_api << "\" (from env)");
        } catch (const std::invalid_argument& e) {
            NSIM_PROV_ERROR("NSIM_RPC_ENABLE set to invalid value");
        } catch (const std::out_of_range& e) {
            NSIM_PROV_ERROR("NSIM_RPC_ENABLE out of range");
        }
    } else {
        if (m_use_rpc_api) {
            NSIM_PROV_INFO("RPC enabled (default");
        } else {
            NSIM_PROV_INFO("RPC disabled (default");
        }
    }

    //
    // Enable NSIM keepalive by default (unless disabled with a value <= 0)
    //
    NSIM_PROV_TRACE();
    auto NSIM_SET_KEEPALIVE_TIMEOUT_IN_SEC = getenv("NSIM_SET_KEEPALIVE_TIMEOUT_IN_SEC");
    if (NSIM_SET_KEEPALIVE_TIMEOUT_IN_SEC == nullptr) {
        if (m_additional_params["set_keepalive_timeout_in_sec"] == "") {
            m_additional_params["set_keepalive_timeout_in_sec"] = "180"; // default
        }
    } else {
        try {
            auto str_val = std::string(NSIM_SET_KEEPALIVE_TIMEOUT_IN_SEC);
            auto set_keepalive_timeout_in_sec = std::stoi(str_val);
            if (set_keepalive_timeout_in_sec > 0) {
                NSIM_PROV_DEBUG("Set NSIM_SET_KEEPALIVE_TIMEOUT_IN_SEC to " << str_val);
            } else {
                NSIM_PROV_DEBUG("Set NSIM_SET_KEEPALIVE_TIMEOUT_IN_SEC to disabled");
            }
            m_additional_params["set_keepalive_timeout_in_sec"] = str_val;
        } catch (const std::invalid_argument& e) {
            NSIM_PROV_ERROR("NSIM_SET_KEEPALIVE_TIMEOUT_IN_SEC set to invalid value (disabled)");
        } catch (const std::out_of_range& e) {
            NSIM_PROV_ERROR("NSIM_SET_KEEPALIVE_TIMEOUT_IN_SEC out of range (disabled)");
        }
    }

    //
    // Enable abort on keepalive timeout.
    //
    NSIM_PROV_TRACE();
    auto NSIM_SET_KEEPALIVE_TIMEOUT_ABORT = getenv("NSIM_SET_KEEPALIVE_TIMEOUT_ABORT");
    if (NSIM_SET_KEEPALIVE_TIMEOUT_ABORT == nullptr) {
        if (m_additional_params["set_keepalive_timeout_abort"] == "") {
            m_additional_params["set_keepalive_timeout_abort"] = "false"; // default
        }
    } else {
        try {
            auto str_val = std::string(NSIM_SET_KEEPALIVE_TIMEOUT_ABORT);

            if (strcasecmp(NSIM_SET_KEEPALIVE_TIMEOUT_ABORT, "true")) {
                NSIM_PROV_DEBUG("Set NSIM_SET_KEEPALIVE_TIMEOUT_ABORT to enabled");
            } else if (strcasecmp(NSIM_SET_KEEPALIVE_TIMEOUT_ABORT, "false")) {
                NSIM_PROV_DEBUG("Set NSIM_SET_KEEPALIVE_TIMEOUT_ABORT to disabled");
            } else {
                NSIM_PROV_DEBUG("Set NSIM_SET_KEEPALIVE_TIMEOUT_ABORT " << str_val);
            }
            m_additional_params["set_keepalive_timeout_in_sec"] = str_val;
        } catch (const std::invalid_argument& e) {
            NSIM_PROV_ERROR("NSIM_SET_KEEPALIVE_TIMEOUT_ABORT set to invalid value (disabled)");
        } catch (const std::out_of_range& e) {
            NSIM_PROV_ERROR("NSIM_SET_KEEPALIVE_TIMEOUT_ABORT out of range (disabled)");
        }
    }

    //
    // This ignores the timeout checks for the DSIM server, just in case it is very
    // very slow e.g. something like valgrind. To enable, set NSIM_DISABLE_WRAPPER_TIMEOUT=1
    //
    auto NSIM_DISABLE_WRAPPER_TIMEOUT = getenv("NSIM_DISABLE_WRAPPER_TIMEOUT");
    if (NSIM_DISABLE_WRAPPER_TIMEOUT != nullptr) {
        try {
            m_disable_wrapper_timeout = std::stoi(std::string(NSIM_DISABLE_WRAPPER_TIMEOUT));
            NSIM_PROV_DEBUG("Set NSIM_DISABLE_WRAPPER_TIMEOUT = \"" << m_disable_wrapper_timeout << "\" (from env)");
        } catch (const std::invalid_argument& e) {
            NSIM_PROV_ERROR("NSIM_DISABLE_WRAPPER_TIMEOUT set to invalid value");
        } catch (const std::out_of_range& e) {
            NSIM_PROV_ERROR("NSIM_DISABLE_WRAPPER_TIMEOUT out of range");
        }
    }

    //
    // Ensure NPSUITE_ROOT is set. We need this to find libdsim.so or libdsim_client.so
    //
    NSIM_PROV_TRACE();
    auto NPSUITE_ROOT_CPTR = getenv("NPSUITE_ROOT");
    assert(NPSUITE_ROOT_CPTR != nullptr && "NPSUITE_ROOT is not set");
    m_npsuite_root = std::string(NPSUITE_ROOT_CPTR);
    NSIM_PROV_DEBUG("Set NPSUITE_ROOT = \"" << m_npsuite_root << "\" (from env)");

    //
    // NSIM_SOURCE_PATH is used by DSIM
    //
    NSIM_PROV_TRACE();
    auto NSIM_SOURCE_PATH_CPTR = getenv("NSIM_SOURCE_PATH");
    if (NSIM_SOURCE_PATH_CPTR) {
        m_source_path = std::string(NSIM_SOURCE_PATH_CPTR);
        NSIM_PROV_DEBUG("Set source_path = \"" << m_source_path << "\" (from env)");
    } else {
        NSIM_PROV_DEBUG("Set source_path = \"" << m_source_path << "\" (default)");
    }

    //
    // NSIM_LEABA_DEFINED_FOLDER is used by DSIM
    //
    NSIM_PROV_TRACE();
    auto NSIM_LEABA_DEFINED_FOLDER_CPTR = getenv("NSIM_LEABA_DEFINED_FOLDER");
    if (NSIM_LEABA_DEFINED_FOLDER_CPTR) {
        m_leaba_defined = std::string(NSIM_LEABA_DEFINED_FOLDER_CPTR);
        NSIM_PROV_DEBUG("Set leaba_defined = \"" << m_leaba_defined << "\" (from env)");
    } else {
        NSIM_PROV_DEBUG("Set leaba_defined = \"" << m_leaba_defined << "\" (default)");
    }

    //
    // LOAD_SOURCE_FROM_NSIM_ARCHIVE is used by DSIM
    //
    NSIM_PROV_TRACE();
    auto LOAD_SOURCE_FROM_NSIM_ARCHIVE_CPTR = getenv("LOAD_SOURCE_FROM_NSIM_ARCHIVE");
    if (LOAD_SOURCE_FROM_NSIM_ARCHIVE_CPTR) {
        m_nsim_archive = std::string(LOAD_SOURCE_FROM_NSIM_ARCHIVE_CPTR);
        NSIM_PROV_DEBUG("Set nsim_archive = \"" << m_nsim_archive << "\" (from env)");
    } else {
        NSIM_PROV_DEBUG("Not using NSIM source archive (default)");
    }

    //
    // For SAI
    // TODO: Remove this once dsim_client is created conditionally in nsim.py
    // 1. nsim.py creates one dsim client unconditionally
    // 2. SDK uses one for control plane / config
    // 3. nsim provider uses one for NSIM control
    // 4. SAI uses one for user-space kernel module simulation
    additional_params["max_number_of_clients"] = "4";

    // NOTE: The below options can be set only via environment variables
    // TODO: Give these options proper API calls for both the C and RPC APIs
    //
    // enable reference model
    //
    NSIM_PROV_TRACE();
    const char* USE_REFERENCE_MODEL_ENV = getenv("NSIM_REFERENCE_MODEL");
    if (USE_REFERENCE_MODEL_ENV) {
        NSIM_PROV_DEBUG("Set NSIM reference model from NSIM_REFERENCE_MODEL = " << USE_REFERENCE_MODEL_ENV);
        if (is_true_env_value(USE_REFERENCE_MODEL_ENV)) {
            m_additional_params["use_reference_model"] = "true";
        } else if (is_false_env_value(USE_REFERENCE_MODEL_ENV)) {
            m_additional_params.erase("use_reference_model");
        } else {
            NSIM_PROV_ERROR("Unrecognized NSIM_REFERENCE_MODEL value: " << USE_REFERENCE_MODEL_ENV)
        }
    }

    //
    // set compiler output path, used by the reference model to load microcode
    //
    NSIM_PROV_TRACE();
    const char* COMPILER_OUTPUT_PATH_ENV = getenv("COMPILER_OUTPUT_PATH");
    if (COMPILER_OUTPUT_PATH_ENV) {
        NSIM_PROV_DEBUG("Set compiler output path from COMPILER_OUTPUT_PATH = " << COMPILER_OUTPUT_PATH_ENV);
        m_additional_params["compiler_output_path"] = COMPILER_OUTPUT_PATH_ENV;
    }

    //
    // set macro execution flow logging
    //
    NSIM_PROV_TRACE();
    const char* ENABLE_MACRO_EXECUTION_FLOW_LOGGING_ENV = getenv("NSIM_MACRO_EXECUTION_FLOW_LOGGING");
    if (ENABLE_MACRO_EXECUTION_FLOW_LOGGING_ENV) {
        NSIM_PROV_DEBUG("Set NSIM macro execution flow logging from NSIM_MACRO_EXECUTION_FLOW_LOGGING = "
                        << ENABLE_MACRO_EXECUTION_FLOW_LOGGING_ENV);
        if (is_true_env_value(ENABLE_MACRO_EXECUTION_FLOW_LOGGING_ENV)) {
            m_additional_params["enable_macro_execution_flow_logging"] = "true";
        } else if (is_false_env_value(ENABLE_MACRO_EXECUTION_FLOW_LOGGING_ENV)) {
            m_additional_params.erase("enable_macro_execution_flow_logging");
        } else {
            NSIM_PROV_ERROR("Unrecognized NSIM_MACRO_EXECUTION_FLOW_LOGGING value: " << ENABLE_MACRO_EXECUTION_FLOW_LOGGING_ENV)
        }
    }

    //
    // set macro execution flow log output path
    //
    NSIM_PROV_TRACE();
    const char* NSIM_MACRO_EXECUTION_FLOW_LOG_FILE_PATH_ENV = getenv("NSIM_MACRO_EXECUTION_FLOW_LOG_FILE_PATH");
    if (NSIM_MACRO_EXECUTION_FLOW_LOG_FILE_PATH_ENV) {
        NSIM_PROV_DEBUG("Set NSIM macro execution flow log file output path from NSIM_MACRO_EXECUTION_FLOW_LOG_FILE_PATH = "
                        << NSIM_MACRO_EXECUTION_FLOW_LOG_FILE_PATH_ENV);
        m_additional_params["macro_execution_flow_log_file_path"] = NSIM_MACRO_EXECUTION_FLOW_LOG_FILE_PATH_ENV;
    }
}

std::string
nsim_provider::to_string(void) const
{
    return m_hostname + ":" + std::to_string(m_port);
}

bool
nsim_provider::inject_packet(const sim_packet_info_desc& packet_desc, const sim_initial_metadata_map_t& initial_values)
{
    NSIM_PROV_TRACE();
    return api.inject_packet(packet_desc, initial_values);
}

bool
nsim_provider::step_learn_notify_packet(void)
{
    NSIM_PROV_TRACE();
    trigger_lrc_fifo();
    return step_packet();
}

bool
nsim_provider::step_packet(void)
{
    NSIM_PROV_TRACE();
    return api.step_packet();
}

bool
nsim_provider::step_macro(void)
{
    NSIM_PROV_TRACE();
    return api.step_macro();
}

bool
nsim_provider::step(void)
{
    NSIM_PROV_TRACE();
    return api.step();
}

bool
nsim_provider::trigger_lrc_fifo(void)
{
    NSIM_PROV_TRACE();
    api.trigger_lrc_fifo();
    return true;
}

bool
nsim_provider::packet_dma_enable(bool value)
{
    NSIM_PROV_TRACE();
    api.packet_dma_enable(value);
    return true;
}

bool
nsim_provider::set_log_file(const char* p, bool logPrefixEnabled)
{
    NSIM_PROV_TRACE();
    api.set_log_file(p, logPrefixEnabled);
    return true;
}

bool
nsim_provider::inject_db_trigger(const nsim_db_trigger_info_t& trigger_info)
{
    NSIM_PROV_TRACE();
    return api.inject_db_trigger(trigger_info);
}

bool
nsim_provider::inject_db_trigger(size_t line_id, size_t trigger_type, size_t mp_type)
{
    nsim_db_trigger_info_t trigger_info;
    trigger_info.set_args(line_id, trigger_type, mp_type);
    return inject_db_trigger(trigger_info);
}

sim_packet_info_desc
nsim_provider::get_packet(void)
{
    NSIM_PROV_TRACE();
    return api.get_packet();
}

sim_packet_info_desc_vec_t
nsim_provider::get_packets()
{
    NSIM_PROV_TRACE();
    return api.get_packets();
}

const std::string
nsim_provider::get_connection_handle(void)
{
    NSIM_PROV_TRACE();
    return api.get_connection_handle();
}

const std::string
nsim_provider::get_device_name(void)
{
    NSIM_PROV_TRACE();
    return api.get_device_name();
}

bool
nsim_provider::set_expose_npu_host(void)
{
    NSIM_PROV_TRACE();
    return api.set_expose_npu_host();
}

bool
nsim_provider::set_slice_context(size_t slice_id, size_t context_id)
{
    NSIM_PROV_TRACE();
    return api.set_slice_context(slice_id, context_id);
}

bool
nsim_provider::get_and_clear_event_queue(std::list<nsim::bit_vector>& out)
{
    NSIM_PROV_TRACE();
    return api.get_and_clear_event_queue(out);
}

bool
nsim_provider::is_true_env_value(const char* env_value) const
{
    const std::vector<const char*> truthy_values = {"true", "t", "yes", "y", "on", "1"};
    for (const char* truthy_value : truthy_values) {
        if (strcasecmp(env_value, truthy_value) == 0) {
            return true;
        }
    }
    return false;
}

bool
nsim_provider::is_false_env_value(const char* env_value) const
{
    const std::vector<const char*> falsey_values = {"false", "f", "no", "n", "off", "0"};
    for (const char* falsey_value : falsey_values) {
        if (strcasecmp(env_value, falsey_value) == 0) {
            return true;
        }
    }
    return false;
}

bool
nsim_provider::set_log_level(nsim::nsim_log_module_e level)
{
    NSIM_PROV_TRACE();

    std::initializer_list<std::string> i = {NSIM_LOG_MODULE_ENUMS(LIST_MACRO_FIXED_ENUM_STRING)};
    std::vector<std::string> levels(i);

    if (level >= levels.size()) {
        //
        // Continue on anyway, just in case this is valid on the server?
        //
        NSIM_PROV_ERROR("Unknown ENABLE_NSIM_LOG log level value: " << level);
    } else {
        NSIM_PROV_DEBUG("Set log level to " << levels[level] << " (" << level << ")");
    }
    return api.set_log_level(level);
}

//
// Returns "true" if some form of logging was enabled.
//
bool
nsim_provider::set_log_level_from_env(void)
{
    NSIM_PROV_TRACE();
    auto log_level_cptr = getenv("ENABLE_NSIM_LOG");
    if (log_level_cptr == nullptr) {
        return false;
    }

    if (*log_level_cptr == '\0') {
        return false;
    }

    set_logging(true);
    return true;
}

bool
nsim_provider::set_logging(bool enabled)
{
    NSIM_PROV_TRACE();
    if (enabled) {
        return set_log_level(nsim::NSIM_LOG_FULL);
    } else {
        return set_log_level(nsim::NSIM_LOG_NONE);
    }
}

const char*
nsim_provider::get_device_path(void)
{
    //
    // The SDK provides this value to us during server creation and we cache it.
    // It gets this value via get_connection_handle(), so it seems safe to return
    // this cached value.
    //
    NSIM_PROV_TRACE();
    return m_device_path.c_str();
}

//
// Ripped off from the SDK. Please keep this identical to the SDK timestamp
// as it makes it easier to compare logs.
//
static size_t
sdk_style_timestamp(char* buffer, size_t buffer_size)
{
    size_t chars_printed;
    auto now = std::chrono::system_clock::now();
    auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
    auto msec = std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds);
    auto time_t_date = std::chrono::system_clock::to_time_t(now);
    struct tm result;

#if defined(_WIN32) || defined(_WIN64)
    localtime_s(&result, &time_t_date);
#else
    localtime_r(&time_t_date, &result);
#endif

    chars_printed = strftime(buffer, buffer_size, "%d-%m-%Y %H:%M:%S", &result);
    chars_printed += snprintf(buffer + chars_printed, buffer_size - chars_printed, ".%03d", (int)msec.count());

    return chars_printed;
}

std::string
time_now(void)
{
    char ts[64] = {};
    sdk_style_timestamp(ts, sizeof(ts));
    return std::string(ts);
}

#ifdef ENABLE_NSIM_PROV_DEBUGGING
//
// Just in case we crash in cleanup. The nsim signal handler is gone now, so install our own.
//
static bool atexit_added;
static void
exiting(void)
{
    //
    // Sanity check that all providers were destroyed. I suppose a memory leak check.
    //
    std::lock_guard<std::recursive_mutex> guard(g_providers_mutex);
    for (auto p : g_providers) {
        NSIM_PROV_ERROR("exiting() NSIM provider was not killed cleanly: " << p->to_string());
    }

    NSIM_PROV_G_DEBUG("Exiting");
}
#endif
}
