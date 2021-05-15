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
// | +------------------------+                                 |             |
// | |    nsim_provider.cpp   |                                 |             |
// | +------------------------+                       Dsim RPC server socket  |
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
// | | nsim_provider_rpc_api.cpp |<---------------------------------------------- YOU ARE HERE
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

#include "nsim_provider_rpc_api.h"
#include <cstdio>
#include <fstream>

namespace silicon_one
{
//
// Populate callbacks // for the RPC API backend
//
void
nsim_provider::rpc_api_populate(void)
{
    NSIM_PROV_RPC_API_TRACE();
    api.destructor = std::bind(&nsim_provider::rpc_api_destructor, this);
    api.set_log_file = std::bind(&nsim_provider::rpc_api_set_log_file, this, std::placeholders::_1, std::placeholders::_2);
    api.set_log_level = std::bind(&nsim_provider::rpc_api_set_log_level, this, std::placeholders::_1);
    api.packet_dma_enable = std::bind(&nsim_provider::rpc_api_packet_dma_enable, this, std::placeholders::_1);
    api.inject_packet = std::bind(&nsim_provider::rpc_api_inject_packet, this, std::placeholders::_1, std::placeholders::_2);
    api.step_packet = std::bind(&nsim_provider::rpc_api_step_packet, this);
    api.step_macro = std::bind(&nsim_provider::rpc_api_step_macro, this);
    api.step = std::bind(&nsim_provider::rpc_api_step, this);
    api.get_packet = std::bind(&nsim_provider::rpc_api_get_packet, this);
    api.get_packets = std::bind(&nsim_provider::rpc_api_get_packets, this);
    api.trigger_lrc_fifo = std::bind(&nsim_provider::rpc_api_trigger_lrc_fifo, this);
    api.inject_db_trigger = std::bind(&nsim_provider::rpc_api_inject_db_trigger, this, std::placeholders::_1);
    api.get_connection_handle = std::bind(&nsim_provider::rpc_api_get_connection_handle, this);
    api.get_device_name = std::bind(&nsim_provider::rpc_api_get_device_name, this);
    api.set_expose_npu_host = std::bind(&nsim_provider::rpc_api_set_expose_npu_host, this);
    api.set_slice_context
        = std::bind(&nsim_provider::rpc_api_set_slice_context, this, std::placeholders::_1, std::placeholders::_2);
    api.get_and_clear_event_queue = std::bind(&nsim_provider::rpc_api_get_and_clear_event_queue, this, std::placeholders::_1);
}

//
// Start a DSIM server for us to use as the RPC back end.
//
void
nsim_provider::rpc_api_init(void)
{
    rpc_api_populate();

    //
    // Create a temporary file we will request that the server port is written into.
    // This avoids having to screen scrape the DSIM server.
    //
    char filename[L_tmpnam];
    snprintf(filename, sizeof(filename), "/tmp/dsim-XXXXXX");
    if (!mkstemp(filename)) {
        NSIM_PROV_RPC_API_ERROR("Could not create temp server file: " << filename);
    }
    std::string server_status_file = filename;

    //
    // Start a process that wraps DSIM
    //
    auto args = rpc_api_get_server_args(server_status_file);

    rpc_api_create_server(args, server_status_file);

    //
    // Create a client to server communication method so we can speak to nsim.py remotely.
    //
    rpc_api_connect();

    //
    // Make sure our RPC works
    //
    rpc_api_test_connection();
}

std::vector<std::string>
nsim_provider::rpc_api_get_server_args(const std::string& server_status_file)
{
    NSIM_PROV_RPC_API_DEBUG("Start DSIM server");

    //
    // Find the DSIM server.
    //
    std::string wrapper_name = "nsim.py";
    auto dsim_wrapper = std::string(m_npsuite_root) + "/bin/" + wrapper_name;
    std::ifstream dsim_wrapper_ifstream(dsim_wrapper, std::ios::in);
    assert(dsim_wrapper_ifstream.is_open() && "rpc_api_create_server: DSIM server not found");

    std::vector<std::string> args;
    args.push_back(dsim_wrapper);

    //
    // --debug
    //
    if (m_debug_enabled) {
        args.push_back("--debug");
    }

    if (!m_nsim_archive.empty()) {
        //
        // --load-source-from-nsim-archive
        //
        args.push_back("--load-source-from-nsim-archive");
        args.push_back(m_nsim_archive);
    } else {
        //
        // --source
        //
        args.push_back("--source");
        args.push_back(m_source_path);

        //
        // --leaba-defined
        //
        args.push_back("--leaba-defined");
        args.push_back(m_leaba_defined);
    }

    //
    // --device-path
    //
    args.push_back("--device-path");
    args.push_back(m_device_path);

    //
    // --additional-params
    //
    args.push_back("--additional-params");
    args.push_back(map_to_string(m_additional_params));

    //
    // --hostname
    //
    args.push_back("--host");
    args.push_back(m_hostname);

    //
    // --port
    //
    args.push_back("--port");
    args.push_back(std::to_string(m_port));

    //
    // --server-status-file
    //
    args.push_back("--server-status-file");
    args.push_back(server_status_file);

    //
    // SDK does not do this currently, so stop nsim doing so.
    //
    args.push_back("--disable-api-generation");

    return args;
}

//
// Fork a child process and within that run a DSIM server wrapper. The wrapper is responsible for
// starting the DSIM server and also writing to a configuration file. This file wil contain the
// host and port information of the DSIM server and the parent process upon reading this will then
// be able to get the port information and speak to the DSIM server via RPC.
//
void
nsim_provider::rpc_api_create_server(std::vector<std::string>& args, const std::string& server_status_file)
{
    //
    // Fork a child process to run the server
    //
    auto server_pid = fork();
    if (server_pid == 0) {
        //
        // This is the child process
        //
        NSIM_PROV_RPC_API_DEBUG("Starting DSIM server: " << ::to_string(args));

        //
        // Convert the string args to c style for exec*()
        //
        std::vector<char*> exec_args;
        for (auto& one_arg : args) {
            exec_args.push_back(const_cast<char*>(one_arg.c_str()));
        }
        exec_args.push_back(nullptr);

        //
        // Spawn the DSIM server to replace this process
        //
        char** execvp_args = exec_args.data();
        execvp(execvp_args[0], execvp_args);

        //
        // Should "never" get here.
        //
        NSIM_PROV_RPC_API_FATAL("Could not exec DSIM server process");
    } else {
        //
        // Parent. Return the child pid so we can stop it when done.
        //
        if (server_pid < 0) {
            NSIM_PROV_RPC_API_FATAL("Failed to create child process for DSIM server");
        }

        //
        // Try to get the port info from the server port file. Keep trying until the file exists.
        // It may take a little bit of time for the server to start.
        //
        bool succeeded = false;
        int attempts = 0;
        while (!succeeded) {
            //
            // Keep checking after a small delay, but don't wait forever.
            //
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (++attempts > 10000) {
                //
                // Ignores the timeout checks for the DSIM server? To enable, set NSIM_DISABLE_WRAPPER_TIMEOUT=1
                //
                if (!m_disable_wrapper_timeout) {
                    NSIM_PROV_RPC_API_FATAL("DSIM server took too long to start");
                }
            }
            if (!(attempts % 1000)) {
                NSIM_PROV_RPC_API_INFO("DSIM server is taking longer than expected to start. Check for presence of file: '"
                                       << server_status_file
                                       << "'. Waiting...");
            }

            //
            // Try to open the DSIM server output configuration file.
            //
            std::ifstream server_status_file_stream(server_status_file, std::ios::in);
            if (!server_status_file_stream.is_open()) {
                continue;
            }

            //
            // Read the output configuration file, looking for port information.
            //
            std::string line;
            while (server_status_file_stream.good() && std::getline(server_status_file_stream, line)) {
                //
                // Erase white space and empty lines
                //
                line.erase(remove_if(line.begin(),
                                     line.end(),
                                     [](const char& c) {
                                         std::string chars = "\n\r";
                                         return chars.find(c) != std::string::npos;
                                     }),
                           line.end());

                //
                // Look for port information and make sure we get a full line of output, just in case.
                //
                auto start_of_line = line.find("dsim_server = ");
                auto end_of_line = line.find(";");
                if ((start_of_line != std::string::npos) && (end_of_line != std::string::npos)) {
                    //
                    // Get the last string after ":" which should be the port...
                    //
                    std::string server_port;
                    std::istringstream full_buffer_stream(line);

                    //
                    // Extract characters from full_buffer_stream and store them into server_port until the delimitation character
                    // ':' is found (or the newline character, '\n')
                    //
                    while (getline(full_buffer_stream, server_port, ':')) {
                    }

                    //
                    // Convert the port number.
                    //
                    try {
                        m_port = std::stoi(server_port);
                        succeeded = true;
                        NSIM_PROV_RPC_API_INFO("Using DSIM server port: " << m_port);
                    } catch (const std::invalid_argument& e) {
                        NSIM_PROV_RPC_API_ERROR("Invalid DSIM server port: " << server_port << " " << e.what());
                    } catch (const std::out_of_range& e) {
                        NSIM_PROV_RPC_API_ERROR("Out of range DSIM server port: " << server_port << " " << e.what());
                    }
                }
            }

            if (!succeeded) {
                if (!(attempts % 100)) {
                    NSIM_PROV_RPC_API_INFO("DSIM server file is incomplete: '" << server_status_file << "'. Waiting...");
                }
            }
        }
        unlink(server_status_file.c_str());
    }
}

//
// Stop the DSIM server
//
void
nsim_provider::rpc_api_destructor(void)
{
    NSIM_PROV_RPC_API_TRACE();
    rpc_api_disconnect();
}

//
// Start an RPC connection with the DSIM server wrapper.
//
void
nsim_provider::rpc_api_connect(void)
{
    NSIM_PROV_RPC_API_DEBUG("Start DSIM RPC client");

    m_client = new dsim::dsim_client();
    if (!m_client->initialize(m_hostname.c_str(), m_port)) {
        NSIM_PROV_RPC_API_FATAL("Failed to create DSIM client to use with DSIM server");
    }
}

//
// Final destructor; stop the DSIM server. The DSIM server wrapper should be monitoring
// the server and will exit of its own accord.
//
void
nsim_provider::rpc_api_disconnect(void)
{
    NSIM_PROV_RPC_API_DEBUG("Free RPC objects");
    if (m_client) {
        NSIM_PROV_RPC_API_DEBUG("Calling destroy_simulator()");
        if (m_debug_enabled) {
            (void)m_client->dump_debug_info();
        }
        auto ret = m_client->rpc_destroy_simulator();
        NSIM_PROV_RPC_API_DEBUG("Called destroy_simulator() => " << dsim::to_string(ret));
    }
    delete m_client;
    m_client = nullptr;
}

//
// Make sure our RPC works
//
void
nsim_provider::rpc_api_test_connection(void)
{
    NSIM_PROV_RPC_API_DEBUG("Calling ping()");
    assert(m_client && "rpc_api_test_connection: fail, no DSIM client");

    auto ret = m_client->rpc_ping();
    NSIM_PROV_RPC_API_DEBUG("Called ping() => " << dsim::to_string(ret));
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_FATAL("Test DSIM server connection failed");
    }
}

//
// Call set_server_log_file on the DSIM server
//
bool
nsim_provider::rpc_api_set_log_file(const char* log_file_path, bool logPrefixEnabled)
{
    NSIM_PROV_RPC_API_DEBUG(
        "Calling set_server_log_file(log_file_path=" << log_file_path << ", logPrefixEnabled=" << logPrefixEnabled << ")");
    assert(m_client && "rpc_api_set_server_log_file: fail, no DSIM client");

    auto ret = m_client->rpc_set_server_log_file(std::string(log_file_path), logPrefixEnabled);
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_ERROR(
            "Called set_server_log_file(log_file_path=" << log_file_path << ", logPrefixEnabled=" << logPrefixEnabled << ") => "
                                                        << dsim::to_string(ret));
        return false;
    }
    NSIM_PROV_RPC_API_DEBUG(
        "Called set_server_log_file(log_file_path=" << log_file_path << ", logPrefixEnabled=" << logPrefixEnabled << ") => "
                                                    << dsim::to_string(ret));
    return true;
}

//
// Call set_log_level on the DSIM server
//
bool
nsim_provider::rpc_api_set_log_level(nsim::nsim_log_module_e level)
{
    NSIM_PROV_RPC_API_DEBUG("Calling set_server_log_level(level=" << nsim::nsim_log_module_e_to_string(level) << ")");
    assert(m_client && "rpc_api_set_server_log_file: fail, no DSIM client");

    auto ret = m_client->rpc_set_server_log_level(level);
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_ERROR("Called set_server_log_level(level=" << nsim::nsim_log_module_e_to_string(level) << ") => "
                                                                     << dsim::to_string(ret));
        return false;
    }
    NSIM_PROV_RPC_API_DEBUG("Called set_server_log_level(level=" << nsim::nsim_log_module_e_to_string(level) << ") => "
                                                                 << dsim::to_string(ret));
    return true;
}

//
// Call packet_dma_enable on the DSIM server
//
bool
nsim_provider::rpc_api_packet_dma_enable(bool value)
{
    NSIM_PROV_RPC_API_DEBUG("Calling packet_dma_enable(" << value << ")");
    assert(m_client && "rpc_api_packet_dma_enable: fail, no DSIM client");

    auto ret = m_client->rpc_packet_dma_enable(value);
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_ERROR("Called packet_dma_enable(" << value << ") => " << dsim::to_string(ret));
        return false;
    }
    NSIM_PROV_RPC_API_DEBUG("Called packet_dma_enable(value=" << value << ") => " << dsim::to_string(ret));
    return true;
}

//
// Call inject_packet_desc on the DSIM server
//
bool
nsim_provider::rpc_api_inject_packet(const sim_packet_info_desc& packet_desc, const sim_initial_metadata_map_t& initial_values)
{
    nsim::nsim_packet_info_t packet{};

    //
    // Need to pad the string to include leading zero so the packet is an even number of bytes
    //
    packet.m_packet_data = bit_vector(packet_desc.packet, packet_desc.packet.size() * 4);
    packet.m_slice_id = packet_desc.slice;
    packet.m_ifg = packet_desc.ifg;
    packet.m_pif = packet_desc.pif;

    NSIM_PROV_RPC_API_DEBUG("Calling inject_packet_desc(" << nsim::to_string(packet) << ", values=" << map_to_string(initial_values)
                                                          << ")");
    assert(m_client && "rpc_api_inject_packet_desc: fail, no DSIM client");

    auto ret = m_client->rpc_inject_packet_desc(packet, initial_values);
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_ERROR(
            "Calling inject_packet_desc(" << nsim::to_string(packet) << ", values=" << map_to_string(initial_values) << ") => "
                                          << dsim::to_string(ret));
    } else {
        NSIM_PROV_RPC_API_DEBUG(
            "Calling inject_packet_desc(" << nsim::to_string(packet) << ", values=" << map_to_string(initial_values) << ") => "
                                          << dsim::to_string(ret));
    }

    return ret == dsim::DSIM_STATUS_SUCCESS;
}

//
// Call step_packet on the DSIM server
//
bool
nsim_provider::rpc_api_step_packet(void)
{
    NSIM_PROV_RPC_API_DEBUG("Calling step_packet()");
    assert(m_client && "rpc_api_step_packet: fail, no DSIM client");

    auto ret = m_client->rpc_step_packet();
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_ERROR("Called step_packet() => " << dsim::to_string(ret));
        return false;
    }
    NSIM_PROV_RPC_API_DEBUG("Called step_packet() => " << dsim::to_string(ret));
    return true;
}

//
// Call step_macro on the DSIM server
//
bool
nsim_provider::rpc_api_step_macro(void)
{
    NSIM_PROV_RPC_API_DEBUG("Calling step_macro()");
    assert(m_client && "rpc_api_step_macro: fail, no DSIM client");

    auto ret = m_client->rpc_step_macro();
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_ERROR("Called step_macro() => " << dsim::to_string(ret));
        return false;
    }
    NSIM_PROV_RPC_API_DEBUG("Called step_macro() => " << dsim::to_string(ret));
    return true;
}

//
// Call step on the DSIM server
//
bool
nsim_provider::rpc_api_step(void)
{
    NSIM_PROV_RPC_API_DEBUG("Calling step()");
    assert(m_client && "rpc_api_step: fail, no DSIM client");

    auto ret = m_client->rpc_step();
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_ERROR("Called step() => " << dsim::to_string(ret));
        return false;
    }
    NSIM_PROV_RPC_API_DEBUG("Called step() => " << dsim::to_string(ret));
    return true;
}

//
// Call get_packet on the DSIM server
//
sim_packet_info_desc
nsim_provider::rpc_api_get_packet(void)
{
    NSIM_PROV_RPC_API_DEBUG("Calling get_packet()");
    assert(m_client && "rpc_api_get_packet: fail, no DSIM client");

    struct nsim::nsim_packet_info_t nsim_packet;
    sim_packet_info_desc sim_packet = {};
    auto ret = m_client->rpc_get_packet(nsim_packet);
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_ERROR("Called get_packet() => " << dsim::to_string(ret));
        return sim_packet;
    }

    sim_packet.packet = nsim_packet.m_packet_data.to_string_without_leading_0x();
    sim_packet.slice = nsim_packet.m_slice_id;
    sim_packet.ifg = nsim_packet.m_ifg;
    sim_packet.pif = nsim_packet.m_pif;
    NSIM_PROV_RPC_API_DEBUG("Called get_packet() => " << dsim::to_string(ret) << " packet=" << sim_packet.packet << ", slice="
                                                      << nsim_packet.m_slice_id
                                                      << ", ifg="
                                                      << nsim_packet.m_ifg
                                                      << ", pif="
                                                      << nsim_packet.m_pif);
    return sim_packet;
}

//
// Call get_packets on the DSIM server
//
sim_packet_info_desc_vec_t
nsim_provider::rpc_api_get_packets()
{
    NSIM_PROV_RPC_API_DEBUG("Calling get_packets()");
    assert(m_client && "rpc_api_get_packets: fail, no DSIM client");

    std::list<struct nsim::nsim_packet_info_t> nsim_packets;
    sim_packet_info_desc_vec_t sim_packets;

    auto ret = m_client->rpc_get_packets(nsim_packets);
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_ERROR("Called get_packets() => " << dsim::to_string(ret));
        return sim_packets;
    }

    auto cnt = 0;
    NSIM_PROV_RPC_API_DEBUG("Called get_packets() => " << dsim::to_string(ret) << " count=" << nsim_packets.size());
    for (const auto& nsim_packet : nsim_packets) {
        sim_packet_info_desc sim_packet = {};
        sim_packet.packet = nsim_packet.m_packet_data.to_string_without_leading_0x();
        sim_packet.slice = nsim_packet.m_slice_id;
        sim_packet.ifg = nsim_packet.m_ifg;
        sim_packet.pif = nsim_packet.m_pif;
        sim_packets.push_back(sim_packet);
        NSIM_PROV_RPC_API_DEBUG("Called get_packets([" << cnt++ << "]) => "
                                                       << "packet="
                                                       << sim_packet.packet
                                                       << ", slice="
                                                       << nsim_packet.m_slice_id
                                                       << ", ifg="
                                                       << nsim_packet.m_ifg
                                                       << ", pif="
                                                       << nsim_packet.m_pif);
    }
    return sim_packets;
}

//
// Call trigger_lrc_fifo on the DSIM server
//
bool
nsim_provider::rpc_api_trigger_lrc_fifo(void)
{
    NSIM_PROV_RPC_API_DEBUG("Calling trigger_lrc_fifo()");
    assert(m_client && "rpc_api_trigger_lrc_fifo: fail, no DSIM client");

    auto ret = m_client->rpc_trigger_lrc_fifo();
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_ERROR("Called trigger_lrc_fifo() => " << dsim::to_string(ret));
        return false;
    }
    NSIM_PROV_RPC_API_DEBUG("Called trigger_lrc_fifo() => " << dsim::to_string(ret));
    return true;
}

//
// Call inject_db_trigger on the DSIM server
//
bool
nsim_provider::rpc_api_inject_db_trigger(const nsim_db_trigger_info_t& trigger_info)
{
    NSIM_PROV_RPC_API_DEBUG("Calling inject_db_trigger(trigger_info=" << nsim::to_string(trigger_info) << ")");
    assert(m_client && "inject_db_trigger: fail, no DSIM client");

    auto ret = m_client->rpc_inject_db_trigger(trigger_info);
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_ERROR("Called inject_db_trigger(trigger_info=" << nsim::to_string(trigger_info) << ") => "
                                                                         << dsim::to_string(ret));
        return false;
    }
    NSIM_PROV_RPC_API_DEBUG("Called inject_db_trigger(trigger_info=" << nsim::to_string(trigger_info) << ") => "
                                                                     << dsim::to_string(ret));
    return true;
}

//
// Call get_connection_handle on the DSIM server
//
const std::string
nsim_provider::rpc_api_get_connection_handle(void)
{
    NSIM_PROV_RPC_API_DEBUG("Calling get_connection_handle()");
    assert(m_client && "rpc_api_get_connection_handle: fail, no DSIM client");

    std::string out;
    auto ret = m_client->rpc_get_connection_handle(out);
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_ERROR("Called get_connection_handle() => " << dsim::to_string(ret));
    } else {
        NSIM_PROV_RPC_API_DEBUG("Called get_connection_handle() => " << dsim::to_string(ret) << ", '" << out << "'");
    }
    return out;
}

//
// Call get_device_name on the DSIM server
//
const std::string
nsim_provider::rpc_api_get_device_name(void)
{
    NSIM_PROV_RPC_API_DEBUG("Calling get_device_name()");
    assert(m_client && "rpc_api_get_device_name: fail, no DSIM client");

    std::string out;
    out = m_client->rpc_get_device_name();
    NSIM_PROV_RPC_API_DEBUG("Called get_device_name() => '" << out << "'");
    return out;
}

//
// Call set_expose_npu_host on the DSIM server
//
bool
nsim_provider::rpc_api_set_expose_npu_host(void)
{
    NSIM_PROV_RPC_API_DEBUG("Calling set_expose_npu_host()");
    assert(m_client && "set_expose_npu_host: fail, no DSIM client");

    auto ret = m_client->rpc_set_expose_npu_host();
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_ERROR("Called set_expose_npu_host() => " << dsim::to_string(ret));
        return false;
    }
    NSIM_PROV_RPC_API_DEBUG("Called set_expose_npu_host() => " << dsim::to_string(ret));
    return true;
}

//
// Call set_slice_context on the DSIM server
//
bool
nsim_provider::rpc_api_set_slice_context(size_t slice_id, size_t context_id)
{
    NSIM_PROV_RPC_API_DEBUG("Calling set_slice_context(slice=" << slice_id << ", context=" << context_id << ")");
    assert(m_client && "set_slice_context: fail, no DSIM client");

    auto ret = m_client->rpc_set_slice_context(slice_id, context_id);
    if (ret != dsim::DSIM_STATUS_SUCCESS) {
        NSIM_PROV_RPC_API_ERROR("Called set_slice_context(slice=" << slice_id << ", context=" << context_id << ") => "
                                                                  << dsim::to_string(ret));
        return false;
    }
    NSIM_PROV_RPC_API_DEBUG("Called set_slice_context(slice=" << slice_id << ", context=" << context_id << ") => "
                                                              << dsim::to_string(ret));
    return true;
}

//
// Call get_and_clear_event_queue on the DSIM server
//
bool
nsim_provider::rpc_api_get_and_clear_event_queue(std::list<nsim::bit_vector>& out)
{
    NSIM_PROV_RPC_API_DEBUG("Calling get_and_clear_event_queue()");
    assert(m_client && "get_and_clear_event_queue: fail, no DSIM client");

    out = m_client->rpc_get_and_clear_event_queue();
    return true;
}
}
