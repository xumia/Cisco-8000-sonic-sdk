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
// |             |                  | nsim_provider_c_api.cpp |<----------------- YOU ARE HERE
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

#include "nsim_provider_c_api.h"
#include <dlfcn.h>

namespace silicon_one
{

//
// Populate callback vectors for the C API.
//
void
nsim_provider::c_api_populate(void)
{
    NSIM_PROV_C_API_TRACE();
    api.destructor = std::bind(&nsim_provider::c_api_destructor, this);
    api.set_log_file = std::bind(&nsim_provider::c_api_set_log_file, this, std::placeholders::_1, std::placeholders::_2);
    api.set_log_level = std::bind(&nsim_provider::c_api_set_log_level, this, std::placeholders::_1);
    api.packet_dma_enable = std::bind(&nsim_provider::c_api_packet_dma_enable, this, std::placeholders::_1);
    api.inject_packet = std::bind(&nsim_provider::c_api_inject_packet, this, std::placeholders::_1, std::placeholders::_2);
    api.step_packet = std::bind(&nsim_provider::c_api_step_packet, this);
    api.step_macro = std::bind(&nsim_provider::c_api_step_macro, this);
    api.step = std::bind(&nsim_provider::c_api_step, this);
    api.get_packet = std::bind(&nsim_provider::c_api_get_packet, this);
    api.get_packets = std::bind(&nsim_provider::c_api_get_packets, this);
    api.trigger_lrc_fifo = std::bind(&nsim_provider::c_api_trigger_lrc_fifo, this);
    api.inject_db_trigger = std::bind(&nsim_provider::c_api_inject_db_trigger, this, std::placeholders::_1);
    api.get_connection_handle = std::bind(&nsim_provider::c_api_get_connection_handle, this);
    api.get_device_name = std::bind(&nsim_provider::c_api_get_device_name, this);
    api.set_expose_npu_host = std::bind(&nsim_provider::c_api_set_expose_npu_host, this);
    api.set_slice_context = std::bind(&nsim_provider::c_api_set_slice_context, this, std::placeholders::_1, std::placeholders::_2);
    api.get_and_clear_event_queue = std::bind(&nsim_provider::c_api_get_and_clear_event_queue, this, std::placeholders::_1);
}

void
nsim_provider::c_api_init(void)
{
    c_api_populate();

    c_api_find_symbols();

    c_api_create_server();
}

//
// Start the C API server
//
void
nsim_provider::c_api_create_server(void)
{
    NSIM_PROV_C_API_TRACE();
    m_server = dsim_apis.m_create_and_run_simulator_server(
        m_source_path, m_leaba_defined, m_hostname.c_str(), m_port, m_device_path, m_additional_params);
    assert(m_server && "c_api_create_server: unable to start dsim server");
}

//
// Locate our libdsim.so and other C APIs we need
//
void
nsim_provider::c_api_find_symbols(void)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_INFO("Starting dsim C server");

    m_dl_libdsim_path = std::string(m_npsuite_root) + "/lib/libdsim.so";
    std::ifstream lib(m_dl_libdsim_path, std::ios::in);
    assert(lib.is_open() && "c_api_create_server: $NPSUITE_ROOT/lib/libdsim.so not found");

    m_libdsym_handle = dlopen(m_dl_libdsim_path.c_str(), RTLD_LAZY);
    assert(m_libdsym_handle && "c_api_create_server: cannot dlopen libdsim.so");

    dsim_apis.m_create_and_run_simulator_server
        = (decltype(dsim_apis.m_create_and_run_simulator_server))dlsym(m_libdsym_handle, "create_and_run_simulator_server_default");
    assert(dsim_apis.m_create_and_run_simulator_server
           && "c_api_create_server: cannot find create_and_run_simulator_server() from libdsim.so");

    dsim_apis.m_destroy_simulator = (decltype(dsim_apis.m_destroy_simulator))dlsym(m_libdsym_handle, "destroy_simulator");
    assert(dsim_apis.m_destroy_simulator && "c_api_create_server: cannot find destroy_simulator() from libdsim.so");

    dsim_apis.m_set_log_level = (decltype(dsim_apis.m_set_log_level))dlsym(m_libdsym_handle, "set_log_level");
    assert(dsim_apis.m_set_log_level && "c_api_create_server: cannot find set_log_level() from libdsim.so");

    dsim_apis.m_get_device_name = (decltype(dsim_apis.m_get_device_name))dlsym(m_libdsym_handle, "get_device_name");
    assert(dsim_apis.m_get_device_name && "c_api_create_server: cannot find get_device_name() from libdsim.so");

    dsim_apis.m_get_connection_handle
        = (decltype(dsim_apis.m_get_connection_handle))dlsym(m_libdsym_handle, "get_connection_handle");
    assert(dsim_apis.m_get_connection_handle && "c_api_create_server: cannot find get_connection_handle() from libdsim.so");

    dsim_apis.m_inject_packet = (decltype(dsim_apis.m_inject_packet))dlsym(m_libdsym_handle, "inject_packet");
    assert(dsim_apis.m_inject_packet && "c_api_create_server: cannot find inject_packet() from libdsim.so");

    dsim_apis.m_step_packet = (decltype(dsim_apis.m_step_packet))dlsym(m_libdsym_handle, "step_packet");
    assert(dsim_apis.m_step_packet && "c_api_create_server: cannot find step_packet() from libdsim.so");

    dsim_apis.m_step_macro = (decltype(dsim_apis.m_step_macro))dlsym(m_libdsym_handle, "step_macro");
    assert(dsim_apis.m_step_macro && "c_api_create_server: cannot find step_macro() from libdsim.so");

    dsim_apis.m_step = (decltype(dsim_apis.m_step))dlsym(m_libdsym_handle, "step");
    assert(dsim_apis.m_step && "c_api_create_server: cannot find step() from libdsim.so");

    dsim_apis.m_trigger_lrc_fifo = (decltype(dsim_apis.m_trigger_lrc_fifo))dlsym(m_libdsym_handle, "trigger_lrc_fifo");
    assert(dsim_apis.m_trigger_lrc_fifo && "c_api_create_server: cannot find trigger_lrc_fifo() from libdsim.so");

    dsim_apis.m_packet_dma_enable = (decltype(dsim_apis.m_packet_dma_enable))dlsym(m_libdsym_handle, "packet_dma_enable");
    assert(dsim_apis.m_packet_dma_enable && "c_api_create_server: cannot find packet_dma_enable() from libdsim.so");

    dsim_apis.m_get_and_clear_output_packets
        = (decltype(dsim_apis.m_get_and_clear_output_packets))dlsym(m_libdsym_handle, "get_and_clear_output_packets");
    assert(dsim_apis.m_get_and_clear_output_packets
           && "c_api_create_server: cannot find get_and_clear_output_packets() from libdsim.so");

    dsim_apis.m_set_log_file = (decltype(dsim_apis.m_set_log_file))dlsym(m_libdsym_handle, "set_log_file");
    assert(dsim_apis.m_set_log_file && "c_api_create_server: cannot find set_log_file() from libdsim.so");

    dsim_apis.m_inject_db_trigger = (decltype(dsim_apis.m_inject_db_trigger))dlsym(m_libdsym_handle, "inject_db_trigger");
    assert(dsim_apis.m_inject_db_trigger && "c_api_create_server: cannot find inject_db_trigger() from libdsim.so");

    dsim_apis.m_set_expose_npu_host = (decltype(dsim_apis.m_set_expose_npu_host))dlsym(m_libdsym_handle, "set_expose_npu_host");
    assert(dsim_apis.m_set_expose_npu_host && "c_api_create_server: cannot find set_expose_npu_host() from libdsim.so");

    dsim_apis.m_set_slice_context = (decltype(dsim_apis.m_set_slice_context))dlsym(m_libdsym_handle, "set_slice_context");
    assert(dsim_apis.m_set_slice_context && "c_api_create_server: cannot find set_slice_context() from libdsim.so");

    dsim_apis.m_get_and_clear_event_queue
        = (decltype(dsim_apis.m_get_and_clear_event_queue))dlsym(m_libdsym_handle, "get_and_clear_event_queue");
    assert(dsim_apis.m_get_and_clear_event_queue && "c_api_create_server: cannot find get_and_clear_event_queue() from libdsim.so");
}

void
nsim_provider::c_api_destructor(void)
{
    NSIM_PROV_C_API_TRACE();
    dsim_apis.m_destroy_simulator(m_server);
}

bool
nsim_provider::c_api_set_log_file(const char* p, bool logPrefixEnabled)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling set_log_file()");
    dsim_apis.m_set_log_file(m_server, p, logPrefixEnabled);
    return true;
}

bool
nsim_provider::c_api_set_log_level(nsim::nsim_log_module_e level)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling set_log_level(" << level << ")");
    dsim_apis.m_set_log_level(m_server, level);
    return true;
}

bool
nsim_provider::c_api_packet_dma_enable(bool value)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling packet_dma_enable()");
    dsim_apis.m_packet_dma_enable(m_server, value);
    return true;
}

bool
nsim_provider::c_api_inject_packet(const sim_packet_info_desc& packet_desc, const sim_initial_metadata_map_t& initial_values)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling inject_packet(" << packet_desc.packet << ")");

    nsim_packet_info_t pi;
    nsim::bit_vector bv = nsim::bit_vector(packet_desc.packet, packet_desc.packet.size() * 4);
    pi.set_args(bv, packet_desc.slice, packet_desc.ifg, packet_desc.pif);
    nsim::nsim_name_value_map_t nsim_initial_values;
    for (const auto& key_val_pair : initial_values) {
        nsim_initial_values.emplace(key_val_pair.first, key_val_pair.second);
    }

    auto out = dsim_apis.m_inject_packet(m_server, pi, nsim_initial_values);
    if (!out) {
        NSIM_PROV_C_API_ERROR("Called inject_packet() => failed");
        return false;
    }
    return true;
}

bool
nsim_provider::c_api_step_packet(void)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling step_packet()");

    if (!dsim_apis.m_step_packet(m_server)) {
        NSIM_PROV_C_API_ERROR("Called step_packet() => failed");
        return false;
    }
    return true;
}

bool
nsim_provider::c_api_step_macro(void)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling step_macro()");

    if (!dsim_apis.m_step_macro(m_server)) {
        NSIM_PROV_C_API_ERROR("Called step_macro() => failed");
        return false;
    }
    return true;
}

bool
nsim_provider::c_api_step(void)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling step()");

    if (!dsim_apis.m_step(m_server)) {
        NSIM_PROV_C_API_ERROR("Called step() => failed");
        return false;
    }
    return true;
}

sim_packet_info_desc
nsim_provider::c_api_get_packet(void)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling get_packet()");

    sim_packet_info_desc out{};
    std::list<nsim_packet_info_t> packets;
    dsim_apis.m_get_and_clear_output_packets(m_server, packets);
    if (packets.empty()) {
        NSIM_PROV_C_API_DEBUG("Called get_packet() => None");
        return out;
    }

    auto p = packets.back();
    auto data = p.m_packet_data.to_string();
    if (data.size() >= 2) {
        data.erase(0, 2); // remove 0x
    }
    out.packet = data;
    out.slice = p.m_slice_id;
    out.ifg = p.m_ifg;
    out.pif = p.m_pif;
    NSIM_PROV_C_API_DEBUG(
        "Called get_packet() => (" << out.packet << ", slice " << out.slice << ", ifg " << out.ifg << ", pif " << out.pif << ")");
    return out;
}

sim_packet_info_desc_vec_t
nsim_provider::c_api_get_packets()
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling get_packets()");

    NSIM_PROV_C_API_TRACE();
    sim_packet_info_desc_vec_t out;
    std::list<nsim_packet_info_t> packets;
    dsim_apis.m_get_and_clear_output_packets(m_server, packets);
    for (auto p : packets) {
        sim_packet_info_desc outp;
        auto data = p.m_packet_data.to_string();
        if (data.size() >= 2) {
            data.erase(0, 2); // remove 0x
        }
        outp.packet = data;
        outp.slice = p.m_slice_id;
        outp.ifg = p.m_ifg;
        outp.pif = p.m_pif;
        NSIM_PROV_C_API_DEBUG(
            "Called get_packets() => (" << outp.packet << ", slice " << outp.slice << ", ifg " << outp.ifg << ", pif " << outp.pif
                                        << ")");
        out.push_back(outp);
    }
    return out;
}

bool
nsim_provider::c_api_trigger_lrc_fifo(void)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling trigger_lrc_fifo()");
    dsim_apis.m_trigger_lrc_fifo(m_server);
    return true;
}

bool
nsim_provider::c_api_inject_db_trigger(const nsim_db_trigger_info_t& trigger_info)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling inject_db_trigger()");
    dsim_apis.m_inject_db_trigger(m_server, trigger_info);
    return true;
}

const std::string
nsim_provider::c_api_get_connection_handle(void)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling get_connection_handle()");

    std::string out;
    dsim_apis.m_get_connection_handle(m_server, out);
    NSIM_PROV_C_API_DEBUG("Called get_connection_handle() => " << out);
    return out;
}

const std::string
nsim_provider::c_api_get_device_name(void)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling get_device_name()");

    std::string out;
    dsim_apis.m_get_device_name(m_server, out);
    NSIM_PROV_C_API_DEBUG("Called get_device_name() => " << out);
    return out;
}

bool
nsim_provider::c_api_set_expose_npu_host(void)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling set_expose_npu_host()");
    if (!dsim_apis.m_set_expose_npu_host(m_server)) {
        NSIM_PROV_C_API_ERROR("Calling set_expose_npu_host() => failed");
        return false;
    }
    return true;
}

bool
nsim_provider::c_api_set_slice_context(size_t slice_id, size_t context_id)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling set_slice_context(slice=" << slice_id << ", context=" << context_id << ")");
    if (!dsim_apis.m_set_slice_context(m_server, slice_id, context_id)) {
        NSIM_PROV_C_API_ERROR("Calling set_slice_context(slice=" << slice_id << ", context=" << context_id << ") => failed");
        return false;
    }
    return true;
}

bool
nsim_provider::c_api_get_and_clear_event_queue(std::list<nsim::bit_vector>& out)
{
    NSIM_PROV_C_API_TRACE();
    NSIM_PROV_C_API_DEBUG("Calling get_and_clear_event_queue()");
    if (!dsim_apis.m_get_and_clear_event_queue(m_server, out)) {
        NSIM_PROV_C_API_ERROR("Calling get_and_clear_event_queue() => failed");
        return false;
    }
    // NSIM_PROV_C_API_DEBUG("Calling get_and_clear_event_queue() => " << to_string(out));
    // nsim::bit_vector b;
    // to_string(b);
    return true;
}
}
