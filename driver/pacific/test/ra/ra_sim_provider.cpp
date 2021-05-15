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

#include "ra_sim_provider.h"
#include "common/logger.h"
#include "ra_device_simulator.h"

#include "lld/socket_connection/lld_conn_lib.h"

namespace silicon_one
{

// Definition of socket/file connection from ra_device_simulator.
extern lld_conn_h s_ra_log_socket_h;
extern FILE* s_ra_log_file;

bool
ra_sim_provider::inject_packet(const sim_packet_info_desc& packet_desc, const sim_initial_metadata_map_t& initial_values)
{

    log_debug(SIM, "command::inject_packet");

    return true;
}

bool
ra_sim_provider::step_packet()
{
    log_debug(SIM, "command::poll_packet");

    if (!s_ra_log_socket_h) {
        return true;
    }

    uint8_t out_val[1024];
    lld_conn_recv_message(s_ra_log_socket_h, out_val, 1024);

    sim_packet_info_desc packet_desc;
    packet_desc.slice = out_val[0];
    packet_desc.ifg = out_val[1];
    packet_desc.pif = out_val[2];
    size_t packet_size = out_val[3];
    packet_desc.packet = bytes_to_str(out_val + 4, packet_size);

    m_out_packets.push_back(packet_desc);

    return true;
}

sim_packet_info_desc
ra_sim_provider::get_packet()
{
    if (m_out_packets.empty()) {
        return sim_packet_info_desc();
    }

    sim_packet_info_desc ret = m_out_packets[0];
    m_out_packets.erase(m_out_packets.begin());

    return ret;
}

sim_packet_info_desc_vec_t
ra_sim_provider::get_packets()
{
    sim_packet_info_desc_vec_t ret = m_out_packets;
    m_out_packets.clear();

    return ret;
}

void
ra_sim_provider::step(size_t delay, bool blocking)
{
    if (blocking && s_ra_log_socket_h) {
        log_debug(SIM, "command::step %zd", delay);

        uint8_t out_val[1024];
        lld_conn_recv_message(s_ra_log_socket_h, out_val, 1024);
    } else {
        log_debug(SIM, "command::step_no_response %zd", delay);
    }
}

void
ra_sim_provider::poll(size_t address, size_t val, size_t mask, size_t iterations, bool blocking)
{
    if (blocking && s_ra_log_socket_h) {
        log_debug(SIM, "command::poll %016zx 2 %02zx %02zx %zd", address, val, mask, iterations);

        uint8_t out_val[1024];
        lld_conn_recv_message(s_ra_log_socket_h, out_val, 1024);
    } else {
        log_debug(SIM, "command::poll_no_response %016zx 2 %02zx %02zx %zd", address, val, mask, iterations);
    }
}

void
ra_sim_provider::poll_end_of_traffic()
{
    log_debug(SIM, "command::poll_end_of_traffic");
}

void
ra_sim_provider::flush()
{
    if (s_ra_log_file) {
        fflush(s_ra_log_file);
    }
}

void
ra_sim_provider::stop_simulation()
{
    log_debug(SIM, "command::break");
}

void
ra_sim_provider::reinject_last_packet()
{
    log_debug(SIM, "command::inject_packet");
}

void
ra_sim_provider::pop_packet()
{
    log_debug(SIM, "command::pop_packet");
}

void
ra_sim_provider::force_reg_access_method(size_t reg_access_type)
{
    log_debug(SIM, "command::force_reg_access_method %zd", reg_access_type);
}

} // namespace silicon_one
