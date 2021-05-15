// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __DSIM_NETWORK_INTERFACE_H__
#define __DSIM_NETWORK_INTERFACE_H__

#include "nsim/nsim.h"

#include <thread>
#include <mutex>

namespace npsuite
{
class Logger;
}

namespace dsim
{
class dsim_network_interface
{
public:
    ~dsim_network_interface();

    /// @brief Gets the DSIM network interface, which is created per simulator.
    ///
    /// @param[in] sim                      Simulator for which to create the DSIM network interface
    ///
    /// @retval dsim_network_interface ptr  Pointer to DSIM network interface
    static dsim_network_interface* get_instance(nsim::nsim_core* sim);

    /// @brief Connects the simulator port to a network interface.
    ///
    /// @param[in] slice_id         Slice number
    /// @param[in] ifg              Interface group number
    /// @param[in] pif              Port interface number
    /// @param[in] interface_name   Name of the network interface to connect the port to
    ///
    /// @retval true                Success
    /// @retval false               Port connection failed
    bool connect_port_to_interface(size_t slice_id, size_t ifg, size_t pif, std::string interface_name);

    /// @brief Disconnect the simulator port from a network interface.
    ///
    /// @param[in] slice_id         Slice number
    /// @param[in] ifg              Interface group number
    /// @param[in] pif              Port interface number
    /// @param[in] interface_name   Name of the network interface to disconnect the port from
    void disconnect_port_from_network_interface(size_t slice_id, size_t ifg, size_t pif, std::string interface_name);

    /// @brief Extracts the port ID to network interface name mapping and connects the simulator port to the network interface.
    /// The port ID (map key) is a string of the following format: "netif@slice_id,ifg,pif".
    ///
    /// @param[in] port_id_to_interface_name    Map of port IDs to interface names
    ///
    /// @retval true                            Success
    /// @retval false                           Invalid mapping format or port connection failed
    bool initialize_connections_and_start_listening_on_nework_interfaces(
        std::map<std::string, std::string>& port_id_to_interface_name);

    /// @brief Enables listening for trafick on all ports connected to network interfaces.
    void start_listening_on_nework_interfaces();

    /// @brief Disables listening for trafick on all ports connected to network interfaces.
    void stop_listening_on_network_interfaces();

private:
    dsim_network_interface(nsim::nsim_core* sim);
    dsim_network_interface(const dsim_network_interface& dsim_netif) = delete;
    dsim_network_interface& operator=(const dsim_network_interface& dsim_netif) = delete;

private:
    struct dsim_port {
        dsim_port(size_t slice_id, size_t ifg, size_t pif, std::string interface_name, npsuite::Logger* logger);
        dsim_port(dsim_port&& src);
        dsim_port& operator=(dsim_port&& other);
        ~dsim_port();

        bool connect();
        bool is_connected();
        void disconnect();

        std::string m_interface_name;
        size_t m_slice_id;
        size_t m_ifg;
        size_t m_pif;

        int m_sd;
        npsuite::Logger* m_logger;
    };

    struct dsim_thread_waker {
        dsim_thread_waker();
        ~dsim_thread_waker();

        void notify();
        void wait();

        int m_waker_fd[2];
    };

private:
    static void receive_thread(dsim_network_interface* dsim_netif);
    static void send_thread(dsim_network_interface* dsim_netif);
    void receive_packets();
    void send_packets();
    bool wait_for_read(fd_set* out_readfds, fd_set* out_errfds);
    nsim::bit_vector receive_packet(dsim_port& port);
    void reverse_packet(uint8_t* packet_start, size_t packet_size);

private:
    npsuite::Logger* m_logger;
    nsim::nsim_core* m_nsim;
    dsim_thread_waker m_waker;
    bool m_thread_is_running;
    std::vector<dsim_port> m_ports;
    std::mutex m_ports_mutex;
    std::thread* m_receive_thread;
    std::thread* m_send_thread;
};
} // namespace dsim

#endif
