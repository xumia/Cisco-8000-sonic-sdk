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

#include <stdio.h>
#include <unistd.h>

#include "socket_device.h"

#include <map>
#include <thread>

namespace silicon_one
{

class socket_device_impl : public socket_device
{
public:
    ~socket_device_impl() override;
    uint16_t get_port_rw() const override;
    uint16_t get_port_int() const override;

    bool initialize(uint16_t port_rw, uint16_t port_int);

private:
    void device_server_thread();

    lld_conn_h m_conn_h;
    std::thread m_th;
    uint16_t m_port_rw;
    uint16_t m_port_int;
    volatile int m_started;
};

socket_device*
socket_device::create(uint16_t port_rw, uint16_t port_int)
{
    socket_device_impl* sd = new socket_device_impl;
    bool ok = sd->initialize(port_rw, port_int);
    if (!ok) {
        delete sd;
        return nullptr;
    }

    return sd;
}

bool
socket_device_impl::initialize(uint16_t port_rw, uint16_t port_int)
{
    m_started = 0;

    m_conn_h = lld_server_create(port_rw, port_int);
    if (!m_conn_h) {
        return false;
    }

    lld_server_get_ports(m_conn_h, &m_port_rw, &m_port_int);
    m_th = std::thread(&socket_device_impl::device_server_thread, this);

    while (!m_started) {
        sleep(0);
    }

    return true;
}

socket_device_impl::~socket_device_impl()
{
    if (m_th.joinable()) {
        m_th.join();
    }
    if (m_conn_h) {
        lld_conn_destroy(m_conn_h);
    }
}

uint16_t
socket_device_impl::get_port_rw() const
{
    return m_port_rw;
}

uint16_t
socket_device_impl::get_port_int() const
{
    return m_port_int;
}

void
socket_device_impl::device_server_thread()
{
    struct lld_data {
        uint8_t bytes[LLD_COMMAND_MAX_DATA_LEN];
    };

    std::map<uint64_t, lld_data> memory;
    std::map<uint64_t, lld_data>::iterator memory_it;

    m_started = 1;
    lld_server_wait_conn(m_conn_h);

    while (1) {
        char cmd;
        uint64_t addr;
        lld_data data = {{0}};
        uint32_t data_sz = -1;

        if (lld_conn_recv_command(m_conn_h, &cmd, &addr, data.bytes, &data_sz) < 0) {
            fprintf(stderr, "device: failed to receive a command\n");
            break;
        }
        if (data_sz > sizeof(data)) {
            fprintf(stderr, "device: bad size %u\n", data_sz);
            break;
        }

        switch (cmd) {
        case 'W':
            memory[addr] = data;
            break;
        case 'R':
            memory_it = memory.find(addr);
            if (memory_it != memory.end()) {
                data = memory_it->second;
            }
            lld_conn_send_response(m_conn_h, cmd, addr, data.bytes, data_sz);
            break;
        default:
            fprintf(stderr, "device: bad command 0x%x\n", cmd);
            break;
        }
    }
}

} // namespace silicon_one
