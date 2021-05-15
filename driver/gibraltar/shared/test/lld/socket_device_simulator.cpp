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

#include "socket_device_simulator.h"
#include "common/logger.h"

#include <string.h>
#include <sys/file.h>

#include <sstream>
#include <string>

silicon_one::device_simulator*
create_socket_simulator(const char* device_path)
{
    silicon_one::socket_device_simulator* sim = new silicon_one::socket_device_simulator();

    if (!sim->initialize(device_path)) {
        delete sim;
        return nullptr;
    }

    return sim;
}

namespace silicon_one
{

inline uint64_t
to_addr64(la_block_id_t block_id, la_entry_addr_t addr)
{
    return (((uint64_t)block_id) << 32) | addr;
}

// Safely convert string-to-port, account for empty input string and out-of-range
inline bool
str2port(const char* port_str, uint16_t& port)
{
    char* end;
    long i = strtol(port_str, &end, 10);

    // Port number must be in "User Ports" 1024:49151 range
    // Or "Dynamic ports" range 49152:65535
    // RFC 6335
    if ((port_str == end) || (i < 1024)) {
        log_err(SIM, "%s: Bad port number, not a number or not in 1024 to 65535 range (%s).", __func__, port_str);
        return false;
    }

    port = (uint16_t)i;

    return true;
}

// Parse URI of the form "prefix?host=hostname&port_rw=n&port_int=n"
// Example:
//    /dev/rtl/socket?host=cmpsrv01&port_rw=45678&port_int=56789
static bool
parse_socket_uri(const char* uri, std::string& hostname, uint16_t& port_rw, uint16_t& port_int)
{
    std::stringstream ss(uri);
    std::string key, val;

    // Extract prefix
    if (!std::getline(ss, val, '?')) {
        log_err(SIM, "%s: bad URI format, no prefix", __func__);
        return false;
    }

    // Extract all 'key=val' pairs from 'key0=val0&key1=val1&...'
    // Don't tolerate empty strings.
    // Same key can appear multiple times, we'll take the last occurence.
    bool host_ok = false, port_rw_ok = false, port_int_ok = false;
    while (std::getline(ss, key, '=') && std::getline(ss, val, '&')) {
        if (!key.size() || !val.size()) {
            continue;
        }
        if (key == "host") {
            host_ok = true;
            hostname = val;
        } else if (key == "port_rw") {
            port_rw_ok = str2port(val.c_str(), port_rw);
        } else if (key == "port_int") {
            port_int_ok = str2port(val.c_str(), port_int);
        }
    }

    return host_ok && port_rw_ok && port_int_ok;
}

bool
socket_device_simulator::initialize(const char* device_path)
{
    std::string hostname;
    uint16_t port_rw, port_int;

    log_debug(SIM, "%s: URI '%s'", __PRETTY_FUNCTION__, device_path);

    if (!parse_socket_uri(device_path, hostname, port_rw, port_int)) {
        log_err(SIM,
                "%s: Bad URI format '%s', should be 'prefix?host=hostname&port_rw=n&port_int=n'",
                __PRETTY_FUNCTION__,
                device_path);
        return false;
    }

    log_debug(SIM,
              "%s: Connecting to hostname=%s, port_rw=%hu, port_int=%hu\n",
              __PRETTY_FUNCTION__,
              hostname.c_str(),
              port_rw,
              port_int);

    m_lld_conn = lld_client_connect(hostname.c_str(), port_rw, port_int);
    if (!m_lld_conn) {
        log_err(SIM, "Failed connecting to %s - %d (%s)", device_path, errno, strerror(errno));
        return false;
    }

    return true;
}

socket_device_simulator::socket_device_simulator() : m_lld_conn(nullptr)
{
}

socket_device_simulator::~socket_device_simulator()
{
    if (m_lld_conn) {
        lld_conn_destroy(m_lld_conn);
    }
}

la_device_revision_e
socket_device_simulator::get_device_revision() const
{
    // TODO
    return la_device_revision_e::PACIFIC_A0;
}

la_status
socket_device_simulator::open_device(int& device_fd, int& interrupt_fd, size_t& interrupt_width_bytes)
{
    // Get an already open 'fd'
    int fd = lld_conn_get_interrupt_fd(m_lld_conn);
    if (fd < 0) {
        return LA_STATUS_EUNKNOWN;
    }
    // Lock the 'fd', this increments the in-use reference count of the file descriptor.
    int rc = flock(fd, LOCK_SH);
    if (rc) {
        return LA_STATUS_EUNKNOWN;
    }

    device_fd = -1;
    interrupt_fd = fd;
    interrupt_width_bytes = 4;

    return LA_STATUS_SUCCESS;
}

void
socket_device_simulator::close_device(int device_fd, int interrupt_fd)
{
    flock(interrupt_fd, LOCK_UN);
}

la_status
socket_device_simulator::write_register(la_block_id_t block_id,
                                        la_entry_addr_t addr,
                                        la_entry_width_t width,
                                        size_t count,
                                        const void* in_val)
{
    return do_write(block_id, addr, width, count, in_val);
}

la_status
socket_device_simulator::read_register(la_block_id_t block_id,
                                       la_entry_addr_t addr,
                                       la_entry_width_t width,
                                       size_t count,
                                       void* out_val)
{
    return do_read(block_id, addr, width, count, out_val);
}

la_status
socket_device_simulator::write_memory(la_block_id_t block_id,
                                      la_entry_addr_t addr,
                                      la_entry_width_t width,
                                      size_t count,
                                      const void* in_val)
{
    return do_write(block_id, addr, width, count, in_val);
}

la_status
socket_device_simulator::read_memory(la_block_id_t block_id,
                                     la_entry_addr_t addr,
                                     la_entry_width_t width,
                                     size_t count,
                                     void* out_val)
{
    return do_read(block_id, addr, width, count, out_val);
}

la_status
socket_device_simulator::add_property(std::string, std::string value)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
socket_device_simulator::do_write(la_block_id_t block_id,
                                  la_entry_addr_t addr,
                                  la_entry_width_t width,
                                  size_t count,
                                  const void* in_val)
{
    int rc = 0;
    uint8_t* p = (uint8_t*)in_val;
    for (size_t i = 0; i < count; ++i, ++addr, p += width) {
        rc = lld_conn_write_regmem(m_lld_conn, to_addr64(block_id, addr), p, width);
        if (rc) {
            log_err(SIM, "%s: block_id=0x%x, addr=0x%x, width=%d, count=%ld", __func__, block_id, addr, width, count);
            return LA_STATUS_EUNKNOWN;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
socket_device_simulator::do_read(la_block_id_t block_id, la_entry_addr_t addr, la_entry_width_t width, size_t count, void* out_val)
{
    dassert_crit(count == 1);

    int rc = lld_conn_read_regmem(m_lld_conn, to_addr64(block_id, addr), out_val, width);
    if (rc) {
        log_err(SIM, "%s: block:addr 0x%x:%x", __func__, block_id, addr);
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
