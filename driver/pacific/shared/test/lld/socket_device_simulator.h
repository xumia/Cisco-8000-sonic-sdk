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

#ifndef __RTL_DEVICE_SIMULATOR_H__
#define __RTL_DEVICE_SIMULATOR_H__

#include <string>

#include "lld/device_simulator.h"
#include "lld/socket_connection/lld_conn_lib.h"

/// @brief Create socket simulator implementing #silicon_one::device_simulator interface.
///
/// The simulator uses two TCP/IP sockets as a transport for reads/writes and interrupts.
///
/// @param[in]  device_path URI that encodes the host name and ports for read/write and interrupt.
///
/// @retval     Pointer to the allocated #silicon_one::device_simulator.
silicon_one::device_simulator* create_socket_simulator(const char* device_path);

namespace silicon_one
{

/// @brief Implementation of #silicon_one::device_imulator interface for RTL testing with AV flow.
///
/// Creates a register/memory read/write access trace.
class socket_device_simulator : public device_simulator
{
public:
    socket_device_simulator();

    ~socket_device_simulator();

    bool initialize(const char* device_path);

    la_device_revision_e get_device_revision() const override;

    la_status open_device(int& device_fd, int& interrupt_fd, size_t& interrupt_width_bytes) override;

    void close_device(int device_fd, int interrupt_fd) override;

    la_status write_register(la_block_id_t block_id,
                             la_entry_addr_t reg_address,
                             la_entry_width_t reg_width,
                             size_t count,
                             const void* in_val) override;

    la_status read_register(la_block_id_t block_id,
                            la_entry_addr_t reg_address,
                            la_entry_width_t reg_width,
                            size_t count,
                            void* out_val) override;

    la_status write_memory(la_block_id_t block_id,
                           la_entry_addr_t mem_address,
                           la_entry_width_t mem_width,
                           size_t mem_entries,
                           const void* in_val) override;

    la_status read_memory(la_block_id_t block_id,
                          la_entry_addr_t mem_address,
                          la_entry_width_t mem_width,
                          size_t mem_entries,
                          void* out_val) override;

    la_status add_property(std::string key, std::string value) override;

private:
    lld_conn_h m_lld_conn; // socket interface

    la_status do_write(la_block_id_t block_id,
                       la_entry_addr_t reg_address,
                       la_entry_width_t reg_width,
                       size_t count,
                       const void* in_val);

    la_status do_read(la_block_id_t block_id, la_entry_addr_t reg_address, la_entry_width_t reg_width, size_t count, void* out_val);
};

} // namespace silicon_one

#endif // __RTL_DEVICE_SIMULATOR_H__
