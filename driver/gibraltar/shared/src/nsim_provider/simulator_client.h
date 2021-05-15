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

#ifndef __SIMULATOR_CLIENT_H__
#define __SIMULATOR_CLIENT_H__

#include "device_simulator/dsim_client/dsim_client.h"
#include "device_simulator/dsim_config_interface.h"
#include "lld/device_simulator.h"
#include "utils/npsuite_logger.h"

#define MAX_NUM_OF_CONNECTION_RETRIES (60)
#define MAX_TIMEOUT_BETWEEN_RETRIES (1) // in seconds

namespace dsim
{
class dsim_client;
}

namespace silicon_one
{

/// @brief Client side of server-client device simulation flow.
///
/// The client is instantiated on SDK side and sends commands for execution through a socket.
class simulator_client : public device_simulator
{
public:
    simulator_client();
    ~simulator_client();

    bool initialize(const char* socket_addr, size_t port, const char* sdk_version);

    //
    // This is a callback from nsim when it has logged a message. This hook point allows the
    // SDK to report nsim logs, so that the nsim logs appear alongside SDK logs. This helps
    // with debugging DSIM client issues.
    //
    npsuite::register_log_message_client_handle_t client_log_handle{};
    void handle_npsuite_logger_message_callback(const npsuite::npsuite_logger_message_callback_data_t& data);

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
    la_status dsim_2_la_status(dsim::dsim_status_e status);

    dsim::dsim_client* m_client;
};

}; // namespace silicon_one

#endif //  __SIMULATOR_CLIENT_H__
