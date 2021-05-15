// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "device_simulator/dsim_client/dsim_client.h"
#include "device_simulator/dsim_client/dsim_socket_client.h"
#include "device_simulator/socket_command.h"
#include "device_simulator/dsim_common/nsim_command.h"
#include "utils/logger/logger.h"
#include "utils/rpc_serialize.h"
#include <sstream>
#include <iostream>

using namespace npsuite;
namespace dsim
{

//
// Serialize data and send to the DSIM server
//
template <typename T, typename... Rest>
dsim_status_e
dsim_client::write_rpc_internal(const dsim_rpc_version_t version,
                                const bool has_payload,
                                const socket_command_type_e cmd,
                                const T t,
                                Rest... rest)
{
    socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(m_socket_command_buffer);

    //
    // Flush needs special handling as we send it post existing message construction but
    // prior to send() (to avoid sequence number issues). So we have our own buffer to avoid
    // overwriting the existing command.
    //
    if (cmd == socket_command_type_e::FLUSH) {
        cmd_hdr = reinterpret_cast<socket_command_header*>(m_socket_flush_command_buffer);
    }

    cmd_hdr->cmd = cmd;
    cmd_hdr->client_id = m_client_id;
    cmd_hdr->flags.expecting_reply = true;

    //
    // Serialize the data to be sent
    //
    std::ostringstream out;

    out << encapsulate_value(version);

    if (has_payload) {
        write_rpc_one_arg(out, t, rest...);
    }

    auto out_buf = out.str();
    auto out_buf_len = out_buf.size();

    //
    // Check for overflow
    //
    auto send_size = SOCKET_COMMAND_HEADER_SIZE + out_buf_len;
    if (send_size > SOCKET_COMMAND_BUFFER_LEN) {
        ELOG_INSTANCE(m_logger,
                      NSIM_DEBUG,
                      "DSIM client " + to_string(cmd) + ": serialize to DSIM server buffer overflow, tried to write "
                          + std::to_string(send_size));
        return DSIM_STATUS_ESIZE;
    }

    //
    // Send the serialized data
    //
    auto payload = reinterpret_cast<struct dsim_rpc_t*>(cmd_hdr->payload);
    memcpy(payload, &out_buf[0], out_buf_len);

    if (!send_and_save(send_size, cmd_hdr)) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client " + to_string(cmd) + ": serialize to DSIM server send failed");
        return DSIM_STATUS_EUNKNOWN;
    }

    if (out.fail()) {
        return DSIM_STATUS_ESERIALIZE;
    }
    return DSIM_STATUS_SUCCESS;
}

//
// Write an RPC message with payload and default version
//
template <typename T, typename... Rest>
dsim_status_e
dsim_client::write_rpc(const socket_command_type_e cmd, const T t, Rest... rest)
{
    const dsim_rpc_version_t version = DSIM_RPC_VERSION_1;
    return write_rpc_internal(version, DSIM_RPC_HAS_PAYLOAD, cmd, t, rest...);
}

//
// Write an RPC message with payload and version
//
template <typename T, typename... Rest>
dsim_status_e
dsim_client::write_rpc(const socket_command_type_e cmd, const dsim_rpc_version_t version, const T t, Rest... rest)
{
    return write_rpc_internal(version, DSIM_RPC_HAS_PAYLOAD, cmd, t, rest...);
}

//
// Write an RPC message with payload and default version; and then wait for the status
//
template <typename T, typename... Rest>
dsim_status_e
dsim_client::write_rpc_and_wait_for_status(const socket_command_type_e cmd, const T t, Rest... rest)
{
    const dsim_rpc_version_t version = DSIM_RPC_VERSION_1;
    auto ret = write_rpc_internal(version, DSIM_RPC_HAS_PAYLOAD, cmd, t, rest...);
    return (ret == DSIM_STATUS_SUCCESS) ? read_status(cmd) : ret;
}

//
// Deserialize a response from the DSIM server
//
template <typename T, typename... Rest>
dsim_status_e
dsim_client::read_rpc_internal(dsim_rpc_version_t& version,
                               const bool has_payload,
                               const socket_command_type_e cmd,
                               uint8_t* buf,
                               size_t received_bytes,
                               T& t,
                               Rest&... rest)
{
    std::string tmp((const char*)buf, (size_t)received_bytes);
    std::istringstream in(tmp);

    if (!(in >> encapsulate_value(version))) {
        ELOG_INSTANCE(m_logger,
                      NSIM_DEBUG,
                      "DSIM client " + to_string(cmd) + ": deserialize from DSIM server buffer overflow (read version)");
        return DSIM_STATUS_ESIZE;
    }

    auto status = DSIM_STATUS_SUCCESS;
    if (has_payload) {
        read_rpc_one_arg(in, status, t, rest...);
    }
    if (in.fail()) {
        return DSIM_STATUS_EDESERIALIZE;
    }
    return status;
}

//
// Deserialize a response from the DSIM server
//
template <typename T, typename... Rest>
dsim_status_e
dsim_client::read_rpc_internal(dsim_rpc_version_t& version,
                               const bool has_payload,
                               const socket_command_type_e cmd,
                               T& t,
                               Rest&... rest)
{
    auto buf = reinterpret_cast<uint8_t*>(m_socket_command_buffer);
    auto received_bytes = m_socket_client->receive(buf, sizeof(m_socket_command_buffer));
    return read_rpc_internal(version, has_payload, cmd, buf, received_bytes, t, rest...);
}

//
// Read an RPC message from an existing buffer with payload and default version
//
template <typename T, typename... Rest>
dsim_status_e
dsim_client::read_rpc(const socket_command_type_e cmd, uint8_t* buf, size_t received_bytes, T& t, Rest&... rest)
{
    dsim_rpc_version_t version = DSIM_RPC_VERSION_1;
    return read_rpc_internal(version, DSIM_RPC_HAS_PAYLOAD, cmd, buf, received_bytes, t, rest...);
}

//
// Read an RPC message from the socket with payload and default version
//
template <typename T, typename... Rest>
dsim_status_e
dsim_client::read_rpc(const socket_command_type_e cmd, T& t, Rest&... rest)
{
    dsim_rpc_version_t version = DSIM_RPC_VERSION_1;
    return read_rpc_internal(version, DSIM_RPC_HAS_PAYLOAD, cmd, t, rest...);
}

//
// Read an RPC message from an existing buffer with payload and version
//
template <typename T, typename... Rest>
dsim_status_e
dsim_client::read_rpc(const socket_command_type_e cmd,
                      dsim_rpc_version_t& version,
                      uint8_t* buf,
                      size_t received_bytes,
                      T& t,
                      Rest&... rest)
{
    return read_rpc_internal(version, DSIM_RPC_HAS_PAYLOAD, cmd, buf, received_bytes, t, rest...);
}
}
