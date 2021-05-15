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
#include "npsuite/version.h"
#include "utils/serialize.h"
#include "dsim_client_msg_util.h"

#include <memory>
#include <csignal>
#include <iterator>
#include <algorithm> // std::count
#include <sstream>

using namespace npsuite;
namespace dsim
{

//
// Write an RPC message with no payload and default version
//
dsim_status_e
dsim_client::write_rpc(const socket_command_type_e cmd)
{
    const dsim_rpc_version_t version = DSIM_RPC_VERSION_1;
    bool unused = false;
    return write_rpc_internal(version, DSIM_RPC_HAS_NO_PAYLOAD, cmd, unused);
}

//
// Write an RPC message with no payload, but has version
//
dsim_status_e
dsim_client::write_rpc(const socket_command_type_e cmd, dsim_rpc_version_t version)
{
    bool unused = false;
    return write_rpc_internal(version, DSIM_RPC_HAS_NO_PAYLOAD, cmd, unused);
}

//
// Write an RPC message with no payload and default version
//
dsim_status_e
dsim_client::write_rpc_and_wait_for_status(const socket_command_type_e cmd)
{
    const dsim_rpc_version_t version = DSIM_RPC_VERSION_1;
    bool unused = false;
    auto ret = write_rpc_internal(version, DSIM_RPC_HAS_NO_PAYLOAD, cmd, unused);
    return (ret == DSIM_STATUS_SUCCESS) ? read_status(cmd) : ret;
}

//
// Read an RPC message with no payload and default version
//
dsim_status_e
dsim_client::read_rpc(const socket_command_type_e cmd)
{
    bool unused = false;
    dsim_rpc_version_t version = DSIM_RPC_VERSION_1;
    return read_rpc_internal(version, DSIM_RPC_HAS_NO_PAYLOAD, cmd, unused);
}

//
// Read an RPC message from an existing buffer with no payload but has version
//
dsim_status_e
dsim_client::read_rpc(const socket_command_type_e cmd, dsim_rpc_version_t& version, uint8_t* buf, size_t received_bytes)
{
    bool unused = false;
    return read_rpc_internal(version, DSIM_RPC_HAS_NO_PAYLOAD, cmd, buf, received_bytes, unused);
}

//
// Read an RPC message with DSIM status and default version
//
dsim_status_e
dsim_client::read_status(const socket_command_type_e cmd)
{
    const dsim_status_e expected_result = DSIM_STATUS_SUCCESS;
    dsim_status_e actual_result = DSIM_STATUS_EUNKNOWN;

    auto ret = read_rpc(cmd, actual_result);
    if (ret != expected_result) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, to_string(cmd) + ": command failed, " + to_string(ret));
        return ret;
    }

    if (expected_result != actual_result) {
        ELOG_INSTANCE(
            m_logger, NSIM_DEBUG, to_string(cmd) + ": command succeeded, but has failed status, " + to_string(actual_result));
        return actual_result;
    }

    ILOG_INSTANCE(m_logger, NSIM_DEBUG, to_string(cmd) + ": command success");
    return expected_result;
}
}
