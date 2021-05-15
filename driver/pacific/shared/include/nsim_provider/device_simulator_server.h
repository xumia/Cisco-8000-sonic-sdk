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

#ifndef __DEVICE_SIMULATOR_SERVER_H__
#define __DEVICE_SIMULATOR_SERVER_H__

#include <string>

namespace silicon_one
{
/// @brief Server side interface of server-client Pacific simulation flow.
class device_simulator_server
{
public:
    // D'tor
    virtual ~device_simulator_server() = default;

    /// @brief Returns a descriptor of server connection, which will be used by simulation client.
    ///
    /// @retval Handle of an opened server connection. Handle can be provided as device path to la_create_device.
    virtual std::string get_connection_handle() const = 0;

    /// @brief Runs simulation.
    /// This call might be blocking, waiting for a client connecting to the server.
    ///
    /// @retval     true        Received and executed simulator commands, until connection is not closed or timeout occured.
    /// @retval     false       Connection not established.
    virtual bool run() = 0;
};

} // namespace silicon_one

#endif // __DEVICE_SIMULATOR_SERVER_H__
