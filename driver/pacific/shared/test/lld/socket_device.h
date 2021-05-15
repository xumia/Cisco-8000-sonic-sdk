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

#ifndef __SOCKET_DEVICE_H__
#define __SOCKET_DEVICE_H__

#include "common/la_status.h"
#include "lld/socket_connection/lld_conn_lib.h"

namespace silicon_one
{
class socket_device
{
public:
#ifndef SWIG
    /// @brief  Create a device-side simulator that maintains two socket connections.
    ///
    /// @note   The device side is a server that listens on R/W and Interrupt
    ///         sockets and waits for connection from socket_device_simulator.
    ///
    ///         A "read" from a previously "written" location returns a "written" value.
    ///         A "read" from a never "written" location returns 0.
    ///
    ///         If ports are set to 0, the server chooses ports automatically.
    ///
    /// @param[in]  port_rw             TCP port for R/W (optionally 0).
    /// @param[in]  port_int            TCP port for Interrupt (optionally 0).
    ///
    /// @retval                         Pointer to device-side simulator object.
    static socket_device* create(uint16_t port_rw, uint16_t port_int);
#endif

    virtual ~socket_device() = default;

    /// @brief  Get R/W port of socket device.
    ///
    /// @retval Number of R/W port on success, 0 on failure.
    virtual uint16_t get_port_rw() const = 0;

    /// @brief  Get Interrupt port of socket device.
    ///
    /// @retval Number of Interrupt port on success, 0 on failure.
    virtual uint16_t get_port_int() const = 0;
};
}

#endif
