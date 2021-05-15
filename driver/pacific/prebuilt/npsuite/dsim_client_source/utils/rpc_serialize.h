// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef _RPC_SERIALIZE_H_
#define _RPC_SERIALIZE_H_

#include "utils/serialize.h"
#include "device_simulator/dsim_config_interface.h"

namespace dsim
{

//
// Recursive variadic macros used to write RPC data to a stream
//
template <typename T>
void
write_rpc_one_arg(std::ostringstream& out, T t)
{
    out << encapsulate_value(t);
}

template <typename T, typename... Rest>
void
write_rpc_one_arg(std::ostringstream& out, T t, Rest... rest)
{
    write_rpc_one_arg(out, t);
    write_rpc_one_arg(out, rest...);
}

//
// Recursive variadic macros used to read RPC data from a stream
//
template <typename T>
void
read_rpc_one_arg(std::istringstream& in, enum dsim_status_e& status, T& t)
{
    if (status == DSIM_STATUS_SUCCESS) {
        if (!(in >> encapsulate_value(t))) {
            status = DSIM_STATUS_ESIZE;
        }
    }
}

template <typename T, typename... Rest>
void
read_rpc_one_arg(std::istringstream& in, enum dsim_status_e& status, T& t, Rest&... rest)
{
    read_rpc_one_arg(in, status, t);
    read_rpc_one_arg(in, status, rest...);
}
}
#endif
