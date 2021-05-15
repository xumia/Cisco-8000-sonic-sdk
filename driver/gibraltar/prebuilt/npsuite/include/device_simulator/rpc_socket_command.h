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

#ifndef __RPC_SOCKET_COMMAND_H__
#define __RPC_SOCKET_COMMAND_H__

#include "device_simulator/dsim_config_interface.h"

namespace dsim
{

//
// RPC command messages are encoded with a version and then payload. The payload is variable length data composed of serialized
// C types/structs/classes, see utils/rpc_serialize.h for more info. A version is included at the start of each payload
// and defaults to DSIM_RPC_VERSION_1.
//
// NOTE: on the DSIM client to server direction, the message has a payload header of socket_command_header.
// For DSIM server to client, there is no header. Both directions carry version information.
//
// To write to either end of the stream, write_rpc() is used. To read, read_rpc(). These apis are templatized functions,
// so you can encode data easily e.g.:
//
//     std::string foo:
//     write_rpc(cmd foo);
//     ...
//     read_rpc(cmd foo); // on the other end
//
//     std::string foo:
//     std::list<std::string> bar:
//     write_rpc(cmd, foo, bar);
//     ...
//     read_rpc(cmd, foo, bar); // on the other end
//
//     std::string foo:
//     std::list<std::string> bar:
//     std::map<std::string, std::string> flob:
//     write_rpc(cmd, foo, bar, flob);
//     ...
//     read_rpc(cmd, foo, bar, flob); // on the other end
//
// To serialize a custom class you need to write your own serializers and deserializers.
// On the serialize side you need to consider both const and non const use cases. On the
// deserialize side const is n/a. e.g.:
//
// NOTE: take care to use fixed size datatypes to avoid things getting out of sync on a
// server that is compiled differently.
//
// struct my_awesome_struct {
//     std::string field_1;
//     uint32_t field_2{};
// };
//
// //
// // Serializer
// //
// static inline std::ostream&
// serialize_my_awesome_struct(std::ostream& out, const struct my_awesome_struct& s)
// {
//     out << encapsulate_value(s.field_1);
//     out << encapsulate_value(s.field_2);
//     return out;
// }
//
// static inline std::ostream&
// operator<<(std::ostream& out, TypeWrapper<const struct my_awesome_struct&> wrapped)
// {
//     DEBUG_SERIALIZE("const my_awesome_struct")
//     return serialize_my_awesome_struct(out, wrapped.value);
// }
//
// static inline std::ostream&
// operator<<(std::ostream& out, TypeWrapper<struct my_awesome_struct&> wrapped)
// {
//     DEBUG_SERIALIZE("my_awesome_struct")
//     return serialize_my_awesome_struct(out, wrapped.value);
// }
//
// //
// // Deserializer
// //
// static inline std::istream&
// operator>>(std::istream& in, TypeWrapper<struct my_awesome_struct&> wrapped)
// {
//     uint32_t tmp_uint32; // Use fixed size for serialization instead of size_t
//     DEBUG_DESERIALIZE("my_awesome_struct")
//     in >> encapsulate_value(wrapped.value.field_1);
//     in >> encapsulate_value(wrapped.value.field_2);
//     return in;
// }

//
// Include a single byte of version in each RPC message.
//
using dsim_rpc_version_t = uint8_t;
static const dsim_rpc_version_t DSIM_RPC_VERSION_1 = 1U;
static const dsim_rpc_version_t DSIM_RPC_VERSION_2 = 2U; // Add more versions as needed.

// expecting_reply = true
struct dsim_rpc_t {
    uint8_t buf[1];

private:
    dsim_rpc_t(dsim_rpc_t const&) = delete;
    dsim_rpc_t& operator=(dsim_rpc_t const&) = delete;
};

//
// Internal enum to help with the template case where zero variadic arguments are passed.
//
enum { DSIM_RPC_HAS_PAYLOAD = true, DSIM_RPC_HAS_NO_PAYLOAD = false };
}
#endif
