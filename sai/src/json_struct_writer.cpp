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

#include "json_struct_writer.h"

namespace silicon_one
{
namespace sai
{

json_struct_writer::json_struct_writer(const char* name) : m_name(name)
{
}

void
json_struct_writer::write(const char* key, json_t* json_value)
{
    param_map_t::const_iterator kv = m_str_to_writer_func.find(key);
    if (kv != m_str_to_writer_func.end()) {
        kv->second(json_value);
    } else {
        sai_log_error(SAI_API_SWITCH, "json_struct_writer(%s): Unknown parameter \"%s\"", m_name, key);
    }
}
}
}
