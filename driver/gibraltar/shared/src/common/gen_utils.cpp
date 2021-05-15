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

#include "common/gen_utils.h"
namespace silicon_one
{
size_t
add_timestamp(char* buffer, size_t buffer_size)
{
    size_t chars_printed;
    auto now = std::chrono::system_clock::now();
    auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
    auto msec = std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds);
    auto date = std::chrono::system_clock::to_time_t(now);
    struct tm unused;

    chars_printed = strftime(buffer, buffer_size, "%d-%m-%Y %H:%M:%S", localtime_r(&date, &unused));
    chars_printed += snprintf(buffer + chars_printed, buffer_size - chars_printed, ".%03ld ", msec.count());

    return chars_printed;
}

std::string
get_current_timestamp()
{
    char ts[64] = {};
    add_timestamp(ts, sizeof(ts));
    return std::string(ts);
}
}
