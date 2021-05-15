// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "common/backtrace.h"

#include <cxxabi.h>
#include <execinfo.h>
#include <sstream>
#include <stdlib.h>

namespace silicon_one
{

/// @brief Max default depth of backtrace.
static const int MAX_FRAMES_DEFAULT = 128;

/// @brief Max size of a mangled function name
///@note  g++ has no upper bound specified, but Microsoft c++ and Intel c++ both have a limit of 2048 per identifier name.
static const int FUNC_NAME_MAX_SIZE = 2048; //

std::string
demangled_backtrace(size_t max_frames)
{
    std::ostringstream output_stream;

    if (max_frames == 0) {
        max_frames = MAX_FRAMES_DEFAULT;
    }

    output_stream << "stack trace:" << std::endl;

    void* addr_list[max_frames];
    int addr_len = backtrace(addr_list, sizeof(addr_list) / sizeof(void*));
    if (addr_len == 0) {
        output_stream << "  <empty, possibly corrupt>" << std::endl;
        return output_stream.str();
    }

    // resolve addresses into strings containing "filename(function+address)",
    // this array must be free()-ed
    char** symbol_list = backtrace_symbols(addr_list, addr_len);

    size_t func_name_size = FUNC_NAME_MAX_SIZE;
    char* func_name = (char*)malloc(func_name_size);

    // iterate over the returned symbol lines. skip the first, it is the
    // address of this function.
    for (int i = 1; i < addr_len; i++) {
        char *begin_name = 0, *begin_offset = 0, *end_offset = 0;

        // find parentheses and +address offset surrounding the mangled name:
        // ./module(function+0x15c) [0x8048a6d]
        for (char* p = symbol_list[i]; *p; ++p) {
            if (*p == '(')
                begin_name = p;
            else if (*p == '+')
                begin_offset = p;
            else if (*p == ')' && begin_offset) {
                end_offset = p;
                break;
            }
        }

        if (begin_name && begin_offset && end_offset && begin_name < begin_offset) {
            *begin_name++ = '\0';
            *begin_offset++ = '\0';
            *end_offset = '\0';

            // mangled name is now in [begin_name, begin_offset) and caller
            // offset in [begin_offset, end_offset). now apply
            // __cxa_demangle():

            int status;
            char* ret = abi::__cxa_demangle(begin_name, func_name, &func_name_size, &status);
            if (status == 0) {
                func_name = ret; // use possibly realloc()-ed string
                output_stream << " " << symbol_list[i] << " : " << func_name << "+" << begin_offset << std::endl;
            } else {
                // demangling failed. Output function name as a C function with
                // no arguments.
                output_stream << "  " << symbol_list[i] << " : " << begin_name << "()+" << begin_offset << std::endl;
            }
        } else {
            // couldn't parse the line? print the whole line.
            output_stream << "  " << symbol_list[i] << std::endl;
        }
    }

    free(symbol_list);

    return output_stream.str();
}

std::string
demangled_backtrace()
{
    return demangled_backtrace(0);
}

} // namespace silicon_one
