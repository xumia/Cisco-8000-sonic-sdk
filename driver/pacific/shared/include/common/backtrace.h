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

#ifndef __COMMON_BACKTRACE_H__
#define __COMMON_BACKTRACE_H__

#include <string>

namespace silicon_one
{

/// @brief Get backtrace in human readable form.
///
/// @param[in] max_frames Max number of stack frames to unwind.
/// @return    String holding the backtrace.
std::string demangled_backtrace(size_t max_frames);

/// @brief Get full backtrace in human readable form.
///
/// @return    String holding the backtrace.
std::string demangled_backtrace();

} // namespace silicon_one

#endif // __COMMON_BACKTRACE_H__
