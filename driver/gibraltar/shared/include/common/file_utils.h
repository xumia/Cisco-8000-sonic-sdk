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

#ifndef __COMMON_FILE_UTILS_H__
#define __COMMON_FILE_UTILS_H__

#include "la_status.h"
#include <jansson.h>
#include <zlib.h>

namespace silicon_one
{

namespace file_utils
{
/// @brief Set an open file descriptor for blocking or non-blocking file operations.
///
/// @param[in]  fd          An open file descriptor.
/// @param[in]  blocking    Set the file descriptor to be blocking or non-blocking.
///
/// @return Status code.
la_status fd_set_blocking(int fd, bool blocking);

/// @brief Open a gzFile.
///
/// If extension is .gz, open in zipped form.
/// If not, open in standard mode.
///
/// @param[in] fname Name of file to open.
/// @return gzFile.
gzFile open_gzfile(std::string fname);

/// @brief Write a JSON tree structure out to a file.
///
/// @param[in] json_root Pointer to JSON tree to write to the file.
/// @param[in] fname     Name of file to open.
/// @return gzFile.
la_status write_json_to_file(json_t* json_root, std::string fname);

} // namespace file_utils

} // namespace silicon_one

#endif
