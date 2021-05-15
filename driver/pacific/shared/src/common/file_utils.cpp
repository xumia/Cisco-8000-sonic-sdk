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

#include "common/file_utils.h"
#include <fcntl.h>

namespace silicon_one
{

namespace file_utils
{

la_status
fd_set_blocking(int fd, bool blocking)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return LA_STATUS_EUNKNOWN;
    }

    int is_nonblock = flags & O_NONBLOCK;
    if ((blocking && !is_nonblock) || (!blocking && is_nonblock)) {
        // flags is already ok, nothing to do
        return LA_STATUS_SUCCESS;
    }

    if (is_nonblock) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }

    int rc = fcntl(fd, F_SETFL, flags);

    return rc ? LA_STATUS_EUNKNOWN : LA_STATUS_SUCCESS;
}

bool
is_compressed(std::string fname)
{
    std::string name(fname);
    std::string extension(".gz");
    return (name.rfind(extension) == (name.size() - extension.size()));
}

gzFile
open_gzfile(std::string fname)
{
    const char* mode = is_compressed(fname) ? "w" : "wT";
    return (gzopen(fname.c_str(), mode));
}

la_status
write_json_to_file(json_t* json_root, std::string fname)
{
    json_dump_callback_t write_to_gzfile([](const char* buffer, size_t size, void* data) {
        int num_of_bytes = gzwrite((gzFile)data, buffer, size);
        if (0 < num_of_bytes) {
            return 0;
        } else {
            return -1;
        }
    });

    gzFile file = open_gzfile(fname);
    if (file == nullptr) {
        return LA_STATUS_EINVAL;
    }

    int retval = json_dump_callback(json_root, write_to_gzfile, file, JSON_INDENT(4) | JSON_PRESERVE_ORDER);
    gzclose(file);
    if (retval == -1) {
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

} // namespace file_utils

} // namespace silicon_one
