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

#include "common/proc_maps.h"

#include <fstream>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>

namespace silicon_one
{

std::string
proc_maps()
{

    std::ostringstream output_stream;

    output_stream << "/proc/self/maps:" << std::endl;
    std::ifstream proc_maps;
    char file_name[256];
    sprintf(file_name, "/proc/%d/maps", getpid());
    proc_maps.open(file_name);

    if (proc_maps.is_open()) {
        char line[1025];
        while (proc_maps.getline(line, 1024)) {
            output_stream << line << std::endl;
        }
    } else {
        output_stream << "Unable to open " << file_name << std::endl;
    }

    return output_stream.str();
}

} // namespace silicon_one
