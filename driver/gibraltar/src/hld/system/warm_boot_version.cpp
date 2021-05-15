// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "system/warm_boot_version.h"
#include <map>

using namespace std;

namespace silicon_one
{

// A map from SDK versions to WB revisions.
// key is an sdk version and value is its wb revision.
// This map should contain WB revision mapping for all supported SDK versions.
static const map<string, la_uint32_t> sdk_ver_wb_revision_map = {
    // e.g. {"1.39.0", 2}
};

la_status
sdk_version_to_wb_revision(const std::string sdk_version, la_uint32_t& out_wb_revision)
{
    auto it = sdk_ver_wb_revision_map.find(sdk_version);
    if (it == sdk_ver_wb_revision_map.end()) {
        return LA_STATUS_EINVAL;
    }

    out_wb_revision = it->second;
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
