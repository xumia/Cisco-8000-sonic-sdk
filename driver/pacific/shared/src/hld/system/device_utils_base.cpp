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

#include <sys/types.h>

#include "common/common_strings.h"
#include "common/logger.h"
#include "device_utils_base.h"

namespace silicon_one
{

namespace device_utils
{

size_t
get_num_of_pif_per_ifg(la_device_revision_e device_revision)
{
    switch (device_revision) {
    case la_device_revision_e::NONE:
        log_debug(HLD, "%s: device revision NONE has no meaning for this function", __func__);
        return (size_t)-1;
    case la_device_revision_e::PACIFIC_A0:
    case la_device_revision_e::PACIFIC_B0:
    case la_device_revision_e::PACIFIC_B1:
        return PACIFIC_NUM_PIF_PER_IFG;
    case la_device_revision_e::GIBRALTAR_A0:
    case la_device_revision_e::GIBRALTAR_A1:
    case la_device_revision_e::GIBRALTAR_A2:
        return GB_MAX_NUM_PIF_PER_IFG;
    default:
        log_debug(HLD,
                  "%s: The requested device revision (%s) is not supported",
                  __func__,
                  silicon_one::to_string(device_revision).c_str());
        return (size_t)-1;
    }
}

} // namespace device_utils

} // namespace silicon_one
