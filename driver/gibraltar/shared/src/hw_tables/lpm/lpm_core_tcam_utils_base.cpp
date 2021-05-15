// BEGIN_LEGAL
//
// Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "lpm_core_tcam_utils_base.h"
#include "lpm_common.h"
#include "lpm_core_tcam_utils_akpg.h"
#include "lpm_core_tcam_utils_pacific_gb.h"

namespace silicon_one
{

lpm_core_tcam_utils_scptr
create_core_tcam_utils(const ll_device_sptr& ll_device)
{
    if (is_akpg_revision(ll_device)) {
        return std::make_shared<lpm_core_tcam_utils_akpg>();
    } else if (is_pacific_or_gibraltar_revision(ll_device)) {
        return std::make_shared<lpm_core_tcam_utils_pacific_gb>();
    }

    dassert_crit(false, "Device not supported");
    return nullptr;
}

} // namespace silicon_one
