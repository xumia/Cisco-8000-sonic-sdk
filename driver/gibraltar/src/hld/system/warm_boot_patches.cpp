// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "system/la_device_impl.h"

namespace silicon_one
{

la_status
la_device_impl::warm_boot_apply_upgrade_patches(la_uint32_t base_wb_revision)
{
    // Apply patches introduced in wb_revision '2'
    if (base_wb_revision < 2) {
        // ...
    }

    // Apply patches introduced in wb_revision: '3'
    if (base_wb_revision < 3) {
        // ...
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::warm_boot_apply_rollback_patches(la_uint32_t target_wb_revision)
{
    // Apply inverse patches introduced in wb_revision '2'
    if (target_wb_revision < 2) {
        // ...
    }

    // Apply inverse patches introduced in wb_revision '3'
    if (target_wb_revision < 3) {
        // ...
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
