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

#ifndef __LLD_LLD_INTERNAL_TYPES_H__
#define __LLD_LLD_INTERNAL_TYPES_H__

#include <memory>

#include "api/types/la_common_types.h"
#include "common/weak_ptr_unsafe.h"

namespace silicon_one
{

class access_engine;
class arc_cpu;
class ll_device_impl;

using access_engine_uptr = std::unique_ptr<access_engine>;
using arc_cpu_uptr = std::unique_ptr<arc_cpu>;

using ll_device_impl_sptr = std::shared_ptr<ll_device_impl>;
using ll_device_impl_wptr = weak_ptr_unsafe<ll_device_impl>;

struct arc_cpu_info {
    la_entry_addr_t arc_run_halt_reg;
    la_entry_addr_t arc_status_reg;
    la_entry_addr_t reset_reg;
};

struct access_engine_info {
    // access engine addresses and sizes
    la_entry_addr_t cmd_mem_addr;
    la_entry_addr_t data_mem_addr;
    la_entry_addr_t go_reg_addr;
    la_entry_addr_t cmd_ptr_reg_addr;
    la_entry_addr_t status_reg_addr;

    size_t data_width;
    size_t data_mem_entries;

    size_t cmd_entries;
};
};

#endif
