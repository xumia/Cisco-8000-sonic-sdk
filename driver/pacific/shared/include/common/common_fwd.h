// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __COMMON_FWD_H__
#define __COMMON_FWD_H__

#include "common/weak_ptr_unsafe.h"
#include <memory>

namespace silicon_one
{

// Smart pointer definitions
class resource_monitor;
using resource_monitor_sptr = std::shared_ptr<resource_monitor>;
using resource_monitor_scptr = std::shared_ptr<const resource_monitor>;
using resource_monitor_wptr = weak_ptr_unsafe<resource_monitor>;
using resource_monitor_wcptr = weak_ptr_unsafe<const resource_monitor>;

class ranged_index_generator;
using ranged_index_generator_sptr = std::shared_ptr<ranged_index_generator>;
using ranged_index_generator_scptr = std::shared_ptr<const ranged_index_generator>;
using ranged_index_generator_wptr = weak_ptr_unsafe<ranged_index_generator>;
using ranged_index_generator_wcptr = weak_ptr_unsafe<const ranged_index_generator>;
}

#endif
