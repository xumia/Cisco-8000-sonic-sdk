// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

// -----------------------------------------
// Some portions are also:
//
// Copyright (C) 2014 Mellanox Technologies, Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License); You may
// Obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//
// -----------------------------------------
//

#include <memory>

#include "sai_device.h"

namespace silicon_one
{
namespace sai
{

using namespace std;

sai_status_t
laobj_db_ingress_priority_group::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    // TODO until ingress priority group supported is added, set object count to zero
    *count = 0;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_ingress_priority_group::get_object_keys(std::shared_ptr<lsai_device> sdev,
                                                 uint32_t* object_count,
                                                 sai_object_key_t* object_list) const
{
    // TODO
    return SAI_STATUS_SUCCESS;
}
}
}
