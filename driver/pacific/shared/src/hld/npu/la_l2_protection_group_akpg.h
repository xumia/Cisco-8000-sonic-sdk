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

#ifndef __LA_L2_PROTECTION_GROUP_AKPG_H__
#define __LA_L2_PROTECTION_GROUP_AKPG_H__

#include "la_l2_protection_group_gibraltar.h"

namespace silicon_one
{

class la_device_impl;

class la_l2_protection_group_akpg : public la_l2_protection_group_gibraltar
{

public:
    // la_l2_protection_group_akpg API-s
    explicit la_l2_protection_group_akpg(const la_device_impl_wptr& device);

    ~la_l2_protection_group_akpg() override;

    // la_object API-s
    std::string to_string() const override;
};

} // namespace silicon_one

#endif // __LA_L2_PROTECTION_GROUP_AKPG_H__
