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

#ifndef __LA_COPC_PACIFIC_H__
#define __LA_COPC_PACIFIC_H__

#include "la_copc_base.h"

namespace silicon_one
{

class la_copc_pacific : public la_copc_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_copc_pacific(la_device_impl_wptr device);
    ~la_copc_pacific() override;

private:
    la_copc_pacific() = default; // For serialization only.
};

} // namespace silicon_one

#endif // __LA_COPC_PACIFIC_H__
