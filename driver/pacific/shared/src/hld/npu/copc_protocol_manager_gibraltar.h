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

#ifndef __COPC_PROTOCOL_MANAGER_GIBRALTAR_H__
#define __COPC_PROTOCOL_MANAGER_GIBRALTAR_H__

#include "copc_protocol_manager_base.h"

namespace silicon_one
{

class copc_protocol_manager_gibraltar : public copc_protocol_manager_base
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit copc_protocol_manager_gibraltar(const la_device_impl_wptr& device);
    ~copc_protocol_manager_gibraltar();

private:
    copc_protocol_manager_gibraltar() = default; // For serialization only.
};

} // namespace silicon_one

#endif // __COPC_PROTOCOL_MANAGER_GIBRALTAR_H__
