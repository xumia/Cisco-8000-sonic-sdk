// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_BFD_SESSION_GIBRALTAR_H__
#define __LA_BFD_SESSION_GIBRALTAR_H__

#include "la_bfd_session_base.h"

namespace silicon_one
{

class la_device_impl;

class la_bfd_session_gibraltar : public la_bfd_session_base
{
    ////////// SERIALIZATION /////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_bfd_session_gibraltar() = default;
    //////////////////////////////////////
public:
    explicit la_bfd_session_gibraltar(const la_device_impl_wptr& device);
    ~la_bfd_session_gibraltar() override;

private:
    // Helper functions
    la_status set_npu_host_interval_mapping(uint64_t entry, uint64_t value) override;
    la_status set_npu_host_max_ccm_counter(uint64_t entry, uint64_t value) override;
};

} // namespace silicon_one

#endif //  __LA_BFD_SESSION_GIBRALTAR_H__
