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

#ifndef __IPV4_SIP_INDEX_MANAGER_H__
#define __IPV4_SIP_INDEX_MANAGER_H__

#include "api/types/la_ip_types.h"
#include "common/profile_allocator.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

///
/// Manages SIP index.
/// The local IP address is mapped to the SIP index. The SIP index is used for
/// - retrieve local IP address for encap.
/// - as part of key to retrive IP tunnel termination table.
///

namespace silicon_one
{

class la_device_impl;

class ipv4_sip_index_manager
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit ipv4_sip_index_manager(const la_device_impl_wptr& device);
    ~ipv4_sip_index_manager() = default;

    using ipv4_sip_index_profile_t = profile_allocator<la_ipv4_prefix_t>::profile_ptr;

    const la_device_impl_wptr& get_device() const;

    /// @brief allocate sip index for local IP address.
    /// @param[in]  local_ip                    The local IP address.
    /// @param[out] sip_index                   sip index allocated.
    ///@retval      LA_STATUS_SUCCESS           Operation completed successfully.
    ///@retval      LA_STATUS_ERESOURCE         Out of sip index.
    la_status allocate_sip_index(la_ipv4_prefix_t local_ip, ipv4_sip_index_profile_t& sip_index_profile);

    /// @brief free sip index corresponding to the local IP address.
    /// @param[in]  local_ip                    The IP address of which the sip index will be freed.
    ///@retval      LA_STATUS_SUCCESS           Operation completed successfully.
    ///@retval      LA_STATUS_ENOTFOUND         The local IP address not found.
    la_status free_sip_index(ipv4_sip_index_profile_t& sip_index_profile);

private:
    /// The creating device
    la_device_impl_wptr m_device;

    ipv4_sip_index_manager() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif // __IPV4_SIP_INDEX_MANAGER_H__
