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

#include "common/la_ip_addr.h"
#include "api/types/la_ip_types.h"
#include "common/dassert.h"

namespace silicon_one
{

la_ip_addr::la_ip_addr(silicon_one::la_ipv4_addr_t v4_address) : m_v4_address(v4_address), m_ip_version(version_e::V4)
{
}

la_ip_addr::la_ip_addr(silicon_one::la_ipv6_addr_t v6_address) : m_v6_address(v6_address), m_ip_version(version_e::V6)
{
}

bool
la_ip_addr::is_v4() const
{
    return m_ip_version == version_e::V4;
}

bool
la_ip_addr::is_v6() const
{
    return m_ip_version == version_e::V6;
}

bool
la_ip_addr::is_unspecified() const
{
    return m_ip_version == version_e::UNSPECIFIED;
}

silicon_one::la_ipv4_addr_t
la_ip_addr::to_v4() const
{
    dassert_crit(is_v4());
    return m_v4_address;
}

silicon_one::la_ipv6_addr_t
la_ip_addr::to_v6() const
{
    dassert_crit(is_v6());
    return m_v6_address;
}

bool
operator==(const la_ip_addr& lhs, const la_ip_addr& rhs)
{
    if (lhs.m_ip_version != rhs.m_ip_version) {
        return false;
    }
    if (lhs.is_v4()) {
        return lhs.to_v4().s_addr == rhs.to_v4().s_addr;
    } else if (lhs.is_v6()) {
        return lhs.to_v6().s_addr == rhs.to_v6().s_addr;
    } else {
        return lhs.is_unspecified();
    }
}

} // namespace silicon_one
