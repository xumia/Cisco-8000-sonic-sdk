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

#ifndef __LA_IP_ADDR_H__
#define __LA_IP_ADDR_H__

#include "api/types/la_ip_types.h"
#include "common/cereal_utils.h"

/// @file
/// @brief IP address class definition.

namespace silicon_one
{

class la_ip_addr
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief la_ip_addr
    ///
    la_ip_addr() = default;

    /// @brief la_ip_addr
    ///
    /// @param[in]  v4_address        IPv4 address
    la_ip_addr(silicon_one::la_ipv4_addr_t v4_address);

    /// @brief la_ip_addr
    ///
    /// @param[in]  v6_address        IPv6 address
    la_ip_addr(silicon_one::la_ipv6_addr_t v6_address);

    /// @brief Check if address is IPv4
    ///
    /// @retval True/False
    bool is_v4() const;

    /// @brief Check if address is IPv6
    ///
    /// @retval True/False
    bool is_v6() const;

    /// @brief Check if address is not specified
    ///
    /// @retval True/False
    bool is_unspecified() const;

    /// @brief get IPv4 address
    ///
    /// @retval IPv4 address la_ipv4_addr_t
    silicon_one::la_ipv4_addr_t to_v4() const;

    /// @brief get IPv6 address
    ///
    /// @retval IPv6 address la_ipv6_addr_t
    silicon_one::la_ipv6_addr_t to_v6() const;

    la_ip_addr& operator=(const la_ip_addr&) = default;
    friend bool operator==(const la_ip_addr& lhs, const la_ip_addr& rhs);

private:
    /// address version
    enum class version_e {
        UNSPECIFIED,
        V4,
        V6,
    };

    /// member attributes
    la_ipv4_addr_t m_v4_address;

    la_ipv6_addr_t m_v6_address;

    version_e m_ip_version;
};

} // namespace silicon_one

#endif // __LA_IP_ADDR_H__
