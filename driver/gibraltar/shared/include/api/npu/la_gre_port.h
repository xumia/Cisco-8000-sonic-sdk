// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_GRE_PORT_H__
#define __LA_GRE_PORT_H__

#include "api/npu/la_ip_tunnel_port.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_tunnel_types.h"

namespace silicon_one
{

/// @file
/// @brief Leaba GRE Port API-s.
///
/// Defines API-s for managing GRE port object.

class la_gre_port : public la_ip_tunnel_port
{

public:
    enum class tunnel_termination_type_e {
        P2P = 0, ///< Both source IP and destination IP are used to match tunnel termination.
        P2MP     ///< Only destination IP is used to match tunnel termination.
    };
    /// @addtogroup L3PORT_GRE
    /// @{

    /// GRE DIP entropy mode.
    enum class la_gre_dip_entropy_mode_e {
        GRE_DIP_ENTROPY_NONE, ///< DIP entropy disabled (32-bit DIP).
        GRE_DIP_ENTROPY_24,   ///< 8-bit DIP entropy (24-bit DIP).
        GRE_DIP_ENTROPY_28    ///< 4-bit DIP entropy (28-bit DIP).
    };

    /// @brief Get key for this port.
    ///
    /// @return    The key associated with this port.
    virtual la_gre_key_t get_key() const = 0;

    /// @brief Set key for this port.
    ///
    /// @param[in]  key                          Key value.
    ///
    /// @retval     LA_STATUS_SUCCESS            Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN           An unknown error occurred.
    virtual la_status set_key(la_gre_key_t key) = 0;

    /// @brief Get sequence number for this port.
    ///
    /// @return    The sequence number associated with this port.
    virtual la_gre_seq_num_t get_sequence_number() const = 0;

    /// @brief Set sequence number for this port.
    ///
    /// @param[in]  sequence_number              sequence number value
    ///
    /// @retval     LA_STATUS_SUCCESS            Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN           An unknown error occurred.
    virtual la_status set_sequence_number(la_gre_seq_num_t sequence_number) = 0;

    /// @brief Set tunnel termination type.
    ///
    /// Default tunnel termination type is #silicon_one::la_gre_port::tunnel_termination_type_e::P2P.
    ///
    /// @param[in]  tunnel_termination_type  Tunnel termination type.
    ///
    /// @retval     LA_STATUS_SUCCESS        Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN       An unknown error occurred.
    virtual la_status set_tunnel_termination_type(tunnel_termination_type_e tunnel_termination_type) = 0;

    /// @brief Retrieve tunnel termination type.
    ///
    /// @param[out] out_term_type Tunnel termination type.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_tunnel_termination_type(tunnel_termination_type_e& out_term_type) const = 0;

    /// @brief Get DIP entropy mode for this port.
    ///
    /// @return    The DIP entropy mode associated with this port.
    virtual la_gre_dip_entropy_mode_e get_dip_entropy_mode() const = 0;

    /// @brief Get local IPv4 prefix for this port.
    ///
    /// @param[out] local_ip_prefix              Local prefix associated with the GRE port.
    ///
    /// @retval     LA_STATUS_SUCCESS            Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN           An unknown error occurred.
    virtual la_status get_local_ip_prefix(la_ipv4_prefix_t& local_ip_prefix) const = 0;

    /// @brief Set local IPv4 prefix for this port.
    ///
    /// @param[in]  local_ip_prefix              Local prefix associated with the GRE port.
    ///
    /// @retval     LA_STATUS_SUCCESS            Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL             Invalid address specified.
    /// @retval     LA_STATUS_EUNKNOWN           An unknown error occurred.
    virtual la_status set_local_ip_prefix(const la_ipv4_prefix_t local_ip_prefix) = 0;

    /// @brief Get remote IPv4 prefix for this port.
    ///
    /// @param[out] remote_ip_prefix             Remote prefix associated with the GRE port.
    ///
    /// @retval     LA_STATUS_SUCCESS            Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN           An unknown error occurred.
    virtual la_status get_remote_ip_prefix(la_ipv4_prefix_t& remote_ip_prefix) const = 0;

    /// @brief Set remote IPv4 address for this port.
    ///
    /// If remote mask length is less than 32 bits, an entropy is applied
    /// on the DIP of the encap packet. Else, there is no entropy applied.
    ///
    /// @param[in]  remote_ip_prefix             Remote prefix associated with the GRE port.
    ///
    /// @retval     LA_STATUS_SUCCESS            Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL             Invalid address specified.
    /// @retval     LA_STATUS_EUNKNOWN           An unknown error occurred.
    virtual la_status set_remote_ip_prefix(const la_ipv4_prefix_t remote_ip_prefix) = 0;

    /// @brief Set local and remote IPv4 address for this port.
    ///
    /// If remote mask length is less than 32 bits, an entropy is applied
    /// on the DIP of the encap packet. Else, there is no entropy applied.
    ///
    /// @param[in]  local_ip_prefix              Local prefix associated with the GRE port.
    /// @param[in]  remote_ip_prefix             Remote prefix associated with the GRE port.
    ///
    /// @retval     LA_STATUS_SUCCESS            Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL             Invalid address specified.
    /// @retval     LA_STATUS_EUNKNOWN           An unknown error occurred.
    /// @retval     LA_STATUS_EEXIST             A tunnel with same local and remote IPV4 prefix already exists
    virtual la_status set_local_and_remote_ip_prefix(const la_ipv4_prefix_t local_ip_prefix,
                                                     const la_ipv4_prefix_t remote_ip_prefix)
        = 0;

protected:
    ~la_gre_port() override = default;
    /// @}
};

} // namepace leaba

#endif // __LA_GRE_PORT_H__
