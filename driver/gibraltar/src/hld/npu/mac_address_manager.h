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

#ifndef _MAC_ADDRESS_MANAGER_H_
#define _MAC_ADDRESS_MANAGER_H_

#include <stdint.h>
#include <vector>

#include "api/types/la_ethernet_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

///
/// Manages the use of internal MAC addresses, which are a limited resource in the device.
/// Internal MAC addresses are those of internal objects, e.g. SVI port.
/// The device uses a compression scheme for such MAC addresses, in which the NUM_OF_MSB_BITS msb bits
/// are replaced by an index of NUM_OF_PREFIX_BITS bits. The number of available indices
/// is smaller the number of possible prefixes, so the use of MAC addresses need to be
/// controled.
///

namespace silicon_one
{

class mac_address_manager
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    mac_address_manager() = default;
    //////////////////////////////

public:
    explicit mac_address_manager(const la_device_impl_wptr& device);
    ~mac_address_manager() = default;

    /// Size of a MAC address
    static const uint64_t NUM_OF_MAC_ADDR_BITS = 48;

    /// Size of the lsb part in bits
    static const uint64_t NUM_OF_LSB_BITS = 16; // TODO In GB and AKPG it's 19 actually. Need to fix if scale is important.

    /// Size of the msb part in bits
    static const uint64_t NUM_OF_MSB_BITS = NUM_OF_MAC_ADDR_BITS - NUM_OF_LSB_BITS;

    /// Size of index in bits
    static const uint64_t NUM_OF_PREFIX_BITS = 4;

    /// Number of allowed indices
    static const uint64_t NUM_OF_ALLOWED_PREFIXES = (1 << NUM_OF_PREFIX_BITS);

    /// @brief Initialize the mac_address_manager, and static entries in controlled tables.
    ///
    /// @retval     LA_STATUS_SUCCESS    Initialization completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN   An unknown error occurred.
    la_status initialize();

    /// @brief Calculate the lsb part of the given address
    ///
    /// @param[in]  mac_addr  The MAC address
    ///
    /// @retval     The lsb part of the given address
    static uint64_t get_lsbits(la_mac_addr_t mac_addr);

    /// @brief Calculate the msb part of the given address
    ///
    /// @param[in]  mac_addr
    ///
    /// @retval     The msb part of the given address
    static uint64_t get_msbits(la_mac_addr_t mac_addr);

    /// @brief Calculate the index of the given address
    ///
    /// @param[in]  mac_addr
    /// @param[out] out_prefix          Holds the index of the given address on success
    ///
    /// @retval    LA_STATUS_SUCCESS    Operation completed successfuly
    /// @retval    LA_STATUS_ENOTFOUND  The given address is not enabled in the device
    la_status get_index(la_mac_addr_t mac_addr, uint64_t& out_index) const;

    /// @brief Enable the given MAC address for use in the device
    ///
    /// @param[in]  mac_addr                 The MAC addresa
    /// @param[in]  type                     The MAC DA type
    ///
    ///@retval      LA_STATUS_SUCCESS        Operation completed successfully. out_index contains the address' index
    ///@retval      LA_STATUS_ERESOURCE      All avaliable indices are in use. User should use a MAC address with an already used
    /// index
    la_status add(la_mac_addr_t mac_addr, npl_mac_da_type_e type);

    /// @brief Mark the given MAC address as not-used
    ///
    /// @param[in]  mac_addr              The MAC address
    /// @param[in[  type                  The MAC DA type
    ///
    ///@retval      LA_STATUS_SUCCESS     Operation completed successfully
    ///@retval      LA_STATUS_ENOTFOUND   The given address is not registered
    la_status remove(la_mac_addr_t mac_addr, npl_mac_da_type_e type);

    /// @brief Calculate the 'prefix' value that serves in several tables.
    ///
    /// @param[in]  mac_addr              The MAC address
    /// @param[out] out_prefix            Holds the prefix on success
    ///
    ///@retval      LA_STATUS_SUCCESS     Operation completed successfully
    ///@retval      LA_STATUS_ENOTFOUND   The given address is not registered
    la_status get_prefix(la_mac_addr_t mac_addr, uint64_t& out_prefix) const;

private:
    /// The creating device
    la_device_impl_wptr m_device;

    /// All the msb's of the compressed addresses.
    std::vector<uint64_t> m_msbs;

    /// Refcount of the indices in use
    std::vector<uint64_t> m_msbs_refcount;

    /// Index of first managed prefix. Lower indices are used for static prefixes.
    size_t m_first_dynamic_prefix_index;

private:
    /// Manage the device tables
    la_status add_to_sa_prefix_table(la_mac_addr_t mac_addr, uint64_t index);
    la_status add_to_mac_da_table(la_mac_addr_t mac_addr, uint64_t index, npl_mac_da_type_e type);
    la_status remove_from_sa_prefix_table(la_mac_addr_t mac_addr, uint64_t index);
    la_status remove_from_mac_da_table(la_mac_addr_t mac_addr, uint64_t index);
};

} // namespace silicon_one

#endif // _MAC_ADDRESS_MANAGER_H_
