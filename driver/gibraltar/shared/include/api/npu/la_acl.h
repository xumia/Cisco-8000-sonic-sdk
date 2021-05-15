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

#ifndef __LA_ACL_H__
#define __LA_ACL_H__

#include "api/npu/la_acl_command_profile.h"
#include "api/npu/la_acl_key_profile.h"
#include "api/types/la_acl_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief Leaba ACL API-s.
///
/// Defines API-s for configuring Access Control Lists.

/// @addtogroup ACL
/// @{

namespace silicon_one
{

/// @brief Access Control List.
///
/// @details Access Control List is an ordered list of Access Control Entries.\n
///          Each entry defines a match rule and an action to perform on the packet if that rule is matched.

class la_acl : public la_object
{
public:
    /// @brief Stage at which ACL is configured.
    enum class stage_e {
        INGRESS_TERM = 0,   ///< Ingress Termination stage ACL.
        INGRESS_FWD,        ///< Ingress Forwarding stage ACL.
        SECOND_INGRESS_FWD, ///< Second Ingress Forwarding stage ACL.
        EGRESS,             ///< Egress ACL.
        LAST,
    };

    /// @brief ACL type.
    enum class type_e {
        QOS = 0, ///< QoS ACL.
        UNIFIED, ///< Unified ACL (Security and QoS).
        PBR,     ///< PBR ACL.
        SGACL,   ///< Security Group ACL.
        LAST,
    };

    /// @brief ACL range type.
    /// Used for range compression of keys with ranges.
    enum class range_type_e {
        VLAN = 0,    ///< VLAN ID range.
        L4_SRC_PORT, ///< Layer 4 source port range.
        L4_DST_PORT, ///< Layer 4 destination port range.
    };

    /// @brief Get ACL type.
    ///
    /// @param[out] out_type            ACL type.
    ///
    /// @retval     LA_STATUS_SUCCESS   Type retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_type(type_e& out_type) const = 0;

    /// @brief Get ACL key profile.
    ///
    /// @param[out] out_acl_key_profile     ACL key profile.
    ///
    /// @retval     LA_STATUS_SUCCESS   ACL key profile retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_acl_key_profile(const la_acl_key_profile*& out_acl_key_profile) const = 0;

    /// @brief Get ACL command profile.
    ///
    /// @param[out] out_acl_command_profile     ACL command profile.
    ///
    /// @retval     LA_STATUS_SUCCESS   ACL command profile retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_acl_command_profile(const la_acl_command_profile*& out_acl_command_profile) const = 0;

    /// @brief Get ACE count in the ACL.
    ///
    /// @param[out] out_count           ACE count.
    ///
    /// @retval     LA_STATUS_SUCCESS   Key retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_count(size_t& out_count) const = 0;

    /// @brief Create and add an ACE to the end of the ACL.
    ///
    /// @param[in]  key                 ACL key value to set.
    /// @param[in]  cmd                 ACL command actions to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   ACL modified successfully.
    /// @retval     LA_STATUS_EINVAL    Either key or command are invalid.
    /// @retval     LA_STATUS_ERESOURCE No resources for appending an ACE.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status append(const la_acl_key& key, const la_acl_command_actions& cmd) = 0;

    /// @brief Add an ACE to an ACL at a specified position.
    ///
    /// @param[in]  position    ACE index in the ACL. If it's greater than ACL size, then it will be appended.
    /// @param[in]  key         ACL key value to set.
    /// @param[in]  cmd         ACL command actions to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   ACL modified successfully.
    /// @retval     LA_STATUS_EINVAL    Either key or command are invalid.
    /// @retval     LA_STATUS_ERESOURCE No resources for inserting an ACE.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status insert(size_t position, const la_acl_key& key, const la_acl_command_actions& cmd) = 0;

    /// @brief Update an ACE of an ACL at a specified position.
    ///
    /// @param[in]  position    ACE index in the ACL.
    /// @param[in]  key         ACL key value to set.
    /// @param[in]  cmd         ACL command to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   ACL modified successfully.
    /// @retval     LA_STATUS_EINVAL    Either key or command are invalid.
    /// @retval     LA_STATUS_ENOTFOUND No ACE at a given position.
    /// @retval     LA_STATUS_ERESOURCE No resources to update the ACE.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set(size_t position, const la_acl_key& key, const la_acl_command_actions& cmd) = 0;

    /// @brief Erase an ACE at a specific location from the ACL.
    ///
    /// @param[in]  position            The position of the ACE in the ACL.
    ///
    /// @retval     LA_STATUS_SUCCESS   ACE successfully removed.
    /// @retval     LA_STATUS_EINVAL    Position is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No ACE at a given position.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status erase(size_t position) = 0;

    /// @brief Delete all ACE's from the ACL.
    ///
    /// @retval     LA_STATUS_SUCCESS   All ACEs successfully removed.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear() = 0;

    /// @brief Retrieve an ACE from ACL's specific position.
    ///
    /// @param[in]  position            The position of the ACE in the ACL.
    /// @param[out] out_acl_entry_desc  ACE descriptor to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   ACE found successfully.
    /// @retval     LA_STATUS_EINVAL    Position is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No ACE at a given position.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get(size_t position, acl_entry_desc& out_acl_entry_desc) const = 0;

    ///@brief Calclute the maximum number of lines that can be inserted successfully,
    /// in the current system state.
    ///
    ///@param[out] out_available_space number of lines that can be successfully inserted.
    ///@retval     LA_STATUS_SUCCESS The value returned is valid.
    virtual la_status get_max_available_space(size_t& out_available_space) const = 0;

protected:
    ~la_acl() override = default;
};

} // namespace silicon_one

/// @}
#endif // __LA_ACL_H__
