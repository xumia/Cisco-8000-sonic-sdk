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

#ifndef __LA_ACL_SCALED_H__
#define __LA_ACL_SCALED_H__

#include "api/npu/la_acl.h"

/// @file
/// @brief Leaba Scaled ACL API-s.
///
/// Defines API-s for configuring Scaled Access Control Lists.

/// @addtogroup ACL
/// @{

namespace silicon_one
{

/// @brief Scaled Access Control List.
///
/// @details Scaled Access Control List is an ordered list of Access Control Entries.\n
///          Each entry defines a match rule and an action to perform on the packet if that rule is matched.
///          Scaling is achieved using two stage search - first create a compressed key using a predefined fields (e.g. SIP, DIP),
///          then using the compressed key during ACE lookup.

class la_acl_scaled : public la_acl
{
public:
    /// @brief Scale field.
    enum class scale_field_e {
        UNDEF = 0, ///< Undefined scale field.
        SIP,       ///< SIP scale field.
        DIP,       ///< DIP scale field.
        LAST,
    };

    using la_acl::get_count;
    using la_acl::append;
    using la_acl::insert;
    using la_acl::set;
    using la_acl::erase;
    using la_acl::get;

    /// @brief Get scale field count in the ACL.
    ///
    /// @param[in]  scale_field         Scale field list to query.
    /// @param[out] out_count           Scale field list count.
    ///
    /// @retval     LA_STATUS_SUCCESS   Key retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_count(scale_field_e scale_field, size_t& out_count) const = 0;

    /// @brief Add scale field entry to the end of the scale field list of the ACL.
    ///
    /// @param[in]  scale_field         Scale field list to manipulate.
    /// @param[in]  sf_key              Scale field key value to set.
    /// @param[in]  sf_val              Scale field value to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   ACL modified successfully.
    /// @retval     LA_STATUS_EINVAL    Either key or command are invalid.
    /// @retval     LA_STATUS_ERESOURCE No resources for appending an ACE.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status append(scale_field_e scale_field, const la_acl_scale_field_key& sf_key, const la_acl_scale_field_val& sf_val)
        = 0;

    /// @brief Add scale field entry to the scale field list of the ACL at a specified position.
    ///
    /// @param[in]  scale_field         Scale field list to manipulate.
    /// @param[in]  position            Scale field entry index. If it's greater than scale field current size, it will be appended.
    /// @param[in]  sf_key              Scale field key value to set.
    /// @param[in]  sf_val              Scale field value to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   ACL modified successfully.
    /// @retval     LA_STATUS_EINVAL    Either key or command are invalid.
    /// @retval     LA_STATUS_ERESOURCE No resources for inserting an ACE.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status insert(scale_field_e scale_field,
                             size_t position,
                             const la_acl_scale_field_key& sf_key,
                             const la_acl_scale_field_val& sf_val)
        = 0;

    /// @brief Update scale field entry of a scale field list of the ACL at a specified position.
    ///
    /// @param[in]  scale_field         Scale field list to manipulate.
    /// @param[in]  position            Scale field entry index.
    /// @param[in]  sf_key              Scale field key value to set.
    /// @param[in]  sf_val              Scale field value to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   ACL modified successfully.
    /// @retval     LA_STATUS_EINVAL    Either key or command are invalid.
    /// @retval     LA_STATUS_ENOTFOUND No ACE at a given position.
    /// @retval     LA_STATUS_ERESOURCE No resources to update the ACE.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set(scale_field_e scale_field,
                          size_t position,
                          const la_acl_scale_field_key& sf_key,
                          const la_acl_scale_field_val& sf_val)
        = 0;

    /// @brief Erase scale field entry from a specific location in the scale field list.
    ///
    /// @param[in]  scale_field         Scale field list to manipulate.
    /// @param[in]  position            Scale field entry index in the list.
    ///
    /// @retval     LA_STATUS_SUCCESS   ACE successfully removed.
    /// @retval     LA_STATUS_EINVAL    Position is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No ACE at a given position.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status erase(scale_field_e scale_field, size_t position) = 0;

    /// @brief Retrieve scale field entry from scale field list's specific position.
    ///
    /// @param[in]  scale_field         Scale field list to query.
    /// @param[in]  position            Scale field entry index in the list.
    /// @param[out] out_sf_key          Scale field key value to populate.
    /// @param[out] out_sf_val          Scale field value to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   ACE found successfully.
    /// @retval     LA_STATUS_EINVAL    Position is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No ACE at a given position.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get(scale_field_e scale_field,
                          size_t position,
                          const la_acl_scale_field_key*& out_sf_key,
                          const la_acl_scale_field_val*& out_sf_val) const = 0;

protected:
    ~la_acl_scaled() override = default;
};

} // namespace silicon_one

/// @}
#endif // __LA_ACL_SCALED_H__
