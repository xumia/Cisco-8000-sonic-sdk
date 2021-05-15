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

#ifndef __LA_PCL_H__
#define __LA_PCL_H__

#include "api/types/la_ip_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief Leaba PCL API-s.
///
/// Defines API-s for configuring Prefix Compression Lists.

/// @addtogroup PCL
/// @{

namespace silicon_one
{

/// @brief Prefix Compression List.
///
/// @details Prefix Compression List is a list of (prefix, bincode) pairs.
///          This object is used in conjunction with an Object Group ACL.

class la_pcl : public la_object
{
public:
    /// @brief PCL type.
    enum class pcl_type_e {
        IPV4 = 0, ///< IPV4 PCL
        IPV6,     ///< IPV6 PCL
        LAST,
    };

    /// @brief Get PCL type.
    ///
    /// @param[out] out_type            PCL type.
    ///
    /// @retval     LA_STATUS_SUCCESS   Type retrieved successfully.
    virtual la_status get_type(pcl_type_e& out_type) const = 0;

    /// @brief Get PCL feature attached to type.
    ///
    /// @param[out] out_feature          Feature type the PCL is attached too.
    ///
    /// @retval     LA_STATUS_SUCCESS    Type retrieved successfully.
    virtual la_status get_feature(pcl_feature_type_e& out_feature) const = 0;

    /// @brief Get PCL ID.
    ///
    /// @param[out] out_pcl_gid            PCL ID.
    ///
    /// @retval     LA_STATUS_SUCCESS   Type retrieved successfully.
    virtual la_status get_pcl_gid(la_pcl_gid_t& out_pcl_gid) const = 0;

    /// @brief Get Prefixes.
    ///
    /// @param[out] out_prefixes          Vector of IPV4 Prefixes
    ///
    /// @retval     LA_STATUS_SUCCESS   Type retrieved successfully.
    virtual la_status get_prefixes(la_pcl_v4_vec_t& out_prefixes) const = 0;

    /// @brief Get Prefixes.
    ///
    /// @param[out] out_prefixes          Vector of IPV6 Prefixes
    ///
    /// @retval     LA_STATUS_SUCCESS   Type retrieved successfully.
    virtual la_status get_prefixes(la_pcl_v6_vec_t& out_prefixes) const = 0;

    /// @brief Add prefixes to a Prefix Compression List.
    ///
    /// @param[in]  prefixes                  Vector of IPV4 prefix compression entries
    ///
    /// @retval     LA_STATUS_SUCCESS         PCL updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EINVAL          Invalid parameter was passed.
    virtual la_status add_prefixes(const la_pcl_v4_vec_t& prefixes) = 0;

    /// @brief Add prefixes to a Prefix Compression List.
    ///
    /// @param[in]  prefixes                  Vector of IPV6 prefix compression entries
    ///
    /// @retval     LA_STATUS_SUCCESS         PCL updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EINVAL          Invalid parameter was passed.
    virtual la_status add_prefixes(const la_pcl_v6_vec_t& prefixes) = 0;

    /// @brief Remove prefixes from a Prefix Compression List.
    ///
    /// @param[in]  prefixes                  Vector of IPV4 prefix compression entries
    ///
    /// @retval     LA_STATUS_SUCCESS         PCL updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EINVAL          Invalid parameter was passed.
    virtual la_status remove_prefixes(const la_pcl_v4_vec_t& prefixes) = 0;

    /// @brief Remove prefixes from a Prefix Compression List.
    ///
    /// @param[in]  prefixes                  Vector of IPV6 prefix compression entries
    ///
    /// @retval     LA_STATUS_SUCCESS         PCL updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EINVAL          Invalid parameter was passed.
    virtual la_status remove_prefixes(const la_pcl_v6_vec_t& prefixes) = 0;

    /// @brief Replace all prefixes in a Prefix Compression List.
    ///
    /// @param[in]  prefixes                  Vector of IPV4 prefix compression entries
    ///
    /// @retval     LA_STATUS_SUCCESS         PCL updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EINVAL          Invalid parameter was passed.
    virtual la_status replace_prefixes(const la_pcl_v4_vec_t& prefixes) = 0;

    /// @brief Replace all the prefixes in a Prefix Compression List.
    ///
    /// @param[in]  prefixes                  Vector of IPV6 prefix compression entries
    ///
    /// @retval     LA_STATUS_SUCCESS         PCL updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EINVAL          Invalid parameter was passed.
    virtual la_status replace_prefixes(const la_pcl_v6_vec_t& prefixes) = 0;

    /// @brief Update prefixes in a Prefix Compression List.
    ///
    /// @param[in]  prefixes                  Vector of IPV4 prefix compression entries
    ///
    /// @retval     LA_STATUS_SUCCESS         PCL updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EINVAL          Invalid parameter was passed.
    virtual la_status modify_prefixes(const la_pcl_v4_vec_t& prefixes) = 0;

    /// @brief Update prefixes in a Prefix Compression List.
    ///
    /// @param[in]  prefixes                  Vector of IPV6 prefix compression entries
    ///
    /// @retval     LA_STATUS_SUCCESS         PCL updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    /// @retval     LA_STATUS_EINVAL          Invalid parameter was passed.
    virtual la_status modify_prefixes(const la_pcl_v6_vec_t& prefixes) = 0;

protected:
    ~la_pcl() override = default;
};

} // namespace silicon_one

/// @}
#endif // __LA_PCL_H__
