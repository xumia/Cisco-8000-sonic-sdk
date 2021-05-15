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

#ifndef __LA_MIRROR_COMMAND_H__
#define __LA_MIRROR_COMMAND_H__

/// @file
/// @brief Leaba Mirror command API-s.
///
/// Mirror command is an abstract class for mirror command classes.
///

#include "api/types/la_object.h"

/// @addtogroup PACKET
/// @{

namespace silicon_one
{

/// @brief Mirror command base class.
///
/// @details Mirror command serves as a base class for mirror commands classes and used to snoop/mirror traffic.
class la_mirror_command : public la_object
{
public:
    /// @brief Get mirror command's Global ID.
    ///
    /// @return Global ID of mirror command.
    virtual la_mirror_gid_t get_gid() const = 0;

    /// @brief Set sampling probability.
    ///
    /// @param[in]  probability         Sampling probability.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_probability(double probability) = 0;

    /// @brief Get sampling probability.
    ///
    /// @param[out] out_probability        Probability to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_probability(double& out_probability) const = 0;

    /// @brief Set the offset from base VOQ used for this mirror command.
    ///
    /// @param[in]  voq_offset          Offset from base VOQ for TC mapping.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    offset is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_voq_offset(la_uint_t voq_offset) = 0;

    /// @brief Return the offset from base VOQ used by this mirror command.
    ///
    /// @return Offset from base VOQ for TC mapping.
    virtual la_uint_t get_voq_offset() const = 0;

protected:
    ~la_mirror_command() override = default;
};
}

/// @}

#endif // __LA_MIRROR_COMMAND_H__
