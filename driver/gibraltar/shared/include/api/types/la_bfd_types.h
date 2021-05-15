// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_BFD_TYPES_H__
#define __LA_BFD_TYPES_H__

#include "api/types/la_common_types.h"

/// @addtogroup BFD
/// @{

namespace silicon_one
{

/// @file
/// @brief BFD definitions.
///
/// Defines BFD related types used by the Leaba API.

class la_bfd_session;

/// BFD local or remote discriminator
enum class la_bfd_discriminator : uint32_t;

/// @brief BFD state field
enum class la_bfd_state_e : uint8_t {
    ADMIN_DOWN, ///< Administratively Down state.
    DOWN,       ///< Down state.
    INIT,       ///< Init state
    UP,         ///< Up state.
};

/// @brief BFD diagnostic code field
enum class la_bfd_diagnostic_code_e : uint8_t {
    NO_DIAGNOSTIC,                   ///< No Diagnostic.
    CONTROL_TIME_EXPIRED,            ///< Control Detection Time Expired.
    ECHO_FUNCTION_FAILED,            ///< Echo Function Failed.
    NEIGHBOR_SIGNALED_SESSION_DOWN,  ///< Neighbor Signaled Session Down.
    FORWARDING_PLANE_RESET,          ///< Forwarding Plane Reset.
    PATH_DOWN,                       ///< Path Down.
    CONCATENATED_PATH_DOWN,          ///< Concatenated Path Down.
    ADMINISTRATIVELY_DOWN,           ///< Administratively Down.
    REVERSE_CONCATENTATED_PATH_DOWN, ///< Reverse Concatenated Path Down.
};

/// @brief BFD flags field, including state
union la_bfd_flags {
    struct bfd_flags_fields {
        uint8_t multipoint : 1;                ///< Multipoint (M)
        uint8_t demand : 1;                    ///< Demand (D)
        uint8_t authentication_present : 1;    ///< Authentication Present (A)
        uint8_t control_plane_independent : 1; ///< Control Plane Independent (C)
        uint8_t final : 1;                     ///< Final (F)
        uint8_t poll : 1;                      ///< Poll (P)
        uint8_t state : 2;                     ///< silicon_one::la_bfd_state_e
    } fields;

    uint8_t flat; ///< Flattend flags and state.
};

} // namespace silicon_one

/// @}

#endif // __LA_BFD_TYPES_H__
