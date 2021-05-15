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

#ifndef __CTM_CONFIG_H__
#define __CTM_CONFIG_H__

#include "common/la_status.h"
#include "ctm_common.h"
#include "ctm_config_group.h"
#include "ctm_sram_allocator.h"
#include "lld/lld_fwd.h"

#include <boost/variant.hpp>
#include <map>
#include <stddef.h>
#include <vector>

namespace silicon_one
{

/// @brief Static configuration of CDB Central Tcam.
///
class ctm_config
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // C'tor
    ctm_config(const ll_device_sptr& ldevice, size_t number_of_slices);

    // D'tor
    virtual ~ctm_config() = default;

    /// @brief Write Database configuration to the device.
    ///
    /// @retval     status code.
    virtual la_status configure_hw() = 0;
    virtual size_t get_max_group_scale(const ctm::group_desc& group) const = 0;

protected:
    using groups_vec = vector_alloc<ctm_config_group>;

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    ctm_config() = default;

    // Members
    ll_device_sptr m_ll_device;

    size_t m_num_of_slices;
};

} // namespace silicon_one

#endif // __CTM_CONFIG_H__
