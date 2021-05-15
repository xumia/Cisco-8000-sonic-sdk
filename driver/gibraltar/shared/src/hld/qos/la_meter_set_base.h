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

#ifndef __LA_METER_SET_BASE_H__
#define __LA_METER_SET_BASE_H__

#include "api/qos/la_meter_set.h"
#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_system_types.h"
#include "common/defines.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"
namespace silicon_one
{

class la_meter_set_base : public la_meter_set
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    la_meter_set_base() = default;
    virtual ~la_meter_set_base();

protected:
    slice_manager_smart_ptr m_slice_id_manager;

    // Meter profile allocation per slice_ifg
    ifg_use_count_uptr m_ifg_use_count;

}; // class la_meter_set

} // namespace silicon_one

#endif // __LA_METER_SET_BASE_H__
