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

#include "la_voq_set_base.h"

#include "system/la_device_impl.h"
#include "tm/voq_counter_set.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/stopwatch.h"
#include "common/transaction.h"
#include "hld_types.h"
#include "hld_utils.h"
#include "system/slice_id_manager_base.h"

namespace silicon_one
{

la_voq_set_base::la_voq_set_base(const la_device_impl_wptr& device)
    : m_device(device),
      m_oid(LA_OBJECT_ID_INVALID),
      m_base_voq((la_voq_gid_t)-1),
      m_set_size((size_t)-1),
      m_dest_device((la_device_id_t)-1),
      m_dest_slice((la_slice_id_t)-1),
      m_dest_ifg((la_ifg_id_t)-1)
{
}

la_voq_set_base::~la_voq_set_base()
{
}

la_object_id_t
la_voq_set_base::oid() const
{
    return m_oid;
}

const la_device*
la_voq_set_base::get_device() const
{
    return m_device.get();
}

la_device_id_t
la_voq_set_base::get_destination_device() const
{
    return m_dest_device;
}

la_slice_id_t
la_voq_set_base::get_destination_slice() const
{
    return m_dest_slice;
}

la_ifg_id_t
la_voq_set_base::get_destination_ifg() const
{
    return m_dest_ifg;
}

la_voq_gid_t
la_voq_set_base::get_base_voq_id() const
{
    return m_base_voq;
}

size_t
la_voq_set_base::get_set_size() const
{
    return m_set_size;
}
} // namespace silicon_one
