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

#include "npu/la_forus_destination_impl.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"

#include "nplapi/npl_constants.h"

#include "api_tracer.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_forus_destination_impl::la_forus_destination_impl(const la_device_impl_wptr& device) : m_device(device)
{
}

la_forus_destination_impl::~la_forus_destination_impl()
{
}

la_status
la_forus_destination_impl::initialize(la_object_id_t oid)
{
    m_oid = oid;
    m_bincode = 0;
    // Update object dependencies
    return LA_STATUS_SUCCESS;
}

la_status
la_forus_destination_impl::initialize(la_object_id_t oid, la_uint_t bincode)
{
    m_oid = oid;
    m_bincode = bincode & 0x1fff;
    // Update object dependencies
    return LA_STATUS_SUCCESS;
}

la_status
la_forus_destination_impl::destroy()
{
    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_forus_destination_impl::type() const
{
    return object_type_e::FORUS_DESTINATION;
}

const la_device*
la_forus_destination_impl::get_device() const
{
    return m_device.get();
}

std::string
la_forus_destination_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_forus_destination_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_forus_destination_impl::oid() const
{
    return m_oid;
}

lpm_destination_id
la_forus_destination_impl::get_lpm_destination_id(resolution_step_e prev_step) const
{
    // NPL looks at bit 0 of the destination to process LPTS
    return lpm_destination_id(NPL_LPM_COMPRESSED_DESTINATION_LPTS_MASK | (1 << 0) | (m_bincode << 1));
}

la_uint_t
la_forus_destination_impl::get_bincode() const
{
    start_api_getter_call();
    return m_bincode;
}
}
