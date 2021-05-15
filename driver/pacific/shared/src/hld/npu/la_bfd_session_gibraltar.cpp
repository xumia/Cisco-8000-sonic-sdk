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

#include "la_bfd_session_gibraltar.h"
#include "lld/gibraltar_tree.h"

#include <sstream>

namespace silicon_one
{

la_bfd_session_gibraltar::la_bfd_session_gibraltar(const la_device_impl_wptr& device) : la_bfd_session_base(device)
{
}

la_bfd_session_gibraltar::~la_bfd_session_gibraltar()
{
}

la_status
la_bfd_session_gibraltar::set_npu_host_interval_mapping(uint64_t entry, uint64_t value)
{
    la_status status;
    auto& lld = m_device->m_ll_device;
    auto& npuh = lld->get_gibraltar_tree()->npuh;

    status = lld->write_memory(npuh->host->interval_mapping, entry, value);
    return status;
}

la_status
la_bfd_session_gibraltar::set_npu_host_max_ccm_counter(uint64_t entry, uint64_t value)
{
    la_status status;
    auto& lld = m_device->m_ll_device;
    auto& npuh = lld->get_gibraltar_tree()->npuh;

    status = lld->write_memory(npuh->host->max_ccm_counter, entry, value);
    return status;
}

} // namespace silicon_one
