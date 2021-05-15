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

#include "ipv4_sip_index_manager.h"
#include "api/npu/la_vrf.h"
#include "common/logger.h"
#include "la_strings.h"
#include "nplapi/npl_constants.h"
#include "nplapi/nplapi_tables.h"
#include "system/la_device_impl.h"

#include <sstream>
#include <tuple>

namespace silicon_one
{

ipv4_sip_index_manager::ipv4_sip_index_manager(const la_device_impl_wptr& device) : m_device(device)
{
}

const la_device_impl_wptr&
ipv4_sip_index_manager::get_device() const
{
    return m_device;
}

la_status
ipv4_sip_index_manager::allocate_sip_index(la_ipv4_prefix_t local_ip, ipv4_sip_index_profile_t& sip_index_profile)
{
    la_status status;
    npl_sip_index_table_key_t k;
    npl_sip_index_table_value_t v;
    npl_sip_index_table_entry_t* e;

    status = m_device->m_profile_allocators.ipv4_sip_index->reallocate(sip_index_profile, local_ip);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "failed to allocte sip index, status=%s", la_status2str(status).c_str());
        return status;
    }

    if (sip_index_profile.use_count() == 1) {
        k.sip_index = sip_index_profile->id();
        v.action = NPL_SIP_INDEX_TABLE_ACTION_WRITE;
        v.payloads.sip = local_ip.addr.s_addr;

        status = m_device->m_tables.sip_index_table->insert(k, v, e);
        if (status != LA_STATUS_SUCCESS) {
            sip_index_profile.reset();
            log_err(HLD, "sip_index_table insertion failed, status=%s", la_status2str(status).c_str());
            return status;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
ipv4_sip_index_manager::free_sip_index(ipv4_sip_index_profile_t& sip_index_profile)
{
    if (sip_index_profile.use_count() == 1) {
        // no one is using the local ip address. Delete it
        npl_sip_index_table_key_t k;

        k.sip_index = sip_index_profile->id();
        la_status status = m_device->m_tables.sip_index_table->erase(k);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "sip_index_table erase failed, status=%s", la_status2str(status).c_str());
            return status;
        }
    }
    sip_index_profile.reset();

    return LA_STATUS_SUCCESS;
}
}
