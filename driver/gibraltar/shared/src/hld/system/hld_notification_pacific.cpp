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

#include "system/hld_notification_pacific.h"
#include "api/types/la_common_types.h"
#include "api/types/la_notification_types.h"
#include "api_tracer.h"
#include "common/device_id.h"
#include "common/file_utils.h"
#include "common/gen_utils.h"
#include "common/pipe.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "lld/device_mem_structs.h"
#include "lld/device_reg_structs.h"
#include "lld/device_tree.h"
#include "lld/leaba_kernel_types.h"
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_base.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_output_queue_scheduler_impl.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>

using namespace std;

namespace silicon_one
{

hld_notification_pacific::hld_notification_pacific(const la_device_impl_wptr& la_device) : hld_notification_base(la_device)
{
}

hld_notification_pacific::~hld_notification_pacific()
{
    stop();
}

la_status
hld_notification_pacific::initialize()
{
    auto tree = m_device->m_ll_device->get_pacific_tree();

    for (la_slice_ifg ifg_i : m_device->get_slice_id_manager()->get_all_possible_ifgs()) {
        const auto& ifg = tree->slice[ifg_i.slice]->ifg[ifg_i.ifg];

        m_mac_pool_serdes_bases[ifg->mac_pool8[0]->get_block_id()]
            = mac_pool_serdes_base{.slice_i = ifg_i.slice, .ifg_i = ifg_i.ifg, .serdes_base = 0};

        m_mac_pool_serdes_bases[ifg->mac_pool8[1]->get_block_id()]
            = mac_pool_serdes_base{.slice_i = ifg_i.slice, .ifg_i = ifg_i.ifg, .serdes_base = 8};

        m_mac_pool_serdes_bases[ifg->mac_pool2->get_block_id()]
            = mac_pool_serdes_base{.slice_i = ifg_i.slice, .ifg_i = ifg_i.ifg, .serdes_base = 16};
    }

    return LA_STATUS_SUCCESS;
}

bool
hld_notification_pacific::is_msi_clear()
{
    bit_vector val;
    bit_vector mask;

    auto tree = m_device->m_ll_device->get_pacific_tree();
    m_device->m_ll_device->read_register(*tree->sbif->msi_master_interrupt_reg, val);
    m_device->m_ll_device->read_register(*tree->sbif->msi_master_interrupt_reg_mask, mask);

    // Pacific SBIF mask is active high (1 == enabled).
    val &= mask;

    return val.is_zero();
}

void
hld_notification_pacific::init_static_mapping(const la_device_impl_wptr& la_device, vector_alloc<lld_memory_scptr>& out_vect) const
{
    const auto& tree = la_device->m_ll_device->get_pacific_tree();
    for (la_slice_id_t sid : la_device->get_used_slices()) {
        auto& slice = tree->slice[sid];
        if (sid < 4) {
            out_vect.push_back(slice->pdvoq->static_mapping);
        } else {
            out_vect.push_back(slice->fabric_pdvoq->static_mapping);
        }
    }
}

} // namespace silicon_one
