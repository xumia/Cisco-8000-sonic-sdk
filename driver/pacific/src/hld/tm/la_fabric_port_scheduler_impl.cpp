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

#include "common/dassert.h"

#include "hld_utils.h"
#include "la_fabric_port_scheduler_impl.h"
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"
#include "system/la_device_impl.h"
#include "tm_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_fabric_port_scheduler_impl::la_fabric_port_scheduler_impl(const la_device_impl_wptr& device,
                                                             la_slice_id_t slice_id,
                                                             la_ifg_id_t ifg_id,
                                                             la_uint_t fab_intf_id)
    : m_device(device), m_slice_id(slice_id), m_ifg_id(ifg_id), m_fab_intf_id(fab_intf_id)
{
}

la_fabric_port_scheduler_impl::~la_fabric_port_scheduler_impl()
{
}

la_status
la_fabric_port_scheduler_impl::initialize(la_object_id_t oid)
{
    m_oid = oid;
    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_scheduler_impl::destroy()
{
    return LA_STATUS_SUCCESS;
}

// la_object API-s
la_object::object_type_e
la_fabric_port_scheduler_impl::type() const
{
    return object_type_e::FABRIC_PORT_SCHEDULER;
}

std::string
la_fabric_port_scheduler_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_fabric_port_scheduler_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_fabric_port_scheduler_impl::oid() const
{
    return m_oid;
}

const la_device*
la_fabric_port_scheduler_impl::get_device() const
{
    return m_device.get();
}

la_status
la_fabric_port_scheduler_impl::get_output_queue_weight(fabric_ouput_queue_e oq, la_wfq_weight_t& out_weight) const
{
    size_t oqpg = get_oq2pg(oq);
    if (oqpg == INVALID_PG) {
        return LA_STATUS_EINVAL;
    }

    bit_vector tpse_wfq_cfg;

    la_status status = m_device->m_ll_device->read_memory(
        (*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->tpse_wfq_cfg)[m_ifg_id], m_fab_intf_id, tpse_wfq_cfg);
    return_on_error(status);

    size_t lsb = oqpg * WFQ_WEIGHT_WIDTH;
    size_t msb = lsb + WFQ_WEIGHT_WIDTH - 1;

    out_weight = tpse_wfq_cfg.bits(msb, lsb).get_value();

    return LA_STATUS_SUCCESS;
}

la_status
la_fabric_port_scheduler_impl::set_output_queue_weight(fabric_ouput_queue_e oq, la_wfq_weight_t weight)
{
    start_api_call("oq=", oq, "weight=", weight);

    if (weight > tm_utils::TM_WFQ_WEIGHT_MAX) {
        return LA_STATUS_EINVAL;
    }

    size_t oqpg = get_oq2pg(oq);
    if (oqpg == INVALID_PG) {
        return LA_STATUS_EINVAL;
    }

    size_t lsb = oqpg * WFQ_WEIGHT_WIDTH;
    size_t msb = lsb + WFQ_WEIGHT_WIDTH - 1;

    la_status status = m_device->m_ll_device->read_modify_write_memory(
        *(*m_device->m_pacific_tree->slice[m_slice_id]->pdoq->top->tpse_wfq_cfg)[m_ifg_id], m_fab_intf_id, msb, lsb, weight);

    return status;
}

size_t
la_fabric_port_scheduler_impl::get_oq2pg(fabric_ouput_queue_e oq) const
{
    switch (oq) {
    case fabric_ouput_queue_e::PLB_UC_HIGH:
        return fabric_oq_pg_e::PLB_UC_HIGH;

    case fabric_ouput_queue_e::PLB_UC_LOW:
        return fabric_oq_pg_e::PLB_UC_LOW;

    case fabric_ouput_queue_e::PLB_MC:
        return fabric_oq_pg_e::PLB_MC;

    default:
        return INVALID_PG;
    }
}

} // namespace silicon_one
