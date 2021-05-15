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

#include "la_rate_limiter_set_base.h"

#include "api_tracer.h"
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"

namespace silicon_one
{

la_rate_limiter_set_base::la_rate_limiter_set_base(la_device_impl_wptr device) : m_device(device)
{
}

la_rate_limiter_set_base::~la_rate_limiter_set_base()
{
}

la_status
la_rate_limiter_set_base::initialize(la_object_id_t oid, const la_system_port_wptr& system_port)
{
    m_oid = oid;

    if (system_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(this, system_port)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    m_system_port = system_port.weak_ptr_static_cast<la_system_port_base>();

    m_device->add_object_dependency(system_port, this);
    auto cir = la_rate_2_npl_meter_weight(LA_RATE_UNLIMITED, m_device->m_rate_limiters_shaper_rate);
    for (auto& packet_type_cir : m_cir) {
        // Reflects the hardware shaper configuration table entry configured at init
        packet_type_cir = cir;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_rate_limiter_set_base::destroy()
{
    auto cir = la_rate_2_npl_meter_weight(LA_RATE_UNLIMITED, m_device->m_rate_limiters_shaper_rate);
    for (auto it = std::begin(m_cir); it != std::end(m_cir); ++it) {
        auto packet_type = static_cast<la_rate_limiters_packet_type_e>(it - std::begin(m_cir));
        *it = cir;
        // ignoring return status as this is a destroy function
        do_set_cir(packet_type);
    }

    m_device->remove_object_dependency(m_system_port, this);

    return LA_STATUS_SUCCESS;
}

npl_meter_weight_t
la_rate_limiter_set_base::la_rate_2_npl_meter_weight(la_rate_t rate, float shaper_max_rate) const
{
    npl_meter_weight_t weight;

    la_rate_t total_bank_rate = shaper_max_rate * UNITS_IN_GIGA;
    tm_utils::token_bucket_ratio_cfg_t ratio_cfg = tm_utils::calc_rate_ratio(total_bank_rate, rate);
    weight.weight = ratio_cfg.fields.mantissa;
    weight.weight_factor = ratio_cfg.fields.exponent;

    return weight;
}

la_rate_t
la_rate_limiter_set_base::la_npl_meter_weight_2_rate(npl_meter_weight_t weight, float shaper_max_rate) const
{

    la_rate_t total_bank_rate = shaper_max_rate * UNITS_IN_GIGA;
    uint32_t mantissa = weight.weight;
    uint32_t exponent = weight.weight_factor;
    float ratio = tm_utils::convert_float_from_device_val(exponent, mantissa);
    la_rate_t rate = ratio * total_bank_rate;

    return rate;
}

la_status
la_rate_limiter_set_base::do_set_cir(la_rate_limiters_packet_type_e packet_type)
{
    la_slice_id_t slice_id = m_system_port->get_slice();
    la_ifg_id_t ifg_id = m_system_port->get_ifg();
    la_uint_t port_id = m_system_port->get_base_pif();

    la_status status = configure_rate_limiters_shaper_configuration_entry(slice_id, ifg_id, port_id, packet_type);
    return status;
}

la_status
la_rate_limiter_set_base::set_cir(la_rate_limiters_packet_type_e packet_type, la_rate_t cir)
{
    start_api_call("packet_type=", packet_type, "cir=", cir);
    cir = user_rate_to_meter_rate(cir);
    m_cir[(la_uint_t)packet_type] = la_rate_2_npl_meter_weight(cir, m_device->m_rate_limiters_shaper_rate);

    la_status status = do_set_cir(packet_type);
    return status;
}

la_status
la_rate_limiter_set_base::get_cir(la_rate_limiters_packet_type_e packet_type, la_rate_t& out_cir) const
{
    start_api_getter_call();
    out_cir = la_npl_meter_weight_2_rate(m_cir[(la_uint_t)packet_type], m_device->m_rate_limiters_shaper_rate);
    out_cir = meter_rate_to_user_rate(out_cir);
    return LA_STATUS_SUCCESS;
}

la_status
la_rate_limiter_set_base::get_system_port(la_system_port*& out_system_port) const
{
    start_api_getter_call();

    out_system_port = m_system_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_rate_limiter_set_base::configure_rate_limiters_shaper_configuration_entry(la_slice_id_t slice_id,
                                                                             la_ifg_id_t ifg_id,
                                                                             la_uint_t port_id,
                                                                             la_rate_limiters_packet_type_e packet_type)
{
    npl_rx_meter_rate_limiter_shaper_configuration_table_t::key_type k;
    k.table_index.value = (slice_id * NUM_IFGS_PER_SLICE) + ifg_id;
    k.table_entry_index.value = (port_id * (la_uint_t)la_rate_limiters_packet_type_e::LAST) + (la_uint_t)packet_type;
    npl_rx_meter_rate_limiter_shaper_configuration_table_t::value_type v;
    v.payloads.rx_meter_rate_limiter_shaper_configuration_result.cir_weight = m_cir[(la_uint_t)packet_type];

    npl_rx_meter_rate_limiter_shaper_configuration_table_t::entry_pointer_type e = nullptr;
    la_status status = m_device->m_tables.rx_meter_rate_limiter_shaper_configuration_table->set(k, v, e);

    return status;
}

la_rate_t
la_rate_limiter_set_base::user_rate_to_meter_rate(la_rate_t rate) const
{
    return (la_rate_t)(rate / bit_utils::BITS_IN_BYTE);
}

la_rate_t
la_rate_limiter_set_base::meter_rate_to_user_rate(la_rate_t rate) const
{
    return (la_rate_t)(rate * bit_utils::BITS_IN_BYTE);
}

std::string
la_rate_limiter_set_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_rate_limiter_set_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_rate_limiter_set_base::oid() const
{
    return m_oid;
}

la_device*
la_rate_limiter_set_base::get_device() const
{
    return m_device.get();
}

la_object::object_type_e
la_rate_limiter_set_base::type() const
{
    start_api_getter_call("");
    return object_type_e::RATE_LIMITER_SET;
}
}
