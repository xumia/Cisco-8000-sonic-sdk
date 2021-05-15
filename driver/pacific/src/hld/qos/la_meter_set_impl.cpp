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

#include "la_meter_set_impl.h"
#include "api/npu/la_l2_port.h"
#include "api/npu/la_l3_port.h"
#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/math_utils.h"
#include "hld_types.h"
#include "hld_utils.h"
#include "ifg_use_count.h"
#include "la_strings.h"
#include "lld/ll_device.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"
#include "npu/la_acl_impl.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_svi_port_base.h"
#include "system/la_device_impl.h"
#include "system/slice_id_manager_base.h"
#include "tm/tm_utils.h"

#include <sstream>
#include <thread>

namespace silicon_one
{

la_meter_set_impl::la_meter_set_impl(const la_device_impl_wptr& device) : m_device(device), m_lpts_entry_meter(false)
{
}

la_meter_set_impl::~la_meter_set_impl()
{
}

la_status
la_meter_set_impl::initialize(la_object_id_t oid, type_e type, size_t size)
{
    m_slice_id_manager = m_device->get_slice_id_manager();
    m_ifg_use_count = make_unique<ifg_use_count>(m_slice_id_manager);
    m_oid = oid;
    m_meter_type = type;

    // A set size of 32 is needed to support 32 class map counter offsets
    if ((size == 0) || (size > PER_QOS_TC_SET_SIZE)) {
        log_err(HLD, "Invalid set size");
        return LA_STATUS_EINVAL;
    }

    m_set_size = size;
    m_meters_properties.resize(size);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }
    for (size_t meter_index = 0; meter_index < m_set_size; ++meter_index) {
        la_status status = detach_meter_action_profile(meter_index);
        return_on_error(status);

        status = detach_meter_profile(meter_index);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

size_t
la_meter_set_impl::get_set_size() const
{
    return m_set_size;
}

la_status
la_meter_set_impl::detach_meter_profile(size_t meter_index)
{
    auto meter_profile_impl = m_meters_properties[meter_index].meter_profile;
    if (meter_profile_impl == nullptr) {
        return LA_STATUS_SUCCESS;
    }
    la_status status = do_detach_meter_profile(meter_index);
    return_on_error(status);

    m_device->remove_object_dependency(meter_profile_impl, this);
    m_meters_properties[meter_index].meter_profile = nullptr;
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::validate_meter_profile(size_t meter_index, const la_meter_profile_impl_wcptr& meter_profile)
{
    if (!of_same_device(meter_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_meter_profile::type_e meter_profile_type = meter_profile->get_type();
    if ((meter_profile_type == la_meter_profile::type_e::PER_IFG) && (m_meter_type != type_e::PER_IFG_EXACT)) {
        log_err(HLD, "PER_IFG meter profile cannot be set to non per-ifg meter");
        return LA_STATUS_EINVAL;
    }

    // Meter should be COLOR-AWARE
    la_meter_profile::color_awareness_mode_e color_awareness_mode;
    la_status status = meter_profile->get_color_awareness_mode(color_awareness_mode);
    return_on_error(status);
    if (color_awareness_mode != la_meter_profile::color_awareness_mode_e::AWARE) {
        log_err(HLD, "Color blind metering mode is not supported");
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    status = validate_coupling_mode(meter_profile, m_meters_properties[meter_index].coupling_mode);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::set_meter_profile(size_t meter_index, const la_meter_profile* meter_profile)
{
    start_api_call("meter_index=", meter_index, "meter_profile=", meter_profile);

    if (!m_user_to_aggregation.empty()) {
        log_err(HLD, "Changing meter-profile while meter is active is not supported");
        return LA_STATUS_EBUSY;
    }

    // TODO: Wait for 50usec to ensure that there's no traffic on the meter

    if (meter_index >= m_set_size) {
        log_err(HLD, "meter_index is out of range index=%ld size=%ld", meter_index, m_set_size);
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_meters_properties[meter_index].meter_profile != nullptr) {
        detach_meter_profile(meter_index);
    }

    if (meter_profile == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    auto meter_profile_impl = m_device->get_sptr<la_meter_profile_impl>(meter_profile);
    la_status status = validate_meter_profile(meter_index, meter_profile_impl);
    return_on_error(status);

    status = do_set_meter_profile(meter_index, meter_profile_impl);
    return_on_error(status);

    m_meters_properties[meter_index].meter_profile = meter_profile_impl;

    m_device->add_object_dependency(meter_profile_impl, this);

    return LA_STATUS_SUCCESS;
}

la_meter_set::type_e
la_meter_set_impl::get_type() const
{
    return m_meter_type;
}

la_status
la_meter_set_impl::get_meter_profile(size_t meter_index, const la_meter_profile*& out_meter_profile) const
{
    out_meter_profile = m_meters_properties[meter_index].meter_profile.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::detach_meter_action_profile(size_t meter_index)
{
    auto meter_action_profile_impl = m_meters_properties[meter_index].meter_action_profile;
    if (meter_action_profile_impl == nullptr) {
        return LA_STATUS_SUCCESS;
    }
    la_status status = do_detach_meter_action_profile(meter_index);
    return_on_error(status);

    m_device->remove_object_dependency(meter_action_profile_impl, this);
    m_meters_properties[meter_index].meter_action_profile = nullptr;
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::set_meter_action_profile(size_t meter_index, const la_meter_action_profile* meter_action_profile)
{
    start_api_call("meter_index=", meter_index, "meter_action_profile=", meter_action_profile);

    if (!m_user_to_aggregation.empty()) {
        log_err(HLD, "Changing meter-action-profile while meter is active is not supported");

        return LA_STATUS_EBUSY;
    }

    if (meter_index >= m_set_size) {
        log_err(HLD, "meter_index is out of range index=%ld size=%ld", meter_index, m_set_size);
        return LA_STATUS_EOUTOFRANGE;
    }

    if ((meter_action_profile != nullptr) && (!of_same_device(meter_action_profile, this))) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_meters_properties[meter_index].meter_action_profile != nullptr) {
        detach_meter_action_profile(meter_index);
    }

    if (meter_action_profile == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    auto meter_action_profile_impl = m_device->get_sptr<la_meter_action_profile_impl>(meter_action_profile);
    m_meters_properties[meter_index].meter_action_profile = meter_action_profile_impl;

    la_status status = do_set_meter_action_profile(meter_index, meter_action_profile_impl);
    return_on_error(status);

    m_device->add_object_dependency(meter_action_profile_impl, this);
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::get_meter_action_profile(size_t meter_index, const la_meter_action_profile*& out_meter_action_profile) const
{
    out_meter_action_profile = m_meters_properties[meter_index].meter_action_profile.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::validate_coupling_mode(const la_meter_profile_impl_wcptr& meter_profile, coupling_mode_e coupling_mode)
{
    if (meter_profile != nullptr) {
        la_meter_profile::meter_rate_mode_e meter_rate_mode;
        la_status status = meter_profile->get_meter_rate_mode(meter_rate_mode);
        return_on_error(status);
        if (meter_rate_mode == la_meter_profile::meter_rate_mode_e::SR_TCM) {
            // Coupling mode must be TO_EXCESS_BUCKET
            if (coupling_mode != coupling_mode_e::TO_EXCESS_BUCKET) {
                log_err(HLD, "Only TO_EXCESS_BUFFER coupling mode is supported for single-rate metering");
                return LA_STATUS_ENOTIMPLEMENTED;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::set_committed_bucket_coupling_mode(size_t meter_index, coupling_mode_e coupling_mode)
{
    start_api_call("meter_index=", meter_index, "coupling_mode=", coupling_mode);
    if (meter_index >= m_set_size) {
        log_err(HLD, "meter_index is out of range index=%ld size=%ld", meter_index, m_set_size);
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status status = validate_coupling_mode(m_meters_properties[meter_index].meter_profile, coupling_mode);
    return_on_error(status);

    m_meters_properties[meter_index].coupling_mode = coupling_mode;
    status = do_set_committed_bucket_coupling_mode(meter_index, coupling_mode);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::get_committed_bucket_coupling_mode(size_t meter_index, coupling_mode_e& out_coupling_mode) const
{
    out_coupling_mode = m_meters_properties[meter_index].coupling_mode;
    return LA_STATUS_SUCCESS;
}

npl_meter_weight_t
la_meter_set_impl::la_rate_2_npl_meter_weight(la_rate_t rate, float shaper_max_rate) const
{
    npl_meter_weight_t weight;

    la_rate_t total_bank_rate = shaper_max_rate * UNITS_IN_GIGA;
    tm_utils::token_bucket_ratio_cfg_t ratio_cfg = tm_utils::calc_rate_ratio(total_bank_rate, rate);
    weight.weight = ratio_cfg.fields.mantissa;
    weight.weight_factor = ratio_cfg.fields.exponent;

    return weight;
}

float
la_meter_set_impl::get_shaper_max_rate(size_t meter_index, bool is_cir) const
{
    return m_device->m_meter_shaper_rate;
}

la_rate_t
la_meter_set_impl::user_rate_to_meter_rate(size_t meter_index, la_rate_t rate) const
{
    la_meter_profile::meter_measure_mode_e meter_measure_mode;
    m_meters_properties[meter_index].meter_profile->get_meter_measure_mode(meter_measure_mode);
    if (meter_measure_mode == la_meter_profile::meter_measure_mode_e::BYTES) {
        rate = (la_rate_t)(rate / bit_utils::BITS_IN_BYTE);
    }

    return rate;
}

la_rate_t
la_meter_set_impl::meter_rate_to_user_rate(size_t meter_index, la_rate_t rate) const
{
    la_meter_profile::meter_measure_mode_e meter_measure_mode;
    m_meters_properties[meter_index].meter_profile->get_meter_measure_mode(meter_measure_mode);
    if (meter_measure_mode == la_meter_profile::meter_measure_mode_e::BYTES) {
        rate = (la_rate_t)(rate * bit_utils::BITS_IN_BYTE);
    }

    return rate;
}

la_status
la_meter_set_impl::set_cir(size_t meter_index, la_rate_t cir)
{
    start_api_call("meter_index=", meter_index, "cir=", cir);
    if (meter_index >= m_set_size) {
        log_err(HLD, "meter_index is out of range index=%ld size=%ld", meter_index, m_set_size);
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_meter_type == type_e::PER_IFG_EXACT) {
        log_err(HLD, "Non per-ifg function is called for per-ifg meter.");
        return LA_STATUS_EINVAL;
    }

    npl_meter_weight_t out_weight;
    la_status status = populate_weight_from_cir_or_eir(meter_index, cir, true /*is_cir*/, out_weight);
    return_on_error(status);
    m_meters_properties[meter_index].cir_weight[SINGLE_ALLOCATION_IFG] = out_weight;
    m_meters_properties[meter_index].user_cir[SINGLE_ALLOCATION_IFG] = cir;

    status = do_set_cir(meter_index);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::get_cir(size_t meter_index, la_rate_t& out_cir) const
{
    start_api_getter_call();
    if (meter_index >= m_set_size) {
        log_err(HLD, "meter_index is out of range index=%ld size=%ld", meter_index, m_set_size);
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_meter_type == type_e::PER_IFG_EXACT) {
        log_err(HLD, "Non per-ifg function is called for per-ifg meter");
        return LA_STATUS_EINVAL;
    }

    npl_meter_weight_t cir_weight = m_meters_properties[meter_index].cir_weight[SINGLE_ALLOCATION_IFG];
    la_rate_t cir_before_factor;
    la_status status = populate_cir_or_eir_from_weight(meter_index, cir_weight, true /*is_cir*/, cir_before_factor);
    return_on_error(status);
    out_cir = cir_before_factor / m_device->get_meter_cir_eir_factor(m_meter_type);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::set_eir(size_t meter_index, la_rate_t eir)
{
    start_api_call("meter_index=", meter_index, "eir=", eir);
    if (m_meter_type == type_e::PER_IFG_EXACT) {
        log_err(HLD, "Non per-ifg function is called for per-ifg meter");
        return LA_STATUS_EINVAL;
    }

    if (meter_index >= m_set_size) {
        log_err(HLD, "meter_index is out of range index=%ld size=%ld", meter_index, m_set_size);
        return LA_STATUS_EOUTOFRANGE;
    }

    npl_meter_weight_t out_weight;
    la_status status = populate_weight_from_cir_or_eir(meter_index, eir, false /*is_cir*/, out_weight);
    return_on_error(status);
    m_meters_properties[meter_index].eir_weight[SINGLE_ALLOCATION_IFG] = out_weight;
    m_meters_properties[meter_index].user_eir[SINGLE_ALLOCATION_IFG] = eir;

    status = do_set_eir(meter_index);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::get_eir(size_t meter_index, la_rate_t& out_eir) const
{
    start_api_getter_call();
    if (m_meter_type == type_e::PER_IFG_EXACT) {
        log_err(HLD, "Non per-ifg function is called for per-ifg meter");
        return LA_STATUS_EINVAL;
    }

    if (meter_index >= m_set_size) {
        log_err(HLD, "meter_index is out of range index=%ld size=%ld", meter_index, m_set_size);
        return LA_STATUS_EOUTOFRANGE;
    }

    npl_meter_weight_t eir_weight = m_meters_properties[meter_index].eir_weight[SINGLE_ALLOCATION_IFG];
    la_rate_t eir_before_factor;
    la_status status = populate_cir_or_eir_from_weight(meter_index, eir_weight, false /*is_cir*/, eir_before_factor);
    return_on_error(status);
    out_eir = eir_before_factor / m_device->get_meter_cir_eir_factor(m_meter_type);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::populate_weight_from_cir_or_eir(size_t meter_index,
                                                   la_rate_t rate,
                                                   bool is_cir,
                                                   npl_meter_weight_t& out_weight) const
{
    if (m_meters_properties[meter_index].meter_profile == nullptr) {
        log_err(HLD, "Cannot set %s before a meter profile is set.", (is_cir ? "cir" : "eir"));
        return LA_STATUS_ENOTINITIALIZED;
    }

    rate = user_rate_to_meter_rate(meter_index, rate);
    size_t configured_rate = rate * m_device->get_meter_cir_eir_factor(m_meter_type);
    float shaper_max_rate = get_shaper_max_rate(meter_index, is_cir);
    out_weight = la_rate_2_npl_meter_weight(configured_rate, shaper_max_rate);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::populate_cir_or_eir_from_weight(size_t meter_index,
                                                   npl_meter_weight_t weight,
                                                   bool is_cir,
                                                   la_rate_t& out_rate) const
{
    if (m_meters_properties[meter_index].meter_profile == nullptr) {
        log_err(HLD, "Cannot get %s before a meter profile is set.", (is_cir ? "cir" : "eir"));
        return LA_STATUS_ENOTINITIALIZED;
    }

    float shaper_max_rate = get_shaper_max_rate(meter_index, is_cir);
    out_rate = npl_meter_weight_2_la_rate(weight, shaper_max_rate);
    out_rate = meter_rate_to_user_rate(meter_index, out_rate);

    return LA_STATUS_SUCCESS;
}

bool
la_meter_set_impl::is_lpts_entry_meter() const
{
    return m_lpts_entry_meter;
}

bool
la_meter_set_impl::is_supported_user(const la_object_wcptr& user, bool is_lpts_entry_meter) const
{
    la_object::object_type_e object_type = user->type();
    switch (object_type) {
    case la_object::object_type_e::L2_SERVICE_PORT: {
        auto service_port = user.weak_ptr_static_cast<const la_l2_service_port_base>();
        bool is_ac = (service_port->get_port_type() == la_l2_service_port::port_type_e::AC);
        return is_ac;
    }

    case la_object::object_type_e::LPTS:
        if (!is_lpts_entry_meter) {
            return true;
        }

        if (m_device->is_in_use(this)) {
            log_err(HLD, "LPTS counting meter cannot be shared by different LPTS objects");
            return false;
        } else {
            return true;
        }
    case la_object::object_type_e::DEVICE:
    case la_object::object_type_e::L3_AC_PORT:
    case la_object::object_type_e::COUNTER_SET:
    case la_object::object_type_e::VRF:
    case la_object::object_type_e::SVI_PORT:
    case la_object::object_type_e::GRE_PORT:
    case la_object::object_type_e::METER_SET:
    case la_object::object_type_e::L2_MIRROR_COMMAND:
    case la_object::object_type_e::MAC_PORT: {
        return true;
    }

    case la_object::object_type_e::ACL: {
        return true;
    }

    default:
        return false;
    }
}

bool
la_meter_set_impl::is_valid_set_size(const la_object_wcptr& user, bool is_lpts_entry_meter) const
{
    la_object::object_type_e type = user->type();

    switch (type) {
    case la_object::object_type_e::DEVICE:
        // Meter is attached to trap/redirect
        return (m_set_size == 1);

    case la_object::object_type_e::LPTS:
        // Meter is attached to trap/redirect
        return (m_set_size == 1);

    case la_object::object_type_e::ACL:
        return (m_set_size == 1);

    default:
        return true;
    }
}

la_status
la_meter_set_impl::attach_user(const la_object_wcptr& user, bool is_aggregate, bool is_lpts_entry_meter)
{
    if (m_user_to_aggregation.find(user) != m_user_to_aggregation.end()) {
        return LA_STATUS_SUCCESS;
    }

    if (!is_initialized()) {
        log_err(HLD, "meter-set is not initialized. probably no profiles are set for it");
        return LA_STATUS_ENOTINITIALIZED;
    }

    if (!is_supported_user(user, is_lpts_entry_meter)) {
        log_err(HLD, "Cannot attach meter to user type %s", la_object_type_to_string(user->type()).c_str());
        return LA_STATUS_EINVAL;
    }

    if (!is_valid_set_size(user, is_lpts_entry_meter)) {
        log_err(
            HLD, "meter-set size %lu is not valid for user type %s", m_set_size, la_object_type_to_string(user->type()).c_str());
        return LA_STATUS_EINVAL;
    }

    m_lpts_entry_meter = is_lpts_entry_meter;

    // First of all we do allocation, then add the user. The order is important here.
    la_status status = do_attach_user(user, is_aggregate);
    return_on_error(status);
    m_user_to_aggregation[user] = is_aggregate;

    m_device->add_object_dependency(this, user);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::detach_user(const la_object_wcptr& user)
{
    if (user == nullptr || (m_user_to_aggregation.find(user) == m_user_to_aggregation.end())) {
        return LA_STATUS_EUNKNOWN;
    }

    la_status status = do_detach_user(user);
    return_on_error(status);

    // An LPTS Entry meter has utmost one user.
    m_lpts_entry_meter = false;

    m_device->remove_object_dependency(this, user);

    m_user_to_aggregation.erase(user);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::configure_metering(la_slice_ifg ifg)
{
    for (size_t meter_index = 0; meter_index < m_set_size; ++meter_index) {
        la_status status = configure_meter_state_entry(ifg, meter_index);
        return_on_error(status);

        status = configure_meters_attribute_entry(ifg, meter_index);
        return_on_error(status);

        status = configure_meter_shaper_configuration_entry(ifg, meter_index);
        return_on_error(status);

        status = configure_meters_table_entry(ifg, meter_index);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::erase_metering(la_slice_ifg ifg)
{
    for (size_t meter_index = 0; meter_index < m_set_size; ++meter_index) {
        la_status status = erase_meter_state_entry(ifg, meter_index);
        return_on_error(status);

        status = erase_meters_attribute_entry(ifg, meter_index);
        return_on_error(status);

        status = erase_meter_shaper_configuration_entry(ifg, meter_index);
        return_on_error(status);

        status = erase_meters_table_entry(ifg, meter_index);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::erase_meter_state_entry(la_slice_ifg ifg, size_t meter_index)
{
    // The meter-state table is multival-sram and dynamic memory. As such it cannot be modeled by NPL table.
    // Hence there's no meaning to 'erasing' an entry.
    return LA_STATUS_SUCCESS;
}

la_status
la_meter_set_impl::erase_meters_table_entry(la_slice_ifg ifg, size_t meter_index)
{
    // The meters table is multival-sram and dynamic memory. As such it cannot be modeled by NPL table.
    // Hence there's no meaning to 'erasing' an entry.
    return LA_STATUS_SUCCESS;
}

bool
la_meter_set_impl::is_initialized() const
{
    for (auto properties : m_meters_properties) {
        if (properties.meter_profile == nullptr || properties.meter_action_profile == nullptr) {
            return false;
        }
    }
    return true;
}

la_rate_t
la_meter_set_impl::npl_meter_weight_2_la_rate(npl_meter_weight_t weight, float shaper_max_rate) const
{
    uint32_t mantissa = weight.weight;
    uint32_t exponent = weight.weight_factor;
    float ratio = tm_utils::convert_float_from_device_val(exponent, mantissa);

    la_rate_t total_bank_rate = shaper_max_rate * UNITS_IN_GIGA;
    la_rate_t out_rate = ratio * total_bank_rate;
    return out_rate;
}

la_object::object_type_e
la_meter_set_impl::type() const
{
    return object_type_e::METER_SET;
}

const la_device*
la_meter_set_impl::get_device() const
{
    return m_device.get();
}

uint64_t
la_meter_set_impl::oid() const
{
    return m_oid;
}

std::string
la_meter_set_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_meter_set_impl(oid=" << m_oid << ")";
    return log_message.str();
}

template <typename _Key>
void
la_meter_set_impl::populate_general_key(la_slice_ifg ifg, size_t meter_index, _Key& key) const
{
    size_t bank_index;
    size_t set_base_index;
    get_bank_and_base_index(ifg, bank_index, set_base_index);
    key.bank_index.value = bank_index;
    key.meter_index.value = set_base_index + meter_index;
}

template <typename _Payload>
la_status
la_meter_set_impl::populate_meters_attribute_payload(la_slice_ifg ifg, size_t meter_index, _Payload& payload) const
{
    size_t meter_action_profile_index;
    la_status status = get_meter_action_profile_allocation(ifg, meter_index, meter_action_profile_index);
    return_on_error(status);

    size_t meter_profile_index;
    status = get_meter_profile_allocation(ifg, meter_index, meter_profile_index);
    return_on_error(status);

    payload.profile.value = meter_profile_index;
    payload.meter_decision_mapping_profile.value = meter_action_profile_index;
    payload.commited_coupling_flag = la_2_meter_coupling_mode(m_meters_properties[meter_index].coupling_mode);

    return LA_STATUS_SUCCESS;
}

template <typename _EntryType>
la_status
la_meter_set_impl::populate_meter_state_entry(la_slice_ifg ifg, size_t meter_index, _EntryType& entry) const
{
    la_meter_profile::color_awareness_mode_e color_awareness_mode;
    la_meter_profile::meter_rate_mode_e meter_rate_mode;
    m_meters_properties[meter_index].meter_profile->get_color_awareness_mode(color_awareness_mode);
    m_meters_properties[meter_index].meter_profile->get_meter_rate_mode(meter_rate_mode);
    size_t meter_action_profile_index;

    la_status status = get_meter_action_profile_allocation(ifg, meter_index, meter_action_profile_index);
    return_on_error(status);

    if ((meter_index % 2) == 0) {
        entry.fields.meters_state_entry0_color_aware_mode = la_2_meter_color_aware_mode(color_awareness_mode);
        entry.fields.meters_state_entry0_meter_mode = la_2_meter_rate_mode(meter_rate_mode);
        entry.fields.meters_state_entry0_meter_decision_mapping_profile = meter_action_profile_index;
        entry.fields.meters_state_entry0_commited_above_zero = TRAFFIC_ALLOWED;
        entry.fields.meters_state_entry0_excess_above_zero = TRAFFIC_ALLOWED;
    } else {
        entry.fields.meters_state_entry1_color_aware_mode = la_2_meter_color_aware_mode(color_awareness_mode);
        entry.fields.meters_state_entry1_meter_mode = la_2_meter_rate_mode(meter_rate_mode);
        entry.fields.meters_state_entry1_meter_decision_mapping_profile = meter_action_profile_index;
        entry.fields.meters_state_entry1_commited_above_zero = TRAFFIC_ALLOWED;
        entry.fields.meters_state_entry1_excess_above_zero = TRAFFIC_ALLOWED;
    }

    return LA_STATUS_SUCCESS;
}

template <typename _Payload>
la_status
la_meter_set_impl::populate_meter_shaper_configuration_payload(la_slice_ifg ifg, size_t meter_index, _Payload& payload) const
{
    size_t g_ifg = (m_meter_type == type_e::PER_IFG_EXACT) ? m_ifg_use_count->get_index(ifg) : 0;
    payload.cir_weight = m_meters_properties[meter_index].cir_weight[g_ifg];
    payload.eir_weight = m_meters_properties[meter_index].eir_weight[g_ifg];

    return LA_STATUS_SUCCESS;
}

template <typename _EntryType>
la_status
la_meter_set_impl::do_configure_meters_table_entry(la_slice_ifg ifg,
                                                   size_t meter_index,
                                                   lld_memory_scptr meters_table,
                                                   size_t line_index)
{
    // Get the burst size from the associated meter profile
    auto meter_profile = m_meters_properties[meter_index].meter_profile;
    la_meter_profile::type_e profile_type = meter_profile->get_type();
    la_status status;

    bool is_global_profile = (profile_type == la_meter_profile::type_e::GLOBAL);
    la_uint64_t cbs;
    status = is_global_profile ? meter_profile->get_cbs(cbs) : meter_profile->get_cbs(ifg, cbs);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "meter_profile->get_cbs failed %s", la_status2str(status).c_str());
        return status;
    }

    la_uint64_t ebs;
    status = is_global_profile ? meter_profile->get_ebs_or_pbs(ebs) : meter_profile->get_ebs_or_pbs(ifg, ebs);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "meter_profile->get_ebs_or_pbs failed %s", la_status2str(status).c_str());
        return status;
    }

    la_meter_profile::meter_rate_mode_e meter_rate_mode;
    status = meter_profile->get_meter_rate_mode(meter_rate_mode);
    return_on_error(status);

    // TODO (Yoav): finalize a decision about whether ebs = 0 is supported for SR_TCM metering mode.
    /*
    if ((meter_rate_mode == la_meter_profile::meter_rate_mode_e::SR_TCM) && (ebs == 0)) {
        log_err(HLD, "Zero EBS for single-rate metering is not supported");
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    */

    _EntryType entry;
    status = m_device->m_ll_device->read_memory(meters_table, line_index, entry);
    return_on_error(status);

    la_meter_profile::meter_measure_mode_e measure_mode;
    status = meter_profile->get_meter_measure_mode(measure_mode);
    return_on_error(status);
    la_meter_set::type_e meter_type = (measure_mode == la_meter_profile::meter_measure_mode_e::PACKETS)
                                          ? la_meter_set::type_e::STATISTICAL
                                          : la_meter_set::type_e::EXACT;

    if ((meter_index % 2) == 0) {
        entry.fields.table_entry0_commited_meter = cbs * m_device->get_meter_cir_eir_factor(meter_type);
        entry.fields.table_entry0_excess_meter = ebs * m_device->get_meter_cir_eir_factor(meter_type);
    } else {
        entry.fields.table_entry1_commited_meter = cbs * m_device->get_meter_cir_eir_factor(meter_type);
        entry.fields.table_entry1_excess_meter = ebs * m_device->get_meter_cir_eir_factor(meter_type);
    }

    status = m_device->m_ll_device->write_memory(meters_table, line_index, entry);

    return status;
}

// Templates specialization, this code is needed so the compiler can know the needed signatures of the templated functions
template void la_meter_set_impl::populate_general_key(la_slice_ifg,
                                                      size_t,
                                                      npl_rx_meter_block_meter_attribute_table_t::key_type&) const;

template void la_meter_set_impl::populate_general_key(la_slice_ifg, size_t, npl_rx_meter_meters_attribute_table_t::key_type&) const;

template void la_meter_set_impl::populate_general_key(la_slice_ifg,
                                                      size_t,
                                                      npl_rx_meter_block_meter_shaper_configuration_table_t::key_type&) const;

template void la_meter_set_impl::populate_general_key(la_slice_ifg,
                                                      size_t,
                                                      npl_rx_meter_meter_shaper_configuration_table_t::key_type&) const;

template la_status la_meter_set_impl::populate_meters_attribute_payload(la_slice_ifg,
                                                                        size_t,
                                                                        npl_rx_meter_block_meter_attribute_result_t&) const;
template la_status la_meter_set_impl::populate_meters_attribute_payload(la_slice_ifg,
                                                                        size_t,
                                                                        npl_rx_meter_meters_attribute_result_t&) const;

template la_status la_meter_set_impl::populate_meter_state_entry(la_slice_ifg,
                                                                 size_t,
                                                                 rx_meter_block_meters_state_table_memory&) const;
template la_status la_meter_set_impl::populate_meter_state_entry(la_slice_ifg, size_t, rx_meter_meters_state_table_memory&) const;

template la_status la_meter_set_impl::populate_meter_shaper_configuration_payload(
    la_slice_ifg,
    size_t,
    npl_rx_meter_block_meter_shaper_configuration_result_t&) const;

template la_status la_meter_set_impl::populate_meter_shaper_configuration_payload(
    la_slice_ifg,
    size_t,
    npl_rx_meter_meter_shaper_configuration_result_t&) const;

template la_status la_meter_set_impl::do_configure_meters_table_entry<rx_meter_block_meters_table_memory>(la_slice_ifg,
                                                                                                          size_t,
                                                                                                          lld_memory_scptr,
                                                                                                          size_t);
template la_status la_meter_set_impl::do_configure_meters_table_entry<rx_meter_meters_table_memory>(la_slice_ifg,
                                                                                                    size_t,
                                                                                                    lld_memory_scptr,
                                                                                                    size_t);

} // namespace silicon_one
