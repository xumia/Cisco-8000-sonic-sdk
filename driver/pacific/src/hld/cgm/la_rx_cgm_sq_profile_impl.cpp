// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "la_rx_cgm_sq_profile_impl.h"

#include "api_tracer.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "rx_cgm_handler.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_rx_cgm_sq_profile_impl::la_rx_cgm_sq_profile_impl(const la_device_impl_wptr& device)
    : m_device(device), m_is_default(false), m_hr_timer_or_threshold_value(0)
{
    for (size_t i = 0; i < m_profile_id.size(); i++) {
        m_profile_id[i] = (la_uint_t)-1;
    }
}

la_rx_cgm_sq_profile_impl::~la_rx_cgm_sq_profile_impl()
{
}

la_status
la_rx_cgm_sq_profile_impl::destroy()
{
    if (!m_is_default) {
        for (size_t slice : m_device->get_used_slices()) {
            if (m_ifg_use_count->is_slice_in_use(slice)) {
                return LA_STATUS_EBUSY;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_rx_cgm_sq_profile_impl::initialize(la_object_id_t oid, bool is_default)
{
    m_oid = oid;
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    la_status status = configure_default_policy_mapping();
    return_on_error(status);

    la_uint_t default_threshold_value
        = bit_utils::ones(rx_cgm_sq_profile_lut_memory::fields::SLICE_SQ_THR0_WIDTH) * la_device_impl::SMS_BLOCK_SIZE_IN_BYTES;

    m_thresholds.thresholds[0] = default_threshold_value;
    m_thresholds.thresholds[1] = default_threshold_value;
    m_thresholds.thresholds[2] = default_threshold_value;

    // If default profile, write to HW
    if (is_default) {
        auto nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
        for (la_slice_id_t slice : nw_slices) {
            m_profile_id[slice] = LA_RX_CGM_DEFAULT_PROFILE_ID;
            // Use count for default profile is statically 1
            la_slice_ifg ifg = {.slice = slice, .ifg = 0};
            bool ifg_added, slice_added, slice_pair_added;
            m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);

            la_status status = set_slice_thresholds(slice, m_thresholds);
            return_on_error(status);

            status = set_slice_hr_value(slice, m_hr_timer_or_threshold_value);
            return_on_error(status);

            for (auto it = m_rx_cgm_policy_map.begin(); it != m_rx_cgm_policy_map.end(); it++) {
                status = set_slice_policy(
                    slice, it->first, it->second.flow_control, it->second.drop_yellow, it->second.drop_green, it->second.fc_trig);
                return_on_error(status);
            }
        }
    }

    m_is_default = is_default;
    return LA_STATUS_SUCCESS;
}

la_status
la_rx_cgm_sq_profile_impl::set_thresholds(const la_rx_cgm_sq_profile_thresholds& thresholds)
{
    start_api_call("thresholds=", thresholds);

    for (la_slice_id_t slice : m_ifg_use_count->get_slices()) {
        la_status status = set_slice_thresholds(slice, thresholds);
        return_on_error(status);
    }

    m_thresholds = thresholds;

    return LA_STATUS_SUCCESS;
}

la_status
la_rx_cgm_sq_profile_impl::get_thresholds(la_rx_cgm_sq_profile_thresholds& out_thresholds) const
{
    start_api_getter_call();

    out_thresholds = m_thresholds;

    return LA_STATUS_SUCCESS;
}

la_status
la_rx_cgm_sq_profile_impl::set_rx_cgm_policy(const la_rx_cgm_policy_status& status,
                                             bool flow_control,
                                             bool drop_yellow,
                                             bool drop_green,
                                             bool fc_trig)
{
    start_api_call("status=",
                   status,
                   "flow_control=",
                   flow_control,
                   "drop_yellow=",
                   drop_yellow,
                   "drop_green=",
                   drop_green,
                   "fc_trig=",
                   fc_trig);

    la_status ret_val = validate_profile_status(status);
    return_on_error(ret_val);

    for (la_slice_id_t slice : m_ifg_use_count->get_slices()) {
        ret_val = set_slice_policy(slice, status, flow_control, drop_yellow, drop_green, fc_trig);
        return_on_error(ret_val);
    }

    m_rx_cgm_policy_map[status].flow_control = flow_control;
    m_rx_cgm_policy_map[status].drop_yellow = drop_yellow;
    m_rx_cgm_policy_map[status].drop_green = drop_green;
    m_rx_cgm_policy_map[status].fc_trig = fc_trig;

    return LA_STATUS_SUCCESS;
}

la_status
la_rx_cgm_sq_profile_impl::validate_profile_status(const la_rx_cgm_policy_status& status)
{
    // Regions may be from 0-3
    if (status.counter_a_region >= LA_CGM_NUM_SMS_BYTES_QUANTIZATION_REGIONS) {
        return LA_STATUS_EINVAL;
    }
    if (status.sq_group_region >= LA_RX_CGM_NUM_SQG_QUANTIZATION_REGIONS) {
        return LA_STATUS_EINVAL;
    }
    if (status.sq_profile_region >= LA_RX_CGM_NUM_SQ_PROFILE_QUANTIZATION_REGIONS) {
        return LA_STATUS_EINVAL;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_rx_cgm_sq_profile_impl::get_rx_cgm_policy(const la_rx_cgm_policy_status& status,
                                             bool& out_flow_control,
                                             bool& out_drop_yellow,
                                             bool& out_drop_green,
                                             bool& out_fc_trig) const
{
    start_api_getter_call();

    auto it = m_rx_cgm_policy_map.find(status);
    if (it == m_rx_cgm_policy_map.end()) {
        // Should not occur
        return LA_STATUS_EUNKNOWN;
    }

    out_flow_control = it->second.flow_control;
    out_drop_yellow = it->second.drop_yellow;
    out_drop_green = it->second.drop_green;
    out_fc_trig = it->second.fc_trig;

    return LA_STATUS_SUCCESS;
}

la_status
la_rx_cgm_sq_profile_impl::set_pfc_headroom_timer(std::chrono::nanoseconds time)
{
    start_api_call("time=", time);

    la_rx_cgm_headroom_mode_e mode;
    la_status status = m_device->m_rx_cgm_handler->get_rx_cgm_hr_management_mode(mode);
    return_on_error(status);

    if (mode != la_rx_cgm_headroom_mode_e::TIMER) {
        return LA_STATUS_EINVAL;
    }

    for (la_slice_id_t slice : m_ifg_use_count->get_slices()) {
        status = set_slice_hr_value(slice, time.count());
        return_on_error(status);
    }

    m_hr_timer_or_threshold_value = time.count();

    return LA_STATUS_SUCCESS;
}

la_status
la_rx_cgm_sq_profile_impl::set_pfc_headroom_threshold(la_uint_t threshold)
{
    start_api_call("threshold=", threshold);

    la_rx_cgm_headroom_mode_e mode;
    la_status status = m_device->m_rx_cgm_handler->get_rx_cgm_hr_management_mode(mode);
    return_on_error(status);

    if (mode != la_rx_cgm_headroom_mode_e::THRESHOLD) {
        return LA_STATUS_EINVAL;
    }

    for (la_slice_id_t slice : m_ifg_use_count->get_slices()) {
        status = set_slice_hr_value(slice, threshold);
        return_on_error(status);
    }

    m_hr_timer_or_threshold_value = threshold;

    return LA_STATUS_SUCCESS;
}

la_status
la_rx_cgm_sq_profile_impl::add_ifg(la_slice_ifg ifg)
{
    transaction txn;

    if (m_is_default) {
        // Default profile is already written to all slices
        return LA_STATUS_SUCCESS;
    }

    bool ifg_added, slice_added, slice_pair_added;
    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([&]() {
        bool dummy;
        m_ifg_use_count->remove_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (slice_added) {
        la_uint_t new_id;
        txn.status = m_device->m_rx_cgm_handler->allocate_rx_cgm_sq_profile_id(ifg.slice, new_id);
        return_on_error(txn.status);
        txn.on_fail([&]() { m_device->m_rx_cgm_handler->release_rx_cgm_sq_profile_id(ifg.slice, new_id); });

        m_profile_id[ifg.slice] = new_id;
        txn.on_fail([&]() { m_profile_id[ifg.slice] = (la_uint_t)-1; });

        txn.status = set_slice_thresholds(ifg.slice, m_thresholds);
        return_on_error(txn.status);

        txn.status = set_slice_hr_value(ifg.slice, m_hr_timer_or_threshold_value);
        return_on_error(txn.status);

        for (auto it = m_rx_cgm_policy_map.begin(); it != m_rx_cgm_policy_map.end(); it++) {
            txn.status = set_slice_policy(
                ifg.slice, it->first, it->second.flow_control, it->second.drop_yellow, it->second.drop_green, it->second.fc_trig);
            return_on_error(txn.status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_rx_cgm_sq_profile_impl::remove_ifg(la_slice_ifg ifg)
{
    transaction txn;
    if (m_is_default) {
        // No need to remove IFGs for default profile
        return LA_STATUS_SUCCESS;
    }

    dassert_crit(m_ifg_use_count->is_ifg_in_use(ifg));
    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);
    txn.on_fail([&]() {
        bool dummy;
        m_ifg_use_count->add_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (slice_removed) {
        txn.status = m_device->m_rx_cgm_handler->release_rx_cgm_sq_profile_id(ifg.slice, m_profile_id[ifg.slice]);
        return_on_error(txn.status);

        m_profile_id[ifg.slice] = (la_uint_t)-1;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_rx_cgm_sq_profile_impl::configure_default_policy_mapping()
{
    for (la_uint_t ctr_a_status = 0; ctr_a_status < LA_CGM_NUM_SMS_BYTES_QUANTIZATION_REGIONS; ctr_a_status++) {
        for (la_uint_t sqg_status = 0; sqg_status < LA_RX_CGM_NUM_SQG_QUANTIZATION_REGIONS; sqg_status++) {
            for (la_uint_t sq_status = 0; sq_status < LA_RX_CGM_NUM_SQ_PROFILE_QUANTIZATION_REGIONS; sq_status++) {
                la_rx_cgm_policy_status my_status = {
                    .counter_a_region = ctr_a_status, .sq_group_region = sqg_status, .sq_profile_region = sq_status,
                };
                /* Default policy */
                m_rx_cgm_policy_map[my_status].flow_control = false;
                m_rx_cgm_policy_map[my_status].drop_yellow = false;
                m_rx_cgm_policy_map[my_status].drop_green = false;
                m_rx_cgm_policy_map[my_status].fc_trig = false;
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_rx_cgm_sq_profile_impl::set_slice_thresholds(la_slice_id_t slice, const la_rx_cgm_sq_profile_thresholds& thresholds)
{
    la_status status = m_device->m_rx_cgm_handler->set_rx_cgm_sq_profile_thresholds(slice, m_profile_id[slice], thresholds);
    return status;
}

la_status
la_rx_cgm_sq_profile_impl::set_slice_policy(la_slice_id_t slice,
                                            const la_rx_cgm_policy_status& status,
                                            bool flow_control,
                                            bool drop_yellow,
                                            bool drop_green,
                                            bool fc_trig)
{
    la_status return_status = m_device->m_rx_cgm_handler->set_rx_cgm_sq_profile_policy(
        slice, m_profile_id[slice], status, flow_control, drop_yellow, drop_green, fc_trig);
    return return_status;
}

la_status
la_rx_cgm_sq_profile_impl::set_slice_hr_value(la_slice_id_t slice, la_uint_t hr_value)
{
    la_status status = m_device->m_rx_cgm_handler->set_rx_cgm_hr_timer_or_threshold_value(slice, m_profile_id[slice], hr_value);
    return status;
}

bool
la_rx_cgm_sq_profile_impl::is_default() const
{
    return m_is_default;
}

la_uint_t
la_rx_cgm_sq_profile_impl::get_internal_id(la_slice_id_t slice) const
{
    start_api_getter_call();

    return m_profile_id[slice];
}

la_status
la_rx_cgm_sq_profile_impl::get_pfc_headroom_value(la_uint_t& out_value) const
{
    start_api_getter_call();

    out_value = m_hr_timer_or_threshold_value;

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_rx_cgm_sq_profile_impl::type() const
{
    return object_type_e::RX_CGM_SQ_PROFILE;
}

const la_device*
la_rx_cgm_sq_profile_impl::get_device() const
{
    return m_device.get();
}

la_object_id_t
la_rx_cgm_sq_profile_impl::oid() const
{
    return m_oid;
}

std::string
la_rx_cgm_sq_profile_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_rx_cgm_sq_profile_impl(oid=" << m_oid << ")";
    return log_message.str();
}

} // namespace silicon_one
